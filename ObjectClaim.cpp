#include <windows.h>
#include <winternl.h>
#include <sddl.h>

#include <algorithm>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cwchar>
#include <iomanip>
#include <iostream>
#include <set>
#include <string>
#include <utility>
#include <vector>

namespace {

constexpr NTSTATUS status_info_length_mismatch = static_cast<NTSTATUS>(0xC0000004u);
constexpr NTSTATUS status_buffer_overflow = static_cast<NTSTATUS>(0x80000005u);
constexpr NTSTATUS status_buffer_too_small = static_cast<NTSTATUS>(0xC0000023u);
constexpr NTSTATUS status_object_name_collision = static_cast<NTSTATUS>(0xC0000035u);
constexpr NTSTATUS status_access_denied = static_cast<NTSTATUS>(0xC0000022u);
constexpr NTSTATUS status_privilege_not_held = static_cast<NTSTATUS>(0xC0000061u);
constexpr NTSTATUS status_object_path_not_found = static_cast<NTSTATUS>(0xC000003Au);
constexpr NTSTATUS status_object_type_mismatch = static_cast<NTSTATUS>(0xC0000024u);
constexpr auto system_extended_handle_information = static_cast<SYSTEM_INFORMATION_CLASS>(64);

struct HandleEntry {
    void* object;
    ULONG_PTR pid;
    ULONG_PTR value;
    ULONG access;
    USHORT backtrace;
    USHORT type_index;
    ULONG attributes;
    ULONG reserved;
};

struct HandleTable {
    ULONG_PTR count;
    ULONG_PTR reserved;
    HandleEntry entries[1];
};

static_assert(sizeof(void*) == 8);
static_assert(sizeof(HandleEntry) == 40);
static_assert(offsetof(HandleTable, entries) == 16);

using QuerySystem = NTSTATUS(NTAPI*)(SYSTEM_INFORMATION_CLASS, void*, ULONG, ULONG*);
using QueryObject = NTSTATUS(NTAPI*)(HANDLE, OBJECT_INFORMATION_CLASS, void*, ULONG, ULONG*);
using NtCreateEventFn = NTSTATUS(NTAPI*)(HANDLE*, ACCESS_MASK, OBJECT_ATTRIBUTES*, ULONG, BOOLEAN);
using NtCreateMutantFn = NTSTATUS(NTAPI*)(HANDLE*, ACCESS_MASK, OBJECT_ATTRIBUTES*, BOOLEAN);
using NtCreateSectionFn = NTSTATUS(NTAPI*)(HANDLE*, ACCESS_MASK, OBJECT_ATTRIBUTES*, LARGE_INTEGER*, ULONG, ULONG, HANDLE);

struct Native {
    QuerySystem query_system = nullptr;
    QueryObject query_object = nullptr;
    NtCreateEventFn create_event = nullptr;
    NtCreateMutantFn create_mutant = nullptr;
    NtCreateSectionFn create_section = nullptr;

    Native() {
        HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
        if (!ntdll) return;
        query_system = reinterpret_cast<QuerySystem>(GetProcAddress(ntdll, "NtQuerySystemInformation"));
        query_object = reinterpret_cast<QueryObject>(GetProcAddress(ntdll, "NtQueryObject"));
        create_event = reinterpret_cast<NtCreateEventFn>(GetProcAddress(ntdll, "NtCreateEvent"));
        create_mutant = reinterpret_cast<NtCreateMutantFn>(GetProcAddress(ntdll, "NtCreateMutant"));
        create_section = reinterpret_cast<NtCreateSectionFn>(GetProcAddress(ntdll, "NtCreateSection"));
    }

    explicit operator bool() const {
        return query_system && query_object && create_event && create_mutant && create_section;
    }
};

bool parse_number(const wchar_t* text, unsigned long long& value) {
    if (!text || !*text || *text == L'-') return false;
    wchar_t* end = nullptr;
    errno = 0;
    value = std::wcstoull(text, &end, 0);
    return errno != ERANGE && end && *end == L'\0';
}

bool needs_more_space(NTSTATUS status) {
    return status == status_info_length_mismatch ||
           status == status_buffer_overflow ||
           status == status_buffer_too_small;
}

bool system_handles(const Native& native, std::vector<HandleEntry>& entries, NTSTATUS& status) {
    std::vector<std::uint8_t> bytes(1 << 20);
    while (bytes.size() <= 128u * 1024u * 1024u) {
        ULONG needed = 0;
        status = native.query_system(system_extended_handle_information, bytes.data(),
                                     static_cast<ULONG>(bytes.size()), &needed);
        if (status >= 0) {
            const auto* table = reinterpret_cast<const HandleTable*>(bytes.data());
            if (table->count > (bytes.size() - offsetof(HandleTable, entries)) / sizeof(HandleEntry))
                return false;
            entries.assign(table->entries, table->entries + table->count);
            return true;
        }
        if (!needs_more_space(status)) return false;
        bytes.resize(std::max(bytes.size() * 2, static_cast<std::size_t>(needed) + 4096));
    }
    return false;
}

std::wstring object_text(const Native& native, HANDLE handle, OBJECT_INFORMATION_CLASS kind) {
    std::vector<std::uint8_t> bytes(512);
    while (bytes.size() <= 65536) {
        ULONG needed = 0;
        NTSTATUS status = native.query_object(handle, kind, bytes.data(),
                                               static_cast<ULONG>(bytes.size()), &needed);
        if (status >= 0) {
            const auto* value = reinterpret_cast<const UNICODE_STRING*>(bytes.data());
            const auto start = reinterpret_cast<std::uintptr_t>(bytes.data());
            const auto end = start + bytes.size();
            const auto ptr = reinterpret_cast<std::uintptr_t>(value->Buffer);
            if (!value->Buffer || value->Length % sizeof(wchar_t) || ptr < start ||
                ptr > end || value->Length > end - ptr)
                return {};
            return {value->Buffer, value->Length / sizeof(wchar_t)};
        }
        if (!needs_more_space(status)) return {};
        bytes.resize(std::max(bytes.size() * 2, static_cast<std::size_t>(needed) + 128));
    }
    return {};
}

std::wstring token_sid(HANDLE token) {
    DWORD size = 0;
    GetTokenInformation(token, TokenUser, nullptr, 0, &size);
    if (!size) return {};
    std::vector<std::uint8_t> data(size);
    if (!GetTokenInformation(token, TokenUser, data.data(), size, &size)) return {};
    auto* user = reinterpret_cast<TOKEN_USER*>(data.data());
    wchar_t* value = nullptr;
    if (!ConvertSidToStringSidW(user->User.Sid, &value)) return {};
    std::wstring sid(value);
    LocalFree(value);
    return sid;
}

std::wstring current_sid() {
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) return {};
    std::wstring sid = token_sid(token);
    CloseHandle(token);
    return sid;
}

bool elevated() {
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) return false;
    TOKEN_ELEVATION elevation{};
    DWORD size = 0;
    bool result = GetTokenInformation(token, TokenElevation, &elevation,
                                      sizeof(elevation), &size) && elevation.TokenIsElevated;
    CloseHandle(token);
    return result;
}

void enable_debug() {
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token))
        return;
    TOKEN_PRIVILEGES privileges{};
    privileges.PrivilegeCount = 1;
    privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    if (LookupPrivilegeValueW(nullptr, SE_DEBUG_NAME, &privileges.Privileges[0].Luid))
        AdjustTokenPrivileges(token, FALSE, &privileges, 0, nullptr, nullptr);
    CloseHandle(token);
}

const wchar_t* status_name(NTSTATUS status) {
    if (status == status_object_name_collision) return L"name collision";
    if (status == status_access_denied) return L"access denied";
    if (status == status_privilege_not_held) return L"privilege not held";
    if (status == status_object_path_not_found) return L"object path not found";
    if (status == status_object_type_mismatch) return L"object type mismatch";
    return L"error";
}

void print_status(NTSTATUS status) {
    std::wcerr << status_name(status) << L" status=0x" << std::hex << std::uppercase
               << static_cast<unsigned long>(status) << std::dec << L'\n';
}

std::wstring utc_time() {
    SYSTEMTIME time{};
    GetSystemTime(&time);
    wchar_t text[32]{};
    std::swprintf(text, 32, L"%04u-%02u-%02uT%02u:%02u:%02u.%03uZ",
                  time.wYear, time.wMonth, time.wDay, time.wHour, time.wMinute,
                  time.wSecond, time.wMilliseconds);
    return text;
}

void process_details(DWORD pid, std::wstring& image, std::wstring& sid) {
    image = L"-";
    sid = L"-";
    HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!process) return;
    wchar_t path[32768]{};
    DWORD length = 32768;
    if (QueryFullProcessImageNameW(process, 0, path, &length))
        image.assign(path, length);
    HANDLE token = nullptr;
    if (OpenProcessToken(process, TOKEN_QUERY, &token)) {
        std::wstring value = token_sid(token);
        if (!value.empty()) sid = std::move(value);
        CloseHandle(token);
    }
    CloseHandle(process);
}

int list(const Native& native, DWORD pid) {
    if (!elevated()) {
        std::wcerr << L"list requires an elevated token\n";
        return 1;
    }
    enable_debug();
    HANDLE process = OpenProcess(PROCESS_DUP_HANDLE, FALSE, pid);
    if (!process) {
        std::wcerr << L"OpenProcess failed error=" << GetLastError() << L'\n';
        return 1;
    }
    std::vector<HandleEntry> entries;
    NTSTATUS status = 0;
    if (!system_handles(native, entries, status)) {
        print_status(status);
        CloseHandle(process);
        return 1;
    }
    unsigned matches = 0;
    unsigned skipped = 0;
    for (const auto& entry : entries) {
        if (entry.pid != pid) continue;
        HANDLE copy = nullptr;
        if (!DuplicateHandle(process, reinterpret_cast<HANDLE>(entry.value),
                             GetCurrentProcess(), &copy, 0, FALSE, DUPLICATE_SAME_ACCESS)) {
            ++skipped;
            continue;
        }
        std::wstring type = object_text(native, copy, ObjectTypeInformation);
        if (type == L"Event" || type == L"Mutant" || type == L"Section") {
            std::wstring name = object_text(native, copy, ObjectNameInformation);
            if (!name.empty()) {
                PUBLIC_OBJECT_BASIC_INFORMATION basic{};
                ULONG returned = 0;
                NTSTATUS query_status = native.query_object(copy, ObjectBasicInformation,
                                                              &basic, sizeof(basic), &returned);
                if (query_status < 0) {
                    ++skipped;
                    CloseHandle(copy);
                    continue;
                }
                std::wcout << L"type=" << type << L" handle=0x" << std::hex
                           << entry.value << L" access=0x" << basic.GrantedAccess << std::dec
                           << L" name=" << name << L'\n';
                ++matches;
            }
        }
        CloseHandle(copy);
    }
    CloseHandle(process);
    DWORD session = 0;
    bool session_known = ProcessIdToSessionId(pid, &session);
    std::wcout << L"pid=" << pid
               << L" session=" << (session_known ? std::to_wstring(session) : L"-")
               << L" matches=" << matches << L" inaccessible=" << skipped << L'\n';
    return 0;
}

int claim(const Native& native, int argc, wchar_t** argv) {
    if (argc < 4) return 2;
    const std::wstring type = argv[2];
    const std::wstring name = argv[3];
    if (type != L"event" && type != L"mutant" && type != L"section") return 2;
    if (name.size() < 3 || name.front() != L'\\' ||
        name.find(L'\\', 1) == std::wstring::npos || name.size() > 32760)
        return 2;

    unsigned long long section_size = 4096;
    bool section_size_set = false;
    unsigned long long seconds = 0;
    std::wstring sddl;
    for (int i = 4; i < argc; i += 2) {
        if (i + 1 == argc) return 2;
        const std::wstring option = argv[i];
        if (option == L"--size") {
            section_size_set = true;
            if (!parse_number(argv[i + 1], section_size) || section_size == 0 ||
                section_size > 0x7FFFFFFFFFFFFFFFULL)
                return 2;
        } else if (option == L"--sddl") {
            sddl = argv[i + 1];
        } else if (option == L"--seconds") {
            if (!parse_number(argv[i + 1], seconds) || seconds > 86400) return 2;
        } else {
            return 2;
        }
    }
    if (type != L"section" && section_size_set) return 2;

    std::wstring sid = current_sid();
    if (sid.empty()) {
        std::wcerr << L"cannot read caller SID\n";
        return 1;
    }
    if (sddl.empty())
        sddl = L"D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;" + sid + L")";
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.c_str(), SDDL_REVISION_1, &descriptor, nullptr)) {
        std::wcerr << L"invalid SDDL error=" << GetLastError() << L'\n';
        return 1;
    }

    UNICODE_STRING native_name{};
    native_name.Buffer = const_cast<wchar_t*>(name.c_str());
    native_name.Length = static_cast<USHORT>(name.size() * sizeof(wchar_t));
    native_name.MaximumLength = native_name.Length;
    OBJECT_ATTRIBUTES attributes{};
    attributes.Length = sizeof(attributes);
    attributes.ObjectName = &native_name;
    attributes.Attributes = OBJ_CASE_INSENSITIVE;
    attributes.SecurityDescriptor = descriptor;

    HANDLE handle = nullptr;
    NTSTATUS status = 0;
    if (type == L"event") {
        status = native.create_event(&handle, MAXIMUM_ALLOWED, &attributes, 0, FALSE);
    } else if (type == L"mutant") {
        status = native.create_mutant(&handle, MAXIMUM_ALLOWED, &attributes, FALSE);
    } else {
        LARGE_INTEGER size{};
        size.QuadPart = static_cast<LONGLONG>(section_size);
        status = native.create_section(&handle, MAXIMUM_ALLOWED, &attributes, &size,
                                       PAGE_READWRITE, SEC_COMMIT, nullptr);
    }
    LocalFree(descriptor);
    if (status < 0) {
        print_status(status);
        return 1;
    }

    DWORD session = 0;
    ProcessIdToSessionId(GetCurrentProcessId(), &session);
    std::wcout << L"created pid=" << GetCurrentProcessId() << L" handle=0x"
               << std::hex << reinterpret_cast<std::uintptr_t>(handle) << std::dec
               << L" session=" << session << L" elevated=" << (elevated() ? 1 : 0)
               << L" sid=" << sid << L" type=" << type << L" name=" << name << std::endl;
    const ULONGLONG deadline = seconds ? GetTickCount64() + seconds * 1000 : 0;
    while (!deadline || GetTickCount64() < deadline) Sleep(200);
    CloseHandle(handle);
    return 0;
}

int watch(const Native& native, DWORD claim_pid, ULONG_PTR claim_handle, unsigned seconds) {
    if (!elevated()) {
        std::wcerr << L"watch requires an elevated token\n";
        return 1;
    }
    enable_debug();
    HANDLE process = OpenProcess(PROCESS_DUP_HANDLE, FALSE, claim_pid);
    if (!process) {
        std::wcerr << L"OpenProcess failed error=" << GetLastError() << L'\n';
        return 1;
    }
    HANDLE copy = nullptr;
    BOOL duplicated = DuplicateHandle(process, reinterpret_cast<HANDLE>(claim_handle),
                                      GetCurrentProcess(), &copy, 0, FALSE, DUPLICATE_SAME_ACCESS);
    DWORD duplicate_error = duplicated ? ERROR_SUCCESS : GetLastError();
    CloseHandle(process);
    if (!duplicated) {
        std::wcerr << L"DuplicateHandle failed error=" << duplicate_error << L'\n';
        return 1;
    }
    std::wstring type = object_text(native, copy, ObjectTypeInformation);
    std::wstring name = object_text(native, copy, ObjectNameInformation);
    if (name.empty() || (type != L"Event" && type != L"Mutant" && type != L"Section")) {
        std::wcerr << L"claim handle is not a named event, mutant, or section\n";
        CloseHandle(copy);
        return 1;
    }

    std::vector<HandleEntry> entries;
    NTSTATUS status = 0;
    if (!system_handles(native, entries, status)) {
        print_status(status);
        CloseHandle(copy);
        return 1;
    }
    void* object = nullptr;
    const DWORD self_pid = GetCurrentProcessId();
    const auto copy_value = reinterpret_cast<ULONG_PTR>(copy);
    for (const auto& entry : entries) {
        if (entry.pid == self_pid && entry.value == copy_value) {
            object = entry.object;
            break;
        }
    }
    bool claim_alive = false;
    for (const auto& entry : entries) {
        if (entry.pid == claim_pid && entry.value == claim_handle && entry.object == object)
            claim_alive = true;
    }
    if (!object || !claim_alive) {
        std::wcerr << L"claim handle not found or object identity unavailable\n";
        CloseHandle(copy);
        return 1;
    }
    std::wcout << L"watching pid=" << claim_pid << L" handle=0x" << std::hex
               << claim_handle << std::dec << L" type=" << type << L" name=" << name
               << L" interval=100ms" << std::endl;

    std::set<std::pair<ULONG_PTR, ULONG_PTR>> previous;
    const ULONGLONG deadline = seconds ? GetTickCount64() + static_cast<ULONGLONG>(seconds) * 1000 : 0;
    while (true) {
        if (!system_handles(native, entries, status)) {
            print_status(status);
            CloseHandle(copy);
            return 1;
        }
        claim_alive = false;
        std::set<std::pair<ULONG_PTR, ULONG_PTR>> current;
        for (const auto& entry : entries) {
            if (entry.pid == claim_pid && entry.value == claim_handle && entry.object == object)
                claim_alive = true;
            if (entry.object != object || entry.pid == claim_pid || entry.pid == self_pid)
                continue;
            auto key = std::make_pair(entry.pid, entry.value);
            current.insert(key);
            if (previous.count(key)) continue;
            std::wstring image;
            std::wstring sid;
            process_details(static_cast<DWORD>(entry.pid), image, sid);
            DWORD session = 0;
            bool session_known = ProcessIdToSessionId(static_cast<DWORD>(entry.pid), &session);
            std::wcout << L"seen=" << utc_time() << L" pid=" << entry.pid
                       << L" handle=0x" << std::hex << entry.value
                       << L" access=0x" << entry.access << std::dec
                       << L" session=" << (session_known ? std::to_wstring(session) : L"-")
                       << L" image=\"" << image << L"\" sid=" << sid << std::endl;
        }
        if (!claim_alive) {
            std::wcerr << L"claim handle closed\n";
            CloseHandle(copy);
            return 1;
        }
        previous = std::move(current);
        if (deadline && GetTickCount64() >= deadline) break;
        Sleep(100);
    }
    CloseHandle(copy);
    return 0;
}

void usage() {
    std::wcerr
        << L"ObjectClaim.exe list <pid>\n"
        << L"ObjectClaim.exe claim <event|mutant|section> <absolute-NT-path> "
           L"[--size bytes] [--sddl sddl] [--seconds n]\n"
        << L"ObjectClaim.exe watch <claim-pid> <claim-handle> [--seconds n]\n";
}

}

int wmain(int argc, wchar_t** argv) {
    if (argc < 2) {
        usage();
        return 2;
    }
    Native native;
    if (!native) {
        std::wcerr << L"missing ntdll export\n";
        return 1;
    }
    const std::wstring command = argv[1];
    if (command == L"list" && argc == 3) {
        unsigned long long pid = 0;
        if (parse_number(argv[2], pid) && pid <= 0xFFFFFFFFULL)
            return list(native, static_cast<DWORD>(pid));
    } else if (command == L"claim") {
        int result = claim(native, argc, argv);
        if (result != 2) return result;
    } else if (command == L"watch" && (argc == 4 || argc == 6)) {
        unsigned long long pid = 0;
        unsigned long long handle = 0;
        unsigned long long seconds = 60;
        if (argc == 6 && (std::wstring(argv[4]) != L"--seconds" ||
                          !parse_number(argv[5], seconds) || seconds > 86400))
            seconds = 86401;
        if (parse_number(argv[2], pid) && pid <= 0xFFFFFFFFULL &&
            parse_number(argv[3], handle) && seconds <= 86400)
            return watch(native, static_cast<DWORD>(pid),
                         static_cast<ULONG_PTR>(handle), static_cast<unsigned>(seconds));
    }
    usage();
    return 2;
}
