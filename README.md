# ObjectClaim

Build with an x64 C++17 toolchain:

```
cmake -S . -B build
cmake --build build --config Release
```

Run `list` and `watch` in an elevated console; run `claim` as a standard user. Names are absolute NT paths, such as `\BaseNamedObjects\Name`.

```
ObjectClaim.exe list <pid>
ObjectClaim.exe claim <event|mutant|section> <absolute-NT-path> [--size bytes] [--sddl sddl] [--seconds n]
ObjectClaim.exe watch <claim-pid> <claim-handle> [--seconds n]
```

`claim` holds the object until Ctrl-C, or for the specified number of seconds. Its default DACL grants full access to SYSTEM, Administrators, and the caller SID. Use `--sddl` to change it. Creating a global section from a user session may require SeCreateGlobalPrivilege.

`watch` samples handles for 60 seconds by default. It reports handles to the same object, including handles that may have been inherited or duplicated. Short-lived handles can be missed.
