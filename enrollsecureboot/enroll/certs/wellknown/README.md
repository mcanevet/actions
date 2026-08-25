# well-known db certificates

Microsoft's own published UEFI CA certificates, commonly used to sign third-party UEFI Option ROM
drivers (e.g. RAID/HBA controllers) and bootloaders. Public certificate data, not creative/source
material - vendored here (rather than fetched at build/run time) so `INCLUDE_WELL_KNOWN_CERTIFICATES`
works offline and deterministically.

Same three certificates Talos's own `secureboot database` generator embeds via its
`IncludeWellKnownCertificates` option (`internal/pkg/secureboot/database/certs/db/*.der` in
[siderolabs/talos](https://github.com/siderolabs/talos)):

- `MicCorUEFCA2011_2011-06-27.der` - Microsoft Corporation UEFI CA 2011
- `microsoft option rom uefi ca 2023.der` - Microsoft Option ROM UEFI CA 2023
- `microsoft uefi ca 2023.der` - Microsoft UEFI CA 2023
