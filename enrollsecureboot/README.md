# enrollsecureboot

```bash
quay.io/tinkerbell/actions/enrollsecureboot:latest
```

This Action enrolls a UEFI Secure Boot trust anchor into `db` while the firmware is in
[Setup Mode](https://uefi.org/specs/UEFI/2.10/32_Secure_Boot_and_Driver_Signing.html), the state a
freshly-reset or factory Secure Boot key database is in before any key has been enrolled. It's
meant to run during provisioning, after an OS has been written to disk but before the machine
reboots into it - so a later boot enforces Secure Boot against a `db` that actually trusts the
installed OS.

`PK` and `KEK` are populated with a throwaway, freshly generated self-signed keypair: nothing
re-signs `db`/`KEK` afterwards, so there's no `PK`/`KEK` material worth persisting, and Setup Mode
accepts any well-formed signed variable update regardless of whether the signing key is already
trusted. Re-enrolling later just means resetting the keys again and re-running this Action.

| env var | data type | default value | required | description |
|---------|-----------|---------------|----------|-------------|
| DB_CERT_URL | string | "" | yes | URL of a PEM-encoded X.509 certificate to enroll into `db` |
| PRESERVE_VENDOR_CERTIFICATES | bool | false | no | Keep whatever is already enrolled in `db` and `KEK` (typically the vendor's factory-default sets, if a `ResetAllKeysToDefault` BMC action ran before this one) instead of discarding them |
| INCLUDE_WELL_KNOWN_CERTIFICATES | bool | false | no | Additionally enroll a small, fixed bundle of Microsoft's UEFI CA certificates (commonly used to sign third-party Option ROM drivers), regardless of what's currently in `db` |

Both default to `false` - enrolling only `DB_CERT_URL`'s certificate is the narrowest possible
trust set, matching Talos's own `IncludeWellKnownCertificates` default. Enabling either broadens
what's trusted to boot, which is a real security tradeoff (an attacker doesn't need to break your
own signing if a still-validly-signed but vulnerable bootloader chains up through a CA left in
`db`), so it's opt-in rather than automatic. `PRESERVE_VENDOR_CERTIFICATES` captures whatever's
actually on the specific machine (can include vendor-specific certs no generic bundle would know
about, but isn't reproducible across hardware); `INCLUDE_WELL_KNOWN_CERTIFICATES` is a fixed,
deterministic bundle that doesn't depend on anything already being enrolled. They can be combined.

## Requirements

- The Action needs `/sys:/sys` mounted so it can reach `/sys/firmware/efi/efivars`. If that mount
  doesn't already expose the host's efivarfs (for example, a non-recursive bind mount), the Action
  mounts efivarfs itself.
- The firmware must already be in Setup Mode. Getting there is BMC/vendor-specific - for Redfish,
  reset the `SecureBoot` resource's keys (`ResetKeys` with `ResetType: DeletePK`, or an equivalent
  BMC action) before running this Action. The Action fails rather than skipping if the firmware
  isn't in Setup Mode, since a silent skip combined with Secure Boot being enforced afterwards would
  leave a machine that refuses to boot.

```yaml
actions:
- name: "enroll secure boot db certificate"
  image: quay.io/tinkerbell/actions/enrollsecureboot:latest
  timeout: 90
  environment:
      DB_CERT_URL: https://factory.talos.dev/secureboot/signing-cert.pem
```
