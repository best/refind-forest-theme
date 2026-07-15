# rEFInd Forest Themes

[Simplified Chinese](README.zh-CN.md)

Two coordinated 2560x1600 themes for the ASUS ROG Flow Z13 rEFInd setup:

- Variant A is the default and uses modern Ubuntu orange and Windows blue.
- Variant B uses ice-white marks on translucent dark-green badges.

Both variants include matching recovery, firmware, reboot, shutdown, Ventoy,
and generic UEFI media icons. rEFInd continues to discover Ubuntu kernels,
Windows, and removable boot media automatically.

## Safety warning

Some commands require root privileges and can write to the EFI System
Partition (ESP) or change NVRAM boot variables. A wrong target, interrupted
write, or unreviewed signing input can make a system unbootable. Build and test
without privileges first, verify the mounted ESP and its physical identity,
keep validated backups outside the ESP, and maintain a tested firmware or
operating-system recovery path before any hardware deployment.

Theme installation writes Forest files and configuration below the selected
ESP. The loader `stage`, `boot-next`, `promote`, and `rollback` workflow also
manages alternate loader files and NVRAM entries. Never run those operations
concurrently with `efibootmgr` or another firmware-variable writer. Do not run
privileged commands copied from this document until their paths and effects
have been reviewed for the target machine.

Privileged Make targets invoke `sudo` themselves; do not run `sudo make`.
State-changing privileged targets require the exact `CONFIRM=YES` argument as
an explicit acknowledgement. That acknowledgement does not validate the ESP,
backup, signing material, or recovery plan for you.
The read-only `theme-verify` and `loader-status` targets also invoke `sudo`, but
do not require `CONFIRM`.

## Source checkout and Python support

This is a source-only release. Run the commands below from a source checkout;
the patch and asset resources used by the build workflows are not yet installed
as wheel package data, so an installed wheel is not a supported command
environment.

The project requires Python 3.12 or newer with `venv` support; on Debian and
Ubuntu, install the matching `python3-venv` package if necessary. Its test
matrix covers Python 3.12 and Python 3.14. Let Make create the project-owned
`.venv` and install the project in editable mode before running tests or builds:

```bash
make setup
```

Subsequent targets select the `.venv` interpreter without requiring shell
activation. Run `make help` to list the available targets.

## Build and inspect

Run the test suite and build both variants without writing to the EFI System
Partition:

```bash
make test
make build
```

Run the deterministic-build and public-tree audits separately when investigating
a failure, or use the aggregate local gate:

```bash
make deterministic
make audit
make check
```

`make ci` runs the CI aggregate. `make clean` removes generated output while
preserving the virtual environment, download cache, and backups. The
`make distclean` target also removes the virtual environment and download
cache, but always preserves backups.

The generated theme package is stored under `build/refind-theme/`. Variant A is
selected in the generated `theme-active.conf`. Keep this directory separate
from loader build output. Loader downloads are cached under
`.cache/refind-loader/` by default.

## Patched loader workflow

Loader replacement is a separate, explicit workflow. It does not run as part
of theme installation. First build and verify the reproducible unsigned image,
then sign it with a locally managed, root-owned key and certificate:

```bash
make loader-build
make loader-verify
make loader-sign CONFIRM=YES
make loader-verify \
  LOADER_IMAGE=build/refind-loader/refind_x64.signed.efi
```

By default, signing reads `/etc/refind.d/keys/refind_local.key` and
`/etc/refind.d/keys/refind_local.crt`. Provision a matching private key and
certificate and establish trust in that certificate using the platform's
Secure Boot process before relying on the signed loader. The key must be a
root-owned regular file with no group or other permissions; the certificate
must be root-owned and not group- or world-writable. This project does not
generate, enroll, or distribute signing keys or certificates. The securely
opened local certificate is the trust source for verification.

Signing also publishes `refind_x64.signed.crt` beside the signed image. Both
published files are public `0644` artifacts so offline verification does not
need root access; the private key remains inside the root-only key directory
and is never copied.

If publication fails after creating either output, the error reports each
retained public artifact under a `.refind-loader-retained-*` directory. The
invoking user may inspect and remove those reported paths before retrying;
they contain only the signed EFI image or public certificate, never the
private key. Remove the empty `.refind-loader-retained-*` container after its
reported file.

Run the isolated OVMF/QEMU smoke test before writing the candidate to the
physical ESP. Its output directory must not already exist:

```bash
make loader-smoke
```

Before staging for the first time, prepare the root-only transaction backup
directory:

```bash
make loader-backup-init CONFIRM=YES
```

Once that gate passes, stage the signed image in its alternate slot and capture
the transaction path printed by `stage`:

```bash
make loader-stage CONFIRM=YES
BACKUP_PATH=/var/lib/refind-forest/loader-backups/loader-TRANSACTION
make loader-status BACKUP_PATH="$BACKUP_PATH"
make loader-boot-next BACKUP_PATH="$BACKUP_PATH" CONFIRM=YES
```

Staging leaves `refind_x64.efi` and normal `BootOrder` unchanged. The user may
then reboot during a maintenance window and boot Ubuntu from the candidate
menu. On return, status must report that `BootCurrent` is the recorded
candidate entry before promotion is allowed:

```bash
make loader-status BACKUP_PATH="$BACKUP_PATH"
make loader-promote BACKUP_PATH="$BACKUP_PATH" CONFIRM=YES
make loader-status BACKUP_PATH="$BACKUP_PATH"
```

If candidate validation fails, boot the unchanged normal rEFInd or Ubuntu
entry and restore the recorded transaction:

```bash
make loader-rollback BACKUP_PATH="$BACKUP_PATH" CONFIRM=YES
```

No Make target reboots the machine automatically. Keep the alternate old-loader
entry and external transaction backup until a later normal-entry boot has
successfully launched Ubuntu and Windows. Do not run `efibootmgr` or another
privileged firmware-variable manager concurrently with `stage`, `boot-next`,
`promote`, or `rollback`: Linux efivarfs has no content-conditional unlink, so
the transaction lock coordinates cooperating loader-management processes but
cannot serialize an independent root or firmware writer.

## Install

Installation writes to `/boot/efi` by default and requires `sudo`. The Make
target requests privilege itself; do not run `sudo make`. Record the current
boot state and rEFInd configuration checksum first:

```bash
efibootmgr -v > /tmp/efibootmgr-before-forest.txt
sha256sum /boot/efi/EFI/refind/refind.conf > /tmp/refind-conf-before-forest.sha256
make theme-install CONFIRM=YES | tee /tmp/refind-forest-install.txt
make theme-verify
```

The final line printed by `theme-install` is the absolute backup directory.
Capture and validate it before rebooting:

```bash
BACKUP_PATH="$(tail -n 1 /tmp/refind-forest-install.txt)"
test -f "$BACKUP_PATH/backup.json"
```

Backups are stored under the repository's `backups/` directory by default.
Keep the selected backup until both installed operating systems and removable
media have passed runtime acceptance.

Make targets default to `ESP=/boot/efi`. Override `ESP` only after verifying the
alternate mount point and its physical identity.

## Switch themes

Activate a variant from Ubuntu, then reboot to see it:

```bash
make theme-switch VARIANT=a CONFIRM=YES
make theme-switch VARIANT=b CONFIRM=YES
```

Run verification after switching when diagnosing an unexpected result:

```bash
make theme-verify
```

## Roll back

Use the exact backup path captured during installation:

```bash
make theme-rollback BACKUP_PATH="$BACKUP_PATH" CONFIRM=YES
sha256sum -c /tmp/refind-conf-before-forest.sha256
efibootmgr -v > /tmp/efibootmgr-after-rollback.txt
diff -u /tmp/efibootmgr-before-forest.txt /tmp/efibootmgr-after-rollback.txt
make theme-verify
```

Rollback restores the original `refind.conf` bytes and any Forest files that
existed before installation. It leaves unrelated EFI files untouched. When no
Forest theme existed before installation, the final `theme-verify` command is
expected to exit with status 1 and report that the Forest manifest is missing;
that result confirms the Forest installation was removed.

## Firmware recovery

If rEFInd does not render correctly, open the firmware boot menu and select the
existing Ubuntu NVRAM entry. Once Ubuntu starts, run the rollback command above.

The installer does not change EFI `BootOrder`, `refind_x64.efi`, GRUB, Shim,
Windows Boot Manager, Linux kernels, or initrds.

## Runtime acceptance

Complete these checks after installation:

1. Boot without USB media. The first row should contain one folded Ubuntu entry
   and one Windows entry, with Ubuntu selected and an eight-second countdown.
2. Confirm themed Windows recovery, firmware, reboot, and shutdown tools appear
   when rEFInd discovers or supports them.
3. Explicitly boot Ubuntu and Windows once each.
4. Activate variant B and confirm the layout is unchanged while the marks use
   the ice-white glass treatment.
5. Attach a Ventoy drive and a directly written Ubuntu or Windows installer
   drive. Confirm each appears, then remove it and confirm it disappears. Do not
   launch an operating-system installer during this check.

External boot entries appear only while their media is attached. Recognized
Ubuntu, Windows, and Ventoy media use their matching themed icons; unrecognized
media use the themed generic UEFI icon.

## License and third-party names

Original project code and documentation are licensed under GPL-3.0-or-later.
The Yaru source artwork and generated derivatives are covered by
CC-BY-SA-4.0. The downloaded rEFInd and GNU-EFI inputs retain their upstream,
file-specific terms. See `LICENSE`, `LICENSES/CC-BY-SA-4.0.txt`, and
`THIRD_PARTY_NOTICES.md` for the complete notices.

This project is independent and unofficial. It is not endorsed by the owners
of the rEFInd, Ubuntu, Windows, Ventoy, Linux, UEFI, ASUS, ROG, or other names
and marks used for compatibility and identification. See `TRADEMARKS.md`.

Security reports for boot-chain or privileged-operation vulnerabilities must
follow `SECURITY.md` and must not be filed as public issues.
