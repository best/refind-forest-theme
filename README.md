# rEFInd Forest Themes

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

## Source checkout and Python support

This is a source-only release. Run the commands below from a source checkout;
the patch and asset resources used by the build workflows are not yet installed
as wheel package data, so an installed wheel is not a supported command
environment.

The project requires Python 3.12 or newer; its test matrix covers Python 3.12
and Python 3.14. Install the Python dependency in an isolated environment before
running tests or builds:

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e .
```

## Build and inspect

Run the test suite and build both variants without writing to the EFI System
Partition:

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
./bin/refind-forest build --output build/refind-theme
```

The generated theme package is stored under `build/refind-theme/`. Variant A is
selected in the generated `theme-active.conf`. Keep this directory separate
from loader build output. Loader downloads are cached under
`.cache/refind-loader/` by default.

## Patched loader workflow

Loader replacement is a separate, explicit workflow. It does not run as part
of theme installation. First build and verify the reproducible unsigned image,
then sign it with a locally managed, root-owned key and certificate:

```bash
./bin/refind-loader build --output build/refind-loader
./bin/refind-loader verify build/refind-loader/refind_x64.efi
sudo ./bin/refind-loader sign build/refind-loader/refind_x64.efi
./bin/refind-loader verify build/refind-loader/refind_x64.signed.efi
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

Run the isolated OVMF/QEMU comparison before writing the candidate to the
physical ESP. Before staging for the first time, prepare the root-only
transaction backup directory:

```bash
sudo install -d -m 0700 -o root -g root \
  /var/lib/refind-forest/loader-backups
```

Once that gate passes, stage the signed image in its alternate slot and capture
the transaction path printed by `stage`:

```bash
sudo ./bin/refind-loader stage build/refind-loader/refind_x64.signed.efi
BACKUP_PATH=/var/lib/refind-forest/loader-backups/loader-TRANSACTION
sudo ./bin/refind-loader status "$BACKUP_PATH"
sudo ./bin/refind-loader boot-next "$BACKUP_PATH"
```

Staging leaves `refind_x64.efi` and normal `BootOrder` unchanged. The user may
then reboot during a maintenance window and boot Ubuntu from the candidate
menu. On return, status must report that `BootCurrent` is the recorded
candidate entry before promotion is allowed:

```bash
sudo ./bin/refind-loader status "$BACKUP_PATH"
sudo ./bin/refind-loader promote "$BACKUP_PATH"
sudo ./bin/refind-loader status "$BACKUP_PATH"
```

If candidate validation fails, boot the unchanged normal rEFInd or Ubuntu
entry and restore the recorded transaction:

```bash
sudo ./bin/refind-loader rollback "$BACKUP_PATH"
```

No command reboots the machine automatically. Keep the alternate old-loader
entry and external transaction backup until a later normal-entry boot has
successfully launched Ubuntu and Windows. Do not run `efibootmgr` or another
privileged firmware-variable manager concurrently with `stage`, `boot-next`,
`promote`, or `rollback`: Linux efivarfs has no content-conditional unlink, so
the transaction lock coordinates cooperating loader-management processes but
cannot serialize an independent root or firmware writer.

## Install

Installation writes to `/boot/efi` and requires `sudo`. Record the current boot
state and rEFInd configuration checksum first:

```bash
efibootmgr -v > /tmp/efibootmgr-before-forest.txt
sha256sum /boot/efi/EFI/refind/refind.conf > /tmp/refind-conf-before-forest.sha256
sudo ./bin/refind-forest install | tee /tmp/refind-forest-install.txt
sudo ./bin/refind-forest verify
```

The final line printed by `install` is the absolute backup directory. Capture
and validate it before rebooting:

```bash
BACKUP_PATH="$(tail -n 1 /tmp/refind-forest-install.txt)"
test -f "$BACKUP_PATH/backup.json"
```

Backups are stored under the repository's `backups/` directory by default.
Keep the selected backup until both installed operating systems and removable
media have passed runtime acceptance.

## Switch themes

Activate a variant from Ubuntu, then reboot to see it:

```bash
sudo ./bin/refind-forest switch-theme a
sudo ./bin/refind-forest switch-theme b
```

Run verification after switching when diagnosing an unexpected result:

```bash
sudo ./bin/refind-forest verify
```

## Roll back

Use the exact backup path captured during installation:

```bash
sudo ./bin/refind-forest rollback "$BACKUP_PATH"
sha256sum -c /tmp/refind-conf-before-forest.sha256
efibootmgr -v > /tmp/efibootmgr-after-rollback.txt
diff -u /tmp/efibootmgr-before-forest.txt /tmp/efibootmgr-after-rollback.txt
sudo ./bin/refind-forest verify
```

Rollback restores the original `refind.conf` bytes and any Forest files that
existed before installation. It leaves unrelated EFI files untouched. When no
Forest theme existed before installation, the final `verify` command is
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
