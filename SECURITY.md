# Security Policy

[Simplified Chinese](SECURITY.zh-CN.md)

This project builds and can deploy EFI boot-manager files. A defect in path,
identity, backup, signing, or firmware-variable handling can affect the boot
chain and may leave a machine unable to boot normally.

## Reporting a vulnerability

Use GitHub private vulnerability reporting for suspected vulnerabilities. Open
the repository's **Security** tab, select **Report a vulnerability**, and submit
the report through
<https://github.com/best/refind-forest-theme/security/advisories/new>. Do not
open a public issue for boot-chain vulnerabilities or for a weakness that could
expose signing material, modify an ESP, or change NVRAM state. If unsure whether
a report is security-sensitive, use the private channel first.

Include the affected revision, the operation involved, expected and observed
behavior, and the smallest safe reproduction available. Use QEMU/OVMF or
synthetic fixtures where possible. Sanitize all attachments: do not include
private keys, certificates, tokens, EFI variable dumps, disk identifiers,
machine snapshots, private boot configuration, or absolute home-directory
paths.

## Safe investigation

Do not reproduce a report on a production boot path when an isolated image is
sufficient. Do not grant root privileges to unreviewed changes. Keep a tested
firmware or operating-system recovery path and verified backups before any
authorized hardware test that can write to the EFI System Partition or NVRAM.

General usage questions and non-sensitive defects may use public issues after
logs and configuration have been sanitized.
