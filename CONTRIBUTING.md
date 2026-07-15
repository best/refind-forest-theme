# Contributing

Contributions are welcome when they keep the project reproducible, reviewable,
and safe to test without privileged access to real firmware or disks.

## Development setup

Work from a source checkout. The patch and artwork inputs used by the build
commands are not installed as wheel package data.

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e .
PYTHONPATH=src python -W error -m unittest discover -s tests -v
```

Every change must include or update focused tests. Run the affected modules
with warnings treated as errors, then run the full suite before submitting a
pull request. Tests must use temporary directories, synthetic identifiers, and
mocked firmware interfaces. They must not require root access or touch a real
EFI System Partition (ESP), block device, or NVRAM.

## Sensitive data

Do not commit credentials, private keys, certificates, tokens, machine
snapshots, EFI variable dumps, disk or partition identifiers, private boot
configuration, absolute home-directory paths, or logs from a real machine.
Sanitize diagnostic material before including it in an issue, test, commit, or
pull request.

## Licensing and visual assets

Contributions to project code and documentation are accepted under
GPL-3.0-or-later. Preserve upstream file-specific notices when changing the
rEFInd patch or documenting downloaded build inputs.

Contributors must have the rights to contributed visual assets and must provide
their source, copyright attribution, and license. Visual assets derived from
the Yaru artwork must remain compatible with CC-BY-SA-4.0 and retain the
attribution recorded in `THIRD_PARTY_NOTICES.md`. Do not submit third-party
marks merely as decoration; follow `TRADEMARKS.md`.

## Developer Certificate of Origin

All commits must carry a sign-off under the
[Developer Certificate of Origin 1.1](https://developercertificate.org/). Add
it with `git commit -s`; the resulting commit message must contain a line in
this form:

```text
Signed-off-by: Your Name <your-address@example.invalid>
```

By signing off, you certify the Developer Certificate of Origin 1.1 and confirm
that you have the right to submit the contribution under the applicable project
and asset licenses.
