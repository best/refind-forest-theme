# Third-Party Notices

This repository does not distribute a prebuilt EFI executable. The loader
workflow obtains the inputs described below and can produce a local build.

## Yaru artwork

`assets/source/ubuntu-logo.png` is an unmodified copy of Yaru's
`256x256/places/start-here.png`. The generated Ubuntu logo images derived from
that source are also covered by this notice.

- Upstream: https://github.com/ubuntu/yaru
- Copyright: 2018, Sam Hewitt <sam@snwh.org>, and the Yaru contributors
- License: Creative Commons Attribution-ShareAlike 4.0 International
  (CC-BY-SA-4.0)
- License text: `LICENSES/CC-BY-SA-4.0.txt`
- Source SHA-256:
  `c28d4166e067916d6d8191fbb8283715e2d6554585a9d83ebd16c39c7b78d42a`

## rEFInd 0.14.2

The loader workflow downloads the rEFInd 0.14.2 source and its Ubuntu Debian
delta as build inputs. This repository contains
`patches/refind-0.14.2-gnu-efi-abi.patch`, which is applied to that source.

- Upstream: https://www.rodsbooks.com/refind/
- Source package: https://archive.ubuntu.com/ubuntu/pool/universe/r/refind/
- Upstream license mapping: mixed, file-specific terms documented by the
  upstream `LICENSE.txt`, `COPYING.txt`, file headers, and Debian `copyright`
  file, including BSD and GPL terms
- This project's original code and patch contributions: GPL-3.0-or-later;
  see `LICENSE`

The upstream copyright notices and file-specific license terms continue to
apply to the downloaded rEFInd source.

## GNU-EFI

GNU-EFI is a downloaded build input used for its headers, startup objects, and
libraries. It is not vendored in this repository.

- Upstream: https://github.com/ncroxon/gnu-efi
- Binary package source: https://archive.ubuntu.com/ubuntu/pool/main/g/gnu-efi/
- License mapping: mixed, file-specific BSD, Expat, and alternative GPL terms
  recorded in the package's upstream notices and Debian `copyright` file

The copyright and license notices supplied with the downloaded GNU-EFI package
remain authoritative for that input.

## Pillow

Pillow is a non-vendored Python dependency used to generate and inspect image
assets. It is installed separately according to `pyproject.toml`.

- Upstream and license notices: https://python-pillow.github.io/

## DejaVu Sans

DejaVu Sans and DejaVu Sans Bold are non-vendored system font dependencies used
when rasterizing labels. The generator reads the installed font files; this
repository does not include the font files.

- Upstream and license notices: https://dejavu-fonts.github.io/
