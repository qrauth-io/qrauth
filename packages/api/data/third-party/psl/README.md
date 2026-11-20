# Public Suffix List

`public_suffix_list.dat` is the Public Suffix List (https://publicsuffix.org),
used by the lookalike check (`src/lib/public-suffix.ts`, ADR-0007) to find the
registrable domain of a host. Both sections are used, ICANN and PRIVATE, so
tenant hosts on shared platforms (`*.github.io`, `*.blogspot.com`) count as
registrable domains of their own. Bundled unmodified; never fetched at runtime.

| | |
|---|---|
| Source | https://publicsuffix.org/list/public_suffix_list.dat |
| Version | 2026-10-31_14-17-28_UTC (commit 73f8cc701c084fe07d888ec552b2f0b53281a674) |
| SHA-256 | `617d1b276660e5a01209d7b58159450e400cf636634a7a9c2cfd50a1c6675d01` |
| Licence | Mozilla Public License 2.0, `LICENSE.txt` here (from https://www.mozilla.org/media/MPL/2.0/index.txt). Permitted for unmodified bundled data files by ADR-0005 D9 (amended by ADR-0007). |

The file must stay unmodified (MPL-2.0 applies per file; a test checks the
hash). To update: download the current list, replace the file, update the
version and hash above and `PSL_SHA256` in `src/lib/public-suffix.ts`, and run
the lookalike tests.
