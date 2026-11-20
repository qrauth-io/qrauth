# Unicode security data (UTS #39)

`confusables.txt` is the Unicode confusables data, used by the lookalike
check (`src/lib/confusables.ts`, ADR-0007) to compute UTS #39 skeletons. It is
bundled and never fetched at runtime.

| | |
|---|---|
| Source | https://www.unicode.org/Public/17.0.0/security/confusables.txt |
| Version | 17.0.0 (matches the Unicode version of Node 22 and 24, `process.versions.unicode`) |
| SHA-256 | `091c7f82fc39ef208faf8f94d29c244de99254675e09de163160c810d13ef22a` |
| Licence | Unicode License v3, `LICENSE.txt` here (from https://www.unicode.org/license.txt) |

To update: download the file for the Unicode version Node reports, replace
`confusables.txt`, update the version and hash above and in
`src/lib/confusables.ts` (`CONFUSABLES_VERSION`), and run the lookalike tests.
