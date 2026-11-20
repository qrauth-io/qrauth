#!/usr/bin/env bash
# Rebuilds packages/shared/assets/fonts/NotoSans-SemiBold-frames.ttf, the one
# font frame/CTA text is outlined with (ADR-0005 PR 5). Reproducible: a pinned
# source commit and checksum, a pinned fontTools and a fixed timestamp.
#
#   python3 -m venv /tmp/ft && /tmp/ft/bin/pip install fonttools==4.60.1
#   PATH=/tmp/ft/bin:$PATH packages/shared/scripts/subset-frame-font.sh
#
# After a rebuild, regenerate FRAME_FONT_COVERAGE (src/qr-render/frames/coverage.ts):
#   UPDATE_FONT_COVERAGE=1 npm test -w packages/shared -- font-coverage
set -euo pipefail
cd "$(dirname "$0")/.."

COMMIT=8b0a1d0f5983c89bc2b93f1b5fb55f9e252744b5 # google/fonts, ofl/notosans
SOURCE_SHA256=bfb7bb691513f12e734dc346c03a03f784912432d7e3fa8e56efcf906fe86b3d
OUT=assets/fonts/NotoSans-SemiBold-frames.ttf

# Latin (Basic, Latin-1 Supplement without the soft hyphen, Extended-A),
# Greek and Coptic, Cyrillic, and common punctuation. Combining marks are
# left out: frame text is drawn without shaping, so only precomposed
# characters are supported.
UNICODES="U+0020-007E,U+00A0-00AC,U+00AE-00FF,U+0100-017F,U+0370-0377,U+037A-037F,U+0384-038A,U+038C,U+038E-03A1,U+03A3-03FF,U+0400-0482,U+048A-04FF,U+2013-2014,U+2018-201A,U+201C-201E,U+2022,U+2026,U+2039-203A,U+20AC,U+2122"

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
curl -sSfL -o "$work/vf.ttf" "https://raw.githubusercontent.com/google/fonts/$COMMIT/ofl/notosans/NotoSans%5Bwdth%2Cwght%5D.ttf"
echo "$SOURCE_SHA256  $work/vf.ttf" | shasum -a 256 -c -

export SOURCE_DATE_EPOCH=1793318400 # 2026-10-30T00:00:00Z, written to head.modified
fonttools varLib.instancer "$work/vf.ttf" wght=600 wdth=100 --static -o "$work/semibold.ttf"
mkdir -p "$(dirname "$OUT")"
pyftsubset "$work/semibold.ttf" \
  --unicodes="$UNICODES" \
  --layout-features='' --drop-tables+=GSUB,GPOS,GDEF,DSIG,STAT \
  --no-hinting --notdef-outline --name-IDs='*' --name-languages='*' \
  --output-file="$OUT"
shasum -a 256 "$OUT"
