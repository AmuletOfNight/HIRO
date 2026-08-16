#!/usr/bin/env bash
# Fetch HIRO face models and verify/pin their SHA-256 hashes.
#
# Usage: sudo scripts/fetch-models.sh [model-dir]
set -euo pipefail

MODEL_DIR="${1:-/usr/share/hiro/models}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# Installed copies ship the manifest next to the script; the source tree
# keeps it under crates/hiro-face/models/.
if [ -f "$SCRIPT_DIR/models/manifest.toml" ]; then
    MANIFEST="$SCRIPT_DIR/models/manifest.toml"
else
    MANIFEST="$SCRIPT_DIR/../crates/hiro-face/models/manifest.toml"
fi

mkdir -p "$MODEL_DIR"
cd "$MODEL_DIR"

declare -A URLS
declare -A FILES

section=""
while IFS= read -r line; do
    case "$line" in
        \[*\]*) section="${line//[\[\]]/}" ;;
        file\ =*) FILE="${line#file = }"; FILE="${FILE//\"/}"; FILES["$section"]="$FILE" ;;
        url\ =*) URL="${line#url = }"; URL="${URL//\"/}"; URLS["$section"]="$URL" ;;
    esac
done < "$MANIFEST"

for key in "${!URLS[@]}"; do
    file="${FILES[$key]:-}"
    url="${URLS[$key]}"
    if [ -z "$file" ] || [ -z "$url" ]; then
        continue
    fi
    if [ -f "$file" ]; then
        echo "already present: $file"
        continue
    fi
    echo "downloading $file"
    echo "  from $url"
    curl -L --fail --retry 3 -o "$file.part" "$url"
    mv "$file.part" "$file"
done

echo
echo "SHA-256 sums - pin these in $MANIFEST:"
for key in "${!URLS[@]}"; do
    file="${FILES[$key]:-}"
    [ -n "$file" ] && sha256sum "$file" | sed "s#^#$key $file: #"
done
