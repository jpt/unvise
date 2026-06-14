#!/usr/bin/env sh
# Fetch the public Installer VISE samples as fuzz seeds (not checked in)
# Source: https://sembiance.com/fileFormatSamples/archive/installerVISE/
# Usage: fuzz/fetch-corpus.sh   (needs curl)
set -eu

cd "$(dirname "$0")"

BASE="https://sembiance.com/fileFormatSamples/archive/installerVISE/"
SEEDS="seeds"
mkdir -p "$SEEDS"

echo "fetching sample list from $BASE"
# file links from the directory listing, minus sort/dir/parent entries
curl -fsSL "$BASE" \
  | grep -oiE 'href="[^"]+"' \
  | sed -E 's/.*href="([^"]+)".*/\1/' \
  | grep -vE '^\?|^/|/$|^\.\.|^$' \
  | while IFS= read -r href; do
      name=$(basename "$href")
      echo "  $name"
      curl -fsSL "$BASE$href" -o "$SEEDS/$name"
    done

# parse/macbinary take whole archives; deflate takes size-prefixed bodies
count=$(find "$SEEDS" -type f | wc -l | tr -d ' ')
for t in parse macbinary; do
  mkdir -p "corpus/$t"
  find "$SEEDS" -type f -exec cp {} "corpus/$t/" \;
done

echo "done: $count samples in $SEEDS, copied into corpus/parse and corpus/macbinary"
