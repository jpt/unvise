#!/usr/bin/env bash
# Deploy this repo to a remote host and launch the fuzzing pass there.
# Usage: ./fuzz/fuzz-remote.sh <host> [user] [remote-dir]
set -euo pipefail

host="${1:?usage: fuzz/fuzz-remote.sh <host> [user] [remote-dir]}"
user="${2:-root}"
dir="${3:-unvise}"
dest="$user@$host"

cd "$(dirname "$0")/.."   # repo root, regardless of cwd

echo "==> deploying to $dest:$dir/"
rsync -az \
  --exclude .git --exclude target --exclude fuzz/target \
  --exclude fuzz/corpus --exclude fuzz/seeds --exclude fuzz/artifacts \
  ./ "$dest:$dir/"

echo "==> provisioning + launching on $dest (first run installs the toolchain)"
ssh "$dest" "cd $dir && ./fuzz/launch-fuzz.sh"

cat <<EOF

==> running. useful commands:
  attach:       ssh $dest -t 'tmux attach -t fuzz'
  pull crashes: rsync -az $dest:$dir/fuzz/artifacts/ fuzz/artifacts/
EOF
