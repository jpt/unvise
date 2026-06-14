#!/usr/bin/env bash
# Provision a Linux box and launch a multi-target cargo-fuzz pass in tmux.
# Run from the repo root on the remote host:  ./fuzz/launch-fuzz.sh
set -euo pipefail

# system packages first: a fresh box has no compiler, and cargo-fuzz plus the
# libfuzzer-sys C++ driver need a C/C++ toolchain (assumes Debian/Ubuntu)
if command -v apt-get >/dev/null; then
  need=""
  command -v cc    >/dev/null || need="$need build-essential"
  command -v clang >/dev/null || need="$need clang"
  command -v tmux  >/dev/null || need="$need tmux"
  command -v curl  >/dev/null || need="$need curl"
  if [ -n "$need" ]; then apt-get update && apt-get install -y $need; fi
fi

# rust toolchain (idempotent)
command -v cargo >/dev/null || curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
# shellcheck disable=SC1091
. "$HOME/.cargo/env"
rustup toolchain list | grep -q '^nightly' || rustup toolchain install nightly
command -v cargo-fuzz >/dev/null || cargo install cargo-fuzz --locked

# Run the targets one at a time. ASan roughly doubles memory, so four at once can
# OOM a small box; sequentially each still gets both cores via -fork. parse is the
# deepest target and gets the most time (tune the seconds below). fork mode keeps
# fuzzing past a crash, and each crash is saved under fuzz/artifacts
N=$(nproc)
parse_secs=7200
other_secs=1800
cmd="cargo +nightly fuzz run parse -- -dict=fuzz/vise.dict -max_len=65536 -fork=$N -ignore_crashes=1 -max_total_time=$parse_secs"
for t in deflate macbinary; do
  cmd="$cmd; cargo +nightly fuzz run $t -- -max_len=65536 -fork=$N -ignore_crashes=1 -max_total_time=$other_secs"
done
cmd="$cmd; echo ALL DONE"

tmux kill-session -t fuzz 2>/dev/null || true
tmux new-session -d -s fuzz "$cmd"

echo "launched all four targets in tmux session 'fuzz' on $N core(s)"
echo "  parse ${parse_secs}s, then deflate/macbinary ${other_secs}s each"
echo "watch:   tmux attach -t fuzz        (detach with Ctrl-b d, do NOT Ctrl-C)"
echo "crashes: fuzz/artifacts/<target>/"
