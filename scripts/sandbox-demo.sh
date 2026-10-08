#!/usr/bin/env bash
# Run sweep against a generated fixture tree inside a throwaway sandbox.
#
#   make demo              # build, run, clean up
#   KEEP=1 make demo       # keep the sandbox to poke around afterwards
#   SHELL_IN=1 make demo   # drop into a shell inside the sandbox
#
# Safety: $HOME is redirected into the sandbox, so sweep's cache (and, in
# later phases, its audit log and Trash) never touch your real home. The only
# thing ever removed is the sandbox directory this script created.
set -euo pipefail

BIN=${BIN:-"$(cd "$(dirname "$0")/.." && pwd)/bin/sweep"}
[[ -x "$BIN" ]] || { echo "sweep binary not found at $BIN (run 'make build')" >&2; exit 1; }

REAL_HOME=$(cd "$HOME" && pwd -P)
SANDBOX=$(mktemp -d "${TMPDIR:-/tmp}/sweep-sandbox.XXXXXX")
SANDBOX=$(cd "$SANDBOX" && pwd -P)
case "$SANDBOX/" in
  "$REAL_HOME"/*) echo "refusing: sandbox $SANDBOX is inside your home directory" >&2; exit 1 ;;
esac

cleanup() {
  # Only ever remove the exact directory mktemp created above.
  case "$SANDBOX" in
    */sweep-sandbox.??????)
      chmod -R u+rwx "$SANDBOX" 2>/dev/null || true
      rm -rf -- "$SANDBOX"
      ;;
    *) echo "not removing unexpected path: $SANDBOX" >&2 ;;
  esac
}
if [[ "${KEEP:-0}" != 1 ]]; then trap cleanup EXIT; fi

export HOME="$SANDBOX/home"
T="$HOME"   # the fixture is a fake home, so the built-in rules apply to it
mkdir -p "$HOME"

blob() { mkdir -p "$(dirname "$1")"; dd if=/dev/urandom of="$1" bs=1000 count="$2" status=none; }

echo "Building fixture tree in $T ..."
# Dev projects
blob "$T/code/web/package.json" 1
blob "$T/code/web/node_modules/react/index.js" 3000
blob "$T/code/web/node_modules/next/dist/server.js" 8000
blob "$T/code/web/.next/cache/webpack.pack" 12000
blob "$T/code/api/Cargo.toml" 1
blob "$T/code/api/target/debug/api" 20000
blob "$T/code/ml/.venv/lib/torch.so" 15000
blob "$T/code/ml/.venv/pyvenv.cfg" 1
# Media and downloads
blob "$T/Movies/holiday.mov" 25000
ln "$T/Movies/holiday.mov" "$T/Movies/holiday-hardlink.mov"     # counted once
blob "$T/Downloads/Xcode_16.xip" 30000
ln -s "$T/Movies" "$T/Downloads/movies-shortcut"                 # never followed
# Sparse Docker Desktop disk: 50 GB apparent, almost nothing allocated
D="$T/Library/Containers/com.docker.docker/Data/vms/0/data"
mkdir -p "$D"
dd if=/dev/zero of="$D/Docker.raw" bs=1 count=0 seek=50000000000 status=none
dd if=/dev/urandom of="$D/Docker.raw" bs=1000 count=4000 conv=notrunc status=none
# Things that look like artifacts but are not (no project marker / installed tool)
blob "$T/code/notes/build/plan.txt" 5
blob "$T/.vscode/extensions/ext/package.json" 1
blob "$T/.vscode/extensions/ext/node_modules/lib.js" 2000
blob "$T/Library/Caches/com.example.browser/Cache.db" 6000
# Protected
blob "$T/.ssh/id_ed25519" 1
# Unreadable directory (like a TCC-protected folder without Full Disk Access)
blob "$T/Private/secret.db" 1000
chmod 000 "$T/Private"

run() { echo; echo "\$ sweep $*"; "$BIN" "$@"; }
run scan "$T"
run top -n 8 --dirs
run report
run rules list | sed -n 1,6p   # (first few of 50)| head -6
run explain "$T/code/web/node_modules"
run explain "$T/code/web/node_modules/react/index.js"
run explain "$T/code/notes/build"
run explain "$T/.vscode/extensions/ext/node_modules"
run explain "$D/Docker.raw"
run explain "$T/.ssh/id_ed25519"
run scan "$T" --json >/dev/null && echo "(--json output OK)"

echo; echo "=== Inspect, then clean only node_modules and .next ==="
run ls "$T/code" --depth 2
run clean --name node_modules --name .next
# --skip-native: the demo never runs real tools (docker, go, brew).
# The fake HOME means "the Trash" here is $SANDBOX/home/.Trash.
run clean --name node_modules --name .next --skip-native --execute --yes
echo; echo "\$ ls -A ~/.Trash"; ls -A "$HOME/.Trash"
echo; echo "\$ tail -n 1 ~/Library/Logs/sweep/history.jsonl"; tail -n 1 "$HOME/Library/Logs/sweep/history.jsonl"
run clean --tier caution --skip-native
run restore --execute --yes

echo
echo "Sandbox: $SANDBOX"
echo "  fake HOME: $HOME  (cache at \$HOME/Library/Caches/sweep/)"
if [[ "${SHELL_IN:-0}" == 1 ]]; then
  echo "Starting a shell with HOME=$HOME. Exit to clean up."
  (cd "$T" && PATH="$(dirname "$BIN"):$PATH" "${SHELL:-/bin/bash}")
fi
if [[ "${KEEP:-0}" == 1 ]]; then
  echo "  kept (KEEP=1). Remove with: chmod -R u+rwx '$SANDBOX' && rm -rf '$SANDBOX'"
else
  echo "  removed on exit"
fi
