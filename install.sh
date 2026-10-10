#!/bin/sh
# Installs the latest sweep release for macOS.
#
#   curl -fsSL https://raw.githubusercontent.com/mishraprayash/macsweep/main/install.sh | sh
#
# Environment:
#   SWEEP_VERSION      a release tag such as v0.3.0 (default: the latest release)
#   SWEEP_INSTALL_DIR  where to put the binary (default: ~/.local/bin)
set -eu

repo="mishraprayash/macsweep"
dir="${SWEEP_INSTALL_DIR:-$HOME/.local/bin}"
asset="sweep-darwin-universal.tar.gz"

if [ "$(uname -s)" != "Darwin" ]; then
	echo "sweep only runs on macOS." >&2
	exit 1
fi

if [ -n "${SWEEP_BASE_URL:-}" ]; then
	base="$SWEEP_BASE_URL" # a mirror, or file:// for testing
elif [ -n "${SWEEP_VERSION:-}" ]; then
	base="https://github.com/$repo/releases/download/$SWEEP_VERSION"
else
	base="https://github.com/$repo/releases/latest/download"
fi

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

echo "Downloading $asset ..."
curl -fsSL -o "$tmp/$asset" "$base/$asset"
curl -fsSL -o "$tmp/SHA256SUMS" "$base/SHA256SUMS"

echo "Verifying checksum ..."
(cd "$tmp" && grep " $asset\$" SHA256SUMS | shasum -a 256 -c -) >/dev/null || {
	echo "Checksum mismatch for $asset; not installing." >&2
	exit 1
}

tar -xzf "$tmp/$asset" -C "$tmp" sweep
mkdir -p "$dir"
install -m 0755 "$tmp/sweep" "$dir/sweep"
echo "Installed $("$dir/sweep" --version) to $dir/sweep"

case ":$PATH:" in
*":$dir:"*) ;;
*)
	echo
	echo "$dir is not on your PATH. Add this line to ~/.zshrc, then open a new terminal:"
	echo "  export PATH=\"$dir:\$PATH\""
	;;
esac

echo
echo "Next: sweep doctor    (checks Full Disk Access)"
echo "      sweep scan      (read-only; nothing is deleted)"
