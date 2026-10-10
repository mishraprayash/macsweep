#!/bin/sh
# Installs the latest sweep release for macOS.
#
#   curl -fsSL https://raw.githubusercontent.com/mishraprayash/macsweep/main/install.sh | sh
#
# Environment:
#   SWEEP_VERSION      a release tag such as v0.4.0 (default: the latest release)
#   SWEEP_INSTALL_DIR  where to put the binary (default: ~/.local/bin)
#   SWEEP_NO_MODIFY_PATH  set to leave shell startup files alone; otherwise, if
#                      the install folder is not on PATH, one line is added to
#                      ~/.zshrc, ~/.bash_profile or fish's conf.d
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

# tilde shortens a path in the home folder to ~/... for messages.
tilde() {
	case "$1" in
	"$HOME"/*) echo "~/${1#"$HOME"/}" ;;
	*) echo "$1" ;;
	esac
}

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
echo "Installed $("$dir/sweep" --version) to $(tilde "$dir/sweep")"

# add_to_path makes new terminal windows find sweep, by adding one line to
# the user's shell startup file. It never adds the line twice.
add_to_path() {
	case "$dir" in
	"$HOME"/*) shown_dir="\$HOME/${dir#"$HOME"/}" ;; # stays correct if HOME moves
	*) shown_dir="$dir" ;;
	esac
	case "$(basename "${SHELL:-}")" in
	zsh)
		rc="${ZDOTDIR:-$HOME}/.zshrc"
		line="export PATH=\"$shown_dir:\$PATH\""
		;;
	bash)
		rc="$HOME/.bash_profile" # what Terminal's login shells read on macOS
		line="export PATH=\"$shown_dir:\$PATH\""
		;;
	fish)
		rc="$HOME/.config/fish/conf.d/sweep.fish"
		line="fish_add_path \"$dir\""
		;;
	*)
		return 1
		;;
	esac
	if [ -f "$rc" ] && grep -qF "$line" "$rc"; then
		return 0
	fi
	mkdir -p "$(dirname "$rc")"
	printf '\n# Added by the sweep installer\n%s\n' "$line" >>"$rc"
	echo "Added $(tilde "$dir") to your PATH in $(tilde "$rc")"
}

case ":$PATH:" in
*":$dir:"*)
	next="sweep"
	;;
*)
	next="$dir/sweep"
	echo
	if [ -n "${SWEEP_NO_MODIFY_PATH:-}" ]; then
		echo "$(tilde "$dir") is not on your PATH (left alone: SWEEP_NO_MODIFY_PATH is set)."
	elif add_to_path; then
		echo "Open a new Terminal window to use 'sweep' (or run $(tilde "$dir/sweep") now)."
		next="sweep"
	else
		echo "$dir is not on your PATH. Add it in your shell's startup file:"
		echo "  export PATH=\"$dir:\$PATH\""
	fi
	;;
esac

echo
echo "Next: $next doctor    (checks Full Disk Access)"
echo "      $next           (scans your home folder; nothing is deleted)"
