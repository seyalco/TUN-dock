#!/usr/bin/env bash
set -euo pipefail

root=$(cd -- "$(dirname -- "$0")/.." && pwd)
output=$(realpath -- "${1:-/tmp}")
[[ -d "$output" ]]
version=$(cd -- "$root" && /usr/bin/python3 -B -c 'from tundock import __version__; print(__version__)')
name=tundock-$version
staging=$(mktemp -d)
trap 'rm -r -- "$staging"' EXIT
install -d "$staging/$name"/{tundock,tests,packaging/portable,docs}
cp -- "$root"/{README.md,run-tundock,install.sh} "$staging/$name/"
cp -- "$root"/tundock/*.py "$root"/tundock/{style.css,tundock.png} "$staging/$name/tundock/"
cp -- "$root"/tests/*.py "$staging/$name/tests/"
cp -- "$root"/packaging/{make-release.sh,make-portable.sh,io.github.tundock.Tundock.desktop.in} "$staging/$name/packaging/"
cp -- "$root/packaging/portable/launcher.go" "$staging/$name/packaging/portable/"
cp -- "$root/docs/upgrade-0.2.md" "$staging/$name/docs/"
tar -C "$staging" -czf "$output/$name.tar.gz" "$name"
(cd -- "$output" && sha256sum "$name.tar.gz" > "$name.tar.gz.sha256")
printf '%s\n' "$output/$name.tar.gz"
