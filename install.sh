#!/usr/bin/env bash
set -euo pipefail

if (( EUID == 0 )); then
    printf 'Run this installer as your desktop user.\n' >&2
    exit 1
fi

source_dir=$(dirname -- "$(readlink -f -- "$0")")
data_home=${XDG_DATA_HOME:-"$HOME/.local/share"}
destination=$data_home/tundock
launcher=$HOME/.local/bin/tundock
desktop=$data_home/applications/io.github.tundock.Tundock.desktop
icon=$data_home/icons/hicolor/256x256/apps/io.github.tundock.Tundock.png
marker=$destination/.tundock-managed
icon_marker=$destination/.tundock-icon.sha256
engine=
portable=

case ${1:-} in
    --uninstall)
        (( $# == 1 )) || exit 2
        if [[ ! -f "$marker" || -L "$marker" || -L "$destination" ]]; then
            printf 'No managed Tundock installation found.\n' >&2
            exit 1
        fi
        if [[ -f "$launcher" ]] && [[ $(sed -n '2p' "$launcher") == '# Managed by Tundock' ]]; then
            rm -- "$launcher"
        fi
        if [[ -f "$desktop" ]] && grep -qx 'X-Tundock-Managed=true' "$desktop"; then
            rm -- "$desktop"
        fi
        if [[ -f "$icon" && ! -L "$icon" && -f "$icon_marker" && ! -L "$icon_marker" ]] &&
            [[ $(sha256sum -- "$icon" | cut -d ' ' -f 1) == "$(cat -- "$icon_marker")" ]]; then
            rm -- "$icon"
        fi
        rm -r -- "$destination"
        printf 'Tundock removed. Your saved presets are still available.\n'
        exit 0
        ;;
    --engine)
        if (( $# != 2 )) || [[ ! -f "$2" || ! -x "$2" ]]; then
            printf 'Usage: %s --engine /path/to/sing-box\n' "$0" >&2
            exit 2
        fi
        engine=$(readlink -f -- "$2")
        ;;
    --use-portable)
        if (( $# != 2 )) || [[ ! -f "$2" || ! -x "$2" ]]; then
            printf 'Usage: %s --use-portable /path/to/Tundock\n' "$0" >&2
            exit 2
        fi
        portable=$(readlink -f -- "$2")
        if [[ $(od -An -tx1 -N4 -- "$portable" | tr -d ' \n') != 7f454c46 ]]; then
            printf 'Choose the portable Tundock ELF executable.\n' >&2
            exit 2
        fi
        ;;
    '')
        ;;
    *)
        printf 'Usage: %s [--engine /path/to/sing-box | --use-portable /path/to/Tundock | --uninstall]\n' "$0" >&2
        exit 2
        ;;
esac

if [[ -z "$portable" && "$source_dir" == "$destination" ]]; then
    printf 'Run the installer from the extracted source release.\n' >&2
    exit 1
fi
if [[ -e "$destination" || -L "$destination" ]]; then
    [[ -d "$destination" && ! -L "$destination" && -f "$marker" && ! -L "$marker" ]] || {
        printf 'Installation directory already exists and is unmanaged.\n' >&2
        exit 1
    }
fi
if [[ -L "$desktop" ]] || { [[ -e "$desktop" ]] && ! grep -qx 'X-Tundock-Managed=true' "$desktop"; }; then
    printf 'An unmanaged desktop entry already exists at %s\n' "$desktop" >&2
    exit 1
fi

if [[ -n "$portable" ]]; then
    install -d -- "$destination" "$(dirname -- "$desktop")"
    touch -- "$marker"
else
    if [[ -L "$launcher" ]] || { [[ -e "$launcher" ]] && [[ $(sed -n '2p' "$launcher") != '# Managed by Tundock' ]]; }; then
        printf 'An unmanaged launcher already exists at %s\n' "$launcher" >&2
        exit 1
    fi
    install -d -- "$destination/tundock" "$(dirname -- "$launcher")" "$(dirname -- "$desktop")"
    touch -- "$marker"
    install -m 644 -- "$source_dir"/tundock/*.py "$source_dir"/tundock/{style.css,tundock.png} "$destination/tundock/"
    install -m 644 -- "$source_dir/README.md" "$destination/README.md"
    install -m 755 -- "$source_dir/run-tundock" "$destination/run-tundock"
fi

python3_bin=/usr/bin/python3
"$python3_bin" - "$source_dir" "$destination" "$launcher" "$desktop" "$icon" "$icon_marker" "$engine" "$portable" <<'PY'
from pathlib import Path
import hashlib
import os
import shlex
import sys
import tempfile

source, destination, launcher, desktop, icon, icon_marker = map(Path, sys.argv[1:7])
engine, portable = sys.argv[7:9]
icon_name = "io.github.tundock.Tundock"

def write_atomic(path, content, mode):
    fd, tmp = tempfile.mkstemp(dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as file:
            file.write(content.encode() if isinstance(content, str) else content)
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    finally:
        Path(tmp).unlink(missing_ok=True)

def desktop_quote(path):
    # First quote the Exec argument, then escape it for the desktop entry parser.
    argument = str(path).replace("%", "%%")
    for char in ('\\', '"', '`', '$'):
        argument = argument.replace(char, '\\' + char)
    argument = argument.replace('\\', '\\\\')
    if "\n" in argument or "\r" in argument:
        raise ValueError("The launcher path contains a line break.")
    return '"' + argument + '"'

def portable_entry():
    lines = desktop.read_text().splitlines(keepends=True)
    try:
        start = next(i for i, line in enumerate(lines) if line.strip() == "[Desktop Entry]") + 1
    except StopIteration:
        raise SystemExit("Tundock's desktop entry is missing its main section.") from None
    end = next((i for i in range(start, len(lines)) if lines[i].startswith("[")), len(lines))
    settings = lines[start:end]
    if "X-Tundock-Managed=true" not in {line.strip() for line in settings}:
        raise SystemExit("The desktop entry is unmanaged.")
    values = [f"Exec={desktop_quote(portable)}\n", f"Icon={icon_name}\n", f"StartupWMClass={icon_name}\n"]
    settings = [line for line in settings if not line.startswith(("Exec=", "Icon=", "StartupWMClass="))]
    return "".join(lines[:start] + values + settings + lines[end:])

def install_icon():
    payload = (source / "tundock/tundock.png").read_bytes()
    if icon.is_symlink():
        return
    if icon.exists() and (
        not icon.is_file() or icon_marker.is_symlink() or not icon_marker.is_file()
        or hashlib.sha256(icon.read_bytes()).hexdigest() != icon_marker.read_text().strip()
    ):
        return
    icon.parent.mkdir(parents=True, exist_ok=True)
    write_atomic(icon, payload, 0o644)
    write_atomic(icon_marker, hashlib.sha256(payload).hexdigest() + "\n", 0o644)

if portable and desktop.is_file():
    entry = portable_entry()
elif portable:
    template = (source / "packaging/io.github.tundock.Tundock.desktop.in").read_text()
    entry = template.replace("@LAUNCHER@", desktop_quote(portable)) + "X-Tundock-Managed=true\n"
else:
    wrapper = "#!/usr/bin/env bash\n# Managed by Tundock\n"
    if engine:
        wrapper += "export TUNDOCK_SING_BOX=" + shlex.quote(engine) + "\n"
    wrapper += "exec " + shlex.quote(str(destination / "run-tundock")) + ' "$@"\n'
    template = (source / "packaging/io.github.tundock.Tundock.desktop.in").read_text()
    entry = template.replace("@LAUNCHER@", desktop_quote(launcher)) + "X-Tundock-Managed=true\n"
    write_atomic(launcher, wrapper, 0o755)
install_icon()
write_atomic(desktop, entry, 0o644)
PY

if command -v update-desktop-database >/dev/null; then
    update-desktop-database "$(dirname -- "$desktop")" || :
fi
if [[ -n "$portable" ]]; then
    printf 'The Tundock menu entry now opens %s.\n' "$portable"
else
    printf 'Tundock is ready. Open it from your application menu or run %s.\n' "$launcher"
fi
