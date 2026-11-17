"""Checks for desktop commands that can hand execution back to the host."""

import os
from pathlib import Path
import re
import shutil
import subprocess

INDIRECT_LAUNCHERS = {
    "appimagelauncher", "exo-open", "gtk-launch", "kde-open", "kioclient", "kioclient5", "kioclient6",
    "kstart", "kstart5", "kstart6", "snap", "systemd-run", "xdg-open",
}
BROWSER_BINARIES = {
    "firefox": {"firefox", "firefox-bin", "firefox-esr"},
    "chrome": {"chrome", "google-chrome", "google-chrome-stable"},
    "chromium": {"chromium", "chromium-browser"},
    "brave": {"brave", "brave-browser", "brave-browser-stable"},
    "edge": {"microsoft-edge", "microsoft-edge-stable", "msedge"},
    "vivaldi": {"vivaldi", "vivaldi-bin", "vivaldi-stable"},
}


def launch_target(args):
    """Find the target of a standard env-prefix without running a shell."""
    if Path(args[0]).name != "env":
        return args
    for index, token in enumerate(args[1:], 1):
        if token == "--":
            return args[index + 1:]
        if token in ("-i", "--ignore-environment") or re.match(r"^[A-Za-z_][A-Za-z_0-9]*=", token):
            continue
        return args[index:] if not token.startswith("-") else []
    return []


def delegation(args):
    target = launch_target(args)
    if not target:
        return "Choose the actual executable instead of an env command with unsupported options."
    name = Path(target[0]).name
    if (name in INDIRECT_LAUNCHERS or
            (name == "gio" and target[1:2] in (["open"], ["launch"])) or
            (name == "flatpak-spawn" and "--host" in target[1:])):
        return f"{name} can start an app through services outside Tundock. Choose the app executable directly."
    return ""


def already_running(args, *, cwd=None):
    """Return the PID of an existing instance without reading its command line."""
    target = launch_target(args)
    if not target:
        return None
    executable = target[0]
    name = Path(executable).name
    if re.fullmatch(r"(?:ba|da|fi|z|k)?sh|python[0-9.]*|node|nodejs|deno|perl|ruby|java|flatpak", name):
        return None
    resolved = Path(cwd or Path.home()) / executable if "/" in executable else shutil.which(executable)
    if not resolved:
        return None
    try:
        expected = os.stat(resolved)
    except OSError:
        return None
    related = next((family for family in BROWSER_BINARIES.values() if name in family), set())
    for process in Path("/proc").iterdir():
        if not process.name.isdecimal() or int(process.name) == os.getpid():
            continue
        try:
            if process.stat().st_uid != os.getuid():
                continue
            actual = (process / "exe").stat()
            other_name = Path(os.readlink(process / "exe")).name.removesuffix(" (deleted)")
            if os.path.samestat(expected, actual) or (related and other_name in related):
                return int(process.name)
        except OSError:
            continue
    return None


def flatpak_target(args):
    target = launch_target(args)
    if not target or Path(target[0]).name != "flatpak":
        return None
    if target[1:2] != ["run"]:
        raise ValueError("Choose a Flatpak application entry rather than a Flatpak maintenance command.")
    for index, token in enumerate(target[2:], 2):
        if token.startswith("-"):
            continue
        parts = token.removeprefix("app/").split("/")
        if re.fullmatch(r"[A-Za-z_][\w-]*(?:\.[A-Za-z_][\w-]*){2,}", parts[0]):
            return target[0], parts[0], len(args) - len(target) + index
        break
    raise ValueError("Choose an installed Flatpak application with a standard Exec entry.")


def private_flatpak_args(args, app_id, app_index):
    options = args[:app_index]
    app = args[app_index]
    trailing = args[app_index + 1:]
    # A standard exported D-Bus activation is only a request to a session bus.
    # Use the installed Flatpak's default executable for an ordinary app launch.
    if trailing == ["launch", app_id] and "--command=gapplication" in options:
        options = [arg for arg in options if arg != "--command=gapplication"]
        return [*options, "--share=network", app], True
    return [*options, "--share=network", app, *trailing], False


def running_flatpak(executable, app_id):
    path = shutil.which(executable)
    if not path:
        return False
    try:
        completed = subprocess.run(
            [path, "ps", "--columns=application"], capture_output=True,
            text=True, timeout=3, stdin=subprocess.DEVNULL,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return completed.returncode == 0 and app_id in completed.stdout.split()
