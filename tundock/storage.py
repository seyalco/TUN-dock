"""Local presets and proxy bookmarks with credential-free addresses."""

from dataclasses import asdict, dataclass
import json
import os
from pathlib import Path
import tempfile

from .core import Options, Proxy

DIRECTORY = Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config") / "tundock"


@dataclass(frozen=True)
class Preset:
    name: str
    address: str
    command: str
    directory: str
    options: Options


@dataclass(frozen=True)
class ProxyBookmark:
    name: str
    address: str

    def __post_init__(self):
        if not isinstance(self.name, str) or not self.name.strip() or not isinstance(self.address, str):
            raise ValueError("A saved proxy has an invalid name or address.")
        object.__setattr__(self, "name", self.name.strip())
        object.__setattr__(self, "address", Proxy.parse(self.address).address)


def load():
    try:
        raw = json.loads((DIRECTORY / "presets.json").read_text())
    except FileNotFoundError:
        return []
    if not isinstance(raw, list):
        raise ValueError("The preset file must contain a list.")
    presets = []
    for item in raw:
        values = [item[key] for key in ("name", "address", "command", "directory")]
        if not all(isinstance(value, str) for value in values):
            raise ValueError("A saved preset has an invalid field.")
        name, address, command, directory = values
        presets.append(Preset(name, Proxy.parse(address).address, command, directory, Options(**item["options"])))
    return presets


def save(presets):
    _write_records("presets.json", [asdict(preset) for preset in presets])


def load_bookmarks():
    try:
        raw = json.loads((DIRECTORY / "proxies.json").read_text())
    except FileNotFoundError:
        return []
    if not isinstance(raw, list):
        raise ValueError("The saved proxy file must contain a list.")
    return [ProxyBookmark(item["name"], item["address"]) for item in raw]


def save_bookmarks(bookmarks):
    records = [asdict(ProxyBookmark(item.name, item.address)) for item in bookmarks]
    _write_records("proxies.json", records)


def _write_records(filename, records):
    DIRECTORY.mkdir(parents=True, exist_ok=True, mode=0o700)
    file = tempfile.NamedTemporaryFile(
        mode="w", dir=DIRECTORY, prefix=f".{Path(filename).stem}-", delete=False,
    )
    temporary = Path(file.name)
    try:
        with file:
            json.dump(records, file, indent=2, ensure_ascii=False)
            file.write("\n")
        temporary.replace(DIRECTORY / filename)
    finally:
        temporary.unlink(missing_ok=True)
