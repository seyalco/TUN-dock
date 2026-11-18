import argparse
import subprocess
import sys

from . import __version__
from .core import TunnelError, dependency_paths, engine_version


def main():
    parser = argparse.ArgumentParser(description="Launch applications through a private TUN.")
    parser.add_argument("--version", action="version", version=f"Tundock {__version__}")
    parser.add_argument("--check-runtime", action="store_true",
                        help="check dependencies without opening the desktop window")
    parser.add_argument("--new-instance", action="store_true", help="open a separate Tundock instance")
    options = parser.parse_args()
    try:
        from .ui import Application
        if options.check_runtime:
            version = engine_version(dependency_paths())
            print(f"Tundock {__version__} · GTK and libadwaita available · sing-box {version}")
            print("Kernel namespace permissions and proxy connectivity are checked in the window.")
            return 0
    except ImportError as error:
        print(f"Tundock: Python GTK 4 and libadwaita bindings are required ({error}).", file=sys.stderr)
        return 1
    except ValueError as error:
        print(f"Tundock: GTK or libadwaita could not load ({error}).", file=sys.stderr)
        return 1
    except (TunnelError, OSError, subprocess.SubprocessError) as error:
        print(f"Tundock: {error}", file=sys.stderr)
        return 1
    return Application(new_instance=options.new_instance).run([])


if __name__ == "__main__":
    raise SystemExit(main())
