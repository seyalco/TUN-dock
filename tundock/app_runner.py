"""Start the requested executable only after verifying the private network."""

import os
from pathlib import Path
import subprocess
import sys


def main():
    marker, expected_namespace, *args = sys.argv[1:]
    namespace = os.readlink("/proc/self/ns/net")
    if namespace != expected_namespace:
        print("Tundock: refused to start the program outside its private network.", file=sys.stderr, flush=True)
        return 126

    try:
        process = subprocess.Popen(args)
    except OSError as error:
        print(f"Tundock: could not execute {Path(args[0]).name}: {error.strerror}", file=sys.stderr, flush=True)
        return 127 if isinstance(error, FileNotFoundError) else 126

    marker = Path(marker)
    temporary = marker.with_suffix(".pending")
    temporary.write_text(namespace)
    temporary.replace(marker)
    code = process.wait()
    return code if code >= 0 else 128 - code


if __name__ == "__main__":
    raise SystemExit(main())
