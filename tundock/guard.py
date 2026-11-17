"""Stop the proxy engine if its owning desktop or CLI process dies."""

import ctypes
import os
import signal
import sys

PR_SET_PDEATHSIG = 1
PR_SET_NO_NEW_PRIVS = 38

if __name__ == "__main__":
    parent = int(sys.argv[1])
    prctl = ctypes.CDLL(None, use_errno=True).prctl
    if prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
        sys.exit("Could not restrict proxy privileges.")
    if prctl(PR_SET_PDEATHSIG, signal.SIGTERM, 0, 0, 0) != 0:
        sys.exit("Could not register proxy cleanup.")
    if os.getppid() != parent:
        sys.exit("The launcher exited before its proxy engine started.")
    os.execv(sys.argv[2], sys.argv[2:])
