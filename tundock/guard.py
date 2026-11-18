"""Stop the proxy engine if its owning desktop or CLI process dies."""

import ctypes
import os
import signal
import sys

PR_SET_PDEATHSIG = 1
PR_SET_NO_NEW_PRIVS = 38


def enter_engine_user_namespace(libc, fd):
    # Keep the engine's main threads in the host network for upstream sockets.
    # Capabilities gained here apply only to the retained private user namespace.
    if os.fstat(fd).st_ino == os.stat("/proc/self/ns/user").st_ino:
        sys.exit("Refused to grant engine capabilities in the current user namespace.")

    class Header(ctypes.Structure):
        _fields_ = [("version", ctypes.c_uint32), ("pid", ctypes.c_int)]

    class Capabilities(ctypes.Structure):
        _fields_ = [("effective", ctypes.c_uint32), ("permitted", ctypes.c_uint32),
                    ("inheritable", ctypes.c_uint32)]

    clone_newuser = 0x10000000
    cap_sys_admin, cap_net_admin = 21, 12
    mask = (1 << cap_sys_admin) | (1 << cap_net_admin)
    header = Header(0x20080522, 0)
    data = (Capabilities * 2)(Capabilities(mask, mask, mask), Capabilities())
    if libc.setns(fd, clone_newuser) != 0:
        sys.exit("Could not join the retained private user namespace.")
    os.close(fd)
    if libc.capset(ctypes.byref(header), ctypes.byref(data)) != 0:
        sys.exit("Could not restrict private engine capabilities.")
    for capability in (cap_sys_admin, cap_net_admin):
        if libc.prctl(47, 2, capability, 0, 0) != 0:  # PR_CAP_AMBIENT_RAISE
            sys.exit("Could not pass private engine capabilities to sing-box.")


if __name__ == "__main__":
    parent = int(sys.argv[1])
    command = sys.argv[2:]
    libc = ctypes.CDLL(None, use_errno=True)
    prctl = libc.prctl
    if prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
        sys.exit("Could not restrict proxy privileges.")
    if command[0] == "--userns":
        enter_engine_user_namespace(libc, int(command[1]))
        command = command[2:]
    if prctl(PR_SET_PDEATHSIG, signal.SIGTERM, 0, 0, 0) != 0:
        sys.exit("Could not register proxy cleanup.")
    if os.getppid() != parent:
        sys.exit("The launcher exited before its proxy engine started.")
    os.execv(command[0], command)
