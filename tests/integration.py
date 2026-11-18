"""Integration test using only local proxy and echo services."""

from contextlib import ExitStack
import fcntl
import json
import os
import shutil
from pathlib import Path
import socket
import socketserver
import subprocess
import sys
import tempfile
import threading
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tundock.core import Options, Proxy, Tunnel, TunnelError, dependency_paths, socks_udp_associate, stop_process


class EchoTCP(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.sendall(self.request.recv(256))


class EchoUDP(socketserver.BaseRequestHandler):
    def handle(self):
        data, sock = self.request
        sock.sendto(data, self.client_address)


def service(stack, kind, handler, address=("127.0.0.1", 0)):
    instance = stack.enter_context(kind(address, handler))
    thread = threading.Thread(target=instance.serve_forever, daemon=True)
    thread.start()
    stack.callback(instance.shutdown)
    return instance.server_address[1]


def proxy_config(port, protocol, target_port=None):
    rule = {"action": "route", "outbound": "echo", "override_address": "127.0.0.1"}
    if target_port is not None:
        rule["override_port"] = target_port
    return {
        "log": {"level": "error"},
        "inbounds": [{"type": protocol, "listen": "127.0.0.1", "listen_port": port}],
        "outbounds": [{"type": "direct", "tag": "echo"}],
        "route": {"rules": [rule], "final": "echo"},
    }


def proxy_service(stack, directory, tools, protocol, *, target_port=None):
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        port = reservation.getsockname()[1]
    config = directory / f"{protocol}-{port}.json"
    config.write_text(json.dumps(proxy_config(port, protocol, target_port)))
    process = subprocess.Popen([tools["sing-box"], "run", "-c", str(config)], start_new_session=True)
    stack.callback(stop_process, process)
    for _ in range(100):
        if process.poll() is not None:
            raise RuntimeError("The test proxy exited before startup.")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.25):
                scheme = "socks5" if protocol == "socks" else "http"
                return Proxy.parse(f"{scheme}://127.0.0.1:{port}")
        except OSError:
            time.sleep(.05)
    raise RuntimeError("The test proxy did not become ready.")


CLIENT = """
import pathlib
import socket
import sys

family, proto, target, port = sys.argv[1:]
family = socket.AF_INET6 if family == '6' else socket.AF_INET
kind = socket.SOCK_DGRAM if proto == 'udp' else socket.SOCK_STREAM
with socket.socket(family, kind) as conn:
    conn.settimeout(1.2)
    conn.connect((target, int(port)))
    conn.sendall(b'tundock-echo')
    assert conn.recv(128) == b'tundock-echo'
assert 'nameserver 172.30.88.2' in pathlib.Path('/etc/resolv.conf').read_text()
assert '0000000000000000' in next(line for line in open('/proc/self/status') if line.startswith('CapEff'))
"""


def check(tunnel, family, protocol, target, port, *, works=True):
    run = tunnel.run([sys.executable, "-c", CLIENT, family, protocol, target, str(port)], timeout=4)
    assert (run.returncode == 0) == works, run.stderr


def loopback(tunnel, tcp_port):
    code = """
import socket
import sys
for family, address in ((socket.AF_INET, '127.0.0.1'), (socket.AF_INET6, '::1')):
    with socket.socket(family) as server:
        server.bind((address, int(sys.argv[1])))
        server.listen()
        with socket.create_connection((address, int(sys.argv[1])), timeout=2) as client:
            peer, _ = server.accept()
            with peer:
                client.sendall(b'ok')
                assert peer.recv(2) == b'ok'
"""
    run = tunnel.run([sys.executable, "-c", code, str(tcp_port)])
    assert run.returncode == 0, run.stderr


SWITCH_ADDRESS = "198.18.0.2"


class SwitchServer(socketserver.ThreadingTCPServer):
    daemon_threads = True


class RouteLabel(socketserver.BaseRequestHandler):
    proxy_label = b"proxied"

    def handle(self):
        label = b"direct" if self.server.server_address[0] == SWITCH_ADDRESS else self.proxy_label
        with self.request.makefile("rwb") as wire:
            for _ in wire:
                wire.write(label + b"\n")
                wire.flush()


class ReplacementRouteLabel(RouteLabel):
    proxy_label = b"replacement"


SWITCH_CLIENT = r"""
import fcntl
import os
from pathlib import Path
import socket
import sys
import time

directory, target, port = Path(sys.argv[1]), sys.argv[2], int(sys.argv[3])

def publish(name, value):
    pending = directory / (name + ".tmp")
    pending.write_text(value)
    pending.replace(directory / name)

def connect():
    return socket.create_connection((target, port), timeout=3)

def exchange(conn):
    with conn.makefile("rwb") as wire:
        wire.write(b"test\n")
        wire.flush()
        return wire.readline().decode().strip()

lifetime = (directory / "lifetime").open("w")
fcntl.flock(lifetime, fcntl.LOCK_EX)
local = socket.socket()
local.bind(("127.0.0.1", 0))
local.listen()
publish("ready", os.readlink("/proc/self/ns/net"))
sequence = 0
held = None
while True:
    request = directory / f"request-{sequence}"
    if not request.exists():
        time.sleep(.015)
        continue
    action = request.read_text()
    if action == "open":
        if held is not None:
            held.close()
        held = connect()
        result = exchange(held)
    elif action == "held":
        result = exchange(held)
    elif action == "fresh":
        try:
            with connect() as fresh:
                result = exchange(fresh)
        except OSError:
            result = "blocked"
    elif action == "local":
        with socket.create_connection(local.getsockname(), timeout=2) as client:
            peer, _ = local.accept()
            with peer:
                peer.settimeout(2)
                client.sendall(b"local")
                result = peer.recv(5).decode()
    elif action == "namespace":
        result = os.readlink("/proc/self/ns/net")
    else:
        raise AssertionError(action)
    publish(f"reply-{sequence}", result)
    sequence += 1
"""


class SwitchClient:
    def __init__(self, tunnel, directory, port):
        self.directory = directory
        directory.mkdir()
        self.sequence = 0
        self.process = tunnel.spawn(
            [sys.executable, "-c", SWITCH_CLIENT, str(directory), SWITCH_ADDRESS, str(port)],
            directory,
        )
        self.namespace = self._read("ready")

    def _read(self, name):
        deadline = time.monotonic() + 6
        while time.monotonic() < deadline:
            if (path := self.directory / name).exists():
                return path.read_text()
            assert self.process.poll() is None, f"{self.directory.name} exited before {name}."
            time.sleep(.02)
        raise AssertionError(f"{self.directory.name} did not publish {name}.")

    def exchange(self, action):
        pending = self.directory / "request.tmp"
        pending.write_text(action)
        pending.replace(self.directory / f"request-{self.sequence}")
        result = self._read(f"reply-{self.sequence}")
        self.sequence += 1
        return result

    def verify_stopped(self):
        self.process.wait(timeout=4)
        # A wrapper exit alone is insufficient. The live program held this lock.
        deadline = time.monotonic() + 4
        with (self.directory / "lifetime").open("r+") as lifetime:
            while time.monotonic() < deadline:
                try:
                    fcntl.flock(lifetime, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    return
                except BlockingIOError:
                    time.sleep(.02)
        raise AssertionError(f"{self.directory.name} retained resources after shutdown.")


def switch_fixture():
    tools = dependency_paths()
    with ExitStack() as stack:
        directory = Path(stack.enter_context(tempfile.TemporaryDirectory(prefix="toggle-fixture-")))
        port = service(stack, SwitchServer, RouteLabel, (SWITCH_ADDRESS, 0))
        service(stack, SwitchServer, RouteLabel, ("127.0.0.1", port))
        proxy = proxy_service(stack, directory, tools, "socks")
        replacement_port = service(stack, SwitchServer, ReplacementRouteLabel)
        replacement = proxy_service(stack, directory, tools, "socks", target_port=replacement_port)
        with Tunnel(proxy, Options(), udp=False, ipv6=False, switchable=True, initial_direct=False) as tunnel:
            tunnel.start()
            first = SwitchClient(tunnel, directory / "first", port)
            second = SwitchClient(tunnel, directory / "second", port)
            expected = f"net:[{os.fstat(tunnel.ns_fds[1]).st_ino}]"
            assert first.namespace == second.namespace == expected
            assert expected != os.readlink("/proc/self/ns/net")
            assert first.exchange("open") == second.exchange("open") == "proxied"

            tunnel.set_direct(True)
            assert first.exchange("held") == second.exchange("held") == "proxied"
            assert first.exchange("open") == second.exchange("fresh") == "direct"

            tunnel.set_direct(False)
            assert first.exchange("held") == "direct"
            assert second.exchange("held") == second.exchange("fresh") == "proxied"
            assert first.exchange("fresh") == "proxied"
            assert first.process.poll() is None and second.process.poll() is None

            old_engine = tunnel.engine
            tunnel.stop_network()
            assert old_engine.poll() is not None
            assert tunnel.engine is None
            assert first.exchange("namespace") == second.exchange("namespace") == expected
            assert first.exchange("local") == second.exchange("local") == "local"
            assert first.exchange("fresh") == second.exchange("fresh") == "blocked"

            tunnel.configure(replacement, Options(), udp=False, ipv6=False)
            tunnel.start()
            assert f"net:[{os.fstat(tunnel.ns_fds[1]).st_ino}]" == expected
            assert first.exchange("namespace") == second.exchange("namespace") == expected
            assert first.exchange("fresh") == second.exchange("fresh") == "replacement"

            tunnel.stop_app(first.process)
            first.verify_stopped()
            assert second.exchange("fresh") == "replacement"
            namespace_fds = tunnel.ns_fds
            tunnel.stop_network()
            assert tunnel.ns_fds == namespace_fds
            assert second.exchange("local") == "local"
            tunnel.stop_app(second.process)
            second.verify_stopped()
            assert not tunnel.ns_fds
            assert not any(Path(f"/proc/self/fd/{fd}").is_symlink() for fd in namespace_fds)

        with Tunnel(None, Options(), udp=False, ipv6=False, initial_direct=True) as direct:
            direct.start()
            client = SwitchClient(direct, directory / "direct", port)
            assert client.exchange("fresh") == "direct"
            try:
                direct.set_direct(False)
            except TunnelError as error:
                assert "upstream proxy" in str(error), error
            else:
                raise AssertionError("A direct-only session switched to an unconfigured proxy.")
        client.verify_stopped()
    print("Verified shared TUN, live proxy/direct switching, established TCP, and independent app stop.")
    print("Verified offline applications retain loopback, reattach to a replacement proxy, and release the namespace when idle.")
    print("Verified direct-only sessions and rejection of an unconfigured proxy route.")


SWITCH_SETUP = r"""
setpriv=$1
ip=$2
address=$3
shift 3

network_setup() {
    "$setpriv" --bounding-set=-all,+net_admin --inh-caps=-all,+net_admin \
        --ambient-caps=-all,+net_admin -- "$ip" "$@"
}

network_setup link set lo up
network_setup -4 address add "$address/32" dev lo
exec "$setpriv" --bounding-set=-all --inh-caps=-all --ambient-caps=-all -- "$@"
"""


def check_route_switch(tools):
    # Both test listeners are on the loopback device of an outer namespace
    # with no uplink. Only the address setup commands have CAP_NET_ADMIN.
    unshare, setpriv = (shutil.which(name) for name in ("unshare", "setpriv"))
    assert unshare and setpriv, "Route-switch fixture needs unshare and setpriv."
    subprocess.run(
        [unshare, "--user", "--map-current-user", "--keep-caps", "--net", "--pid",
         "--kill-child", "--mount-proc", "/bin/sh", "-eu", "-c", SWITCH_SETUP, "switch-fixture",
         setpriv, tools["ip"], SWITCH_ADDRESS, sys.executable, str(Path(__file__).resolve()), "--switch-fixture"],
        check=True, timeout=75,
    )


def main():
    tools = dependency_paths()
    route = [tools["ip"], "route", "show"]
    host_before = subprocess.check_output(route)
    with ExitStack() as stack:
        directory = Path(stack.enter_context(tempfile.TemporaryDirectory(prefix="tundock-test-")))
        tcp_port = service(stack, socketserver.TCPServer, EchoTCP)
        udp_port = service(stack, socketserver.UDPServer, EchoUDP)
        proxy = proxy_service(stack, directory, tools, "socks")
        assert socks_udp_associate(proxy).state == "Accepted"

        with Tunnel(proxy, Options(), udp=True, ipv6=True) as tunnel:
            tunnel.start()
            check(tunnel, "4", "tcp", "203.0.113.17", tcp_port)
            check(tunnel, "4", "udp", "203.0.113.17", udp_port)
            check(tunnel, "6", "tcp", "2001:db8::17", tcp_port)
            loopback(tunnel, tcp_port)
            with Tunnel(proxy, Options(), udp=False, ipv6=False) as restricted:
                restricted.start()
                assert os.fstat(tunnel.ns_fds[1]).st_ino != os.fstat(restricted.ns_fds[1]).st_ino
                check(restricted, "4", "tcp", "203.0.113.17", tcp_port)
                check(restricted, "4", "udp", "203.0.113.17", udp_port, works=False)
                check(restricted, "6", "tcp", "2001:db8::17", tcp_port, works=False)
                loopback(restricted, tcp_port)
                stop_process(restricted.engine)
                check(restricted, "4", "tcp", "203.0.113.17", tcp_port, works=False)
                check(tunnel, "4", "tcp", "203.0.113.17", tcp_port)

        outputs = []
        with Tunnel(proxy, Options(), udp=False, ipv6=False,
                    output=lambda source, line: outputs.append((source, line))) as tunnel:
            tunnel.start()
            code = CLIENT + "\nprint('fixture stdout', flush=True)\nprint('fixture stderr', file=sys.stderr, flush=True)"
            args = [sys.executable, "-c", code, "4", "tcp", "203.0.113.17", str(tcp_port)]
            tunnel.launch(args, directory)
            assert tunnel.follow(threading.Event()) == 0
        assert ("App", "fixture stdout") in outputs, outputs
        assert ("App stderr", "fixture stderr") in outputs, outputs
        assert any(source == "Network" and "execution verified" in line for source, line in outputs), outputs
        assert any(source == "Proxy" and "outbound connection to 203.0.113.17" in line
                   for source, line in outputs), outputs

        fixture_executable = directory / "existing-app"
        shutil.copy2(shutil.which("sleep"), fixture_executable)
        existing = subprocess.Popen([str(fixture_executable), "30"], start_new_session=True)
        stack.callback(stop_process, existing)
        with Tunnel(proxy, Options(), udp=False, ipv6=False) as tunnel:
            tunnel.start()
            try:
                tunnel.launch([str(fixture_executable), "1"], directory)
            except TunnelError as error:
                assert "already running" in str(error), error
                assert existing.poll() is None
            else:
                raise AssertionError("A currently running program was silently reused.")

        http = proxy_service(stack, directory, tools, "http")
        with Tunnel(http, Options(), udp=False, ipv6=False) as tunnel:
            tunnel.start()
            check(tunnel, "4", "tcp", "203.0.113.17", tcp_port)
        check_route_switch(tools)
    assert subprocess.check_output(route) == host_before
    print("Verified private TCP, UDP, IPv6, HTTP CONNECT, both loopbacks, fail-closed and unchanged host routing.")
    print("Verified launch receipt, live stdout/stderr, actual upstream flow, and existing-process guard.")


if __name__ == "__main__":
    if sys.argv[1:] == ["--switch-fixture"]:
        switch_fixture()
    else:
        main()
