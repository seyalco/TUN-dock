"""Integration test using only local proxy and echo services."""

from contextlib import ExitStack
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


def service(stack, kind, handler):
    instance = stack.enter_context(kind(("127.0.0.1", 0), handler))
    thread = threading.Thread(target=instance.serve_forever, daemon=True)
    thread.start()
    stack.callback(instance.shutdown)
    return instance.server_address[1]


def proxy_config(port, protocol):
    return {
        "log": {"level": "error"},
        "inbounds": [{"type": protocol, "listen": "127.0.0.1", "listen_port": port}],
        "outbounds": [{"type": "direct", "tag": "echo"}],
        "route": {"rules": [{
            "action": "route", "outbound": "echo", "override_address": "127.0.0.1",
        }], "final": "echo"},
    }


def proxy_service(stack, directory, tools, protocol):
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        port = reservation.getsockname()[1]
    config = directory / (protocol + ".json")
    config.write_text(json.dumps(proxy_config(port, protocol)))
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
    assert subprocess.check_output(route) == host_before
    print("Verified private TCP, UDP, IPv6, HTTP CONNECT, both loopbacks, fail-closed and unchanged host routing.")
    print("Verified launch receipt, live stdout/stderr, actual upstream flow, and existing-process guard.")


if __name__ == "__main__":
    main()
