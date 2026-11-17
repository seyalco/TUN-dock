"""Loopback listener for a VPN Dock process launched in a private namespace."""

import ipaddress
from pathlib import Path
import select
import socket
import socketserver
import tempfile
import threading


def read_exact(conn, length):
    data = bytearray()
    while len(data) < length:
        chunk = conn.recv(length - len(data))
        if not chunk:
            raise OSError("Incomplete SOCKS handshake.")
        data.extend(chunk)
    return bytes(data)


class _Relay(socketserver.BaseRequestHandler):
    def handle(self):
        export = self.server.export
        if not export.ready:
            return
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as upstream:
            upstream.settimeout(3)
            self.request.settimeout(3)
            try:
                upstream.connect(str(export.socket_path))
                if not self._permit_tcp(upstream):
                    return
                peers = {self.request: upstream, upstream: self.request}
                active = set(peers)
                while active and not export.closed.is_set():
                    readable, _, _ = select.select(list(active), [], [], .2)
                    for conn in readable:
                        packet = conn.recv(65536)
                        if packet:
                            peers[conn].sendall(packet)
                        else:
                            active.remove(conn)
                            peers[conn].shutdown(socket.SHUT_WR)
            except OSError:
                return

    def _permit_tcp(self, upstream):
        if self.request.recv(1, socket.MSG_PEEK) != b"\x05":
            return True
        greeting = read_exact(self.request, 2)
        upstream.sendall(greeting + read_exact(self.request, greeting[1]))
        choice = read_exact(upstream, 2)
        self.request.sendall(choice)
        if choice != b"\x05\x00":
            return False
        request = read_exact(self.request, 4)
        if request[:3] != b"\x05\x01\x00":
            self.request.sendall(b"\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00")
            return False
        upstream.sendall(request)
        return True


class _Listener(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True
    request_queue_size = 32

    def __init__(self, export, port):
        self.export = export
        self.limit = threading.BoundedSemaphore(64)
        super().__init__(("127.0.0.1", port), _Relay)

    def process_request(self, request, client_address):
        if not self.limit.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self.limit.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.limit.release()


class ProxyExport:
    """Own the host loopback end of a VPN Dock session."""

    def __init__(self, port=1089):
        self.port = port
        self.closed = threading.Event()
        self.socket_path = None

    @property
    def address(self):
        return f"socks5://127.0.0.1:{self.port}"

    @property
    def ready(self):
        return (not self.closed.is_set() and self.socket_path is not None
                and self.socket_path.is_socket() and self.socket_path.with_suffix(".ready").is_file())

    @property
    def environment(self):
        if self.socket_path is None or self.closed.is_set():
            raise RuntimeError("The VPN Dock export is not running.")
        return {"VPNDOCK_EXPORT_SOCKET": str(self.socket_path), "VPNDOCK_EXPORT_PORT": str(self.port)}

    def feeds(self, proxy):
        if proxy.port != self.port:
            return False
        try:
            address = ipaddress.ip_address(proxy.host)
            return address.is_loopback or address.is_unspecified or bool(
                isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped
                and address.ipv4_mapped.is_loopback
            )
        except ValueError:
            # Reject aliases on the same port as well: an alias could resolve to loopback.
            return True

    def __enter__(self):
        self.directory = tempfile.TemporaryDirectory(prefix="tundock-vpndock-", dir="/tmp")
        self.socket_path = Path(self.directory.name) / "proxy.sock"
        try:
            self.listener = _Listener(self, self.port)
        except OSError as error:
            self.directory.cleanup()
            raise RuntimeError(f"Cannot open VPN Dock output on 127.0.0.1:{self.port}: {error.strerror}.") from error
        self.port = self.listener.server_address[1]
        self.thread = threading.Thread(target=self.listener.serve_forever, kwargs={"poll_interval": .15}, daemon=True)
        self.thread.start()
        return self

    def __exit__(self, *_):
        self.closed.set()
        self.listener.shutdown()
        self.listener.server_close()
        self.thread.join()
        self.directory.cleanup()
