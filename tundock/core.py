"""Network engine and lifecycle. No GTK dependencies."""

from collections import deque
from contextlib import ExitStack
from dataclasses import dataclass, field
import ipaddress
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time
from urllib.parse import quote, unquote, urlsplit

from .launchcheck import already_running, delegation, flatpak_target, private_flatpak_args, running_flatpak
from .proxy_export import ProxyExport

ROOT = Path(__file__).resolve().parent
DEVICE = "tundock0"
DNS_ADDRESS = "172.30.88.2"
RESOLVERS = {
    "Cloudflare": ("1.1.1.1", "cloudflare-dns.com"),
    "Google": ("8.8.8.8", "dns.google"),
    "Quad9": ("9.9.9.9", "dns.quad9.net"),
}
POLICIES = ("Automatic", "Block", "Allow")


class TunnelError(RuntimeError):
    """An actionable error for the person running Tundock."""


class IPv6RouteUnavailable(TunnelError):
    """The tunnel has an IPv4 route but could not establish its IPv6 route."""


@dataclass(frozen=True)
class Proxy:
    scheme: str
    host: str
    port: int
    username: str = field(default="", repr=False)
    password: str = field(default="", repr=False)

    @classmethod
    def parse(cls, value, username="", password=""):
        value = value.strip()
        if any(char.isspace() or ord(char) < 32 for char in value):
            raise TunnelError("The proxy address contains whitespace or control characters.")
        try:
            parts = urlsplit(value if "://" in value else f"socks5://{value}")
            port = parts.port
            host = parts.hostname
        except ValueError as exc:
            raise TunnelError("Enter a valid proxy address with a port.") from exc
        if parts.scheme not in {"socks5", "socks5h", "http", "https"}:
            raise TunnelError("Use socks5://, http:// or https:// for a CONNECT proxy.")
        if not host or not port or parts.path not in {"", "/"} or parts.query or parts.fragment:
            raise TunnelError("Enter a proxy host and port without a path or query.")
        try:
            host = str(ipaddress.ip_address(host))
        except ValueError:
            try:
                host = host.encode("idna").decode()
            except UnicodeError as exc:
                raise TunnelError("The proxy hostname is invalid.") from exc
            if not re.fullmatch(r"[a-zA-Z0-9._-]+", host):
                raise TunnelError("The proxy hostname is invalid.")
        if parts.username is not None or parts.password is not None:
            if username or password:
                raise TunnelError("Enter credentials in the address or the sign-in fields.")
            username = unquote(parts.username or "")
            password = unquote(parts.password or "")
        if password and not username:
            raise TunnelError("Enter a username for this proxy password.")
        if any(ord(char) < 32 for char in username + password):
            raise TunnelError("Proxy credentials contain control characters.")
        scheme = "socks5" if parts.scheme.startswith("socks5") else parts.scheme
        if scheme == "socks5" and max(len(username.encode()), len(password.encode())) > 255:
            raise TunnelError("SOCKS5 credentials must each fit in 255 bytes.")
        return cls(scheme, host, port, username, password)

    @property
    def address(self):
        host = f"[{self.host}]" if ":" in self.host else self.host
        return f"{self.scheme}://{host}:{self.port}"


@dataclass(frozen=True)
class Options:
    resolver: str = "Cloudflare"
    udp: str = "Automatic"
    ipv6: str = "Automatic"
    desktop_services: bool = False

    def __post_init__(self):
        if (self.resolver not in RESOLVERS or self.udp not in POLICIES or
                self.ipv6 not in POLICIES or type(self.desktop_services) is not bool):
            raise TunnelError("Invalid DNS or network policy.")


@dataclass(frozen=True)
class Result:
    state: str = "Not tested"
    detail: str = ""

    @property
    def verified(self):
        return self.state == "Verified"


@dataclass(frozen=True)
class Report:
    tun: Result = Result()
    tcp: Result = Result()
    dns: Result = Result()
    udp: Result = Result()
    ipv6: Result = Result()


def app_command(value, directory):
    try:
        args = shlex.split(value)
    except ValueError as exc:
        raise TunnelError("Check the quotes in the program command.") from exc
    if not args:
        raise TunnelError("Choose a program or enter its executable path.")
    cwd = Path(directory or Path.home()).expanduser().resolve()
    if not cwd.is_dir():
        raise TunnelError("The working folder does not exist.")
    name = os.path.expanduser(args[0])
    if "/" in name:
        path = (cwd / name).absolute()
        executable = str(path) if path.is_file() and os.access(path, os.X_OK) else None
    else:
        executable = shutil.which(name)
    if not executable:
        raise TunnelError("The program executable was not found or is not executable.")
    return [str(Path(executable).absolute()), *args[1:]], cwd


def dependency_paths():
    if sys.platform != "linux" or os.geteuid() == 0:
        raise TunnelError("Run Tundock on Linux as a regular user.")
    candidates = {name: shutil.which(name) for name in ("bwrap", "nsenter", "ip")}
    preferred = os.environ.get("TUNDOCK_SING_BOX")
    local = Path.home() / ".local/bin/sing-box"
    sing = (shutil.which(preferred) if preferred else
            shutil.which("sing-box") or (str(local) if os.access(local, os.X_OK) else None))
    candidates["sing-box"] = sing
    missing = [name for name, path in candidates.items() if not path]
    if missing:
        raise TunnelError(f"Missing system tools: {', '.join(missing)}. See the installation guide.")
    try:
        device = Path("/dev/net/tun")
        if not stat.S_ISCHR(device.stat().st_mode) or not os.access(device, os.R_OK | os.W_OK):
            raise OSError("unavailable")
    except OSError as exc:
        raise TunnelError("The /dev/net/tun device is unavailable to your user.") from exc
    return {name: str(Path(path).absolute()) for name, path in candidates.items()}


def network_modes(proxy, options, report):
    udp = proxy.scheme == "socks5" and (
        options.udp == "Allow" or (options.udp == "Automatic" and report.udp.verified)
    )
    ipv6 = options.ipv6 == "Allow" or (options.ipv6 == "Automatic" and report.ipv6.verified)
    return udp, ipv6


def engine_config(proxy, options, holder, udp, ipv6, *, log_level="fatal"):
    resolver_ip, resolver_name = RESOLVERS[options.resolver]
    outbound = {
        "type": "socks" if proxy.scheme == "socks5" else "http",
        "tag": "upstream",
        "server": proxy.host,
        "server_port": proxy.port,
    }
    if proxy.username:
        outbound.update(username=proxy.username, password=proxy.password)
    if proxy.scheme == "socks5":
        outbound["version"] = "5"
        if not udp:
            outbound["network"] = "tcp"
    if proxy.scheme == "https":
        outbound["tls"] = {"enabled": True, "server_name": proxy.host}
    addresses = ["172.30.88.1/30"]
    if ipv6:
        addresses.append("fd2d:7140:88::1/126")
    dns = {
        "servers": [{
            "type": "https",
            "tag": "doh",
            "server": resolver_ip,
            "tls": {"server_name": resolver_name},
            "detour": "upstream",
        }],
        "final": "doh",
    }
    if not ipv6:
        dns["strategy"] = "ipv4_only"
    rules = [{"port": 53, "action": "hijack-dns"}]
    if not udp:
        rules.append({"network": "udp", "action": "reject"})
    return {
        "log": {"level": log_level, "disabled": False},
        "network_namespaces": [{"type": "unshare", "tag": "app", "pid_file": str(holder)}],
        "dns": dns,
        "inbounds": [{
            "type": "tun",
            "netns": "app",
            "interface_name": DEVICE,
            "address": addresses,
            "mtu": 1400,
            "auto_route": True,
            "strict_route": True,
            "dns_mode": "disabled",
        }],
        "outbounds": [outbound],
        "route": {"rules": rules, "final": "upstream"},
    }


def stop_process(process):
    if process is None or process.poll() is not None:
        return
    try:
        os.killpg(process.pid, signal.SIGTERM)
        process.wait(timeout=2)
    except ProcessLookupError:
        pass
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait()


def require_active(stop):
    if stop is not None and stop.is_set():
        raise InterruptedError("Session cancelled.")


def run_process(args, *, timeout, stop=None, input_text=None, **kwargs):
    """Capture a command with a finite deadline and terminate its group on cancellation."""
    require_active(stop)
    deadline = time.monotonic() + timeout
    with subprocess.Popen(
        args, stdin=subprocess.PIPE if input_text is not None else subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, errors="replace",
        start_new_session=True, **kwargs,
    ) as process:
        try:
            while True:
                require_active(stop)
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise subprocess.TimeoutExpired(args, timeout)
                try:
                    stdout, stderr = process.communicate(input_text, timeout=min(remaining, 0.2))
                    return subprocess.CompletedProcess(args, process.returncode, stdout, stderr)
                except subprocess.TimeoutExpired:
                    input_text = None
        finally:
            stop_process(process)


def engine_version(tools, stop=None):
    check = run_process([tools["sing-box"], "version"], timeout=4, stop=stop)
    match = re.search(r"sing-box version (\d+\.\d+)([^\s]*)", check.stdout)
    if check.returncode or not match or tuple(map(int, match[1].split("."))) < (1, 14):
        raise TunnelError("Install sing-box 1.14 or newer for rootless per-app networking.")
    return match[1] + match[2]


class Tunnel:
    """A private network namespace held open by a host-side sing-box process."""

    def __init__(self, proxy, options, *, udp, ipv6, output=None, capture_enabled=None, export=None):
        self.proxy, self.options = proxy, options
        self.udp, self.ipv6 = udp, ipv6
        self.files = ExitStack()
        self.engine = None
        self.app = None
        self.ns_fds = ()
        self.export = export
        self.output = output
        self.capture_enabled = capture_enabled
        self._readers = []
        self._engine_tail = deque(maxlen=12)
        self._app_tail = deque(maxlen=8)
        self._exit_check_lock = threading.Lock()

    def _capture_allowed(self):
        return self.capture_enabled is None or self.capture_enabled()

    def _emit(self, source, line):
        if self.output and self._capture_allowed():
            self.output(source, line)

    def _safe_line(self, data):
        line = data.decode(errors="replace")
        line = re.sub(r"\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07\x1b]*(?:\x07|\x1b\\))", "", line)
        line = "".join(char for char in line if char == "\t" or char.isprintable()).strip()
        for secret in (self.proxy.username, self.proxy.password):
            if not secret:
                continue
            for value in {secret, quote(secret, safe="")}:
                if len(value) >= 3:
                    line = line.replace(value, "[redacted]")
                else:
                    line = re.sub(r"(?<!\w)" + re.escape(value) + r"(?!\w)", "[redacted]", line)
        return line

    def _drain(self, pipe, source, tail=None):
        def read():
            with pipe:
                while data := pipe.readline(4096):
                    if not self._capture_allowed():
                        continue
                    line = self._safe_line(data)
                    if line and self._capture_allowed():
                        if tail is not None:
                            tail.append(line)
                        self._emit(source, line)

        reader = threading.Thread(target=read, name=f"tundock-{source.lower()}-output", daemon=True)
        reader.start()
        self._readers.append(reader)
        return reader

    def __enter__(self):
        return self

    def __exit__(self, *_):
        try:
            stop_process(self.app)
        finally:
            try:
                stop_process(self.engine)
            finally:
                for reader in self._readers:
                    reader.join(0.2)
                with self._exit_check_lock:
                    self.files.close()

    def start(self, stop=None):
        if self.export and self.export.feeds(self.proxy):
            raise TunnelError("Stage A cannot use the host endpoint that its VPN Dock session exports.")
        self.tools = dependency_paths()
        version = engine_version(self.tools, stop)
        self._emit("Network", f"Preparing private TUN with sing-box {version}.")
        self.directory = Path(self.files.enter_context(tempfile.TemporaryDirectory(prefix="tundock-")))
        holder = self.directory / "namespace.pid"
        config = engine_config(self.proxy, self.options, holder, self.udp, self.ipv6,
                               log_level="info" if self.output else "fatal")
        # sing-box can reopen its configuration. A RAM-backed file supports repeated reads.
        fd = os.memfd_create("tundock-config", os.MFD_CLOEXEC)
        with os.fdopen(fd, "wb") as memory:
            memory.write(json.dumps(config).encode())
            memory.flush()
            self.engine = subprocess.Popen(
                [sys.executable, str(ROOT / "guard.py"), str(os.getpid()), self.tools["sing-box"],
                 "run", "-c", f"/proc/self/fd/{fd}"],
                cwd=self.directory, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                start_new_session=True, pass_fds=(fd,),
            )
        engine_reader = self._drain(self.engine.stdout, "Proxy", self._engine_tail)
        deadline = time.monotonic() + 8
        ipv4_ready = False
        while time.monotonic() < deadline:
            require_active(stop)
            if self.engine.poll() is not None:
                engine_reader.join(0.3)
                detail = self._engine_tail[-1] if self._engine_tail else ""
                raise TunnelError(detail or "sing-box stopped before the tunnel was ready.")
            if not self.ns_fds:
                self._open_namespaces(holder)
            ipv4_ready = self.ns_fds and self._link_ready() and self._route_ready("4", "1.1.1.1")
            if ipv4_ready and (not self.ipv6 or self._route_ready("6", "2606:4700:4700::1111")):
                require_active(stop)
                self._prepare_dns()
                self._emit("Network", f"Private TUN {DEVICE} is ready. Upstream: {self.proxy.address}.")
                self._emit("Network", f"DNS through {self.options.resolver} DoH over the proxy.")
                return
            if stop is None:
                time.sleep(0.05)
            else:
                stop.wait(0.05)
        if self.ipv6 and ipv4_ready:
            raise IPv6RouteUnavailable("The private TUN could not establish an IPv6 route.")
        raise TunnelError("TUN did not become ready. Check unprivileged user namespaces and /dev/net/tun.")

    def _open_namespaces(self, holder):
        try:
            pid = int(holder.read_text().strip())
        except (OSError, ValueError):
            return
        with ExitStack() as handles:
            try:
                fds = tuple(
                    handles.enter_context(open(f"/proc/{pid}/ns/{name}", "rb")).fileno()
                    for name in ("user", "net")
                )
            except OSError:
                return
            own = Path("/proc/self/ns/net").stat()
            other = os.fstat(fds[1])
            if (own.st_dev, own.st_ino) == (other.st_dev, other.st_ino):
                raise TunnelError("The tunnel did not create a separate network namespace.")
            self.ns_fds = fds
            self.files.enter_context(handles.pop_all())

    def _enter(self):
        user, net = self.ns_fds
        return [self.tools["nsenter"], f"--user=/proc/self/fd/{user}",
                f"--net=/proc/self/fd/{net}", "--preserve-credentials", "--"]

    def _ip_info(self, *command):
        result = subprocess.run(
            [*self._enter(), self.tools["ip"], "-j", *command],
            pass_fds=self.ns_fds, capture_output=True, timeout=2,
        )
        if result.returncode:
            return {}
        rows = json.loads(result.stdout)
        return rows[0] if rows else {}

    def _link_ready(self):
        flags = self._ip_info("link", "show", "dev", DEVICE).get("flags", ())
        return "UP" in flags and "LOWER_UP" in flags

    def _route_ready(self, family, target):
        return self._ip_info(f"-{family}", "route", "get", target).get("dev") == DEVICE

    def _prepare_dns(self):
        (self.directory / "resolv.conf").write_text(f"nameserver {DNS_ADDRESS}\noptions timeout:3 attempts:2\n")
        nss = Path("/etc/nsswitch.conf")
        if nss.is_file():
            config = nss.read_text(errors="replace")
            config = re.sub(r"(?m)^[ \t]*hosts[ \t]*:.*$", "", config)
        else:
            config = ""
        (self.directory / "nsswitch.conf").write_text(config + "\nhosts: files dns\n")

    def command(self, args, *, flatpak=False):
        user_ns = [
            *self._enter(), self.tools["bwrap"], "--unshare-user", "--unshare-pid",
            "--die-with-parent", "--bind", "/", "/", "--dev-bind", "/dev", "/dev", "--proc", "/proc",
        ]
        system_services = ("/run/systemd/resolve", "/run/nscd", "/var/run/nscd", "/run/dbus")
        for directory in dict.fromkeys(Path(path).resolve() for path in system_services):
            if directory.is_dir():
                user_ns.extend(("--tmpfs", str(directory)))
        if flatpak:
            user_ns.extend(("--unsetenv", "DBUS_SYSTEM_BUS_ADDRESS"))
        else:
            user_ns.extend(("--setenv", "DBUS_SYSTEM_BUS_ADDRESS", "unix:path=/run/tundock-system-bus-disabled"))
        user_ns.extend(("--ro-bind", str(self.directory / "resolv.conf"), str(Path("/etc/resolv.conf").resolve())))
        nss = Path("/etc/nsswitch.conf")
        if nss.exists():
            user_ns.extend(("--ro-bind", str(self.directory / "nsswitch.conf"), str(nss.resolve())))
        if not self.options.desktop_services:
            if flatpak:
                user_ns.extend(("--unsetenv", "DBUS_SESSION_BUS_ADDRESS"))
            else:
                user_ns.extend(("--setenv", "DBUS_SESSION_BUS_ADDRESS", "unix:path=/run/tundock-session-bus-disabled"))
            runtime = os.environ.get("XDG_RUNTIME_DIR")
            if runtime:
                bus = Path(runtime) / "bus"
                if bus.is_socket():
                    user_ns.extend(("--ro-bind", "/dev/null", str(bus)))
        return [*user_ns, "--", *args]

    def environment(self):
        return {
            key: value for key, value in os.environ.items()
            if key.lower() not in {"all_proxy", "http_proxy", "https_proxy", "no_proxy", "ftp_proxy"}
            and key not in {"RES_OPTIONS", "LOCALDOMAIN", "HOSTALIASES",
                            "VPNDOCK_EXPORT_SOCKET", "VPNDOCK_EXPORT_PORT"}
        }

    def run(self, args, *, cwd=None, timeout=10, stop=None):
        return run_process(
            self.command(args), cwd=cwd or Path.home(), env=self.environment(), pass_fds=self.ns_fds,
            timeout=timeout, stop=stop,
        )

    def launch(self, args, cwd, *, interactive=False, stop=None):
        require_active(stop)
        if problem := delegation(args):
            raise TunnelError(problem)
        if self.app is not None:
            raise TunnelError("This private session has already launched a program.")
        flatpak = flatpak_target(args)
        if flatpak:
            executable, app_id, app_index = flatpak
            if running_flatpak(executable, app_id):
                raise TunnelError(f"{app_id} is already running. Close its other windows and retry.")
            args, direct = private_flatpak_args(args, app_id, app_index)
            if direct:
                self._emit("Network", "Starting the Flatpak executable directly instead of sending a D-Bus launch request.")
            self._emit("Network", f"Flatpak {app_id} will inherit this session's private network.")
        elif self.export is None and (other := already_running(args, cwd=cwd)):
            raise TunnelError(f"This program is already running (PID {other}). Close its other windows and retry. "
                              "An existing process keeps its original network.")
        require_active(stop)
        marker = self.directory / "app.started"
        expected = f"net:[{os.fstat(self.ns_fds[1]).st_ino}]"
        args = [sys.executable, str(ROOT / "app_runner.py"), str(marker), expected, *args]
        capture = not interactive and self.output is not None
        environment = self.environment()
        if self.export:
            environment.update(self.export.environment)
        if capture:
            environment.setdefault("PYTHONUNBUFFERED", "1")
        self.app = subprocess.Popen(
            self.command(args, flatpak=bool(flatpak)), cwd=cwd, env=environment, pass_fds=self.ns_fds,
            start_new_session=True, stdout=subprocess.PIPE if capture else (None if interactive else subprocess.DEVNULL),
            stderr=None if interactive else subprocess.PIPE,
            stdin=None if interactive else subprocess.DEVNULL,
        )
        if capture:
            self._drain(self.app.stdout, "App")
        error_reader = self._drain(self.app.stderr, "App stderr", self._app_tail) if not interactive else None
        deadline = time.monotonic() + 6
        while time.monotonic() < deadline:
            require_active(stop)
            status = self.app.poll()
            if marker.exists():
                if marker.read_text() != expected:
                    raise TunnelError("The program did not enter the expected private network.")
                self._emit("Network", f"Program execution verified inside the private namespace ({expected}).")
                return
            if status is not None:
                if error_reader:
                    error_reader.join(0.3)
                detail = self._app_tail[-1] if self._app_tail else f"Exit status {status}."
                raise TunnelError(f"The program did not start in the private network. {detail}")
            time.sleep(0.025)
        raise TunnelError("The program did not confirm startup inside the private network in time.")

    def check_exit(self, stop=None):
        with self._exit_check_lock:
            if self.app is None or self.app.poll() is not None or self.engine.poll() is not None:
                raise TunnelError("The isolated session is no longer running.")
            response = self.run(
                [sys.executable, "-m", "tundock.probe", "--exit-ip"], cwd=ROOT.parent, timeout=9, stop=stop,
            )
            if response.returncode:
                raise TunnelError("No verified HTTPS response from the exit-IP service.")
            address = json.loads(response.stdout)
            if not address.get("ip"):
                raise TunnelError("The exit-IP service did not return an address.")
            ipaddress.ip_address(address["ip"])
            return address

    def follow(self, stop):
        while self.app.poll() is None:
            require_active(stop)
            if self.engine.poll() is not None:
                raise TunnelError("The proxy engine stopped. The isolated session was closed.")
            time.sleep(0.2)
        return self.app.returncode


def socks_udp_associate(proxy):
    if proxy.scheme != "socks5":
        return Result("Unavailable", "HTTP CONNECT carries TCP.")
    try:
        with socket.create_connection((proxy.host, proxy.port), timeout=3) as sock, sock.makefile("rb") as reply:
            auth = 2 if proxy.username else 0
            sock.sendall(bytes((5, 1, auth)))
            if reply.read(2) != bytes((5, auth)):
                return Result("Unverified", "The SOCKS5 authentication method was declined.")
            if auth:
                user, password = proxy.username.encode(), proxy.password.encode()
                sock.sendall(bytes((1, len(user))) + user + bytes((len(password),)) + password)
                if reply.read(2) != b"\x01\x00":
                    return Result("Unverified", "SOCKS5 authentication failed.")
            sock.sendall(b"\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00")
            response = reply.read(4)
            if len(response) != 4 or response[0] != 5:
                return Result("Unverified", "The proxy did not return a UDP status.")
            if response[1] == 7:
                return Result("Unavailable", "SOCKS5 UDP ASSOCIATE is unsupported (reply 07).")
            if response[1]:
                return Result("Unverified", f"SOCKS5 UDP ASSOCIATE was declined (reply {response[1]:02X}).")
            return Result("Accepted", "The proxy accepted SOCKS5 UDP ASSOCIATE.")
    except OSError:
        return Result("Unverified", "The SOCKS5 server did not complete the UDP negotiation.")
