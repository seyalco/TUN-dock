"""Network engine and lifecycle. No GTK dependencies."""

from collections import deque
from contextlib import ExitStack
from dataclasses import dataclass, field
from http.client import HTTPConnection, HTTPException
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
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

from .capture import capture_lines
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


class SingBoxUnavailable(TunnelError):
    """The configured or default sing-box executable was not found."""


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


def sing_box_path():
    instructions = ("Install sing-box 1.14 or newer with Clash API support. Place the binary at "
                    "~/.local/bin/sing-box and mark it executable, or install a compatible system package.")
    preferred = os.environ.get("TUNDOCK_SING_BOX")
    if preferred:
        path = shutil.which(os.path.expanduser(preferred))
        if path and Path(path).is_file():
            return str(Path(path).absolute())
        raise SingBoxUnavailable("TUNDOCK_SING_BOX does not select an executable. Fix it or unset it.\n\n"
                                 + instructions)

    home = Path.home()
    data_home = Path(os.environ.get("XDG_DATA_HOME", ""))
    if not data_home.is_absolute():
        data_home = home / ".local/share"
    launcher_directory = Path(os.environ.get("TUNDOCK_LAUNCHER_DIR", ""))
    roots = [ROOT.parent]
    if launcher_directory.is_absolute():
        roots.insert(0, launcher_directory)
    candidates = [root / name for root in roots for name in ("bin/sing-box", "sing-box")]
    candidates.extend((data_home / "tundock/bin/sing-box", home / ".local/bin/sing-box"))
    for candidate in candidates:
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return str(candidate)
    path = shutil.which("sing-box")
    if path and Path(path).is_file():
        return str(Path(path).absolute())
    raise SingBoxUnavailable(instructions)


def dependency_paths():
    if sys.platform != "linux" or os.geteuid() == 0:
        raise TunnelError("Run Tundock on Linux as a regular user.")
    candidates = {name: shutil.which(name) for name in ("bwrap", "nsenter", "ip")}
    candidates["sing-box"] = sing_box_path()
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
    if proxy is None:
        return options.udp != "Block", options.ipv6 != "Block"
    udp = proxy.scheme == "socks5" and (
        options.udp == "Allow" or (options.udp == "Automatic" and report.udp.verified)
    )
    ipv6 = options.ipv6 == "Allow" or (options.ipv6 == "Automatic" and report.ipv6.verified)
    return udp, ipv6


def engine_config(proxy, options, holder, udp, ipv6, *, log_level="fatal", device=DEVICE,
                  controller=None, initial_direct=False, namespace_path=None):
    resolver_ip, resolver_name = RESOLVERS[options.resolver]
    outbounds = []
    if proxy:
        outbound = {"type": "socks" if proxy.scheme == "socks5" else "http", "tag": "upstream",
                    "server": proxy.host, "server_port": proxy.port}
        if proxy.username:
            outbound.update(username=proxy.username, password=proxy.password)
        if proxy.scheme == "socks5":
            outbound["version"] = "5"
            if not udp:
                outbound["network"] = "tcp"
        if proxy.scheme == "https":
            outbound["tls"] = {"enabled": True, "server_name": proxy.host}
        outbounds.append(outbound)
    if proxy is None or controller:
        outbounds.append({"type": "direct", "tag": "direct"})
    egress = "upstream" if proxy else "direct"
    if controller:
        egress = "egress"
        outbounds.append({"type": "selector", "tag": egress, "outbounds": ["upstream", "direct"],
                          "default": "direct" if initial_direct else "upstream",
                          "interrupt_exist_connections": False})
    addresses = ["172.30.88.1/30"]
    if ipv6:
        addresses.append("fd2d:7140:88::1/126")
    dns = {
        "servers": [{
            "type": "https",
            "tag": "doh",
            "server": resolver_ip,
            "tls": {"server_name": resolver_name},
        }],
        "final": "doh",
    }
    if proxy:
        dns["servers"][0]["detour"] = egress
    if not ipv6:
        dns["strategy"] = "ipv4_only"
    rules = [{"port": 53, "action": "hijack-dns"}]
    if options.udp == "Block" or (not controller and not udp):
        rules.append({"network": "udp", "action": "reject"})
    config = {
        "log": {"level": log_level, "disabled": False},
        "network_namespaces": [
            {"type": "default", "tag": "app", "path": namespace_path} if namespace_path else
            {"type": "unshare", "tag": "app", "pid_file": str(holder)},
        ],
        "dns": dns,
        "inbounds": [{
            "type": "tun",
            "netns": "app",
            "interface_name": device,
            "address": addresses,
            "mtu": 1400,
            "auto_route": True,
            "strict_route": True,
            "dns_mode": "disabled",
        }],
        "outbounds": outbounds,
        "route": {"rules": rules, "final": egress},
    }
    if controller:
        address, secret = controller
        config["experimental"] = {"clash_api": {"external_controller": address, "secret": secret}}
    return config


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


def engine_version(tools, stop=None, *, selector=False):
    check = run_process([tools["sing-box"], "version"], timeout=4, stop=stop)
    match = re.search(r"sing-box version (\d+\.\d+)([^\s]*)", check.stdout)
    if check.returncode or not match or tuple(map(int, match[1].split("."))) < (1, 14):
        raise TunnelError("Install sing-box 1.14 or newer for rootless per-app networking.")
    if selector and not re.search(r"(?m)^Tags:.*\bwith_clash_api\b", check.stdout):
        raise TunnelError("Use a sing-box build with Clash API support for live route switching.")
    return match[1] + match[2]


class Tunnel:
    """A private network namespace held open by a host-side sing-box process."""

    def __init__(self, proxy, options, *, udp, ipv6, output=None, capture_enabled=None, export=None,
                 switchable=False, initial_direct=False):
        self.proxy, self.options = proxy, options
        self.udp, self.ipv6 = udp, ipv6
        self.files = ExitStack()
        self.directory = None
        self.engine = None
        self._network_ready = False
        self.app = None
        self.ns_fds = ()
        self.export = export
        self.output = output
        self.capture_enabled = capture_enabled
        self.direct = proxy is None or initial_direct
        self.switchable = switchable
        self.device = "td" + secrets.token_hex(5)
        self._control = None
        self._closing = threading.Event()
        self._lifecycle_lock = threading.Lock()
        self._apps = set()
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
        credentials = (self.proxy.username, self.proxy.password) if self.proxy else ()
        for secret in credentials:
            if not secret:
                continue
            for value in {secret, quote(secret, safe="")}:
                if len(value) >= 3:
                    line = line.replace(value, "[redacted]")
                else:
                    line = re.sub(r"(?<!\w)" + re.escape(value) + r"(?!\w)", "[redacted]", line)
        return line

    def _drain(self, pipe, source, tail=None, *, output=None, capture_enabled=None):
        allowed = capture_enabled if capture_enabled is not None else self._capture_allowed
        output = output if output is not None else self.output

        def read():
            with pipe:
                for data in capture_lines(pipe, allowed):
                    if not allowed():
                        continue
                    line = self._safe_line(data)
                    if line and allowed():
                        if tail is not None:
                            tail.append(line)
                        if output is not None and allowed():
                            output(source, line)

        reader = threading.Thread(target=read, name=f"tundock-{source.lower()}-output", daemon=True)
        reader.start()
        self._readers.append(reader)
        return reader

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self._closing.set()
        with self._lifecycle_lock:
            apps = tuple(self._apps)
            self._apps.clear()
            try:
                self._stop_network()
            finally:
                for process in apps:
                    stop_process(process)
                for reader in self._readers:
                    reader.join(0.2)
                self._release_if_idle()

    def configure(self, proxy, options, *, udp, ipv6, initial_direct=False, output=None, capture_enabled=None):
        with self._lifecycle_lock:
            if self.engine is not None:
                raise TunnelError("Stop the session before changing the upstream configuration.")
            self.proxy, self.options = proxy, options
            self.udp, self.ipv6 = udp, ipv6
            self.direct = proxy is None or initial_direct
            if output is not None:
                self.output = output
            if capture_enabled is not None:
                self.capture_enabled = capture_enabled

    def _release_if_idle(self):
        if self.engine is not None:
            return
        self._apps = {process for process in self._apps if process.poll() is None}
        if not self._apps:
            with self._exit_check_lock:
                self.files.close()
                self.ns_fds = ()
                self.directory = None

    def _stop_network(self):
        self._network_ready = False
        stop_process(self.engine)
        self.engine = None
        self._control = None

    def stop_network(self):
        """Stop egress while leaving the programs and their private loopback alive."""
        with self._lifecycle_lock:
            self._stop_network()
            self._release_if_idle()

    def start(self, stop=None):
        with self._lifecycle_lock:
            require_active(self._closing)
            if self.engine is not None:
                raise TunnelError("The isolated network is already started.")
            try:
                self._start_network(stop)
            except BaseException:
                self._stop_network()
                self._release_if_idle()
                raise

    def _start_network(self, stop):
        if self.export and self.proxy and self.export.feeds(self.proxy):
            raise TunnelError("Stage A cannot use the host endpoint that its VPN Dock session exports.")
        self.tools = dependency_paths()
        version = engine_version(self.tools, stop, selector=bool(self.switchable and self.proxy))
        self._emit("Network", f"Preparing private TUN with sing-box {version}.")
        if self.directory is None:
            self.directory = Path(self.files.enter_context(tempfile.TemporaryDirectory(prefix="tundock-")))
            self._prepare_dns()
        holder = self.directory / "namespace.pid"
        namespace_path = f"/proc/self/fd/{self.ns_fds[1]}" if self.ns_fds else None
        if self.switchable and self.proxy:
            with socket.socket() as reserved:
                reserved.bind(("127.0.0.1", 0))
                self._control = (reserved.getsockname()[1], secrets.token_urlsafe(32))
        controller = (f"127.0.0.1:{self._control[0]}", self._control[1]) if self._control else None
        config = engine_config(self.proxy, self.options, holder, self.udp, self.ipv6,
                               log_level="info" if self.output else "fatal", device=self.device,
                               controller=controller, initial_direct=self.direct, namespace_path=namespace_path)
        # sing-box can reopen its configuration. A RAM-backed file supports repeated reads.
        fd = os.memfd_create("tundock-config", os.MFD_CLOEXEC)
        with os.fdopen(fd, "wb") as memory:
            memory.write(json.dumps(config).encode())
            memory.flush()
            private_user = ["--userns", str(self.ns_fds[0])] if self.ns_fds else []
            self.engine = subprocess.Popen(
                [sys.executable, str(ROOT / "guard.py"), str(os.getpid()), *private_user, self.tools["sing-box"],
                 "run", "-c", f"/proc/self/fd/{fd}"],
                cwd=self.directory, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                start_new_session=True, pass_fds=(fd, *self.ns_fds),
            )
        self._engine_tail.clear()
        self._readers = [reader for reader in self._readers if reader.is_alive()]
        engine_reader = self._drain(self.engine.stdout, "Proxy", self._engine_tail)
        deadline = time.monotonic() + 8
        ipv4_ready = False
        while time.monotonic() < deadline:
            require_active(stop)
            require_active(self._closing)
            if self.engine.poll() is not None:
                engine_reader.join(0.3)
                detail = self._engine_tail[-1] if self._engine_tail and self._capture_allowed() else ""
                raise TunnelError(detail or "sing-box stopped before the tunnel was ready.")
            if not self.ns_fds:
                self._open_namespaces(holder)
            ipv4_ready = self.ns_fds and self._link_ready() and self._route_ready("4", "1.1.1.1")
            if ipv4_ready and (not self.ipv6 or self._route_ready("6", "2606:4700:4700::1111")):
                require_active(stop)
                if self._control and not self._selection_ready():
                    if stop is not None:
                        stop.wait(0.05)
                    else:
                        time.sleep(0.05)
                    continue
                self._network_ready = True
                route = "Direct" if self.direct else self.proxy.address
                self._emit("Network", f"Private TUN {self.device} is ready · {route}.")
                self._emit("Network", f"DNS through {self.options.resolver} DoH.")
                return
            if stop is None:
                time.sleep(0.05)
            else:
                stop.wait(0.05)
        if self.ipv6 and ipv4_ready:
            raise IPv6RouteUnavailable("The private TUN could not establish an IPv6 route.")
        raise TunnelError("TUN did not become ready. Check unprivileged user namespaces and /dev/net/tun.")

    def _selector_request(self, method, selection=None):
        port, token = self._control
        request = HTTPConnection("127.0.0.1", port, timeout=0.6)
        body = json.dumps({"name": selection}) if selection else None
        try:
            request.request(method, "/proxies/egress", body,
                            {"Authorization": f"Bearer {token}", "Content-Type": "application/json"})
            response = request.getresponse()
            data = response.read(4096)
            if method == "PUT":
                return response.status == 204
            return json.loads(data).get("now") if response.status == 200 else None
        except (OSError, HTTPException, ValueError):
            return None
        finally:
            request.close()

    def _selection_ready(self):
        return self._selector_request("GET") == ("direct" if self.direct else "upstream")

    def set_direct(self, direct):
        with self._lifecycle_lock:
            self._require_running()
            if not self._control:
                if direct == self.direct:
                    return
                raise TunnelError("Start a new session with an upstream proxy to switch routes.")
            desired = "direct" if direct else "upstream"
            if (self._selector_request("GET") != desired and not self._selector_request("PUT", desired)
                    and self._selector_request("GET") != desired):
                raise TunnelError("The route switch could not be confirmed.")
            self.direct = direct
            self._emit("Network", "New connections use direct access." if direct else "New connections use the upstream proxy.")

    def _require_running(self):
        if self._closing.is_set() or not self._network_ready or self.engine is None or self.engine.poll() is not None:
            raise TunnelError("The isolated session is no longer running.")

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
        flags = self._ip_info("link", "show", "dev", self.device).get("flags", ())
        return "UP" in flags and "LOWER_UP" in flags

    def _route_ready(self, family, target):
        return self._ip_info(f"-{family}", "route", "get", target).get("dev") == self.device

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
            "--uid", str(os.getuid()), "--gid", str(os.getgid()), "--cap-drop", "ALL",
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
                            "VPNDOCK_EXPORT_SOCKET", "VPNDOCK_EXPORT_PORT", "WAYLAND_SOCKET"}
        }

    def run(self, args, *, cwd=None, timeout=10, stop=None):
        return run_process(
            self.command(args), cwd=cwd or Path.home(), env=self.environment(), pass_fds=self.ns_fds,
            timeout=timeout, stop=stop,
        )

    def launch(self, args, cwd, *, interactive=False, stop=None):
        if self.app is not None:
            raise TunnelError("This private session has already launched a program.")
        self.app = self.spawn(args, cwd, interactive=interactive, stop=stop, export=self.export)

    def spawn(self, args, cwd, *, interactive=False, stop=None, output=None, capture_enabled=None, export=None):
        require_active(stop)
        if problem := delegation(args):
            raise TunnelError(problem)
        if export and self.proxy and export.feeds(self.proxy):
            raise TunnelError("The upstream proxy and the exported endpoint must use different ports.")
        output = output if output is not None else self._emit
        capture_enabled = capture_enabled if capture_enabled is not None else self._capture_allowed

        def note(message):
            if capture_enabled():
                output("Network", message)

        flatpak = flatpak_target(args)
        if flatpak:
            executable, app_id, app_index = flatpak
            if running_flatpak(executable, app_id):
                raise TunnelError(f"{app_id} is already running. Close its other windows and retry.")
            args, direct = private_flatpak_args(args, app_id, app_index)
            if direct:
                note("Starting the Flatpak executable inside the private network.")
            note(f"Flatpak {app_id} will inherit this session's private network.")
        elif export is None and (other := already_running(args, cwd=cwd)):
            raise TunnelError(f"This program is already running (PID {other}). Close its other windows and retry. "
                              "An existing process keeps its original network.")
        require_active(stop)
        with self._lifecycle_lock:
            self._require_running()
            marker = self.directory / f"app-{secrets.token_hex(8)}.started"
            expected = f"net:[{os.fstat(self.ns_fds[1]).st_ino}]"
            args = [sys.executable, str(ROOT / "app_runner.py"), str(marker), expected, *args]
            environment = self.environment()
            if export:
                environment.update(export.environment)
            if not interactive:
                environment.setdefault("PYTHONUNBUFFERED", "1")
            process = subprocess.Popen(
                self.command(args, flatpak=bool(flatpak)), cwd=cwd, env=environment, pass_fds=self.ns_fds,
                start_new_session=True, stdout=None if interactive else subprocess.PIPE,
                stderr=None if interactive else subprocess.PIPE,
                stdin=None if interactive else subprocess.DEVNULL,
            )
            self._apps.add(process)
            tail = deque(maxlen=1)
            if not interactive:
                self._readers = [reader for reader in self._readers if reader.is_alive()]
                self._drain(process.stdout, "App", output=output, capture_enabled=capture_enabled)
                error_reader = self._drain(process.stderr, "App stderr", tail,
                                           output=output, capture_enabled=capture_enabled)
        try:
            deadline = time.monotonic() + 6
            while time.monotonic() < deadline:
                require_active(stop)
                require_active(self._closing)
                if marker.exists():
                    if marker.read_text() != expected:
                        raise TunnelError("The program did not enter the expected private network.")
                    note(f"Program execution verified inside the private namespace ({expected}).")
                    return process
                if (status := process.poll()) is not None:
                    if not interactive:
                        error_reader.join(0.3)
                    detail = tail[-1] if tail and capture_enabled() else f"Exit status {status}."
                    raise TunnelError(f"The program did not start in the private network. {detail}")
                self._closing.wait(0.025)
            raise TunnelError("The program did not confirm startup inside the private network in time.")
        except BaseException:
            self.stop_app(process)
            raise
        finally:
            marker.unlink(missing_ok=True)

    def stop_app(self, process):
        with self._lifecycle_lock:
            if process not in self._apps:
                return
            stop_process(process)
            self._apps.remove(process)
            self._release_if_idle()

    def check_exit(self, stop=None, *, process=None):
        with self._exit_check_lock:
            self._require_running()
            if process is not None and process.poll() is not None:
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
            if self.engine is None or self.engine.poll() is not None:
                raise TunnelError("The proxy engine stopped. The isolated network is offline.")
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
