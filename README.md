# Tundock

Tundock is a native Linux desktop app for running a selected program and its children through a per-app TUN interface. It is built with GTK 4, libadwaita, Python, and sing-box.

## Run the portable executable

Open the executable for your architecture from your file manager or run it in a terminal. If the file manager removed the executable permission on download, mark it executable in Properties or use:

```sh
chmod +x Tundock-0.3.0-linux-x86_64
./Tundock-0.3.0-linux-x86_64
```

The bundled-engine build contains Tundock and sing-box in one Linux ELF. It loads them into a private temporary directory and removes that directory when the app exits. It uses no application installer or FUSE. Tundock keeps saved presets and proxy bookmarks in `${XDG_CONFIG_HOME:-$HOME/.config}/tundock`.

Enter a proxy, select **Test connection**, choose a program, and select **Launch isolated**. The launch policy shows what Automatic, Allow or Block will do for the next session. Use **Stop** to close a session or **Save preset** to reuse its settings.

### Save and reuse proxy addresses

Use **Save proxy** to name the current address. Open **Saved proxies** to select it for the next session or remove it with the delete button. Only the name and address are stored. Applying a bookmark clears proxy sign-in fields. **Save preset** remains available for storing a program together with its session settings.

### See what happened after Launch

Open the arrow on the program's row under **Sessions**, or select **Latest log**. Each drawer shows the most recent 500 lines from Tundock, the proxy engine, and the program's standard output and errors. Tundock keeps them in memory for this window. The program can also keep its own logs independently. Standard output availability depends on what the program emits.

**Check exit IP** performs an HTTPS request to Cloudflare from that running session. This measures the session's tunnel egress. Use the same drawer's `Proxy` outbound lines to see connections going to the configured upstream. Programs with their own application-level proxy can still make an additional proxy hop.

Tundock detects an existing copy of common browsers and directly matched executables. Close the existing app before launching it with a different proxy. A program that reuses an existing copy through its own desktop services may exit quickly, which Tundock marks as a possible handoff. Launch the actual program executable rather than a desktop URL, terminal-only menu entry, or a command that hands execution back to the host. Standard Flatpak application entries inherit the session network. A standard self-activation entry that uses `gapplication launch` is started through the Flatpak’s default command inside the private session. Desktop portals may still be limited by the session's integration settings.

### Host requirements

Python 3.10+, GTK 4, libadwaita 1.2+, PyGObject, bubblewrap, util-linux (`nsenter`), iproute2 and an accessible `/dev/net/tun` are needed. Linux must allow unprivileged user namespaces. The Linux x86-64 portable build has been tested on Fedora 44 KDE.

On Fedora, the desktop and networking tools are provided by `python3-gobject gtk4 libadwaita bubblewrap util-linux iproute`. The executable's `--check-runtime` checks the host tools and the engine without opening a window. Use the in-app test to verify that the current account can create a working TUN.

For an existing Tundock-managed application-menu entry, `./install.sh --use-portable /absolute/path/to/Tundock` points it to the portable file and updates the icon. Keep that file at a stable path.

## Proxy addresses and capabilities

| Setting | Behavior |
| --- | --- |
| `socks5://127.0.0.1:8083` | SOCKS5. User and password authentication is optional. A bare `host:port` uses SOCKS5. |
| `http://host:port` or `https://host:port` | HTTP CONNECT. HTTPS verifies the proxy certificate. CONNECT carries TCP. |
| DNS | Port 53 requests are intercepted in the private namespace. Tundock sends DoH through the selected proxy to Cloudflare, Google, or Quad9. |
| UDP | Automatic uses UDP only after an end-to-end NTP response. A proxy may accept UDP but block the probe's destination or port. **Allow** can be used with a known SOCKS5 configuration. HTTP CONNECT always blocks UDP. |
| IPv6 | Automatic enables IPv6 only after an IPv6 HTTPS response through the tunnel. IPv6 loopback remains available in either mode. |
| Authentication | Proxy credentials can be entered under **Connection options**. Presets omit them. The engine receives its configuration in a RAM-backed file, so proxy credentials are kept off disk. |

The connection test sends HTTPS and, when supported, an NTP request to Cloudflare. The DNS check sends a wire query to the TUN resolver, which forwards it to your selected DoH provider. The tests show what was verified. Results can vary by destination, protocol, and proxy. The proxy endpoint hostname itself is resolved by the host as needed to establish the upstream connection. Use a literal IP for the upstream endpoint when that lookup matters.

## Isolation and compatibility

- Each launch gets a separate Linux network namespace with its own loopback and TUN. The engine creates routes only in that namespace. The only configured outbound is the proxy you supply. Losing the engine closes the session. Losing the upstream leaves no direct network route.
- **Share desktop services** allows the program to use the desktop session bus for portals and sign-in. Some programs depend on those services. Work delegated to host applications and services runs outside the tunnel.
- Close any copy of a single-instance program before launching it. A program may otherwise hand the request to an existing host process, for example via its own Unix socket. Sandboxed packages, helper daemons and programs that require elevated privileges may need their own integration.
- Tundock is for running trusted applications with isolated IP routing. It shares your filesystem and display session with the program. It is not a security sandbox for software you don't trust.

## Develop and package

From a source checkout, `./run-tundock` opens the app. For source runs, install [sing-box 1.14 or later](https://sing-box.sagernet.org/installation/) or set `TUNDOCK_SING_BOX` to an existing binary. Go and Python are needed to build a portable executable. No runtime toolchain is needed.

```sh
/usr/bin/python3 -m unittest discover -s tests -p 'test_*.py'
TUNDOCK_SING_BOX=/path/to/sing-box /usr/bin/python3 tests/integration.py
./packaging/make-portable.sh \
  --engine /path/to/sing-box \
  --engine-license /path/to/sing-box-notices.txt \
  --engine-source https://github.com/SagerNet/sing-box/tree/v1.14.4 \
  /tmp/Tundock-0.3.0-linux-x86_64
```

Use the exact license notices and source location for the binary you bundle. `--portable-notices` displays the bundled notice and source reference. The builder writes a companion SHA-256 file. `./packaging/make-release.sh /tmp` produces a source archive.

The integration test uses local echo services and an isolated proxy to exercise TCP, UDP, IPv6, loopback, HTTP CONNECT, and engine loss. See the [0.2 audit and release brief](docs/upgrade-0.2.md). The bundled executable is a local release candidate. Before public distribution, select Tundock's license and verify the corresponding-source arrangements for the bundled engine.

## راهنمای سریع

فایل اجرایی را باز کن. پراکسی خود را وارد کن و روی **Test connection** بزن. با **Installed apps** یا **Browse** برنامه را انتخاب کن و **Launch isolated** را بزن. هر اجرا شبکهٔ خصوصی خودش را دارد. اگر تست UDP یا IPv6 نتیجه ندهد، حالت خودکار آن پروتکل را برای اجرای بعدی مسدود می‌کند. در صورت نیاز به ورود از طریق مرورگر یا سرویس‌های دسکتاپ، گزینهٔ **Share desktop services** در تنظیمات اتصال قرار دارد.
