# Tundock

Tundock is a native Linux desktop app for running a selected program and its children through a per-app TUN interface. It is built with GTK 4, libadwaita, Python, and sing-box.

## Run the portable executable

Open the executable for your architecture from your file manager or run it in a terminal. If the file manager removed the executable permission on download, mark it executable in Properties or use:

```sh
chmod +x Tundock-1.5.0-linux-x86_64
./Tundock-1.5.0-linux-x86_64
```

The release executable contains Tundock in one Linux ELF. Install [sing-box 1.14 or later](https://sing-box.sagernet.org/installation/) with Clash API support, or set `TUNDOCK_SING_BOX` to a compatible executable. Tundock keeps saved presets and proxy bookmarks in `${XDG_CONFIG_HOME:-$HOME/.config}/tundock`.

Enter a proxy and select **Test connection** to check connectivity and protocol support. Use **Installed apps**, **Browse**, or **Add to list** to prepare programs. **Start Session** creates a private namespace and TUN. The **Run** button on each row launches that item and its children into that network. **Stop Session** takes those programs offline and leaves their windows and processes running. Each program’s **Stop** button closes that program. Use **Save preset** to keep a program and its settings across restarts.

While the session is stopped, you can edit the proxy address and settings. **Start Session** reattaches the tunnel to the retained namespace so the apps can open fresh connections. Connections that were interrupted by Stop may need to reconnect. Tundock releases the namespace after the session is stopped and the last program exits.

When closing the main window with programs running, **Keep running** hides Tundock. Open it again from the same launcher to manage those programs. **Stop and quit** closes the programs and ends Tundock. Independent instances started with `--new-instance` can keep their own windows open for management.

### Switch to direct access

Turn off **Use upstream proxy** to send new connections directly through the host’s network while the session and its programs keep running. Turn it back on to use the configured proxy. Connections already open keep their original route until they close. DNS for new lookups follows the selected route. You can start in direct mode with an empty proxy field. Stop and start the session to apply a different upstream address or IPv6 policy.

Pass `--new-instance` to open an independent Tundock process with its own namespace and TUN interface.

### Use VPN Dock as an upstream

Start [VPN Dock](https://github.com/seyalco/VPN-dock) independently. Once it shows **Ready**, enter its SOCKS5 or HTTP CONNECT localhost address in Tundock’s proxy field and start the session.

### Run a terminal command

Select **Add Command** beside **Browse**. Enter a Bash command, including pipes or redirections if needed. Use **Run command** while the session is active, or add it to the list and use its play button later. Commands run noninteractively, with the chosen working folder and the session’s private TUN. Standard output and errors appear in **Sessions** when capture is on. Command text stays in the window unless you explicitly save it elsewhere.

### Save and reuse proxy addresses

Use **Save proxy** to name the current address. Open **Saved proxies** to select it for the next session or remove it with the delete button. Only the name and address are stored. Applying a bookmark clears proxy sign-in fields. **Save preset** remains available for storing a program together with its session settings.

### Inspect application output

Open the program’s log from its row or expand its entry under **Sessions**. Each drawer holds up to 500 lines in memory. Clear **Enable Logging** in the app menu to pause collection across all sessions. Tundock discards subprocess output while capture is off. Previously captured lines stay visible. Programs manage their own log files independently.

**Check exit IP** performs an HTTPS request to Cloudflare from that running session. This measures the session's tunnel egress. Use the same drawer's `Proxy` outbound lines to see connections going to the configured upstream. Programs with their own application-level proxy can still make an additional proxy hop.

Tundock detects an existing copy of common browsers and directly matched executables. To put an already open program in TUN, quit it and launch it via its play button. A running process and its existing sockets cannot be moved into this rootless network namespace from the outside. A program that reuses an existing copy through its own desktop services may exit quickly, which Tundock marks as a possible handoff. Launch the actual program executable rather than a desktop URL, terminal-only menu entry, or a command that hands execution back to the host. Standard Flatpak application entries inherit the session network. A standard self-activation entry that uses `gapplication launch` is started through the Flatpak’s default command inside the private session. Desktop portals may still be limited by the session's integration settings.

### Host requirements

Python 3.10+, GTK 4, libadwaita 1.2+, PyGObject, bubblewrap, util-linux (`nsenter`), iproute2 and an accessible `/dev/net/tun` are needed. Linux must allow unprivileged user namespaces. The Linux x86-64 portable build has been tested on Fedora 44 KDE.

On Fedora, the desktop and networking tools are provided by `python3-gobject gtk4 libadwaita bubblewrap util-linux iproute`. The executable's `--check-runtime` checks the host tools and the engine without opening a window. Use the in-app test to verify that the current account can create a working TUN.

From the extracted source package, run `./install.sh --use-portable /absolute/path/to/Tundock` to register the executable and its icon in your application menu. Keep the executable at a stable path. Tundock follows the desktop’s light or dark appearance setting.

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

- Each session uses a separate Linux network namespace with its own loopback and TUN. Programs enter it when launched through Tundock. Stopping or losing the engine leaves the programs running with private loopback access. Their external connections remain offline until the tunnel starts again. When upstream mode is selected, direct access requires an explicit switch.
- **Share desktop services** allows the program to use the desktop session bus for portals and sign-in. Some programs depend on those services. Work delegated to host applications and services runs outside the tunnel.
- Close any copy of a single-instance program before launching it. A program may otherwise hand the request to an existing host process, for example via its own Unix socket. Sandboxed packages, helper daemons and programs that require elevated privileges may need their own integration.
- Tundock is for running trusted applications with isolated IP routing. It shares your filesystem and display session with the program. It is not a security sandbox for software you don't trust.

## Develop and package

From a source checkout, `./run-tundock` opens the app. For source runs, install [sing-box 1.14 or later](https://sing-box.sagernet.org/installation/) with Clash API support or set `TUNDOCK_SING_BOX` to a compatible binary. Go and Python are used to build the portable executable.

```sh
/usr/bin/python3 -m unittest discover -s tests -p 'test_*.py'
TUNDOCK_SING_BOX=/path/to/sing-box /usr/bin/python3 tests/integration.py
./packaging/make-portable.sh /tmp/Tundock-1.5.0-linux-x86_64
./packaging/make-release.sh /tmp
```

The builder writes a companion SHA-256 file. The source archive includes the launcher source and desktop registration files.

The integration test uses local echo services and isolated proxies to exercise TCP, UDP, IPv6, loopback, HTTP CONNECT, engine loss, and reattaching running apps to a different upstream in the same namespace.

## License

Tundock is licensed under GPL-3.0-or-later. See [LICENSE](LICENSE) and the portable launcher’s [third-party notices](THIRD-PARTY-NOTICES).

## راهنمای سریع

فایل اجرایی را باز کن. با **Installed apps** یا **Browse** برنامه را به فهرست اضافه کن. ابتدا **Start Session** و سپس فلش اجرای همان برنامه را بزن. برای اتصال مستقیم، **Use upstream proxy** را خاموش کن. نشست و برنامه‌ها باز می‌مانند و اتصال‌های تازه از مسیر مستقیم برقرار می‌شوند. گزینهٔ **Share desktop services** در تنظیمات اتصال قرار دارد.
