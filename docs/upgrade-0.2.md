# Tundock 0.2 release brief

## Baseline audit

- The previous release required extracting source and running a shell installer. It also relied on discovering a compatible sing-box binary on each user's machine.
- Closing a window could end the UI before its background workers cleaned up child processes. A connection test occupied the window until I/O timed out.
- Protocol badges described sampled connectivity, while the launch policy also depended on Automatic, Allow or Block. This made it easy to confuse a failed test with a hard policy decision.
- The route check validated a lookup against a device name. Explicitly verify the TUN link and route together, and handle process exits and bounded waits cleanly.
- The per-app design still depends on Linux kernel support and desktop packages. Distribution must identify these requirements and the architectures actually tested.

## Implementation prompt

> Ship Tundock 0.2 as one directly executable Linux x86-64 file that opens the desktop UI without installing the application, requiring root, mounting FUSE or downloading anything at launch. Bundle a verified engine alongside the UI payload and document the remaining host dependencies and component licensing. Keep the current per-app namespace architecture. Make diagnostics cancellable, show the distinction between tested connectivity and effective launch policy, and wait for sessions to clean up when closing. Keep proxy credentials off disk. Verify the payload and test launch from a different working directory, concurrent isolated sessions, IPv4/IPv6 loopback, DNS detour, SOCKS5 TCP and UDP, HTTP CONNECT, and failure without direct fallback. Package a checksum and a reproducible build recipe. Record known restrictions and results. Treat public publication as a separate delivery step.

## Acceptance

- The release file identifies as Linux ELF and opens on Fedora KDE from outside the project without using the installed Tundock launcher.
- The packaged version supplies its engine. No modified Bash configuration or persistent system routing is needed to start it.
- A stopped diagnostic or application session releases its private network and owned processes.
- A missing or failed dependency, failed probe, or protocol rejected by policy has a distinct user-visible description.
- Run and document both isolated local fixtures and an external test with the user's existing SOCKS5 proxy.
