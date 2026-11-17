from dataclasses import replace
import unittest

from tundock.core import Options, Proxy, Report, Result, Tunnel, TunnelError, engine_config, network_modes
from tundock.launchcheck import delegation, flatpak_target, private_flatpak_args


class ProxyTests(unittest.TestCase):
    def test_parsing_and_redaction(self):
        proxy = Proxy.parse("socks5h://a%40b:p%3Ass@[::1]:1080")
        self.assertEqual(proxy.address, "socks5://[::1]:1080")
        self.assertEqual((proxy.username, proxy.password), ("a@b", "p:ss"))
        self.assertNotIn(proxy.password, repr(proxy))
        self.assertEqual(Proxy.parse("127.0.0.1:8083").scheme, "socks5")

    def test_incomplete_and_unsupported_settings(self):
        for value in ("localhost", "ftp://localhost:80", "socks5://localhost:0",
                      "http://localhost:8080/path", "socks5://:pwd@localhost:1080"):
            with self.subTest(value=value), self.assertRaises(TunnelError):
                Proxy.parse(value)

    def test_network_policies_default_to_block_until_verified(self):
        proxy = Proxy.parse("127.0.0.1:1080")
        self.assertEqual(network_modes(proxy, Options(), Report()), (False, False))
        verified = replace(Report(), udp=Result("Verified"), ipv6=Result("Verified"))
        self.assertEqual(network_modes(proxy, Options(), verified), (True, True))
        self.assertEqual(network_modes(proxy, Options(udp="Block"), verified), (False, True))
        http = Proxy.parse("https://example.org:443")
        self.assertEqual(network_modes(http, Options(udp="Allow", ipv6="Allow"), verified), (False, True))

    def test_private_default_and_explicit_dns_detour(self):
        for address in ("127.0.0.1:1080", "https://alice:q@example.org:443"):
            with self.subTest(address=address):
                proxy = Proxy.parse(address)
                config = engine_config(proxy, Options(), "/tmp/holder.pid", False, False)
                self.assertEqual(config["inbounds"][0]["netns"], "app")
                self.assertTrue(config["inbounds"][0]["auto_route"])
                self.assertEqual(config["outbounds"][0]["tag"], config["route"]["final"])
                self.assertEqual(config["dns"]["servers"][0]["detour"], config["route"]["final"])
                self.assertEqual(len(config["outbounds"]), 1)


class LaunchTests(unittest.TestCase):
    def test_host_delegation_is_signalled(self):
        self.assertIn("outside Tundock", delegation(["/usr/bin/env", "LANG=C", "/usr/bin/xdg-open", "/tmp/a"]))
        self.assertIn("outside Tundock", delegation(["/usr/bin/flatpak-spawn", "--host", "firefox"]))
        self.assertEqual(delegation(["/usr/bin/firefox"]), "")

    def test_standard_flatpak_command_preserves_application_args(self):
        args = ["/usr/bin/flatpak", "run", "--branch=stable", "--file-forwarding",
                "com.github.tchx84.Flatseal", "@@u", "@@"]
        self.assertEqual(flatpak_target(args), ("/usr/bin/flatpak", "com.github.tchx84.Flatseal", 4))
        self.assertIsNone(flatpak_target(["/usr/bin/dolphin"]))

    def test_flatpak_dbus_activation_uses_manifest_command(self):
        app_id = "io.frama.tractor.carburetor"
        args = ["/usr/bin/flatpak", "run", "--branch=stable", "--command=gapplication",
                app_id, "launch", app_id]
        self.assertEqual(private_flatpak_args(args, app_id, 4),
                         (["/usr/bin/flatpak", "run", "--branch=stable", "--share=network", app_id], True))
        direct = ["/usr/bin/flatpak", "run", "--command=rclone-shuttle", "io.github.pieterdd.RcloneShuttle"]
        self.assertEqual(private_flatpak_args(direct, direct[3], 3),
                         ([*direct[:3], "--share=network", direct[3]], False))

    def test_session_stream_hides_proxy_credentials_and_terminal_escapes(self):
        proxy = Proxy.parse("socks5://example-user:s%3Dsecret@127.0.0.1:8083")
        tunnel = Tunnel(proxy, Options(), udp=False, ipv6=False)
        message = tunnel._safe_line(b"\x1b[31mexample-user s=secret s%3Dsecret\x1b[0m\n")
        self.assertEqual(message, "[redacted] [redacted] [redacted]")


if __name__ == "__main__":
    unittest.main()
