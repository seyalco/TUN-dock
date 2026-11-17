from unittest import TestCase

from tundock.core import Options, Proxy, ProxyExport, Tunnel, TunnelError


class ProxyExportTests(TestCase):
    def test_stage_a_rejects_local_export_before_network_startup(self):
        export = ProxyExport(port=1089)
        for address in ("socks5://127.0.0.1:1089", "http://localhost:1089", "http://[::1]:1089",
                        "http://[::ffff:127.0.0.1]:1089", "http://alias.example:1089"):
            with self.subTest(address=address):
                proxy = Proxy.parse(address)
                with self.assertRaisesRegex(TunnelError, "Stage A"):
                    Tunnel(proxy, Options(), udp=False, ipv6=False, export=export).start()

    def test_unrelated_upstreams_remain_distinct(self):
        export = ProxyExport(port=1089)
        self.assertFalse(export.feeds(Proxy.parse("127.0.0.1:8083")))
        self.assertFalse(export.feeds(Proxy.parse("socks5://192.0.2.1:1089")))
        self.assertFalse(export.ready)
