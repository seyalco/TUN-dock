import struct
import sys
import threading
import time
import unittest
from unittest.mock import patch

from tundock.core import run_process
from tundock.probe import dns


class DiagnosticsTests(unittest.TestCase):
    def reply_to_query(self, *, bad_transaction=False):
        with patch("tundock.probe.socket.socket") as socket_factory:
            conn = socket_factory.return_value.__enter__.return_value

            def reply(_):
                payload = conn.send.call_args.args[0]
                transaction = int.from_bytes(payload[:2], "big") ^ int(bad_transaction)
                answer = b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x01\x00\x04\x01\x01\x01\x01"
                return struct.pack("!6H", transaction, 0x8180, 1, 1, 0, 0) + payload[12:] + answer

            conn.recv.side_effect = reply
            if bad_transaction:
                with self.assertRaisesRegex(OSError, "invalid DNS response"):
                    dns(timeout=1)
            else:
                self.assertEqual(dns(timeout=1), "")
            conn.connect.assert_called_once_with(("172.30.88.2", 53))
            self.assertTrue(conn.send.call_args.args[0][12:].startswith(b"\x03one"))

    def test_dns_sends_wire_query(self):
        self.reply_to_query()

    def test_dns_rejects_wrong_transaction(self):
        self.reply_to_query(bad_transaction=True)

    def test_cancelling_a_diagnostic_terminates_the_subprocess(self):
        stop = threading.Event()
        timer = threading.Timer(0.15, stop.set)
        timer.start()
        started = time.monotonic()
        try:
            with self.assertRaises(InterruptedError):
                run_process([sys.executable, "-c", "import time; time.sleep(20)"], timeout=5, stop=stop)
        finally:
            timer.cancel()
        self.assertLess(time.monotonic() - started, 3)


if __name__ == "__main__":
    unittest.main()
