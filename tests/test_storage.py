from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase
from unittest.mock import patch

from tundock import storage
from tundock.core import Options


class StorageTests(TestCase):
    def test_proxy_bookmarks_are_independent_of_presets_and_omit_credentials(self):
        with TemporaryDirectory() as temporary, patch.object(storage, "DIRECTORY", Path(temporary)):
            preset = storage.Preset("Browser", "socks5://127.0.0.1:8083", "firefox", "", Options())
            storage.save([preset])
            self.assertEqual(storage.load_bookmarks(), [])

            local = storage.ProxyBookmark("Local", "socks5://sample-user:sample-password@127.0.0.1:8083")
            office = storage.ProxyBookmark("Office", "http://proxy.example.org:3128")
            storage.save_bookmarks([local, office])

            saved = (Path(temporary) / "proxies.json").read_text()
            self.assertNotIn("sample-user", saved)
            self.assertNotIn("sample-password", saved)
            self.assertEqual(storage.load_bookmarks(), [local, office])
            self.assertEqual(storage.load(), [preset])

            storage.save_bookmarks([office])
            self.assertEqual(storage.load_bookmarks(), [office])
            self.assertEqual(storage.load(), [preset])
