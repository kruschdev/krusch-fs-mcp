import unittest
from krusch_fs.fleet import classify_privacy, should_ignore_path


class TestFleetValidation(unittest.TestCase):
    def test_should_ignore_path_guards_invalid_inputs(self):
        # SEC-01: should_ignore_path rejects None and empty strings
        with self.assertRaises(ValueError):
            should_ignore_path(None)
        with self.assertRaises(ValueError):
            should_ignore_path("")
        with self.assertRaises(ValueError):
            should_ignore_path("   ")
        self.assertFalse(should_ignore_path("/home/alice/Documents/notes.md"))

    def test_classify_privacy_guards_invalid_inputs(self):
        # SEC-02: classify_privacy rejects non-string fpath and non-numeric size_b
        with self.assertRaises(ValueError):
            classify_privacy(None, 100)
        with self.assertRaises(ValueError):
            classify_privacy("", 100)
        with self.assertRaises(ValueError):
            classify_privacy("/tmp/test.md", "not-a-number")
        with self.assertRaises(ValueError):
            classify_privacy("/tmp/test.md", -5)
        self.assertEqual(classify_privacy("/tmp/test.md", 128), "standard")

    def test_classify_privacy_single_typed_definition(self):
        # BUG-01 & TYPE-01: Single canonical typed classify_privacy in fleet.py
        import inspect
        import krusch_fs.fleet as fleet_mod

        sig = inspect.signature(classify_privacy)
        self.assertEqual(sig.parameters["fpath"].annotation, str)
        self.assertEqual(sig.parameters["size_b"].annotation, int)
        self.assertEqual(sig.return_annotation, str)

        src = inspect.getsource(fleet_mod)
        self.assertEqual(src.count("def classify_privacy("), 1)
        self.assertIn("def classify_privacy(fpath: str, size_b: int) -> str:", fleet_mod.REMOTE_SCANNER_SCRIPT_TEMPLATE)

    def test_get_host_node_and_memory_to_item_validate_node_and_log_bbox_errors(self):
        # Pass #6 SEC-01, BUG-01, ARCH-01
        import argparse
        import os
        from types import SimpleNamespace
        from unittest.mock import patch
        from krusch_fs.config import get_host_node
        from krusch_fs.client import KruschFSClient

        with patch.dict(os.environ, {"KRUSCH_FS_NODE": "bad;node"}, clear=False):
            with self.assertRaises(argparse.ArgumentTypeError):
                get_host_node(None)

        with patch.dict(os.environ, {"KRUSCH_FS_NODE": ""}, clear=False):
            with self.assertRaises(argparse.ArgumentTypeError):
                get_host_node(None)

        with patch.dict(os.environ, {"KRUSCH_FS_NODE": "kruschdev"}, clear=False):
            self.assertEqual(get_host_node(None), "kruschdev")

        fake_mem = SimpleNamespace(
            id=1,
            host_node="krusch",
            file_id=1,
            workspace="homelab_code",
            page_number=1,
            printed_page="1",
            category="annotation",
            memory_key="k1",
            memory_content="content",
            quoted_sentence="quote",
            citation="cit",
            locator="Page 1",
            bbox="{invalid-json",
            char_start=0,
            char_end=5,
            anchor_page_hash="abc",
            is_drifted=False,
            created_at=None,
        )
        with self.assertLogs("krusch_fs.client", level="ERROR") as log_ctx:
            item = KruschFSClient._memory_to_item(fake_mem, "/tmp/test.md")
        self.assertIsNone(item.bbox)
        self.assertTrue(any("BBox deserialization failed" in m for m in log_ctx.output))


if __name__ == "__main__":
    unittest.main()


