import base64
import unittest
from vishare_quick.advertise import make_endpoint_info, make_instance_name, SERVICE_TYPE


class TestAdvertise(unittest.TestCase):
    def test_instance_name_shape(self):
        name, endpoint_id = make_instance_name()
        self.assertEqual(len(endpoint_id), 4)
        self.assertTrue(name.endswith(SERVICE_TYPE))
        payload = name.split(".", 1)[0]
        raw = base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4))
        self.assertEqual(len(raw), 10)
        self.assertEqual(raw[0], 0x23)
        self.assertEqual(raw[1:5].decode("ascii"), endpoint_id)
        self.assertEqual(raw[5:8], bytes.fromhex("FC9F5E"))
        self.assertEqual(raw[8:10], b"\x00\x00")

    def test_endpoint_info_includes_visible_name(self):
        raw = make_endpoint_info("ViShare Quick")
        self.assertEqual(len(raw[1:17]), 16)
        self.assertEqual(raw[17], len("ViShare Quick".encode("utf-8")))
        self.assertEqual(raw[18:].decode("utf-8"), "ViShare Quick")

    def test_endpoint_info_rejects_empty_name(self):
        with self.assertRaises(ValueError):
            make_endpoint_info("")


if __name__ == "__main__":
    unittest.main()
