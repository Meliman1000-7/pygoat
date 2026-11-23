import io
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import yaml
from yaml_utils import parse_yaml


class SafeYamlLoadingTests(unittest.TestCase):
    def test_parses_benign_mapping(self):
        data = parse_yaml("name: pygoat\nversion: 1\nitems:\n  - a\n  - b\n")
        self.assertEqual(data, {"name": "pygoat", "version": 1, "items": ["a", "b"]})

    def test_parses_from_bytes_stream(self):
        stream = io.BytesIO(b"key: value\nnested:\n  flag: true\n")
        self.assertEqual(parse_yaml(stream), {"key": "value", "nested": {"flag": True}})

    def test_rejects_python_object_apply(self):
        malicious = "!!python/object/apply:os.system ['echo pwned']"
        with self.assertRaises(yaml.YAMLError):
            parse_yaml(malicious)

    def test_rejects_python_object_new(self):
        malicious = "!!python/object/new:os.system ['id']"
        with self.assertRaises(yaml.YAMLError):
            parse_yaml(malicious)


if __name__ == "__main__":
    unittest.main()
