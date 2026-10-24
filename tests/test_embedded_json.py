import json
from pathlib import Path
import re
import unittest


class EmbeddedJsonTests(unittest.TestCase):
    def test_builtin_mba_patterns_parse(self):
        source = (Path(__file__).resolve().parents[1] / 'plugin/tools/api_hexrays/mba_rules.h').read_text(encoding='utf-8')
        patterns = re.findall(r'nlohmann::json::parse\(R"\((.*?)\)"\)', source, re.S)
        self.assertGreaterEqual(len(patterns), 30)
        for pattern in patterns:
            with self.subTest(pattern=pattern):
                value = json.loads(pattern)
                self.assertIsInstance(value, dict)
                self.assertIn('op', value)


if __name__ == '__main__':
    unittest.main()
