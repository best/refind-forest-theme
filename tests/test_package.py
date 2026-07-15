import unittest

import refind_forest


class PackageTests(unittest.TestCase):
    def test_version_is_exposed(self) -> None:
        self.assertEqual(refind_forest.__version__, "0.1.0")


if __name__ == "__main__":
    unittest.main()
