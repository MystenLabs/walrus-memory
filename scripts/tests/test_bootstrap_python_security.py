import importlib.util
import io
from pathlib import Path
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location(
    "bootstrap_python_security", Path(__file__).parents[1] / "bootstrap-python-security.py"
)
bootstrap = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bootstrap)


class BootstrapIntegrityTest(unittest.TestCase):
    def test_untrusted_wheel_never_reaches_pip(self):
        with patch.object(bootstrap.urllib.request, "urlopen", return_value=io.BytesIO(b"tampered")):
            with patch.object(bootstrap.subprocess, "run") as install:
                with self.assertRaisesRegex(SystemExit, "checksum mismatch"):
                    bootstrap.bootstrap()
                install.assert_not_called()


if __name__ == "__main__":
    unittest.main()
