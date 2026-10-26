"""Bootstrap pip from a fixed wheel hash before using its patched CA bundle."""

import hashlib
from pathlib import Path
import subprocess
import sys
import tempfile
import urllib.request

PIP_URL = (
    "https://files.pythonhosted.org/packages/3f/06/"
    "3e4420302363fbb71be3c7f35ce042f54bfca330e3e66b3a2e3c4cca579f/"
    "pip-26.2.2-py3-none-any.whl"
)
PIP_SHA256 = "fd7f4dfa8190e014013b9f08f3e973f4e4c26ffd179a204895533a7254813a70"


def bootstrap():
    if sys.version_info < (3, 11):
        raise SystemExit("Use a supported, patched Python 3.11+ runtime and recreate this venv.")
    with tempfile.TemporaryDirectory(prefix="memwal-pip-") as directory:
        with urllib.request.urlopen(PIP_URL, timeout=60) as response:
            data = response.read()
        if hashlib.sha256(data).hexdigest() != PIP_SHA256:
            raise SystemExit("pip wheel checksum mismatch; no package was installed.")
        wheel = Path(directory) / "pip-26.2.2-py3-none-any.whl"
        wheel.write_bytes(data)
        subprocess.run(
            [sys.executable, "-m", "pip", "install", "--no-index", "--no-deps", "--upgrade", str(wheel)],
            check=True,
        )
    subprocess.run(
        [sys.executable, "-m", "pip", "install", "--upgrade", "--only-binary=:all:",
         "certifi>=2026.10.19", "setuptools>=83.0.0"],
        check=True,
    )


if __name__ == "__main__":
    bootstrap()
