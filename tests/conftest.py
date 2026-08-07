"""Put the repository root on sys.path so `from tools import ...` resolves.

Deliberately minimal: this repository ships the desktop app, its build tooling and the
release gate, so the test suite needs nothing beyond an importable project root.
"""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
