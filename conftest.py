"""Pytest bootstrap: ensure the repo root is importable as the package root.

Lets `fixtures`, `scorer`, and `harness` import cleanly when pytest is invoked
from anywhere in the tree.
"""
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))
