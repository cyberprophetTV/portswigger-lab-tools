"""
Pytest conftest at repo root.

Adds the project directory to sys.path so tests can do
`from intruder import RawRequest` etc. without us having
to set up a package structure for what's essentially a
collection of standalone scripts.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
