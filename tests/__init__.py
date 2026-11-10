"""Tests for evidence-seal.

No test may read or write a real user's settings or library, so every run gets an empty home folder
of its own, removed when the run ends. Commands the tests start as separate processes inherit it.
"""

import atexit
import os
import shutil
import tempfile

_TEST_HOME = tempfile.mkdtemp(prefix="evidence-seal-home-")
os.environ["EVIDENCE_SEAL_HOME"] = _TEST_HOME
atexit.register(shutil.rmtree, _TEST_HOME, True)
