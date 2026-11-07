"""Allows ``python -m evidence_seal``."""

import sys

from .cli import main

if __name__ == "__main__":
    sys.exit(main())
