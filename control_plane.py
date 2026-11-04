#!/usr/bin/env python3
"""Control plane entry point. The implementation lives in the `sdn` package."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from sdn.cli import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
