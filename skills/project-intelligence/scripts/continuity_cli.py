#!/usr/bin/env python3
"""Executable wrapper for the sibling Continuity package CLI."""

from __future__ import annotations

import sys


sys.dont_write_bytecode = True

from continuity.cli import main


if __name__ == "__main__":
    raise SystemExit(main())
