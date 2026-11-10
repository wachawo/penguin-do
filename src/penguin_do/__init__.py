#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""penguin-do: a plain-language request turned into one shell command by a local model."""

from importlib import metadata

try:
    __version__ = metadata.version("penguin-do")
except metadata.PackageNotFoundError:
    __version__ = "0.0.0"

# Local imports
# Imported after __version__: model_store reads it while this package is still initialising.
from penguin_do.cli import main  # noqa: E402

__all__ = ["__version__", "main"]
