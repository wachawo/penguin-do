#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ANSI color helpers for penguin-do terminal output."""

import os
import sys
from typing import Optional

RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"

FG_BLACK = "\033[30m"
FG_RED = "\033[31m"
FG_GREEN = "\033[32m"
FG_YELLOW = "\033[33m"
FG_BLUE = "\033[34m"
FG_MAGENTA = "\033[35m"
FG_CYAN = "\033[36m"
FG_WHITE = "\033[37m"
FG_BRIGHT_BLACK = "\033[90m"

color_enabled = True


def init_colors(force_no_color: bool = False) -> None:
    """Decide whether colored output should be enabled."""
    global color_enabled
    if force_no_color:
        color_enabled = False
        return
    if os.getenv("NO_COLOR"):
        color_enabled = False
        return
    if not sys.stdout.isatty():
        color_enabled = False
        return
    color_enabled = True


def colored(text: str, color: str, bold: bool = False) -> str:
    """Wrap text in ANSI color codes when colors are enabled."""
    if not color_enabled:
        return text
    prefix = (BOLD if bold else "") + color
    return f"{prefix}{text}{RESET}"


def green(text: str, bold: bool = False) -> str:
    return colored(text, FG_GREEN, bold=bold)


def red(text: str, bold: bool = False) -> str:
    return colored(text, FG_RED, bold=bold)


def yellow(text: str, bold: bool = False) -> str:
    return colored(text, FG_YELLOW, bold=bold)


def cyan(text: str, bold: bool = False) -> str:
    return colored(text, FG_CYAN, bold=bold)


def blue(text: str, bold: bool = False) -> str:
    return colored(text, FG_BLUE, bold=bold)


def dim(text: str) -> str:
    if not color_enabled:
        return text
    return f"{DIM}{text}{RESET}"


def bold(text: str) -> str:
    if not color_enabled:
        return text
    return f"{BOLD}{text}{RESET}"


def status_marker(status: str) -> str:
    """Render a status marker like [OK] / [WARN] / [FAIL]."""
    s = status.upper()
    if s == "OK":
        return green("[ OK ]", bold=True)
    if s in ("WARN", "WARNING"):
        return yellow("[WARN]", bold=True)
    if s in ("FAIL", "ERROR", "CRIT", "CRITICAL"):
        return red("[FAIL]", bold=True)
    if s in ("INFO", "SKIP", "N/A"):
        return cyan(f"[{s:^4}]")
    return f"[{s}]"


def section(title: str, width: Optional[int] = None) -> str:
    """Render a section header as a plain `# TITLE` line.

    The `width` argument is accepted for backward compatibility but ignored —
    headers are left-aligned and not padded to the terminal width.
    """
    return cyan(f"# {title.strip()}", bold=True)


def main():
    pass


if __name__ == "__main__":
    main()
