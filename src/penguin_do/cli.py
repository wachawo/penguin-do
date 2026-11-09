#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Command-line entry point for `penguin-do`."""

import argparse
import logging
import os
import sys
from typing import List, Optional

# Local imports
from penguin_do import __version__, colors, i18n

DESCRIPTION = "Turn a plain-language request into one shell command with a short explanation, and ask before running it."
RC_ERROR = 1
RC_INTERRUPTED = 130

LOGGING = {
    "handlers": [
        logging.StreamHandler(),
    ],
    "format": "%(asctime)s.%(msecs)03d [%(levelname)s]: (%(name)s) %(message)s",
    "level": logging.WARNING,
    "datefmt": "%Y-%m-%d %H:%M:%S",
}
logger = logging.getLogger(__name__)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="penguin-do",
        description=DESCRIPTION,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Examples:\n"
        '  penguin-do "who is using swap?"                  # suggest a command and ask before running it\n'
        '  penguin-do -n "show the biggest files in /var"   # print the command without running it\n'
        '  penguin-do -f json "list listening ports"        # machine-readable answer\n'
        "  penguin-do --pull                                # download the local model\n",
    )
    parser.add_argument("request", nargs="*", help="The request in plain language, in any of the supported languages")
    parser.add_argument("-n", "--dry-run", action="store_true", help="Print the suggested command without offering to run it")
    parser.add_argument("-f", "--format", choices=["text", "plain", "json"], default="text", help="Output format (default: text)")
    parser.add_argument(
        "--lang",
        choices=list(i18n.LANGUAGES),
        default=None,
        metavar="CODE",
        help=f"UI language: {' '.join(i18n.LANGUAGES)}. Default: the PENGUIN_DO_LANG env var, then the language of the request, then $LANG.",
    )
    parser.add_argument("--no-color", action="store_true", help="Disable colored output")
    parser.add_argument("-v", "--verbose", action="count", default=0, help="More logging (-v info, -vv debug); errors show a traceback")
    parser.add_argument("-q", "--quiet", action="store_true", help="Reduce logging output")
    parser.add_argument("-V", "--version", action="version", version=f"penguin-do {__version__}")
    models = parser.add_mutually_exclusive_group()
    models.add_argument("--models", dest="action", action="store_const", const="status", help="Show the local model status")
    models.add_argument("--pull", dest="action", action="store_const", const="pull", help="Download the local model")
    models.add_argument("--rm", dest="action", action="store_const", const="rm", help="Remove the local model and any partial download")
    return parser


def configure_logging(verbose: int, quiet: bool) -> None:
    """Root logging: WARNING by default, -v INFO, -vv DEBUG, -q ERROR."""
    logging.basicConfig(**LOGGING)
    if verbose >= 2:
        logging.getLogger().setLevel(logging.DEBUG)
    elif verbose == 1:
        logging.getLogger().setLevel(logging.INFO)
    elif quiet:
        logging.getLogger().setLevel(logging.ERROR)


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    # parse_intermixed_args does not honour "--", so everything after the
    # first "--" is taken as request words before parsing the rest.
    argv = list(sys.argv[1:] if argv is None else argv)
    tail = []
    if "--" in argv:
        cut = argv.index("--")
        argv, tail = argv[:cut], argv[cut + 1:]
    args = parser.parse_intermixed_args(argv)
    args.request = list(args.request) + tail
    if args.action and args.request:
        parser.error("a request cannot be combined with --models, --pull or --rm")

    configure_logging(args.verbose, args.quiet)
    colors.init_colors(force_no_color=args.no_color)

    try:
        # Imported here so --help and --version never load the model code.
        from penguin_do import ask

        if args.action:
            return ask.cmd_model(args)
        return ask.cmd_ask(args)
    except KeyboardInterrupt:
        sys.stdout.write("\ninterrupted\n")
        sys.stdout.flush()
        return RC_INTERRUPTED
    except Exception as exc:
        if args.verbose or os.environ.get("PENGUIN_DO_DEBUG"):
            raise
        sys.stderr.write(f"error: {type(exc).__name__}: {str(exc)}\n")
        return RC_ERROR


if __name__ == "__main__":
    sys.exit(main())
