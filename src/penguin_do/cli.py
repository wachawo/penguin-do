#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Command-line entry point for `penguin-do`."""

import argparse
import logging
import os
import sys
from typing import List, Optional

# Local imports
from penguin_do import __version__, colors, i18n, model_store

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
        "  penguin-do --pull                                # choose and download a local model\n"
        "  penguin-do --model qwen2.5-1.5b \"free disk\"      # use another downloaded model once\n",
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
    model_keys = list(model_store.MODELS)
    parser.add_argument(
        "--model",
        choices=model_keys,
        default=None,
        metavar="MODEL",
        help=f"Model for this run: {' '.join(model_keys)}. Default: PENGUIN_DO_MODEL, then the one chosen with --pull.",
    )
    parser.add_argument("--no-color", action="store_true", help="Disable colored output")
    parser.add_argument("-v", "--verbose", action="count", default=0, help="More logging (-v info, -vv debug); errors show a traceback")
    parser.add_argument("-q", "--quiet", action="store_true", help="Reduce logging output")
    parser.add_argument("-V", "--version", action="version", version=f"penguin-do {__version__}")
    models = parser.add_mutually_exclusive_group()
    models.add_argument("--models", action="store_true", help="Show the local models and which one is in use")
    models.add_argument("--pull", nargs="?", const="", default=None, metavar="MODEL", help="Download a model and use it from now on; without MODEL a menu asks which")
    models.add_argument("--rm", nargs="?", const="", default=None, metavar="MODEL", help="Remove a model and any partial download; without MODEL the one in use")
    return parser


def model_action(args: argparse.Namespace) -> Optional[str]:
    """Which of --models, --pull, --rm was given (they exclude each other), and its MODEL in args.model_key."""
    args.model_key = args.pull or args.rm or ""
    if args.models:
        return "status"
    if args.pull is not None:
        return "pull"
    if args.rm is not None:
        return "rm"
    return None


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
    args.action = model_action(args)
    if args.model_key and args.model_key not in model_store.MODELS:
        parser.error(f"unknown model {args.model_key!r}; choose from {', '.join(model_store.MODELS)}")
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
