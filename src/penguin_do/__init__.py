#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""penguin-do: placeholder package, coming soon."""

import logging

__version__ = "0.0.0"

LOGGING = {
    "handlers": [
        logging.StreamHandler(),
    ],
    "format":  "%(asctime)s.%(msecs)03d [%(levelname)s]: (%(name)s) %(message)s",
    "level":   logging.INFO,
    "datefmt": "%Y-%m-%d %H:%M:%S",
}
logger = logging.getLogger(__name__)


def main() -> int:
    # Configured here, not at import: importing a library must not touch logging.
    logging.basicConfig(**LOGGING)
    logger.info("Coming soon... The penguin is still learning to do things.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
