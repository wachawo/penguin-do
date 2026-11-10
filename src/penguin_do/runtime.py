#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Thin lazy wrapper around llama-cpp-python: load a GGUF once, run greedy completions."""

import contextlib
import importlib.util
import logging
import os
import signal
import sys
import threading
import time
import traceback
from typing import Any, Dict, Iterator, List, Optional

logger = logging.getLogger(__name__)

INSTALL_HINT = "pip install --force-reinstall llama-cpp-python --extra-index-url https://abetlen.github.io/llama-cpp-python/whl/cpu"
DEFAULT_STOP = ["<|im_end|>"]

# Loaded models keyed by path: loading costs ~0.5 s and hundreds of MB, so it happens once per process.
LOADED_MODELS: Dict[str, Any] = {}


class RuntimeMissing(Exception):
    """llama-cpp-python is not installed."""


def runtime_available() -> bool:
    """True when the llama_cpp package can be imported, without importing it."""
    try:
        return importlib.util.find_spec("llama_cpp") is not None
    except (ImportError, ValueError):
        # find_spec raises ValueError for a module already in sys.modules without a __spec__.
        return sys.modules.get("llama_cpp") is not None


@contextlib.contextmanager
def silenced_stderr() -> Iterator[None]:
    """Point file descriptor 2 at /dev/null for the duration, so C-level chatter is dropped."""
    try:
        sys.stderr.flush()
    except (AttributeError, ValueError, OSError):
        pass
    try:
        saved_fd = os.dup(2)
    except OSError:
        yield
        return
    devnull_fd = os.open(os.devnull, os.O_WRONLY)
    try:
        os.dup2(devnull_fd, 2)
        yield
    finally:
        os.dup2(saved_fd, 2)
        os.close(saved_fd)
        os.close(devnull_fd)


@contextlib.contextmanager
def deferred_sigint() -> Iterator[None]:
    """Hold Ctrl+C back while llama.cpp loads a model and raise KeyboardInterrupt once it returns.

    During the constructor Python's own handler raises inside a ctypes callback,
    where the exception is swallowed, so a Ctrl+C pressed while loading was lost.
    """
    if threading.current_thread() is not threading.main_thread():
        yield
        return
    received: List[int] = []

    def remember(signum, frame) -> None:
        received.append(signum)

    previous = signal.signal(signal.SIGINT, remember)
    try:
        yield
    finally:
        signal.signal(signal.SIGINT, previous)
    if received:
        raise KeyboardInterrupt


def load_model(path: str, n_ctx: int = 2048) -> Any:
    """Return a llama_cpp.Llama for `path`, loading it on first use; RuntimeMissing without llama_cpp."""
    cached = LOADED_MODELS.get(path)
    if cached is not None:
        return cached
    try:
        import llama_cpp
    except (ImportError, OSError) as exc:
        # OSError: the package is there but its shared library (libllama.so) does not load.
        logger.debug(f"{type(exc).__name__}: {exc}\n{traceback.format_exc()}")
        raise RuntimeMissing(INSTALL_HINT) from exc
    start_time = time.monotonic()
    try:
        with deferred_sigint(), silenced_stderr():
            llm = llama_cpp.Llama(model_path=path, n_ctx=n_ctx, verbose=False)
    except Exception as exc:
        logger.debug(f"{type(exc).__name__}: {exc}\n{traceback.format_exc()}")
        raise
    logger.debug(f"Loaded {path} ({time.monotonic() - start_time:.2f})")
    LOADED_MODELS[path] = llm
    return llm


def generate(llm: Any, prompt: str, max_tokens: int, stop: Optional[List[str]] = None) -> str:
    """Greedy completion of an already-templated prompt; special tokens are parsed, no BOS is added."""
    tokens = llm.tokenize(prompt.encode("utf-8"), add_bos=False, special=True)
    output = llm.create_completion(
        tokens,
        max_tokens=max_tokens,
        temperature=0.0,
        top_k=1,
        stop=list(DEFAULT_STOP if stop is None else stop),
    )
    return output["choices"][0]["text"].strip()


def main():
    pass


if __name__ == "__main__":
    main()
