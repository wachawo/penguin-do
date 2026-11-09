#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Local GGUF model store: where models live, and a resumable verified download."""

import contextlib
import hashlib
import http.client
import logging
import os
import sys
import time
import traceback
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any, Callable, Dict, Iterator, Optional

# Local imports
from penguin_do import __version__

try:
    import fcntl
except ImportError:
    fcntl = None

logger = logging.getLogger(__name__)

CHUNK_SIZE = 1024 * 1024
DEFAULT_ENDPOINT = "https://huggingface.co"
USER_AGENT = f"penguin-do/{__version__}"


@dataclass(frozen=True)
class ModelSpec:
    """One downloadable model file with the numbers it is verified against."""

    key: str
    repo: str
    filename: str
    size: int
    sha256: str
    license: str
    description: str


class DownloadError(Exception):
    """The download could not finish; a partial file is kept for resume."""


class ChecksumError(DownloadError):
    """The downloaded bytes do not match the expected size or sha256; the partial file was removed."""


DALE = ModelSpec(
    key="dale",
    repo="manuelgscom/dale-0.8b-GGUF",
    filename="dale-0.8b-1.0.0-Q4_K_M.gguf",
    size=529297952,
    sha256="8738d2535680cf7b8227001013a0ba6e6b2a4c8e8f3d149fd181c17cb96e2d3d",
    license="Apache-2.0",
    description="dale-0.8b: plain-language request to one bash command",
)

MODELS: Dict[str, ModelSpec] = {"dale": DALE}


def models_dir() -> str:
    """Directory holding the model files: $PENGUIN_DO_MODELS_DIR, else $XDG_CACHE_HOME/penguin-do/models."""
    override = os.environ.get("PENGUIN_DO_MODELS_DIR")
    if override:
        return os.path.expanduser(override)
    cache_home = os.environ.get("XDG_CACHE_HOME") or os.path.join(os.path.expanduser("~"), ".cache")
    return os.path.join(cache_home, "penguin-do", "models")


def model_path(spec: ModelSpec) -> str:
    """Final on-disk path of a model file."""
    return os.path.join(models_dir(), spec.filename)


def is_present(spec: ModelSpec) -> bool:
    """True when the model file exists with the expected size (no hashing on every run)."""
    path = model_path(spec)
    try:
        return os.path.isfile(path) and os.path.getsize(path) == spec.size
    except OSError:
        return False


def download_url(spec: ModelSpec) -> str:
    """Hugging Face resolve URL, honouring $HF_ENDPOINT for mirrors."""
    endpoint = (os.environ.get("HF_ENDPOINT") or DEFAULT_ENDPOINT).rstrip("/")
    return f"{endpoint}/{spec.repo}/resolve/main/{spec.filename}"


def hash_file(path: str) -> Any:
    """Return a sha256 object fed with the current contents of `path`."""
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        while True:
            chunk = handle.read(CHUNK_SIZE)
            if not chunk:
                break
            digest.update(chunk)
    return digest


def remove_quietly(path: str) -> bool:
    """Delete a file if it exists; True when something was removed."""
    try:
        os.remove(path)
        return True
    except FileNotFoundError:
        return False


def finish_download(spec: ModelSpec, part_path: str, digest: Any, written: int) -> str:
    """Verify size and sha256 of the .part file and move it into place."""
    if written < spec.size:
        raise DownloadError(f"connection closed after {written} of {spec.size} bytes")
    if written > spec.size or digest.hexdigest() != spec.sha256:
        remove_quietly(part_path)
        raise ChecksumError(f"{spec.filename}: expected {spec.size} bytes with sha256 {spec.sha256}, got {written} bytes with sha256 {digest.hexdigest()}")
    # The digest covers the bytes this process streamed; make sure nothing else wrote to the file meanwhile.
    on_disk = os.path.getsize(part_path)
    if on_disk != spec.size:
        remove_quietly(part_path)
        raise ChecksumError(f"{spec.filename}: expected {spec.size} bytes on disk, found {on_disk}")
    final_path = model_path(spec)
    os.replace(part_path, final_path)
    logger.info(f"Saved {spec.key} to {final_path}")
    return final_path


def open_stream(url: str, offset: int, timeout: float):
    """Open the URL, asking for bytes from `offset` on when it is non-zero."""
    headers = {"User-Agent": USER_AGENT}
    if offset:
        headers["Range"] = f"bytes={offset}-"
    request = urllib.request.Request(url, headers=headers)
    return urllib.request.urlopen(request, timeout=timeout)


def range_start(response) -> Optional[int]:
    """First byte offset named by a 206 Content-Range header, or None when absent or unparsable."""
    value = response.headers.get("Content-Range") or ""
    try:
        return int(value.split()[1].split("-")[0])
    except (IndexError, ValueError):
        return None


def open_resumed(spec: ModelSpec, url: str, offset: int, timeout: float):
    """Open the download, resuming at `offset` when the server agrees; any other answer starts from byte 0.

    A 200 reply already carries the whole file, so its body is used as the restart.
    A 416, or a 206 that starts somewhere else, is reopened without a range.
    """
    if not offset:
        return open_stream(url, 0, timeout)
    try:
        response = open_stream(url, offset, timeout)
    except urllib.error.HTTPError as exc:
        if exc.code != 416:
            raise
        exc.close()
        logger.info(f"Server refused the resume range for {spec.filename}; restarting")
        return open_stream(url, 0, timeout)
    if response.status == 206 and range_start(response) != offset:
        response.close()
        logger.info(f"Server resumed {spec.filename} at the wrong offset; restarting")
        return open_stream(url, 0, timeout)
    if response.status != 206:
        logger.info(f"Server ignored the resume range for {spec.filename} (HTTP {response.status}); restarting")
    return response


@contextlib.contextmanager
def download_lock(spec: ModelSpec) -> Iterator[None]:
    """Hold an exclusive lock on `<file>.lock`, so two downloads of one model never write the same .part."""
    with open(model_path(spec) + ".lock", "a", encoding="utf-8") as handle:
        if fcntl is not None:
            try:
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            except OSError as exc:
                # Some network filesystems do not lock; download unprotected rather than not at all.
                logger.debug(f"{type(exc).__name__}: {exc}\n{traceback.format_exc()}")
        yield


def download(spec: ModelSpec, progress: Optional[Callable[[int, int], None]] = None, timeout: float = 30) -> str:
    """Download `spec` into models_dir(), resuming a previous .part file; return the final path.

    A second download of the same model waits for the first and then finds it present.
    """
    os.makedirs(models_dir(), exist_ok=True)
    with download_lock(spec):
        if is_present(spec):
            return model_path(spec)
        return fetch_model(spec, progress, timeout)


def fetch_model(spec: ModelSpec, progress: Optional[Callable[[int, int], None]], timeout: float) -> str:
    """The download itself, run under download_lock."""
    part_path = model_path(spec) + ".part"
    url = download_url(spec)
    offset = os.path.getsize(part_path) if os.path.isfile(part_path) else 0
    if offset > spec.size:
        logger.info(f"Partial file {part_path} is larger than {spec.filename}; restarting")
        remove_quietly(part_path)
        offset = 0
    if offset == spec.size:
        # Everything is already on disk: verify it rather than ask for an empty range.
        return finish_download(spec, part_path, hash_file(part_path), offset)
    try:
        response = open_resumed(spec, url, offset, timeout)
        with response:
            if response.status != 206:
                offset = 0
            digest = hash_file(part_path) if offset else hashlib.sha256()
            written = offset
            with open(part_path, "ab" if offset else "wb") as handle:
                if progress:
                    progress(written, spec.size)
                while True:
                    chunk = response.read(CHUNK_SIZE)
                    if not chunk:
                        break
                    handle.write(chunk)
                    digest.update(chunk)
                    written += len(chunk)
                    if progress:
                        progress(written, spec.size)
    except (urllib.error.URLError, http.client.HTTPException, OSError) as exc:
        logger.debug(f"{type(exc).__name__}: {exc}\n{traceback.format_exc()}")
        raise DownloadError(f"{type(exc).__name__}: {exc}") from exc
    return finish_download(spec, part_path, digest, written)


def remove(spec: ModelSpec) -> bool:
    """Delete the model file and any partial download; True when something was removed."""
    final_path = model_path(spec)
    removed_model = remove_quietly(final_path)
    removed_part = remove_quietly(final_path + ".part")
    remove_quietly(final_path + ".lock")
    return removed_model or removed_part


def human_size(size: int) -> str:
    """Decimal human-readable size: '529 MB', '1.1 GB'."""
    if size >= 1000**3:
        return f"{size / 1000**3:.1f} GB"
    if size >= 1000**2:
        return f"{size / 1000**2:.0f} MB"
    if size >= 1000:
        return f"{size / 1000:.0f} KB"
    return f"{size} B"


def progress_bar(name: str) -> Callable[[int, int], None]:
    """Return a progress callback drawing a one-line bar on stderr; a no-op when stderr is not a TTY."""
    stream = sys.stderr
    try:
        interactive = stream.isatty()
    except (AttributeError, ValueError):
        interactive = False
    if not interactive:
        return lambda done, total: None
    state = {"start": 0.0, "first": -1, "drawn": 0.0}

    def draw(done: int, total: int) -> None:
        now = time.monotonic()
        if state["first"] < 0:
            state["start"] = now
            state["first"] = done
        finished = total > 0 and done >= total
        if not finished and now - state["drawn"] < 0.1:
            return
        state["drawn"] = now
        elapsed = now - state["start"]
        speed = (done - state["first"]) / elapsed / 1000**2 if elapsed > 0 else 0.0
        percent = int(done * 100 / total) if total else 0
        width = 30
        filled = width * percent // 100
        bar = "#" * filled + "-" * (width - filled)
        line = f"\r{name} [{bar}] {percent:3d}% {done / 1000**2:.0f}/{total / 1000**2:.0f} MB {speed:.1f} MB/s"
        stream.write(line + ("\n" if finished else ""))
        stream.flush()

    return draw


def main():
    pass


if __name__ == "__main__":
    main()
