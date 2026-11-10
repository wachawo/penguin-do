# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `penguin-do "<request>"` turns a plain-language request into one shell command with a one-line explanation, using the local dale-0.8b GGUF model through `llama-cpp-python`.
- `Run? [Y/n/e]` prompt before anything runs: Enter or `y` runs the command through `bash -c`, `n` cancels, `e` edits it with Tab completion.
- Offline risk rating (`safe`, `caution`, `danger`) of every suggested and edited command; `danger` flips the prompt default to no (`Run anyway? [y/N/e]`).
- `-n`/`--dry-run` and `-f`/`--format text|plain|json`; without a terminal the command is printed and never run.
- Model management with `--models`, `--pull` and `--rm`: resumable download with size and sha256 check, stored in `$PENGUIN_DO_MODELS_DIR` or `$XDG_CACHE_HOME/penguin-do/models`.
- Choice of model: dale, Qwen3.5-0.8B or Qwen2.5-1.5B-Instruct, picked from a menu on the first request or with `--pull [MODEL]`; the pick is remembered in `$XDG_CONFIG_HOME/penguin-do/model`, and `--model MODEL` or `PENGUIN_DO_MODEL` override it for one run.
- Messages in 11 languages (en, es, pt, fr, de, it, ru, zh, ja, hi, ko), chosen by `--lang`, `PENGUIN_DO_LANG`, the request language or the locale.
- `llama-cpp-python>=0.3.36` dependency.

### Changed

- The `penguin-do` command no longer logs the "Coming soon..." placeholder message; it now runs the request-to-command flow.

## [0.0.0] - 2026-11-09

### Added

- Placeholder package reserving the `penguin-do` name on PyPI.
- `penguin-do` command that logs "Coming soon... The penguin is still learning to do things." to stderr and exits with code 0.
