#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CLI flow for `penguin-do "<request>"` (plain language to bash) and the model flags."""

import argparse
import glob
import importlib
import json
import logging
import os
import shutil
import subprocess
import sys
import traceback
from typing import Callable, List, Optional

# Local imports
from penguin_do import colors, i18n, model_store, nl2bash, runtime, shellrisk

logger = logging.getLogger(__name__)

RC_CANCELLED = 1
RC_USAGE = 2
RC_MISSING = 3
RC_INTERRUPTED = 130

COMPLETER_DELIMS = " \t\n;|&<>"
COMMAND_SEPARATORS = (";", "|", "&", "(", "`")
SHELL_BUILTINS = (
    "alias",
    "bg",
    "cd",
    "command",
    "declare",
    "echo",
    "eval",
    "exec",
    "exit",
    "export",
    "fg",
    "history",
    "jobs",
    "kill",
    "printf",
    "pwd",
    "read",
    "set",
    "source",
    "test",
    "time",
    "type",
    "ulimit",
    "umask",
    "unalias",
    "unset",
    "wait",
)
YES_ANSWERS = ("y", "yes")
NO_ANSWERS = ("n", "no")


def is_interactive() -> bool:
    """True when both stdin and stdout are terminals (a prompt can be answered)."""
    try:
        return sys.stdin.isatty() and sys.stdout.isatty()
    except (AttributeError, ValueError):
        return False


def stderr_is_tty() -> bool:
    try:
        return sys.stderr.isatty()
    except (AttributeError, ValueError):
        return False


def show_status(text: str) -> None:
    """Draw a transient status line on stderr (TTY only)."""
    if stderr_is_tty():
        sys.stderr.write("\r\033[K" + colors.dim(text))
        sys.stderr.flush()


def clear_status() -> None:
    if stderr_is_tty():
        sys.stderr.write("\r\033[K")
        sys.stderr.flush()


def read_line(prompt: str) -> Optional[str]:
    """input() that returns None on Ctrl+C / EOF instead of raising."""
    try:
        return input(prompt)
    except (KeyboardInterrupt, EOFError):
        sys.stdout.write("\n")
        return None


def ask_yes_no(prompt: str) -> Optional[bool]:
    """Ask a [Y/n] question: Enter means yes. None on Ctrl+C / EOF."""
    while True:
        answer = read_line(prompt)
        if answer is None:
            return None
        choice = answer.strip().lower()
        if choice == "" or choice in YES_ANSWERS:
            return True
        if choice in NO_ANSWERS:
            return False


def download_model(spec, lang: str) -> bool:
    """Download one model with a progress bar; report the outcome on stderr."""
    sys.stderr.write(i18n.message("downloading", lang, name=spec.filename) + "\n")
    try:
        path = model_store.download(spec, progress=model_store.progress_bar(spec.filename))
    except model_store.ChecksumError:
        clear_status()
        sys.stderr.write(colors.red(i18n.message("checksum_failed", lang, name=spec.filename)) + "\n")
        return False
    except Exception as exc:
        logger.debug(f"{type(exc).__name__}: {exc}\n{traceback.format_exc()}")
        clear_status()
        sys.stderr.write(colors.red(i18n.message("download_failed", lang, error=str(exc))) + "\n")
        return False
    sys.stderr.write(colors.dim(i18n.message("download_done", lang, path=path)) + "\n")
    return True


def ensure_dale(lang: str) -> Optional[int]:
    """Make sure the dale model is on disk. None when ready, else the exit code to return."""
    spec = model_store.DALE
    if model_store.is_present(spec):
        return None
    size = model_store.human_size(spec.size)
    if not is_interactive():
        sys.stderr.write(i18n.message("model_missing", lang, name=spec.filename, size=size) + "\n")
        sys.stderr.write("  penguin-do --pull\n")
        return RC_MISSING
    answer = ask_yes_no(i18n.message("download_ask", lang, name=spec.filename, size=size, path=model_store.model_path(spec)))
    if answer is None:
        sys.stdout.write(i18n.message("cancelled", lang) + "\n")
        return RC_INTERRUPTED
    if not answer:
        sys.stdout.write(i18n.message("cancelled", lang) + "\n")
        return RC_CANCELLED
    if not download_model(spec, lang):
        return RC_CANCELLED
    return None


def answer_type(suggestion) -> str:
    answer = suggestion.answer
    return answer.type if answer is not None else "invalid"


def answer_command(suggestion) -> str:
    answer = suggestion.answer
    if answer is None or answer.type != "command":
        return ""
    return answer.command


def risk_line(risk, lang: str) -> str:
    """The coloured caution / danger line, or "" for a safe command."""
    if risk is None or risk.level == "safe":
        return ""
    reasons = ", ".join(risk.reasons)
    if risk.level == "danger":
        return colors.red(i18n.message("risk_danger", lang, reasons=reasons), bold=True)
    return colors.yellow(i18n.message("risk_caution", lang, reasons=reasons))


def render_json(suggestion, ui_lang: str) -> str:
    risk = suggestion.risk
    data = {
        "request": suggestion.request,
        "language": suggestion.request_language,
        "ui_language": ui_lang,
        "type": answer_type(suggestion),
        "command": answer_command(suggestion),
        "explanation": suggestion.explanation,
        "risk": risk.level if risk is not None else None,
        "reasons": list(risk.reasons) if risk is not None else [],
    }
    return json.dumps(data, indent=2, ensure_ascii=False)


def render_failure(suggestion, lang: str) -> str:
    """Localized message for a refuse / unsure / invalid answer."""
    kind = answer_type(suggestion)
    explanation = suggestion.explanation or (suggestion.answer.explanation if suggestion.answer else "")
    if kind == "refuse":
        return i18n.message("refused", lang, explanation=explanation)
    if kind == "unsure":
        return i18n.message("unsure", lang, explanation=explanation)
    return i18n.message("invalid", lang)


def render_text(suggestion, lang: str) -> List[str]:
    """The compact block shown above the run prompt."""
    lines = [f"  {colors.green(answer_command(suggestion), bold=True)}"]
    if suggestion.explanation:
        lines.append(f"  {colors.dim(suggestion.explanation)}")
    warning = risk_line(suggestion.risk, lang)
    if warning:
        lines.append(f"  {warning}")
    return lines


def is_danger(risk) -> bool:
    return risk is not None and risk.level == "danger"


def run_command(command: str, lang: str) -> int:
    """Run the command through bash (or /bin/sh) with inherited stdio; return its exit code."""
    argv = ["bash", "-c", command] if shutil.which("bash") else ["/bin/sh", "-c", command]
    try:
        result = subprocess.run(argv, check=False)
    except KeyboardInterrupt:
        return RC_INTERRUPTED
    except (OSError, ValueError) as exc:
        # ValueError: an embedded NUL byte; parse_answer rejects those, but an edited command is not parsed.
        logger.error(f"{type(exc).__name__}: {exc}\n{traceback.format_exc()}")
        return 127
    code = result.returncode
    if code < 0:
        code = 128 - code
    if code != 0:
        sys.stderr.write(colors.dim(i18n.message("exit_code", lang, code=code)) + "\n")
    return code


def path_executables(prefix: str) -> List[str]:
    """Executable names on PATH starting with prefix."""
    names = set()
    for folder in os.environ.get("PATH", "").split(os.pathsep):
        if not folder:
            continue
        try:
            entries = os.listdir(folder)
        except OSError:
            continue
        for name in entries:
            if not name.startswith(prefix):
                continue
            full_path = os.path.join(folder, name)
            if os.path.isfile(full_path) and os.access(full_path, os.X_OK):
                names.add(name)
    return sorted(names)


def path_matches(text: str) -> List[str]:
    """Filesystem completions for text; directories end with '/', a leading '~' is kept."""
    expanded = os.path.expanduser(text)
    home_prefix = ""
    if text.startswith("~") and expanded != text:
        home_prefix = text.split("/", 1)[0]
    matches = []
    for match in sorted(glob.glob(glob.escape(expanded) + "*")):
        if os.path.isdir(match):
            match += "/"
        if home_prefix:
            match = home_prefix + match[len(os.path.expanduser(home_prefix)) :]
        matches.append(match)
    return matches


def is_command_position(line_before: str) -> bool:
    """True when the word being completed is the first word of a simple command."""
    stripped = line_before.rstrip()
    return stripped == "" or stripped.endswith(COMMAND_SEPARATORS)


def complete_candidates(text: str, line_before: str) -> List[str]:
    """Tab-completion candidates: commands for the first word, paths for the rest."""
    if is_command_position(line_before) and "/" not in text and not text.startswith("~"):
        builtins = [name for name in SHELL_BUILTINS if name.startswith(text)]
        return sorted(set(path_executables(text)) | set(builtins))
    return path_matches(text)


def make_completer(readline_module) -> Callable[[str, int], Optional[str]]:
    """A readline completer over complete_candidates, computed once per word."""
    cache = {"text": None, "matches": []}

    def completer(text: str, state: int) -> Optional[str]:
        if state == 0 or cache["text"] != text:
            line_before = readline_module.get_line_buffer()[: readline_module.get_begidx()]
            cache["text"] = text
            cache["matches"] = complete_candidates(text, line_before)
        matches = cache["matches"]
        return matches[state] if state < len(matches) else None

    return completer


def load_readline():
    try:
        return importlib.import_module("readline")
    except ImportError:
        return None


def edit_command(command: str, lang: str) -> Optional[str]:
    """Let the user edit the command (readline, pre-filled, Tab completion). None on Ctrl+C / EOF."""
    prompt = i18n.message("prompt_edit", lang)
    readline_module = load_readline()
    if readline_module is None:
        return read_line(prompt)
    previous_completer = readline_module.get_completer()
    previous_delims = readline_module.get_completer_delims()
    readline_module.set_completer_delims(COMPLETER_DELIMS)
    readline_module.set_completer(make_completer(readline_module))
    if "libedit" in (readline_module.__doc__ or ""):
        readline_module.parse_and_bind("bind ^I rl_complete")
    else:
        readline_module.parse_and_bind("tab: complete")
    readline_module.set_startup_hook(lambda: readline_module.insert_text(command))
    try:
        return read_line(prompt)
    finally:
        readline_module.set_startup_hook(None)
        readline_module.set_completer(previous_completer)
        readline_module.set_completer_delims(previous_delims)


def confirm_and_run(command: str, risk, lang: str) -> int:
    """The Run? [Y/n/e] loop. Danger commands need an explicit y/yes."""
    danger = is_danger(risk if risk is not None else shellrisk.classify(command))
    while True:
        prompt = i18n.message("prompt_run_danger" if danger else "prompt_run", lang)
        answer = read_line(prompt)
        if answer is None:
            sys.stdout.write(i18n.message("cancelled", lang) + "\n")
            return RC_INTERRUPTED
        choice = answer.strip().lower()
        if choice in YES_ANSWERS or (choice == "" and not danger):
            return run_command(command, lang)
        if choice in NO_ANSWERS or choice == "":
            sys.stdout.write(i18n.message("cancelled", lang) + "\n")
            return RC_CANCELLED
        if choice != "e":
            continue
        edited = edit_command(command, lang)
        if edited is None:
            sys.stdout.write(i18n.message("cancelled", lang) + "\n")
            return RC_INTERRUPTED
        edited = edited.strip()
        if not edited:
            sys.stdout.write(i18n.message("cancelled", lang) + "\n")
            return RC_CANCELLED
        command = edited
        edited_risk = shellrisk.classify(command)
        if not is_danger(edited_risk):
            return run_command(command, lang)
        sys.stdout.write(f"  {risk_line(edited_risk, lang)}\n")
        danger = True


def request_suggestion(request: str, ui_lang: str):
    """Call the model with a transient `thinking` line on stderr."""
    show_status(i18n.message("thinking", ui_lang))
    try:
        return nl2bash.suggest(request)
    finally:
        clear_status()


def cmd_ask(args: argparse.Namespace) -> int:
    """Turn a plain-language request into one bash command, show it and offer to run it."""
    request = " ".join(getattr(args, "request", None) or []).strip()
    ui_lang = i18n.resolve_ui_language(getattr(args, "lang", None), request)
    output_format = getattr(args, "format", None) or "text"
    interactive = is_interactive()

    if not request:
        sys.stderr.write(i18n.message("empty_request", ui_lang) + "\n")
        return RC_USAGE
    if not runtime.runtime_available():
        return report_runtime_missing(ui_lang)
    missing_rc = ensure_dale(ui_lang)
    if missing_rc is not None:
        return missing_rc

    try:
        suggestion = request_suggestion(request, ui_lang)
    except KeyboardInterrupt:
        sys.stdout.write(i18n.message("cancelled", ui_lang) + "\n")
        return RC_INTERRUPTED
    except runtime.RuntimeMissing:
        # find_spec saw llama_cpp, but importing it failed (broken install, missing libllama.so).
        return report_runtime_missing(ui_lang)
    command = answer_command(suggestion)

    if output_format == "json":
        sys.stdout.write(render_json(suggestion, ui_lang) + "\n")
        return 0 if command else RC_CANCELLED
    if output_format == "plain":
        if command:
            sys.stdout.write(command + "\n")
            # stdout stays the bare command for `| sh` and friends; the warning goes to stderr.
            warning = risk_line(suggestion.risk, ui_lang)
            if warning:
                sys.stdout.flush()
                sys.stderr.write(warning + "\n")
        return 0 if command else RC_CANCELLED
    if not command:
        sys.stdout.write(render_failure(suggestion, ui_lang) + "\n")
        return RC_CANCELLED
    sys.stdout.write("\n".join(render_text(suggestion, ui_lang)) + "\n")

    if getattr(args, "dry_run", False):
        return 0
    if not interactive:
        # Flush first so that with `2>&1` the notice comes after the block it is about.
        sys.stdout.flush()
        sys.stderr.write(i18n.message("no_tty", ui_lang) + "\n")
        return 0
    return confirm_and_run(command, suggestion.risk, ui_lang)


def report_runtime_missing(lang: str) -> int:
    sys.stderr.write(i18n.message("runtime_missing", lang) + "\n")
    sys.stderr.write(i18n.message("runtime_install_hint", lang) + "\n")
    sys.stderr.write(f"  {runtime.INSTALL_HINT}\n")
    return RC_MISSING


def selected_models() -> List:
    return [model_store.DALE]


def model_status_rows() -> List[dict]:
    rows = []
    for key, spec in model_store.MODELS.items():
        rows.append(
            {
                "key": key,
                "present": model_store.is_present(spec),
                "size": spec.size,
                "size_human": model_store.human_size(spec.size),
                "path": model_store.model_path(spec),
                "license": spec.license,
                "repo": spec.repo,
                "description": spec.description,
            }
        )
    return rows


def print_model_status(output_format: str) -> int:
    rows = model_status_rows()
    if output_format == "json":
        sys.stdout.write(json.dumps({"models_dir": model_store.models_dir(), "runtime": runtime.runtime_available(), "models": rows}, indent=2) + "\n")
        return 0
    if output_format == "plain":
        for row in rows:
            present = "yes" if row["present"] else "no"
            sys.stdout.write(f"{row['key']}\t{present}\t{row['size_human']}\t{row['path']}\t{row['license']}\n")
        return 0
    sys.stdout.write(colors.section("MODELS") + "\n")
    for row in rows:
        present = colors.green("yes") if row["present"] else colors.yellow("no ")
        sys.stdout.write(f"  {row['key']:<11} {present}  {row['size_human']:>7}  {row['path']}  {colors.dim(row['license'])}\n")
    if not runtime.runtime_available():
        sys.stdout.write(colors.dim(f"  runtime llama-cpp-python is not installed: {runtime.INSTALL_HINT}") + "\n")
    return 0


def pull_models(specs: List, output_format: str) -> int:
    results = []
    for spec in specs:
        path = model_store.model_path(spec)
        if model_store.is_present(spec):
            results.append({"key": spec.key, "ok": True, "path": path, "status": "present", "error": None})
            continue
        if output_format == "text":
            sys.stderr.write(f"Downloading {spec.filename} ({model_store.human_size(spec.size)})\n")
        progress = model_store.progress_bar(spec.filename) if output_format == "text" else None
        try:
            path = model_store.download(spec, progress=progress)
            results.append({"key": spec.key, "ok": True, "path": path, "status": "downloaded", "error": None})
        except Exception as exc:
            logger.debug(f"{type(exc).__name__}: {exc}\n{traceback.format_exc()}")
            clear_status()
            results.append({"key": spec.key, "ok": False, "path": path, "status": "failed", "error": f"{type(exc).__name__}: {exc}"})
    print_model_results(results, output_format)
    return 0 if all(result["ok"] for result in results) else 1


def remove_models(specs: List, output_format: str) -> int:
    results = []
    for spec in specs:
        removed = model_store.remove(spec)
        status = "removed" if removed else "absent"
        results.append({"key": spec.key, "ok": True, "path": model_store.model_path(spec), "status": status, "error": None})
    print_model_results(results, output_format)
    return 0


def print_model_results(results: List[dict], output_format: str) -> None:
    if output_format == "json":
        sys.stdout.write(json.dumps({"results": results}, indent=2) + "\n")
        return
    for result in results:
        if output_format == "plain":
            sys.stdout.write(f"{result['key']}\t{result['status']}\t{result['path']}\n")
        elif result["ok"]:
            sys.stdout.write(f"  {result['key']:<11} {colors.green(result['status'])}  {result['path']}\n")
        else:
            sys.stdout.write(f"  {result['key']:<11} {colors.red(result['status'])}  {result['error']}\n")


def cmd_model(args: argparse.Namespace) -> int:
    """`penguin-do --models | --pull | --rm`: status, download or removal of the dale model."""
    action = getattr(args, "action", None) or "status"
    output_format = getattr(args, "format", None) or "text"
    if action == "status":
        return print_model_status(output_format)
    specs = selected_models()
    if action == "pull":
        return pull_models(specs, output_format)
    return remove_models(specs, output_format)


def main():
    pass


if __name__ == "__main__":
    main()
