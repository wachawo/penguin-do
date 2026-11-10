#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Plain-language request to one bash command via a local model (dale or Qwen)."""

import json
import logging
import re
import shutil
import unicodedata
from dataclasses import dataclass
from typing import Callable, Optional

# Local imports
from penguin_do import i18n, model_store, runtime, shellrisk

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = (
    "Turn the request into one bash command for the Linux system described in the first line of the user message.\n"
    'Reply with only JSON {"type":"command|refuse|unsure","command":"...","explanation":"..."}: '
    '"command" is "" unless type is command; "explanation" is one short sentence in the language of the request.'
)

# dale was trained on SYSTEM_PROMPT; a general Qwen model copies its "command|refuse|unsure"
# literally, so it gets the contract spelled out with a few examples instead.
QWEN_SYSTEM_PROMPT = (
    "You turn a user's request into exactly one bash command for Linux.\n"
    "Answer with one line of JSON and nothing else, with exactly these keys:\n"
    '{"type": T, "command": C, "explanation": E}\n'
    'T is one of: "command" (you give a command), "refuse" (harmful or not a shell task), "unsure" (the request is unclear).\n'
    'C is the bash command, or "" when T is not "command".\n'
    "E is one short sentence that explains the command, written in the same language as the request.\n"
    "Examples:\n"
    'Request: how much free disk space\n{"type": "command", "command": "df -h", "explanation": "Shows free and used space on every mounted disk."}\n'
    'Request: show open ports\n{"type": "command", "command": "ss -tulpn", "explanation": "Lists listening TCP and UDP ports with their processes."}\n'
    'Request: tell me a joke\n{"type": "refuse", "command": "", "explanation": "This is not a shell task."}'
)
EMPTY_THINK = "<think>\n\n</think>\n\n"
CODE_FENCE_RE = re.compile(r"^```[a-zA-Z]*\s*\n?(.*?)\n?```$", re.DOTALL)

CONTEXT_TOOLS = (
    "fd", "fdfind", "rg", "bat", "batcat", "eza", "tree", "ncdu", "fzf", "jq", "yq",
    "zip", "unzip", "7z", "zstd", "xz", "unrar", "curl", "wget", "ip", "ss", "netstat",
    "nmcli", "dig", "nc", "nmap", "ssh", "rsync", "iptables", "nft", "ufw", "firewall-cmd",
    "systemctl", "journalctl", "lsof", "htop", "sudo", "doas", "hostnamectl", "timedatectl",
    "loginctl", "setfacl", "getfacl", "docker", "podman", "kubectl", "apt", "dnf", "yum",
    "pacman", "zypper", "apk", "flatpak", "snap", "git", "python3", "make", "gcc", "ffmpeg",
    "convert", "magick", "exiftool", "pdftotext",
)  # fmt: skip

PACKAGE_MANAGERS = ("apt", "dnf", "yum", "pacman", "zypper", "apk")

ANSWER_TYPES = ("command", "refuse", "unsure")
ANSWER_KEYS = {"type", "command", "explanation"}

MAX_REQUEST_BYTES = 1000
MAX_EXPLANATION_CHARS = 240
MAX_TOKENS = 200

# A 1-4 char unit repeated six or more times in a row (".0.0.0.0.0.0...");
# a plain IP address such as 10.0.0.0 repeats its unit only three times.
REPEATED_UNIT_RE = re.compile(r"(.{1,4}?)\1{5,}", re.DOTALL)
BIDI_CONTROLS = set("\u061c\u200e\u200f\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069")


@dataclass
class Answer:
    """One parsed model reply."""

    type: str
    command: str
    explanation: str


@dataclass
class Suggestion:
    """The outcome of one request: the answer plus what it took to get it."""

    request: str
    request_language: str
    model: str
    answer: Optional[Answer]
    explanation: str
    risk: Optional[shellrisk.Risk]


@dataclass
class Engine:
    """One loaded model: complete(prompt) -> text, and the spec that says how to prompt it."""

    spec: model_store.ModelSpec
    complete: Callable[[str], str]


def read_os_release(path: str) -> dict:
    """Parse KEY=VALUE lines of an os-release file; {} when unreadable."""
    fields = {}
    try:
        with open(path, encoding="utf-8", errors="replace") as handle:
            for line in handle:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, value = line.split("=", 1)
                fields[key.strip()] = value.strip().strip("\"'")
    except OSError:
        return {}
    return fields


def system_context(os_release_path: str = "/etc/os-release", which: Callable[[str], Optional[str]] = shutil.which) -> str:
    """Build the first line of the user message that describes this host."""
    fields = read_os_release(os_release_path)
    distro_id = fields.get("ID", "").lower()
    version_id = fields.get("VERSION_ID", "").lower()
    if distro_id and version_id:
        distro = f"{distro_id}-{version_id}"
    else:
        distro = distro_id or "unknown"
    found = [tool for tool in CONTEXT_TOOLS if which(tool)]
    package_manager = next((name for name in PACKAGE_MANAGERS if name in found), "none")
    tools = ",".join(sorted(found)) or "none"
    return f"os=linux distro={distro} pm={package_manager} tools={tools}"


def normalize_request(text: str) -> str:
    """Collapse whitespace and cut to MAX_REQUEST_BYTES of UTF-8 on a char boundary."""
    collapsed = " ".join(text.split())
    raw = collapsed.encode("utf-8")
    if len(raw) <= MAX_REQUEST_BYTES:
        return collapsed
    return raw[:MAX_REQUEST_BYTES].decode("utf-8", errors="ignore").rstrip()


def build_prompt(request: str, context: str) -> str:
    """The dale prompt, exactly as the model was trained on it."""
    return f"<|im_start|>system\n{SYSTEM_PROMPT}<|im_end|>\n<|im_start|>user\n{context}\n{normalize_request(request)}<|im_end|>\n<|im_start|>assistant\n{EMPTY_THINK}"


def build_qwen_prompt(request: str, context: str, think: bool) -> str:
    """The few-shot prompt for a general Qwen model; Qwen3 gets an empty think block so it answers at once."""
    tail = EMPTY_THINK if think else ""
    return f"<|im_start|>system\n{QWEN_SYSTEM_PROMPT}<|im_end|>\n<|im_start|>user\nSystem: {context}\nRequest: {normalize_request(request)}<|im_end|>\n<|im_start|>assistant\n{tail}"


def build_model_prompt(spec: model_store.ModelSpec, request: str, context: str) -> str:
    """The prompt `spec` expects."""
    if spec.prompt == "dale":
        return build_prompt(request, context)
    return build_qwen_prompt(request, context, think=spec.prompt == "qwen-think")


def strip_code_fence(text: str) -> str:
    """Unwrap a reply the model put in a ```json fence; anything else is returned as is."""
    stripped = text.strip()
    match = CODE_FENCE_RE.match(stripped)
    return match.group(1).strip() if match else stripped


def has_control_chars(text: str) -> bool:
    """True for control, format or unassigned characters (ESC, NUL, newline, bidi overrides, ...); a tab is allowed."""
    return any(char != "\t" and unicodedata.category(char).startswith("C") for char in text)


def clean_explanation(text: str) -> str:
    """Blank out terminal control characters, collapse degenerate repeats and clip to MAX_EXPLANATION_CHARS.

    Only Cc and bidi controls go: zero-width joiners are part of Hindi and other scripts.
    """
    printable = "".join(" " if unicodedata.category(char) == "Cc" or char in BIDI_CONTROLS else char for char in text)
    collapsed = REPEATED_UNIT_RE.sub(r"\1", printable.strip())
    if len(collapsed) > MAX_EXPLANATION_CHARS:
        return collapsed[:MAX_EXPLANATION_CHARS].rstrip() + "..."
    return collapsed


def parse_answer(text: str) -> Optional[Answer]:
    """Parse one model reply; None unless it follows the contract exactly."""
    try:
        data = json.loads(text.strip())
    except (ValueError, AttributeError):
        return None
    if not isinstance(data, dict) or set(data) != ANSWER_KEYS:
        return None
    if not all(isinstance(data[key], str) for key in ANSWER_KEYS):
        return None
    answer_type = data["type"]
    raw_command = data["command"]
    command = raw_command.strip()
    if answer_type not in ANSWER_TYPES:
        return None
    if answer_type == "command":
        # An ESC sequence could hide part of the command from the user who is asked to run it.
        if not command or has_control_chars(raw_command):
            return None
    elif raw_command != "":
        return None
    return Answer(type=answer_type, command=command, explanation=clean_explanation(data["explanation"]))


def ask_model(engine: Engine, request: str, context: str) -> Optional[Answer]:
    """One model round trip."""
    reply = engine.complete(build_model_prompt(engine.spec, request, context))
    return parse_answer(strip_code_fence(reply))


def suggest(request: str, spec: model_store.ModelSpec = model_store.DEFAULT_MODEL, engine: Optional[Engine] = None) -> Suggestion:
    """Ask the model for one command and rate its risk."""
    if engine is None:
        engine = make_engine(spec)
    text = normalize_request(request)
    language = i18n.detect_language(text)
    answer = ask_model(engine, text, system_context())
    explanation = answer.explanation if answer is not None else ""
    risk = shellrisk.classify(answer.command) if answer is not None and answer.type == "command" else None
    return Suggestion(
        request=text,
        request_language=language,
        model=engine.spec.key,
        answer=answer,
        explanation=explanation,
        risk=risk,
    )


def make_engine(
    spec: model_store.ModelSpec,
    load: Callable = runtime.load_model,
    generate: Callable = runtime.generate,
    path_of: Callable = model_store.model_path,
) -> Engine:
    """Production engine for `spec`: the model is loaded on first use."""

    def complete(prompt: str) -> str:
        return generate(load(path_of(spec)), prompt, MAX_TOKENS, stop=runtime.DEFAULT_STOP)

    return Engine(spec=spec, complete=complete)


def main():
    pass


if __name__ == "__main__":
    main()
