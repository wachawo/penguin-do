#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Static risk rating of a shell command line: text analysis only, nothing is ever run."""

import logging
import posixpath
import re
import traceback
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Sequence, Set, Tuple

logger = logging.getLogger(__name__)

SAFE = "safe"
CAUTION = "caution"
DANGER = "danger"
LEVEL_RANK = {SAFE: 0, CAUTION: 1, DANGER: 2}
MAX_DEPTH = 8
MAX_WRAPPERS = 16
MAX_NAME_LEN = 40

Finding = Tuple[str, str]
Options = List[Tuple[str, Optional[str]]]

CONTROL_OPERATORS = ("&&", "||", ";;", ";&", "|&", "|", "&", ";", "\n", "(", ")")
REDIRECT_OPERATORS = ("&>>", "&>", ">>", ">|", ">&", "<<<", "<<-", "<<", "<&", "<>", ">", "<")
WRITE_REDIRECTS = {">", ">>", ">|", "&>", "&>>", ">&", "<>"}
APPEND_REDIRECTS = {">>", "&>>"}
SAFE_SINKS = {"/dev/null", "/dev/stdout", "/dev/stderr", "/dev/tty", "/dev/zero"}
FD_TARGET_RE = re.compile(r"^(\d+|-)$")
ASSIGNMENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(\[[^\]]*\])?\+?=")
FORK_BOMB_RE = re.compile(r"([\w:.-]+)\s*\(\s*\)\s*\{[^}]*?\1\s*\|\s*&?\s*\1")
DOWNLOAD_RE = re.compile(r"\b(curl|wget|fetch)\b")
BLOCK_DEVICE_RE = re.compile(r"^/dev/(sd[a-z]|hd[a-z]|vd[a-z]|xvd[a-z]|nvme\d|mmcblk\d|md\d|dm-\d|mapper/|disk/)")
TRAILING_GLOB_RE = re.compile(r"(/\*|/\.\*|/\.)+/*$")
HOME_RE = re.compile(r"^(~[\w.-]*|\$HOME|\$\{HOME\})$")
INTERPRETER_RE = re.compile(r"^(python|perl|ruby|node|nodejs|php|lua)[\d.]*$")
BACKUP_NAME_RE = re.compile(r"(\.(bak|orig|old|backup|save|dist|copy|new|tmp|\d+)|~)$")
AWK_STRING_RE = re.compile(r'"(\\.|[^"\\])*"')
AWK_GROUP_RE = re.compile(r"\([^()]*\)")
SYSRQ_TRIGGER = "/proc/sysrq-trigger"

SHELL_KEYWORDS = {"!", "{", "}", "then", "do", "else", "elif", "if", "while", "until", "fi", "done", "esac"}
STRUCTURAL_KEYWORDS = {"for", "select", "case", "function", "in"}
SHELLS = {"sh", "bash", "zsh", "dash", "ksh", "mksh", "ash", "fish", "csh", "tcsh"}
DOWNLOADERS = {"curl", "wget", "fetch"}
ROOT_USERS = {"root", "0", "#0"}

SYSTEM_DIRS = {
    "bin",
    "boot",
    "dev",
    "etc",
    "home",
    "lib",
    "lib32",
    "lib64",
    "libx32",
    "media",
    "mnt",
    "opt",
    "proc",
    "root",
    "run",
    "sbin",
    "snap",
    "srv",
    "sys",
    "tmp",
    "usr",
    "var",
}
SYSTEM_SUBDIRS = {
    "/usr/bin",
    "/usr/sbin",
    "/usr/lib",
    "/usr/lib32",
    "/usr/lib64",
    "/usr/libexec",
    "/usr/local",
    "/usr/share",
    "/usr/include",
    "/var/lib",
    "/var/log",
    "/var/spool",
    "/var/cache",
    "/var/mail",
}
SYSTEM_FILE_DIRS = ("/etc", "/boot", "/usr", "/bin", "/sbin", "/lib", "/lib32", "/lib64")

SAFE_COMMANDS = {
    "ls",
    "cat",
    "head",
    "tail",
    "less",
    "more",
    "grep",
    "egrep",
    "fgrep",
    "zgrep",
    "zcat",
    "rg",
    "fd",
    "fdfind",
    "du",
    "df",
    "free",
    "ps",
    "pgrep",
    "pstree",
    "top",
    "htop",
    "uptime",
    "w",
    "who",
    "whoami",
    "id",
    "groups",
    "uname",
    "cal",
    "wc",
    "uniq",
    "cut",
    "tr",
    "stat",
    "file",
    "which",
    "whereis",
    "type",
    "printenv",
    "lsblk",
    "lscpu",
    "lsmem",
    "lspci",
    "lsusb",
    "lsof",
    "lsmod",
    "lslocks",
    "lsns",
    "netstat",
    "findmnt",
    "dig",
    "host",
    "nslookup",
    "tree",
    "echo",
    "printf",
    "pwd",
    "nproc",
    "vmstat",
    "iostat",
    "mpstat",
    "sar",
    "basename",
    "dirname",
    "realpath",
    "readlink",
    "md5sum",
    "sha1sum",
    "sha256sum",
    "sha512sum",
    "b2sum",
    "cksum",
    "diff",
    "cmp",
    "jq",
    "yq",
    "column",
    "numfmt",
    "seq",
    "test",
    "[",
    "[[",
    "true",
    "false",
    ":",
    "sleep",
    "bat",
    "batcat",
    "eza",
    "exa",
    "ncdu",
    "cd",
    "pushd",
    "popd",
    "dirs",
    "export",
    "alias",
    "unalias",
    "man",
    "help",
    "getent",
    "locale",
    "tty",
    "arch",
    "od",
    "hexdump",
    "xxd",
    "strings",
    "nl",
    "fold",
    "fmt",
    "rev",
    "tac",
    "paste",
    "join",
    "comm",
    "expand",
    "unexpand",
    "last",
    "lastlog",
    "blkid",
    "getconf",
    "sensors",
    "apt-cache",
    "dpkg-query",
    "history",
    "jobs",
    "wait",
    "lsb_release",
    "hostid",
    "getfacl",
    "lsattr",
    "ldd",
    "locate",
    "plocate",
    "mlocate",
    "whois",
    "traceroute",
    "tracepath",
    "mtr",
    "ulimit",
    "umask",
}

NOTED_COMMANDS = {
    "curl": "network access",
    "wget": "network access",
    "tar": "creates or extracts archives",
    "zip": "creates or extracts archives",
    "unzip": "creates or extracts archives",
    "gzip": "compresses files in place",
    "gunzip": "decompresses files in place",
    "bzip2": "compresses files in place",
    "xz": "compresses files in place",
    "unxz": "decompresses files in place",
    "zstd": "compresses files",
    "7z": "creates or extracts archives",
    "unrar": "extracts archives",
    "scp": "copies files over the network",
    "sftp": "connects to a remote host",
    "telnet": "connects to a remote host",
    "nc": "opens a network connection",
    "ncat": "opens a network connection",
    "netcat": "opens a network connection",
    "socat": "opens a network connection",
    "nmap": "scans the network",
    "make": "builds software",
    "cmake": "builds software",
    "gcc": "builds software",
    "cc": "builds software",
    "ffmpeg": "writes media files",
    "convert": "writes media files",
    "magick": "writes media files",
    "exiftool": "may rewrite file metadata",
    "vi": "opens an editor",
    "vim": "opens an editor",
    "nano": "opens an editor",
    "emacs": "opens an editor",
    "modprobe": "changes kernel modules",
    "insmod": "changes kernel modules",
    "rmmod": "changes kernel modules",
    "at": "schedules a command",
    "npx": "runs a package from the network",
    "useradd": "changes users or groups",
    "adduser": "changes users or groups",
    "usermod": "changes users or groups",
    "groupadd": "changes users or groups",
    "groupmod": "changes users or groups",
    "groupdel": "changes users or groups",
    "gpasswd": "changes users or groups",
    "chsh": "changes users or groups",
    "chfn": "changes users or groups",
    "chage": "changes users or groups",
    "ln": "creates links",
    "mkdir": "creates directories",
    "touch": "creates or updates files",
    "rmdir": "removes directories",
    "unlink": "deletes files",
    "pkill": "kills processes",
    "killall": "kills processes",
    "umount": "unmounts a filesystem",
    "swapoff": "disables swap",
}

DANGER_COMMANDS = {
    "wipefs": "wipes filesystem signatures",
    "shred": "shreds files",
    "mkswap": "formats a swap area",
    "killall5": "kills every process",
    "userdel": "deletes a user",
    "deluser": "deletes a user",
    "passwd": "changes a password",
    "chpasswd": "changes passwords",
    "poweroff": "shuts down or reboots the machine",
    "reboot": "shuts down or reboots the machine",
    "halt": "shuts down or reboots the machine",
    "blkdiscard": "discards every block on a device",
    "mkntfs": "creates a filesystem",
    "mkdosfs": "creates a filesystem",
    "mkexfatfs": "creates a filesystem",
    "mkfatfs": "creates a filesystem",
    "lvremove": "deletes a logical volume",
    "vgremove": "deletes a volume group",
    "pvremove": "wipes an LVM physical volume",
}

# Disk tools whose listed subcommands or flags destroy data; anything else they do needs care.
DISK_TOOL_SUBCOMMANDS = {
    "cryptsetup": ({"luksformat", "erase", "lukserase", "reencrypt"}, "formats or erases an encrypted volume"),
    "zpool": ({"destroy", "labelclear"}, "destroys a ZFS pool"),
    "zfs": ({"destroy"}, "destroys a ZFS dataset"),
    "nvme": ({"format", "sanitize"}, "erases an NVMe drive"),
}
DISK_TOOL_FLAGS = {
    "hdparm": ({"--security-erase", "--security-erase-enhanced", "--trim-sector-ranges", "--trim-sector-ranges-stdin"}, "erases a drive"),
    "badblocks": ({"-w"}, "overwrites the whole device"),
    "mdadm": ({"--zero-superblock"}, "wipes RAID metadata"),
}

PARTITION_TOOLS = {"fdisk", "cfdisk", "sfdisk", "gdisk", "sgdisk", "cgdisk", "parted"}
PARTITION_READ_FLAGS = {"-l", "--list", "-p", "--print", "-d", "--dump", "-s", "--show-size"}

SYSTEMCTL_SAFE = {
    "status",
    "list-units",
    "list-unit-files",
    "list-timers",
    "list-sockets",
    "list-jobs",
    "list-dependencies",
    "list-machines",
    "list-automounts",
    "list-paths",
    "is-active",
    "is-enabled",
    "is-failed",
    "is-system-running",
    "show",
    "cat",
    "help",
    "get-default",
    "show-environment",
}
SYSTEMCTL_POWER = {"poweroff", "reboot", "halt", "kexec", "soft-reboot"}

PACKAGE_ALIASES = {"pip3": "pip", "yum": "dnf", "microdnf": "dnf", "pnpm": "yarn", "aptitude": "apt", "apt-get": "apt"}
PACKAGE_READ_VERBS = {
    "apt": {"list", "search", "show", "showsrc", "policy", "depends", "rdepends", "madison", "changelog", "help", "moo", "check", "why", "why-not", "versions"},
    "dnf": {"list", "info", "search", "provides", "whatprovides", "repolist", "repoquery", "repoinfo", "history", "check-update", "deplist", "help", "updateinfo"},
    "zypper": {
        "search",
        "se",
        "info",
        "if",
        "list-updates",
        "lu",
        "list-patches",
        "lp",
        "patches",
        "repos",
        "lr",
        "packages",
        "pa",
        "products",
        "pd",
        "what-provides",
        "wp",
        "help",
        "locks",
        "ll",
    },
    "apk": {"info", "search", "list", "policy", "stats", "dot", "version", "help"},
    "snap": {"list", "info", "find", "search", "version", "changes", "change", "connections", "services", "warnings", "known", "help", "interfaces", "logs", "aliases"},
    "flatpak": {"list", "info", "search", "remotes", "remote-ls", "remote-info", "history", "ps", "help"},
    "pip": {"list", "show", "freeze", "check", "search", "help", "inspect", "index", "debug"},
    "pipx": {"list", "environment", "help"},
    "npm": {"ls", "list", "ll", "la", "view", "info", "show", "v", "outdated", "search", "s", "help", "doctor", "explain", "why", "root", "prefix", "query", "fund"},
    "yarn": {"list", "ls", "info", "why", "outdated", "help"},
    "gem": {"list", "search", "info", "help", "query", "contents", "environment", "specification", "which", "outdated", "dependency"},
    "brew": {"list", "ls", "info", "search", "outdated", "deps", "uses", "leaves", "config", "doctor", "help", "home", "desc", "commands"},
}
PACKAGE_ARG_SHORT = {"apt": "otc", "dnf": "c", "pip": "r", "zypper": "", "apk": "X", "npm": "", "yarn": ""}

DOCKER_GROUPS = {"container", "image", "network", "volume", "system", "compose", "builder", "buildx", "context", "plugin", "node", "service", "stack"}
DOCKER_SAFE = {
    "ps",
    "images",
    "logs",
    "inspect",
    "stats",
    "top",
    "version",
    "info",
    "df",
    "port",
    "diff",
    "history",
    "events",
    "search",
    "container ls",
    "container list",
    "container ps",
    "container logs",
    "container inspect",
    "container stats",
    "container top",
    "container port",
    "container diff",
    "image ls",
    "image list",
    "image inspect",
    "image history",
    "network ls",
    "network list",
    "network inspect",
    "volume ls",
    "volume list",
    "volume inspect",
    "system df",
    "system info",
    "system events",
    "compose ps",
    "compose logs",
    "compose ls",
    "compose config",
    "compose top",
    "compose images",
    "compose version",
    "context ls",
    "context show",
    "context inspect",
    "buildx ls",
    "compose",
    "system",
}

GIT_SAFE = {
    "status",
    "log",
    "diff",
    "show",
    "blame",
    "shortlog",
    "describe",
    "rev-parse",
    "rev-list",
    "ls-files",
    "ls-tree",
    "ls-remote",
    "grep",
    "whatchanged",
    "cat-file",
    "show-ref",
    "name-rev",
    "help",
    "version",
    "count-objects",
    "for-each-ref",
    "merge-base",
    "cherry",
    "range-diff",
    "annotate",
    "diff-tree",
    "diff-files",
    "diff-index",
    "var",
    "check-ignore",
    "check-attr",
    "verify-commit",
    "verify-tag",
}
GIT_BRANCH_WRITE = {
    "-d",
    "-D",
    "-m",
    "-M",
    "-c",
    "-C",
    "--delete",
    "--move",
    "--copy",
    "-u",
    "--set-upstream-to",
    "--unset-upstream",
    "-f",
    "--force",
    "--edit-description",
    "-t",
    "--track",
}
GIT_CONFIG_READ = {"--get", "--get-all", "--get-regexp", "--list", "-l", "--show-origin", "--show-scope"}
GIT_CONFIG_WRITE = {"--unset", "--unset-all", "--add", "--replace-all", "--rename-section", "--remove-section", "-e", "--edit"}

VERB_TOOLS = {
    "loginctl": (
        {"list-sessions", "list-users", "list-seats", "session-status", "user-status", "seat-status", "show-session", "show-user", "show-seat", "help"},
        "changes login sessions",
    ),
    "kubectl": (
        {"get", "describe", "logs", "top", "explain", "version", "api-resources", "api-versions", "cluster-info", "config", "auth", "diff", "events", "help", "completion"},
        "changes the Kubernetes cluster",
    ),
    "resolvectl": (
        {"status", "query", "statistics", "service", "openpgp", "tlsa", "monitor", "show-cache", "show-server-state", "help"},
        "changes DNS settings",
    ),
    "nmcli": (set(), "changes network configuration"),
}
VERB_TOOL_ARG_SHORT = {"kubectl": "nlcos", "nmcli": "fgem"}
NMCLI_CHANGE_WORDS = {"up", "down", "delete", "add", "modify", "connect", "disconnect", "reload", "on", "off", "edit", "import", "clone", "set-hostname", "load"}

IP_CHANGE_VERBS = {"add", "del", "delete", "set", "flush", "change", "replace", "append", "prepend", "exec", "save", "restore", "attach", "detach"}
FIND_EXEC = {"-exec", "-execdir", "-ok", "-okdir"}
FIND_WRITES = {"-fprint", "-fprint0", "-fprintf", "-fls"}
FIND_NAME_TESTS = {"-name", "-iname", "-path", "-ipath", "-wholename", "-iwholename", "-regex", "-iregex", "-lname", "-ilname"}
DELETING_COMMANDS = {"rm", "unlink", "shred"}
FIND_GLOBAL_OPTIONS = {
    "-maxdepth",
    "-mindepth",
    "-depth",
    "-xdev",
    "-mount",
    "-follow",
    "-noleaf",
    "-ignore_readdir_race",
    "-noignore_readdir_race",
    "-regextype",
    "-warn",
    "-nowarn",
    "-daystart",
    "-print",
    "-print0",
    "-H",
    "-L",
    "-P",
}
SWAPON_READ = {"--show", "-s", "--summary", "--noheadings", "--bytes", "--raw", "-h", "--help", "-V", "--version"}
CHMOD_FLAGS = {"-c", "-f", "-v", "-R", "--changes", "--silent", "--quiet", "--verbose", "--recursive", "--preserve-root", "--no-preserve-root", "--help", "--version"}


@dataclass
class Risk:
    """Risk rating of a command line: level is safe, caution or danger; reasons are short English phrases."""

    level: str
    reasons: List[str] = field(default_factory=list)


@dataclass
class Token:
    """One lexical unit: a word, a control operator or a redirection operator."""

    kind: str
    value: str
    substitutions: List[str] = field(default_factory=list)
    body: Optional[str] = None


@dataclass
class SimpleCommand:
    """Words of one simple command plus its redirections and the command substitutions inside it."""

    words: List[str] = field(default_factory=list)
    redirects: List[Tuple[str, str, Optional[str]]] = field(default_factory=list)
    substitutions: List[str] = field(default_factory=list)


@dataclass
class LexState:
    """Mutable cursor over the command text used by the lexer functions."""

    text: str
    pos: int = 0
    tokens: List[Token] = field(default_factory=list)
    chars: List[str] = field(default_factory=list)
    started: bool = False
    substitutions: List[str] = field(default_factory=list)
    balanced: bool = True
    heredocs: List[Token] = field(default_factory=list)


def shorten(text: str) -> str:
    """Make user text safe to quote inside a one-line reason."""
    flat = " ".join(str(text).split())
    if len(flat) > MAX_NAME_LEN:
        return flat[: MAX_NAME_LEN - 3] + "..."
    return flat


def command_name(word: str) -> str:
    """Program name of a command word (`/usr/bin/rm` -> `rm`)."""
    if "/" in word and "$" not in word and "`" not in word:
        return posixpath.basename(word)
    return word


def flush_word(state: LexState) -> None:
    """Close the word being built, if any, and remember heredoc delimiters."""
    if not state.started:
        return
    token = Token("word", "".join(state.chars), state.substitutions)
    if state.tokens and state.tokens[-1].kind == "redir" and state.tokens[-1].value in ("<<", "<<-"):
        state.heredocs.append(token)
    state.tokens.append(token)
    state.chars = []
    state.started = False
    state.substitutions = []


def skip_quoted(text: str, start: int) -> int:
    """Index just past the quoted run that opens at text[start], or -1 when it never closes."""
    quote = text[start]
    index = start + 1
    while index < len(text):
        char = text[index]
        if char == "\\" and quote != "'":
            index += 2
            continue
        if char == quote:
            return index + 1
        index += 1
    return -1


def read_balanced(text: str, start: int) -> Tuple[str, int, bool]:
    """Read up to the parenthesis that closes an already opened one: (inner text, next index, closed)."""
    depth = 1
    index = start
    while index < len(text):
        char = text[index]
        if char == "\\":
            index += 2
            continue
        if char in "'\"`":
            end = skip_quoted(text, index)
            if end < 0:
                return text[start:], len(text), False
            index = end
            continue
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                return text[start:index], index + 1, True
        index += 1
    return text[start:], len(text), False


def lex_backslash(state: LexState) -> None:
    """Backslash outside quotes: escape the next character, or join a continued line."""
    text = state.text
    if state.pos + 1 < len(text):
        if text[state.pos + 1] != "\n":
            state.chars.append(text[state.pos + 1])
            state.started = True
        state.pos += 2
        return
    state.pos += 1


def lex_single(state: LexState) -> None:
    """Single-quoted run: everything literal up to the next single quote."""
    text = state.text
    end = text.find("'", state.pos + 1)
    state.started = True
    if end < 0:
        state.balanced = False
        state.chars.append(text[state.pos + 1 :])
        state.pos = len(text)
        return
    state.chars.append(text[state.pos + 1 : end])
    state.pos = end + 1


def lex_double(state: LexState) -> None:
    """Double-quoted run: literal except for escapes, `$(...)`, `${...}` and backticks."""
    text = state.text
    state.pos += 1
    state.started = True
    while state.pos < len(text):
        char = text[state.pos]
        if char == '"':
            state.pos += 1
            return
        if char == "\\" and state.pos + 1 < len(text) and text[state.pos + 1] in '$`"\\\n':
            if text[state.pos + 1] != "\n":
                state.chars.append(text[state.pos + 1])
            state.pos += 2
        elif char == "`":
            lex_backtick(state)
        elif char == "$":
            lex_dollar(state)
        else:
            state.chars.append(char)
            state.pos += 1
    state.balanced = False


def lex_backtick(state: LexState) -> None:
    """Backtick command substitution."""
    text = state.text
    index = state.pos + 1
    while index < len(text) and text[index] != "`":
        index += 2 if text[index] == "\\" else 1
    if index >= len(text):
        state.balanced = False
        inner = text[state.pos + 1 :]
        state.pos = len(text)
    else:
        inner = text[state.pos + 1 : index]
        state.pos = index + 1
    state.substitutions.append(inner)
    state.chars.append("`" + inner + "`")
    state.started = True


def lex_dollar(state: LexState) -> None:
    """`$(...)`, `$((...))`, `${...}` or a plain dollar sign."""
    text = state.text
    following = text[state.pos + 1 : state.pos + 2]
    state.started = True
    if following == "(":
        inner, end, closed = read_balanced(text, state.pos + 2)
        if not closed:
            state.balanced = False
        arithmetic = inner.startswith("(") and inner.endswith(")")
        if not arithmetic or re.search(r"[;|&`]|\$\(|\s-\w", inner):
            state.substitutions.append(inner)
        state.chars.append("$(" + inner + ")")
        state.pos = end
    elif following == "{":
        end = text.find("}", state.pos + 2)
        if end < 0:
            state.balanced = False
            end = len(text) - 1
        content = text[state.pos + 2 : end]
        if "$(" in content or "`" in content:
            inner_tokens, unused_balanced = lex(content)
            for token in inner_tokens:
                state.substitutions.extend(token.substitutions)
        state.chars.append(text[state.pos : end + 1])
        state.pos = end + 1
    else:
        state.chars.append("$")
        state.pos += 1


def lex_heredoc_bodies(state: LexState) -> None:
    """After a newline, consume the bodies of pending heredocs and attach them to their delimiters."""
    text = state.text
    for delimiter in state.heredocs:
        lines = []
        while state.pos < len(text):
            end = text.find("\n", state.pos)
            line = text[state.pos :] if end < 0 else text[state.pos : end]
            state.pos = len(text) if end < 0 else end + 1
            if line.strip() == delimiter.value:
                break
            lines.append(line)
        delimiter.body = "\n".join(lines)
    state.heredocs = []


def lex_operator(state: LexState) -> None:
    """Control operators, redirections and process substitution."""
    text = state.text
    char = text[state.pos]
    if char in "<>" and text[state.pos + 1 : state.pos + 2] == "(":
        inner, end, closed = read_balanced(text, state.pos + 2)
        state.balanced = state.balanced and closed
        state.substitutions.append(inner)
        state.chars.append(char + "(" + inner + ")")
        state.started = True
        state.pos = end
        return
    if char in "<>" or text.startswith("&>", state.pos):
        if state.started and "".join(state.chars).isdigit() and not state.substitutions:
            state.chars = []
            state.started = False
        flush_word(state)
        operator = next(op for op in REDIRECT_OPERATORS if text.startswith(op, state.pos))
        state.tokens.append(Token("redir", operator))
        state.pos += len(operator)
        return
    flush_word(state)
    operator = next(op for op in CONTROL_OPERATORS if text.startswith(op, state.pos))
    state.tokens.append(Token("op", operator))
    state.pos += len(operator)
    if operator == "\n" and state.heredocs:
        lex_heredoc_bodies(state)


def lex(text: str) -> Tuple[List[Token], bool]:
    """Split a command line into tokens; the flag is False when quotes or brackets never close."""
    state = LexState(text)
    handlers: Dict[str, Callable[[LexState], None]] = {
        "\\": lex_backslash,
        "'": lex_single,
        '"': lex_double,
        "`": lex_backtick,
        "$": lex_dollar,
    }
    while state.pos < len(text):
        char = text[state.pos]
        if char in handlers:
            handlers[char](state)
        elif char in " \t\r":
            flush_word(state)
            state.pos += 1
        elif char == "#" and not state.started:
            end = text.find("\n", state.pos)
            state.pos = len(text) if end < 0 else end
        elif char in "\n;&|()<>":
            lex_operator(state)
        else:
            state.chars.append(char)
            state.started = True
            state.pos += 1
    flush_word(state)
    return state.tokens, state.balanced


def parse(tokens: Sequence[Token]) -> List[List[SimpleCommand]]:
    """Group tokens into pipelines of simple commands."""
    pipelines: List[List[SimpleCommand]] = []
    pipeline: List[SimpleCommand] = []
    current = SimpleCommand()
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if token.kind == "word":
            current.words.append(token.value)
            current.substitutions.extend(token.substitutions)
        elif token.kind == "redir":
            target = tokens[index + 1] if index + 1 < len(tokens) and tokens[index + 1].kind == "word" else None
            if target is None:
                current.redirects.append((token.value, "", None))
            else:
                current.redirects.append((token.value, target.value, target.body))
                current.substitutions.extend(target.substitutions)
                index += 1
        elif token.value in ("|", "|&"):
            pipeline.append(current)
            current = SimpleCommand()
        else:
            pipeline.append(current)
            pipelines.append(pipeline)
            pipeline = []
            current = SimpleCommand()
        index += 1
    pipeline.append(current)
    pipelines.append(pipeline)
    return [[cmd for cmd in group if cmd.words or cmd.redirects or cmd.substitutions] for group in pipelines]


def expand_short(arg: str, args: Sequence[str], index: int, short_with_arg: str, options: Options) -> int:
    """Expand a short-option cluster such as `-rf` or `-uroot`; return the index of the next argument."""
    for position in range(1, len(arg)):
        letter = arg[position]
        if letter in short_with_arg:
            rest = arg[position + 1 :]
            if rest:
                options.append(("-" + letter, rest))
                return index + 1
            options.append(("-" + letter, args[index + 1] if index + 1 < len(args) else ""))
            return index + 2
        options.append(("-" + letter, None))
    return index + 1


def split_options(args: Sequence[str], short_with_arg: str = "", long_with_arg: Sequence[str] = (), stop_at_operand: bool = False) -> Tuple[Options, List[str]]:
    """Split getopt-style arguments into (option, value) pairs and operands."""
    options: Options = []
    operands: List[str] = []
    index = 0
    while index < len(args):
        arg = args[index]
        if arg == "--":
            operands.extend(args[index + 1 :])
            break
        if arg.startswith("--"):
            name, separator, value = arg.partition("=")
            if not separator and name in long_with_arg:
                value = args[index + 1] if index + 1 < len(args) else ""
                index += 1
            options.append((name, value if separator or name in long_with_arg else None))
            index += 1
        elif arg.startswith("-") and len(arg) > 1:
            index = expand_short(arg, args, index, short_with_arg, options)
        elif stop_at_operand:
            operands.extend(args[index:])
            break
        else:
            operands.append(arg)
            index += 1
    return options, operands


def option_names(options: Options) -> Set[str]:
    """Names of the options seen, without values."""
    return {name for name, unused_value in options}


def option_value(options: Options, *names: str) -> Optional[str]:
    """Value of the last occurrence of any of the given options."""
    found = None
    for name, value in options:
        if name in names:
            found = value
    return found


def normalize_path(target: str) -> str:
    """Canonical form of a path operand: trailing `/`, `/*` and `/.` removed, `..` resolved."""
    path = target.strip()
    absolute = path.startswith("/")
    path = TRAILING_GLOB_RE.sub("", path)
    if absolute:
        path = posixpath.normpath("/" + path.lstrip("/"))
    elif path:
        path = path.rstrip("/") or path
    return path


def is_home(path: str) -> bool:
    """True for `~`, `~user`, `$HOME` and their trailing-slash or glob forms."""
    return bool(HOME_RE.match(normalize_path(path)))


def is_system_path(target: str) -> bool:
    """True for `/`, a top-level system directory or a key second-level one."""
    path = normalize_path(target)
    if path == "/":
        return True
    if path.startswith("/") and path.count("/") == 1 and path[1:] in SYSTEM_DIRS:
        return True
    return path in SYSTEM_SUBDIRS


def is_critical_target(target: str) -> bool:
    """Targets whose recursive or forced removal wipes far more than a single project."""
    path = normalize_path(target)
    if path in ("*", ".", "..", ".*"):
        return True
    return is_home(path) or is_system_path(path)


def is_block_device(target: str) -> bool:
    """True for a raw disk or partition node such as /dev/sda or /dev/nvme0n1p1."""
    return bool(BLOCK_DEVICE_RE.match(target.strip()))


def is_system_file(target: str) -> bool:
    """True for a path inside directories whose files must not be truncated."""
    path = normalize_path(target)
    return any(path == directory or path.startswith(directory + "/") for directory in SYSTEM_FILE_DIRS)


def is_outside_project(target: str) -> bool:
    """True for an absolute path, a path under the home directory or one that climbs out with `..`."""
    path = target.strip()
    if path.startswith(("/", "~", "$HOME", "${HOME}")):
        return True
    return ".." in path.split("/")


def overwrites_system_file(destination: str, into_directory: bool) -> bool:
    """True when copying, moving or linking onto `destination` replaces a file under /etc, /usr, /boot and the like."""
    if into_directory or not destination or destination.endswith("/"):
        return False
    path = normalize_path(destination)
    if path in SYSTEM_FILE_DIRS or is_system_path(path) or BACKUP_NAME_RE.search(path):
        return False
    return is_system_file(path)


def is_interpreter(name: str) -> bool:
    """True for shells and script interpreters that execute what they read."""
    return name in SHELLS or bool(INTERPRETER_RE.match(name))


def has_download_substitution(args: Sequence[str]) -> bool:
    """True when an argument substitutes the output of a download (`$(curl ...)`, `<(wget ...)`)."""
    return any(("$(" in arg or "`" in arg or "<(" in arg) and DOWNLOAD_RE.search(arg) for arg in args)


def write_target_findings(targets: Sequence[str], truncates: bool) -> List[Finding]:
    """Rate writing to each of the given files."""
    findings: List[Finding] = []
    for target in targets:
        if target in SAFE_SINKS or target.startswith("/dev/fd/"):
            continue
        if is_block_device(target):
            findings.append((DANGER, f"writes to the raw disk '{shorten(target)}'"))
        elif normalize_path(target) == SYSRQ_TRIGGER:
            findings.append((DANGER, "reboots or crashes the machine"))
        elif truncates and is_system_file(target):
            findings.append((DANGER, f"overwrites the system file '{shorten(target)}'"))
        else:
            findings.append((CAUTION, "writes to a file"))
    return findings


def classify_redirects(redirects: Sequence[Tuple[str, str, Optional[str]]]) -> List[Finding]:
    """Rate output redirections of one simple command."""
    findings: List[Finding] = []
    for redirect in redirects:
        operator, target = redirect[0], redirect[1]
        if operator not in WRITE_REDIRECTS:
            continue
        if operator == ">&" and FD_TARGET_RE.match(target):
            continue
        findings.extend(write_target_findings([target], operator not in APPEND_REDIRECTS and operator != "<>"))
    return findings


def strip_prefix_words(words: Sequence[str]) -> List[str]:
    """Drop shell keywords and variable assignments in front of the command name."""
    index = 0
    while index < len(words) and words[index] in SHELL_KEYWORDS:
        index += 1
    remaining = list(words[index:])
    if remaining and remaining[0] == "function":
        body = remaining[2:]
        if body and body[0] == "()":
            body = body[1:]
        return strip_prefix_words(body) if body else []
    if remaining and remaining[0] in STRUCTURAL_KEYWORDS:
        return []
    while remaining and ASSIGNMENT_RE.match(remaining[0]):
        remaining = remaining[1:]
    return remaining


def unwrap_root(name: str, args: Sequence[str]) -> Tuple[List[str], List[Finding]]:
    """sudo / doas / pkexec / run0: the wrapped command plus the privilege finding."""
    if name == "sudoedit":
        return [], [(CAUTION, "edits files as root")]
    short = {"sudo": "ugCDhprtTU", "doas": "uC", "run0": "uDM"}.get(name, "")
    long_with_arg = ("--user", "--group", "--close-from", "--chdir", "--host", "--prompt", "--role", "--type", "--command-timeout", "--other-user")
    options, operands = split_options(args, short, long_with_arg, stop_at_operand=True)
    flags = option_names(options)
    user = option_value(options, "-u", "--user")
    reason = "runs as root" if user is None or user in ROOT_USERS else f"runs as user '{shorten(user)}'"
    findings: List[Finding] = [(CAUTION, reason)]
    if "-e" in flags or "--edit" in flags:
        return [], findings + [(CAUTION, "edits files as root")]
    if not operands and flags & {"-i", "-s", "--login", "--shell"}:
        findings.append((CAUTION, "opens a root shell"))
    while operands and ASSIGNMENT_RE.match(operands[0]):
        operands = operands[1:]
    return operands, findings


def unwrap_env(args: Sequence[str]) -> List[str]:
    """env [options] [NAME=VALUE...] command."""
    options, operands = split_options(args, "uCS", ("--unset", "--chdir", "--split-string"), stop_at_operand=True)
    while operands and ASSIGNMENT_RE.match(operands[0]):
        operands = operands[1:]
    split_string = option_value(options, "-S", "--split-string")
    if split_string:
        tokens, unused_balanced = lex(split_string)
        operands = [token.value for token in tokens if token.kind == "word"] + operands
    return operands


WRAPPER_OPTIONS = {
    "nice": ("n", ("--adjustment",)),
    "nohup": ("", ()),
    "time": ("fo", ("--format", "--output")),
    "exec": ("a", ()),
    "builtin": ("", ()),
    "stdbuf": ("ioe", ("--input", "--output", "--error")),
    "ionice": ("cnpPu", ("--class", "--classdata", "--pid", "--pgid", "--uid")),
    "timeout": ("sk", ("--signal", "--kill-after")),
    "command": ("", ()),
    "setsid": ("", ()),
    "unbuffer": ("", ()),
}


def unwrap_step(words: List[str]) -> Optional[Tuple[List[str], List[Finding]]]:
    """Strip one wrapper program; None when the first word is not a wrapper."""
    name = command_name(words[0])
    args = words[1:]
    if name in ("sudo", "doas", "pkexec", "run0", "sudoedit"):
        return unwrap_root(name, args)
    if name == "env":
        return unwrap_env(args), []
    if name not in WRAPPER_OPTIONS:
        return None
    short, long_with_arg = WRAPPER_OPTIONS[name]
    options, operands = split_options(args, short, long_with_arg, stop_at_operand=True)
    if name == "command" and option_names(options) & {"-v", "-V"}:
        return [], []
    if name == "timeout":
        operands = operands[1:]
    return operands, []


def unwrap_command(words: Sequence[str]) -> Tuple[List[str], List[Finding]]:
    """Peel sudo, env, nice, nohup, time, timeout and similar prefixes off a command."""
    current = list(words)
    findings: List[Finding] = []
    steps = 0
    while steps < MAX_WRAPPERS:
        steps += 1
        current = strip_prefix_words(current)
        if not current:
            break
        step = unwrap_step(current)
        if step is None:
            break
        current, found = step
        findings.extend(found)
    return current, findings


def effective_words(words: Sequence[str]) -> List[str]:
    """The command that really runs once wrappers and prefixes are removed."""
    return unwrap_command(strip_prefix_words(words))[0]


def shell_reads_stdin(args: Sequence[str]) -> bool:
    """True when a shell invoked with these arguments takes its script from standard input."""
    operands = []
    for arg in args:
        if arg == "--command" or arg.startswith("--command="):
            return False
        if arg.startswith("-") and not arg.startswith("--") and "c" in arg[1:]:
            return False
        if arg.startswith("-") and not arg.startswith("--") and "s" in arg[1:]:
            return True
        if not arg.startswith(("-", "+")):
            operands.append(arg)
    return not operands or operands[0] == "-"


def classify_rm(name: str, args: Sequence[str], depth: int) -> List[Finding]:
    """rm: anything recursive and forced, or any wide target, is dangerous."""
    options, operands = split_options(args)
    flags = option_names(options)
    recursive = bool(flags & {"-r", "-R", "--recursive"})
    force = bool(flags & {"-f", "--force"})
    if "--no-preserve-root" in flags:
        return [(DANGER, "rm --no-preserve-root")]
    critical = [target for target in operands if is_critical_target(target)]
    if critical and (recursive or force):
        kind = "recursive" if recursive else "forced"
        return [(DANGER, f"{kind} delete of '{shorten(critical[0])}'")]
    if recursive and force:
        return [(DANGER, "recursive forced delete")]
    wide = [target for target in operands if is_outside_project(target)]
    if recursive and wide:
        return [(DANGER, f"recursive delete of '{shorten(wide[0])}'")]
    if recursive:
        return [(CAUTION, "recursive delete")]
    system = [target for target in operands if is_system_file(target)]
    if system:
        return [(DANGER, f"deletes the system file '{shorten(system[0])}'")]
    return [(CAUTION, "deletes files")]


def classify_dd(name: str, args: Sequence[str], depth: int) -> List[Finding]:
    """dd: writing with of= overwrites its target."""
    for arg in args:
        if arg.startswith("of="):
            target = arg[3:]
            if is_block_device(target):
                return [(DANGER, f"dd writes to the raw disk '{shorten(target)}'")]
            return [(DANGER, f"dd overwrites '{shorten(target)}'")]
    return [(CAUTION, "copies raw data with dd")]


def classify_partition(name: str, args: Sequence[str], depth: int) -> List[Finding]:
    """Partition editors: listing is fine, anything else rewrites a partition table."""
    options, operands = split_options(args)
    if option_names(options) & PARTITION_READ_FLAGS or (name == "parted" and "print" in operands):
        return [(CAUTION, "reads the partition table (needs root)")]
    return [(DANGER, "edits the partition table")]


def classify_permissions(name: str, args: Sequence[str], depth: int) -> List[Finding]:
    """chmod / chown / chgrp: recursive changes on system directories are dangerous."""
    options, operands = split_options(args)
    flags = option_names(options)
    what = "permissions" if name == "chmod" else "ownership"
    recursive = bool(flags & {"-R", "--recursive"})
    mode_was_option = name == "chmod" and bool(flags - CHMOD_FLAGS - {"--reference"})
    targets = operands if "--reference" in flags or mode_was_option else operands[1:]
    for target in targets:
        if normalize_path(target) == "/":
            return [(DANGER, f"changes {what} of '/'")]
        if recursive and is_system_path(target):
            return [(DANGER, f"recursively changes {what} of '{shorten(target)}'")]
    if recursive:
        return [(CAUTION, f"recursively changes {what}")]
    return [(CAUTION, f"changes {what}")]


def classify_mv(name: str, args: Sequence[str], depth: int) -> List[Finding]:
    """mv: moving / or a system directory breaks the machine."""
    options, operands = split_options(args, "tS", ("--target-directory", "--suffix"))
    has_target_dir = bool(option_names(options) & {"-t", "--target-directory"})
    sources = operands if has_target_dir else operands[:-1]
    for source in sources:
        if is_system_path(source) or is_home(source):
            return [(DANGER, f"moves '{shorten(source)}'")]
    if operands and not has_target_dir and operands[-1] == "/dev/null":
        return [(DANGER, "moves files into /dev/null")]
    destination = operands[-1] if operands else ""
    if overwrites_system_file(destination, has_target_dir or len(operands) > 2):
        return [(DANGER, f"overwrites the system file '{shorten(destination)}'")]
    return [(CAUTION, "moves files")]


def classify_cp(name: str, args: Sequence[str], depth: int) -> List[Finding]:
    """cp: copying onto a raw disk is dangerous, otherwise it writes files."""
    options, operands = split_options(args, "tS", ("--target-directory", "--suffix"))
    target_dir = option_value(options, "-t", "--target-directory")
    destination = target_dir or (operands[-1] if operands else "")
    if is_block_device(destination):
        return [(DANGER, f"writes to the raw disk '{shorten(destination)}'")]
    if overwrites_system_file(destination, target_dir is not None or len(operands) > 2):
        return [(DANGER, f"overwrites the system file '{shorten(destination)}'")]
    return [(CAUTION, "copies files")]


def classify_install(name: str, args: Sequence[str], depth: int) -> List[Finding]:
    """install: like cp, it replaces its destination file."""
    long_with_arg = ("--group", "--mode", "--owner", "--suffix", "--target-directory", "--strip-program")
    options, operands = split_options(args, "gmoSt", long_with_arg)
    flags = option_names(options)
    if flags & {"-d", "--directory"}:
        return [(CAUTION, "creates directories")]
    into_directory = bool(flags & {"-t", "--target-directory"}) or len(operands) > 2
    destination = operands[-1] if operands else ""
    if overwrites_system_file(destination, into_directory):
        return [(DANGER, f"overwrites the system file '{shorten(destination)}'")]
    return [(CAUTION, "installs files")]


def classify_ln(name: str, args: Sequence[str], depth: int) -> List[Finding]:
    """ln -f replaces its destination, which is fatal for a system file."""
    options, operands = split_options(args, "St", ("--suffix", "--target-directory"))
    flags = option_names(options)
    into_directory = bool(flags & {"-t", "--target-directory"}) or len(operands) > 2
    destination = operands[-1] if len(operands) >= 2 else ""
    if flags & {"-f", "--force"} and overwrites_system_file(destination, into_directory):
        return [(DANGER, f"replaces the system file '{shorten(destination)}'")]
    return [(CAUTION, "creates links")]


def classify_tee(name: str, args: Sequence[str], depth: int) -> List[Finding]:
    """tee: truncates and writes every file operand, unless -a appends."""
    options, operands = split_options(args)
    return write_target_findings(operands, truncates=not option_names(options) & {"-a", "--append"})


def classify_truncate(name: str, args: Sequence[str], depth: int) -> List[Finding]:
    """truncate: emptying a system file is as bad as `> /etc/...`."""
    unused_options, operands = split_options(args, "sr", ("--size", "--reference"))
    for target in operands:
        if is_system_file(target) or is_block_device(target):
            return [(DANGER, f"truncates the system file '{shorten(target)}'")]
    return [(CAUTION, "truncates files")]


def classify_kill(name: str, args: Sequence[str], depth: int) -> List[Finding]:
    """kill: signalling pid -1 hits every process the user can reach."""
    index = 0
    if index < len(args) and args[index] in ("-s", "-n"):
        index += 2
    elif index < len(args) and args[index].startswith("-") and args[index] != "--":
        index += 1
    if index < len(args) and args[index] == "--":
        index += 1
    if "-1" in args[index:]:
        return [(DANGER, "kills every process")]
    if args and all(arg in ("-l", "-L", "--list", "--table") for arg in args):
        return []
    return [(CAUTION, "sends a signal to a process")]


def classify_shutdown(name: str, args: Sequence[str], depth: int) -> List[Finding]:
    """shutdown: cancelling is harmless, anything else powers the machine off."""
    if "-c" in args:
        return [(CAUTION, "cancels a scheduled shutdown")]
    return [(DANGER, "shuts down or reboots the machine")]


def classify_init(name: str, args: Sequence[str], depth: int) -> List[Finding]:
    """init / telinit with runlevel 0 or 6 halts or reboots."""
    if set(args) & {"0", "6"}:
        return [(DANGER, "shuts down or reboots the machine")]
    return [(CAUTION, "changes the runlevel")]


def classify_crontab(name: str, args: Sequence[str], depth: int) -> List[Finding]:
    """crontab: -r wipes the table, -l only reads it."""
    options, unused_operands = split_options(args, "u")
    flags = option_names(options)
    if "-r" in flags:
        return [(DANGER, "removes the whole crontab")]
    if "-l" in flags:
        return []
    return [(CAUTION, "edits the crontab")]


def classify_firewall(name: str, args: Sequence[str], depth: int) -> List[Finding]:
    """iptables / nft / ufw / firewall-cmd."""
    words = [arg.lower() for arg in args]
    if name.startswith(("iptables", "ip6tables")):
        options, unused_operands = split_options(args, "tAIDRPNXEjioscmp")
        flags = option_names(options)
        if flags & {"-F", "--flush"}:
            return [(DANGER, "flushes firewall rules")]
        if flags & {"-L", "-S", "--list", "--list-rules"} and not flags & {"-A", "-I", "-D", "-R", "-P", "-N", "-X", "-E", "-Z"}:
            return [(CAUTION, "reads firewall rules (needs root)")]
    elif name == "nft":
        if "flush" in words:
            return [(DANGER, "flushes firewall rules")]
        if "list" in words:
            return [(CAUTION, "reads firewall rules (needs root)")]
    elif name == "ufw":
        if set(words) & {"disable", "reset"}:
            return [(DANGER, "disables or resets the firewall")]
        if "status" in words or "show" in words:
            return [(CAUTION, "reads firewall rules (needs root)")]
    elif all(word.startswith(("--list", "--get", "--query", "--state")) for word in words):
        return [(CAUTION, "reads firewall rules (needs root)")]
    return [(CAUTION, "changes firewall rules")]


def classify_git(name: str, args: Sequence[str], depth: int) -> List[Finding]:
    """git: read-only subcommands are safe, history rewriting is dangerous."""
    unused_options, operands = split_options(args, "Cc", ("--git-dir", "--work-tree", "--namespace"), stop_at_operand=True)
    if not operands:
        return []
    sub = operands[0]
    sub_options, sub_operands = split_options(operands[1:], "o" if sub == "push" else "")
    flags = option_names(sub_options)
    danger = git_danger(sub, flags, sub_operands)
    if danger:
        return [(DANGER, danger)]
    if sub in GIT_SAFE or git_read_only(sub, flags, sub_operands):
        return []
    return [(CAUTION, f"changes the repository (git {shorten(sub)})")]


def git_danger(sub: str, flags: Set[str], operands: Sequence[str]) -> str:
    """Reason when a git invocation destroys work, otherwise an empty string."""
    if sub == "push" and (flags & {"-f", "--force", "--mirror"} or any(op.startswith("+") for op in operands)):
        return "force push"
    if sub == "reset" and "--hard" in flags:
        return "discards uncommitted changes"
    if sub == "clean" and flags & {"-f", "--force"} and not flags & {"-n", "--dry-run"}:
        return "deletes untracked files"
    return ""


def git_read_only(sub: str, flags: Set[str], operands: Sequence[str]) -> bool:
    """True for read-only forms of subcommands that can also write."""
    first = operands[0] if operands else ""
    if sub == "branch":
        return not flags & GIT_BRANCH_WRITE and (not operands or bool(flags & {"-l", "--list"}))
    if sub == "remote":
        return first in ("", "show", "get-url")
    if sub == "config":
        return bool(flags & GIT_CONFIG_READ) or (len(operands) <= 1 and not flags & GIT_CONFIG_WRITE)
    if sub in ("stash", "worktree"):
        return first == "list" or (sub == "stash" and first == "show")
    if sub == "tag":
        return not operands or bool(flags & {"-l", "--list"})
    if sub == "reflog":
        return first in ("", "show")
    return False


def classify_docker(name: str, args: Sequence[str], depth: int) -> List[Finding]:
    """docker / podman: inspection is safe, pruning everything is dangerous."""
    if name in ("docker-compose", "podman-compose"):
        args = ["compose"] + list(args)
        name = name.split("-")[0]
    unused_options, operands = split_options(args, "Hcl", ("--host", "--context", "--config", "--log-level"), stop_at_operand=True)
    if not operands:
        return []
    sub = operands[0]
    action = ""
    if sub in DOCKER_GROUPS:
        unused_sub_options, sub_operands = split_options(operands[1:], "fp", ("--file", "--project-name", "--project-directory"), stop_at_operand=True)
        action = sub_operands[0] if sub_operands else ""
    pair = f"{sub} {action}".strip()
    if pair == "system prune" and any(arg == "--all" or (arg.startswith("-") and not arg.startswith("--") and "a" in arg) for arg in args):
        return [(DANGER, "removes all unused images, containers and networks")]
    if pair == "volume prune" or (pair == "system prune" and "--volumes" in args):
        return [(DANGER, "deletes unused volumes")]
    if pair == "system reset":
        return [(DANGER, "deletes every container, image and volume")]
    if pair in DOCKER_SAFE:
        return []
    return [(CAUTION, f"changes containers or images ({name} {shorten(pair)})")]


def classify_systemctl(name: str, args: Sequence[str], depth: int) -> List[Finding]:
    """systemctl: status queries are safe, state changes need care, power actions are dangerous."""
    long_with_arg = ("--type", "--property", "--lines", "--output", "--host", "--machine", "--state", "--signal", "--kill-whom", "--root", "--job-mode")
    unused_options, operands = split_options(args, "tpnoHMs", long_with_arg)
    if not operands:
        return []
    verb = operands[0]
    if verb in SYSTEMCTL_SAFE:
        return []
    if verb in SYSTEMCTL_POWER:
        return [(DANGER, "shuts down or reboots the machine")]
    return [(CAUTION, f"changes service state (systemctl {shorten(verb)})")]


def classify_service(name: str, args: Sequence[str], depth: int) -> List[Finding]:
    """service NAME status is safe, any other action changes the service."""
    if list(args) == ["--status-all"] or (len(args) >= 2 and args[1] == "status"):
        return []
    return [(CAUTION, f"changes service state (service {shorten(' '.join(args))})")]


def classify_package(name: str, args: Sequence[str], depth: int) -> List[Finding]:
    """apt, dnf, zypper, apk, snap, flatpak, pip, npm, yarn, gem, brew: queries are safe."""
    family = PACKAGE_ALIASES.get(name, name)
    unused_options, operands = split_options(args, PACKAGE_ARG_SHORT.get(family, ""))
    if not operands:
        return []
    verb = operands[0]
    if verb in PACKAGE_READ_VERBS.get(family, set()) and not (verb == "audit" and "fix" in operands):
        return []
    return [(CAUTION, f"changes packages ({name} {shorten(verb)})")]


def classify_pacman(name: str, args: Sequence[str], depth: int) -> List[Finding]:
    """pacman: -Q and the query forms of -S/-F are safe."""
    cluster = next((arg for arg in args if arg.startswith("-") and not arg.startswith("--")), "")
    letters = set(cluster[1:])
    if not args or "--query" in args or letters & {"Q", "T"}:
        return []
    if "S" in letters and letters & set("silgp") and not letters & set("yuc"):
        return []
    if "F" in letters and "y" not in letters:
        return []
    return [(CAUTION, f"changes packages (pacman {shorten(cluster or ' '.join(args))})")]


def classify_dpkg(name: str, args: Sequence[str], depth: int) -> List[Finding]:
    """dpkg / rpm: query options are safe, install and remove options are not."""
    options, unused_operands = split_options(args)
    flags = option_names(options)
    if name == "rpm":
        reads = flags & {"-q", "--query", "-V", "--verify"}
        writes = flags & {"-i", "-U", "-F", "-e", "--install", "--upgrade", "--freshen", "--erase", "--import", "--rebuilddb", "--initdb", "--setperms", "--setugids", "--restore"}
    else:
        reads = flags & {
            "-l",
            "--list",
            "-L",
            "--listfiles",
            "-s",
            "--status",
            "-S",
            "--search",
            "-p",
            "--print-avail",
            "-c",
            "--contents",
            "-I",
            "--info",
            "--print-architecture",
            "--get-selections",
            "--audit",
            "-C",
            "--version",
            "--help",
        }
        writes = flags - reads
    if reads and not writes:
        return []
    return [(CAUTION, f"changes packages ({name})")]


def classify_journalctl(name: str, args: Sequence[str], depth: int) -> List[Finding]:
    """journalctl: reading is safe, vacuuming and rotating delete or move journal files."""
    for arg in args:
        if arg.startswith("--vacuum") or arg in ("--rotate", "--flush", "--sync", "--relinquish-var", "--setup-keys", "--update-catalog"):
            return [(CAUTION, "rotates or deletes journal files")]
    return []


def classify_ip(name: str, args: Sequence[str], depth: int) -> List[Finding]:
    """ip: show-style queries are safe, add/del/set/flush change the network."""
    lowered = {arg.lower() for arg in args}
    if lowered & {"-b", "-batch", "-force"}:
        return [(CAUTION, "runs ip commands from a file")]
    if lowered & IP_CHANGE_VERBS:
        return [(CAUTION, "changes network configuration")]
    return []


def classify_ss(name: str, args: Sequence[str], depth: int) -> List[Finding]:
    """ss: listing sockets is safe, -K closes them."""
    options, unused_operands = split_options(args, "fAFN", ("--family", "--query", "--filter", "--net"))
    if option_names(options) & {"-K", "--kill"}:
        return [(CAUTION, "closes sockets")]
    return []


def classify_settings_tool(name: str, args: Sequence[str], depth: int) -> List[Finding]:
    """hostnamectl / timedatectl / localectl: set-* verbs change the system."""
    unused_options, operands = split_options(args, "H", ("--host",))
    if not operands:
        return []
    verb = operands[0]
    if verb.startswith("set-") or (verb in ("hostname", "icon-name", "chassis", "deployment", "location") and len(operands) > 1):
        return [(CAUTION, "changes system settings")]
    return []


def classify_mount(name: str, args: Sequence[str], depth: int) -> List[Finding]:
    """mount without a device only lists; swapon --show only lists."""
    if name == "swapon":
        if all(arg in SWAPON_READ or arg.startswith("--show=") for arg in args):
            return []
        return [(CAUTION, "enables swap")]
    options, operands = split_options(args, "tO", ("--types", "--test-opts"))
    if not operands and option_names(options) <= {"-l", "-t", "--types", "--show-labels"}:
        return []
    return [(CAUTION, "mounts a filesystem")]


def classify_ping(name: str, args: Sequence[str], depth: int) -> List[Finding]:
    """ping is safe when it stops by itself (-c or -w)."""
    options, unused_operands = split_options(args, "cwWisItlQSpM")
    if option_names(options) & {"-c", "-w"}:
        return []
    return [(CAUTION, "pings until interrupted")]


def classify_sed(name: str, args: Sequence[str], depth: int) -> List[Finding]:
    """sed is safe unless it edits files in place; editing a system file in place is dangerous."""
    for arg in args:
        if arg.startswith("--in-place") or (arg.startswith("-") and not arg.startswith("--") and "i" in arg[1:]):
            system = [target for target in args if not target.startswith("-") and is_system_file(target)]
            if system:
                return [(DANGER, f"edits the system file '{shorten(system[0])}' in place")]
            return [(CAUTION, "edits files in place")]
    return []


def classify_rsync(name: str, args: Sequence[str], depth: int) -> List[Finding]:
    """rsync: --delete onto /, the home directory or a system directory wipes whatever the source lacks."""
    deletes = any(arg.startswith("--delete") or arg == "--remove-source-files" for arg in args)
    operands = [arg for arg in args if not arg.startswith("-")]
    destination = operands[-1] if len(operands) > 1 else ""
    if deletes and destination and ":" not in destination:
        if is_critical_target(destination) or is_system_file(destination):
            return [(DANGER, f"rsync --delete into '{shorten(destination)}'")]
    if deletes:
        return [(CAUTION, "copies files and deletes extra ones")]
    return [(CAUTION, "copies files")]


def classify_awk(name: str, args: Sequence[str], depth: int) -> List[Finding]:
    """awk is safe unless its program runs commands or prints into files."""
    program = AWK_STRING_RE.sub('""', " ".join(args))
    if re.search(r"\bsystem\s*\(", program) or re.search(r"\|\s*getline", program):
        return [(CAUTION, "awk runs shell commands")]
    # `print (a > b)` compares; only an unparenthesised `>` or `|` after print redirects.
    previous = None
    while previous != program:
        previous, program = program, AWK_GROUP_RE.sub("", program)
    if re.search(r"\bprintf?\b[^;}]*\|", program):
        return [(CAUTION, "awk runs shell commands")]
    if re.search(r"\bprintf?\b[^;}]*>", program):
        return [(CAUTION, "writes to a file")]
    return []


def classify_sort(name: str, args: Sequence[str], depth: int) -> List[Finding]:
    """sort -o writes its output to a file."""
    options, unused_operands = split_options(args, "kotST", ("--key", "--output", "--field-separator", "--buffer-size", "--temporary-directory"))
    if option_names(options) & {"-o", "--output"}:
        return [(CAUTION, "writes to a file")]
    return []


def classify_date(name: str, args: Sequence[str], depth: int) -> List[Finding]:
    """date is safe unless it sets the clock."""
    options, unused_operands = split_options(args, "dfrs", ("--date", "--file", "--reference", "--set"))
    if option_names(options) & {"-s", "--set"}:
        return [(CAUTION, "sets the system clock")]
    return []


def classify_hostname(name: str, args: Sequence[str], depth: int) -> List[Finding]:
    """hostname with a name or -F sets the host name."""
    options, operands = split_options(args, "F", ("--file",))
    if operands or option_names(options) & {"-F", "--file", "-b", "--boot"}:
        return [(CAUTION, "changes the hostname")]
    return []


def classify_dmesg(name: str, args: Sequence[str], depth: int) -> List[Finding]:
    """dmesg is safe unless it clears the kernel ring buffer."""
    options, unused_operands = split_options(args, "fFlnsS", ("--facility", "--level", "--console-level", "--buffer-size", "--file"))
    if option_names(options) & {"-c", "-C", "--clear", "--read-clear", "-n", "--console-level"}:
        return [(CAUTION, "clears or reconfigures the kernel log")]
    return []


def classify_sysctl(name: str, args: Sequence[str], depth: int) -> List[Finding]:
    """sysctl is safe when it only reads values."""
    options, operands = split_options(args, "p", ())
    if option_names(options) & {"-w", "--write", "-p", "--load", "--system"} or any("=" in operand for operand in operands):
        return [(CAUTION, "changes kernel parameters")]
    return []


def is_name_filter(test: str, value: str) -> bool:
    """True for a -name/-path style test that really narrows the match (not just `*`)."""
    return test in FIND_NAME_TESTS and value.strip() not in ("", "*", ".*", "*.*")


def classify_find(name: str, args: Sequence[str], depth: int) -> List[Finding]:
    """find: -delete and -exec make it act on every match; the -exec command is rated too.

    Deleting under /, ~, . or a system directory is dangerous unless a name or
    path pattern narrows the match: -type, -mtime or -size still leave most files.
    """
    findings: List[Finding] = []
    starts = list(args[: next((i for i, a in enumerate(args) if a.startswith(("-", "(", "!"))), len(args))])
    deletes = False
    has_test = False
    narrowed = False
    index = 0
    while index < len(args):
        arg = args[index]
        if arg in FIND_EXEC:
            end = next((i for i in range(index + 1, len(args)) if args[i] in (";", "+")), len(args))
            findings.append((CAUTION, "runs a command on found files"))
            executed = effective_words(args[index + 1 : end])
            if executed:
                findings.extend(classify_words(args[index + 1 : end], depth + 1))
                deletes = deletes or command_name(executed[0]) in DELETING_COMMANDS
            index = end + 1
            continue
        if arg == "-delete":
            deletes = True
        elif arg in FIND_WRITES:
            findings.append((CAUTION, "writes to a file"))
        elif arg.startswith("-") and arg not in FIND_GLOBAL_OPTIONS:
            has_test = True
            narrowed = narrowed or is_name_filter(arg, args[index + 1] if index + 1 < len(args) else "")
        index += 1
    if deletes:
        wide = [start for start in (starts or ["."]) if is_critical_target(start)]
        if wide and not narrowed:
            what = "files throughout" if has_test else "everything under"
            findings.append((DANGER, f"deletes {what} '{shorten(wide[0])}'"))
        else:
            findings.append((CAUTION, "deletes found files"))
    return findings


def classify_xargs(name: str, args: Sequence[str], depth: int) -> List[Finding]:
    """xargs runs its command once per input batch; the command is rated too."""
    long_with_arg = ("--arg-file", "--delimiter", "--max-lines", "--max-args", "--max-procs", "--max-chars", "--process-slot-var")
    unused_options, operands = split_options(args, "aEIdLnPs", long_with_arg, stop_at_operand=True)
    return [(CAUTION, "runs a command for each input item")] + classify_words(operands or ["echo"], depth + 1)


def classify_watch(name: str, args: Sequence[str], depth: int) -> List[Finding]:
    """watch repeats a command; the command decides the rating."""
    options, operands = split_options(args, "nq", ("--interval", "--equexit"), stop_at_operand=True)
    if not operands:
        return []
    if option_names(options) & {"-x", "--exec"}:
        return classify_words(operands, depth + 1)
    return classify_text(" ".join(operands), depth + 1)


def classify_shell(name: str, args: Sequence[str], depth: int) -> List[Finding]:
    """bash/sh/zsh -c STRING: rate the string; a script file or a bare shell needs care."""
    if has_download_substitution(args):
        return [(DANGER, "runs a downloaded script")]
    index = 0
    while index < len(args):
        arg = args[index]
        if arg == "--":
            index += 1
            break
        if arg == "--command" or (arg.startswith("-") and not arg.startswith("--") and "c" in arg[1:]):
            return classify_text(args[index + 1] if index + 1 < len(args) else "", depth + 1)
        if arg.startswith("--command="):
            return classify_text(arg.partition("=")[2], depth + 1)
        if not arg.startswith(("-", "+")):
            break
        index += 2 if arg in ("-o", "+o", "-O", "+O", "--rcfile", "--init-file") else 1
    operands = args[index:]
    if operands and operands[0] != "-":
        return [(CAUTION, "runs a script")]
    return [(CAUTION, "starts a shell")]


def classify_ssh(name: str, args: Sequence[str], depth: int) -> List[Finding]:
    """ssh HOST [COMMAND]: the remote command is rated as if it ran here."""
    unused_options, operands = split_options(args, "bcDEeFIiJLlmOopQRSWw", stop_at_operand=True)
    findings: List[Finding] = [(CAUTION, "connects to a remote host")]
    if len(operands) > 1:
        findings.extend(classify_text(" ".join(operands[1:]), depth + 1))
    return findings


def classify_disk_tool(name: str, args: Sequence[str], depth: int) -> List[Finding]:
    """cryptsetup, zpool, zfs, nvme, hdparm, badblocks, mdadm: the erasing forms are dangerous."""
    if name in DISK_TOOL_SUBCOMMANDS:
        verbs, reason = DISK_TOOL_SUBCOMMANDS[name]
        unused_options, operands = split_options(args, stop_at_operand=True)
        if operands and operands[0].lower() in verbs:
            return [(DANGER, reason)]
    else:
        flags_wanted, reason = DISK_TOOL_FLAGS[name]
        options, unused_operands = split_options(args)
        if option_names(options) & flags_wanted:
            return [(DANGER, reason)]
    return [(CAUTION, f"manages disks or volumes ({name})")]


def classify_verb_tool(name: str, args: Sequence[str], depth: int) -> List[Finding]:
    """nmcli, loginctl, kubectl, resolvectl: listing and showing verbs are safe."""
    read_verbs, reason = VERB_TOOLS[name]
    unused_options, operands = split_options(args, VERB_TOOL_ARG_SHORT.get(name, ""), stop_at_operand=name != "nmcli")
    words = [operand.lower() for operand in operands]
    if name == "kubectl" and words[:1] == ["delete"] and (set(args) & {"--all", "-A", "--all-namespaces"} or words[1:2] in (["namespace"], ["ns"], ["namespaces"])):
        return [(DANGER, "deletes Kubernetes resources across the board")]
    if name == "loginctl" and words[:1] and words[0] in SYSTEMCTL_POWER:
        return [(DANGER, "shuts down or reboots the machine")]
    if name == "nmcli":
        if set(words) & NMCLI_CHANGE_WORDS:
            return [(CAUTION, reason)]
        return []
    if name == "kubectl" and words[:1] == ["config"] and words[1:2] not in (["view"], ["get-contexts"], ["current-context"], ["get-clusters"], ["get-users"], []):
        return [(CAUTION, "changes the Kubernetes client configuration")]
    if not words or words[0] in read_verbs:
        return []
    return [(CAUTION, reason)]


def classify_ifconfig(name: str, args: Sequence[str], depth: int) -> List[Finding]:
    """ifconfig alone or with one interface only lists."""
    operands = [arg for arg in args if not arg.startswith("-")]
    if len(operands) <= 1:
        return []
    return [(CAUTION, "changes network configuration")]


def classify_openssl(name: str, args: Sequence[str], depth: int) -> List[Finding]:
    """openssl reads and prints unless it is told to write a file."""
    if set(args) & {"-out", "-keyout", "-writerand"}:
        return [(CAUTION, "writes to a file")]
    return []


def classify_busybox(name: str, args: Sequence[str], depth: int) -> List[Finding]:
    """busybox APPLET ...: rate the applet as if it ran directly."""
    if not args:
        return []
    return classify_words(args, depth + 1)


def classify_interpreter(name: str, args: Sequence[str], depth: int) -> List[Finding]:
    """python / perl / ruby / node: inline code and scripts can do anything."""
    if has_download_substitution(args):
        return [(DANGER, "runs a downloaded script")]
    if len(args) >= 2 and args[0] == "-m" and args[1] in ("pip", "pip3"):
        return classify_package("pip", args[2:], depth)
    if list(args) in (["--version"], ["-V"], ["-v"]):
        return []
    if any(arg in ("-c", "-e", "-E", "-r", "--eval") for arg in args):
        return [(CAUTION, "runs inline code")]
    if args:
        return [(CAUTION, "runs a script")]
    return [(CAUTION, "starts an interpreter")]


def classify_su(name: str, args: Sequence[str], depth: int) -> List[Finding]:
    """su [-] [user] [-c command]: runs as another user, the command is rated too."""
    options, operands = split_options(args, "csgG", ("--command", "--shell", "--group", "--supp-group"))
    users = [operand for operand in operands if operand != "-"]
    user = users[0] if users else "root"
    reason = "runs as root" if user in ROOT_USERS else f"runs as user '{shorten(user)}'"
    command = option_value(options, "-c", "--command")
    if command is None:
        return [(CAUTION, reason), (CAUTION, "opens a root shell" if user in ROOT_USERS else "opens a shell as another user")]
    return [(CAUTION, reason)] + classify_text(command, depth + 1)


def classify_eval(name: str, args: Sequence[str], depth: int) -> List[Finding]:
    """eval / source: rate the evaluated text; a downloaded script is dangerous."""
    if has_download_substitution(args):
        return [(DANGER, "runs a downloaded script")]
    if name == "eval":
        return classify_text(" ".join(args), depth + 1)
    return [(CAUTION, "runs a script in the current shell")]


def classify_mkfs(name: str, args: Sequence[str], depth: int) -> List[Finding]:
    """mkfs and friends format a device."""
    return [(DANGER, "creates a filesystem")]


HANDLERS: Dict[str, Callable[[str, Sequence[str], int], List[Finding]]] = {
    "rm": classify_rm,
    "dd": classify_dd,
    "mv": classify_mv,
    "cp": classify_cp,
    "tee": classify_tee,
    "truncate": classify_truncate,
    "kill": classify_kill,
    "shutdown": classify_shutdown,
    "init": classify_init,
    "telinit": classify_init,
    "crontab": classify_crontab,
    "git": classify_git,
    "systemctl": classify_systemctl,
    "service": classify_service,
    "pacman": classify_pacman,
    "dpkg": classify_dpkg,
    "rpm": classify_dpkg,
    "journalctl": classify_journalctl,
    "ip": classify_ip,
    "ss": classify_ss,
    "mount": classify_mount,
    "swapon": classify_mount,
    "ping": classify_ping,
    "ping6": classify_ping,
    "sed": classify_sed,
    "rsync": classify_rsync,
    "sort": classify_sort,
    "date": classify_date,
    "hostname": classify_hostname,
    "dmesg": classify_dmesg,
    "sysctl": classify_sysctl,
    "find": classify_find,
    "xargs": classify_xargs,
    "watch": classify_watch,
    "busybox": classify_busybox,
    "su": classify_su,
    "eval": classify_eval,
    "source": classify_eval,
    ".": classify_eval,
    "mke2fs": classify_mkfs,
}
HANDLERS.update(dict.fromkeys(PARTITION_TOOLS, classify_partition))
HANDLERS.update(dict.fromkeys(("chmod", "chown", "chgrp"), classify_permissions))
HANDLERS.update(dict.fromkeys(("iptables", "ip6tables", "iptables-legacy", "iptables-nft", "nft", "ufw", "firewall-cmd"), classify_firewall))
HANDLERS.update(dict.fromkeys(("docker", "podman", "docker-compose", "podman-compose"), classify_docker))
HANDLERS.update(
    dict.fromkeys(
        ("apt", "apt-get", "aptitude", "dnf", "yum", "microdnf", "zypper", "apk", "snap", "flatpak", "pip", "pip3", "pipx", "npm", "pnpm", "yarn", "gem", "brew"), classify_package
    )
)
HANDLERS.update(dict.fromkeys(("hostnamectl", "timedatectl", "localectl"), classify_settings_tool))
HANDLERS.update(dict.fromkeys(("awk", "gawk", "mawk", "nawk"), classify_awk))
HANDLERS.update(dict.fromkeys(SHELLS, classify_shell))
HANDLERS.update(dict.fromkeys(list(DISK_TOOL_SUBCOMMANDS) + list(DISK_TOOL_FLAGS), classify_disk_tool))
HANDLERS.update(dict.fromkeys(VERB_TOOLS, classify_verb_tool))
HANDLERS.update(
    {
        "install": classify_install,
        "ln": classify_ln,
        "ssh": classify_ssh,
        "ifconfig": classify_ifconfig,
        "openssl": classify_openssl,
        "systemd-analyze": classify_settings_tool,
    }
)


def classify_words(words: Sequence[str], depth: int) -> List[Finding]:
    """Rate one command given as words, after wrappers have been removed."""
    if depth > MAX_DEPTH:
        return [(CAUTION, "too deeply nested to analyse")]
    inner, findings = unwrap_command(words)
    if not inner:
        return findings
    name = command_name(inner[0])
    args = inner[1:]
    handler = HANDLERS.get(name)
    if handler is not None:
        return findings + handler(name, args, depth)
    if is_interpreter(name):
        return findings + classify_interpreter(name, args, depth)
    if name.startswith("mkfs"):
        return findings + classify_mkfs(name, args, depth)
    if name in DANGER_COMMANDS:
        return findings + [(DANGER, DANGER_COMMANDS[name])]
    if name in SAFE_COMMANDS:
        return findings
    if name in NOTED_COMMANDS:
        return findings + [(CAUTION, NOTED_COMMANDS[name])]
    return findings + [(CAUTION, f"unknown command '{shorten(name)}'")] + wrapped_danger(args, depth)


def is_rated_command(word: str) -> bool:
    """True for a program this module knows to be destructive in some form."""
    name = command_name(word)
    return name in HANDLERS or name in DANGER_COMMANDS or name.startswith("mkfs")


def wrapped_danger(args: Sequence[str], depth: int) -> List[Finding]:
    """An unknown program may be a wrapper (chroot, taskset, flock, ...): rate any known command among its arguments.

    Only dangerous findings are kept, so `mytool rm` stays a plain caution while
    `chrt -f 99 rm -rf /` is dangerous like the `rm -rf /` it runs.
    """
    findings: List[Finding] = []
    for index, arg in enumerate(args):
        if is_rated_command(arg):
            findings.extend(finding for finding in classify_words(args[index:], depth + 1) if finding[0] == DANGER)
            break
    return findings


def classify_stdin_script(words: Sequence[str], redirects: Sequence[Tuple[str, str, Optional[str]]], depth: int) -> List[Finding]:
    """A shell fed a heredoc or here-string runs that text: rate it."""
    inner = effective_words(words)
    if not inner or command_name(inner[0]) not in SHELLS or not shell_reads_stdin(inner[1:]):
        return []
    findings: List[Finding] = []
    for operator, target, body in redirects:
        if operator in ("<<", "<<-") and body:
            findings.extend(classify_text(body, depth + 1))
        elif operator == "<<<":
            findings.extend(classify_text(target, depth + 1))
    return findings


def classify_command(command: SimpleCommand, depth: int) -> List[Finding]:
    """Rate one simple command: its substitutions, redirections and the program itself."""
    findings: List[Finding] = []
    for inner in command.substitutions:
        findings.append((CAUTION, "command substitution"))
        findings.extend(classify_text(inner, depth + 1))
    findings.extend(classify_redirects(command.redirects))
    words = strip_prefix_words(command.words)
    if words:
        findings.extend(classify_words(words, depth))
        findings.extend(classify_stdin_script(words, command.redirects, depth))
    return findings


def classify_pipeline(pipeline: Sequence[SimpleCommand], depth: int) -> List[Finding]:
    """Rate every command of a pipeline plus what flows between them (download into a shell)."""
    findings: List[Finding] = []
    effective = []
    for command in pipeline:
        findings.extend(classify_command(command, depth))
        effective.append(effective_words(command.words))
    for index in range(1, len(effective)):
        sink = effective[index]
        if not sink or not is_interpreter(command_name(sink[0])):
            continue
        sources = [command_name(words[0]) for words in effective[:index] if words]
        if any(source in DOWNLOADERS for source in sources):
            findings.append((DANGER, "pipes a download into a shell"))
            continue
        if command_name(sink[0]) in SHELLS and shell_reads_stdin(sink[1:]):
            script = fed_text(effective[index - 1], pipeline[index - 1].redirects)
            if script:
                findings.extend(classify_text(script, depth + 1))
    return findings


def fed_text(words: Sequence[str], redirects: Sequence[Tuple[str, str, Optional[str]]]) -> str:
    """Literal text a pipeline stage feeds forward: echo/printf arguments or a cat heredoc."""
    if not words:
        return ""
    name = command_name(words[0])
    if name in ("echo", "printf"):
        args = list(words[1:])
        while name == "echo" and args and re.match(r"^-[neE]+$", args[0]):
            args = args[1:]
        return " ".join(args).replace("\\n", "\n")
    if name == "cat":
        parts = [body or "" for operator, unused_target, body in redirects if operator in ("<<", "<<-")]
        parts.extend(target for operator, target, unused_body in redirects if operator == "<<<")
        return "\n".join(parts)
    return ""


def classify_text(text: str, depth: int) -> List[Finding]:
    """Rate a whole command line (lists, pipelines and nested substitutions)."""
    if depth > MAX_DEPTH:
        return [(CAUTION, "too deeply nested to analyse")]
    findings: List[Finding] = []
    if FORK_BOMB_RE.search(text):
        findings.append((DANGER, "fork bomb"))
    tokens, balanced = lex(text)
    if not balanced:
        findings.append((CAUTION, "unbalanced quotes or brackets"))
    pipelines = parse(tokens)
    for pipeline in pipelines:
        findings.extend(classify_pipeline(pipeline, depth))
    findings.extend(downloaded_script_findings(pipelines))
    return findings


def url_basename(url: str) -> str:
    """File name a downloader saves a URL under by default."""
    path = url.split("://", 1)[-1].split("?", 1)[0].split("#", 1)[0]
    if "/" not in path:
        return "index.html"
    return posixpath.basename(path) or "index.html"


def download_targets(name: str, args: Sequence[str]) -> List[str]:
    """Base names of the files curl or wget writes (-o / -O / --output / wget's default)."""
    output_letter, remote_letter = ("o", "O") if name == "curl" else ("O", "")
    long_names = ("--output",) if name == "curl" else ("--output-document",)
    targets: List[str] = []
    remote_name = name != "curl"
    index = 0
    while index < len(args):
        arg = args[index]
        value = None
        if arg in long_names:
            value = args[index + 1] if index + 1 < len(args) else ""
            index += 1
        elif arg.startswith(tuple(f"{long}=" for long in long_names)):
            value = arg.partition("=")[2]
        elif arg in ("--remote-name", "--remote-name-all"):
            remote_name = True
        elif arg.startswith("-") and not arg.startswith("--"):
            letters = arg[1:]
            if remote_letter and remote_letter in letters:
                remote_name = True
            if output_letter in letters:
                rest = letters[letters.index(output_letter) + 1 :]
                value = rest or (args[index + 1] if index + 1 < len(args) else "")
                if not rest:
                    index += 1
        if value is not None:
            remote_name = remote_name and name == "curl"
            if value != "-":
                targets.append(posixpath.basename(value))
        index += 1
    if remote_name:
        targets.extend(url_basename(arg) for arg in args if "://" in arg)
    return [target for target in targets if target]


def runs_file(words: Sequence[str]) -> str:
    """Base name of the script a command executes: `sh x.sh`, `python3 x.py`, `source x`, `./x.sh`; "" otherwise."""
    name = command_name(words[0])
    if "/" in words[0] and "$" not in words[0]:
        return name
    if name in ("source", ".") or is_interpreter(name):
        operands = [arg for arg in words[1:] if not arg.startswith(("-", "+"))]
        if operands and not any(arg == "-c" or (arg.startswith("-") and "c" in arg[1:] and not arg.startswith("--")) for arg in words[1:]):
            return posixpath.basename(operands[0])
    return ""


def downloaded_script_findings(pipelines: Sequence[Sequence[SimpleCommand]]) -> List[Finding]:
    """`curl -o x.sh URL && sh x.sh`: running a file downloaded earlier on the line is as bad as `curl | sh`."""
    downloaded: Set[str] = set()
    for pipeline in pipelines:
        for command in pipeline:
            words = effective_words(command.words)
            if not words:
                continue
            name = command_name(words[0])
            if name in ("curl", "wget"):
                downloaded.update(download_targets(name, words[1:]))
            elif downloaded and runs_file(words) in downloaded:
                return [(DANGER, "runs a downloaded script")]
    return []


def summarize(findings: Sequence[Finding]) -> Risk:
    """Fold findings into a Risk: the worst level wins, reasons are deduplicated, worst first."""
    level = max((found[0] for found in findings), key=LEVEL_RANK.__getitem__, default=SAFE)
    reasons: List[str] = []
    for wanted in (DANGER, CAUTION):
        for found_level, reason in findings:
            if found_level == wanted and reason not in reasons:
                reasons.append(reason)
    return Risk(level, reasons)


def classify(command: str) -> Risk:
    """Rate how risky running a shell command line would be; never runs it and never raises."""
    try:
        if not isinstance(command, str):
            return Risk(CAUTION, ["not a command string"])
        return summarize(classify_text(command, 0))
    except Exception as exc:
        logger.warning(f"{type(exc).__name__}: {exc}\n{traceback.format_exc()}")
        return Risk(CAUTION, ["could not analyse the command"])


def main():
    pass


if __name__ == "__main__":
    main()
