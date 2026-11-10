# penguin-do

Type what you want in plain language, get one shell command back with a short
explanation, read it, and run it only if you agree.

```
$ penguin-do "show the list of files"
  ls
  Lists the files here
Run? [Y/n/e]

$ penguin-do "delete everything in the home directory"
  rm -r ~
  Deletes everything in your home
  DANGER: recursive delete of '~'
Run anyway? [y/N/e]
```

The command comes from a small language model that runs on your machine.
Nothing is sent anywhere after the one-time model download, and the only thing
penguin-do ever executes is the command you have just seen and confirmed.

The model is small and it is sometimes wrong. Read every command before you
press Enter.

## Install

penguin-do runs the model on the CPU with
[`llama-cpp-python`](https://github.com/abetlen/llama-cpp-python), which is
installed as a dependency.

Recommended, with prebuilt CPU wheels (no compiler, takes seconds):

```bash
pip install penguin-do --extra-index-url https://abetlen.github.io/llama-cpp-python/whl/cpu
```

With pipx:

```bash
pipx install penguin-do --pip-args='--extra-index-url https://abetlen.github.io/llama-cpp-python/whl/cpu'
```

A plain `pip install penguin-do` also works, but PyPI only ships the
`llama-cpp-python` source package, so pip compiles llama.cpp locally. That
needs a C/C++ compiler and CMake and takes several minutes:

```bash
sudo apt install build-essential cmake python3-dev    # Debian / Ubuntu
sudo dnf install gcc-c++ cmake python3-devel          # Fedora / RHEL
```

The same source build happens when the extra index has no wheel for your
Python version or CPU architecture. No GPU is needed.

If the runtime is installed but cannot be loaded, penguin-do says so and
suggests:

```bash
pip install --force-reinstall llama-cpp-python --extra-index-url https://abetlen.github.io/llama-cpp-python/whl/cpu
```

## Usage

```bash
penguin-do "who is using swap?"               # suggest a command and ask before running it
penguin-do show the list of files             # quotes are optional for simple text
penguin-do -n "what is eating swap"           # print the suggestion, do not run it
penguin-do --lang de "show the list of files" # German messages for an English request
penguin-do -f json "which ports are open"     # machine-readable, never runs anything
cmd=$(penguin-do -f plain "count lines in all .py files here")
```

All words after the options are joined with spaces into one request. Quote the
request when it contains `?`, `*`, `'`, `$`, `!` or `&`: the shell interprets
those before penguin-do sees them.

| flag                                | meaning                                                         |
|-------------------------------------|-----------------------------------------------------------------|
| `-n`, `--dry-run`                   | show the suggestion and stop, never prompt or run               |
| `-f`, `--format text\|plain\|json`  | output format (default `text`), also for the model flags        |
| `--lang CODE`                       | language of messages: `en es pt fr de it ru zh ja hi ko`        |
| `--model MODEL`                     | model for this run only: `dale qwen3.5-0.8b qwen2.5-1.5b`       |
| `--no-color`                        | disable colored output                                          |
| `-v`, `--verbose`                   | more logging (`-v` info, `-vv` debug); errors show a traceback  |
| `-q`, `--quiet`                     | errors only in the log                                          |
| `-V`, `--version`                   | print `penguin-do <version>`                                    |
| `--models`                          | show the models and which one is in use                         |
| `--pull [MODEL]`                    | download a model and use it from now on; no MODEL: a menu       |
| `--rm [MODEL]`                      | remove a model and any partial download; no MODEL: the one in use |

`--models`, `--pull` and `--rm` exclude each other and cannot be combined with
a request.

### Output formats

`text` (default) is a compact block: the command in bold green, the model's
one-sentence explanation dimmed, and a yellow `caution: ...` or red
`DANGER: ...` line when the command is not safe. When the model declines, its
reason is printed instead:

```
$ penguin-do "what is the weather tomorrow"
Not a shell task: Weather is a real-world question, not shell
```

`plain` prints the command alone, for `$(...)`, pipes and the clipboard. A
`caution` or `DANGER` line goes to stderr, so stdout stays the bare command.

`json` prints one object and never runs the command:

```json
{
  "request": "show the list of files",
  "language": "en",
  "ui_language": "en",
  "type": "command",
  "command": "ls",
  "explanation": "Lists the files here",
  "risk": "safe",
  "reasons": []
}
```

`type` is `command`, `refuse` (not a shell task) or `unsure` (the request was
too vague). `language` is the language detected in the request, `ui_language`
the one used for messages.

## The Y/n/e prompt

| answer             | effect                         |
|--------------------|--------------------------------|
| Enter, `y`, `yes`  | run the command                |
| `n`, `no`          | print `Cancelled.` and exit 1  |
| `e`                | edit the command first         |
| Ctrl+C, Ctrl+D     | cancel, exit 130               |
| anything else      | ask again                      |

Answers are case-insensitive, and the letters stay `Y/n/e` in every language.

**Danger flips the default.** When the command is rated `danger`, the prompt
becomes `Run anyway? [y/N/e]` and Enter means no: only an explicit `y` or
`yes` runs it.

**Editing.** `e` opens the command in an editable line, pre-filled, with Tab
completion: the first word completes commands on `PATH` and shell builtins,
later words complete file paths. Enter accepts the edit. An empty line cancels
(exit 1). The edited command is rated again: if it is now `danger`, you see the
`DANGER` line and `Run anyway? [y/N/e]` again, otherwise it runs right away.
Without `readline` the edit is a plain input line with no pre-fill or
completion.

**Running.** The command runs as your user through `bash -c` (or `/bin/sh -c`
when bash is missing), attached to your terminal. penguin-do adds no `sudo` and
no wrapper. If the command needs root, the model writes `sudo` into it, and you
see that before you agree.

**No terminal, no prompt.** When stdin or stdout is not a terminal (a pipe,
cron, `ssh host penguin-do ...` without `-t`), the suggestion is printed,
`Not a terminal: printing the command without running it.` goes to stderr, and
nothing runs.

## Risk rating

Every suggested and every edited command is rated `safe`, `caution` or `danger`
before you are asked. The rating is a fixed set of rules over the command text:
offline, deterministic, and it never executes anything. It splits the line on
`|`, `||`, `&&`, `;`, `&` and newlines, looks inside `$(...)`, backticks,
`bash -c '...'` and `ssh host '...'`, and sees through prefixes such as `sudo`,
`env`, `nice`, `nohup`, `time` and `xargs`. The worst part decides the level.

| level     | examples                                                                                     |
|-----------|----------------------------------------------------------------------------------------------|
| `safe`    | read-only tools: `ls`, `cat`, `grep`, `du`, `df`, `free`, `ps`, `ss`, `journalctl`, `swapon --show` |
| `caution` | `sudo`; writing files; `rm`, `mv`, `chmod`; `kill`; services; package installs; `curl`/`wget`; anything not on the read-only list |
| `danger`  | `rm -rf`; recursive delete of `/` or `~`; `dd of=`; `mkfs`, `wipefs`, `shred`; overwriting files in `/etc`, `/usr`, `/boot`; `curl ... \| sh`; `iptables -F`; `git push --force`; `shutdown`, `reboot`; fork bombs |

It is a seatbelt, not a sandbox. It reads text only, so it cannot know what a
script you call does or which file a variable points at.

## Models

| key            | model                                                                                       | size   | license    | author        |
|----------------|---------------------------------------------------------------------------------------------|--------|------------|---------------|
| `dale`         | [dale-0.8b](https://huggingface.co/manuelgscom/dale-0.8b-GGUF), Q4_K_M GGUF                | 529 MB | Apache-2.0 | Manuel García |
| `qwen3.5-0.8b` | [Qwen3.5-0.8B](https://huggingface.co/ggml-org/Qwen3.5-0.8B-GGUF), Q4_0 GGUF               | 563 MB | Apache-2.0 | Qwen team     |
| `qwen2.5-1.5b` | [Qwen2.5-1.5B-Instruct](https://huggingface.co/Qwen/Qwen2.5-1.5B-Instruct-GGUF), Q4_K_M GGUF | 1.1 GB | Apache-2.0 | Qwen team     |

dale is trained for exactly this task and is the default. The two Qwen models
are general chat models prompted with a few examples: Qwen3.5-0.8B is the same
size as dale but its commands are often wrong, Qwen2.5-1.5B is twice the size
and closer to dale.

On the first request with no model downloaded, a terminal gets a menu:

```
Choose a model to download:
  1) dale           529 MB  dale-0.8b: trained to turn a request into one bash command
  2) qwen3.5-0.8b   563 MB  Qwen3.5-0.8B: general small model, same size as dale
  3) qwen2.5-1.5b   1.1 GB  Qwen2.5-1.5B-Instruct: general model, twice the size of dale
Model [1]:
```

Enter picks dale. The pick is downloaded and remembered. Without a terminal
penguin-do never downloads anything and suggests `penguin-do --pull` instead.

The model used for a request is the first of these that is set:

1. `--model MODEL`
2. `PENGUIN_DO_MODEL`
3. the choice saved by the menu or `--pull` in `$XDG_CONFIG_HOME/penguin-do/model`
   (`~/.config/penguin-do/model`)
4. the first downloaded model in the table above

When the chosen model is not downloaded yet, a terminal is asked
`Download <file> (<size>) to ...? [Y/n]`.

```bash
penguin-do --models                # present yes/no, * marks the model in use
penguin-do --models -f json
penguin-do --pull                  # menu, then download and use the pick
penguin-do --pull qwen2.5-1.5b     # download this one and use it from now on
penguin-do --model dale "free disk"  # another downloaded model, this run only
penguin-do --rm                    # delete the model in use, its .part and .lock files
penguin-do --rm qwen3.5-0.8b       # delete this one
```

How downloads behave:

- The file is written as `<name>.part` and moved into place only after its size
  and sha256 match. A mismatch deletes the partial file.
- An interrupted download resumes where it stopped: run the same command again.
- A progress bar is drawn on stderr when it is a terminal.
- Later runs only check that the file exists with the right size.

### Where it is stored

The first of these that is set wins:

1. `$PENGUIN_DO_MODELS_DIR`
2. `$XDG_CACHE_HOME/penguin-do/models`
3. `~/.cache/penguin-do/models`

| file                                | bytes      | sha256                                                             |
|-------------------------------------|------------|--------------------------------------------------------------------|
| `dale-0.8b-1.0.0-Q4_K_M.gguf`       | 529297952  | `8738d2535680cf7b8227001013a0ba6e6b2a4c8e8f3d149fd181c17cb96e2d3d` |
| `Qwen3.5-0.8B-Q4_0.gguf`            | 563036064  | `57d1997790d1744fba5b40a7317df71ea5e2acee28c47e78f0cce39c0703f8cf` |
| `qwen2.5-1.5b-instruct-q4_k_m.gguf` | 1117320736 | `6a1a2eb6d15622bf3c96857206351ba97e1af16c30d7a74ee38970e434e9407e` |

On a machine without internet access, download the file from the model page on
another machine, check it with `sha256sum`, and copy it into the models
directory under the same name.

## Languages

Messages are available in 11 languages: English, Spanish, Portuguese, French,
German, Italian, Russian, Chinese, Japanese, Hindi and Korean. The message
language is the first of these that is set:

1. `--lang CODE`
2. `PENGUIN_DO_LANG` (a code, a locale string such as `ru_RU.UTF-8`, or a language name)
3. the language of the request, when it is clear
4. your locale (`LC_ALL`, `LC_MESSAGES`, `LANG`)
5. English

Requests in any of these languages go to the model as typed. dale was trained
on English and Spanish: in other languages the explanation may come back in
Spanish or English, and in Japanese, Hindi and Korean the command is sometimes
confidently wrong. When a request in another language keeps missing, write it
in English.

## Limits

- dale-0.8b is a 0.8-billion-parameter model. Its model card reports roughly
  one command in five is wrong even in English.
- One request gives one command. There are no multi-step plans and no memory
  between requests.
- The model never sees your files or command output. All it knows about the
  machine is one context line built locally: OS, distro, package manager and
  which of a fixed list of common tools are on `PATH`.

## Environment variables

| variable                 | meaning                                                        |
|--------------------------|----------------------------------------------------------------|
| `PENGUIN_DO_LANG`        | language of messages                                           |
| `PENGUIN_DO_MODEL`       | model to use: `dale`, `qwen3.5-0.8b` or `qwen2.5-1.5b`         |
| `PENGUIN_DO_MODELS_DIR`  | where the models are stored                                    |
| `XDG_CACHE_HOME`         | base of the default models directory                           |
| `XDG_CONFIG_HOME`        | base of the file that remembers the chosen model               |
| `HF_ENDPOINT`            | Hugging Face mirror to download from                           |
| `https_proxy`            | HTTP proxy for the download                                    |
| `PENGUIN_DO_DEBUG`       | show the traceback of an unexpected error                      |

## Exit codes

| code | meaning                                                                                       |
|------|-----------------------------------------------------------------------------------------------|
| 0    | a command was printed (dry run, not a terminal, `plain`, `json`), or it ran and succeeded     |
| N    | the command ran and exited with N (`exit code N` is printed)                                  |
| 1    | refused, unsure or no usable command; you answered `n`; you emptied the edit line; the download was declined or failed; an unexpected error |
| 2    | the request is empty, or the options are invalid                                             |
| 3    | the runtime is not installed, or the model is missing and there is no terminal to ask in     |
| 130  | Ctrl+C or EOF at a prompt, or Ctrl+C while the command runs                                   |

## Privacy

- Everything runs locally. Apart from the model download, penguin-do makes no
  network connections: no API, no telemetry, no update checks.
- Your request, the context line and the explanation stay on the machine.
- The download comes from `https://huggingface.co/<repo>/resolve/main/<file>`,
  or from `$HF_ENDPOINT` when it is set.
- Each model is a plain file in the models directory. `penguin-do --rm MODEL` removes it.

## Credits

- [dale-0.8b](https://huggingface.co/manuelgscom/dale-0.8b-GGUF) by Manuel García, Apache-2.0.
- [Qwen3.5-0.8B](https://huggingface.co/ggml-org/Qwen3.5-0.8B-GGUF) and
  [Qwen2.5-1.5B-Instruct](https://huggingface.co/Qwen/Qwen2.5-1.5B-Instruct-GGUF) by the Qwen team, Apache-2.0.

## License

MIT, see [LICENSE](LICENSE).
