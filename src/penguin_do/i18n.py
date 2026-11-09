#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Localized messages and request-language detection for `penguin-do "<request>"`."""

import functools
import json
import logging
import os
import re
import traceback
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

CODES = ("en", "es", "pt", "fr", "de", "it", "ru", "zh", "ja", "hi", "ko")
DEFAULT_LANGUAGE = "en"
LOCALES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "locales")
LATIN_LANGUAGES = ("en", "es", "pt", "fr", "de", "it")
LOCALE_ENV_VARS = ("LC_ALL", "LC_MESSAGES", "LANG")

# Script detection, checked in this order: kana must win over Han because
# Japanese text mixes both, while Chinese text carries no kana at all.
SCRIPT_PATTERNS = (
    ("ko", re.compile("[\u1100-\u11ff\u3130-\u318f\uac00-\ud7a3]")),
    ("ja", re.compile("[\u3040-\u309f\u30a0-\u30ff\u31f0-\u31ff\uff66-\uff9f]")),
    ("zh", re.compile("[\u3400-\u4dbf\u4e00-\u9fff\uf900-\ufaff]")),
    ("hi", re.compile("[\u0900-\u097f]")),
    ("ru", re.compile("[\u0400-\u04ff]")),
)

# Letters that point at one Latin-script language (escaped to keep the source ASCII).
ACCENT_HINTS = {
    "es": "\u00f1\u00bf\u00a1",
    "pt": "\u00e3\u00f5",
    "fr": "\u00e7\u00e8\u00ea\u00e0\u0153",
    "de": "\u00e4\u00f6\u00fc\u00df",
    "it": "\u00ec\u00f2",
}
WORD_PATTERN = re.compile(r"[^\W\d_]+")
# A Latin-script guess must be this strong to override the locale: one shared
# word such as "per" or "com" is not enough to call English text Italian.
MIN_LATIN_SCORE = 1.5
MIN_LATIN_MARGIN = 1.0


def locale_file(code: str) -> str:
    """Path of the JSON file holding one language's messages."""
    return os.path.join(LOCALES_DIR, f"messages_{code.upper()}.json")


@functools.lru_cache(maxsize=None)
def read_locale(code: str) -> dict:
    """Read and cache one locale file; an unreadable file yields an empty locale."""
    try:
        with open(locale_file(code), encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError) as exc:
        logger.error(f"{type(exc).__name__}: {exc}\n{traceback.format_exc()}")
        return {}
    if not isinstance(data, dict):
        logger.error(f"Locale {code} is not a JSON object")
        return {}
    return data


def load_locale(code: str) -> dict:
    """Locale data for `code`; unknown or broken codes fall back to English."""
    lang = (code or "").lower()
    if lang not in CODES:
        lang = DEFAULT_LANGUAGE
    data = read_locale(lang)
    if not data and lang != DEFAULT_LANGUAGE:
        data = read_locale(DEFAULT_LANGUAGE)
    return data


def build_languages() -> Dict[str, str]:
    """Map every supported code to its native language name."""
    return {code: read_locale(code).get("language") or code for code in CODES}


LANGUAGES: Dict[str, str] = build_languages()


def english_name(code: str) -> str:
    """English name of a language, e.g. "Russian" for "ru"."""
    return load_locale(code).get("english_name") or "English"


def message(key: str, lang: str, **fields) -> str:
    """Format a localized message, falling back to English and then to the key."""
    candidates = [load_locale(lang).get("messages", {}).get(key), load_locale(DEFAULT_LANGUAGE).get("messages", {}).get(key)]
    templates = [template for template in candidates if isinstance(template, str)]
    for template in templates:
        try:
            return template.format(**fields)
        except (KeyError, IndexError, ValueError) as exc:
            logger.warning(f"Message {key} ({lang}) does not format: {type(exc).__name__}: {exc}")
    if templates:
        return templates[0]
    logger.warning(f"Message {key} is missing in every locale")
    return key


@functools.lru_cache(maxsize=None)
def stopword_weights() -> Dict[str, Dict[str, float]]:
    """Per-language stopword weights; a word listed by n languages counts 1/n for each."""
    owners: Dict[str, List[str]] = {}
    for code in LATIN_LANGUAGES:
        for word in read_locale(code).get("stopwords", []):
            owners.setdefault(word.lower(), []).append(code)
    weights: Dict[str, Dict[str, float]] = {code: {} for code in LATIN_LANGUAGES}
    for word, codes in owners.items():
        for code in codes:
            weights[code][word] = 1.0 / len(codes)
    return weights


def script_language(text: str) -> Optional[str]:
    """Language implied by a non-Latin script in `text`, if any."""
    for code, pattern in SCRIPT_PATTERNS:
        if pattern.search(text):
            return code
    return None


def latin_scores(text: str) -> Dict[str, float]:
    """Score Latin-script text against each language's stopwords and accent letters."""
    lowered = text.lower()
    words = WORD_PATTERN.findall(lowered)
    weights = stopword_weights()
    scores = {code: sum(weights[code].get(word, 0.0) for word in words) for code in LATIN_LANGUAGES}
    for code, letters in ACCENT_HINTS.items():
        scores[code] += sum(1.0 for letter in letters if letter in lowered)
    return scores


def guess_language(text: Optional[str]) -> Optional[str]:
    """Detected language of `text`, or None when the text gives no clear signal."""
    if not text:
        return None
    by_script = script_language(text)
    if by_script:
        return by_script
    scores = latin_scores(text)
    best = max(scores.values())
    if best <= 0:
        return None
    leaders = [code for code, score in scores.items() if score == best]
    if len(leaders) > 1:
        return None
    return leaders[0]


def confident_language(text: Optional[str]) -> Optional[str]:
    """Language of `text` only when the signal is clear: a non-Latin script or a well-separated Latin score."""
    if not text:
        return None
    by_script = script_language(text)
    if by_script:
        return by_script
    ranked = sorted(latin_scores(text).items(), key=lambda item: item[1], reverse=True)
    best_code, best = ranked[0]
    second = ranked[1][1]
    if best >= MIN_LATIN_SCORE and best - second >= MIN_LATIN_MARGIN:
        return best_code
    return None


def detect_language(text: str) -> str:
    """Language code of `text`: script first, then stopwords and accents; ties or no signal give "en"."""
    return guess_language(text) or DEFAULT_LANGUAGE


def normalize_language(value: Optional[str]) -> Optional[str]:
    """Turn "ru", "RU", "ru_RU.UTF-8", "pt-BR", "russian" or a native name into a code, else None."""
    if not value or not isinstance(value, str):
        return None
    text = value.strip()
    lowered = text.casefold()
    for code in CODES:
        if lowered in (english_name(code).casefold(), LANGUAGES[code].casefold()):
            return code
    head = re.split(r"[_.@\-]", lowered, maxsplit=1)[0]
    if head in CODES:
        return head
    return None


def locale_language() -> Optional[str]:
    """Language from the POSIX locale variables; the first one set wins, as in libc."""
    for name in LOCALE_ENV_VARS:
        value = os.environ.get(name)
        if value:
            return normalize_language(value)
    return None


def resolve_ui_language(cli_lang: Optional[str], request_text: Optional[str]) -> str:
    """UI language: --lang, then $PENGUIN_DO_LANG, then the request itself, then the locale, then "en".

    The request only wins when its language is clear (see confident_language);
    a weak guess comes after the locale, so `ping google.com` stays English.
    """
    for candidate in (cli_lang, os.environ.get("PENGUIN_DO_LANG")):
        code = normalize_language(candidate)
        if code:
            return code
    return confident_language(request_text) or locale_language() or guess_language(request_text) or DEFAULT_LANGUAGE


def main():
    pass


if __name__ == "__main__":
    main()
