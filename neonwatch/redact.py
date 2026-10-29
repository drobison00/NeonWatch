"""Secret-shaped text removed from anything leaving the root agent.

Two passes. Values under a key that names a secret (`password`, `token`, `api_key`...) are
replaced whole, whatever they look like. Everywhere else, text is scanned for token shapes —
bearer headers, forge and cloud keys, private key blocks, `KEY=value` assignments of secret names
on a command line — and each is replaced and counted.

Command lines get the shapes cron jobs and unit files use: `curl -u/--user u:p`,
`-pPASS` after a mysql/mariadb word, `sshpass -p`, `smbclient -U u%p`, `Authorization:` and
API-key headers, secret query parameters, and URL credentials with or without a user. Where a
shape has a harmless lead (the command, the header name, `?key=`), that lead is kept in front
of the mask so the reader still sees what ran.

This is a floor, not a proof: it catches what has a recognisable shape, and a job's command is
written by whoever owns the job, so it is hygiene, not a boundary. It does not model a password
passed positionally, in a file a command reads, or under a flag of a tool not named above. The
count travels with the observation so a reader can see that something was cut.

Every pattern starts at a fixed anchor (a lookbehind, a literal, or a bounded gap), so no
pattern retries from every character of a long word, and where an anchor can recur within one
word (`-u` after any non-word character) the run that follows it is bounded, so each start scans
a bounded distance: linear in what a local user controls.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

MASK = "[REDACTED]"

#: A key naming a secret. Matched against the whole key, case-insensitively.
SECRET_KEY = re.compile(
    r"(?i)^.*(pass(word|wd|phrase)?|_pwd|secret|token|api[_-]?key|private[_-]?key|credential|"
    r"auth(orization)?|cookie|session[_-]?id|access[_-]?key)s?$")

TOKENS = re.compile("|".join([
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----",
    r"(?i:bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}",
    r"\bfga?_[A-Za-z0-9]{16,}",
    r"\b(?:sk|pk|rk)-[A-Za-z0-9_-]{16,}",
    r"\bgh[pousr]_[A-Za-z0-9]{20,}",
    r"\bgithub_pat_[A-Za-z0-9_]{20,}",
    r"\bxox[abprs]-[A-Za-z0-9-]{10,}",
    r"\bAKIA[0-9A-Z]{16}\b",
    r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",  # a JWT
    # Hyphens count as part of a key: `-dev-root-token-id=value` is a live command-line shape.
    # The lookbehind anchors the match to the START of a key: without it the engine retries
    # from every character of an unbroken word, which is quadratic in a length any local user
    # controls (a journal message, a process argument) — CPU burned as root.
    # The key is then taken whole and never given back (`++`), with a lookahead for the secret
    # word: `[A-Z0-9_-]*word[A-Z0-9_-]*` backtracks over every occurrence of the word in one long
    # key, quadratic again (`atokenatoken...`, 1.3 s for 24 KB before this).
    r"(?<![A-Za-z0-9_-])(?i:(?=[A-Z0-9_-]*?(?:pass(?:word|wd)?|_pwd|secret|token|api[_-]?key|"
    r"credential))[A-Z0-9_-]++)"
    r"\s*[=:]\s*[\"']?[^\s\"',;]{4,}",
    r"(?i:--(?:password|passwd|token|secret|api-key))[= ]\S+",
    r"://[^/\s:@]*:[^/\s@]+@",  # credentials in a URL, the user possibly empty
    # From here on, a pattern's one capturing group is the harmless lead kept before the mask.
    # curl -u/--user user:pass; a password that is all digits is a uid:gid (`docker -u 0:0`).
    # The user is bounded and never given back: every `-u` after a non-word character is a fresh
    # start, so an unbounded user made each one scan to the end of the word, quadratic in a word
    # of `(-u(-u...` (0.45 s for 24 KB; `(--user=` 1.2 s). A longer user is not taken for one.
    r"(?<![\w-])(?:-u\s*+|--user[=\s]\s*+)[\"']?[^\s:\"']{1,256}+:(?!/)"
    r"(?=[^\s\"']*[^\d\s\"'])[^\s\"']+",
    # -pPASS (no space: `-p` alone prompts) within 256 characters of a mysql/mariadb word.
    r"((?<![\w-])(?:mysql|mysqldump|mysqladmin|mariadb|mariadb-dump)(?![\w-])[^\n|;&]{0,256}?"
    r"\s)-p[\"']?[^\s\"']+[\"']?",
    r"((?<![\w-])sshpass\s+)-p\s*[\"']?[^\s\"']+",
    # smbclient -U user%pass; the user bounded for the same reason as `-u`'s.
    r"(?<![\w-])-U\s*+[\"']?[^\s%\"']{1,256}+%[^\s\"']+",
    r"((?<![\w-])(?i:proxy-)?(?i:authorization)\s*:\s*)[^\s\"']+(?:[ \t]+[^\s\"']+)?",
    r"((?<![\w-])(?i:x-api-key|api-key|x-auth-token|token)\s*:\s*)[^\s\"']+",
    r"([?&](?i:key|apikey|api_key|token|access_token|auth|sig|signature|password)=)[^&\s\"'#]+",
]))


def _mask(match: re.Match[str]) -> str:
    return next((lead for lead in match.groups() if lead is not None), "") + MASK


def redact(text: str) -> tuple[str, int]:
    """`text` with every token shape replaced, and how many there were."""
    return TOKENS.subn(_mask, text)


def redact_mapping(data: Mapping[str, Any]) -> tuple[dict[str, Any], int]:
    """A copy of `data` with secret-named values masked and token shapes cut, recursively."""
    out, count = _walk(dict(data))
    return out, count


def _walk(value: Any, key: str = "") -> tuple[Any, int]:
    if key and SECRET_KEY.match(key) and value not in (None, "", [], {}):
        return MASK, 1
    if isinstance(value, str):
        return redact(value)
    if isinstance(value, Mapping):
        total, out = 0, {}
        for name, item in value.items():
            out[name], found = _walk(item, str(name))
            total += found
        return out, total
    if isinstance(value, list | tuple):
        total, items = 0, []
        for item in value:
            cleaned, found = _walk(item)
            items.append(cleaned)
            total += found
        return (tuple(items) if isinstance(value, tuple) else items), total
    return value, 0
