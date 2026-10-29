"""The last journal lines, read on demand by the unprivileged service, redacted and templated.

The root agent is not involved. The service's user reads the system journal through its group
(`adm` or `systemd-journal`), with ONE fixed argv (`ARGV`): no shell, no runtime parameter, an
empty environment, `/` as the working directory, a timeout and an output cap. The binary is run
only when it is root-owned and not group- or world-writable.

Each line is JSON. `MESSAGE` (and any field) may be a string, a list of byte values (journald's
form for text that is not UTF-8 or holds control characters), a list of either when a field
repeats, or null over journald's size threshold; each decodes to one string as the journal probes
decode it. Unlike the probes, a line with no readable time or priority is kept (shown as
unknown). Every message is redacted with `neonwatch.redact` before anything else sees it, then
capped, so nothing stored, sent or shown is unredacted.

Templating collapses repeats: the variable parts of a message (UUIDs, MACs, IP addresses, hex
ids, durations, numbers, which covers pids, ports and counters) are masked, and a line's `key`
is a short hash of its source (the syslog identifier, else the unit, masked the same way) and
its template. Two lines with one key are the same kind of line, so one explanation serves both.

`read_journal` never raises: a failure is a `JournalRead` with `error` set.
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import json
import os
import re
import stat
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any

from neonwatch.redact import redact

JOURNALCTL = "/usr/bin/journalctl"
LINES = 200
#: The one command this component runs. Every flag only formats or bounds what is read.
ARGV = (JOURNALCTL, "-n", str(LINES), "-o", "json",
        "--output-fields=MESSAGE,PRIORITY,_SYSTEMD_UNIT,SYSLOG_IDENTIFIER,__REALTIME_TIMESTAMP",
        "--no-pager", "-q")
TIMEOUT_S = 10.0
#: 200 lines measured at ~110 KB on one desktop; past this the read stops and says so.
MAX_OUTPUT = 4 * 1024 * 1024
MAX_STDERR = 4096
MAX_ERROR = 500
#: Characters kept of a message (after redaction), of a template, and of a source name.
MAX_MESSAGE = 2000
MAX_TEMPLATE = 500
MAX_SOURCE = 128
KEY_HEX = 16

#: syslog priorities, 0 (emerg) to 7 (debug).
PRIORITY_NAMES = ("emerg", "alert", "crit", "err", "warning", "notice", "info", "debug")


@dataclass(frozen=True, slots=True)
class LogLine:
    #: Epoch seconds, or None when the journal gave no readable time.
    at: float | None
    #: 0-7, or None when absent or unreadable.
    priority: int | None
    unit: str
    identifier: str
    #: Redacted and capped.
    message: str
    #: The masked source (identifier, else unit) the key is computed over.
    source: str
    template: str
    key: str


@dataclass(frozen=True, slots=True)
class JournalRead:
    #: Oldest first, as journalctl prints them.
    lines: tuple[LogLine, ...]
    #: Lines that were not a JSON object and were left out.
    skipped: int = 0
    #: Output stopped at `MAX_OUTPUT`; the lines are those read before the cut.
    truncated: bool = False
    error: str = ""


# --- templating --------------------------------------------------------------------------------

_HEX = "[0-9A-Fa-f]"
#: Applied in order; each replaces what it matches with its mask. Every pattern starts at a
#: boundary lookbehind, so no pattern retries from every character of a long run.
_MASKS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(rf"(?<!{_HEX}){_HEX}{{8}}-{_HEX}{{4}}-{_HEX}{{4}}-{_HEX}{{4}}-{_HEX}{{12}}"
                rf"(?!{_HEX})"), "<uuid>"),
    (re.compile(rf"(?<![0-9A-Fa-f:]){_HEX}{{2}}(?::{_HEX}{{2}}){{5}}(?![0-9A-Fa-f:])"), "<mac>"),
    # IPv6: eight groups, or a compressed form with `::`; an optional %zone.
    (re.compile(rf"(?<![\w:.])(?:(?:{_HEX}{{1,4}}:){{7}}{_HEX}{{1,4}}"
                rf"|(?:{_HEX}{{1,4}}(?::{_HEX}{{1,4}}){{0,6}})?::"
                rf"(?:{_HEX}{{1,4}}(?::{_HEX}{{1,4}}){{0,6}})?)(?:%[\w.-]+)?(?![\w:])"), "<ip>"),
    (re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])"), "<ip>"),
    (re.compile(r"(?<![0-9A-Za-z])0x[0-9A-Fa-f]+"), "<hex>"),
    # A hex run of 6+ holding a digit and a letter: container ids, hashes, `veth1a2b3c`.
    (re.compile(rf"(?<!{_HEX})(?=[0-9A-Fa-f]*\d)(?=[0-9A-Fa-f]*[A-Fa-f]){_HEX}{{6,}}"
                rf"(?!{_HEX})"), "<hex>"),
    # Durations, several parts collapsing into one: `900ms`, `1.5s`, `2min 3.250s`.
    (re.compile(r"(?<![\w.])\d+(?:\.\d+)?\s?(?:ns|us|µs|ms|s|sec|min|h)"
                r"(?:\s\d+(?:\.\d+)?\s?(?:ns|us|µs|ms|s|sec|min|h)){0,4}(?![\w])"), "<dur>"),
    (re.compile(r"\d+(?:\.\d+)?"), "<n>"),
)
_SPACE = re.compile(r"\s+")


def template_of(text: str) -> str:
    """`text` with its variable parts masked and whitespace collapsed, capped."""
    for pattern, mask in _MASKS:
        text = pattern.sub(mask, text)
    return _SPACE.sub(" ", text).strip()[:MAX_TEMPLATE]


def template_key(source: str, template: str) -> str:
    """The short hash naming one kind of line from one source."""
    digest = hashlib.sha256(f"{source}\x00{template}".encode("utf-8", "surrogatepass"))
    return digest.hexdigest()[:KEY_HEX]


# --- parsing -----------------------------------------------------------------------------------


def field_text(value: Any) -> str:
    """A journal JSON field as one string, coerced as the journal probes coerce it
    (docs/probes.md): text as is, a list of byte values decoded with replacement, a repeated
    field joined with `|`, and `null` (over journald's size threshold) or anything else `""`."""
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        if all(isinstance(b, int) and not isinstance(b, bool) and 0 <= b <= 255 for b in value):
            return bytes(value).decode("utf-8", "replace")
        return "|".join(field_text(item) for item in value)
    return ""


def _priority(value: Any) -> int | None:
    text = field_text(value).strip()
    return int(text) if text.isdigit() and int(text) < len(PRIORITY_NAMES) else None


def _realtime(value: Any) -> float | None:
    text = field_text(value).strip()
    return int(text) / 1_000_000 if text.isdigit() else None


def parse_line(entry: dict[str, Any]) -> LogLine:
    """One journal entry, its message redacted before anything else reads it."""
    message, _ = redact(field_text(entry.get("MESSAGE")))
    message = message[:MAX_MESSAGE]
    unit = redact(field_text(entry.get("_SYSTEMD_UNIT")))[0][:MAX_SOURCE]
    identifier = redact(field_text(entry.get("SYSLOG_IDENTIFIER")))[0][:MAX_SOURCE]
    source = template_of(identifier or unit)[:MAX_SOURCE]
    template = template_of(message)
    return LogLine(at=_realtime(entry.get("__REALTIME_TIMESTAMP")),
                   priority=_priority(entry.get("PRIORITY")), unit=unit, identifier=identifier,
                   message=message, source=source, template=template,
                   key=template_key(source, template))


def parse(output: bytes, truncated: bool = False) -> JournalRead:
    """Every complete JSON-object line of `output`; the rest is counted in `skipped`."""
    text = output.decode("utf-8", "replace")
    pieces = text.split("\n")
    if truncated:
        pieces = pieces[:-1]  # the last piece was cut mid-line
    lines, skipped = [], 0
    for piece in pieces:
        if not piece.strip():
            continue
        try:
            entry = json.loads(piece)
        except ValueError:
            skipped += 1
            continue
        if not isinstance(entry, dict):
            skipped += 1
            continue
        lines.append(parse_line(entry))
    return JournalRead(lines=tuple(lines), skipped=skipped, truncated=truncated)


# --- reading -----------------------------------------------------------------------------------


def binary_refusal(st: os.stat_result) -> str:
    """Why a binary with this stat is not trusted to run, or `""`."""
    if st.st_uid != 0:
        return f"not owned by root (uid {st.st_uid})"
    if st.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        return f"group- or world-writable (mode {stat.S_IMODE(st.st_mode):o})"
    return ""


async def _bounded(stream: asyncio.StreamReader, limit: int) -> tuple[bytes, bool]:
    """Up to `limit` bytes of `stream`, and whether there was more."""
    data = b""
    while len(data) <= limit:
        chunk = await stream.read(65536)
        if not chunk:
            return data, False
        data += chunk
    return data[:limit], True


async def _output(process: Any) -> tuple[bytes, bool, bytes]:
    """(stdout, whether it was cut at the cap, stderr). Past the cap, stderr is not waited for."""
    errors = asyncio.ensure_future(_bounded(process.stderr, MAX_STDERR))
    try:
        out, cut = await _bounded(process.stdout, MAX_OUTPUT)
        if cut:
            return out, True, b""
        return out, False, (await errors)[0]
    finally:
        errors.cancel()


async def read_journal(timeout_s: float = TIMEOUT_S) -> JournalRead:
    """The last `LINES` journal lines, parsed and redacted. Never raises."""
    try:
        refusal = binary_refusal(os.stat(JOURNALCTL))
    except OSError as error:
        return JournalRead((), error=f"cannot check {JOURNALCTL}: {error}"[:MAX_ERROR])
    if refusal:
        return JournalRead((), error=f"refusing to run {JOURNALCTL}: {refusal}")
    try:
        process = await asyncio.create_subprocess_exec(
            *ARGV, stdin=asyncio.subprocess.DEVNULL, stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE, env={}, cwd="/")
    except OSError as error:
        return JournalRead((), error=f"journalctl could not run: {error}"[:MAX_ERROR])
    try:
        out, cut, err = await asyncio.wait_for(_output(process), timeout_s)
    except TimeoutError:
        await _stop(process)
        return JournalRead((), error=f"journalctl did not finish within {timeout_s:g} s")
    if cut:
        await _stop(process)
        return parse(out, truncated=True)
    code = await process.wait()
    if code != 0:
        detail = redact(err.decode("utf-8", "replace").strip())[0]
        return JournalRead((), error=f"journalctl exited {code}: {detail}"[:MAX_ERROR])
    return parse(out)


async def _stop(process: Any) -> None:
    with contextlib.suppress(ProcessLookupError):  # it may have exited meanwhile
        process.kill()
    await process.wait()


#: What the web layer is handed: a call that reads the journal now.
Reader = Callable[[], Awaitable[JournalRead]]
