"""Desktop notifications for issues: the threshold, the dedupe, the rate limits, and the D-Bus call.

`Notifier.consider` decides whether an issue reaches the desktop. It is async because it awaits
the injected `send`, which the service wires to `gdbus_send` (and tests to a fake):

- only an OPEN issue at or above `notify.min_severity` is sent, and `notify.enabled = False`
  sends nothing;
- once per (issue, severity): an escalation above the highest severity already sent for that
  issue notifies again, a de-escalation or a repeat does not;
- per issue, at most one notification per `notify.rate_limit_s`;
- globally, at most `GLOBAL_LIMIT` per `GLOBAL_WINDOW_S`. Past that, issues are held and one
  summary per window says how many were held since the last summary.

An issue that was held or whose send failed is not recorded as sent, so its next update after
the limit clears delivers it. `send` returns an error string or None, and never raises;
`gdbus_send` keeps that contract so no desktop failure reaches the service loop.
"""

from __future__ import annotations

import asyncio
import os
import stat
from collections import deque
from collections.abc import Awaitable, Callable
from dataclasses import dataclass

from neonwatch.config import Config
from neonwatch.schema import Issue, IssueState, Severity

#: Exec'd by absolute path, never resolved from PATH (security review).
GDBUS = "/usr/bin/gdbus"
GLOBAL_LIMIT = 5
GLOBAL_WINDOW_S = 60.0
MAX_SUMMARY = 120
MAX_BODY = 400
MAX_ERROR = 500
GDBUS_TIMEOUT_S = 10.0
TIMEOUT_MS = 10_000

#: Severity -> the freedesktop urgency byte: 0 low, 1 normal, 2 critical.
URGENCY = {Severity.INFO: 0, Severity.WATCH: 1, Severity.WARN: 1, Severity.CRITICAL: 2}
ICON = {0: "dialog-information", 1: "dialog-warning", 2: "dialog-error"}


@dataclass(frozen=True, slots=True)
class Notification:
    #: The issue it is about, or None for a storm summary.
    issue_id: str | None
    summary: str
    body: str
    urgency: int


#: Sends one notification; returns an error string, or None when it was delivered.
Send = Callable[[Notification], Awaitable[str | None]]


class Notifier:
    def __init__(self, send: Send, config: Config, clock: Callable[[], float]) -> None:
        self._send = send
        self._enabled = config.notify.enabled
        self._min_rank = Severity(config.notify.min_severity).rank
        self._rate_limit_s = config.notify.rate_limit_s
        self._clock = clock
        #: issue id -> the highest severity rank sent for it.
        self._sent_rank: dict[str, int] = {}
        #: issue id -> when it was last sent.
        self._sent_at: dict[str, float] = {}
        #: When each recent issue notification went out, oldest first.
        self._window: deque[float] = deque()
        #: issue id -> urgency, for issues held by the global limit since the last summary.
        self._held: dict[str, int] = {}
        self._summary_at: float | None = None

    async def consider(self, issue: Issue) -> Notification | None:
        """What was sent for this issue (itself or a storm summary), or None."""
        rank = issue.severity.rank
        if (not self._enabled or issue.state is not IssueState.OPEN or rank < self._min_rank
                or rank <= self._sent_rank.get(issue.id, -1)):
            return None
        now = self._clock()
        last = self._sent_at.get(issue.id)
        if last is not None and now - last < self._rate_limit_s:
            return None
        while self._window and now - self._window[0] >= GLOBAL_WINDOW_S:
            self._window.popleft()
        urgency = URGENCY[issue.severity]
        if len(self._window) >= GLOBAL_LIMIT:
            self._held[issue.id] = urgency
            return await self._summarise(now)
        notification = Notification(
            issue_id=issue.id,
            summary=_cap(f"neonwatch: {issue.severity.name} — {issue.title}", MAX_SUMMARY),
            body=_cap(f"{issue.domain}/{issue.entity}\n{issue.next_step}", MAX_BODY),
            urgency=urgency)
        if await self._send(notification) is not None:
            return None
        self._sent_rank[issue.id] = rank
        self._sent_at[issue.id] = now
        self._window.append(now)
        self._held.pop(issue.id, None)
        return notification

    async def _summarise(self, now: float) -> Notification | None:
        if self._summary_at is not None and now - self._summary_at < GLOBAL_WINDOW_S:
            return None
        count = len(self._held)
        noun = "issue needs" if count == 1 else "issues need"
        notification = Notification(
            issue_id=None, summary=f"neonwatch: {count} more {noun} attention",
            body="Held back to avoid flooding the desktop. Open the neonwatch dashboard.",
            urgency=max(self._held.values()))
        if await self._send(notification) is not None:
            return None
        self._summary_at = now
        self._held.clear()
        return notification


def _cap(text: str, limit: int) -> str:
    return text if len(text) <= limit else text[: limit - 1] + "…"


def gvariant_string(text: str) -> str:
    """`text` as a GVariant text-format string literal that g_variant_parse reads back exactly.

    Single-quoted; backslash and quote are escaped, newline and tab use their short escapes,
    other control characters are \\u escapes, and NUL (which a GVariant string cannot hold) is
    dropped.
    """
    out = []
    for ch in text:
        if ch in "\\'":
            out.append("\\" + ch)
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\t":
            out.append("\\t")
        elif ch == "\x00":
            continue
        elif ch < " " or ch == "\x7f":
            out.append(f"\\u{ord(ch):04x}")
        else:
            out.append(ch)
    return "'" + "".join(out) + "'"


def _escape_markup(text: str) -> str:
    """Notification bodies may be read as markup; issue text is not markup."""
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def gdbus_argv(notification: Notification) -> list[str]:
    """The fixed argv for org.freedesktop.Notifications.Notify carrying `notification`."""
    if notification.urgency not in ICON:
        raise ValueError(f"urgency must be 0, 1 or 2, not {notification.urgency!r}")
    return [
        GDBUS, "call", "--session",
        "--dest", "org.freedesktop.Notifications",
        "--object-path", "/org/freedesktop/Notifications",
        "--method", "org.freedesktop.Notifications.Notify",
        gvariant_string("neonwatch"),                      # app_name
        "uint32 0",                                       # replaces_id
        gvariant_string(ICON[notification.urgency]),     # app_icon
        gvariant_string(notification.summary),
        gvariant_string(_escape_markup(notification.body)),
        "@as []",                                         # actions
        f"{{'urgency': <byte {notification.urgency}>}}",  # hints
        f"int32 {TIMEOUT_MS}",                            # expire_timeout
    ]


def binary_refusal(st: os.stat_result) -> str:
    """Why a binary with this stat is not trusted to run, or `""`."""
    if st.st_uid != 0:
        return f"not owned by root (uid {st.st_uid})"
    if st.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        return f"group- or world-writable (mode {stat.S_IMODE(st.st_mode):o})"
    return ""


async def gdbus_send(notification: Notification) -> str | None:
    """Show `notification` on the session bus. Returns an error string, or None; never raises.

    Refuses to run `GDBUS` unless it is root-owned and not group- or world-writable.
    """
    try:
        argv = gdbus_argv(notification)
    except ValueError as error:
        return str(error)
    try:
        refusal = binary_refusal(os.stat(GDBUS))
    except OSError as error:
        return _cap(f"cannot check {GDBUS}: {error}", MAX_ERROR)
    if refusal:
        return f"refusing to run {GDBUS}: {refusal}"
    try:
        process = await asyncio.create_subprocess_exec(
            *argv, stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    except OSError as error:
        return _cap(f"gdbus could not run: {error}", MAX_ERROR)
    try:
        _, stderr = await asyncio.wait_for(process.communicate(), GDBUS_TIMEOUT_S)
    except TimeoutError:
        process.kill()
        await process.wait()
        return f"gdbus timed out after {GDBUS_TIMEOUT_S} s"
    if process.returncode != 0:
        detail = stderr.decode(errors="replace").strip()
        return _cap(f"gdbus exited {process.returncode}: {detail}", MAX_ERROR)
    return None
