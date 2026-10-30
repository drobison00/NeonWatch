"""The notifier decides when an issue reaches the desktop; D-Bus is never touched here."""

from __future__ import annotations

import asyncio
import dataclasses
import os
import stat

import pytest

from neonwatch import notifier
from neonwatch.config import Config, Notify
from neonwatch.notifier import (
    GDBUS,
    GLOBAL_LIMIT,
    GLOBAL_WINDOW_S,
    MAX_BODY,
    MAX_SUMMARY,
    Notification,
    Notifier,
    binary_refusal,
    gdbus_argv,
    gdbus_send,
    gvariant_string,
)
from neonwatch.schema import Issue, IssueState, Severity


class Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


class Sent:
    """A fake `send` that records what it was given and fails when told to."""

    def __init__(self) -> None:
        self.calls: list[Notification] = []
        self.fail: str | None = None

    async def __call__(self, notification: Notification) -> str | None:
        self.calls.append(notification)
        return self.fail


def issue(id: str = "disk-nvme0", **overrides) -> Issue:
    fields = {"id": id, "state": IssueState.OPEN, "severity": Severity.CRITICAL,
              "title": "nvme0 reports a critical warning", "domain": "storage",
              "entity": "nvme0n1", "opened_at": 1.0, "updated_at": 2.0, "deterministic": True,
              "reasons": ("smart.critical_warning",),
              "next_step": "Back up now and replace the drive."}
    fields.update(overrides)
    return Issue(**fields)


def make(min_severity: str = "critical", rate_limit_s: int = 300, enabled: bool = True):
    config = Config(notify=Notify(enabled=enabled, min_severity=min_severity,
                                  rate_limit_s=rate_limit_s))
    sent, clock = Sent(), Clock()
    return Notifier(sent, config, clock), sent, clock


# --- across a restart ----------------------------------------------------------------------


async def test_what_was_sent_is_recorded_and_a_new_notifier_does_not_send_it_again():
    # 2026-10-30: every service restart re-sent every open issue to the desktop.
    recorded: dict[str, tuple[int, float]] = {}
    config = Config(notify=Notify(min_severity="warn", rate_limit_s=300))
    sent, clock = Sent(), Clock()
    first = Notifier(sent, config, clock, record=lambda i, r, at: recorded.update({i: (r, at)}))
    assert await first.consider(issue()) is not None
    assert recorded == {"disk-nvme0": (Severity.CRITICAL.rank, clock())}
    clock.now += 3600
    again = Notifier(sent, config, clock, sent=recorded)
    assert await again.consider(issue()) is None                        # same severity: once
    assert await again.consider(issue(severity=Severity.WARN)) is None   # lower: never
    assert await again.consider(issue(id="disk-nvme1")) is not None            # another issue: sent
    assert len(sent.calls) == 2


async def test_an_escalation_after_a_restart_still_waits_out_the_rate_limit():
    config = Config(notify=Notify(min_severity="warn", rate_limit_s=300))
    sent, clock = Sent(), Clock()
    earlier = {"disk-nvme0": (Severity.WARN.rank, clock() - 60)}
    restarted = Notifier(sent, config, clock, sent=earlier)
    assert await restarted.consider(issue()) is None    # CRITICAL, but WARN went 60 s ago
    clock.now += 300
    assert await restarted.consider(issue()) is not None


# --- threshold and state -------------------------------------------------------------------


async def test_an_open_issue_at_the_threshold_is_sent():
    n, sent, _ = make()
    got = await n.consider(issue())
    assert got == Notification(
        issue_id="disk-nvme0",
        summary="neonwatch: CRITICAL — nvme0 reports a critical warning",
        body="storage/nvme0n1\nBack up now and replace the drive.",
        urgency=2)
    assert sent.calls == [got]


async def test_below_the_threshold_is_not_sent():
    n, sent, _ = make(min_severity="warn")
    assert await n.consider(issue(severity=Severity.WATCH)) is None
    assert await n.consider(issue(id="b", severity=Severity.INFO)) is None
    assert sent.calls == []


async def test_above_the_threshold_is_sent_with_its_own_urgency():
    n, _, _ = make(min_severity="info")
    urgencies = {}
    for severity in Severity:
        got = await n.consider(issue(id=severity.value, severity=severity))
        urgencies[severity] = got.urgency
        assert got.summary.startswith(f"neonwatch: {severity.name} — ")
    assert urgencies == {Severity.INFO: 0, Severity.WATCH: 1, Severity.WARN: 1,
                         Severity.CRITICAL: 2}


@pytest.mark.parametrize("state", [IssueState.ACKNOWLEDGED, IssueState.SNOOZED,
                                   IssueState.RESOLVED])
async def test_only_open_issues_are_sent(state):
    n, sent, _ = make()
    assert await n.consider(issue(state=state)) is None
    assert sent.calls == []


async def test_disabled_never_sends():
    n, sent, _ = make(enabled=False, min_severity="info")
    assert await n.consider(issue()) is None
    assert sent.calls == []


# --- once per (issue, severity) ------------------------------------------------------------


async def test_a_repeat_at_the_same_severity_is_not_sent_even_after_the_rate_limit():
    n, sent, clock = make()
    assert await n.consider(issue()) is not None
    clock.now += 10_000
    assert await n.consider(issue(updated_at=99.0)) is None
    assert len(sent.calls) == 1


async def test_an_escalation_is_sent_again():
    n, sent, clock = make(min_severity="warn")
    assert (await n.consider(issue(severity=Severity.WARN))).urgency == 1
    clock.now += 300
    assert (await n.consider(issue(severity=Severity.CRITICAL))).urgency == 2
    assert len(sent.calls) == 2


async def test_a_de_escalation_is_not_sent_nor_its_return():
    n, sent, clock = make(min_severity="warn")
    await n.consider(issue(severity=Severity.CRITICAL))
    clock.now += 1000
    assert await n.consider(issue(severity=Severity.WARN)) is None
    clock.now += 1000
    assert await n.consider(issue(severity=Severity.CRITICAL)) is None
    assert len(sent.calls) == 1


async def test_an_acknowledged_issue_that_reopens_at_the_same_severity_is_not_sent():
    n, _, clock = make()
    await n.consider(issue())
    await n.consider(issue(state=IssueState.ACKNOWLEDGED))
    clock.now += 1000
    assert await n.consider(issue()) is None


# --- per-issue rate limit ------------------------------------------------------------------


async def test_an_escalation_inside_the_rate_limit_waits_for_it():
    n, sent, clock = make(min_severity="warn", rate_limit_s=300)
    await n.consider(issue(severity=Severity.WARN))
    clock.now += 299
    assert await n.consider(issue(severity=Severity.CRITICAL)) is None
    clock.now += 1
    # Not recorded as notified while held, so the next update after the window delivers it.
    assert (await n.consider(issue(severity=Severity.CRITICAL))).urgency == 2
    assert len(sent.calls) == 2


async def test_the_rate_limit_is_per_issue():
    n, sent, _ = make()
    await n.consider(issue("a"))
    assert await n.consider(issue("b")) is not None
    assert len(sent.calls) == 2


# --- global rate limit ---------------------------------------------------------------------


async def test_a_storm_gets_one_summary_instead_of_a_flood():
    n, sent, clock = make()
    for i in range(GLOBAL_LIMIT):
        assert await n.consider(issue(f"i{i}")) is not None
        clock.now += 1
    summary = await n.consider(issue("over-1"))
    assert summary == Notification(
        issue_id=None, summary="neonwatch: 1 more issue needs attention",
        body="Held back to avoid flooding the desktop. Open the neonwatch dashboard.",
        urgency=2)
    assert await n.consider(issue("over-2")) is None
    assert await n.consider(issue("over-3")) is None
    assert await n.consider(issue("over-2")) is None  # a repeat is not counted twice
    assert len(sent.calls) == GLOBAL_LIMIT + 1


async def test_the_window_slides_and_the_next_summary_counts_what_was_held():
    n, sent, clock = make()
    start = clock.now
    for i in range(GLOBAL_LIMIT):
        await n.consider(issue(f"i{i}"))
    await n.consider(issue("over-1"))          # the summary
    await n.consider(issue("over-2"))          # held
    await n.consider(issue("over-3"))          # held
    clock.now = start + GLOBAL_WINDOW_S
    # The window has room again: a held issue is delivered on its next update.
    assert (await n.consider(issue("over-2"))).issue_id == "over-2"
    for i in range(GLOBAL_LIMIT - 1):
        assert (await n.consider(issue(f"j{i}"))).issue_id == f"j{i}"
    summary = await n.consider(issue("over-4"))
    assert summary.summary == "neonwatch: 2 more issues need attention"  # over-3 and over-4
    assert await n.consider(issue("over-5")) is None
    assert sum(call.issue_id is None for call in sent.calls) == 2
    assert len(sent.calls) == 2 * GLOBAL_LIMIT + 2


async def test_only_one_summary_per_window():
    n, sent, clock = make()
    for i in range(GLOBAL_LIMIT):
        await n.consider(issue(f"i{i}"))
    assert (await n.consider(issue("over-1"))).issue_id is None
    clock.now += GLOBAL_WINDOW_S - 1
    assert await n.consider(issue("over-2")) is None
    assert len(sent.calls) == GLOBAL_LIMIT + 1


async def test_the_summary_urgency_is_the_highest_held():
    n, _, _ = make(min_severity="warn")
    for i in range(GLOBAL_LIMIT):
        await n.consider(issue(f"i{i}"))
    assert (await n.consider(issue("over", severity=Severity.WARN))).urgency == 1


# --- a failed send -------------------------------------------------------------------------


async def test_a_failed_send_is_not_recorded_and_is_retried():
    n, sent, _ = make()
    sent.fail = "no session bus"
    assert await n.consider(issue()) is None
    sent.fail = None
    assert await n.consider(issue()) is not None
    assert len(sent.calls) == 2


async def test_failed_sends_do_not_use_up_the_global_limit():
    n, sent, _ = make()
    sent.fail = "no session bus"
    for i in range(GLOBAL_LIMIT + 3):
        assert await n.consider(issue(f"i{i}")) is None
    sent.fail = None
    for i in range(GLOBAL_LIMIT):
        assert (await n.consider(issue(f"j{i}"))).issue_id == f"j{i}"


async def test_a_failed_summary_is_retried_on_the_next_overflow():
    n, sent, _ = make()
    for i in range(GLOBAL_LIMIT):
        await n.consider(issue(f"i{i}"))
    sent.fail = "no session bus"
    assert await n.consider(issue("over-1")) is None
    sent.fail = None
    got = await n.consider(issue("over-2"))
    assert got.summary == "neonwatch: 2 more issues need attention"


# --- text ----------------------------------------------------------------------------------


async def test_long_text_is_capped():
    n, _, _ = make()
    got = await n.consider(issue(title="t" * 1000, next_step="s" * 5000, entity="e" * 300))
    assert len(got.summary) == MAX_SUMMARY and got.summary.endswith("…")
    assert len(got.body) == MAX_BODY and got.body.endswith("…")
    assert got.body.startswith("storage/eee")


async def test_short_text_is_untouched():
    n, _, _ = make()
    got = await n.consider(issue(title="x", next_step="y", domain="d", entity="e"))
    assert (got.summary, got.body) == ("neonwatch: CRITICAL — x", "d/e\ny")


# --- the gdbus argv ------------------------------------------------------------------------


@pytest.mark.parametrize(("text", "literal"), [
    ("plain", "'plain'"),
    ("it's", r"'it\'s'"),
    ('say "hi"', "'say \"hi\"'"),
    ("back\\slash", r"'back\\slash'"),
    ("two\nlines", r"'two\nlines'"),
    ("tab\there", r"'tab\there'"),
    ("bell\x07cr\r", r"'bell\u0007cr\u000d'"),
    ("nul\x00gone", "'nulgone'"),
    ("del\x7f", r"'del\u007f'"),
    ("\\'", r"'\\\''"),
    ("ünïcode — ok", "'ünïcode — ok'"),
    ("", "''"),
])
def test_gvariant_string_quoting(text, literal):
    assert gvariant_string(text) == literal


def test_gdbus_argv_is_fixed_and_carries_the_notification():
    note = Notification(issue_id="x", summary="neonwatch: CRITICAL — it's \"bad\"",
                        body="a\\b\nc <b>&</b>", urgency=2)
    assert gdbus_argv(note) == [
        "/usr/bin/gdbus", "call", "--session",
        "--dest", "org.freedesktop.Notifications",
        "--object-path", "/org/freedesktop/Notifications",
        "--method", "org.freedesktop.Notifications.Notify",
        "'neonwatch'",
        "uint32 0",
        "'dialog-error'",
        r"""'neonwatch: CRITICAL — it\'s "bad"'""",
        r"'a\\b\nc &lt;b&gt;&amp;&lt;/b&gt;'",
        "@as []",
        "{'urgency': <byte 2>}",
        "int32 10000",
    ]


@pytest.mark.parametrize(("urgency", "icon"), [(0, "'dialog-information'"),
                                                (1, "'dialog-warning'"),
                                                (2, "'dialog-error'")])
def test_gdbus_argv_icon_and_urgency_follow_the_urgency(urgency, icon):
    argv = gdbus_argv(Notification(issue_id=None, summary="s", body="b", urgency=urgency))
    assert argv[11] == icon
    assert argv[15] == f"{{'urgency': <byte {urgency}>}}"


def test_gdbus_argv_refuses_an_unknown_urgency():
    with pytest.raises(ValueError, match="urgency"):
        gdbus_argv(Notification(issue_id=None, summary="s", body="b", urgency=3))


# --- gdbus_send with the subprocess faked --------------------------------------------------


class FakeProcess:
    def __init__(self, returncode: int, stderr: bytes = b"", hang: bool = False) -> None:
        self.returncode = returncode
        self._stderr = stderr
        self._hang = hang
        self.killed = False

    async def communicate(self):
        if self._hang:
            await asyncio.sleep(3600)
        return b"(uint32 7,)\n", self._stderr

    def kill(self):
        self.killed = True

    async def wait(self):
        return self.returncode


def fake_exec(monkeypatch, result, trusted=True):
    """Fake the exec; `trusted` also stands in a binary that passes the ownership check."""
    seen = {}
    if trusted:
        monkeypatch.setattr(notifier, "GDBUS", __file__)  # exists on every host
        monkeypatch.setattr(notifier, "binary_refusal", lambda st: "")

    async def create_subprocess_exec(*argv, **kwargs):
        seen["argv"], seen["kwargs"] = list(argv), kwargs
        if isinstance(result, BaseException):
            raise result
        return result

    monkeypatch.setattr(notifier.asyncio, "create_subprocess_exec", create_subprocess_exec)
    return seen


NOTE = Notification(issue_id="x", summary="s", body="b", urgency=1)


async def test_gdbus_send_runs_the_fixed_argv_without_a_shell(monkeypatch):
    seen = fake_exec(monkeypatch, FakeProcess(0))
    assert await gdbus_send(NOTE) is None
    assert seen["argv"] == gdbus_argv(NOTE)
    assert "shell" not in seen["kwargs"]
    assert seen["kwargs"]["stdin"] == asyncio.subprocess.DEVNULL


async def test_gdbus_send_reports_a_non_zero_exit(monkeypatch):
    fake_exec(monkeypatch, FakeProcess(
        1, b"Error connecting: Cannot autolaunch D-Bus without X11 $DISPLAY\n"))
    error = await gdbus_send(NOTE)
    assert error == "gdbus exited 1: Error connecting: Cannot autolaunch D-Bus without X11 $DISPLAY"


async def test_gdbus_send_caps_a_long_error(monkeypatch):
    fake_exec(monkeypatch, FakeProcess(1, b"x" * 10_000))
    assert len(await gdbus_send(NOTE)) < 600


async def test_gdbus_send_reports_a_missing_binary(monkeypatch):
    fake_exec(monkeypatch, FileNotFoundError(2, "No such file or directory", "gdbus"))
    assert (await gdbus_send(NOTE)).startswith("gdbus could not run: ")


def test_gdbus_is_an_absolute_path():
    assert GDBUS == "/usr/bin/gdbus"


def stat_of(mode: int, uid: int) -> os.stat_result:
    return os.stat_result((stat.S_IFREG | mode, 1, 1, 1, uid, 0, 100, 0, 0, 0))


@pytest.mark.parametrize(("mode", "uid", "why"), [
    (0o755, 0, ""),
    (0o555, 0, ""),
    (0o755, 1000, "not owned by root"),
    (0o775, 0, "group- or world-writable"),
    (0o757, 0, "group- or world-writable"),
    (0o777, 1000, "not owned by root"),
])
def test_binary_refusal(mode, uid, why):
    refusal = binary_refusal(stat_of(mode, uid))
    assert (why in refusal) if why else refusal == ""


async def test_gdbus_send_refuses_a_binary_not_owned_by_root(monkeypatch, tmp_path):
    fake = tmp_path / "gdbus"
    fake.write_text("#!/bin/sh\n")
    monkeypatch.setattr(notifier, "GDBUS", str(fake))
    seen = fake_exec(monkeypatch, FakeProcess(0), trusted=False)
    error = await gdbus_send(NOTE)
    assert error == f"refusing to run {fake}: not owned by root (uid {os.getuid()})"
    assert seen == {}


async def test_gdbus_send_refuses_a_missing_binary_without_running(monkeypatch, tmp_path):
    monkeypatch.setattr(notifier, "GDBUS", str(tmp_path / "absent"))
    seen = fake_exec(monkeypatch, FakeProcess(0), trusted=False)
    assert (await gdbus_send(NOTE)).startswith(f"cannot check {tmp_path / 'absent'}: ")
    assert seen == {}


async def test_gdbus_send_reports_an_unknown_urgency_without_running(monkeypatch):
    seen = fake_exec(monkeypatch, FakeProcess(0))
    bad = Notification(issue_id=None, summary="s", body="b", urgency=9)
    assert (await gdbus_send(bad)).startswith("urgency must be")
    assert seen == {}


async def test_gdbus_send_kills_a_hung_call(monkeypatch):
    process = FakeProcess(0, hang=True)
    fake_exec(monkeypatch, process)
    monkeypatch.setattr(notifier, "GDBUS_TIMEOUT_S", 0.01)
    assert await gdbus_send(NOTE) == "gdbus timed out after 0.01 s"
    assert process.killed


def test_notification_is_frozen():
    with pytest.raises(dataclasses.FrozenInstanceError):
        NOTE.summary = "changed"  # type: ignore[misc]
