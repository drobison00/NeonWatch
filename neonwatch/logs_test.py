"""The journal reader: one fixed argv, redaction before anything reads a message, and templating
that collapses repeats of one kind of line but never two different ones."""

from __future__ import annotations

import asyncio
import json
import os
import stat
import time

import pytest

from neonwatch import logs
from neonwatch.logs import (
    ARGV,
    MAX_MESSAGE,
    MAX_TEMPLATE,
    JournalRead,
    binary_refusal,
    field_text,
    parse,
    parse_line,
    read_journal,
    template_key,
    template_of,
)
from neonwatch.redact import MASK


def entry(message, ident="kernel", unit="", priority="6", at="1761500000123456"):
    found = {"MESSAGE": message, "PRIORITY": priority, "__REALTIME_TIMESTAMP": at}
    if ident:
        found["SYSLOG_IDENTIFIER"] = ident
    if unit:
        found["_SYSTEMD_UNIT"] = unit
    return found


def key_of(message, ident="kernel"):
    return parse_line(entry(message, ident)).key


# --- the command ---------------------------------------------------------------------------


def test_the_argv_is_fixed_and_bounded():
    assert ARGV == ("/usr/bin/journalctl", "-n", "200", "-o", "json",
                    "--output-fields=MESSAGE,PRIORITY,_SYSTEMD_UNIT,SYSLOG_IDENTIFIER,"
                    "__REALTIME_TIMESTAMP", "--no-pager", "-q")


# --- fields ----------------------------------------------------------------------------------


@pytest.mark.parametrize(("value", "text"), [
    ("plain", "plain"),
    (list(b"caf\xc3\xa9 \x1b[1m"), "café \x1b[1m"),
    (list(b"\xff"), "�"),
    (["a", "b"], "a|b"),
    ([list(b"x"), "y"], "x|y"),
    ([], ""),
    (None, ""),
    (7, ""),
    ({"a": 1}, ""),
])
def test_field_text_decodes_every_journal_form(value, text):
    assert field_text(value) == text


def test_a_line_is_parsed_with_its_time_priority_unit_and_identifier():
    line = parse_line(entry("hello", ident="sshd", unit="ssh.service", priority="3"))
    assert line.at == pytest.approx(1761500000.123456)
    assert (line.priority, line.unit, line.identifier, line.message) == (3, "ssh.service",
                                                                          "sshd", "hello")
    assert line.source == "sshd"
    assert len(line.key) == 16


@pytest.mark.parametrize("priority", [None, "", "x", "8", "-1", [1, 2]])
def test_an_unreadable_priority_is_none(priority):
    assert parse_line(entry("m", priority=priority)).priority is None


@pytest.mark.parametrize("at", [None, "", "soon", "-5"])
def test_an_unreadable_time_is_none(at):
    assert parse_line(entry("m", at=at)).at is None


def test_the_unit_is_the_source_when_there_is_no_identifier():
    line = parse_line(entry("m", ident="", unit="docker-1234.scope"))
    assert line.source == "docker-<n>.scope"


def test_a_missing_message_is_empty():
    assert parse_line({"PRIORITY": "6"}).message == ""


# --- redaction comes first -------------------------------------------------------------------


def test_a_message_is_redacted_before_it_is_stored_templated_or_keyed():
    secret = "ghp_" + "A1b2C3d4" * 4
    line = parse_line(entry(f"pushing with token {secret} now"))
    assert secret not in line.message and MASK in line.message
    assert secret not in line.template
    assert line.key == key_of(f"pushing with token {'ghp_' + 'Z9y8X7w6' * 4} now")


def test_a_byte_list_message_is_redacted_too():
    line = parse_line(entry(list(b"auth: Bearer abcdefghijklmnop1234")))
    assert "abcdefghijklmnop1234" not in line.message


def test_the_cap_applies_after_redaction_so_a_secret_at_the_cut_is_still_masked():
    secret = "ghp_" + "Q" * 40
    line = parse_line(entry("x" * (MAX_MESSAGE - 10) + " " + secret))
    assert len(line.message) == MAX_MESSAGE
    assert "QQQQQQQQ" not in line.message


def test_identifier_and_unit_are_redacted():
    line = parse_line(entry("m", ident="tool --token=hunter22secret", unit="x.service"))
    assert "hunter22secret" not in line.identifier


# --- templating: the measured kinds of repeats collapse -----------------------------------------


@pytest.mark.parametrize(("one", "two"), [
    # pids in brackets and counters
    ("audit[1234]: op=open res=1", "audit[98765]: op=open res=0"),
    # durations, in different units and with several parts
    ("Finished in 900ms.", "Finished in 1.250s."),
    ("Took 2min 3.250s CPU time.", "Took 41.5s CPU time."),
    # IPv4 with a port, IPv6 with a zone, MAC addresses
    ("connect to 10.0.0.12:5353 failed", "connect to 192.168.1.7:80 failed"),
    ("from fe80::1a2b:3c4d%enp5s0 port 546", "from 2001:db8::7 port 547"),
    ("lease 2001:db8:0:0:0:0:0:1", "lease fd00:1:2:3:4:5:6:7"),
    ("mac 00:1a:2b:3c:4d:5e up", "mac aa:bb:cc:dd:ee:ff up"),
    # UUIDs, container ids, veth names, 0x values
    ("boot 3f2504e0-4f89-11d3-9a0c-0305e82c3301 done",
     "boot 6ba7b810-9dad-11d1-80b4-00c04fd430c8 done"),
    ("container 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08 died",
     "container e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 died"),
    ("veth1a2b3c4: entered promiscuous mode", "vethd4e5f61: entered promiscuous mode"),
    ("addr 0x7ffd2a1c, flags 0x3", "addr 0xdeadbeef, flags 0x10"),
    # timestamps and whitespace
    ("at 2026-10-27T10:00:01 ok", "at 2026-10-28T23:59:59   ok"),
])
def test_repeats_of_one_kind_of_line_collapse(one, two):
    assert template_of(one) == template_of(two)
    assert key_of(one) == key_of(two)


@pytest.mark.parametrize(("one", "two"), [
    ("Started Session 3 of User alice.", "Stopped Session 3 of User alice."),
    ("eth0: link up", "eth0: link down"),
    ("unit foo.service failed", "unit bar.service failed"),
    ("Failed to open /etc/passwd", "Failed to open /etc/shadow"),
    ("deadbeef added", "cafebabe added"),  # hex words with no digit are words
])
def test_different_messages_do_not_collapse(one, two):
    assert key_of(one) != key_of(two)


def test_one_message_from_two_sources_is_two_kinds():
    assert key_of("started", ident="cron") != key_of("started", ident="sshd")


def test_identifiers_are_masked_like_messages():
    assert key_of("x", ident="docker-1234") == key_of("x", ident="docker-99")


def test_templates_are_capped():
    assert len(template_of("word " * 1000)) == MAX_TEMPLATE


def test_template_key_is_a_stable_short_hash():
    assert template_key("kernel", "t") == template_key("kernel", "t")
    assert template_key("kernel", "t") != template_key("kernel", "u")
    assert len(template_key("a", "b")) == 16


@pytest.mark.parametrize("hostile", ["a" * 200_000, "1a" * 100_000, ":" * 200_000,
                                     "1." * 100_000, "1s " * 60_000, "f:" * 100_000])
def test_templating_is_linear_on_hostile_input(hostile):
    start = time.process_time()
    template_of(hostile)
    assert time.process_time() - start < 1.0


# --- parsing the whole output ----------------------------------------------------------------


def test_parse_keeps_objects_and_counts_the_rest():
    out = "\n".join([json.dumps(entry("one")), "not json", "[1, 2]", "",
                     json.dumps(entry("two"))]).encode()
    read = parse(out)
    assert [line.message for line in read.lines] == ["one", "two"]
    assert read.skipped == 2 and not read.truncated


def test_a_truncated_output_drops_the_cut_line_and_says_so():
    whole = json.dumps(entry("one"))
    read = parse((whole + "\n" + whole[:10]).encode(), truncated=True)
    assert [line.message for line in read.lines] == ["one"]
    assert read.truncated and read.skipped == 0


# --- the binary check ------------------------------------------------------------------------


def stat_result(uid=0, mode=0o755):
    return os.stat_result((stat.S_IFREG | mode, 0, 0, 1, uid, 0, 0, 0, 0, 0))


def test_binary_refusal():
    assert binary_refusal(stat_result()) == ""
    assert "owned" in binary_refusal(stat_result(uid=1000))
    assert "writable" in binary_refusal(stat_result(mode=0o775))
    assert "writable" in binary_refusal(stat_result(mode=0o757))


# --- read_journal with the process faked -----------------------------------------------------


class FakeProcess:
    def __init__(self, out=b"", err=b"", code=0, eof=True):
        self.stdout, self.stderr = asyncio.StreamReader(), asyncio.StreamReader()
        self.stdout.feed_data(out)
        self.stderr.feed_data(err)
        if eof:
            self.stdout.feed_eof()
            self.stderr.feed_eof()
        self.code = code
        self.returncode = None
        self.killed = False

    def kill(self):
        self.killed = True
        if self.returncode is not None:
            raise ProcessLookupError
        self.returncode = -9

    async def wait(self):
        if self.returncode is None:
            self.returncode = self.code
        return self.returncode


def fake_exec(monkeypatch, make, trusted=True):
    seen = {}

    async def create_subprocess_exec(*argv, **kwargs):
        seen["argv"], seen["kwargs"] = argv, kwargs
        seen["process"] = make() if callable(make) else make
        if isinstance(seen["process"], Exception):
            raise seen["process"]
        return seen["process"]

    monkeypatch.setattr(logs, "JOURNALCTL", __file__)  # exists on every host
    monkeypatch.setattr(logs, "binary_refusal", lambda st: "" if trusted else "not owned")
    monkeypatch.setattr(logs.asyncio, "create_subprocess_exec", create_subprocess_exec)
    return seen


async def test_read_journal_runs_the_fixed_argv_with_no_environment(monkeypatch):
    out = (json.dumps(entry("one")) + "\n" + json.dumps(entry("two")) + "\n").encode()
    seen = fake_exec(monkeypatch, lambda: FakeProcess(out))
    read = await read_journal()
    assert seen["argv"] == ARGV
    assert seen["kwargs"]["env"] == {} and seen["kwargs"]["cwd"] == "/"
    assert "shell" not in seen["kwargs"]
    assert [line.message for line in read.lines] == ["one", "two"]
    assert read.error == ""


async def test_read_journal_reports_a_non_zero_exit_redacted(monkeypatch):
    fake_exec(monkeypatch, lambda: FakeProcess(err=b"No journal files: token=supersecret99",
                                               code=1))
    read = await read_journal()
    assert read.lines == () and read.error.startswith("journalctl exited 1")
    assert "supersecret99" not in read.error


async def test_read_journal_kills_a_process_that_overruns_its_timeout(monkeypatch):
    seen = fake_exec(monkeypatch, lambda: FakeProcess(eof=False))
    read = await read_journal(timeout_s=0.05)
    assert "did not finish" in read.error
    assert seen["process"].killed


async def test_read_journal_stops_at_the_output_cap(monkeypatch):
    monkeypatch.setattr(logs, "MAX_OUTPUT", 300)
    line = json.dumps(entry("one")) + "\n"
    seen = fake_exec(monkeypatch, lambda: FakeProcess((line * 10).encode(), eof=False))
    read = await read_journal()
    assert read.truncated and seen["process"].killed
    assert 1 <= len(read.lines) < 10 and read.skipped == 0


async def test_stopping_a_process_that_already_exited_is_fine():
    process = FakeProcess()
    process.returncode = 0
    await logs._stop(process)
    assert process.killed


async def test_read_journal_refuses_an_untrusted_binary(monkeypatch):
    seen = fake_exec(monkeypatch, lambda: FakeProcess(), trusted=False)
    read = await read_journal()
    assert read.error.startswith("refusing to run") and "argv" not in seen


async def test_read_journal_reports_a_binary_it_cannot_stat(monkeypatch):
    fake_exec(monkeypatch, lambda: FakeProcess())
    monkeypatch.setattr(logs, "JOURNALCTL", "/nonexistent/journalctl")
    read = await read_journal()
    assert read.error.startswith("cannot check")


async def test_read_journal_reports_a_spawn_failure(monkeypatch):
    fake_exec(monkeypatch, PermissionError("denied"))
    read = await read_journal()
    assert read.error.startswith("journalctl could not run") and read.lines == ()


def test_a_journal_read_defaults_to_no_problem():
    assert JournalRead(()) == JournalRead((), skipped=0, truncated=False, error="")
