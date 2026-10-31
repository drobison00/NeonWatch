"""The service: its loops against fakes, and its whole wiring against a real nats-server.

The integration test starts `.tools/nats-server` from `broker.init` in `tmp_path` on a free port,
runs the service with a fake judge (no judge) and a tmp store, publishes observations as the
AGENT role, and follows one CRITICAL disk-full alarm through the evaluator, the stream, the store,
the live broadcaster and the notifier.
"""

from __future__ import annotations

import asyncio
import dataclasses
import io
import json
import logging
import os
import re
import shutil
import signal
import socket
import ssl
import stat
import subprocess
import time
import urllib.error
import urllib.request
from pathlib import Path

import pytest

from neonwatch import agent_token, broker, service, web
from neonwatch.bus import BusError, connect
from neonwatch.config import Analyst, Broker, Cadence, Config, Retention, Store, Web
from neonwatch.evaluator import RESOLVE_AFTER, EvaluatorError
from neonwatch.judge import JudgeHealth
from neonwatch.schema import (
    Event,
    Heartbeat,
    Issue,
    IssueState,
    Kind,
    Observation,
    SchemaError,
    Severity,
    to_body,
)
from neonwatch.service import Live, LiveBehind, Service
from neonwatch.store import Store as SqliteStore
from neonwatch.store import StoreError

BINARY = Path(__file__).resolve().parent.parent / ".tools" / "nats-server"


def free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def observation(probe: str, data: dict, at: float | None = None) -> Event:
    return Event(Kind.OBSERVATION, time.time() if at is None else at, "agent", f"obs.{probe}",
                 to_body(Observation(probe=probe, data=data, cpu_ms=1)))


def issue(severity: Severity = Severity.CRITICAL, state: IssueState = IssueState.OPEN,
          id: str = "i-1") -> Issue:
    return Issue(id=id, state=state, severity=severity, title="Filesystem / is 99% full",
                 domain="storage", entity="mount:/", opened_at=1.0, updated_at=2.0,
                 deterministic=True, reasons=("disk.fill",), next_step="df -h /")


def issue_event(record: Issue | None = None) -> Event:
    record = record or issue()
    return Event(Kind.ISSUE, 2.0, "evaluator", f"issue.{record.id}", to_body(record))


FULL_DISK = {"filesystems": [{"mount": "/", "used_pct": 99.0, "source": "/dev/nvme0n1p2",
                              "fstype": "ext4"}]}


# --- fakes ---------------------------------------------------------------------------------------


class FakeJudge:
    def __init__(self) -> None:
        self.asked = 0
        self.retargeted: list = []

    def retarget(self, post, server) -> None:
        self.retargeted.append((post, server))

    async def attest(self, contexts):
        self.asked += len(contexts)
        return ()

    def health(self) -> JudgeHealth:
        return JudgeHealth(reachable=None, last_error="", p50_ms=None, p95_ms=None,
                           in_flight=0, requests=0, refused_answers=0, failed_requests=0)


class FakeSubscription:
    def __init__(self, events, then: BaseException | None = None) -> None:
        self._events = list(events)
        self._then = then

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return None

    def __aiter__(self):
        return self

    async def __anext__(self):
        if self._events:
            return self._events.pop(0)
        if self._then is not None:
            then, self._then = self._then, None
            raise then
        await asyncio.Event().wait()   # a quiet stream: wait until cancelled
        raise AssertionError("unreachable")


class FakeBus:
    def __init__(self, *, fail_publishes: int = 0, streams: dict | None = None) -> None:
        self.fail_publishes = fail_publishes
        self.published: list[Event] = []
        self.attempts = 0
        self.closed = False
        self.ensured = False
        self.streams = streams or {}
        self.subscribed: list[tuple[str, str]] = []

    async def publish(self, event: Event) -> int:
        self.attempts += 1
        if self.fail_publishes:
            self.fail_publishes -= 1
            raise BusError("TimeoutError: nats: timeout")
        self.published.append(event)
        return len(self.published)

    def subscribe(self, subject: str, durable: str):
        self.subscribed.append((subject, durable))
        made = self.streams.get(durable)
        if isinstance(made, list) and made:
            made = made.pop(0)
        if isinstance(made, BaseException):
            raise made
        return made if made is not None else FakeSubscription(())

    async def ensure_streams(self, config) -> None:
        self.ensured = True

    async def close(self) -> None:
        self.closed = True


class FakeEvaluator:
    def __init__(self, events=(), fail: BaseException | None = None) -> None:
        self.observed: list[Event] = []
        self.events = tuple(events)
        self.fail = fail
        self.collated: list[float] = []

    def observe(self, event: Event) -> None:
        if event.subject == "obs.nope":
            raise EvaluatorError("unknown probe")
        self.observed.append(event)

    async def collate(self, now: float):
        self.collated.append(now)
        if self.fail is not None:
            raise self.fail

        class Collation:
            events = self.events
            issues = ()
            deferred_contexts = 0
            questions_asked = 0
            duration_ms = 0
        return Collation()


class FakeStore:
    def __init__(self, refuse: BaseException | None = None) -> None:
        self.applied: list[Event] = []
        self.refuse = refuse
        self.pruned: list[float] = []
        self.closed = False
        self.noted: list[tuple[list[str], float]] = []
        self.refuse_noting: BaseException | None = None

    def apply(self, event: Event) -> None:
        if self.refuse is not None:
            raise self.refuse
        self.applied.append(event)

    def prune(self, now: float) -> int:
        self.pruned.append(now)
        return 3

    def note_services(self, names: list[str], at: float) -> None:
        if isinstance(self.refuse_noting, BaseException):
            raise self.refuse_noting
        self.noted.append((names, at))

    def close(self) -> None:
        self.closed = True


class FakeNotifier:
    def __init__(self) -> None:
        self.considered: list[Issue] = []

    async def consider(self, record: Issue):
        self.considered.append(record)
        return None


def make(*, evaluator_bus=None, viewer_bus=None, notifier_bus=None, store=None, evaluator=None,
         notifier=None, config=None, out=None) -> Service:
    return Service(config or Config(), evaluator_bus=evaluator_bus or FakeBus(),
                   viewer_bus=viewer_bus or FakeBus(), notifier_bus=notifier_bus or FakeBus(),
                   store=store or FakeStore(), judge=FakeJudge(),
                   evaluator=evaluator or FakeEvaluator(), notifier=notifier or FakeNotifier(),
                   analyst=None, token="t" * 43, clock=lambda: 100.0,
                   out=out or io.StringIO())


@pytest.fixture
def quick(monkeypatch):
    monkeypatch.setattr(service, "BACKOFF_MIN_S", 0.001)
    monkeypatch.setattr(service, "BACKOFF_MAX_S", 0.004)


# --- the live broadcaster ------------------------------------------------------------------------


async def test_live_fans_each_event_out_to_every_subscriber():
    live = Live()
    a, b = live.subscribe(), live.subscribe()
    event = issue_event()
    live.publish(event)
    assert await anext(a) is event
    assert await anext(b) is event
    assert live.subscribers == 2


async def test_live_registers_a_subscriber_before_it_is_first_awaited():
    live = Live()
    sub = live.subscribe()
    live.publish(issue_event())   # published before the first anext
    assert (await anext(sub)).kind is Kind.ISSUE


async def test_a_subscriber_that_falls_behind_is_dropped_loudly_not_silently():
    live = Live(queue_size=2)
    slow, fast = live.subscribe(), live.subscribe()
    for _ in range(3):
        live.publish(issue_event())
        await anext(fast)
    with pytest.raises(LiveBehind):
        await anext(slow)
    assert live.overflowed == 1
    assert live.subscribers == 1
    with pytest.raises(StopAsyncIteration):   # once behind, it stays ended
        await anext(slow)


async def test_close_ends_every_subscription_and_later_ones_at_once():
    live = Live(queue_size=1)
    sub = live.subscribe()
    live.publish(issue_event())
    live.close()
    with pytest.raises(StopAsyncIteration):
        await anext(sub)
    assert [e async for e in live.subscribe()] == []
    live.publish(issue_event())   # after close: nobody to tell, nothing raised


async def test_a_cancelled_subscriber_is_forgotten():
    live = Live()
    sub = live.subscribe()
    waiting = asyncio.create_task(anext(sub))
    await asyncio.sleep(0)
    waiting.cancel()
    with pytest.raises(asyncio.CancelledError):
        await waiting
    assert live.subscribers == 0


async def test_aclose_forgets_a_subscriber():
    live = Live()
    sub = live.subscribe()
    assert sub.__aiter__() is sub
    await sub.aclose()
    assert live.subscribers == 0


def test_live_refuses_a_queue_size_below_one():
    with pytest.raises(ValueError):
        Live(queue_size=0)


# --- publishing ----------------------------------------------------------------------------------


async def test_publish_retries_a_broker_timeout_then_succeeds(quick):
    bus = FakeBus(fail_publishes=2)
    svc = make(evaluator_bus=bus)
    await svc.publish([issue_event()])
    assert len(bus.published) == 1
    assert svc.counts.published == 1 and svc.counts.retries == 2 and svc.counts.dropped == 0


async def test_an_issue_that_cannot_be_published_is_logged_and_counted(quick, caplog):
    bus = FakeBus(fail_publishes=10**6)
    svc = make(evaluator_bus=bus)
    finding = Event(Kind.FINDING, 1.0, "evaluator", "finding.disk.fill", {})
    await svc.publish([issue_event(), finding])
    assert bus.attempts == 2 * service.PUBLISH_ATTEMPTS
    assert svc.counts.dropped == 2 and svc.counts.dropped_issues == 1
    errors = [r.getMessage() for r in caplog.records if r.levelno >= logging.ERROR]
    assert any("issue.i-1" in m for m in errors)


async def test_an_event_the_schema_refuses_is_dropped_without_retrying(quick, caplog):
    class Refusing(FakeBus):
        async def publish(self, event):
            self.attempts += 1
            raise SchemaError("too big")
    bus = Refusing()
    svc = make(evaluator_bus=bus)
    await svc.publish([issue_event()])
    assert bus.attempts == 1 and svc.counts.dropped_issues == 1


# --- the consumers -------------------------------------------------------------------------------


async def test_an_observation_the_evaluator_refuses_is_counted_and_skipped():
    evaluator = FakeEvaluator()
    svc = make(evaluator=evaluator)
    await svc.handle_observation(observation("nope", {}))
    await svc.handle_observation(observation("load", {"load1": 1.0}))
    assert svc.counts.refused == 1 and svc.counts.observed == 1
    assert [e.subject for e in evaluator.observed] == ["obs.load"]


async def test_a_viewed_event_is_stored_then_broadcast():
    store = FakeStore()
    svc = make(store=store)
    sub = svc.live.subscribe()
    event = issue_event()
    await svc.handle_view(event)
    assert store.applied == [event]
    assert await anext(sub) is event
    assert svc.counts.stored == 1


def unit(id: str) -> dict:
    return {"id": id, "description": "", "user": "", "exec": [], "active": "active",
            "sub": "running", "result": "success", "restarts": 0, "main_status": None,
            "started": None, "exited": None, "enabled": "enabled", "file": ""}


async def test_the_services_a_units_observation_lists_are_noted_as_seen():
    store = FakeStore()
    svc = make(store=store)
    sub = svc.live.subscribe()
    seen = observation("units.detail", {"units": [unit("ssh.service"), unit("ssh.socket"),
                                                  unit("cron.service")]}, at=100.0)
    await svc.handle_view(seen)
    await svc.handle_view(observation("load", {"load1": 1.0}, at=101.0))
    failed = Event(Kind.OBSERVATION, 102.0, "agent", "obs.units.detail",
                   to_body(Observation(probe="units.detail", data={}, cpu_ms=1, error="timeout")))
    await svc.handle_view(failed)
    assert store.noted == [(["cron.service", "ssh.service"], 100.0)]  # services only, sorted
    assert await anext(sub) is seen


@pytest.mark.parametrize("bad", [{"units": [{"id": "x.service"}]}, {"units": [7]}])
async def test_services_that_cannot_be_listed_or_noted_do_not_stop_the_viewer(bad, caplog):
    store = FakeStore()
    svc = make(store=store)
    await svc.handle_view(observation("units.detail", bad))
    store.refuse_noting = StoreError("locked")
    await svc.handle_view(observation("units.detail", {"units": [unit("a.service")]}))
    assert len(store.applied) == 2 and svc.counts.stored == 2 and store.noted == []
    assert caplog.text.count("could not note the services") == 2


@pytest.mark.parametrize("refusal", [SchemaError("bad link"), StoreError("no")])
async def test_an_event_the_store_refuses_is_not_broadcast(refusal):
    svc = make(store=FakeStore(refuse=refusal))
    sub = svc.live.subscribe()
    await svc.handle_view(issue_event())
    svc.live.close()
    assert [e async for e in sub] == []
    assert svc.counts.refused == 1


async def test_an_issue_event_is_decoded_and_considered_for_the_desktop():
    notifier = FakeNotifier()
    svc = make(notifier=notifier)
    await svc.handle_issue(issue_event())
    assert notifier.considered == [issue()]


@pytest.mark.parametrize("event", [
    Event(Kind.ISSUE, 1.0, "evaluator", "issue.i-1", {"id": "i-1"}),
    Event(Kind.FINDING, 1.0, "evaluator", "finding.x", {}),
])
async def test_the_notifier_consumer_refuses_what_is_not_an_issue(event):
    notifier = FakeNotifier()
    svc = make(notifier=notifier)
    await svc.handle_issue(event)
    assert notifier.considered == [] and svc.counts.refused == 1


async def test_a_consumer_resubscribes_after_the_bus_fails(quick):
    first = FakeSubscription([observation("load", {"load1": 1.0})], then=BusError("gone"))
    second = FakeSubscription([observation("load", {"load1": 2.0}, at=time.time() + 1)])
    bus = FakeBus(streams={"evaluator": [BusError("refused"), first, second]})
    evaluator = FakeEvaluator()
    svc = make(evaluator_bus=bus, evaluator=evaluator)
    task = asyncio.create_task(svc.consume(bus, "obs.>", "evaluator", svc.handle_observation))
    for _ in range(200):
        if len(evaluator.observed) == 2:
            break
        await asyncio.sleep(0.005)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert len(evaluator.observed) == 2
    assert bus.subscribed == [("obs.>", "evaluator")] * 3


# --- collation and pruning -----------------------------------------------------------------------


async def test_a_collation_publishes_every_event_it_returns():
    events = (issue_event(), Event(Kind.FINDING, 1.0, "evaluator", "finding.disk.fill", {}))
    bus = FakeBus()
    svc = make(evaluator_bus=bus, evaluator=FakeEvaluator(events))
    await svc.collate_once(100.0)
    assert bus.published == list(events)
    assert svc.counts.collations == 1


async def test_the_collate_loop_survives_a_failing_collation(caplog):
    evaluator = FakeEvaluator(fail=RuntimeError("bug"))
    svc = make(evaluator=evaluator, config=Config(cadence=Cadence(collate=1)))
    svc._collate_every = 0.001
    task = asyncio.create_task(svc.collate_forever())
    for _ in range(200):
        if len(evaluator.collated) >= 2:
            break
        await asyncio.sleep(0.005)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert svc.counts.collate_failures >= 2
    assert "collation failed" in caplog.text


async def test_the_store_is_pruned_on_its_schedule(monkeypatch):
    monkeypatch.setattr(service, "PRUNE_EVERY_S", 0.001)
    store = FakeStore()
    svc = make(store=store)
    task = asyncio.create_task(svc.prune_forever())
    for _ in range(200):
        if len(store.pruned) >= 2:
            break
        await asyncio.sleep(0.005)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert store.pruned[:2] == [100.0, 100.0]


async def test_a_failing_prune_is_logged_and_retried_next_time(monkeypatch, caplog):
    monkeypatch.setattr(service, "PRUNE_EVERY_S", 0.001)

    class Broken(FakeStore):
        def prune(self, now):
            self.pruned.append(now)
            raise StoreError("disk I/O error")
    store = Broken()
    svc = make(store=store)
    task = asyncio.create_task(svc.prune_forever())
    for _ in range(200):
        if len(store.pruned) >= 2:
            break
        await asyncio.sleep(0.005)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert "prune failed" in caplog.text


# --- run and shutdown, with fakes but the real web server ---------------------------------------


def web_config(tmp_path: Path, **kw) -> Config:
    return Config(web=Web(port=free_port()), store=Store(path=str(tmp_path / "s.sqlite3")), **kw)


async def test_run_serves_prints_the_url_once_and_closes_everything_on_stop(tmp_path):
    config = web_config(tmp_path)
    buses = [FakeBus(), FakeBus(), FakeBus()]
    store = SqliteStore(tmp_path / "s.sqlite3", config)
    out = io.StringIO()
    svc = Service(config, evaluator_bus=buses[0], viewer_bus=buses[1], notifier_bus=buses[2],
                  store=store, judge=FakeJudge(), evaluator=FakeEvaluator(),
                  notifier=FakeNotifier(), analyst=None, token="k" * 43, clock=time.time,
                  out=out)
    stop = asyncio.Event()
    running = asyncio.create_task(svc.run(stop))
    url = f"http://127.0.0.1:{config.web.port}/"
    for _ in range(200):
        if out.getvalue():
            break
        await asyncio.sleep(0.01)
    # Not a terminal, so not the token: a unit's stdout goes to the journal, which adm reads.
    assert out.getvalue() == (f"{url} (the sign-in URL, with its token: "
                              f"{tmp_path / service.URL_FILE})\n")
    health = await asyncio.to_thread(get, config.web.port, "/api/health", "k" * 43)
    assert health[0] == 200 and b"judge" in health[1]
    stop.set()
    assert await running == 0
    assert all(b.closed for b in buses)
    assert sorted(buses[0].subscribed) == [("hb.>", "evaluator-hb"), ("obs.>", "evaluator")]
    assert buses[1].subscribed == [(">", "viewer")]
    assert buses[2].subscribed == [("issue.>", "notifier")]
    with pytest.raises(Exception):  # noqa: B017 - the store's connection is closed
        store.issues()
    await svc.close()   # idempotent


class Terminal(io.StringIO):
    def isatty(self) -> bool:
        return True


async def test_the_token_is_printed_only_to_a_terminal(tmp_path):
    for out, token_shown in ((Terminal(), True), (io.StringIO(), False)):
        config = web_config(tmp_path)
        svc = Service(config, evaluator_bus=FakeBus(), viewer_bus=FakeBus(),
                      notifier_bus=FakeBus(), store=SqliteStore(tmp_path / "s.sqlite3", config),
                      judge=FakeJudge(), evaluator=FakeEvaluator(), notifier=FakeNotifier(),
                      analyst=None, token="k" * 43, clock=time.time, out=out)
        stop = asyncio.Event()
        running = asyncio.create_task(svc.run(stop))
        await started(out)
        assert ("k" * 43 in out.getvalue()) is token_shown
        stop.set()
        assert await running == 0


def quiet_service(tmp_path: Path, config: Config) -> tuple[Service, io.StringIO]:
    out = io.StringIO()
    svc = Service(config, evaluator_bus=FakeBus(), viewer_bus=FakeBus(), notifier_bus=FakeBus(),
                  store=SqliteStore(tmp_path / "s.sqlite3", config), judge=FakeJudge(),
                  evaluator=FakeEvaluator(), notifier=FakeNotifier(), analyst=None,
                  token="k" * 43, clock=time.time, out=out)
    return svc, out


async def started(out: io.StringIO) -> None:
    for _ in range(200):
        if out.getvalue():
            return
        await asyncio.sleep(0.01)


async def test_run_writes_the_url_for_the_desktop_app_privately_and_removes_it_on_stop(tmp_path):
    config = web_config(tmp_path)
    svc, out = quiet_service(tmp_path, config)
    stop = asyncio.Event()
    running = asyncio.create_task(svc.run(stop))
    await started(out)
    written = tmp_path / service.URL_FILE
    assert written.read_text() == f"http://127.0.0.1:{config.web.port}/?token={'k' * 43}\n"
    assert stat.S_IMODE(written.stat().st_mode) == 0o600
    assert [p.name for p in tmp_path.iterdir() if p.name.startswith(".")] == []   # no staging
    stop.set()
    assert await running == 0
    assert not written.exists()


async def test_a_url_file_another_service_has_replaced_is_left_alone(tmp_path):
    config = web_config(tmp_path)
    svc, out = quiet_service(tmp_path, config)
    stop = asyncio.Event()
    running = asyncio.create_task(svc.run(stop))
    await started(out)
    (tmp_path / service.URL_FILE).write_text("http://127.0.0.1:1/?token=newer\n")
    stop.set()
    assert await running == 0
    assert (tmp_path / service.URL_FILE).read_text() == "http://127.0.0.1:1/?token=newer\n"


async def test_a_url_file_that_cannot_be_written_or_removed_only_warns(tmp_path, monkeypatch,
                                                                      caplog):
    config = web_config(tmp_path)
    svc, out = quiet_service(tmp_path, config)

    def refuse(where, text):
        raise PermissionError(13, "Permission denied")
    monkeypatch.setattr(service, "write_private", refuse)
    stop = asyncio.Event()
    running = asyncio.create_task(svc.run(stop))
    await started(out)
    stop.set()
    assert await running == 0
    assert "cannot sign in by itself" in caplog.text
    svc._withdraw_url(tmp_path / "missing" / service.URL_FILE)   # gone already: warns, no raise
    assert "could not remove" in caplog.text


def test_write_private_replaces_a_symlink_instead_of_writing_through_it(tmp_path):
    target = tmp_path / "victim"
    target.write_text("keep")
    link = tmp_path / service.URL_FILE
    link.symlink_to(target)
    service.write_private(link, "url\n")
    assert target.read_text() == "keep" and not link.is_symlink()
    assert link.read_text() == "url\n" and stat.S_IMODE(link.stat().st_mode) == 0o600


def test_write_private_leaves_no_staged_file_when_the_rename_fails(tmp_path):
    (tmp_path / service.URL_FILE).mkdir()   # a directory is in the way: the rename fails
    with pytest.raises(OSError):
        service.write_private(tmp_path / service.URL_FILE, "url\n")
    assert sorted(p.name for p in tmp_path.iterdir()) == [service.URL_FILE]


async def test_run_wires_the_journal_reader_into_the_logs_view(tmp_path, monkeypatch):
    from neonwatch import logs

    async def fake_read() -> logs.JournalRead:
        return logs.JournalRead((logs.parse_line({"MESSAGE": "hello", "PRIORITY": "6"}),))

    monkeypatch.setattr(logs, "read_journal", fake_read)
    config = web_config(tmp_path)
    store = SqliteStore(tmp_path / "s.sqlite3", config)
    out = io.StringIO()
    svc = Service(config, evaluator_bus=FakeBus(), viewer_bus=FakeBus(), notifier_bus=FakeBus(),
                  store=store, judge=FakeJudge(), evaluator=FakeEvaluator(),
                  notifier=FakeNotifier(), analyst=None, token="k" * 43, clock=time.time,
                  out=out)
    stop = asyncio.Event()
    running = asyncio.create_task(svc.run(stop))
    for _ in range(200):
        if out.getvalue():
            break
        await asyncio.sleep(0.01)
    status, body = await asyncio.to_thread(get, config.web.port, "/api/logs", "k" * 43)
    stop.set()
    assert await running == 0
    assert status == 200 and b'"message": "hello"' in body


async def test_run_stops_with_an_error_code_when_a_task_dies(tmp_path, caplog):
    config = web_config(tmp_path)
    store = SqliteStore(tmp_path / "s.sqlite3", config)

    class Crashing(FakeBus):
        def subscribe(self, subject, durable):
            raise RuntimeError("a bug")
    svc = Service(config, evaluator_bus=FakeBus(), viewer_bus=Crashing(),
                  notifier_bus=FakeBus(), store=store, judge=FakeJudge(),
                  evaluator=FakeEvaluator(), notifier=FakeNotifier(), analyst=None,
                  token="k" * 43, clock=time.time, out=io.StringIO())
    assert await asyncio.wait_for(svc.run(asyncio.Event()), 10) == 1
    assert "viewer" in caplog.text and "a bug" in caplog.text


def get(port: int, path: str, token: str | None = None,
        headers: dict[str, str] | None = None) -> tuple[int, bytes]:
    request = urllib.request.Request(f"http://127.0.0.1:{port}{path}", headers=headers or {})
    if token:
        request.add_header("Authorization", f"Bearer {token}")
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(request, timeout=5) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as refused:
        return refused.code, refused.read()


# --- open_service --------------------------------------------------------------------------------


def fake_connect(monkeypatch, made: list, fail_at: int | None = None):
    async def connect_(url, creds, *, owner):
        if fail_at is not None and len(made) == fail_at:
            raise BusError("could not connect")
        bus = FakeBus()
        bus.creds, bus.owner = creds, owner
        made.append(bus)
        return bus
    monkeypatch.setattr(service.bus, "connect", connect_)


async def test_open_service_connects_each_role_with_its_own_credentials(monkeypatch, tmp_path):
    made: list[FakeBus] = []
    fake_connect(monkeypatch, made)
    config = web_config(tmp_path, broker=Broker(state_dir=str(tmp_path / "b")))
    svc = await service.open_service(config, environ={}, judge=FakeJudge(), owner=1234)
    try:
        assert [b.owner for b in made] == [1234, 1234, 1234]
        assert [b.creds.name for b in made] == ["evaluator.creds.json", "viewer.creds.json",
                                                "notifier.creds.json"]
        assert all(b.creds.parent == tmp_path / "b" for b in made)
        assert made[0].ensured and not made[1].ensured and not made[2].ensured
        assert svc.analyst is None
        assert len(svc.token) >= 43
    finally:
        await svc.close()


async def test_open_service_makes_the_agent_token_beside_the_store(monkeypatch, tmp_path, caplog):
    caplog.set_level(logging.INFO)
    fake_connect(monkeypatch, [])
    svc = await service.open_service(web_config(tmp_path), environ={}, judge=FakeJudge())
    try:
        where = tmp_path / "agent.token"
        token = svc.agent_token()
        assert where.read_text() == token + "\n"
        assert stat.S_IMODE(where.stat().st_mode) == 0o600
        assert f"agent API token created at {where}" in caplog.text
        assert token not in caplog.text
        where.write_text("r" * 43 + "\n")  # rotated: the next request reads the new one
        assert svc.agent_token() == "r" * 43
        assert service._agent_token(svc._config)() == "r" * 43  # found, not made again
        assert caplog.text.count("agent API token created") == 1
    finally:
        await svc.close()


async def test_an_unsafe_agent_token_file_leaves_the_agent_api_off(monkeypatch, tmp_path, caplog):
    fake_connect(monkeypatch, [])
    (tmp_path / "elsewhere").write_text("x" * 43)
    (tmp_path / "agent.token").symlink_to(tmp_path / "elsewhere")
    svc = await service.open_service(web_config(tmp_path), environ={}, judge=FakeJudge())
    try:
        assert "the agent API is off until its token file is fixed" in caplog.text
        with pytest.raises(agent_token.TokenError, match="symlink"):
            svc.agent_token()
    finally:
        await svc.close()


async def test_run_serves_the_agent_api_with_the_agent_token(tmp_path):
    config = web_config(tmp_path)
    store = SqliteStore(tmp_path / "s.sqlite3", config)
    out = io.StringIO()
    svc = Service(config, evaluator_bus=FakeBus(), viewer_bus=FakeBus(), notifier_bus=FakeBus(),
                  store=store, judge=FakeJudge(), evaluator=FakeEvaluator(),
                  notifier=FakeNotifier(), analyst=None, token="k" * 43, clock=time.time,
                  out=out, agent_token=lambda: "a" * 43)
    stop = asyncio.Event()
    running = asyncio.create_task(svc.run(stop))
    for _ in range(200):
        if out.getvalue():
            break
        await asyncio.sleep(0.01)
    port = config.web.port
    named = {"X-Neonwatch-Agent": "test"}
    summary = await asyncio.to_thread(get, port, "/api/agent/v1/summary", "a" * 43, named)
    browser_token = await asyncio.to_thread(get, port, "/api/agent/v1/summary", "k" * 43, named)
    agent_on_browser = await asyncio.to_thread(get, port, "/api/overview", "a" * 43)
    stop.set()
    assert await running == 0
    assert summary[0] == 200 and b'"vitals"' in summary[1]
    assert browser_token[0] == 401 and agent_on_browser[0] == 401


async def test_open_service_closes_what_it_opened_when_a_later_step_fails(monkeypatch, tmp_path):
    made: list[FakeBus] = []
    fake_connect(monkeypatch, made, fail_at=2)
    config = web_config(tmp_path, broker=Broker(state_dir=str(tmp_path / "b")))
    with pytest.raises(BusError):
        await service.open_service(config, environ={}, judge=FakeJudge())
    assert len(made) == 2 and all(b.closed for b in made)


async def test_open_service_builds_the_real_judge_by_default(monkeypatch, tmp_path):
    made: list[FakeBus] = []
    fake_connect(monkeypatch, made)
    svc = await service.open_service(web_config(tmp_path), environ={})
    try:
        assert type(svc.judge).__name__ == "Judge"
    finally:
        await svc.close()


async def test_a_restarted_service_does_not_tell_the_desktop_again(monkeypatch, tmp_path):
    # 2026-10-30: every restart re-sent every open issue the desktop had already been told of.
    config = web_config(tmp_path)
    config = dataclasses.replace(config, notify=dataclasses.replace(config.notify,
                                                                    min_severity="warn"))
    before = SqliteStore(Path(config.store.path), config)
    told = issue(id="i-told")
    before.note_notified(told.id, told.severity.rank, 900.0)
    before.close()
    fake_connect(monkeypatch, [])
    sent: list = []

    async def send(notification):
        sent.append(notification.issue_id)
        return None
    svc = await service.open_service(config, environ={}, judge=FakeJudge(), send=send,
                                     clock=lambda: 1000.0)
    try:
        await svc._notifier.consider(told)
        await svc._notifier.consider(issue(id="i-new"))
        assert sent == ["i-new"]
        assert set(svc.store.notified()) == {"i-told", "i-new"}
    finally:
        await svc.close()


async def test_the_evaluator_adopts_the_stores_issues_and_the_hold_survives_until_resolved(
        monkeypatch, tmp_path):
    config = web_config(tmp_path)
    before = SqliteStore(Path(config.store.path), config)   # what the previous process left
    for record in (issue(id="i-held"), issue(id="i-open"),
                   issue(id="i-done", state=IssueState.RESOLVED)):
        before.apply(issue_event(record))
    before.ack("i-held", 3.0)
    before.close()
    made: list[FakeBus] = []
    fake_connect(monkeypatch, made)
    svc = await service.open_service(config, environ={}, judge=FakeJudge(),
                                     clock=lambda: 1000.0)
    try:
        states = []
        for n in range(1, RESOLVE_AFTER + 1):   # nothing observed: every condition is absent
            made[0].published.clear()
            await svc.collate_once(1000.0 + n)
            said = [e for e in made[0].published if e.kind is Kind.ISSUE]
            assert {"issue.i-held", "issue.i-open"} <= {e.subject for e in said}
            assert "issue.i-done" not in {e.subject for e in said}
            for event in said:
                svc.store.apply(event)
            states.append({id: svc.store.issue(id).state for id in ("i-held", "i-open", "i-done")})
        held, opened = IssueState.ACKNOWLEDGED, IssueState.OPEN
        resolved = IssueState.RESOLVED
        assert states == [{"i-held": held, "i-open": opened, "i-done": resolved}] * (
            RESOLVE_AFTER - 1) + [dict.fromkeys(("i-held", "i-open", "i-done"), resolved)]
    finally:
        await svc.close()


ANALYST = Analyst(provider="openai-compatible", base_url="http://127.0.0.1:9/v1", model="m",
                  api_key_env="NEONWATCH_TEST_KEY")


async def test_the_analyst_key_is_read_from_the_named_variable_and_never_logged(
        monkeypatch, tmp_path, caplog):
    caplog.set_level(logging.DEBUG)
    made: list[FakeBus] = []
    fake_connect(monkeypatch, made)
    secret = "sk-test-" + "x" * 40
    svc = await service.open_service(web_config(tmp_path, analyst=ANALYST),
                                     environ={"NEONWATCH_TEST_KEY": secret}, judge=FakeJudge())
    try:
        assert svc.analyst is not None and svc.analyst._api_key == secret
        assert secret not in caplog.text
    finally:
        await svc.close()


async def test_a_named_key_that_is_not_set_disables_the_analyst(monkeypatch, tmp_path, caplog):
    made: list[FakeBus] = []
    fake_connect(monkeypatch, made)
    svc = await service.open_service(web_config(tmp_path, analyst=ANALYST), environ={},
                                     judge=FakeJudge())
    try:
        assert svc.analyst is None
        assert "NEONWATCH_TEST_KEY" in caplog.text
    finally:
        await svc.close()


async def test_an_analyst_without_a_key_variable_runs_keyless(monkeypatch, tmp_path):
    made: list[FakeBus] = []
    fake_connect(monkeypatch, made)
    keyless = Analyst(provider="openai-compatible", base_url="http://127.0.0.1:9/v1", model="m")
    svc = await service.open_service(web_config(tmp_path, analyst=keyless), environ={},
                                     judge=FakeJudge())
    try:
        assert svc.analyst is not None and svc.analyst._api_key == ""
    finally:
        await svc.close()


async def test_the_desktop_send_is_logged(caplog):
    caplog.set_level(logging.INFO)
    results = iter([None, "gdbus exited 1: no session bus"])

    async def send(notification):
        return next(results)
    logged = service.logging_send(send)
    from neonwatch.notifier import Notification
    note = Notification(issue_id="i-1", summary="neonwatch: CRITICAL", body="b", urgency=2)
    assert await logged(note) is None
    assert await logged(note) == "gdbus exited 1: no session bus"
    assert "notified" in caplog.text and "no session bus" in caplog.text


# --- main ----------------------------------------------------------------------------------------


def test_the_service_refuses_to_run_as_root(capsys):
    assert service.main([], uid=0, environ={}) == 1
    assert "root" in capsys.readouterr().err


def test_a_config_that_does_not_load_is_refused(tmp_path, capsys):
    bad = tmp_path / "c.toml"
    bad.write_text("[nope]\n")
    assert service.main(["--config", str(bad)], uid=1000, environ={}) == 2
    assert "unknown section" in capsys.readouterr().err


def test_an_unknown_argument_is_a_usage_error(capsys):
    assert service.main(["--frobnicate"], uid=1000, environ={}) == 2


def test_an_unreachable_broker_is_reported_and_exits_1(monkeypatch, capsys):
    async def refuse(url, creds, **_):
        raise BusError("could not connect to nats://127.0.0.1:4222 within 5.0s: no answer")
    monkeypatch.setattr(service.bus, "connect", refuse)
    assert service.main([], uid=1000, environ={}) == 1
    assert "could not connect" in capsys.readouterr().err


def test_sigterm_stops_the_service_cleanly(monkeypatch):
    seen = {}

    class Running:
        async def run(self, stop):
            asyncio.get_running_loop().call_later(0.05, os.kill, os.getpid(), signal.SIGTERM)
            await asyncio.wait_for(stop.wait(), 5)
            seen["stopped"] = True
            return 0

    async def opened(config, **kw):
        seen["environ"], seen["owner"] = kw["environ"], kw["owner"]
        seen["models_dir"] = kw["models_dir"]
        return Running()
    monkeypatch.setattr(service, "open_service", opened)
    monkeypatch.setattr(service.Path, "home", lambda: Path("/home/alice"))
    assert service.main([], uid=1000, environ={"A": "1"}) == 0
    assert seen == {"stopped": True, "environ": {"A": "1"}, "owner": 1000,
                    "models_dir": Path("/home/alice/.config/neonwatch")}


# --- the models the dashboard sets ------------------------------------------------------------

LOCAL_LLM = {"provider": "openai-compatible", "base_url": "http://127.0.0.1:8888/v1",
             "model": "qwen"}


def private_json(path: Path, data) -> None:
    path.write_text(json.dumps(data))
    path.chmod(0o600)


async def test_the_service_starts_on_the_dashboards_models_and_keys(monkeypatch, tmp_path):
    config = web_config(tmp_path)
    private_json(tmp_path / "models.json", {"analyst": LOCAL_LLM, "judge": {"model": "e2"}})
    private_json(tmp_path / "secrets.json", {"analyst": "sk-dash"})
    fake_connect(monkeypatch, [])
    svc = await service.open_service(config, environ={}, judge=FakeJudge(),
                                     models_dir=tmp_path)
    try:
        assert svc.models is not None and svc.models.keys.analyst == "sk-dash"
        assert svc.analyst is not None and svc._config.judge.model == "e2"
        assert "sk-dash" not in repr(svc.analyst)
    finally:
        await svc.close()


async def test_an_unusable_overlay_is_logged_and_the_config_applies(monkeypatch, tmp_path, caplog):
    config = web_config(tmp_path)
    private_json(tmp_path / "models.json", {"judge": {"url": "http://10.0.0.9:8200/"}})
    fake_connect(monkeypatch, [])
    with caplog.at_level(logging.WARNING):
        svc = await service.open_service(config, environ={}, judge=FakeJudge(),
                                         models_dir=tmp_path)
    try:
        assert svc._config.judge == config.judge and svc.analyst is None
        assert "must be loopback" in caplog.text and "config.toml applies instead" in caplog.text
    finally:
        await svc.close()


async def test_without_a_models_directory_the_view_is_off(monkeypatch, tmp_path):
    fake_connect(monkeypatch, [])
    svc = await service.open_service(web_config(tmp_path), environ={}, judge=FakeJudge())
    try:
        assert svc.models is None
    finally:
        await svc.close()


async def test_a_change_retargets_the_judge_and_rebuilds_the_analyst_without_a_restart(
        monkeypatch, tmp_path):
    fake_connect(monkeypatch, [])
    judge = FakeJudge()
    svc = await service.open_service(web_config(tmp_path), environ={"MY_KEY": "env-k"},
                                     judge=judge, models_dir=tmp_path)
    try:
        config, analyst = svc.models.save({
            "judge": {"url": "http://127.0.0.1:8201/v1/systemone", "model": "e3"},
            "analyst": LOCAL_LLM, "keys": {"judge": "ek"}})
        assert analyst is svc.analyst and analyst is not None
        ((_, server),) = judge.retargeted
        assert server.url == "http://127.0.0.1:8201/v1/systemone" and server.model == "e3"
        assert svc._config is config
        _, off = svc.models.save({"analyst": None})
        assert off is None and svc.analyst is None
    finally:
        await svc.close()


def test_the_analyst_key_comes_from_the_dashboard_before_the_environment(caplog):
    from neonwatch.models import Keys
    named = Config(analyst=dataclasses.replace(Config().analyst, provider="openai-compatible",
                                               model="m", base_url="http://127.0.0.1:1/v1",
                                               api_key_env="MY_KEY"))
    assert service._analyst(named, Keys(analyst="dash"), {}) is not None
    assert service._analyst(named, Keys(), {"MY_KEY": "env"}) is not None
    with caplog.at_level(logging.WARNING):
        assert service._analyst(named, Keys(), {}) is None
    assert "no key is set from the dashboard" in caplog.text


def test_the_config_is_read_with_the_services_own_uid_as_owner(monkeypatch, tmp_path):
    seen = []

    def load(path, *, owner):
        seen.append((path, owner))
        raise service.ConfigError("stop here")
    monkeypatch.setattr(service, "load", load)
    assert service.main(["--config", str(tmp_path / "c.toml")], uid=4321, environ={}) == 2
    assert seen == [(tmp_path / "c.toml", 4321)]


def test_a_port_already_in_use_is_reported_and_exits_1(monkeypatch, capsys):
    class Busy:
        async def run(self, stop):
            raise OSError(98, "address already in use")

    async def opened(config, **kw):
        return Busy()
    monkeypatch.setattr(service, "open_service", opened)
    assert service.main([], uid=1000, environ={}) == 1
    assert "address already in use" in capsys.readouterr().err


def test_logging_goes_to_stderr_and_the_access_log_cannot_carry_the_token():
    service.configure_logging()
    assert logging.getLogger("aiohttp.access").getEffectiveLevel() >= logging.WARNING


# --- TLS and the password -----------------------------------------------------------------------

needs_openssl = pytest.mark.skipif(
    shutil.which("openssl") is None,
    reason="openssl makes the test certificate: the standard library cannot create one")
PASSWORD = "a long enough passphrase"


@pytest.fixture(scope="module")
def password_hash():
    return web.hash_password(PASSWORD)


@pytest.fixture
def pair(tmp_path):
    """A self-signed certificate for 127.0.0.1 and its key, mode 0600."""
    cert, key = tmp_path / "cert.pem", tmp_path / "key.pem"
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
         "-nodes", "-days", "2", "-subj", "/CN=monitor.test", "-keyout", str(key), "-out",
         str(cert), "-addext", "subjectAltName=DNS:monitor.test,IP:127.0.0.1"],
        check=True, capture_output=True, timeout=30)
    key.chmod(0o600)
    return cert, key


def test_no_tls_settings_means_no_tls_context():
    assert service.tls_context(Web()) is None


@needs_openssl
def test_the_tls_context_is_a_server_context_with_tls12_at_least(pair):
    cert, key = pair
    context = service.tls_context(Web(tls_cert=str(cert), tls_key=str(key)))
    assert context.protocol is ssl.PROTOCOL_TLS_SERVER
    assert context.minimum_version is ssl.TLSVersion.TLSv1_2


@needs_openssl
def test_a_tilde_in_the_tls_paths_means_home(pair, monkeypatch):
    cert, _key = pair
    monkeypatch.setenv("HOME", str(cert.parent))
    assert service.tls_context(Web(tls_cert="~/cert.pem", tls_key="~/key.pem")) is not None


@needs_openssl
@pytest.mark.parametrize("mode", [0o640, 0o604, 0o660, 0o644, 0o602])
def test_a_key_others_can_reach_is_refused(pair, mode):
    cert, key = pair
    key.chmod(mode)
    with pytest.raises(ValueError, match=f"mode {mode:04o}.*chmod 600"):
        service.tls_context(Web(tls_cert=str(cert), tls_key=str(key)))


@needs_openssl
@pytest.mark.parametrize("broken", ["missing cert", "missing key", "unreadable cert",
                                    "unreadable key"])
def test_a_missing_or_unreadable_file_is_refused(pair, broken):
    cert, key = pair
    target = cert if "cert" in broken else key
    if broken.startswith("missing"):
        target.unlink()
    else:
        target.chmod(0)
    name = "tls_cert" if "cert" in broken else "tls_key"
    with pytest.raises(ValueError, match=f"web.{name} {re.escape(str(target))}: cannot read it"):
        service.tls_context(Web(tls_cert=str(cert), tls_key=str(key)))


@needs_openssl
def test_a_pair_that_does_not_load_is_refused(pair):
    cert, key = pair
    cert.write_text("not a certificate\n")
    with pytest.raises(ValueError, match="cannot load the certificate and key"):
        service.tls_context(Web(tls_cert=str(cert), tls_key=str(key)))


@needs_openssl
def test_the_service_refuses_to_start_with_a_group_readable_key(pair, tmp_path, monkeypatch,
                                                                capsys):
    cert, key = pair
    key.chmod(0o640)

    async def never(*_a, **_k):
        raise AssertionError("connected before checking the key")
    monkeypatch.setattr(service.bus, "connect", never)
    config = tmp_path / "c.toml"
    config.write_text(f'[web]\ntls_cert = "{cert}"\ntls_key = "{key}"\n')
    assert service.main(["--config", str(config)], uid=os.getuid(), environ={}) == 1
    err = capsys.readouterr().err
    assert "cannot start" in err and "web.tls_key" in err and "chmod 600" in err


@needs_openssl
async def test_open_service_hands_the_tls_context_to_the_service(monkeypatch, tmp_path, pair):
    made: list[FakeBus] = []
    fake_connect(monkeypatch, made)
    cert, key = pair
    config = web_config(tmp_path)
    config = Config(web=Web(port=config.web.port, tls_cert=str(cert), tls_key=str(key)),
                    store=config.store)
    svc = await service.open_service(config, environ={}, judge=FakeJudge())
    try:
        assert isinstance(svc.ssl_context, ssl.SSLContext)
    finally:
        await svc.close()


def test_the_printed_url_follows_tls_the_password_and_the_allowed_hosts(password_hash):
    def url(**web_settings):
        svc = make(config=Config(web=Web(**web_settings)))
        svc.ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER) if web_settings.get(
            "tls_cert") else None
        return svc.url()
    token = "t" * 43
    assert url() == f"http://127.0.0.1:8765/?token={token}"
    assert url(host="::1") == f"http://[::1]:8765/?token={token}"
    assert url(tls_cert="c", tls_key="k") == f"https://127.0.0.1:8765/?token={token}"
    assert url(password_hash=password_hash) == "http://127.0.0.1:8765/"
    assert url(host="192.168.1.50", tls_cert="c", tls_key="k", password_hash=password_hash,
               allowed_hosts=("myhost:8765", "192.168.1.50:8765")) == "https://myhost:8765/"


@needs_openssl
async def test_run_over_tls_with_a_password_prints_the_https_url_and_no_token(
        tmp_path, pair, password_hash):
    cert, key = pair
    port = free_port()
    config = Config(web=Web(port=port, tls_cert=str(cert), tls_key=str(key),
                            password_hash=password_hash, allowed_hosts=(f"127.0.0.1:{port}",)),
                    store=Store(path=str(tmp_path / "s.sqlite3")))
    store = SqliteStore(tmp_path / "s.sqlite3", config)
    out = io.StringIO()
    svc = Service(config, evaluator_bus=FakeBus(), viewer_bus=FakeBus(), notifier_bus=FakeBus(),
                  store=store, judge=FakeJudge(), evaluator=FakeEvaluator(),
                  notifier=FakeNotifier(), analyst=None, token="k" * 43, clock=time.time,
                  out=out, ssl_context=service.tls_context(config.web))
    stop = asyncio.Event()
    running = asyncio.create_task(svc.run(stop))
    try:
        for _ in range(200):
            if out.getvalue():
                break
            await asyncio.sleep(0.01)
        assert out.getvalue() == f"https://127.0.0.1:{port}/\n"
        trust = ssl.create_default_context(cafile=str(cert))

        def fetch(path):
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}),
                                                 urllib.request.HTTPSHandler(context=trust))
            try:
                with opener.open(f"https://127.0.0.1:{port}{path}", timeout=5) as response:
                    return response.status, response.headers
            except urllib.error.HTTPError as refused:
                return refused.code, refused.headers
        status, headers = await asyncio.to_thread(fetch, "/login")
        assert status == 200 and headers["Strict-Transport-Security"] == "max-age=31536000"
        assert (await asyncio.to_thread(fetch, "/api/health"))[0] == 401
        assert (await asyncio.to_thread(fetch, f"/api/health?token={'k' * 43}"))[0] == 401
    finally:
        stop.set()
        assert await running == 0


# --- hash-password ---------------------------------------------------------------------------


def answers(*replies):
    asked = []
    queue = list(replies)

    def ask(prompt):
        asked.append(prompt)
        reply = queue.pop(0)
        if isinstance(reply, BaseException):
            raise reply
        return reply
    return ask, asked


def test_hash_password_asks_twice_and_prints_one_pasteable_line(capsys):
    ask, asked = answers(PASSWORD, PASSWORD)
    assert service.hash_password_command(ask=ask) == 0
    assert asked == ["Dashboard password: ", "The same password again: "]
    out, err = capsys.readouterr()
    assert err == "" and out.count("\n") == 1
    match = re.fullmatch(r'password_hash = "(scrypt\$[^"]+)"\n', out)
    assert match and web.verify_password(PASSWORD, match[1])
    assert PASSWORD not in out


@pytest.mark.parametrize("replies, why", [
    ((PASSWORD, PASSWORD + "x"), "differ"),
    (("short pass", "short pass"), "at least 12 characters"),
    (("y" * 1025, "y" * 1025), "at most 1024 characters"),
    ((EOFError(),), "no password"),
    ((PASSWORD, KeyboardInterrupt()), "no password"),
])
def test_hash_password_refuses_and_prints_no_hash(replies, why, capsys):
    ask, _ = answers(*replies)
    assert service.hash_password_command(ask=ask) == 1
    out, err = capsys.readouterr()
    assert out == "" and why in err and "scrypt" not in err


def test_hash_password_reads_with_getpass_by_default(monkeypatch, capsys):
    seen = []
    monkeypatch.setattr(service.getpass, "getpass", lambda prompt: seen.append(prompt) or PASSWORD)
    assert service.hash_password_command() == 0
    assert len(seen) == 2 and capsys.readouterr().out.startswith('password_hash = "scrypt$')


# --- the whole wiring, against a real nats-server ------------------------------------------------


@pytest.fixture
def nats(tmp_path):
    port = free_port()
    config = Config(broker=Broker(url=f"nats://127.0.0.1:{port}",
                                  state_dir=str(tmp_path / "broker"), binary=str(BINARY)),
                    store=Store(path=str(tmp_path / "store.sqlite3")),
                    web=Web(port=free_port()), cadence=Cadence(collate=1),
                    retention=Retention(max_bytes=64 * 1024**2))
    paths = broker.init(config)
    log = (tmp_path / "nats.log").open("wb")
    proc = subprocess.Popen([str(BINARY), "-c", str(paths.config_file)], stdout=log,
                            stderr=subprocess.STDOUT)
    deadline = time.monotonic() + 10
    while True:
        assert proc.poll() is None, (tmp_path / "nats.log").read_text()
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
            break
        except OSError:
            assert time.monotonic() < deadline, "nats-server did not accept connections"
            time.sleep(0.05)
    yield config, paths
    proc.terminate()
    proc.wait(timeout=10)
    log.close()


async def test_an_agent_observation_becomes_a_stored_live_notified_critical_issue(
        nats, caplog):
    caplog.set_level(logging.INFO)
    service.configure_logging()
    config, paths = nats
    sent = []

    async def send(notification):
        sent.append(notification)
        return None
    judge = FakeJudge()
    out = io.StringIO()
    svc = await service.open_service(config, environ={}, judge=judge, send=send, out=out,
                                     owner=os.getuid())
    watching = svc.live.subscribe()
    stop = asyncio.Event()
    running = asyncio.create_task(svc.run(stop))

    agent = await connect(config.broker.url, paths.creds[broker.Role.AGENT])
    try:
        await agent.publish(observation("disk.fill", FULL_DISK))
        await agent.publish(Event(Kind.HEARTBEAT, time.time(), "agent", "hb.agent", to_body(
            Heartbeat(cpu_fraction=0.001, confined=False, writable=("/",), ran=1, failed=0,
                      deferred=0))))
        # The agent's credential publishes observations and heartbeats, nothing else.
        with pytest.raises(BusError):
            await agent.publish(issue_event())
    finally:
        await agent.close()

    live_kinds: list[Kind] = []
    critical = None
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline and not (critical and sent and Kind.ISSUE in live_kinds):
        try:
            event = await asyncio.wait_for(anext(watching), 0.2)
            live_kinds.append(event.kind)
        except TimeoutError:
            pass
        critical = next((i for i in svc.store.issues()
                         if i.severity is Severity.CRITICAL and i.entity == "mount:/"), None)
    stop.set()
    assert await asyncio.wait_for(running, 15) == 0

    assert critical is not None and critical.state is IssueState.OPEN and critical.deterministic
    assert Kind.OBSERVATION in live_kinds and Kind.ISSUE in live_kinds
    assert Kind.HEARTBEAT in live_kinds
    assert any(n.issue_id == critical.id and n.urgency == 2 for n in sent)
    assert judge.asked >= 1   # the fake judge was asked; no judge was
    assert svc.counts.dropped == 0 and svc.counts.refused == 0
    # stdout is not a terminal here, so it has the URL without the token (a unit's stdout goes
    # to the journal), and no log line has the token either.
    assert out.getvalue().count(svc.token) == 0
    assert out.getvalue().startswith(f"http://127.0.0.1:{config.web.port}/ (the sign-in URL")
    assert svc.token not in caplog.text


async def test_visiting_the_dashboard_url_does_not_put_the_token_in_a_log(nats, caplog):
    caplog.set_level(logging.DEBUG)
    service.configure_logging()
    config, _ = nats
    svc = await service.open_service(config, environ={}, judge=FakeJudge(), out=io.StringIO(),
                                     owner=os.getuid())
    stop = asyncio.Event()
    running = asyncio.create_task(svc.run(stop))
    try:
        status = 0
        for _ in range(200):
            try:
                status, _body = await asyncio.to_thread(get, config.web.port, "/api/health",
                                                        svc.token)
            except urllib.error.URLError:   # not listening yet
                status = 0
            if status == 200:
                break
            await asyncio.sleep(0.02)
        await asyncio.to_thread(get, config.web.port, f"/?token={svc.token}")
    finally:
        stop.set()
        await asyncio.wait_for(running, 15)
    assert status == 200
    assert svc.token not in caplog.text
