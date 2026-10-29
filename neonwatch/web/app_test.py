"""The loopback web layer: every route, every security rule, the SSE framing and the analysis flow.

Nothing here reaches the network except the loopback server each test starts. The store, the live
event source and the analyst are fakes; one test at the end runs the real `Store` in `tmp_path`.
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import dataclasses
import json
import logging
import re
import shutil
import socket
import ssl
import subprocess
from collections.abc import AsyncIterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import aiohttp
import pytest
from aiohttp.test_utils import TestClient, TestServer

from neonwatch import jobs as real_jobs
from neonwatch.analyst import Analyst, LogExplained, ServicesDescribed, ServiceText
from neonwatch.config import Analyst as AnalystConfig
from neonwatch.config import Cadence, Config, Retention, Web, load
from neonwatch.logs import JournalRead, parse_line
from neonwatch.probes import CATALOG
from neonwatch.schema import (
    Analysis,
    Attestation,
    Event,
    Finding,
    Heartbeat,
    Issue,
    IssueState,
    Kind,
    Link,
    Observation,
    Severity,
    to_body,
)
from neonwatch.store import (
    AuditEntry,
    DomainSummary,
    Hold,
    Incident,
    LogExplanation,
    Point,
    ServiceDescription,
    Store,
    StoreError,
)
from neonwatch.web import app as web_app
from neonwatch.web import hash_password, make_app, start, verify_password

TOKEN = "t0ken-" + "x" * 40
NOW = 1_000_000.0
AUTH = {"Authorization": f"Bearer {TOKEN}"}


# --- fakes ----------------------------------------------------------------------------------


def issue(id: str = "i1", severity: Severity = Severity.WARN, state: IssueState = IssueState.OPEN,
          entity: str = "unit:foo.service", domain: str = "services", updated_at: float = NOW - 60,
          reasons: tuple[str, ...] = ("units.failed",), score: float = 1.0) -> Issue:
    return Issue(id=id, state=state, severity=severity, title=f"{id} is bad", domain=domain,
                 entity=entity, opened_at=updated_at - 100, updated_at=updated_at,
                 deterministic=True, reasons=reasons, next_step="systemctl status foo",
                 score=score)


def finding(rule: str = "units.failed", entity: str = "unit:foo.service",
            severity: Severity = Severity.WARN) -> Finding:
    return Finding(rule=rule, severity=severity, title=f"{rule} on {entity}", entity=entity,
                   evidence={"probe": "units.failed"})


def attestation(question: str = "q.health", entity: str = "unit:foo.service",
                context: str = "ctx-foo", domain: str = "services") -> Attestation:
    return Attestation(context=context, context_kind="unit", domain=domain, entity=entity,
                       question=question, instructions="is it healthy?", answer={"value": "no"},
                       severity=Severity.WARN, cause="it failed", next_step="look",
                       confidence=0.8, stable=True, latency_ms=12)


def observation(probe: str = "units.failed", data: dict | None = None) -> Observation:
    return Observation(probe=probe, data=data if data is not None else
                       {"units": [{"unit": "foo.service", "active": "failed"}]}, cpu_ms=3)


def heartbeat(confined: bool = False) -> Heartbeat:
    return Heartbeat(cpu_fraction=0.004, confined=confined,
                     writable=() if confined else ("/", "/etc"), ran=30, failed=1, deferred=0)


def analysis(id: str = "an-1", subjects: tuple[str, ...] = ("issue:i1",), error: str = "",
             completed_at: float = NOW - 10) -> Analysis:
    return Analysis(id=id, requested_at=completed_at - 5, completed_at=completed_at,
                    backend="openai-compatible", model="m", subjects=subjects, question="why?",
                    text="probably foo", suggested_checks=("systemctl status foo",),
                    input_chars=100, output_chars=12, error=error)


class FakeStore:
    """Answers the store's public reads from lists, filtering the way the real store does."""

    def __init__(self) -> None:
        self.observations: list[tuple[float, Observation]] = []
        self.issue_rows: dict[str, Issue] = {}
        self.finding_rows: list[tuple[float, Finding]] = []
        self.attestation_rows: list[tuple[float, Attestation]] = []
        self.heartbeat: tuple[float, Heartbeat] | None = None
        self.domain_rows: dict[str, DomainSummary] = {}
        self.incident_rows: list[Incident] = []
        self.analysis_rows: list[Analysis] = []
        self.points: tuple[Point, ...] = ()
        self.series_calls: list[tuple[str, str, float, int]] = []
        self.acks: list[tuple[str, float]] = []
        self.snoozes: list[tuple[str, float]] = []
        self.broken = False
        self.explained: dict[str, LogExplanation] = {}
        self.touched: list[tuple[str, float]] = []
        self.described: dict[str, ServiceDescription] = {}
        self.sightings: dict[str, tuple[float, bool]] = {}
        self.touched_services: list[tuple[str, float]] = []
        self.hold_rows: dict[str, Hold] = {}
        self.audit_rows: list[AuditEntry] = []

    def latest(self, probe: str | None = None) -> tuple[tuple[float, Observation], ...]:
        rows = [r for r in self.observations if probe is None or r[1].probe == probe]
        return tuple(sorted(rows, key=lambda r: -r[0]))

    def series(self, probe: str, field: str, since: float, step_s: int) -> tuple[Point, ...]:
        self.series_calls.append((probe, field, since, step_s))
        return self.points

    def issues(self, state: IssueState | None = None) -> tuple[Issue, ...]:
        rows = [i for i in self.issue_rows.values() if state is None or i.state is state]
        return tuple(sorted(rows, key=lambda i: (-i.score, -i.updated_at, i.id)))

    def issue(self, issue_id: str) -> Issue | None:
        return self.issue_rows.get(issue_id)

    def findings(self, since: float | None = None,
                 latest: bool = False) -> tuple[tuple[float, Finding], ...]:
        rows = [r for r in self.finding_rows if since is None or r[0] >= since]
        if latest:
            newest: dict[tuple[str, str], tuple[float, Finding]] = {}
            for at, f in sorted(rows, key=lambda r: r[0]):
                newest[(f.rule, f.entity)] = (at, f)
            rows = list(newest.values())
        return tuple(sorted(rows, key=lambda r: -r[0]))

    def attestations(self, context: str | None = None, question: str | None = None,
                     since: float | None = None,
                     latest: bool = False) -> tuple[tuple[float, Attestation], ...]:
        rows = [r for r in self.attestation_rows
                if (context is None or r[1].context == context)
                and (question is None or r[1].question == question)
                and (since is None or r[0] >= since)]
        if latest:
            newest: dict[tuple[str, str], tuple[float, Attestation]] = {}
            for at, a in sorted(rows, key=lambda r: r[0]):
                newest[(a.context, a.question)] = (at, a)
            rows = list(newest.values())
        return tuple(sorted(rows, key=lambda r: -r[0]))

    def last_heartbeat(self) -> tuple[float, Heartbeat] | None:
        if self.broken:
            raise StoreError("database is locked")
        return self.heartbeat

    def domains(self) -> dict[str, DomainSummary]:
        return dict(self.domain_rows)

    def incidents(self) -> tuple[Incident, ...]:
        return tuple(self.incident_rows)

    def analyses(self, subject: str | None = None) -> tuple[Analysis, ...]:
        rows = [a for a in self.analysis_rows if subject is None or subject in a.subjects]
        return tuple(sorted(rows, key=lambda a: -a.completed_at))

    def save_analysis(self, record: Analysis) -> None:
        self.analysis_rows = [a for a in self.analysis_rows if a.id != record.id] + [record]

    def log_explanations(self, keys: Any) -> dict[str, LogExplanation]:
        return {k: self.explained[k] for k in set(keys) if k in self.explained}

    def touch_log_explanations(self, keys: Any, at: float) -> None:
        self.touched += [(k, at) for k in sorted(keys)]

    def save_log_explanations(self, rows: Any) -> int:
        for row in rows:
            self.explained[row.key] = row
        return 0

    def service_descriptions(self, names: Any) -> dict[str, ServiceDescription]:
        return {n: self.described[n] for n in set(names) if n in self.described}

    def service_sightings(self) -> dict[str, tuple[float, bool]]:
        return dict(self.sightings)

    def touch_service_descriptions(self, names: Any, at: float) -> None:
        self.touched_services += [(n, at) for n in sorted(names)]

    def save_service_descriptions(self, rows: Any) -> int:
        for row in rows:
            self.described[row.name] = row
        return 0

    def ack(self, issue_id: str, at: float, by: str = "") -> Issue:
        return self._hold(issue_id, IssueState.ACKNOWLEDGED, at, self.acks, Hold(by, at, None))

    def snooze(self, issue_id: str, until: float, by: str = "") -> Issue:
        return self._hold(issue_id, IssueState.SNOOZED, until, self.snoozes,
                          Hold(by, None, until))

    def _hold(self, issue_id: str, state: IssueState, value: float, log: list,
              hold: Hold) -> Issue:
        current = self.issue_rows.get(issue_id)
        if current is None:
            raise KeyError(issue_id)
        if current.state is IssueState.RESOLVED:
            raise StoreError("resolved")
        log.append((issue_id, value))
        self.issue_rows[issue_id] = dataclasses.replace(current, state=state)
        self.hold_rows[issue_id] = hold
        return self.issue_rows[issue_id]

    def holds(self) -> dict[str, Hold]:
        held = {i.id for i in self.issue_rows.values()
                if i.state in (IssueState.ACKNOWLEDGED, IssueState.SNOOZED)}
        return {i: self.hold_rows.get(i, Hold("", None, None)) for i in held}

    def audit(self, at: float, agent: str, action: str, target: str, detail: Any) -> None:
        self.audit_rows.append(AuditEntry(len(self.audit_rows) + 1, at, agent, action, target,
                                          dict(detail)))

    def audit_log(self, limit: int = 100, agent: str | None = None,
                  since: float | None = None) -> tuple[AuditEntry, ...]:
        rows = [r for r in reversed(self.audit_rows) if (agent is None or r.agent == agent)
                and (since is None or r.at >= since)]
        return tuple(rows[:limit])


class FakeLive:
    """`subscribe()` yields what the test pushes; `fail()` makes the next subscription raise."""

    def __init__(self) -> None:
        self.queues: list[asyncio.Queue] = []
        self.subscribed = asyncio.Event()
        self.error: BaseException | None = None

    async def subscribe(self) -> AsyncIterator[Event]:
        if self.error is not None:
            raise self.error
        queue: asyncio.Queue = asyncio.Queue()
        self.queues.append(queue)
        self.subscribed.set()
        while True:
            item = await queue.get()
            if item is None:
                return
            yield item

    async def push(self, event: Event | None) -> None:
        await asyncio.wait_for(self.subscribed.wait(), 2)
        for queue in self.queues:
            queue.put_nowait(event)


@dataclass(frozen=True)
class FakeEstimate:
    chars: int
    approx_tokens: int
    backend: str
    model: str
    url_host: str
    remote: bool


@dataclass(frozen=True)
class FakeLogEstimate(FakeEstimate):
    requests: int
    templates: int


@dataclass(frozen=True)
class FakeServiceEstimate(FakeEstimate):
    requests: int
    services: int


class FakeAnalyst:
    """Records each request; `analyze` waits for `release` so a test can see it running."""

    def __init__(self, error: str = "", raises: BaseException | None = None) -> None:
        self.requests: list[Any] = []
        self.release = asyncio.Event()
        self.error = error
        self.raises = raises

    def estimate_logs(self, templates: Any) -> FakeLogEstimate:
        return FakeLogEstimate(chars=99 * len(templates), approx_tokens=25 * len(templates),
                               backend="openai-compatible", model="m", url_host="127.0.0.1",
                               remote=False, requests=1, templates=len(templates))

    async def explain_logs(self, templates: Any, progress: Any = None) -> LogExplained:
        self.requests.append(list(templates))
        self.progress = progress
        await self.release.wait()
        if self.raises is not None:
            raise self.raises
        if self.error:
            return LogExplained({}, "m", 1, 1, 10, 0, self.error)
        return LogExplained({t.key: f"means {t.template}" for t in templates}, "m", 1, 0, 10, 9)

    def estimate_services(self, units: Any) -> FakeServiceEstimate:
        return FakeServiceEstimate(chars=300 * len(units), approx_tokens=75 * len(units),
                                   backend="openai-compatible", model="m", url_host="127.0.0.1",
                                   remote=False, requests=1, services=len(units))

    async def describe_services(self, units: Any, progress: Any = None) -> ServicesDescribed:
        self.requests.append(list(units))
        self.progress = progress
        await self.release.wait()
        if self.raises is not None:
            raise self.raises
        if self.error:
            return ServicesDescribed({}, "m", 1, 1, 10, 0, self.error)
        return ServicesDescribed({u.key: ServiceText(f"{u.name} is a daemon.",
                                                     f"{u.name} runs {u.exec}.") for u in units},
                                 "m", 1, 0, 10, 9)

    def estimate(self, request: Any) -> FakeEstimate:
        self.requests.append(request)
        return FakeEstimate(chars=1234, approx_tokens=309, backend="openai-compatible",
                            model="m", url_host="127.0.0.1", remote=False)

    async def analyze(self, request: Any) -> Analysis:
        self.requests.append(request)
        await self.release.wait()
        if self.raises is not None:
            raise self.raises
        return Analysis(id="analyst-own-id", requested_at=NOW, completed_at=NOW + 1,
                        backend="openai-compatible", model="m", subjects=request.subjects,
                        question=request.question, text="" if self.error else "it is foo",
                        suggested_checks=("systemctl status foo",), input_chars=1234,
                        output_chars=9, error=self.error)


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@dataclass
class Harness:
    client: TestClient
    store: Any
    live: FakeLive
    port: int
    csrf: str

    @property
    def origin(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def post_headers(self, **extra: str) -> dict[str, str]:
        return {**AUTH, "Origin": self.origin, "X-CSRF-Token": self.csrf, **extra}

    async def post(self, path: str, body: Any = None, **kwargs: Any):
        headers = kwargs.pop("headers", self.post_headers())
        return await self.client.post(path, json=body, headers=headers, **kwargs)

    async def get(self, path: str, **kwargs: Any):
        headers = kwargs.pop("headers", AUTH)
        return await self.client.get(path, headers=headers, **kwargs)


@contextlib.asynccontextmanager
async def serve(store: Any = None, analyst: Any = None, live: FakeLive | None = None,
                retention: Retention | None = None, cadence: Cadence | None = None,
                analyst_config: AnalystConfig | None = None,
                **options: Any) -> AsyncIterator[Harness]:
    port = free_port()
    store = store if store is not None else FakeStore()
    live = live if live is not None else FakeLive()
    config = Config(web=Web(port=port), retention=retention or Retention(),
                    cadence=cadence or Cadence(), analyst=analyst_config or AnalystConfig())
    options.setdefault("clock", lambda: NOW)
    app = make_app(store, live, TOKEN, config, analyst=analyst, **options)
    client = TestClient(TestServer(app, host="127.0.0.1", port=port))
    await client.start_server()
    try:
        session = await client.get("/api/session", headers=AUTH)
        csrf = (await session.json())["csrf"] if session.status == 200 else ""
        yield Harness(client, store, live, port, csrf)
    finally:
        await client.close()


def populated() -> FakeStore:
    s = FakeStore()
    s.issue_rows = {
        "i1": issue("i1", Severity.WARN, score=2.0),
        "i2": issue("i2", Severity.CRITICAL, entity="disk:/dev/nvme0", domain="storage",
                    reasons=("smart.critical",), score=5.0),
        "i3": issue("i3", Severity.INFO, state=IssueState.ACKNOWLEDGED),
        "i4": issue("i4", Severity.WARN, state=IssueState.RESOLVED),
    }
    s.observations = [(NOW - 30, observation()),
                      (NOW - 7200, observation("smart.nvme0n1",
                                               {"device": "/dev/nvme0", "critical_warning": 1})),
                      (NOW - 5, observation("load", {"load1": 0.5}))]
    s.finding_rows = [(NOW - 200, finding()), (NOW - 100, finding()),
                      (NOW - 50, finding("smart.critical", "disk:/dev/nvme0", Severity.CRITICAL))]
    s.attestation_rows = [(NOW - 90, attestation()),
                          (NOW - 80, attestation("q.other", entity="unit:bar.service",
                                                 context="ctx-bar"))]
    s.heartbeat = (NOW - 20, heartbeat())
    s.domain_rows = {"services": DomainSummary(
        open={sev: (1 if sev is Severity.WARN else 0) for sev in Severity},
        attested={sev: (2 if sev is Severity.WARN else 0) for sev in Severity})}
    lk = Link(id="l1", members=("issue:i1", "finding:smart.critical@disk:/dev/nvme0"),
              basis="shared-entity", related=0.9, likely_cause="issue:i1", confidence=0.7,
              stable=True)
    s.incident_rows = [Incident(at=NOW - 40, link=lk, issues=(s.issue_rows["i1"],),
                                findings=((NOW - 50, s.finding_rows[2][1]),), missing=())]
    s.analysis_rows = [analysis()]
    return s


# --- the Host header: DNS-rebinding defence -------------------------------------------------


@pytest.mark.parametrize("host", ["evil.example:{port}", "127.0.0.1:1", "localhost",
                                  "127.0.0.1", "127.0.0.2:{port}", "localhost.:{port}"])
async def test_a_foreign_host_header_is_refused_on_every_path(host: str) -> None:
    async with serve() as h:
        for path in ("/api/health", "/", "/?token=" + TOKEN):
            resp = await h.get(path, headers={**AUTH, "Host": host.format(port=h.port)},
                               allow_redirects=False)
            assert resp.status == 403, path
            assert await resp.json() == {"error": "unexpected Host header"}


async def test_localhost_and_the_ip_are_both_accepted() -> None:
    async with serve() as h:
        for host in (f"127.0.0.1:{h.port}", f"localhost:{h.port}"):
            resp = await h.get("/api/health", headers={**AUTH, "Host": host})
            assert resp.status == 200


def test_an_empty_token_is_refused_at_construction() -> None:
    with pytest.raises(ValueError, match="token"):
        make_app(FakeStore(), FakeLive(), "", Config())


# --- the token ------------------------------------------------------------------------------


@pytest.mark.parametrize("headers", [
    {}, {"Authorization": "Bearer wrong"}, {"Authorization": TOKEN},
    {"Authorization": f"Basic {TOKEN}"}, {"Authorization": f"Bearer {TOKEN}x"},
    {"Authorization": "Bearer "}, {"Cookie": "neonwatch_token=wrong"},
    {"Authorization": "Bearer éé"},
])
async def test_api_requests_need_the_token(headers: dict[str, str]) -> None:
    async with serve() as h:
        for path in ("/api/health", "/api/overview", "/api/stream", "/api/nope",
                     "/api/scheduled", "/api/services"):
            resp = await h.get(path, headers=headers)
            assert resp.status == 401, path
            assert await resp.json() == {"error": "missing or wrong token"}


async def test_the_comparison_is_constant_time(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[tuple[bytes, bytes]] = []
    real = web_app.hmac.compare_digest

    def spy(a: bytes, b: bytes) -> bool:
        seen.append((a, b))
        return real(a, b)

    monkeypatch.setattr(web_app.hmac, "compare_digest", spy)
    async with serve(populated()) as h:
        assert (await h.get("/api/health")).status == 200
        assert (await h.post("/api/issues/i1/ack")).status == 200
    assert (TOKEN.encode(), TOKEN.encode()) in seen
    assert (h.csrf.encode(), h.csrf.encode()) in seen


async def test_the_cookie_flow_sets_an_httponly_strict_cookie_and_drops_the_token() -> None:
    async with serve() as h:
        resp = await h.client.get(f"/?token={TOKEN}", allow_redirects=False)
        assert resp.status == 303
        assert resp.headers["Location"] == "/"
        cookie = resp.headers["Set-Cookie"]
        assert cookie.startswith(f"neonwatch_token={TOKEN};")
        assert "HttpOnly" in cookie and "SameSite=Strict" in cookie and "Path=/" in cookie
        # The client's jar now holds it: a plain GET of the API works with no header.
        resp = await h.client.get("/api/health")
        assert resp.status == 200


async def test_a_wrong_token_in_the_url_sets_nothing() -> None:
    async with serve() as h:
        resp = await h.client.get("/?token=nope", allow_redirects=False)
        assert resp.status == 401
        assert "Set-Cookie" not in resp.headers
        assert await resp.json() == {"error": "missing or wrong token"}


# --- writes: bearer AND same-origin ---------------------------------------------------------


async def test_a_post_with_only_the_cookie_is_refused() -> None:
    async with serve(populated()) as h:
        await h.client.get(f"/?token={TOKEN}", allow_redirects=False)
        resp = await h.client.post("/api/issues/i1/ack", headers={"Origin": h.origin})
        assert resp.status == 403
        assert await resp.json() == {"error": "missing or wrong CSRF token"}
        assert h.store.acks == []


async def test_the_dashboard_writes_with_the_cookie_and_the_csrf_token() -> None:
    async with serve(populated()) as h:
        await h.client.get(f"/?token={TOKEN}", allow_redirects=False)
        # What the page's script does: read the CSRF token with the cookie, then send it.
        session = await h.client.get("/api/session")
        assert session.status == 200
        csrf = (await session.json())["csrf"]
        assert csrf == h.csrf
        resp = await h.client.post("/api/issues/i1/ack",
                                   headers={"Origin": h.origin, "X-CSRF-Token": csrf})
        assert resp.status == 200
        assert h.store.acks == [("i1", NOW)]


async def test_the_session_needs_the_token_and_sends_no_cors_headers() -> None:
    async with serve() as h:
        assert (await h.client.get("/api/session")).status == 401
        resp = await h.get("/api/session", headers={**AUTH, "Origin": "http://evil.example"})
        assert resp.status == 200
        assert not [k for k in resp.headers if k.lower().startswith("access-control-")]
        body = await resp.json()
        assert list(body) == ["csrf"]
        assert len(body["csrf"]) >= 32 and body["csrf"] != TOKEN
        preflight = await h.client.options("/api/issues/i1/ack", headers={
            "Origin": "http://evil.example", "Access-Control-Request-Method": "POST"})
        assert preflight.status in (401, 403, 405)
        assert not [k for k in preflight.headers if k.lower().startswith("access-control-")]
    async with serve() as other:
        assert other.csrf != h.csrf  # per launch


@pytest.mark.parametrize("csrf", [None, "", "wrong", "{csrf}x", TOKEN])
async def test_a_bearer_post_needs_the_csrf_token_too(csrf: str | None) -> None:
    async with serve(populated()) as h:
        headers = {**AUTH, "Origin": h.origin}
        if csrf is not None:
            headers["X-CSRF-Token"] = csrf.format(csrf=h.csrf)
        resp = await h.client.post("/api/issues/i1/ack", headers=headers)
        assert resp.status == 403
        assert await resp.json() == {"error": "missing or wrong CSRF token"}
        assert h.store.acks == []


async def test_a_cookie_post_with_a_wrong_csrf_token_is_refused() -> None:
    async with serve(populated()) as h:
        await h.client.get(f"/?token={TOKEN}", allow_redirects=False)
        resp = await h.client.post("/api/issues/i1/ack",
                                   headers={"Origin": h.origin, "X-CSRF-Token": "wrong"})
        assert resp.status == 403
        assert h.store.acks == []


@pytest.mark.parametrize("origin", [None, "http://evil.example", "null",
                                    "http://localhost:{port}", "https://127.0.0.1:{port}",
                                    "http://127.0.0.1:1"])
async def test_a_post_from_another_origin_is_refused(origin: str | None) -> None:
    async with serve(populated()) as h:
        headers = {**AUTH, "X-CSRF-Token": h.csrf}
        if origin is not None:
            headers["Origin"] = origin.format(port=h.port)
        resp = await h.client.post("/api/issues/i1/ack", headers=headers)
        assert resp.status == 403
        assert await resp.json() == {"error": "cross-origin write refused"}
        assert h.store.acks == []


async def test_a_post_with_a_wrong_bearer_is_refused() -> None:
    async with serve(populated()) as h:
        resp = await h.post("/api/issues/i1/ack",
                            headers={"Authorization": "Bearer nope", "Origin": h.origin,
                                     "X-CSRF-Token": h.csrf})
        assert resp.status == 401
        assert await resp.json() == {"error": "missing or wrong token"}
        assert h.store.acks == []


async def test_the_origin_must_match_the_host_it_was_sent_to() -> None:
    async with serve(populated()) as h:
        host = f"localhost:{h.port}"
        resp = await h.client.post("/api/issues/i1/ack",
                                   headers={**h.post_headers(), "Host": host,
                                            "Origin": f"http://{host}"})
        assert resp.status == 200


async def test_other_methods_are_held_to_the_write_rules_then_refused() -> None:
    async with serve(populated()) as h:
        assert (await h.client.delete("/api/issues/i1", headers=AUTH)).status == 403
        resp = await h.client.put("/api/issues/i1", headers=h.post_headers())
        assert resp.status == 405
        assert await resp.json() == {"error": "method not allowed"}


async def test_an_oversized_body_is_refused() -> None:
    async with serve(populated(), analyst=FakeAnalyst()) as h:
        big = {"subjects": ["issue:i1"], "question": "x" * (web_app.MAX_BODY + 1)}
        resp = await h.post("/api/analyses/estimate", big)
        assert resp.status == 413
        assert await resp.json() == {"error": "request body too large"}


# --- response headers and errors ------------------------------------------------------------


async def test_every_response_carries_the_security_headers() -> None:
    async with serve(populated()) as h:
        for resp in (await h.get("/api/overview"), await h.get("/api/nope"),
                     await h.client.get("/"), await h.client.get("/api/health"),
                     await h.get("/", headers={"Host": "evil:1"})):
            assert resp.headers["Cache-Control"] == "no-store"
            assert resp.headers["X-Content-Type-Options"] == "nosniff"
            assert resp.headers["Referrer-Policy"] == "no-referrer"
            csp = resp.headers["Content-Security-Policy"]
            assert "default-src 'self'" in csp and "frame-ancestors 'none'" in csp


async def test_unknown_routes_are_json_404s() -> None:
    async with serve() as h:
        for path in ("/api/nope", "/api/issues/i1/extra", "/nope.js", "/../etc/passwd",
                     "/.hidden"):
            resp = await h.get(path)
            assert resp.status == 404, path
            assert await resp.json() == {"error": "not found"}


async def test_an_internal_error_is_json_without_a_trace(caplog) -> None:
    store = populated()
    store.domains = None  # type: ignore[assignment]  # calling it raises TypeError
    async with serve(store) as h:
        resp = await h.get("/api/overview")
        assert resp.status == 500
        body = await resp.text()
        assert json.loads(body) == {"error": "internal error"}
        assert "Traceback" not in body and "TypeError" not in body


# --- static files ---------------------------------------------------------------------------


async def test_without_a_static_directory_the_root_is_a_placeholder(tmp_path: Path) -> None:
    async with serve(static_dir=tmp_path / "missing") as h:
        resp = await h.client.get("/")
        assert resp.status == 200
        assert resp.content_type == "text/html"
        assert "neonwatch" in await resp.text()
        assert (await h.client.get("/app.js")).status == 404


async def test_the_static_directory_is_served(tmp_path: Path) -> None:
    (tmp_path / "index.html").write_text("<!doctype html><title>dash</title>")
    (tmp_path / "app.js").write_text("console.log(1)")
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "x.js").write_text("no")
    async with serve(static_dir=tmp_path) as h:
        resp = await h.client.get("/")
        assert resp.status == 200 and "dash" in await resp.text()
        resp = await h.client.get("/app.js")
        assert resp.status == 200 and await resp.text() == "console.log(1)"
        assert resp.headers["X-Content-Type-Options"] == "nosniff"
        for path in ("/sub", "/sub/x.js", "/%2e%2e/app_test.py", "/missing.css"):
            assert (await h.client.get(path)).status == 404, path


async def test_a_static_directory_without_an_index_is_a_placeholder(tmp_path: Path) -> None:
    async with serve(static_dir=tmp_path) as h:
        assert "neonwatch" in await (await h.client.get("/")).text()


def test_the_default_static_directory_is_beside_the_module() -> None:
    assert Path(web_app.STATIC) == Path(web_app.__file__).parent / "static"


# --- the read API ---------------------------------------------------------------------------


async def test_overview() -> None:
    async with serve(populated()) as h:
        resp = await h.get("/api/overview")
        assert resp.status == 200
        body = await resp.json()
    assert body["now"] == NOW
    assert [i["id"] for i in body["open"]["critical"]] == ["i2"]
    assert [i["id"] for i in body["open"]["warn"]] == ["i1"]
    assert body["open"]["info"] == [] and body["open"]["watch"] == []
    assert list(body["open"]) == ["critical", "warn", "watch", "info"]
    assert body["counts"] == {"critical": 1, "warn": 1, "watch": 0, "info": 0}
    assert body["incidents"][0]["link"]["id"] == "l1"
    assert body["incidents"][0]["findings"][0]["at"] == NOW - 50
    assert body["incidents"][0]["findings"][0]["rule"] == "smart.critical"
    assert body["domains"]["services"]["open"]["warn"] == 1
    assert body["domains"]["services"]["attested"]["warn"] == 2
    hb = body["heartbeat"]
    assert hb["at"] == NOW - 20 and hb["age_s"] == 20
    assert hb["confined"] is False and hb["writable"] == ["/", "/etc"]
    assert body["probes"][:3] == [
        {"probe": "load", "at": NOW - 5, "age_s": 5, "error": "", "truncated": False,
         "tier": "fast", "expected_s": 60, "stale": False},
        {"probe": "units.failed", "at": NOW - 30, "age_s": 30, "error": "", "truncated": False,
         "tier": "medium", "expected_s": 300, "stale": False},
        {"probe": "smart.nvme0n1", "at": NOW - 7200, "age_s": 7200, "error": "",
         "truncated": False, "tier": "slow", "expected_s": 3600, "stale": False},
    ]


async def test_probes_that_never_reported_are_listed_as_unknown() -> None:
    catalog = [spec for spec in CATALOG if not spec.devices]
    async with serve() as h:
        rows = (await (await h.get("/api/overview")).json())["probes"]
    assert [r["probe"] for r in rows] == [spec.id for spec in catalog]
    assert "smart" not in [r["probe"] for r in rows]  # a template, with no device invented
    for row, spec in zip(rows, catalog, strict=True):
        assert row == {"probe": spec.id, "at": None, "age_s": None, "error": "",
                       "truncated": False, "tier": spec.tier.value,
                       "expected_s": getattr(Cadence(), spec.tier.value), "stale": True}


async def test_a_reported_probe_is_not_listed_twice() -> None:
    async with serve(populated()) as h:
        rows = (await (await h.get("/api/overview")).json())["probes"]
    names = [r["probe"] for r in rows]
    assert len(names) == len(set(names))
    # Reported rows first, newest first, as before; then the rest of the catalog, unknown.
    assert names[:3] == ["load", "units.failed", "smart.nvme0n1"]
    assert rows[0]["at"] == NOW - 5 and rows[0]["stale"] is False
    expected = [spec.id for spec in CATALOG
                if not spec.devices and spec.id not in ("load", "units.failed")]
    assert names[3:] == expected
    assert all(r["at"] is None and r["stale"] is True for r in rows[3:])


async def test_overview_staleness_comes_from_the_catalog_and_the_cadence() -> None:
    store = FakeStore()
    store.observations = [
        (NOW - 181, observation("memory", {})),         # fast: 181 > 3 x 60
        (NOW - 180, observation("load", {})),           # fast: exactly 3 x 60 is not stale
        (NOW - 31, observation("uptime", {})),          # fast, but the cadence says 10 s
        (NOW - 3 * 86400 - 1, observation("units.files", {})),  # daily
        (NOW - 40000, observation("smart.sda", {})),    # the smart template: slow
        (NOW - 1, observation("smart.bogus!", {})),     # not a device the template takes
        (NOW - 1, observation("not.in.catalog", {})),
    ]
    cadence = Cadence(fast=10)
    async with serve(store, cadence=cadence) as h:
        rows = {r["probe"]: r for r in (await (await h.get("/api/overview")).json())["probes"]}
    assert (rows["memory"]["tier"], rows["memory"]["expected_s"]) == ("fast", 10)
    assert rows["memory"]["stale"] is True
    assert rows["uptime"]["stale"] is True  # 31 > 3 x 10
    assert (rows["units.files"]["tier"], rows["units.files"]["stale"]) == ("daily", True)
    assert (rows["smart.sda"]["tier"], rows["smart.sda"]["expected_s"]) == ("slow", 3600)
    assert rows["smart.sda"]["stale"] is True
    # A probe with no known cadence is never shown as fresh.
    for unknown in ("smart.bogus!", "not.in.catalog"):
        assert (rows[unknown]["tier"], rows[unknown]["expected_s"]) == (None, None)
        assert rows[unknown]["stale"] is True
    fresh = FakeStore()
    fresh.observations = [(NOW - 180, observation("load", {}))]
    async with serve(fresh) as h:
        rows = (await (await h.get("/api/overview")).json())["probes"]
    assert next(r for r in rows if r["probe"] == "load")["stale"] is False


async def test_overview_on_an_empty_store() -> None:
    async with serve() as h:
        body = await (await h.get("/api/overview")).json()
    assert body["heartbeat"] is None and body["incidents"] == []
    assert body["counts"] == {"critical": 0, "warn": 0, "watch": 0, "info": 0}


async def test_issues_list_and_filter() -> None:
    async with serve(populated()) as h:
        body = await (await h.get("/api/issues")).json()
        assert [i["id"] for i in body["issues"]] == ["i2", "i1", "i3", "i4"]
        body = await (await h.get("/api/issues?state=acknowledged")).json()
        assert [i["id"] for i in body["issues"]] == ["i3"]
        assert body["issues"][0]["state"] == "acknowledged"
        resp = await h.get("/api/issues?state=bogus")
        assert resp.status == 400
        assert "state" in (await resp.json())["error"]


async def test_one_issue_with_its_evidence() -> None:
    store = populated()
    store.analysis_rows.append(analysis("an-2", subjects=("issue:i2",)))
    async with serve(store) as h:
        body = await (await h.get("/api/issues/i1")).json()
        assert (await h.get("/api/issues/zzz")).status == 404
    assert body["issue"]["id"] == "i1" and body["issue"]["severity"] == "warn"
    # Its attestations: the latest for its entity (or naming a reason); not bar's.
    assert [a["question"] for a in body["attestations"]] == ["q.health"]
    # The latest finding per rule for its entity, with its time.
    assert [(f["rule"], f["at"]) for f in body["findings"]] == [("units.failed", NOW - 100)]
    # Latest observations whose data names the entity.
    assert [o["probe"] for o in body["observations"]] == ["units.failed"]
    assert body["observations"][0]["at"] == NOW - 30
    assert [a["id"] for a in body["analyses"]] == ["an-1"]


async def test_an_issues_evidence_is_its_own_entitys_answers_only() -> None:
    """As the evaluator builds it. A shared reason is no link: `impact` and `action` are asked
    of every process, and a process's issue listed every other process's answers."""
    store = populated()
    store.issue_rows["i1"] = issue("i1", reasons=("units.failed", "q.other", "action"))
    store.attestation_rows += [
        (NOW - 70, attestation("action", entity="unit:bar.service", context="ctx-bar")),
        (NOW - 70, attestation("action", entity="domain:cpu", context="cpu", domain="cpu")),
        (NOW - 70, attestation("action", context="ctx-foo-elsewhere", domain="units"))]
    async with serve(store) as h:
        body = await (await h.get("/api/issues/i1")).json()
    assert [(a["question"], a["entity"]) for a in body["attestations"]] == [
        ("q.health", "unit:foo.service")]


async def test_observations_match_the_entity_only_in_identity_fields() -> None:
    store = FakeStore()
    store.issue_rows = {"p": issue("p", entity="process:2211", domain="processes"),
                        "c": issue("c", entity="container:web", domain="containers"),
                        "d": issue("d", entity="disk:/dev/nvme0n1", domain="storage")}
    store.observations = [
        # A journal line naming the pid in its message: the false positive this guards.
        (NOW - 10, observation("journal.errors", {"entries": [
            {"unit": "", "identifier": "openvpn", "message": "openvpn[2211]: web down",
             "priority": 3}], "by_unit": {"2211": 1}})),
        (NOW - 11, observation("load", {"last_pid": 2211})),
        (NOW - 12, observation("processes", {"top_cpu": [{"pid": 2211, "comm": "openvpn",
                                                          "args": "/opt/web"}]})),
        (NOW - 13, observation("containers", {"containers": [
            {"name": "web-1", "image": "web"}, {"name": "web", "image": "nginx"}]})),
        (NOW - 14, observation("net.dev", {"interfaces": [{"name": "webbr0"}]})),
        (NOW - 15, observation("disk.fill", {"filesystems": [
            {"source": "/dev/nvme0n1p6", "mount": "/"}]})),
        (NOW - 16, observation("smart.nvme0n1", {"device": "/dev/nvme0n1", "ok": True})),
        (NOW - 17, observation("gpu", {"gpus": [{"index": 0, "name": "RTX"}]})),
    ]
    async with serve(store) as h:
        seen = {i: [o["probe"] for o in (await (await h.get(f"/api/issues/{i}")).json())
                    ["observations"]] for i in ("p", "c", "d")}
    assert seen == {"p": ["processes"], "c": ["containers"], "d": ["smart.nvme0n1"]}


async def test_a_short_entity_name_pulls_no_unrelated_observation_into_the_context() -> None:
    # `unit:a` used to match every observation containing "a".
    store = FakeStore()
    store.issue_rows = {"i": issue("i", entity="unit:a")}
    store.observations = [
        (NOW - 5, observation("processes", {"top_cpu": [{"pid": 1, "comm": "bash",
                                                         "args": "a a a"}]})),
        (NOW - 6, observation("journal.warnings", {"entries": [
            {"unit": "a.service", "message": "a", "identifier": "a"}]})),
        (NOW - 7, observation("units.failed", {"units": [
            {"unit": "b.service", "description": "a"}, {"unit": "a", "description": "x"}]})),
    ]
    analyst = FakeAnalyst()
    async with serve(store, analyst=analyst) as h:
        detail = await (await h.get("/api/issues/i")).json()
        await h.post("/api/analyses/estimate", {"subjects": ["issue:i"]})
    assert [o["probe"] for o in detail["observations"]] == ["units.failed"]
    [request] = analyst.requests
    observed = [c["subject"] for c in request.context if c["kind"] == "observation"]
    assert observed == ["observation:units.failed"]


async def test_an_issue_with_an_unnamed_entity_matches_no_observation() -> None:
    store = populated()
    store.issue_rows["i1"] = issue("i1", entity="")
    async with serve(store) as h:
        body = await (await h.get("/api/issues/i1")).json()
    assert body["observations"] == []


async def test_incidents() -> None:
    async with serve(populated()) as h:
        body = await (await h.get("/api/incidents")).json()
    [incident] = body["incidents"]
    assert incident["at"] == NOW - 40 and incident["missing"] == []
    assert incident["issues"][0]["id"] == "i1"


async def test_one_domain() -> None:
    async with serve(populated()) as h:
        body = await (await h.get("/api/domains/services")).json()
        assert (await h.get("/api/domains/nowhere")).status == 404
    assert body["domain"] == "services"
    assert body["summary"]["open"]["warn"] == 1
    assert [i["id"] for i in body["issues"]] == ["i1", "i3", "i4"]
    assert sorted(a["question"] for a in body["attestations"]) == ["q.health", "q.other"]


async def test_series_defaults_and_validation() -> None:
    store = populated()
    store.points = (Point(999_960.0, 0.5), Point(1_000_020.0, 0.7))
    async with serve(store) as h:
        body = await (await h.get("/api/series?probe=load&field=load1")).json()
        assert body == {"probe": "load", "field": "load1", "since": NOW - 3600, "step": 60,
                        "points": [{"t": 999_960.0, "value": 0.5},
                                   {"t": 1_000_020.0, "value": 0.7}]}
        assert store.series_calls[-1] == ("load", "load1", NOW - 3600, 60)
        ok = await h.get(f"/api/series?probe=load&field=load1&since={NOW - 60}&step=5")
        assert ok.status == 200
        assert store.series_calls[-1] == ("load", "load1", NOW - 60, 5)
        for query in ("field=load1", "probe=load", "probe=load&field=load1&since=abc",
                      "probe=load&field=load1&since=nan", "probe=load&field=load1&since=-1",
                      "probe=load&field=load1&step=0", "probe=load&field=load1&step=1.5",
                      "probe=load&field=load1&step=100000",
                      f"probe=load&field=load1&since={NOW - 86400}&step=1",
                      "probe=" + "p" * 300 + "&field=x"):
            resp = await h.get(f"/api/series?{query}")
            assert resp.status == 400, query
            assert "error" in await resp.json()


def test_a_bad_board_layout_refuses_the_app(tmp_path) -> None:
    from neonwatch.web.board import BoardError
    path = tmp_path / "board.toml"
    path.write_text('name = "x"\n')
    config = Config(web=Web(board=str(path)))
    with pytest.raises(BoardError, match="missing"):
        make_app(FakeStore(), FakeLive(), TOKEN, config)


async def test_hardware_joins_the_latest_readings_with_an_hour_of_each_series() -> None:
    store = populated()
    store.observations = [
        (NOW - 30, observation("sensors", {"readings": [
            {"chip": "k10temp-pci-00c3", "label": "Tctl", "kind": "temp", "input": 78.4},
            {"chip": "nvme-pci-0100", "label": "Composite", "kind": "temp", "input": 66.0,
             "max": 81.85, "crit": 84.85},
            {"chip": "nvme-pci-0100", "label": "Sensor 2", "kind": "temp", "input": 90.9,
             "max": 65261.85}]})),
        (NOW - 600, observation("block.devices", {"entries": ["nvme0n1"], "links": {
            "nvme0n1": "../devices/pci0000:00/0000:00:01.1/0000:01:00.0/nvme/nvme0/nvme0n1"}})),
        (NOW - 10, Observation("gpu", {}, cpu_ms=1, error="nvidia-smi: no devices were found")),
    ]
    store.points = (Point(NOW - 120, 70.0), Point(NOW - 60, 71.0))
    async with serve(store) as h:
        body = await (await h.get("/api/hardware")).json()
    assert body["now"] == NOW and body["step"] == 60 and body["since"] == NOW - 3600
    (tctl,) = body["cpu"]["temps"]
    assert (tctl["label"], tctl["level"], body["cpu"]["stale"]) == ("Tctl", "warm", False)
    (disk,) = body["disks"]
    assert disk["attach"] == "cpu" and disk["temps"][1]["level"] == "over"
    assert disk["temps"][1]["borrowed"] is True
    assert body["gpus"] == []                     # the latest GPU read failed: no data, not zero
    assert body["board"]["layout"]["name"] == "Generic ATX"   # web.board's default
    assert body["board"]["placed"] == {"cpu": {"slot": "socket", "assumed": False},
                                       "disk:nvme0n1": {"slot": "M2_1", "assumed": False}}
    assert {(s["probe"], s["field"]) for s in body["history"]} == {
        ("sensors", "readings.0.input"), ("sensors", "readings.1.input"),
        ("sensors", "readings.2.input"), ("load", "load1")}
    assert body["history"][0]["points"] == [{"t": NOW - 120, "value": 70.0},
                                            {"t": NOW - 60, "value": 71.0}]
    assert ("cpu.stat", "idle", NOW - 3600, 60) in store.series_calls
    # Every tick counter reads the same fake points, so two of the eight are idle: 75% busy.
    assert body["cpu_util"] == [{"t": NOW - 60, "value": 75.0}]
    store.observations[0] = (NOW - 181, store.observations[0][1])   # three fast intervals
    async with serve(store) as h:
        body = await (await h.get("/api/hardware")).json()
    assert body["cpu"]["stale"] is True


async def test_health() -> None:
    async def judge_status() -> dict:
        return {"ok": True, "latency_ms": 12}

    async with serve(populated(), analyst=FakeAnalyst(), judge_health=judge_status) as h:
        body = await (await h.get("/api/health")).json()
    assert body == {"store": {"ok": True, "error": ""},
                    "live": {"streams": 0, "error": ""},
                    "analyst": {"configured": True, "provider": "", "model": ""},
                    "judge": {"ok": True, "latency_ms": 12}}


async def test_health_reports_failures_without_detail() -> None:
    async def judge_status() -> dict:
        raise ConnectionRefusedError("secret detail")

    store = populated()
    store.broken = True
    async with serve(store, judge_health=judge_status) as h:
        body = await (await h.get("/api/health")).json()
    assert body["store"] == {"ok": False, "error": "StoreError"}
    assert body["analyst"]["configured"] is False
    assert body["judge"] == {"ok": False, "error": "ConnectionRefusedError"}


async def test_health_without_judge() -> None:
    async with serve() as h:
        assert (await (await h.get("/api/health")).json())["judge"] is None


# --- the writes -----------------------------------------------------------------------------


async def test_ack() -> None:
    async with serve(populated()) as h:
        resp = await h.post("/api/issues/i1/ack")
        assert resp.status == 200
        assert (await resp.json())["issue"]["state"] == "acknowledged"
        assert h.store.acks == [("i1", NOW)]
        assert (await h.post("/api/issues/zzz/ack")).status == 404
        resp = await h.post("/api/issues/i4/ack")
        assert resp.status == 409
        assert await resp.json() == {"error": "issue i4 is resolved"}


async def test_snooze_is_bounded_to_seven_days() -> None:
    async with serve(populated()) as h:
        until = NOW + 3600
        resp = await h.post("/api/issues/i1/snooze", {"until": until})
        assert resp.status == 200
        assert (await resp.json())["issue"]["state"] == "snoozed"
        assert h.store.snoozes == [("i1", until)]
        edge = await h.post("/api/issues/i2/snooze", {"until": NOW + 7 * 86400})
        assert edge.status == 200
        for body in ({"until": NOW + 7 * 86400 + 1}, {"until": NOW}, {"until": NOW - 5},
                     {"until": "tomorrow"}, {"until": True}, {"until": float("inf")}, {},
                     {"until": NOW + 60, "extra": 1}, [NOW + 60], None):
            resp = await h.post("/api/issues/i3/snooze", body)
            assert resp.status == 400, body
            assert "error" in await resp.json()
        resp = await h.client.post("/api/issues/i3/snooze", data=b"{not json",
                                   headers=h.post_headers())
        assert resp.status == 400
        assert (await h.post("/api/issues/zzz/snooze", {"until": NOW + 60})).status == 404
        assert (await h.post("/api/issues/i4/snooze", {"until": NOW + 60})).status == 409
        assert h.store.snoozes == [("i1", until), ("i2", NOW + 7 * 86400)]


# --- analyses -------------------------------------------------------------------------------


async def test_estimate_builds_the_request_from_the_store() -> None:
    analyst = FakeAnalyst()
    async with serve(populated(), analyst=analyst) as h:
        resp = await h.post("/api/analyses/estimate",
                            {"subjects": ["issue:i1"], "question": "why?"})
        assert resp.status == 200
        body = await resp.json()
    assert body["estimate"] == {"chars": 1234, "approx_tokens": 309,
                                "backend": "openai-compatible", "model": "m",
                                "url_host": "127.0.0.1", "remote": False}
    [request] = analyst.requests
    assert request.subjects == ("issue:i1",) and request.question == "why?"
    assert [i["subject"] for i in request.items] == ["issue:i1"]
    assert request.items[0]["record"]["title"] == "i1 is bad"
    kinds = [(c["kind"], c["at"]) for c in request.context]
    # Same entity within the window, newest first: the latest observation naming the entity,
    # its attestation, and the finding history. bar's attestation is another entity.
    assert kinds == [("observation", NOW - 30), ("attestation", NOW - 90),
                     ("finding", NOW - 100), ("finding", NOW - 200)]
    assert body["items"] == 1 and body["context"] == len(request.context)


async def test_the_context_window_excludes_far_away_history() -> None:
    store = populated()
    store.finding_rows.append((NOW - 100_000, finding()))
    analyst = FakeAnalyst()
    async with serve(store, analyst=analyst) as h:
        await h.post("/api/analyses/estimate", {"subjects": ["issue:i1"]})
    [request] = analyst.requests
    assert request.question == ""
    assert all(c["at"] != NOW - 100_000 for c in request.context)


async def test_items_without_an_entity_get_no_context() -> None:
    store = populated()
    store.issue_rows["i1"] = issue("i1", entity="")
    analyst = FakeAnalyst()
    async with serve(store, analyst=analyst) as h:
        await h.post("/api/analyses/estimate", {"subjects": ["issue:i1"]})
    [request] = analyst.requests
    assert len(request.items) == 1 and request.context == ()


async def test_the_same_selection_builds_the_same_request() -> None:
    analyst = FakeAnalyst()
    async with serve(populated(), analyst=analyst) as h:
        for _ in range(2):
            await h.post("/api/analyses/estimate",
                         {"subjects": ["link:l1", "issue:i2"], "question": "q"})
    first, second = analyst.requests
    assert first == second


async def test_subjects_of_every_kind() -> None:
    analyst = FakeAnalyst()
    async with serve(populated(), analyst=analyst) as h:
        resp = await h.post("/api/analyses/estimate", {"subjects": [
            "finding:units.failed@unit:foo.service", "link:l1",
            f"window:{NOW - 95:.0f}-{NOW - 45:.0f}"]})
        assert resp.status == 200
    [request] = analyst.requests
    subjects = [i["subject"] for i in request.items]
    # The finding, the link and its resolved members, then the window's contents, each once.
    assert subjects[:4] == ["finding:units.failed@unit:foo.service", "link:l1", "issue:i1",
                            "finding:smart.critical@disk:/dev/nvme0"]
    assert "attestation:ctx-foo/q.health" in subjects
    assert "attestation:ctx-bar/q.other" in subjects
    assert len(subjects) == len(set(subjects))
    link_item = request.items[1]
    assert link_item["kind"] == "link" and link_item["record"]["members"][0] == "issue:i1"


QUESTION_REFUSED = "question must be a string of at most 2000 chars"


@pytest.mark.parametrize(("body", "status", "message"), [
    ({"subjects": ["issue:zzz"]}, 404, "no such subject: issue:zzz"),
    ({"subjects": ["finding:nope@x"]}, 404, "no such subject: finding:nope@x"),
    ({"subjects": ["link:nope"]}, 404, "no such subject: link:nope"),
    ({"subjects": ["event:x"]}, 400, "unknown subject: event:x"),
    ({"subjects": ["finding:rule-only"]}, 400, "unknown subject: finding:rule-only"),
    ({"subjects": ["issue:"]}, 400, "unknown subject: issue:"),
    ({"subjects": ["window:10-5"]}, 400, "unknown subject: window:10-5"),
    ({"subjects": ["window:0-100000"]}, 400, "unknown subject: window:0-100000"),
    ({"subjects": ["window:a-b"]}, 400, "unknown subject: window:a-b"),
    ({"subjects": []}, 400, "subjects must be a list of 1-20 strings"),
    ({"subjects": ["issue:i1"] * 21}, 400, "subjects must be a list of 1-20 strings"),
    ({"subjects": "issue:i1"}, 400, "subjects must be a list of 1-20 strings"),
    ({"subjects": [1]}, 400, "subjects must be a list of 1-20 strings"),
    ({"subjects": ["x" * 300]}, 400, "subjects must be a list of 1-20 strings"),
    ({"subjects": ["issue:i1"], "question": 5}, 400, QUESTION_REFUSED),
    ({"subjects": ["issue:i1"], "question": "q" * 2001}, 400, QUESTION_REFUSED),
    ({"subjects": ["issue:i1"], "tools": ["sh"]}, 400, "unexpected field(s): tools"),
    ({"question": "x"}, 400, "missing field(s): subjects"),
    (["issue:i1"], 400, "body must be a JSON object"),
])
async def test_a_bad_selection_is_refused(body: Any, status: int, message: str) -> None:
    analyst = FakeAnalyst()
    async with serve(populated(), analyst=analyst) as h:
        for path in ("/api/analyses/estimate", "/api/analyses"):
            resp = await h.post(path, body)
            assert resp.status == status, (path, body)
            assert await resp.json() == {"error": message}
    assert analyst.requests == []


async def test_a_window_is_bounded_in_items() -> None:
    store = FakeStore()
    store.finding_rows = [(NOW - n, finding(entity=f"unit:u{n}.service"))
                          for n in range(web_app.MAX_ITEMS + 50)]
    analyst = FakeAnalyst()
    async with serve(store, analyst=analyst) as h:
        await h.post("/api/analyses/estimate", {"subjects": [f"window:{NOW - 1000}-{NOW}"]})
    [request] = analyst.requests
    assert len(request.items) == web_app.MAX_ITEMS
    assert len(request.context) <= web_app.MAX_CONTEXT


async def test_without_an_analyst_the_analysis_routes_refuse() -> None:
    async with serve(populated()) as h:
        for path in ("/api/analyses/estimate", "/api/analyses"):
            resp = await h.post(path, {"subjects": ["issue:i1"]})
            assert resp.status == 503
            assert await resp.json() == {"error": "no analysis backend is configured"}


# --- scheduled jobs and services ------------------------------------------------------------

JOB_ID = "cron:0123456789ab"
CRON_JOB = {"id": JOB_ID, "source": "cron", "file": "/etc/cron.d/backup", "user": "root",
            "schedule": "*/5 * * * *", "command": "/usr/local/bin/backup --quiet", "unit": None,
            "static": {"source": "cron", "file": "/etc/cron.d/backup", "user": "root",
                       "schedule": "*/5 * * * *", "command": "/usr/local/bin/backup --quiet",
                       "unit": None},
            "last": None, "next": None, "result": None}
TIMER_JOB = {"id": "timer:apt-daily.timer", "source": "timer",
             "file": "/usr/lib/systemd/system/apt-daily.timer", "user": "root",
             "schedule": "*-*-* 6,18:00", "command": "/usr/lib/apt/apt.systemd.daily update",
             "unit": "apt-daily.service", "static": {}, "last": NOW - 600, "next": NOW + 3600,
             "result": "success"}
SERVICE = {"name": "foo.service", "description": "Foo", "user": "", "exec": ["/usr/bin/foo -d"],
           "active": "failed", "sub": "failed", "result": "exit-code", "restarts": 3,
           "main_status": 1, "started": NOW - 100, "exited": NOW - 90, "enabled": "enabled",
           "file": "/etc/systemd/system/foo.service"}


class FakeJobs:
    """Stands in for `neonwatch.jobs`: literal records, and the `latest` mapping it was given."""

    PROBES = frozenset({"cron.d", "units.detail", "units.timers"})

    def __init__(self) -> None:
        self.given: list[dict[str, Any]] = []

    def scheduled(self, latest: Any) -> tuple[list[dict[str, Any]], int]:
        self.given.append(dict(latest))
        return ([dict(CRON_JOB), dict(TIMER_JOB)], 2) if latest else ([], 0)

    def services(self, latest: Any) -> list[dict[str, Any]]:
        self.given.append(dict(latest))
        return [dict(SERVICE)] if latest else []

    service_key = staticmethod(real_jobs.service_key)


@pytest.fixture
def fake_jobs(monkeypatch: pytest.MonkeyPatch) -> FakeJobs:
    fake = FakeJobs()
    monkeypatch.setattr(web_app, "jobs", fake)
    return fake


def job_attestation(question: str, severity: Severity, stable: bool | None,
                    entity: str = f"job:{JOB_ID}", context: str = "ctx-job") -> Attestation:
    return dataclasses.replace(attestation(question, entity=entity, context=context,
                                           domain="security"),
                               context_kind="job", severity=severity, stable=stable,
                               next_step=f"cat {question}")


def scheduled_store() -> FakeStore:
    store = populated()
    store.observations += [
        (NOW - 300, observation("cron.d", {"files": ["backup"]})),
        (NOW - 120, observation("units.detail", {"units": []})),
        # Failed: its data says nothing, so it is not handed to the join; it is still listed.
        (NOW - 60, Observation(probe="units.timers", data={}, cpu_ms=1, error="timed out")),
    ]
    store.attestation_rows += [
        (NOW - 7200, job_attestation("job.fetch_run", Severity.INFO, True)),
        (NOW - 7100, job_attestation("job.tmp_root", Severity.WARN, False)),
        (NOW - 7000, job_attestation("job.tmp_root", Severity.INFO, True,
                                     entity="job:cron:ffffffffffff", context="ctx-other")),
    ]
    return store


async def test_scheduled_lists_every_job_with_its_latest_attestations(fake_jobs: FakeJobs) -> None:
    async with serve(scheduled_store()) as h:
        resp = await h.get("/api/scheduled")
        assert resp.status == 200
        body = await resp.json()
    # The newest observation the records were built from; `load` (NOW - 5) is not one of them.
    assert body["as_of"] == NOW - 120
    assert body["skipped"] == 2
    assert body["probes"] == {"cron.d": {"at": NOW - 300, "error": ""},
                              "units.detail": {"at": NOW - 120, "error": ""},
                              "units.timers": {"at": NOW - 60, "error": "timed out"}}
    assert fake_jobs.given == [{"cron.d": {"files": ["backup"]}, "units.detail": {"units": []}}]
    cron, timer = body["jobs"]
    assert {k: cron[k] for k in CRON_JOB} == CRON_JOB
    assert cron["worst"] == "warn" and cron["unstable"] is True
    assert cron["attestations"] == [
        {"at": NOW - 7100, "question": "job.tmp_root", "severity": "warn", "stable": False,
         "confidence": 0.8, "cause": "it failed", "next_step": "cat job.tmp_root"},
        {"at": NOW - 7200, "question": "job.fetch_run", "severity": "info", "stable": True,
         "confidence": 0.8, "cause": "it failed", "next_step": "cat job.fetch_run"}]
    assert timer["attestations"] == [] and timer["worst"] is None and timer["unstable"] is False


async def test_unread_ignored_and_overflow_markers_are_passed_through(
        fake_jobs: FakeJobs, monkeypatch: pytest.MonkeyPatch) -> None:
    unread = {**CRON_JOB, "id": "cron:/etc/cron.daily/link", "source": "cron-periodic",
              "command": "", "unread": True, "skipped_by_run_parts": True, "overflow": 3}
    monkeypatch.setattr(fake_jobs, "scheduled", lambda latest: ([dict(unread)], 0))
    async with serve(scheduled_store()) as h:
        [job] = (await (await h.get("/api/scheduled")).json())["jobs"]
    assert {k: job[k] for k in unread} == unread


async def test_services_carry_their_open_issues_and_attestations(fake_jobs: FakeJobs) -> None:
    async with serve(scheduled_store()) as h:
        body = await (await h.get("/api/services")).json()
    assert body["as_of"] == NOW - 120
    [service] = body["services"]
    assert {k: service[k] for k in SERVICE} == SERVICE
    # i1 is open on unit:foo.service; i3 is acknowledged and i4 resolved on the same unit.
    assert service["issues"] == [{"id": "i1", "severity": "warn", "title": "i1 is bad"}]
    assert [a["question"] for a in service["attestations"]] == ["q.health"]
    assert service["worst"] == "warn" and service["unstable"] is False


async def test_with_nothing_observed_the_lists_are_empty_and_unknown(fake_jobs: FakeJobs) -> None:
    async with serve(populated()) as h:
        scheduled = await (await h.get("/api/scheduled")).json()
        services = await (await h.get("/api/services")).json()
    never = {probe: {"at": None, "error": ""} for probe in FakeJobs.PROBES}
    assert scheduled == {"as_of": None, "probes": never, "jobs": [], "skipped": 0}
    assert services == {"as_of": None, "probes": never, "services": []}


async def test_a_job_is_analysed_from_the_server_record_with_its_attestations(
        fake_jobs: FakeJobs) -> None:
    analyst = FakeAnalyst()
    async with serve(scheduled_store(), analyst=analyst) as h:
        resp = await h.post("/api/analyses/estimate", {"subjects": [f"job:{JOB_ID}"]})
        assert resp.status == 200
    [request] = analyst.requests
    assert request.items == ({"kind": "job", "subject": f"job:{JOB_ID}", "at": NOW - 120,
                              "record": CRON_JOB},)
    # Its attestations are hours older than the context window, and come anyway: they are asked
    # only when the job is new or changes. Another job's do not.
    assert [(c["kind"], c["subject"], c["at"]) for c in request.context] == [
        ("attestation", "attestation:ctx-job/job.tmp_root", NOW - 7100),
        ("attestation", "attestation:ctx-job/job.fetch_run", NOW - 7200)]


async def test_a_service_is_analysed_with_only_its_own_records(fake_jobs: FakeJobs) -> None:
    analyst = FakeAnalyst()
    async with serve(scheduled_store(), analyst=analyst) as h:
        resp = await h.post("/api/analyses/estimate", {"subjects": ["unit:foo.service"]})
        assert resp.status == 200
        assert (await resp.json())["items"] == 1
    [request] = analyst.requests
    assert request.items == ({"kind": "service", "subject": "unit:foo.service",
                              "at": NOW - 120, "record": SERVICE},)
    # Its attestation, its latest finding, and the issues on it; no observation.
    assert [(c["kind"], c["subject"]) for c in request.context] == [
        ("issue", "issue:i1"), ("issue", "issue:i3"), ("issue", "issue:i4"),
        ("attestation", "attestation:ctx-foo/q.health"),
        ("finding", "finding:units.failed@unit:foo.service")]


async def test_a_unit_analysis_sends_no_other_unit(fake_jobs: FakeJobs) -> None:
    """The one `units.detail` observation names every service; analysing one must not
    ship it. Before, a timer's `unit` field naming the service pulled it all in."""
    others = [{"name": f"svc{n}.service", "exec": [f"/usr/bin/other-{n} --opt {'x' * 200}"]}
              for n in range(200)]
    store = scheduled_store()
    store.observations.append((NOW - 100, observation("units.detail", {
        "units": [{"name": "apt-daily.timer", "unit": "foo.service"}, *others]})))
    sent: list[str] = []

    async def post(url: str, headers: Any, body: str) -> dict[str, Any]:
        sent.append(body)
        return {}

    local = AnalystConfig(provider="openai-compatible", model="m",
                          base_url="http://127.0.0.1:1/v1")
    async with serve(store, analyst=Analyst(post, Config(analyst=local)),
                     analyst_config=local) as h:
        estimate = await (await h.post("/api/analyses/estimate",
                                       {"subjects": ["unit:foo.service"]})).json()
        assert (await h.post("/api/analyses", {"subjects": ["unit:foo.service"]})).status == 202
        await wait_saved(h.store, 2)
    [body] = sent
    assert "foo.service" in body
    assert "svc0.service" not in body and "other-199" not in body and "units.detail" not in body
    # The observation alone is over 40 000 chars; the whole request is a small fraction of it.
    assert len(json.dumps(others)) > 40_000
    assert estimate["estimate"]["chars"] < 8_000


async def test_a_timer_job_brings_its_service_record(fake_jobs: FakeJobs,
                                                     monkeypatch: pytest.MonkeyPatch) -> None:
    service = {**SERVICE, "name": "apt-daily.service", "active": "inactive"}
    monkeypatch.setattr(fake_jobs, "services", lambda latest: [dict(SERVICE), dict(service)])
    analyst = FakeAnalyst()
    async with serve(scheduled_store(), analyst=analyst) as h:
        await h.post("/api/analyses/estimate", {"subjects": ["job:timer:apt-daily.timer"]})
    [request] = analyst.requests
    assert [c["subject"] for c in request.context] == ["unit:apt-daily.service"]
    assert request.context[0]["record"] == service


async def test_a_job_analysis_runs_and_is_listed_under_its_subject(fake_jobs: FakeJobs) -> None:
    analyst = FakeAnalyst()
    analyst.release.set()
    async with serve(scheduled_store(), analyst=analyst) as h:
        resp = await h.post("/api/analyses", {"subjects": [f"job:{JOB_ID}"], "question": "ok?"})
        assert resp.status == 202
        job = (await resp.json())["id"]
        await wait_saved(h.store, 2)
    assert h.store.analyses(f"job:{JOB_ID}")[0].id == job


async def test_a_job_is_not_sent_off_the_machine_when_reach_is_local(
        fake_jobs: FakeJobs) -> None:
    sent: list[str] = []

    async def post(url: str, headers: Any, body: str) -> dict[str, Any]:
        sent.append(url)
        return {}

    remote = AnalystConfig(provider="openai-compatible", model="m",
                           base_url="https://llm.example/v1")
    config = Config(analyst=remote)
    async with serve(scheduled_store(), analyst=Analyst(post, config),
                     analyst_config=remote) as h:
        estimate = await (await h.post("/api/analyses/estimate",
                                       {"subjects": [f"job:{JOB_ID}"]})).json()
        assert estimate["estimate"]["remote"] is True
        assert (await h.post("/api/analyses", {"subjects": [f"job:{JOB_ID}"]})).status == 202
        await wait_saved(h.store, 2)
    [saved] = h.store.analyses(f"job:{JOB_ID}")
    assert "not loopback" in saved.error and sent == []


@pytest.mark.parametrize(("body", "status", "message"), [
    ({"subjects": ["job:cron:nope"]}, 404, "no such subject: job:cron:nope"),
    ({"subjects": ["unit:nope.service"]}, 404, "no such subject: unit:nope.service"),
    ({"subjects": ["job:"]}, 400, "unknown subject: job:"),
    ({"subjects": ["unit:"]}, 400, "unknown subject: unit:"),
    ({"subjects": [f"job:{JOB_ID}"], "record": CRON_JOB}, 400, "unexpected field(s): record"),
])
async def test_an_unknown_job_or_service_is_refused(fake_jobs: FakeJobs, body: Any, status: int,
                                                    message: str) -> None:
    analyst = FakeAnalyst()
    async with serve(scheduled_store(), analyst=analyst) as h:
        for path in ("/api/analyses/estimate", "/api/analyses"):
            resp = await h.post(path, body)
            assert resp.status == status, (path, body)
            assert await resp.json() == {"error": message}
    assert analyst.requests == []


async def read_event(resp, within: float = 2.0) -> str:
    return (await asyncio.wait_for(resp.content.readuntil(b"\n\n"), within)).decode()


def parse(frame: str) -> dict[str, str]:
    fields = {}
    for line in frame.strip("\n").split("\n"):
        name, _, value = line.partition(": ")
        fields[name] = value
    return fields


async def test_the_analysis_flow_end_to_end() -> None:
    analyst = FakeAnalyst()
    async with serve(populated(), analyst=analyst) as h:
        stream = await h.get("/api/stream")
        await asyncio.wait_for(h.live.subscribed.wait(), 2)
        resp = await h.post("/api/analyses", {"subjects": ["issue:i1"], "question": "why?"})
        assert resp.status == 202
        started = await resp.json()
        job = started["id"]
        assert started == {"id": job, "status": "running"}
        running = await (await h.get(f"/api/analyses/{job}")).json()
        assert running["status"] == "running" and running["subjects"] == ["issue:i1"]
        assert running["requested_at"] == NOW

        analyst.release.set()
        frame = parse(await read_event(stream))
        assert frame["event"] == "analysis"
        data = json.loads(frame["data"])
        assert data["id"] == job and data["subject"] == f"analysis.{job}"
        assert data["text"] == "it is foo" and data["at"] == NOW + 1

        done = await (await h.get(f"/api/analyses/{job}")).json()
        assert done["status"] == "done" and done["text"] == "it is foo"
        assert done["suggested_checks"] == ["systemctl status foo"]
        # Saved under the id the dashboard was given, and listed on the issue.
        assert h.store.analyses("issue:i1")[0].id == job
        detail = await (await h.get("/api/issues/i1")).json()
        assert detail["analyses"][0]["id"] == job
        stream.close()


async def test_a_failed_analysis_is_saved_and_reported() -> None:
    analyst = FakeAnalyst(error="backend refused")
    analyst.release.set()
    async with serve(populated(), analyst=analyst) as h:
        job = (await (await h.post("/api/analyses", {"subjects": ["issue:i1"]})).json())["id"]
        for _ in range(100):
            body = await (await h.get(f"/api/analyses/{job}")).json()
            if body["status"] != "running":
                break
            await asyncio.sleep(0.01)
    assert body["status"] == "failed" and body["error"] == "backend refused"


async def test_an_analyst_that_raises_is_recorded_as_failed() -> None:
    analyst = FakeAnalyst(raises=RuntimeError("boom with detail"))
    analyst.release.set()
    async with serve(populated(), analyst=analyst) as h:
        job = (await (await h.post("/api/analyses", {"subjects": ["issue:i1"]})).json())["id"]
        for _ in range(100):
            body = await (await h.get(f"/api/analyses/{job}")).json()
            if body["status"] != "running":
                break
            await asyncio.sleep(0.01)
    # Saved like any other result, so it outlives the in-memory job entry.
    assert body["id"] == job and body["status"] == "failed"
    assert body["error"] == "analysis failed: RuntimeError"
    assert "boom with detail" not in json.dumps(body)
    assert body["subjects"] == ["issue:i1"] and body["requested_at"] == NOW
    assert h.store.analyses("issue:i1")[0].error == "analysis failed: RuntimeError"


async def wait_saved(store: FakeStore, count: int) -> None:
    for _ in range(200):
        if len(store.analysis_rows) >= count:
            return
        await asyncio.sleep(0.01)
    raise AssertionError(f"only {len(store.analysis_rows)} analyses saved")


async def test_concurrent_analyses_are_capped() -> None:
    assert web_app.MAX_RUNNING == 2
    analyst = FakeAnalyst()  # held until released
    async with serve(populated(), analyst=analyst) as h:
        selection = {"subjects": ["issue:i1"]}
        assert (await h.post("/api/analyses", selection)).status == 202
        assert (await h.post("/api/analyses", selection)).status == 202
        over = await h.post("/api/analyses", selection)
        assert over.status == 429
        assert await over.json() == {
            "error": "2 analyses are already running; wait for one to finish"}
        assert len(analyst.requests) == 2  # the refused one never reached the backend
        # An estimate sends nothing, so it is not capped.
        assert (await h.post("/api/analyses/estimate", selection)).status == 200
        analyst.release.set()
        await wait_saved(h.store, 3)  # an-1 plus the two
        # Finished jobs left `running`: the cap is free again.
        assert (await h.post("/api/analyses", selection)).status == 202


async def test_failed_jobs_free_their_slot() -> None:
    analyst = FakeAnalyst(raises=RuntimeError("boom"))
    analyst.release.set()
    async with serve(populated(), analyst=analyst) as h:
        for round_ in range(3):
            for _ in range(2):
                assert (await h.post("/api/analyses", {"subjects": ["issue:i1"]})).status == 202
            await wait_saved(h.store, 1 + 2 * (round_ + 1))


async def test_an_analysis_the_store_cannot_save_is_streamed_as_failed() -> None:
    store = populated()

    def refuse(_record: Analysis) -> None:
        raise StoreError("disk full")

    store.save_analysis = refuse  # type: ignore[method-assign]
    analyst = FakeAnalyst()
    analyst.release.set()
    async with serve(store, analyst=analyst) as h:
        stream = await h.get("/api/stream")
        await asyncio.wait_for(h.live.subscribed.wait(), 2)
        job = (await (await h.post("/api/analyses", {"subjects": ["issue:i1"]})).json())["id"]
        data = json.loads(parse(await read_event(stream))["data"])
        assert data["id"] == job
        assert data["error"] == "the analysis could not be saved: StoreError"
        # Nothing holds it in memory, and the slot is free.
        assert (await h.get(f"/api/analyses/{job}")).status == 404
        for _ in range(2):
            assert (await h.post("/api/analyses", {"subjects": ["issue:i1"]})).status == 202
        stream.close()


async def test_an_analysis_that_times_out_is_saved_and_streamed_as_failed() -> None:
    analyst = FakeAnalyst()  # never released: the backend never answers
    config = AnalystConfig(provider="openai-compatible", model="slow-model", timeout_s=0.05)
    async with serve(populated(), analyst=analyst, analyst_config=config) as h:
        stream = await h.get("/api/stream")
        await asyncio.wait_for(h.live.subscribed.wait(), 2)
        started = await h.post("/api/analyses", {"subjects": ["issue:i1"], "question": "why?"})
        job = (await started.json())["id"]
        frame = parse(await read_event(stream))
        assert frame["event"] == "analysis"
        data = json.loads(frame["data"])
        assert data["id"] == job
        assert data["error"] == "the analysis backend did not answer within 0.05 s"
        body = await (await h.get(f"/api/analyses/{job}")).json()
        assert body["status"] == "failed" and body["error"] == data["error"]
        assert body["backend"] == "openai-compatible" and body["model"] == "slow-model"
        assert body["subjects"] == ["issue:i1"] and body["question"] == "why?"
        assert body["text"] == "" and body["suggested_checks"] == []
        assert body["requested_at"] == NOW
        saved = h.store.analyses("issue:i1")[0]
        assert saved.id == job and saved.error == data["error"]
        stream.close()


async def test_an_existing_analysis_and_an_unknown_one() -> None:
    async with serve(populated()) as h:
        body = await (await h.get("/api/analyses/an-1")).json()
        assert body["status"] == "done" and body["text"] == "probably foo"
        assert (await h.get("/api/analyses/zzz")).status == 404


async def test_a_running_analysis_is_cancelled_on_shutdown() -> None:
    analyst = FakeAnalyst()
    async with serve(populated(), analyst=analyst) as h:
        assert (await h.post("/api/analyses", {"subjects": ["issue:i1"]})).status == 202
        await asyncio.sleep(0)
    # Leaving the context closed the server with the task still waiting; nothing was saved.
    assert [a.id for a in h.store.analysis_rows] == ["an-1"]


# --- the event stream -----------------------------------------------------------------------


def live_event(kind: Kind, subject: str, body: dict, at: float = NOW) -> Event:
    return Event(kind, at, "evaluator", subject, body)


async def test_sse_framing() -> None:
    async with serve() as h:
        resp = await h.get("/api/stream")
        assert resp.status == 200
        assert resp.headers["Content-Type"].startswith("text/event-stream")
        assert resp.headers["Cache-Control"] == "no-store"
        await h.live.push(live_event(Kind.ISSUE, "issue.i1", to_body(issue("i1"))))
        await h.live.push(live_event(Kind.OBSERVATION, "obs.load",
                                     to_body(observation("load", {"load1": 1})), at=NOW + 1))
        first, second = parse(await read_event(resp)), parse(await read_event(resp))
        assert first["id"] == f"1:issue:{NOW!r}" and first["event"] == "issue"
        data = json.loads(first["data"])
        assert data["id"] == "i1" and data["at"] == NOW and data["subject"] == "issue.i1"
        assert second["id"] == f"2:observation:{NOW + 1!r}"
        assert json.loads(second["data"])["data"] == {"load1": 1}
        resp.close()


async def test_a_live_issue_goes_out_as_the_store_holds_it() -> None:
    """The evaluator knows nothing of holds: its view of an acknowledged issue says open, and
    the page moved the issue back to open until it next refetched."""
    store = populated()
    store.ack("i1", NOW, by="agent:claude")
    async with serve(store) as h:
        resp = await h.get("/api/stream")
        await h.live.push(live_event(Kind.ISSUE, "issue.i1", to_body(issue("i1"))))
        await h.live.push(live_event(Kind.ISSUE, "issue.i9", to_body(issue("i9"))))
        held, unknown = [json.loads(parse(await read_event(resp))["data"]) for _ in range(2)]
        resp.close()
        replay = await h.get("/api/stream",
                             headers={**AUTH, "Last-Event-ID": f"1:issue:{NOW - 95!r}"})
        replayed = [json.loads(parse(await read_event(replay))["data"]) for _ in range(6)]
        replay.close()
    assert (held["state"], held["held_by"]) == ("acknowledged", "agent:claude")
    assert unknown["state"] == "open" and "held_by" not in unknown  # not stored: as it came
    assert {f["id"]: f["held_by"] for f in replayed if f["subject"].startswith("issue.")} == {
        "i1": "agent:claude", "i2": None, "i3": "operator", "i4": None}


async def test_a_live_issue_the_store_cannot_read_goes_out_as_it_came() -> None:
    store = populated()

    def refuse(_issue_id: str) -> None:
        raise StoreError("database is locked")

    store.issue = refuse  # type: ignore[method-assign]
    async with serve(store) as h:
        resp = await h.get("/api/stream")
        await h.live.push(live_event(Kind.ISSUE, "issue.i3", to_body(issue("i3"))))
        frame = json.loads(parse(await read_event(resp))["data"])
        resp.close()
    assert frame["state"] == "open"  # the stream carries on rather than ending


async def test_an_event_that_is_not_strict_json_is_dropped() -> None:
    async with serve() as h:
        resp = await h.get("/api/stream")
        await h.live.push(live_event(Kind.OBSERVATION, "obs.load",
                                     {"probe": "load", "data": {"x": float("nan")}}))
        await h.live.push(live_event(Kind.ISSUE, "issue.i1", to_body(issue("i1"))))
        frame = parse(await read_event(resp))
        assert frame["id"] == f"1:issue:{NOW!r}"
        resp.close()


async def test_sse_ids_are_per_connection() -> None:
    async with serve() as h:
        a = await h.get("/api/stream")
        await asyncio.wait_for(h.live.subscribed.wait(), 2)
        h.live.subscribed.clear()
        b = await h.get("/api/stream")
        await h.live.push(live_event(Kind.HEARTBEAT, "hb.agent", to_body(heartbeat())))
        assert parse(await read_event(a))["id"].startswith("1:heartbeat:")
        assert parse(await read_event(b))["id"].startswith("1:heartbeat:")
        await h.live.push(live_event(Kind.HEARTBEAT, "hb.agent", to_body(heartbeat())))
        assert parse(await read_event(a))["id"].startswith("2:")
        health = await (await h.get("/api/health")).json()
        assert health["live"]["streams"] == 2
        a.close()
        b.close()


async def test_head_of_the_stream_returns_headers_and_closes() -> None:
    async with serve() as h:
        resp = await asyncio.wait_for(h.client.head("/api/stream", headers=AUTH), 2)
        assert resp.status == 200
        assert resp.headers["Content-Type"].startswith("text/event-stream")
        assert resp.headers["Cache-Control"] == "no-store"
        assert h.live.queues == []  # nothing subscribed
        health = await (await h.get("/api/health")).json()
        assert health["live"]["streams"] == 0


async def test_sse_heartbeat_comments() -> None:
    async with serve(keepalive_s=0.05) as h:
        resp = await h.get("/api/stream")
        assert await read_event(resp) == ": keepalive\n\n"
        resp.close()


def test_the_keepalive_default_is_fifteen_seconds() -> None:
    assert web_app.KEEPALIVE_S == 15.0


async def test_last_event_id_replays_what_the_store_holds() -> None:
    async with serve(populated()) as h:
        since = NOW - 95
        resp = await h.get("/api/stream",
                           headers={**AUTH, "Last-Event-ID": f"7:issue:{since!r}"})
        frames = [parse(await read_event(resp)) for _ in range(5)]
        kinds = [(f["event"], json.loads(f["data"])["at"]) for f in frames]
        # Oldest first: attestations at -90 and -80, the -60 issues (i1, i2, i3, i4 all at
        # -60, sorted by id) ... findings at -50. Ids restart at 1 on the new connection.
        assert kinds[0] == ("attestation", NOW - 90)
        assert frames[0]["id"] == f"1:attestation:{NOW - 90!r}"
        assert [json.loads(f["data"])["subject"] for f in frames[:2]] == [
            "attest.ctx-foo", "attest.ctx-bar"]
        more = [parse(await read_event(resp)) for _ in range(2)]
        subjects = [json.loads(f["data"])["subject"] for f in frames + more]
        assert subjects[2:6] == ["issue.i1", "issue.i2", "issue.i3", "issue.i4"]
        assert subjects[6] == "finding.smart.critical"
        # Then live events continue on the same connection.
        await h.live.push(live_event(Kind.ISSUE, "issue.i9", to_body(issue("i9"))))
        assert parse(await read_event(resp))["id"] == f"8:issue:{NOW!r}"
        resp.close()


@pytest.mark.parametrize("last", ["garbage", "1:issue", "x:issue:5.0", "1:issue:nan",
                                  "1:issue:-5", f"1:issue:{NOW + 10}", "1:issue:10.0"])
async def test_an_unusable_last_event_id_sends_reset(last: str) -> None:
    async with serve(populated(), retention=Retention(max_age_s=86400)) as h:
        resp = await h.get("/api/stream", headers={**AUTH, "Last-Event-ID": last})
        frame = parse(await read_event(resp))
        assert frame["event"] == "reset"
        assert frame["id"] == f"1:reset:{NOW!r}"
        assert json.loads(frame["data"])["subject"] == "reset"
        resp.close()


async def test_too_much_to_replay_sends_reset() -> None:
    store = FakeStore()
    store.finding_rows = [(NOW - 10, finding(entity=f"unit:{n}"))
                          for n in range(web_app.MAX_REPLAY + 1)]
    async with serve(store) as h:
        resp = await h.get("/api/stream", headers={**AUTH, "Last-Event-ID": f"1:x:{NOW - 20}"})
        frame = parse(await read_event(resp))
        assert frame["event"] == "reset"
        assert json.loads(frame["data"])["reason"] == "too much to replay"
        resp.close()


async def test_a_slow_client_is_told_to_reset() -> None:
    async with serve(queue_size=2) as h:
        resp = await h.get("/api/stream")
        await asyncio.wait_for(h.live.subscribed.wait(), 2)
        for n in range(5):
            h.live.queues[0].put_nowait(
                live_event(Kind.HEARTBEAT, "hb.agent", to_body(heartbeat()), at=NOW + n))
        await asyncio.sleep(0.05)
        events = []
        while "reset" not in events and len(events) < 3:
            events.append(parse(await read_event(resp))["event"])
        assert "reset" in events
        resp.close()


async def test_the_stream_ends_when_the_live_source_does() -> None:
    async with serve() as h:
        resp = await h.get("/api/stream")
        await h.live.push(None)
        assert await asyncio.wait_for(resp.content.read(), 2) == b""


async def test_a_failing_live_source_ends_the_stream_and_shows_in_health() -> None:
    live = FakeLive()
    live.error = ConnectionError("nats down: secret detail")
    async with serve(live=live) as h:
        resp = await h.get("/api/stream")
        assert await asyncio.wait_for(resp.content.read(), 2) == b""
        health = await (await h.get("/api/health")).json()
        assert health["live"] == {"streams": 0, "error": "ConnectionError"}


async def test_open_streams_end_on_shutdown() -> None:
    async with serve() as h:
        resp = await h.get("/api/stream")
        await asyncio.wait_for(h.live.subscribed.wait(), 2)
        closing = asyncio.create_task(h.client.server.close())
        assert await asyncio.wait_for(resp.content.read(), 5) == b""
        await asyncio.wait_for(closing, 5)


async def test_a_disconnected_client_is_forgotten() -> None:
    async with serve() as h:
        resp = await h.get("/api/stream")
        await asyncio.wait_for(h.live.subscribed.wait(), 2)
        resp.close()
        for _ in range(100):
            await h.live.push(live_event(Kind.HEARTBEAT, "hb.agent", to_body(heartbeat())))
            health = await (await h.get("/api/health")).json()
            if health["live"]["streams"] == 0:
                break
            await asyncio.sleep(0.02)
        assert health["live"]["streams"] == 0


# --- with the real store --------------------------------------------------------------------


async def test_against_the_real_store(tmp_path: Path) -> None:
    store = Store(tmp_path / "store.sqlite3", Config())
    store.apply(Event(Kind.ISSUE, NOW - 60, "evaluator", "issue.i1", to_body(issue("i1"))))
    store.apply(Event(Kind.FINDING, NOW - 70, "evaluator", "finding.units.failed",
                      to_body(finding())))
    store.apply(Event(Kind.ATTESTATION, NOW - 65, "evaluator", "attest.ctx-foo",
                      to_body(attestation())))
    store.apply(Event(Kind.OBSERVATION, NOW - 30, "agent", "obs.units.failed",
                      to_body(observation())))
    store.apply(Event(Kind.HEARTBEAT, NOW - 5, "agent", "hb.agent", to_body(heartbeat(True))))
    analyst = FakeAnalyst()
    analyst.release.set()
    try:
        async with serve(store, analyst=analyst) as h:
            overview = await (await h.get("/api/overview")).json()
            assert overview["heartbeat"]["confined"] is True
            assert overview["counts"]["warn"] == 1
            detail = await (await h.get("/api/issues/i1")).json()
            assert [f["rule"] for f in detail["findings"]] == ["units.failed"]
            assert [o["probe"] for o in detail["observations"]] == ["units.failed"]
            assert (await (await h.get("/api/domains/services")).json())["issues"]
            assert (await h.get("/api/series?probe=units.failed&field=x")).status == 200
            assert (await h.post("/api/issues/i1/ack")).status == 200
            assert store.issue("i1").state is IssueState.ACKNOWLEDGED
            job = (await (await h.post("/api/analyses",
                                       {"subjects": ["issue:i1"]})).json())["id"]
            for _ in range(100):
                if store.analyses("issue:i1"):
                    break
                await asyncio.sleep(0.01)
            assert store.analyses("issue:i1")[0].id == job
    finally:
        store.close()


# --- binding ------------------------------------------------------------------------------


async def test_start_binds_serves_over_a_real_socket_and_stop_releases_the_port() -> None:
    port = free_port()
    app = make_app(populated(), FakeLive(), TOKEN, Config(web=Web(port=port)))
    stop = await start(app, "127.0.0.1", port)
    try:
        async with aiohttp.ClientSession() as session, session.get(
                f"http://127.0.0.1:{port}/api/issues", headers=AUTH) as resp:
            assert resp.status == 200
            assert (await resp.json())["issues"][0]["id"] == "i2"
    finally:
        await stop()
    await stop()  # idempotent
    with socket.socket() as probe:  # the port is free again
        probe.bind(("127.0.0.1", port))


@pytest.mark.parametrize("host", ["0.0.0.0", "::", "192.168.1.10", "example.com", "",
                                  "localhost.example"])
async def test_start_refuses_a_non_loopback_host_before_binding(
        host: str, monkeypatch: pytest.MonkeyPatch) -> None:
    def no_runner(*_args: Any, **_kwargs: Any) -> None:
        raise AssertionError("a runner was created")

    monkeypatch.setattr(web_app.web, "AppRunner", no_runner)
    app = make_app(FakeStore(), FakeLive(), TOKEN, Config())
    with pytest.raises(ValueError, match="loopback"):
        await start(app, host, free_port())


async def test_start_accepts_localhost_and_ipv6_loopback() -> None:
    for host in ("localhost", "::1"):
        port = free_port()
        stop = await start(make_app(FakeStore(), FakeLive(), TOKEN, Config(web=Web(port=port))),
                           host, port)
        await stop()


async def test_start_on_a_taken_port_raises_and_cleans_up() -> None:
    with socket.socket() as taken:
        taken.bind(("127.0.0.1", 0))
        taken.listen()
        port = taken.getsockname()[1]
        app = make_app(FakeStore(), FakeLive(), TOKEN, Config(web=Web(port=port)))
        cleaned: list[bool] = []

        async def note(_app: Any) -> None:
            cleaned.append(True)

        app.on_cleanup.append(note)
        with pytest.raises(OSError):
            await start(app, "127.0.0.1", port)
        assert cleaned == [True]


# --- passwords --------------------------------------------------------------------------------

PASSWORD = "correct horse battery staple"
SCRYPT_SHAPE = re.compile(r"scrypt\$32768\$8\$1\$([A-Za-z0-9+/]{22}==)\$([A-Za-z0-9+/]{43}=)")


@pytest.fixture(scope="module")
def password_hash() -> str:
    return hash_password(PASSWORD)


def test_hash_password_writes_the_format_config_accepts(password_hash: str,
                                                       tmp_path: Path) -> None:
    match = SCRYPT_SHAPE.fullmatch(password_hash)
    assert match, password_hash
    assert len(base64.b64decode(match[1])) == 16 and len(base64.b64decode(match[2])) == 32
    assert hash_password(PASSWORD) != password_hash  # a fresh salt every time
    config = tmp_path / "c.toml"
    config.write_text(f'[web]\npassword_hash = "{password_hash}"\n')
    assert load(config).web.password_hash == password_hash


def test_verify_password_round_trip(password_hash: str) -> None:
    assert verify_password(PASSWORD, password_hash)
    assert not verify_password(PASSWORD + " ", password_hash)
    assert not verify_password("", password_hash)
    assert not verify_password(PASSWORD.upper(), password_hash)


def _recoded(encoded: str, index: int, value: str) -> str:
    parts = encoded.split("$")
    parts[index] = value
    return "$".join(parts)


@pytest.mark.parametrize("mangle", [
    lambda h: "",
    lambda h: "scrypt",
    lambda h: h.replace("scrypt$", "bcrypt$", 1),
    lambda h: h.rsplit("$", 1)[0],                 # five fields
    lambda h: h + "$extra",                        # seven fields
    lambda h: _recoded(h, 1, "abc"),
    lambda h: _recoded(h, 1, "+32768"),
    lambda h: _recoded(h, 1, "\uff13\uff12\uff17\uff16\uff18"),  # fullwidth digits
    lambda h: _recoded(h, 1, "32767"),             # not a power of two
    lambda h: _recoded(h, 1, "8192"),              # below 2^14
    lambda h: _recoded(h, 1, str(2**21)),          # more memory than allowed
    lambda h: _recoded(h, 1, ""),
    lambda h: _recoded(h, 2, "7"),                 # r below 8
    lambda h: _recoded(h, 2, "4096"),              # r absurdly large
    lambda h: _recoded(h, 3, "0"),
    lambda h: _recoded(h, 3, "64"),                # p absurdly large
    lambda h: _recoded(h, 4, ""),
    lambda h: _recoded(h, 4, "not*base64!"),
    lambda h: _recoded(h, 4, "QUJD"),              # a 3-byte salt
    lambda h: _recoded(h, 5, ""),
    lambda h: _recoded(h, 5, "QUJDREVGR0g="),      # an 8-byte key
    lambda h: _recoded(h, 5, "####"),
    lambda h: _recoded(h, 5, base64.b64encode(b"x" * 32).decode() + "\n"),
])
def test_a_malformed_hash_never_verifies_and_never_raises(mangle: Any,
                                                          password_hash: str) -> None:
    assert verify_password(PASSWORD, mangle(password_hash)) is False


@pytest.mark.parametrize("password, encoded", [
    (None, "{h}"), (b"bytes", "{h}"), ("\ud800 lone surrogate", "{h}"),
    (PASSWORD, None), (PASSWORD, b"scrypt$1$2$3$4$5"), (PASSWORD, 42),
])
def test_wrong_types_never_verify(password: Any, encoded: Any, password_hash: str) -> None:
    if encoded == "{h}":
        encoded = password_hash
    assert verify_password(password, encoded) is False


def test_verify_compares_in_constant_time(password_hash: str,
                                          monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[int] = []
    real = web_app.hmac.compare_digest

    def spy(a: bytes, b: bytes) -> bool:
        seen.append(len(a))
        return real(a, b)

    monkeypatch.setattr(web_app.hmac, "compare_digest", spy)
    assert not verify_password("wrong password!", password_hash)
    assert seen == [32]


# --- password mode: the login flow ------------------------------------------------------------


@dataclass
class Clock:
    now: float = NOW

    def __call__(self) -> float:
        return self.now


@dataclass
class Gate:
    client: TestClient
    store: Any
    port: int
    clock: Clock
    live: FakeLive

    @property
    def origin(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    async def login(self, password: str = PASSWORD, origin: str | None = None,
                    client: Any = None, **headers: str):
        client = client or self.client
        url = self.client.make_url("/login") if client is not self.client else "/login"
        return await client.post(url, data={"password": password}, allow_redirects=False,
                                 headers={"Origin": origin or self.origin, **headers})

    async def logged_in(self) -> str:
        resp = await self.login()
        assert resp.status == 303, await resp.text()
        return resp.cookies["neonwatch_session"].value

    async def csrf(self) -> str:
        resp = await self.client.get("/api/session")
        assert resp.status == 200
        return (await resp.json())["csrf"]


@contextlib.asynccontextmanager
async def gated(password_hash: str, *, allowed_hosts: tuple[str, ...] = (),
                session_s: int = 3600, **options: Any) -> AsyncIterator[Gate]:
    port = free_port()
    clock = Clock()
    store = populated()
    live = FakeLive()
    config = Config(web=Web(port=port, password_hash=password_hash, session_s=session_s,
                            allowed_hosts=tuple(h.format(port=port) for h in allowed_hosts)))
    app = make_app(store, live, "", config, clock=clock, **options)
    client = TestClient(TestServer(app, host="127.0.0.1", port=port))
    await client.start_server()
    try:
        yield Gate(client, store, port, clock, live)
    finally:
        await client.close()


def without_cookies(gate: Gate) -> None:
    gate.client.session.cookie_jar.clear()


async def test_the_login_page_is_a_plain_form_with_no_script_or_style(password_hash: str) -> None:
    async with gated(password_hash) as g:
        resp = await g.client.get("/login")
        assert resp.status == 200 and resp.content_type == "text/html"
        page = await resp.text()
        assert re.search(r'<form method="post" action="/login">', page)
        assert 'name="password"' in page and 'type="password"' in page
        assert "<script" not in page and "<style" not in page and "style=" not in page
        assert "not accepted" not in page
        assert "default-src 'self'" in resp.headers["Content-Security-Policy"]
        # A form POST under `no-referrer` carries `Origin: null`, which the login refuses; the
        # login page alone says `same-origin`, so the browser sends its real origin.
        assert resp.headers["Referrer-Policy"] == "same-origin"
        failed = await (await g.client.get("/login?failed=1")).text()
        assert "That password was not accepted." in failed


async def test_password_mode_needs_a_session_everywhere_but_the_login(password_hash: str) -> None:
    async with gated(password_hash) as g:
        resp = await g.client.get("/", allow_redirects=False)
        assert resp.status == 303 and resp.headers["Location"] == "/login"
        for path in ("/api/health", "/api/session", "/api/overview", "/api/stream",
                     "/api/scheduled", "/api/services"):
            resp = await g.client.get(path)
            assert resp.status == 401, path
            assert await resp.json() == {"error": "not logged in"}
        resp = await g.client.post("/api/issues/i1/ack", headers={"Origin": g.origin})
        assert resp.status == 401
        assert g.store.acks == []


@pytest.mark.parametrize("credential", [
    {"Authorization": f"Bearer {TOKEN}"}, {"Authorization": "Bearer "},
    {"Cookie": f"neonwatch_token={TOKEN}"}, {"Cookie": "neonwatch_session=guess"},
    {"Cookie": "neonwatch_session="},
])
async def test_the_token_is_not_a_way_in_once_a_password_is_set(password_hash: str,
                                                                credential: dict) -> None:
    port = free_port()
    config = Config(web=Web(port=port, password_hash=password_hash))
    app = make_app(populated(), FakeLive(), TOKEN, config, clock=lambda: NOW)
    async with TestClient(TestServer(app, host="127.0.0.1", port=port)) as client:
        assert (await client.get("/api/health", headers=credential)).status == 401
        resp = await client.get(f"/?token={TOKEN}", allow_redirects=False)
        assert resp.status == 303 and resp.headers["Location"] == "/login"
        assert "Set-Cookie" not in resp.headers


async def test_a_login_sets_an_httponly_strict_session_cookie(password_hash: str) -> None:
    async with gated(password_hash) as g:
        resp = await g.login()
        assert resp.status == 303 and resp.headers["Location"] == "/"
        cookie = resp.headers["Set-Cookie"]
        sid = resp.cookies["neonwatch_session"].value
        assert cookie.startswith(f"neonwatch_session={sid};")
        assert len(sid) >= 43
        assert "HttpOnly" in cookie and "SameSite=Strict" in cookie and "Path=/" in cookie
        assert "Secure" not in cookie  # plain HTTP here; the TLS test sees it set
        assert "Strict-Transport-Security" not in resp.headers
        assert (await g.client.get("/api/health")).status == 200
        root = await g.client.get("/", allow_redirects=False)
        assert root.status == 200 and root.content_type == "text/html"
        assert sid != await g.logged_in()  # each login is a new session


async def test_a_wrong_password_makes_no_session_and_says_nothing(password_hash: str,
                                                                   caplog: Any) -> None:
    caplog.set_level(logging.DEBUG)
    async with gated(password_hash) as g:
        resp = await g.login("hunter2-wrong-guess")
        assert resp.status == 303 and resp.headers["Location"] == "/login?failed=1"
        assert "Set-Cookie" not in resp.headers
        assert "hunter2" not in await resp.text()
        assert (await g.client.get("/api/health")).status == 401
        sid = await g.logged_in()
    assert "hunter2-wrong-guess" not in caplog.text and PASSWORD not in caplog.text
    assert sid not in caplog.text
    assert "failed login from 127.0.0.1" in caplog.text


@pytest.mark.parametrize("send", [
    {"json": {"password": PASSWORD}},
    {"data": {"pass": PASSWORD}},
    {"data": {"password": PASSWORD, "other": "x"}},
    {"data": [("password", PASSWORD), ("password", PASSWORD)]},
    {"data": {"password": "x" * 1025}},
    {"data": b"password=x", "headers": {"Content-Type": "text/plain"}},
])
async def test_a_malformed_login_is_400_and_not_counted(password_hash: str, send: dict) -> None:
    async with gated(password_hash) as g:
        headers = {"Origin": g.origin, **send.pop("headers", {})}
        for _ in range(6):
            resp = await g.client.post("/login", allow_redirects=False, headers=headers, **send)
            assert resp.status == 400
            assert await resp.json() == {"error": "the login form sends one password field"}
        assert (await g.login()).status == 303


@pytest.mark.parametrize("origin", [None, "null", "http://evil.example",
                                    "https://127.0.0.1:{port}", "http://localhost:{port}",
                                    "http://127.0.0.1:1"])
async def test_a_cross_origin_login_is_refused(password_hash: str, origin: str | None) -> None:
    async with gated(password_hash) as g:
        headers = {} if origin is None else {"Origin": origin.format(port=g.port)}
        resp = await g.client.post("/login", data={"password": PASSWORD}, headers=headers,
                                   allow_redirects=False)
        assert resp.status == 403
        assert await resp.json() == {"error": "cross-origin login refused"}
        assert "Set-Cookie" not in resp.headers


async def test_failed_logins_are_limited_per_address(password_hash: str) -> None:
    async with gated(password_hash) as g:
        for _ in range(5):
            assert (await g.login("wrong password")).headers["Location"] == "/login?failed=1"
        g.clock.now += 10
        resp = await g.login()  # even the right password, until the window passes
        assert resp.status == 429
        assert resp.headers["Retry-After"] == "290"
        assert "Set-Cookie" not in resp.headers
        assert "Too many failed attempts" in await resp.text()
        g.clock.now = NOW + web_app.LOGIN_WINDOW_S
        assert (await g.login()).status == 303


async def test_concurrent_guesses_cannot_outrun_the_limit(password_hash: str) -> None:
    async with gated(password_hash) as g:
        replies = await asyncio.gather(*(g.login(f"guess {n}") for n in range(12)))
        statuses = sorted(r.status for r in replies)
        assert statuses == [303] * 5 + [429] * 7


async def test_a_successful_login_does_not_count_as_a_failure(password_hash: str) -> None:
    async with gated(password_hash) as g:
        for _ in range(10):
            assert (await g.login()).status == 303
        for _ in range(5):
            assert (await g.login("wrong")).status == 303
        assert (await g.login()).status == 429


async def test_a_global_cap_stops_address_rotation(password_hash: str,
                                                   monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(web_app, "LOGIN_GLOBAL_FAILURES", 7)
    async with gated(password_hash) as g:
        async def from_address(address: str, password: str) -> int:
            connector = aiohttp.TCPConnector(local_addr=(address, 0))
            async with aiohttp.ClientSession(connector=connector) as other:
                return (await g.login(password, client=other)).status

        for _ in range(5):
            assert await from_address("127.0.0.2", "wrong") == 303
        for _ in range(2):
            assert await from_address("127.0.0.3", "wrong") == 303
        assert await from_address("127.0.0.4", PASSWORD) == 429
        assert (await g.login()).status == 429
        g.clock.now += web_app.LOGIN_WINDOW_S
        assert await from_address("127.0.0.4", PASSWORD) == 303


def test_the_login_limits_are_as_specified() -> None:
    assert (web_app.LOGIN_ADDRESS_FAILURES, web_app.LOGIN_GLOBAL_FAILURES,
            web_app.LOGIN_WINDOW_S) == (5, 30, 300)


async def test_a_session_expires_and_is_removed(password_hash: str) -> None:
    async with gated(password_hash, session_s=600) as g:
        first = await g.logged_in()
        g.clock.now = NOW + 599
        assert (await g.client.get("/api/health")).status == 200
        g.clock.now = NOW + 600
        assert (await g.client.get("/api/health")).status == 401
        assert (await g.client.get("/", allow_redirects=False)).status == 303
        g.clock.now = NOW  # removed, not merely compared: going back does not revive it
        assert (await g.client.get("/api/health")).status == 401
        # A login sweeps every other expired session too.
        without_cookies(g)
        second = await g.logged_in()
        g.clock.now = NOW + 700
        without_cookies(g)
        await g.logged_in()
        without_cookies(g)
        g.clock.now = NOW
        for sid in (first, second):
            resp = await g.client.get("/api/health",
                                      headers={"Cookie": f"neonwatch_session={sid}"})
            assert resp.status == 401


async def test_logout_needs_csrf_and_ends_the_session(password_hash: str) -> None:
    async with gated(password_hash) as g:
        sid = await g.logged_in()
        resp = await g.client.post("/logout", headers={"Origin": g.origin},
                                   allow_redirects=False)
        assert resp.status == 403
        assert await resp.json() == {"error": "missing or wrong CSRF token"}
        csrf = await g.csrf()
        resp = await g.client.post("/logout", headers={"Origin": "http://evil.example",
                                                       "X-CSRF-Token": csrf},
                                   allow_redirects=False)
        assert resp.status == 403
        resp = await g.client.post("/logout", headers={"Origin": g.origin, "X-CSRF-Token": csrf},
                                   allow_redirects=False)
        assert resp.status == 303 and resp.headers["Location"] == "/login"
        assert resp.cookies["neonwatch_session"].value == ""
        without_cookies(g)
        resp = await g.client.get("/api/health", headers={"Cookie": f"neonwatch_session={sid}"})
        assert resp.status == 401
        assert (await g.client.post("/logout", headers={"Origin": g.origin})).status == 401


async def test_csrf_is_still_enforced_on_writes_with_a_session(password_hash: str) -> None:
    async with gated(password_hash) as g:
        await g.logged_in()
        csrf = await g.csrf()
        assert len(csrf) >= 32
        for headers in ({"Origin": g.origin}, {"Origin": g.origin, "X-CSRF-Token": "wrong"},
                        {"Origin": g.origin, "X-CSRF-Token": csrf + "x"}):
            resp = await g.client.post("/api/issues/i1/ack", headers=headers)
            assert resp.status == 403
            assert await resp.json() == {"error": "missing or wrong CSRF token"}
        resp = await g.client.post("/api/issues/i1/ack",
                                   headers={"Origin": "https://127.0.0.1:1", "X-CSRF-Token": csrf})
        assert resp.status == 403
        assert await resp.json() == {"error": "cross-origin write refused"}
        assert g.store.acks == []
        # Each session has its own CSRF token; another session's does not work here.
        without_cookies(g)
        await g.logged_in()
        other = await g.csrf()
        assert other != csrf
        resp = await g.client.post("/api/issues/i1/ack",
                                   headers={"Origin": g.origin, "X-CSRF-Token": csrf})
        assert resp.status == 403
        resp = await g.client.post("/api/issues/i1/ack",
                                   headers={"Origin": g.origin, "X-CSRF-Token": other})
        assert resp.status == 200
        assert g.store.acks == [("i1", NOW)]


async def test_only_the_allowed_hosts_are_answered(password_hash: str) -> None:
    async with gated(password_hash, allowed_hosts=("monitor.test:{port}",)) as g:
        name = f"monitor.test:{g.port}"
        for host in (f"127.0.0.1:{g.port}", f"localhost:{g.port}", "evil.example", name + "."):
            resp = await g.client.get("/login", headers={"Host": host})
            assert resp.status == 403, host
            assert await resp.json() == {"error": "unexpected Host header"}
        assert (await g.client.get("/login", headers={"Host": name})).status == 200
        refused = await g.login(origin=g.origin, Host=name)
        assert refused.status == 403  # the Origin must name the allowed host, too
        resp = await g.login(origin=f"http://{name}", Host=name)
        assert resp.status == 303


async def test_the_login_route_does_not_exist_without_a_password() -> None:
    async with serve() as h:
        assert (await h.client.get("/login")).status == 404
        assert (await h.client.post("/login", data={"password": "x"})).status == 405
        assert (await h.client.post("/logout")).status == 405


async def test_an_unexpected_login_failure_is_a_500_without_detail(
        password_hash: str, monkeypatch: pytest.MonkeyPatch, caplog: Any) -> None:
    def broken(_password: str, _encoded: str) -> bool:
        raise RuntimeError("boom")

    monkeypatch.setattr(web_app, "verify_password", broken)
    async with gated(password_hash) as g:
        resp = await g.login()
        assert resp.status == 500
        assert await resp.json() == {"error": "internal error"}
    assert PASSWORD not in caplog.text


# --- TLS ----------------------------------------------------------------------------------------

needs_openssl = pytest.mark.skipif(
    shutil.which("openssl") is None,
    reason="openssl makes the test certificate: the standard library cannot create one")


@pytest.fixture(scope="module")
def certificate(tmp_path_factory: pytest.TempPathFactory) -> tuple[Path, Path]:
    where = tmp_path_factory.mktemp("tls")
    cert, key = where / "cert.pem", where / "key.pem"
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
         "-nodes", "-days", "2", "-subj", "/CN=monitor.test", "-keyout", str(key), "-out",
         str(cert), "-addext", "subjectAltName=DNS:monitor.test,IP:127.0.0.1",
         "-addext", "basicConstraints=critical,CA:FALSE"],
        check=True, capture_output=True, timeout=30)
    return cert, key


@needs_openssl
async def test_a_real_tls_round_trip(password_hash: str, certificate: tuple[Path, Path]) -> None:
    cert, key = certificate
    port = free_port()
    server = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    server.load_cert_chain(cert, key)
    trust = ssl.create_default_context(cafile=str(cert))
    config = Config(web=Web(port=port, password_hash=password_hash,
                            allowed_hosts=(f"127.0.0.1:{port}",)))
    app = make_app(populated(), FakeLive(), "", config, clock=lambda: NOW)
    stop = await start(app, "127.0.0.1", port, ssl_context=server)
    base = f"https://127.0.0.1:{port}"
    try:
        jar = aiohttp.CookieJar(unsafe=True)
        async with aiohttp.ClientSession(cookie_jar=jar) as client:
            login = await client.get(f"{base}/login", ssl=trust)
            assert login.status == 200
            assert login.headers["Strict-Transport-Security"] == "max-age=31536000"
            refused = await client.post(f"{base}/login", data={"password": PASSWORD},
                                        headers={"Origin": f"http://127.0.0.1:{port}"},
                                        ssl=trust, allow_redirects=False)
            assert refused.status == 403  # over TLS the origin is https
            resp = await client.post(f"{base}/login", data={"password": PASSWORD},
                                     headers={"Origin": base}, ssl=trust, allow_redirects=False)
            assert resp.status == 303
            cookie = resp.headers["Set-Cookie"]
            # Under TLS the cookie is `__Host-`: the browser holds it Secure, Path=/, no Domain.
            assert cookie.startswith("__Host-neonwatch_session=")
            assert "Domain" not in cookie and "Path=/" in cookie
            assert "Secure" in cookie and "HttpOnly" in cookie and "SameSite=Strict" in cookie
            sid = resp.cookies["__Host-neonwatch_session"].value
            assert resp.headers["Strict-Transport-Security"] == "max-age=31536000"
            health = await client.get(f"{base}/api/health", ssl=trust)
            assert health.status == 200
            assert health.headers["Strict-Transport-Security"] == "max-age=31536000"
            csrf = (await (await client.get(f"{base}/api/session", ssl=trust)).json())["csrf"]
            ack = await client.post(f"{base}/api/issues/i1/ack", ssl=trust,
                                    headers={"Origin": base, "X-CSRF-Token": csrf})
            assert ack.status == 200
            async with aiohttp.ClientSession(cookie_jar=aiohttp.DummyCookieJar()) as bare:
                for name, status in (("neonwatch_session", 401),
                                     ("__Host-neonwatch_session", 200)):
                    # Only the cookie name that matches the transport is a session.
                    probe = await bare.get(f"{base}/api/health", ssl=trust,
                                           headers={"Cookie": f"{name}={sid}"})
                    assert probe.status == status, name
            out = await client.post(f"{base}/logout", ssl=trust, allow_redirects=False,
                                    headers={"Origin": base, "X-CSRF-Token": csrf})
            assert out.status == 303
            assert out.headers["Set-Cookie"].startswith("__Host-neonwatch_session=")
            assert "Secure" in out.headers["Set-Cookie"]
            with pytest.raises(aiohttp.ClientError):  # nothing is served in clear text
                await client.get(f"http://127.0.0.1:{port}/login")
            with pytest.raises(aiohttp.ClientConnectorCertificateError):
                await client.get(f"{base}/login")  # an untrusted certificate is refused
    finally:
        await stop()


# --- start: when a non-loopback bind is allowed ------------------------------------------------


@pytest.mark.parametrize("with_password, with_tls", [(False, False), (False, True),
                                                     (True, False)])
async def test_start_refuses_the_network_without_tls_and_a_password(
        with_password: bool, with_tls: bool, password_hash: str,
        monkeypatch: pytest.MonkeyPatch) -> None:
    def no_runner(*_args: Any, **_kwargs: Any) -> None:
        raise AssertionError("a runner was created")

    monkeypatch.setattr(web_app.web, "AppRunner", no_runner)
    config = Config(web=Web(password_hash=password_hash if with_password else ""))
    app = make_app(FakeStore(), FakeLive(), TOKEN, config)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER) if with_tls else None
    with pytest.raises(ValueError, match="loopback"):
        await start(app, "192.168.1.10", free_port(), ssl_context=context)


async def test_start_binds_the_network_with_tls_and_a_password(
        password_hash: str, monkeypatch: pytest.MonkeyPatch) -> None:
    bound: list[tuple[str, int, Any]] = []

    class Site:
        def __init__(self, _runner: Any, host: str, port: int, *, ssl_context: Any) -> None:
            bound.append((host, port, ssl_context))

        async def start(self) -> None:
            return None

    monkeypatch.setattr(web_app.web, "TCPSite", Site)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    app = make_app(FakeStore(), FakeLive(), "", Config(web=Web(password_hash=password_hash)))
    stop = await start(app, "192.168.1.10", 8765, ssl_context=context)
    await stop()
    assert bound == [("192.168.1.10", 8765, context)]


async def test_a_token_app_on_loopback_passes_no_tls_context(
        monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[Any] = []

    class Site:
        def __init__(self, _runner: Any, _host: str, _port: int, *, ssl_context: Any) -> None:
            seen.append(ssl_context)

        async def start(self) -> None:
            return None

    monkeypatch.setattr(web_app.web, "TCPSite", Site)
    stop = await start(make_app(FakeStore(), FakeLive(), TOKEN, Config()), "127.0.0.1", 1)
    await stop()
    assert seen == [None]


# --- streams end with their session ------------------------------------------------------------


async def open_stream(g: Gate) -> Any:
    stream = await g.client.get("/api/stream")
    assert stream.status == 200
    await asyncio.wait_for(g.live.subscribed.wait(), 2)
    return stream


async def drained(stream: Any, within: float = 3.0) -> bytes:
    """Everything the stream sends until it ends; a stream that does not end fails the test."""
    return await asyncio.wait_for(stream.content.read(), within)


async def test_logout_ends_the_open_stream(password_hash: str) -> None:
    async with gated(password_hash) as g:
        await g.logged_in()
        csrf = await g.csrf()
        stream = await open_stream(g)
        await g.live.push(live_event(Kind.ISSUE, "issue.i1", to_body(issue("i1"))))
        assert "issue.i1" in await read_event(stream)
        out = await g.client.post("/logout", headers={"Origin": g.origin, "X-CSRF-Token": csrf},
                                  allow_redirects=False)
        assert out.status == 303
        await g.live.push(live_event(Kind.ISSUE, "issue.i9", to_body(issue("i9"))))
        assert b"issue.i9" not in await drained(stream)


async def test_logout_ends_only_that_sessions_streams(password_hash: str) -> None:
    async with gated(password_hash) as g:
        await g.logged_in()
        mine = await open_stream(g)
        without_cookies(g)
        await g.logged_in()
        csrf = await g.csrf()
        g.live.subscribed.clear()
        other = await open_stream(g)
        await g.client.post("/logout", headers={"Origin": g.origin, "X-CSRF-Token": csrf},
                            allow_redirects=False)
        assert await drained(other) == b""
        await g.live.push(live_event(Kind.ISSUE, "issue.i1", to_body(issue("i1"))))
        assert "issue.i1" in await read_event(mine)
        mine.close()


async def test_an_expired_session_gets_no_further_events(password_hash: str) -> None:
    async with gated(password_hash, session_s=600) as g:
        await g.logged_in()
        stream = await open_stream(g)
        g.clock.now = NOW + 600
        await g.live.push(live_event(Kind.ISSUE, "issue.i9", to_body(issue("i9"))))
        assert b"issue.i9" not in await drained(stream)
        g.clock.now = NOW  # and it was removed, not merely skipped
        assert (await g.client.get("/api/health")).status == 401


async def test_the_stream_rechecks_the_session_at_every_keepalive(password_hash: str) -> None:
    async with gated(password_hash, session_s=600, keepalive_s=0.05) as g:
        await g.logged_in()
        stream = await open_stream(g)
        assert (await asyncio.wait_for(stream.content.readline(), 2)) == b": keepalive\n"
        g.clock.now = NOW + 600  # no event at all: the keepalive notices
        await drained(stream)


async def test_an_expiry_noticed_elsewhere_ends_the_stream(password_hash: str) -> None:
    async with gated(password_hash, session_s=600) as g:
        await g.logged_in()
        stream = await open_stream(g)
        g.clock.now = NOW + 600
        assert (await g.client.get("/api/health")).status == 401  # removes the session
        assert await drained(stream) == b""


async def test_a_replay_is_delivered_while_the_session_lives(password_hash: str) -> None:
    async with gated(password_hash, session_s=600) as g:
        await g.logged_in()
        g.store.finding_rows = [(NOW - 5, finding())]
        g.clock.now = NOW + 599
        stream = await g.client.get("/api/stream", headers={
            "Last-Event-ID": f"1:issue:{NOW - 10!r}"})
        assert stream.status == 200
        assert "finding" in await read_event(stream)
        stream.close()


# --- static files need a session, except what the login page needs ------------------------------


async def test_static_files_need_a_session_except_the_login_pages_own(password_hash: str) -> None:
    async with gated(password_hash) as g:
        resp = await g.client.get("/index.html", allow_redirects=False)
        assert resp.status == 303 and resp.headers["Location"] == "/login"
        for name in ("app.js", "missing.js", "nope"):
            resp = await g.client.get(f"/{name}", allow_redirects=False)
            assert resp.status == 401, name
            assert await resp.json() == {"error": "not logged in"}
        for name in ("app.css", "login.html"):
            assert (await g.client.get(f"/{name}")).status == 200, name
        await g.logged_in()
        for name in ("index.html", "app.js", "app.css"):
            assert (await g.client.get(f"/{name}")).status == 200, name
        assert (await g.client.get("/missing.js")).status == 404


# --- Host is matched case-insensitively --------------------------------------------------------


async def test_the_host_header_is_matched_without_regard_to_case(password_hash: str) -> None:
    async with gated(password_hash, allowed_hosts=("Monitor.Test:{port}",)) as g:
        for host in (f"monitor.test:{g.port}", f"MONITOR.TEST:{g.port}", f"Monitor.Test:{g.port}"):
            assert (await g.client.get("/login", headers={"Host": host})).status == 200, host
        resp = await g.login(origin=f"http://monitor.test:{g.port}", Host=f"MONITOR.test:{g.port}")
        assert resp.status == 303
        assert (await g.client.get("/login", headers={"Host": "evil.test"})).status == 403


# --- scrypt runs on its own single worker -------------------------------------------------------


async def test_verify_runs_on_a_dedicated_single_worker_shut_down_on_cleanup(
        password_hash: str, monkeypatch: pytest.MonkeyPatch) -> None:
    made: list[Any] = []
    real = web_app.ThreadPoolExecutor

    class Recording(real):  # type: ignore[misc, valid-type]
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            super().__init__(*args, **kwargs)
            self.kwargs, self.closed = kwargs, False
            made.append(self)

        def shutdown(self, *args: Any, **kwargs: Any) -> None:
            self.closed = True
            super().shutdown(*args, **kwargs)

    threads: list[str] = []
    verify = web_app.verify_password

    def spy(password: str, encoded: str) -> bool:
        import threading
        threads.append(threading.current_thread().name)
        return verify(password, encoded)

    monkeypatch.setattr(web_app, "ThreadPoolExecutor", Recording)
    monkeypatch.setattr(web_app, "verify_password", spy)
    async with gated(password_hash) as g:
        assert (await g.login()).status == 303
        assert (await g.login("wrong")).status == 303
    assert len(made) == 1 and made[0].kwargs["max_workers"] == 1
    assert threads and all(t.startswith("neonwatch-login") for t in threads)
    assert made[0].closed


def test_a_token_app_makes_no_login_worker(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(web_app, "ThreadPoolExecutor",
                        lambda **_: pytest.fail("a login worker in token mode"))
    make_app(FakeStore(), FakeLive(), TOKEN, Config())


# --- IPv6 clients are limited per /64 -----------------------------------------------------------


@pytest.mark.parametrize("remote, key", [
    ("192.0.2.7", "192.0.2.7"),
    ("2001:db8:1:2:aaaa::1", "2001:db8:1:2::/64"),
    ("2001:db8:1:2:ffff:ffff:ffff:fffe", "2001:db8:1:2::/64"),
    ("2001:db8:1:3::1", "2001:db8:1:3::/64"),
    ("::ffff:192.0.2.7", "192.0.2.7"),
    ("fe80::1%eth0", "fe80::/64"),
    ("::1", "::/64"),
    (None, ""),
    ("not an address", "not an address"),
])
def test_the_login_limit_key(remote: str | None, key: str) -> None:
    assert web_app._client_key(remote) == key


async def test_failures_from_one_ipv6_64_share_a_quota(password_hash: str,
                                                       monkeypatch: pytest.MonkeyPatch) -> None:
    addresses = iter(f"2001:db8::{n:x}" for n in range(1, 100))
    real = web_app._client_key
    monkeypatch.setattr(web_app, "_client_key", lambda _remote: real(next(addresses)))
    async with gated(password_hash) as g:
        for _ in range(5):
            assert (await g.login("wrong")).status == 303
        assert (await g.login()).status == 429  # a sixth address in the same /64


# --- the cookie name follows the transport ------------------------------------------------------


async def test_over_plain_http_only_the_plain_cookie_name_is_a_session(password_hash: str) -> None:
    async with gated(password_hash) as g:
        sid = await g.logged_in()
        without_cookies(g)
        for name, status in (("__Host-neonwatch_session", 401), ("neonwatch_session", 200)):
            resp = await g.client.get("/api/health", headers={"Cookie": f"{name}={sid}"})
            assert resp.status == status, name


# --- the Logs view --------------------------------------------------------------------------


def journal_entry(message: str, ident: str = "kernel", priority: str = "6",
                  at: int = 1_000_000_000_000) -> dict[str, Any]:
    return {"MESSAGE": message, "SYSLOG_IDENTIFIER": ident, "PRIORITY": priority,
            "__REALTIME_TIMESTAMP": str(at), "_SYSTEMD_UNIT": f"{ident}.service"}


class FakeJournal:
    """`read_logs` for the app: counts reads, returns the lines it is given."""

    def __init__(self, *messages: dict[str, Any], error: str = "") -> None:
        self.lines = tuple(parse_line(m) for m in messages)
        self.error = error
        self.reads = 0

    async def __call__(self) -> JournalRead:
        self.reads += 1
        return JournalRead(self.lines, error=self.error)


def journal() -> FakeJournal:
    return FakeJournal(journal_entry("audit[12]: op=open", priority="7"),
                       journal_entry("audit[345]: op=open", priority="4"),
                       journal_entry("Started foo.", ident="systemd"),
                       journal_entry("eth0: link down", priority="3"))


async def wait_job(h: Harness, job: str) -> dict[str, Any]:
    for _ in range(200):
        body = await (await h.get(f"/api/logs/explain/{job}")).json()
        if body["status"] != "running":
            return body
        await asyncio.sleep(0.01)
    raise AssertionError("the job did not finish")


async def test_without_a_reader_the_logs_route_refuses() -> None:
    async with serve() as h:
        resp = await h.get("/api/logs")
        assert resp.status == 503
        assert await resp.json() == {"error": "the journal reader is not configured"}


async def test_loading_lists_lines_with_keys_and_sends_nothing() -> None:
    analyst, reader = FakeAnalyst(), journal()
    async with serve(analyst=analyst, read_logs=reader) as h:
        body = await (await h.get("/api/logs")).json()
    assert reader.reads == 1 and analyst.requests == []
    lines = body["lines"]
    assert [line["message"] for line in lines] == ["audit[12]: op=open", "audit[345]: op=open",
                                                   "Started foo.", "eth0: link down"]
    assert lines[0]["key"] == lines[1]["key"] != lines[2]["key"]
    assert lines[0]["priority"] == 7 and lines[0]["unit"] == "kernel.service"
    assert lines[0]["identifier"] == "kernel" and lines[0]["at"] == 1_000_000.0
    assert all(line["explanation"] is None for line in lines)
    assert body["templates"] == 3 and body["uncached"] == 3
    assert body["error"] == "" and body["read_at"] == NOW


async def test_a_cached_explanation_is_shown_on_every_line_of_its_kind_and_touched() -> None:
    store, reader = FakeStore(), journal()
    key = reader.lines[0].key
    store.explained[key] = LogExplanation(key, "kernel", "t", "routine audit", "m9", NOW - 5,
                                          NOW - 5)
    async with serve(store, read_logs=reader) as h:
        body = await (await h.get("/api/logs")).json()
    shown = [line["explanation"] for line in body["lines"]]
    assert shown[0] == shown[1] == {"text": "routine audit", "model": "m9",
                                    "created_at": NOW - 5}
    assert shown[2] is None and body["uncached"] == 2
    assert store.touched == [(key, NOW)]


async def test_a_reader_error_is_reported_not_hidden() -> None:
    async with serve(read_logs=FakeJournal(error="journalctl exited 1: no access")) as h:
        body = await (await h.get("/api/logs")).json()
    assert body["error"] == "journalctl exited 1: no access" and body["lines"] == []


async def test_estimating_needs_an_analyst_and_valid_keys() -> None:
    async with serve(read_logs=journal()) as h:
        assert (await h.post("/api/logs/estimate", {"keys": ["0" * 16]})).status == 503
    async with serve(analyst=FakeAnalyst(), read_logs=journal()) as h:
        for bad in ([], ["nothex"], ["0" * 16 + "\n"], "0" * 16, ["0" * 16] * 201, [7]):
            resp = await h.post("/api/logs/estimate", {"keys": bad})
            assert resp.status == 400, bad
        assert (await h.post("/api/logs/estimate", {})).status == 400


async def test_only_keys_from_the_last_listing_that_are_not_cached_are_estimated() -> None:
    store, reader = FakeStore(), journal()
    audit, started, link = (reader.lines[0].key, reader.lines[2].key, reader.lines[3].key)
    store.explained[started] = LogExplanation(started, "systemd", "t", "x", "m", NOW, NOW)
    async with serve(store, analyst=FakeAnalyst(), read_logs=reader) as h:
        resp = await h.post("/api/logs/estimate", {"keys": [audit]})
        assert resp.status == 409  # nothing was listed yet
        await h.get("/api/logs")
        resp = await h.post("/api/logs/estimate", {"keys": [link, audit, started, "f" * 16]})
        body = await resp.json()
    assert resp.status == 200
    assert body["keys"] == sorted([audit, link])
    assert body["estimate"]["templates"] == 2 and body["estimate"]["requests"] == 1
    assert body["estimate"]["url_host"] == "127.0.0.1" and body["estimate"]["remote"] is False


async def test_the_explain_flow_end_to_end() -> None:
    analyst, reader = FakeAnalyst(), journal()
    async with serve(analyst=analyst, read_logs=reader) as h:
        keys = [line["key"] for line in (await (await h.get("/api/logs")).json())["lines"]]
        resp = await h.post("/api/logs/explain", {"keys": keys})
        assert resp.status == 202
        started = await resp.json()
        job = started["id"]
        assert started == {"id": job, "status": "running", "keys": 3}
        running = await (await h.get(f"/api/logs/explain/{job}")).json()
        assert running["status"] == "running" and running["requested_at"] == NOW
        again = await h.post("/api/logs/explain", {"keys": keys})
        assert again.status == 429
        analyst.release.set()
        done = await wait_job(h, job)
        assert done["status"] == "done" and done["explained"] == 3 and done["error"] == ""
        sent = analyst.requests[0]
        assert [t.key for t in sent] == sorted(set(keys))
        audit = next(t for t in sent if t.key == keys[0])
        assert audit.priority == 4  # the most severe of its lines
        saved = h.store.explained[keys[0]]
        assert saved.model == "m" and saved.created_at == NOW and saved.source == "kernel"
        body = await (await h.get("/api/logs")).json()
        assert body["uncached"] == 0
        assert body["lines"][0]["explanation"]["text"] == f"means {audit.template}"
        # Explained once: the same kind is never sent again.
        assert (await h.post("/api/logs/explain", {"keys": keys})).status == 409
        assert len(analyst.requests) == 1


async def test_a_backend_that_explains_nothing_fails_the_job() -> None:
    analyst, reader = FakeAnalyst(error="no analysis backend is configured"), journal()
    analyst.release.set()
    async with serve(analyst=analyst, read_logs=reader) as h:
        await h.get("/api/logs")
        job = (await (await h.post("/api/logs/explain",
                                   {"keys": [reader.lines[0].key]})).json())["id"]
        done = await wait_job(h, job)
    assert done["status"] == "failed" and "no analysis backend" in done["error"]
    assert h.store.explained == {}


async def test_an_explainer_that_raises_or_times_out_fails_the_job() -> None:
    analyst, reader = FakeAnalyst(raises=RuntimeError("secret detail")), journal()
    analyst.release.set()
    async with serve(analyst=analyst, read_logs=reader) as h:
        await h.get("/api/logs")
        job = (await (await h.post("/api/logs/explain",
                                   {"keys": [reader.lines[0].key]})).json())["id"]
        done = await wait_job(h, job)
    assert done == {**done, "status": "failed", "error": "log explanation failed: RuntimeError"}
    config = AnalystConfig(provider="openai-compatible", model="m", timeout_s=0.05)
    async with serve(analyst=FakeAnalyst(), read_logs=reader, analyst_config=config) as h:
        await h.get("/api/logs")
        job = (await (await h.post("/api/logs/explain",
                                   {"keys": [reader.lines[0].key]})).json())["id"]
        done = await wait_job(h, job)
    assert done["status"] == "failed"
    assert done["error"] == "the analysis backend did not answer within 0.05 s"


async def test_finished_explain_jobs_are_bounded(monkeypatch) -> None:
    monkeypatch.setattr(web_app, "MAX_LOG_JOBS", 2)
    analyst = FakeAnalyst()
    analyst.release.set()
    reader = FakeJournal(*(journal_entry(f"kind {chr(97 + n)}") for n in range(4)))
    async with serve(analyst=analyst, read_logs=reader) as h:
        await h.get("/api/logs")
        jobs = []
        for line in reader.lines:
            jobs.append((await (await h.post("/api/logs/explain",
                                             {"keys": [line.key]})).json())["id"])
            await wait_job(h, jobs[-1])
        assert (await h.get(f"/api/logs/explain/{jobs[0]}")).status == 404
        assert (await h.get(f"/api/logs/explain/{jobs[-1]}")).status == 200
        assert (await h.get("/api/logs/explain/lx-unknown")).status == 404


async def test_a_running_explain_is_failed_on_shutdown() -> None:
    analyst, reader = FakeAnalyst(), journal()
    async with serve(analyst=analyst, read_logs=reader) as h:
        await h.get("/api/logs")
        job = (await (await h.post("/api/logs/explain",
                                   {"keys": [reader.lines[0].key]})).json())["id"]
        await asyncio.sleep(0)
        web = next(f.__self__ for f in h.client.server.app.on_shutdown  # the _Web behind it
                   if hasattr(getattr(f, "__self__", None), "log_jobs"))
    # Leaving the context closed the server with the task still waiting.
    assert web.log_jobs[job]["status"] == "failed" and h.store.explained == {}


@pytest.mark.parametrize("path", ["/api/logs/estimate", "/api/logs/explain"])
async def test_log_writes_need_csrf_and_the_same_origin(path: str) -> None:
    analyst, reader = FakeAnalyst(), journal()
    async with serve(analyst=analyst, read_logs=reader) as h:
        await h.get("/api/logs")
        body = {"keys": [reader.lines[0].key]}
        no_csrf = await h.post(path, body, headers={**AUTH, "Origin": h.origin})
        assert no_csrf.status == 403
        foreign = await h.post(path, body, headers={**AUTH, "X-CSRF-Token": h.csrf,
                                                    "Origin": "http://evil.example"})
        assert foreign.status == 403
        no_auth = await h.client.get("/api/logs")
        assert no_auth.status == 401
    assert analyst.requests == []


async def test_logs_against_the_real_store(tmp_path: Path) -> None:
    store = Store(tmp_path / "store.sqlite3", Config())
    analyst, reader = FakeAnalyst(), journal()
    analyst.release.set()
    try:
        async with serve(store, analyst=analyst, read_logs=reader) as h:
            keys = [line["key"] for line in (await (await h.get("/api/logs")).json())["lines"]]
            job = (await (await h.post("/api/logs/explain", {"keys": keys})).json())["id"]
            assert (await wait_job(h, job))["explained"] == 3
            body = await (await h.get("/api/logs")).json()
        assert body["uncached"] == 0 and body["lines"][3]["explanation"]["model"] == "m"
    finally:
        store.close()


# --- service descriptions ---------------------------------------------------------------------

FOO_KEY = real_jobs.service_key(SERVICE)
APT_SERVICE = {**SERVICE, "name": "apt-daily.service", "active": "inactive", "sub": "dead",
               "result": "success", "exec": ["/usr/lib/apt/apt.systemd.daily update"],
               "user": "", "restarts": 0, "file": "/usr/lib/systemd/system/apt-daily.service"}
APT_KEY = real_jobs.service_key(APT_SERVICE)


def foo_described(key: str = FOO_KEY) -> ServiceDescription:
    return ServiceDescription("foo.service", key, "The foo daemon.", "Foo does foo.", "m9",
                              NOW - 5, NOW - 5)


@pytest.fixture
def two_services(fake_jobs: FakeJobs, monkeypatch: pytest.MonkeyPatch) -> FakeJobs:
    monkeypatch.setattr(fake_jobs, "services",
                        lambda latest: [dict(APT_SERVICE), dict(SERVICE)] if latest else [])
    return fake_jobs


async def wait_described(h: Harness, job: str) -> dict[str, Any]:
    for _ in range(200):
        body = await (await h.get(f"/api/services/describe/{job}")).json()
        if body["status"] != "running":
            return body
        await asyncio.sleep(0.01)
    raise AssertionError("the job did not finish")


async def test_services_carry_their_key_timers_and_cached_description(
        two_services: FakeJobs) -> None:
    store = scheduled_store()
    store.described["foo.service"] = foo_described()
    analyst = FakeAnalyst()
    async with serve(store, analyst=analyst) as h:
        body = await (await h.get("/api/services")).json()
    apt, foo = body["services"]
    assert (apt["key"], foo["key"]) == (APT_KEY, FOO_KEY)
    assert apt["timers"] == ["apt-daily.timer"] and foo["timers"] == []  # from TIMER_JOB
    assert foo["described"] == {"brief": "The foo daemon.", "full": "Foo does foo.",
                                "model": "m9", "created_at": NOW - 5}
    assert apt["described"] is None
    assert store.touched_services == [("foo.service", NOW)] and analyst.requests == []


async def test_services_say_when_they_were_first_seen_and_whether_that_was_new(
        two_services: FakeJobs) -> None:
    store = scheduled_store()
    store.sightings = {"apt-daily.service": (NOW - 86400, False), "foo.service": (NOW - 60, True)}
    async with serve(store, analyst=FakeAnalyst()) as h:
        apt, foo = (await (await h.get("/api/services")).json())["services"]
    assert (apt["first_seen_at"], apt["new"]) == (NOW - 86400, False)
    assert (foo["first_seen_at"], foo["new"]) == (NOW - 60, True)
    assert apt["description_outdated"] is False  # never described is not outdated
    store.sightings = {}
    async with serve(store, analyst=FakeAnalyst()) as h:
        apt, _ = (await (await h.get("/api/services")).json())["services"]
    assert (apt["first_seen_at"], apt["new"]) == (None, False)  # not yet noted: not new


async def test_a_description_written_for_another_definition_is_not_shown(
        fake_jobs: FakeJobs) -> None:
    store = scheduled_store()
    store.described["foo.service"] = foo_described(key="0" * 16)
    async with serve(store, analyst=FakeAnalyst()) as h:
        [foo] = (await (await h.get("/api/services")).json())["services"]
        assert foo["described"] is None and store.touched_services == []
        assert foo["description_outdated"] is True
        # ... and the service may be described afresh.
        resp = await h.post("/api/services/estimate", {"keys": [FOO_KEY]})
        assert resp.status == 200 and (await resp.json())["keys"] == [FOO_KEY]


async def test_estimating_services_needs_an_analyst_valid_keys_and_a_listing(
        two_services: FakeJobs) -> None:
    async with serve(scheduled_store()) as h:
        assert (await h.post("/api/services/estimate", {"keys": [FOO_KEY]})).status == 503
    store = scheduled_store()
    store.described["foo.service"] = foo_described()
    async with serve(store, analyst=FakeAnalyst()) as h:
        for bad in ([], ["nothex"], "0" * 16, ["0" * 16] * 201, [7]):
            resp = await h.post("/api/services/estimate", {"keys": bad})
            assert resp.status == 400, bad
            assert "service keys" in (await resp.json())["error"]
        assert (await h.post("/api/services/estimate", {"keys": [APT_KEY]})).status == 409
        await h.get("/api/services")
        resp = await h.post("/api/services/estimate", {"keys": [FOO_KEY, APT_KEY, "f" * 16]})
        body = await resp.json()
    assert resp.status == 200 and body["keys"] == [APT_KEY]  # foo is described; f… unknown
    assert body["estimate"]["services"] == 1 and body["estimate"]["remote"] is False


async def test_the_describe_flow_end_to_end(two_services: FakeJobs) -> None:
    analyst = FakeAnalyst()
    async with serve(scheduled_store(), analyst=analyst) as h:
        await h.get("/api/services")
        resp = await h.post("/api/services/describe", {"keys": [FOO_KEY, APT_KEY]})
        assert resp.status == 202
        started = await resp.json()
        job = started["id"]
        assert started == {"id": job, "status": "running", "keys": 2} and job.startswith("sd-")
        assert (await h.post("/api/services/describe", {"keys": [FOO_KEY]})).status == 429
        analyst.release.set()
        done = await wait_described(h, job)
        assert done["status"] == "done" and done["described"] == 2 and done["error"] == ""
        [sent] = analyst.requests
        apt = next(u for u in sent if u.key == APT_KEY)
        assert (apt.name, apt.exec, apt.user, apt.timers) == (
            "apt-daily.service", "/usr/lib/apt/apt.systemd.daily update", "", ("apt-daily.timer",))
        assert (apt.active, apt.sub, apt.result, apt.restarts) == ("inactive", "dead", "success", 0)
        saved = h.store.described["apt-daily.service"]
        assert (saved.key, saved.model, saved.created_at) == (APT_KEY, "m", NOW)
        assert saved.brief == "apt-daily.service is a daemon."
        services = (await (await h.get("/api/services")).json())["services"]
        assert all(s["described"] for s in services)
        # Described once: the same definition is never sent again.
        assert (await h.post("/api/services/describe", {"keys": [FOO_KEY]})).status == 409
        assert len(analyst.requests) == 1


async def test_a_describe_that_fails_or_raises_saves_nothing(fake_jobs: FakeJobs) -> None:
    for analyst, error in ((FakeAnalyst(error="the backend left 1 service(s) undescribed"),
                            "the backend left 1 service(s) undescribed"),
                           (FakeAnalyst(raises=RuntimeError("secret")),
                            "service description failed: RuntimeError")):
        analyst.release.set()
        async with serve(scheduled_store(), analyst=analyst) as h:
            await h.get("/api/services")
            job = (await (await h.post("/api/services/describe",
                                       {"keys": [FOO_KEY]})).json())["id"]
            done = await wait_described(h, job)
        assert done["status"] == "failed" and done["error"] == error
        assert h.store.described == {}
    async with serve(scheduled_store(), analyst=FakeAnalyst()) as h:
        assert (await h.get("/api/services/describe/sd-unknown")).status == 404


@pytest.mark.parametrize("path", ["/api/services/estimate", "/api/services/describe"])
async def test_service_writes_need_csrf_and_the_same_origin(fake_jobs: FakeJobs,
                                                            path: str) -> None:
    analyst = FakeAnalyst()
    async with serve(scheduled_store(), analyst=analyst) as h:
        await h.get("/api/services")
        no_csrf = await h.post(path, {"keys": [FOO_KEY]}, headers={**AUTH, "Origin": h.origin})
        foreign = await h.post(path, {"keys": [FOO_KEY]},
                               headers={**AUTH, "X-CSRF-Token": h.csrf,
                                        "Origin": "http://evil.example"})
        assert (no_csrf.status, foreign.status) == (403, 403)
    assert analyst.requests == []


async def test_service_descriptions_against_the_real_store(fake_jobs: FakeJobs,
                                                           tmp_path: Path) -> None:
    store = Store(tmp_path / "store.sqlite3", Config())
    store.apply(Event(Kind.OBSERVATION, NOW - 120, "agent", "units.detail",
                      to_body(observation("units.detail", {"units": []}))))
    analyst = FakeAnalyst()
    analyst.release.set()
    try:
        async with serve(store, analyst=analyst) as h:
            await h.get("/api/services")
            job = (await (await h.post("/api/services/describe",
                                       {"keys": [FOO_KEY]})).json())["id"]
            assert (await wait_described(h, job))["described"] == 1
            [foo] = (await (await h.get("/api/services")).json())["services"]
        assert foo["described"]["brief"] == "foo.service is a daemon."
        assert foo["described"]["model"] == "m"
    finally:
        store.close()



async def test_a_running_describe_shows_progress_and_keeps_each_batch(
        two_services: FakeJobs) -> None:
    """20 requests took minutes with nothing to show (live, 2026-10-27): the job now carries its
    progress, and each request's answers are saved as it finishes."""
    class Halfway(FakeAnalyst):
        async def describe_services(self, units: Any, progress: Any = None) -> ServicesDescribed:
            first = [u for u in units if u.key == FOO_KEY]
            progress(1, 2, ServicesDescribed({u.key: ServiceText(f"{u.name} is a daemon.",
                                                                  "full") for u in first},
                                             "m", 1, 0, 0, 0, ""))
            await self.release.wait()
            return ServicesDescribed({u.key: ServiceText(f"{u.name} is a daemon.", "full")
                                      for u in units}, "m", 2, 0, 0, 0, "")

    analyst = Halfway()
    async with serve(scheduled_store(), analyst=analyst) as h:
        await h.get("/api/services")
        job = (await (await h.post("/api/services/describe",
                                   {"keys": [FOO_KEY, APT_KEY]})).json())["id"]
        for _ in range(50):
            running = await (await h.get(f"/api/services/describe/{job}")).json()
            if running.get("requests_done"):
                break
            await asyncio.sleep(0.01)
        assert running["status"] == "running"
        counts = (running["requests_done"], running["requests_total"], running["described"])
        assert counts == (1, 2, 1)
        assert running["started_at"] == NOW
        assert set(h.store.described) == {"foo.service"}  # saved before the job finished
        analyst.release.set()
        done = await wait_described(h, job)
    assert done["status"] == "done" and done["described"] == 2
    assert set(h.store.described) == {"foo.service", "apt-daily.service"}
