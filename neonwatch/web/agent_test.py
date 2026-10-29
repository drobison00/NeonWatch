"""The local agent API, `/api/agent/v1`: who may call it, what it answers, and what it may do.

The store, live source, analyst and journal are the fakes `app_test` uses; each test starts its
own loopback server. The non-loopback cases meet the real guard twice: through a request whose
socket peer is a LAN address, and, when this host has one, over a real connection to it. The
last tests run `neonwatch mcp` and `neonwatch agent-token` as child processes against the real app
over a real store.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import shutil
import socket
import ssl
import subprocess
import sys
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any
from unittest import mock

import pytest
from aiohttp import ClientSession, web
from aiohttp.test_utils import TestClient, TestServer, make_mocked_request

from neonwatch.config import Config, Web, load
from neonwatch.schema import Event, Issue, IssueState, Kind, Severity, to_body
from neonwatch.store import Hold, ServiceDescription
from neonwatch.store import Store as SqliteStore
from neonwatch.web import agent, make_app
from neonwatch.web import app as web_app
from neonwatch.web.app_test import (
    APT_SERVICE,
    AUTH,
    NOW,
    SERVICE,
    TOKEN,
    Clock,
    FakeAnalyst,
    FakeJobs,
    FakeJournal,
    FakeLive,
    FakeStore,
    Harness,
    attestation,
    free_port,
    issue,
    journal,
    journal_entry,
    parse,
    populated,
    read_event,
    scheduled_store,
    serve,
)

AGENT_TOKEN = "a9ent-" + "y" * 40
AGENT = {"Authorization": f"Bearer {AGENT_TOKEN}", "X-Neonwatch-Agent": "claude"}
P = agent.PREFIX


@contextlib.asynccontextmanager
async def agents(store: Any = None, **options: Any) -> AsyncIterator[Harness]:
    options.setdefault("agent_token", lambda: AGENT_TOKEN)
    async with serve(store if store is not None else populated(), **options) as h:
        yield h


async def get(h: Harness, path: str, headers: dict[str, str] | None = None) -> Any:
    return await h.client.get(P + path, headers=AGENT if headers is None else headers)


async def post(h: Harness, path: str, body: Any = None,
               headers: dict[str, str] | None = None) -> Any:
    return await h.client.post(P + path, json=body,
                               headers=AGENT if headers is None else headers)


@pytest.fixture
def services(monkeypatch: pytest.MonkeyPatch) -> FakeJobs:
    fake = FakeJobs()
    monkeypatch.setattr(fake, "services",
                        lambda latest: [dict(APT_SERVICE), dict(SERVICE)] if latest else [])
    monkeypatch.setattr(web_app, "jobs", fake)
    return fake


# --- who may call it -----------------------------------------------------------------------


@pytest.mark.parametrize("headers", [
    {"X-Neonwatch-Agent": "claude"},
    {"X-Neonwatch-Agent": "claude", "Authorization": "Bearer wrong"},
    {"X-Neonwatch-Agent": "claude", "Authorization": AGENT_TOKEN},
    {"X-Neonwatch-Agent": "claude", "Authorization": f"Basic {AGENT_TOKEN}"},
    {"X-Neonwatch-Agent": "claude", "Authorization": f"Bearer {AGENT_TOKEN}x"},
    {"X-Neonwatch-Agent": "claude", "Authorization": "Bearer éé"},
    {"X-Neonwatch-Agent": "claude", "Cookie": f"neonwatch_token={AGENT_TOKEN}"},
    # The dashboard's token never works here.
    {"X-Neonwatch-Agent": "claude", **AUTH},
    {"X-Neonwatch-Agent": "claude", "Cookie": f"neonwatch_token={TOKEN}"},
])
async def test_the_agent_api_needs_the_agent_token(headers: dict[str, str]) -> None:
    async with agents() as h:
        for path in ("/summary", "/issues", "/nope"):
            resp = await get(h, path, headers)
            assert resp.status == 401, path
            assert await resp.json() == {"error": "missing or wrong agent token"}
        resp = await post(h, "/issues/i1/ack", headers=headers)
        assert resp.status == 401
        assert h.store.acks == []


async def test_the_token_is_not_accepted_as_a_query_parameter() -> None:
    async with agents() as h:
        resp = await get(h, f"/summary?token={AGENT_TOKEN}", {"X-Neonwatch-Agent": "claude"})
        assert resp.status == 401


async def test_the_agent_token_works_nowhere_but_the_agent_api() -> None:
    async with agents() as h:
        bearer = {"Authorization": f"Bearer {AGENT_TOKEN}"}
        for path in ("/api/overview", "/api/session", "/api/issues"):
            resp = await h.client.get(path, headers=bearer)
            assert resp.status == 401, path
        resp = await h.client.post("/api/issues/i1/ack",
                                   headers={**bearer, "Origin": h.origin, "X-CSRF-Token": h.csrf})
        assert resp.status == 401 and h.store.acks == []
        resp = await h.client.get(f"/?token={AGENT_TOKEN}", allow_redirects=False)
        assert resp.status == 401 and "Set-Cookie" not in resp.headers


@pytest.mark.parametrize("name", [None, "", "has space", "x" * 65, "café", "a/b", "a\tb"])
async def test_the_agent_must_name_itself(name: str | None) -> None:
    headers = {"Authorization": f"Bearer {AGENT_TOKEN}"}
    if name is not None:
        headers["X-Neonwatch-Agent"] = name
    async with agents() as h:
        resp = await get(h, "/summary", headers)
        assert resp.status == 400
        assert "X-Neonwatch-Agent must name the agent" in (await resp.json())["error"]


@pytest.mark.parametrize("name", ["claude", "mcp", "a.b_c:d-e", "x" * 64, "0"])
async def test_names_in_the_charset_are_accepted(name: str) -> None:
    async with agents() as h:
        assert (await get(h, "/summary", {**AGENT, "X-Neonwatch-Agent": name})).status == 200


async def test_a_request_from_a_browser_is_refused() -> None:
    async with agents() as h:
        for origin in (h.origin, "http://evil.example", "null"):
            resp = await get(h, "/summary", {**AGENT, "Origin": origin})
            assert resp.status == 403
            assert await resp.json() == {"error": "the agent API does not answer browsers"}


async def test_a_foreign_host_header_is_refused() -> None:
    async with agents() as h:
        resp = await get(h, "/summary", {**AGENT, "Host": "evil.example"})
        assert resp.status == 403 and await resp.json() == {"error": "unexpected Host header"}
        for host in (f"127.0.0.1:{h.port}", f"localhost:{h.port}"):
            assert (await get(h, "/summary", {**AGENT, "Host": host})).status == 200


async def test_without_a_token_reader_the_agent_api_is_off() -> None:
    async with agents(agent_token=None) as h:
        resp = await get(h, "/summary")
        assert resp.status == 503
        assert await resp.json() == {"error": "the agent API is not configured"}


async def test_an_unreadable_token_file_refuses_without_saying_why(caplog) -> None:
    def broken() -> str:
        raise OSError("/home/x/agent.token: mode 0644")

    async with agents(agent_token=broken) as h:
        resp = await get(h, "/summary")
        assert resp.status == 503
        assert await resp.json() == {"error": "the agent token cannot be read; see the service "
                                              "log"}
    assert "mode 0644" in caplog.text


async def test_an_empty_token_never_matches() -> None:
    async with agents(agent_token=lambda: "") as h:
        resp = await get(h, "/summary", {**AGENT, "Authorization": "Bearer "})
        assert resp.status == 401


async def test_a_rotated_token_takes_effect_at_once() -> None:
    current = [AGENT_TOKEN]
    async with agents(agent_token=lambda: current[0]) as h:
        assert (await get(h, "/summary")).status == 200
        current[0] = "n3w-" + "z" * 40
        assert (await get(h, "/summary")).status == 401
        resp = await get(h, "/summary", {**AGENT, "Authorization": f"Bearer {current[0]}"})
        assert resp.status == 200


async def test_the_comparison_is_constant_time(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[tuple[bytes, bytes]] = []
    real = web_app.hmac.compare_digest
    monkeypatch.setattr(web_app.hmac, "compare_digest",
                        lambda a, b: seen.append((a, b)) or real(a, b))
    async with agents() as h:
        assert (await get(h, "/summary")).status == 200
    assert (AGENT_TOKEN.encode(), AGENT_TOKEN.encode()) in seen


@pytest.mark.parametrize("remote, loopback", [
    ("127.0.0.1", True), ("127.8.9.10", True), ("::1", True), ("::ffff:127.0.0.1", True),
    ("192.168.1.20", False), ("10.0.0.1", False), ("::ffff:192.168.1.20", False),
    ("fe80::1", False), ("", False), (None, False), ("not-an-address", False),
])
def test_loopback_peers(remote: str | None, loopback: bool) -> None:
    assert agent.loopback_peer(remote) is loopback


def _from(peer: str, app: web.Application, path: str, headers: dict[str, str]) -> web.Request:
    """A request whose socket peer is `peer`, as aiohttp reads it from the transport."""
    transport = mock.Mock()
    extra = {"peername": (peer, 50123)}
    transport.get_extra_info.side_effect = lambda name, default=None: extra.get(name, default)
    return make_mocked_request("GET", path, headers=headers, app=app, transport=transport)


@pytest.mark.parametrize("password", [False, True])
async def test_a_lan_peer_is_refused_even_with_every_credential(password: bool,
                                                                 password_hash: str) -> None:
    port = 8765
    settings = (Web(port=port, password_hash=password_hash,
                    allowed_hosts=(f"monitor.lan:{port}",)) if password else Web(port=port))
    app = make_app(FakeStore(), FakeLive(), "" if password else TOKEN, Config(web=settings),
                   agent_token=lambda: AGENT_TOKEN)
    guard = app.middlewares[0]
    called: list[web.Request] = []

    async def handler(request: web.Request) -> web.Response:
        called.append(request)
        return web.Response(text="served")

    host = f"monitor.lan:{port}" if password else f"127.0.0.1:{port}"
    for extra in ({}, {"X-Forwarded-For": "127.0.0.1"}, {"X-Real-IP": "127.0.0.1"}):
        request = _from("192.168.1.20", app, f"{P}/summary", {**AGENT, "Host": host, **extra})
        resp = await guard(request, handler)
        assert resp.status == 403
        assert json.loads(resp.body) == {"error": "the agent API answers loopback clients only"}
    assert called == []
    # The same request from loopback is served.
    loop = _from("127.0.0.1", app, f"{P}/summary", {**AGENT, "Host": host})
    assert (await guard(loop, handler)).status == 200 and len(called) == 1


@pytest.fixture(scope="module")
def password_hash() -> str:
    return web_app.hash_password("correct horse battery staple")


def _lan_address() -> str | None:
    """A non-loopback IPv4 address of this host, if it has one (nothing is sent)."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
            probe.connect(("10.254.254.254", 9))
            address = probe.getsockname()[0]
    except OSError:
        return None
    return None if agent.loopback_peer(address) else address


async def test_over_a_real_lan_connection_the_agent_api_is_refused(password_hash: str) -> None:
    lan = _lan_address()
    if lan is None:
        pytest.skip("this host has no non-loopback address")
    port = free_port()
    settings = Web(port=port, password_hash=password_hash, allowed_hosts=(f"monitor.lan:{port}",))
    app = make_app(populated(), FakeLive(), "", Config(web=settings),
                   agent_token=lambda: AGENT_TOKEN, clock=lambda: NOW)
    client = TestClient(TestServer(app, host="0.0.0.0", port=port))
    await client.start_server()
    try:
        session = client.session
        host = {"Host": f"monitor.lan:{port}"}
        resp = await session.get(f"http://{lan}:{port}{P}/summary", headers={**AGENT, **host})
        assert resp.status == 403
        assert await resp.json() == {"error": "the agent API answers loopback clients only"}
        # From loopback, under a loopback name the browser routes would refuse, it answers.
        resp = await session.get(f"http://127.0.0.1:{port}{P}/summary", headers=AGENT)
        assert resp.status == 200
        resp = await session.get(f"http://127.0.0.1:{port}/api/overview")
        assert resp.status == 403  # the dashboard's own rule: only the allowed host names
    finally:
        await client.close()


# --- reads ---------------------------------------------------------------------------------


async def test_the_summary_is_compact_and_complete() -> None:
    store = populated()
    async with agents(store, judge_health=_judge) as h:
        body = await (await get(h, "/summary")).json()
    assert body["now"] == NOW
    vitals = body["vitals"]
    assert vitals["agent"]["heartbeat_age_s"] == 20 and vitals["agent"]["confined"] is False
    assert vitals["judge"] == {"reachable": True}
    assert vitals["store"] == {"ok": True, "error": ""}
    assert vitals["analyst"] == {"configured": False, "provider": "", "model": "",
                                 "reach": "local"}
    assert body["counts"] == {"critical": 1, "warn": 1, "watch": 0, "info": 0}
    assert body["held"] == 1
    assert [i["id"] for i in body["open"]] == ["i2", "i1"]
    assert body["open"][0] == {
        "id": "i2", "state": "open", "severity": "critical", "title": "i2 is bad",
        "domain": "storage", "entity": "disk:/dev/nvme0", "reasons": ["smart.critical"],
        "next_step": "systemctl status foo", "deterministic": True, "score": 5.0,
        "opened_at": NOW - 160, "updated_at": NOW - 60, "last_seen": None, "evidence": {},
        "why": "", "held_by": None, "snoozed_until": None}
    assert body["incidents"] == [{
        "id": "l1", "at": NOW - 40, "severity": "critical", "basis": "shared-entity",
        "related": 0.9, "likely_cause": "issue:i1", "confidence": 0.7, "stable": True,
        "members": ["issue:i1", "finding:smart.critical@disk:/dev/nvme0"], "issues": ["i1"],
        "findings": ["smart.critical@disk:/dev/nvme0"], "missing": []}]


async def _judge() -> dict[str, Any]:
    return {"reachable": True}


async def test_the_summary_reports_a_broken_store_and_no_heartbeat() -> None:
    store = populated()
    store.broken = True
    async with agents(store) as h:
        vitals = (await (await get(h, "/summary")).json())["vitals"]
    assert vitals["store"] == {"ok": False, "error": "StoreError"} and vitals["agent"] is None
    assert vitals["judge"] is None


async def test_issues_filter_by_state_and_say_who_holds_them() -> None:
    store = populated()
    store.hold_rows["i3"] = Hold("agent:claude", NOW - 5, None)
    async with agents(store) as h:
        everything = await (await get(h, "/issues")).json()
        held = await (await get(h, "/issues?state=acknowledged")).json()
        bad = await get(h, "/issues?state=bogus")
    assert [i["id"] for i in everything["issues"]] == ["i2", "i1", "i3", "i4"]
    assert held["issues"] == [{**held["issues"][0], "id": "i3", "state": "acknowledged",
                               "held_by": "agent:claude", "snoozed_until": None}]
    assert bad.status == 400


async def test_one_issue_carries_its_findings_attestations_and_analyses() -> None:
    async with agents() as h:
        body = await (await get(h, "/issues/i1")).json()
        missing = await get(h, "/issues/nope")
    assert body["issue"]["id"] == "i1"
    assert [f["rule"] for f in body["findings"]] == ["units.failed"]
    assert body["findings"][0] == {"at": NOW - 100, "rule": "units.failed", "severity": "warn",
                                   "title": "units.failed on unit:foo.service",
                                   "entity": "unit:foo.service",
                                   "evidence": {"probe": "units.failed"}, "next_step": ""}
    assert [a["question"] for a in body["attestations"]] == ["q.health"]
    assert set(body["attestations"][0]) == {"at", "context", "question", "entity", "severity",
                                            "answer", "cause", "next_step", "confidence",
                                            "stable"}
    assert body["analyses"] == [{"id": "an-1", "completed_at": NOW - 10, "model": "m",
                                 "question": "why?", "text": "probably foo",
                                 "suggested_checks": ["systemctl status foo"], "error": ""}]
    assert missing.status == 404


async def test_one_issue_leaves_out_another_domains_answer_to_its_reason() -> None:
    store = populated()
    store.issue_rows["i1"] = issue("i1", reasons=("units.failed", "action"))
    store.attestation_rows.append(
        (NOW - 70, attestation("action", entity="domain:cpu", context="cpu", domain="cpu")))
    async with agents(store) as h:
        body = await (await get(h, "/issues/i1")).json()
    assert [a["entity"] for a in body["attestations"]] == ["unit:foo.service"]


async def test_services_list_compactly_with_their_key_and_cached_description(
        services: FakeJobs) -> None:
    store = scheduled_store()
    foo_key = web_app.jobs.service_key(SERVICE)
    store.described["foo.service"] = ServiceDescription("foo.service", foo_key, "Foo.",
                                                        "Foo does foo.", "m9", NOW - 5, NOW - 5)
    async with agents(store) as h:
        body = await (await get(h, "/services")).json()
        one = await (await get(h, "/services/foo.service")).json()
        missing = await get(h, "/services/nope.service")
    assert body["uncached"] == 1
    listed = {s["name"]: s for s in body["services"]}
    assert set(listed["foo.service"]) == set(agent.SERVICE_FIELDS)
    assert listed["foo.service"]["key"] == foo_key
    assert listed["foo.service"]["described"] == {"brief": "Foo.", "full": "Foo does foo.",
                                                  "model": "m9", "created_at": NOW - 5}
    assert listed["apt-daily.service"]["described"] is None
    assert listed["foo.service"]["issues"] == [{"id": "i1", "severity": "warn",
                                                "title": "i1 is bad"}]
    assert one["service"]["exec"] == ["/usr/bin/foo -d"]
    assert one["service"]["file"] == "/etc/systemd/system/foo.service"
    assert missing.status == 404


async def test_scheduled_jobs_are_listed_without_their_context_copy(services: FakeJobs) -> None:
    async with agents(scheduled_store()) as h:
        body = await (await get(h, "/scheduled")).json()
    assert body["skipped"] == 2 and body["as_of"] == NOW - 120
    cron = body["jobs"][0]
    assert set(cron) == set(agent.JOB_FIELDS)
    assert cron["id"] == "cron:0123456789ab" and cron["worst"] == "warn" and cron["unstable"]


async def test_logs_are_read_with_their_keys_and_explanations() -> None:
    reader = journal()
    async with agents(read_logs=reader) as h:
        body = await (await get(h, "/logs")).json()
    assert reader.reads == 1
    assert len(body["lines"]) == 4 and body["uncached"] == 3
    assert all(line["explanation"] is None and len(line["key"]) == 16 for line in body["lines"])


# --- holds ---------------------------------------------------------------------------------


async def test_an_agent_acknowledges_an_issue_in_its_own_name() -> None:
    clock = Clock()
    async with agents(clock=clock) as h:
        stream = await h.get("/api/stream")
        await asyncio.wait_for(h.live.subscribed.wait(), 2)
        resp = await post(h, "/issues/i1/ack")
        assert resp.status == 200
        body = await resp.json()
        assert body["issue"]["state"] == "acknowledged"
        assert body["issue"]["held_by"] == "agent:claude"
        # Open dashboards are told at once, with who holds it.
        frame = parse(await read_event(stream))
        data = json.loads(frame["data"])
        assert frame["event"] == "issue" and data["id"] == "i1"
        assert data["state"] == "acknowledged" and data["held_by"] == "agent:claude"
        stream.close()
        # The dashboard's own listing says the same.
        held = await (await h.get("/api/issues?state=acknowledged")).json()
        assert {i["id"]: i["held_by"] for i in held["issues"]} == {"i1": "agent:claude",
                                                                    "i3": "operator"}
        assert (await post(h, "/issues/i1/ack", {})).status == 200  # an empty object is fine
        assert (await post(h, "/issues/i1/ack", {"note": "x"})).status == 400
    assert h.store.acks[0] == ("i1", NOW)
    rows = h.store.audit_log()
    assert [(r.agent, r.action, r.target, r.detail) for r in rows] == [
        ("claude", "ack", "i1", {}), ("claude", "ack", "i1", {})]


async def test_the_dashboards_own_holds_read_as_the_operators() -> None:
    async with serve(populated(), agent_token=lambda: AGENT_TOKEN) as h:
        acked = await (await h.post("/api/issues/i1/ack")).json()
        assert acked["issue"]["held_by"] == "operator"
        listed = await (await h.get("/api/issues?state=open")).json()
        assert all(i["held_by"] is None for i in listed["issues"])
        overview = await (await h.get("/api/overview")).json()
        assert overview["open"]["critical"][0]["held_by"] is None
        detail = await (await h.get("/api/issues/i1")).json()
        assert detail["issue"]["held_by"] == "operator"
        domain = await (await h.get("/api/domains/services")).json()
        assert {i["id"]: i["held_by"] for i in domain["issues"]}["i1"] == "operator"
    assert h.store.audit_rows == []  # the operator's writes are not the agent audit


async def test_an_agent_snoozes_until_a_time_or_for_a_span() -> None:
    async with agents() as h:
        resp = await post(h, "/issues/i1/snooze", {"for_s": 3600})
        assert resp.status == 200
        body = (await resp.json())["issue"]
        assert body["state"] == "snoozed" and body["snoozed_until"] == NOW + 3600
        assert body["held_by"] == "agent:claude"
        resp = await post(h, "/issues/i2/snooze", {"until": NOW + 60})
        assert resp.status == 200 and (await resp.json())["issue"]["snoozed_until"] == NOW + 60
    assert h.store.snoozes == [("i1", NOW + 3600), ("i2", NOW + 60)]
    assert [(r.action, r.target, r.detail) for r in reversed(h.store.audit_log())] == [
        ("snooze", "i1", {"until": NOW + 3600}), ("snooze", "i2", {"until": NOW + 60})]


@pytest.mark.parametrize("body, status", [
    ({}, 400), ({"until": NOW + 60, "for_s": 60}, 400), ({"for_s": 0}, 400),
    ({"for_s": 7 * 86400 + 1}, 400), ({"for_s": True}, 400), ({"for_s": "60"}, 400),
    ({"until": NOW}, 400), ({"until": NOW + 7 * 86400 + 1}, 400), ({"until": None}, 400),
    ({"when": 5}, 400), ([], 400),
])
async def test_a_snooze_out_of_bounds_is_refused_and_not_audited(body: Any, status: int) -> None:
    async with agents() as h:
        resp = await post(h, "/issues/i1/snooze", body)
        assert resp.status == status
    assert h.store.snoozes == [] and h.store.audit_rows == []


async def test_holding_an_unknown_or_resolved_issue_is_refused_and_not_audited() -> None:
    async with agents() as h:
        assert (await post(h, "/issues/nope/ack")).status == 404
        assert (await post(h, "/issues/i4/ack")).status == 409
        assert (await post(h, "/issues/i4/snooze", {"for_s": 60})).status == 409
    assert h.store.audit_rows == []


# --- the write limit -----------------------------------------------------------------------


async def test_writes_are_limited_per_agent_and_in_total() -> None:
    clock = Clock()
    async with agents(clock=clock) as h:
        for n in range(agent.WRITES_PER_AGENT):
            assert (await post(h, "/issues/i1/ack")).status == 200, n
        resp = await post(h, "/issues/i1/ack")
        assert resp.status == 429
        assert "30 a minute per agent and 60 in all; try again in 60 s" in (
            await resp.json())["error"]
        other = {**AGENT, "X-Neonwatch-Agent": "other"}
        for n in range(agent.WRITES_TOTAL - agent.WRITES_PER_AGENT):
            assert (await post(h, "/issues/i1/ack", headers=other)).status == 200, n
        assert (await post(h, "/issues/i1/ack", headers=other)).status == 429  # the total
        assert (await get(h, "/summary")).status == 200  # reads are not limited
        clock.now += agent.WRITE_WINDOW_S
        assert (await post(h, "/issues/i1/ack")).status == 200
    assert len(h.store.audit_rows) == agent.WRITES_TOTAL + 1


def test_the_limit_counts_nothing_it_refuses_and_forgets_old_writes() -> None:
    limit = agent.WriteLimit(per_agent=2, total=3, window_s=10)
    assert [limit.take("a", t) for t in (0, 1, 2)] == [0, 0, 8]
    assert limit.take("b", 5) == 0
    assert limit.take("c", 5) == 5  # the total: the oldest write leaves at t=10
    assert limit.take("a", 10.5) == 0 and limit.take("c", 11.5) == 0
    assert set(limit.times) == {"a", "b", "c"}
    assert limit.take("d", 100) == 0 and set(limit.times) == {"d"}


# --- LLM jobs ------------------------------------------------------------------------------


async def test_an_agent_estimates_and_starts_an_analysis_without_a_confirm_step() -> None:
    analyst = FakeAnalyst()
    async with agents(analyst=analyst) as h:
        estimate = await (await post(h, "/jobs/analysis/estimate",
                                     {"subjects": ["issue:i1"], "question": "why?"})).json()
        assert estimate["estimate"]["chars"] == 1234 and estimate["subjects"] == ["issue:i1"]
        assert h.store.audit_rows == []  # an estimate sends nothing and writes nothing
        resp = await post(h, "/jobs/analysis", {"subjects": ["issue:i1"], "question": "why?"})
        assert resp.status == 202
        started = await resp.json()
        job = started["id"]
        assert started["kind"] == "analysis" and started["status"] == "running"
        assert started["estimate"] == {"chars": 1234, "approx_tokens": 309,
                                       "backend": "openai-compatible", "model": "m",
                                       "url_host": "127.0.0.1", "remote": False}
        running = await (await get(h, f"/jobs/{job}")).json()
        assert running["kind"] == "analysis" and running["status"] == "running"
        analyst.release.set()
        for _ in range(200):
            done = await (await get(h, f"/jobs/{job}")).json()
            if done["status"] != "running":
                break
            await asyncio.sleep(0.01)
        assert done["status"] == "done" and done["text"] == "it is foo"
    (row,) = h.store.audit_log()
    assert (row.agent, row.action, row.target) == ("claude", "start_analysis", job)
    assert row.detail == {"chars": 1234, "requests": 1, "url_host": "127.0.0.1",
                          "remote": False, "model": "m", "subjects": ["issue:i1"],
                          "question": "why?"}


async def test_one_analysis_slot_rule_holds_for_agents_too(monkeypatch) -> None:
    monkeypatch.setattr(web_app, "MAX_RUNNING", 1)
    analyst = FakeAnalyst()
    async with agents(analyst=analyst) as h:
        assert (await post(h, "/jobs/analysis", {"subjects": ["issue:i1"]})).status == 202
        resp = await post(h, "/jobs/analysis", {"subjects": ["issue:i1"]})
        assert resp.status == 429
        # The dashboard shares the slots.
        assert (await h.post("/api/analyses", {"subjects": ["issue:i1"]})).status == 429
        analyst.release.set()
    assert len(h.store.audit_rows) == 1


async def test_an_agent_describes_every_undescribed_service(services: FakeJobs) -> None:
    analyst = FakeAnalyst()
    store = scheduled_store()
    async with agents(store, analyst=analyst) as h:
        estimate = await (await post(h, "/jobs/describe/estimate",
                                     {"keys": "all_uncached"})).json()
        assert len(estimate["keys"]) == 2 and estimate["estimate"]["services"] == 2
        resp = await post(h, "/jobs/describe", {"keys": "all_uncached"})
        assert resp.status == 202
        started = await resp.json()
        assert started["kind"] == "describe" and started["keys"] == 2
        assert started["estimate"] == {**estimate["estimate"]}
        again = await post(h, "/jobs/describe", {"keys": "all_uncached"})
        assert again.status == 429  # one description job at a time
        analyst.release.set()
        done = await _finished(h, started["id"])
        assert done["kind"] == "describe" and done["status"] == "done"
        assert done["described"] == 2 and done["requests_done"] == 0
        assert {"requests_total", "started_at", "error", "requests_done"} <= set(done)
        nothing = await post(h, "/jobs/describe", {"keys": "all_uncached"})
        assert nothing.status == 409
    (row,) = h.store.audit_log()
    assert row.action == "start_describe" and row.target == started["id"]
    assert row.detail == {"chars": 600, "requests": 1, "url_host": "127.0.0.1",
                          "remote": False, "model": "m", "keys": 2}


async def test_an_agent_describes_named_services_only(services: FakeJobs) -> None:
    analyst = FakeAnalyst()
    analyst.release.set()
    foo_key = web_app.jobs.service_key(SERVICE)
    async with agents(scheduled_store(), analyst=analyst) as h:
        started = await (await post(h, "/jobs/describe", {"keys": [foo_key]})).json()
        assert started["keys"] == 1
        assert [u.name for u in analyst.requests[0]] == ["foo.service"]
        assert (await post(h, "/jobs/describe", {"keys": ["nothex"]})).status == 400
        assert (await post(h, "/jobs/describe", {"keys": "everything"})).status == 400


async def test_an_agent_explains_every_unexplained_kind_of_log_line() -> None:
    analyst = FakeAnalyst()
    reader = journal()
    async with agents(analyst=analyst, read_logs=reader) as h:
        estimate = await (await post(h, "/jobs/explain/estimate",
                                     {"keys": "all_uncached"})).json()
        assert estimate["estimate"]["templates"] == 3
        resp = await post(h, "/jobs/explain", {"keys": "all_uncached"})
        assert resp.status == 202
        started = await resp.json()
        assert started["kind"] == "explain" and started["keys"] == 3
        assert started["estimate"]["chars"] == 297
        # It read the journal itself; the dashboard's last listing is left alone.
        assert reader.reads == 2 and h.store.touched == []
        assert (await post(h, "/jobs/explain", {"keys": "all_uncached"})).status == 429
        analyst.release.set()
        done = await _finished(h, started["id"])
        assert done["kind"] == "explain" and done["explained"] == 3
        listed = await (await get(h, "/logs")).json()
        assert listed["uncached"] == 0
        assert (await post(h, "/jobs/explain", {"keys": "all_uncached"})).status == 409
    (row,) = h.store.audit_log()
    assert row.action == "start_explain" and row.detail["keys"] == 3
    assert row.detail["chars"] == 297 and row.detail["requests"] == 1


async def test_named_log_keys_must_be_in_the_journal_now() -> None:
    analyst = FakeAnalyst()
    reader = FakeJournal(journal_entry("Started foo.", ident="systemd"))
    async with agents(analyst=analyst, read_logs=reader) as h:
        key = (await (await get(h, "/logs")).json())["lines"][0]["key"]
        assert (await post(h, "/jobs/explain", {"keys": ["0" * 16]})).status == 409
        resp = await post(h, "/jobs/explain/estimate", {"keys": [key]})
        assert (await resp.json())["keys"] == [key]


async def test_without_an_analyst_the_job_routes_refuse_and_count_no_write() -> None:
    async with agents() as h:
        for path in ("/jobs/analysis", "/jobs/analysis/estimate", "/jobs/describe",
                     "/jobs/describe/estimate", "/jobs/explain", "/jobs/explain/estimate"):
            resp = await post(h, path, {"keys": "all_uncached"})
            assert resp.status == 503, path
        assert h.store.audit_rows == []


async def test_an_unknown_job_is_not_found() -> None:
    async with agents() as h:
        for job in ("an-nope", "lx-nope", "sd-nope", "zz-1"):
            assert (await get(h, f"/jobs/{job}")).status == 404, job


async def test_a_dashboard_job_can_be_followed_by_an_agent() -> None:
    analyst = FakeAnalyst()
    async with agents(analyst=analyst, read_logs=journal()) as h:
        keys = [line["key"] for line in (await (await h.get("/api/logs")).json())["lines"]]
        job = (await (await h.post("/api/logs/explain", {"keys": keys})).json())["id"]
        status = await (await get(h, f"/jobs/{job}")).json()
        assert status["kind"] == "explain" and status["status"] == "running"
        analyst.release.set()


async def _finished(h: Harness, job: str) -> dict[str, Any]:
    for _ in range(200):
        body = await (await get(h, f"/jobs/{job}")).json()
        if body["status"] != "running":
            return body
        await asyncio.sleep(0.01)
    raise AssertionError("the job did not finish")


# --- the audit log -------------------------------------------------------------------------


async def test_the_audit_log_is_listed_and_filtered() -> None:
    clock = Clock()
    async with agents(clock=clock) as h:
        await post(h, "/issues/i1/ack")
        clock.now += 10
        await post(h, "/issues/i2/snooze", {"for_s": 60},
                   headers={**AGENT, "X-Neonwatch-Agent": "mcp"})
        everything = await (await get(h, "/audit")).json()
        mine = await (await get(h, "/audit?agent=claude")).json()
        recent = await (await get(h, f"/audit?since={NOW + 5}&limit=1")).json()
        for query in ("limit=0", "limit=501", "limit=x", "agent=a%20b", "since=x"):
            assert (await get(h, f"/audit?{query}")).status == 400, query
    assert [(e["agent"], e["action"], e["target"]) for e in everything["entries"]] == [
        ("mcp", "snooze", "i2"), ("claude", "ack", "i1")]
    assert set(everything["entries"][0]) == {"id", "at", "agent", "action", "target", "detail"}
    assert [e["target"] for e in mine["entries"]] == ["i1"]
    assert [e["target"] for e in recent["entries"]] == ["i2"]


async def test_a_held_issue_stays_held_in_the_agent_view_when_severity_is_unchanged() -> None:
    store = populated()
    async with agents(store) as h:
        await post(h, "/issues/i2/ack")
        body = await (await get(h, "/issues/i2")).json()
    assert body["issue"]["state"] == IssueState.ACKNOWLEDGED.value
    assert body["issue"]["severity"] == Severity.CRITICAL.value
    assert body["issue"]["held_by"] == "agent:claude"


# --- `neonwatch mcp` against the real app ---------------------------------------------------
#
# The MCP server and the token command run as the real CLI in a child process, speaking stdio,
# against this app over a real store; `web` may not import `mcp`, and need not.


def cli(*args: str, stdin: str = "", home: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run([sys.executable, "-I", "-B", "-m", "neonwatch.launch", *args],
                          input=stdin, capture_output=True, text=True, timeout=60, cwd="/",
                          env={"HOME": str(home), "PATH": "/usr/bin:/bin"})


def rpc_lines(*calls: tuple[str, dict[str, Any]]) -> str:
    return "".join(json.dumps({"jsonrpc": "2.0", "id": n, "method": "tools/call",
                               "params": {"name": name, "arguments": arguments}}) + "\n"
                   for n, (name, arguments) in enumerate(calls))


@contextlib.asynccontextmanager
async def real_dashboard(tmp_path: Path, tls: tuple[Path, Path] | None = None
                         ) -> AsyncIterator[tuple[Path, SqliteStore]]:
    """The real app over a real store, its config file, and the token `agent-token` made."""
    port = free_port()
    state = tmp_path / "state"
    web_table = f"[web]\nport = {port}\n"
    if tls:
        web_table += f'tls_cert = "{tls[0]}"\ntls_key = "{tls[1]}"\n'
    config_file = tmp_path / "config.toml"
    config_file.write_text(web_table + f'[store]\npath = "{state / "store.sqlite3"}"\n')
    config = load(config_file)
    store = SqliteStore(Path(config.store.path), config)
    found = Issue(id="i1", state=IssueState.OPEN, severity=Severity.WARN, title="disk filling",
                  domain="storage", entity="disk:/", opened_at=1.0, updated_at=2.0,
                  deterministic=True, reasons=("disk.full",), next_step="df -h /")
    store.apply(Event(Kind.ISSUE, 2.0, "evaluator", "issue.i1", to_body(found)))
    made = await asyncio.to_thread(cli, "agent-token", "--config", str(config_file),
                                   home=tmp_path)
    assert made.returncode == 0 and made.stdout.startswith("made the agent token at "), made
    analyst = FakeAnalyst()
    analyst.release.set()
    token_file = state / "agent.token"
    app = make_app(store, FakeLive(), TOKEN, config, analyst,
                   agent_token=lambda: token_file.read_text().strip())
    context = None
    if tls:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(*tls)
    stop = await web_app.start(app, "127.0.0.1", port, ssl_context=context)
    try:
        yield config_file, store
    finally:
        await stop()
        store.close()


async def test_neonwatch_mcp_end_to_end_through_the_real_app(tmp_path: Path) -> None:
    async with real_dashboard(tmp_path) as (config_file, store):
        ran = await asyncio.to_thread(
            cli, "mcp", "--agent", "e2e", "--config", str(config_file), home=tmp_path,
            stdin=json.dumps({"jsonrpc": "2.0", "id": "a", "method": "initialize"}) + "\n"
            + rpc_lines(("status", {}), ("acknowledge_issue", {"id": "i1"}),
                        ("list_issues", {"state": "acknowledged"}),
                        ("start_analysis", {"subjects": ["issue:i1"], "question": "why?"}),
                        ("audit", {}), ("get_issue", {"id": "nope"})))
        assert ran.returncode == 0, ran.stderr
        replies = [json.loads(line) for line in ran.stdout.splitlines()]
        assert replies[0]["result"]["serverInfo"]["name"] == "neonwatch"
        status, acked, held, started, audit, missing = (r["result"] for r in replies[1:])
        assert status["structuredContent"]["counts"]["warn"] == 1
        assert acked["structuredContent"]["issue"]["held_by"] == "agent:e2e"
        assert [i["id"] for i in held["structuredContent"]["issues"]] == ["i1"]
        assert started["structuredContent"]["kind"] == "analysis"
        assert started["structuredContent"]["estimate"]["url_host"] == "127.0.0.1"
        assert [(e["agent"], e["action"]) for e in audit["structuredContent"]["entries"]] == [
            ("e2e", "start_analysis"), ("e2e", "ack")]
        assert missing == {"content": [{"type": "text", "text": "HTTP 404: not found"}],
                           "isError": True}
        assert store.holds()["i1"].by == "agent:e2e"
        token = (tmp_path / "state" / "agent.token").read_text().strip()
        assert token not in ran.stdout + ran.stderr


async def test_a_rotated_token_works_at_once_and_the_old_one_stops(tmp_path: Path) -> None:
    async with real_dashboard(tmp_path) as (config_file, _):
        old = (tmp_path / "state" / "agent.token").read_text().strip()
        rotated = await asyncio.to_thread(cli, "agent-token", "--rotate", "--config",
                                          str(config_file), home=tmp_path)
        assert rotated.returncode == 0 and "rotated" in rotated.stdout
        assert old not in rotated.stdout
        ran = await asyncio.to_thread(cli, "mcp", "--config", str(config_file), home=tmp_path,
                                      stdin=rpc_lines(("status", {})))
        assert "isError" not in json.loads(ran.stdout)["result"]
        port = load(config_file).web.port
        stale = {"Authorization": f"Bearer {old}", "X-Neonwatch-Agent": "x"}
        async with ClientSession() as session, session.get(
                f"http://127.0.0.1:{port}{P}/summary", headers=stale) as resp:
            assert resp.status == 401


@pytest.mark.skipif(shutil.which("openssl") is None, reason="openssl makes the certificate")
async def test_neonwatch_mcp_end_to_end_over_tls(tmp_path: Path) -> None:
    cert, key = tmp_path / "cert.pem", tmp_path / "key.pem"
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
         "-nodes", "-days", "2", "-subj", "/CN=monitor.lan", "-keyout", str(key), "-out",
         str(cert), "-addext", "subjectAltName=DNS:monitor.lan"],
        check=True, capture_output=True, timeout=30)
    key.chmod(0o600)
    async with real_dashboard(tmp_path, tls=(cert, key)) as (config_file, _):
        ran = await asyncio.to_thread(cli, "mcp", "--config", str(config_file), home=tmp_path,
                                      stdin=rpc_lines(("status", {})))
        result = json.loads(ran.stdout)["result"]
        assert "isError" not in result, result
        assert result["structuredContent"]["counts"]["warn"] == 1
