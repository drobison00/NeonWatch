"""The broker's policy, proved against a real nats-server started from the rendered config.

Every refusal below is the server's own `-ERR 'Permissions Violation ...'` (or a JetStream API
error), observed by a nats-py client. A refusal that only this module asserts proves nothing.
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import signal
import socket
import stat
import subprocess
import threading
import time
from collections.abc import Iterator
from pathlib import Path

import nats
import pytest
from nats.js.api import StreamConfig

from neonwatch import broker
from neonwatch.broker import (
    STREAM,
    SUBJECTS,
    BrokerError,
    Paths,
    Permissions,
    Role,
    inbox_prefix,
    init,
    permissions,
    render_config,
    run,
)
from neonwatch.config import Broker, Config, Retention, creds_file
from neonwatch.schema import SUBJECT

NATS_SERVER = Path(__file__).resolve().parent.parent / ".tools" / "nats-server"
GOOD = "x" * 43


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def make_config(tmp_path: Path, port: int = 4222, binary: Path = NATS_SERVER) -> Config:
    return Config(
        broker=Broker(url=f"nats://127.0.0.1:{port}", state_dir=str(tmp_path / "a" / "state"),
                      binary=str(binary)),
        retention=Retention(max_bytes=64 * 1024**2),
    )


def mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


# ---------------------------------------------------------------- the policy as data

def test_the_permission_table_is_exactly_this() -> None:
    # Pinned in full so any widening is a visible diff here, not a quiet edit to the data.
    api = "$JS.API"
    assert permissions(Role.AGENT) == Permissions(
        publish=("obs.>", "hb.>"),
        subscribe=("_INBOX.agent.>",),
    )
    assert permissions(Role.EVALUATOR) == Permissions(
        publish=("finding.>", "attest.>", "issue.>", "link.>",
                 f"{api}.STREAM.CREATE.NEONWATCH", f"{api}.STREAM.UPDATE.NEONWATCH",
                 f"{api}.STREAM.INFO.NEONWATCH",
                 f"{api}.CONSUMER.INFO.NEONWATCH.evaluator",
                 f"{api}.CONSUMER.CREATE.NEONWATCH.evaluator.obs.>",
                 f"{api}.CONSUMER.MSG.NEXT.NEONWATCH.evaluator",
                 "$JS.ACK.NEONWATCH.evaluator.>",
                 f"{api}.CONSUMER.INFO.NEONWATCH.evaluator-hb",
                 f"{api}.CONSUMER.CREATE.NEONWATCH.evaluator-hb.hb.>",
                 f"{api}.CONSUMER.MSG.NEXT.NEONWATCH.evaluator-hb",
                 "$JS.ACK.NEONWATCH.evaluator-hb.>"),
        subscribe=("_INBOX.evaluator.>",),
    )
    assert permissions(Role.VIEWER) == Permissions(
        publish=(f"{api}.CONSUMER.INFO.NEONWATCH.viewer",
                 f"{api}.CONSUMER.CREATE.NEONWATCH.viewer",
                 f"{api}.CONSUMER.CREATE.NEONWATCH.viewer.>",
                 f"{api}.CONSUMER.MSG.NEXT.NEONWATCH.viewer",
                 "$JS.ACK.NEONWATCH.viewer.>"),
        subscribe=("_INBOX.viewer.>",),
    )
    assert permissions(Role.NOTIFIER) == Permissions(
        publish=(f"{api}.CONSUMER.INFO.NEONWATCH.notifier",
                 f"{api}.CONSUMER.CREATE.NEONWATCH.notifier.issue.>",
                 f"{api}.CONSUMER.MSG.NEXT.NEONWATCH.notifier",
                 "$JS.ACK.NEONWATCH.notifier.>"),
        subscribe=("_INBOX.notifier.>",),
    )


def test_invariants_hold_for_every_role() -> None:
    for role in Role:
        allowed = permissions(role)
        assert allowed.subscribe == (f"{inbox_prefix(role)}.>",)
        assert not any(s in {">", "_INBOX.>", "$JS.API.>"} for s in allowed.publish)
        assert not any(".DELETE." in s or ".PURGE." in s or "MSG.GET" in s or "DIRECT" in s
                       for s in allowed.publish)
        creates_stream = any(s.startswith("$JS.API.STREAM.") for s in allowed.publish)
        assert creates_stream == (role is Role.EVALUATOR)
    assert inbox_prefix(Role.AGENT) == "_INBOX.agent"
    assert STREAM == "NEONWATCH"
    assert SUBJECTS == ("obs.>", "finding.>", "attest.>", "issue.>", "hb.>", "link.>")
    assert tuple(f"{prefix}.>" for prefix in SUBJECT.values()) == SUBJECTS


def test_every_event_kind_is_published_by_exactly_one_role() -> None:
    # A kind added to schema with no publisher here fails this test rather than going
    # silently unpublishable (or, worse, being granted by a wildcard).
    for kind, prefix in SUBJECT.items():
        publishers = [r for r in Role if f"{prefix}.>" in permissions(r).publish]
        assert len(publishers) == 1, (kind, publishers)
    assert [r for r in Role if "link.>" in permissions(r).publish] == [Role.EVALUATOR]


def test_unknown_role_is_refused() -> None:
    with pytest.raises(BrokerError):
        permissions("agent")  # type: ignore[arg-type]


# ---------------------------------------------------------------- render_config

PASSWORDS = {role: GOOD for role in Role}


def test_render_listens_on_loopback_only(tmp_path: Path) -> None:
    text = render_config(make_config(tmp_path, port=14222), PASSWORDS)
    # Every key the file sets, so a monitoring port, cluster, websocket, leafnode, mqtt or
    # gateway listener (or no_auth_user) could only appear as a failing diff here.
    keys = {m[1] for m in re.finditer(r"^\s*(\w+)\s*[:={]", text, re.MULTILINE)}
    assert keys == {"listen", "jetstream", "store_dir", "max_file_store", "authorization",
                    "users"}
    assert re.findall(r"^listen: .*$", text, re.MULTILINE) == ['listen: "127.0.0.1:14222"']


def test_render_jetstream_store_and_headroom(tmp_path: Path) -> None:
    config = make_config(tmp_path)
    text = render_config(config, PASSWORDS)
    store = Path(config.broker.state_dir) / "data"
    assert f"store_dir: {json.dumps(str(store))}" in text
    assert f"max_file_store: {64 * 1024**2 * 5 // 4}" in text


def test_render_every_role_with_its_permissions(tmp_path: Path) -> None:
    text = render_config(make_config(tmp_path), PASSWORDS)
    for role in Role:
        assert f'user: "{role.value}"' in text
        assert json.dumps(list(permissions(role).publish)) in text


def test_render_expands_home_in_state_dir(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    config = Config(broker=Broker(url="nats://127.0.0.1:4222"))
    text = render_config(config, PASSWORDS)
    assert json.dumps(str(tmp_path / ".local/state/neonwatch/broker/data")) in text


@pytest.mark.parametrize("url", [
    "nats://0.0.0.0:4222", "nats://10.0.0.5:4222", "nats://localhost:4222", "tls://127.0.0.1:4222",
    "nats://127.0.0.1", "nats://127.0.0.1:0", "nats://127.0.0.1:65536", "nats://127.0.0.1:4222/x",
    "nats://user:pw@127.0.0.1:4222",
])
def test_render_refuses_anything_but_a_loopback_nats_url(tmp_path: Path, url: str) -> None:
    config = Config(broker=Broker(url=url, state_dir=str(tmp_path)))
    with pytest.raises(BrokerError):
        render_config(config, PASSWORDS)


@pytest.mark.parametrize("passwords", [
    {Role.AGENT: GOOD},
    {**PASSWORDS, "intruder": GOOD},
    {**PASSWORDS, Role.VIEWER: "short"},
    {**PASSWORDS, Role.VIEWER: 'x' * 40 + '"}'},
])
def test_render_refuses_bad_password_sets(tmp_path: Path, passwords) -> None:
    with pytest.raises(BrokerError):
        render_config(make_config(tmp_path), passwords)


# ---------------------------------------------------------------- init

def test_init_creates_private_state(tmp_path: Path) -> None:
    config = make_config(tmp_path)
    paths = init(config)
    assert isinstance(paths, Paths)
    assert paths.state_dir == Path(config.broker.state_dir)
    assert mode(paths.state_dir) == 0o700
    assert mode(paths.config_file) == 0o600
    assert paths.store_dir == paths.state_dir / "data"
    assert set(paths.creds) == set(Role)
    for role, path in paths.creds.items():
        assert path == paths.state_dir / f"{role.value}.creds.json"
        assert mode(path) == 0o600
        creds = json.loads(path.read_text())
        assert set(creds) == {"user", "password"}
        assert creds["user"] == role.value
        assert len(creds["password"]) >= 43
    passwords = {role: json.loads(p.read_text())["password"] for role, p in paths.creds.items()}
    assert len(set(passwords.values())) == len(Role)
    assert paths.config_file.read_text() == render_config(config, passwords)
    assert not list(paths.state_dir.glob("*.tmp"))


def test_paths_computes_without_touching_anything(tmp_path: Path) -> None:
    # The root agent calls this to find its creds; it must create, read, write and chmod nothing.
    config = make_config(tmp_path)
    computed = broker.paths(config)
    assert not (tmp_path / "a").exists()
    assert computed == init(config)
    state = Path(config.broker.state_dir)
    assert computed.creds[Role.AGENT] == state / "agent.creds.json"
    # One naming rule, shared with the root agent through config (which never imports broker).
    assert all(computed.creds[r] == creds_file(state, r.value) for r in Role)
    os.chmod(state, 0o755)
    os.chmod(computed.creds[Role.AGENT], 0o644)
    assert broker.paths(config) == computed
    assert (mode(state), mode(computed.creds[Role.AGENT])) == (0o755, 0o644)


def test_paths_takes_creds_naming_from_config(tmp_path: Path, monkeypatch) -> None:
    # Red if broker spells the file name itself: it must follow config's rule, whatever it is.
    monkeypatch.setattr(broker, "creds_file", lambda state, role: Path(state) / f"moved-{role}")
    config = make_config(tmp_path)
    state = Path(config.broker.state_dir)
    assert broker.paths(config).creds == {r: state / f"moved-{r.value}" for r in Role}


def test_init_is_idempotent_and_rotates_on_request(tmp_path: Path) -> None:
    config = make_config(tmp_path)
    first = init(config)
    before = {r: p.read_text() for r, p in first.creds.items()}
    config_before = first.config_file.read_text()
    second = init(config)
    assert {r: p.read_text() for r, p in second.creds.items()} == before
    assert second.config_file.read_text() == config_before
    rotated = init(config, rotate=True)
    after = {r: p.read_text() for r, p in rotated.creds.items()}
    assert all(after[r] != before[r] for r in Role)
    assert rotated.config_file.read_text() != config_before


def test_init_tightens_loose_modes(tmp_path: Path) -> None:
    config = make_config(tmp_path)
    paths = init(config)
    os.chmod(paths.state_dir, 0o755)
    os.chmod(paths.creds[Role.AGENT], 0o644)
    os.chmod(paths.config_file, 0o644)
    init(config)
    assert mode(paths.state_dir) == 0o700
    assert mode(paths.creds[Role.AGENT]) == 0o600
    assert mode(paths.config_file) == 0o600


@pytest.mark.parametrize("content", [
    "not json", "[]", '{"user": "agent"}', '{"user": "viewer", "password": "' + GOOD + '"}',
    '{"user": "agent", "password": "' + GOOD + '", "extra": 1}',
    '{"user": "agent", "password": "weak"}',
])
def test_init_refuses_a_malformed_creds_file(tmp_path: Path, content: str) -> None:
    config = make_config(tmp_path)
    paths = init(config)
    paths.creds[Role.AGENT].write_text(content)
    with pytest.raises(BrokerError):
        init(config)
    init(config, rotate=True)  # rotation is the way out, and it does not read the old file


# ---------------------------------------------------------------- run

def wait_for_port(port: int, timeout: float = 10.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return
        except OSError:
            time.sleep(0.02)
    raise AssertionError(f"nothing listened on {port}")


@pytest.mark.parametrize("sig", [signal.SIGTERM, signal.SIGINT])
def test_run_forwards_signals_and_returns_the_exit_code(tmp_path: Path, sig) -> None:
    port = free_port()
    config = make_config(tmp_path, port=port)
    before = signal.getsignal(sig)

    def stop() -> None:
        wait_for_port(port)
        os.kill(os.getpid(), sig)

    killer = threading.Thread(target=stop)
    killer.start()
    code = run(config)
    killer.join()
    assert code == 0
    assert signal.getsignal(sig) is before
    assert mode(Path(config.broker.state_dir) / "nats-server.conf") == 0o600


@pytest.mark.parametrize(("script", "expected"), [
    ("exit 3", 3),
    ("kill -KILL $$", 128 + signal.SIGKILL),
])
def test_run_reports_the_server_exit(tmp_path: Path, script: str, expected: int) -> None:
    fake = tmp_path / "fake-nats-server"
    fake.write_text(f"#!/bin/sh\n{script}\n")
    fake.chmod(0o700)
    assert run(make_config(tmp_path, binary=fake)) == expected


# ---------------------------------------------------------------- the policy, on a real server

@pytest.fixture
def server(tmp_path: Path) -> Iterator[tuple[Paths, str, Path]]:
    port = free_port()
    paths = init(make_config(tmp_path, port=port))
    log = tmp_path / "nats.log"
    with log.open("w") as out:
        proc = subprocess.Popen([str(NATS_SERVER), "-c", str(paths.config_file)],
                                stdout=out, stderr=subprocess.STDOUT)
    try:
        deadline = time.monotonic() + 10
        while "Server is ready" not in log.read_text():
            assert proc.poll() is None, log.read_text()
            assert time.monotonic() < deadline, log.read_text()
            time.sleep(0.02)
        yield paths, f"nats://127.0.0.1:{port}", log
    finally:
        proc.terminate()
        proc.wait(timeout=10)


class Client:
    """One role's connection, recording every error the server sends it."""

    def __init__(self) -> None:
        self.errors: list[str] = []
        self.nc: nats.NATS

    @classmethod
    async def connect(cls, server, role: Role) -> Client:
        paths, url, _ = server
        client = cls()
        creds = json.loads(paths.creds[role].read_text())

        async def on_error(error: Exception) -> None:
            client.errors.append(str(error).lower())

        client.nc = await nats.connect(url, user=creds["user"], password=creds["password"],
                                       inbox_prefix=inbox_prefix(role), error_cb=on_error,
                                       allow_reconnect=False, max_reconnect_attempts=0)
        return client

    @property
    def js(self):
        return self.nc.jetstream(timeout=1.0)

    async def refused(self, action: str, subject: str) -> bool:
        """Whether the server refused `action` ("publish" or "subscription") on `subject`."""
        want = f'permissions violation for {action} to "{subject.lower()}"'
        for _ in range(100):
            if any(want in e for e in self.errors):
                return True
            await asyncio.sleep(0.02)
        return False

    async def publish_refused(self, subject: str, payload: bytes = b"{}") -> bool:
        await self.nc.publish(subject, payload)
        await self.nc.flush()
        return await self.refused("publish", subject)

    async def subscribe_refused(self, subject: str) -> bool:
        await self.nc.subscribe(subject)
        await self.nc.flush()
        return await self.refused("subscription", subject)

    async def close(self) -> None:
        await self.nc.close()


async def make_stream(server) -> Client:
    evaluator = await Client.connect(server, Role.EVALUATOR)
    await evaluator.js.add_stream(StreamConfig(name=STREAM, subjects=list(SUBJECTS),
                                               max_bytes=64 * 1024**2))
    return evaluator


async def test_server_listens_only_on_loopback(server) -> None:
    paths, url, log = server
    listening = [line for line in log.read_text().splitlines() if "Listening" in line]
    assert len(listening) == 1
    assert f"client connections on {url.removeprefix('nats://')}" in listening[0]
    text = log.read_text().lower()
    for other in ("http monitor", "cluster", "websocket", "leafnode", "mqtt", "gateway"):
        assert other not in text, other
    assert str(paths.store_dir / "jetstream") in log.read_text()


async def test_unauthenticated_and_wrong_password_are_refused(server) -> None:
    _, url, _ = server
    for creds in ({}, {"user": "agent", "password": GOOD}, {"user": "nobody", "password": GOOD}):
        with pytest.raises(nats.errors.Error, match="Authorization Violation"):
            await nats.connect(url, allow_reconnect=False, max_reconnect_attempts=0,
                               connect_timeout=1, **creds)


async def test_evaluator_creates_the_stream_and_publishes_judgements(server) -> None:
    evaluator = await make_stream(server)
    assert (await evaluator.js.stream_info(STREAM)).config.subjects == list(SUBJECTS)
    await evaluator.js.update_stream(StreamConfig(name=STREAM, subjects=list(SUBJECTS),
                                                  max_bytes=32 * 1024**2))
    for subject in ("attest.ctx1", "finding.disk_full", "issue.i1"):
        ack = await evaluator.js.publish(subject, b"{}")
        assert ack.stream == STREAM
    assert evaluator.errors == []
    for forbidden in ("obs.x", "hb.agent", "$JS.API.STREAM.DELETE.NEONWATCH",
                      "$JS.API.STREAM.PURGE.NEONWATCH", "$JS.API.STREAM.CREATE.OTHER",
                      "$JS.API.STREAM.MSG.GET.NEONWATCH", "$JS.API.DIRECT.GET.NEONWATCH",
                      "$JS.API.CONSUMER.CREATE.NEONWATCH.evaluator.issue.>",
                      "$JS.API.CONSUMER.CREATE.NEONWATCH.evaluator",
                      "$JS.API.CONSUMER.DURABLE.CREATE.NEONWATCH.evaluator",
                      "$JS.API.CONSUMER.MSG.NEXT.NEONWATCH.notifier"):
        assert await evaluator.publish_refused(forbidden), forbidden
    assert await evaluator.subscribe_refused("obs.>")
    await evaluator.close()


async def test_agent_publishes_observations_with_acks_and_nothing_else(server) -> None:
    evaluator = await make_stream(server)
    agent = await Client.connect(server, Role.AGENT)
    first = await agent.js.publish("obs.load", b"{}")
    beat = await agent.js.publish("hb.agent", b"{}")
    assert (first.stream, beat.stream) == (STREAM, STREAM)
    assert beat.seq == first.seq + 1
    assert agent.errors == []

    for data in ("issue.x", "attest.x", "finding.x"):
        assert await agent.publish_refused(data), data
    for api in ("$JS.API.STREAM.CREATE.NEONWATCH", "$JS.API.STREAM.DELETE.NEONWATCH",
                "$JS.API.STREAM.INFO.NEONWATCH", "$JS.API.STREAM.MSG.GET.NEONWATCH",
                "$JS.API.CONSUMER.CREATE.NEONWATCH.agent",
                "$JS.API.CONSUMER.DURABLE.CREATE.NEONWATCH.agent",
                "$JS.API.CONSUMER.DELETE.NEONWATCH.evaluator"):
        assert await agent.publish_refused(api), api
    for subject in ("obs.>", "issue.>", ">", "_INBOX.>", "_INBOX.evaluator.>"):
        assert await agent.subscribe_refused(subject), subject

    # The high-level call fails too: no stream is created, the request goes unanswered.
    with pytest.raises(nats.errors.TimeoutError):
        await agent.js.add_stream(StreamConfig(name="AGENTS", subjects=["agent.>"]))
    assert await agent.refused("publish", "$JS.API.STREAM.CREATE.AGENTS")
    await agent.close()
    await evaluator.close()


async def test_evaluator_reads_observations_through_its_durable(server) -> None:
    evaluator = await make_stream(server)
    agent = await Client.connect(server, Role.AGENT)
    await agent.js.publish("obs.load", b"one")
    await evaluator.js.publish("issue.i1", b"not for the evaluator's consumer")
    sub = await evaluator.js.pull_subscribe("obs.>", durable="evaluator", stream=STREAM)
    [msg] = await sub.fetch(1, timeout=2)
    assert (msg.subject, msg.data) == ("obs.load", b"one")
    await msg.ack_sync()
    info = await evaluator.js.consumer_info(STREAM, "evaluator")
    assert (info.num_ack_pending, info.num_pending) == (0, 0)
    assert evaluator.errors == []
    await agent.close()
    await evaluator.close()


async def test_evaluator_reads_heartbeats_through_its_second_durable(server) -> None:
    # A missing or late heartbeat is the alarm for "the machine stopped reporting".
    evaluator = await make_stream(server)
    agent = await Client.connect(server, Role.AGENT)
    await agent.js.publish("obs.load", b"o")
    await agent.js.publish("hb.agent", b"beat")
    sub = await evaluator.js.pull_subscribe("hb.>", durable="evaluator-hb", stream=STREAM)
    [msg] = await sub.fetch(1, timeout=2)
    assert (msg.subject, msg.data) == ("hb.agent", b"beat")
    await msg.ack_sync()
    info = await evaluator.js.consumer_info(STREAM, "evaluator-hb")
    assert (info.num_ack_pending, info.num_pending) == (0, 0)
    assert evaluator.errors == []
    for forbidden in ("$JS.API.CONSUMER.CREATE.NEONWATCH.evaluator-hb.obs.>",
                      "$JS.API.CONSUMER.CREATE.NEONWATCH.evaluator-hb",
                      "$JS.API.CONSUMER.CREATE.NEONWATCH.evaluator.hb.>",
                      "$JS.API.CONSUMER.CREATE.NEONWATCH.heartbeats.hb.>",
                      "$JS.API.CONSUMER.CREATE.NEONWATCH.evaluator-hb.issue.>"):
        assert await evaluator.publish_refused(forbidden), forbidden
    # Through the client: an unlisted durable name is refused at its first API call (INFO).
    with pytest.raises(nats.errors.TimeoutError):
        await evaluator.js.pull_subscribe("hb.>", durable="heartbeats", stream=STREAM)
    assert await evaluator.refused("publish", "$JS.API.CONSUMER.INFO.NEONWATCH.heartbeats")
    await agent.close()
    await evaluator.close()


async def test_only_the_evaluator_publishes_links(server) -> None:
    evaluator = await make_stream(server)
    ack = await evaluator.js.publish("link.x", b"{}")
    assert ack.stream == STREAM
    assert evaluator.errors == []
    agent = await Client.connect(server, Role.AGENT)
    viewer = await Client.connect(server, Role.VIEWER)
    notifier = await Client.connect(server, Role.NOTIFIER)
    for client in (agent, viewer, notifier):
        assert await client.publish_refused("link.x")
    # The viewer's whole-stream durable sees links; the notifier's issue durable cannot ask.
    sub = await viewer.js.pull_subscribe(">", durable="viewer", stream=STREAM)
    [msg] = await sub.fetch(1, timeout=2)
    assert msg.subject == "link.x"
    assert await notifier.publish_refused("$JS.API.CONSUMER.CREATE.NEONWATCH.notifier.link.>")
    assert (await evaluator.js.stream_info(STREAM)).state.messages == 1
    for c in (notifier, viewer, agent, evaluator):
        await c.close()


async def test_viewer_reads_the_stream_but_cannot_write_or_delete(server) -> None:
    evaluator = await make_stream(server)
    agent = await Client.connect(server, Role.AGENT)
    await agent.js.publish("obs.load", b"o")
    await evaluator.js.publish("issue.i1", b"i")
    viewer = await Client.connect(server, Role.VIEWER)
    sub = await viewer.js.pull_subscribe(">", durable="viewer", stream=STREAM)
    msgs = await sub.fetch(2, timeout=2)
    assert [m.subject for m in msgs] == ["obs.load", "issue.i1"]
    for m in msgs:
        await m.ack_sync()
    assert viewer.errors == []
    # a filtered durable of its own is also allowed
    filtered = await viewer.js.pull_subscribe("issue.>", durable="viewer", stream=STREAM)
    assert filtered is not None

    for forbidden in ("obs.x", "hb.agent", "issue.x", "attest.x", "finding.x",
                      "$JS.API.STREAM.DELETE.NEONWATCH", "$JS.API.STREAM.CREATE.NEONWATCH",
                      "$JS.API.STREAM.PURGE.NEONWATCH", "$JS.API.STREAM.MSG.DELETE.NEONWATCH",
                      "$JS.API.CONSUMER.DELETE.NEONWATCH.viewer",
                      "$JS.API.CONSUMER.CREATE.NEONWATCH.evaluator.obs.>",
                      "$JS.API.CONSUMER.MSG.NEXT.NEONWATCH.evaluator",
                      "$JS.ACK.NEONWATCH.evaluator.1.1.1.1.0"):
        assert await viewer.publish_refused(forbidden), forbidden
    for subject in ("obs.>", "_INBOX.>", "_INBOX.evaluator.>", "_INBOX.agent.>"):
        assert await viewer.subscribe_refused(subject), subject
    assert (await evaluator.js.stream_info(STREAM)).state.messages == 2
    for c in (viewer, agent, evaluator):
        await c.close()


async def test_notifier_reads_issues_only(server) -> None:
    evaluator = await make_stream(server)
    agent = await Client.connect(server, Role.AGENT)
    await agent.js.publish("obs.load", b"o")
    await evaluator.js.publish("issue.i1", b"i")
    notifier = await Client.connect(server, Role.NOTIFIER)
    sub = await notifier.js.pull_subscribe("issue.>", durable="notifier", stream=STREAM)
    [msg] = await sub.fetch(1, timeout=2)
    assert msg.subject == "issue.i1"
    await msg.ack_sync()
    assert notifier.errors == []

    for forbidden in ("$JS.API.CONSUMER.CREATE.NEONWATCH.notifier.obs.>",
                      "$JS.API.CONSUMER.CREATE.NEONWATCH.notifier",
                      "$JS.API.CONSUMER.DURABLE.CREATE.NEONWATCH.notifier",
                      "$JS.API.STREAM.DELETE.NEONWATCH", "issue.x", "obs.x"):
        assert await notifier.publish_refused(forbidden), forbidden
    await notifier.close()
    await agent.close()
    await evaluator.close()


async def test_the_filter_in_the_body_cannot_widen_the_filter_in_the_subject(server) -> None:
    # Measured against nats-server v2.15.0: the server checks the create subject's filter
    # against the request body, and refuses multi-filter bodies on the subject-based API.
    # That is what makes a subject-level grant on CONSUMER.CREATE.<stream>.<name>.<filter> a
    # read restriction rather than a naming convention.
    evaluator = await make_stream(server)
    notifier = await Client.connect(server, Role.NOTIFIER)
    subject = "$JS.API.CONSUMER.CREATE.NEONWATCH.notifier.issue.>"
    for config, code in (({"filter_subject": "obs.>"}, 10131),
                         ({"filter_subjects": ["obs.>"]}, 10137),
                         ({}, 10131)):
        body = {"stream_name": STREAM,
                "config": {"name": "notifier", "durable_name": "notifier",
                           "ack_policy": "explicit", **config}}
        reply = await notifier.nc.request(subject, json.dumps(body).encode(), timeout=2)
        assert json.loads(reply.data)["error"]["err_code"] == code
    assert notifier.errors == []
    await notifier.close()
    await evaluator.close()


async def test_a_shared_inbox_would_leak_data_which_is_why_inboxes_are_per_role(server) -> None:
    # Measured: with `_INBOX.>` granted, any role could read messages JetStream delivers to
    # another role's pull inbox. Each role's inbox is `_INBOX.<role>` and it may subscribe
    # only there; here the notifier tries to read the evaluator's deliveries and is refused.
    evaluator = await make_stream(server)
    notifier = await Client.connect(server, Role.NOTIFIER)
    assert await notifier.subscribe_refused("_INBOX.evaluator.>")
    assert await notifier.subscribe_refused("_INBOX.>")
    # ...and a client that does not use its role's inbox prefix cannot even get its acks.
    paths, url, _ = server
    creds = json.loads(paths.creds[Role.AGENT].read_text())
    errors: list[str] = []

    async def on_error(error: Exception) -> None:
        errors.append(str(error).lower())

    bare = await nats.connect(url, user=creds["user"], password=creds["password"],
                              error_cb=on_error, allow_reconnect=False)
    with pytest.raises(nats.errors.TimeoutError):
        await bare.jetstream(timeout=1.0).publish("obs.load", b"{}")
    assert any("permissions violation for subscription" in e for e in errors)
    await bare.close()
    await notifier.close()
    await evaluator.close()


def test_module_exports() -> None:
    assert broker.Role.AGENT.value == "agent"
    assert {r.value for r in Role} == {"agent", "evaluator", "viewer", "notifier"}


def test_a_missing_server_binary_says_how_to_get_one(tmp_path: Path) -> None:
    from neonwatch.config import ConfigError
    with pytest.raises(ConfigError, match=r"fetch-nats-server.*repository root"):
        run(make_config(tmp_path, binary=str(tmp_path / "no-such-nats-server")))
