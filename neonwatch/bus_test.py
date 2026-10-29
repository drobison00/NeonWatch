"""The bus against a real nats-server: ordered, acknowledged, resumable, and strict at the edges.

Every test that talks to a broker starts its own `.tools/nats-server` on a free loopback port with
its store in `tmp_path`, and stops it afterwards.
"""

from __future__ import annotations

import asyncio
import json
import os
import socket
import subprocess
import time
from pathlib import Path

import nats
import pytest

from neonwatch.bus import STREAM, SUBJECTS, Bus, BusError, connect
from neonwatch.config import Config, Retention
from neonwatch.schema import (
    SUBJECT,
    Event,
    Kind,
    Observation,
    SchemaError,
    encode_event,
    to_body,
)

BINARY = Path(__file__).resolve().parent.parent / ".tools" / "nats-server"


def free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


class Server:
    """One nats-server process that can be stopped and started again on the same port and store."""

    def __init__(self, args: list[str], port: int, log: Path) -> None:
        self.args, self.port, self.log = args, port, log
        self.proc: subprocess.Popen | None = None

    @property
    def url(self) -> str:
        return f"nats://127.0.0.1:{self.port}"

    def start(self) -> None:
        with self.log.open("ab") as log:
            self.proc = subprocess.Popen([str(BINARY), *self.args], stdout=log,
                                         stderr=subprocess.STDOUT)
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            if self.proc.poll() is not None:
                pytest.fail(f"nats-server exited: {self.log.read_text()}")
            try:
                socket.create_connection(("127.0.0.1", self.port), timeout=0.2).close()
                return
            except OSError:
                time.sleep(0.05)
        pytest.fail(f"nats-server did not accept connections: {self.log.read_text()}")

    def stop(self) -> None:
        if self.proc is not None and self.proc.poll() is None:
            self.proc.terminate()
            self.proc.wait(timeout=10)

    def restart(self) -> None:
        self.stop()
        self.start()


@pytest.fixture
def server(tmp_path):
    port = free_port()
    running = Server(["-js", "-a", "127.0.0.1", "-p", str(port), "-sd", str(tmp_path / "js")],
                     port, tmp_path / "nats.log")
    running.start()
    yield running
    running.stop()


@pytest.fixture
def auth_server(tmp_path):
    port = free_port()
    conf = tmp_path / "auth.conf"
    conf.write_text(f'listen: 127.0.0.1:{port}\n'
                    f'jetstream {{ store_dir: "{tmp_path / "js-auth"}" }}\n'
                    'authorization { user: "neonwatch", password: "right-password" }\n')
    running = Server(["-c", str(conf)], port, tmp_path / "nats-auth.log")
    running.start()
    yield running
    running.stop()


@pytest.fixture
async def bus(server):
    connected = await connect(server.url, None)
    await connected.ensure_streams(Config())
    yield connected
    await connected.close()


def observation(i: int, probe: str = "load") -> Event:
    return Event(Kind.OBSERVATION, float(i), "test", f"obs.{probe}",
                 to_body(Observation(probe=probe, data={"i": i}, cpu_ms=1)))


async def next_event(subscription, within: float = 5.0) -> Event:
    return await asyncio.wait_for(anext(subscription), within)


async def stream_info(url: str):
    nc = await nats.connect(url)
    try:
        return await nc.jetstream().stream_info(STREAM)
    finally:
        await nc.close()


def creds_file(tmp_path: Path, content: str, mode: int = 0o600) -> Path:
    path = tmp_path / "creds.json"
    path.write_text(content)
    path.chmod(mode)
    return path


# --- publish and subscribe --------------------------------------------------------------------


async def test_publish_returns_increasing_stream_sequences(bus):
    sequences = [await bus.publish(observation(i)) for i in range(5)]
    assert sequences == [1, 2, 3, 4, 5]


async def test_a_subscriber_receives_events_in_publish_order(bus):
    events = [observation(i, probe=f"p{i}") for i in range(5)]
    for event in events:
        await bus.publish(event)
    async with bus.subscribe("obs.>", "reader") as subscription:
        received = [await next_event(subscription) for _ in events]
    assert received == events


async def test_a_subscription_sees_only_its_subject(bus):
    await bus.publish(observation(1, probe="disk"))
    await bus.publish(observation(2, probe="load"))
    async with bus.subscribe("obs.load", "load-only") as subscription:
        assert await next_event(subscription) == observation(2, probe="load")
        with pytest.raises(TimeoutError):
            await next_event(subscription, within=1.5)


async def test_the_whole_stream_is_read_with_a_bare_wildcard(bus):
    # The viewer reads everything with `>`: nats-py then sends no filter token (broker policy).
    events = [observation(1), Event(Kind.HEARTBEAT, 2.0, "test", "hb.agent", {}),
              Event(Kind.FINDING, 3.0, "test", "finding.disk", {})]
    for event in events:
        await bus.publish(event)
    async with bus.subscribe(">", "viewer") as subscription:
        assert [await next_event(subscription) for _ in events] == events


async def test_a_durable_resumes_at_the_next_unread_event(server, bus):
    events = [observation(i) for i in range(6)]
    for event in events:
        await bus.publish(event)
    first = []
    async with bus.subscribe("obs.>", "store") as subscription:
        async for event in subscription:
            first.append(event)
            if len(first) == 3:
                break
    await bus.close()

    again = await connect(server.url, None)
    try:
        async with again.subscribe("obs.>", "store") as subscription:
            rest = [await next_event(subscription) for _ in range(3)]
            with pytest.raises(TimeoutError):
                await next_event(subscription, within=1.5)
    finally:
        await again.close()
    assert first + rest == events  # no duplicates, no gaps


async def test_a_durable_resumes_across_a_broker_restart(server, bus):
    events = [observation(i) for i in range(4)]
    await bus.publish(events[0])
    await bus.publish(events[1])
    subscription = bus.subscribe("obs.>", "restart")
    assert await next_event(subscription) == events[0]

    server.restart()  # same port, same store: the client reconnects on its own

    # A publish written before the client notices the restart is lost with the old socket, and
    # says so: it raises after the ack timeout rather than returning (measured). Retrying is the
    # caller's job; a heartbeat stands in for that here, off the subscription's subject.
    failures = []
    for _ in range(5):
        try:
            await bus.publish(Event(Kind.HEARTBEAT, 1.0, "test", "hb.agent", {}))
            break
        except BusError as lost:
            failures.append(lost)
    else:
        pytest.fail(f"never reconnected: {failures}")
    assert all("timeout" in str(failure) for failure in failures)

    await bus.publish(events[2])
    await bus.publish(events[3])
    assert [await next_event(subscription) for _ in range(3)] == events[1:]
    await subscription.close()


async def test_an_error_in_the_consumer_redelivers_the_event_it_held(bus):
    events = [observation(i) for i in range(3)]
    for event in events:
        await bus.publish(event)
    with pytest.raises(RuntimeError):
        async with bus.subscribe("obs.>", "fragile") as subscription:
            async for event in subscription:
                if event == events[1]:
                    raise RuntimeError("processing failed")
    async with bus.subscribe("obs.>", "fragile") as subscription:
        assert [await next_event(subscription) for _ in range(2)] == events[1:]


async def test_closing_a_subscription_is_idempotent_and_ends_iteration(bus):
    await bus.publish(observation(1))
    subscription = bus.subscribe("obs.>", "closer")
    await subscription.close()  # before it ever fetched
    await subscription.close()
    assert [event async for event in subscription] == []


# --- what the bus refuses ---------------------------------------------------------------------


async def test_a_corrupt_message_is_acknowledged_skipped_and_counted(server, bus):
    raw = await nats.connect(server.url)
    try:
        js = raw.jetstream()
        await js.publish("obs.raw", b"this is not json", stream=STREAM)
        # A well-formed finding, delivered on an observation subject: decodes, but lies about
        # where it came from, and broker permissions are written against the subject.
        finding = Event(Kind.FINDING, 1.0, "test", "finding.disk", {})
        await js.publish("obs.smuggled", encode_event(finding), stream=STREAM)
    finally:
        await raw.close()
    good = observation(7)
    await bus.publish(good)

    assert bus.rejected == 0 and bus.last_rejection == ""
    async with bus.subscribe("obs.>", "strict") as subscription:
        assert await next_event(subscription) == good
    assert bus.rejected == 2
    assert "obs.smuggled" in bus.last_rejection and "finding.disk" in bus.last_rejection

    # Rejections were acknowledged: the durable does not see them again.
    async with bus.subscribe("obs.>", "strict") as subscription:
        with pytest.raises(TimeoutError):
            await next_event(subscription, within=1.5)
    assert bus.rejected == 2


async def publish_raw(url: str, subject: str, payload: bytes) -> None:
    raw = await nats.connect(url)
    try:
        await raw.jetstream().publish(subject, payload, stream=STREAM)
    finally:
        await raw.close()


NAN_TIME = (b'{"at":NaN,"body":{},"kind":"heartbeat","source":"agent",'
            b'"subject":"hb.agent","v":1}')


@pytest.mark.parametrize("payload, reason", [
    (b"[" * 200_000, "not JSON"),  # nesting deep enough to raise RecursionError in json
    (NAN_TIME, "not JSON"),
], ids=["deep-nesting", "nan-time"])
async def test_a_hostile_payload_is_skipped_and_the_subscription_lives(server, bus, payload,
                                                                        reason):
    await publish_raw(server.url, "hb.agent", payload)
    good = Event(Kind.HEARTBEAT, 1.0, "agent", "hb.agent", {})
    await bus.publish(good)
    async with bus.subscribe("hb.>", "hostile") as subscription:
        assert await next_event(subscription) == good
    assert bus.rejected == 1
    assert "hb.agent" in bus.last_rejection and reason in bus.last_rejection


async def test_an_unexpected_decoder_error_is_skipped_and_counted(server, bus, monkeypatch):
    import neonwatch.bus as module
    real = module.decode_event

    def fragile(data: bytes) -> Event:
        if data == b"boom":
            raise RuntimeError("the decoder broke")
        return real(data)

    monkeypatch.setattr(module, "decode_event", fragile)
    await publish_raw(server.url, "obs.boom", b"boom")
    good = observation(1)
    await bus.publish(good)
    async with bus.subscribe("obs.>", "survivor") as subscription:
        assert await next_event(subscription) == good
    assert bus.rejected == 1
    assert "RuntimeError" in bus.last_rejection and "the decoder broke" in bus.last_rejection


async def test_publish_refuses_an_event_whose_subject_does_not_match_its_kind(bus):
    wrong = Event(Kind.FINDING, 1.0, "test", "obs.load", {})
    with pytest.raises(SchemaError):
        await bus.publish(wrong)


@pytest.mark.parametrize("subject", ["obs.*", "obs.>", "obs.a.>", "obs..x", "obs.", "hb"])
async def test_publish_refuses_a_subject_that_is_not_one_literal_address(bus, server, subject):
    # JetStream would store `obs.*` and `obs.>` verbatim (measured), so the bus refuses them.
    with pytest.raises(BusError):
        await bus.publish(Event(Kind.OBSERVATION if subject != "hb" else Kind.HEARTBEAT, 1.0,
                                "test", subject, {}))
    assert (await stream_info(server.url)).state.messages == 0


@pytest.mark.parametrize("subject", ["nope.>", "obs.>.x", "obs.a*", "", "obs. x", "*", ">.obs"])
async def test_subscribe_refuses_a_subject_outside_the_stream(bus, subject):
    with pytest.raises(BusError):
        await next_event(bus.subscribe(subject, "any"))


@pytest.mark.parametrize("durable", ["", "has.dot", "has space", "wild*", "wild>"])
async def test_subscribe_refuses_a_bad_durable_name(bus, durable):
    with pytest.raises(BusError):
        await next_event(bus.subscribe("obs.>", durable))


async def test_a_durable_cannot_be_rebound_to_a_different_subject(bus):
    await bus.publish(observation(1))
    async with bus.subscribe("obs.>", "bound") as subscription:
        await next_event(subscription)
    # nats-py would bind silently and keep delivering `obs.>` (measured); the bus refuses.
    with pytest.raises(BusError, match="obs"):
        await next_event(bus.subscribe("hb.>", "bound"))


async def test_a_closed_bus_raises_bus_errors(server):
    closed = await connect(server.url, None)
    await closed.ensure_streams(Config())
    subscription = closed.subscribe("obs.>", "late")
    await closed.close()
    with pytest.raises(BusError):
        await closed.publish(observation(1))
    with pytest.raises(BusError):
        await closed.ensure_streams(Config())
    with pytest.raises(BusError):
        await next_event(subscription)


async def test_a_broken_subscription_raises_a_bus_error_mid_stream(server):
    bus = await connect(server.url, None)
    await bus.ensure_streams(Config())
    subscription = bus.subscribe("obs.>", "broken")
    await bus.publish(observation(1))
    assert await next_event(subscription) == observation(1)
    await bus.close()
    with pytest.raises(BusError):
        await next_event(subscription)


# --- the stream -------------------------------------------------------------------------------


async def test_the_stream_carries_the_retention_from_config(server):
    bus = await connect(server.url, None)
    try:
        await bus.ensure_streams(Config(retention=Retention(max_age_s=3600, max_bytes=1 << 20)))
        info = await stream_info(server.url)
        assert info.config.name == STREAM
        # The stream follows the schema: every kind's prefix, and nothing else.
        assert sorted(info.config.subjects) == sorted(f"{prefix}.>" for prefix in SUBJECT.values())
        assert sorted(info.config.subjects) == sorted(SUBJECTS)
        assert "link.>" in info.config.subjects
        assert info.config.storage == "file"  # nats-py reads these back as plain strings
        assert info.config.discard == "old"
        assert info.config.max_age == 3600
        assert info.config.max_bytes == 1 << 20

        # Create or update: running it again with other limits changes them in place.
        await bus.publish(observation(1))
        await bus.ensure_streams(Config(retention=Retention(max_age_s=7200, max_bytes=2 << 20)))
        info = await stream_info(server.url)
        assert (info.config.max_age, info.config.max_bytes) == (7200, 2 << 20)
        assert info.state.messages == 1
    finally:
        await bus.close()


async def test_the_default_retention_is_seven_days_or_ten_gib(bus, server):
    info = await stream_info(server.url)
    assert info.config.max_age == 7 * 86400
    assert info.config.max_bytes == 10 * 1024**3


async def test_the_byte_limit_discards_the_oldest_events(server):
    bus = await connect(server.url, None)
    try:
        await bus.ensure_streams(Config(retention=Retention(max_age_s=86400, max_bytes=4096)))
        last = 0
        for i in range(40):
            last = await bus.publish(observation(i))
        info = await stream_info(server.url)
        assert 0 < info.state.bytes <= 4096
        assert info.state.first_seq > 1  # the oldest went
        assert info.state.last_seq == last  # the newest stayed
    finally:
        await bus.close()


async def test_the_age_limit_discards_expired_events(server):
    bus = await connect(server.url, None)
    try:
        await bus.ensure_streams(Config(retention=Retention(max_age_s=1, max_bytes=1 << 30)))
        for i in range(3):
            await bus.publish(observation(i))
        assert (await stream_info(server.url)).state.messages == 3
        deadline = time.monotonic() + 10
        while (await stream_info(server.url)).state.messages and time.monotonic() < deadline:
            await asyncio.sleep(0.25)
        assert (await stream_info(server.url)).state.messages == 0
    finally:
        await bus.close()


async def test_ensure_streams_refuses_a_stream_it_cannot_update(server):
    # A NEONWATCH stream in memory storage cannot be turned into file storage.
    raw = await nats.connect(server.url)
    try:
        from nats.js.api import StorageType, StreamConfig
        await raw.jetstream().add_stream(StreamConfig(name=STREAM, subjects=["obs.>"],
                                                      storage=StorageType.MEMORY))
    finally:
        await raw.close()
    bus = await connect(server.url, None)
    try:
        with pytest.raises(BusError, match="storage"):
            await bus.ensure_streams(Config())
    finally:
        await bus.close()


@pytest.fixture
def role_server(tmp_path):
    """A broker whose `agent` user has the agent's grants: publish obs/hb, replies on its inbox."""
    port = free_port()
    conf = tmp_path / "roles.conf"
    conf.write_text(f"""
listen: 127.0.0.1:{port}
jetstream {{ store_dir: "{tmp_path / "js-roles"}" }}
authorization {{ users: [
  {{ user: admin, password: admin-pw }}
  {{ user: agent, password: agent-pw,
     permissions: {{ publish: ["obs.>", "hb.>"], subscribe: ["_INBOX.agent.>"] }} }}
] }}
""")
    running = Server(["-c", str(conf)], port, tmp_path / "nats-roles.log")
    running.start()
    yield running
    running.stop()


async def test_a_role_publishes_with_ack_through_its_own_inbox_prefix(role_server, tmp_path):
    admin_creds = tmp_path / "admin"
    admin_creds.mkdir()
    admin = await connect(role_server.url, creds_file(
        admin_creds, json.dumps({"user": "admin", "password": "admin-pw"})))
    try:
        await admin.ensure_streams(Config())
    finally:
        await admin.close()

    agent = await connect(role_server.url, creds_file(
        tmp_path, json.dumps({"user": "agent", "password": "agent-pw"})))
    try:
        assert await agent.publish(observation(1)) == 1
        assert await agent.publish(Event(Kind.HEARTBEAT, 2.0, "agent", "hb.agent", {})) == 2
        with pytest.raises(BusError):  # the agent may not publish findings
            await agent.publish(Event(Kind.FINDING, 3.0, "agent", "finding.disk", {}))
    finally:
        await agent.close()

    # The same user without the prefix cannot receive its own publish ack. The message itself is
    # allowed, so it is stored anyway: the publisher just never learns that it was.
    bare = await nats.connect(role_server.url, user="agent", password="agent-pw")
    try:
        with pytest.raises(nats.errors.Error):
            await bare.jetstream().publish("obs.load", encode_event(observation(4)),
                                           stream=STREAM, timeout=1)
    finally:
        await bare.close()
    assert (await stream_info_as(role_server.url, "admin", "admin-pw")).state.messages == 3


async def stream_info_as(url: str, user: str, password: str):
    nc = await nats.connect(url, user=user, password=password)
    try:
        return await nc.jetstream().stream_info(STREAM)
    finally:
        await nc.close()


# --- connecting -------------------------------------------------------------------------------


@pytest.mark.parametrize("url", [
    "nats://203.0.113.9:4222",            # off the machine
    "nats://localhost:4222",              # a name, resolved by whoever controls the resolver
    "tls://127.0.0.1:4222",               # another scheme
    "nats://127.0.0.1",                   # no explicit port
    "nats://agent:secret-pw@127.0.0.1:4222",  # userinfo
    "nats://127.0.0.1:4222/path",
    "nats://127.0.0.1:4222/",
    "nats://127.0.0.1:4222?x=1",
    "nats://127.0.0.1:0",
    "nats://127.0.0.1:65536",
    "nats://127.0.0.1:4222,nats://203.0.113.9:4222",
    " nats://127.0.0.1:4222",
    "nats://127.0.0.1:4222\n",
])
async def test_connect_refuses_any_url_but_loopback_nats_before_connecting(url, monkeypatch):
    import neonwatch.bus as module
    calls = []

    async def no_network(*args, **kwargs):
        calls.append(args)
        raise AssertionError("connect reached the network")

    monkeypatch.setattr(module.nats, "connect", no_network)
    monkeypatch.setattr(module._PinnedClient, "connect", no_network)
    with pytest.raises(BusError, match=r"nats://127\.0\.0\.1:<port>") as refused:
        await connect(url, None)
    assert calls == []
    assert "secret-pw" not in str(refused.value)


#: Addresses a hostile broker announces: one in its first INFO, one in an INFO sent later.
ANNOUNCED = ("203.0.113.9:4222", "198.51.100.7:4222")


def _info(connect_url: str) -> bytes:
    info = {"server_id": "fake", "version": "2.10.0", "proto": 1, "headers": True,
            "max_payload": 1 << 20, "connect_urls": [connect_url]}
    return b"INFO " + json.dumps(info).encode() + b"\r\n"


async def announcing_broker():
    """A loopback server that speaks just enough NATS to announce two foreign servers.

    It answers the client's CONNECT and PING, sends a second INFO, then PINGs and waits for the
    PONG: the client parses in order, so once that PONG arrives the second INFO has been read.
    """
    seen = asyncio.Event()

    async def session(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        writer.write(_info(ANNOUNCED[0]))
        while not (await reader.readline()).startswith(b"PING"):
            pass
        writer.write(b"PONG\r\n" + _info(ANNOUNCED[1]) + b"PING\r\n")
        while not (await reader.readline()).startswith(b"PONG"):
            pass
        seen.set()
        await reader.read()  # until the client closes
        writer.close()

    server = await asyncio.start_server(session, "127.0.0.1", 0)
    return server, server.sockets[0].getsockname()[1], seen


async def test_servers_a_broker_announces_never_join_the_reconnect_pool():
    server, port, seen = await announcing_broker()
    async with server:
        bus = await connect(f"nats://127.0.0.1:{port}", None, timeout=5)
        try:
            await asyncio.wait_for(seen.wait(), 5)
            pool = [srv.uri.netloc for srv in bus._nc._server_pool]
            assert pool == [f"127.0.0.1:{port}"]
            assert bus._nc.discovered_servers == []
        finally:
            await bus.close()


async def test_a_stock_client_would_have_added_them():
    """The control: without the pin, nats-py adds both announced servers to its pool."""
    server, port, seen = await announcing_broker()
    async with server:
        nc = await nats.connect(f"nats://127.0.0.1:{port}")
        try:
            await asyncio.wait_for(seen.wait(), 5)
            pool = {srv.uri.netloc for srv in nc._server_pool}
            assert pool == {f"127.0.0.1:{port}", *ANNOUNCED}
        finally:
            await nc.close()


async def test_connect_names_the_reason_it_could_not_reach_the_broker():
    with pytest.raises(BusError, match=r"(?i)refused"):
        await connect(f"nats://127.0.0.1:{free_port()}", None, timeout=0.5)


async def test_the_right_credentials_connect_and_publish(auth_server, tmp_path):
    creds = creds_file(tmp_path, json.dumps({"user": "neonwatch", "password": "right-password"}))
    bus = await connect(auth_server.url, creds, timeout=2)
    try:
        await bus.ensure_streams(Config())
        assert await bus.publish(observation(1)) == 1
    finally:
        await bus.close()


async def test_the_wrong_credentials_are_refused(auth_server, tmp_path):
    creds = creds_file(tmp_path, json.dumps({"user": "neonwatch", "password": "wrong"}))
    with pytest.raises(BusError, match="Authorization Violation"):
        await connect(auth_server.url, creds, timeout=1)


async def test_no_credentials_are_refused_by_a_broker_that_wants_them(auth_server):
    with pytest.raises(BusError, match="Authorization Violation"):
        await connect(auth_server.url, None, timeout=1)


@pytest.mark.parametrize("content, message", [
    ("{not json", "not JSON"),
    ('["neonwatch", "pw"]', "object"),
    ('{"user": "neonwatch"}', "exactly"),
    ('{"user": "neonwatch", "password": "pw", "role": "agent"}', "exactly"),
    ('{"user": "", "password": "pw"}', "non-empty string"),
    ('{"user": "neonwatch", "password": 12}', "non-empty string"),
    ('{"user": "neonwatch", "password": "   "}', "non-empty string"),
    ('{"user": "a.b", "password": "pw"}', "one subject token"),
    ('{"user": "a*", "password": "pw"}', "one subject token"),
])
async def test_a_malformed_credentials_file_is_refused(tmp_path, content, message):
    with pytest.raises(BusError, match=message):
        await connect("nats://127.0.0.1:1", creds_file(tmp_path, content))


@pytest.mark.parametrize("mode", [0o644, 0o640, 0o604, 0o620, 0o602])
async def test_a_credentials_file_others_can_reach_is_refused(tmp_path, mode):
    creds = creds_file(tmp_path, json.dumps({"user": "u", "password": "p"}), mode)
    with pytest.raises(BusError, match=oct(mode)[2:]):
        await connect("nats://127.0.0.1:1", creds)


VALID_CREDS = json.dumps({"user": "u", "password": "p"})


async def test_a_symlinked_credentials_file_is_refused(tmp_path):
    real = creds_file(tmp_path, VALID_CREDS)
    link = tmp_path / "link.json"
    link.symlink_to(real)
    with pytest.raises(BusError, match="cannot read"):  # O_NOFOLLOW: ELOOP
        await connect("nats://127.0.0.1:1", link)


async def test_a_fifo_is_refused_without_hanging(tmp_path):
    fifo = tmp_path / "creds.fifo"
    os.mkfifo(fifo, 0o600)

    def attempt() -> BaseException | None:
        try:
            asyncio.run(connect("nats://127.0.0.1:1", fifo))
        except BaseException as refused:
            return refused
        return None

    # In a thread, so a blocking open fails this test after 1 s instead of hanging the run;
    # opening the write end then releases the stuck reader so the thread can finish.
    pending = asyncio.ensure_future(asyncio.to_thread(attempt))
    done, _ = await asyncio.wait({pending}, timeout=1)
    if not done:
        os.close(os.open(fifo, os.O_WRONLY | os.O_NONBLOCK))
        await pending
        pytest.fail("connect blocked opening a FIFO")
    refused = pending.result()
    assert isinstance(refused, BusError) and "regular file" in str(refused)


async def test_an_oversized_credentials_file_is_refused(tmp_path):
    padded = json.dumps({"user": "u", "password": "p" * 4096})
    with pytest.raises(BusError, match="4096"):
        await connect("nats://127.0.0.1:1", creds_file(tmp_path, padded))


async def test_a_credentials_file_that_is_not_utf8_is_refused(tmp_path):
    path = tmp_path / "creds.json"
    path.write_bytes(b'{"user": "\xff", "password": "p"}')
    path.chmod(0o600)
    with pytest.raises(BusError, match="cannot read"):
        await connect("nats://127.0.0.1:1", path)


async def test_a_credentials_file_owned_by_someone_else_is_refused(tmp_path):
    with pytest.raises(BusError, match="owned by uid"):
        await connect("nats://127.0.0.1:1", creds_file(tmp_path, VALID_CREDS),
                      owner=os.getuid() + 1)


async def test_a_credentials_file_owned_by_the_expected_user_is_read(auth_server, tmp_path):
    creds = creds_file(tmp_path, json.dumps({"user": "neonwatch", "password": "right-password"}))
    bus = await connect(auth_server.url, creds, timeout=2, owner=os.getuid())
    await bus.close()


async def test_a_missing_credentials_file_is_refused(tmp_path):
    with pytest.raises(BusError, match="cannot read"):
        await connect("nats://127.0.0.1:1", tmp_path / "absent.json")


def test_bus_is_the_public_type():
    assert isinstance(Bus, type)
    assert os.fspath(BINARY).endswith(".tools/nats-server")
