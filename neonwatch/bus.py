"""The NATS JetStream adapter, and the only module that imports a NATS client.

One stream, `NEONWATCH`, holds every subject the system uses. Events go in through
`schema.encode_event` and come out through `schema.decode_event`; nothing else is put on or
taken off the wire.

Delivery is at least once. A subscription acknowledges an event when its consumer asks for the
next one, or leaves cleanly; an exception out of `async with` gives the event back to the broker,
which redelivers it first. A consumer that neither asks again nor closes (a crash) leaves the event
unacknowledged, and the broker redelivers it after the consumer's ack wait (30 s by default).

Everything nats-py raises is re-raised as `BusError`, so callers never need to import `nats`.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import os
import re
import stat
from collections import deque
from collections.abc import Iterator
from pathlib import Path

import nats
import nats.errors
import nats.js.errors
from nats.js.api import DiscardPolicy, StorageType, StreamConfig

from neonwatch.config import Config
from neonwatch.schema import SUBJECT, Event, SchemaError, decode_event, encode_event

STREAM = "NEONWATCH"
SUBJECTS = tuple(f"{prefix}.>" for prefix in SUBJECT.values())

#: How long `connect` keeps trying before it gives up and says why.
CONNECT_TIMEOUT_S = 5.0
#: Pause between reconnect attempts. Once connected, the client reconnects without limit.
RECONNECT_WAIT_S = 0.5
#: How long one pull waits for a message before pulling again.
POLL_S = 1.0

#: A durable name, and a credentials user (it becomes the inbox prefix): one subject token.
_NAME = re.compile(r"[A-Za-z0-9_-]+")
_PREFIXES = frozenset(SUBJECT.values())
#: The only broker address accepted: loopback, by number, explicit port, nothing else.
_URL = re.compile(r"nats://127\.0\.0\.1:([0-9]{1,5})")
#: Largest credentials file read. The broker writes well under 100 bytes.
_MAX_CREDS_BYTES = 4096

_log = logging.getLogger(__name__)


class BusError(RuntimeError):
    """The broker refused, could not be reached, or was handed something the bus will not send."""


class _PinnedClient(nats.NATS):
    """A NATS client whose server pool stays the one URL it was given.

    nats-py adds every address a server announces in INFO `connect_urls` to the reconnect pool
    without checking it (2.16.0, `Client._process_info`), and `connect` reconnects without limit.
    A hostile or confused broker could announce any host, and the next time the loopback
    connection dropped the root agent would reconnect there and send its password. One loopback
    broker has no cluster to discover, so the announcement is removed before nats-py reads INFO.
    """

    async def _process_info(self, info: dict[str, object],
                            initial_connection: bool = False) -> None:
        pinned = {key: value for key, value in info.items() if key != "connect_urls"}
        await super()._process_info(pinned, initial_connection)


@contextlib.contextmanager
def _translated() -> Iterator[None]:
    try:
        yield
    except nats.errors.Error as bad:
        raise BusError(f"{type(bad).__name__}: {bad}") from bad


async def connect(url: str, creds: Path | None, *, timeout: float = CONNECT_TIMEOUT_S,
                  owner: int | None = None) -> Bus:
    """A bus on the broker at `url`, authenticated with the credentials file `creds` if given.

    nats-py retries even a refused first connection for minutes (measured), so the attempt is
    bounded by `timeout` and the refusal names what the broker said. When `owner` is given, the
    credentials file must belong to that uid or to root.

    Only `nats://127.0.0.1:<port>` is accepted, checked before anything is read or sent: the
    agent's password and every root observation cross this connection in cleartext.
    It is also the only address ever tried: servers the broker announces are ignored.
    """
    match = _URL.fullmatch(url)
    if match is None or not 1 <= int(match[1]) <= 65535:
        # The URL is not echoed: a refused one may carry userinfo.
        raise BusError("the broker url must be exactly nats://127.0.0.1:<port>")
    options: dict[str, str] = {}
    if creds is not None:
        user, password = _read_creds(Path(creds), owner)
        # Each role may subscribe only to its own inbox; without this, publish acks are refused.
        options = {"user": user, "password": password, "inbox_prefix": f"_INBOX.{user}"}
    reasons: deque[str] = deque(maxlen=4)

    async def on_error(error: Exception) -> None:
        reasons.append(f"{type(error).__name__}: {error}")
        _log.warning("nats: %s", reasons[-1])

    client = _PinnedClient()
    try:
        await asyncio.wait_for(
            client.connect(url, error_cb=on_error, max_reconnect_attempts=-1,
                           reconnect_time_wait=RECONNECT_WAIT_S, **options),
            timeout)
    except TimeoutError:
        why = "; ".join(dict.fromkeys(reasons)) or "no answer"
        raise BusError(f"could not connect to {url} within {timeout}s: {why}") from None
    return Bus(client)


def _read_creds(path: Path, owner: int | None) -> tuple[str, str]:
    """The user and password in `path`, read so that a user-controlled file cannot hang or
    redirect the reader: no symlinks, no blocking open (a FIFO), a regular file only, bounded."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except OSError as bad:
        raise BusError(f"{path}: cannot read credentials: {bad}") from None
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise BusError(f"{path}: credentials must be a regular file")
        if info.st_size > _MAX_CREDS_BYTES:
            raise BusError(f"{path}: credentials are {info.st_size} bytes, over {_MAX_CREDS_BYTES}")
        mode = info.st_mode & 0o777
        if mode & 0o077:
            raise BusError(f"{path}: mode {mode:o} lets others reach the credentials; "
                           "it must be 600")
        if owner is not None and info.st_uid not in (owner, 0):
            raise BusError(f"{path}: credentials are owned by uid {info.st_uid}, "
                           f"not {owner} or root")
        text = os.read(fd, _MAX_CREDS_BYTES).decode()
    except (OSError, UnicodeDecodeError) as bad:
        raise BusError(f"{path}: cannot read credentials: {bad}") from None
    finally:
        os.close(fd)
    try:
        raw = json.loads(text)
    except json.JSONDecodeError as bad:
        raise BusError(f"{path}: credentials are not JSON: {bad}") from None
    if not isinstance(raw, dict):
        raise BusError(f"{path}: credentials must be a JSON object")
    if set(raw) != {"user", "password"}:
        raise BusError(f"{path}: credentials must have exactly 'password' and 'user', "
                       f"got {sorted(raw)}")
    for key in ("user", "password"):
        if not isinstance(raw[key], str) or not raw[key].strip():
            raise BusError(f"{path}: `{key}` must be a non-empty string")
    if not _NAME.fullmatch(raw["user"]):
        raise BusError(f"{path}: `user` must be one subject token (letters, digits, - and _)")
    return raw["user"], raw["password"]


def _check_subject(subject: str, *, wildcards: bool) -> None:
    """Refuse anything but a literal subject (or, for a filter, a wildcard one) in the stream.

    JetStream stores a message published to `obs.*` or `obs.>` verbatim (measured), and accepts
    a consumer filter that no stream subject can match, so neither is left to the server.
    """
    if wildcards and subject == ">":
        return
    tokens = subject.split(".")
    for i, token in enumerate(tokens):
        literal = bool(token) and not any(ch.isspace() or ch in "*>" for ch in token)
        wildcard = wildcards and i > 0 and (token == "*" or (token == ">" and i == len(tokens) - 1))
        if not (literal or wildcard):
            break
    else:
        if tokens[0] in _PREFIXES and len(tokens) > 1:
            return
    kind = "subject filter" if wildcards else "literal subject"
    raise BusError(f"{subject!r} is not a {kind} in the {STREAM} stream")


class Bus:
    """A connection to the broker. `rejected` counts messages that did not decode, and
    `last_rejection` says which and why."""

    def __init__(self, client: nats.NATS) -> None:
        self._nc = client
        self._js = client.jetstream()
        self.rejected = 0
        self.last_rejection = ""

    async def ensure_streams(self, config: Config) -> None:
        """Create the stream, or bring its settings to `config`. Whichever limit hits first
        discards the oldest events: that is JetStream's own behaviour."""
        wanted = StreamConfig(name=STREAM, subjects=list(SUBJECTS), storage=StorageType.FILE,
                              discard=DiscardPolicy.OLD, max_age=config.retention.max_age_s,
                              max_bytes=config.retention.max_bytes)
        with _translated():
            try:
                await self._js.stream_info(STREAM)
            except nats.js.errors.NotFoundError:
                await self._js.add_stream(wanted)
            else:
                await self._js.update_stream(wanted)

    async def publish(self, event: Event) -> int:
        """Publish `event` and wait for the stream to store it. Returns its stream sequence."""
        data = encode_event(event)
        _check_subject(event.subject, wildcards=False)
        with _translated():
            ack = await self._js.publish(event.subject, data, stream=STREAM)
        return ack.seq

    def subscribe(self, subject: str, durable: str) -> Subscription:
        """Events on `subject` (a filter; `>` is the whole stream) from where `durable` left off."""
        _check_subject(subject, wildcards=True)
        if not _NAME.fullmatch(durable):
            raise BusError(f"durable name {durable!r} must be letters, digits, - and _")
        return Subscription(self, subject, durable)

    async def close(self) -> None:
        await self._nc.close()

    def _accept(self, message: nats.aio.msg.Msg) -> Event | None:
        """The event in `message`, or None after counting why it was refused.

        Any exception from one message refuses that message and nothing else: a subscription
        must outlive whatever a publisher manages to put on the stream (security review).
        """
        try:
            event = decode_event(message.data)
        except SchemaError as bad:
            why = str(bad)
        except Exception as bad:
            why = f"{type(bad).__name__}: {bad}"
        else:
            if event.subject == message.subject:
                return event
            why = f"addressed to {event.subject!r} but delivered on {message.subject!r}"
        self.rejected += 1
        self.last_rejection = f"{message.subject} #{message.metadata.sequence.stream}: {why}"
        _log.warning("bus: skipped %s", self.last_rejection)
        return None


class Subscription:
    """An `AsyncIterator[Event]` over one durable pull consumer, and an async context manager.

    The event last returned is acknowledged when the next is asked for or the subscription
    closes; if the `async with` block raises, it is handed back for redelivery instead.
    """

    def __init__(self, bus: Bus, subject: str, durable: str) -> None:
        self._bus, self._subject, self._durable = bus, subject, durable
        self._sub: nats.js.JetStreamContext.PullSubscription | None = None
        self._held: nats.aio.msg.Msg | None = None
        self._closed = False

    def __aiter__(self) -> Subscription:
        return self

    async def __aenter__(self) -> Subscription:
        return self

    async def __aexit__(self, kind: object, error: BaseException | None, trace: object) -> None:
        if error is not None and self._held is not None:
            held, self._held = self._held, None
            with _translated():
                await held.nak()
        await self.close()

    async def __anext__(self) -> Event:
        if self._closed:
            raise StopAsyncIteration
        with _translated():
            await self._release()
            if self._sub is None:
                self._sub = await self._bind()
            while True:
                try:
                    message = (await self._sub.fetch(1, timeout=POLL_S))[0]
                except nats.errors.TimeoutError:
                    continue  # also what a pull raises while the client reconnects (measured)
                event = self._bus._accept(message)
                if event is None:
                    await message.ack()
                    continue
                self._held = message
                return event

    async def close(self) -> None:
        """Acknowledge the event in hand and stop. The durable keeps its place on the broker."""
        if self._closed:
            return
        self._closed = True
        with _translated():
            await self._release()
            if self._sub is not None:
                await self._sub.unsubscribe()

    async def _release(self) -> None:
        if self._held is not None:
            held, self._held = self._held, None
            await held.ack()

    async def _bind(self) -> nats.js.JetStreamContext.PullSubscription:
        # nats-py binds to an existing durable without comparing its filter (measured), so a
        # durable made for `obs.>` would silently keep delivering observations to `hb.>`.
        try:
            info = await self._bus._js.consumer_info(STREAM, self._durable)
        except nats.js.errors.NotFoundError:
            pass
        else:
            if info.config.filter_subject != self._subject or info.config.filter_subjects:
                raise BusError(f"durable {self._durable!r} reads "
                               f"{info.config.filter_subject or info.config.filter_subjects!r}, "
                               f"not {self._subject!r}")
        # Bound to the stream by name: no role is granted the stream-name lookup.
        return await self._bus._js.pull_subscribe(self._subject, durable=self._durable,
                                                  stream=STREAM)
