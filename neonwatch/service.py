"""The unprivileged composition root: run as the operator, in the desktop session. Never as root.

It opens three bus connections, one per broker role, each with that role's credentials file:

- **evaluator** creates the `NEONWATCH` stream, reads `obs.>` (durable `evaluator`) and `hb.>`
  (`evaluator-hb`) into the evaluator, and every `cadence.collate` seconds publishes whatever the
  collation returns: findings, attestations, issues and links;
- **viewer** reads the whole stream (`viewer`) into the store, then hands each stored event to
  `Live`, the broadcaster the dashboard's server-sent events subscribe to;
- **notifier** reads `issue.>` (`notifier`), decodes each issue and lets the notifier decide
  whether it reaches the desktop.

At startup the evaluator adopts the store's unresolved issues, so an issue a previous process
opened is resolved when its condition has gone, rather than left open forever.

It also prunes the store every `PRUNE_EVERY_S`, and serves the dashboard. On loopback without a
password, that is with a per-launch token: the dashboard URL, token included, is printed to stdout
once, the operator's way in. It is never logged, and aiohttp's access log (which would record the
`?token=` of the first visit) is silenced. With `web.password_hash` set there is no token: the URL
printed is `https://<first allowed host>/`, and the browser logs in there. With `web.tls_cert`
and `web.tls_key` set the dashboard is served over TLS 1.2 or later only, and the service will not
start if either file is missing or unreadable, or if the key is reachable by group or other.

`hash_password_command` is `neonwatch hash-password`: it lives here, not in the launcher, because
the launcher is privileged code with a closed import list (no `getpass`, no web).

Refusals. An event a component refuses (the evaluator, the store, or the issue decoder) is logged,
counted in `counts.refused`, acknowledged and skipped: a poison event must not be redelivered
forever. A publish that fails with `BusError` (a broker restart times out, measured) is retried
`PUBLISH_ATTEMPTS` times with capped backoff; one that still fails is logged at ERROR and counted
in `counts.dropped` (and `dropped_issues` for an issue). An open issue is re-emitted by the next
collation; a resolution is said once, which is why losing one is an ERROR. A consumer whose
subscription fails is resubscribed with backoff. Any other exception out of a task is a bug: the
service stops with exit code 1 rather than run half-wired.

The agent API's token (`agent_token`) is created here at startup when it is missing, in the
store's directory, and handed to the dashboard as a reader, so `neonwatch agent-token --rotate`
takes effect without a restart. A token file that is unsafe (a symlink, another owner, readable
by others) is refused and logged; the dashboard still starts, and the agent API answers 503
until the file is fixed or rotated.

The analyst's API key is read here, at the edge, from the environment variable that
`analyst.api_key_env` names. It is handed to `Analyst` and never logged.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import dataclasses
import getpass
import ipaddress
import logging
import os
import secrets
import signal
import ssl
import stat
import sys
import time
from collections.abc import Awaitable, Callable, Iterable, Mapping
from pathlib import Path
from typing import Any, TextIO

from neonwatch import agent_token, broker, bus, jobs, logs, rules, web
from neonwatch.analyst import Analyst
from neonwatch.analyst import urllib_transport as analyst_transport
from neonwatch.bus import Bus, BusError
from neonwatch.config import Config, ConfigError, Web, load
from neonwatch.correlator import Correlator
from neonwatch.evaluator import Evaluator, EvaluatorError
from neonwatch.judge import Judge
from neonwatch.judge import urllib_transport as judge_transport
from neonwatch.notifier import Notification, Notifier, Send, gdbus_send
from neonwatch.schema import Event, Issue, Kind, SchemaError, from_body
from neonwatch.store import Store, StoreError

PRUNE_EVERY_S = 3600.0
#: Events held for one live subscriber before it counts as fallen behind.
LIVE_QUEUE = 1000
PUBLISH_ATTEMPTS = 6
BACKOFF_MIN_S = 0.5
BACKOFF_MAX_S = 30.0
#: Shortest dashboard password `hash-password` accepts. The longest is what the login accepts.
MIN_PASSWORD = 12

log = logging.getLogger(__name__)


# --- the live broadcaster ------------------------------------------------------------------------


class LiveBehind(Exception):
    """This subscriber fell `queue_size` events behind and was dropped. The dashboard's stream
    ends, and the browser reconnects with Last-Event-ID, which replays from the store."""


_END = object()
_BEHIND = object()


class LiveSubscription:
    """An `AsyncIterator[Event]`, registered with its broadcaster as soon as it is made."""

    def __init__(self, live: Live, queue_size: int) -> None:
        self._live = live
        self._queue: asyncio.Queue[Any] = asyncio.Queue(maxsize=queue_size)
        self._done = False

    def __aiter__(self) -> LiveSubscription:
        return self

    async def __anext__(self) -> Event:
        if self._done:
            raise StopAsyncIteration
        try:
            item = await self._queue.get()
        except asyncio.CancelledError:
            self._forget()
            raise
        if item is _END:
            self._forget()
            raise StopAsyncIteration
        if item is _BEHIND:
            self._forget()
            raise LiveBehind(f"fell {self._queue.maxsize} events behind")
        return item

    async def aclose(self) -> None:
        self._forget()

    def _offer(self, item: Any) -> bool:
        """Queue `item`; False when the queue is full."""
        try:
            self._queue.put_nowait(item)
        except asyncio.QueueFull:
            return False
        return True

    def _end(self, item: object) -> None:
        """Replace whatever is queued with `item`, the last thing this subscriber will see."""
        while not self._queue.empty():
            self._queue.get_nowait()
        self._queue.put_nowait(item)

    def _forget(self) -> None:
        self._done = True
        self._live._subscribers.discard(self)


class Live:
    """Fans stored events out to every dashboard stream, each through its own bounded queue."""

    def __init__(self, queue_size: int = LIVE_QUEUE) -> None:
        if queue_size < 1:
            raise ValueError("queue_size must be at least 1")
        self._queue_size = queue_size
        self._subscribers: set[LiveSubscription] = set()
        self._closed = False
        #: Subscribers dropped for falling behind.
        self.overflowed = 0

    @property
    def subscribers(self) -> int:
        return len(self._subscribers)

    def subscribe(self) -> LiveSubscription:
        subscription = LiveSubscription(self, self._queue_size)
        if self._closed:
            subscription._end(_END)
        else:
            self._subscribers.add(subscription)
        return subscription

    def publish(self, event: Event) -> None:
        for subscription in list(self._subscribers):
            if not subscription._offer(event):
                self._subscribers.discard(subscription)
                subscription._end(_BEHIND)
                self.overflowed += 1
                log.warning("a live subscriber fell %d events behind and was dropped",
                            self._queue_size)

    def close(self) -> None:
        self._closed = True
        for subscription in list(self._subscribers):
            subscription._end(_END)
        self._subscribers.clear()


# --- the service ---------------------------------------------------------------------------------


@dataclasses.dataclass(slots=True)
class Counts:
    observed: int = 0
    stored: int = 0
    considered: int = 0
    #: Events a component refused: skipped and acknowledged.
    refused: int = 0
    collations: int = 0
    collate_failures: int = 0
    published: int = 0
    retries: int = 0
    dropped: int = 0
    dropped_issues: int = 0


def logging_send(send: Send) -> Send:
    """`send`, with its outcome logged. The notification's text is untrusted; it is not logged."""

    async def logged(notification: Notification) -> str | None:
        error = await send(notification)
        if error is None:
            log.info("notified the desktop about %s", notification.issue_id or "held issues")
        else:
            log.warning("desktop notification failed: %s", error)
        return error

    return logged


class Service:
    """Everything wired. Built by `open_service`; `run` serves until `stop` is set."""

    def __init__(self, config: Config, *, evaluator_bus: Bus, viewer_bus: Bus,
                 notifier_bus: Bus, store: Store, judge: Any, evaluator: Evaluator,
                 notifier: Notifier, analyst: Analyst | None, token: str,
                 clock: Callable[[], float], out: TextIO,
                 ssl_context: ssl.SSLContext | None = None,
                 agent_token: Callable[[], str] | None = None) -> None:
        self._config = config
        self._evaluator_bus, self._viewer_bus = evaluator_bus, viewer_bus
        self._notifier_bus = notifier_bus
        self.store, self.judge, self.analyst = store, judge, analyst
        self._evaluator, self._notifier = evaluator, notifier
        self.token = token
        #: Reads the agent API's token, for every agent request; None leaves that API off.
        self.agent_token = agent_token
        #: Set when the dashboard is served over TLS (`tls_context`).
        self.ssl_context = ssl_context
        self._clock, self._out = clock, out
        self._collate_every = float(config.cadence.collate)
        self.live = Live()
        self.counts = Counts()
        self._closed = False

    # --- one event -----------------------------------------------------------------------

    async def handle_observation(self, event: Event) -> None:
        try:
            self._evaluator.observe(event)
        except (EvaluatorError, SchemaError) as bad:
            self._refuse("evaluator", event, bad)
            return
        self.counts.observed += 1

    async def handle_view(self, event: Event) -> None:
        try:
            self.store.apply(event)
        except (SchemaError, StoreError) as bad:
            self._refuse("store", event, bad)
            return
        self.counts.stored += 1
        if (event.kind is Kind.OBSERVATION and event.body.get("probe") == "units.detail"
                and not event.body.get("error")):
            self.note_services(event)
        self.live.publish(event)

    def note_services(self, event: Event) -> None:
        """When each service first appeared, for the Services view's "new" alert. A failure
        here costs only that: the observation is already stored, and the viewer goes on."""
        try:
            listed = jobs.services({"units.detail": event.body.get("data") or {}})
            self.store.note_services([s["name"] for s in listed], event.at)
        except (KeyError, TypeError, AttributeError, StoreError) as bad:
            log.warning("could not note the services in %s: %s", event.subject, bad)

    async def handle_issue(self, event: Event) -> None:
        try:
            if event.kind is not Kind.ISSUE:
                raise SchemaError(f"expected an issue, got {event.kind.value}")
            issue = from_body(Issue, event.body)
        except SchemaError as bad:
            self._refuse("notifier", event, bad)
            return
        self.counts.considered += 1
        await self._notifier.consider(issue)

    def _refuse(self, who: str, event: Event, bad: Exception) -> None:
        self.counts.refused += 1
        log.warning("%s refused %s: %s", who, event.subject, bad)

    # --- publishing ----------------------------------------------------------------------

    async def publish(self, events: Iterable[Event]) -> None:
        for event in events:
            if not await self._publish_one(event):
                self.counts.dropped += 1
                if event.kind is Kind.ISSUE:
                    self.counts.dropped_issues += 1
                    log.error("issue event %s was NOT published; the dashboard and notifier "
                              "miss this state until a later collation re-emits it",
                              event.subject)

    async def _publish_one(self, event: Event) -> bool:
        delay = BACKOFF_MIN_S
        for attempt in range(1, PUBLISH_ATTEMPTS + 1):
            try:
                await self._evaluator_bus.publish(event)
            except SchemaError as bad:
                log.error("%s cannot be encoded, not publishing it: %s", event.subject, bad)
                return False
            except BusError as bad:
                if attempt == PUBLISH_ATTEMPTS:
                    log.error("publishing %s failed %d times: %s", event.subject, attempt, bad)
                    return False
                self.counts.retries += 1
                log.warning("publishing %s failed (%s); retrying in %.1f s",
                            event.subject, bad, delay)
                await asyncio.sleep(delay)
                delay = min(delay * 2, BACKOFF_MAX_S)
            else:
                self.counts.published += 1
                return True
        raise AssertionError("unreachable")  # pragma: no cover

    # --- the loops -----------------------------------------------------------------------

    async def consume(self, source: Bus, subject: str, durable: str,
                      handle: Callable[[Event], Awaitable[None]]) -> None:
        """Feed `durable`'s events to `handle` forever, resubscribing when the bus fails."""
        delay = BACKOFF_MIN_S
        while True:
            try:
                async with source.subscribe(subject, durable) as subscription:
                    async for event in subscription:
                        delay = BACKOFF_MIN_S
                        await handle(event)
            except BusError as bad:
                log.warning("consumer %s on %s failed (%s); resubscribing in %.1f s",
                            durable, subject, bad, delay)
                await asyncio.sleep(delay)
                delay = min(delay * 2, BACKOFF_MAX_S)

    async def collate_once(self, now: float) -> None:
        collation = await self._evaluator.collate(now)
        self.counts.collations += 1
        log.info("collation: %d issue(s), %d event(s), %d question(s) asked, %d deferred, "
                 "%d ms", len(collation.issues), len(collation.events), collation.questions_asked,
                 collation.deferred_contexts, collation.duration_ms)
        await self.publish(collation.events)

    async def collate_forever(self) -> None:
        while True:
            await asyncio.sleep(self._collate_every)
            try:
                await self.collate_once(self._clock())
            except Exception:
                self.counts.collate_failures += 1
                log.exception("collation failed; the next one runs on schedule")

    async def prune_forever(self) -> None:
        while True:
            await asyncio.sleep(PRUNE_EVERY_S)
            try:
                removed = self.store.prune(self._clock())
            except Exception:
                log.exception("store prune failed; retrying in %.0f s", PRUNE_EVERY_S)
            else:
                log.info("store pruned: %d row(s) removed", removed)

    # --- the whole ---------------------------------------------------------------------------

    async def _judge_health(self) -> Mapping[str, Any]:
        return dataclasses.asdict(self.judge.health())

    def url(self) -> str:
        """Where the operator goes: the first allowed host when there are any, the token only
        when there is no password."""
        settings = self._config.web
        scheme = "https" if self.ssl_context is not None else "http"
        if settings.allowed_hosts:
            where = settings.allowed_hosts[0]
        else:
            host = settings.host
            with contextlib.suppress(ValueError):
                if ipaddress.ip_address(host).version == 6:
                    host = f"[{host}]"
            where = f"{host}:{settings.port}"
        if settings.password_hash:
            return f"{scheme}://{where}/"
        return f"{scheme}://{where}/?token={self.token}"

    async def run(self, stop: asyncio.Event) -> int:
        """Serve until `stop` is set (0), or until a task dies of a bug (1). Closes everything."""
        tasks: dict[asyncio.Task, str] = {}
        stop_web: Callable[[], Awaitable[None]] | None = None
        try:
            app = web.make_app(self.store, self.live, self.token, self._config, self.analyst,
                               judge_health=self._judge_health, read_logs=logs.read_journal,
                               agent_token=self.agent_token)
            stop_web = await web.start(app, self._config.web.host, self._config.web.port,
                                       ssl_context=self.ssl_context)
            print(self.url(), file=self._out, flush=True)
            log.info("dashboard listening on %s:%d%s (%s)", self._config.web.host,
                     self._config.web.port, " over TLS" if self.ssl_context else "",
                     "log in at the URL on stdout" if self._config.web.password_hash
                     else "the URL with its token is on stdout")
            jobs = {
                "evaluator": self.consume(self._evaluator_bus, "obs.>", "evaluator",
                                          self.handle_observation),
                "evaluator-hb": self.consume(self._evaluator_bus, "hb.>", "evaluator-hb",
                                             self.handle_observation),
                "viewer": self.consume(self._viewer_bus, ">", "viewer", self.handle_view),
                "notifier": self.consume(self._notifier_bus, "issue.>", "notifier",
                                         self.handle_issue),
                "collate": self.collate_forever(),
                "prune": self.prune_forever(),
            }
            tasks = {asyncio.create_task(job, name=name): name for name, job in jobs.items()}
            stopped = asyncio.create_task(stop.wait(), name="stop")
            done, _ = await asyncio.wait({stopped, *tasks}, return_when=asyncio.FIRST_COMPLETED)
            code = 0
            for task in done - {stopped}:
                code = 1
                log.error("task %s stopped: %r; shutting down", tasks[task], task.exception())
            stopped.cancel()
            return code
        finally:
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            self.live.close()
            if stop_web is not None:
                await stop_web()
            await self.close()
            log.info("service stopped: %s", self.counts)

    async def close(self) -> None:
        """Close the bus connections and the store. Safe to call again."""
        if self._closed:
            return
        self._closed = True
        for connection in (self._evaluator_bus, self._viewer_bus, self._notifier_bus):
            try:
                await connection.close()
            except Exception as bad:
                log.warning("closing a bus connection: %s", bad)
        self.store.close()


# --- assembly ------------------------------------------------------------------------------------


def tls_context(settings: Web) -> ssl.SSLContext | None:
    """The dashboard's TLS server context, or None without `tls_cert`. Raises ValueError, naming
    the file, when either file cannot be read, the key is reachable by group or other, or the
    pair does not load. (Config guarantees the two are set together.)"""
    if not settings.tls_cert:
        return None
    cert, key = Path(settings.tls_cert).expanduser(), Path(settings.tls_key).expanduser()
    for name, path in (("tls_cert", cert), ("tls_key", key)):
        try:
            path.open("rb").close()
        except OSError as bad:
            raise ValueError(f"web.{name} {path}: cannot read it ({bad.strerror})") from None
    mode = stat.S_IMODE(key.stat().st_mode)
    if mode & 0o077:
        raise ValueError(f"web.tls_key {key} is mode {mode:04o}, so other users may read the "
                         f"private key; chmod 600 it")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    try:
        context.load_cert_chain(cert, key)
    except ssl.SSLError as bad:
        raise ValueError(f"web.tls_cert {cert} and web.tls_key {key}: cannot load the "
                         f"certificate and key ({bad.reason or bad})") from None
    return context


def _analyst(config: Config, environ: Mapping[str, str]) -> Analyst | None:
    settings = config.analyst
    if not settings.provider:
        return None
    key = ""
    if settings.api_key_env:
        if settings.api_key_env not in environ:
            log.warning("analyst disabled: analyst.api_key_env names %s, which is not set in "
                        "the service's environment", settings.api_key_env)
            return None
        key = environ[settings.api_key_env]
    log.info("analyst: %s model %s", settings.provider, settings.model)
    return Analyst(analyst_transport(settings.timeout_s), config, key)


async def open_service(config: Config, *, environ: Mapping[str, str], judge: Any = None,
                       send: Send = gdbus_send, clock: Callable[[], float] = time.time,
                       out: TextIO | None = None, owner: int | None = None) -> Service:
    """Connect each role, create the stream, open the store and build every component.

    `judge` defaults to the real judge client. `owner` is the uid each credentials file must
    belong to (the bus also accepts root). On any failure, what was opened is closed.
    """
    creds = broker.paths(config).creds
    ssl_context = tls_context(config.web)   # before anything is connected
    async with contextlib.AsyncExitStack() as opened:
        connections = []
        for role in (broker.Role.EVALUATOR, broker.Role.VIEWER, broker.Role.NOTIFIER):
            connection = await bus.connect(config.broker.url, creds[role], owner=owner)
            opened.push_async_callback(connection.close)
            connections.append(connection)
        await connections[0].ensure_streams(config)
        store = Store(Path(config.store.path).expanduser(), config)
        opened.callback(store.close)
        if judge is None:
            judge = Judge(judge_transport(config.judge.url, config.judge.timeout_s), config)
        evaluator = Evaluator(rules.evaluate, judge, Correlator(judge, config), config, clock)
        evaluator.adopt(store.issues())   # or an issue that went away meanwhile never resolves
        service = Service(config, evaluator_bus=connections[0], viewer_bus=connections[1],
                          notifier_bus=connections[2], store=store, judge=judge,
                          evaluator=evaluator,
                          notifier=Notifier(logging_send(send), config, clock),
                          analyst=_analyst(config, environ), token=secrets.token_urlsafe(32),
                          clock=clock, out=out or sys.stdout, ssl_context=ssl_context,
                          agent_token=_agent_token(config))
        opened.pop_all()
    return service


def _agent_token(config: Config) -> Callable[[], str]:
    """Make the agent token if there is none, and return what reads it. Never logs it."""
    where, uid = agent_token.path(config), os.getuid()
    try:
        if agent_token.ensure(where, uid)[1]:
            log.info("agent API token created at %s", where)
    except (agent_token.TokenError, OSError) as bad:
        log.warning("the agent API is off until its token file is fixed: %s", bad)
    return lambda: agent_token.read(where, uid)


def hash_password_command(*, ask: Callable[[str], str] | None = None,
                          out: TextIO | None = None, err: TextIO | None = None) -> int:
    """`neonwatch hash-password`: read a password twice (with getpass) and print the one line
    `password_hash = "..."` to paste into `[web]`. The password itself is never printed."""
    ask = ask or getpass.getpass
    out, err = out or sys.stdout, err or sys.stderr
    try:
        first = ask("Dashboard password: ")
        second = ask("The same password again: ")
    except (EOFError, KeyboardInterrupt):
        print("neonwatch hash-password: no password read; nothing printed", file=err)
        return 1
    if first != second:
        print("neonwatch hash-password: the two passwords differ; nothing printed", file=err)
        return 1
    if not MIN_PASSWORD <= len(first) <= web.MAX_PASSWORD:
        print(f"neonwatch hash-password: the password must be at least {MIN_PASSWORD} characters "
              f"and at most {web.MAX_PASSWORD} characters; nothing printed", file=err)
        return 1
    print(f'password_hash = "{web.hash_password(first)}"', file=out, flush=True)
    return 0


def configure_logging() -> None:
    """Log to stderr. aiohttp's access log records request paths, and the first visit's path
    carries the token, so it is held above INFO."""
    logging.basicConfig(stream=sys.stderr, level=logging.INFO,
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    logging.getLogger("aiohttp.access").setLevel(logging.WARNING)


def main(argv: list[str], *, uid: int | None = None,
         environ: Mapping[str, str] | None = None) -> int:
    """`neonwatch service [--config PATH]`. Without `--config`, the built-in defaults."""
    uid = os.getuid() if uid is None else uid
    if uid == 0:
        print("neonwatch service: refusing to run as root. The service is unprivileged: run it "
              "as yourself, in your desktop session.", file=sys.stderr)
        return 1
    parser = argparse.ArgumentParser(prog="neonwatch service")
    parser.add_argument("--config", type=Path, help="the config file (default: built-in)")
    try:
        args = parser.parse_args(argv)
    except SystemExit as done:
        return int(done.code or 0)
    try:
        config = load(args.config, owner=uid)
    except ConfigError as bad:
        print(f"neonwatch service: {bad}", file=sys.stderr)
        return 2
    configure_logging()
    return asyncio.run(_serve(config, os.environ if environ is None else environ, uid))


async def _serve(config: Config, environ: Mapping[str, str], uid: int) -> int:
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, stop.set)
    try:
        try:
            service = await open_service(config, environ=environ, owner=uid)
        except (BusError, StoreError, OSError, ValueError) as bad:
            print(f"neonwatch service: cannot start: {bad}", file=sys.stderr)
            return 1
        try:
            return await service.run(stop)
        except OSError as bad:   # the web port is taken, most likely
            print(f"neonwatch service: cannot serve the dashboard: {bad}", file=sys.stderr)
            return 1
    finally:
        for sig in (signal.SIGINT, signal.SIGTERM):
            loop.remove_signal_handler(sig)
