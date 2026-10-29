"""The dashboard's HTTP surface: a read API over the store, a server-sent event stream fed from
the bus, and the operator's only writes (ack, snooze, and asking for an analysis or for log
explanations).

Security, in the order a request meets it:
  1. `Host` must be one of `config.web.allowed_hosts` when that is set, else `127.0.0.1:<port>`,
     `localhost:<port>` or `[::1]:<port>` for `config.web.port`, compared without regard to case.
     A DNS-rebinding page reaches us under its own name, and is refused.
  2. Who may ask. Without `config.web.password_hash` (loopback only; config guarantees it), the
     per-launch token: `Authorization: Bearer <token>`, or the HttpOnly, SameSite=Strict cookie
     that visiting `/?token=<token>` once sets (then redirects to `/`, so the token leaves the
     address bar). With a password hash, the token is not accepted anywhere: `/login` is a plain
     form, and a correct password makes a server-side session (`config.web.session_s` long) held
     in an HttpOnly, SameSite=Strict, Path=/ cookie: `__Host-neonwatch_session` (so also Secure,
     with no Domain) over TLS, `neonwatch_session` without; only the name that matches the
     transport is read. `/` and `/index.html` without a session redirect to `/login`; `/api/*`
     and every other static file answer 401, except what the login page itself needs
     (`LOGIN_ASSETS`). An open event stream belongs to its session: logout or expiry ends it, and
     it re-checks the session before every event and at every keepalive. Secrets are compared in
     constant time; a session id is never stored, only its HMAC under a per-launch key, which is
     what the session table is keyed by. Failed logins are limited per client (an IPv4 address,
     or an IPv6 /64) and in total (`LOGIN_*`), counted before the slow scrypt check so concurrent
     guesses cannot all pass the limit. The check runs on the app's own single worker thread, not
     the default pool other calls share. Neither the password nor a session id is ever logged.
  3. Anything but GET/HEAD is authenticated the same way, and additionally needs `X-CSRF-Token`
     equal to the CSRF token (per launch, or per session with a password) and an `Origin` equal
     to `<scheme>://<the Host it was sent to>`, where the scheme is https on a TLS connection.
     One rule, no exceptions: a script using Bearer sends the CSRF header too, and so does
     `POST /logout`. The CSRF token is random, distinct from the credential, and readable only
     from `GET /api/session` (which needs auth like any `/api` route). No CORS headers are sent
     anywhere, so another origin can neither read it nor send the custom header, and a
     cross-site form that carries the cookie is refused for lacking it. `POST /login` has no
     session yet, so it has the Origin check alone (against login CSRF).
Bodies are capped at `MAX_BODY`. Errors are `{"error": "..."}` with no trace. Every response
carries `Cache-Control: no-store`, `nosniff`, a `default-src 'self'` CSP and `no-referrer`, plus
`Strict-Transport-Security` over TLS. The login page alone says `Referrer-Policy: same-origin`:
under `no-referrer` a browser sends `Origin: null` with a form POST, and the login would refuse
every real browser.

Nothing here executes anything on the host. The analyst's answer is stored and shown as text.

The Logs view. `GET /api/logs` runs the injected journal reader (`logs.read_journal`, one fixed
argv, one read at a time) and lists its lines with each line's template key and cached
explanation, or null; it sends nothing anywhere, and only marks the kinds it showed as seen in
the cache. The kinds of line it found are kept in memory, so `POST /api/logs/estimate` and
`POST /api/logs/explain` (both `{"keys": [...]}`) act only on what the operator was shown: a key
not in the last listing, or already explained, is dropped. Explaining is a job, polled at
`GET /api/logs/explain/{id}`, one at a time; its explanations are saved with the model that wrote
them.

Service descriptions work the same way. `GET /api/services` gives each service its `key`
(`jobs.service_key`, a hash of its definition), the timers that start it, and its cached
description (brief, full, model, time) when one was written for that same key, else null; it
sends nothing. `POST /api/services/estimate` and `POST /api/services/describe` (`{"keys":
[...]}`) act only on services the last listing showed and the cache does not describe for their
current key. Describing is a job, polled at `GET /api/services/describe/{id}`, one at a time.

The hardware strip and the Board view read `GET /api/hardware`: the CPU, each disk and each GPU
from the latest observations, every temperature against a limit and with where that limit came
from (`hardware.snapshot`), and the last hour of each series behind them; the page refetches it
when one of those probes reports.

The event stream. Each event is framed as
    id: <n>:<kind>:<at>      n counts per connection from 1; `at` is the event's time
    event: <kind>
    data: <the body as JSON, plus "at" and "subject">
with a `: keepalive` comment every `keepalive_s`. On reconnect, `Last-Event-ID` is read for its
`at`: issues, findings and attestations the store holds from that time on are replayed oldest
first, then live events follow. When the store cannot answer (an unreadable id, a time outside
retention or in the future, more than `MAX_REPLAY` rows), a `reset` event tells the UI to
refetch instead. A client too slow to keep up gets a `reset` in place of what it missed.
Observations, heartbeats and links are not replayed; the UI refetches the overview for those.

The agent API, `/api/agent/v1/...`, is for AI agents on this machine (docs/agent-api.md). It has
its own guard, met instead of 1-3 above: the peer must be loopback (whatever `web.host` is),
`Host` must be one of the dashboard's or a loopback name for the port, a request carrying
`Origin` is refused (a browser has no business here), and the caller sends
`Authorization: Bearer <agent token>` and `X-Neonwatch-Agent: <name>`. The agent token is read
through `agent_token` on every request, so rotating it takes effect at once; it is never
accepted as a cookie or a query parameter, so CSRF does not apply. The dashboard's token and
sessions do not work there, and the agent token works nowhere else. Agents read what the
dashboard shows, hold issues (recorded as `agent:<name>`, and pushed to open dashboards), and
start LLM jobs without the operator's confirm step; every such write is rate-limited
(`agent.WriteLimit`) and recorded in the store's audit log, a job with the estimate it was
started from. The jobs are the dashboard's own (`start_analysis`, `start_explain`,
`start_describe`): one of each kind at a time, the analyst's reach rules unchanged.
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import dataclasses
import enum
import hashlib
import hmac
import ipaddress
import json
import logging
import math
import re
import secrets
import time
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable, Iterable, Iterator, Mapping
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from ssl import SSLContext
from typing import Any, Protocol

from aiohttp import web

from neonwatch import jobs
from neonwatch.analyst import AnalysisRequest, LogTemplate, ServiceUnit
from neonwatch.config import Config
from neonwatch.logs import JournalRead
from neonwatch.probes import CATALOG, ProbeSpec
from neonwatch.schema import (
    Analysis,
    Attestation,
    Event,
    Issue,
    IssueState,
    Kind,
    Severity,
    to_body,
)
from neonwatch.store import LogExplanation, ServiceDescription, Store, StoreError
from neonwatch.web import agent, board, hardware

log = logging.getLogger(__name__)

MAX_BODY = 64 * 1024
KEEPALIVE_S = 15.0
SNOOZE_MAX_S = 7 * 86400
COOKIE = "neonwatch_token"
SESSION_COOKIE = "neonwatch_session"
#: The session cookie's name under TLS: the prefix makes the browser keep it Secure, Path=/ and
#: host-only, so it is not handed to other services on the same name.
TLS_SESSION_COOKIE = "__Host-neonwatch_session"
#: Static files served without a session in password mode: what the login page loads.
LOGIN_ASSETS = frozenset({"login.html", "app.css"})
STATIC = Path(__file__).parent / "static"
LOGIN_PAGE = STATIC / "login.html"
HSTS = "max-age=31536000"

#: Failed logins allowed in any `LOGIN_WINDOW_S`, from one client address and from all of them.
LOGIN_ADDRESS_FAILURES = 5
LOGIN_GLOBAL_FAILURES = 30
LOGIN_WINDOW_S = 300
MAX_PASSWORD = 1024

#: What `hash_password` writes. `verify_password` reads any parameters inside the bounds below.
SCRYPT_N, SCRYPT_R, SCRYPT_P = 2**15, 8, 1
SALT_BYTES, KEY_BYTES = 16, 32
#: The most memory a stored hash may make one verify spend (scrypt needs about 128·r·N bytes).
SCRYPT_MAX_MEMORY = 256 * 1024**2
SCRYPT_MAX_P = 16

#: Bounds on a series query: the step, and the number of buckets it may ask for.
MAX_STEP_S = 86400
MAX_POINTS = 10_000
MAX_NAME = 200

#: Bounds on an analysis selection and on what is gathered for it.
MAX_SUBJECTS = 20
MAX_SUBJECT_LEN = 256
MAX_QUESTION = 2000
MAX_ITEMS = 100
MAX_CONTEXT = 200
MAX_WINDOW_S = 86400
#: Analyses in flight at once; each is a backend call that may cost money.
MAX_RUNNING = 2
#: Context is gathered from this far either side of the selected items' times.
CONTEXT_WINDOW_S = 900
#: Item kinds that bring only their own records as context, never a whole observation.
OWN_KINDS = ("job", "service")

#: Bounds on a log explanation or service description request, and the finished jobs of each
#: kind remembered for polling.
MAX_LOG_KEYS = 200
MAX_LOG_JOBS = 20
#: A template key (`logs.template_key`) or a service key (`jobs.service_key`).
_KEY = re.compile(r"[0-9a-f]{16}")
#: What an agent sends as `keys` to mean every kind or service not yet explained or described.
ALL_UNCACHED = "all_uncached"
#: Most audit rows one agent request lists.
MAX_AUDIT_LIST = 500

#: More rows than this since a Last-Event-ID, and the client is told to reset instead.
MAX_REPLAY = 1000
#: Events buffered per stream before a slow client is told to reset.
QUEUE_SIZE = 1000

#: A probe is stale once its latest observation is older than this many expected intervals.
STALE_AFTER = 3
#: The hardware strip's sparklines: the last hour, a point a minute (the fast tier's cadence).
HARDWARE_WINDOW_S = 3600
HARDWARE_STEP_S = 60
#: Keys in observation data that name a thing, where an entity's name is matched as a token.
IDENTITY_FIELDS = frozenset({"pid", "name", "unit", "device", "mount", "index"})

HEADERS = {
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
    "Content-Security-Policy": ("default-src 'self'; base-uri 'none'; form-action 'self'; "
                                "frame-ancestors 'none'"),
    "Referrer-Policy": "no-referrer",
}

PLACEHOLDER = ("<!doctype html><html><head><meta charset=\"utf-8\"><title>neonwatch</title></head>"
               "<body><h1>neonwatch</h1><p>The dashboard is not installed. "
               "The API is at <code>/api/overview</code>.</p></body></html>")

_STATIC_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")
_WINDOW = re.compile(r"^window:(\d+(?:\.\d+)?)-(\d+(?:\.\d+)?)$")
_SEVERITIES = tuple(reversed(Severity))  # critical first


def hash_password(password: str) -> str:
    """`scrypt$N$r$p$<salt>$<key>` (standard base64) for `password`, with a fresh 16-byte salt."""
    salt = secrets.token_bytes(SALT_BYTES)
    key = _scrypt(password.encode("utf-8"), salt, SCRYPT_N, SCRYPT_R, SCRYPT_P, KEY_BYTES)
    return "$".join(("scrypt", str(SCRYPT_N), str(SCRYPT_R), str(SCRYPT_P),
                     base64.b64encode(salt).decode(), base64.b64encode(key).decode()))


def verify_password(password: str, encoded: str) -> bool:
    """Whether `password` is the one `encoded` was made from. Anything malformed is False."""
    if not isinstance(password, str) or not isinstance(encoded, str):
        return False
    try:
        n, r, p, salt, expected = _parse_scrypt(encoded)
        candidate = _scrypt(password.encode("utf-8"), salt, n, r, p, len(expected))
    except ValueError:  # includes binascii.Error and UnicodeEncodeError
        return False
    return hmac.compare_digest(candidate, expected)


_DECIMAL = re.compile(r"[1-9][0-9]*")  # ASCII digits only, no sign, no leading zero


def _parse_scrypt(encoded: str) -> tuple[int, int, int, bytes, bytes]:
    parts = encoded.split("$")
    if len(parts) != 6 or parts[0] != "scrypt" or not all(
            _DECIMAL.fullmatch(part) for part in parts[1:4]):
        raise ValueError("not an scrypt hash")
    n, r, p = (int(part) for part in parts[1:4])
    if (n < 2**14 or n & (n - 1) or r < 8 or not 1 <= p <= SCRYPT_MAX_P
            or _scrypt_memory(n, r, p) > SCRYPT_MAX_MEMORY):
        raise ValueError("scrypt parameters out of bounds")
    salt, key = (base64.b64decode(part, validate=True) for part in parts[4:])
    if len(salt) < SALT_BYTES or not 16 <= len(key) <= 64:
        raise ValueError("scrypt salt or key has the wrong length")
    return n, r, p, salt, key


def _scrypt_memory(n: int, r: int, p: int) -> int:
    return 128 * r * (n + p + 2)


def _scrypt(password: bytes, salt: bytes, n: int, r: int, p: int, length: int) -> bytes:
    return hashlib.scrypt(password, salt=salt, n=n, r=r, p=p, dklen=length,
                          maxmem=_scrypt_memory(n, r, p) + 1024 * 1024)


class Live(Protocol):
    def subscribe(self) -> AsyncIterator[Event]:
        ...


def _bears_on(a: Attestation, issue: Issue) -> bool:
    """An answer the issue rests on. The evaluator builds an issue from the answers about its
    domain and entity alone, so matching a reason would add only others' answers: `impact` or
    `action` is asked of every process, and a process's issue listed them all."""
    return a.entity == issue.entity and a.domain == issue.domain


class _Refused(Exception):
    """A request this layer will not serve, and the one line it says about why."""

    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.message = message


@dataclasses.dataclass(frozen=True, slots=True)
class _Frame:
    """One event on its way to the stream."""

    kind: str
    at: float
    subject: str
    body: Mapping[str, Any]


@dataclasses.dataclass(slots=True)
class _Session:
    expires: float
    csrf: str


class _Ended(Exception):
    """The stream's session is gone: logged out or expired."""


_END = object()  # the live source ended, the session ended, or the server is shutting down
_RESET = object()  # the client fell behind
#: Set on an app built with a password; `start` reads it.
_PASSWORD = web.AppKey("neonwatch.password", bool)
#: Where the guard leaves a request's (table key, session) for the handler.
_SESSION = web.RequestKey("neonwatch.session", tuple)
#: Where the agent guard leaves the caller's name.
_AGENT = web.RequestKey("neonwatch.agent", str)
LOGIN_FAILED = "That password was not accepted."
LOGIN_LIMITED = "Too many failed attempts. Try again in a few minutes."


def make_app(store: Store, live: Live, token: str, config: Config, analyst: Any = None, *,
             judge_health: Callable[[], Awaitable[Mapping[str, Any]]] | None = None,
             read_logs: Callable[[], Awaitable[JournalRead]] | None = None,
             agent_token: Callable[[], str] | None = None,
             clock: Callable[[], float] = time.time, keepalive_s: float = KEEPALIVE_S,
             static_dir: Path = STATIC, queue_size: int = QUEUE_SIZE) -> web.Application:
    """The application. Binding it (to `config.web.host`, `config.web.port`) is the caller's job.

    `analyst` has `estimate(AnalysisRequest)`, `async analyze(AnalysisRequest)`,
    `estimate_logs(templates)` and `async explain_logs(templates)`; without it the analysis and
    log-explanation routes answer 503. `judge_health`, when given, is awaited by `/api/health`.
    `read_logs` reads the journal for `/api/logs`; without it that route answers 503. With
    `config.web.password_hash` set, `token` is ignored (and may be empty): the login replaces it.
    `agent_token` returns the agent API's token (it may raise when the file is unusable); it is
    called for every agent request, and without it the agent API answers 503.
    """
    if not token and not config.web.password_hash:
        raise ValueError("the per-launch token must not be empty")
    return _Web(store, live, token, config, analyst, judge_health, read_logs, clock,
                keepalive_s, Path(static_dir), queue_size, agent_token).app


async def start(app: web.Application, host: str, port: int,
                ssl_context: SSLContext | None = None) -> Callable[[], Awaitable[None]]:
    """Serve `app` on exactly `host`:`port`, over TLS when `ssl_context` is given, and return the
    function that stops it.

    Refuses (ValueError), before anything is bound, a host that is not loopback unless there is
    an `ssl_context` and `app` was made with a password hash. The stop function cleans up the
    runner, running the app's shutdown and cleanup; calling it again is a no-op.
    """
    try:
        loopback = ipaddress.ip_address(host).is_loopback
    except ValueError:
        loopback = host == "localhost"
    if not loopback and (ssl_context is None or not app.get(_PASSWORD, False)):
        raise ValueError(f"the web server binds beyond loopback only with TLS and a password; "
                         f"refusing {host!r}")
    runner = web.AppRunner(app)
    await runner.setup()
    try:
        await web.TCPSite(runner, host, port, ssl_context=ssl_context).start()
    except BaseException:
        await runner.cleanup()
        raise
    stopped = False

    async def stop() -> None:
        nonlocal stopped
        if not stopped:
            stopped = True
            await runner.cleanup()

    return stop


class _Web:
    def __init__(self, store: Store, live: Live, token: str, config: Config, analyst: Any,
                 judge_health: Callable[[], Awaitable[Mapping[str, Any]]] | None,
                 read_logs: Callable[[], Awaitable[JournalRead]] | None,
                 clock: Callable[[], float], keepalive_s: float, static_dir: Path,
                 queue_size: int, agent_token: Callable[[], str] | None = None) -> None:
        self.store = store
        self.live = live
        self.token = token.encode()
        self.csrf = secrets.token_urlsafe(32)
        self.config = config
        self.analyst = analyst
        self.judge_health = judge_health
        #: The Board view's layout, read once: a bad one refuses the service at start.
        self.board = board.load(config.web.board)
        self.read_logs = read_logs
        #: One journal read at a time; the kinds of line the last listing showed, by key.
        self.log_lock = asyncio.Lock()
        self.log_kinds: dict[str, LogTemplate] = {}
        #: Explain jobs by id, running or recently finished (at most `MAX_LOG_JOBS` finished).
        self.log_jobs: dict[str, dict[str, Any]] = {}
        #: The services the last listing showed, by key, and describe jobs as explain jobs are.
        self.service_units: dict[str, ServiceUnit] = {}
        self.service_jobs: dict[str, dict[str, Any]] = {}
        self.clock = clock
        self.keepalive_s = keepalive_s
        self.static_dir = static_dir
        self.queue_size = queue_size
        port = config.web.port
        loopback = frozenset({f"127.0.0.1:{port}", f"localhost:{port}", f"[::1]:{port}"})
        self.hosts = frozenset(h.lower() for h in config.web.allowed_hosts) or loopback
        #: The agent API answers loopback peers only, under the dashboard's names or these.
        self.agent_hosts = self.hosts | loopback
        self.agent_token = agent_token
        self.writes = agent.WriteLimit()
        self.password_hash = config.web.password_hash
        #: HMAC(session_key, session id) -> session. The id itself is never kept.
        self.sessions: dict[bytes, _Session] = {}
        self.session_key = secrets.token_bytes(32)
        #: Times of failed (or in-flight) logins in the window, per client and all together.
        self.failures: dict[str, list[float]] = {}
        self.all_failures: list[float] = []
        #: scrypt runs here, one at a time, so logins queue rather than crowd the default pool.
        self.verifier = (ThreadPoolExecutor(max_workers=1, thread_name_prefix="neonwatch-login")
                         if self.password_hash else None)
        self.streams: set[asyncio.Queue] = set()
        #: An open stream's queue -> the session table key it was opened with.
        self.stream_owners: dict[asyncio.Queue, bytes] = {}
        self.live_error = ""
        self.running: dict[str, dict[str, Any]] = {}
        self.tasks: set[asyncio.Task] = set()

        app = web.Application(middlewares=[self.guard], client_max_size=MAX_BODY)
        app[_PASSWORD] = bool(self.password_hash)
        app.on_response_prepare.append(self.headers)
        app.on_shutdown.append(self.shutdown)
        app.on_cleanup.append(self.cleanup)
        r = app.router
        r.add_get("/", self.root)
        r.add_get("/api/overview", self.overview)
        r.add_get("/api/issues", self.issues)
        r.add_get("/api/issues/{id}", self.issue)
        r.add_post("/api/issues/{id}/ack", self.ack)
        r.add_post("/api/issues/{id}/snooze", self.snooze)
        r.add_get("/api/incidents", self.incidents)
        r.add_get("/api/domains/{domain}", self.domain)
        r.add_get("/api/series", self.series)
        r.add_get("/api/hardware", self.hardware)
        r.add_get("/api/scheduled", self.scheduled)
        r.add_get("/api/services", self.services)
        r.add_get("/api/health", self.health)
        r.add_get("/api/session", self.session)
        r.add_get("/api/stream", self.stream)
        r.add_post("/api/analyses/estimate", self.estimate)
        r.add_post("/api/analyses", self.analyze)
        r.add_get("/api/analyses/{id}", self.analysis)
        r.add_get("/api/logs", self.logs)
        r.add_post("/api/logs/estimate", self.estimate_logs)
        r.add_post("/api/logs/explain", self.explain_logs)
        r.add_get("/api/logs/explain/{id}", self.log_job)
        r.add_post("/api/services/estimate", self.estimate_services)
        r.add_post("/api/services/describe", self.describe_services)
        r.add_get("/api/services/describe/{id}", self.service_job)
        a = agent.PREFIX
        r.add_get(f"{a}/summary", self.agent_summary)
        r.add_get(f"{a}/issues", self.agent_issues)
        r.add_get(f"{a}/issues/{{id}}", self.agent_issue)
        r.add_post(f"{a}/issues/{{id}}/ack", self.agent_ack)
        r.add_post(f"{a}/issues/{{id}}/snooze", self.agent_snooze)
        r.add_get(f"{a}/services", self.agent_services)
        r.add_get(f"{a}/services/{{name}}", self.agent_service)
        r.add_get(f"{a}/scheduled", self.agent_scheduled)
        r.add_get(f"{a}/logs", self.agent_logs)
        r.add_post(f"{a}/jobs/analysis/estimate", self.agent_estimate_analysis)
        r.add_post(f"{a}/jobs/analysis", self.agent_start_analysis)
        r.add_post(f"{a}/jobs/describe/estimate", self.agent_estimate_describe)
        r.add_post(f"{a}/jobs/describe", self.agent_start_describe)
        r.add_post(f"{a}/jobs/explain/estimate", self.agent_estimate_explain)
        r.add_post(f"{a}/jobs/explain", self.agent_start_explain)
        r.add_get(f"{a}/jobs/{{id}}", self.agent_job)
        r.add_get(f"{a}/audit", self.agent_audit)
        if self.password_hash:
            self.login_page = LOGIN_PAGE.read_text()
            r.add_get("/login", self.login_form)
            r.add_post("/login", self.login)
            r.add_post("/logout", self.logout)
        r.add_get("/{name}", self.static)
        self.app = app

    # --- the guard ------------------------------------------------------------------------

    @web.middleware
    async def guard(self, request: web.Request, handler: Any) -> web.StreamResponse:
        try:
            if request.path.startswith(agent.PREFIX + "/"):
                self.authorize_agent(request)
                return await handler(request)
            host = request.headers.get("Host", "").lower()
            if host not in self.hosts:
                raise _Refused(403, "unexpected Host header")
            if request.path.startswith("/api/") or (self.password_hash
                                                    and request.path == "/logout"):
                self.authorize(request, host)
            return await handler(request)
        except _Refused as refused:
            return _error(refused.status, refused.message)
        except web.HTTPException as http:
            if http.status < 400:
                raise  # a redirect
            return _error(http.status, _HTTP_MESSAGES.get(http.status, "request refused"))
        except Exception:
            log.exception("%s %s failed", request.method, request.path)
            return _error(500, "internal error")

    def authorize(self, request: web.Request, host: str) -> None:
        if self.password_hash:
            found = self.session_of(request)
            if found is None:
                raise _Refused(401, "not logged in")
            request[_SESSION] = found
            csrf = found[1].csrf
        else:
            header = request.headers.get("Authorization")
            bearer = header[7:] if header is not None and header.startswith("Bearer ") else None
            if not (self.valid(bearer) or self.valid(request.cookies.get(COOKIE))):
                raise _Refused(401, "missing or wrong token")
            csrf = self.csrf
        if request.method in ("GET", "HEAD"):
            return
        if not _same(request.headers.get("X-CSRF-Token"), csrf.encode()):
            raise _Refused(403, "missing or wrong CSRF token")
        if request.headers.get("Origin") != _origin(request, host):
            raise _Refused(403, "cross-origin write refused")

    def valid(self, candidate: str | None) -> bool:
        return _same(candidate, self.token)

    def authorize_agent(self, request: web.Request) -> None:
        """The agent API's guard: loopback peer, Host, no Origin, the agent token, a name."""
        if not agent.loopback_peer(request.remote):
            raise _Refused(403, "the agent API answers loopback clients only")
        if request.headers.get("Host", "").lower() not in self.agent_hosts:
            raise _Refused(403, "unexpected Host header")
        if "Origin" in request.headers:
            raise _Refused(403, "the agent API does not answer browsers")
        if self.agent_token is None:
            raise _Refused(503, "the agent API is not configured")
        try:
            expected = self.agent_token()
        except Exception as bad:
            log.warning("the agent token cannot be read: %s", bad)
            raise _Refused(503, "the agent token cannot be read; see the service log") from None
        header = request.headers.get("Authorization")
        bearer = header[7:] if header is not None and header.startswith("Bearer ") else None
        if not expected or not _same(bearer, expected.encode()):
            raise _Refused(401, "missing or wrong agent token")
        name = request.headers.get(agent.NAME_HEADER)
        if not agent.valid_name(name):
            raise _Refused(400, f"{agent.NAME_HEADER} must name the agent: 1-64 of "
                                "A-Z a-z 0-9 . _ : -")
        request[_AGENT] = name

    def session_of(self, request: web.Request) -> tuple[bytes, _Session] | None:
        """The live session this request's cookie names; an expired one is removed."""
        sid = request.cookies.get(_session_cookie(request))
        if not sid:
            return None
        key = self.table_key(sid)
        return (key, self.sessions[key]) if self.live_session(key) else None

    def live_session(self, key: bytes) -> bool:
        """Whether the session under `key` exists and has not expired; an expired one ends."""
        session = self.sessions.get(key)
        if session is None:
            return False
        if session.expires <= self.clock():
            self.end_session(key)
            return False
        return True

    def end_session(self, key: bytes) -> None:
        """Forget the session, and end every stream opened with it."""
        self.sessions.pop(key, None)
        for queue, owner in list(self.stream_owners.items()):
            if owner == key:
                _offer(queue, _END)

    def table_key(self, sid: str) -> bytes:
        return hmac.new(self.session_key, sid.encode("utf-8", "surrogateescape"),
                        hashlib.sha256).digest()

    async def headers(self, request: web.Request, response: web.StreamResponse) -> None:
        response.headers.update(HEADERS)
        if request.secure:
            response.headers["Strict-Transport-Security"] = HSTS
        if self.password_hash and request.path == "/login":
            response.headers["Referrer-Policy"] = "same-origin"

    # --- logging in -----------------------------------------------------------------------

    async def login_form(self, request: web.Request) -> web.Response:
        return self.page(LOGIN_FAILED if "failed" in request.query else "")

    def page(self, message: str, status: int = 200) -> web.Response:
        """The login page, with one of this module's fixed messages (never request text)."""
        note = f'<p class="status" role="alert">{message}</p>' if message else ""
        return web.Response(text=self.login_page.replace("<!--status-->", note, 1),
                            content_type="text/html", status=status)

    async def login(self, request: web.Request) -> web.StreamResponse:
        if request.headers.get("Origin") != _origin(request, request.headers["Host"].lower()):
            raise _Refused(403, "cross-origin login refused")
        password = await _login_password(request)
        address, client, now = request.remote or "", _client_key(request.remote), self.clock()
        wait = self.limited(client, now)
        if wait:
            log.warning("login from %s refused: too many failed attempts", address)
            refused = self.page(LOGIN_LIMITED, status=429)
            refused.headers["Retry-After"] = str(wait)
            return refused
        # Counted before the check, which yields for ~0.1 s: concurrent guesses see each other.
        self.failures.setdefault(client, []).append(now)
        self.all_failures.append(now)
        if not await asyncio.get_running_loop().run_in_executor(
                self.verifier, verify_password, password, self.password_hash):
            log.warning("failed login from %s", address)
            raise web.HTTPSeeOther("/login?failed=1")
        for attempts in (self.failures.get(client, []), self.all_failures):
            with contextlib.suppress(ValueError):
                attempts.remove(now)
        for key in [k for k, s in self.sessions.items() if s.expires <= now]:
            self.end_session(key)
        sid = secrets.token_urlsafe(32)
        self.sessions[self.table_key(sid)] = _Session(now + self.config.web.session_s,
                                                      secrets.token_urlsafe(32))
        log.info("login from %s", address)
        response = web.HTTPSeeOther("/")
        response.set_cookie(_session_cookie(request), sid, httponly=True, samesite="Strict",
                            path="/", secure=request.secure or None)
        raise response

    def limited(self, client: str, now: float) -> int:
        """Whole seconds until `client` (see `_client_key`) may try again; 0 when it may now."""
        cutoff = now - LOGIN_WINDOW_S
        self.all_failures = [t for t in self.all_failures if t > cutoff]
        self.failures = {a: kept for a, times in self.failures.items()
                         if (kept := [t for t in times if t > cutoff])}
        waits = [times[-cap] + LOGIN_WINDOW_S - now
                 for times, cap in ((self.failures.get(client, []), LOGIN_ADDRESS_FAILURES),
                                    (self.all_failures, LOGIN_GLOBAL_FAILURES))
                 if len(times) >= cap]
        return max(1, math.ceil(max(waits))) if waits else 0

    async def logout(self, request: web.Request) -> web.StreamResponse:
        key, _ = request[_SESSION]
        self.end_session(key)
        response = web.HTTPSeeOther("/login")
        response.del_cookie(_session_cookie(request), path="/", secure=request.secure or None,
                            httponly=True, samesite="Strict")
        raise response

    # --- the page -------------------------------------------------------------------------

    async def root(self, request: web.Request) -> web.StreamResponse:
        if self.password_hash:
            if self.session_of(request) is None:
                raise web.HTTPSeeOther("/login")
        elif "token" in request.query:
            if not self.valid(request.query["token"]):
                raise _Refused(401, "missing or wrong token")
            response = web.HTTPSeeOther("/")
            response.set_cookie(COOKIE, self.token.decode(), httponly=True, samesite="Strict",
                                path="/")
            raise response
        index = self.static_dir / "index.html"
        if index.is_file():
            return web.FileResponse(index)
        return web.Response(text=PLACEHOLDER, content_type="text/html")

    async def static(self, request: web.Request) -> web.StreamResponse:
        name = request.match_info["name"]
        if (self.password_hash and name not in LOGIN_ASSETS
                and self.session_of(request) is None):
            if name == "index.html":
                raise web.HTTPSeeOther("/login")
            raise _Refused(401, "not logged in")
        path = self.static_dir / name
        if not _STATIC_NAME.match(name) or not path.is_file():
            raise web.HTTPNotFound()
        return web.FileResponse(path)

    # --- reads ----------------------------------------------------------------------------

    async def overview(self, _request: web.Request) -> web.Response:
        now = self.clock()
        open_issues = self.store.issues(IssueState.OPEN)
        grouped = {s.value: self.issue_bodies([i for i in open_issues if i.severity is s])
                   for s in _SEVERITIES}
        beat = self.store.last_heartbeat()
        heartbeat = None if beat is None else {"at": beat[0], "age_s": now - beat[0],
                                               **to_body(beat[1])}
        probes = []
        for at, obs in self.store.latest():
            spec = _spec(obs.probe)
            expected = None if spec is None else getattr(self.config.cadence, spec.tier.value)
            probes.append({"probe": obs.probe, "at": at, "age_s": now - at, "error": obs.error,
                           "truncated": obs.truncated,
                           "tier": None if spec is None else spec.tier.value,
                           "expected_s": expected,
                           # No known cadence is never shown as fresh.
                           "stale": expected is None or now - at > STALE_AFTER * expected})
        # A catalog probe that never reported is unknown, not absent. Templates appear only
        # through the expansions that have reported.
        reported = {row["probe"] for row in probes}
        probes += [{"probe": spec.id, "at": None, "age_s": None, "error": "", "truncated": False,
                    "tier": spec.tier.value,
                    "expected_s": getattr(self.config.cadence, spec.tier.value), "stale": True}
                   for spec in CATALOG if not spec.devices and spec.id not in reported]
        return _json({
            "now": now,
            "open": grouped,
            "counts": {sev: len(items) for sev, items in grouped.items()},
            "incidents": _plain(self.store.incidents()),
            "domains": _plain(self.store.domains()),
            "heartbeat": heartbeat,
            "probes": probes,
        })

    async def issues(self, request: web.Request) -> web.Response:
        state = request.query.get("state")
        try:
            wanted = IssueState(state) if state is not None else None
        except ValueError:
            raise _Refused(400, f"state must be one of {[s.value for s in IssueState]}") from None
        return _json({"issues": self.issue_bodies(self.store.issues(wanted))})

    async def issue(self, request: web.Request) -> web.Response:
        issue_id = request.match_info["id"]
        found = self.store.issue(issue_id)
        if found is None:
            raise _Refused(404, "not found")
        attestations = [(at, a) for at, a in self.store.attestations(latest=True)
                        if _bears_on(a, found)]
        findings = [(at, f) for at, f in self.store.findings(latest=True)
                    if f.entity == found.entity]
        return _json({
            "issue": self.issue_bodies([found])[0],
            "attestations": _plain(attestations),
            "findings": _plain(findings),
            "observations": _plain(self.observations_for({found.entity})),
            "analyses": _plain(self.store.analyses(f"issue:{issue_id}")),
        })

    async def incidents(self, _request: web.Request) -> web.Response:
        return _json({"incidents": _plain(self.store.incidents())})

    async def domain(self, request: web.Request) -> web.Response:
        name = request.match_info["domain"]
        summary = self.store.domains().get(name)
        if summary is None:
            raise _Refused(404, "not found")
        return _json({
            "domain": name,
            "summary": _plain(summary),
            "issues": self.issue_bodies([i for i in self.store.issues() if i.domain == name]),
            "attestations": _plain([(at, a) for at, a in self.store.attestations(latest=True)
                                    if a.domain == name]),
        })

    async def series(self, request: web.Request) -> web.Response:
        now = self.clock()
        query = request.query
        probe, field = query.get("probe", ""), query.get("field", "")
        if not probe or not field or len(probe) > MAX_NAME or len(field) > MAX_NAME:
            raise _Refused(400, f"probe and field are required, each at most {MAX_NAME} chars")
        since = _number(query.get("since"), now - 3600.0)
        if since is None or since < 0:
            raise _Refused(400, "since must be a non-negative epoch time")
        step_raw = query.get("step", "60")
        if not step_raw.isdigit() or not 1 <= int(step_raw) <= MAX_STEP_S:
            raise _Refused(400, f"step must be a whole number of seconds, 1-{MAX_STEP_S}")
        step = int(step_raw)
        if (now - since) / step > MAX_POINTS:
            raise _Refused(400, f"that asks for more than {MAX_POINTS} points; raise step")
        points = self.store.series(probe, field, since, step)
        return _json({"probe": probe, "field": field, "since": since, "step": step,
                      "points": _plain(points)})

    async def hardware(self, _request: web.Request) -> web.Response:
        """The hardware strip's and Board view's data (`hardware.snapshot`), with the last
        `HARDWARE_WINDOW_S` of every series it names, in `HARDWARE_STEP_S` buckets, and CPU
        utilisation from the tick counters over the same buckets; and the Board view's layout
        (`web.board`) with the slot each part is drawn in (`board.place`)."""
        now = self.clock()
        latest: dict[str, tuple[float, Any]] = {}
        errors: dict[str, str] = {}
        for at, obs in self.store.latest():
            if obs.error:
                errors[obs.probe] = obs.error
            else:
                latest[obs.probe] = (at, obs.data)

        def stale_after(probe: str) -> float:
            spec = _spec(probe)
            return 0.0 if spec is None else STALE_AFTER * getattr(self.config.cadence,
                                                                  spec.tier.value)

        found = hardware.snapshot(latest, errors, now, stale_after)
        since = now - HARDWARE_WINDOW_S
        history = [{"probe": probe, "field": field,
                    "points": _plain(self.store.series(probe, field, since, HARDWARE_STEP_S))}
                   for probe, field in hardware.series_of(found)]
        ticks = {name: [(p.t, p.value) for p in self.store.series("cpu.stat", name, since,
                                                                   HARDWARE_STEP_S)]
                 for name in hardware.TICKS}
        util = hardware.cpu_util(ticks)
        return _json({**found, "since": since, "step": HARDWARE_STEP_S, "history": history,
                      "cpu_util": [{"t": t, "value": v} for t, v in util],
                      "board": {"layout": self.board, "placed": board.place(self.board, found)}})

    async def scheduled(self, _request: web.Request) -> web.Response:
        latest, as_of, probes = self.parsed()
        found, skipped = jobs.scheduled(latest)
        attested = self.attested()
        return _json({"as_of": as_of, "probes": probes, "skipped": skipped,
                      "jobs": [_judged(job, attested.get(f"job:{job['id']}", []))
                               for job in found]})

    async def services(self, _request: web.Request) -> web.Response:
        listing, self.service_units = self.service_listing()
        return _json(listing)

    def service_listing(self) -> tuple[dict[str, Any], dict[str, ServiceUnit]]:
        """The Services view's listing, and what describing each service would send, by key."""
        latest, as_of, probes = self.parsed()
        attested = self.attested()
        issues: dict[str, list[dict[str, Any]]] = {}
        for i in self.store.issues(IssueState.OPEN):
            issues.setdefault(i.entity, []).append(
                {"id": i.id, "severity": i.severity.value, "title": i.title})
        timers: dict[str, list[str]] = {}
        for job in jobs.scheduled(latest)[0]:
            if job["source"] == "timer" and job["unit"]:
                timers.setdefault(job["unit"], []).append(job["id"].removeprefix("timer:"))
        listed = jobs.services(latest)
        cached = self.store.service_descriptions(s["name"] for s in listed)
        sightings = self.store.service_sightings()
        units: dict[str, ServiceUnit] = {}
        found = []
        for service in listed:
            entity, key = f"unit:{service['name']}", jobs.service_key(service)
            units[key] = _service_unit(service, key, timers.get(service["name"], []))
            known = cached.get(service["name"])
            first_seen, new = sightings.get(service["name"], (None, False))
            found.append({**_judged(service, attested.get(entity, [])),
                          "issues": issues.get(entity, []), "key": key,
                          "timers": list(units[key].timers),
                          "described": _described(known if known and known.key == key else None),
                          # Described once, but the definition has changed since.
                          "description_outdated": known is not None and known.key != key,
                          # New: first seen after the services the monitor started with.
                          "first_seen_at": first_seen, "new": new})
        self.store.touch_service_descriptions(
            [s["name"] for s in found if s["described"]], self.clock())
        return {"as_of": as_of, "probes": probes, "services": found}, units

    def parsed(self) -> tuple[dict[str, Any], float | None, dict[str, dict[str, Any]]]:
        """What `jobs` joins: each of its probes' latest data (a failed probe's is left out),
        the newest of their times, and every one of its probes' time and error."""
        probes: dict[str, dict[str, Any]] = {p: {"at": None, "error": ""}
                                             for p in sorted(jobs.PROBES)}
        latest: dict[str, Any] = {}
        as_of = None
        for at, obs in self.store.latest():
            if obs.probe in probes:
                probes[obs.probe] = {"at": at, "error": obs.error}
                if not obs.error:
                    latest[obs.probe] = obs.data
                    as_of = at if as_of is None else max(as_of, at)
        return latest, as_of, probes

    def attested(self) -> dict[str, list[dict[str, Any]]]:
        """Each entity's latest attestations, summarised, newest first."""
        found: dict[str, list[dict[str, Any]]] = {}
        for at, a in self.store.attestations(latest=True):
            found.setdefault(a.entity, []).append({
                "at": at, "question": a.question, "severity": a.severity.value,
                "stable": a.stable, "confidence": a.confidence, "cause": a.cause,
                "next_step": a.next_step})
        return found

    async def health(self, _request: web.Request) -> web.Response:
        try:
            self.store.last_heartbeat()
            store = {"ok": True, "error": ""}
        except Exception as bad:
            store = {"ok": False, "error": type(bad).__name__}
        return _json({
            "store": store,
            "live": {"streams": len(self.streams), "error": self.live_error},
            "analyst": {"configured": self.analyst is not None,
                        "provider": self.config.analyst.provider,
                        "model": self.config.analyst.model},
            "judge": await self.judge_status(),
        })

    async def judge_status(self) -> dict[str, Any] | None:
        """The judge's health as the judge reports it, or None when nothing reports it."""
        if self.judge_health is None:
            return None
        try:
            return dict(await self.judge_health())
        except Exception as bad:
            return {"ok": False, "error": type(bad).__name__}

    async def session(self, request: web.Request) -> web.Response:
        return _json({"csrf": request[_SESSION][1].csrf if self.password_hash else self.csrf})

    async def analysis(self, request: web.Request) -> web.Response:
        return _json(self.analysis_status(request.match_info["id"]))

    def analysis_status(self, analysis_id: str) -> dict[str, Any]:
        if analysis_id in self.running:
            return self.running[analysis_id]
        for record in self.store.analyses():
            if record.id == analysis_id:
                return {"status": "failed" if record.error else "done", **to_body(record)}
        raise _Refused(404, "not found")

    # --- writes ---------------------------------------------------------------------------

    async def ack(self, request: web.Request) -> web.Response:
        issue_id = request.match_info["id"]
        held = self.hold(issue_id, self.store.ack, self.clock())
        return _json({"issue": self.issue_bodies([held])[0]})

    async def snooze(self, request: web.Request) -> web.Response:
        issue_id = request.match_info["id"]
        body = await _body(request, required={"until"})
        until = _until(body["until"], self.clock())
        held = self.hold(issue_id, self.store.snooze, until)
        return _json({"issue": self.issue_bodies([held])[0]})

    def hold(self, issue_id: str, action: Callable[..., Any], value: float, by: str = "") -> Any:
        try:
            return action(issue_id, value, by=by)
        except KeyError:
            raise _Refused(404, "not found") from None
        except StoreError:
            raise _Refused(409, f"issue {issue_id} is resolved") from None

    def issue_bodies(self, issues: Iterable[Issue]) -> list[dict[str, Any]]:
        """Issues as the dashboard's routes give them: the record, plus `held_by` (who holds
        it: "operator", `agent:<name>`, or null when it is not held)."""
        holds = self.store.holds()
        return [{**to_body(i), "held_by": agent.holder(holds.get(i.id))} for i in issues]

    async def estimate(self, request: web.Request) -> web.Response:
        analyst = self.need_analyst()
        built = self.build(await _body(request, required={"subjects"}, optional={"question"}))
        return _json({"estimate": _plain(analyst.estimate(built)),
                      "subjects": list(built.subjects), "items": len(built.items),
                      "context": len(built.context)})

    async def analyze(self, request: web.Request) -> web.Response:
        analyst = self.need_analyst()
        self.analysis_slot()
        built = self.build(await _body(request, required={"subjects"}, optional={"question"}))
        return _json({"id": self.start_analysis(analyst, built), "status": "running"},
                     status=202)

    def analysis_slot(self) -> None:
        if len(self.running) >= MAX_RUNNING:
            raise _Refused(429, f"{MAX_RUNNING} analyses are already running; "
                                "wait for one to finish")

    def start_analysis(self, analyst: Any, built: AnalysisRequest) -> str:
        """Start one analysis job (429 when `MAX_RUNNING` are running); returns its id."""
        self.analysis_slot()
        job = f"an-{uuid.uuid4().hex}"
        self.running[job] = {"id": job, "status": "running", "subjects": list(built.subjects),
                             "requested_at": self.clock()}
        task = asyncio.create_task(self.run_analysis(analyst, job, built))
        self.tasks.add(task)
        task.add_done_callback(self.tasks.discard)
        return job

    async def run_analysis(self, analyst: Any, job: str, built: AnalysisRequest) -> None:
        """Every outcome is saved as an `Analysis` (a failure has `error` set), then streamed,
        and the job leaves `running`, so memory stays bounded by `MAX_RUNNING`."""
        timeout = self.config.analyst.timeout_s
        try:
            try:
                answer = await asyncio.wait_for(analyst.analyze(built), timeout)
            except TimeoutError:
                answer = self.failed(job, built,
                                     f"the analysis backend did not answer within {timeout:g} s")
            except Exception as bad:
                log.exception("analysis %s failed", job)
                answer = self.failed(job, built, f"analysis failed: {type(bad).__name__}")
            result: Analysis = dataclasses.replace(answer, id=job)
            try:
                self.store.save_analysis(result)
            except Exception as bad:
                log.exception("analysis %s could not be saved", job)
                result = dataclasses.replace(
                    result, error=f"the analysis could not be saved: {type(bad).__name__}")
        finally:
            self.running.pop(job, None)
        self.broadcast(_Frame("analysis", result.completed_at, f"analysis.{job}",
                              to_body(result)))

    def failed(self, job: str, built: AnalysisRequest, error: str) -> Analysis:
        return Analysis(id=job, requested_at=self.running[job]["requested_at"],
                        completed_at=self.clock(), backend=self.config.analyst.provider,
                        model=self.config.analyst.model, subjects=built.subjects,
                        question=built.question, text="", suggested_checks=(), input_chars=0,
                        output_chars=0, error=error)

    def need_analyst(self) -> Any:
        if self.analyst is None:
            raise _Refused(503, "no analysis backend is configured")
        return self.analyst

    # --- the Logs view ----------------------------------------------------------------------

    async def logs(self, _request: web.Request) -> web.Response:
        listing, self.log_kinds = await self.log_listing()
        return _json(listing)

    async def log_listing(self) -> tuple[dict[str, Any], dict[str, LogTemplate]]:
        """Read the journal: the Logs view's listing, and the kinds of line in it by key."""
        if self.read_logs is None:
            raise _Refused(503, "the journal reader is not configured")
        async with self.log_lock:
            read = await self.read_logs()
        now = self.clock()
        kinds: dict[str, LogTemplate] = {}
        for line in read.lines:
            known = kinds.get(line.key)
            seen = [p for p in (line.priority, known.priority if known else None) if p is not None]
            kinds[line.key] = LogTemplate(line.key, line.source, line.template,
                                          min(seen, default=None))
        cached = self.store.log_explanations(kinds)
        self.store.touch_log_explanations(cached, now)
        return {
            "read_at": now, "error": read.error, "truncated": read.truncated,
            "skipped": read.skipped, "templates": len(kinds),
            "uncached": len(set(kinds) - set(cached)),
            "lines": [{"at": line.at, "priority": line.priority, "unit": line.unit,
                       "identifier": line.identifier, "message": line.message, "key": line.key,
                       "explanation": _explanation(cached.get(line.key))}
                      for line in read.lines]}, kinds

    def log_templates(self, keys: list[str], kinds: Mapping[str, LogTemplate],
                      again: str = "load the lines again") -> list[LogTemplate]:
        """The requested kinds the listing `kinds` showed and the cache does not hold."""
        cached = self.store.log_explanations(keys)
        wanted = sorted({k for k in keys if k in kinds and k not in cached})
        if not wanted:
            raise _Refused(409, "nothing new to explain: every key is explained or was not in "
                                f"the last listing; {again}")
        return [kinds[k] for k in wanted]

    async def estimate_logs(self, request: web.Request) -> web.Response:
        analyst = self.need_analyst()
        keys = _keys(await _body(request, required={"keys"}), "template")
        templates = self.log_templates(keys, self.log_kinds)
        return _json({"estimate": _plain(analyst.estimate_logs(templates)),
                      "keys": [t.key for t in templates]})

    async def explain_logs(self, request: web.Request) -> web.Response:
        analyst = self.need_analyst()
        self.explain_slot()
        keys = _keys(await _body(request, required={"keys"}), "template")
        templates = self.log_templates(keys, self.log_kinds)
        return _json({"id": self.start_explain(analyst, templates), "status": "running",
                      "keys": len(templates)}, status=202)

    def explain_slot(self) -> None:
        if any(job["status"] == "running" for job in self.log_jobs.values()):
            raise _Refused(429, "log lines are already being explained; wait for that to finish")

    def start_explain(self, analyst: Any, templates: list[LogTemplate]) -> str:
        """Start one log explanation job (429 while one runs); returns its id."""
        self.explain_slot()
        by_key = {t.key: t for t in templates}

        def save(result: Any, now: float) -> int:
            self.store.save_log_explanations(
                LogExplanation(key=key, source=by_key[key].source,
                               template=by_key[key].template, explanation=text,
                               model=result.model, created_at=now, last_seen_at=now)
                for key, text in result.explanations.items() if key in by_key)
            return len(result.explanations)

        return self.start_keyed(self.log_jobs, "lx", len(templates), lambda job: self.run_keyed(
            self.log_jobs, job, lambda: analyst.estimate_logs(templates),
            lambda progress: analyst.explain_logs(templates, progress), save, "explained",
            "log explanation"))

    async def log_job(self, request: web.Request) -> web.Response:
        return _json(self.keyed_job(self.log_jobs, request.match_info["id"]))

    def service_targets(self, keys: list[str], units: Mapping[str, ServiceUnit],
                        again: str = "load the services again") -> list[ServiceUnit]:
        """The requested services the listing `units` showed that are not described for their
        current definition."""
        shown = [units[k] for k in sorted(set(keys)) if k in units]
        cached = self.store.service_descriptions(u.name for u in shown)
        wanted = [u for u in shown if (c := cached.get(u.name)) is None or c.key != u.key]
        if not wanted:
            raise _Refused(409, "nothing new to describe: every key is described or was not in "
                                f"the last listing; {again}")
        return wanted

    async def estimate_services(self, request: web.Request) -> web.Response:
        analyst = self.need_analyst()
        keys = _keys(await _body(request, required={"keys"}), "service")
        units = self.service_targets(keys, self.service_units)
        return _json({"estimate": _plain(analyst.estimate_services(units)),
                      "keys": [u.key for u in units]})

    async def describe_services(self, request: web.Request) -> web.Response:
        analyst = self.need_analyst()
        self.describe_slot()
        keys = _keys(await _body(request, required={"keys"}), "service")
        units = self.service_targets(keys, self.service_units)
        return _json({"id": self.start_describe(analyst, units), "status": "running",
                      "keys": len(units)}, status=202)

    def describe_slot(self) -> None:
        if any(job["status"] == "running" for job in self.service_jobs.values()):
            raise _Refused(429, "services are already being described; wait for that to finish")

    def start_describe(self, analyst: Any, units: list[ServiceUnit]) -> str:
        """Start one service description job (429 while one runs); returns its id."""
        self.describe_slot()
        by_key = {u.key: u for u in units}

        def save(result: Any, now: float) -> int:
            self.store.save_service_descriptions(
                ServiceDescription(name=by_key[key].name, key=key, brief=text.brief,
                                   full=text.full, model=result.model, created_at=now,
                                   last_seen_at=now)
                for key, text in result.descriptions.items() if key in by_key)
            return len(result.descriptions)

        return self.start_keyed(self.service_jobs, "sd", len(units), lambda job: self.run_keyed(
            self.service_jobs, job, lambda: analyst.estimate_services(units),
            lambda progress: analyst.describe_services(units, progress), save, "described",
            "service description"))

    async def service_job(self, request: web.Request) -> web.Response:
        return _json(self.keyed_job(self.service_jobs, request.match_info["id"]))

    def start_keyed(self, jobs_of: dict[str, dict[str, Any]], prefix: str, count: int,
                    run: Callable[[str], Awaitable[None]]) -> str:
        job = f"{prefix}-{uuid.uuid4().hex}"
        jobs_of[job] = {"id": job, "status": "running", "requested_at": self.clock(),
                        "keys": count}
        task = asyncio.create_task(run(job))
        self.tasks.add(task)
        task.add_done_callback(self.tasks.discard)
        return job

    async def run_keyed(self, jobs_of: dict[str, dict[str, Any]], job: str,
                        estimate: Callable[[], Any],
                        call: Callable[[Callable[[int, int, Any], None]], Awaitable[Any]],
                        save: Callable[[Any, float], int], counted: str, what: str) -> None:
        """Every outcome ends the job with a status; what was answered is saved first. The
        timeout is the analyst's per request, times the requests the estimate says it takes.

        Each request's answers are saved as it finishes, and the job carries requests_done,
        requests_total, started_at and the count saved so far, so the dashboard can show a
        bar and a time left; a timeout keeps what was saved before it (live, 20 requests took
        minutes with nothing to show, 2026-10-27). Saving is idempotent, so the final save of
        the whole result repeats the batches harmlessly."""
        record = jobs_of[job]
        timeout = self.config.analyst.timeout_s
        saved = 0

        def progress(done: int, total: int, partial: Any) -> None:
            nonlocal saved
            saved += save(partial, self.clock())
            record.update({"requests_done": done, "requests_total": total, counted: saved})

        try:
            requests = max(1, estimate().requests)
            record.update({"requests_done": 0, "requests_total": requests,
                           "started_at": self.clock(), counted: 0})
            timeout *= requests
            result = await asyncio.wait_for(call(progress), timeout)
            answered = save(result, self.clock())
            record.update({counted: answered, "requests": result.requests,
                           "failed": result.failed, "error": result.error,
                           "status": "done" if answered or not result.error else "failed"})
        except TimeoutError:
            record.update({"status": "failed", counted: saved,
                           "error": f"the analysis backend did not answer within {timeout:g} s"
                                    + (f"; {saved} saved before that" if saved else "")})
        except Exception as bad:
            log.exception("%s %s failed", what, job)
            record.update({"status": "failed", counted: 0,
                           "error": f"{what} failed: {type(bad).__name__}"})
        finally:
            if record["status"] == "running":  # cancelled on shutdown
                record["status"] = "failed"
            record["completed_at"] = self.clock()
            finished = [k for k, j in jobs_of.items() if j["status"] != "running"]
            for old in finished[:-MAX_LOG_JOBS]:
                del jobs_of[old]

    def keyed_job(self, jobs_of: dict[str, dict[str, Any]], job: str) -> dict[str, Any]:
        found = jobs_of.get(job)
        if found is None:
            raise _Refused(404, "not found")
        return found

    # --- the agent API --------------------------------------------------------------------

    def agent_write(self, request: web.Request) -> str:
        """The caller's name, once this write is within the limit; 429 beyond it."""
        name = request[_AGENT]
        wait = self.writes.take(name, self.clock())
        if wait:
            raise _Refused(429, f"too many writes: {self.writes.per_agent} a minute per agent "
                                f"and {self.writes.total} in all; try again in {wait} s")
        return name

    def audit(self, name: str, action: str, target: str, detail: Mapping[str, Any]) -> None:
        self.store.audit(self.clock(), name, action, target, detail)

    async def agent_summary(self, _request: web.Request) -> web.Response:
        now = self.clock()
        try:
            beat = self.store.last_heartbeat()
            store = {"ok": True, "error": ""}
        except Exception as bad:
            beat, store = None, {"ok": False, "error": type(bad).__name__}
        open_issues = self.store.issues(IssueState.OPEN)
        settings = self.config.analyst
        return _json({
            "now": now,
            "vitals": {
                "agent": None if beat is None else {
                    "heartbeat_at": beat[0], "heartbeat_age_s": now - beat[0],
                    **to_body(beat[1])},
                "judge": await self.judge_status(),
                "store": store,
                "analyst": {"configured": self.analyst is not None,
                            "provider": settings.provider, "model": settings.model,
                            "reach": settings.reach},
            },
            "counts": agent.counts(open_issues),
            "held": len(self.store.holds()),
            "open": [agent.issue(i, None) for i in open_issues],
            "incidents": [agent.incident(i) for i in self.store.incidents()],
        })

    async def agent_issues(self, request: web.Request) -> web.Response:
        state = request.query.get("state")
        try:
            wanted = IssueState(state) if state is not None else None
        except ValueError:
            raise _Refused(400, f"state must be one of {[s.value for s in IssueState]}") from None
        holds = self.store.holds()
        return _json({"issues": [agent.issue(i, holds.get(i.id))
                                 for i in self.store.issues(wanted)]})

    async def agent_issue(self, request: web.Request) -> web.Response:
        issue_id = request.match_info["id"]
        found = self.store.issue(issue_id)
        if found is None:
            raise _Refused(404, "not found")
        return _json({
            "issue": agent.issue(found, self.store.holds().get(issue_id)),
            "findings": [agent.finding(at, f) for at, f in self.store.findings(latest=True)
                         if f.entity == found.entity],
            "attestations": [agent.attestation(at, a)
                             for at, a in self.store.attestations(latest=True)
                             if _bears_on(a, found)],
            "analyses": [{"id": a.id, "completed_at": a.completed_at, "model": a.model,
                          "question": a.question, "text": a.text,
                          "suggested_checks": list(a.suggested_checks), "error": a.error}
                         for a in self.store.analyses(f"issue:{issue_id}")],
        })

    async def agent_ack(self, request: web.Request) -> web.Response:
        name = self.agent_write(request)
        await _empty_body(request)
        issue_id = request.match_info["id"]
        held = self.hold(issue_id, self.store.ack, self.clock(), by=f"agent:{name}")
        self.audit(name, "ack", issue_id, {})
        return self.announce(held)

    async def agent_snooze(self, request: web.Request) -> web.Response:
        name = self.agent_write(request)
        body = await _body(request, required=set(), optional={"until", "for_s"})
        now = self.clock()
        if len(body) != 1:
            raise _Refused(400, "give one of until (epoch seconds) or for_s (seconds)")
        if "for_s" in body:
            span = body["for_s"]
            if (isinstance(span, bool) or not isinstance(span, int | float)
                    or not 0 < span <= SNOOZE_MAX_S):
                raise _Refused(400, f"for_s must be 1-{SNOOZE_MAX_S} seconds")
            until = now + float(span)
        else:
            until = _until(body["until"], now)
        issue_id = request.match_info["id"]
        held = self.hold(issue_id, self.store.snooze, until, by=f"agent:{name}")
        self.audit(name, "snooze", issue_id, {"until": until})
        return self.announce(held)

    def announce(self, held: Issue) -> web.Response:
        """Tell open dashboards about an agent's hold, and answer the agent with it."""
        self.broadcast(_Frame("issue", self.clock(), f"issue.{held.id}",
                              self.issue_bodies([held])[0]))
        return _json({"issue": agent.issue(held, self.store.holds().get(held.id))})

    async def agent_services(self, _request: web.Request) -> web.Response:
        listing, _ = self.service_listing()
        found = [agent.pick(s, agent.SERVICE_FIELDS) for s in listing["services"]]
        return _json({"as_of": listing["as_of"],
                      "uncached": sum(1 for s in found if s["described"] is None),
                      "services": found})

    async def agent_service(self, request: web.Request) -> web.Response:
        name = request.match_info["name"]
        listing, _ = self.service_listing()
        for service in listing["services"]:
            if service["name"] == name:
                return _json({"as_of": listing["as_of"], "service": service})
        raise _Refused(404, "not found")

    async def agent_scheduled(self, _request: web.Request) -> web.Response:
        latest, as_of, _ = self.parsed()
        found, skipped = jobs.scheduled(latest)
        attested = self.attested()
        return _json({"as_of": as_of, "skipped": skipped,
                      "jobs": [agent.pick(_judged(job, attested.get(f"job:{job['id']}", [])),
                                          agent.JOB_FIELDS) for job in found]})

    async def agent_logs(self, _request: web.Request) -> web.Response:
        listing, _ = await self.log_listing()
        return _json(listing)

    def planned_analysis(self, analyst: Any, built: AnalysisRequest) -> dict[str, Any]:
        return {"estimate": _plain(analyst.estimate(built)), "subjects": list(built.subjects),
                "items": len(built.items), "context": len(built.context)}

    async def agent_estimate_analysis(self, request: web.Request) -> web.Response:
        analyst = self.need_analyst()
        built = self.build(await _body(request, required={"subjects"}, optional={"question"}))
        return _json(self.planned_analysis(analyst, built))

    async def agent_start_analysis(self, request: web.Request) -> web.Response:
        analyst = self.need_analyst()
        name = self.agent_write(request)
        self.analysis_slot()
        built = self.build(await _body(request, required={"subjects"}, optional={"question"}))
        planned = self.planned_analysis(analyst, built)
        job = self.start_analysis(analyst, built)
        self.audit(name, "start_analysis", job,
                   {**_audited(planned["estimate"]), "subjects": planned["subjects"],
                    "question": built.question[:200]})
        return _json({"id": job, "kind": "analysis", "status": "running", **planned},
                     status=202)

    async def agent_describe_targets(self, request: web.Request) -> list[ServiceUnit]:
        body = await _body(request, required={"keys"})
        _, units = self.service_listing()
        keys = sorted(units) if body["keys"] == ALL_UNCACHED else _keys(body, "service")
        return self.service_targets(keys, units, again="list the services again")

    async def agent_estimate_describe(self, request: web.Request) -> web.Response:
        analyst = self.need_analyst()
        units = await self.agent_describe_targets(request)
        return _json({"estimate": _plain(analyst.estimate_services(units)),
                      "keys": [u.key for u in units]})

    async def agent_start_describe(self, request: web.Request) -> web.Response:
        analyst = self.need_analyst()
        name = self.agent_write(request)
        self.describe_slot()
        units = await self.agent_describe_targets(request)
        estimate = _plain(analyst.estimate_services(units))
        job = self.start_describe(analyst, units)
        self.audit(name, "start_describe", job, {**_audited(estimate), "keys": len(units)})
        return _json({"id": job, "kind": "describe", "status": "running", "keys": len(units),
                      "estimate": estimate}, status=202)

    async def agent_explain_targets(self, request: web.Request) -> list[LogTemplate]:
        body = await _body(request, required={"keys"})
        keys = None if body["keys"] == ALL_UNCACHED else _keys(body, "template")
        _, kinds = await self.log_listing()
        return self.log_templates(sorted(kinds) if keys is None else keys, kinds,
                                  again="read the logs again")

    async def agent_estimate_explain(self, request: web.Request) -> web.Response:
        analyst = self.need_analyst()
        templates = await self.agent_explain_targets(request)
        return _json({"estimate": _plain(analyst.estimate_logs(templates)),
                      "keys": [t.key for t in templates]})

    async def agent_start_explain(self, request: web.Request) -> web.Response:
        analyst = self.need_analyst()
        name = self.agent_write(request)
        self.explain_slot()
        templates = await self.agent_explain_targets(request)
        estimate = _plain(analyst.estimate_logs(templates))
        job = self.start_explain(analyst, templates)
        self.audit(name, "start_explain", job, {**_audited(estimate), "keys": len(templates)})
        return _json({"id": job, "kind": "explain", "status": "running",
                      "keys": len(templates), "estimate": estimate}, status=202)

    async def agent_job(self, request: web.Request) -> web.Response:
        job = request.match_info["id"]
        if job.startswith("an-"):
            return _json({"kind": "analysis", **self.analysis_status(job)})
        if job.startswith("lx-"):
            return _json({"kind": "explain", **self.keyed_job(self.log_jobs, job)})
        if job.startswith("sd-"):
            return _json({"kind": "describe", **self.keyed_job(self.service_jobs, job)})
        raise _Refused(404, "not found")

    async def agent_audit(self, request: web.Request) -> web.Response:
        query = request.query
        limit = query.get("limit", "100")
        if not limit.isdigit() or not 1 <= int(limit) <= MAX_AUDIT_LIST:
            raise _Refused(400, f"limit must be 1-{MAX_AUDIT_LIST}")
        who = query.get("agent")
        if who is not None and not agent.valid_name(who):
            raise _Refused(400, "agent must be an agent name")
        since = _number(query.get("since"), None)
        if "since" in query and since is None:
            raise _Refused(400, "since must be an epoch time")
        rows = self.store.audit_log(int(limit), who, since)
        return _json({"entries": [dataclasses.asdict(row) for row in rows]})

    # --- building an analysis request ------------------------------------------------------

    def build(self, body: Mapping[str, Any]) -> AnalysisRequest:
        subjects, question = body["subjects"], body.get("question", "")
        if (not isinstance(subjects, list) or not 1 <= len(subjects) <= MAX_SUBJECTS
                or not all(isinstance(s, str) and len(s) <= MAX_SUBJECT_LEN for s in subjects)):
            raise _Refused(400, f"subjects must be a list of 1-{MAX_SUBJECTS} strings")
        if not isinstance(question, str) or len(question) > MAX_QUESTION:
            raise _Refused(400, f"question must be a string of at most {MAX_QUESTION} chars")
        items: dict[str, dict[str, Any]] = {}
        for subject in subjects:
            for item in self.resolve(subject):
                items.setdefault(item["subject"], item)
        chosen = list(items.values())[:MAX_ITEMS]
        return AnalysisRequest(subjects=tuple(subjects), question=question,
                               items=tuple(chosen), context=self.context(chosen))

    def resolve(self, subject: str) -> list[dict[str, Any]]:
        """The items one subject names. Unknown shapes are 400; nothing stored is 404."""
        kind, _, key = subject.partition(":")
        if kind == "issue" and key:
            found = self.store.issue(key)
            if found is not None:
                return [_item("issue", subject, found.updated_at, found)]
        elif kind == "finding" and _finding_key(key):
            rule, _, entity = key.partition("@")
            for at, f in self.store.findings(latest=True):
                if f.rule == rule and f.entity == entity:
                    return [_item("finding", subject, at, f)]
        elif kind == "link" and key:
            for incident in self.store.incidents():
                if incident.link.id == key:
                    return [_item("link", subject, incident.at, incident.link),
                            *(_item("issue", f"issue:{i.id}", i.updated_at, i)
                              for i in incident.issues),
                            *(_item("finding", f"finding:{f.rule}@{f.entity}", at, f)
                              for at, f in incident.findings)]
        elif kind in ("job", "unit") and key:
            latest, as_of, _ = self.parsed()
            if kind == "job":
                found = [(j, "job") for j in jobs.scheduled(latest)[0] if j["id"] == key]
            else:
                found = [(s, "service") for s in jobs.services(latest) if s["name"] == key]
            if found:
                record, label = found[0]
                return [{"kind": label, "subject": subject, "at": as_of, "record": record}]
        elif (window := _WINDOW.match(subject)) is not None:
            start, end = float(window[1]), float(window[2])
            if start < end <= start + MAX_WINDOW_S:
                return self.window(start, end)
            raise _Refused(400, f"unknown subject: {subject}")
        else:
            raise _Refused(400, f"unknown subject: {subject}")
        raise _Refused(404, f"no such subject: {subject}")

    def window(self, start: float, end: float) -> list[dict[str, Any]]:
        found = [_item("issue", f"issue:{i.id}", i.updated_at, i) for i in self.store.issues()
                 if start <= i.updated_at <= end]
        found += [_item("finding", f"finding:{f.rule}@{f.entity}", at, f)
                  for at, f in self.store.findings(since=start) if at <= end]
        found += [_item("attestation", f"attestation:{a.context}/{a.question}", at, a)
                  for at, a in self.store.attestations(since=start) if at <= end]
        found.sort(key=lambda item: (item["at"], item["subject"]))
        return found

    def context(self, items: list[dict[str, Any]]) -> tuple[dict[str, Any], ...]:
        """Related records, none repeating an item, newest first. A job or a service brings only
        its own (`own`); any other item its entities' records near its time (`nearby`)."""
        own = [item for item in items if item["kind"] in OWN_KINDS]
        found = self.nearby([item for item in items if item["kind"] not in OWN_KINDS])
        found += self.own(own)
        taken = {(item["kind"], item["subject"], item["at"]) for item in items}
        unique: dict[tuple[str, str, float], dict[str, Any]] = {}
        for c in found:
            unique.setdefault((c["kind"], c["subject"], c["at"]), c)
        found = [c for key, c in unique.items() if key not in taken]
        found.sort(key=lambda c: (-c["at"], c["kind"], c["subject"]))
        return tuple(found[:MAX_CONTEXT])

    def nearby(self, items: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Same entities, within `CONTEXT_WINDOW_S` of the items' times."""
        entities = {e for item in items if (e := item["record"].get("entity"))}
        times = [item["at"] for item in items]
        if not entities or not times:
            return []
        low, high = min(times) - CONTEXT_WINDOW_S, max(times) + CONTEXT_WINDOW_S
        found = [_item("finding", f"finding:{f.rule}@{f.entity}", at, f)
                 for at, f in self.store.findings(since=low)
                 if at <= high and f.entity in entities]
        found += [_item("attestation", f"attestation:{a.context}/{a.question}", at, a)
                  for at, a in self.store.attestations(since=low)
                  if at <= high and a.entity in entities]
        found += [_item("observation", f"observation:{o.probe}", at, o)
                  for at, o in self.observations_for(entities)]
        return found

    def own(self, items: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """A job's or service's own latest attestations however old (a job is asked about only
        when it is new or changes), the findings and issues on it, and a timer's service record.
        Never an observation: one `units.detail` holds every service's command."""
        subjects = {item["subject"] for item in items}
        found = [_item("attestation", f"attestation:{a.context}/{a.question}", at, a)
                 for at, a in self.store.attestations(latest=True) if a.entity in subjects]
        found += [_item("finding", f"finding:{f.rule}@{f.entity}", at, f)
                  for at, f in self.store.findings(latest=True) if f.entity in subjects]
        found += [_item("issue", f"issue:{i.id}", i.updated_at, i)
                  for i in self.store.issues() if i.entity in subjects]
        units = {unit for item in items if item["kind"] == "job"
                 and (unit := item["record"].get("unit"))}
        if units:
            latest, as_of, _ = self.parsed()
            found += [{"kind": "service", "subject": f"unit:{s['name']}", "at": as_of,
                       "record": s} for s in jobs.services(latest) if s["name"] in units]
        return found

    def observations_for(self, entities: set[str]) -> list[tuple[float, Any]]:
        """Latest observations naming one of the entities (the part after `kind:`) as a whole
        token in an identity field (`IDENTITY_FIELDS`), never in free text such as a message."""
        names = {e.partition(":")[2] or e for e in entities if e}
        return [(at, obs) for at, obs in self.store.latest()
                if names & set(_identity_tokens(obs.data))]

    # --- the event stream -----------------------------------------------------------------

    async def stream(self, request: web.Request) -> web.StreamResponse:
        if request.method == "HEAD":  # headers only; nothing to hold open
            return web.Response(headers={"Content-Type": "text/event-stream"})
        response = web.StreamResponse(headers={"Content-Type": "text/event-stream"})
        await response.prepare(request)
        queue: asyncio.Queue = asyncio.Queue(maxsize=self.queue_size)
        self.streams.add(queue)
        owner = request[_SESSION][0] if self.password_hash else None
        if owner is not None:
            self.stream_owners[queue] = owner
        pump = asyncio.create_task(self.pump(queue))
        count = 0

        def check() -> None:
            if owner is not None and not self.live_session(owner):
                raise _Ended

        async def send(frame: _Frame) -> None:
            nonlocal count
            check()
            try:
                data = _frame(count + 1, frame)
            except ValueError:  # NaN or infinity: not JSON a browser can parse
                log.warning("dropped an unencodable %s event on %s", frame.kind, frame.subject)
                return
            count += 1
            await response.write(data)

        try:
            last = request.headers.get("Last-Event-ID")
            if last is not None:
                for frame in self.replay(last):
                    await send(frame)
            while True:
                try:
                    item = await asyncio.wait_for(queue.get(), self.keepalive_s)
                except TimeoutError:
                    check()
                    await response.write(b": keepalive\n\n")
                    continue
                if item is _END:
                    break
                await send(self.reset("fell behind") if item is _RESET else item)
        except (ConnectionError, _Ended):
            pass  # the client went away, or its session did
        finally:
            self.streams.discard(queue)
            self.stream_owners.pop(queue, None)
            pump.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await pump
        return response

    async def pump(self, queue: asyncio.Queue) -> None:
        try:
            async for event in self.live.subscribe():
                self.live_error = ""
                _offer(queue, self.live_frame(event))
        except Exception as bad:
            self.live_error = type(bad).__name__
            log.warning("live source failed: %s", self.live_error)
        _offer(queue, _END)

    def live_frame(self, event: Event) -> _Frame:
        """An event as the page shows it. An issue goes out as the store keeps it: the evaluator
        knows nothing of holds, so its view of an acknowledged issue still says open."""
        body = event.body
        if event.kind is Kind.ISSUE:
            try:
                stored = self.store.issue(str(body.get("id")))
            except StoreError as bad:
                log.warning("live issue %s sent as the evaluator saw it: %s", event.subject, bad)
                stored = None
            if stored is not None:
                body = self.issue_bodies([stored])[0]
        return _Frame(event.kind.value, event.at, event.subject, body)

    def broadcast(self, frame: _Frame) -> None:
        for queue in list(self.streams):
            _offer(queue, frame)

    def replay(self, last: str) -> list[_Frame]:
        """What the store holds since the `at` in a Last-Event-ID, or one reset frame."""
        parts = last.split(":")
        at = _number(parts[2], None) if len(parts) == 3 else None
        now = self.clock()
        if (at is None or not parts[0].isdigit() or not parts[1]
                or not now - self.config.retention.max_age_s <= at <= now):
            return [self.reset("cannot replay from that id")]
        replayed = [i for i in self.store.issues() if i.updated_at >= at]
        frames = [_Frame("issue", i.updated_at, f"issue.{i.id}", body)
                  for i, body in zip(replayed, self.issue_bodies(replayed), strict=True)]
        frames += [_Frame("finding", t, f"finding.{f.rule}", to_body(f))
                   for t, f in self.store.findings(since=at)]
        frames += [_Frame("attestation", t, f"attest.{a.context}", to_body(a))
                   for t, a in self.store.attestations(since=at)]
        if len(frames) > MAX_REPLAY:
            return [self.reset("too much to replay")]
        return sorted(frames, key=lambda f: (f.at, f.subject))

    def reset(self, reason: str) -> _Frame:
        return _Frame("reset", self.clock(), "reset", {"reason": reason})

    # --- lifecycle ------------------------------------------------------------------------

    async def shutdown(self, _app: web.Application) -> None:
        for queue in list(self.streams):
            _drain(queue)
            queue.put_nowait(_END)

    async def cleanup(self, _app: web.Application) -> None:
        for task in list(self.tasks):
            task.cancel()
        await asyncio.gather(*self.tasks, return_exceptions=True)
        if self.verifier is not None:
            self.verifier.shutdown(wait=False, cancel_futures=True)


# --- helpers ------------------------------------------------------------------------------------

_HTTP_MESSAGES = {404: "not found", 405: "method not allowed", 413: "request body too large"}


_BY_ID = {spec.id: spec for spec in CATALOG}


def _spec(probe: str) -> ProbeSpec | None:
    """The catalog entry for a probe id; an expanded `<template>.<device>` id finds its template."""
    if probe in _BY_ID:
        return _BY_ID[probe]
    template, _, device = probe.partition(".")
    spec = _BY_ID.get(template)
    if spec is not None and spec.devices and re.fullmatch(spec.devices, device):
        return spec
    return None


def _identity_tokens(data: Any) -> Iterator[str]:
    """Whitespace-separated tokens of every identity field's scalar value, at any depth."""
    if isinstance(data, Mapping):
        for key, value in data.items():
            if key in IDENTITY_FIELDS and isinstance(value, str | int) \
                    and not isinstance(value, bool):
                yield from str(value).split()
            else:
                yield from _identity_tokens(value)
    elif isinstance(data, list):
        for value in data:
            yield from _identity_tokens(value)


def _same(candidate: str | None, secret: bytes) -> bool:
    """Constant-time equality of a presented value with a secret."""
    if candidate is None:
        return False
    return hmac.compare_digest(candidate.encode("utf-8", "surrogateescape"), secret)


def _session_cookie(request: web.Request) -> str:
    """The session cookie's name on this request's transport; the other name is never read."""
    return TLS_SESSION_COOKIE if request.secure else SESSION_COOKIE


def _client_key(remote: str | None) -> str:
    """Whom a failed login is counted against: an IPv4 address (an IPv4-mapped IPv6 address
    counts as its IPv4 address), or an IPv6 address's /64, since one host may hold many."""
    if not remote:
        return ""
    try:
        address = ipaddress.ip_address(remote)
    except ValueError:
        return remote
    if isinstance(address, ipaddress.IPv6Address):
        if address.ipv4_mapped is not None:
            return str(address.ipv4_mapped)
        return str(ipaddress.IPv6Network((int(address) >> 64 << 64, 64)))
    return str(address)


def _origin(request: web.Request, host: str) -> str:
    """The one Origin a write to `host` may come from: https on a TLS connection."""
    return f"{'https' if request.secure else 'http'}://{host}"


async def _login_password(request: web.Request) -> str:
    """The one `password` field of a urlencoded login form, or 400."""
    if request.content_type == "application/x-www-form-urlencoded":
        form = await request.post()
        values = form.getall("password", [])
        if (set(form) == {"password"} and len(values) == 1 and isinstance(values[0], str)
                and len(values[0]) <= MAX_PASSWORD):
            return values[0]
    raise _Refused(400, "the login form sends one password field")


def _error(status: int, message: str) -> web.Response:
    return _json({"error": message}, status=status)


def _json(data: Any, status: int = 200) -> web.Response:
    return web.json_response(data, status=status,
                             dumps=lambda d: json.dumps(d, allow_nan=False))


def _frame(count: int, frame: _Frame) -> bytes:
    data = json.dumps({**frame.body, "at": frame.at, "subject": frame.subject},
                      separators=(",", ":"), allow_nan=False)
    return (f"id: {count}:{frame.kind}:{frame.at!r}\nevent: {frame.kind}\n"
            f"data: {data}\n\n").encode()


def _offer(queue: asyncio.Queue, item: Any) -> None:
    """Queue an item for a stream; a full queue is emptied and replaced by a reset."""
    try:
        queue.put_nowait(item)
    except asyncio.QueueFull:
        _drain(queue)
        queue.put_nowait(_END if item is _END else _RESET)


def _drain(queue: asyncio.Queue) -> None:
    while not queue.empty():
        queue.get_nowait()


async def _body(request: web.Request, required: set[str],
                optional: frozenset[str] | set[str] = frozenset()) -> dict[str, Any]:
    """The JSON object in a request body, with exactly the fields allowed."""
    raw = await request.read()  # raises 413 past client_max_size
    try:
        body = json.loads(raw, parse_constant=_no_constant)
    except (ValueError, UnicodeDecodeError):
        raise _Refused(400, "body is not JSON") from None
    if not isinstance(body, dict):
        raise _Refused(400, "body must be a JSON object")
    if extra := sorted(set(body) - required - set(optional)):
        raise _Refused(400, f"unexpected field(s): {', '.join(extra)}")
    if missing := sorted(required - set(body)):
        raise _Refused(400, f"missing field(s): {', '.join(missing)}")
    return body


async def _empty_body(request: web.Request) -> None:
    """No body, or an empty JSON object."""
    if await request.read():
        await _body(request, required=set())


def _until(until: Any, now: float) -> float:
    """A snooze's end: an epoch time after `now` and at most `SNOOZE_MAX_S` from it."""
    if (isinstance(until, bool) or not isinstance(until, int | float)
            or not now < until <= now + SNOOZE_MAX_S):
        raise _Refused(400, "until must be an epoch time within the next 7 days")
    return float(until)


def _audited(estimate: Mapping[str, Any]) -> dict[str, Any]:
    """What the audit log keeps of the estimate an LLM job was started from."""
    return {"chars": estimate["chars"], "requests": estimate.get("requests", 1),
            "url_host": estimate["url_host"], "remote": estimate["remote"],
            "model": estimate["model"]}


def _no_constant(name: str) -> None:
    raise ValueError(f"{name} is not a number")


def _number(raw: str | None, default: float | None) -> float | None:
    """A finite float from a query value, the default when absent, None when unreadable."""
    if raw is None:
        return default
    try:
        value = float(raw)
    except ValueError:
        return None
    return value if math.isfinite(value) else None


def _finding_key(key: str) -> bool:
    rule, at, entity = key.partition("@")
    return bool(rule and at and entity)


def _judged(record: dict[str, Any], attestations: list[dict[str, Any]]) -> dict[str, Any]:
    """A job or service with its attestations, their worst severity, and whether any wavered."""
    worst = max((Severity(a["severity"]) for a in attestations), key=lambda s: s.rank,
                default=None)
    return {**record, "attestations": attestations,
            "worst": None if worst is None else worst.value,
            "unstable": any(a["stable"] is False for a in attestations)}


def _keys(body: Mapping[str, Any], what: str) -> list[str]:
    keys = body["keys"]
    if (not isinstance(keys, list) or not 1 <= len(keys) <= MAX_LOG_KEYS
            or not all(isinstance(k, str) and _KEY.fullmatch(k) for k in keys)):
        raise _Refused(400, f"keys must be a list of 1-{MAX_LOG_KEYS} {what} keys")
    return keys


def _service_unit(service: Mapping[str, Any], key: str, timers: list[str]) -> ServiceUnit:
    """What describing a service sends: its name, definition and state, and its timers."""
    restarts = service.get("restarts")
    return ServiceUnit(
        key=key, name=service["name"], description=service.get("description") or "",
        exec=" ; ".join(map(str, service.get("exec") or [])), file=service.get("file") or "",
        user=service.get("user") or "", active=service.get("active") or "",
        sub=service.get("sub") or "", result=service.get("result") or "",
        enabled=service.get("enabled") or "",
        restarts=restarts if isinstance(restarts, int) and not isinstance(restarts, bool)
        else None, timers=tuple(sorted(timers)))


def _described(cached: ServiceDescription | None) -> dict[str, Any] | None:
    if cached is None:
        return None
    return {"brief": cached.brief, "full": cached.full, "model": cached.model,
            "created_at": cached.created_at}


def _explanation(cached: LogExplanation | None) -> dict[str, Any] | None:
    if cached is None:
        return None
    return {"text": cached.explanation, "model": cached.model, "created_at": cached.created_at}


def _item(kind: str, subject: str, at: float, record: Any) -> dict[str, Any]:
    return {"kind": kind, "subject": subject, "at": at, "record": to_body(record)}


def _plain(value: Any) -> Any:
    """Records, enums and tuples as JSON. An `(at, record)` pair becomes `{"at": at, ...}`."""
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return {f.name: _plain(getattr(value, f.name)) for f in dataclasses.fields(value)}
    if isinstance(value, enum.Enum):
        return value.value
    if isinstance(value, Mapping):
        return {_plain(k): _plain(v) for k, v in value.items()}
    if isinstance(value, tuple | list):
        if (len(value) == 2 and isinstance(value[0], float)
                and dataclasses.is_dataclass(value[1])):
            return {"at": value[0], **_plain(value[1])}
        return [_plain(v) for v in value]
    return value
