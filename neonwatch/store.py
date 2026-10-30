"""The dashboard's query index: one SQLite database in WAL mode, written by the service alone.

It holds the latest observation per probe, a numeric series for charts, findings, attestations,
issues and heartbeats, each decoded strictly with `schema.from_body` before anything is written.
A body that does not decode raises `SchemaError`, and every event is written in one transaction,
so a refused or failed event leaves nothing behind.

Replaying events is safe: history rows are keyed by their natural key and time, and a
latest-value row only moves forward in time.

The operator's hold on an issue. `ack` and `snooze` are the only writes the web layer makes to
the evaluator's records. Each records who held it (`by`: "" for the dashboard's operator,
`agent:<name>` for a local agent), read back with `holds`; the column is additive, so a database
made before it gains it on open, its existing holds by "". While an issue is acknowledged or
snoozed, a later OPEN event from the evaluator keeps the hold, and who made it (its other fields
still update) unless:
  - its severity ranks above the severity the operator held it at — an escalation reopens it;
  - it is snoozed, and the event arrives at or after the snooze's `until` — the snooze lapsed.
A RESOLVED event ends any hold, and an issue that recurs after resolution is plainly open.
Nothing reads the clock: a snooze lapses on the first event at or after `until`, and `issues()`
reports the stored state.

Series field names. `apply` turns an observation's data into one series per numeric field, at
most `MAX_FIELDS` of them, counted after flattening in the data's own traversal order:
  - a nested object joins its keys with dots: `pressure.memory.some_avg10`;
  - a list of objects names each element by the value of its first key, in `IDENTITY_KEYS`
    order (`index`, `mount`, `device`, `name`, `id`), that holds a non-empty string or an
    integer, so the name survives reordering: `gpus.0.temperature_c`,
    `filesystems./.used_pct`, `filesystems./home.used_pct`. That key itself is not a series.
    An element with none of them is named by its position (`rows.0.v`), and when two elements
    of one list claim the same name, the first keeps it and the second is skipped;
  - booleans, strings, nulls, non-finite numbers, lists of scalars and lists inside lists are
    skipped.
Names are built, not parsed: an identity may itself contain dots or slashes, so the UI forms a
name from the list's key, the identity and the field rather than splitting one apart.

Links and incidents. A LINK event's members must each be `issue:<id>` or
`finding:<rule>@<entity>` (split at the first `@`), and there must be two or more; anything else
is refused, because the store could not resolve it. `incidents()` resolves the latest version of
every link against the issues and latest findings it holds; a member it holds nothing for (not
yet arrived, or pruned) is listed in `missing`, never dropped silently.

Analyses are the operator's manual LLM analyses, saved locally by `save_analysis` (never from
the bus) and replaced whole when saved again under the same id.

Log explanations are a cache, not history: one row per kind of journal line (its template key),
written by `save_log_explanations` when the operator asks the backend LLM to explain lines, and
read back so a line already explained is never sent again. Each row records the model that wrote
it. `touch_log_explanations` marks the kinds a listing showed, and the cache holds at most
`MAX_LOG_EXPLANATIONS` rows: past that, the least recently seen go first. Age and size retention
leave it alone, since the cap already bounds it. The table is additive: a database made before
it existed gains it on open, with the schema version unchanged.

Service descriptions are a cache of the same kind: one row per systemd service (its unit name),
holding the `jobs.service_key` of the definition it was written for, a brief and a full
description, and the model that wrote them. The reader compares the key with the unit's current
one, so a redefined service reads as undescribed and is described afresh, replacing the row. At
most `MAX_SERVICE_DESCRIPTIONS` rows, least recently seen removed first; additive like the log
cache. Both caches share one implementation (`_CACHES`).

The audit log records every write and LLM job a local agent makes through the agent API: when,
which agent, the action, its target, and a JSON detail (for an LLM job, the estimate it was made
from). At most `MAX_AUDIT` rows, the oldest removed first; age and size retention leave it alone,
since the cap already bounds it. Additive like the caches.

Retention (`prune`): rows older than `retention.max_age_s` go first, latest-value rows included
(analyses by `completed_at`); live (unresolved) issues never do. Then, while
`page_count * page_size` exceeds `retention.max_bytes`, rows are deleted oldest first in
batches, the freed pages released with `incremental_vacuum` after each, in two tiers:
  1. history: series, findings, attestations, links, heartbeats and resolved issues;
  2. analyses, only once no history is left.
Latest-value rows (observations, findings, attestations, links) and live issues are never
removed for size.
"""

from __future__ import annotations

import dataclasses
import json
import math
import os
import sqlite3
from collections import defaultdict
from collections.abc import Callable, Iterable, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from itertools import islice
from pathlib import Path
from typing import Any

from neonwatch.config import Config
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
    SchemaError,
    Severity,
    from_body,
    to_body,
)

VERSION = 1

#: Numeric fields kept per observation for the series; the rest are in the latest row only.
MAX_FIELDS = 200

#: Keys that name a list element in a series field, first present wins. See the module doc.
IDENTITY_KEYS = ("index", "mount", "device", "name", "id")

#: History rows deleted per step of size pruning, between measurements.
PRUNE_BATCH = 2000

#: Cached log explanations kept; the least recently seen beyond this are removed.
MAX_LOG_EXPLANATIONS = 2000
#: Cached service descriptions kept, the same way.
MAX_SERVICE_DESCRIPTIONS = 2000
#: Audit rows kept; the oldest beyond this are removed.
MAX_AUDIT = 10_000


class StoreError(Exception):
    """This database cannot be used, or an operator action does not apply."""


@dataclass(frozen=True, slots=True)
class Point:
    """One bucket of a series: its start (a multiple of the step) and the mean in it."""

    t: float
    value: float


#: A latest attestation is current when it came from its context's latest ask. One ask answers
#: a context's questions together, at one time; a question left out of a later ask (removed
#: from the bank, or no longer evidenced) keeps its row but is no longer current, as it is no
#: longer among the answers the evaluator holds. A dropped question's last WARN sat in the
#: security domain's summary for days otherwise (writable_path, 2026-10-28).
CURRENT = ("attestations_latest.at = (SELECT MAX(l.at) FROM attestations_latest AS l "
           "WHERE l.context = attestations_latest.context)")


@dataclass(frozen=True, slots=True)
class DomainSummary:
    #: Issues in state OPEN, by severity. Every severity is present.
    open: dict[Severity, int]
    #: The current attestations (`CURRENT`), by severity. Every severity is present.
    attested: dict[Severity, int]


@dataclass(frozen=True, slots=True)
class Incident:
    """The latest version of one link, with its members as the store holds them."""

    #: When this version of the link was published.
    at: float
    link: Link
    #: Member issues, in the link's member order.
    issues: tuple[Issue, ...]
    #: Member findings as (at, finding), latest per rule and entity, in member order.
    findings: tuple[tuple[float, Finding], ...]
    #: Member ids the store holds nothing for.
    missing: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class LogExplanation:
    """What one kind of journal line means, as the backend LLM explained it."""

    #: The template key (`logs.template_key`).
    key: str
    #: The masked syslog identifier, else unit, the key was computed over.
    source: str
    template: str
    explanation: str
    #: The model that wrote the explanation.
    model: str
    created_at: float
    last_seen_at: float


@dataclass(frozen=True, slots=True)
class ServiceDescription:
    """What one systemd service is, as the backend LLM described it."""

    #: The unit name.
    name: str
    #: `jobs.service_key` of the definition it was described for.
    key: str
    #: One line.
    brief: str
    full: str
    #: The model that wrote it.
    model: str
    created_at: float
    last_seen_at: float


@dataclass(frozen=True, slots=True)
class Hold:
    """Who holds an acknowledged or snoozed issue, and since or until when."""

    #: "" for the dashboard's operator (or a hold made before this was recorded), else
    #: `agent:<name>`.
    by: str
    #: When it was acknowledged; None for a snooze.
    at: float | None
    #: When a snooze lapses; None for an acknowledgement.
    until: float | None


@dataclass(frozen=True, slots=True)
class AuditEntry:
    """One write or LLM job a local agent made through the agent API."""

    id: int
    at: float
    #: The name the agent gave (`X-Neonwatch-Agent`).
    agent: str
    action: str
    #: What it acted on: an issue id, a job id.
    target: str
    detail: dict[str, Any]


#: Each bounded cache: record type -> (table, its cap, read when used). Its columns are the
#: record's fields, the first the primary key, and `last_seen_at` orders what the cap removes.
_CACHES: dict[type, tuple[str, Callable[[], int]]] = {
    LogExplanation: ("log_explanations", lambda: MAX_LOG_EXPLANATIONS),
    ServiceDescription: ("service_descriptions", lambda: MAX_SERVICE_DESCRIPTIONS),
}

TABLES = ("meta", "observations", "series", "findings", "findings_latest", "attestations",
          "attestations_latest", "issues", "heartbeats", "links", "links_latest", "analyses",
          "log_explanations", "service_descriptions", "audit")

_DDL = (
    "CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value INTEGER NOT NULL)",
    "CREATE TABLE IF NOT EXISTS observations "
    "(probe TEXT PRIMARY KEY, at REAL NOT NULL, body TEXT NOT NULL)",
    "CREATE TABLE IF NOT EXISTS series (probe TEXT NOT NULL, field TEXT NOT NULL, "
    "t REAL NOT NULL, value REAL NOT NULL, PRIMARY KEY (probe, field, t))",
    "CREATE INDEX IF NOT EXISTS series_t ON series (t)",
    "CREATE TABLE IF NOT EXISTS findings (rule TEXT NOT NULL, entity TEXT NOT NULL, "
    "at REAL NOT NULL, body TEXT NOT NULL, PRIMARY KEY (rule, entity, at))",
    "CREATE INDEX IF NOT EXISTS findings_at ON findings (at)",
    "CREATE TABLE IF NOT EXISTS findings_latest (rule TEXT NOT NULL, entity TEXT NOT NULL, "
    "at REAL NOT NULL, body TEXT NOT NULL, PRIMARY KEY (rule, entity))",
    "CREATE TABLE IF NOT EXISTS attestations (context TEXT NOT NULL, question TEXT NOT NULL, "
    "at REAL NOT NULL, body TEXT NOT NULL, PRIMARY KEY (context, question, at))",
    "CREATE INDEX IF NOT EXISTS attestations_at ON attestations (at)",
    "CREATE TABLE IF NOT EXISTS attestations_latest (context TEXT NOT NULL, "
    "question TEXT NOT NULL, domain TEXT NOT NULL, severity TEXT NOT NULL, at REAL NOT NULL, "
    "body TEXT NOT NULL, PRIMARY KEY (context, question))",
    "CREATE TABLE IF NOT EXISTS issues (id TEXT PRIMARY KEY, state TEXT NOT NULL, "
    "severity TEXT NOT NULL, domain TEXT NOT NULL, score REAL NOT NULL, "
    "updated_at REAL NOT NULL, held_severity TEXT, held_at REAL, snoozed_until REAL, "
    "body TEXT NOT NULL, held_by TEXT)",
    "CREATE INDEX IF NOT EXISTS issues_rank ON issues (score DESC, updated_at DESC)",
    "CREATE INDEX IF NOT EXISTS issues_updated ON issues (updated_at)",
    "CREATE TABLE IF NOT EXISTS heartbeats (at REAL PRIMARY KEY, body TEXT NOT NULL)",
    "CREATE TABLE IF NOT EXISTS links (id TEXT NOT NULL, at REAL NOT NULL, "
    "body TEXT NOT NULL, PRIMARY KEY (id, at))",
    "CREATE INDEX IF NOT EXISTS links_at ON links (at)",
    "CREATE TABLE IF NOT EXISTS links_latest "
    "(id TEXT PRIMARY KEY, at REAL NOT NULL, body TEXT NOT NULL)",
    "CREATE TABLE IF NOT EXISTS analyses "
    "(id TEXT PRIMARY KEY, completed_at REAL NOT NULL, body TEXT NOT NULL)",
    "CREATE INDEX IF NOT EXISTS analyses_completed ON analyses (completed_at)",
    "CREATE TABLE IF NOT EXISTS log_explanations (key TEXT PRIMARY KEY, source TEXT NOT NULL, "
    "template TEXT NOT NULL, explanation TEXT NOT NULL, model TEXT NOT NULL, "
    "created_at REAL NOT NULL, last_seen_at REAL NOT NULL)",
    "CREATE INDEX IF NOT EXISTS log_explanations_seen ON log_explanations (last_seen_at)",
    "CREATE TABLE IF NOT EXISTS service_descriptions (name TEXT PRIMARY KEY, key TEXT NOT NULL, "
    "brief TEXT NOT NULL, full TEXT NOT NULL, model TEXT NOT NULL, created_at REAL NOT NULL, "
    "last_seen_at REAL NOT NULL)",
    "CREATE INDEX IF NOT EXISTS service_descriptions_seen ON service_descriptions "
    "(last_seen_at)",
    "CREATE TABLE IF NOT EXISTS service_sightings (name TEXT PRIMARY KEY, "
    "first_seen_at REAL NOT NULL, new INTEGER NOT NULL)",
    "CREATE TABLE IF NOT EXISTS audit (id INTEGER PRIMARY KEY, at REAL NOT NULL, "
    "agent TEXT NOT NULL, action TEXT NOT NULL, target TEXT NOT NULL, detail TEXT NOT NULL)",
    "CREATE INDEX IF NOT EXISTS audit_at ON audit (at)",
    "CREATE TABLE IF NOT EXISTS notified (issue_id TEXT PRIMARY KEY, rank INTEGER NOT NULL, "
    "at REAL NOT NULL)",
    "INSERT OR IGNORE INTO meta (key, value) VALUES ('schema_version', ?)",
)
#: Columns added to a table after it first shipped: (table, column, its declaration).
_ADDED_COLUMNS = (("issues", "held_by", "TEXT"),)

#: Everything older than the cutoff, except issues that are still live.
_AGE_PRUNE = (
    "DELETE FROM observations WHERE at < ?",
    "DELETE FROM series WHERE t < ?",
    "DELETE FROM findings WHERE at < ?",
    "DELETE FROM findings_latest WHERE at < ?",
    "DELETE FROM attestations WHERE at < ?",
    "DELETE FROM attestations_latest WHERE at < ?",
    "DELETE FROM heartbeats WHERE at < ?",
    "DELETE FROM issues WHERE state = 'resolved' AND updated_at < ?",
    "DELETE FROM links WHERE at < ?",
    "DELETE FROM links_latest WHERE at < ?",
    "DELETE FROM analyses WHERE completed_at < ?",
    "DELETE FROM notified WHERE at < ?",
)

#: Size-pruning tiers, each the oldest rows first: every history table merged in time order,
#: then analyses once no history is left.
_SHED = (
    "SELECT 'series', rowid, t FROM series"
    " UNION ALL SELECT 'findings', rowid, at FROM findings"
    " UNION ALL SELECT 'attestations', rowid, at FROM attestations"
    " UNION ALL SELECT 'links', rowid, at FROM links"
    " UNION ALL SELECT 'heartbeats', rowid, at FROM heartbeats"
    " UNION ALL SELECT 'issues', rowid, updated_at FROM issues WHERE state = 'resolved'"
    " ORDER BY 3 LIMIT ?",
    "SELECT 'analyses', rowid, completed_at FROM analyses ORDER BY 3 LIMIT ?",
)

_HELD = (IssueState.ACKNOWLEDGED, IssueState.SNOOZED)


class Store:
    """The query index. Not thread-safe: one connection, used from the thread that opened it."""

    def __init__(self, path: Path, config: Config) -> None:
        self._retention = config.retention
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        os.close(os.open(path, os.O_RDWR | os.O_CREAT, 0o600))  # private before SQLite opens it
        self._db = sqlite3.connect(path, isolation_level=None)
        try:
            self._open(path)
        except sqlite3.DatabaseError as bad:
            self._db.close()
            raise StoreError(f"cannot open {path}: {bad}") from None
        except StoreError:
            self._db.close()
            raise

    def _open(self, path: Path) -> None:
        names = {row[0] for row in
                 self._db.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
        if names and "meta" not in names:
            raise StoreError(f"{path} is not a neonwatch store; refusing to add tables to it")
        if "meta" in names:
            row = self._db.execute("SELECT value FROM meta WHERE key = 'schema_version'")
            version = row.fetchone()
            if version is None:
                raise StoreError(f"{path} records no schema version")
            if version[0] > VERSION:
                raise StoreError(f"{path} has schema version {version[0]}, newer than "
                                 f"{VERSION}; refusing to open it")
            if version[0] < VERSION:
                raise StoreError(f"{path} has schema version {version[0]} and there is no "
                                 f"migration to {VERSION}")
        else:
            # Only takes effect before the first table exists; lets prune release pages.
            self._db.execute("PRAGMA auto_vacuum = INCREMENTAL")
        mode = self._db.execute("PRAGMA journal_mode = WAL").fetchone()[0]
        if mode != "wal":
            raise StoreError(f"{path} cannot run in WAL mode (journal_mode is {mode!r})")
        with self._tx():
            for statement in _DDL:
                self._db.execute(statement, (VERSION,) if "?" in statement else ())
            for table, column, declared in _ADDED_COLUMNS:
                present = {row[1] for row in self._db.execute(f"PRAGMA table_info({table})")}
                if column not in present:
                    self._db.execute(f"ALTER TABLE {table} ADD COLUMN {column} {declared}")

    def close(self) -> None:
        self._db.close()

    @contextmanager
    def _tx(self) -> Iterator[None]:
        self._db.execute("BEGIN IMMEDIATE")
        try:
            yield
        except BaseException:
            self._db.execute("ROLLBACK")
            raise
        self._db.execute("COMMIT")

    # --- writes -----------------------------------------------------------------------------

    def apply(self, event: Event) -> None:
        """Index one event. Raises `SchemaError` for a body that does not decode."""
        handler = _HANDLERS.get(event.kind)
        if handler is None:
            raise SchemaError(f"unknown kind {event.kind!r}")
        cls, write = handler
        record = from_body(cls, event.body)
        body = _json(to_body(record))
        with self._tx():
            write(self, event.at, record, body)

    def _observation(self, at: float, obs: Observation, body: str) -> None:
        self._db.execute(
            "INSERT INTO observations (probe, at, body) VALUES (?, ?, ?) ON CONFLICT (probe) "
            "DO UPDATE SET at = excluded.at, body = excluded.body "
            "WHERE excluded.at >= observations.at", (obs.probe, at, body))
        points = [(obs.probe, name, at, value)
                  for name, value in islice(_flatten(obs.data), MAX_FIELDS)]
        self._db.executemany(
            "INSERT OR REPLACE INTO series (probe, field, t, value) VALUES (?, ?, ?, ?)", points)

    def _finding(self, at: float, finding: Finding, body: str) -> None:
        key = (finding.rule, finding.entity, at, body)
        self._db.execute(
            "INSERT OR REPLACE INTO findings (rule, entity, at, body) VALUES (?, ?, ?, ?)", key)
        self._db.execute(
            "INSERT INTO findings_latest (rule, entity, at, body) VALUES (?, ?, ?, ?) "
            "ON CONFLICT (rule, entity) DO UPDATE SET at = excluded.at, body = excluded.body "
            "WHERE excluded.at >= findings_latest.at", key)

    def _attestation(self, at: float, att: Attestation, body: str) -> None:
        self._db.execute(
            "INSERT OR REPLACE INTO attestations (context, question, at, body) "
            "VALUES (?, ?, ?, ?)", (att.context, att.question, at, body))
        self._db.execute(
            "INSERT INTO attestations_latest (context, question, domain, severity, at, body) "
            "VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT (context, question) DO UPDATE SET "
            "domain = excluded.domain, severity = excluded.severity, at = excluded.at, "
            "body = excluded.body WHERE excluded.at >= attestations_latest.at",
            (att.context, att.question, att.domain, att.severity.value, at, body))

    def _issue(self, at: float, issue: Issue, _body: str) -> None:
        row = self._db.execute(
            "SELECT state, updated_at, held_severity, held_at, snoozed_until, held_by "
            "FROM issues WHERE id = ?", (issue.id,)).fetchone()
        state, held_severity, held_at, until, held_by = issue.state, None, None, None, None
        if row is not None:
            stored, updated_at, stored_held, stored_held_at, stored_until, stored_by = row
            if issue.updated_at < updated_at:
                return  # stale: the evaluator has already said something newer
            stored = IssueState(stored)
            if stored in _HELD and issue.state is IssueState.OPEN:
                escalated = issue.severity.rank > Severity(stored_held).rank
                lapsed = stored is IssueState.SNOOZED and at >= stored_until
                if not (escalated or lapsed):
                    state, held_severity, held_at, until, held_by = (
                        stored, stored_held, stored_held_at, stored_until, stored_by)
        effective = dataclasses.replace(issue, state=state)
        self._put_issue(effective, held_severity, held_at, until, held_by)

    def _put_issue(self, issue: Issue, held_severity: str | None, held_at: float | None,
                   until: float | None, held_by: str | None = None) -> None:
        self._db.execute(
            "INSERT OR REPLACE INTO issues (id, state, severity, domain, score, updated_at, "
            "held_severity, held_at, snoozed_until, body, held_by) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (issue.id, issue.state.value, issue.severity.value, issue.domain, issue.score,
             issue.updated_at, held_severity, held_at, until, _json(to_body(issue)), held_by))

    def _heartbeat(self, at: float, _hb: Heartbeat, body: str) -> None:
        self._db.execute("INSERT OR REPLACE INTO heartbeats (at, body) VALUES (?, ?)",
                         (at, body))

    def _link(self, at: float, link: Link, body: str) -> None:
        if len(link.members) < 2:
            raise SchemaError(f"link {link.id!r} has {len(link.members)} member(s); "
                              "a link relates two or more")
        for member in link.members:
            _member(member)
        self._db.execute("INSERT OR REPLACE INTO links (id, at, body) VALUES (?, ?, ?)",
                         (link.id, at, body))
        self._db.execute(
            "INSERT INTO links_latest (id, at, body) VALUES (?, ?, ?) ON CONFLICT (id) "
            "DO UPDATE SET at = excluded.at, body = excluded.body "
            "WHERE excluded.at >= links_latest.at", (link.id, at, body))

    def save_analysis(self, analysis: Analysis) -> None:
        """Save (or replace, by id) one manual analysis. Refuses a malformed record."""
        record = from_body(Analysis, to_body(analysis))
        with self._tx():
            self._db.execute(
                "INSERT OR REPLACE INTO analyses (id, completed_at, body) VALUES (?, ?, ?)",
                (record.id, record.completed_at, _json(to_body(record))))

    def save_log_explanations(self, explanations: Iterable[LogExplanation]) -> int:
        """Save (or replace, by key) explanations, then keep only the `MAX_LOG_EXPLANATIONS`
        most recently seen. Returns the number of rows removed by that cap."""
        return self._save_cached(LogExplanation, explanations)

    def touch_log_explanations(self, keys: Iterable[str], at: float) -> None:
        """Mark the cached explanations of these keys as seen at `at` (never moved back)."""
        self._touch_cached(LogExplanation, keys, at)

    def save_service_descriptions(self, descriptions: Iterable[ServiceDescription]) -> int:
        """Save (or replace, by unit name) descriptions, then keep only the
        `MAX_SERVICE_DESCRIPTIONS` most recently seen. Returns the rows removed by that cap."""
        return self._save_cached(ServiceDescription, descriptions)

    def touch_service_descriptions(self, names: Iterable[str], at: float) -> None:
        """Mark the cached descriptions of these units as seen at `at` (never moved back)."""
        self._touch_cached(ServiceDescription, names, at)

    def note_services(self, names: Iterable[str], at: float) -> None:
        """Record when each of these services was first seen. The first ones ever noted are the
        machine as the monitor found it, not new; any seen for the first time after are new."""
        rows = sorted(set(names))
        if not rows:
            return
        with self._tx():
            new = self._db.execute("SELECT EXISTS (SELECT 1 FROM service_sightings)").fetchone()[0]
            self._db.executemany(
                "INSERT OR IGNORE INTO service_sightings (name, first_seen_at, new) "
                "VALUES (?, ?, ?)",
                [(name, at, new) for name in rows])

    def note_notified(self, issue_id: str, rank: int, at: float) -> None:
        """Record that the desktop was told about an issue at a severity rank, so a restart
        does not tell it again (2026-10-30: every restart re-sent every open issue)."""
        with self._tx():
            self._db.execute(
                "INSERT INTO notified (issue_id, rank, at) VALUES (?, ?, ?) ON CONFLICT(issue_id) "
                "DO UPDATE SET rank = max(rank, excluded.rank), at = excluded.at",
                (issue_id, rank, at))

    def _save_cached(self, cls: type, records: Iterable[Any]) -> int:
        table, cap = _CACHES[cls]
        columns = [f.name for f in dataclasses.fields(cls)]
        rows = [dataclasses.astuple(record) for record in records]
        with self._tx():
            self._db.executemany(
                f"INSERT OR REPLACE INTO {table} ({', '.join(columns)}) "
                f"VALUES ({', '.join('?' * len(columns))})", rows)
            return self._db.execute(
                f"DELETE FROM {table} WHERE {columns[0]} NOT IN (SELECT {columns[0]} FROM "
                f"{table} ORDER BY last_seen_at DESC, {columns[0]} LIMIT ?)", (cap(),)).rowcount

    def _touch_cached(self, cls: type, ids: Iterable[str], at: float) -> None:
        table, _ = _CACHES[cls]
        key = dataclasses.fields(cls)[0].name
        with self._tx():
            self._db.executemany(
                f"UPDATE {table} SET last_seen_at = ? WHERE {key} = ? AND last_seen_at < ?",
                [(at, one, at) for one in set(ids)])

    def ack(self, issue_id: str, at: float, by: str = "") -> Issue:
        """Acknowledge an issue at time `at`, held by `by`. Returns it as now stored."""
        return self._hold(issue_id, IssueState.ACKNOWLEDGED, at, None, by)

    def snooze(self, issue_id: str, until: float, by: str = "") -> Issue:
        """Snooze an issue until `until`, held by `by`. Returns it as now stored."""
        return self._hold(issue_id, IssueState.SNOOZED, None, until, by)

    def _hold(self, issue_id: str, state: IssueState, at: float | None,
              until: float | None, by: str) -> Issue:
        with self._tx():
            current = self.issue(issue_id)
            if current is None:
                raise KeyError(issue_id)
            if current.state is IssueState.RESOLVED:
                raise StoreError(f"issue {issue_id!r} is resolved; there is nothing to hold")
            held = dataclasses.replace(current, state=state)
            self._put_issue(held, current.severity.value, at, until, by)
        return held

    def audit(self, at: float, agent: str, action: str, target: str,
              detail: Mapping[str, Any]) -> None:
        """Record one agent write or LLM job, then keep only the `MAX_AUDIT` newest rows."""
        body = _json(dict(detail))
        with self._tx():
            self._db.execute("INSERT INTO audit (at, agent, action, target, detail) "
                             "VALUES (?, ?, ?, ?, ?)", (at, agent, action, target, body))
            self._db.execute("DELETE FROM audit WHERE id NOT IN "
                             "(SELECT id FROM audit ORDER BY id DESC LIMIT ?)", (MAX_AUDIT,))

    # --- reads ------------------------------------------------------------------------------

    def latest(self, probe: str | None = None) -> tuple[tuple[float, Observation], ...]:
        """(at, observation), one per probe, newest first: a stale probe shows its age."""
        where, args = _where(("probe = ?", probe))
        rows = self._db.execute(
            f"SELECT at, body FROM observations{where} ORDER BY at DESC, probe", args)
        return tuple((at, _decode(Observation, body)) for at, body in rows)

    def series(self, probe: str, field: str, since: float, step_s: int) -> tuple[Point, ...]:
        """Mean of `field` per `step_s` bucket from `since` on. Empty buckets are absent."""
        if step_s <= 0:
            raise ValueError(f"step_s must be positive, got {step_s!r}")
        rows = self._db.execute(
            "SELECT CAST(t / ? AS INTEGER) * ? AS bucket, AVG(value) FROM series "
            "WHERE probe = ? AND field = ? AND t >= ? GROUP BY bucket ORDER BY bucket",
            (step_s, step_s, probe, field, since))
        return tuple(Point(float(bucket), value) for bucket, value in rows)

    def issues(self, state: IssueState | None = None) -> tuple[Issue, ...]:
        """Issues by score, highest first, then most recently updated."""
        where, args = _where(("state = ?", state.value if state else None))
        rows = self._db.execute(
            f"SELECT body FROM issues{where} ORDER BY score DESC, updated_at DESC, id", args)
        return tuple(_decode(Issue, body) for (body,) in rows)

    def holds(self) -> dict[str, Hold]:
        """Every acknowledged or snoozed issue's hold, by issue id."""
        rows = self._db.execute(
            "SELECT id, held_by, held_at, snoozed_until FROM issues "
            "WHERE state IN ('acknowledged', 'snoozed')")
        return {issue_id: Hold(by or "", at, until) for issue_id, by, at, until in rows}

    def audit_log(self, limit: int = 100, agent: str | None = None,
                  since: float | None = None) -> tuple[AuditEntry, ...]:
        """Audit rows, newest first: at most `limit`, only `agent`'s and from `since` on if
        given."""
        where, args = _where(("agent = ?", agent), ("at >= ?", since))
        rows = self._db.execute(
            f"SELECT id, at, agent, action, target, detail FROM audit{where} "
            f"ORDER BY id DESC LIMIT ?", (*args, limit))
        return tuple(AuditEntry(i, at, who, action, target, json.loads(detail))
                     for i, at, who, action, target, detail in rows)

    def issue(self, issue_id: str) -> Issue | None:
        row = self._db.execute("SELECT body FROM issues WHERE id = ?", (issue_id,)).fetchone()
        return None if row is None else _decode(Issue, row[0])

    def findings(self, since: float | None = None,
                 latest: bool = False) -> tuple[tuple[float, Finding], ...]:
        """(at, finding), newest first. `latest` gives only the newest per rule and entity."""
        table = "findings_latest" if latest else "findings"
        where, args = _where(("at >= ?", since))
        rows = self._db.execute(
            f"SELECT at, body FROM {table}{where} ORDER BY at DESC, rule, entity", args)
        return tuple((at, _decode(Finding, body)) for at, body in rows)

    def attestations(self, context: str | None = None, question: str | None = None,
                     since: float | None = None,
                     latest: bool = False) -> tuple[tuple[float, Attestation], ...]:
        """(at, attestation), newest first. `latest` gives only the current ones (`CURRENT`)."""
        table = "attestations_latest" if latest else "attestations"
        where, args = _where(("context = ?", context), ("question = ?", question),
                             ("at >= ?", since), (CURRENT, () if latest else None))
        rows = self._db.execute(
            f"SELECT at, body FROM {table}{where} ORDER BY at DESC, context, question", args)
        return tuple((at, _decode(Attestation, body)) for at, body in rows)

    def last_heartbeat(self) -> tuple[float, Heartbeat] | None:
        row = self._db.execute(
            "SELECT at, body FROM heartbeats ORDER BY at DESC LIMIT 1").fetchone()
        return None if row is None else (row[0], _decode(Heartbeat, row[1]))

    def domains(self) -> dict[str, DomainSummary]:
        """Per domain named by any issue or latest attestation, by domain name."""
        summary: dict[str, DomainSummary] = {}

        def entry(domain: str) -> DomainSummary:
            return summary.setdefault(domain, DomainSummary(dict.fromkeys(Severity, 0),
                                                            dict.fromkeys(Severity, 0)))

        for (domain,) in self._db.execute("SELECT DISTINCT domain FROM issues"):
            entry(domain)
        for domain, severity, n in self._db.execute(
                "SELECT domain, severity, COUNT(*) FROM issues WHERE state = 'open' "
                "GROUP BY domain, severity"):
            entry(domain).open[Severity(severity)] = n
        for domain, severity, n in self._db.execute(
                f"SELECT domain, severity, COUNT(*) FROM attestations_latest WHERE {CURRENT} "
                "GROUP BY domain, severity"):
            entry(domain).attested[Severity(severity)] = n
        return dict(sorted(summary.items()))

    def incidents(self) -> tuple[Incident, ...]:
        """Every link's latest version with its members resolved: highest member severity
        first, then highest member-issue score, then link id. No resolved member sorts last."""
        ranked = []
        for at, body in self._db.execute(
                "SELECT at, body FROM links_latest").fetchall():
            link = _decode(Link, body)
            issues, findings, missing = [], [], []
            for member in link.members:
                kind, key, entity = _member(member)
                if kind == "issue":
                    found = self.issue(key)
                    if found is not None:
                        issues.append(found)
                        continue
                else:
                    row = self._db.execute(
                        "SELECT at, body FROM findings_latest WHERE rule = ? AND entity = ?",
                        (key, entity)).fetchone()
                    if row is not None:
                        findings.append((row[0], _decode(Finding, row[1])))
                        continue
                missing.append(member)
            severity = max([i.severity.rank for i in issues]
                           + [f.severity.rank for _, f in findings], default=-1)
            score = max((i.score for i in issues), default=0.0)
            ranked.append(((-severity, -score, link.id),
                           Incident(at, link, tuple(issues), tuple(findings), tuple(missing))))
        return tuple(incident for _, incident in sorted(ranked, key=lambda pair: pair[0]))

    def analyses(self, subject: str | None = None) -> tuple[Analysis, ...]:
        """Manual analyses, newest completed first; only those naming `subject`, if given."""
        where, args = _where((
            "EXISTS (SELECT 1 FROM json_each(analyses.body, '$.subjects') WHERE value = ?)",
            subject))
        rows = self._db.execute(
            f"SELECT body FROM analyses{where} ORDER BY completed_at DESC, id", args)
        return tuple(_decode(Analysis, body) for (body,) in rows)

    def log_explanations(self, keys: Iterable[str]) -> dict[str, LogExplanation]:
        """The cached explanations of those of `keys` that have one, by key."""
        return self._cached(LogExplanation, keys)

    def service_sightings(self) -> dict[str, tuple[float, bool]]:
        """Each service ever noted: when it was first seen, and whether it was new then."""
        return {name: (at, bool(new)) for name, at, new in self._db.execute(
            "SELECT name, first_seen_at, new FROM service_sightings")}

    def notified(self) -> dict[str, tuple[int, float]]:
        """Each issue the desktop was told about: the highest severity rank sent, and when."""
        return {issue_id: (rank, at) for issue_id, rank, at in self._db.execute(
            "SELECT issue_id, rank, at FROM notified")}

    def service_descriptions(self, names: Iterable[str]) -> dict[str, ServiceDescription]:
        """The cached descriptions of those of the units `names` that have one, by name, for
        whatever definition they were written for: compare `key` before using one."""
        return self._cached(ServiceDescription, names)

    def _cached(self, cls: type, ids: Iterable[str]) -> dict[str, Any]:
        table, _ = _CACHES[cls]
        columns = [f.name for f in dataclasses.fields(cls)]
        wanted = sorted(set(ids))
        found: dict[str, Any] = {}
        for start in range(0, len(wanted), 500):  # under SQLite's bound-parameter limit
            chunk = wanted[start:start + 500]
            rows = self._db.execute(
                f"SELECT {', '.join(columns)} FROM {table} "
                f"WHERE {columns[0]} IN ({','.join('?' * len(chunk))})", chunk)
            found.update((row[0], cls(*row)) for row in rows)
        return found

    def size(self) -> int:
        """The database's size in bytes, as `page_count * page_size`."""
        pages = self._db.execute("PRAGMA page_count").fetchone()[0]
        return pages * self._db.execute("PRAGMA page_size").fetchone()[0]

    # --- retention --------------------------------------------------------------------------

    def prune(self, now: float) -> int:
        """Apply retention as of `now`. Returns the number of rows removed."""
        removed = 0
        cutoff = now - self._retention.max_age_s
        with self._tx():
            for statement in _AGE_PRUNE:
                removed += self._db.execute(statement, (cutoff,)).rowcount
            self._release()
        for oldest in _SHED:
            while self.size() > self._retention.max_bytes:
                with self._tx():
                    rows = self._db.execute(oldest, (PRUNE_BATCH,)).fetchall()
                    by_table: dict[str, list[int]] = defaultdict(list)
                    for table, rowid, _t in rows:
                        by_table[table].append(rowid)
                    for table, ids in by_table.items():
                        marks = ",".join("?" * len(ids))
                        removed += self._db.execute(
                            f"DELETE FROM {table} WHERE rowid IN ({marks})", ids).rowcount
                    self._release()
                if not rows:
                    break  # this tier is empty; go on to the next
        return removed

    def _release(self) -> None:
        # The cursor must be drained: an undrained incremental_vacuum frees a single page.
        self._db.execute("PRAGMA incremental_vacuum").fetchall()


_HANDLERS: dict[Kind, tuple[type, Any]] = {
    Kind.OBSERVATION: (Observation, Store._observation),
    Kind.FINDING: (Finding, Store._finding),
    Kind.ATTESTATION: (Attestation, Store._attestation),
    Kind.ISSUE: (Issue, Store._issue),
    Kind.HEARTBEAT: (Heartbeat, Store._heartbeat),
    Kind.LINK: (Link, Store._link),
}


def _member(member: str) -> tuple[str, str, str]:
    """A link member id as ("issue", id, "") or ("finding", rule, entity)."""
    kind, _, rest = member.partition(":")
    if kind == "issue" and rest:
        return "issue", rest, ""
    rule, at, entity = rest.partition("@")
    if kind == "finding" and rule and at and entity:
        return "finding", rule, entity
    raise SchemaError(f"link member {member!r} is not issue:<id> or finding:<rule>@<entity>")


def _flatten(data: Mapping[str, Any], prefix: str = "") -> Iterator[tuple[str, float]]:
    """Finite numbers in `data`, named as the module docstring's "Series field names" says."""
    for key, value in data.items():
        name = f"{prefix}{key}"
        if isinstance(value, Mapping):
            yield from _flatten(value, name + ".")
        elif isinstance(value, list):
            yield from _flatten_list(value, name + ".")
        elif isinstance(value, int | float) and not isinstance(value, bool):
            try:
                number = float(value)
            except OverflowError:
                continue
            if math.isfinite(number):
                yield name, number


def _flatten_list(items: list[Any], prefix: str) -> Iterator[tuple[str, float]]:
    seen: set[str] = set()
    for position, item in enumerate(items):
        if not isinstance(item, Mapping):
            continue  # scalars and nested lists have no stable name
        key = next((k for k in IDENTITY_KEYS if _is_identity(item.get(k))), None)
        label = str(position) if key is None else str(item[key])
        if label in seen:
            continue  # two elements claiming one name: the first keeps it
        seen.add(label)
        yield from _flatten({k: v for k, v in item.items() if k != key}, f"{prefix}{label}.")


def _is_identity(value: Any) -> bool:
    return (isinstance(value, str) and value != "") or (
        isinstance(value, int) and not isinstance(value, bool))


def _json(body: dict[str, Any]) -> str:
    try:
        return json.dumps(body, sort_keys=True, separators=(",", ":"))
    except (TypeError, ValueError) as bad:
        raise SchemaError(f"body is not JSON: {bad}") from None


def _decode[T](cls: type[T], body: str) -> T:
    return from_body(cls, json.loads(body))


def _where(*conditions: tuple[str, Any]) -> tuple[str, tuple[Any, ...]]:
    """A WHERE clause from the conditions whose value is not None. A tuple value is the
    condition's parameters, spread (`()` for one that takes none)."""
    present = [(clause, value) for clause, value in conditions if value is not None]
    if not present:
        return "", ()
    return (" WHERE " + " AND ".join(clause for clause, _ in present),
            tuple(v for _, value in present
                  for v in (value if isinstance(value, tuple) else (value,))))
