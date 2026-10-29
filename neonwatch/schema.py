"""The wire types every process shares, and the only encoder and decoder for them.

Decoding is strict. An event with a field nobody declared, a kind nobody knows, or a subject
that does not match its kind is refused, not passed through: every consumer downstream acts on
these, and the notifier acts on them on your desktop.

An `Event` is the envelope; its `body` is one of the typed records below, converted with
`to_body` and `from_body`, which are just as strict.
"""

from __future__ import annotations

import dataclasses
import enum
import json
import types
import typing
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

VERSION = 1

#: Largest encoded event accepted. Probe output is capped well below this at the executor.
MAX_BYTES = 1 << 20


class SchemaError(ValueError):
    """This is not an event this version understands."""


class Kind(enum.Enum):
    OBSERVATION = "observation"
    FINDING = "finding"
    ATTESTATION = "attestation"
    ISSUE = "issue"
    HEARTBEAT = "heartbeat"
    LINK = "link"


#: Kind -> the first subject token. The broker's permissions are written against these.
SUBJECT = {Kind.OBSERVATION: "obs", Kind.FINDING: "finding", Kind.ATTESTATION: "attest",
           Kind.ISSUE: "issue", Kind.HEARTBEAT: "hb", Kind.LINK: "link"}


class Severity(enum.Enum):
    INFO = "info"
    WATCH = "watch"
    WARN = "warn"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return list(Severity).index(self)


class IssueState(enum.Enum):
    OPEN = "open"
    ACKNOWLEDGED = "acknowledged"
    SNOOZED = "snoozed"
    RESOLVED = "resolved"


@dataclass(frozen=True, slots=True)
class Event:
    kind: Kind
    at: float
    source: str
    subject: str
    body: Mapping[str, Any]


def encode_event(event: Event) -> bytes:
    _check_envelope(event.kind, event.at, event.source, event.subject, event.body)
    try:
        data = json.dumps({"v": VERSION, "kind": event.kind.value, "at": event.at,
                           "source": event.source, "subject": event.subject, "body": event.body},
                          sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    except (ValueError, TypeError, RecursionError) as bad:
        raise SchemaError(f"event body is not strict JSON: {type(bad).__name__}") from None
    if len(data) > MAX_BYTES:
        raise SchemaError(f"event is {len(data)} bytes, over the {MAX_BYTES}-byte limit")
    return data


def decode_event(data: bytes) -> Event:
    if len(data) > MAX_BYTES:
        raise SchemaError(f"event is {len(data)} bytes, over the {MAX_BYTES}-byte limit")
    try:
        raw = json.loads(data, parse_constant=_no_constant)
    except (ValueError, RecursionError) as bad:
        # ValueError covers JSONDecodeError, UnicodeDecodeError and the NaN/Infinity refusal;
        # RecursionError is what deeply nested input raises. Either way: not an event.
        raise SchemaError(f"not JSON: {type(bad).__name__}: {str(bad)[:200]}") from None
    if not isinstance(raw, dict):
        raise SchemaError("an event is a JSON object")
    expected = {"v", "kind", "at", "source", "subject", "body"}
    if set(raw) != expected:
        raise SchemaError(f"event fields must be exactly {sorted(expected)}, got {sorted(raw)}")
    if raw["v"] != VERSION:
        raise SchemaError(f"version {raw['v']!r} is not {VERSION}")
    try:
        kind = Kind(raw["kind"])
    except ValueError:
        raise SchemaError(f"unknown kind {raw['kind']!r}") from None
    _check_envelope(kind, raw["at"], raw["source"], raw["subject"], raw["body"])
    return Event(kind, float(raw["at"]), raw["source"], raw["subject"], raw["body"])


def _no_constant(name: str) -> Any:
    raise ValueError(f"{name} is not a JSON number an event may carry")


def _check_envelope(kind: Kind, at: Any, source: Any, subject: Any, body: Any) -> None:
    if (isinstance(at, bool) or not isinstance(at, int | float) or at != at
            or at in (float("inf"), float("-inf")) or at < 0):
        raise SchemaError(f"`at` must be a non-negative number, got {at!r}")
    for name, value in (("source", source), ("subject", subject)):
        if not isinstance(value, str) or not value.strip():
            raise SchemaError(f"`{name}` must be a non-empty string")
    if subject.split(".", 1)[0] != SUBJECT[kind]:
        raise SchemaError(f"a {kind.value} event's subject starts with {SUBJECT[kind]!r}, "
                          f"got {subject!r}")
    if not isinstance(body, Mapping):
        raise SchemaError("`body` must be an object")


# --- typed bodies ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Observation:
    probe: str
    data: dict[str, Any]
    cpu_ms: int
    truncated: bool = False
    #: Why the probe produced no data, when it did not. `""` on success.
    error: str = ""


@dataclass(frozen=True, slots=True)
class Finding:
    """A deterministic alarm. Nothing a model says can clear one."""

    rule: str
    severity: Severity
    title: str
    #: What it is about: `disk:/dev/nvme0`, `unit:foo.service`, `container:shopfront-worker-1`.
    entity: str
    evidence: dict[str, Any] = field(default_factory=dict)
    #: A read-only check for a person to run, from the rule. Never executed by the system.
    next_step: str = ""
    #: Why it matters, for the person reading the issue. `""` when the rule gives none.
    why: str = ""


@dataclass(frozen=True, slots=True)
class Context:
    """What one batch of questions is about. Built by the evaluator, never sent by the agent."""

    id: str
    kind: str
    domain: str
    entity: str
    state: dict[str, Any]


@dataclass(frozen=True, slots=True)
class Attestation:
    """One judge answer to one question about one context, and what it means."""

    context: str
    context_kind: str
    domain: str
    entity: str
    question: str
    instructions: str
    answer: dict[str, Any]
    severity: Severity
    cause: str
    next_step: str
    confidence: float
    #: Whether the answer held with the options reversed. `None` when not checked.
    stable: bool | None
    latency_ms: int
    #: What it was about, redacted (`judge.evidence`). Empty on attestations recorded before.
    evidence: dict[str, Any] = field(default_factory=dict)
    #: The `judge.name` that answered. `""` on attestations recorded before names existed.
    judge: str = ""


@dataclass(frozen=True, slots=True)
class Issue:
    id: str
    state: IssueState
    severity: Severity
    title: str
    domain: str
    entity: str
    opened_at: float
    updated_at: float
    #: True when a deterministic finding stands behind it.
    deterministic: bool
    #: Rule ids and attestation question ids that raised or ranked it.
    reasons: tuple[str, ...]
    next_step: str
    #: The percolation score the evaluator ranked it by. Higher surfaces first.
    score: float = 0.0
    #: What it is about, for a person: the leading finding's evidence, else the leading
    #: attestation's (`Attestation.evidence`). Empty on issues recorded before.
    evidence: dict[str, Any] = field(default_factory=dict)
    #: Why it matters, from the leading finding's rule. `""` when it gives none.
    why: str = ""
    #: When its conditions were last present: `updated_at` while they are, earlier once they
    #: are gone (the issue stays open until `RESOLVE_AFTER` collations without them). 0 when
    #: recorded before this was kept.
    last_seen: float = 0.0


@dataclass(frozen=True, slots=True)
class Heartbeat:
    """The agent's own cost and liveness. The last one before a gap says when it stopped."""

    cpu_fraction: float
    confined: bool
    #: Paths the write canary found writable. Empty when confined.
    writable: tuple[str, ...]
    ran: int
    failed: int
    deferred: int
    #: Observations dropped from the agent's bounded publish queue during a broker outage.
    dropped: int = 0
    #: Probes with a run still outstanding after its deadline (an abandoned, stuck thread).
    hung: int = 0


@dataclass(frozen=True, slots=True)
class Link:
    """A judged relation between two or more findings or issues, published by the evaluator.

    Members are ids such as `issue:i-1` or `finding:smart.critical@disk:/dev/nvme0`. A link groups
    what is probably one problem; it never changes the state of any member.
    """

    id: str
    members: tuple[str, ...]
    #: Why code proposed the candidate: `shared-entity`, `co-occurrence`, `template:<name>`.
    basis: str
    #: The judge's probability that the members are one underlying problem.
    related: float
    #: The member the judge rated the likely cause, or `""` when it could not say.
    likely_cause: str
    confidence: float
    stable: bool | None


@dataclass(frozen=True, slots=True)
class Analysis:
    """A manual, operator-requested analysis by the configured backend LLM. Advisory text only."""

    id: str
    requested_at: float
    completed_at: float
    backend: str
    model: str
    #: What was analysed: event, issue, link or window ids.
    subjects: tuple[str, ...]
    question: str
    #: The model's answer, rendered as plain text by the UI and never executed.
    text: str
    #: Suggested read-only checks, shown for the operator to copy; never run by the system.
    suggested_checks: tuple[str, ...]
    input_chars: int
    output_chars: int
    #: Why it produced nothing, when it did not.
    error: str = ""


def to_body(record: Any) -> dict[str, Any]:
    """A typed record as a JSON-ready body."""
    if not dataclasses.is_dataclass(record) or isinstance(record, type):
        raise SchemaError(f"not a record: {record!r}")
    return {f.name: _plain(getattr(record, f.name)) for f in dataclasses.fields(record)}


def from_body[T](cls: type[T], body: Mapping[str, Any]) -> T:
    """A body as the typed record, refusing missing, extra and mistyped fields."""
    if not isinstance(body, Mapping):
        raise SchemaError(f"{cls.__name__} body must be an object")
    hints = typing.get_type_hints(cls)
    fields = {f.name: f for f in dataclasses.fields(cls)}
    if extra := sorted(set(body) - set(fields)):
        raise SchemaError(f"{cls.__name__} has no field(s) {extra}")
    values = {}
    for name, spec in fields.items():
        if name not in body:
            if spec.default is dataclasses.MISSING and spec.default_factory is dataclasses.MISSING:
                raise SchemaError(f"{cls.__name__} is missing {name}")
            continue
        values[name] = _typed(f"{cls.__name__}.{name}", hints[name], body[name])
    return cls(**values)


def _plain(value: Any) -> Any:
    if isinstance(value, enum.Enum):
        return value.value
    if isinstance(value, tuple):
        return [_plain(item) for item in value]
    return value


def _typed(where: str, hint: Any, value: Any) -> Any:
    origin = typing.get_origin(hint)
    if origin in (types.UnionType, typing.Union):
        options = typing.get_args(hint)
        if value is None and type(None) in options:
            return None
        errors = []
        for option in options:
            if option is type(None):
                continue
            try:
                return _typed(where, option, value)
            except SchemaError as bad:
                errors.append(str(bad))
        raise SchemaError("; ".join(errors))
    if isinstance(hint, type) and issubclass(hint, enum.Enum):
        try:
            return hint(value)
        except ValueError:
            raise SchemaError(f"{where}: {value!r} is not one of "
                              f"{[m.value for m in hint]}") from None
    if origin is tuple:
        if not isinstance(value, list | tuple):
            raise SchemaError(f"{where}: expected a list, got {type(value).__name__}")
        item = typing.get_args(hint)[0]
        return tuple(_typed(where, item, each) for each in value)
    if origin is dict or hint is dict:
        if not isinstance(value, dict):
            raise SchemaError(f"{where}: expected an object, got {type(value).__name__}")
        return value
    if hint is bool:
        if not isinstance(value, bool):
            raise SchemaError(f"{where}: expected a boolean, got {value!r}")
        return value
    if hint in (int, float):
        if isinstance(value, bool) or not isinstance(value, int | float) or (
                hint is int and not isinstance(value, int)):
            raise SchemaError(f"{where}: expected {hint.__name__}, got {value!r}")
        return hint(value)
    if hint is str:
        if not isinstance(value, str):
            raise SchemaError(f"{where}: expected a string, got {value!r}")
        return value
    raise SchemaError(f"{where}: no rule for {hint!r}")  # pragma: no cover — a schema bug
