"""What the local agent API (`/api/agent/v1`, served by `app`) needs beyond the dashboard's
routes: who may call it, how often it may write, and the compact shapes it answers with.

Who. A request must come from a loopback peer (`loopback_peer`: the socket's address, never a
header), carry `Authorization: Bearer <the agent token>` and name its caller in
`X-Neonwatch-Agent` (`valid_name`: 1-64 of `[A-Za-z0-9._:-]`). The name is attribution, not
authentication: anyone holding the token may give any name, which is why the write limit below
has a total as well as a per-name bound.

How often. `WriteLimit` allows `WRITES_PER_AGENT` writes per agent name and `WRITES_TOTAL` in
all in any `WRITE_WINDOW_S`; a write is an acknowledgement, a snooze, or starting an LLM job.

Shapes. Stable, documented field names (docs/agent-api.md), flatter than the dashboard's: an
issue carries its hold (`held_by`: "operator" for the dashboard, `agent:<name>` for an agent,
null when not held; `snoozed_until`), an incident names its members instead of embedding them.
"""

from __future__ import annotations

import ipaddress
import re
from collections import deque
from collections.abc import Iterable, Mapping
from typing import Any

from neonwatch.schema import Attestation, Finding, Issue, Severity
from neonwatch.store import Hold, Incident

PREFIX = "/api/agent/v1"
NAME_HEADER = "X-Neonwatch-Agent"
_NAME = re.compile(r"[A-Za-z0-9._:-]{1,64}")

WRITES_PER_AGENT = 30
WRITES_TOTAL = 60
WRITE_WINDOW_S = 60.0

#: Who holds an issue the dashboard's operator acknowledged or snoozed.
OPERATOR = "operator"


def valid_name(name: str | None) -> bool:
    return name is not None and _NAME.fullmatch(name) is not None


def loopback_peer(remote: str | None) -> bool:
    """Whether the connection's peer address is loopback (an IPv4-mapped one counts)."""
    try:
        address = ipaddress.ip_address(remote or "")
    except ValueError:
        return False
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        address = address.ipv4_mapped
    return address.is_loopback


def holder(hold: Hold | None) -> str | None:
    """`held_by` for an issue: who holds it, or None when it is not held."""
    if hold is None:
        return None
    return hold.by or OPERATOR


class WriteLimit:
    """Sliding-window counts of writes, per agent name and in total."""

    def __init__(self, per_agent: int = WRITES_PER_AGENT, total: int = WRITES_TOTAL,
                 window_s: float = WRITE_WINDOW_S) -> None:
        self.per_agent, self.total, self.window_s = per_agent, total, window_s
        self.times: dict[str, deque[float]] = {}
        self.all: deque[float] = deque()

    def take(self, agent: str, now: float) -> int:
        """Count one write by `agent` at `now` and return 0, or return the whole seconds until
        one is allowed and count nothing."""
        cutoff = now - self.window_s
        for times in (*self.times.values(), self.all):
            while times and times[0] <= cutoff:
                times.popleft()
        self.times = {name: times for name, times in self.times.items() if times}
        mine = self.times.get(agent, deque())
        waits = [times[0] + self.window_s - now
                 for times, cap in ((mine, self.per_agent), (self.all, self.total))
                 if len(times) >= cap]
        if waits:
            return max(1, int(max(waits) + 0.999))
        mine.append(now)
        self.times[agent] = mine
        self.all.append(now)
        return 0


# --- shapes ----------------------------------------------------------------------------------


def issue(found: Issue, hold: Hold | None) -> dict[str, Any]:
    return {"id": found.id, "state": found.state.value, "severity": found.severity.value,
            "title": found.title, "domain": found.domain, "entity": found.entity,
            "reasons": list(found.reasons), "next_step": found.next_step,
            "deterministic": found.deterministic, "score": found.score,
            "opened_at": found.opened_at, "updated_at": found.updated_at,
            "last_seen": found.last_seen or None, "evidence": found.evidence, "why": found.why,
            "held_by": holder(hold), "snoozed_until": hold.until if hold else None}


def incident(found: Incident) -> dict[str, Any]:
    ranks = ([i.severity for i in found.issues] + [f.severity for _, f in found.findings])
    worst = max(ranks, key=lambda s: s.rank, default=None)
    link = found.link
    return {"id": link.id, "at": found.at, "severity": worst.value if worst else None,
            "basis": link.basis, "related": link.related, "likely_cause": link.likely_cause,
            "confidence": link.confidence, "stable": link.stable, "members": list(link.members),
            "issues": [i.id for i in found.issues],
            "findings": [f"{f.rule}@{f.entity}" for _, f in found.findings],
            "missing": list(found.missing)}


def finding(at: float, found: Finding) -> dict[str, Any]:
    return {"at": at, "rule": found.rule, "severity": found.severity.value,
            "title": found.title, "entity": found.entity, "evidence": found.evidence,
            "next_step": found.next_step}


def attestation(at: float, found: Attestation) -> dict[str, Any]:
    return {"at": at, "context": found.context, "question": found.question,
            "entity": found.entity, "severity": found.severity.value, "answer": found.answer,
            "cause": found.cause, "next_step": found.next_step,
            "confidence": found.confidence, "stable": found.stable}


def counts(issues: Iterable[Issue]) -> dict[str, int]:
    found = {s.value: 0 for s in reversed(Severity)}
    for each in issues:
        found[each.severity.value] += 1
    return found


#: A service's fields in a listing; the one-service route adds the rest of the record.
SERVICE_FIELDS = ("name", "description", "active", "sub", "result", "enabled", "user",
                  "restarts", "key", "timers", "worst", "unstable", "issues", "described")
#: A scheduled job's fields: the record without its judge context copy or attestations.
JOB_FIELDS = ("id", "source", "file", "user", "schedule", "command", "unit", "last", "next",
              "result", "worst", "unstable")


def pick(record: Mapping[str, Any], fields: Iterable[str]) -> dict[str, Any]:
    return {name: record.get(name) for name in fields}
