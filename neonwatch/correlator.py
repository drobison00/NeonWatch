"""The linking pass: which findings and issues are probably one problem.

**Candidates** are proposed by code, deterministically and bounded. `candidates(items, window_s,
limit)` looks for groups of 2-6 items on three bases:

- `shared-entity`: items about the same object. Either the same entity string, or a *name* that
  one item's entity carries and another item mentions. Names are taken only from entities of the
  kinds in `NAMED_KINDS` (`container:<name>`, `unit:<name>`, ...), only when at least
  `MIN_NAME_CHARS` long, and match only as a whole token, case-sensitively, in the other item's
  title or entity: `shopfront-worker-1` matches "python in shopfront-worker-1 at 98% CPU" and
  `log_burst:shopfront-worker-1`, never `shopfront-worker-10` or `.../shopfront-worker-1/x`.
  Pids, GPU indexes and `/` are too short or too generic to mean one object, so they never match
  by name. No time window: the same object is the same object.
- `co-occurrence`: items in different domains within `window_s` of each other, one per domain
  (the most severe, then newest), strength falling with the time span.
- `template:<name>`: a known pattern from `TEMPLATES`, each a tuple of `Slot`s; a group fills at
  least two slots with distinct items within `window_s`. Fuller is stronger. Adding a pattern is
  one table entry.

Windows are anchored on each item in time order and kept only when maximal (a window lying inside
the previous one adds nothing), so one burst yields one group rather than its every suffix. The
same member set proposed on two bases keeps the stronger. Candidates rank by strength, then by
their newest member, then by member ids, and at most `limit` are returned. An item seen more than
once (the same finding in several collations) counts once, at its newest sighting.

**Links.** `Correlator.link` makes one `correlation` context per candidate, asks the judge about
all of them in one `attest` call (The judge packs and paces), and reads each context's answers:
`related` is the `same_problem` p, `likely_cause` is the member chosen by `likely_cause` (`mN` is
the N-th member, in the order they were sent), `confidence` is the `same_problem` answer's, and
`stable` is False if any of the three answers flipped on re-ask, True if any held, else None. A
link is emitted when `related` or the `one_incident` p reaches `LINK_THRESHOLD`. Without a valid
`same_problem` answer there is no `related`, so there is no link: The judge down means no links,
never guessed ones. A link never changes a member.
"""

from __future__ import annotations

import hashlib
import math
import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from typing import Any

from neonwatch.config import Config
from neonwatch.judge import Judge
from neonwatch.questions import ContextKind
from neonwatch.schema import Attestation, Context, Finding, Issue, Link, Severity

#: `related` or `one_incident` at or above this makes a link.
LINK_THRESHOLD = 0.5
#: The CORRELATION bank's question ids this reads.
SAME_PROBLEM, ONE_INCIDENT, LIKELY_CAUSE = "same_problem", "one_incident", "likely_cause"
MEMBERS = (2, 6)

SHARED_ENTITY = "shared-entity"
CO_OCCURRENCE = "co-occurrence"
#: The same entity string; a name carried in another form is a little weaker.
ENTITY_STRENGTH, NAME_STRENGTH = 0.9, 0.8
#: Co-occurrence at span 0; it falls linearly to half this at a span of `window_s`.
CO_OCCURRENCE_STRENGTH = 0.6
#: A template filling k of n slots: base + span * k / n.
TEMPLATE_BASE, TEMPLATE_SPAN = 0.7, 0.25

#: Entity kinds whose value names one object that other items may mention.
NAMED_KINDS = frozenset({"container", "unit", "log", "disk", "mount"})
MIN_NAME_CHARS = 4

#: Rule id prefix -> the domain a finding belongs to, in the bank's domain names. A prefix not
#: listed is its own domain.
RULE_DOMAINS = {
    "edac": "hardware", "smart": "storage", "drive": "storage", "disk": "storage",
    "cpu": "cpu", "gpu": "gpu", "memory": "memory", "container": "containers",
    "unit": "services", "journal": "logs", "listener": "network", "net": "network",
    "kernel": "kernel", "agent": "security", "process": "processes",
}

#: Daemons that own networking (container runtimes included: they create the veths).
NETWORK_DAEMONS = ("NetworkManager", "systemd-networkd", "systemd-resolved", "wpa_supplicant",
                   "vpnagentd", "openvpn", "wg-quick", "tailscaled", "dnsmasq", "avahi-daemon",
                   "dhclient", "dhcpcd", "ModemManager", "dockerd", "docker", "containerd")
NETWORK_DAEMON = (r"^(?:unit|log):(?:" + "|".join(map(re.escape, NETWORK_DAEMONS))
                  + r")(?:@[^.\s]*)?(?:\.service)?$")


# --- items ---------------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Item:
    """A finding or an issue, flattened for linking."""

    #: `issue:<id>` or `finding:<rule>@<entity>`, the forms the store resolves.
    id: str
    kind: str
    domain: str
    entity: str
    #: A finding's collation time; an issue's `opened_at`, when its problem began.
    at: float
    severity: Severity
    title: str
    rule: str = ""
    reasons: tuple[str, ...] = ()
    #: A finding's evidence, sent to the judge as the member's detail.
    evidence: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def of_issue(cls, issue: Issue) -> Item:
        return cls(f"issue:{issue.id}", "issue", issue.domain, issue.entity, issue.opened_at,
                   issue.severity, issue.title, reasons=tuple(issue.reasons))

    @classmethod
    def of_finding(cls, at: float, finding: Finding) -> Item:
        prefix = finding.rule.split(".", 1)[0]
        return cls(f"finding:{finding.rule}@{finding.entity}", "finding",
                   RULE_DOMAINS.get(prefix, prefix), finding.entity, at, finding.severity,
                   finding.title, rule=finding.rule, evidence=dict(finding.evidence))


@dataclass(frozen=True, slots=True)
class Candidate:
    """2-6 distinct items code proposes as possibly one problem, and why."""

    members: tuple[Item, ...]
    basis: str
    strength: float

    def __post_init__(self) -> None:
        low, high = MEMBERS
        if not low <= len({m.id for m in self.members}) == len(self.members) <= high:
            raise ValueError(f"a candidate has 2-6 distinct members, got "
                             f"{[m.id for m in self.members]}")


@dataclass(frozen=True, slots=True)
class Slot:
    """One place in a template. Every field given must match; `rule` ending `.*` is a prefix,
    and matches an issue through its reasons; `entity` is a regular expression searched for."""

    rule: str = ""
    domain: str = ""
    kind: str = ""
    entity: str = ""

    def __post_init__(self) -> None:
        if not (self.rule or self.domain or self.kind or self.entity):
            raise ValueError("a template slot that names nothing matches everything")

    def matches(self, item: Item) -> bool:
        rules = (item.rule, *item.reasons) if item.rule else item.reasons
        if self.rule.endswith(".*"):
            rule_ok = any(r.startswith(self.rule[:-1]) for r in rules)
        else:
            rule_ok = not self.rule or self.rule in rules
        return (rule_ok and self.domain in ("", item.domain) and self.kind in ("", item.kind)
                and (not self.entity or re.search(self.entity, item.entity) is not None))


#: Known patterns: name -> slots. A group fills at least two slots within the window.
TEMPLATES: dict[str, tuple[Slot, ...]] = {
    # A crash-looping container churns veths while a network daemon floods the journal: the
    # pattern seen before a hard lock with no kernel trace.
    "crash-loop": (Slot(rule="container.crash_loop"), Slot(rule="net.interface_churn"),
                   Slot(rule="journal.flood", entity=NETWORK_DAEMON)),
    "thermal-gpu": (Slot(rule="gpu.temperature"), Slot(rule="gpu.throttle")),
    "thermal-cpu": (Slot(rule="cpu.temperature"), Slot(rule="memory.pressure")),
    "storage": (Slot(rule="smart.*"), Slot(rule="disk.fill")),
    "memory": (Slot(rule="memory.pressure"), Slot(rule="memory.oom_kill"),
               Slot(kind="issue", entity=r"^process:")),
}


# --- candidates ----------------------------------------------------------------------------------


def _chronological(item: Item) -> tuple[float, str]:
    return (item.at, item.id)


def _salient(item: Item) -> tuple[int, float, str]:
    """Most severe, then newest, first."""
    return (-item.severity.rank, -item.at, item.id)


def _windows(items: Sequence[Item], window_s: float) -> Iterable[list[Item]]:
    """Maximal runs of time-ordered items spanning at most `window_s`."""
    ordered = sorted(items, key=_chronological)
    end = -1
    for start, anchor in enumerate(ordered):
        last = start
        while last + 1 < len(ordered) and ordered[last + 1].at - anchor.at <= window_s:
            last += 1
        if last > end:
            end = last
            yield ordered[start:last + 1]


def _group(members: Iterable[Item], basis: str, strength: float) -> Candidate:
    chosen = sorted(members, key=_salient)[:MEMBERS[1]]
    return Candidate(tuple(sorted(chosen, key=_chronological)), basis, strength)


def _mentions(item: Item, name: str) -> bool:
    token = rf"(?<![\w./-]){re.escape(name)}(?![\w/-])(?!\.\w)"
    return re.search(token, f"{item.title} {item.entity}") is not None


def _shared_entity(items: Sequence[Item]) -> Iterable[Candidate]:
    by_entity: dict[str, list[Item]] = {}
    for item in items:
        if item.entity:
            by_entity.setdefault(item.entity, []).append(item)
    for group in by_entity.values():
        if len(group) >= 2:
            yield _group(group, SHARED_ENTITY, ENTITY_STRENGTH)
    names = {name for item in items
             for kind, sep, name in [item.entity.partition(":")]
             if sep and kind in NAMED_KINDS and len(name) >= MIN_NAME_CHARS}
    for name in sorted(names):
        group = [item for item in items if _mentions(item, name)]
        if len(group) >= 2:
            yield _group(group, SHARED_ENTITY, NAME_STRENGTH)


def _co_occurrence(items: Sequence[Item], window_s: float) -> Iterable[Candidate]:
    for window in _windows(items, window_s):
        by_domain: dict[str, Item] = {}
        for item in sorted(window, key=_salient):
            by_domain.setdefault(item.domain, item)
        if len(by_domain) >= 2:
            members = sorted(by_domain.values(), key=_salient)[:MEMBERS[1]]
            span = max(m.at for m in members) - min(m.at for m in members)
            yield _group(members, CO_OCCURRENCE,
                         CO_OCCURRENCE_STRENGTH * (1 - 0.5 * span / window_s))


def _templates(items: Sequence[Item], window_s: float) -> Iterable[Candidate]:
    for name, slots in TEMPLATES.items():
        fitting = [item for item in items if any(slot.matches(item) for slot in slots)]
        for window in _windows(fitting, window_s):
            ranked = sorted(window, key=_salient)
            filled: list[Item] = []
            for slot in slots:
                pick = next((i for i in ranked if slot.matches(i) and i not in filled), None)
                if pick is not None:
                    filled.append(pick)
            if len(filled) >= 2:
                yield _group(filled, f"template:{name}",
                             TEMPLATE_BASE + TEMPLATE_SPAN * len(filled) / len(slots))


def candidates(items: Sequence[Item], window_s: float, limit: int) -> tuple[Candidate, ...]:
    """Groups worth asking the judge about, strongest first, at most `limit`; same input, same
    output."""
    if isinstance(window_s, bool) or not isinstance(window_s, int | float) \
            or not math.isfinite(window_s) or window_s <= 0:
        raise ValueError(f"window_s must be a positive number of seconds, got {window_s!r}")
    if isinstance(limit, bool) or not isinstance(limit, int) or limit < 0:
        raise ValueError(f"limit must be a non-negative integer, got {limit!r}")
    newest: dict[str, Item] = {}
    for item in sorted(items, key=_chronological):
        newest[item.id] = item
    unique = sorted(newest.values(), key=_chronological)
    best: dict[frozenset[str], Candidate] = {}
    for found in (*_shared_entity(unique), *_co_occurrence(unique, window_s),
                  *_templates(unique, window_s)):
        key = frozenset(m.id for m in found.members)
        held = best.get(key)
        if held is None or (found.strength, held.basis) > (held.strength, found.basis):
            best[key] = found
    ranked = sorted(best.values(), key=lambda c: (-c.strength, -max(m.at for m in c.members),
                                                  tuple(m.id for m in c.members)))
    return tuple(ranked[:limit])


# --- links ---------------------------------------------------------------------------------------


def context_id(candidate: Candidate) -> str:
    """A stable id for a member set, whatever order or basis it came in."""
    digest = hashlib.sha256("\n".join(sorted(m.id for m in candidate.members)).encode())
    return f"corr-{digest.hexdigest()[:16]}"


def _context(candidate: Candidate) -> Context:
    id = context_id(candidate)
    members = [{"id": m.id, "domain": m.domain, "entity": m.entity, "at": m.at, "title": m.title}
               for m in candidate.members]
    evidence = [{"id": m.id, "severity": m.severity.value, "rule": m.rule,
                 "reasons": list(m.reasons), "detail": m.evidence} for m in candidate.members]
    return Context(id=id, kind=ContextKind.CORRELATION.value, domain="correlation",
                   entity=f"correlation:{id}",
                   state={"members": members, "basis": candidate.basis, "evidence": evidence})


def _p(attestation: Attestation | None) -> float | None:
    value = attestation.answer.get("noul") if attestation is not None else None
    if isinstance(value, bool) or not isinstance(value, int | float) or not 0 <= value <= 1:
        return None
    return float(value)


def _cause(attestation: Attestation | None, members: Sequence[Item]) -> str:
    choice = attestation.answer.get("choice") if attestation is not None else None
    found = re.fullmatch(r"m([1-9][0-9]?)", choice) if isinstance(choice, str) else None
    if found is None or int(found[1]) > len(members):
        return ""
    return members[int(found[1]) - 1].id


def _stable(answers: Iterable[Attestation | None]) -> bool | None:
    held = [a.stable for a in answers if a is not None and a.stable is not None]
    return all(held) if held else None


class Correlator:
    """Asks the judge about candidate groups and turns its answers into Links."""

    def __init__(self, judge: Judge, config: Config) -> None:
        self._judge = judge
        self._config = config

    async def link(self, candidates: Sequence[Candidate]) -> tuple[Link, ...]:
        """One Link per candidate the judge rated related; the rest, and the unanswered, none."""
        asked: dict[str, tuple[Candidate, Context]] = {}
        for candidate in candidates:
            context = _context(candidate)
            asked.setdefault(context.id, (candidate, context))
        if not asked:
            return ()
        attestations = await self._judge.attest([context for _, context in asked.values()])
        answers: dict[str, dict[str, Attestation]] = {}
        for attestation in attestations:
            if attestation.context in asked:
                answers.setdefault(attestation.context, {})[attestation.question] = attestation
        links = []
        for id, (candidate, _) in asked.items():
            got = answers.get(id, {})
            same, together, cause = (got.get(q) for q in (SAME_PROBLEM, ONE_INCIDENT,
                                                          LIKELY_CAUSE))
            related = _p(same)
            if same is None or related is None \
                    or max(related, _p(together) or 0.0) < LINK_THRESHOLD:
                continue
            links.append(Link(
                id=id, members=tuple(m.id for m in candidate.members), basis=candidate.basis,
                related=related, likely_cause=_cause(cause, candidate.members),
                confidence=same.confidence, stable=_stable((same, together, cause))))
        return tuple(links)
