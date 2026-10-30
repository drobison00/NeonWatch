"""Classification: observations in; findings, attestations, issues and links out.

The evaluator keeps a short in-memory window of what the agent reported, and every collation it
runs the deterministic rules, asks the judge (through `judge`) about what changed, turns both into
issues, and asks the correlator which issues are probably one problem. It publishes nothing:
`collate` returns the events, and the service publishes them.

**The window.** Per probe, the last `HISTORY` good observations (the newest is `latest`, the one
before it `previous`, for deltas), and separately the newest error. An errored observation never
replaces a good value, so a probe that keeps failing ages out and `probe.stale` fires. An
observation or heartbeat dated more than `MAX_SKEW_S` ahead of the clock is refused and counted
(`refused_future`): it never becomes latest, so `agent.stopped` rests on the newest heartbeat
actually accepted. A probe is
held to its cadence once it has reported a good value, or once the evaluator has been running for
`rules.MISSED_CADENCES` of its cadence: after a restart the window is empty, and a daily probe
must not read as stale for the first day. A `smart.<dev>` probe whose device the latest
`block.devices` no longer lists is not held to its cadence at all (a removed disk is not a stale
probe): it is left out of the snapshot altogether, so rules stop alarming on it and neither its
`disk:` context nor its entry in the storage state is built, and its issues resolve through the
normal hysteresis. Listed again, it is held again (its readings are kept meanwhile).
Observations that are not newer than what is held (a redelivery, or out of order) are ignored.
Each probe's domain and tier come from `probes.CATALOG` (an expanded `smart.<dev>` id maps to the
`smart` template), and a tier's seconds from `config.cadence`; an id the catalog does not hold
is refused.

**Contexts.** One per domain that has data, with a compact state (the top rows of the process table,
not the table; counts and the newest lines of the journal, not 500 entries), plus one per entity
worth a look, named as the rules name it: a process over `PROCESS_CPU_PCT` of a core (recent use,
from `cpu_s` deltas, when there is a previous sample; otherwise ps's lifetime figure, and only once
it has run `PROCESS_MIN_AGE_S`) or `PROCESS_RSS_SHARE` of memory, or running from /tmp
(`process:<pid>`, at most `MAX_PROCESSES`); each failed unit (`unit:<name>`, with its service record
where `units.detail` has one); each restarting container, or running one whose healthcheck reads
unhealthy (`container:<name>`: a stopped container's health is Docker's last word, not evidence, so
no context carries it); each new wildcard listener (`listener:<proto>/<port>`); each disk
(`disk:/dev/<dev>`); each GPU (`gpu:<index>`); a log burst (`unit:<name>` or `log:<identifier>`, as
`journal.flood` names it) for a source with `LOG_BURST_LINES` or more in `journal.errors`, or
flooding a capped `journal.warnings`; and each scheduled job (`job:<id>`, in domain `job`, the
domain the `job.*` rules fall in), whose state is the job's `static` definition only, so it is due
exactly when a job is new or changed. Services are not asked about one by one: only failed units are
entities, as above.

**Scheduled work.** `neonwatch.jobs` joins the cron and systemd probes (`jobs.PROBES`) into job
and service records once per snapshot, which carries them for the rules (`jobs`, `services`, and
`previous_services` from the previous observations). Those probes' raw data never enters a
domain state (whole crontabs and every unit's properties would not fit): the security domain
gets `jobs`, the job set's diff since the previous observations (added, removed and changed,
each with schedule, user and command, at most `JOB_CHANGES` listed and every count complete), and
the services domain gets `services`, a summary (states, failed, restarted since the previous
observation, and the state of each of `KEY_UNITS` that is loaded) with the timers added and
removed.

**Facts stated, not left to be read.** Where a judgement rests on a fact the code can compute,
the state carries the fact: the firewall's `inbound_filtered` (whether anything on the input hook
filters), the security domain's `exposure` (every wildcard port, its processes and the running
containers publishing it, and `inbound_filtered` again), and the kernel domain's `kernels` (the
running release against the newest in /boot; `KERNEL_PROBES` are joined, never carried raw).
A context is **due** when its state differs from the state it was last answered for, or when it
has not been answered for `REFRESH_EVERY` collations. A context is answered when the judge returned
at least one attestation for it; one that got none stays due.

**Budget.** the judge is serial, ~12 questions/s (`QUESTIONS_PER_S`, measured). A pass may take
`PASS_S` seconds, so `PASS_QUESTIONS` asks. A context costs its bank's questions plus every
stability-checked one (the worst case: each re-asked), so the cap holds whatever judge answers.
`CORRELATION_LIMIT` correlation contexts are reserved; the rest is `CONTEXT_BUDGET`. Due contexts
are taken in priority order until the next one does not fit, and the rest are deferred and
counted (they stay due): first contexts touched by a deterministic finding (the same entity, or a
domain a finding belongs to), then entities, then changed domains, then new or changed jobs, then
refreshes. A job new on first sight is inventory, not a symptom, and after every restart the
window is empty and every job is new: so jobs fill what the domains leave and spread over the
next collations, while a job a deterministic finding touches (`job.runs_from_tmp`) goes first.
Whatever their tier, job contexts take at most `JOB_SHARE` of a pass (touched ones first among
them); a job past it is deferred and stays due, and the pass goes on with everything else. Any
user writes jobs, and the findings that touch them, so jobs alone cannot fill a pass.

**Issues** (the heart of it):

1. An issue is identified by (domain, entity, family): the family is the rule id for a
   deterministic issue and the context kind for a judged one. `issue_id` hashes the three, so
   the same problem keeps the same id across collations.
2. A deterministic issue is OPEN while its finding is active. A context's attestations attach to
   the deterministic issues active on the same (domain, entity); only when there is none does the
   context stand for an issue of its own, and that opens when its attestations reach WARN or
   above and those are not all unstable. An unstable-only WARN stays an attestation, no issue.
3. Severity is the maximum of the active finding's severity and the attached attestations', not
   counting unstable ones. A judgement can raise or rank an issue, never clear or lower a
   deterministic one: while its finding is active the issue is open at no less than the finding's
   severity, whatever the judge says.
4. The attestations an issue rests on are each context's latest answers, kept while that context
   is still current (asked this time or not). The judge returning nothing keeps the previous
   answers: silence is not evidence that a problem went away.
5. RESOLVED after its conditions have been absent for `RESOLVE_AFTER` consecutive collations
   (hysteresis); until then it stays OPEN at its last severity. A deterministic issue's condition
   is its finding. A condition that returns resets the count; one that returns after resolution
   reopens the same id with a new `opened_at`.
6. `reasons`: the rule id, then the question ids of attached attestations at WATCH or above.
   `next_step`: the most severe non-unstable reading that has one; failing that, the most severe
   finding's, so a deterministic issue never lacks a step its finding carries. `title`: the
   finding's, or the top reading's cause and the entity.
7. `score` (percolation, `percolate`): severity dominates, then deterministic first, then urgency
   (the `urgency` score attestation, normalised to [0, 1]), then stability (any unstable
   attestation behind it lowers it), then novelty (opened or escalated within `NOVELTY_S`).
   `rank` orders by it.
8. Every open issue is emitted each collation with fresh fields, and a resolution once. The
   operator's hold (acknowledged, snoozed) lives in the store, which keeps it across these.
9. Issues survive a restart. The window starts empty but the store does not: at startup the
   service hands `adopt` the store's unresolved issues (open, acknowledged or snoozed), and each
   is tracked as if this process had opened it. One whose condition still holds goes on under
   the same id and `opened_at`; one whose condition has gone resolves after `RESOLVE_AFTER`
   collations, like any other. The evaluator says only OPEN and RESOLVED, so a held issue is
   tracked as OPEN and the store keeps the hold. What the score does not carry is not known:
   an adopted issue was last escalated, as far as novelty goes, when it opened.

**Links.** The correlator is handed the open issues, plus active findings that no open issue
carries (so an issue is never paired with its own finding), at most `CORRELATION_LIMIT`
candidates within `CORRELATION_WINDOW_S`.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import re
import signal
from collections import Counter, deque
from collections.abc import Awaitable, Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Protocol

from neonwatch import jobs, rules
from neonwatch.config import Config
from neonwatch.correlator import RULE_DOMAINS, Candidate, Item, candidates
from neonwatch.probes import CATALOG, ProbeSpec
from neonwatch.questions import DOMAINS, ContextKind, bank_for, needs_present
from neonwatch.rules import Snapshot
from neonwatch.schema import (
    Attestation,
    Context,
    Event,
    Finding,
    Heartbeat,
    Issue,
    IssueState,
    Kind,
    Link,
    Observation,
    Severity,
    from_body,
    to_body,
)

SOURCE = "evaluator"

# --- the window ----------------------------------------------------------------------------------

#: Good observations kept per probe.
HISTORY = 6
#: How far ahead of this process's clock an event may be dated. Anything later is refused and
#: counted, so a heartbeat from the far future can never become the newest one and hide a
#: dead agent.
MAX_SKEW_S = 120.0
HEARTBEATS = 16

#: Probe id -> spec, from the catalog. A template (a spec with `devices`) is never observed
#: itself; its expansions `<template>.<device>` are, for the devices its regex admits.
SPECS: dict[str, ProbeSpec] = {spec.id: spec for spec in CATALOG}
TEMPLATES = tuple(spec for spec in CATALOG if spec.devices)
#: Where a template's device names come from: a device it no longer lists is not held to its
#: cadence (a removed disk is not a stale probe).
DEVICE_LISTING = "block.devices"
#: The template whose expansions are disks.
SMART = "smart"

# --- contexts ------------------------------------------------------------------------------------

#: Rows of each process list a domain context carries.
TOP_N = 8
#: Journal lines a context carries, newest last.
LINES = 8
MESSAGE_CHARS = 200
ARGS_CHARS = 160
#: Names listed when a set changed (the counts are always complete).
NAMES = 20
PROCESS_CPU_PCT = 90.0
PROCESS_RSS_SHARE = 0.10
MAX_PROCESSES = 5
#: Seconds a process must have run before ps's `pcpu` (CPU time over lifetime) counts. The
#: process probe's own ps read itself at 700% at 0 s elapsed and was asked about every pass
#: (2026-10-28). A previous sample's `recent_cpu_pct` counts at any age.
PROCESS_MIN_AGE_S = 10
#: Wildcard ports the security domain's exposure lists (the count is complete).
EXPOSED_PORTS = 40
#: Units whose state the services domain names outright: logging and security services, read
#: from `units.detail` where loaded. The summary alone said only how many were active.
KEY_UNITS = ("systemd-journald.service", "rsyslog.service", "apparmor.service", "ufw.service",
             "firewalld.service", "auditd.service", "fail2ban.service",
             "unattended-upgrades.service", "ssh.service", "docker.service")
#: Probes the kernel domain carries joined, as `kernels`, rather than raw.
KERNEL_PROBES = ("boot", "kernel.release")
#: hwmon drivers whose temperatures are the CPU's, by their lm-sensors chip prefix: AMD's
#: k10temp and zenpower, Intel's coretemp.
CPU_CHIPS = ("k10temp-", "zenpower-", "coretemp-")
LOG_BURST_LINES = 20
#: Jobs listed per kind of change in the security domain's job diff (the counts are complete).
JOB_CHANGES = 10
#: The domain of job contexts: `domain_of` gives it to the `job.*` rules too, so a job's
#: attestations attach to its deterministic issues.
JOB_DOMAIN = "job"
#: Collations an unchanged context waits before it is asked again.
REFRESH_EVERY = 6

# --- the budget ----------------------------------------------------------------------------------

#: Measured 2026-09-30: The judge answers ~12-13 questions/s, serially.
QUESTIONS_PER_S = 12
PASS_S = 45
PASS_QUESTIONS = PASS_S * QUESTIONS_PER_S
CORRELATION_LIMIT = 3
CORRELATION_WINDOW_S = 900.0


def asks(context: Context) -> int:
    """Questions the judge puts to this context: those whose evidence it carries."""
    return sum(needs_present(q, context.state) for q in bank_for(ContextKind(context.kind)))


def cost(kind: ContextKind) -> int:
    """Worst-case asks for one context: its bank, and a re-ask of every stability-checked one."""
    bank = bank_for(kind)
    return len(bank) + sum(q.stability_check for q in bank)


CORRELATION_RESERVE = CORRELATION_LIMIT * cost(ContextKind.CORRELATION)
CONTEXT_BUDGET = PASS_QUESTIONS - CORRELATION_RESERVE
#: The most of `CONTEXT_BUDGET` job contexts may take in one pass, in any tier: any user writes
#: jobs (and the findings that touch them), so jobs never crowd out the rest.
JOB_SHARE = CONTEXT_BUDGET // 3

# --- issues --------------------------------------------------------------------------------------

#: Consecutive collations without its conditions before an issue resolves.
RESOLVE_AFTER = 3
#: An issue opened or escalated this recently ranks as new.
NOVELTY_S = 3600.0
URGENCY = "urgency"

_TIERS = ("touched", "entity", "changed", "jobs", "refresh")


class EvaluatorError(ValueError):
    """An event the evaluator does not accept."""


class Judge(Protocol):
    def attest(self, contexts: Sequence[Context]) -> Awaitable[tuple[Attestation, ...]]: ...


class Correlator(Protocol):
    def link(self, candidates: Sequence[Candidate]) -> Awaitable[tuple[Link, ...]]: ...


Rules = Callable[[Snapshot, Config], Sequence[Finding]]


@dataclass(frozen=True, slots=True)
class Collation:
    findings: tuple[Finding, ...]
    attestations: tuple[Attestation, ...]
    #: Every open issue and every issue resolved this collation, ranked.
    issues: tuple[Issue, ...]
    links: tuple[Link, ...]
    #: What the service publishes: findings, attestations, issues, links, in that order.
    events: tuple[Event, ...]
    #: Due contexts left for the next collation by the question budget.
    deferred_contexts: int
    #: Bank questions in the contexts asked (first asks; re-asks are the judge's).
    questions_asked: int
    duration_ms: int


def dumps(value: Any) -> str:
    """Compact, key-sorted JSON: how a state is compared and measured."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def _digest(text: str, n: int = 12) -> str:
    return hashlib.sha256(text.encode()).hexdigest()[:n]


def issue_id(domain: str, entity: str, family: str) -> str:
    return "i-" + _digest(f"{domain}\n{entity}\n{family}", 16)


def percolate(severity: Severity, deterministic: bool, urgency: float, *, unstable: bool,
              novel: bool) -> float:
    """Severity, then deterministic, then urgency (to 0.01), then stability, then novelty."""
    return float(severity.rank * 10_000 + deterministic * 1_000
                 + round(min(max(urgency, 0.0), 1.0) * 100) * 5 + (0 if unstable else 2)
                 + (1 if novel else 0))


def rank(issues: Sequence[Issue]) -> tuple[Issue, ...]:
    """Highest score first; the id breaks ties, so the order is the same every time."""
    return tuple(sorted(issues, key=lambda i: (-i.score, i.id)))


def domain_of(rule: str) -> str:
    """A rule's domain, as the correlator reads it."""
    prefix = rule.split(".", 1)[0]
    return RULE_DOMAINS.get(prefix, prefix)


def correlation_items(now: float, findings: Sequence[Finding],
                      issues: Sequence[Issue]) -> list[Item]:
    """Open issues, then active findings that no open issue carries."""
    live = [i for i in issues if i.state is IssueState.OPEN]
    carried = {(rule, i.entity) for i in live for rule in i.reasons}
    return [*(Item.of_issue(i) for i in live),
            *(Item.of_finding(now, f) for f in findings if (f.rule, f.entity) not in carried)]


# --- reading observations ------------------------------------------------------------------------


def _num(data: Mapping[str, Any], key: str) -> float | None:
    value = data.get(key)
    return value if isinstance(value, int | float) and not isinstance(value, bool) else None


def _rows(data: Mapping[str, Any] | None, key: str) -> list[dict[str, Any]]:
    value = (data or {}).get(key)
    return [r for r in value if isinstance(r, dict)] if isinstance(value, list) else []


def _diff(now: Iterable[str], before: Iterable[str] | None) -> dict[str, list[str]]:
    if before is None:
        return {}
    now, before = set(now), set(before)
    return {"added": sorted(now - before)[:NAMES], "removed": sorted(before - now)[:NAMES]}


def _names(rows: list[dict[str, Any]], key: str) -> list[str]:
    return [r[key] for r in rows if isinstance(r.get(key), str)]


def _increase(now: Mapping[str, Any], before: Mapping[str, Any] | None,
              keys: Iterable[str]) -> dict[str, float]:
    out = {}
    for key in keys if before is not None else ():
        a, b = _num(now, key), _num(before, key)
        if a is not None and b is not None and a > b:
            out[key] = a - b
    return out


def _source(line: Mapping[str, Any]) -> str:
    """The journal parser's `by_unit` key: unit, else identifier, else "unknown"."""
    return line.get("unit") or line.get("identifier") or "unknown"


def _line(line: Mapping[str, Any]) -> dict[str, Any]:
    return {"source": _source(line), "priority": line.get("priority"),
            "message": str(line.get("message", ""))[:MESSAGE_CHARS]}


def _proc(row: Mapping[str, Any]) -> dict[str, Any]:
    out = {k: row.get(k) for k in ("pid", "ppid", "user", "state", "cpu_pct", "rss_kb",
                                   "elapsed_s", "threads", "comm", "pid_ns")}
    out["args"] = str(row.get("args", ""))[:ARGS_CHARS]
    return out


def _entity_kind(source: str) -> str:
    return "unit" if source.endswith(rules.UNIT_SUFFIXES) else "log"


# --- compact state per probe: (latest, previous or None, seconds between) -> state -------------

Compact = Callable[[dict[str, Any], dict[str, Any] | None, float | None], Any]

_TICKS = ("user", "nice", "system", "idle", "iowait", "irq", "softirq", "steal")


def _as_is(d: dict[str, Any], p: dict[str, Any] | None, dt: float | None) -> Any:
    return d


def _uptime(d: dict[str, Any], p: dict[str, Any] | None, dt: float | None) -> Any:
    now, was = _num(d, "uptime_s"), _num(p or {}, "uptime_s")
    return {"uptime_days": None if now is None else round(now / 86400, 1),
            "rebooted": now is not None and was is not None and now < was}


def _cpu_stat(d: dict[str, Any], p: dict[str, Any] | None, dt: float | None) -> Any:
    out = {k: d.get(k) for k in ("cpus", "procs_running", "procs_blocked")}
    ticks = _increase(d, p, _TICKS)
    total = sum(ticks.values())
    if total:
        out["pct"] = {k: round(100 * ticks.get(k, 0) / total, 1) for k in _TICKS}
    if p is not None and dt:
        for key, name in (("ctxt", "ctxt_per_s"), ("processes", "forks_per_s")):
            out[name] = round(_increase(d, p, (key,)).get(key, 0) / dt, 1)
    return out


def _vmstat(d: dict[str, Any], p: dict[str, Any] | None, dt: float | None) -> Any:
    return {**d, "increase": _increase(d, p, ("oom_kill", "pgmajfault", "pswpin", "pswpout"))}


def _reading(r: Mapping[str, Any]) -> dict[str, Any]:
    """One sensor reading, and for a temperature its `limit_c` and `headroom_c`, so a reading is
    judged against a limit rather than as a bare number (Tctl at 77 C, 18 C under the 95 C an
    AMD CPU allows, read as overheating, 2026-10-27).

    The limit is the nearer of the sensor's own high (`max`) and `crit`, dropping lm-sensors'
    sentinels (NVMe reports 65261.85 C, 0xFFFF kelvin, for "none"), with `limit_source` saying
    which. A CPU sensor that reports neither (k10temp never does) gets `rules.CPU_LIMIT_C`, the
    limit `cpu.temperature` holds it to; any other has no limit stated.
    """
    out = {k: r[k] for k in ("chip", "label", "kind", "input", "max", "crit", "alarm")
           if r.get(k) is not None}
    value = _num(r, "input")
    if r.get("kind") != "temp" or value is None:
        return out
    low, high = rules.PLAUSIBLE_CRIT_C
    limits = []
    for key in ("max", "crit"):
        if (limit := _num(r, key)) is not None and low < limit < high:
            limits.append((limit, key))
        else:
            out.pop(key, None)
    if not limits and str(r.get("chip", "")).startswith(CPU_CHIPS):
        limits.append((rules.CPU_LIMIT_C, "cpu default"))
    if limits:
        limit, source = min(limits)
        out |= {"limit_c": limit, "limit_source": source, "headroom_c": round(limit - value, 1)}
    return out


def _sensors(d: dict[str, Any], p: dict[str, Any] | None, dt: float | None) -> Any:
    return [_reading(r) for r in _rows(d, "readings")]


def _disk_fill(d: dict[str, Any], p: dict[str, Any] | None, dt: float | None) -> Any:
    return [{k: fs.get(k) for k in ("mount", "source", "fstype", "used_pct", "avail_bytes",
                                    "inodes_used_pct")} for fs in _rows(d, "filesystems")]


def _net_dev(d: dict[str, Any], p: dict[str, Any] | None, dt: float | None) -> Any:
    now = _rows(d, "interfaces")
    before = {r.get("name"): r for r in _rows(p, "interfaces")}
    out: dict[str, Any] = {"count": d.get("count"),
                           **_diff(_names(now, "name"), _names(list(before.values()), "name")
                                   if p is not None else None)}
    if p is not None and dt:
        rates, errors = [], []
        for r in now:
            old = before.get(r.get("name"))
            if old is None:
                continue
            grew = _increase(r, old, ("rx_bytes", "tx_bytes", "rx_errs", "rx_drop", "tx_errs",
                                      "tx_drop"))
            rx, tx = grew.get("rx_bytes", 0) / dt, grew.get("tx_bytes", 0) / dt
            if rx or tx:
                rates.append({"name": r["name"], "rx_bytes_per_s": round(rx, 1),
                              "tx_bytes_per_s": round(tx, 1)})
            if bad := {k: v for k, v in grew.items() if not k.endswith("bytes")}:
                errors.append({"name": r["name"], **bad})
        out["busiest"] = sorted(rates, key=lambda r: (-(r["rx_bytes_per_s"]
                                                        + r["tx_bytes_per_s"]), r["name"]))[:5]
        if errors:
            out["errors"] = errors[:NAMES]
    return out


def _recent(rows: list[dict[str, Any]], p: dict[str, Any] | None,
            dt: float | None) -> list[dict[str, Any]]:
    """Rows compacted, with `recent_cpu_pct` from `cpu_s` where the previous sample has the
    same process (same pid, not younger than before)."""
    before = {r.get("pid"): r for key in ("top_cpu", "top_rss", "from_tmp")
              for r in _rows(p, key)}
    out = []
    for row in rows:
        compact = _proc(row)
        old = before.get(row.get("pid"))
        if old is not None and dt and (_num(old, "elapsed_s") or 0) <= (
                _num(row, "elapsed_s") or 0):
            used = _increase(row, old, ("cpu_s",)).get("cpu_s", 0)
            compact["recent_cpu_pct"] = round(100 * used / dt, 1)
        out.append(compact)
    return out


def _processes(d: dict[str, Any], p: dict[str, Any] | None, dt: float | None) -> Any:
    out = {k: d.get(k) for k in ("count", "threads", "rss_kb_total", "cpu_pct_total", "zombies",
                                 "uninterruptible")}
    for key, n in (("top_cpu", TOP_N), ("top_rss", TOP_N), ("from_tmp", NAMES)):
        out[key] = _recent(_rows(d, key)[:n], p, dt)
    out["tmp_test_runs"] = [{k: r.get(k) for k in ("pid", "user", "pid_ns", "args", "processes")}
                            for r in _rows(d, "tmp_test_runs")[:NAMES]]
    return out


def _journal(d: dict[str, Any], p: dict[str, Any] | None, dt: float | None) -> Any:
    by_unit = d.get("by_unit") if isinstance(d.get("by_unit"), dict) else {}
    top = sorted(((n, k) for k, n in by_unit.items() if isinstance(n, int)),
                 key=lambda item: (-item[0], item[1]))[:10]
    return {"count": d.get("count"), "capped": d.get("capped"),
            "top_sources": {k: n for n, k in top}, "by_priority": d.get("by_priority"),
            "recent": [_line(e) for e in _rows(d, "entries")[-LINES:]]}


def _exposed(rows: list[dict[str, Any]]) -> dict[tuple[str, int], list[dict[str, Any]]]:
    """Wildcard listeners by (proto, port), as `listener.new_wildcard` counts them."""
    out: dict[tuple[str, int], list[dict[str, Any]]] = {}
    for r in rows:
        proto, port = r.get("proto"), r.get("port")
        if r.get("wildcard") is not True or not isinstance(port, int):
            continue
        if (proto == "tcp" and r.get("state") == "LISTEN") or (
                proto == "udp" and port < rules.EPHEMERAL_FLOOR):
            out.setdefault((proto, port), []).append(r)
    return out


def _new_listeners(d: dict[str, Any], p: dict[str, Any] | None
                   ) -> dict[tuple[str, int], list[dict[str, Any]]]:
    if p is None or not isinstance(p.get("listeners"), list):
        return {}
    standing = _exposed(_rows(p, "listeners"))
    return {k: v for k, v in _exposed(_rows(d, "listeners")).items() if k not in standing}


def _listeners(d: dict[str, Any], p: dict[str, Any] | None, dt: float | None) -> Any:
    exposed = [{"proto": r["proto"], "address": r.get("address"), "port": r["port"],
                "process": r.get("process")} for socks in _exposed(_rows(d, "listeners")).values()
               for r in socks]
    return {"count": d.get("count"), "wildcard_count": d.get("wildcard_count"),
            "wildcard": exposed[:NAMES],
            "new": [f"{proto}/{port}" for proto, port in _new_listeners(d, p)]}


def _health(c: Mapping[str, Any]) -> Any:
    """A container's healthcheck status while it runs, else None. Docker keeps the last status
    of a container that has stopped (a compose one-shot that exited 0 weeks ago still reads
    `unhealthy`), and no check runs on a stopped one, so its health is not evidence."""
    return c.get("health") if c.get("state") == "running" else None


def _exit_meaning(code: Any) -> str | None:
    """What an exit code above 128 says: the process died of signal `code - 128`, and nothing
    about who sent it. 137 is SIGKILL, which `docker stop` (after its grace), `docker kill`,
    `compose down` and the OOM killer all send; `/containers/json` carries no OOMKilled flag,
    so an exit code alone never shows an OOM kill (imagegen, exit 137, OOMKilled=false,
    2026-10-27)."""
    if not isinstance(code, int) or isinstance(code, bool) or not 128 < code <= 128 + 64:
        return None
    try:
        name = f" ({signal.Signals(code - 128).name})"
    except ValueError:
        name = ""
    return (f"killed by signal {code - 128}{name}; whether the OOM killer sent it is not "
            "reported")


def _port(p: Mapping[str, Any]) -> str:
    """A published port as Docker prints it: `0.0.0.0:6379->6379/tcp`."""
    return f"{p.get('ip') or '*'}:{p.get('port')}->{p.get('container_port')}/{p.get('proto')}"


def _container(c: Mapping[str, Any]) -> dict[str, Any]:
    """One container as a context carries it: health only while it runs (`_health`), a death
    by signal spelled out (`_exit_meaning`), and its published ports as Docker prints them."""
    meaning = _exit_meaning(c.get("exit_code"))
    out = {**c, "health": _health(c), **({"exit_meaning": meaning} if meaning else {})}
    if isinstance(c.get("published"), list):
        out["published"] = [_port(p) for p in c["published"] if isinstance(p, dict)]
    return out


#: Container fields a list carries only where they say something: a port published, the
#: host's network, a host mount.
_NOTABLE = (("published", lambda v: bool(v)), ("network_mode", lambda v: v == "host"),
            ("host_mounts", lambda v: bool(v)))


def _pick(c: Mapping[str, Any], keys: Iterable[str]) -> dict[str, Any]:
    """`keys` of a `_container` view, its exit meaning where it has one, and its notable
    fields (`_NOTABLE`)."""
    return {k: c.get(k) for k in keys} | (
        {"exit_meaning": c["exit_meaning"]} if "exit_meaning" in c else {}) | {
        k: c[k] for k, notable in _NOTABLE if notable(c.get(k))}


#: Docker's humanised durations in a status ("Exited (0) 5 weeks ago", "Up About an hour",
#: "Up Less than a second"): a number or "a"/"an"/"about a(n)"/"less than a(n)", then a unit.
_STATUS_AGE = re.compile(r"(?:(?P<n>\d+)|(?P<word>less than an?|about an?|an?))\s+"
                         r"(?P<unit>second|minute|hour|day|week|month|year)s?\b", re.I)
_UNIT_S = {"second": 1, "minute": 60, "hour": 3600, "day": 86_400, "week": 604_800,
           "month": 2_592_000, "year": 31_536_000}
#: A container that exited or started this recently counts as churn.
CHURN_WINDOW_S = 3600
#: Names of churning containers a context carries, at most.
CHURN_NAMES = 5


def _status_age_s(status: Any) -> int | None:
    """Seconds since a container's status changed, read from Docker's text; None if unsaid."""
    match = _STATUS_AGE.search(status) if isinstance(status, str) else None
    if match is None:
        return None
    word = (match["word"] or "").lower()
    n = int(match["n"]) if match["n"] else 0 if word.startswith("less") else 1
    return n * _UNIT_S[match["unit"].lower()]


def _churn(rows: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    """Churn counted here rather than left to be read off statuses. With nothing restarting,
    imagegen's exit 137 from 21 hours before was judged `oom` churn (2026-10-27): an exit weeks
    or hours old is history, not churn."""
    def recent(c: Mapping[str, Any], state: str) -> bool:
        age = _status_age_s(c.get("status"))
        return c.get("state") == state and age is not None and age < CHURN_WINDOW_S

    restarting = [c.get("name") for c in rows if c.get("state") == "restarting"]
    exited = [c.get("name") for c in rows if recent(c, "exited")]
    return {"restarting": len(restarting), "exited_last_hour": len(exited),
            "started_last_hour": sum(recent(c, "running") for c in rows),
            "names": [n for n in restarting + exited if isinstance(n, str)][:CHURN_NAMES]}


def _containers(d: dict[str, Any], p: dict[str, Any] | None, dt: float | None) -> Any:
    rows = [_container(c) for c in _rows(d, "containers")]
    return {"count": d.get("count"), "by_state": d.get("by_state"), "churn": _churn(rows),
            "containers": [_pick(c, ("name", "image", "state", "health", "exit_code"))
                           for c in rows][:30]}


def _gpu(g: Mapping[str, Any], old: Mapping[str, Any] | None) -> dict[str, Any]:
    """One GPU as a context carries it, its PCIe width told against its previous width and not
    its maximum. Boards wire some slots narrower than the card (GPU0 in a chipset slot is x4 of
    x16 for good, idle, unthrottled, 2026-10-27), so a width below the maximum that never
    changed is the slot, and only a drop is news; `gpu.pcie_degraded` reads it the same way.
    The maximum is left out so the bare gap cannot read as a fault. A different card in the
    same index has no previous width."""
    out = {k: v for k, v in g.items() if k != "pcie_width_max"}
    width = _num(g, "pcie_width")
    was = _num(old, "pcie_width") if old is not None and old.get("name") == g.get("name") \
        else None
    out["pcie_width_previous"] = was
    out["pcie_width_dropped"] = width is not None and was is not None and width < was
    return out


def _gpus(d: dict[str, Any], p: dict[str, Any] | None, dt: float | None) -> Any:
    was = {g.get("index"): g for g in _rows(p, "gpus")}
    return {**d, "gpus": [_gpu(g, was.get(g.get("index"))) for g in _rows(d, "gpus")]}


_SMART_FIELDS = ("device", "model", "serial", "passed", "temperature_c", "critical_warning",
                 "available_spare_pct", "percentage_used", "media_errors", "error_log_entries",
                 "unsafe_shutdowns", "reallocated_sectors", "pending_sectors",
                 "offline_uncorrectable", "reported_uncorrect", "udma_crc_errors",
                 "failing_attributes")


def _smart(d: dict[str, Any], p: dict[str, Any] | None, dt: float | None) -> Any:
    return {k: d[k] for k in _SMART_FIELDS if d.get(k) is not None}


def _input_chains(d: Mapping[str, Any]) -> list[dict[str, Any]]:
    return [{k: ch.get(k) for k in ("family", "table", "policy", "rules")}
            for ch in _rows(d, "base_chains") if ch.get("hook") == "input"]


def _filtered(d: Mapping[str, Any]) -> bool:
    """Whether any base chain on the input hook drops by default or holds rules. False is
    certain: nothing filters inbound traffic. A judge can read a ruleset of Docker's nat and
    forward chains alone as "managed" with filtering, so the fact is stated, not left to be read
    off the chains."""
    return any(ch.get("policy") in ("drop", "reject") or (_num(ch, "rules") or 0) > 0
               for ch in _input_chains(d))


def _firewall(d: dict[str, Any], p: dict[str, Any] | None, dt: float | None) -> Any:
    return {**d, "changed": p is not None and p.get("hash") != d.get("hash"),
            "input_chains": _input_chains(d), "inbound_filtered": _filtered(d)}


def _exposure(listeners: Mapping[str, Any], firewall: Mapping[str, Any] | None,
              containers: Mapping[str, Any] | None) -> dict[str, Any]:
    """What the network can reach: every wildcard port (not only new ones), its processes and
    the running containers publishing it, and whether anything filters inbound traffic. Without
    this the security questions about exposure would be asked of a state with no listeners in
    it, and a database on 0.0.0.0 with no input filtering would go unremarked."""
    published: dict[tuple[Any, Any], set[str]] = {}
    for c in _rows(containers, "containers"):
        if c.get("state") == "running" and isinstance(c.get("name"), str):
            for p in _rows(c, "published"):
                if p.get("ip") in ("", "0.0.0.0", "::"):
                    published.setdefault((p.get("proto"), p.get("port")), set()).add(c["name"])
    ports = []
    for (proto, port), socks in sorted(_exposed(_rows(listeners, "listeners")).items(),
                                       key=lambda item: (item[0][1], item[0][0])):
        entry: dict[str, Any] = {"proto": proto, "port": port, "processes": sorted(
            {s["process"] for s in socks if isinstance(s.get("process"), str)})}
        if names := published.get((proto, port)):
            entry["containers"] = sorted(names)
        ports.append(entry)
    out: dict[str, Any] = {"wildcard_ports": len(ports), "listening": ports[:EXPOSED_PORTS]}
    if firewall is not None:
        out["inbound_filtered"] = _filtered(firewall)
    return out


def _kernels(boot: Mapping[str, Any], release: Mapping[str, Any]) -> dict[str, Any]:
    """The running kernel against the newest installed one (`/boot/vmlinuz-<release>`)."""
    def version(name: str) -> tuple[int, ...]:
        return tuple(int(n) for n in re.findall(r"\d+", name))

    installed = sorted((e.removeprefix("vmlinuz-") for e in boot.get("entries") or []
                        if isinstance(e, str) and e.startswith("vmlinuz-")), key=version)
    running = release.get("release")
    newest = installed[-1] if installed else None
    return {"running": running, "newest_installed": newest, "installed": len(installed),
            "running_is_newest": newest is None or not isinstance(running, str)
            or version(running) >= version(newest)}


def _mounts(d: dict[str, Any], p: dict[str, Any] | None, dt: float | None) -> Any:
    mounts = _rows(d, "mounts")
    targets = _names(mounts, "target")
    return {"count": d.get("count"),
            "read_only": [m.get("target") for m in mounts if m.get("read_only") is True],
            "network": [{k: m.get(k) for k in ("target", "source", "fstype")}
                        for m in mounts if m.get("network") is True][:NAMES],
            **_diff(targets, _names(_rows(p, "mounts"), "target") if p is not None else None)}


def _modules(d: dict[str, Any], p: dict[str, Any] | None, dt: float | None) -> Any:
    before = p.get("modules") if p is not None and isinstance(p.get("modules"), list) else None
    return {"count": d.get("count"), "tainting": d.get("tainting"),
            "not_live": d.get("not_live"), **_diff(d.get("modules") or [], before)}


def _keys(d: dict[str, Any], p: dict[str, Any] | None, dt: float | None) -> Any:
    keys = _rows(d, "keys")
    return {"files": [{k: f.get(k) for k in ("path", "keys", "invalid_lines")}
                      for f in _rows(d, "files")],
            "keys": [{k: key.get(k) for k in ("path", "type", "fingerprint", "comment",
                                              "options")} for key in keys][:30],
            **_diff(_names(keys, "fingerprint"),
                    _names(_rows(p, "keys"), "fingerprint") if p is not None else None)}


def _entries(d: dict[str, Any], p: dict[str, Any] | None, dt: float | None) -> Any:
    """A listing and what it gained or lost. Its link targets stay out: under /sys/block every
    entry is a link into /sys/devices, which says nothing about a disk's health."""
    return {**{k: v for k, v in d.items() if k != "links"},
            **_diff(d.get("entries") or [], (p or {}).get("entries") if p is not None else None)}


def _unit_files(d: dict[str, Any], p: dict[str, Any] | None, dt: float | None) -> Any:
    units = d.get("units") if isinstance(d.get("units"), dict) else {}
    before = p.get("units") if p is not None and isinstance(p.get("units"), dict) else None
    return {"count": d.get("count"), "by_state": d.get("by_state"), **_diff(units, before)}


def _views(s: Snapshot) -> tuple[dict[str, dict], dict[str, dict] | None]:
    """What `jobs` joins, as it takes it: the latest of `jobs.PROBES`, and the same with each
    probe's previous observation where there is one (None when no probe has one: no baseline)."""
    now = {p: s.latest[p][1] for p in jobs.PROBES if p in s.latest}
    was = {p: s.previous[p][1] for p in jobs.PROBES if p in s.previous}
    return now, ({**now, **was} if was else None)


def _brief(job: Mapping[str, Any]) -> dict[str, Any]:
    return {"id": job["id"], "source": job.get("source"), "user": job.get("user"),
            "schedule": job.get("schedule"), "command": str(job.get("command", ""))[:ARGS_CHARS]}


def _scheduled(now: Sequence[Mapping[str, Any]], skipped: int,
               before: Sequence[Mapping[str, Any]] | None) -> dict[str, Any]:
    """The security domain's view of the job set: counts, and what changed since `before`."""
    out: dict[str, Any] = {"count": len(now), "skipped": skipped, "by_source": dict(sorted(
        Counter(str(j.get("source")) for j in now).items()))}
    if before is None:
        return out
    is_, was = {j["id"]: j for j in now}, {j["id"]: j for j in before}
    changes = {"added": [is_[i] for i in sorted(is_.keys() - was.keys())],
               "removed": [was[i] for i in sorted(was.keys() - is_.keys())],
               "changed": [is_[i] for i in sorted(is_.keys() & was.keys())
                           if is_[i].get("static") != was[i].get("static")]}
    for change, rows in changes.items():
        out[change] = [_brief(j) for j in rows[:JOB_CHANGES]]
        out[f"{change}_count"] = len(rows)
    return out


def _services(now: Sequence[Mapping[str, Any]], before: Sequence[Mapping[str, Any]],
              found: Sequence[Mapping[str, Any]],
              was: Sequence[Mapping[str, Any]] | None) -> dict[str, Any]:
    """The services domain's view: states, failed and restarted services, and the timers among
    the jobs `found`, added or removed since `was`."""
    restarts = {svc.get("name"): svc for svc in before}
    restarted = []
    for svc in now:
        grew = _increase(svc, restarts.get(svc.get("name")), ("restarts",)).get("restarts")
        if grew:
            restarted.append({"name": svc.get("name"), "restarts": svc.get("restarts"),
                              "increase": grew})
    timers = [j["id"] for j in found if j.get("source") == "timer"]
    return {"count": len(now), "by_active": dict(sorted(
                Counter(str(svc.get("active")) for svc in now).items())),
            "failed": sorted(str(svc.get("name")) for svc in now
                             if svc.get("active") == "failed")[:NAMES],
            "restarted": sorted(restarted, key=lambda r: (-r["increase"], r["name"]))[:NAMES],
            "key_units": {svc["name"]: {k: svc.get(k) for k in ("active", "sub", "enabled")}
                          for svc in now if svc.get("name") in KEY_UNITS},
            "timers": {"count": len(timers), **_diff(timers, None if was is None else [
                j["id"] for j in was if j.get("source") == "timer"])}}


COMPACT: dict[str, Compact] = {
    "uptime": _uptime, "cpu.stat": _cpu_stat, "vmstat": _vmstat, "sensors": _sensors,
    "disk.fill": _disk_fill, "net.dev": _net_dev, "processes": _processes,
    "journal.warnings": _journal, "journal.errors": _journal, "listeners": _listeners,
    "containers": _containers, "firewall": _firewall, "kernel.modules": _modules,
    "ssh.keys.home": _keys, "ssh.keys.root": _keys, "block.devices": _entries,
    "units.files": _unit_files, "gpu": _gpus, SMART: _smart, "mounts": _mounts,
}


def template(probe: str) -> ProbeSpec | None:
    """The template `probe` expands, or None for a plain catalog probe or an unknown id."""
    for spec in TEMPLATES:
        name = probe.removeprefix(spec.id + ".")
        if name != probe and re.fullmatch(spec.devices, name):
            return spec
    return None


def _listed(latest: Mapping[str, tuple[float, dict]], probe: str) -> bool:
    """Whether a device probe's device is still present: listed by the latest `block.devices`,
    or not yet contradicted by one. A plain probe always is."""
    listing = latest.get(DEVICE_LISTING)
    entries = listing[1].get("entries") if listing is not None else None
    return template(probe) is None or not isinstance(entries, list) \
        or probe.split(".", 1)[1] in entries


def place(probe: str) -> tuple[str, str]:
    """A probe's (domain, tier), from the catalog. An id it does not hold is refused."""
    spec = SPECS.get(probe)
    if spec is None or spec.devices:
        spec = template(probe)
    if spec is None:
        raise EvaluatorError(f"unknown probe {probe!r}")
    return spec.domain, spec.tier.value


# --- issue bookkeeping ---------------------------------------------------------------------------


def _counted(attestations: Iterable[Attestation]) -> list[Attestation]:
    return [a for a in attestations if a.stable is not False]


def _opens(attestations: Sequence[Attestation]) -> bool:
    warn = [a for a in attestations if a.severity.rank >= Severity.WARN.rank]
    return bool(_counted(warn))


def _urgency(attestations: Iterable[Attestation]) -> float:
    best = 0.0
    for a in _counted(attestations):
        if a.question != URGENCY or a.answer.get("type") != "score":
            continue
        value = a.answer.get("expected", a.answer.get("score"))
        levels = next((len(q.levels) for q in bank_for(ContextKind(a.context_kind))
                       if q.id == URGENCY), 0)
        if isinstance(value, int | float) and not isinstance(value, bool) and levels > 1:
            best = max(best, value / (levels - 1))
    return best


def _top(attestations: Sequence[Attestation]) -> Attestation | None:
    """The most severe non-unstable reading that says what to do next."""
    ranked = sorted(enumerate(a for a in _counted(attestations) if a.next_step),
                    key=lambda ia: (-ia[1].severity.rank, -ia[1].confidence, ia[0]))
    return ranked[0][1] if ranked else None


@dataclass(frozen=True, slots=True)
class _Present:
    domain: str
    entity: str
    family: str
    deterministic: bool
    severity: Severity
    title: str
    reasons: tuple[str, ...]
    next_step: str
    urgency: float
    unstable: bool
    evidence: dict[str, Any] = dataclasses.field(default_factory=dict)
    why: str = ""


@dataclass(slots=True)
class _Track:
    issue: Issue
    #: What it was last seen as; its score is recomputed from this while it is absent.
    seen: _Present
    escalated_at: float
    absent: int = 0


def _present(domain: str, entity: str, family: str, findings: Sequence[Finding],
             attestations: Sequence[Attestation]) -> _Present:
    behind = [a for a in attestations if a.severity.rank >= Severity.WATCH.rank]
    top = _top(attestations)
    severities = [f.severity for f in findings] + [a.severity for a in _counted(attestations)]
    severity = max(severities, key=lambda s: s.rank)
    leading = max(findings, key=lambda f: f.severity.rank) if findings else None
    if leading is not None:
        title, evidence, why = leading.title, leading.evidence, leading.why
    else:
        judged = top or _loudest(attestations)
        evidence = judged.evidence if judged is not None else {}
        title = _title(top.cause if top is not None else family, domain, entity, evidence)
        why = ""
    reasons = tuple(dict.fromkeys([*(f.rule for f in findings), *(a.question for a in behind)]))
    stepped = sorted((f for f in findings if f.next_step), key=lambda f: -f.severity.rank)
    step = top.next_step if top is not None else (stepped[0].next_step if stepped else "")
    return _Present(domain, entity, family, bool(findings), severity, title, reasons, step,
                    _urgency(attestations),
                    any(a.stable is False for a in behind), dict(evidence), why)


def _loudest(attestations: Sequence[Attestation]) -> Attestation | None:
    counted = _counted(attestations)
    return max(counted, key=lambda a: (a.severity.rank, a.confidence)) if counted else None


#: Words a cause slug spells in lower case that a title spells as they are written.
_ACRONYMS = {"cpu": "CPU", "gpu": "GPU", "io": "I/O", "oom": "OOM", "ssh": "SSH", "dns": "DNS",
             "smart": "SMART", "nvme": "NVMe", "psi": "PSI", "pid": "PID", "tmp": "tmp",
             "vpn": "VPN", "nfs": "NFS", "usb": "USB", "pcie": "PCIe", "udp": "UDP",
             "tcp": "TCP", "llm": "LLM", "api": "API"}


def _title(cause: str, domain: str, entity: str, evidence: Mapping[str, Any]) -> str:
    """A judge-raised issue's title, for a person: the cause in words (`suspicious-process` ->
    "Suspicious process"), then what it is about, named from the evidence where it can be (a
    process by its program and pid) rather than as an id."""
    words = " ".join(_ACRONYMS.get(w.lower(), w)
                     for w in cause.replace("-", " ").replace("_", " ").split())
    words = words[:1].upper() + words[1:] if words else "Judged issue"
    if entity == f"domain:{domain}":
        return f"{words} ({domain})"
    return f"{words}: {_label(entity, evidence)}"


def _label(entity: str, evidence: Mapping[str, Any]) -> str:
    kind, _, bare = entity.partition(":")
    if kind != "process":
        return entity
    found: dict[str, Any] = {}
    for key, value in evidence.items():
        if key == "process" and isinstance(value, Mapping):
            found.update(value)
        elif key.startswith("process/"):
            found[key.split("/", 1)[1]] = value
    args, comm = found.get("args"), found.get("comm")
    program = args.split(" ", 1)[0].rsplit("/", 1)[-1] if isinstance(args, str) and args \
        else comm if isinstance(comm, str) and comm else ""
    return f"{program} (pid {bare})" if program else f"pid {bare}"


def _score(p: _Present, now: float, opened: float, escalated: float) -> float:
    return percolate(p.severity, p.deterministic, p.urgency, unstable=p.unstable,
                     novel=now - max(opened, escalated) < NOVELTY_S)


def _adopted(issue: Issue) -> _Present:
    """What a stored issue was last seen as. `percolate` packs urgency (to 0.01) and stability
    into the score below its thousands, exactly, so both are read back from it; the family is
    already in the id, and nothing reads it again."""
    low = round(issue.score) % 1_000
    return _Present(issue.domain, issue.entity, "", issue.deterministic, issue.severity,
                    issue.title, issue.reasons, issue.next_step, urgency=low // 5 / 100,
                    unstable=low % 5 < 2, evidence=dict(issue.evidence), why=issue.why)


# --- the evaluator -------------------------------------------------------------------------------


class Evaluator:
    """One per service. Not safe to share across event loops; everything runs on one."""

    def __init__(self, rules: Rules, judge: Judge, correlator: Correlator,
                 config: Config, clock: Callable[[], float]) -> None:
        """`rules` is `rules.evaluate`; `clock` is wall-clock seconds, on the timeline of the
        `now` handed to `contexts` and `collate` (the start of the staleness grace, and a
        collation's duration)."""
        self._rules = rules
        self._judge = judge
        self._correlator = correlator
        self._config = config
        self._clock = clock
        self._started = clock()
        self._good: dict[str, deque[tuple[float, dict[str, Any]]]] = {}
        self._errors: dict[str, tuple[float, str]] = {}
        self._beats: deque[tuple[float, Heartbeat]] = deque(maxlen=HEARTBEATS)
        #: context id -> (state digest, collation it was answered in)
        self._asked: dict[str, tuple[str, int]] = {}
        #: context id -> its latest answers
        self._answers: dict[str, tuple[Attestation, ...]] = {}
        self._issues: dict[str, _Track] = {}
        self._n = 0
        #: Events refused for being dated more than `MAX_SKEW_S` ahead of the clock.
        self.refused_future = 0

    # --- in ---

    def adopt(self, issues: Iterable[Issue]) -> None:
        """Track issues a previous process left unresolved: the store's, once, at startup. Each
        is then re-emitted while its condition holds and resolved after `RESOLVE_AFTER`
        collations without it. A resolved issue, or one already tracked, is skipped."""
        for issue in issues:
            if issue.state is IssueState.RESOLVED or issue.id in self._issues:
                continue
            self._issues[issue.id] = _Track(dataclasses.replace(issue, state=IssueState.OPEN),
                                            _adopted(issue), issue.opened_at)

    def observe(self, event: Event) -> None:
        """Take one observation or heartbeat event. Anything else is refused. One dated more
        than `MAX_SKEW_S` ahead of the clock is counted in `refused_future` and skipped."""
        if event.kind is Kind.HEARTBEAT:
            beat = from_body(Heartbeat, event.body)
            if self._future(event):
                return
            if not self._beats or event.at > self._beats[-1][0]:
                self._beats.append((event.at, beat))
            return
        if event.kind is not Kind.OBSERVATION:
            raise EvaluatorError(f"the evaluator takes observations and heartbeats, not "
                                 f"{event.kind.value}")
        observation = from_body(Observation, event.body)
        if event.subject != f"obs.{observation.probe}":
            raise EvaluatorError(f"subject {event.subject!r} does not match probe "
                                 f"{observation.probe!r}")
        place(observation.probe)
        if self._future(event):
            return
        probe = observation.probe
        if observation.error:
            if probe not in self._errors or event.at > self._errors[probe][0]:
                self._errors[probe] = (event.at, observation.error)
            return
        held = self._good.setdefault(probe, deque(maxlen=HISTORY))
        if not held or event.at > held[-1][0]:
            held.append((event.at, observation.data))

    def _future(self, event: Event) -> bool:
        if event.at > self._clock() + MAX_SKEW_S:
            self.refused_future += 1
            return True
        return False

    # --- the window ---

    def history(self, probe: str) -> tuple[tuple[float, dict[str, Any]], ...]:
        return tuple(self._good.get(probe, ()))

    def failing(self) -> dict[str, tuple[float, str]]:
        """Probes whose newest report is an error: probe -> (at, error)."""
        return {p: e for p, e in self._errors.items()
                if p not in self._good or e[0] > self._good[p][-1][0]}

    def snapshot(self, now: float) -> Snapshot:
        held = {p: h[-1] for p, h in self._good.items()}
        # A device the latest listing no longer has is gone: rules, contexts and staleness
        # stop seeing it, so its issues resolve like any other.
        latest = {p: at_data for p, at_data in held.items() if _listed(held, p)}
        previous = {p: h[-2] for p, h in self._good.items() if len(h) >= 2 and p in latest}
        known = {spec.id for spec in CATALOG if not spec.devices}
        known |= {p for p in (*self._good, *self._errors)
                  if template(p) is not None and _listed(latest, p)}
        cadence = {}
        for probe in sorted(known):
            seconds = float(getattr(self._config.cadence, place(probe)[1]))
            if probe in latest or now - self._started >= rules.MISSED_CADENCES * seconds:
                cadence[probe] = seconds
        snapshot = Snapshot(now=now, latest=latest, previous=previous,
                            heartbeats=tuple(self._beats), cadence=cadence)
        joined, before = _views(snapshot)
        return dataclasses.replace(
            snapshot, jobs=tuple(jobs.scheduled(joined)[0]),
            services=tuple(jobs.services(joined)),
            previous_services=tuple(jobs.services(before)) if before is not None else ())

    # --- contexts ---

    def _state(self, snapshot: Snapshot, probe: str) -> Any:
        at, data = snapshot.latest[probe]
        before = snapshot.previous.get(probe)
        spec = template(probe)
        compact = COMPACT.get(spec.id if spec is not None else probe, _as_is)
        return compact(data, before[1] if before else None,
                       at - before[0] if before else None)

    def _build(self, snapshot: Snapshot) -> list[Context]:
        failing = self.failing()
        joined, before = _views(snapshot)
        found, skipped = jobs.scheduled(joined)
        was = jobs.scheduled(before)[0] if before is not None else None
        reported = {place(p)[0] for p in joined}
        out = []
        for kind in DOMAINS:
            domain = kind.value
            state = {p: self._state(snapshot, p) for p in sorted(snapshot.latest)
                     if place(p)[0] == domain and p not in jobs.PROBES
                     and p not in KERNEL_PROBES}
            if kind is ContextKind.SECURITY and domain in reported:
                state["jobs"] = _scheduled(found, skipped, was)
            if kind is ContextKind.SERVICES and domain in reported:
                state["services"] = _services(snapshot.services, snapshot.previous_services,
                                              found, was)
            if domain == ContextKind.SECURITY.value and self._beats:
                beat = self._beats[-1][1]
                # Named for whose they are: as plain "writable", the judge read the agent's own
                # mounts as a writable PATH and raised it as a security issue.
                state["agent"] = {"confined": beat.confined,
                                  "mounts_this_agent_can_write": list(beat.writable),
                                  "failed": beat.failed, "deferred": beat.deferred}
            latest = {p: d for p, (_, d) in snapshot.latest.items()}
            if kind is ContextKind.SECURITY and "listeners" in latest:
                state["exposure"] = _exposure(latest["listeners"], latest.get("firewall"),
                                              latest.get("containers"))
            if kind is ContextKind.KERNEL and all(p in latest for p in KERNEL_PROBES):
                state["kernels"] = _kernels(*(latest[p] for p in KERNEL_PROBES))
            if not state:
                continue
            if down := {p: e for p, (_, e) in sorted(failing.items()) if place(p)[0] == domain}:
                state["unavailable"] = down
            out.append(Context(id=domain, kind=domain, domain=domain, entity=f"domain:{domain}",
                               state=state))
        out += self._entities(snapshot)
        return out

    def _entities(self, s: Snapshot) -> list[Context]:
        def data(probe: str, when: Mapping[str, tuple[float, dict]] = s.latest) -> dict | None:
            entry = when.get(probe)
            return entry[1] if entry is not None else None

        found: list[tuple[ContextKind, str, str, dict[str, Any]]] = []
        found += self._processes(s)
        journals = [e for p in ("journal.errors", "journal.warnings") for e in
                    _rows(data(p), "entries")]
        # The failed list says only that a unit failed; its service record says how it runs
        # and how often it restarted, which crash_loop and suspicious_exec read.
        services = {svc.get("name"): svc for svc in s.services}
        for u in _rows(data("units.failed"), "units"):
            if isinstance(name := u.get("unit"), str) and name:
                lines = [_line(e) for e in journals if _source(e) == name][-LINES:]
                unit: dict[str, Any] = {"unit": u, "journal": lines}
                if (svc := services.get(name)) is not None:
                    unit["service"] = {**svc, "exec": [str(c)[:ARGS_CHARS]
                                                       for c in svc.get("exec") or []]}
                found.append((ContextKind.UNIT, "services", f"unit:{name}", unit))
        before = {c.get("name"): c for c in _rows(data("containers", s.previous), "containers")}
        for c in _rows(data("containers"), "containers"):
            name = c.get("name")
            if isinstance(name, str) and name and (c.get("state") == "restarting"
                                                  or _health(c) == "unhealthy"):
                old = before.get(name)
                state: dict[str, Any] = {"container": _container(c)}
                if old is not None:
                    state["previous"] = _pick(_container(old),
                                              ("state", "health", "exit_code", "status"))
                found.append((ContextKind.CONTAINER, "containers", f"container:{name}", state))
        firewall = [{k: ch.get(k) for k in ("family", "table", "hook", "policy")}
                    for ch in _rows(data("firewall"), "base_chains") if ch.get("hook") == "input"]
        latest, previous = data("listeners"), data("listeners", s.previous)
        for (proto, port), socks in _new_listeners(latest or {}, previous).items():
            found.append((ContextKind.LISTENER, "network", f"listener:{proto}/{port}",
                          {"proto": proto, "port": port, "firewall_input": firewall,
                           "sockets": [{k: x.get(k) for k in ("address", "interface", "state",
                                                               "process", "pid")}
                                       for x in socks]}))
        filesystems = _rows(data("disk.fill"), "filesystems")
        for probe in sorted(p for p in s.latest
                            if (spec := template(p)) is not None and spec.id == SMART):
            device = "/dev/" + probe.removeprefix(SMART + ".")
            d, old = s.latest[probe][1], data(probe, s.previous)
            same = old is not None and old.get("serial") == d.get("serial")
            found.append((ContextKind.DISK, "storage", f"disk:{device}", {
                "disk": _smart(d, None, None),
                "increase": _increase(d, old if same else None,
                                      (*rules.MEDIA_COUNTERS, "error_log_entries",
                                       "unsafe_shutdowns")),
                "filesystems": [f for f in _disk_fill({"filesystems": filesystems}, None, None)
                                if re.fullmatch(re.escape(device) + r"p?\d*",
                                                str(f.get("source", "")))]}))
        was = {g.get("index"): g for g in _rows(data("gpu", s.previous), "gpus")}
        for g in _rows(data("gpu"), "gpus"):
            if isinstance(index := g.get("index"), int) and not isinstance(index, bool):
                found.append((ContextKind.GPU_DEVICE, "gpu", f"gpu:{index}",
                              {"gpu": _gpu(g, was.get(index))}))
        found += self._bursts(data("journal.errors"), data("journal.warnings"))
        # A name run-parts will not run is listed on the Scheduled page but is not a job to judge:
        # /etc/cron.hourly/.placeholder, the cron package's keep-the-directory file, was asked
        # about as root-writable-exec (2026-10-27).
        found += [(ContextKind.JOB, JOB_DOMAIN, f"job:{job['id']}", dict(job["static"]))
                  for job in s.jobs if not job.get("skipped_by_run_parts")]
        return [Context(id=f"{kind.value}-{_digest(entity)}", kind=kind.value, domain=domain,
                        entity=entity, state=state) for kind, domain, entity, state in found]

    def _processes(self, s: Snapshot) -> list[tuple[ContextKind, str, str, dict[str, Any]]]:
        entry, before = s.latest.get("processes"), s.previous.get("processes")
        if entry is None:
            return []
        at, d = entry
        dt = at - before[0] if before else None
        rows = {r.get("pid"): r for key in ("top_cpu", "top_rss", "from_tmp")
                for r in _rows(d, key)}
        tmp = {r.get("pid") for r in _rows(d, "from_tmp")}
        tested = {pid: r.get("args") for r in _rows(d, "tmp_test_runs")
                  for pid in (r.get("pids") if isinstance(r.get("pids"), list) else [])}
        memory = s.latest.get("memory", (0.0, {}))[1]
        total = _num(memory, "mem_total_kb")
        machine = {"cpus": s.latest.get("cpu.stat", (0.0, {}))[1].get("cpus"),
                   "load1": s.latest.get("load", (0.0, {}))[1].get("load1"),
                   "load5": s.latest.get("load", (0.0, {}))[1].get("load5"),
                   "mem_total_kb": total, "mem_available_kb": memory.get("mem_available_kb"),
                   "psi_cpu_some_avg60": s.latest.get("psi.cpu", (0.0, {}))[1].get("some_avg60"),
                   "psi_memory_some_avg60":
                       s.latest.get("psi.memory", (0.0, {}))[1].get("some_avg60")}
        machine = {k: v for k, v in machine.items() if v is not None}
        hot = []
        for pid, compact in zip(rows, _recent(list(rows.values()),
                                              before[1] if before else None, dt), strict=True):
            cpu = compact.get("recent_cpu_pct", compact.get("cpu_pct"))
            rss = compact.get("rss_kb")
            aged = "recent_cpu_pct" in compact or (
                compact.get("elapsed_s") or 0) >= PROCESS_MIN_AGE_S
            why = [reason for reason, hit in (
                ("cpu", aged and isinstance(cpu, int | float) and cpu >= PROCESS_CPU_PCT),
                ("rss", total is not None and isinstance(rss, int)
                 and rss >= PROCESS_RSS_SHARE * total),
                ("from_tmp", pid in tmp)) if hit]
            if why and isinstance(pid, int):
                hot.append((pid not in tmp, -(cpu or 0), -(rss or 0), pid, compact, why))
        hot.sort(key=lambda h: h[:4])
        return [(ContextKind.PROCESS, "processes", f"process:{pid}",
                 {"process": compact, "why": why, "machine": machine}
                 | ({"test_run": {"runner": tested[pid], "directory": "pytest's own, under "
                                  "/tmp/pytest-of-<user>, writable by that user alone"}}
                    if pid in tested else {}))
                for _, _, _, pid, compact, why in hot[:MAX_PROCESSES]]

    def _bursts(self, errors: dict | None, warnings: dict | None
                ) -> list[tuple[ContextKind, str, str, dict[str, Any]]]:
        def counts(d: dict | None) -> dict[str, int]:
            by = (d or {}).get("by_unit")
            return {k: n for k, n in by.items() if isinstance(n, int)
                    and not isinstance(n, bool)} if isinstance(by, dict) else {}

        err, warn = counts(errors), counts(warnings)
        sources = {k for k, n in err.items() if n >= LOG_BURST_LINES}
        total = (warnings or {}).get("count")
        if (warnings or {}).get("capped") is True and isinstance(total, int) and total and warn:
            top = min(warn, key=lambda k: (-warn[k], k))
            if warn[top] >= rules.FLOOD_SHARE * total:
                sources.add(top)
        lines = [e for d in (errors, warnings) for e in _rows(d, "entries")]
        return [(ContextKind.LOG_BURST, "logs", f"{_entity_kind(src)}:{src}",
                 {"source": src, "errors": err.get(src, 0), "warnings": warn.get(src, 0),
                  "capped": {"errors": (errors or {}).get("capped") is True,
                             "warnings": (warnings or {}).get("capped") is True},
                  "lines": [_line(e) for e in lines if _source(e) == src][-LINES:]})
                for src in sorted(sources)]

    def _select(self, built: Sequence[Context], findings: Sequence[Finding]
                ) -> tuple[list[Context], int]:
        touching: dict[str, int] = {}
        for f in findings:
            for key in (f.entity, f"domain:{domain_of(f.rule)}"):
                touching[key] = max(touching.get(key, -1), f.severity.rank)
        due = []
        for index, context in enumerate(built):
            held = self._asked.get(context.id)
            changed = held is None or held[0] != _digest(dumps(context.state), 64)
            if not changed and self._n - held[1] < REFRESH_EVERY:
                continue
            is_domain = ContextKind(context.kind) in DOMAINS
            if context.entity in touching:
                tier = _TIERS.index("touched")
            elif not changed:
                tier = _TIERS.index("refresh")
            elif is_domain:
                tier = _TIERS.index("changed")
            else:
                tier = _TIERS.index("jobs" if context.kind == ContextKind.JOB.value
                                    else "entity")
            due.append((tier, -touching.get(context.entity, -1), index, context))
        due.sort(key=lambda d: d[:3])
        chosen, spent, on_jobs, skipped = [], 0, 0, 0
        for n, (*_, context) in enumerate(due):
            price = cost(ContextKind(context.kind))
            job = context.kind == ContextKind.JOB.value
            if job and on_jobs + price > JOB_SHARE:
                skipped += 1   # past the job share: due next time, and the rest goes on
                continue
            if spent + price > CONTEXT_BUDGET:
                return chosen, skipped + len(due) - n
            chosen.append(context)
            spent += price
            on_jobs += price if job else 0
        return chosen, skipped

    def contexts(self, now: float) -> tuple[Context, ...]:
        """The contexts the next collation would ask, in priority order, within the budget."""
        snapshot = self.snapshot(now)
        return tuple(self._select(self._build(snapshot),
                                  self._rules(snapshot, self._config))[0])

    def deferred(self, now: float) -> int:
        """How many due contexts the budget would leave for a later collation."""
        snapshot = self.snapshot(now)
        return self._select(self._build(snapshot), self._rules(snapshot, self._config))[1]

    # --- a collation ---

    async def collate(self, now: float) -> Collation:
        start = self._clock()
        snapshot = self.snapshot(now)
        findings = tuple(self._rules(snapshot, self._config))
        built = self._build(snapshot)
        chosen, deferred = self._select(built, findings)
        attestations = tuple(await self._judge.attest(chosen)) if chosen else ()
        self._record(built, chosen, attestations)
        issues = self._lifecycle(now, findings)
        found = candidates(correlation_items(now, findings, issues), CORRELATION_WINDOW_S,
                           CORRELATION_LIMIT)
        links = tuple(await self._correlator.link(found)) if found else ()
        asked = sum(asks(c) for c in chosen) + len(found) * len(bank_for(ContextKind.CORRELATION))
        self._n += 1
        events = (*(self._event(Kind.FINDING, now, f"finding.{f.rule}", f) for f in findings),
                  *(self._event(Kind.ATTESTATION, now, f"attest.{a.context}", a)
                    for a in attestations),
                  *(self._event(Kind.ISSUE, now, f"issue.{i.id}", i) for i in issues),
                  *(self._event(Kind.LINK, now, f"link.{link.id}", link) for link in links))
        return Collation(findings, attestations, issues, links, events, deferred, asked,
                         max(0, round((self._clock() - start) * 1000)))

    @staticmethod
    def _event(kind: Kind, now: float, subject: str, record: Any) -> Event:
        return Event(kind, now, SOURCE, subject, to_body(record))

    def _record(self, built: Sequence[Context], chosen: Sequence[Context],
                attestations: Sequence[Attestation]) -> None:
        answered: dict[str, list[Attestation]] = {}
        for a in attestations:
            answered.setdefault(a.context, []).append(a)
        for context in chosen:
            if context.id in answered:
                self._answers[context.id] = tuple(answered[context.id])
                self._asked[context.id] = (_digest(dumps(context.state), 64), self._n)
        current = {c.id for c in built}
        for store in (self._answers, self._asked):
            for id in [id for id in store if id not in current]:
                del store[id]

    def _lifecycle(self, now: float, findings: Sequence[Finding]) -> tuple[Issue, ...]:
        by_entity: dict[tuple[str, str], list[Attestation]] = {}
        kinds: dict[tuple[str, str], str] = {}
        for answers in self._answers.values():
            for a in answers:
                by_entity.setdefault((a.domain, a.entity), []).append(a)
                kinds[(a.domain, a.entity)] = a.context_kind
        deterministic: dict[tuple[str, str, str], list[Finding]] = {}
        for f in findings:
            deterministic.setdefault((domain_of(f.rule), f.entity, f.rule), []).append(f)
        present = [_present(d, e, rule, fs, by_entity.get((d, e), ()))
                   for (d, e, rule), fs in deterministic.items()]
        covered = {(d, e) for d, e, _ in deterministic}
        present += [_present(d, e, kinds[(d, e)], (), atts)
                    for (d, e), atts in by_entity.items()
                    if (d, e) not in covered and _opens(atts)]
        out = []
        seen = set()
        for p in present:
            id = issue_id(p.domain, p.entity, p.family)
            seen.add(id)
            track = self._issues.get(id)
            opened = now if track is None else track.issue.opened_at
            escalated = now if track is None or p.severity.rank > track.issue.severity.rank \
                else track.escalated_at
            issue = Issue(id=id, state=IssueState.OPEN, severity=p.severity, title=p.title,
                          domain=p.domain, entity=p.entity, opened_at=opened, updated_at=now,
                          deterministic=p.deterministic, reasons=p.reasons,
                          next_step=p.next_step, score=_score(p, now, opened, escalated),
                          evidence=p.evidence, why=p.why, last_seen=now)
            self._issues[id] = _Track(issue, p, escalated)
            out.append(issue)
        for id, track in list(self._issues.items()):
            if id in seen:
                continue
            track.absent += 1
            state = IssueState.RESOLVED if track.absent >= RESOLVE_AFTER else IssueState.OPEN
            track.issue = dataclasses.replace(
                track.issue, state=state, updated_at=now,
                score=_score(track.seen, now, track.issue.opened_at, track.escalated_at))
            out.append(track.issue)
            if state is IssueState.RESOLVED:
                del self._issues[id]   # said once; a recurrence opens afresh under the same id
        return rank(out)
