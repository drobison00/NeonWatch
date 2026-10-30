"""Deterministic hard alarms over a snapshot. Nothing a model says can clear one of these.

Each rule is a small pure function `(snapshot, config) -> Iterable[Alarm]`, registered in `RULES`
under its stable rule id. `evaluate` runs the table and stamps each alarm with that id, so adding
a rule is one function and one table entry; the dispatcher never changes.

Rules read the fields in `docs/probes.md` and nothing else, plus the scheduled-job and service
records `neonwatch.jobs` joins from the cron and systemd probes (the shapes in docs/design.md,
"Scheduled work and services"). The evaluator joins them once and hands them over on the snapshot
(`jobs`, `services`, and `previous_services` from the previous observation), so this module does
not import `jobs` and the dashboard and the rules read one join. They are conservative: a field
that is missing, `null`, or the wrong type is not evidence, so it raises nothing, except in the two
rules that are about absence (`agent.stopped`, `probe.stale`), where unknown is never healthy.
Counters are cumulative, so an "increase" needs `previous`; a first observation is a baseline.

A job's command is text any user can write (their own crontab), so `job.runs_from_tmp` reads only
where the command runs a program, never what it says about itself, and every value a step quotes
is shell-quoted.

Two plan items have no rule of their own, by decision. Journald gaps are covered by
`probe.stale` on `journal.warnings`. MCE has no probe field (no mcelog or rasdaemon source), so a
machine check shows up only as the taint flag `M`, caught by `kernel.taint_changed`.
"""

from __future__ import annotations

import re
import shlex
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from typing import Any, NamedTuple

from neonwatch.config import Config
from neonwatch.schema import Finding, Heartbeat, Severity


@dataclass(frozen=True, slots=True)
class Snapshot:
    now: float
    #: probe id -> (observed at, data), the newest observation of each probe.
    latest: Mapping[str, tuple[float, dict]]
    #: probe id -> (observed at, data), the observation before `latest`, for deltas.
    previous: Mapping[str, tuple[float, dict]]
    #: Recent heartbeats, oldest first.
    heartbeats: tuple[tuple[float, Heartbeat], ...]
    #: probe id -> expected seconds between observations.
    cadence: Mapping[str, float]
    #: Scheduled jobs, as `jobs.scheduled` joins them from `latest`.
    jobs: tuple[Mapping[str, Any], ...] = ()
    #: Loaded services, as `jobs.services` joins them from `latest`.
    services: tuple[Mapping[str, Any], ...] = ()
    #: The same from the previous observation, for deltas; empty when there is none.
    previous_services: tuple[Mapping[str, Any], ...] = ()


class Alarm(NamedTuple):
    """What a rule raises; `evaluate` adds the rule id to make it a `Finding`."""

    severity: Severity
    title: str
    entity: str
    evidence: dict[str, Any]
    #: A read-only command a person can run to look closer, with real values quoted in.
    #: Required, so a rule cannot forget it. Shown to the operator, never executed.
    next_step: str
    #: Why it matters, in a sentence or two for the person reading the issue. Optional.
    why: str = ""


Rule = Callable[[Snapshot, Config], Iterable[Alarm]]

WARN, CRITICAL, WATCH, INFO = Severity.WARN, Severity.CRITICAL, Severity.WATCH, Severity.INFO

CPU_LIMIT_C = 95
GPU_LIMIT_C = 90
#: A drive's reported `crit` outside this range is an lm-sensors sentinel, not a threshold.
PLAUSIBLE_CRIT_C = (0.0, 200.0)
DISK_WARN_PCT, DISK_CRITICAL_PCT = 90, 97
WEAR_LIMIT_PCT = 90
PSI_FULL_LIMIT = 10
FLOOD_SHARE = 0.8
#: Linux's default ephemeral floor. Unconnected UDP client sockets sit on wildcard ports above it.
EPHEMERAL_FLOOR = 32768
CHURN_LIMIT_PER_HOUR = 60
#: Names carried in churn evidence; the counts are always complete.
CHURN_NAMES = 20
#: Missing this many cadences in a row is "stopped", not "late".
MISSED_CADENCES = 3
GPU_BRAKES = frozenset({"sw_thermal_slowdown", "hw_thermal_slowdown", "hw_power_brake_slowdown"})
#: SMART counters that mean data was lost or media is failing. Not `udma_crc_errors` (cabling)
#: and not `error_log_entries` (usually unsupported-command noise).
MEDIA_COUNTERS = ("media_errors", "reallocated_sectors", "pending_sectors",
                  "offline_uncorrectable", "reported_uncorrect")
#: Automatic restarts between two observations of a service that make a restart loop.
RESTART_LOOP = 3
#: Docker's status for a container started under a minute ago: `Up Less than a second`,
#: `Up 1 second`, `Up 12 seconds`, maybe followed by ` (healthy)`. Past a minute it says minutes.
_JUST_UP = re.compile(r"Up (?:Less than a second|(\d+) seconds?)(?: |$)")
#: Directories anyone can write: a program run from one can be swapped by any user.
TMP_DIRS = ("/tmp/", "/var/tmp/", "/dev/shm/")
#: Characters of a job's command carried in evidence.
COMMAND_CHARS = 200
#: Processes running from a world-writable directory that raise a finding each, per snapshot.
PROCESS_FINDINGS = 10
#: Characters of a program's path in a title.
TITLE_PATH_CHARS = 80
#: `job.*` findings per defining file and rule; one summary finding stands for the rest, so one
#: crontab (any user writes their own) cannot flood the issue table.
JOB_FINDINGS_PER_FILE = 5
UNIT_SUFFIXES = (".service", ".socket", ".target", ".device", ".mount", ".automount", ".swap",
                 ".timer", ".path", ".slice", ".scope")

#: Shell-quotes a value put into a next step. Unit, container and log-source names can be set by
#: any local user (`logger -t`), so a pasted step must stay the one read-only command it reads as.
q = shlex.quote


def evaluate(snapshot: Snapshot, config: Config) -> tuple[Finding, ...]:
    """Every alarm every registered rule raises, in table order."""
    findings: list[Finding] = []
    for rule_id, rule in RULES.items():
        try:
            alarms = tuple(rule(snapshot, config))
        except Exception as bad:  # one broken rule must not silence the others
            findings.append(Finding("rules.error", WATCH,
                                    f"Rule {rule_id} could not run, so its alarms are unknown",
                                    f"rule:{rule_id}", {"error": repr(bad)},
                                    f"Report the error in rule {rule_id}; until it is fixed, "
                                    "check what it covers by hand"))
            continue
        findings.extend(Finding(rule_id, a.severity, a.title, a.entity, dict(a.evidence),
                                a.next_step, a.why) for a in alarms)
    return tuple(findings)


# --- reading observations defensively -------------------------------------------------------


def _obs(observations: Mapping[str, tuple[float, dict]], probe: str) -> dict:
    entry = observations.get(probe)
    return entry[1] if entry is not None and isinstance(entry[1], dict) else {}


def _num(data: dict, key: str) -> float | int | None:
    value = data.get(key)
    return value if isinstance(value, int | float) and not isinstance(value, bool) else None


def _int(data: dict, key: str) -> int | None:
    value = data.get(key)
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _str(data: dict, key: str) -> str:
    value = data.get(key)
    return value if isinstance(value, str) else ""


def _dicts(data: dict, key: str) -> list[dict]:
    value = data.get(key)
    return [item for item in value if isinstance(item, dict)] if isinstance(value, list) else []


def _records(rows: Iterable[Any]) -> list[dict]:
    return [dict(row) for row in rows if isinstance(row, Mapping)]


def _increase(now: int | None, before: int | None) -> int | None:
    return now - before if now is not None and before is not None and now > before else None


def _temps(snapshot: Snapshot) -> Iterable[tuple[str, str, float, dict]]:
    for r in _dicts(_obs(snapshot.latest, "sensors"), "readings"):
        value = _num(r, "input")
        if _str(r, "kind") == "temp" and value is not None and _str(r, "chip"):
            yield _str(r, "chip"), _str(r, "label"), value, r


def _gpus(data: dict) -> dict[int, dict]:
    return {g["index"]: g for g in _dicts(data, "gpus") if _int(g, "index") is not None}


# --- hardware errors ------------------------------------------------------------------------


def _edac_step(mc: str) -> str:
    return (f"grep -H . /sys/devices/system/edac/mc/{q(mc)}/*_count; "
            "journalctl -k -g EDAC -n 50 --no-pager")


def edac_uncorrected(s: Snapshot, c: Config) -> Iterable[Alarm]:
    for mc in _dicts(_obs(s.latest, "edac"), "controllers"):
        name, ue = _str(mc, "mc"), _int(mc, "ue_count")
        if name and ue is not None and ue > 0:
            yield Alarm(CRITICAL, f"Uncorrected memory errors on memory controller {name}",
                        f"edac:{name}", {"ue_count": ue}, _edac_step(name))


def edac_corrected(s: Snapshot, c: Config) -> Iterable[Alarm]:
    before = {_str(mc, "mc"): _int(mc, "ce_count")
              for mc in _dicts(_obs(s.previous, "edac"), "controllers")}
    for mc in _dicts(_obs(s.latest, "edac"), "controllers"):
        name, ce = _str(mc, "mc"), _int(mc, "ce_count")
        if name and (grew := _increase(ce, before.get(name))):
            yield Alarm(WARN, f"Corrected memory errors increasing on {name}; check the DIMMs",
                        f"edac:{name}", {"ce_count": ce, "previous": before[name],
                                         "increase": grew}, _edac_step(name))


# --- SMART, per smart.<device> --------------------------------------------------------------


def _disks(s: Snapshot) -> Iterable[tuple[str, str, str, dict]]:
    for probe in sorted(s.latest):
        if probe.startswith("smart."):
            device = f"/dev/{probe.removeprefix('smart.')}"
            yield probe, device, f"disk:{device}", _obs(s.latest, probe)


def smart_critical_warning(s: Snapshot, c: Config) -> Iterable[Alarm]:
    for _, device, entity, d in _disks(s):
        if (warning := _int(d, "critical_warning")) is not None and warning != 0:
            yield Alarm(CRITICAL, f"{device} reports an NVMe critical warning; back it up",
                        entity, {"critical_warning": warning}, f"sudo smartctl -a {q(device)}")


def smart_health_failed(s: Snapshot, c: Config) -> Iterable[Alarm]:
    for _, device, entity, d in _disks(s):
        if d.get("passed") is False:
            yield Alarm(CRITICAL, f"{device} fails its SMART health self-assessment; back it up",
                        entity, {"passed": False}, f"sudo smartctl -a {q(device)}")


def smart_media_errors(s: Snapshot, c: Config) -> Iterable[Alarm]:
    for probe, device, entity, d in _disks(s):
        before = _obs(s.previous, probe)
        if d.get("serial") and before.get("serial") and d["serial"] != before["serial"]:
            continue  # a different disk in the same slot: its counters are not a delta
        grown = {k: {"previous": before[k], "now": d[k]} for k in MEDIA_COUNTERS
                 if _increase(_int(d, k), _int(before, k))}
        if grown:
            yield Alarm(CRITICAL, f"{device} media errors increased; back it up", entity,
                        {"increased": grown}, f"sudo smartctl -a {q(device)}")


def smart_wear(s: Snapshot, c: Config) -> Iterable[Alarm]:
    for _, device, entity, d in _disks(s):
        if (used := _int(d, "percentage_used")) is not None and used >= WEAR_LIMIT_PCT:
            yield Alarm(WARN, f"{device} has used {used}% of its rated endurance; plan a "
                        "replacement", entity, {"percentage_used": used},
                        f"sudo smartctl -a {q(device)}")


# --- thermal --------------------------------------------------------------------------------


def cpu_temperature(s: Snapshot, c: Config) -> Iterable[Alarm]:
    for chip, label, value, _ in _temps(s):
        if (label == "Tctl" or label.startswith("Package id")) and value >= CPU_LIMIT_C:
            yield Alarm(WARN, f"CPU at {value:g} °C ({label}); check cooling", f"cpu:{chip}",
                        {"label": label, "temperature_c": value, "limit_c": CPU_LIMIT_C},
                        f"sensors {q(chip)}")


def drive_temperature(s: Snapshot, c: Config) -> Iterable[Alarm]:
    """Against the threshold the drive itself reports through lm-sensors (NVMe CCTEMP)."""
    low, high = PLAUSIBLE_CRIT_C
    for chip, label, value, r in _temps(s):
        crit = _num(r, "crit")
        if (chip.startswith(("nvme-", "drivetemp-")) and crit is not None
                and low < crit < high and value >= crit):
            yield Alarm(WARN, f"Drive {chip} {label} at {value:g} °C, at or over its own "
                        f"critical {crit:g} °C", f"sensor:{chip}/{label}",
                        {"temperature_c": value, "critical_c": crit}, f"sensors {q(chip)}")


def gpu_temperature(s: Snapshot, c: Config) -> Iterable[Alarm]:
    for index, g in _gpus(_obs(s.latest, "gpu")).items():
        if (t := _int(g, "temperature_c")) is not None and t >= GPU_LIMIT_C:
            yield Alarm(WARN, f"GPU {index} at {t} °C; check cooling", f"gpu:{index}",
                        {"temperature_c": t, "limit_c": GPU_LIMIT_C},
                        f"nvidia-smi -q -i {index} -d TEMPERATURE,PERFORMANCE")


def gpu_throttle(s: Snapshot, c: Config) -> Iterable[Alarm]:
    for index, g in _gpus(_obs(s.latest, "gpu")).items():
        throttle = g.get("throttle")
        reasons = [r for r in throttle if r in GPU_BRAKES] if isinstance(throttle, list) else []
        if reasons:
            yield Alarm(WARN, f"GPU {index} is throttling ({', '.join(reasons)})",
                        f"gpu:{index}", {"reasons": reasons},
                        f"nvidia-smi -q -i {index} -d TEMPERATURE,POWER,PERFORMANCE")


def gpu_pcie_degraded(s: Snapshot, c: Config) -> Iterable[Alarm]:
    """Against this GPU's previous width, never its maximum: some slots are narrow by design."""
    before = _gpus(_obs(s.previous, "gpu"))
    for index, g in _gpus(_obs(s.latest, "gpu")).items():
        old = before.get(index)
        if old is None or g.get("name") != old.get("name"):
            continue
        width, was = _int(g, "pcie_width"), _int(old, "pcie_width")
        if width is not None and was is not None and width < was:
            yield Alarm(WARN, f"GPU {index} PCIe link degraded from x{was} to x{width}",
                        f"gpu:{index}", {"pcie_width": width, "previous": was,
                                         "pcie_width_max": g.get("pcie_width_max")},
                        f"nvidia-smi -i {index} --format=csv --query-gpu="
                        "pcie.link.width.current,pcie.link.width.max,pcie.link.gen.current")


# --- storage and memory ---------------------------------------------------------------------


def disk_fill(s: Snapshot, c: Config) -> Iterable[Alarm]:
    for fs in _dicts(_obs(s.latest, "disk.fill"), "filesystems"):
        mount, used = fs.get("mount"), _num(fs, "used_pct")
        if not isinstance(mount, str) or used is None or used < DISK_WARN_PCT:
            continue
        severity = CRITICAL if used >= DISK_CRITICAL_PCT else WARN
        yield Alarm(severity, f"Filesystem {mount} is {used:g}% full", f"mount:{mount}",
                    {"used_pct": used, "source": fs.get("source"), "fstype": fs.get("fstype"),
                     "warn_pct": DISK_WARN_PCT, "critical_pct": DISK_CRITICAL_PCT},
                    f"df -h {q(mount)}; sudo du -xh -d 1 {q(mount)} | sort -h | tail -20")


def memory_oom_kill(s: Snapshot, c: Config) -> Iterable[Alarm]:
    now = _int(_obs(s.latest, "vmstat"), "oom_kill")
    was = _int(_obs(s.previous, "vmstat"), "oom_kill")
    if killed := _increase(now, was):
        yield Alarm(WARN, f"The OOM killer killed {killed} process(es)", "memory:oom",
                    {"oom_kill": now, "previous": was, "killed": killed},
                    "journalctl -k -g 'Out of memory' -n 20 --no-pager; "
                    "cat /proc/pressure/memory")


def memory_pressure(s: Snapshot, c: Config) -> Iterable[Alarm]:
    full = _num(_obs(s.latest, "psi.memory"), "full_avg60")
    if full is not None and full >= PSI_FULL_LIMIT:
        yield Alarm(WARN, f"All tasks stalled on memory {full:g}% of the last minute",
                    "memory:pressure", {"full_avg60": full, "limit": PSI_FULL_LIMIT},
                    "cat /proc/pressure/memory; free -h")


# --- services, containers, logs -------------------------------------------------------------


def _up_for(ct: dict) -> int | None:
    """Seconds a running container has been up, if Docker says it started under a minute ago."""
    match = _JUST_UP.match(_str(ct, "status")) if ct.get("state") == "running" else None
    return None if match is None else int(match[1] or 0)


def container_crash_loop(s: Snapshot, c: Config) -> Iterable[Alarm]:
    """`restarting` when sampled, or freshly started in two observations running.

    A container that dies within a second is mostly sampled between restarts, as `running` and
    `Up 1 second`. Seen just started in both the previous observation and this one, and up for
    less than the time between them, it has started at least twice in that span: a loop. The
    same id is required, so a container recreated under the same name (compose) is not one.
    """
    latest, previous = s.latest.get("containers"), s.previous.get("containers")
    interval = latest[0] - previous[0] if latest and previous else 0
    before = {ct_id: ct for ct in _dicts(_obs(s.previous, "containers"), "containers")
              if (ct_id := _str(ct, "id"))}
    for ct in _dicts(_obs(s.latest, "containers"), "containers"):
        name, was = _str(ct, "name"), before.get(_str(ct, "id"), {})
        step = f"docker logs --tail 100 {q(name)}; docker inspect {q(name)}"
        if name and ct.get("state") == "restarting":
            yield Alarm(WARN, f"Container {name} is in a crash loop", f"container:{name}",
                        {"state": "restarting", "status": ct.get("status"),
                         "exit_code": ct.get("exit_code"), "image": ct.get("image")}, step)
            continue
        up = _up_for(ct)
        if (not name or up is None or up >= interval
                or not (was.get("state") == "restarting" or _up_for(was) is not None)):
            continue
        yield Alarm(WARN, f"Container {name} is in a crash loop", f"container:{name}",
                    {"state": "running", "status": ct.get("status"),
                     "previous_status": was.get("status"), "interval_s": round(interval),
                     "exit_code": ct.get("exit_code"), "image": ct.get("image")}, step)


def unit_failed(s: Snapshot, c: Config) -> Iterable[Alarm]:
    for u in _dicts(_obs(s.latest, "units.failed"), "units"):
        if name := _str(u, "unit"):
            yield Alarm(WARN, f"Unit {name} has failed", f"unit:{name}",
                        {k: u.get(k) for k in ("load", "active", "sub", "description")},
                        f"systemctl status {q(name)} --no-pager; "
                        f"journalctl -u {q(name)} -n 100 --no-pager")


def _unit_step(unit: str) -> str:
    return (f"systemctl status {q(unit)} --no-pager; "
            f"journalctl -u {q(unit)} -n 100 --no-pager")


def unit_restart_loop(s: Snapshot, c: Config) -> Iterable[Alarm]:
    """`restarts` (NRestarts) up by `RESTART_LOOP` or more since the previous observation. It
    counts automatic restarts and resets when a unit is started by hand, so a drop is no loop."""
    before = {name: _int(svc, "restarts") for svc in _records(s.previous_services)
              if (name := _str(svc, "name"))}
    for svc in _records(s.services):
        name, restarts = _str(svc, "name"), _int(svc, "restarts")
        grew = _increase(restarts, before.get(name)) if name else None
        if grew is not None and grew >= RESTART_LOOP:
            yield Alarm(WARN, f"Service {name} is in a restart loop ({grew} restarts since the "
                        "last look)", f"unit:{name}",
                        {"restarts": restarts, "previous": before[name], "increase": grew,
                         **{k: svc.get(k) for k in ("active", "sub", "result")}},
                        _unit_step(name))


# --- scheduled jobs -------------------------------------------------------------------------


def _per_file(hits: Iterable[tuple[str, Alarm]]) -> Iterable[Alarm]:
    """At most `JOB_FINDINGS_PER_FILE` alarms per defining file (the first by job id), then one
    summary at the most severe of the rest, naming them. Files in the order first seen."""
    by_file: dict[str, list[Alarm]] = {}
    for file, alarm in hits:
        by_file.setdefault(file, []).append(alarm)
    for file, alarms in by_file.items():
        alarms.sort(key=lambda a: a.entity)
        shown, rest = alarms[:JOB_FINDINGS_PER_FILE], alarms[JOB_FINDINGS_PER_FILE:]
        yield from shown
        if rest:
            yield Alarm(max((a.severity for a in rest), key=lambda v: v.rank),
                        f"{len(alarms)} jobs in {file} match; {len(shown)} shown",
                        f"file:{file}", {"file": file, "matched": len(alarms),
                                         "shown": len(shown),
                                         "not_shown": [a.entity for a in rest][:CHURN_NAMES]},
                        f"sudo cat {q(file)}")


def job_timer_failed(s: Snapshot, c: Config) -> Iterable[Alarm]:
    """A timer whose service last ended with a result other than `success`. WATCH: a service
    that stays failed already raises `unit.failed`; this names the schedule behind it."""
    def hits() -> Iterable[tuple[str, Alarm]]:
        for job in _records(s.jobs):
            id, unit, result = _str(job, "id"), _str(job, "unit"), _str(job, "result")
            if id and job.get("source") == "timer" and unit and result and result != "success":
                yield _str(job, "file"), Alarm(
                    WATCH, f"Scheduled {unit} last ended with {result}", f"job:{id}",
                    {"unit": unit, "result": result, "last": job.get("last"),
                     "schedule": job.get("schedule")}, _unit_step(unit))

    return _per_file(hits())


#: Words that run the word after them: a wrapper's own flags and numbers are skipped too.
_WRAPPERS = frozenset({"sudo", "nohup", "nice", "ionice", "exec", "env", "command", "time",
                       "timeout", "setsid", "sh", "bash", "dash", "zsh", "python", "python3",
                       "perl"})
#: Wrappers whose `-c` word is itself a shell command line.
_SHELLS = frozenset({"sh", "bash", "dash", "zsh"})
#: `-c`, alone or among other single-letter flags (`-ec`, `-lc`).
_SCRIPT_FLAG = re.compile(r"-[A-Za-z]*c[A-Za-z]*")
#: How many shells deep a `-c` command line is read: `sh -c "bash -c '...'"` is two.
SCRIPT_DEPTH = 4


def _runs_from_tmp(command: str, depth: int = 0) -> str:
    """The program under a `TMP_DIRS` directory that `command` runs, or "".

    Only the command word of each shell segment counts (after env assignments, wrappers,
    interpreters and their flags), so `find /tmp -delete` and `> /tmp/log` do not. The word a
    shell's `-c` runs is a command line of its own and is read the same way, up to
    `SCRIPT_DEPTH` shells deep, so `bash -c 'cd /; /tmp/x'` counts. Unbalanced quotes fall back
    to whitespace words.
    """
    try:
        lexer = shlex.shlex(command, posix=True, punctuation_chars=True)
        lexer.whitespace_split = True
        tokens = list(lexer)
    except ValueError:
        tokens = command.split()
    head, target, shell, script = True, False, False, False
    for token in tokens:
        if token and set(token) <= set("();<>|&"):
            target = "<" in token or ">" in token   # the next word is a file, not a command
            if not target:
                head, shell, script = True, False, False
            continue
        if target:
            target = False
            continue
        if not head or not token:
            continue
        name = token.rsplit("/", 1)[-1]
        if (re.fullmatch(r"[A-Za-z_]\w*=.*", token) or token.startswith("-")
                or token.isdigit() or name in _WRAPPERS):
            shell = shell or name in _SHELLS
            script = script or (shell and bool(_SCRIPT_FLAG.fullmatch(token)))
            continue
        head = False
        if token.startswith(TMP_DIRS):
            return token.split()[0]
        if script and depth < SCRIPT_DEPTH and (inner := _runs_from_tmp(token, depth + 1)):
            return inner
    return ""


def job_runs_from_tmp(s: Snapshot, c: Config) -> Iterable[Alarm]:
    """WARN; CRITICAL when it runs as root, since any user can replace the program first."""
    def hits() -> Iterable[tuple[str, Alarm]]:
        for job in _records(s.jobs):
            id, command = _str(job, "id"), _str(job, "command")
            if not id or not (path := _runs_from_tmp(command)):
                continue
            user, unit, file = _str(job, "user"), _str(job, "unit"), _str(job, "file")
            where = (f"systemctl cat {q(unit)} --no-pager"
                     if job.get("source") == "timer" and unit else f"sudo cat {q(file)}")
            yield file, Alarm(
                CRITICAL if user == "root" else WARN,
                f"Scheduled job runs {path} from a world-writable directory", f"job:{id}",
                {"path": path, "user": user, "source": job.get("source"),
                 "file": job.get("file"), "schedule": job.get("schedule"),
                 "command": command[:COMMAND_CHARS]},
                f"{where}; sudo ls -la {q(path)}")

    return _per_file(hits())


def process_runs_from_tmp(s: Snapshot, c: Config) -> Iterable[Alarm]:
    """One finding per process whose program is in a world-writable directory (`from_tmp`), with
    the process row as evidence: what ran, as whom, from what parent, for how long. WARN;
    CRITICAL when it runs as root in the host's PID namespace, since any user could have swapped
    the program first. In another namespace (a container, a sandbox) /tmp is its own.

    A snapshot sees only what is running at that instant, and a process seen once may be gone
    by the time anyone looks, so the step reads the journal around the moment it was seen and
    names the parent, which often outlives it."""
    entry = s.latest.get("processes")
    if entry is None or not isinstance(entry[1], dict):
        return
    at, data = entry
    rows = [r for r in _dicts(data, "from_tmp") if _int(r, "pid") is not None]
    for r in rows[:PROCESS_FINDINGS]:
        pid, ppid, args, user = r["pid"], _int(r, "ppid"), _str(r, "args"), _str(r, "user")
        program = args.split(" ", 1)[0]
        where = next((d.rstrip("/") for d in TMP_DIRS if program.startswith(d)), "/tmp")
        namespace = r.get("pid_ns")
        aside = " in a container or sandbox" if namespace == "separate" else ""
        shown = program if len(program) <= TITLE_PATH_CHARS else \
            "…" + program[-(TITLE_PATH_CHARS - 1):]
        pids = f"{pid},{ppid}" if ppid else str(pid)
        yield Alarm(
            CRITICAL if user == "root" and namespace == "host" else WARN,
            f"A program is running from {where}{aside}: {shown}", f"process:{pid}",
            {"program": program, "args": args[:COMMAND_CHARS], "user": user, "pid": pid,
             "ppid": ppid, "pid_ns": namespace, "elapsed_s": r.get("elapsed_s"),
             "cpu_pct": r.get("cpu_pct"), "threads": r.get("threads"),
             "rss_kb": r.get("rss_kb"), "seen_at": at},
            f"ps -o pid,ppid,user,lstart,args -p {pids}; journalctl --since @{int(at) - 60} "
            f"--until @{int(at) + 10} -o short-iso --no-pager | tail -n 40",
            f"Anyone can write to {where}, so a program there can be swapped before it runs, "
            f"and dropped-and-run malware starts this way. Build and test runners (go run, go "
            f"test) and self-extracting installers also run from there, briefly: the parent "
            f"and the journal at that moment usually say which.")


def process_tests_from_tmp(s: Snapshot, c: Config) -> Iterable[Alarm]:
    """One INFO finding per pytest run whose test programs run from pytest's own directory under
    /tmp (`tmp_test_runs`), about the runner. That directory is the user's alone, so nobody else
    could have swapped the program; it is shown rather than dropped, so a test run is visible as
    what is running from /tmp, and these are not asked about one process at a time."""
    entry = s.latest.get("processes")
    if entry is None or not isinstance(entry[1], dict):
        return
    at, data = entry
    for run in _dicts(data, "tmp_test_runs")[:PROCESS_FINDINGS]:
        if (pid := _int(run, "pid")) is None:
            continue
        args, n = _str(run, "args"), _int(run, "processes") or 0
        shown = args if len(args) <= TITLE_PATH_CHARS else args[:TITLE_PATH_CHARS - 1] + "…"
        aside = " in a container or sandbox" if run.get("pid_ns") == "separate" else ""
        yield Alarm(
            INFO, f"A test run{aside} is running {n} program{'s' * (n != 1)} from its own "
            f"/tmp directory: {shown}", f"process:{pid}",
            {"runner": args[:COMMAND_CHARS], "user": _str(run, "user"), "pid": pid,
             "pid_ns": run.get("pid_ns"), "processes": n, "programs": run.get("programs"),
             "seen_at": at},
            f"ps -o pid,ppid,user,lstart,args -p {pid} --ppid {pid}",
            "pytest runs its test programs from /tmp/pytest-of-<user>, which it makes for that "
            "user alone and refuses if anyone else owns it, so no other account could have "
            "swapped them. The runner is named so you can tell whose test run it is.")


def job_crontab_flood(s: Snapshot, c: Config) -> Iterable[Alarm]:
    """A file holding more entries than the parser reads per file (`overflow`, missing is 0):
    the jobs past the cap are not seen, by the dashboard, the rules or the judge."""
    flooded: dict[str, int] = {}
    for job in _records(s.jobs):
        if (over := _int(job, "overflow")) and over > 0:
            file = _str(job, "file")
            flooded[file] = max(over, flooded.get(file, 0))
    for file, over in flooded.items():
        yield Alarm(WARN, f"{file} holds {over} more entries than are read; they are not shown",
                    f"file:{file}", {"file": file, "overflow": over}, f"sudo wc -l {q(file)}")


def journal_flood(s: Snapshot, c: Config) -> Iterable[Alarm]:
    j = _obs(s.latest, "journal.warnings")
    count, by_unit = _int(j, "count"), j.get("by_unit")
    if j.get("capped") is not True or not count or not isinstance(by_unit, dict):
        return
    counts = [(n, k) for k, n in by_unit.items() if isinstance(n, int) and not isinstance(n, bool)]
    if not counts:
        return
    lines, source = min(counts, key=lambda item: (-item[0], item[1]))
    if lines >= FLOOD_SHARE * count:
        kind = "unit" if source.endswith(UNIT_SUFFIXES) else "log"
        yield Alarm(WATCH, f"log flood: {source} wrote {lines} of {count} warnings and filled "
                    "the journal read cap", f"{kind}:{source}",
                    {"lines": lines, "of": count, "share": round(lines / count, 3),
                     "capped": True},
                    f"journalctl {'-u' if kind == 'unit' else '-t'} {q(source)} -p warning "
                    "-n 50 --no-pager")


# --- network and kernel ---------------------------------------------------------------------


def _exposed(sockets: list[dict]) -> dict[tuple[str, int], list[dict]]:
    """Wildcard-bound listeners by (proto, port). UDP only below the ephemeral range."""
    exposed: dict[tuple[str, int], list[dict]] = {}
    for sock in sockets:
        proto, port = _str(sock, "proto"), _int(sock, "port")
        if sock.get("wildcard") is not True or port is None:
            continue
        if (proto == "tcp" and sock.get("state") == "LISTEN") or (
                proto == "udp" and port < EPHEMERAL_FLOOR):
            exposed.setdefault((proto, port), []).append(sock)
    return exposed


def listener_new_wildcard(s: Snapshot, c: Config) -> Iterable[Alarm]:
    before = _obs(s.previous, "listeners").get("listeners")
    if not isinstance(before, list):
        return  # no baseline: every listener would look new
    standing = _exposed([x for x in before if isinstance(x, dict)])
    now = _exposed(_dicts(_obs(s.latest, "listeners"), "listeners"))
    for (proto, port), socks in now.items():
        if (proto, port) in standing:
            continue
        process = next((p for x in socks if (p := _str(x, "process"))), "")
        named = f" ({process})" if process else ""
        yield Alarm(WARN, f"New listener on all interfaces: {proto}/{port}{named}",
                    f"listener:{proto}/{port}",
                    {"addresses": [_str(x, "address") for x in socks], "process": process},
                    f"sudo ss -ltnup {q(f'sport = :{port}')}")


def _interface_names(entry: tuple[float, dict] | None) -> set[str] | None:
    if entry is None or not isinstance(entry[1], dict):
        return None
    interfaces = entry[1].get("interfaces")
    if not isinstance(interfaces, list):
        return None
    return {n for i in interfaces if isinstance(i, dict) and (n := _str(i, "name"))}


def net_interface_churn(s: Snapshot, c: Config) -> Iterable[Alarm]:
    """Interfaces added plus removed, per hour: veth churn is what a crash-looping container
    leaves behind, and it can precede a hard lock with no kernel trace."""
    latest, previous = s.latest.get("net.dev"), s.previous.get("net.dev")
    now, before = _interface_names(latest), _interface_names(previous)
    if latest is None or previous is None or now is None or before is None:
        return
    interval = latest[0] - previous[0]
    if interval <= 0:
        return
    added, removed = sorted(now - before), sorted(before - now)
    per_hour = (len(added) + len(removed)) * 3600 / interval
    if per_hour >= CHURN_LIMIT_PER_HOUR:
        yield Alarm(WATCH, f"Network interfaces churning at {per_hour:.0f}/hour "
                    f"({len(added)} added, {len(removed)} removed)", "net:interfaces",
                    {"added": added[:CHURN_NAMES], "removed": removed[:CHURN_NAMES],
                     "added_count": len(added), "removed_count": len(removed),
                     "interval_s": interval, "per_hour": round(per_hour, 1),
                     "limit_per_hour": CHURN_LIMIT_PER_HOUR},
                    "ip -o link show type veth; docker ps -a --filter status=restarting")


def kernel_taint_changed(s: Snapshot, c: Config) -> Iterable[Alarm]:
    now, was = _obs(s.latest, "kernel.tainted"), _obs(s.previous, "kernel.tainted")
    value, previous = _int(now, "value"), _int(was, "value")
    if value is not None and previous is not None and value != previous:
        yield Alarm(WATCH, f"Kernel taint changed from {previous} to {value}", "kernel:taint",
                    {"value": value, "flags": now.get("flags"), "previous": previous,
                     "previous_flags": was.get("flags")},
                    "cat /proc/sys/kernel/tainted; journalctl -k -g taint -n 20 --no-pager")


def security_hardlinks_unprotected(s: Snapshot, c: Config) -> Iterable[Alarm]:
    """WARN when `fs.protected_hardlinks` is anything but 1. The agent reads cron files as root
    and refuses symlinks, not hardlinks: without the sysctl a user could link a file they cannot
    read into a directory the agent reads, and its contents would reach the store."""
    value = _int(_obs(s.latest, "fs.protected_hardlinks"), "value")
    if value is not None and value != 1:
        yield Alarm(WARN, f"fs.protected_hardlinks is {value}: users can hardlink files they "
                          f"do not own", "sysctl:fs.protected_hardlinks", {"value": value},
                    "sysctl fs.protected_hardlinks; grep -rs protected_hardlinks /etc/sysctl.conf "
                    "/etc/sysctl.d /usr/lib/sysctl.d")


def kernel_reboot_required(s: Snapshot, c: Config) -> Iterable[Alarm]:
    r = _obs(s.latest, "reboot.required")
    if r.get("required") is True:
        packages = r.get("packages")
        yield Alarm(INFO, "A reboot is required to finish updates", "kernel:reboot",
                    {"packages": packages if isinstance(packages, list) else []},
                    "cat /var/run/reboot-required /var/run/reboot-required.pkgs")


# --- absence: unknown is never healthy ------------------------------------------------------


def _newest(s: Snapshot) -> tuple[float, Heartbeat] | None:
    return max(s.heartbeats, key=lambda beat: beat[0], default=None)


def agent_stopped(s: Snapshot, c: Config) -> Iterable[Alarm]:
    limit = MISSED_CADENCES * c.cadence.fast
    newest = _newest(s)
    age = None if newest is None else s.now - newest[0]
    if age is None or age > limit:
        when = "" if age is None else f" {age:.0f} s ago"
        yield Alarm(CRITICAL, f"agent stopped reporting{when}", "agent:collector",
                    {"last_heartbeat_at": None if newest is None else newest[0],
                     "age_s": age, "limit_s": limit},
                    "Check the terminal running sudo neonwatch agent; "
                    "journalctl -n 50 --no-pager; journalctl -b -1 -n 50 --no-pager")


def agent_unconfined(s: Snapshot, c: Config) -> Iterable[Alarm]:
    newest = _newest(s)
    if newest is not None and newest[1].confined is False:
        yield Alarm(INFO, "agent running unconfined (manual mode)", "agent:collector",
                    {"writable": list(newest[1].writable)},
                    "pgrep -a -f 'neonwatch agent'")


def probe_stale(s: Snapshot, c: Config) -> Iterable[Alarm]:
    for probe, cadence in sorted(s.cadence.items()):
        limit = MISSED_CADENCES * cadence
        entry = s.latest.get(probe)
        age = None if entry is None else s.now - entry[0]
        if age is None or age > limit:
            when = "has never reported" if age is None else f"last reported {age:.0f} s ago"
            yield Alarm(WATCH, f"probe stale: {probe} {when}", f"probe:{probe}",
                        {"last_at": None if entry is None else entry[0], "age_s": age,
                         "limit_s": limit},
                        f"Check probe {probe} in the agent terminal output for its error")


#: rule id -> rule. The only registry: `evaluate` runs exactly these, in this order.
RULES: dict[str, Rule] = {
    "edac.uncorrected": edac_uncorrected,
    "edac.corrected": edac_corrected,
    "smart.critical_warning": smart_critical_warning,
    "smart.health_failed": smart_health_failed,
    "smart.media_errors": smart_media_errors,
    "smart.wear": smart_wear,
    "cpu.temperature": cpu_temperature,
    "drive.temperature": drive_temperature,
    "gpu.temperature": gpu_temperature,
    "gpu.throttle": gpu_throttle,
    "gpu.pcie_degraded": gpu_pcie_degraded,
    "disk.fill": disk_fill,
    "memory.oom_kill": memory_oom_kill,
    "memory.pressure": memory_pressure,
    "container.crash_loop": container_crash_loop,
    "unit.failed": unit_failed,
    "unit.restart_loop": unit_restart_loop,
    "job.timer_failed": job_timer_failed,
    "job.runs_from_tmp": job_runs_from_tmp,
    "job.crontab_flood": job_crontab_flood,
    "process.runs_from_tmp": process_runs_from_tmp,
    "process.tests_from_tmp": process_tests_from_tmp,
    "journal.flood": journal_flood,
    "listener.new_wildcard": listener_new_wildcard,
    "net.interface_churn": net_interface_churn,
    "kernel.taint_changed": kernel_taint_changed,
    "kernel.reboot_required": kernel_reboot_required,
    "security.hardlinks_unprotected": security_hardlinks_unprotected,
    "agent.stopped": agent_stopped,
    "agent.unconfined": agent_unconfined,
    "probe.stale": probe_stale,
}
