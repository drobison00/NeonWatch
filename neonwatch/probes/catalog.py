"""The closed probe catalog: every read the root agent may make, as data.

Nothing here executes anything. `executor` runs these specs and refuses anything that is not one;
`tools/gates.py` imports `CATALOG` and refuses any argv that is not an allowlisted read-only
invocation. Adding a probe is a code change to this file, and it goes through that gate.

Every command names its binary by absolute path: the executor passes no environment, so there
is no PATH to resolve a bare name against, and a root agent should not resolve one anyway.

A spec is one of five kinds, and each kind uses exactly one of `argv` or `path`:

- COMMAND: exec `argv` as given. No shell, no environment, no runtime parameter except the one
  device name a template's `devices` regex has admitted (see `expand`).
- FILE: read the one file at `path`.
- GLOB: read every file matching the one glob `path`; matching nothing is a valid answer.
- LISTDIR: list the names in the one directory at `path`.
- DOCKER: HTTP GET `path` on the Docker Engine API socket.
"""

from __future__ import annotations

import dataclasses
import enum
import re
from collections.abc import Iterable
from dataclasses import dataclass


class Tier(enum.Enum):
    """How often a probe runs; the seconds per tier are `config.Cadence`."""

    FAST = "fast"
    MEDIUM = "medium"
    SLOW = "slow"
    DAILY = "daily"


class Kind(enum.Enum):
    COMMAND = "command"
    FILE = "file"
    GLOB = "glob"
    LISTDIR = "listdir"
    DOCKER = "docker"


class Cost(enum.Enum):
    """A budget class for the collector's deferral, not a measurement."""

    CHEAP = "cheap"
    MODERATE = "moderate"
    HEAVY = "heavy"


DOMAINS = frozenset({"hardware", "cpu", "memory", "storage", "gpu", "network", "firewall",
                     "processes", "services", "containers", "logs", "security", "kernel"})

#: The one placeholder a command template may carry.
DEVICE = "{device}"

#: `journalctl -n`: the most entries one journal probe returns. The parser reports reaching it.
JOURNAL_LINES = 500
#: `journalctl -n` for the err-and-worse probe: its own cap, so a warning flood cannot hide errors.
JOURNAL_ERROR_LINES = 200

#: The uid and gid an `unprivileged` command runs as: nobody/nogroup, which own nothing.
NOBODY = 65534

_ID = re.compile(r"[a-z][a-z0-9_]*(\.[a-z0-9_]+)*")
_WILDCARD = re.compile(r"[*?\[]")


@dataclass(frozen=True, slots=True)
class ProbeSpec:
    id: str
    tier: Tier
    kind: Kind
    #: The exact argv, COMMAND only; `()` otherwise.
    argv: tuple[str, ...]
    #: The file, glob, directory or Docker API path; `""` for COMMAND.
    path: str
    cost: Cost
    domain: str
    description: str
    #: A regex over block device names. Non-empty only on a template whose argv carries
    #: `{device}`; `expand` makes one concrete spec per admitted name.
    devices: str = ""
    #: COMMAND only: run as `NOBODY` with no supplementary groups instead of as root, for a
    #: read that needs no privilege and that, run as root, changes the host anyway.
    unprivileged: bool = False

    def __post_init__(self) -> None:
        problem = _problem(self)
        if problem:
            raise ValueError(f"probe {self.id!r}: {problem}")


def _problem(spec: ProbeSpec) -> str:
    if not isinstance(spec.id, str) or not _ID.fullmatch(spec.id):
        return "id must be lower-case dotted words"
    for name, value, enum_type in (("tier", spec.tier, Tier), ("kind", spec.kind, Kind),
                                   ("cost", spec.cost, Cost)):
        if not isinstance(value, enum_type):
            return f"{name} must be a {enum_type.__name__}"
    if spec.domain not in DOMAINS:
        return f"domain {spec.domain!r} is not one of {sorted(DOMAINS)}"
    if not isinstance(spec.description, str) or not spec.description.strip():
        return "description must say what the probe reads"
    if not isinstance(spec.argv, tuple):
        return "argv must be a tuple"
    if not isinstance(spec.unprivileged, bool):
        return "unprivileged must be a bool"
    if spec.unprivileged and spec.kind is not Kind.COMMAND:
        return "only a command runs as another user"
    if spec.kind is Kind.COMMAND:
        if not spec.argv:
            return "a command needs an argv"
        if spec.path:
            return "a command takes no path"
        if not isinstance(spec.argv[0], str) or not spec.argv[0].startswith("/"):
            return "a command names its binary by absolute path"
        for word in spec.argv:
            if not isinstance(word, str):
                return "every argv word must be a string"
            if not word:
                return "an argv word may not be empty"
    else:
        if spec.argv:
            return f"a {spec.kind.value} probe takes no argv"
        if not spec.path.startswith("/"):
            return "path must be absolute"
        if "/../" in spec.path + "/" or "/./" in spec.path + "/":
            return "path may not contain .. or . segments"
        if spec.kind in (Kind.FILE, Kind.LISTDIR) and _WILDCARD.search(spec.path):
            return "a wildcard belongs in a glob probe"
    templated = any(DEVICE in word for word in spec.argv)
    if spec.devices:
        try:
            re.compile(spec.devices)
        except re.error as bad:
            return f"devices regex does not compile: {bad}"
        if not templated:
            return f"a devices regex needs an argv carrying {DEVICE}"
    elif templated:
        return f"an argv carrying {DEVICE} needs a devices regex"
    return ""


def expand(spec: ProbeSpec, device_names: Iterable[str]) -> tuple[ProbeSpec, ...]:
    """One concrete spec per device name, id `<template>.<name>`.

    Every name must fully match the template's regex; one that does not refuses the whole call,
    so a caller cannot slip an unvetted string into an argv by mixing it with good ones.
    """
    if not spec.devices or not any(DEVICE in word for word in spec.argv):
        raise ValueError(f"probe {spec.id!r} is not a device template")
    names = tuple(device_names)
    for name in names:
        if not isinstance(name, str) or not re.fullmatch(spec.devices, name):
            raise ValueError(f"device {name!r} does not match {spec.devices!r} for {spec.id!r}")
    return tuple(
        dataclasses.replace(spec, id=f"{spec.id}.{name}", devices="",
                            argv=tuple(word.replace(DEVICE, name) for word in spec.argv))
        for name in names)


def _command(id: str, tier: Tier, cost: Cost, domain: str, description: str,
             *argv: str, devices: str = "", unprivileged: bool = False) -> ProbeSpec:
    return ProbeSpec(id, tier, Kind.COMMAND, argv, "", cost, domain, description, devices,
                     unprivileged)


def _read(id: str, tier: Tier, kind: Kind, path: str, domain: str, description: str,
          cost: Cost = Cost.CHEAP) -> ProbeSpec:
    return ProbeSpec(id, tier, kind, (), path, cost, domain, description)


def _journal(id: str, priority: str, lines: int, description: str) -> ProbeSpec:
    return _command(id, Tier.MEDIUM, Cost.HEAVY, "logs", description,
                    "/usr/bin/journalctl", "-q", "-p", priority, "-o", "json",
                    f"--output-fields={JOURNAL_FIELDS}", "--no-pager", "-n", str(lines),
                    "--since", "-6min")


F, M, S, D = Tier.FAST, Tier.MEDIUM, Tier.SLOW, Tier.DAILY
FILE, GLOB, LISTDIR = Kind.FILE, Kind.GLOB, Kind.LISTDIR

GPU_FIELDS = ("index,name,temperature.gpu,power.draw,power.limit,memory.used,memory.total,"
              "utilization.gpu,clocks_event_reasons.active,pcie.link.width.current,"
              "pcie.link.width.max")

PS_FORMAT = ("pid=,ppid=,user:32=,stat=,pcpu=,rss=,etimes=,nlwp=,times=,pidns=,comm:15=,args=")

JOURNAL_FIELDS = "MESSAGE,PRIORITY,_SYSTEMD_UNIT,SYSLOG_IDENTIFIER,_TRANSPORT"

UNIT_PROPERTIES = ("Id,Description,User,ExecStart,ActiveState,SubState,Result,NRestarts,"
                   "ExecMainStatus,ExecMainStartTimestamp,ExecMainExitTimestamp,UnitFileState,"
                   "FragmentPath,Triggers,TriggeredBy,TimersCalendar,TimersMonotonic,Unit")

CATALOG: tuple[ProbeSpec, ...] = (
    # --- fast -------------------------------------------------------------------------------
    _read("load", F, FILE, "/proc/loadavg", "cpu", "Load averages and runnable threads."),
    _read("uptime", F, FILE, "/proc/uptime", "kernel",
          "Seconds since boot; a drop means the host rebooted."),
    _read("psi.cpu", F, FILE, "/proc/pressure/cpu", "cpu", "CPU pressure stall information."),
    _read("psi.memory", F, FILE, "/proc/pressure/memory", "memory",
          "Memory pressure stall information."),
    _read("psi.io", F, FILE, "/proc/pressure/io", "storage", "IO pressure stall information."),
    _read("memory", F, FILE, "/proc/meminfo", "memory", "Memory and swap use."),
    _read("vmstat", F, FILE, "/proc/vmstat", "memory",
          "OOM kills, major faults and swap traffic counters."),
    _read("cpu.stat", F, FILE, "/proc/stat", "cpu",
          "Aggregate CPU time, context switches, forks, blocked tasks."),
    _command("sensors", F, Cost.CHEAP, "hardware", "hwmon temperatures, fans and voltages.",
             "/usr/bin/sensors", "-j"),
    # Unprivileged: as root, nvidia-smi unlinks and recreates the /dev/char/195:* links on every
    # run. The device nodes are 0666, so as nobody it reads the same and changes nothing.
    _command("gpu", F, Cost.MODERATE, "gpu",
             "Per-GPU temperature, power, memory, utilisation, throttle reasons, PCIe width.",
             "/usr/bin/nvidia-smi", "--query-gpu", GPU_FIELDS, "--format=csv,noheader,nounits",
             unprivileged=True),
    # -l: local filesystems only. A stat of a dead NFS mount blocks in D state, beyond any
    # timeout the executor can enforce.
    _command("disk.fill", F, Cost.CHEAP, "storage", "Space and inode use per local filesystem.",
             "/usr/bin/df", "-l", "-B1", "-x", "squashfs", "-x", "overlay", "-x", "efivarfs",
             "-x", "devtmpfs", "--output=source,fstype,size,used,avail,itotal,iused,target"),
    _read("net.dev", F, FILE, "/proc/net/dev", "network",
          "Per-interface byte, packet, error and drop counters."),
    # --- medium -----------------------------------------------------------------------------
    _command("processes", M, Cost.MODERATE, "processes",
             "Process table: top by CPU and RSS, zombies, D state, binaries run from /tmp.",
             "/usr/bin/ps", "-e", "-o", PS_FORMAT),
    _command("units.failed", M, Cost.CHEAP, "services", "systemd units in the failed state.",
             "/usr/bin/systemctl", "list-units", "--failed", "-o", "json", "--no-pager"),
    # The window overlaps the 5-minute cadence by a minute so nothing falls between runs.
    _journal("journal.warnings", "warning", JOURNAL_LINES,
             "Journal entries at warning or worse from the last six minutes, capped."),
    # The same read at err and worse, capped separately: a unit flooding warnings saturates the
    # probe above and would otherwise hide every real error in the window.
    _journal("journal.errors", "err", JOURNAL_ERROR_LINES,
             "Journal entries at err or worse from the last six minutes, capped."),
    _command("listeners", M, Cost.MODERATE, "network",
             "Listening TCP and bound UDP sockets with their processes.",
             "/usr/bin/ss", "-ltnupH"),
    _read("kernel.tainted", M, FILE, "/proc/sys/kernel/tainted", "kernel",
          "Kernel taint flags: machine checks, oopses, soft lockups, unsigned modules."),
    ProbeSpec("containers", M, Kind.DOCKER, (), "/containers/json?all=1", Cost.MODERATE,
              "containers", "Every container's state, status, health and exit code."),
    _read("edac", M, GLOB, "/sys/devices/system/edac/mc/mc*/[cu]e_count", "hardware",
          "Corrected and uncorrected memory error counts per memory controller."),
    _read("routes", M, FILE, "/proc/net/route", "network",
          "The IPv4 routing table: whether there is a default route, and through what."),
    # PID 1's table, not the agent's own: a sandboxed agent may see a mount namespace of its
    # own. A read of the table never touches a mount, so a dead NFS server cannot hang it.
    _read("mounts", M, FILE, "/proc/1/mounts", "storage",
          "Mounted data filesystems, network shares among them, and which are read-only."),
    # --- slow -------------------------------------------------------------------------------
    _read("block.devices", S, LISTDIR, "/sys/block", "storage",
          "Block device names; the source for expanding the SMART template."),
    _command("smart", S, Cost.HEAVY, "storage", "SMART / NVMe health log of one disk.",
             "/usr/sbin/smartctl", "-j", "-a", f"/dev/{DEVICE}", devices=r"nvme\d+n\d+|sd[a-z]+"),
    _command("firewall", S, Cost.MODERATE, "firewall",
             "The nftables ruleset: a stable hash, counts and base chain policies.",
             "/usr/sbin/nft", "-j", "list", "ruleset"),
    _read("kernel.modules", S, FILE, "/proc/modules", "kernel",
          "Loaded kernel modules and which of them taint the kernel."),
    # A glob, not a file: the file's absence is the ordinary answer, not an error.
    _read("reboot.required", S, GLOB, "/var/run/reboot-required*", "kernel",
          "Whether a reboot is pending, and for which packages."),
    # Scheduled work, read whole: what runs, as whom, when. Absence is an answer for each glob.
    _read("cron.system", S, FILE, "/etc/crontab", "security", "The system crontab."),
    _read("cron.anacron", S, GLOB, "/etc/anacrontab*", "security", "anacron's job table."),
    _read("cron.d", S, GLOB, "/etc/cron.d/*", "security", "System cron job files."),
    # Each scheduled directory is listed as well as read: the glob refuses a symlink and skips a
    # dot name, and either can still be there to run.
    _read("cron.d.names", S, LISTDIR, "/etc/cron.d", "security", "Names in /etc/cron.d."),
    _read("cron.user", S, GLOB, "/var/spool/cron/crontabs/*", "security",
          "Every user's personal crontab."),
    # What the cron reads above rely on: with it 0, a user can hardlink a file they cannot read
    # (/etc/shadow) into a directory root reads, and O_NOFOLLOW does not stop a hardlink.
    _read("fs.protected_hardlinks", S, FILE, "/proc/sys/fs/protected_hardlinks", "security",
          "Whether the kernel refuses a hardlink to a file the linking user does not own."),
    # The installed kernels are the vmlinuz-<release> names; the running one is beside it.
    _read("boot", S, LISTDIR, "/boot", "kernel", "Names in /boot: the installed kernels."),
    _read("kernel.release", S, FILE, "/proc/sys/kernel/osrelease", "kernel",
          "The running kernel's release."),
    # Unprivileged: a simulation reads the package lists as last fetched and needs no lock;
    # as nobody it cannot write the package cache, which as root it may rebuild.
    _command("apt.upgrades", S, Cost.HEAVY, "security",
             "What an upgrade would install, security updates counted apart.",
             "/usr/bin/apt-get", "-s", "dist-upgrade", unprivileged=True),
    _command("units.timers", S, Cost.CHEAP, "services",
             "Every loaded systemd timer, with its last and next trigger.",
             "/usr/bin/systemctl", "list-timers", "--all", "-o", "json", "--no-pager"),
    # Patterns, not unit names: a pattern matches loaded units only, so PID 1 loads nothing to
    # answer. systemctl expands them itself; there is no shell. --all: without it a pattern
    # matches active units only, which leaves out most services a timer starts.
    _command("units.detail", S, Cost.MODERATE, "services",
             "Each loaded service's and timer's command, user, state, result and schedule.",
             "/usr/bin/systemctl", "show", "--all", "-p", UNIT_PROPERTIES, "--timestamp=unix",
             "--no-pager", "*.service", "*.timer"),
    # --- daily ------------------------------------------------------------------------------
    _read("ssh.keys.home", D, GLOB, "/home/*/.ssh/authorized_keys*", "security",
          "SSH keys authorised for each home directory."),
    _read("ssh.keys.root", D, GLOB, "/root/.ssh/authorized_keys*", "security",
          "SSH keys authorised for root."),
    _read("cron.hourly", D, GLOB, "/etc/cron.hourly/*", "security", "Scripts run hourly."),
    _read("cron.daily", D, GLOB, "/etc/cron.daily/*", "security", "Scripts run daily."),
    _read("cron.weekly", D, GLOB, "/etc/cron.weekly/*", "security", "Scripts run weekly."),
    _read("cron.monthly", D, GLOB, "/etc/cron.monthly/*", "security", "Scripts run monthly."),
    *(_read(f"cron.{period}.names", D, LISTDIR, f"/etc/cron.{period}", "security",
            f"Names in /etc/cron.{period}.")
      for period in ("hourly", "daily", "weekly", "monthly")),
    _command("units.files", D, Cost.MODERATE, "services",
             "Every installed systemd unit file and its enablement state.",
             "/usr/bin/systemctl", "list-unit-files", "-o", "json", "--no-pager"),
)
