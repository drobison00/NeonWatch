"""Pure parsers from a probe's raw bytes to its observation data.

One parser per probe id. Each returns a JSON-ready dict whose field names are a contract: the
rules, the evaluator and the UI read them, and `docs/probes.md` lists every one. A parser that
cannot read its input raises `ParseError`; it never returns part of an answer as if it were whole.

Command lines and log messages are redacted here, inside the root agent, before anything leaves.

GLOB and LISTDIR results reach a parser in one framing, produced by `frame_files` and
`frame_listing`, so the executor and the parsers agree by construction.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import ipaddress
import json
import posixpath
import re
from collections import Counter
from collections.abc import Callable, Iterable, Mapping
from typing import Any

from neonwatch.probes.catalog import CATALOG, JOURNAL_ERROR_LINES, JOURNAL_LINES
from neonwatch.redact import redact
from neonwatch.schema import MAX_BYTES


class ParseError(ValueError):
    """This probe output is not something its parser can read."""


#: Entries kept in each of the process table's top lists.
TOP_N = 20
#: Characters of a redacted command line kept.
ARGS_CHARS = 300
#: Characters of a redacted journal message kept.
MESSAGE_CHARS = 300
#: Journal entries kept, newest last. Counts cover everything read.
JOURNAL_KEPT = 200
#: Processes listed as running from a temporary directory.
FROM_TMP_N = 20
#: Characters kept of a sender-chosen name: journal unit, identifier and transport, ps user,
#: ss process name.
IDENT_CHARS = 128
#: Characters of a field that redaction reads (see `_clean`): journald's 4 KiB field threshold.
REDACT_CHARS = 4096
#: Characters of a redacted cron or unit command kept: the command is what a job is judged by.
COMMAND_CHARS = 1024
#: Characters of a redacted periodic script kept, from its start; `truncated` says there was more.
SCRIPT_CHARS = REDACT_CHARS
#: What one crontab-shaped observation keeps: any user's own valid crontab could
#: otherwise make it too large to publish, blanking every user's. Entries per file and in all,
#: environment names per file, and the JSON bytes of all kept entries and env values: half the
#: event cap, because counts alone allow 500 entries of 1024 twelve-byte escapes. What is not
#: kept is counted (`dropped`, `env_dropped`), never lost silently.
MAX_ENTRIES_PER_FILE = 100
MAX_ENTRIES_TOTAL = 500
MAX_ENV_PER_FILE = 32
KEPT_BYTES = MAX_BYTES // 2
#: Read first, so no user's crontab can spend the caps before root's is read.
ROOT_CRONTAB = "/var/spool/cron/crontabs/root"
TMP_DIRS = ("/tmp/", "/var/tmp/", "/dev/shm/")
#: pytest's own temporary directory. pytest makes /tmp/pytest-of-<user> 0700 and refuses one
#: that another user owns, so only that user could swap a program in it.
PYTEST_TMP = "/tmp/pytest-of-"
#: A command line that runs pytest: `pytest`, `py.test`, a path ending in either, or `-m pytest`.
PYTEST = re.compile(r"(?:^|[/\s])py\.?test(?:\s|$)|\s-m\s+pytest(?:\s|$)")
#: Parents walked from a program in a temporary directory to the first one outside it.
ANCESTRY = 8

Data = dict[str, Any]


# --- framing ----------------------------------------------------------------------------------


def frame_files(files: Mapping[str, bytes]) -> bytes:
    """A GLOB result: a JSON object of matched path -> contents, decoded as UTF-8 (replacing)."""
    return json.dumps({path: files[path].decode("utf-8", "replace") for path in sorted(files)},
                      separators=(",", ":")).encode()


def frame_listing(names: Iterable[str], links: Mapping[str, str] | None = None) -> bytes:
    """A LISTDIR result: a JSON object of the entry names, sorted, and the target of each listed
    name that is a symbolic link (`links`, name -> target as the link spells it)."""
    names = sorted(names)
    listed = set(names)
    return json.dumps({"names": names, "links": {name: target for name, target in
                                                 sorted((links or {}).items())
                                                 if name in listed}},
                      separators=(",", ":")).encode()


def _files(raw: bytes) -> dict[str, str]:
    files = _json(raw)
    if not isinstance(files, dict):
        raise ParseError("a glob result is a JSON object of path -> contents")
    for path, text in files.items():
        if not path.startswith("/") or not isinstance(text, str):
            raise ParseError(f"glob entry {path!r} is not an absolute path with text")
    return files


def _listing(raw: bytes) -> Data:
    """Names, and where each one that is a symbolic link points. The target is the link's own
    text (it was never followed), redacted and cut to `ARGS_CHARS`: it says where cron would run
    a periodic script from, which the read beside the listing refuses to follow."""
    listing = _json(raw)
    if not isinstance(listing, dict) or set(listing) != {"names", "links"}:
        raise ParseError("a listing is a JSON object of names and links")
    names, links = listing["names"], listing["links"]
    if not isinstance(names, list) or not all(isinstance(n, str) and n and "/" not in n
                                              for n in names):
        raise ParseError("a listing's names are a JSON array of entry names")
    if len(set(names)) != len(names):
        raise ParseError("a listing names an entry twice")
    if not isinstance(links, dict) or not all(
            name in names and isinstance(target, str) and target
            for name, target in links.items()):
        raise ParseError("a listing's links map a listed name to a non-empty target")
    return {"entries": sorted(names), "count": len(names),
            "links": {name: _clean(links[name], ARGS_CHARS)[0] for name in sorted(links)}}


# --- helpers ----------------------------------------------------------------------------------


def _text(raw: bytes) -> str:
    return raw.decode("utf-8", "replace")


def _json(raw: bytes) -> Any:
    if not raw.strip():
        raise ParseError("empty output")
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError) as bad:
        raise ParseError(f"not JSON: {bad}") from None


def _lines(raw: bytes) -> list[str]:
    lines = [line for line in _text(raw).splitlines() if line.strip()]
    if not lines:
        raise ParseError("empty output")
    return lines


def _int(value: Any, what: str) -> int:
    if isinstance(value, bool):
        raise ParseError(f"{what}: expected an integer, got {value!r}")
    if isinstance(value, int):
        return value
    if isinstance(value, str) and re.fullmatch(r"-?\d+", value.strip()):
        return int(value)
    raise ParseError(f"{what}: expected an integer, got {value!r}")


def _float(value: Any, what: str) -> float:
    if isinstance(value, bool):
        raise ParseError(f"{what}: expected a number, got {value!r}")
    if isinstance(value, int | float):
        return float(value)
    if isinstance(value, str) and re.fullmatch(r"-?\d+(\.\d+)?", value.strip()):
        return float(value)
    raise ParseError(f"{what}: expected a number, got {value!r}")


def _opt_int(value: Any, what: str) -> int | None:
    return None if value is None else _int(value, what)


def _str(value: Any, what: str) -> str:
    if not isinstance(value, str):
        raise ParseError(f"{what}: expected a string, got {value!r}")
    return value


def _pct(part: float, whole: float) -> float | None:
    return round(100.0 * part / whole, 2) if whole else None


def _clean(text: str, limit: int) -> tuple[str, int]:
    """Redacted, then cut to `limit` for display.

    Redaction reads the whole field up to `REDACT_CHARS`, so a token that starts inside the
    kept part and ends far past it (a private key block) is matched whole before the cut.
    Past that cap nothing is kept, so nothing there needs redacting.
    """
    cleaned, count = redact(text[:REDACT_CHARS])
    return cleaned[:limit], count


#: What one unreadable record inside a list-shaped output raises. Caught per record, so it is
#: skipped and counted instead of failing the probe.
RECORD_ERRORS = (ValueError, KeyError, TypeError, IndexError, AttributeError)


def _records[T, R](items: Iterable[T], read: Callable[[T], R], what: str,
                   *, all_bad_is_error: bool = True) -> tuple[list[R], int]:
    """Each item read, the unreadable ones skipped: `(read items, skipped count)`.

    One hostile record never blanks a probe. Output where no record at all could be read is
    still refused, because then the shape is wrong, not one record. The journal parsers opt
    out of that: a sender can fill a whole window with hostile entries.
    """
    good, skipped = [], 0
    for item in items:
        try:
            good.append(read(item))
        except RECORD_ERRORS:
            skipped += 1
    if skipped and not good and all_bad_is_error:
        raise ParseError(f"no {what} could be read ({skipped} unreadable)")
    return good, skipped


def _array(raw: bytes, what: str) -> list[Any]:
    data = _json(raw)
    if not isinstance(data, list):
        raise ParseError(f"{what} is a JSON array")
    return data


def _object(item: Any, what: str) -> Mapping[str, Any]:
    if not isinstance(item, dict):
        raise ParseError(f"a {what} is a JSON object")
    return item


def _fields(item: Mapping[str, Any], names: Iterable[str], what: str) -> Data:
    missing = [name for name in names if name not in item]
    if missing:
        raise ParseError(f"{what} is missing {missing}")
    return {name: _str(item[name], f"{what}.{name}") for name in names}


# --- fast tier --------------------------------------------------------------------------------


def parse_load(raw: bytes) -> Data:
    words = _text(raw).split()
    if len(words) != 5 or "/" not in words[3]:
        raise ParseError("loadavg is five fields: three loads, runnable/threads, last pid")
    runnable, threads = words[3].split("/", 1)
    return {"load1": _float(words[0], "load1"), "load5": _float(words[1], "load5"),
            "load15": _float(words[2], "load15"), "runnable": _int(runnable, "runnable"),
            "threads": _int(threads, "threads"), "last_pid": _int(words[4], "last_pid")}


def parse_uptime(raw: bytes) -> Data:
    words = _text(raw).split()
    if len(words) != 2:
        raise ParseError("uptime is two fields")
    return {"uptime_s": _float(words[0], "uptime"), "idle_s": _float(words[1], "idle")}


def parse_psi(raw: bytes) -> Data:
    seen: dict[str, dict[str, str]] = {}
    for line in _lines(raw):
        kind, *pairs = line.split()
        if kind not in ("some", "full") or kind in seen:
            raise ParseError(f"unexpected pressure line {line!r}")
        values = dict(pair.split("=", 1) for pair in pairs if "=" in pair)
        if set(values) != {"avg10", "avg60", "avg300", "total"}:
            raise ParseError(f"pressure line {line!r} lacks avg10/avg60/avg300/total")
        seen[kind] = values
    if "some" not in seen:
        raise ParseError("pressure has no `some` line")
    out: Data = {}
    for kind in ("some", "full"):
        values = seen.get(kind)
        for window in ("avg10", "avg60", "avg300"):
            out[f"{kind}_{window}"] = (_float(values[window], window) if values else None)
        out[f"{kind}_total_us"] = _int(values["total"], "total") if values else None
    return out


MEMINFO = {"MemTotal": "mem_total_kb", "MemFree": "mem_free_kb",
           "MemAvailable": "mem_available_kb", "Buffers": "buffers_kb", "Cached": "cached_kb",
           "SwapTotal": "swap_total_kb", "SwapFree": "swap_free_kb",
           "SwapCached": "swap_cached_kb", "Dirty": "dirty_kb", "Writeback": "writeback_kb",
           "AnonPages": "anon_pages_kb", "Shmem": "shmem_kb", "Slab": "slab_kb",
           "CommitLimit": "commit_limit_kb", "Committed_AS": "committed_as_kb"}


def parse_memory(raw: bytes) -> Data:
    values: dict[str, int] = {}
    for line in _lines(raw):
        name, sep, rest = line.partition(":")
        if sep:
            values[name.strip()] = _int(rest.split()[0], name)
    missing = [name for name in MEMINFO if name not in values]
    if missing:
        raise ParseError(f"meminfo is missing {missing}")
    if values["MemTotal"] <= 0:
        raise ParseError("MemTotal is not positive")
    out: Data = {field: values[name] for name, field in MEMINFO.items()}
    out["hardware_corrupted_kb"] = values.get("HardwareCorrupted")
    out["mem_available_pct"] = _pct(values["MemAvailable"], values["MemTotal"])
    swap_used = values["SwapTotal"] - values["SwapFree"]
    out["swap_used_pct"] = _pct(swap_used, values["SwapTotal"]) or 0.0
    return out


VMSTAT = ("oom_kill", "pgfault", "pgmajfault", "pswpin", "pswpout")


def parse_vmstat(raw: bytes) -> Data:
    values = dict(line.split(None, 1) for line in _lines(raw) if " " in line)
    missing = [name for name in VMSTAT if name not in values]
    if missing:
        raise ParseError(f"vmstat is missing {missing}")
    return {name: _int(values[name], name) for name in VMSTAT}


CPU_FIELDS = ("user", "nice", "system", "idle", "iowait", "irq", "softirq", "steal")
STAT_COUNTERS = ("ctxt", "btime", "processes", "procs_running", "procs_blocked")


def parse_cpu_stat(raw: bytes) -> Data:
    out: Data = {}
    cpus = 0
    counters: dict[str, str] = {}
    for line in _lines(raw):
        name, *values = line.split()
        if name == "cpu":
            if len(values) < len(CPU_FIELDS):
                raise ParseError("the cpu line has fewer than eight fields")
            out.update({f: _int(v, f) for f, v in zip(CPU_FIELDS, values, strict=False)})
        elif re.fullmatch(r"cpu\d+", name):
            cpus += 1
        elif name in STAT_COUNTERS and values:
            counters[name] = values[0]
    if "user" not in out:
        raise ParseError("/proc/stat has no aggregate cpu line")
    missing = [name for name in STAT_COUNTERS if name not in counters]
    if missing:
        raise ParseError(f"/proc/stat is missing {missing}")
    out["cpus"] = cpus
    out.update({name: _int(counters[name], name) for name in STAT_COUNTERS})
    return out


def _reading(chip: str, adapter: Any, label: str, sensor: str, values: dict) -> Data:
    def value(suffix: str) -> float | None:
        got = values.get(f"{sensor}_{suffix}")
        return None if got is None else _float(got, f"{chip}.{label}.{suffix}")

    return {"chip": chip, "adapter": _str(adapter, "adapter"), "label": label, "sensor": sensor,
            "kind": re.sub(r"\d+$", "", sensor), "input": value("input"), "min": value("min"),
            "max": value("max"), "crit": value("crit"), "alarm": value("alarm")}


def parse_sensors(raw: bytes) -> Data:
    chips = _json(raw)
    if not isinstance(chips, dict):
        raise ParseError("sensors -j is a JSON object of chips")
    # A record is one sensor reading; a chip that is not an object is one unreadable record.
    found: list[tuple[str, Any, str, str, Any]] = []
    for chip, features in chips.items():
        if not isinstance(features, dict):
            found.append((chip, None, "", "", None))
            continue
        for label, values in features.items():
            if isinstance(values, dict):
                found.extend((chip, features.get("Adapter", ""), label, key[: -len("_input")],
                              values) for key in values if key.endswith("_input"))
    readings, skipped = _records(found, lambda f: _reading(*f), "sensor reading")
    return {"readings": readings, "count": len(readings), "skipped": skipped}


#: nvidia-smi `clocks_event_reasons` bits, as named in its documentation.
THROTTLE = ((0x1, "gpu_idle"), (0x2, "applications_clocks_setting"), (0x4, "sw_power_cap"),
            (0x8, "hw_slowdown"), (0x10, "sync_boost"), (0x20, "sw_thermal_slowdown"),
            (0x40, "hw_thermal_slowdown"), (0x80, "hw_power_brake_slowdown"),
            (0x100, "display_clock_setting"))


def _gpu_value(text: str, convert: Callable[[Any, str], Any], what: str) -> Any:
    text = text.strip()
    if text.startswith("[") and text.endswith("]"):  # [N/A], [Not Supported]
        return None
    return convert(text, what)


def _hex(value: str, what: str) -> int:
    if not re.fullmatch(r"0x[0-9a-fA-F]+", value):
        raise ParseError(f"{what}: expected a hex bitmask, got {value!r}")
    return int(value, 16)


def _gpu(line: str) -> Data:
    cells = [cell.strip() for cell in line.split(",")]
    if len(cells) != 11:
        raise ParseError(f"nvidia-smi line has {len(cells)} fields, not 11: {line!r}")
    index, name, temp, power, limit, used, total, util, reasons, width, width_max = cells
    bits = _gpu_value(reasons, _hex, "throttle")
    return {
        "index": _int(index, "index"), "name": name,
        "temperature_c": _gpu_value(temp, _int, "temperature"),
        "power_w": _gpu_value(power, _float, "power.draw"),
        "power_limit_w": _gpu_value(limit, _float, "power.limit"),
        "memory_used_mib": _gpu_value(used, _int, "memory.used"),
        "memory_total_mib": _gpu_value(total, _int, "memory.total"),
        "utilization_pct": _gpu_value(util, _int, "utilization"),
        "throttle_reasons": bits,
        "throttle": [label for bit, label in THROTTLE if bits and bits & bit],
        "pcie_width": _gpu_value(width, _int, "pcie width"),
        "pcie_width_max": _gpu_value(width_max, _int, "pcie max width"),
    }


def parse_gpu(raw: bytes) -> Data:
    gpus, skipped = _records(_lines(raw), _gpu, "GPU line")
    return {"gpus": gpus, "count": len(gpus), "skipped": skipped}


def _filesystem(line: str) -> Data:
    cells = line.split(None, 7)
    if len(cells) != 8:
        raise ParseError(f"df line has fewer than eight fields: {line!r}")
    source, fstype, *numbers, mount = cells
    size, used, avail, inodes, iused = (_int(n, "df") for n in numbers)
    return {"source": source, "fstype": fstype, "mount": mount, "size_bytes": size,
            "used_bytes": used, "avail_bytes": avail, "used_pct": _pct(used, used + avail),
            "inodes": inodes, "inodes_used": iused, "inodes_used_pct": _pct(iused, inodes)}


def parse_disk_fill(raw: bytes) -> Data:
    lines = _lines(raw)
    if not lines[0].startswith("Filesystem"):
        raise ParseError("df output has no header")
    if len(lines) == 1:
        raise ParseError("df listed no filesystems")
    filesystems, skipped = _records(lines[1:], _filesystem, "filesystem")
    return {"filesystems": filesystems, "count": len(filesystems), "skipped": skipped}


NET_FIELDS = tuple(f"rx_{n}" for n in ("bytes", "packets", "errs", "drop", "fifo", "frame",
                                       "compressed", "multicast")) + tuple(
    f"tx_{n}" for n in ("bytes", "packets", "errs", "drop", "fifo", "colls", "carrier",
                        "compressed"))


def _interface(line: str) -> Data:
    name, sep, rest = line.partition(":")
    counters = rest.split()
    if not sep or len(counters) != len(NET_FIELDS):
        raise ParseError(f"not an interface line: {line!r}")
    return {"name": name.strip()} | {
        field: _int(value, field) for field, value in zip(NET_FIELDS, counters, strict=True)}


def parse_net_dev(raw: bytes) -> Data:
    lines = _lines(raw)[2:]
    if not lines:
        raise ParseError("/proc/net/dev lists no interfaces")
    interfaces, skipped = _records(lines, _interface, "interface")
    return {"interfaces": interfaces, "count": len(interfaces), "skipped": skipped}


# --- medium tier ------------------------------------------------------------------------------

#: One `ps -o pid=,ppid=,user:32=,stat=,pcpu=,rss=,etimes=,nlwp=,times=,pidns=,comm:15=,args=`
#: line. `comm` is a fixed 15-character column because it may contain spaces; `args` is the
#: rest. `pidns` is the PID namespace's inode, or `-` where ps could not read it.
PS_LINE = re.compile(r"\s*(\d+)\s+(\d+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)"
                     r"\s+(\d+|-) (.{15}) (.*)")


def _process(line: str) -> tuple[Data, int]:
    match = PS_LINE.fullmatch(line)
    if not match:
        raise ParseError(f"not a ps line: {line[:120]!r}")
    pid, ppid, user, state, pcpu, rss, elapsed, threads, cpu_s, ns, comm, args = match.groups()
    args, found = _clean(args, ARGS_CHARS)
    return {"pid": int(pid), "ppid": int(ppid), "user": user[:IDENT_CHARS], "state": state,
            "cpu_pct": _float(pcpu, "pcpu"), "rss_kb": int(rss), "elapsed_s": int(elapsed),
            "threads": int(threads), "cpu_s": int(cpu_s), "comm": comm.rstrip(),
            "args": args, "pid_ns": None if ns == "-" else int(ns)}, found


def _namespaces(procs: list[Data]) -> None:
    """Each process's `pid_ns` as `host` (PID 1's PID namespace) or `separate` (another one: a
    container, such as a Docker or kind workload, or a sandbox), None where either inode is
    unknown. Root inside a container is ordinary, and without this a context could not tell a
    root uvicorn in a compose service from one on the host (unexpected_root, 2026-10-27)."""
    host = next((p["pid_ns"] for p in procs if p["pid"] == 1), None)
    for p in procs:
        ns = p["pid_ns"]
        p["pid_ns"] = None if host is None or ns is None else "host" if ns == host else "separate"


def _from_tmp(procs: list[Data]) -> tuple[list[Data], list[Data]]:
    """Processes whose program is in a temporary directory, split in two. A test run's: the
    program is under `PYTEST_TMP` and the first ancestor outside a temporary directory runs
    pytest; those are grouped by that runner (2026-10-30: every test of a suite in a container
    was a separate issue). Everything else is listed one row per process, as before."""
    by_pid = {p["pid"]: p for p in procs}
    rows: list[Data] = []
    runs: dict[int, Data] = {}
    for proc in procs:
        if not proc["args"].startswith(TMP_DIRS):
            continue
        runner = by_pid.get(proc["ppid"])
        for _ in range(ANCESTRY):
            if runner is None or not runner["args"].startswith(TMP_DIRS):
                break
            runner = by_pid.get(runner["ppid"])
        if (runner is None or runner["args"].startswith(TMP_DIRS)
                or not proc["args"].startswith(PYTEST_TMP) or not PYTEST.search(runner["args"])):
            rows.append(proc)
            continue
        run = runs.setdefault(runner["pid"], {
            "pid": runner["pid"], "user": runner["user"], "pid_ns": runner["pid_ns"],
            "args": runner["args"], "processes": 0, "programs": [], "pids": []})
        run["processes"] += 1
        if len(run["pids"]) < FROM_TMP_N:
            run["pids"].append(proc["pid"])
        program = proc["args"].split(" ", 1)[0]
        if program not in run["programs"] and len(run["programs"]) < 3:
            run["programs"].append(program)
    return rows[:FROM_TMP_N], list(runs.values())[:FROM_TMP_N]


def parse_processes(raw: bytes) -> Data:
    read, skipped = _records(_lines(raw), _process, "ps line")
    procs = [proc for proc, _ in read]
    _namespaces(procs)
    from_tmp, test_runs = _from_tmp(procs)
    return {
        "count": len(procs),
        "threads": sum(p["threads"] for p in procs),
        "rss_kb_total": sum(p["rss_kb"] for p in procs),
        "cpu_pct_total": round(sum(p["cpu_pct"] for p in procs), 1),
        "zombies": sum(p["state"].startswith("Z") for p in procs),
        "uninterruptible": sum(p["state"].startswith("D") for p in procs),
        "top_cpu": sorted(procs, key=lambda p: (-p["cpu_pct"], p["pid"]))[:TOP_N],
        "top_rss": sorted(procs, key=lambda p: (-p["rss_kb"], p["pid"]))[:TOP_N],
        "from_tmp": from_tmp,
        "tmp_test_runs": test_runs,
        "redacted": sum(found for _, found in read),
        "skipped": skipped,
    }


def parse_units_failed(raw: bytes) -> Data:
    names = ("unit", "load", "active", "sub", "description")
    units, skipped = _records(_array(raw, "list-units"),
                              lambda item: _fields(_object(item, "unit"), names, "unit"), "unit")
    return {"units": units, "count": len(units), "skipped": skipped}


def _jtext(value: Any) -> str:
    """One journal field as text, whatever `journalctl -o json` encoded it as.

    `null` (a field over the size threshold) is `""`; an array of byte values is decoded; an
    array of values (a repeated field) is each value decoded and joined with `|`. Anything
    else is dropped to `""`. Never raises: these fields are chosen by whoever logs.
    """
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        if all(isinstance(b, int) and not isinstance(b, bool) and 0 <= b < 256 for b in value):
            return bytes(value).decode("utf-8", "replace")
        if all(isinstance(v, str | list) for v in value):
            return "|".join(_jtext(v) for v in value)
    return ""


def _journal_entry(line: str) -> tuple[Data, int]:
    entry = _object(json.loads(line), "journal entry")
    at = _int(entry["__REALTIME_TIMESTAMP"], "timestamp") / 1e6
    priority = _int(entry["PRIORITY"], "priority")
    message, found = _clean(_jtext(entry.get("MESSAGE")), MESSAGE_CHARS)
    return {"at": at, "unit": _jtext(entry.get("_SYSTEMD_UNIT"))[:IDENT_CHARS],
            "identifier": _jtext(entry.get("SYSLOG_IDENTIFIER"))[:IDENT_CHARS],
            "transport": _jtext(entry.get("_TRANSPORT"))[:IDENT_CHARS], "priority": priority,
            "message": message}, found


def parse_journal(raw: bytes, cap: int = JOURNAL_LINES) -> Data:
    """`cap` is the probe's `journalctl -n`; `capped` says the read reached it.

    journalctl ends every entry with a newline, so output that does not end with one was cut
    (at the executor's byte cap): the partial last line is dropped and `truncated` set. An
    entry that cannot be read is skipped and counted. Nothing a sender logs fails the probe.
    """
    lines = _text(raw).split("\n")
    tail = lines.pop()  # "" when the output ended with a newline
    truncated = False
    if tail.strip():
        try:
            json.loads(tail)
            lines.append(tail)
        except ValueError:
            truncated = True
    read, skipped = _records([line for line in lines if line.strip()], _journal_entry,
                             "journal entry", all_bad_is_error=False)
    entries = [entry for entry, _ in read]
    by_unit = Counter(e["unit"] or e["identifier"] or "unknown" for e in entries)
    by_priority = Counter(str(e["priority"]) for e in entries)
    kept = entries[-JOURNAL_KEPT:]
    return {"entries": kept, "count": len(entries), "kept": len(kept),
            "capped": len(entries) + skipped >= cap, "by_unit": dict(by_unit),
            "by_priority": dict(sorted(by_priority.items())),
            "redacted": sum(found for _, found in read), "skipped": skipped,
            "truncated": truncated}


USERS = re.compile(r'\("((?:[^"\\]|\\.)*)",pid=(\d+),fd=\d+\)')


def _address(local: str) -> tuple[str, str, int, ipaddress.IPv4Address | ipaddress.IPv6Address
                                  | None]:
    host, sep, port = local.rpartition(":")
    if not sep or not port.isdigit():
        raise ParseError(f"not an address:port: {local!r}")
    host, _, interface = host.partition("%")
    host = host.removeprefix("[").removesuffix("]")
    if host == "*":
        return host, interface, int(port), None
    try:
        return host, interface, int(port), ipaddress.ip_address(host)
    except ValueError:
        raise ParseError(f"not a numeric address: {host!r}") from None


def _listener(line: str) -> Data:
    cells = line.split(None, 6)
    if len(cells) < 6:
        raise ParseError(f"not an ss line: {line!r}")
    proto, state, _, _, local = cells[:5]
    address, interface, port, ip = _address(local)
    users = USERS.findall(cells[6]) if len(cells) > 6 else []
    mapped = getattr(ip, "ipv4_mapped", None)
    return {
        "proto": proto, "state": state, "address": address, "interface": interface,
        "port": port, "process": users[0][0][:IDENT_CHARS] if users else "",
        "pid": int(users[0][1]) if users else None,
        "wildcard": ip is None or ip.is_unspecified or bool(mapped and mapped.is_unspecified),
        "loopback": ip is not None and (ip.is_loopback or bool(mapped and mapped.is_loopback)),
    }


def parse_listeners(raw: bytes) -> Data:
    listeners, skipped = _records([line for line in _text(raw).splitlines() if line.strip()],
                                  _listener, "socket")
    return {"listeners": listeners, "count": len(listeners),
            "wildcard_count": sum(item["wildcard"] for item in listeners), "skipped": skipped}


#: Kernel taint bits in order, as `Documentation/admin-guide/tainted-kernels.rst` letters them.
TAINT = "PFSRMBUDAWCIOELKXTN"


def parse_tainted(raw: bytes) -> Data:
    value = _int(_text(raw).strip(), "tainted")
    if value < 0:
        raise ParseError("taint is a non-negative bitmask")
    bits = [bit for bit in range(value.bit_length()) if value >> bit & 1]
    return {"value": value, "flags": "".join(TAINT[b] if b < len(TAINT) else "?" for b in bits),
            "bits": bits}


def parse_routes(raw: bytes) -> Data:
    """/proc/net/route: the IPv4 routing table, its default routes decoded (addresses there are
    little-endian hex)."""
    lines = _lines(raw)
    if lines[0].split()[:4] != ["Iface", "Destination", "Gateway", "Flags"]:
        raise ParseError("not a /proc/net/route table")
    default = []
    for line in lines[1:]:
        cells = line.split()
        if len(cells) < 8:
            raise ParseError(f"route line has too few fields: {line!r}")
        if cells[1] == "00000000" and cells[7] == "00000000":
            gateway = int(cells[2], 16).to_bytes(4, "little")
            default.append({"interface": _clean(cells[0], IDENT_CHARS)[0],
                            "gateway": ".".join(str(b) for b in gateway),
                            "metric": _int(cells[6], "metric"),
                            "up": bool(int(cells[3], 16) & 0x1)})
    return {"count": len(lines) - 1, "default": sorted(default, key=lambda r: r["metric"])}


#: Filesystems kept from the mount table: block, network and stacked ones that hold data. The
#: rest (proc, sysfs, cgroup, overlay, nsfs, tmpfs...) are the kernel's or Docker's.
REAL_FS = frozenset({"ext2", "ext3", "ext4", "xfs", "btrfs", "zfs", "vfat", "exfat", "ntfs",
                     "ntfs3", "f2fs", "fuseblk", "ecryptfs", "nfs", "nfs4", "cifs", "smb3"})
NETWORK_FS = frozenset({"nfs", "nfs4", "cifs", "smb3"})
_OCTAL = re.compile(r"\\([0-7]{3})")


def parse_mounts(raw: bytes) -> Data:
    """A mount table (/proc/<pid>/mounts): the data filesystems, read-only or not. Read as a
    file, so a dead network mount cannot hang it the way a stat would."""
    mounts = []
    for line in _lines(raw):
        cells = line.split()
        if len(cells) != 6:
            raise ParseError(f"mount line does not have six fields: {line!r}")
        source, target, fstype, options = (
            _OCTAL.sub(lambda m: chr(int(m.group(1), 8)), cell) for cell in cells[:4])
        if fstype in REAL_FS:
            mounts.append({"source": _clean(source, ARGS_CHARS)[0],
                           "target": _clean(target, ARGS_CHARS)[0], "fstype": fstype,
                           "read_only": "ro" in options.split(","),
                           "network": fstype in NETWORK_FS})
    return {"mounts": mounts, "count": len(mounts)}


_RELEASE = re.compile(r"[0-9][0-9A-Za-z.+_~-]{0,63}")


def parse_kernel_release(raw: bytes) -> Data:
    release = _text(raw).strip()
    if not _RELEASE.fullmatch(release):
        raise ParseError("not a kernel release")
    return {"release": release}


_INST = re.compile(r"Inst (\S+) (?:\[[^\]]*\] )?\(([^)]*)\)")
_APT_SUMMARY = re.compile(r"(\d+) upgraded, (\d+) newly installed, (\d+) to remove and "
                          r"(\d+) not upgraded\.")
#: Package names listed, security updates first.
APT_NAMES = 30


def parse_apt_upgrades(raw: bytes) -> Data:
    """`apt-get -s dist-upgrade`: what an upgrade would install, from the package lists as
    last fetched. A package counts as a security update when a suite it comes from is a
    `-security` pocket."""
    text = _text(raw)
    summary = _APT_SUMMARY.search(text)
    if summary is None:
        raise ParseError("apt-get printed no upgrade summary")
    found = [(m.group(1), "-security" in m.group(2)) for m in _INST.finditer(text)]
    security = [name for name, is_security in found if is_security]
    names = security + [name for name, is_security in found if not is_security]
    return {"upgradable": len(found), "security": len(security),
            "packages": [_clean(n, IDENT_CHARS)[0] for n in names[:APT_NAMES]],
            "not_upgraded": int(summary.group(4))}


def parse_protected_hardlinks(raw: bytes) -> Data:
    """The sysctl's value; only 1 protects (kernel docs: 0 off, 1 on)."""
    value = _int(_text(raw).strip(), "protected_hardlinks")
    return {"value": value, "protected": value == 1}


EXIT = re.compile(r"(?:Exited|Restarting) \((-?\d+)\)")
HEALTH = re.compile(r"\((healthy|unhealthy|health: starting)\)")


def _container(raw_item: Any) -> Data:
    item = _object(raw_item, "container")
    names = item.get("Names")
    if not isinstance(names, list) or not names:
        raise ParseError("a container has no name")
    fields = _fields(item, ("Id", "Image", "State", "Status"), "container")
    status = fields["Status"]
    health = (item.get("Health") or {}).get("Status", "none")
    if health == "none":
        found = HEALTH.search(status)
        health = found.group(1).removeprefix("health: ") if found else ""
    exit_code = EXIT.match(status)
    labels = item.get("Labels") or {}
    return {
        "id": fields["Id"][:12], "name": _str(names[0], "name").lstrip("/"),
        "image": fields["Image"], "state": fields["State"], "status": status,
        "health": _str(health, "health"),
        "exit_code": int(exit_code.group(1)) if exit_code else None,
        "created": _int(item.get("Created"), "Created"),
        "compose_project": _str(labels.get("com.docker.compose.project", ""), "project"),
        "published": [_published(port) for port in item.get("Ports") or []
                      if isinstance(port, dict) and port.get("PublicPort")],
        "network_mode": _str((item.get("HostConfig") or {}).get("NetworkMode", ""),
                             "NetworkMode"),
        "host_mounts": sorted({_str(m.get("Source"), "mount source")
                               for m in item.get("Mounts") or [] if isinstance(m, dict)
                               and m.get("Source") in HOST_MOUNTS}),
    }


#: Bind-mount sources that hand a container the host: its root, or the Docker API.
HOST_MOUNTS = frozenset({"/", "/var/run/docker.sock", "/run/docker.sock"})


def _published(port: dict[str, Any]) -> Data:
    """One published port: where on the host it listens (`ip`, empty for every address on an
    older Engine) and the container port behind it."""
    return {"ip": _str(port.get("IP", ""), "IP"), "port": _int(port["PublicPort"], "PublicPort"),
            "container_port": _int(port.get("PrivatePort"), "PrivatePort"),
            "proto": _str(port.get("Type", ""), "Type")}


def parse_containers(raw: bytes) -> Data:
    containers, skipped = _records(_array(raw, "/containers/json"), _container, "container")
    return {"containers": containers, "count": len(containers),
            "by_state": dict(Counter(c["state"] for c in containers)), "skipped": skipped}


def _controller(item: tuple[str, dict[str, str]]) -> Data:
    mc, files = item
    out: Data = {"mc": mc, "ce_count": 0, "ue_count": 0}
    for name, text in files.items():
        if name not in ("ce_count", "ue_count"):
            raise ParseError(f"unexpected EDAC file {mc}/{name}")
        out[name] = _int(text.strip(), f"{mc}/{name}")
    return out


def parse_edac(raw: bytes) -> Data:
    grouped: dict[str, dict[str, str]] = {}
    for path, text in sorted(_files(raw).items()):
        mc = posixpath.basename(posixpath.dirname(path))
        grouped.setdefault(mc, {})[posixpath.basename(path)] = text
    listed, skipped = _records(grouped.items(), _controller, "memory controller")
    return {"controllers": listed, "ce_total": sum(c["ce_count"] for c in listed),
            "ue_total": sum(c["ue_count"] for c in listed), "skipped": skipped}


# --- slow tier --------------------------------------------------------------------------------

#: ATA attribute id -> output field.
ATA = {5: "reallocated_sectors", 197: "pending_sectors", 198: "offline_uncorrectable",
       187: "reported_uncorrect", 199: "udma_crc_errors"}
NVME = {"critical_warning": "critical_warning", "available_spare": "available_spare_pct",
        "available_spare_threshold": "available_spare_threshold_pct",
        "percentage_used": "percentage_used", "media_errors": "media_errors",
        "num_err_log_entries": "error_log_entries", "unsafe_shutdowns": "unsafe_shutdowns"}


def _attribute(row: Any) -> Data:
    row = _object(row, "SMART attribute")
    return {"id": _int(row["id"], "id"), "name": _str(row["name"], "name"),
            "raw": _int(row["raw"]["value"], "raw"),
            "when_failed": _str(row.get("when_failed", ""), "when_failed")}


def parse_smart(raw: bytes) -> Data:
    data = _json(raw)
    if not isinstance(data, dict) or not isinstance(data.get("smartctl"), dict) or \
            not isinstance(data.get("device"), dict):
        raise ParseError("smartctl JSON has no smartctl or device section")
    status = _int(data["smartctl"].get("exit_status"), "exit_status")
    if status & 0b11:  # bit 0: command line did not parse; bit 1: device open failed
        said = "; ".join(str(m.get("string", "")) for m in data["smartctl"].get("messages", []))
        raise ParseError(f"smartctl could not read the device (exit {status}): {said}")
    device = data["device"]
    health = data.get("nvme_smart_health_information_log") or {}
    table = (data.get("ata_smart_attributes") or {}).get("table") or []
    rows, skipped = _records(table, _attribute, "ATA attribute")
    ata = {row["id"]: row for row in rows}
    passed = (data.get("smart_status") or {}).get("passed")
    out: Data = {
        "device": _str(device.get("name"), "device.name"),
        "type": _str(device.get("type", ""), "device.type"),
        "protocol": _str(device.get("protocol", ""), "device.protocol"),
        "model": _str(data.get("model_name", ""), "model_name"),
        "serial": _str(data.get("serial_number", ""), "serial_number"),
        "firmware": _str(data.get("firmware_version", ""), "firmware_version"),
        "exit_status": status,
        "passed": passed if isinstance(passed, bool) else None,
        "temperature_c": _opt_int((data.get("temperature") or {}).get("current"), "temperature"),
        "power_on_hours": _opt_int((data.get("power_on_time") or {}).get("hours"), "hours"),
        "power_cycles": _opt_int(data.get("power_cycle_count"), "power_cycle_count"),
    }
    for key, field in NVME.items():
        out[field] = _opt_int(health.get(key), key)
    for number, field in ATA.items():
        out[field] = ata[number]["raw"] if number in ata else None
    out["failing_attributes"] = [row["name"] for row in rows if row["when_failed"]]
    out["skipped"] = skipped
    return out


def _stable(value: Any) -> Any:
    """The ruleset without what changes while it stays the same: handles, and the packet and
    byte counts of counters (iptables-nft gives every rule one, so traffic alone moved them)."""
    if isinstance(value, dict):
        return {k: _stable({c: n for c, n in v.items() if c not in ("packets", "bytes")}
                           if k == "counter" and isinstance(v, dict) else v)
                for k, v in value.items() if k != "handle"}
    if isinstance(value, list):
        return [_stable(v) for v in value]
    return value


def parse_firewall(raw: bytes) -> Data:
    data = _json(raw)
    items = data.get("nftables") if isinstance(data, dict) else None
    if not isinstance(items, list):
        raise ParseError("nft -j output is an object with an nftables array")
    version = ""
    ruleset = []
    counts: Counter[str] = Counter()
    tables, chains, rules_per_chain = [], [], Counter()
    for item in items:
        if not isinstance(item, dict) or len(item) != 1:
            raise ParseError(f"not an nftables object: {item!r}")
        (kind, body), = item.items()
        if not isinstance(body, dict):
            raise ParseError(f"nftables {kind} is not an object")
        if kind == "metainfo":
            version = _str(body.get("version", ""), "version")
            continue
        ruleset.append(item)
        counts[kind] += 1
        if kind == "table":
            tables.append(f"{_str(body.get('family'), 'family')} {_str(body.get('name'), 'name')}")
        elif kind == "chain" and "hook" in body:
            chains.append(body)
        elif kind == "rule":
            rules_per_chain[(body.get("family"), body.get("table"), body.get("chain"))] += 1
    base = [{"family": _str(c.get("family"), "family"), "table": _str(c.get("table"), "table"),
             "name": _str(c.get("name"), "name"), "hook": _str(c["hook"], "hook"),
             "type": _str(c.get("type", ""), "type"), "priority": _int(c.get("prio"), "prio"),
             "policy": _str(c.get("policy", ""), "policy"),
             "rules": rules_per_chain[(c.get("family"), c.get("table"), c.get("name"))]}
            for c in chains]
    canonical = json.dumps(_stable(ruleset), sort_keys=True, separators=(",", ":"))
    return {"hash": hashlib.sha256(canonical.encode()).hexdigest(), "version": version,
            "tables": counts["table"], "chains": counts["chain"], "rules": counts["rule"],
            "sets": counts["set"] + counts["map"], "table_names": tables, "base_chains": base}


MODULE_LINE = re.compile(r"(\S+) (\d+) (\d+|-) (\S+) (\S+) (0x[0-9a-f]+)(?: \((\w+)\))?")


def _module(line: str) -> tuple[str, str, str]:
    match = MODULE_LINE.fullmatch(line.strip())
    if not match:
        raise ParseError(f"not a /proc/modules line: {line!r}")
    return match.group(1), match.group(5), match.group(7) or ""


def parse_modules(raw: bytes) -> Data:
    modules, skipped = _records(_lines(raw), _module, "module")
    return {"modules": sorted(name for name, _, _ in modules), "count": len(modules),
            "tainting": {name: flags for name, _, flags in modules if flags},
            "not_live": sorted(name for name, state, _ in modules if state != "Live"),
            "skipped": skipped}


def parse_reboot_required(raw: bytes) -> Data:
    files = {posixpath.basename(path): text for path, text in _files(raw).items()}
    unexpected = set(files) - {"reboot-required", "reboot-required.pkgs"}
    if unexpected:
        raise ParseError(f"unexpected reboot files {sorted(unexpected)}")
    packages = files.get("reboot-required.pkgs", "").split()
    return {"required": "reboot-required" in files, "packages": sorted(set(packages))}


# --- daily tier -------------------------------------------------------------------------------

KEY = re.compile(r"(?:^|\s)((?:ssh|ecdsa|sk)-[\w@.-]+)\s+([A-Za-z0-9+/]+={0,2})(?:\s+(.*))?$")
#: Keys kept from one authorized_keys file. With `KEPT_BYTES` over all of them, it bounds the
#: observation as `_table` bounds crontabs: a valid file within the read caps grows
#: about threefold into key records, so without them one user's file could make the observation
#: too large to publish, blanking every home's keys. What is not kept is counted (`dropped`).
MAX_KEYS_PER_FILE = 100


def parse_authorized_keys(raw: bytes) -> Data:
    files, keys, spent = [], [], 0
    for path, text in sorted(_files(raw).items()):
        count = invalid = kept = 0
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            match = KEY.search(line)
            try:
                blob = base64.b64decode(match.group(2), validate=True) if match else b""
            except binascii.Error:
                blob = b""
            if not blob:
                invalid += 1
                continue
            digest = base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")
            key = {"path": path, "type": match.group(1)[:IDENT_CHARS],
                   "fingerprint": f"SHA256:{digest}",
                   "comment": _clean((match.group(3) or "").strip(), ARGS_CHARS)[0],
                   "options": bool(line[: match.start(1)].strip())}
            count += 1
            cost = _json_bytes(key)
            if kept < MAX_KEYS_PER_FILE and spent + cost <= KEPT_BYTES:
                keys.append(key)
                spent += cost
                kept += 1
        files.append({"path": path, "keys": count, "dropped": count - kept,
                      "invalid_lines": invalid,
                      "sha256": hashlib.sha256(text.encode()).hexdigest()})
    return {"files": files, "keys": keys, "count": len(keys),
            "dropped": sum(f["dropped"] for f in files)}


def _unit_file(item: Any) -> Data:
    return _fields(_object(item, "unit file"), ("unit_file", "state"), "unit file")


def parse_unit_files(raw: bytes) -> Data:
    files, skipped = _records(_array(raw, "list-unit-files"), _unit_file, "unit file")
    units = {f["unit_file"]: f["state"] for f in files}
    return {"units": units, "count": len(units), "by_state": dict(Counter(units.values())),
            "skipped": skipped}


def _usec(value: Any, what: str) -> float | None:
    value = _opt_int(value, what)
    return value / 1e6 if value else None


def _timer(item: Any) -> Data:
    item = _object(item, "timer")
    return _fields(item, ("unit", "activates"), "timer") | {
        "next": _usec(item.get("next"), "next"), "last": _usec(item.get("last"), "last")}


def parse_timers(raw: bytes) -> Data:
    timers, skipped = _records(_array(raw, "list-timers"), _timer, "timer")
    return {"timers": timers, "count": len(timers), "skipped": skipped}


# --- scheduled work ---------------------------------------------------------------------------

#: A crontab or anacrontab environment line, `NAME=value`. cron reads one before any job line,
#: so a job line (its first word is a time field or an @word, then whitespace) never matches.
ENV_LINE = re.compile(r"([^\s=]+)\s*=\s*(.*)")
CRON_WORDS = frozenset({"@reboot", "@yearly", "@annually", "@monthly", "@weekly", "@daily",
                        "@midnight", "@hourly"})
CRON_FIELD = re.compile(r"[0-9A-Za-z*/,-]+")
#: cron(8): the first `%` not escaped as `\%` ends the command and starts its standard input.
STDIN = re.compile(r"(?<!\\)%")
ANACRON_PERIOD = re.compile(r"\d+|@(?:daily|weekly|monthly|yearly|annually)")
SYSTEM_CRONTAB = "/etc/crontab"


def _json_bytes(value: Any) -> int:
    """Bytes `value` takes in an event: ASCII JSON, as `schema.encode_event` writes it."""
    return len(json.dumps(value, separators=(",", ":")))


def _table(files: Mapping[str, str], job: Callable[[str, str], tuple[Data, int]]) -> Data:
    """Crontab-shaped files: comments and blank lines dropped, `NAME=value` lines kept per file
    as `env`, every other line one entry read by `job(path, line)` or skipped and counted.
    Root's spool file first, then by path; what the caps do not keep is counted.

    There is no line continuation: cron has none, so a trailing backslash is command text.
    """
    listed, entries, skipped, dropped, redacted, spent = [], [], 0, 0, 0, 0
    for path in sorted(files, key=lambda path: (path != ROOT_CRONTAB, path)):
        env: dict[str, str] = {}
        env_dropped = 0
        lines = []
        for line in (line.strip() for line in files[path].splitlines()):
            if not line or line.startswith("#"):
                continue
            assignment = ENV_LINE.fullmatch(line)
            if not assignment:
                lines.append(line)
                continue
            name = assignment.group(1)[:IDENT_CHARS]
            value, found = _clean(assignment.group(2), ARGS_CHARS)
            redacted += found
            cost = _json_bytes({name: value})
            if len(env) < MAX_ENV_PER_FILE and spent + cost <= KEPT_BYTES:
                env[name] = value
                spent += cost
            else:
                env_dropped += 1
        read, bad = _records(lines, lambda line, path=path: job(path, line), "job line",
                             all_bad_is_error=False)
        redacted += sum(found for _, found in read)
        kept = 0
        for entry, _ in read:
            cost = _json_bytes(entry)
            if kept == MAX_ENTRIES_PER_FILE or len(entries) == MAX_ENTRIES_TOTAL or \
                    spent + cost > KEPT_BYTES:
                break
            entries.append(entry)
            spent += cost
            kept += 1
        skipped += bad
        dropped += len(read) - kept
        listed.append({"path": path, "env": env, "env_dropped": env_dropped, "entries": kept,
                       "total": len(read), "dropped": len(read) - kept, "skipped": bad})
    return {"files": listed, "entries": entries, "count": len(entries), "skipped": skipped,
            "dropped": dropped, "redacted": redacted}


def _cron_job(path: str, line: str, owner: str | None) -> tuple[Data, int]:
    """One crontab job line. `owner` is the spool file's user; `None` means the line names one
    (the system format of /etc/crontab and /etc/cron.d)."""
    times = 1 if line.startswith("@") else 5
    words = line.split(None, times + (owner is None))
    if len(words) != times + (owner is None) + 1:
        raise ParseError(f"not a crontab job line: {line[:120]!r}")
    schedule = words[:times]
    if times == 1:
        if schedule[0] not in CRON_WORDS:
            raise ParseError(f"not a cron @word: {schedule[0][:IDENT_CHARS]!r}")
    elif not all(CRON_FIELD.fullmatch(field) for field in schedule):
        raise ParseError(f"not a cron schedule: {line[:120]!r}")
    command, found = _clean(words[-1], COMMAND_CHARS)
    return {"file": path, "user": (owner or words[times])[:IDENT_CHARS],
            "schedule": " ".join(schedule)[:IDENT_CHARS], "command": command,
            "stdin": bool(STDIN.search(words[-1]))}, found


def parse_crontab_system(raw: bytes) -> Data:
    return _table({SYSTEM_CRONTAB: _text(raw)}, lambda path, line: _cron_job(path, line, None))


def parse_cron_d(raw: bytes) -> Data:
    return _table(_files(raw), lambda path, line: _cron_job(path, line, None))


def parse_cron_user(raw: bytes) -> Data:
    """A spool crontab has no user field: its owner is the file's name."""
    return _table(_files(raw), lambda path, line: _cron_job(path, line, posixpath.basename(path)))


def _anacron_job(path: str, line: str) -> tuple[Data, int]:
    period, delay, job_id, rest = line.split(None, 3)
    if not ANACRON_PERIOD.fullmatch(period):
        raise ParseError(f"not an anacron period: {period[:IDENT_CHARS]!r}")
    command, found = _clean(rest, COMMAND_CHARS)
    return {"file": path, "period": period, "delay": _int(delay, "delay"),
            "job_id": job_id[:IDENT_CHARS], "command": command}, found


def parse_anacron(raw: bytes) -> Data:
    return _table(_files(raw), _anacron_job)


def parse_periodic(raw: bytes) -> Data:
    """Each script run-parts would find: its size in bytes as read, and the head of its text.

    The executor reads hidden files nowhere and refuses symlinks (O_NOFOLLOW); those appear in
    the observation's warnings, not here.
    """
    scripts, redacted = [], 0
    for path, text in sorted(_files(raw).items()):
        head, found = _clean(text, SCRIPT_CHARS)
        scripts.append({"path": path, "size": len(text.encode()),
                        "truncated": len(text) > SCRIPT_CHARS, "head": head})
        redacted += found
    return {"scripts": scripts, "count": len(scripts), "redacted": redacted}


#: One `ExecStart=` value: `{ path=... ; argv[]=<the command> ; ignore_errors=... }`. Greedy, so
#: an argument that itself contains ` ; ignore_errors=` stays in the command.
EXEC_ARGV = re.compile(r"\{ path=.*? ; argv\[\]=(.*) ; ignore_errors=.*")
#: One `TimersCalendar=` value: `{ OnCalendar=<spec> ; next_elapse=... }`.
CALENDAR = re.compile(r"\{ OnCalendar=(.*) ; next_elapse=.*")
#: One `TimersMonotonic=` value: `{ On<base>USec=<span> ; next_elapse=... }`; kept as the unit
#: file spells it, `On<base>Sec=<span>`.
MONOTONIC = re.compile(r"\{ (On(?:Boot|Startup|UnitActive|UnitInactive|Active)USec=.*?)"
                       r" ; next_elapse=.*")
#: Properties `systemctl show` repeats, one line per value.
REPEATED = ("ExecStart", "TimersCalendar", "TimersMonotonic")


def _stamp(value: str, what: str) -> float | None:
    """A `--timestamp=unix` value, `@<epoch>`, as seconds; empty (never) is `None`."""
    if not value:
        return None
    if not value.startswith("@"):
        raise ParseError(f"{what}: expected @<epoch seconds>, got {value[:IDENT_CHARS]!r}")
    return _float(value[1:], what)


def _matched(pattern: re.Pattern[str], value: str, what: str) -> str:
    match = pattern.fullmatch(value)
    if not match:
        raise ParseError(f"unreadable {what}: {value[:120]!r}")
    return match.group(1)


def _unit(block: str) -> tuple[Data, int]:
    props: dict[str, str] = {}
    repeated: dict[str, list[str]] = {name: [] for name in REPEATED}
    for line in block.splitlines():
        key, sep, value = line.partition("=")
        if not sep:
            raise ParseError(f"not a property line: {line[:120]!r}")
        if key in repeated:
            if value:  # `Key=` with nothing after it is an empty list, which some systemds print
                repeated[key].append(value)
        else:
            props[key] = value
    if not props.get("Id"):
        raise ParseError("a unit block has no Id")
    commands = [_clean(_matched(EXEC_ARGV, value, "ExecStart"), COMMAND_CHARS)
                for value in repeated["ExecStart"]]

    def word(name: str, limit: int = IDENT_CHARS) -> str:
        return props.get(name, "")[:limit]

    return {
        "id": word("Id"), "description": word("Description", ARGS_CHARS), "user": word("User"),
        "exec": [command for command, _ in commands], "active": word("ActiveState"),
        "sub": word("SubState"), "result": word("Result"),
        "restarts": _opt_int(props.get("NRestarts") or None, "NRestarts"),
        "main_status": _opt_int(props.get("ExecMainStatus") or None, "ExecMainStatus"),
        "started": _stamp(word("ExecMainStartTimestamp"), "ExecMainStartTimestamp"),
        "exited": _stamp(word("ExecMainExitTimestamp"), "ExecMainExitTimestamp"),
        "enabled": word("UnitFileState"), "file": word("FragmentPath", ARGS_CHARS),
        "triggers": [name[:IDENT_CHARS] for name in word("Triggers", REDACT_CHARS).split()],
        "triggered_by": [name[:IDENT_CHARS]
                         for name in word("TriggeredBy", REDACT_CHARS).split()],
        "calendar": [_matched(CALENDAR, value, "TimersCalendar")[:IDENT_CHARS]
                     for value in repeated["TimersCalendar"]],
        "monotonic": [_matched(MONOTONIC, value, "TimersMonotonic").replace("USec=", "Sec=", 1)
                      [:IDENT_CHARS] for value in repeated["TimersMonotonic"]],
        "unit": word("Unit"),
    }, sum(found for _, found in commands)


def parse_unit_detail(raw: bytes) -> Data:
    """`systemctl show`: one blank-line-separated block of `Key=value` lines per unit, in no
    fixed property order."""
    blocks = [block for block in re.split(r"\n\s*\n", _text(raw)) if block.strip()]
    if not blocks:
        raise ParseError("empty output")
    read, skipped = _records(blocks, _unit, "unit block")
    units = sorted((unit for unit, _ in read), key=lambda unit: unit["id"])
    return {"units": units, "count": len(units), "skipped": skipped,
            "redacted": sum(found for _, found in read)}


# --- dispatch ---------------------------------------------------------------------------------

PARSERS: dict[str, Callable[[bytes], Data]] = {
    "load": parse_load, "uptime": parse_uptime, "psi.cpu": parse_psi, "psi.memory": parse_psi,
    "psi.io": parse_psi, "memory": parse_memory, "vmstat": parse_vmstat,
    "cpu.stat": parse_cpu_stat, "sensors": parse_sensors, "gpu": parse_gpu,
    "disk.fill": parse_disk_fill, "net.dev": parse_net_dev,
    "processes": parse_processes, "units.failed": parse_units_failed,
    "journal.warnings": parse_journal,
    "journal.errors": lambda raw: parse_journal(raw, JOURNAL_ERROR_LINES),
    "listeners": parse_listeners,
    "kernel.tainted": parse_tainted, "containers": parse_containers, "edac": parse_edac,
    "block.devices": _listing, "smart": parse_smart, "firewall": parse_firewall,
    "kernel.modules": parse_modules, "reboot.required": parse_reboot_required,
    "fs.protected_hardlinks": parse_protected_hardlinks,
    "ssh.keys.home": parse_authorized_keys, "ssh.keys.root": parse_authorized_keys,
    "cron.system": parse_crontab_system, "cron.d": parse_cron_d, "cron.user": parse_cron_user,
    "cron.anacron": parse_anacron, "cron.hourly": parse_periodic, "cron.daily": parse_periodic,
    "cron.weekly": parse_periodic, "cron.monthly": parse_periodic,
    "cron.d.names": _listing, "cron.hourly.names": _listing, "cron.daily.names": _listing,
    "cron.weekly.names": _listing, "cron.monthly.names": _listing,
    "units.files": parse_unit_files, "units.timers": parse_timers,
    "units.detail": parse_unit_detail, "routes": parse_routes, "mounts": parse_mounts,
    "boot": _listing, "kernel.release": parse_kernel_release,
    "apt.upgrades": parse_apt_upgrades,
}

_TEMPLATES = {spec.id: spec.devices for spec in CATALOG if spec.devices}


def _parser_for(probe_id: str) -> Callable[[bytes], Data]:
    if probe_id in PARSERS:
        return PARSERS[probe_id]
    template, _, device = probe_id.partition(".")
    regex = _TEMPLATES.get(template)
    if regex and re.fullmatch(regex, device):
        return PARSERS[template]
    raise ParseError(f"no parser for probe {probe_id!r}")


def parse(probe_id: str, raw: bytes) -> dict:
    """`raw` as `probe_id`'s observation data. Raises `ParseError`, and only that."""
    parser = _parser_for(probe_id)
    try:
        return parser(raw)
    except ParseError:
        raise
    except (ValueError, KeyError, TypeError, IndexError, AttributeError) as bad:
        raise ParseError(f"{probe_id}: unreadable output ({type(bad).__name__}: {bad})") from None
