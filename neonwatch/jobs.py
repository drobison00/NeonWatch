"""Scheduled work and services: the latest cron and systemd observations joined into records.

`scheduled` makes one job per thing that runs on a schedule — a crontab line, an anacrontab
line, a periodic script, a systemd timer — and `services` one record per service `units.detail`
read; `service_key` names a service's definition, for caching what is said about it. The
evaluator and the dashboard both read these, so a job means the same thing to each.

A job's `static` is everything that defines it and nothing that changes when it runs: no
times, no result. It is the judge's context state, so a job is asked about again exactly when it is
new or edited. A job's id is stable across runs for the same reason: a cron line's is a hash of
what defines it, a periodic script's is its path, a timer's is its name. Two different jobs
that share an id both survive (`~2`, `~3`...) and each collision is counted in `skipped`.

The crontab parsers keep a capped number of entries per file. A file that held more is one more
job, `<file>#overflow`, whose `overflow` is how many entries were not kept.

The scheduled directories are listed as well as read. The executor will not read a symlink (a
user's link must not make root read its target), but cron would still run it, so a name listed
and not read is a job with no command and `unread` set. Where the listing says the name is a
link, the job's `target` is where it points (made absolute against its directory, as text: it is
never resolved), since that is where cron would run it from; every other job's is None. A name
`run-parts` would not run is kept, marked `skipped_by_run_parts`, rather than dropped.

Input is `latest`: probe id -> that probe's parsed data, for the probes in `PROBES`; any may be
absent. A record that cannot be read (an older shape still in the store) is skipped and counted
with what the parsers skipped. Pure functions over dicts; imports nothing in this design.
"""

from __future__ import annotations

import hashlib
import json
import posixpath
import re
from collections.abc import Callable, Iterable, Mapping
from typing import Any

Record = dict[str, Any]
Latest = Mapping[str, Mapping[str, Any]]

CRONTABS = ("cron.system", "cron.d", "cron.user")
PERIODIC = {"cron.hourly": "hourly", "cron.daily": "daily", "cron.weekly": "weekly",
            "cron.monthly": "monthly"}
#: Each scheduled directory's read probe -> (directory, source, schedule, user) of a name in it.
#: Its listing is the probe `<read probe>.names`.
DIRECTORIES = {"cron.d": ("/etc/cron.d", "cron", "", "")} | {
    probe: (f"/etc/cron.{period}", "cron-periodic", period, "root")
    for probe, period in PERIODIC.items()}
PROBES = frozenset({*CRONTABS, *PERIODIC, "cron.anacron", "units.timers", "units.detail",
                    *(f"{probe}.names" for probe in DIRECTORIES)})
#: The names run-parts(8) runs in these directories; Debian's cron reads /etc/cron.d by the same
#: rule.
RUN_PARTS_NAME = re.compile(r"[A-Za-z0-9_-]+")
RUN_PARTS_DIRS = frozenset(directory for directory, *_ in DIRECTORIES.values())
#: What reading a record of another shape raises.
RECORD_ERRORS = (KeyError, TypeError, AttributeError)


def _digest(defined: bytes) -> str:
    return hashlib.sha256(defined).hexdigest()[:32]


def _job(source: str, file: str, user: str, schedule: str, command: str, *, id: str = "",
         unit: str | None = None, unread: bool = False, target: str | None = None,
         overflow: int = 0, last: float | None = None, next: float | None = None,
         result: str | None = None) -> Record:
    """A job record; without an `id`, the cron id: a hash of what defines the line."""
    directory, _, name = file.rpartition("/")
    skipped = directory in RUN_PARTS_DIRS and not RUN_PARTS_NAME.fullmatch(name)
    static = {"source": source, "file": file, "user": user, "schedule": schedule,
              "command": command, "unit": unit, "unread": unread, "target": target,
              "skipped_by_run_parts": skipped, "overflow": overflow}
    if not id:
        id = "cron:" + _digest(f"{file}\n{user}\n{schedule}\n{command}".encode())
    return {"id": id, **static, "static": dict(static), "last": last, "next": next,
            "result": result}


def _items(latest: Latest, probe: str, key: str) -> list[Any]:
    return latest.get(probe, {}).get(key, [])


def _cron(entry: Mapping[str, Any]) -> Record:
    return _job("cron", entry["file"], entry["user"], entry["schedule"], entry["command"])


def _anacron(entry: Mapping[str, Any]) -> Record:
    return _job("anacron", entry["file"], "root", entry["period"], entry["command"])


def _periodic(period: str) -> Callable[[Mapping[str, Any]], Record]:
    def read(script: Mapping[str, Any]) -> Record:
        return _job("cron-periodic", script["path"], "root", period, script["head"],
                    id=f"cron:{script['path']}")
    return read


def _overflow(source: str, user: Callable[[str], str]) -> Callable[[Mapping[str, Any]],
                                                                   Record]:
    def read(file: Mapping[str, Any]) -> Record:
        return _job(source, file["path"], user(file["path"]), "", "",
                    id=f"cron:{file['path']}#overflow", overflow=file["dropped"])
    return read


def _unread(source: str, schedule: str, user: str,
            links: Mapping[str, str]) -> Callable[[str], Record]:
    def read(path: str) -> Record:
        directory, _, name = path.rpartition("/")
        target = links.get(name)
        return _job(source, path, user, schedule, "", id=f"cron:{path}", unread=True,
                    target=posixpath.normpath(posixpath.join(directory, target))
                    if target else None)
    return read


def _timer(name: str, units: Mapping[str, Record], listed: Mapping[str, Any]) -> Record:
    """A timer, with its service's command, user and result where that service was read.

    Where it was not, user and command are empty rather than guessed.
    """
    timer = units.get(name, {})
    activates = timer.get("unit") or listed.get("activates") or None
    service = units.get(activates or "")
    return _job("timer", timer.get("file", ""), (service["user"] or "root") if service else "",
                "; ".join(timer.get("calendar", []) + timer.get("monotonic", [])),
                "; ".join(service["exec"]) if service else "", id=f"timer:{name}",
                unit=activates, last=listed.get("last"), next=listed.get("next"),
                result=(service["result"] or None) if service else None)


def scheduled(latest: Latest) -> tuple[list[Record], int]:
    """Every job, sorted by id, and how many records could not be read (parsers' and ours)."""
    found: dict[str, Record] = {}
    skipped = sum(latest[probe].get("skipped", 0) for probe in sorted(PROBES & set(latest)))

    def add(read: Callable[[Any], Record], items: Iterable[Any]) -> None:
        nonlocal skipped
        for item in items:
            try:
                job = read(item)
            except RECORD_ERRORS:
                skipped += 1
                continue
            key, n = job["id"], 1
            while key in found and found[key]["static"] != job["static"]:
                n += 1
                key = f"{job['id']}~{n}"
            if key in found:
                continue  # the same job again: one record
            if n > 1:
                skipped += 1  # a different job under a taken id: kept, and counted
            found[key] = job | {"id": key}

    for probe in CRONTABS:
        add(_cron, _items(latest, probe, "entries"))
    add(_anacron, _items(latest, "cron.anacron", "entries"))
    for probe, source, user in (("cron.system", "cron", lambda path: ""),
                                ("cron.d", "cron", lambda path: ""),
                                ("cron.user", "cron", lambda path: path.rpartition("/")[2]),
                                ("cron.anacron", "anacron", lambda path: "root")):
        add(_overflow(source, user),
            (file for file in _items(latest, probe, "files") if file.get("dropped", 0)))
    for probe, period in PERIODIC.items():
        add(_periodic(period), _items(latest, probe, "scripts"))
    for probe, (directory, source, schedule, user) in DIRECTORIES.items():
        read = {item["path"] for key in ("files", "scripts") for item in _items(latest, probe, key)}
        paths = (f"{directory}/{name}" for name in _items(latest, f"{probe}.names", "entries"))
        links = latest.get(f"{probe}.names", {}).get("links") or {}
        add(_unread(source, schedule, user, links), (path for path in paths if path not in read))
    units = {u["id"]: u for u in _items(latest, "units.detail", "units")}
    listed = {t["unit"]: t for t in _items(latest, "units.timers", "timers")}
    timers = {name for name in units if name.endswith(".timer")} | set(listed)
    add(lambda name: _timer(name, units, listed.get(name, {})), sorted(timers))
    return [found[key] for key in sorted(found)], skipped


#: Hex characters of a service key.
SERVICE_KEY_HEX = 16


def service_key(service: Mapping[str, Any]) -> str:
    """A short hash of a service record's name and definition (description, exec, unit file,
    user), and nothing that changes as it runs: a description cached under it is stale exactly
    when the unit is redefined."""
    defined = json.dumps([service.get(k) for k in ("name", "description", "exec", "file", "user")],
                         ensure_ascii=False, separators=(",", ":"), default=str)
    return hashlib.sha256(defined.encode("utf-8", "surrogatepass")).hexdigest()[:SERVICE_KEY_HEX]


def services(latest: Latest) -> list[Record]:
    """Every service `units.detail` read, sorted by name. No `User=` runs as root."""
    return sorted(({
        "name": u["id"], "description": u["description"], "user": u["user"] or "root",
        "exec": u["exec"], "active": u["active"], "sub": u["sub"], "result": u["result"],
        "restarts": u["restarts"], "main_status": u["main_status"], "started": u["started"],
        "exited": u["exited"], "enabled": u["enabled"], "file": u["file"]}
        for u in _items(latest, "units.detail", "units") if u["id"].endswith(".service")),
        key=lambda service: service["name"])
