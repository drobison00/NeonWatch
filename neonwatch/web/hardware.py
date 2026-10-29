"""What the hardware strip and the Board view show: the CPU, each disk and each GPU as the latest
observations read them, every temperature against a limit and with where that limit came from.

Pure: `snapshot` takes the latest data per probe and the clock, and names the store series behind
each reading (`series`), which `app` fetches for the sparklines; `cpu_util` turns `cpu.stat`'s
tick counters into per-bucket utilisation. Nothing here reads the store or the host.

**Limits.** A reading carries `limit_c`, `limit_source` and `headroom_c`, and a `level` from the
headroom (`LEVELS`), so a hot number is judged against its part, never as a bare number:
  - the CPU against `CPU_LIMIT_C` (k10temp reports no limit; 95 C is what `rules` holds it to);
  - a GPU against `GPU_LIMIT_C`, as `rules` does (nvidia-smi's query carries no slowdown point);
  - an NVMe sensor against its own `max`/`crit` where lm-sensors gives a plausible one (it reports
    65261.85 C, 0xFFFF kelvin, for "none"), else against the same drive's Composite limit,
    marked `borrowed`. Some drives' controller sensor reports none, and it can run well above
    Composite under sustained writes: a figure shown with no limit at all reads as fine.

**Disks.** A drive is found in `block.devices` (its sysfs link names its PCI address), so its
lm-sensors chip (`nvme-pci-<bus><dev>`), its SMART summary (`smart.<dev>`) and its mounts
(`disk.fill`) are joined by that address and name, never by order. `attach` says whether the
drive hangs off a CPU root port or behind a switch (the chipset), from the link's PCI depth.

**Freshness.** Each section has the `at` of the probe it came from and `stale` once that is older
than the `stale_after` the caller gives for the probe (the dashboard's own rule: three expected
intervals). A probe whose latest observation errored has its `error`; no data reads as
`at: null`, never as zero.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Mapping, Sequence
from itertools import pairwise
from typing import Any

#: k10temp, zenpower and coretemp report no limit; this is the one `rules.CPU_LIMIT_C` uses.
CPU_LIMIT_C = 95.0
#: As `rules.GPU_LIMIT_C`.
GPU_LIMIT_C = 90.0
#: A sensor limit outside this range is lm-sensors' "none" sentinel (`rules.PLAUSIBLE_CRIT_C`).
PLAUSIBLE_C = (0.0, 200.0)
#: Headroom (limit minus reading, C) at or below which a reading is at each level.
LEVELS = (("over", 0.0), ("near", 5.0), ("hot", 15.0), ("warm", 30.0))
CPU_CHIPS = ("k10temp-", "zenpower-", "coretemp-")
CPU_LABELS = re.compile(r"Tctl|Tdie|Tccd\d+|Package id \d+")
#: The tick counters of /proc/stat, as `cpu.stat` names them.
TICKS = ("user", "nice", "system", "idle", "iowait", "irq", "softirq", "steal")
IDLE_TICKS = ("idle", "iowait")
_DISK = re.compile(r"nvme\d+n\d+|sd[a-z]+")
_PCI = re.compile(r"[0-9a-f]{4}:([0-9a-f]{2}):([0-9a-f]{2})\.[0-7]")
#: PCI devices on bus 0 that are Intel PCH root ports (ports 1-8, 9-16, 17-24). AMD's root ports
#: are on devices 01-08, so a drive behind one of these is the chipset's on either.
PCH_ROOT_DEVICES = ("1b", "1c", "1d")

Latest = Mapping[str, tuple[float, Mapping[str, Any]]]


def _num(value: Any) -> float | None:
    return float(value) if isinstance(value, int | float) and not isinstance(value, bool) \
        else None


def _rows(data: Mapping[str, Any] | None, key: str) -> list[Mapping[str, Any]]:
    value = (data or {}).get(key)
    return [r for r in value if isinstance(r, Mapping)] if isinstance(value, list) else []


def _plausible(value: Any) -> float | None:
    low, high = PLAUSIBLE_C
    v = _num(value)
    return v if v is not None and low < v < high else None


def level(value: float, limit: float) -> str:
    headroom = limit - value
    return next((name for name, at in LEVELS if headroom <= at), "cool")


def _reading(label: str, value: float | None, limit: float, source: str,
             series: tuple[str, str] | None, **extra: Any) -> dict[str, Any]:
    out: dict[str, Any] = {"label": label, "value_c": value, "limit_c": limit,
                           "limit_source": source, **extra}
    if value is not None:
        out |= {"headroom_c": round(limit - value, 1), "level": level(value, limit)}
    if series is not None:
        out["series"] = {"probe": series[0], "field": series[1]}
    return out


def _section(probe: str, latest: Latest, errors: Mapping[str, str], now: float,
             stale_after: Callable[[str], float]) -> dict[str, Any]:
    entry = latest.get(probe)
    at = entry[0] if entry is not None else None
    return {"probe": probe, "at": at, "stale": at is None or now - at > stale_after(probe),
            **({"error": errors[probe]} if errors.get(probe) else {})}


def _data(probe: str, latest: Latest) -> Mapping[str, Any] | None:
    entry = latest.get(probe)
    return entry[1] if entry is not None else None


def _cpu(latest: Latest, errors: Mapping[str, str], now: float,
         stale_after: Callable[[str], float]) -> dict[str, Any]:
    temps = []
    for i, r in enumerate(_rows(_data("sensors", latest), "readings")):
        label = str(r.get("label", ""))
        if (str(r.get("chip", "")).startswith(CPU_CHIPS) and r.get("kind") == "temp"
                and CPU_LABELS.fullmatch(label)):
            temps.append(_reading(label, _num(r.get("input")), CPU_LIMIT_C, "CPU default",
                                  ("sensors", f"readings.{i}.input"), chip=r.get("chip")))
    load, stat = _data("load", latest) or {}, _data("cpu.stat", latest) or {}
    return {**_section("sensors", latest, errors, now, stale_after), "temps": temps,
            "load1": _num(load.get("load1")), "cpus": _num(stat.get("cpus")),
            "load_series": {"probe": "load", "field": "load1"}}


def _chip(pci: str) -> str | None:
    """lm-sensors' chip name for the NVMe controller at a PCI address: `nvme-pci-<bus><dev>`."""
    found = _PCI.fullmatch(pci)
    return f"nvme-pci-{found.group(1)}{found.group(2)}" if found else None


def _attach(path: Sequence[str]) -> str | None:
    """Where a drive's lanes come from, from its PCI path (root port first, the drive last).
    Two addresses are a drive on a root port: the CPU's, unless the root port is on device
    1b, 1c or 1d of bus 0, which is where Intel's chipset (PCH) puts its own. More addresses,
    and it sits behind a switch: on most desktop boards, the chipset."""
    if not path:
        return None
    root = _PCI.fullmatch(path[0])
    if len(path) > 2 or (root is not None and root.group(1) == "00"
                         and root.group(2) in PCH_ROOT_DEVICES):
        return "chipset"
    return "cpu"


def _disk(name: str, link: str, latest: Latest, errors: Mapping[str, str], now: float,
          stale_after: Callable[[str], float]) -> dict[str, Any]:
    path = [part for part in link.split("/") if _PCI.fullmatch(part)]
    pci = path[-1] if path else None
    smart = _data(f"smart.{name}", latest)
    out: dict[str, Any] = {
        "device": name, "pci": pci,
        "attach": _attach(path),
        "model": (str(smart.get("model") or "").strip() or None) if smart else None,
        "mounts": [str(fs.get("mount")) for fs in _rows(_data("disk.fill", latest), "filesystems")
                   if re.fullmatch(re.escape(f"/dev/{name}") + r"p?\d*", str(fs.get("source")))],
        "smart": None if smart is None else {
            **_section(f"smart.{name}", latest, errors, now, stale_after),
            **{k: smart.get(k) for k in ("passed", "temperature_c", "percentage_used",
                                         "media_errors", "critical_warning",
                                         "unsafe_shutdowns", "power_on_hours")}},
        **_section("sensors", latest, errors, now, stale_after),
    }
    chip = _chip(pci) if pci else None
    readings = [(i, r) for i, r in enumerate(_rows(_data("sensors", latest), "readings"))
                if chip is not None and r.get("chip") == chip and r.get("kind") == "temp"]
    own = {str(r.get("label")): min((v for v in (_plausible(r.get("max")),
                                                 _plausible(r.get("crit"))) if v is not None),
                                    default=None) for _, r in readings}
    composite = own.get("Composite")
    temps = []
    for i, r in readings:
        label, limit = str(r.get("label")), own.get(str(r.get("label")))
        series = ("sensors", f"readings.{i}.input")
        if limit is not None:
            temps.append(_reading(label, _num(r.get("input")), limit, "the sensor's own",
                                  series))
        elif composite is not None:
            temps.append(_reading(label, _num(r.get("input")), composite,
                                  "borrowed from the drive's Composite", series, borrowed=True))
        else:
            temps.append({"label": label, "value_c": _num(r.get("input")), "limit_c": None,
                          "series": {"probe": series[0], "field": series[1]}})
    out["temps"] = temps
    if smart is not None:
        out["smart"]["series"] = {"probe": f"smart.{name}", "field": "temperature_c"}
    return out


def _gpus(latest: Latest, errors: Mapping[str, str], now: float,
          stale_after: Callable[[str], float]) -> list[dict[str, Any]]:
    section = _section("gpu", latest, errors, now, stale_after)
    out = []
    for g in _rows(_data("gpu", latest), "gpus"):
        index = g.get("index")
        if not isinstance(index, int) or isinstance(index, bool):
            continue

        def series(field: str, index: int = index) -> dict[str, str]:
            return {"probe": "gpu", "field": f"gpus.{index}.{field}"}

        temp = _num(g.get("temperature_c"))
        out.append({
            **section, "index": index, "name": g.get("name"),
            "temperature": _reading("GPU", temp, GPU_LIMIT_C, "GPU default", None)
            | {"series": series("temperature_c")},
            **{k: g.get(k) for k in ("utilization_pct", "power_w", "power_limit_w",
                                     "memory_used_mib", "memory_total_mib", "pcie_width",
                                     "pcie_width_max", "throttle")},
            "series": {k: series(k) for k in ("utilization_pct", "power_w", "memory_used_mib")},
        })
    return out


def snapshot(latest: Latest, errors: Mapping[str, str], now: float,
             stale_after: Callable[[str], float]) -> dict[str, Any]:
    """The CPU, disks and GPUs from the latest good data per probe (`latest`: probe -> (at,
    data)) and each probe's latest error (`errors`), judged fresh by `stale_after(probe)`."""
    listing = _data("block.devices", latest) or {}
    links = listing.get("links") if isinstance(listing.get("links"), Mapping) else {}
    names = sorted(n for n in listing.get("entries") or [] if isinstance(n, str)
                   and _DISK.fullmatch(n))
    return {"now": now, "cpu": _cpu(latest, errors, now, stale_after),
            "disks": [_disk(n, str(links.get(n, "")), latest, errors, now, stale_after)
                      for n in names],
            "gpus": _gpus(latest, errors, now, stale_after)}


def series_of(hardware: Mapping[str, Any]) -> list[tuple[str, str]]:
    """Every store series a snapshot names, in order, once each."""
    found: list[tuple[str, str]] = []

    def add(s: Any) -> None:
        if isinstance(s, Mapping) and (s.get("probe"), s.get("field")) not in found:
            found.append((s["probe"], s["field"]))

    cpu = hardware["cpu"]
    for t in cpu["temps"]:
        add(t.get("series"))
    add(cpu["load_series"])
    for d in hardware["disks"]:
        for t in d["temps"]:
            add(t.get("series"))
        add((d.get("smart") or {}).get("series"))
    for g in hardware["gpus"]:
        add(g["temperature"]["series"])
        for s in g["series"].values():
            add(s)
    return found


def cpu_util(counters: Mapping[str, Sequence[tuple[float, float]]]) -> list[tuple[float, float]]:
    """Utilisation, %, per bucket from `cpu.stat`'s tick counters: busy ticks over all ticks
    between one bucket and the next. A bucket some counter lacks is skipped, and so is a pair
    whose total did not grow (a reboot resets the counters)."""
    by_t: dict[float, dict[str, float]] = {}
    for name in TICKS:
        for t, v in counters.get(name, ()):
            by_t.setdefault(t, {})[name] = v
    full = sorted((t, row) for t, row in by_t.items() if len(row) == len(TICKS))
    out = []
    for (_, a), (t, b) in pairwise(full):
        total = sum(b.values()) - sum(a.values())
        idle = sum(b[k] - a[k] for k in IDLE_TICKS)
        if total > 0 and 0 <= idle <= total:
            out.append((t, round(100 * (1 - idle / total), 1)))
    return out
