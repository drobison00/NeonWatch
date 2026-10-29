"""The Board view's motherboard: a top-down schematic read from a TOML layout, and which slot on it
holds each live part (the CPU, each NVMe drive, each GPU).

`load` reads a layout: a built-in one by name (`BUILTIN`, files in `boards/`) or a TOML file by
path. The schema is closed, like the config's: an unknown key, a kind outside the vocabulary or a
number out of range refuses with a `BoardError` that says where, so a typo is an error rather than
a part silently left off the drawing. Coordinates are millimetres from the board's top-left
corner; `docs/board-layouts.md` describes every key. The result is plain JSON for the page.

`place` is pure. It takes a layout and `hardware.snapshot`'s output and says, for each part key
the page uses (`cpu`, `disk:<device>`, `gpu:<index>`), which slot it is drawn in and whether that
is `assumed`. Software can read where a part's lanes come from but not which physical slot it is
in, so:
  - a slot's `pin` (a part key, or a drive's PCI address) places that part there, not assumed;
  - an NVMe drive otherwise goes to a free M.2 slot with the same `attach` (CPU root port or
    chipset, from the PCI path), in PCI order, assumed when more than one such slot was free;
  - a GPU otherwise goes to a free PCIe slot whose `lanes` equal its current link width, assumed
    when more than one matches; failing that, to the widest free slot, assumed.
A part with nowhere to go is not placed, and the page says so rather than drawing it anywhere.
"""

from __future__ import annotations

import re
import tomllib
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from neonwatch.config import ConfigError

BOARDS = Path(__file__).parent / "boards"
#: The layouts that ship with neonwatch, by the name `web.board` may give.
BUILTIN = ("atx",)
DEFAULT = "atx"
#: Largest layout file read.
MAX_BYTES = 64 * 1024
#: Coordinates and sizes, in mm. A full E-ATX board is 305 x 330.
MAX_MM = 600.0
PART_KINDS = ("io", "vrm", "conn", "audio", "chipset", "dimm", "other")
SLOT_KINDS = ("pcie", "m2")
ATTACH = ("cpu", "chipset")
MAX_TEXT = 200
_NAME = re.compile(r"[A-Za-z0-9_.-]{1,24}")
_PCI = re.compile(r"[0-9a-f]{4}:[0-9a-f]{2}:[0-9a-f]{2}\.[0-7]")
_PIN = re.compile(r"disk:nvme\d+n\d+|gpu:\d+|" + _PCI.pattern)
_SENSOR = re.compile(r"[A-Za-z0-9 _.-]{1,32}")
#: SVG path data, absolute and relative moves and lines only.
_TRACE = re.compile(r"[MLHVZmlhvz0-9 .,-]{1,200}")
_NVME = re.compile(r"nvme\d+n\d+")


class BoardError(ConfigError):
    """A layout that cannot be read or is not valid."""


def load(board: str) -> dict[str, Any]:
    """The layout `board` names: a built-in name, or a path (`~` expanded) to a TOML file."""
    if board in BUILTIN:
        path = BOARDS / f"{board}.toml"
    elif "/" in board or board.endswith(".toml"):
        path = Path(board).expanduser()
    else:
        raise BoardError(f"web.board {board!r} is neither a built-in layout {list(BUILTIN)} "
                         f"nor a path to a .toml file")
    try:
        with path.open("rb") as f:
            raw = f.read(MAX_BYTES + 1)
    except OSError as bad:
        raise BoardError(f"board layout {str(path)!r}: {bad.strerror or bad}") from None
    if len(raw) > MAX_BYTES:
        raise BoardError(f"board layout {str(path)!r} is larger than {MAX_BYTES} bytes")
    try:
        data = tomllib.loads(raw.decode())
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as bad:
        raise BoardError(f"board layout {str(path)!r}: {bad}") from None
    return parse(data, str(path))


def parse(data: Mapping[str, Any], where: str = "layout") -> dict[str, Any]:
    """A validated layout from TOML data, normalised: every optional key present."""
    _keys(where, data, required={"name", "width", "height", "socket"},
          optional={"caption", "holes", "traces", "part", "slot"})
    width = _mm(f"{where}: width", data["width"], positive=True)
    height = _mm(f"{where}: height", data["height"], positive=True)
    socket = _table(f"{where}: socket", data["socket"])
    _keys(f"{where}: socket", socket, required={"x", "y", "w", "h"}, optional={"die"})
    dies = []
    for i, die in enumerate(_tables(f"{where}: socket.die", socket.get("die", []))):
        at = f"{where}: socket.die[{i}]"
        _keys(at, die, required={"sensor", "x", "y", "w", "h"})
        dies.append({"sensor": _text(f"{at}.sensor", die["sensor"], _SENSOR), **_rect(at, die)})
    parts = []
    for i, part in enumerate(_tables(f"{where}: part", data.get("part", []))):
        at = f"{where}: part[{i}]"
        _keys(at, part, required={"kind", "x", "y", "w", "h"},
              optional={"label", "label_at", "no_sensor"})
        parts.append({"kind": _choice(f"{at}.kind", part["kind"], PART_KINDS), **_rect(at, part),
                      "label": _text(f"{at}.label", part.get("label", "")),
                      "label_at": _point(f"{at}.label_at", part["label_at"])
                      if "label_at" in part else None,
                      "no_sensor": _text(f"{at}.no_sensor", part.get("no_sensor", ""))})
    slots: list[dict[str, Any]] = []
    for i, slot in enumerate(_tables(f"{where}: slot", data.get("slot", []))):
        at = f"{where}: slot[{i}]"
        _keys(at, slot, required={"name", "kind", "x", "y", "w", "h"},
              optional={"lanes", "attach", "pin"})
        kind = _choice(f"{at}.kind", slot["kind"], SLOT_KINDS)
        name = _text(f"{at}.name", slot["name"], _NAME)
        if any(s["name"] == name for s in slots):
            raise BoardError(f"{at}.name {name!r} is used by another slot")
        if kind == "pcie" and "lanes" not in slot:
            raise BoardError(f"{at}: a pcie slot needs lanes (its electrical width)")
        if kind == "m2" and "attach" not in slot:
            raise BoardError(f"{at}: an m2 slot needs attach (\"cpu\" or \"chipset\")")
        lanes = slot.get("lanes")
        if lanes is not None and lanes not in (1, 2, 4, 8, 16):
            raise BoardError(f"{at}.lanes must be 1, 2, 4, 8 or 16")
        pin = _text(f"{at}.pin", slot.get("pin", ""), _PIN) if "pin" in slot else ""
        if pin and any(s["pin"] == pin for s in slots):
            raise BoardError(f"{at}.pin {pin!r} is pinned to another slot")
        slots.append({"name": name, "kind": kind, **_rect(at, slot), "lanes": lanes,
                      "attach": _choice(f"{at}.attach", slot["attach"], ATTACH)
                      if "attach" in slot else None, "pin": pin})
    located = [(f"{where}: socket", _rect(f"{where}: socket", socket))]
    located += [(f"{where}: socket.die[{i}]", d) for i, d in enumerate(dies)]
    located += [(f"{where}: part[{i}]", p) for i, p in enumerate(parts)]
    located += [(f"{where}: slot[{i}] ({s['name']})", s) for i, s in enumerate(slots)]
    for at, rect in located:
        _fits(at, rect, width, height)
    return {"name": _text(f"{where}: name", data["name"]), "width": width, "height": height,
            "caption": _text(f"{where}: caption", data.get("caption", "")),
            "holes": [_point(f"{where}: holes[{i}]", h)
                      for i, h in enumerate(_list(f"{where}: holes", data.get("holes", [])))],
            "traces": [_text(f"{where}: traces[{i}]", t, _TRACE)
                       for i, t in enumerate(_list(f"{where}: traces", data.get("traces", [])))],
            "socket": {**_rect(f"{where}: socket", socket), "dies": dies},
            "parts": parts, "slots": slots}


def place(layout: Mapping[str, Any], snapshot: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    """Part key -> `{"slot", "assumed"}` for every part the layout has a place for."""
    out: dict[str, dict[str, Any]] = {"cpu": {"slot": "socket", "assumed": False}}
    slots = list(layout["slots"])
    disks = [d for d in snapshot.get("disks") or [] if _NVME.fullmatch(str(d.get("device")))]
    gpus = list(snapshot.get("gpus") or [])
    keys = {f"disk:{d['device']}": d for d in disks} | {f"gpu:{g['index']}": g for g in gpus}
    taken: set[str] = set()
    for slot in slots:
        pin = slot["pin"]
        key = pin if pin in keys else next(
            (k for k, d in keys.items() if k.startswith("disk:") and d.get("pci") == pin), None)
        if key is not None and key not in out:
            out[key] = {"slot": slot["name"], "assumed": False}
            taken.add(slot["name"])

    def free(kind: str) -> list[dict[str, Any]]:
        return [s for s in slots if s["kind"] == kind and s["name"] not in taken]

    for attach in ATTACH:
        group = sorted((d for d in disks if f"disk:{d['device']}" not in out
                        and (d.get("attach") == "cpu") == (attach == "cpu")),
                       key=lambda d: (str(d.get("pci")), str(d.get("device"))))
        room = [s for s in free("m2") if s["attach"] == attach]
        for disk, slot in zip(group, room, strict=False):
            out[f"disk:{disk['device']}"] = {"slot": slot["name"], "assumed": len(room) > 1}
            taken.add(slot["name"])
    waiting = []
    for gpu in sorted(gpus, key=lambda g: g["index"]):
        key = f"gpu:{gpu['index']}"
        if key in out:
            continue
        match = [s for s in free("pcie") if s["lanes"] == gpu.get("pcie_width")]
        if match:
            out[key] = {"slot": match[0]["name"], "assumed": len(match) > 1}
            taken.add(match[0]["name"])
        else:
            waiting.append(key)
    for key in waiting:
        room = sorted(free("pcie"), key=lambda s: -s["lanes"])
        if room:
            out[key] = {"slot": room[0]["name"], "assumed": True}
            taken.add(room[0]["name"])
    return out


# --- validation ------------------------------------------------------------------------------


def _keys(where: str, table: Mapping[str, Any], *, required: set[str],
          optional: frozenset[str] | set[str] = frozenset()) -> None:
    if missing := sorted(required - set(table)):
        raise BoardError(f"{where} is missing {missing}")
    if unknown := sorted(set(table) - required - set(optional)):
        raise BoardError(f"{where} has unknown key(s) {unknown}")


def _table(where: str, value: Any) -> Mapping[str, Any]:
    if not isinstance(value, dict):
        raise BoardError(f"{where} must be a table")
    return value


def _list(where: str, value: Any) -> list[Any]:
    if not isinstance(value, list) or len(value) > 200:
        raise BoardError(f"{where} must be a list of at most 200 entries")
    return value


def _tables(where: str, value: Any) -> list[Mapping[str, Any]]:
    return [_table(f"{where}[{i}]", v) for i, v in enumerate(_list(where, value))]


def _mm(where: str, value: Any, *, positive: bool = False) -> float:
    if isinstance(value, bool) or not isinstance(value, int | float):
        raise BoardError(f"{where} must be a number (mm)")
    if not (value > 0 if positive else value >= 0) or value > MAX_MM:
        raise BoardError(f"{where} must be {'above' if positive else 'at least'} 0 and at most "
                         f"{MAX_MM:g} mm")
    return float(value)


def _rect(where: str, table: Mapping[str, Any]) -> dict[str, float]:
    return {"x": _mm(f"{where}.x", table["x"]), "y": _mm(f"{where}.y", table["y"]),
            "w": _mm(f"{where}.w", table["w"], positive=True),
            "h": _mm(f"{where}.h", table["h"], positive=True)}


def _fits(where: str, rect: Mapping[str, float], width: float, height: float) -> None:
    """A rectangle inside the board: a typo'd coordinate is refused, not drawn off the edge."""
    if rect["x"] + rect["w"] > width:
        raise BoardError(f"{where} runs off the board: x + w = {rect['x'] + rect['w']:g} is past "
                         f"width {width:g}")
    if rect["y"] + rect["h"] > height:
        raise BoardError(f"{where} runs off the board: y + h = {rect['y'] + rect['h']:g} is past "
                         f"height {height:g}")


def _point(where: str, value: Any) -> list[float]:
    if not isinstance(value, list) or len(value) != 2:
        raise BoardError(f"{where} must be [x, y]")
    return [_mm(f"{where}[0]", value[0]), _mm(f"{where}[1]", value[1])]


def _text(where: str, value: Any, pattern: re.Pattern[str] | None = None) -> str:
    if not isinstance(value, str) or len(value) > MAX_TEXT:
        raise BoardError(f"{where} must be a string of at most {MAX_TEXT} characters")
    if pattern is not None and not pattern.fullmatch(value):
        raise BoardError(f"{where} {value!r} does not match {pattern.pattern}")
    return value


def _choice(where: str, value: Any, allowed: tuple[str, ...]) -> str:
    if value not in allowed:
        raise BoardError(f"{where} must be one of {list(allowed)}, got {value!r}")
    return value
