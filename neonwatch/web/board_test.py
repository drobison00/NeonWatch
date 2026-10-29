"""The board layout: loading and validating a TOML layout, and placing each part in a slot."""

from __future__ import annotations

import copy
from pathlib import Path
from typing import Any

import pytest

from neonwatch.web import board
from neonwatch.web.board import BoardError

EXAMPLES = Path(__file__).resolve().parents[2] / "examples" / "boards"

MINIMAL: dict[str, Any] = {
    "name": "Test board", "width": 244, "height": 305,
    "socket": {"x": 74, "y": 44, "w": 44, "h": 44},
    "slot": [
        {"name": "M2_1", "kind": "m2", "attach": "cpu", "x": 46, "y": 111, "w": 80, "h": 11},
        {"name": "M2_2", "kind": "m2", "attach": "chipset", "x": 46, "y": 158, "w": 80, "h": 11},
        {"name": "M2_3", "kind": "m2", "attach": "chipset", "x": 46, "y": 219, "w": 80, "h": 11},
        {"name": "PCIE1", "kind": "pcie", "lanes": 16, "x": 34, "y": 133, "w": 89, "h": 6},
        {"name": "PCIE3", "kind": "pcie", "lanes": 4, "x": 34, "y": 194, "w": 89, "h": 6},
    ],
}


def layout(**changes: Any) -> dict[str, Any]:
    data = copy.deepcopy(MINIMAL)
    data.update(changes)
    return board.parse(data)


def disk(device: str, pci: str | None, attach: str | None) -> dict[str, Any]:
    return {"device": device, "pci": pci, "attach": attach}


def gpu(index: int, width: int | None) -> dict[str, Any]:
    return {"index": index, "pcie_width": width}


# --- loading ---------------------------------------------------------------------------------


@pytest.mark.parametrize("name", board.BUILTIN)
def test_every_builtin_layout_loads(name: str) -> None:
    found = board.load(name)
    assert found["slots"] and found["width"] > 0
    assert board.DEFAULT in board.BUILTIN


def test_every_example_layout_loads() -> None:
    examples = sorted(EXAMPLES.glob("*.toml"))
    assert examples
    for path in examples:
        assert board.load(str(path))["name"]


def test_a_layout_file_by_path(tmp_path: Path) -> None:
    path = tmp_path / "mine.toml"
    path.write_text('name = "Mine"\nwidth = 170\nheight = 170\n'
                    "[socket]\nx = 60\ny = 30\nw = 40\nh = 40\n")
    found = board.load(str(path))
    assert found == {"name": "Mine", "width": 170.0, "height": 170.0, "caption": "", "holes": [],
                     "traces": [], "socket": {"x": 60.0, "y": 30.0, "w": 40.0, "h": 40.0,
                                              "dies": []},
                     "parts": [], "slots": []}


def test_a_home_relative_path_is_expanded(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    (tmp_path / "b.toml").write_text('name = "B"\nwidth = 1\nheight = 1\n'
                                     "[socket]\nx = 0\ny = 0\nw = 1\nh = 1\n")
    assert board.load("~/b.toml")["name"] == "B"


@pytest.mark.parametrize(("name", "message"), [
    ("eatx", "neither a built-in layout"),
    ("/nonexistent/board.toml", "No such file"),
])
def test_an_unknown_name_or_missing_file_refuses(name: str, message: str) -> None:
    with pytest.raises(BoardError, match=message):
        board.load(name)


def test_a_layout_error_is_a_config_error() -> None:
    from neonwatch.config import ConfigError
    assert issubclass(BoardError, ConfigError)


@pytest.mark.parametrize(("content", "message"), [
    (b"name = ", "board layout"),
    (b"\xff\xfe", "board layout"),
    (b"#" * (board.MAX_BYTES + 1), "larger than"),
])
def test_an_unreadable_file_refuses(tmp_path: Path, content: bytes, message: str) -> None:
    path = tmp_path / "bad.toml"
    path.write_bytes(content)
    with pytest.raises(BoardError, match=message):
        board.load(str(path))


@pytest.mark.parametrize(("changes", "message"), [
    ({"colour": "green"}, r"unknown key\(s\) \['colour'\]"),
    ({"width": 0}, "above 0"),
    ({"width": True}, "must be a number"),
    ({"height": 601}, "at most 600"),
    ({"socket": [1]}, "socket must be a table"),
    ({"socket": {"x": 1, "y": 1, "w": 1}}, r"missing \['h'\]"),
    ({"socket": {"x": -1, "y": 1, "w": 1, "h": 1}}, "at least 0"),
    ({"socket": {"x": 1, "y": 1, "w": 1, "h": 1, "die": [{"sensor": "T;", "x": 1, "y": 1,
                                                          "w": 1, "h": 1}]}}, "does not match"),
    ({"part": [{"kind": "fan", "x": 1, "y": 1, "w": 1, "h": 1}]}, "must be one of"),
    ({"part": [{"kind": "io", "x": 1, "y": 1, "w": 1, "h": 1, "label": 7}]}, "must be a string"),
    ({"part": [{"kind": "io", "x": 1, "y": 1, "w": 1, "h": 1, "label_at": [1]}]}, r"\[x, y\]"),
    ({"part": {"kind": "io"}}, "must be a list"),
    ({"holes": [[1, 2, 3]]}, r"\[x, y\]"),
    ({"traces": ["M0 0 <script>"]}, "does not match"),
    ({"caption": "x" * (board.MAX_TEXT + 1)}, "at most"),
    ({"slot": [{"name": "P1", "kind": "pcie", "x": 1, "y": 1, "w": 1, "h": 1}]}, "needs lanes"),
    ({"slot": [{"name": "M1", "kind": "m2", "x": 1, "y": 1, "w": 1, "h": 1}]}, "needs attach"),
    ({"slot": [{"name": "P1", "kind": "pcie", "lanes": 3, "x": 1, "y": 1, "w": 1, "h": 1}]},
     "1, 2, 4, 8 or 16"),
    ({"slot": [{"name": "M1", "kind": "m2", "attach": "south", "x": 1, "y": 1, "w": 1, "h": 1}]},
     "must be one of"),
    ({"slot": [{"name": "bad name", "kind": "pcie", "lanes": 1, "x": 1, "y": 1, "w": 1, "h": 1}]},
     "does not match"),
    ({"slot": [{"name": "P1", "kind": "pcie", "lanes": 1, "x": 1, "y": 1, "w": 1, "h": 1},
               {"name": "P1", "kind": "pcie", "lanes": 1, "x": 1, "y": 9, "w": 1, "h": 1}]},
     "used by another slot"),
    ({"slot": [{"name": "P1", "kind": "pcie", "lanes": 1, "x": 1, "y": 1, "w": 1, "h": 1,
                "pin": "gpu:0"},
               {"name": "P2", "kind": "pcie", "lanes": 1, "x": 1, "y": 9, "w": 1, "h": 1,
                "pin": "gpu:0"}]}, "pinned to another slot"),
    ({"slot": [{"name": "P1", "kind": "pcie", "lanes": 1, "x": 1, "y": 1, "w": 1, "h": 1,
                "pin": "sda"}]}, "does not match"),
])
def test_an_invalid_layout_refuses_saying_where(changes: dict[str, Any], message: str) -> None:
    with pytest.raises(BoardError, match=message):
        layout(**changes)


# --- placing ---------------------------------------------------------------------------------


def test_the_cpu_is_always_in_the_socket() -> None:
    assert board.place(layout(), {}) == {"cpu": {"slot": "socket", "assumed": False}}


def test_drives_go_to_slots_with_their_attach_in_pci_order() -> None:
    placed = board.place(layout(), {"disks": [
        disk("nvme2n1", "0000:06:00.0", "chipset"), disk("nvme0n1", "0000:01:00.0", "cpu"),
        disk("nvme1n1", "0000:05:00.0", "chipset")]})
    assert placed["disk:nvme0n1"] == {"slot": "M2_1", "assumed": False}
    # Two chipset slots: which drive is in which cannot be read from software.
    assert placed["disk:nvme1n1"] == {"slot": "M2_2", "assumed": True}
    assert placed["disk:nvme2n1"] == {"slot": "M2_3", "assumed": True}


def test_a_drive_of_unknown_attach_counts_as_the_chipsets() -> None:
    placed = board.place(layout(), {"disks": [disk("nvme0n1", None, None)]})
    assert placed["disk:nvme0n1"]["slot"] == "M2_2"


def test_sata_drives_and_drives_with_no_room_are_not_placed() -> None:
    placed = board.place(layout(), {"disks": [
        disk("sda", "0000:03:00.0", "chipset"), disk("nvme0n1", "0000:01:00.0", "cpu"),
        disk("nvme1n1", "0000:02:00.0", "cpu")]})
    assert "disk:sda" not in placed
    assert placed["disk:nvme0n1"]["slot"] == "M2_1"
    assert "disk:nvme1n1" not in placed


def test_a_pin_by_pci_address_or_key_places_the_part_for_certain() -> None:
    slots = copy.deepcopy(MINIMAL["slot"])
    slots[2]["pin"] = "0000:05:00.0"
    slots[4]["pin"] = "gpu:0"
    placed = board.place(layout(slot=slots), {
        "disks": [disk("nvme1n1", "0000:05:00.0", "chipset"),
                  disk("nvme2n1", "0000:06:00.0", "chipset")],
        "gpus": [gpu(0, 16), gpu(1, 16)]})
    assert placed["disk:nvme1n1"] == {"slot": "M2_3", "assumed": False}
    # One chipset slot left, so the other drive's place is no longer a guess.
    assert placed["disk:nvme2n1"] == {"slot": "M2_2", "assumed": False}
    assert placed["gpu:0"] == {"slot": "PCIE3", "assumed": False}
    assert placed["gpu:1"] == {"slot": "PCIE1", "assumed": False}


def test_a_pin_naming_no_present_part_leaves_the_slot_free() -> None:
    slots = copy.deepcopy(MINIMAL["slot"])
    slots[3]["pin"] = "gpu:7"
    placed = board.place(layout(slot=slots), {"gpus": [gpu(0, 16)]})
    assert placed["gpu:0"] == {"slot": "PCIE1", "assumed": False}


def test_gpus_go_to_the_slot_whose_lanes_match_their_link_width() -> None:
    placed = board.place(layout(), {"gpus": [gpu(0, 4), gpu(1, 16)]})
    assert placed["gpu:0"] == {"slot": "PCIE3", "assumed": False}
    assert placed["gpu:1"] == {"slot": "PCIE1", "assumed": False}


def test_a_gpu_matching_several_slots_is_assumed() -> None:
    slots = copy.deepcopy(MINIMAL["slot"])
    slots[4]["lanes"] = 16
    placed = board.place(layout(slot=slots), {"gpus": [gpu(0, 16)]})
    assert placed["gpu:0"] == {"slot": "PCIE1", "assumed": True}


def test_a_gpu_with_no_matching_width_takes_the_widest_free_slot_assumed() -> None:
    placed = board.place(layout(), {"gpus": [gpu(0, 16), gpu(1, None), gpu(2, 8)]})
    assert placed["gpu:0"] == {"slot": "PCIE1", "assumed": False}
    assert placed["gpu:1"] == {"slot": "PCIE3", "assumed": True}
    assert "gpu:2" not in placed


@pytest.mark.parametrize(("changes", "message"), [
    ({"socket": {"x": 230, "y": 44, "w": 44, "h": 44}},
     r"socket runs off the board: x \+ w = 274 is past width 244"),
    ({"part": [{"kind": "io", "x": 0, "y": 300, "w": 10, "h": 10}]},
     r"part\[0\] runs off the board: y \+ h = 310"),
    ({"slot": [{"name": "PCIE1", "kind": "pcie", "lanes": 16, "x": 500, "y": 1, "w": 89, "h": 6}]},
     r"slot\[0\] \(PCIE1\) runs off the board"),
])
def test_anything_drawn_must_fit_on_the_board(changes: dict[str, Any], message: str) -> None:
    with pytest.raises(BoardError, match=message):
        layout(**changes)
