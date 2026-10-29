"""The hardware view: joins by address and name, limits with their source, freshness, and CPU
utilisation from tick counters."""

from __future__ import annotations

from typing import Any

import pytest

from neonwatch.web import hardware

NOW = 1_793_224_000.0
ROOT = "../devices/pci0000:00/0000:00:01.1/0000:01:00.0/nvme/nvme0/nvme0n1"
CHIPSET = ("../devices/pci0000:00/0000:00:01.2/0000:20:00.0/0000:21:00.0/0000:05:00.0/nvme/"
           "nvme1/nvme1n1")


def temp(chip: str, label: str, value: float, max: float | None = None,
         crit: float | None = None) -> dict[str, Any]:
    return {"chip": chip, "label": label, "kind": "temp", "input": value, "max": max,
            "crit": crit, "min": -273.15, "alarm": None, "sensor": "temp1", "adapter": "PCI"}


def host() -> dict[str, tuple[float, dict[str, Any]]]:
    """A typical workstation: the root drive on a CPU port, a second
    drive behind the chipset, two GPUs. The readings are in an order that matches nothing."""
    sensors = {"readings": [
        temp("iwlwifi_1-virtual-0", "temp1", 52.0),
        temp("nvme-pci-0500", "Composite", 48.85, max=84.85, crit=84.85),
        temp("nvme-pci-0500", "Sensor 1", 48.85, max=65261.85),        # the "none" sentinel
        temp("k10temp-pci-00c3", "Tctl", 78.4),
        temp("k10temp-pci-00c3", "Tccd1", 67.3),
        temp("nvme-pci-0100", "Composite", 66.85, max=81.85, crit=84.85),
        temp("nvme-pci-0100", "Sensor 2", 90.85, max=65261.85),
        {"chip": "nct6797-isa-0a20", "label": "fan1", "kind": "fan", "input": 900.0}]}
    return {
        "sensors": (NOW - 30, sensors),
        "load": (NOW - 20, {"load1": 12.5, "load5": 11.0, "load15": 9.0}),
        "cpu.stat": (NOW - 25, {"cpus": 32, "user": 1}),
        "block.devices": (NOW - 600, {"entries": ["loop0", "nvme1n1", "nvme0n1"], "count": 3,
                                      "links": {"loop0": "../devices/virtual/block/loop0",
                                                "nvme0n1": ROOT, "nvme1n1": CHIPSET}}),
        "smart.nvme0n1": (NOW - 900, {"model": "Samsung SSD 980 PRO 2TB ", "passed": True,
                                      "temperature_c": 66, "percentage_used": 4,
                                      "media_errors": 0, "critical_warning": 0,
                                      "unsafe_shutdowns": 11, "power_on_hours": 6120}),
        "disk.fill": (NOW - 40, {"filesystems": [
            {"source": "/dev/nvme0n1p6", "mount": "/"},
            {"source": "/dev/nvme0n1p7", "mount": "/home"},
            {"source": "/dev/nvme10n1p1", "mount": "/not-this-one"},
            {"source": "tmpfs", "mount": "/run"}]}),
        "gpu": (NOW - 30, {"gpus": [
            {"index": 0, "name": "RTX 4090", "temperature_c": 55, "utilization_pct": 0,
             "power_w": 29.1, "power_limit_w": 225.0, "memory_used_mib": 42792,
             "memory_total_mib": 49140, "pcie_width": 4, "pcie_width_max": 16,
             "throttle": ["gpu_idle"]},
            {"index": True, "name": "not a gpu"}]}),
    }


def snap(latest: Any = None, errors: Any = None, after: float = 180.0) -> dict[str, Any]:
    return hardware.snapshot(host() if latest is None else latest, errors or {}, NOW,
                             lambda probe: after)


def by_device(s: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {d["device"]: d for d in s["disks"]}


def test_each_drive_is_joined_to_its_sensors_smart_and_mounts_by_address_and_name():
    disks = by_device(snap())
    assert list(disks) == ["nvme0n1", "nvme1n1"]       # sorted; loop devices are not disks
    root = disks["nvme0n1"]
    assert (root["pci"], root["attach"], root["model"]) == ("0000:01:00.0", "cpu",
                                                            "Samsung SSD 980 PRO 2TB")
    assert root["mounts"] == ["/", "/home"]
    assert [t["label"] for t in root["temps"]] == ["Composite", "Sensor 2"]
    assert root["temps"][0]["series"] == {"probe": "sensors", "field": "readings.5.input"}
    assert root["smart"]["passed"] is True and root["smart"]["unsafe_shutdowns"] == 11
    other = disks["nvme1n1"]
    assert (other["attach"], other["smart"], other["model"]) == ("chipset", None, None)
    assert [t["label"] for t in other["temps"]] == ["Composite", "Sensor 1"]


def test_a_sensor_with_no_limit_of_its_own_is_judged_against_the_drives_composite():
    # A drive's controller sensor can read 86-91 C while it reports no limit of its own.
    composite, controller = by_device(snap())["nvme0n1"]["temps"]
    assert (composite["limit_c"], composite["limit_source"]) == (81.85, "the sensor's own")
    assert "borrowed" not in composite and composite["level"] == "hot"   # 15.0 C of headroom
    assert controller["limit_c"] == 81.85 and controller["borrowed"] is True
    assert controller["limit_source"] == "borrowed from the drive's Composite"
    assert controller["headroom_c"] == -9.0 and controller["level"] == "over"


def test_a_drive_with_no_plausible_limit_anywhere_says_so():
    latest = host()
    readings = [temp("nvme-pci-0100", "Composite", 50.0, max=65261.85, crit=-5.0)]
    latest["sensors"] = (NOW - 30, {"readings": readings})
    (t,) = by_device(snap(latest))["nvme0n1"]["temps"]
    assert t["limit_c"] is None and "level" not in t and t["value_c"] == 50.0


def test_the_cpu_is_its_own_temperatures_against_95_c_with_load_and_count():
    cpu = snap()["cpu"]
    assert [(t["label"], t["limit_c"], t["level"]) for t in cpu["temps"]] == [
        ("Tctl", 95.0, "warm"), ("Tccd1", 95.0, "warm")]
    assert cpu["temps"][0]["headroom_c"] == 16.6
    assert (cpu["load1"], cpu["cpus"]) == (12.5, 32.0)
    assert cpu["stale"] is False and cpu["at"] == NOW - 30


def test_gpus_carry_their_limit_and_the_series_behind_each_figure():
    (g,) = snap()["gpus"]   # a record whose index is not an integer is not a GPU
    assert g["temperature"]["limit_c"] == 90.0 and g["temperature"]["level"] == "cool"
    assert g["temperature"]["series"] == {"probe": "gpu", "field": "gpus.0.temperature_c"}
    assert g["series"]["power_w"] == {"probe": "gpu", "field": "gpus.0.power_w"}
    assert (g["power_w"], g["power_limit_w"], g["pcie_width"]) == (29.1, 225.0, 4)


@pytest.mark.parametrize("value, expected", [
    (95.0, "over"), (99.0, "over"), (90.0, "near"), (89.9, "hot"), (80.0, "hot"),
    (79.9, "warm"), (65.0, "warm"), (64.9, "cool")])
def test_levels_come_from_the_headroom(value, expected):
    assert hardware.level(value, 95.0) == expected


def test_an_old_probe_is_stale_a_missing_one_has_no_time_and_an_error_is_shown():
    latest = host()
    del latest["gpu"]
    s = snap(latest, errors={"gpu": "nvidia-smi: no devices"}, after=25)
    assert s["cpu"]["stale"] is True                  # 30 s old against 25
    assert s["gpus"] == []
    assert by_device(s)["nvme0n1"]["smart"]["stale"] is True
    empty = snap({}, errors={"sensors": "sensors: not found"})
    assert empty["cpu"] == {"probe": "sensors", "at": None, "stale": True,
                            "error": "sensors: not found", "temps": [], "load1": None,
                            "cpus": None, "load_series": {"probe": "load", "field": "load1"}}
    assert empty["disks"] == [] and empty["gpus"] == []


def test_series_of_names_each_store_series_once_in_order():
    found = hardware.series_of(snap())
    assert found[:3] == [("sensors", "readings.3.input"), ("sensors", "readings.4.input"),
                         ("load", "load1")]
    assert ("smart.nvme0n1", "temperature_c") in found
    assert ("gpu", "gpus.0.memory_used_mib") in found
    assert len(found) == len(set(found))


def ticks(t: float, busy: float, idle: float) -> dict[str, list[tuple[float, float]]]:
    return {name: [(t, busy if name == "user" else idle if name == "idle" else 0.0)]
            for name in hardware.TICKS}


def merge(*rows: dict[str, list[tuple[float, float]]]) -> dict[str, list[tuple[float, float]]]:
    out: dict[str, list[tuple[float, float]]] = {}
    for row in rows:
        for name, points in row.items():
            out.setdefault(name, []).extend(points)
    return out


def test_cpu_utilisation_is_busy_ticks_over_all_ticks_between_buckets():
    counters = merge(ticks(0, 100, 900), ticks(60, 400, 1600), ticks(120, 400, 2600))
    assert hardware.cpu_util(counters) == [(60.0, 30.0), (120.0, 0.0)]


def test_cpu_utilisation_skips_incomplete_buckets_and_counter_resets():
    counters = merge(ticks(0, 100, 900), ticks(60, 400, 1600), ticks(120, 10, 10),
                     ticks(180, 60, 60))
    del counters["steal"][1]                           # bucket 60 lacks a counter
    assert hardware.cpu_util(counters) == [(180.0, 50.0)]   # 0 -> 120 shrank: a reboot
    assert hardware.cpu_util({}) == []


def test_a_drive_on_an_intel_chipset_root_port_is_the_chipsets():
    # Intel's PCH puts its root ports on devices 1b-1d of bus 0, directly under the host bridge,
    # so a drive there has the same two-address path as one on a CPU root port.
    assert hardware._attach(["0000:00:1c.4", "0000:05:00.0"]) == "chipset"
    assert hardware._attach(["0000:00:1d.0", "0000:06:00.0"]) == "chipset"
    assert hardware._attach(["0000:00:06.0", "0000:02:00.0"]) == "cpu"         # Intel CPU lanes
    assert hardware._attach(["0000:00:01.1", "0000:01:00.0"]) == "cpu"         # AMD CPU lanes
    assert hardware._attach(["0000:00:01.2", "0000:02:00.2", "0000:03:08.0",
                             "0000:05:00.0"]) == "chipset"                     # AMD, a switch
    assert hardware._attach(["0000:40:1c.0", "0000:41:00.0"]) == "cpu"         # not bus 0
    assert hardware._attach([]) is None
