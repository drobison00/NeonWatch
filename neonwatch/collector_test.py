"""Tests for the privileged observer.

Everything the collector touches is injected: a fake execute that records what it was asked to
run, a fake publish that can fail, a fake process clock and a fixed seed. One test runs the real
executor over two `/proc` reads, which is the only host access here.
"""

from __future__ import annotations

import asyncio
import itertools
import math
import os
import threading
import time
from collections import Counter
from types import SimpleNamespace

import pytest

from neonwatch import collector as collector_module
from neonwatch import executor, schema
from neonwatch.collector import CANARY_PATHS, Collector, phase, write_canary
from neonwatch.config import Budget, Cadence
from neonwatch.executor import NotInCatalog, RawResult
from neonwatch.probes import CATALOG, Tier, frame_files, frame_listing
from neonwatch.schema import Heartbeat, Kind, Observation

BY_ID = {spec.id: spec for spec in CATALOG}
PLAIN = tuple(spec for spec in CATALOG if not spec.devices)
LOADAVG = b"0.10 0.20 0.30 1/200 12345\n"
UPTIME = b"123.45 678.90\n"


class FakeExecute:
    """Records (now, id, devices) per call; returns canned stdout, garbage by default."""

    def __init__(self, outputs=None, cpu_ms=None, raises=None, results=None):
        self.outputs = dict(outputs or {})
        self.cpu_ms = dict(cpu_ms or {})
        self.raises = dict(raises or {})
        self.results = dict(results or {})
        self.calls: list[tuple[float, str, object]] = []
        self.now = 0.0

    def __call__(self, spec, timeout_s, max_bytes, *, devices=None):
        assert timeout_s > 0 and max_bytes > 0
        self.calls.append((self.now, spec.id, devices))
        if spec.id in self.raises:
            raise self.raises[spec.id]
        if spec.id in self.results:
            return self.results[spec.id]
        return RawResult(self.outputs.get(spec.id, b"garbage"), 0, self.cpu_ms.get(spec.id, 1),
                         False)

    def ids(self) -> list[str]:
        return [probe for _, probe, _ in self.calls]


class FakePublish:
    """Fails the first `fail` attempts, then accepts; every accepted event must encode."""

    def __init__(self, fail: int = 0):
        self.fail = fail
        self.events: list[schema.Event] = []
        self.attempts = 0

    async def __call__(self, event: schema.Event) -> int:
        self.attempts += 1
        if self.fail:
            self.fail -= 1
            raise TimeoutError("nats: timeout")
        schema.decode_event(schema.encode_event(event))
        self.events.append(event)
        return len(self.events)

    def observations(self) -> list[Observation]:
        return [schema.from_body(Observation, e.body) for e in self.events
                if e.kind is Kind.OBSERVATION]

    def heartbeats(self) -> list[Heartbeat]:
        return [schema.from_body(Heartbeat, e.body) for e in self.events
                if e.kind is Kind.HEARTBEAT]


DEFAULT_BUDGET, DEFAULT_CADENCE = Budget(), Cadence()


def make(catalog=CATALOG, execute=None, publish=None, *, budget=DEFAULT_BUDGET,
         cadence=DEFAULT_CADENCE,
         seed=7, process_time=None, canary=None, outstanding=None, **kwargs) -> Collector:
    return Collector(catalog, execute if execute is not None else FakeExecute(),
                     publish if publish is not None else FakePublish(), lambda: 0.0,
                     budget, cadence, seed=seed,
                     process_time=process_time or (lambda: 0.0),
                     canary=canary or (lambda: ()), outstanding=outstanding or nothing_stuck,
                     **kwargs)


def nothing_stuck() -> dict[str, int]:
    """A fake `executor.outstanding`: no read or child is stuck inside the executor."""
    return {}


async def simulate(collector: Collector, fake: FakeExecute | None, until: float,
                   start: float = 1000.0) -> list[Observation]:
    """Beat and tick at each wake-up the collector asks for, from `start` through `until`."""
    out = list(await tick(collector, fake, start))
    while (now := min(collector.next_wake(), collector.next_heartbeat())) <= until:
        out += await tick(collector, fake, now)
    return out


async def tick(collector: Collector, fake: FakeExecute | None, now: float):
    """What run_forever's two timers do at `now`: the heartbeat if one is due, then the probes."""
    if fake is not None:
        fake.now = now
    if collector.next_heartbeat() <= now:
        await collector.heartbeat(now)
    return await collector.tick(now)


# --- stagger and cadence -------------------------------------------------------------------


def test_phase_is_stable_distinct_and_in_the_unit_interval():
    phases = [phase(spec.id) for spec in CATALOG]
    assert phases == [phase(spec.id) for spec in CATALOG]
    assert all(0 <= p < 1 for p in phases)
    assert len(set(phases)) == len(phases)
    # Not Python's salted hash: the value is fixed across processes.
    assert phase("load") == int.from_bytes(__import__("hashlib").sha256(b"load").digest()[:8],
                                           "big") / 2**64


async def test_startup_runs_the_whole_catalog_once_spread_over_the_first_fast_period():
    fake = FakeExecute()
    c = make(execute=fake)
    await simulate(c, fake, until=1000.0 + 60 + 1.0 - 1e-9)
    first = {}
    for at, probe, _ in fake.calls:
        first.setdefault(probe, at)
    assert Counter(fake.ids()) == Counter(spec.id for spec in PLAIN)  # the template never runs
    assert all(1000.0 <= at < 1000.0 + 60 + 1.0 for at in first.values())
    assert len(set(first.values())) == len(first)  # never two at one instant
    # Spread, not bunched: the first half of the period has neither all nor none of them.
    early = sum(at < 1030.0 for at in first.values())
    assert 5 < early < len(first) - 5


async def test_the_schedule_is_determined_by_the_seed():
    runs = []
    for seed in (7, 7, 8):
        fake = FakeExecute()
        await simulate(make(execute=fake, seed=seed), fake, until=1400.0)
        runs.append(fake.calls)
    assert runs[0] == runs[1]
    assert runs[0] != runs[2]
    assert [p for _, p, _ in runs[0]] != [] and sorted(runs[0]) != []


async def test_each_tier_runs_at_its_own_cadence_with_bounded_jitter():
    fake = FakeExecute()
    cadence = Cadence()
    await simulate(make(execute=fake, cadence=cadence), fake, until=1000.0 + 2 * 3600)
    times: dict[str, list[float]] = {}
    for at, probe, _ in fake.calls:
        times.setdefault(probe, []).append(at)
    period = {Tier.FAST: cadence.fast, Tier.MEDIUM: cadence.medium, Tier.SLOW: cadence.slow,
              Tier.DAILY: cadence.daily}
    for spec in PLAIN:
        runs = times[spec.id]
        expected = 1 + int(2 * 3600 // period[spec.tier])
        assert abs(len(runs) - expected) <= 1, spec.id
        gaps = [b - a for a, b in itertools.pairwise(runs[1:])]
        assert all(abs(gap - period[spec.tier]) <= 1.0 for gap in gaps), spec.id
    assert len(times["load"]) >= 120 and len(times["ssh.keys.home"]) == 1


async def test_at_most_two_probes_are_in_flight():
    lock = threading.Lock()
    state = {"now": 0, "max": 0}

    def execute(spec, timeout_s, max_bytes, *, devices=None):
        with lock:
            state["now"] += 1
            state["max"] = max(state["max"], state["now"])
        time.sleep(0.2)  # long enough that every run the limit admits overlaps this one
        with lock:
            state["now"] -= 1
        return RawResult(b"x", 0, 1, False)

    catalog = tuple(BY_ID[i] for i in ("load", "uptime", "memory", "vmstat"))
    c = make(catalog, execute)
    assert await c.tick(1000.0) == ()
    out = await c.tick(1000.0 + 61)  # a late tick: all four are due at once
    assert len(out) == 4 and state["max"] == 2


async def test_a_late_tick_runs_each_due_probe_once_not_once_per_missed_period():
    fake = FakeExecute()
    c = make((BY_ID["load"],), fake)
    await simulate(c, fake, until=1061.0)
    before = len(fake.calls)
    await tick(c, fake, 1000.0 + 3600)  # the host slept for an hour
    assert len(fake.calls) == before + 1
    assert 1000.0 + 3600 < c.next_wake() <= 1000.0 + 3600 + 61


async def test_a_clock_that_steps_back_shifts_the_schedule_instead_of_stalling_it():
    fake = FakeExecute()
    c = make((BY_ID["load"],), fake)
    await simulate(c, fake, until=5000.0)
    runs = len(fake.calls)
    await tick(c, fake, 2000.0)  # NTP stepped the wall clock back by ~50 minutes
    assert c.next_wake() <= 2000.0 + 61
    await simulate(c, fake, until=2200.0, start=2000.0)
    assert len(fake.calls) >= runs + 3


# --- device expansion ----------------------------------------------------------------------


async def test_the_smart_template_expands_per_block_device_matching_its_regex():
    fake = FakeExecute(outputs={"block.devices": frame_listing(
        ["loop0", "nvme0n1", "nvme0n1p1", "sda", "sr0", "zram0"])})
    cadence = Cadence(fast=60, medium=120, slow=120, daily=240)
    c = make(execute=fake, cadence=cadence)
    await simulate(c, fake, until=1000.0 + 125)
    smart = [(probe, devices) for _, probe, devices in fake.calls if probe.startswith("smart")]
    assert {probe for probe, _ in smart} == {"smart.nvme0n1", "smart.sda"}
    assert all(sorted(devices) == ["nvme0n1", "sda"] for _, devices in smart)
    assert all(devices is None for _, probe, devices in fake.calls if probe != "smart"
               and not probe.startswith("smart."))

    fake.outputs["block.devices"] = frame_listing(["nvme0n1"])  # sda unplugged
    await simulate(c, fake, until=1000.0 + 600, start=c.next_wake())
    since = [(at, probe) for at, probe, _ in fake.calls if at > 1000.0 + 250]
    assert ("smart.nvme0n1" in {p for _, p in since}) and ("smart.sda" not in {p for _, p in since})


async def test_a_failed_block_devices_read_keeps_the_devices_already_known():
    fake = FakeExecute(outputs={"block.devices": frame_listing(["sda"])})
    cadence = Cadence(fast=60, medium=120, slow=120, daily=240)
    c = make(execute=fake, cadence=cadence)
    await simulate(c, fake, until=1000.0 + 130)
    fake.outputs["block.devices"] = b"not json"
    await simulate(c, fake, until=1000.0 + 600, start=c.next_wake())
    assert [p for at, p, _ in fake.calls if at > 1000.0 + 300].count("smart.sda") >= 2


# --- one run: execute, parse, redact, publish ----------------------------------------------


async def test_a_good_run_publishes_a_parsed_observation():
    fake = FakeExecute(outputs={"load": LOADAVG}, cpu_ms={"load": 3})
    publish = FakePublish()
    c = make((BY_ID["load"],), fake, publish)
    out = await simulate(c, fake, until=1061.0)
    assert out[0] == Observation("load", {"load1": 0.1, "load5": 0.2, "load15": 0.3,
                                          "runnable": 1, "threads": 200, "last_pid": 12345},
                                 3, False, "")
    event = next(e for e in publish.events if e.kind is Kind.OBSERVATION)
    assert (event.subject, event.source) == ("obs.load", "agent")
    assert event.body == schema.to_body(out[0])


async def test_observation_data_is_redacted_before_it_leaves():
    units = (b'[{"unit":"x.service","load":"loaded","active":"failed","sub":"failed",'
             b'"description":"runs with --token=ghp_abcdefghijklmnopqrstuvwx"}]')
    fake = FakeExecute(outputs={"units.failed": units})
    publish = FakePublish()
    c = make((BY_ID["units.failed"],), fake, publish)
    await simulate(c, fake, until=1061.0)
    (obs,) = publish.observations()
    assert "ghp_" not in obs.data["units"][0]["description"]
    assert "[REDACTED]" in obs.data["units"][0]["description"] and obs.error == ""


async def test_a_partly_refused_glob_publishes_what_was_admitted_with_its_warnings():
    key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl bob"
    stdout = frame_files({"/home/bob/.ssh/authorized_keys": key.encode()})
    refused = ("refused /home/alice/.ssh/authorized_keys.bak: a symbolic link (O_NOFOLLOW)",
               "refused /home/carol/.ssh/authorized_keys token=abcd1234efgh5678")
    fake = FakeExecute(results={"ssh.keys.home": RawResult(stdout, 0, 1, False,
                                                              warnings=refused)})
    publish = FakePublish()
    c = make((BY_ID["ssh.keys.home"],), fake, publish)
    (obs,) = await simulate(c, fake, until=1061.0)
    assert obs.error == "" and c.failed == 0
    assert obs.data["count"] == 1 and obs.data["keys"][0]["comment"] == "bob"
    assert obs.data["warnings"][0] == refused[0]
    assert "abcd1234efgh5678" not in obs.data["warnings"][1]  # warnings are redacted too
    assert publish.observations() == [obs]


async def test_an_observation_without_warnings_has_no_warnings_key():
    fake = FakeExecute(results={"load": RawResult(LOADAVG, 0, 1, False)})
    c = make((BY_ID["load"],), fake)
    (obs,) = await simulate(c, fake, until=1061.0)
    assert obs.error == "" and "warnings" not in obs.data


async def test_unparseable_output_publishes_an_error_observation_with_no_data():
    fake = FakeExecute(outputs={"load": b"garbage"})
    publish = FakePublish()
    c = make((BY_ID["load"],), fake, publish)
    (obs,) = await simulate(c, fake, until=1061.0)
    assert obs.data == {} and "loadavg" in obs.error
    assert publish.observations() == [obs] and c.failed == 1 and c.ran == 1


async def test_a_command_that_fails_carries_its_exit_code_and_redacted_stderr():
    failed = RawResult(b"", 1, 2, False, b"Operation not permitted password=hunter22\n")
    fake = FakeExecute(results={"firewall": failed})
    c = make((BY_ID["firewall"],), fake)
    (obs,) = await simulate(c, fake, until=1061.0)
    assert obs.data == {} and "exit 1" in obs.error and "Operation not permitted" in obs.error
    assert "hunter22" not in obs.error and obs.cpu_ms == 2


async def test_an_executor_error_publishes_an_error_observation_without_parsing():
    timed_out = RawResult(b'{"partial', -9, 5, True, b"", "timed out after 30.0s; killed")
    fake = FakeExecute(results={"units.failed": timed_out})
    c = make((BY_ID["units.failed"],), fake)
    (obs,) = await simulate(c, fake, until=1061.0)
    assert obs == Observation("units.failed", {}, 5, True, "timed out after 30.0s; killed")


async def test_a_parser_bug_is_reported_on_that_probe_not_raised(monkeypatch):
    def broken(probe_id, raw):
        raise ZeroDivisionError("parser bug")

    monkeypatch.setattr(collector_module.probes, "parse", broken)
    c = make((BY_ID["load"],), FakeExecute())
    (obs,) = await simulate(c, None, until=1061.0)
    assert obs.data == {} and obs.error == "ZeroDivisionError: parser bug"


async def test_an_execute_that_raises_publishes_an_error_observation():
    fake = FakeExecute(raises={"load": OSError("thread pool gone")})
    publish = FakePublish()
    c = make((BY_ID["load"],), fake, publish)
    (obs,) = await simulate(c, fake, until=1061.0)
    assert obs.data == {} and "thread pool gone" in obs.error and obs.cpu_ms == 0
    assert publish.observations() == [obs]


async def test_not_in_catalog_is_counted_published_and_never_retried(caplog):
    fake = FakeExecute(raises={"load": NotInCatalog("'load' is not in the catalog")},
                       outputs={"uptime": UPTIME})
    publish = FakePublish()
    c = make((BY_ID["load"], BY_ID["uptime"]), fake, publish)
    await simulate(c, fake, until=1000.0 + 600)
    assert fake.ids().count("load") == 1 and fake.ids().count("uptime") >= 10
    assert c.refused == 1 and c.failed == 1
    (obs,) = [o for o in publish.observations() if o.probe == "load"]
    assert "not in the catalog" in obs.error
    assert "not in the catalog" in caplog.text


async def test_an_observation_too_large_to_encode_is_replaced_by_an_error_observation():
    names = [f"entry-{i:07d}-padding-padding" for i in range(40_000)]
    fake = FakeExecute(outputs={"cron.d.names": frame_listing(names)})
    publish = FakePublish()
    c = make((BY_ID["cron.d.names"],), fake, publish)
    (obs,) = await simulate(c, fake, until=1061.0)
    assert obs.data == {} and "not publishable" in obs.error and "byte limit" in obs.error
    assert publish.observations() == [obs]


async def test_the_real_executor_end_to_end_over_proc():
    publish = FakePublish()
    catalog = (BY_ID["load"], BY_ID["uptime"])
    c = Collector(catalog, executor.execute, publish, lambda: 0.0, Budget(), Cadence(), seed=1,
                  canary=lambda: ())
    out = await simulate(c, None, until=1061.0)
    assert {o.probe for o in out} == {"load", "uptime"}
    assert all(o.error == "" and o.data for o in out)
    assert {o.probe for o in publish.observations()} == {"load", "uptime"}


# --- budget --------------------------------------------------------------------------------


def budget_catalog():
    return tuple(BY_ID[i] for i in ("gpu", "load", "units.failed", "processes",
                                    "journal.warnings"))


async def test_spend_counts_child_cpu_and_own_process_time_over_the_window():
    cpu = itertools.chain([0.0], itertools.repeat(0.5))
    fake = FakeExecute(cpu_ms={"gpu": 2000, "load": 999})  # load is in-process: not re-counted
    c = make((BY_ID["gpu"], BY_ID["load"]), fake, process_time=lambda: next(cpu))
    assert c.spend(3600) == 0.0
    await simulate(c, fake, until=1061.0)
    # 2.0 s per run from nvidia-smi's own rusage, plus 0.5 s of this process; load's thread
    # time is part of the 0.5 already.
    spent = 2.0 * fake.ids().count("gpu") + 0.5
    assert fake.ids().count("load") >= 1
    assert c.spend(3600) == pytest.approx(spent / 3600)
    assert c.spend(86400) == pytest.approx(spent / 86400)


async def test_spend_forgets_what_is_older_than_the_window():
    fake = FakeExecute(cpu_ms={"gpu": 3600})
    c = make((BY_ID["gpu"],), fake)
    await simulate(c, fake, until=1000.0 + 61)
    assert c.spend(3600) == pytest.approx(3.6 * len(fake.calls) / 3600)
    await tick(c, fake, 1000.0 + 90000)  # a day and a bit later
    assert c.spend(86400) == pytest.approx(3.6 / 86400)  # only the newest run is in the day


async def test_heavy_probes_defer_first_then_moderate_and_vitals_never():
    budget = Budget(cpu_fraction=0.01)  # 864 CPU s a day
    fake = FakeExecute()
    c = make(budget_catalog(), fake, budget=budget)
    await simulate(c, fake, until=1000.0 + 61)  # everything runs once, cheaply
    assert c.deferred == 0

    # 0.85 of the day's budget spent: heavy probes (journal) defer, moderate ones still run.
    fake.cpu_ms["gpu"] = 734_400
    await simulate(c, fake, until=1000.0 + 121, start=c.next_wake())
    fake.cpu_ms["gpu"] = 1
    fake.calls.clear()
    await simulate(c, fake, until=1000.0 + 700, start=c.next_wake())
    ran = set(fake.ids())
    assert "journal.warnings" not in ran
    assert {"processes", "units.failed", "gpu", "load"} <= ran
    heavy_deferred = c.deferred
    assert heavy_deferred >= 2

    # Past the budget: moderate probes defer too; fast and cheap ones still run.
    fake.cpu_ms["gpu"] = 200_000
    await simulate(c, fake, until=1000.0 + 761, start=c.next_wake())
    fake.cpu_ms["gpu"] = 1
    fake.calls.clear()
    await simulate(c, fake, until=1000.0 + 1400, start=c.next_wake())
    ran = set(fake.ids())
    assert "processes" not in ran and "journal.warnings" not in ran
    assert {"units.failed", "gpu", "load"} <= ran
    assert c.deferred > heavy_deferred


async def test_a_probes_last_cost_counts_towards_the_projection():
    budget = Budget(cpu_fraction=0.01)
    # One run costs 0.46 of the day's budget: under the heavy threshold alone, over it with the
    # next run's expected cost added.
    fake = FakeExecute(cpu_ms={"journal.warnings": 400_000})
    c = make((BY_ID["journal.warnings"],), fake, budget=budget)
    await simulate(c, fake, until=1061.0)
    fake.calls.clear()
    await simulate(c, fake, until=1000.0 + 700, start=c.next_wake())
    assert fake.calls == [] and c.deferred == 2


# --- heartbeats ----------------------------------------------------------------------------


async def test_heartbeats_every_fast_period_carry_spend_confinement_and_counts():
    fake = FakeExecute(outputs={"load": LOADAVG})
    publish = FakePublish()
    canary_calls = []

    def canary():
        canary_calls.append(1)
        return ("/home", "/var")

    c = make((BY_ID["load"], BY_ID["uptime"]), fake, publish, canary=canary)
    await simulate(c, fake, until=1000.0 + 180)
    beats = [e for e in publish.events if e.kind is Kind.HEARTBEAT]
    assert [e.at for e in beats] == [1000.0, 1060.0, 1120.0, 1180.0]
    assert all(e.subject == "hb.agent" and e.source == "agent" for e in beats)
    last = publish.heartbeats()[-1]
    assert last.writable == ("/home", "/var") and last.confined is False
    assert (last.ran, last.failed, last.deferred) == (c.ran, c.failed, c.deferred)
    assert last.ran >= 6 and last.failed >= 3  # uptime returns garbage from the fake
    assert last.cpu_fraction == c.spend(3600)
    assert len(canary_calls) == len(beats)
    first = publish.heartbeats()[0]
    assert (first.ran, first.failed) == (0, 0)


async def test_a_confined_agent_says_so():
    publish = FakePublish()
    c = make((BY_ID["load"],), FakeExecute(), publish, canary=lambda: ())
    await tick(c, None, 1000.0)
    (beat,) = publish.heartbeats()
    assert beat.confined is True and beat.writable == ()


# --- write canary --------------------------------------------------------------------------


def test_the_canary_checks_the_six_system_paths_by_default():
    assert CANARY_PATHS == ("/", "/etc", "/home", "/var", "/usr", "/boot")


def test_the_canary_reports_a_writable_directory(tmp_path):
    before = sorted(os.listdir(tmp_path))
    assert write_canary((tmp_path,)) == (str(tmp_path),)
    assert sorted(os.listdir(tmp_path)) == before  # it wrote nothing


@pytest.mark.skipif(os.geteuid() == 0, reason="root passes every permission check")
def test_the_canary_does_not_report_a_directory_it_cannot_write(tmp_path):
    locked = tmp_path / "locked"
    locked.mkdir()
    locked.chmod(0o555)
    try:
        assert write_canary((locked, tmp_path)) == (str(tmp_path),)
    finally:
        locked.chmod(0o755)


def test_a_read_only_mount_is_not_writable_even_where_access_says_yes(tmp_path):
    def statvfs(path):
        flag = os.ST_RDONLY if str(path) == "/ro" else 0
        return SimpleNamespace(f_flag=flag)

    got = write_canary(("/ro", "/rw"), statvfs=statvfs, access=lambda path, mode: True)
    assert got == ("/rw",)


def test_access_is_asked_about_writing():
    asked = []
    write_canary(("/x",), statvfs=lambda p: SimpleNamespace(f_flag=0),
                 access=lambda path, mode: asked.append(mode) or False)
    assert asked == [os.W_OK]


def test_a_path_the_canary_cannot_examine_counts_as_writable(tmp_path):
    missing = tmp_path / "missing"
    assert write_canary((missing,)) == (str(missing),)


# --- publish buffering ---------------------------------------------------------------------


async def test_failed_publishes_are_retried_in_order_with_capped_exponential_backoff():
    publish = FakePublish(fail=12)
    fake = FakeExecute(outputs={"load": LOADAVG})
    c = make((BY_ID["load"],), fake, publish)
    attempts_at = []
    now = 1000.0
    while publish.fail:
        before = publish.attempts
        await tick(c, fake, now)
        if publish.attempts > before:
            attempts_at.append(now)
        now += 0.25
    gaps = [b - a for a, b in itertools.pairwise(attempts_at)]
    assert gaps[0] == pytest.approx(0.5, abs=0.25)
    assert all(b >= a - 0.25 for a, b in itertools.pairwise(gaps))  # non-decreasing
    assert max(gaps) <= collector_module.BACKOFF_MAX_S + 0.25
    assert max(gaps) >= collector_module.BACKOFF_MAX_S - 0.25  # it reached the cap
    queued = c.queued
    await tick(c, fake, now + 60)
    assert c.queued == 0 and len(publish.events) >= queued
    ats = [e.at for e in publish.events]
    assert ats == sorted(ats) and c.dropped == 0


async def test_a_full_queue_drops_the_oldest_observation_and_keeps_heartbeats():
    publish = FakePublish(fail=10**6)
    fake = FakeExecute(outputs={"load": LOADAVG})
    c = make((BY_ID["load"],), fake, publish, outbox_max=5)
    await simulate(c, fake, until=1000.0 + 180)  # four heartbeats and three observations
    assert fake.ids() == ["load"] * 3
    assert c.queued == 5 and c.dropped == 2
    publish.fail = 0
    c._retry_at = -math.inf
    await c._flush()
    assert [e.at for e in publish.events if e.kind is Kind.HEARTBEAT] == [
        1000.0, 1060.0, 1120.0, 1180.0]
    (kept,) = [e for e in publish.events if e.kind is Kind.OBSERVATION]
    assert kept.at == fake.calls[-1][0]  # the newest observation survived
    assert [e.at for e in publish.events] == sorted(e.at for e in publish.events)


async def test_heartbeats_carry_the_outbox_drop_count_through_an_outage():
    publish = FakePublish(fail=10**6)  # the broker is down
    fake = FakeExecute(outputs={"load": LOADAVG})
    c = make((BY_ID["load"],), fake, publish, outbox_max=5)
    await simulate(c, fake, until=1000.0 + 300)  # long enough to overflow the outbox
    assert c.dropped > 0 and publish.events == []
    lost = c.dropped
    publish.fail = 0  # the broker is back
    await simulate(c, fake, until=1000.0 + 360, start=c.next_wake())
    beats = publish.heartbeats()
    assert c.queued == 0 and beats[0].dropped == 0  # queued before anything was dropped
    counts = [beat.dropped for beat in beats]
    assert counts == sorted(counts)  # cumulative: never goes back
    # The heartbeat queued after the outage carries every drop the outage caused.
    assert beats[-1].dropped == c.dropped == lost
    assert [e.at for e in publish.events if e.kind is Kind.HEARTBEAT][-1] == 1000.0 + 360


async def test_concurrent_flushes_publish_each_event_once_and_in_order():
    gate = asyncio.Event()
    sent = []

    async def slow_publish(event):
        await gate.wait()
        sent.append(event.at)
        return len(sent)

    c = make((BY_ID["load"],), FakeExecute(), slow_publish)
    for n in range(3):
        c._enqueue(schema.Event(Kind.HEARTBEAT, float(n), "agent", "hb.agent", {}))
    first = asyncio.create_task(c._flush())
    await asyncio.sleep(0)
    second = asyncio.create_task(c._flush())  # a run finishing while the first is publishing
    await asyncio.sleep(0)
    gate.set()
    await asyncio.gather(first, second)
    assert sent == [0.0, 1.0, 2.0] and c.queued == 0


async def test_a_queue_of_nothing_but_heartbeats_stays_bounded():
    publish = FakePublish(fail=10**6)
    c = make((BY_ID["load"],), FakeExecute(), publish, outbox_max=2)
    for n in range(4):  # heartbeats only, then an observation
        c._enqueue(schema.Event(Kind.HEARTBEAT, float(n), "agent", "hb.agent", {}))
    c._enqueue(schema.Event(Kind.OBSERVATION, 9.0, "agent", "obs.load", {}))
    assert c.queued == 2 and c.dropped == 3
    publish.fail = 0
    c._retry_at = -math.inf
    await c._flush()
    assert [e.at for e in publish.events] == [2.0, 3.0]


# --- a probe that never returns (security review) ------------------------------------------------


class Hang:
    """An execute where one probe blocks until released; every other probe answers at once."""

    def __init__(self, stuck: str):
        self.stuck, self.release = stuck, threading.Event()
        self.calls: list[str] = []
        self.blocked = 0

    def __call__(self, spec, timeout_s, max_bytes, *, devices=None):
        self.calls.append(spec.id)
        if spec.id == self.stuck:
            self.blocked += 1
            self.release.wait(30)
            self.blocked -= 1
        return RawResult(LOADAVG if spec.id == "load" else b"x", 0, 1, False)


async def test_a_hung_probe_is_abandoned_without_holding_back_the_others():
    hang = Hang("gpu")
    publish = FakePublish()
    c = make((BY_ID["gpu"], BY_ID["load"]), hang, publish, timeout_s=0.05, grace_s=0.05)
    try:
        # A late tick: both are due at once, the hung one first.
        await c.heartbeat(1000.0)
        await c.tick(1000.0)
        out = await c.tick(1000.0 + 61)
        (gpu,) = [o for o in out if o.probe == "gpu"]
        assert gpu.data == {} and "abandoned" in gpu.error
        subjects = [e.subject for e in publish.events if e.kind is Kind.OBSERVATION]
        assert subjects == ["obs.load", "obs.gpu"]  # load was published while gpu hung
        assert c.hung == ("gpu",) and hang.blocked == 1

        # Its next periods publish an error without starting another thread.
        for minute in (2, 3, 4):
            out = await c.tick(1000.0 + 61 * minute)
            (gpu,) = [o for o in out if o.probe == "gpu"]
            assert "still running" in gpu.error
        assert hang.calls.count("gpu") == 1 and hang.blocked == 1
        failed = c.failed
        assert failed == 4
        await c.heartbeat(1000.0 + 300)
        assert publish.heartbeats()[-1].failed == failed
        assert publish.heartbeats()[-1].hung == 1

        hang.release.set()  # the stuck read returns
        for _ in range(200):
            if not c.hung:
                break
            await asyncio.sleep(0.01)
        assert c.hung == ()
        await c.heartbeat(1000.0 + 330)
        assert publish.heartbeats()[-1].hung == 0
        out = await c.tick(1000.0 + 61 * 6)
        (gpu,) = [o for o in out if o.probe == "gpu"]
        assert hang.calls.count("gpu") == 2 and "abandoned" not in gpu.error
    finally:
        hang.release.set()


async def test_a_probe_stuck_inside_the_executor_is_not_started_again_until_it_clears():
    stuck = {"load": 2, "uptime": 0}  # executor.outstanding: probe id -> stuck reads/children
    fake = FakeExecute(outputs={"load": LOADAVG, "uptime": UPTIME})
    publish = FakePublish()
    c = make((BY_ID["load"], BY_ID["uptime"]), fake, publish, outstanding=lambda: dict(stuck))
    await simulate(c, fake, until=1000.0 + 180)
    assert fake.ids().count("load") == 0 and fake.ids().count("uptime") >= 3
    loads = [o for o in publish.observations() if o.probe == "load"]
    assert len(loads) >= 3 and all("still running" in o.error for o in loads)
    assert c.hung == ("load",) and c.failed == len(loads)
    assert publish.heartbeats()[-1].hung == 1  # a zero count is not stuck

    stuck.clear()
    await simulate(c, fake, until=1000.0 + 300, start=c.next_wake())
    assert fake.ids().count("load") >= 1 and c.hung == ()
    assert [o for o in publish.observations() if o.probe == "load"][-1].error == ""
    assert publish.heartbeats()[-1].hung == 0


async def test_hung_counts_a_probe_stuck_in_both_places_once():
    hang = Hang("gpu")
    publish = FakePublish()
    stuck: dict[str, int] = {}
    c = make((BY_ID["gpu"],), hang, publish, timeout_s=0.05, grace_s=0.05,
             outstanding=lambda: dict(stuck))
    try:
        await c.tick(1000.0)
        await c.tick(1000.0 + 61)  # gpu hangs and is abandoned here
        stuck.update({"gpu": 1, "load": 1})  # ...and the executor reports it stuck as well
        await c.heartbeat(1000.0 + 62)
        assert publish.heartbeats()[-1].hung == 2 and c.hung == ("gpu", "load")
        await c.tick(1000.0 + 122)
        assert hang.calls == ["gpu"]
    finally:
        hang.release.set()


def test_the_default_outstanding_is_the_executors():
    c = Collector((BY_ID["load"],), FakeExecute(), FakePublish(), lambda: 0.0, Budget(),
                  Cadence())
    assert c._outstanding_elsewhere is executor.outstanding


async def test_a_hung_probe_delays_neither_heartbeats_nor_other_probes_in_run_forever():
    hang = Hang("gpu")
    publish = FakePublish()
    stop = asyncio.Event()
    # Real time, with every tier at one second, so a hang shows up as a late heartbeat.
    c = Collector((BY_ID["gpu"], BY_ID["load"], BY_ID["uptime"]), hang, publish, time.time,
                  Budget(), Cadence(fast=1, medium=1, slow=1, daily=1), seed=3,
                  canary=lambda: (), timeout_s=0.05, grace_s=0.05, jitter_s=0.05,
                  outstanding=nothing_stuck)
    asyncio.get_running_loop().call_later(3.6, stop.set)
    try:
        await asyncio.wait_for(c.run_forever(stop), timeout=10)
    finally:
        hang.release.set()
    beats = [e.at for e in publish.events if e.kind is Kind.HEARTBEAT]
    assert len(beats) >= 3
    assert all(abs(b - a - 1) < 0.25 for a, b in itertools.pairwise(beats))
    assert hang.calls.count("load") >= 3 and hang.calls.count("uptime") >= 3
    assert hang.calls.count("gpu") == 1  # one thread, however many periods it stays stuck
    gpu = [o for o in publish.observations() if o.probe == "gpu"]
    assert "abandoned" in gpu[0].error and all("still running" in o.error for o in gpu[1:])
    assert publish.heartbeats()[-1].failed >= len(gpu)


# --- run_forever ---------------------------------------------------------------------------


async def test_run_forever_ticks_on_the_injected_clock_until_stopped():
    stop = asyncio.Event()
    times = iter(float(t) for t in range(1000, 10**7, 100))
    publish = FakePublish()
    original = publish.__call__

    async def publish_then_stop(event):
        count = await original(event)
        if len(publish.observations()) >= 6:
            stop.set()
        return count

    c = Collector((BY_ID["load"], BY_ID["uptime"]), FakeExecute(), publish_then_stop,
                  lambda: next(times), Budget(), Cadence(), seed=3, canary=lambda: (),
                  outstanding=nothing_stuck)
    await asyncio.wait_for(c.run_forever(stop), timeout=10)
    assert len(publish.observations()) >= 6 and c.ran >= 6 and publish.heartbeats()


async def test_run_forever_returns_at_once_when_already_stopped():
    stop = asyncio.Event()
    stop.set()
    publish = FakePublish()
    c = make((BY_ID["load"],), FakeExecute(), publish)
    await asyncio.wait_for(c.run_forever(stop), timeout=5)
    assert publish.events == []


async def test_run_forever_sleeps_until_the_next_wake(monkeypatch):
    stop = asyncio.Event()
    waits = []
    real_wait_for = asyncio.wait_for

    async def recording_wait_for(awaitable, timeout):
        waits.append(timeout)
        stop.set()
        return await real_wait_for(awaitable, timeout=1)

    monkeypatch.setattr(collector_module.asyncio, "wait_for", recording_wait_for)
    c = Collector((BY_ID["load"],), FakeExecute(), FakePublish(), lambda: 1000.0, Budget(),
                  Cadence(), seed=3, canary=lambda: (), outstanding=nothing_stuck)
    await c.run_forever(stop)
    assert waits and all(0 < wait <= 61 for wait in waits)


def test_the_collector_is_built_from_catalog_types_only():
    with pytest.raises(TypeError):
        Collector(("load",), FakeExecute(), FakePublish(), lambda: 0.0, Budget(), Cadence())
