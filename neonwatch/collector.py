"""The privileged observer: runs the closed catalog on a fixed schedule and publishes what it saw.

This runs as root, and everything it does is deterministic and read-only. It takes no input from
anything downstream: the schedule is the catalog and the cadences, the jitter comes from a seeded
generator, and the only thing it sends anywhere is an observation or a heartbeat through the
injected `publish`.

- **Schedule.** Every probe fires at `start + phase(id) * fast + n * period`, plus a jitter below
  `jitter_s` drawn fresh for each run. `phase` is a stable hash of the id, so every probe keeps
  its own position within the fast period whatever its tier, and two probes never share one.
  The first run of every probe falls inside the first fast period, which is the start-up pass
  over the whole catalog. A tick that comes late (the host slept) runs a due probe once, not
  once per missed period. At most `MAX_IN_FLIGHT` probes run at a time, each as its own task
  that publishes as soon as it finishes.
- **A probe that never returns** (a wedged driver, a stuck /sys read) is abandoned after
  `timeout_s + grace_s`: its thread cannot be killed, so it is left to finish, its in-flight
  slot is freed, and an error observation says so. Until that thread returns, each period of
  that probe publishes an error observation instead of starting another thread, so hung runs
  never pile up. The same holds while the executor reports a read or child of that probe still
  outstanding (`executor.outstanding`), since those are invisible from here. Both count in
  `failed`, and `hung` counts the distinct probes blocked either way; every heartbeat carries
  both.
- **Devices.** A template (`smart`) runs once per block device named in the latest successful
  `block.devices` observation that its regex admits, each on its own staggered slot.
- **One run.** execute -> `probes.parse` -> `redact.redact_mapping` -> `Observation`. Whatever
  fails, an observation is published with `error` set and `data` empty; nothing goes silent.
  A read the executor admitted only in part (a GLOB with a refused match) is not a failure: the
  admitted content is published, and the executor's `warnings` go in `data["warnings"]`. A
  spec the executor refuses as not in the catalog is a bug here: it is logged, counted in
  `refused`, and never scheduled again.
- **Budget.** A rolling 24-hour ledger of CPU seconds: the rusage of each command probe's child,
  plus this process's own CPU by `process_time` deltas (which already include the in-process
  file and glob reads, so those are not counted twice). A deferrable probe whose projected day
  (the ledger plus its own last cost, over one day) passes `DEFER_HEAVY_AT` of the budget is
  skipped to its next period if HEAVY, and past `DEFER_MODERATE_AT` if MODERATE. FAST-tier and
  CHEAP probes, and heartbeats, are never deferred.
- **Heartbeat** every fast period on its own timer, independent of `tick`, so no probe can hold
  it back; the first at start. It carries CPU fraction over the last hour, the
  write canary's answer, and cumulative ran / failed / deferred / dropped counts since start,
  each as of when that heartbeat was queued, and `hung`: how many probes have an abandoned run
  still outstanding right then.
- **Publishing** goes through a bounded in-order queue. A failed publish is retried with capped
  exponential backoff, head first, so order holds. When the queue is full the oldest observation
  is dropped, never a heartbeat while an observation remains; the count is `dropped`, and every
  heartbeat carries it.
"""

from __future__ import annotations

import asyncio
import contextlib
import functools
import hashlib
import logging
import math
import os
import random
import re
import time
from collections import deque
from collections.abc import Awaitable, Callable, Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from neonwatch import executor, probes, redact, schema
from neonwatch.config import Budget, Cadence
from neonwatch.executor import NotInCatalog, RawResult
from neonwatch.probes import Cost, Kind, ProbeSpec, Tier
from neonwatch.schema import Heartbeat, Observation

log = logging.getLogger(__name__)

#: The mounts the write canary examines.
CANARY_PATHS = ("/", "/etc", "/home", "/var", "/usr", "/boot")
#: The probe whose `entries` name the block devices a template expands over.
DEVICE_SOURCE = "block.devices"
MAX_IN_FLIGHT = 2
#: Upper bound on the random delay added to each run, seconds.
JITTER_S = 1.0
OUTBOX_MAX = 2000
BACKOFF_MIN_S = 0.5
BACKOFF_MAX_S = 30.0
#: Fractions of the budget at which the projected day defers HEAVY, then MODERATE, probes.
DEFER_HEAVY_AT = 0.8
DEFER_MODERATE_AT = 1.0
DAY_S = 86400.0
#: The window a heartbeat's `cpu_fraction` covers.
HEARTBEAT_WINDOW_S = 3600.0
TIMEOUT_S = 30.0
#: Seconds past `timeout_s` before a run that has not returned is abandoned. The executor's own
#: kill-and-reap of a timed-out command takes up to its KILL_GRACE_S (2 s) beyond the timeout.
GRACE_S = 5.0
MAX_BYTES = 1 << 20
ERROR_CHARS = 500
SOURCE = "agent"

Execute = Callable[..., RawResult]
Publish = Callable[[schema.Event], Awaitable[Any]]


def phase(probe_id: str) -> float:
    """A stable position in [0, 1) for a probe id: the first 64 bits of its SHA-256."""
    return int.from_bytes(hashlib.sha256(probe_id.encode()).digest()[:8], "big") / 2**64


def write_canary(paths: Iterable[str | Path], *, statvfs: Callable[[Any], Any] = os.statvfs,
                 access: Callable[[Any, int], bool] = os.access) -> tuple[str, ...]:
    """The paths this process could write, found without writing anything.

    A path on a read-only mount (`ST_RDONLY`) is not writable; otherwise `access(W_OK)` decides.
    A path that cannot be examined at all counts as writable: confinement is what has to be
    shown, and not being able to look shows nothing.
    """
    writable = []
    for path in paths:
        try:
            read_only = bool(statvfs(path).f_flag & os.ST_RDONLY)
        except OSError:
            writable.append(str(path))
            continue
        if not read_only and access(path, os.W_OK):
            writable.append(str(path))
    return tuple(writable)


@dataclass(slots=True)
class _Slot:
    spec: ProbeSpec
    period: float
    #: The grid time of the next run; `due` is that plus this run's jitter.
    nominal: float
    due: float
    #: The template id this spec was expanded from, or "".
    template: str = ""


class Collector:
    """The scheduler, budget and publisher. Construct once; drive with `run_forever` or `tick`."""

    def __init__(self, catalog: Iterable[ProbeSpec], execute: Execute, publish: Publish,
                 clock: Callable[[], float], budget: Budget, cadence: Cadence, *,
                 seed: int = 0,
                 canary: Callable[[], tuple[str, ...]] | None = None,
                 process_time: Callable[[], float] = time.process_time,
                 timeout_s: float = TIMEOUT_S, max_bytes: int = MAX_BYTES,
                 jitter_s: float = JITTER_S, outbox_max: int = OUTBOX_MAX,
                 grace_s: float = GRACE_S,
                 outstanding: Callable[[], Mapping[str, int]] | None = None):
        self._catalog = tuple(catalog)
        if not all(type(spec) is ProbeSpec for spec in self._catalog):
            raise TypeError("a collector's catalog holds ProbeSpecs only")
        self._execute, self._publish, self._clock = execute, publish, clock
        self._budget, self._process_time = budget, process_time
        self._canary = canary or functools.partial(write_canary, CANARY_PATHS)
        self._timeout_s, self._max_bytes, self._grace_s = timeout_s, max_bytes, grace_s
        #: Probe id -> reads or children the executor itself abandoned and still holds.
        self._outstanding_elsewhere = outstanding or executor.outstanding
        self._jitter_s, self._outbox_max = jitter_s, outbox_max
        self._fast = float(cadence.fast)
        self._period = {Tier.FAST: float(cadence.fast), Tier.MEDIUM: float(cadence.medium),
                        Tier.SLOW: float(cadence.slow), Tier.DAILY: float(cadence.daily)}
        self._templates = tuple(spec for spec in self._catalog if spec.devices)
        self._rng = random.Random(seed)
        self._in_flight = asyncio.Semaphore(MAX_IN_FLIGHT)
        self._flushing = asyncio.Lock()
        #: Probe id -> the thread's future, for runs abandoned before they returned.
        self._outstanding: dict[str, asyncio.Future[RawResult]] = {}
        self._slots: dict[str, _Slot] = {}
        self._devices: dict[str, tuple[str, ...]] = {}
        self._never: set[str] = set()
        self._last_cost: dict[str, float] = {}
        self._ledger: deque[tuple[float, float]] = deque()
        self._outbox: deque[schema.Event] = deque()
        self._start: float | None = None
        self._now = 0.0
        self._cpu_mark = 0.0
        self._heartbeat_due = -math.inf
        self._retry_at = -math.inf
        self._backoff = BACKOFF_MIN_S
        #: Cumulative since start. `refused` counts NotInCatalog bugs; `dropped` queue drops.
        self.ran = self.failed = self.deferred = self.refused = self.dropped = 0

    @property
    def queued(self) -> int:
        """Events waiting to be published."""
        return len(self._outbox)

    @property
    def hung(self) -> tuple[str, ...]:
        """Probes blocked by an abandoned run: a thread here that has not returned, or a read or
        child the executor reports still outstanding."""
        elsewhere = {probe for probe, count in self._outstanding_elsewhere().items() if count > 0}
        return tuple(sorted(elsewhere | set(self._outstanding)))

    # --- the loop --------------------------------------------------------------------------

    async def run_forever(self, stop: asyncio.Event) -> None:
        """Run probes and heartbeats, each on its own timer, until `stop` is set."""
        beats = asyncio.create_task(self._beat_until(stop))
        runs: set[asyncio.Task[Observation]] = set()
        try:
            while not stop.is_set():
                now = self._clock()
                self._prepare(now)
                for run in self._launch(now):
                    runs.add(run)
                    run.add_done_callback(runs.discard)
                await self._flush()
                await self._sleep_until(stop, self.next_wake())
        finally:
            beats.cancel()
            for run in runs:
                run.cancel()
            await asyncio.gather(beats, *runs, return_exceptions=True)

    async def _beat_until(self, stop: asyncio.Event) -> None:
        while not stop.is_set():
            await self.heartbeat(self._clock())
            await self._sleep_until(stop, self._heartbeat_due)

    async def _sleep_until(self, stop: asyncio.Event, when: float) -> None:
        with contextlib.suppress(TimeoutError):
            await asyncio.wait_for(stop.wait(), timeout=max(0.0, when - self._clock()))

    def next_wake(self) -> float:
        """When the next probe or publish retry is due. Heartbeats: `next_heartbeat`."""
        wake = min((slot.due for slot in self._slots.values()), default=math.inf)
        return min(wake, self._retry_at) if self._outbox else wake

    def next_heartbeat(self) -> float:
        """When the next heartbeat is due; before the first, now."""
        return self._heartbeat_due

    async def tick(self, now: float) -> tuple[Observation, ...]:
        """Start every probe due at `now` and return their observations once they finish.

        Each run publishes as soon as it finishes, so a hung one holds back only this return,
        and only until it is abandoned. Heartbeats are not part of a tick: see `heartbeat`.
        """
        self._prepare(now)
        results = await asyncio.gather(*self._launch(now))
        await self._flush()
        return tuple(results)

    async def heartbeat(self, now: float) -> None:
        """Queue a heartbeat stamped `now` and publish."""
        self._prepare(now)
        self._account(0.0)
        self._enqueue(self._event(schema.Kind.HEARTBEAT, "hb.agent", self._heartbeat(), now))
        while self._heartbeat_due <= now:
            self._heartbeat_due += self._fast
        await self._flush()

    def _prepare(self, now: float) -> None:
        if self._start is None:
            self._begin(now)
        elif now < self._now:
            self._shift(now - self._now)
        self._now = now

    def _launch(self, now: float) -> list[asyncio.Task[Observation]]:
        return [asyncio.create_task(self._run(slot, now)) for slot in self._take_due(now)]

    # --- schedule --------------------------------------------------------------------------

    def _begin(self, now: float) -> None:
        self._start = now
        self._cpu_mark = self._process_time()
        self._heartbeat_due = now
        for spec in self._catalog:
            if not spec.devices:
                self._add(spec, now + phase(spec.id) * self._fast)

    def _add(self, spec: ProbeSpec, nominal: float, template: str = "") -> None:
        self._slots[spec.id] = _Slot(spec, self._period[spec.tier], nominal,
                                     nominal + self._jitter(), template)

    def _jitter(self) -> float:
        return self._rng.random() * self._jitter_s

    def _shift(self, delta: float) -> None:
        """Move everything by `delta`: the wall clock stepped back, and waiting would stall."""
        for slot in self._slots.values():
            slot.nominal += delta
            slot.due += delta
        self._heartbeat_due += delta
        self._retry_at += delta
        self._ledger = deque((at + delta, cpu) for at, cpu in self._ledger)

    def _take_due(self, now: float) -> list[_Slot]:
        """The slots to run now, in due order; each due slot moves on to its next period."""
        due = sorted((slot for slot in self._slots.values() if slot.due <= now),
                     key=lambda slot: (slot.due, slot.spec.id))
        runs = []
        for slot in due:
            while slot.nominal <= now:
                slot.nominal += slot.period
            slot.due = slot.nominal + self._jitter()
            if self._defer(slot.spec):
                self.deferred += 1
            else:
                runs.append(slot)
        return runs

    def _expand(self, names: Iterable[str], now: float) -> None:
        """Bring each template's slots in line with the block devices just observed."""
        names = tuple(names)
        assert self._start is not None
        for template in self._templates:
            chosen = tuple(sorted(n for n in names if re.fullmatch(template.devices, n)))
            self._devices[template.id] = chosen
            wanted = {spec.id: spec for spec in probes.expand(template, chosen)}
            for gone in [probe for probe, slot in self._slots.items()
                         if slot.template == template.id and probe not in wanted]:
                del self._slots[gone]
            for probe, spec in wanted.items():
                if probe not in self._slots and probe not in self._never:
                    # The first point after `now` on this probe's own grid in the fast period.
                    anchor = self._start + phase(probe) * self._fast
                    steps = math.floor((now - anchor) / self._fast) + 1
                    self._add(spec, anchor + max(steps, 0) * self._fast, template.id)

    # --- budget ----------------------------------------------------------------------------

    def _defer(self, spec: ProbeSpec) -> bool:
        if spec.tier is Tier.FAST or spec.cost is Cost.CHEAP:
            return False
        at = DEFER_HEAVY_AT if spec.cost is Cost.HEAVY else DEFER_MODERATE_AT
        projected = (self._spent(DAY_S) + self._last_cost.get(spec.id, 0.0)) / DAY_S
        return projected > at * self._budget.cpu_fraction

    def _account(self, child_cpu_s: float) -> None:
        """Book `child_cpu_s` and this process's CPU since the last booking, at the current time."""
        mark = self._process_time()
        self._ledger.append((self._now, child_cpu_s + max(0.0, mark - self._cpu_mark)))
        self._cpu_mark = mark
        while self._ledger and self._ledger[0][0] <= self._now - DAY_S:
            self._ledger.popleft()

    def _spent(self, window_s: float) -> float:
        total = 0.0
        for at, cpu in reversed(self._ledger):
            if at <= self._now - window_s:
                break
            total += cpu
        return total

    def spend(self, window_s: float) -> float:
        """CPU seconds recorded in the last `window_s` seconds, over `window_s` wall seconds."""
        return self._spent(window_s) / window_s

    # --- one run ---------------------------------------------------------------------------

    async def _run(self, slot: _Slot, now: float) -> Observation:
        """One due slot: run it (or report why not), book it, queue it and publish."""
        spec = slot.spec
        if spec.id in self._outstanding:
            observation = Observation(spec.id, {}, 0, False, _clip(
                f"previous run still running: abandoned after "
                f"{self._timeout_s + self._grace_s:g}s and not returned; not started again"))
        elif (stuck := self._outstanding_elsewhere().get(spec.id, 0)) > 0:
            observation = Observation(spec.id, {}, 0, False, _clip(
                f"previous run still running: the executor holds {stuck} abandoned read(s) "
                f"or unreaped child(ren) for it; not started again"))
        else:
            async with self._in_flight:
                observation = await self._execute_bounded(slot, now)
            self.ran += 1
            self._last_cost[spec.id] = observation.cpu_ms / 1000
        self.failed += bool(observation.error)
        child = observation.cpu_ms / 1000 if spec.kind is Kind.COMMAND else 0.0
        self._account(child)
        self._enqueue(self._event(schema.Kind.OBSERVATION, f"obs.{spec.id}", observation, now))
        if spec.id == DEVICE_SOURCE and not observation.error:
            self._expand(observation.data.get("entries", []), now)
        await self._flush()
        return observation

    async def _execute_bounded(self, slot: _Slot, now: float) -> Observation:
        spec = slot.spec
        devices = self._devices.get(slot.template) if slot.template else None
        work = asyncio.ensure_future(asyncio.to_thread(
            self._execute, spec, self._timeout_s, self._max_bytes, devices=devices))
        limit = self._timeout_s + self._grace_s
        try:
            # shield: on timeout the thread runs on, and `work` still says when it returns.
            raw = await asyncio.wait_for(asyncio.shield(work), limit)
        except TimeoutError:
            self._outstanding[spec.id] = work
            work.add_done_callback(functools.partial(self._returned, spec.id))
            log.error("probe %s returned nothing within %gs; its thread is abandoned, and the "
                      "probe will not start again until it returns", spec.id, limit)
            return Observation(spec.id, {}, 0, False, _clip(
                f"no result within {limit:g}s: abandoned; not started again until it returns"))
        except NotInCatalog as bug:
            self.refused += 1
            self._never.add(spec.id)
            self._slots.pop(spec.id, None)
            log.error("the executor refused %s as not in the catalog; this is a collector "
                      "bug, and the probe will not run again: %s", spec.id, bug)
            return Observation(spec.id, {}, 0, False, _clip(f"refused: {bug}"))
        except Exception as failed:
            log.warning("probe %s: execute failed: %r", spec.id, failed)
            return Observation(spec.id, {}, 0, False,
                               _clip(f"execute failed: {type(failed).__name__}: {failed}"))
        observation = _observe(spec.id, raw)
        try:
            schema.encode_event(self._event(schema.Kind.OBSERVATION, f"obs.{spec.id}",
                                            observation, now))
        except (TypeError, ValueError) as unpublishable:  # SchemaError is a ValueError
            observation = Observation(spec.id, {}, raw.cpu_ms, raw.truncated,
                                      _clip(f"observation not publishable: {unpublishable}"))
        return observation

    def _returned(self, probe: str, work: asyncio.Future[RawResult]) -> None:
        self._outstanding.pop(probe, None)
        failed = None if work.cancelled() else work.exception()
        log.warning("the abandoned run of %s has returned%s", probe,
                    f", raising {failed!r}" if failed else "")

    def _heartbeat(self) -> Heartbeat:
        writable = tuple(self._canary())
        return Heartbeat(cpu_fraction=self.spend(HEARTBEAT_WINDOW_S), confined=not writable,
                         writable=writable, ran=self.ran, failed=self.failed,
                         deferred=self.deferred, dropped=self.dropped,
                         hung=len(self.hung))

    def _event(self, kind: schema.Kind, subject: str, record: Any, at: float) -> schema.Event:
        return schema.Event(kind, at, SOURCE, subject, schema.to_body(record))

    # --- publishing ------------------------------------------------------------------------

    def _enqueue(self, event: schema.Event) -> None:
        if len(self._outbox) >= self._outbox_max:
            self.dropped += 1
            oldest = next((i for i, queued in enumerate(self._outbox)
                           if queued.kind is schema.Kind.OBSERVATION), None)
            if oldest is not None:
                del self._outbox[oldest]
            elif event.kind is schema.Kind.OBSERVATION:
                return  # nothing older to drop: this observation is the oldest one
            else:
                self._outbox.popleft()  # all heartbeats: stay bounded, keep the newest
        self._outbox.append(event)

    async def _flush(self) -> None:
        """Publish from the head until the queue is empty or a publish fails.

        One flusher at a time: a second caller returns at once, and the one flushing picks up
        whatever was queued meanwhile, so order holds and nothing is published twice.
        """
        if self._now < self._retry_at or self._flushing.locked():
            return
        async with self._flushing:
            while self._outbox:
                try:
                    await self._publish(self._outbox[0])
                except Exception as failed:
                    log.warning("publish failed, %d queued, retrying in %.1fs: %r",
                                len(self._outbox), self._backoff, failed)
                    self._retry_at = self._now + self._backoff
                    self._backoff = min(2 * self._backoff, BACKOFF_MAX_S)
                    return
                self._outbox.popleft()
                self._backoff = BACKOFF_MIN_S


def _observe(probe: str, raw: RawResult) -> Observation:
    """The observation one raw result makes: parsed and redacted, or an error with no data."""
    if raw.error:
        return Observation(probe, {}, raw.cpu_ms, raw.truncated, _clip(_redacted(raw.error)))
    try:
        parsed = probes.parse(probe, raw.stdout)
        if raw.warnings:  # what a partly refused read left out (security review); not a failure
            parsed = {**parsed, "warnings": list(raw.warnings)}
        data, _ = redact.redact_mapping(parsed)
    except Exception as bad:  # parse promises ParseError only; a parser bug is reported the same
        why = f"{bad}" if isinstance(bad, probes.ParseError) else f"{type(bad).__name__}: {bad}"
        if raw.exit_code:
            stderr = raw.stderr.decode("utf-8", "replace").strip()
            why += f"; exit {raw.exit_code}" + (f": {stderr}" if stderr else "")
        return Observation(probe, {}, raw.cpu_ms, raw.truncated, _clip(_redacted(why)))
    return Observation(probe, data, raw.cpu_ms, raw.truncated, "")


def _redacted(text: str) -> str:
    return redact.redact(text)[0]


def _clip(text: str) -> str:
    return text[:ERROR_CHARS]
