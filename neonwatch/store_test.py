"""Tests for the dashboard's query index. Every database lives in `tmp_path`."""

from __future__ import annotations

import dataclasses
import sqlite3
import stat
from pathlib import Path

import pytest

from neonwatch import store as store_module
from neonwatch.config import Config, Retention
from neonwatch.schema import (
    Analysis,
    Attestation,
    Event,
    Finding,
    Heartbeat,
    Issue,
    IssueState,
    Kind,
    Link,
    Observation,
    SchemaError,
    Severity,
    to_body,
)
from neonwatch.store import (
    DomainSummary,
    Incident,
    LogExplanation,
    Point,
    ServiceDescription,
    Store,
    StoreError,
)

# --- helpers --------------------------------------------------------------------------------


def config(max_age_s: int = 7 * 86400, max_bytes: int = 10 * 1024**3) -> Config:
    return Config(retention=Retention(max_age_s=max_age_s, max_bytes=max_bytes))


@pytest.fixture
def db(tmp_path: Path) -> Store:
    s = Store(tmp_path / "store.sqlite3", config())
    yield s
    s.close()


def obs_event(probe: str, data: dict, at: float, cpu_ms: int = 3, error: str = "") -> Event:
    body = to_body(Observation(probe=probe, data=data, cpu_ms=cpu_ms, error=error))
    return Event(Kind.OBSERVATION, at, "agent", f"obs.{probe}", body)


def finding(rule: str = "disk.full", entity: str = "disk:/", severity=Severity.WARN,
            title: str = "disk filling") -> Finding:
    return Finding(rule=rule, severity=severity, title=title, entity=entity,
                   evidence={"used": 0.93})


def finding_event(f: Finding, at: float) -> Event:
    return Event(Kind.FINDING, at, "rules", f"finding.{f.rule}", to_body(f))


def attestation(context: str = "ctx1", question: str = "q1", domain: str = "disk",
                severity=Severity.WATCH) -> Attestation:
    return Attestation(context=context, context_kind="disk", domain=domain, entity="disk:/",
                       question=question, instructions="judge", answer={"label": "x"},
                       severity=severity, cause="c", next_step="n", confidence=0.8,
                       stable=None, latency_ms=12)


def attest_event(a: Attestation, at: float) -> Event:
    return Event(Kind.ATTESTATION, at, "judge", f"attest.{a.context}", to_body(a))


def issue(id: str = "i1", state=IssueState.OPEN, severity=Severity.WARN, score: float = 1.0,
          updated_at: float = 100.0, domain: str = "disk") -> Issue:
    return Issue(id=id, state=state, severity=severity, title=f"issue {id}", domain=domain,
                 entity="disk:/", opened_at=50.0, updated_at=updated_at, deterministic=True,
                 reasons=("disk.full",), next_step="clean up", score=score)


def issue_event(i: Issue, at: float | None = None) -> Event:
    return Event(Kind.ISSUE, i.updated_at if at is None else at, "evaluator",
                 f"issue.{i.id}", to_body(i))


def heartbeat(ran: int = 10) -> Heartbeat:
    return Heartbeat(cpu_fraction=0.004, confined=True, writable=(), ran=ran, failed=0,
                     deferred=0)


def hb_event(h: Heartbeat, at: float) -> Event:
    return Event(Kind.HEARTBEAT, at, "agent", "hb.agent", to_body(h))


def count(s: Store, table: str) -> int:
    return s._db.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]


# --- opening --------------------------------------------------------------------------------


def test_creates_a_wal_database_with_a_version(tmp_path: Path) -> None:
    path = tmp_path / "nested" / "store.sqlite3"
    s = Store(path, config())
    s.close()
    raw = sqlite3.connect(path)
    assert raw.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
    assert raw.execute("PRAGMA auto_vacuum").fetchone()[0] == 2  # incremental
    assert raw.execute("SELECT value FROM meta WHERE key='schema_version'").fetchone()[0] == \
        store_module.VERSION
    raw.close()


def test_new_database_is_private_to_its_owner(tmp_path: Path) -> None:
    path = tmp_path / "store.sqlite3"
    Store(path, config()).close()
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_reopening_keeps_what_was_written(tmp_path: Path) -> None:
    path = tmp_path / "store.sqlite3"
    s = Store(path, config())
    s.apply(obs_event("load", {"one": 1.5}, at=10))
    s.apply(issue_event(issue()))
    s.close()
    again = Store(path, config())
    assert again.latest() == ((10.0, Observation("load", {"one": 1.5}, 3)),)
    assert again.issue("i1") == issue()
    again.close()


def test_refuses_a_newer_schema_version(tmp_path: Path) -> None:
    path = tmp_path / "store.sqlite3"
    Store(path, config()).close()
    raw = sqlite3.connect(path)
    raw.execute("UPDATE meta SET value=? WHERE key='schema_version'", (store_module.VERSION + 1,))
    raw.commit()
    raw.close()
    with pytest.raises(StoreError, match="newer"):
        Store(path, config())


def test_refuses_an_older_schema_version_it_cannot_migrate(tmp_path: Path) -> None:
    path = tmp_path / "store.sqlite3"
    Store(path, config()).close()
    raw = sqlite3.connect(path)
    raw.execute("UPDATE meta SET value=0 WHERE key='schema_version'")
    raw.commit()
    raw.close()
    with pytest.raises(StoreError, match="migrat"):
        Store(path, config())


def test_refuses_a_meta_table_without_a_version(tmp_path: Path) -> None:
    path = tmp_path / "store.sqlite3"
    Store(path, config()).close()
    raw = sqlite3.connect(path)
    raw.execute("DELETE FROM meta")
    raw.commit()
    raw.close()
    with pytest.raises(StoreError, match="version"):
        Store(path, config())


def test_refuses_a_database_that_is_not_a_store(tmp_path: Path) -> None:
    path = tmp_path / "other.sqlite3"
    raw = sqlite3.connect(path)
    raw.execute("CREATE TABLE something_else(x)")
    raw.commit()
    raw.close()
    with pytest.raises(StoreError, match="not a neonwatch store"):
        Store(path, config())
    raw = sqlite3.connect(path)
    names = {r[0] for r in raw.execute("SELECT name FROM sqlite_master")}
    raw.close()
    assert names == {"something_else"}  # nothing was added to it


def test_refuses_a_file_that_is_not_sqlite(tmp_path: Path) -> None:
    path = tmp_path / "junk.sqlite3"
    path.write_bytes(b"this is not a database, it is text " * 100)
    with pytest.raises(StoreError, match="cannot open"):
        Store(path, config())


def test_refuses_a_database_that_cannot_run_in_wal_mode(tmp_path: Path, monkeypatch) -> None:
    class NoWal(sqlite3.Connection):
        """A connection whose journal mode request is ignored, as on a VFS without WAL."""

        def execute(self, sql, *args):
            if sql.replace(" ", "").upper().startswith("PRAGMAJOURNAL_MODE="):
                return super().execute("PRAGMA journal_mode")
            return super().execute(sql, *args)

    real = sqlite3.connect
    monkeypatch.setattr(sqlite3, "connect", lambda *a, **k: real(*a, factory=NoWal, **k))
    with pytest.raises(StoreError, match="WAL"):
        Store(tmp_path / "store.sqlite3", config())


# --- apply: strict refusal ------------------------------------------------------------------


@pytest.mark.parametrize("kind,subject", [
    (Kind.OBSERVATION, "obs.x"), (Kind.FINDING, "finding.x"), (Kind.ATTESTATION, "attest.x"),
    (Kind.ISSUE, "issue.x"), (Kind.HEARTBEAT, "hb.agent"), (Kind.LINK, "link.x"),
])
def test_a_body_that_does_not_decode_is_refused(db: Store, kind: Kind, subject: str) -> None:
    with pytest.raises(SchemaError):
        db.apply(Event(kind, 1.0, "src", subject, {"not_a_field": 1}))
    for table in store_module.TABLES:
        if table != "meta":
            assert count(db, table) == 0, table


def test_an_unknown_kind_is_refused(db: Store) -> None:
    with pytest.raises(SchemaError, match="kind"):
        db.apply(Event("gossip", 1.0, "src", "gossip.x", {}))  # type: ignore[arg-type]


def test_a_body_that_cannot_be_stored_is_refused_whole(db: Store) -> None:
    body = {"probe": "p", "data": {"fine": 1, "bad": {1, 2}}, "cpu_ms": 1}
    with pytest.raises(SchemaError, match="JSON"):
        db.apply(Event(Kind.OBSERVATION, 1.0, "agent", "obs.p", body))
    assert db.latest() == ()
    assert count(db, "series") == 0


def test_a_failure_mid_write_leaves_nothing_behind(db: Store, monkeypatch) -> None:
    def broken(*_args):
        raise sqlite3.OperationalError("disk I/O error")

    monkeypatch.setattr(store_module, "_flatten", broken)
    with pytest.raises(sqlite3.OperationalError):
        db.apply(obs_event("load", {"one": 1.0}, at=5))
    assert db.latest() == ()


# --- observations and series ----------------------------------------------------------------


def test_observation_upserts_latest_per_probe(db: Store) -> None:
    db.apply(obs_event("load", {"one": 1.0}, at=10))
    db.apply(obs_event("load", {"one": 2.0}, at=20))
    db.apply(obs_event("mem", {}, at=15, error="permission denied"))
    db.apply(obs_event("cpu", {"n": 8}, at=20))
    # Newest first, so a stale probe sorts last and carries the time it last reported.
    assert db.latest() == ((20.0, Observation("cpu", {"n": 8}, 3)),
                           (20.0, Observation("load", {"one": 2.0}, 3)),
                           (15.0, Observation("mem", {}, 3, error="permission denied")))
    assert db.latest("mem") == ((15.0, Observation("mem", {}, 3, error="permission denied")),)
    assert db.latest("nope") == ()


def test_an_older_observation_does_not_replace_a_newer_one(db: Store) -> None:
    db.apply(obs_event("load", {"one": 2.0}, at=20))
    db.apply(obs_event("load", {"one": 1.0}, at=10))
    assert db.latest("load") == ((20.0, Observation("load", {"one": 2.0}, 3)),)
    assert len(db.series("load", "one", since=0, step_s=1)) == 2  # history still takes it


def test_series_flattens_nested_numbers_and_skips_the_rest(db: Store) -> None:
    data = {"pressure": {"memory": {"some_avg10": 0.5, "full": {"avg60": 2}}},
            "name": "x", "ok": True, "list": [1, 2], "nan": float("nan"),
            "inf": float("inf"), "huge": 10**400, "count": 7}
    db.apply(obs_event("psi", data, at=60))
    fields = {r[0] for r in db._db.execute("SELECT field FROM series")}
    assert fields == {"pressure.memory.some_avg10", "pressure.memory.full.avg60", "count"}
    assert db.series("psi", "pressure.memory.some_avg10", 0, 60) == (Point(60.0, 0.5),)


def _fields(db: Store, probe: str) -> dict[str, float]:
    return dict(db._db.execute("SELECT field, value FROM series WHERE probe = ?", (probe,)))


def test_series_names_gpu_list_elements_by_index(db: Store) -> None:
    # The `gpu` probe's shape (docs/probes.md): one object per GPU, keyed by nvidia-smi index.
    gpu = {"gpus": [
        {"index": 0, "name": "NVIDIA GeForce RTX 4090", "temperature_c": 54,
         "power_w": 71.3, "power_limit_w": 300.0, "memory_used_mib": 20480,
         "memory_total_mib": 49140, "utilization_pct": 37, "throttle_reasons": 0,
         "throttle": [], "pcie_width": 16, "pcie_width_max": 16},
        {"index": 1, "name": "NVIDIA RTX A2000", "temperature_c": None, "power_w": None,
         "power_limit_w": 140.0, "memory_used_mib": 5, "memory_total_mib": 16376,
         "utilization_pct": 0, "throttle_reasons": 1, "throttle": ["gpu_idle"],
         "pcie_width": 8, "pcie_width_max": 16},
    ], "count": 2}
    db.apply(obs_event("gpu", gpu, at=60))
    assert _fields(db, "gpu") == {
        "gpus.0.temperature_c": 54.0, "gpus.0.power_w": 71.3, "gpus.0.power_limit_w": 300.0,
        "gpus.0.memory_used_mib": 20480.0, "gpus.0.memory_total_mib": 49140.0,
        "gpus.0.utilization_pct": 37.0, "gpus.0.throttle_reasons": 0.0,
        "gpus.0.pcie_width": 16.0, "gpus.0.pcie_width_max": 16.0,
        "gpus.1.power_limit_w": 140.0, "gpus.1.memory_used_mib": 5.0,
        "gpus.1.memory_total_mib": 16376.0, "gpus.1.utilization_pct": 0.0,
        "gpus.1.throttle_reasons": 1.0, "gpus.1.pcie_width": 8.0, "gpus.1.pcie_width_max": 16.0,
        "count": 2.0,
    }
    assert db.series("gpu", "gpus.0.temperature_c", since=0, step_s=60) == (Point(60.0, 54.0),)


def test_series_names_filesystems_by_mount_whatever_their_order(db: Store) -> None:
    # The `disk.fill` probe's shape (docs/probes.md), in df order.
    root = {"source": "/dev/nvme0n1p6", "fstype": "ext4", "mount": "/",
            "size_bytes": 500107862016, "used_bytes": 290000000000,
            "avail_bytes": 184000000000, "used_pct": 61.18, "inodes": 30531584,
            "inodes_used": 2154321, "inodes_used_pct": 7.06}
    efi = {"source": "/dev/nvme0n1p1", "fstype": "vfat", "mount": "/boot/efi",
           "size_bytes": 535805952, "used_bytes": 6406144, "avail_bytes": 529399808,
           "used_pct": 1.2, "inodes": 0, "inodes_used": 0, "inodes_used_pct": None}
    home = {"source": "/dev/nvme1n1p1", "fstype": "ext4", "mount": "/home",
            "size_bytes": 2000000000000, "used_bytes": 1500000000000,
            "avail_bytes": 400000000000, "used_pct": 78.95, "inodes": 122101760,
            "inodes_used": 3000000, "inodes_used_pct": 2.46}
    db.apply(obs_event("disk.fill", {"filesystems": [root, efi, home], "count": 3}, at=60))
    # A mount appearing or disappearing reorders df output; the names must not move.
    db.apply(obs_event("disk.fill", {"filesystems": [home, root], "count": 2}, at=120))
    fields = _fields(db, "disk.fill")
    assert {"filesystems./.used_pct", "filesystems./home.used_pct",
            "filesystems./boot/efi.used_pct", "filesystems./.inodes_used_pct"} <= set(fields)
    assert "filesystems./boot/efi.inodes_used_pct" not in fields  # null
    assert not any(name.endswith((".source", ".fstype", ".mount")) for name in fields)
    assert db.series("disk.fill", "filesystems./home.used_pct", 0, 60) == (
        Point(60.0, 78.95), Point(120.0, 78.95))
    assert db.series("disk.fill", "filesystems./.used_pct", 0, 60) == (
        Point(60.0, 61.18), Point(120.0, 61.18))


def test_series_list_identity_rules(db: Store) -> None:
    data = {
        "keyed": [{"index": 3, "name": "b", "v": 1}],           # index beats name
        "named": [{"name": "eth0", "id": "x", "v": 2}],         # name beats id
        "by_id": [{"id": "c1", "v": 3}],
        "by_device": [{"device": "nvme0", "mount": None, "v": 4}],  # null identity is skipped
        "anonymous": [{"v": 5}, {"v": 6}],                      # no identity: position
        "dupes": [{"name": "a", "v": 7}, {"name": "a", "v": 8}],  # first occurrence wins
        "scalars": [1, 2, 3],
        "mixed": [9, {"name": "m", "v": 10}, [11]],
        "flagged": [{"name": True, "v": 12}],                   # a bool is not an identity
        "nested": [{"name": "outer", "inner": [{"index": 0, "v": 13}]}],
    }
    db.apply(obs_event("shapes", data, at=1))
    assert _fields(db, "shapes") == {
        "keyed.3.v": 1.0, "named.eth0.v": 2.0, "by_id.c1.v": 3.0, "by_device.nvme0.v": 4.0,
        "anonymous.0.v": 5.0, "anonymous.1.v": 6.0, "dupes.a.v": 7.0, "mixed.m.v": 10.0,
        "flagged.0.v": 12.0, "nested.outer.inner.0.v": 13.0,
    }


def test_the_field_cap_applies_after_flattening_lists(db: Store) -> None:
    data = {"a": 1, "rows": [{"id": f"r{n:03d}", "v": n} for n in range(300)], "z": 2}
    db.apply(obs_event("wide", data, at=1))
    fields = _fields(db, "wide")
    assert len(fields) == store_module.MAX_FIELDS
    assert "a" in fields and "rows.r198.v" in fields
    assert "rows.r199.v" not in fields and "z" not in fields  # traversal order


def test_series_caps_fields_per_observation(db: Store) -> None:
    data = {f"f{i:03d}": i for i in range(store_module.MAX_FIELDS + 50)}
    db.apply(obs_event("wide", data, at=1))
    assert count(db, "series") == store_module.MAX_FIELDS


def test_replaying_an_observation_does_not_duplicate_its_points(db: Store) -> None:
    event = obs_event("load", {"one": 1.0}, at=10)
    db.apply(event)
    db.apply(event)
    assert count(db, "series") == 1


def test_series_averages_per_step_aligned_to_the_epoch(db: Store) -> None:
    for t, v in [(0, 1.0), (10, 2.0), (29, 3.0), (30, 10.0), (95, 7.0), (200, 99.0)]:
        db.apply(obs_event("load", {"one": v}, at=t))
    db.apply(obs_event("other", {"one": 500.0}, at=10))
    assert db.series("load", "one", since=0, step_s=30) == (
        Point(0.0, 2.0), Point(30.0, 10.0), Point(90.0, 7.0), Point(180.0, 99.0))
    # `since` filters points, not buckets: the 0-30 bucket keeps only t=10 and t=29.
    assert db.series("load", "one", since=10, step_s=30)[0] == Point(0.0, 2.5)
    assert db.series("load", "missing", since=0, step_s=30) == ()


def test_series_refuses_a_non_positive_step(db: Store) -> None:
    with pytest.raises(ValueError, match="step_s"):
        db.series("load", "one", since=0, step_s=0)


# --- findings, attestations, heartbeats -----------------------------------------------------


def test_findings_keep_history_and_latest_per_rule_and_entity(db: Store) -> None:
    db.apply(finding_event(finding(severity=Severity.WARN), at=10))
    db.apply(finding_event(finding(severity=Severity.CRITICAL), at=20))
    db.apply(finding_event(finding(entity="disk:/home"), at=15))
    assert db.findings() == ((20.0, finding(severity=Severity.CRITICAL)),
                             (15.0, finding(entity="disk:/home")),
                             (10.0, finding(severity=Severity.WARN)))
    assert db.findings(since=15) == db.findings()[:2]
    assert db.findings(latest=True) == ((20.0, finding(severity=Severity.CRITICAL)),
                                        (15.0, finding(entity="disk:/home")))
    db.apply(finding_event(finding(severity=Severity.INFO), at=5))  # late arrival
    assert db.findings(latest=True)[0] == (20.0, finding(severity=Severity.CRITICAL))
    assert len(db.findings()) == 4


def test_attestations_filter_by_context_question_and_time(db: Store) -> None:
    a1, a2, a3 = attestation("c1", "q1"), attestation("c1", "q2"), attestation("c2", "q1")
    db.apply(attest_event(a1, at=10))
    db.apply(attest_event(a2, at=20))
    db.apply(attest_event(a3, at=30))
    later = dataclasses.replace(a1, severity=Severity.WARN)
    db.apply(attest_event(later, at=40))
    assert [at for at, _ in db.attestations()] == [40.0, 30.0, 20.0, 10.0]
    assert db.attestations(context="c1", question="q1") == ((40.0, later), (10.0, a1))
    assert db.attestations(question="q1", since=30) == ((40.0, later), (30.0, a3))
    # Current: from c1's latest ask (at 40), so q2, asked only at 20, is no longer current.
    assert db.attestations(context="c1", latest=True) == ((40.0, later),)
    assert db.attestations(latest=True) == ((40.0, later), (30.0, a3))
    db.apply(attest_event(a1, at=1))  # late arrival
    assert db.attestations(context="c1", question="q1", latest=True) == ((40.0, later),)


def test_last_heartbeat_is_the_newest(db: Store) -> None:
    assert db.last_heartbeat() is None
    db.apply(hb_event(heartbeat(ran=2), at=20))
    db.apply(hb_event(heartbeat(ran=1), at=10))
    assert db.last_heartbeat() == (20.0, heartbeat(ran=2))


# --- issues ---------------------------------------------------------------------------------


def test_issues_upsert_by_id_and_order_by_score_then_recency(db: Store) -> None:
    db.apply(issue_event(issue("a", score=1.0, updated_at=100)))
    db.apply(issue_event(issue("b", score=5.0, updated_at=100)))
    db.apply(issue_event(issue("c", score=1.0, updated_at=200)))
    db.apply(issue_event(issue("d", score=9.0, state=IssueState.RESOLVED, updated_at=50)))
    db.apply(issue_event(issue("a", score=2.0, updated_at=150)))
    assert [i.id for i in db.issues()] == ["d", "b", "a", "c"]
    assert [i.id for i in db.issues(IssueState.OPEN)] == ["b", "a", "c"]
    assert db.issue("a").score == 2.0
    assert db.issue("zzz") is None


def test_a_stale_issue_event_is_ignored(db: Store) -> None:
    db.apply(issue_event(issue(state=IssueState.RESOLVED, updated_at=200)))
    db.apply(issue_event(issue(state=IssueState.OPEN, updated_at=100)))
    assert db.issue("i1").state is IssueState.RESOLVED


def test_ack_holds_until_severity_escalates(db: Store) -> None:
    db.apply(issue_event(issue(severity=Severity.WARN, updated_at=100)))
    acked = db.ack("i1", at=110)
    assert acked.state is IssueState.ACKNOWLEDGED
    assert db.issues(IssueState.ACKNOWLEDGED) == (acked,)
    db.apply(issue_event(issue(severity=Severity.WARN, score=3.0, updated_at=120)))
    assert db.issue("i1").state is IssueState.ACKNOWLEDGED
    assert db.issue("i1").score == 3.0  # the evaluator's other fields still update
    db.apply(issue_event(issue(severity=Severity.WATCH, updated_at=130)))
    assert db.issue("i1").state is IssueState.ACKNOWLEDGED
    # Back to WARN is not an escalation over what the operator acknowledged.
    db.apply(issue_event(issue(severity=Severity.WARN, updated_at=140)))
    assert db.issue("i1").state is IssueState.ACKNOWLEDGED
    db.apply(issue_event(issue(severity=Severity.CRITICAL, updated_at=150)))
    assert db.issue("i1").state is IssueState.OPEN
    # Once reopened, the hold is gone: a later same-severity event stays open.
    db.apply(issue_event(issue(severity=Severity.CRITICAL, updated_at=160)))
    assert db.issue("i1").state is IssueState.OPEN


def test_snooze_holds_until_it_lapses_or_escalates(db: Store) -> None:
    db.apply(issue_event(issue(severity=Severity.WARN, updated_at=100)))
    assert db.snooze("i1", until=300).state is IssueState.SNOOZED
    db.apply(issue_event(issue(updated_at=200)))
    assert db.issue("i1").state is IssueState.SNOOZED
    db.apply(issue_event(issue(updated_at=300)))
    assert db.issue("i1").state is IssueState.OPEN

    db.apply(issue_event(issue("j", severity=Severity.WATCH, updated_at=100)))
    db.snooze("j", until=10_000)
    db.apply(issue_event(issue("j", severity=Severity.WARN, updated_at=200)))
    assert db.issue("j").state is IssueState.OPEN


def test_resolution_ends_an_acknowledgement(db: Store) -> None:
    db.apply(issue_event(issue(updated_at=100)))
    db.ack("i1", at=110)
    db.apply(issue_event(issue(state=IssueState.RESOLVED, updated_at=120)))
    assert db.issue("i1").state is IssueState.RESOLVED
    db.apply(issue_event(issue(state=IssueState.OPEN, updated_at=130)))
    assert db.issue("i1").state is IssueState.OPEN  # recurred: not still acknowledged


def test_the_hold_survives_reopening_the_database(tmp_path: Path) -> None:
    path = tmp_path / "store.sqlite3"
    s = Store(path, config())
    s.apply(issue_event(issue(updated_at=100)))
    s.ack("i1", at=110)
    s.close()
    s = Store(path, config())
    s.apply(issue_event(issue(updated_at=120)))
    assert s.issue("i1").state is IssueState.ACKNOWLEDGED
    s.close()


def test_ack_and_snooze_refuse_unknown_and_resolved_issues(db: Store) -> None:
    with pytest.raises(KeyError):
        db.ack("nope", at=1)
    with pytest.raises(KeyError):
        db.snooze("nope", until=1)
    db.apply(issue_event(issue(state=IssueState.RESOLVED)))
    with pytest.raises(StoreError, match="resolved"):
        db.ack("i1", at=1)
    with pytest.raises(StoreError, match="resolved"):
        db.snooze("i1", until=1)


def test_a_hold_records_who_made_it_and_keeps_it_while_the_hold_stands(db: Store) -> None:
    db.apply(issue_event(issue("a", updated_at=100)))
    db.apply(issue_event(issue("b", updated_at=100)))
    db.apply(issue_event(issue("c", updated_at=100)))
    db.ack("a", at=110, by="agent:claude")
    db.snooze("b", until=500, by="agent:mcp")
    assert db.holds() == {"a": store_module.Hold("agent:claude", 110, None),
                          "b": store_module.Hold("agent:mcp", None, 500)}
    db.apply(issue_event(issue("a", updated_at=120)))  # re-emitted: the hold stands
    assert db.holds()["a"].by == "agent:claude"
    db.ack("c", at=130)  # the dashboard's operator
    assert db.holds()["c"] == store_module.Hold("", 130, None)
    db.apply(issue_event(issue("a", severity=Severity.CRITICAL, updated_at=140)))
    db.apply(issue_event(issue("b", updated_at=600)))  # the snooze lapsed
    assert set(db.holds()) == {"c"}
    db.ack("a", at=150)
    assert db.holds()["a"].by == ""  # a new hold replaces the old attribution


def test_a_store_made_before_hold_attribution_gains_it_on_open(tmp_path: Path) -> None:
    path = tmp_path / "store.sqlite3"
    s = Store(path, config())
    s.apply(issue_event(issue(updated_at=100)))
    s.ack("i1", at=110)
    s._db.execute("ALTER TABLE issues DROP COLUMN held_by")
    s.close()
    s = Store(path, config())
    assert s.holds() == {"i1": store_module.Hold("", 110, None)}
    s.snooze("i1", until=900, by="agent:x")
    assert s.holds()["i1"].by == "agent:x"
    assert s._db.execute("SELECT value FROM meta WHERE key='schema_version'").fetchone()[0] \
        == store_module.VERSION
    s.close()


# --- the audit log ----------------------------------------------------------------------------


def test_the_audit_log_lists_newest_first_and_filters(db: Store) -> None:
    db.audit(10, "claude", "ack", "i1", {})
    db.audit(20, "mcp", "start_describe", "sd-1", {"chars": 300, "remote": False})
    db.audit(30, "claude", "snooze", "i2", {"until": 99.0})
    rows = db.audit_log()
    assert [(r.at, r.agent, r.action, r.target) for r in rows] == [
        (30, "claude", "snooze", "i2"), (20, "mcp", "start_describe", "sd-1"),
        (10, "claude", "ack", "i1")]
    assert rows[1].detail == {"chars": 300, "remote": False}
    assert [r.target for r in db.audit_log(agent="claude")] == ["i2", "i1"]
    assert [r.target for r in db.audit_log(since=20)] == ["i2", "sd-1"]
    assert [r.target for r in db.audit_log(limit=1)] == ["i2"]


def test_the_audit_log_is_bounded_and_left_alone_by_retention(tmp_path: Path,
                                                               monkeypatch) -> None:
    monkeypatch.setattr(store_module, "MAX_AUDIT", 2)
    s = Store(tmp_path / "store.sqlite3", config(max_age_s=10, max_bytes=1))
    for n in range(4):
        s.audit(n, "a", "ack", f"i{n}", {})
    assert [r.target for r in s.audit_log()] == ["i3", "i2"]
    s.prune(now=10_000)
    assert [r.target for r in s.audit_log()] == ["i3", "i2"]
    s.close()


def test_an_audit_detail_that_is_not_json_is_refused(db: Store) -> None:
    with pytest.raises(SchemaError, match="JSON"):
        db.audit(1, "a", "ack", "i1", {"bad": {1, 2}})
    assert db.audit_log() == ()


# --- domains --------------------------------------------------------------------------------


def test_domains_summarise_open_issues_and_latest_attestations(db: Store) -> None:
    db.apply(issue_event(issue("a", severity=Severity.WARN, domain="disk")))
    db.apply(issue_event(issue("b", severity=Severity.WARN, domain="disk")))
    db.apply(issue_event(issue("c", severity=Severity.CRITICAL, domain="disk",
                               state=IssueState.RESOLVED)))
    db.apply(issue_event(issue("d", severity=Severity.INFO, domain="net")))
    db.ack("d", at=200)
    db.apply(attest_event(attestation("c1", "q1", "disk", Severity.WATCH), at=10))
    db.apply(attest_event(attestation("c1", "q1", "disk", Severity.CRITICAL), at=20))
    db.apply(attest_event(attestation("c2", "q1", "gpu", Severity.INFO), at=20))
    zero = dict.fromkeys(Severity, 0)
    assert db.domains() == {
        "disk": DomainSummary(open={**zero, Severity.WARN: 2},
                              attested={**zero, Severity.CRITICAL: 1}),
        "net": DomainSummary(open=zero, attested=zero),
        "gpu": DomainSummary(open=zero, attested={**zero, Severity.INFO: 1}),
    }


def test_a_question_left_out_of_its_contexts_latest_ask_is_no_longer_current(db: Store) -> None:
    # writable_path left the bank, and its last WARN sat in the security summary for days.
    db.apply(attest_event(attestation("security", "writable_path", "security", Severity.WARN),
                          at=10))
    db.apply(attest_event(attestation("security", "posture", "security", Severity.INFO), at=10))
    db.apply(attest_event(attestation("security", "posture", "security", Severity.INFO), at=20))
    assert [a.question for _, a in db.attestations(latest=True)] == ["posture"]
    zero = dict.fromkeys(Severity, 0)
    assert db.domains()["security"] == DomainSummary(open=zero,
                                                     attested={**zero, Severity.INFO: 1})
    assert len(db.attestations(question="writable_path")) == 1   # history keeps it


# --- pruning --------------------------------------------------------------------------------


def test_prune_by_age_removes_old_rows_but_never_live_issues(tmp_path: Path) -> None:
    s = Store(tmp_path / "store.sqlite3", config(max_age_s=100))
    s.apply(obs_event("old", {"v": 1}, at=10))
    s.apply(obs_event("new", {"v": 1}, at=950))
    s.apply(finding_event(finding(), at=10))
    s.apply(attest_event(attestation(), at=10))
    s.apply(hb_event(heartbeat(), at=10))
    s.apply(hb_event(heartbeat(), at=950))
    s.apply(issue_event(issue("open", updated_at=10)))
    s.apply(issue_event(issue("gone", state=IssueState.RESOLVED, updated_at=10)))
    s.apply(issue_event(issue("fresh", state=IssueState.RESOLVED, updated_at=950)))
    # old latest + old series point + finding (history+latest) + attestation (history+latest)
    # + old heartbeat + resolved issue = 8
    assert s.prune(now=1000) == 8
    assert [(at, o.probe) for at, o in s.latest()] == [(950.0, "new")]
    assert s.findings() == () and s.findings(latest=True) == ()
    assert s.attestations() == () and s.attestations(latest=True) == ()
    assert s.last_heartbeat()[0] == 950.0
    assert {i.id for i in s.issues()} == {"open", "fresh"}
    assert s.prune(now=1000) == 0
    s.close()


def test_a_notification_keeps_the_highest_rank_sent_and_the_latest_time(tmp_path: Path) -> None:
    path = tmp_path / "store.sqlite3"
    s = Store(path, config(max_age_s=100))
    assert s.notified() == {}
    s.note_notified("i-1", 2, 900.0)
    s.note_notified("i-1", 1, 950.0)      # a lower rank never lowers what was sent
    s.note_notified("i-2", 3, 10.0)
    s.close()
    s = Store(path, config(max_age_s=100))   # what a restarted service reads
    assert s.notified() == {"i-1": (2, 950.0), "i-2": (3, 10.0)}
    s.prune(now=1000)
    assert s.notified() == {"i-1": (2, 950.0)}
    s.close()


def test_a_live_issue_keeps_its_notification_past_retention(tmp_path: Path) -> None:
    s = Store(tmp_path / "store.sqlite3", config(max_age_s=100))
    s.apply(issue_event(issue("open", updated_at=10)))
    s.apply(issue_event(issue("done", state=IssueState.RESOLVED, updated_at=10)))
    for issue_id in ("open", "done", "gone"):
        s.note_notified(issue_id, 2, 10.0)
    s.prune(now=1000)
    assert s.notified() == {"open": (2, 10.0)}   # resolved or no longer stored: forgotten
    s.close()


def _fill(s: Store, n: int) -> None:
    for t in range(n):
        s.apply(obs_event("wide", {f"field{k}": float(t) for k in range(50)}, at=1000 + t))
        s.apply(hb_event(heartbeat(), at=1000 + t))
    s.apply(issue_event(issue("live", updated_at=1000)))
    s.apply(issue_event(issue("done", state=IssueState.RESOLVED, updated_at=1000)))


def test_prune_by_size_empties_history_but_keeps_latest_and_live_issues(tmp_path: Path) -> None:
    s = Store(tmp_path / "store.sqlite3", config(max_bytes=1))
    _fill(s, 200)
    removed = s.prune(now=1300)
    assert removed == 200 * 50 + 200 + 1
    assert count(s, "series") == 0 and s.last_heartbeat() is None
    assert [(at, o.probe) for at, o in s.latest()] == [(1199.0, "wide")]
    assert [i.id for i in s.issues()] == ["live"]
    s.close()


def test_prune_by_size_removes_the_oldest_until_under_the_limit(tmp_path: Path) -> None:
    path = tmp_path / "store.sqlite3"
    s = Store(path, config())
    _fill(s, 400)
    full = s.size()
    s.close()

    limit = full // 2
    s = Store(path, config(max_bytes=limit))
    removed = s.prune(now=1500)
    assert 0 < removed < 400 * 51
    assert s.size() <= limit  # measured from page_count * page_size after vacuum
    assert s._db.execute("PRAGMA freelist_count").fetchone()[0] == 0
    kept = [int(r[0]) for r in s._db.execute("SELECT DISTINCT t FROM series ORDER BY t")]
    assert kept and kept == list(range(kept[0], 1400))  # the newest survive, contiguously
    assert s.prune(now=1500) == 0  # already under
    s.close()


def test_prune_is_a_no_op_under_both_limits(db: Store) -> None:
    db.apply(obs_event("load", {"one": 1.0}, at=10))
    assert db.prune(now=20) == 0
    assert count(db, "series") == 1


def test_close_is_idempotent(tmp_path: Path) -> None:
    s = Store(tmp_path / "store.sqlite3", config())
    s.close()
    s.close()


# --- links and incidents --------------------------------------------------------------------


def link(id: str = "l1", members: tuple[str, ...] = ("issue:a", "issue:b"),
         related: float = 0.9) -> Link:
    return Link(id=id, members=members, basis="shared-entity", related=related,
                likely_cause=members[0], confidence=0.7, stable=True)


def link_event(lk: Link, at: float) -> Event:
    return Event(Kind.LINK, at, "evaluator", f"link.{lk.id}", to_body(lk))


def test_links_keep_history_and_the_latest_per_id(db: Store) -> None:
    db.apply(link_event(link(related=0.5), at=10))
    db.apply(link_event(link(related=0.9), at=20))
    db.apply(link_event(link(related=0.1), at=5))  # late arrival
    db.apply(link_event(link(related=0.9), at=20))  # replay
    assert count(db, "links") == 3
    assert [i.link.related for i in db.incidents()] == [0.9]
    assert db.incidents()[0].at == 20.0


@pytest.mark.parametrize("members", [
    ("issue:a",),                         # a link relates two or more things
    ("issue:a", "issue:"),                # empty id
    ("issue:a", "event:x"),               # not a member kind a link may name
    ("issue:a", "finding:rule-only"),     # finding ids are rule@entity
    ("issue:a", "finding:@disk:/"),
    ("issue:a", "finding:rule@"),
])
def test_a_link_with_an_unresolvable_member_is_refused(db: Store, members) -> None:
    with pytest.raises(SchemaError, match="member"):
        db.apply(link_event(link(members=members), at=1))
    assert count(db, "links") == 0 and count(db, "links_latest") == 0


def test_incidents_resolve_members_and_rank_by_severity_then_score(db: Store) -> None:
    db.apply(issue_event(issue("i1", severity=Severity.WARN, score=1.0)))
    db.apply(issue_event(issue("i2", severity=Severity.CRITICAL, score=0.5)))
    db.apply(issue_event(issue("i3", severity=Severity.WARN, score=5.0)))
    crit = finding(rule="smart.critical", entity="disk:/dev/nvme0", severity=Severity.CRITICAL)
    db.apply(finding_event(finding(rule="smart.critical", entity="disk:/dev/nvme0",
                                   severity=Severity.INFO), at=5))
    db.apply(finding_event(crit, at=30))
    db.apply(link_event(link("warm", ("issue:i1", "issue:i3")), at=40))
    db.apply(link_event(link("hot", ("issue:i1", "finding:smart.critical@disk:/dev/nvme0")),
                        at=40))
    db.apply(link_event(link("gap", ("issue:i2", "issue:gone")), at=40))
    db.apply(link_event(link("ghost", ("issue:x", "finding:r@e")), at=40))
    incidents = db.incidents()
    assert [i.link.id for i in incidents] == ["hot", "gap", "warm", "ghost"]
    hot, gap, warm, ghost = incidents
    assert hot == Incident(at=40.0, link=link("hot", ("issue:i1",
                           "finding:smart.critical@disk:/dev/nvme0")),
                           issues=(db.issue("i1"),), findings=((30.0, crit),), missing=())
    assert gap.issues == (db.issue("i2"),) and gap.missing == ("issue:gone",)
    assert [i.id for i in warm.issues] == ["i1", "i3"]
    assert ghost.issues == () and ghost.findings == ()
    assert ghost.missing == ("issue:x", "finding:r@e")


def test_incidents_follow_the_latest_version_of_a_link(db: Store) -> None:
    db.apply(issue_event(issue("a")))
    db.apply(issue_event(issue("b")))
    db.apply(issue_event(issue("c")))
    db.apply(link_event(link("l1", ("issue:a", "issue:b")), at=10))
    db.apply(link_event(link("l1", ("issue:a", "issue:c")), at=20))
    assert [i.id for i in db.incidents()[0].issues] == ["a", "c"]


# --- analyses -------------------------------------------------------------------------------


def analysis(id: str = "a1", subjects: tuple[str, ...] = ("issue:a",), completed_at: float = 20.0,
             text: str = "probably the disk") -> Analysis:
    return Analysis(id=id, requested_at=completed_at - 5, completed_at=completed_at,
                    backend="openai-compatible", model="m", subjects=subjects,
                    question="why?", text=text, suggested_checks=("smartctl -j -a /dev/x",),
                    input_chars=100, output_chars=len(text))


def test_analyses_are_saved_and_read_newest_first(db: Store) -> None:
    db.save_analysis(analysis("a1", ("issue:a", "link:l1"), completed_at=10))
    db.save_analysis(analysis("a2", ("issue:b",), completed_at=30))
    db.save_analysis(analysis("a3", ("link:l1",), completed_at=20))
    assert [a.id for a in db.analyses()] == ["a2", "a3", "a1"]
    assert [a.id for a in db.analyses("link:l1")] == ["a3", "a1"]
    assert db.analyses("issue:zzz") == ()
    db.save_analysis(analysis("a1", ("issue:a",), completed_at=40, text="revised"))
    assert db.analyses()[0] == analysis("a1", ("issue:a",), completed_at=40, text="revised")
    assert db.analyses("link:l1") == (analysis("a3", ("link:l1",), completed_at=20),)


def test_a_malformed_analysis_is_refused(db: Store) -> None:
    with pytest.raises(SchemaError):
        db.save_analysis(dataclasses.replace(analysis(), subjects=(1, 2)))  # type: ignore[arg-type]
    with pytest.raises(SchemaError, match="not a record"):
        db.save_analysis({"id": "a1"})  # type: ignore[arg-type]
    assert db.analyses() == ()


def test_analyses_survive_reopening(tmp_path: Path) -> None:
    path = tmp_path / "store.sqlite3"
    s = Store(path, config())
    s.save_analysis(analysis())
    s.close()
    s = Store(path, config())
    assert s.analyses() == (analysis(),)
    s.close()


# --- retention for links and analyses -------------------------------------------------------


def test_links_and_analyses_age_out(tmp_path: Path) -> None:
    s = Store(tmp_path / "store.sqlite3", config(max_age_s=100))
    s.apply(link_event(link("old"), at=10))
    s.apply(link_event(link("new"), at=950))
    s.save_analysis(analysis("old", completed_at=10))
    s.save_analysis(analysis("new", completed_at=950))
    assert s.prune(now=1000) == 3  # old link history + old latest link + old analysis
    assert [i.link.id for i in s.incidents()] == ["new"]
    assert [a.id for a in s.analyses()] == ["new"]
    s.close()


def test_size_pruning_takes_history_before_analyses(tmp_path: Path) -> None:
    path = tmp_path / "store.sqlite3"
    s = Store(path, config())
    for n in range(40):
        s.save_analysis(analysis(f"a{n:02d}", completed_at=100 + n, text="x" * 2000))
    s.apply(link_event(link("l1"), at=1000))
    with_analyses = s.size()
    _fill(s, 300)
    for t in range(50):
        s.apply(link_event(link("l1"), at=1001 + t))
    assert s.size() > 2 * with_analyses
    s.close()

    s = Store(path, config(max_bytes=with_analyses + 16 * 4096))
    assert s.prune(now=2100) > 0
    assert s.size() <= with_analyses + 16 * 4096
    assert len(s.analyses()) == 40  # history alone was enough
    s.close()

    s = Store(path, config(max_bytes=1))
    s.prune(now=2100)
    assert s.analyses() == () and count(s, "series") == 0 and count(s, "links") == 0
    assert [i.link.id for i in s.incidents()] == ["l1"]  # the latest link is kept
    assert [i.id for i in s.issues()] == ["live"]
    s.close()


# --- log explanations -----------------------------------------------------------------------


def explained(key: str, seen: float = 100.0, text: str = "routine", model: str = "m1",
              created: float = 50.0) -> LogExplanation:
    return LogExplanation(key=key, source="kernel", template=f"line <n> {key}", explanation=text,
                          model=model, created_at=created, last_seen_at=seen)


def test_log_explanations_are_saved_and_read_by_key(db: Store) -> None:
    db.save_log_explanations([explained("a"), explained("b", model="m2")])
    found = db.log_explanations(["a", "b", "c", "a"])
    assert set(found) == {"a", "b"}
    assert found["a"] == explained("a")
    assert found["b"].model == "m2"  # each records the model that wrote it
    assert db.log_explanations([]) == {}


def test_a_log_explanation_saved_again_replaces_the_old_one(db: Store) -> None:
    db.save_log_explanations([explained("a", text="old")])
    db.save_log_explanations([explained("a", text="new", model="m2")])
    assert db.log_explanations(["a"])["a"].explanation == "new"
    assert count(db, "log_explanations") == 1


def test_many_keys_are_read_past_the_parameter_limit(db: Store) -> None:
    keys = [f"k{n:05d}" for n in range(1200)]
    db.save_log_explanations([explained(k) for k in keys])
    assert len(db.log_explanations(keys)) == 1200


def test_touch_moves_last_seen_forward_only(db: Store) -> None:
    db.save_log_explanations([explained("a", seen=100), explained("b", seen=100)])
    db.touch_log_explanations(["a", "a", "missing"], at=200)
    db.touch_log_explanations(["b"], at=50)
    found = db.log_explanations(["a", "b"])
    assert found["a"].last_seen_at == 200 and found["b"].last_seen_at == 100
    assert "missing" not in db.log_explanations(["missing"])


def test_the_cache_keeps_the_most_recently_seen(db: Store, monkeypatch) -> None:
    monkeypatch.setattr(store_module, "MAX_LOG_EXPLANATIONS", 3)
    db.save_log_explanations([explained(k, seen=t) for k, t in
                              [("a", 1), ("b", 2), ("c", 3)]])
    db.touch_log_explanations(["a"], at=10)
    assert db.save_log_explanations([explained("d", seen=5)]) == 1
    assert set(db.log_explanations("abcd")) == {"a", "c", "d"}  # b was least recently seen


def test_log_explanations_are_left_alone_by_age_and_size_retention(tmp_path: Path) -> None:
    s = Store(tmp_path / "store.sqlite3", config(max_age_s=10, max_bytes=1))
    s.save_log_explanations([explained("a", seen=1, created=1)])
    s.prune(now=10_000)
    assert set(s.log_explanations(["a"])) == {"a"}
    s.close()


def test_a_store_made_before_the_cache_gains_it_on_open(tmp_path: Path) -> None:
    path = tmp_path / "store.sqlite3"
    s = Store(path, config())
    s.save_analysis(analysis("kept"))
    s._db.execute("DROP TABLE log_explanations")
    s.close()
    s = Store(path, config())
    assert [a.id for a in s.analyses()] == ["kept"]
    s.save_log_explanations([explained("a")])
    assert set(s.log_explanations(["a"])) == {"a"}
    assert s._db.execute("SELECT value FROM meta WHERE key='schema_version'").fetchone()[0] \
        == store_module.VERSION
    s.close()


# --- service descriptions ---------------------------------------------------------------------


def described(name: str, key: str = "0123456789abcdef", seen: float = 100.0,
              brief: str = "The cron daemon.", model: str = "m1") -> ServiceDescription:
    return ServiceDescription(name=name, key=key, brief=brief, full=f"{name} runs jobs.\n\n- x",
                              model=model, created_at=50.0, last_seen_at=seen)


def test_the_first_services_noted_are_the_baseline_and_later_ones_are_new(db: Store) -> None:
    db.note_services([], 50.0)  # nothing to note sets no baseline
    db.note_services(["cron.service", "ssh.service", "cron.service"], 100.0)
    db.note_services(["cron.service", "ollama.service"], 200.0)
    db.note_services(["ollama.service"], 300.0)  # first seen stays first seen
    assert db.service_sightings() == {"cron.service": (100.0, False),
                                      "ssh.service": (100.0, False),
                                      "ollama.service": (200.0, True)}


def test_service_descriptions_are_saved_and_read_by_unit_name(db: Store) -> None:
    db.save_service_descriptions([described("cron.service"), described("rtkit.service",
                                                                       model="m2")])
    found = db.service_descriptions(["cron.service", "rtkit.service", "gone.service"])
    assert found == {"cron.service": described("cron.service"),
                     "rtkit.service": described("rtkit.service", model="m2")}
    assert db.service_descriptions([]) == {}


def test_a_redescribed_service_replaces_its_row_and_its_definition_key(db: Store) -> None:
    db.save_service_descriptions([described("cron.service", key="aaaaaaaaaaaaaaaa",
                                            brief="old")])
    db.save_service_descriptions([described("cron.service", key="bbbbbbbbbbbbbbbb",
                                            brief="new")])
    found = db.service_descriptions(["cron.service"])["cron.service"]
    assert (found.key, found.brief) == ("bbbbbbbbbbbbbbbb", "new")
    assert count(db, "service_descriptions") == 1


def test_the_service_cache_is_bounded_by_last_seen(db: Store, monkeypatch) -> None:
    monkeypatch.setattr(store_module, "MAX_SERVICE_DESCRIPTIONS", 2)
    db.save_service_descriptions([described("a", seen=1), described("b", seen=2)])
    db.touch_service_descriptions(["a", "a", "missing"], at=10)
    db.touch_service_descriptions(["b"], at=1)  # never moved back
    assert db.service_descriptions(["b"])["b"].last_seen_at == 2
    assert db.save_service_descriptions([described("c", seen=5)]) == 1
    assert set(db.service_descriptions("abc")) == {"a", "c"}  # b was least recently seen
    assert count(db, "log_explanations") == 0  # the caches are separate


def test_a_store_made_before_the_service_cache_gains_it_on_open(tmp_path: Path) -> None:
    path = tmp_path / "store.sqlite3"
    s = Store(path, config())
    s._db.execute("DROP TABLE service_descriptions")
    s.close()
    s = Store(path, config(max_age_s=10, max_bytes=1))
    s.save_service_descriptions([described("cron.service", seen=1)])
    s.prune(now=10_000)  # left alone by age and size retention
    assert set(s.service_descriptions(["cron.service"])) == {"cron.service"}
    s.close()
