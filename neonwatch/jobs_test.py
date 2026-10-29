"""The job and service join, over parsed probe data shaped exactly as `probes.parsers` emits it.

`jobs` is level 1 and may not import `probes`, so neither may this test: the samples below are
the parsers' real output on the samples in `probes/parsers_test.py`, copied, and must change
with them.
"""

from __future__ import annotations

import hashlib
from typing import Any

import pytest

from neonwatch import jobs


def unit(id: str, **fields: Any) -> dict[str, Any]:
    """One `units.detail` unit, every field the parser emits, empty unless given."""
    return {"id": id, "description": "", "user": "", "exec": [], "active": "", "sub": "",
            "result": "", "restarts": None, "main_status": None, "started": None,
            "exited": None, "enabled": "", "file": "", "triggers": [], "triggered_by": [],
            "calendar": [], "monotonic": [], "unit": ""} | fields


APT_SERVICE = unit("apt-daily.service", description="Daily apt download activities",
                   exec=["/usr/lib/apt/apt.systemd.daily update"], active="inactive", sub="dead",
                   result="success", restarts=0, main_status=0, started=1791809446.0,
                   exited=1791809446.0, enabled="static",
                   file="/usr/lib/systemd/system/apt-daily.service",
                   triggered_by=["apt-daily.timer"])
APT_TIMER = unit("apt-daily.timer", description="Daily apt download activities",
                 active="active", sub="waiting", result="success", enabled="enabled",
                 file="/usr/lib/systemd/system/apt-daily.timer", triggers=["apt-daily.service"],
                 calendar=["*-*-* 06,18:00:00"], unit="apt-daily.service")
CLEAN_TIMER = unit("systemd-tmpfiles-clean.timer", active="active", sub="waiting",
                   result="success", enabled="static",
                   file="/usr/lib/systemd/system/systemd-tmpfiles-clean.timer",
                   triggers=["systemd-tmpfiles-clean.service"],
                   monotonic=["OnUnitActiveSec=1d", "OnBootSec=15min"],
                   unit="systemd-tmpfiles-clean.service")
RESOLVED = unit("systemd-resolved.service", user="systemd-resolve", active="active",
                sub="running", result="success", restarts=0, main_status=0,
                started=1790790975.0, enabled="enabled",
                exec=["/usr/lib/systemd/systemd-resolved"])


def crontab(path: str, *entries: tuple[str, str, str], skipped: int = 0,
            dropped: int = 0) -> dict[str, Any]:
    """A cron.system / cron.d / cron.user observation of one file."""
    listed = [{"file": path, "user": user, "schedule": schedule, "command": command,
               "stdin": "%" in command} for user, schedule, command in entries]
    return {"files": [{"path": path, "env": {}, "env_dropped": 0, "entries": len(listed),
                       "total": len(listed) + dropped, "dropped": dropped, "skipped": skipped}],
            "entries": listed, "count": len(listed), "skipped": skipped, "redacted": 0}


HOURLY = "cd / && run-parts --report /etc/cron.hourly"

EVERYTHING: dict[str, dict[str, Any]] = {
    "cron.system": crontab("/etc/crontab", ("root", "17 * * * *", HOURLY)),
    "cron.d": crontab("/etc/cron.d/sysstat", ("root", "5-55/10 * * * *", "debian-sa1 1 1"),
                      skipped=1),
    "cron.user": crontab("/var/spool/cron/crontabs/alice", ("alice", "@reboot", "/tmp/.x/run")),
    "cron.anacron": {
        "files": [{"path": "/etc/anacrontab", "env": {"SHELL": "/bin/sh"}, "entries": 1,
                   "skipped": 2}],
        "entries": [{"file": "/etc/anacrontab", "period": "1", "delay": 5,
                     "job_id": "cron.daily", "command": "run-parts --report /etc/cron.daily"}],
        "count": 1, "skipped": 2, "redacted": 0},
    "cron.daily": {"scripts": [{"path": "/etc/cron.daily/dpkg", "size": 35, "truncated": False,
                                "head": "#!/bin/sh\n/usr/libexec/dpkg/backup\n"}],
                   "count": 1, "redacted": 0},
    "cron.hourly": {"scripts": [], "count": 0, "redacted": 0},
    "units.timers": {"timers": [
        {"unit": "apt-daily.timer", "activates": "apt-daily.service", "next": 1791849600.0,
         "last": 1791809445.968694},
        {"unit": "orphan.timer", "activates": "orphan.service", "next": None, "last": None}],
        "count": 2, "skipped": 0},
    "units.detail": {"units": [APT_SERVICE, APT_TIMER, RESOLVED, CLEAN_TIMER], "count": 4,
                     "skipped": 0, "redacted": 0},
}


def sha(*parts: str) -> str:
    return "cron:" + hashlib.sha256("\n".join(parts).encode()).hexdigest()[:32]


def by_id(latest: dict[str, dict[str, Any]]) -> dict[str, dict[str, Any]]:
    return {job["id"]: job for job in jobs.scheduled(latest)[0]}


def test_probes_are_the_scheduled_work_probes() -> None:
    expected = {"cron.system", "cron.d", "cron.user", "cron.anacron", "cron.hourly",
                "cron.daily", "cron.weekly", "cron.monthly", "units.timers", "units.detail",
                "cron.d.names", "cron.hourly.names", "cron.daily.names", "cron.weekly.names",
                "cron.monthly.names"}
    assert expected == jobs.PROBES


def test_nothing_observed_is_nothing_scheduled() -> None:
    assert jobs.scheduled({}) == ([], 0)
    assert jobs.services({}) == []


def test_a_cron_job_is_identified_by_its_file_user_schedule_and_command() -> None:
    found, skipped = jobs.scheduled(EVERYTHING)
    key = sha("/etc/crontab", "root", "17 * * * *", HOURLY)
    static = {"source": "cron", "file": "/etc/crontab", "user": "root",
              "schedule": "17 * * * *", "command": HOURLY, "unit": None, "unread": False,
              "target": None, "skipped_by_run_parts": False, "overflow": 0}
    assert {job["id"]: job for job in found}[key] == {
        "id": key, **static, "static": static, "last": None, "next": None, "result": None}
    alice = by_id(EVERYTHING)[sha("/var/spool/cron/crontabs/alice", "alice", "@reboot",
                                  "/tmp/.x/run")]
    assert (alice["source"], alice["user"], alice["schedule"]) == ("cron", "alice", "@reboot")
    assert skipped == 3  # what the parsers skipped: one cron.d line, two anacrontab lines


def test_anacron_and_periodic_jobs() -> None:
    found = by_id(EVERYTHING)
    daily = found[sha("/etc/anacrontab", "root", "1", "run-parts --report /etc/cron.daily")]
    assert (daily["source"], daily["user"], daily["schedule"]) == ("anacron", "root", "1")
    assert found["cron:/etc/cron.daily/dpkg"]["static"] == {
        "source": "cron-periodic", "file": "/etc/cron.daily/dpkg", "user": "root",
        "schedule": "daily", "command": "#!/bin/sh\n/usr/libexec/dpkg/backup\n", "unit": None,
        "unread": False, "target": None, "skipped_by_run_parts": False, "overflow": 0}


def test_a_timer_joins_its_schedule_service_command_and_run_times() -> None:
    static = {"source": "timer", "file": "/usr/lib/systemd/system/apt-daily.timer",
              "user": "root", "schedule": "*-*-* 06,18:00:00",
              "command": "/usr/lib/apt/apt.systemd.daily update", "unit": "apt-daily.service",
              "unread": False, "target": None, "skipped_by_run_parts": False, "overflow": 0}
    assert by_id(EVERYTHING)["timer:apt-daily.timer"] == {
        "id": "timer:apt-daily.timer", **static, "static": static,
        "last": 1791809445.968694, "next": 1791849600.0, "result": "success"}


def test_a_timer_whose_service_was_not_read_says_so_rather_than_guessing() -> None:
    found = by_id(EVERYTHING)
    # Listed by list-timers only: no unit block for the timer or for its service.
    orphan = found["timer:orphan.timer"]
    assert {k: orphan[k] for k in ("file", "user", "schedule", "command", "unit", "last",
                                   "next", "result")} == {
        "file": "", "user": "", "schedule": "", "command": "", "unit": "orphan.service",
        "last": None, "next": None, "result": None}
    # Read by show but not listed, and its service not read.
    clean = found["timer:systemd-tmpfiles-clean.timer"]
    assert (clean["unit"], clean["user"], clean["last"]) == (
        "systemd-tmpfiles-clean.service", "", None)


def test_a_timer_with_no_unit_anywhere_has_none() -> None:
    lone = {"units.detail": {"units": [unit("lone.timer")], "count": 1, "skipped": 0}}
    assert by_id(lone)["timer:lone.timer"]["unit"] is None


def test_an_interval_timer_s_schedule_is_its_intervals_after_any_calendar() -> None:
    assert by_id(EVERYTHING)["timer:systemd-tmpfiles-clean.timer"]["schedule"] == (
        "OnUnitActiveSec=1d; OnBootSec=15min")
    both = {"units.detail": {"units": [unit("motd-news.timer", calendar=["*-*-* 00,12:00:00"],
                                            monotonic=["OnStartupSec=1min"])]}}
    assert by_id(both)["timer:motd-news.timer"]["schedule"] == (
        "*-*-* 00,12:00:00; OnStartupSec=1min")


def test_several_calendars_and_commands_are_joined() -> None:
    data = {"units.detail": {"units": [
        unit("two.timer", unit="two.service",
             calendar=["Mon *-*-* 00:00:00", "Fri *-*-* 00:00:00"]),
        unit("two.service", user="backup", result="exit-code", exec=["/a 1", "/b 2"])],
        "count": 2, "skipped": 0}}
    (job,) = jobs.scheduled(data)[0]
    assert (job["schedule"], job["command"], job["user"], job["result"]) == (
        "Mon *-*-* 00:00:00; Fri *-*-* 00:00:00", "/a 1; /b 2", "backup", "exit-code")


def test_a_service_that_has_not_run_has_no_result() -> None:
    data = {"units.detail": {"units": [unit("t.timer", unit="t.service"), unit("t.service")],
                             "count": 2, "skipped": 0}}
    assert by_id(data)["timer:t.timer"]["result"] is None


def test_static_holds_no_run_state_so_a_run_does_not_change_it() -> None:
    before = {job["id"]: job["static"] for job in jobs.scheduled(EVERYTHING)[0]}
    ran = {**EVERYTHING, "units.timers": {"timers": [
        {"unit": "apt-daily.timer", "activates": "apt-daily.service", "next": 1791892800.0,
         "last": 1791849600.1}], "count": 1, "skipped": 0},
        "units.detail": {**EVERYTHING["units.detail"], "units": [
            APT_SERVICE | {"result": "exit-code", "started": 1791849600.0},
            APT_TIMER, RESOLVED, CLEAN_TIMER]}}
    after = {job["id"]: job["static"] for job in jobs.scheduled(ran)[0]}
    assert after == {key: static for key, static in before.items()
                     if key != "timer:orphan.timer"}
    for static in before.values():
        assert set(static) == {"source", "file", "user", "schedule", "command", "unit", "unread",
                               "target", "skipped_by_run_parts", "overflow"}


def test_output_is_sorted_and_deterministic() -> None:
    found, skipped = jobs.scheduled(EVERYTHING)
    assert [job["id"] for job in found] == sorted(job["id"] for job in found)
    assert jobs.scheduled(dict(reversed(EVERYTHING.items()))) == (found, skipped)
    assert len(found) == 8


LISTED = {
    **EVERYTHING,
    "cron.d": crontab("/etc/cron.d/sysstat", ("root", "5 * * * *", "debian-sa1 1 1")),
    "cron.d.names": {"entries": ["evil.dpkg-old", "sysstat"], "count": 2},
    "cron.daily.names": {"entries": [".placeholder", "dpkg", "google-chrome", "rel"],
                         "count": 4,
                         "links": {"google-chrome": "/opt/google/chrome/cron/google-chrome",
                                   "rel": "../../home/alice/.x/run"}},
    "cron.weekly.names": {"entries": ["man-db"], "count": 1},
}


def test_a_name_listed_but_not_read_is_an_unread_job() -> None:
    found = by_id(LISTED)
    chrome = found["cron:/etc/cron.daily/google-chrome"]
    static = {"source": "cron-periodic", "file": "/etc/cron.daily/google-chrome",
              "user": "root", "schedule": "daily", "command": "", "unit": None, "unread": True,
              "target": "/opt/google/chrome/cron/google-chrome", "skipped_by_run_parts": False,
              "overflow": 0}
    assert chrome == {"id": "cron:/etc/cron.daily/google-chrome", **static, "static": static,
                      "last": None, "next": None, "result": None}
    assert found["cron:/etc/cron.daily/dpkg"]["unread"] is False  # listed and read: one job
    # A whole directory unread (its glob failed) is every name in it.
    assert found["cron:/etc/cron.weekly/man-db"]["static"]["schedule"] == "weekly"
    evil = found["cron:/etc/cron.d/evil.dpkg-old"]
    assert (evil["source"], evil["user"], evil["schedule"], evil["command"], evil["unread"]) == (
        "cron", "", "", "", True)
    # The target is the link's text made absolute against its directory, never resolved; a
    # name the listing does not call a link, or a listing of the older shape, has none.
    assert found["cron:/etc/cron.daily/rel"]["target"] == "/home/alice/.x/run"
    assert evil["target"] is None and found["cron:/etc/cron.weekly/man-db"]["target"] is None
    # cron.d/sysstat was read: its line is the job, not the name.
    assert "cron:/etc/cron.d/sysstat" not in found


def test_a_name_run_parts_skips_is_marked_not_dropped() -> None:
    found = by_id(LISTED)
    assert found["cron:/etc/cron.daily/.placeholder"]["skipped_by_run_parts"] is True
    assert found["cron:/etc/cron.d/evil.dpkg-old"]["static"]["skipped_by_run_parts"] is True
    assert found["cron:/etc/cron.daily/google-chrome"]["skipped_by_run_parts"] is False
    read = crontab("/etc/cron.d/job.bak", ("root", "@daily", "/bin/true"))
    (job,) = jobs.scheduled({"cron.d": read})[0]
    assert job["skipped_by_run_parts"] is True
    # Outside a run-parts directory the rule does not apply.
    spool = crontab("/var/spool/cron/crontabs/a.b", ("a.b", "@daily", "/bin/true"))
    (job,) = jobs.scheduled({"cron.user": spool})[0]
    assert job["skipped_by_run_parts"] is False


def test_entries_a_file_could_not_keep_are_one_overflow_job() -> None:
    latest = {
        "cron.user": crontab("/var/spool/cron/crontabs/alice", ("alice", "@reboot", ":0"),
                             dropped=9989),
        "cron.d": crontab("/etc/cron.d/big", ("root", "@daily", "/bin/true"), dropped=3),
        "cron.anacron": {"files": [{"path": "/etc/anacrontab", "dropped": 1}], "entries": []},
        "cron.system": crontab("/etc/crontab", ("root", "@daily", "/bin/true")),
    }
    found, skipped = jobs.scheduled(latest)
    overflow = {job["id"]: job for job in found if job["overflow"]}
    static = {"source": "cron", "file": "/var/spool/cron/crontabs/alice", "user": "alice",
              "schedule": "", "command": "", "unit": None, "unread": False,
              "target": None, "skipped_by_run_parts": False, "overflow": 9989}
    assert overflow["cron:/var/spool/cron/crontabs/alice#overflow"] == {
        "id": "cron:/var/spool/cron/crontabs/alice#overflow", **static, "static": static,
        "last": None, "next": None, "result": None}
    big = overflow["cron:/etc/cron.d/big#overflow"]
    assert (big["source"], big["user"], big["overflow"]) == ("cron", "", 3)
    ana = overflow["cron:/etc/anacrontab#overflow"]
    assert (ana["source"], ana["user"], ana["overflow"]) == ("anacron", "root", 1)
    assert len(overflow) == 3 and skipped == 0
    # A file record from before the caps has no `dropped`: nothing overflowed.
    old = {"cron.d": {"files": [{"path": "/etc/cron.d/x", "entries": 0, "skipped": 0}]}}
    assert jobs.scheduled(old) == ([], 0)


def test_distinct_jobs_whose_ids_collide_both_survive_and_are_counted(
        monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(jobs, "_digest", lambda data: "0" * 32)
    lines = crontab("/etc/crontab", ("root", "@daily", "/bin/a"), ("root", "@daily", "/bin/b"),
                    ("root", "@daily", "/bin/a"), ("root", "@daily", "/bin/c"))
    found, skipped = jobs.scheduled({"cron.system": lines})
    zero = "cron:" + "0" * 32
    assert [(job["id"], job["command"]) for job in found] == [
        (zero, "/bin/a"), (zero + "~2", "/bin/b"), (zero + "~3", "/bin/c")]
    assert skipped == 2  # two collisions; the repeated /bin/a is the same job, merged


def test_a_cron_id_is_128_bits_of_sha256() -> None:
    (job,) = jobs.scheduled({"cron.system": crontab("/etc/crontab",
                                                     ("root", "@daily", "/bin/a"))})[0]
    assert job["id"] == sha("/etc/crontab", "root", "@daily", "/bin/a")
    assert len(job["id"]) == len("cron:") + 32


def test_a_duplicated_cron_line_is_one_job() -> None:
    twice = crontab("/etc/crontab", ("root", "0 0 * * *", "/bin/true"),
                    ("root", "0 0 * * *", "/bin/true"))
    assert len(jobs.scheduled({"cron.system": twice})[0]) == 1


def test_a_record_in_an_older_shape_is_skipped_and_counted_not_fatal() -> None:
    # `cron.d` was a LISTDIR of names: the store may hold that shape until the probe runs again.
    stale = {"cron.d": {"entries": ["e2scrub_all", "sysstat"], "count": 2},
             "cron.daily": {"scripts": [{"path": "/etc/cron.daily/x"}], "count": 1}}
    assert jobs.scheduled(stale) == ([], 3)


def test_services_are_every_service_read_and_no_timer() -> None:
    found = jobs.services(EVERYTHING)
    assert [s["name"] for s in found] == ["apt-daily.service", "systemd-resolved.service"]
    assert found[0] == {
        "name": "apt-daily.service", "description": "Daily apt download activities",
        "user": "root", "exec": ["/usr/lib/apt/apt.systemd.daily update"],
        "active": "inactive", "sub": "dead", "result": "success", "restarts": 0,
        "main_status": 0, "started": 1791809446.0, "exited": 1791809446.0,
        "enabled": "static", "file": "/usr/lib/systemd/system/apt-daily.service"}
    assert found[1]["user"] == "systemd-resolve"
    assert jobs.services({"units.detail": {"units": [RESOLVED, APT_SERVICE]}}) == found


def test_a_service_key_names_its_definition_and_nothing_that_changes_as_it_runs() -> None:
    [apt, resolved] = jobs.services(EVERYTHING)
    key = jobs.service_key(apt)
    assert len(key) == jobs.SERVICE_KEY_HEX and int(key, 16) >= 0
    assert jobs.service_key(resolved) != key
    ran = apt | {"active": "active", "sub": "running", "result": "exit-code", "restarts": 4,
                 "started": 1.0, "enabled": "enabled"}
    assert jobs.service_key(ran) == key
    for field, value in (("name", "apt-daily2.service"), ("description", "x"),
                         ("exec", ["/usr/bin/evil"]), ("file", "/etc/systemd/system/x"),
                         ("user", "nobody")):
        assert jobs.service_key(apt | {field: value}) != key, field


def test_a_service_key_is_fixed_for_the_same_definition() -> None:
    """Pinned: a cache written by one release must still be found by the next."""
    service = {"name": "cron.service", "description": "Regular background program processing "
               "daemon", "exec": ["/usr/sbin/cron -f -P"], "file":
               "/usr/lib/systemd/system/cron.service", "user": "root"}
    defined = '["cron.service","Regular background program processing daemon",' \
              '["/usr/sbin/cron -f -P"],"/usr/lib/systemd/system/cron.service","root"]'
    assert jobs.service_key(service) == hashlib.sha256(defined.encode()).hexdigest()[:16]
