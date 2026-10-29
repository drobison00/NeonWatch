"""The catalog is closed, read-only and self-consistent; `expand` admits only matching devices."""

from __future__ import annotations

import dataclasses
import re

import pytest

from neonwatch.probes import CATALOG, Cost, Kind, ProbeSpec, Tier, expand
from neonwatch.probes.catalog import DEVICE, DOMAINS, JOURNAL_ERROR_LINES, JOURNAL_LINES
from tools.gates import APPROVED_TEMPLATES, argv_is_read_only

BY_ID = {spec.id: spec for spec in CATALOG}


def spec(**changes: object) -> ProbeSpec:
    base = dict(id="x", tier=Tier.FAST, kind=Kind.FILE, argv=(), path="/proc/loadavg",
                cost=Cost.CHEAP, domain="cpu", description="a probe")
    base.update(changes)
    return ProbeSpec(**base)  # type: ignore[arg-type]


# --- the catalog ------------------------------------------------------------------------------


def test_ids_are_unique() -> None:
    assert len(BY_ID) == len(CATALOG)


def test_every_command_is_an_allowlisted_read_only_invocation() -> None:
    # The gate's exact-argv allowlist; a template is checked as its (argv, devices) pair.
    for probe in CATALOG:
        if probe.kind is Kind.COMMAND:
            assert argv_is_read_only(probe.argv, probe.devices) == "", probe.id


def approved_expansion(argv: tuple[str, ...], device: str) -> bool:
    """Whether `argv` is a gate-approved template filled with a name its approved regex admits."""
    return any(
        re.fullmatch(regex, device) is not None
        and tuple(word.replace(DEVICE, device) for word in template) == argv
        for template, regex in APPROVED_TEMPLATES.items())


def test_every_tier_is_covered() -> None:
    assert {probe.tier for probe in CATALOG} == set(Tier)


def test_every_domain_named_is_known_and_every_kind_is_used() -> None:
    assert {probe.domain for probe in CATALOG} <= DOMAINS
    assert {probe.kind for probe in CATALOG} == set(Kind)


def test_no_argv_word_could_reach_a_shell() -> None:
    shell = re.compile(r"[;&|`$<>\n]")
    for probe in CATALOG:
        for word in probe.argv:
            assert not shell.search(word), (probe.id, word)
        assert probe.argv[:1] not in {("/bin/sh",), ("/bin/bash",), ("/usr/bin/env",)}


def test_the_plan_s_named_probes_are_present_with_their_tiers() -> None:
    expected = {
        "load": Tier.FAST, "psi.cpu": Tier.FAST, "psi.memory": Tier.FAST, "psi.io": Tier.FAST,
        "memory": Tier.FAST, "cpu.stat": Tier.FAST, "sensors": Tier.FAST, "gpu": Tier.FAST,
        "disk.fill": Tier.FAST, "net.dev": Tier.FAST,
        "processes": Tier.MEDIUM, "units.failed": Tier.MEDIUM, "journal.warnings": Tier.MEDIUM,
        "journal.errors": Tier.MEDIUM,
        "listeners": Tier.MEDIUM, "kernel.tainted": Tier.MEDIUM, "containers": Tier.MEDIUM,
        "smart": Tier.SLOW, "firewall": Tier.SLOW, "kernel.modules": Tier.SLOW,
        "reboot.required": Tier.SLOW,
        "cron.system": Tier.SLOW, "cron.anacron": Tier.SLOW, "cron.d": Tier.SLOW,
        "cron.user": Tier.SLOW, "units.timers": Tier.SLOW, "units.detail": Tier.SLOW,
        "ssh.keys.home": Tier.DAILY, "ssh.keys.root": Tier.DAILY, "cron.hourly": Tier.DAILY,
        "cron.daily": Tier.DAILY, "cron.weekly": Tier.DAILY, "cron.monthly": Tier.DAILY,
        "units.files": Tier.DAILY,
    }
    for probe_id, tier in expected.items():
        assert BY_ID[probe_id].tier is tier, probe_id


def test_exact_invocations_the_plan_names() -> None:
    assert BY_ID["firewall"].argv == ("/usr/sbin/nft", "-j", "list", "ruleset")
    assert BY_ID["smart"].argv == ("/usr/sbin/smartctl", "-j", "-a", "/dev/{device}")
    assert BY_ID["units.failed"].argv == ("/usr/bin/systemctl", "list-units", "--failed", "-o",
                                          "json", "--no-pager")
    assert BY_ID["listeners"].argv == ("/usr/bin/ss", "-ltnupH")
    assert BY_ID["containers"].kind is Kind.DOCKER
    assert BY_ID["containers"].path == "/containers/json?all=1"
    assert BY_ID["ssh.keys.home"].kind is Kind.GLOB
    assert BY_ID["units.timers"].argv == ("/usr/bin/systemctl", "list-timers", "--all", "-o",
                                          "json", "--no-pager")
    detail = BY_ID["units.detail"].argv
    # --all: without it a pattern matches active units only, and most timers' services are not.
    assert detail[:4] == ("/usr/bin/systemctl", "show", "--all", "-p")
    assert detail[5:] == ("--timestamp=unix", "--no-pager", "*.service", "*.timer")
    assert {"Id", "TimersCalendar", "TimersMonotonic"} <= set(detail[4].split(","))
    journal = BY_ID["journal.warnings"].argv
    assert journal[journal.index("-n") + 1] == str(JOURNAL_LINES)


def test_scheduled_work_is_read_whole_not_listed() -> None:
    reads = {"cron.system": (Kind.FILE, "/etc/crontab"),
             "cron.anacron": (Kind.GLOB, "/etc/anacrontab*"),
             "cron.d": (Kind.GLOB, "/etc/cron.d/*"),
             "cron.user": (Kind.GLOB, "/var/spool/cron/crontabs/*"),
             "cron.hourly": (Kind.GLOB, "/etc/cron.hourly/*"),
             "cron.daily": (Kind.GLOB, "/etc/cron.daily/*"),
             "cron.weekly": (Kind.GLOB, "/etc/cron.weekly/*"),
             "cron.monthly": (Kind.GLOB, "/etc/cron.monthly/*")}
    for probe_id, (kind, path) in reads.items():
        assert (BY_ID[probe_id].kind, BY_ID[probe_id].path) == (kind, path), probe_id
        assert BY_ID[probe_id].domain == "security", probe_id
    assert "cron.spool" not in BY_ID
    # The names too, so a script the glob cannot read (a symlink, a dot name) is still seen.
    for directory in ("cron.d", "cron.hourly", "cron.daily", "cron.weekly", "cron.monthly"):
        names = BY_ID[f"{directory}.names"]
        assert (names.kind, names.path, names.domain, names.tier) == (
            Kind.LISTDIR, BY_ID[directory].path.removesuffix("/*"), "security",
            BY_ID[directory].tier), directory
    assert BY_ID["units.timers"].domain == BY_ID["units.detail"].domain == "services"


def test_journal_errors_is_the_warning_form_at_err_with_its_own_cap() -> None:
    warnings, errors = BY_ID["journal.warnings"].argv, BY_ID["journal.errors"].argv
    assert errors[errors.index("-p") + 1] == "err"
    assert warnings[warnings.index("-p") + 1] == "warning"
    assert errors[errors.index("-n") + 1] == str(JOURNAL_ERROR_LINES)
    # Everything but the priority and the cap is the same invocation.
    def rest(argv: tuple[str, ...]) -> list[str]:
        words = list(argv)
        for flag in ("-p", "-n"):
            del words[words.index(flag): words.index(flag) + 2]
        return words
    assert rest(errors) == rest(warnings)
    assert BY_ID["journal.errors"].domain == "logs"


def test_gpu_query_is_split_so_the_gate_sees_its_verb() -> None:
    argv = BY_ID["gpu"].argv
    assert argv[:2] == ("/usr/bin/nvidia-smi", "--query-gpu")
    assert argv[2].split(",")[0] == "index"
    assert argv[3] == "--format=csv,noheader,nounits"


def test_only_the_gpu_and_apt_probes_drop_root() -> None:
    # As root nvidia-smi recreates the /dev/char/195:* links each run, and apt may rebuild its
    # package cache; as nobody neither can.
    assert [probe.id for probe in CATALOG if probe.unprivileged] == ["gpu", "apt.upgrades"]


def test_only_the_smart_probe_is_a_device_template() -> None:
    templates = [probe.id for probe in CATALOG if probe.devices]
    assert templates == ["smart"]
    for probe in CATALOG:
        assert (DEVICE in " ".join(probe.argv)) == bool(probe.devices), probe.id


def test_the_catalog_is_immutable() -> None:
    with pytest.raises(dataclasses.FrozenInstanceError):
        CATALOG[0].argv = ("rm", "-rf", "/")  # type: ignore[misc]
    assert isinstance(CATALOG, tuple)


# --- ProbeSpec validation ---------------------------------------------------------------------


@pytest.mark.parametrize(("changes", "message"), [
    ({"id": "Bad Id"}, "id"),
    ({"id": ""}, "id"),
    ({"domain": "weather"}, "domain"),
    ({"description": " "}, "description"),
    ({"tier": "fast"}, "tier"),
    ({"kind": "file"}, "kind"),
    ({"cost": "cheap"}, "cost"),
    ({"kind": Kind.COMMAND, "argv": (), "path": ""}, "argv"),
    ({"kind": Kind.COMMAND, "argv": ("/usr/bin/ss",), "path": "/x"}, "path"),
    ({"kind": Kind.COMMAND, "argv": ["/usr/bin/ss"], "path": ""}, "tuple"),
    ({"kind": Kind.COMMAND, "argv": ("/usr/bin/ss", 3), "path": ""}, "string"),
    ({"kind": Kind.COMMAND, "argv": ("/usr/bin/ss", ""), "path": ""}, "empty"),
    ({"kind": Kind.FILE, "argv": ("cat",)}, "argv"),
    ({"kind": Kind.COMMAND, "argv": ("ss", "-ltnupH"), "path": ""}, "absolute path"),
    ({"kind": Kind.FILE, "path": "proc/loadavg"}, "absolute"),
    ({"kind": Kind.DOCKER, "path": "containers/json"}, "absolute"),
    ({"kind": Kind.FILE, "path": "/proc/../etc/shadow"}, ".."),
    ({"kind": Kind.FILE, "path": "/proc/*"}, "wildcard"),
    ({"kind": Kind.LISTDIR, "path": "/etc/cron.?"}, "wildcard"),
    ({"kind": Kind.GLOB, "path": "/home/*/.ssh/../x"}, ".."),
    ({"devices": "^sd[a-z]$"}, "{device}"),
    ({"kind": Kind.COMMAND, "argv": ("/usr/sbin/smartctl", "-j", "-a", "/dev/{device}"),
      "path": ""}, "regex"),
    ({"kind": Kind.COMMAND, "argv": ("/usr/sbin/smartctl", "-j", "-a", "/dev/sda"), "path": "",
      "devices": "^sd[a-z]$"}, "{device}"),
    ({"kind": Kind.COMMAND, "argv": ("/usr/sbin/smartctl", "/dev/{device}"), "path": "",
      "devices": "(unclosed"}, "regex"),
    ({"unprivileged": True}, "only a command"),
    ({"kind": Kind.COMMAND, "argv": ("/usr/bin/ss",), "path": "", "unprivileged": 1}, "bool"),
])
def test_an_inconsistent_spec_is_refused(changes: dict, message: str) -> None:
    with pytest.raises(ValueError, match=re.escape(message)):
        spec(**changes)


def test_well_formed_specs_of_each_kind_construct() -> None:
    spec(kind=Kind.GLOB, path="/home/*/.ssh/authorized_keys*")
    spec(kind=Kind.LISTDIR, path="/etc/cron.d")
    spec(kind=Kind.DOCKER, path="/containers/json?all=1")
    spec(kind=Kind.COMMAND, argv=("/usr/bin/ss", "-ltnupH"), path="")
    spec(kind=Kind.COMMAND, argv=("/usr/bin/ss", "-ltnupH"), path="", unprivileged=True)


# --- expand -----------------------------------------------------------------------------------


SMART = BY_ID["smart"]


def test_expand_substitutes_each_matching_device() -> None:
    expanded = expand(SMART, ("nvme0n1", "sda"))
    assert [probe.id for probe in expanded] == ["smart.nvme0n1", "smart.sda"]
    assert expanded[0].argv == ("/usr/sbin/smartctl", "-j", "-a", "/dev/nvme0n1")
    assert expanded[1].argv == ("/usr/sbin/smartctl", "-j", "-a", "/dev/sda")
    for probe in expanded:
        assert probe.devices == ""
        assert (probe.tier, probe.kind, probe.cost, probe.domain) == (
            SMART.tier, SMART.kind, SMART.cost, SMART.domain)
        assert approved_expansion(probe.argv, probe.id.removeprefix("smart."))


def test_expand_keeps_a_templates_privilege_drop() -> None:
    template = dataclasses.replace(SMART, unprivileged=True)
    assert all(probe.unprivileged for probe in expand(template, ("sda",)))


def test_the_approved_expansion_check_can_fail() -> None:
    assert not approved_expansion(("/usr/sbin/smartctl", "-j", "-a", "/dev/loop0"), "loop0")
    assert not approved_expansion(("/usr/sbin/smartctl", "-j", "-a", "-s", "/dev/sda"), "sda")
    assert not approved_expansion(("/usr/sbin/smartctl", "-j", "-a", "/dev/sda"), "sdb")


def test_expand_of_no_devices_is_empty() -> None:
    assert expand(SMART, ()) == ()


@pytest.mark.parametrize("name", ["loop0", "nvme0n1p1", "sda1", "dm-0", "../sda", "sda;reboot",
                                  "sda ", "", "nvme0n1\n", "zram0"])
def test_expand_refuses_a_name_the_regex_does_not_fully_match(name: str) -> None:
    with pytest.raises(ValueError, match="does not match"):
        expand(SMART, ("sda", name))


def test_expand_refuses_a_spec_that_is_not_a_template() -> None:
    with pytest.raises(ValueError, match="not a device template"):
        expand(BY_ID["load"], ("sda",))


def test_expand_refuses_a_template_that_lost_its_regex() -> None:
    # Constructing one is refused, so the only way to hold one is to bypass __post_init__.
    broken = object.__new__(ProbeSpec)
    for name, value in dataclasses.asdict(SMART).items():
        object.__setattr__(broken, name, value)
    object.__setattr__(broken, "devices", "")
    with pytest.raises(ValueError, match="not a device template"):
        expand(broken, ("sda",))


def test_the_smart_regex_admits_the_names_sys_block_lists() -> None:
    admitted = [n for n in ("loop0", "nvme0n1", "nvme12n3", "sda", "sdab", "sr0", "zram0")
                if re.fullmatch(SMART.devices, n)]
    assert admitted == ["nvme0n1", "nvme12n3", "sda", "sdab"]
    assert BY_ID["block.devices"].path == "/sys/block"
