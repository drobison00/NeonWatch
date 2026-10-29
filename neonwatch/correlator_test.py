"""The correlator: candidates from plain items, and links from a scripted judge.

The fake judge is an object with an async `attest` that returns scripted Attestations; one test
also runs the real `Judge` over a fake transport, to hold the members contract at its consumer.
"""

from __future__ import annotations

import dataclasses
from collections.abc import Sequence
from typing import Any

import pytest

from neonwatch import correlator as corr
from neonwatch.config import Config
from neonwatch.correlator import Candidate, Correlator, Item, Slot, candidates
from neonwatch.judge import Judge
from neonwatch.questions import DOMAINS, ContextKind, bank_for
from neonwatch.schema import (
    Attestation,
    Context,
    Finding,
    Issue,
    IssueState,
    Link,
    Severity,
)

T0 = 1_790_000_000.0
WARN, WATCH, INFO, CRITICAL = Severity.WARN, Severity.WATCH, Severity.INFO, Severity.CRITICAL

# --- helpers -------------------------------------------------------------------------------------


def finding(rule: str, entity: str, at: float = T0, severity: Severity = WARN,
            title: str = "", evidence: dict[str, Any] | None = None) -> Item:
    return Item.of_finding(at, Finding(rule, severity, title or f"{rule} on {entity}", entity,
                                       evidence or {}))


def issue(id: str, domain: str, entity: str, at: float = T0, severity: Severity = WARN,
          title: str = "", reasons: tuple[str, ...] = ()) -> Item:
    return Item.of_issue(Issue(id=id, state=IssueState.OPEN, severity=severity,
                               title=title or f"issue {id}", domain=domain, entity=entity,
                               opened_at=at, updated_at=at + 900, deterministic=bool(reasons),
                               reasons=reasons, next_step=""))


def ids(candidate: Candidate) -> tuple[str, ...]:
    return tuple(m.id for m in candidate.members)


def groups(out: Sequence[Candidate]) -> dict[frozenset[str], Candidate]:
    return {frozenset(ids(c)): c for c in out}


def lock_case() -> list[Item]:
    """A hard lock's pattern: a crash-looping worker, veth churn, and the VPN agent's log flood."""
    return [
        finding("container.crash_loop", "container:shopfront-worker-1", T0, WARN,
                "Container shopfront-worker-1 is in a crash loop",
                {"state": "restarting", "status": "Restarting (1) 4 seconds ago",
                 "exit_code": 1, "image": "shopfront-worker:latest"}),
        finding("net.interface_churn", "net:interfaces", T0 + 90, WATCH,
                "Network interfaces churning at 412/hour (7 added, 6 removed)",
                {"added": ["veth3a1f2c9"], "removed": ["veth9b0e441"], "added_count": 7,
                 "removed_count": 6, "interval_s": 113.0, "per_hour": 412.0,
                 "limit_per_hour": 60}),
        finding("journal.flood", "unit:openvpn.service", T0 + 200, WATCH,
                "log flood: openvpn.service wrote 180 of 200 warnings and filled the "
                "journal read cap", {"lines": 180, "of": 200, "share": 0.9, "capped": True}),
    ]


def noul(p: float) -> dict[str, Any]:
    return {"type": "noul", "noul": p}


def choice(pick: str, over: Sequence[str]) -> dict[str, Any]:
    return {"type": "choice", "choice": pick,
            "probabilities": {o: (1.0 if o == pick else 0.0) for o in over},
            "confidence": 0.7}


class FakeJudge:
    """Answers `same_problem`, `one_incident` and `likely_cause` per context from a script.

    `script(context) -> {question id: raw answer}`; a question missing from the reply is not
    attested, as when the judge refuses or is down.
    """

    def __init__(self, script: Any = None, *, confidence: float = 0.8,
                 stable: dict[str, bool | None] | None = None) -> None:
        self.script = script or (lambda ctx: {"same_problem": noul(0.9),
                                              "one_incident": noul(0.8),
                                              "likely_cause": choice("m1", ["m1", "m2"])})
        self.confidence = confidence
        self.stable = stable or {}
        self.calls: list[tuple[Context, ...]] = []

    async def attest(self, contexts: Sequence[Context]) -> tuple[Attestation, ...]:
        self.calls.append(tuple(contexts))
        out = []
        for ctx in contexts:
            for question, answer in self.script(ctx).items():
                out.append(Attestation(
                    context=ctx.id, context_kind=ctx.kind, domain=ctx.domain,
                    entity=ctx.entity, question=question, instructions="...", answer=answer,
                    severity=INFO, cause="", next_step="", confidence=self.confidence,
                    stable=self.stable.get(question), latency_ms=80))
        return tuple(out)


def correlator(judge: Any = None) -> Correlator:
    return Correlator(judge or FakeJudge(), Config())


# --- items ---------------------------------------------------------------------------------------


def test_an_item_of_a_finding_has_the_id_the_store_resolves() -> None:
    item = finding("smart.critical_warning", "disk:/dev/nvme0", T0, CRITICAL, "SMART warning",
                   {"critical_warning": 4})
    assert item.id == "finding:smart.critical_warning@disk:/dev/nvme0"
    assert (item.kind, item.domain, item.entity, item.at, item.severity) == (
        "finding", "storage", "disk:/dev/nvme0", T0, CRITICAL)
    assert (item.title, item.rule, item.reasons) == ("SMART warning", "smart.critical_warning", ())
    assert item.evidence == {"critical_warning": 4}


def test_an_item_of_an_issue_is_dated_by_when_it_opened() -> None:
    item = issue("i-7", "containers", "container:web", T0, WATCH, "web restarting",
                 ("container.crash_loop",))
    assert item.id == "issue:i-7"
    assert (item.kind, item.domain, item.entity, item.at, item.severity) == (
        "issue", "containers", "container:web", T0, WATCH)
    assert (item.title, item.rule, item.reasons) == (
        "web restarting", "", ("container.crash_loop",))


@pytest.mark.parametrize(("rule", "domain"), [
    ("container.crash_loop", "containers"), ("net.interface_churn", "network"),
    ("journal.flood", "logs"), ("unit.failed", "services"), ("gpu.throttle", "gpu"),
    ("cpu.temperature", "cpu"), ("memory.oom_kill", "memory"), ("disk.fill", "storage"),
    ("edac.corrected", "hardware"), ("kernel.taint_changed", "kernel"),
    ("probe.stale", "probe"),  # not a domain: its own prefix, so it co-occurs with everything
])
def test_a_finding_domain_comes_from_its_rule(rule, domain) -> None:
    assert finding(rule, "x:y").domain == domain


def test_every_rule_domain_is_a_domain_the_bank_knows() -> None:
    known = {kind.value for kind in DOMAINS}
    assert set(corr.RULE_DOMAINS.values()) <= known


# --- the operator's case -------------------------------------------------------------------------


def test_the_operators_lock_is_one_candidate_grouping_all_three() -> None:
    out = candidates(lock_case(), window_s=600, limit=10)
    assert len(out) == 1
    (only,) = out
    assert ids(only) == ("finding:container.crash_loop@container:shopfront-worker-1",
                         "finding:net.interface_churn@net:interfaces",
                         "finding:journal.flood@unit:openvpn.service")
    assert only.basis == "template:crash-loop"


# --- shared entity -------------------------------------------------------------------------------


def test_items_with_the_same_entity_are_one_candidate() -> None:
    items = [finding("gpu.pcie_degraded", "gpu:0", T0),
             issue("i-1", "gpu", "gpu:0", T0 + 86_400)]  # a day apart: entity needs no window
    (only,) = candidates(items, window_s=60, limit=5)
    assert only.basis == "shared-entity"
    assert ids(only) == ("finding:gpu.pcie_degraded@gpu:0", "issue:i-1")


def test_a_container_named_in_an_issue_title_shares_its_entity() -> None:
    items = [finding("container.crash_loop", "container:shopfront-worker-1", T0),
             issue("i-3", "processes", "process:4242", T0 + 7200,
                   title="python in shopfront-worker-1 at 98% CPU")]
    (only,) = candidates(items, window_s=60, limit=5)
    assert only.basis == "shared-entity"
    assert set(ids(only)) == {"issue:i-3",
                              "finding:container.crash_loop@container:shopfront-worker-1"}


def test_a_name_in_another_form_of_entity_is_shared() -> None:
    items = [finding("unit.failed", "unit:openvpn.service", T0),
             issue("i-4", "logs", "log_burst:openvpn.service", T0 + 7200)]
    (only,) = candidates(items, window_s=60, limit=5)
    assert only.basis == "shared-entity"


@pytest.mark.parametrize("title", [
    "shopfront-worker-10 restarting",   # a longer name is another container
    "xshopfront-worker-1 restarting",
    "shopfront-worker-1/data is full",
    "shopfront-worker-1.bak restarting",
    "SHOPFRONT-WORKER-1 restarting",    # names are case-sensitive
])
def test_a_name_matches_only_as_a_whole_token(title) -> None:
    items = [finding("container.crash_loop", "container:shopfront-worker-1", T0),
             issue("i-5", "processes", "process:1", T0 + 7200, title=title)]
    assert candidates(items, window_s=60, limit=5) == ()


def test_a_name_at_the_end_of_a_sentence_still_matches() -> None:
    items = [finding("container.crash_loop", "container:shopfront-worker-1", T0),
             issue("i-5", "processes", "process:1", T0 + 7200,
                   title="high CPU in shopfront-worker-1.")]
    assert len(candidates(items, window_s=60, limit=5)) == 1


def test_short_names_and_unnamed_kinds_are_not_matched_in_titles() -> None:
    items = [finding("gpu.temperature", "gpu:0", T0, title="GPU 0 at 93 °C"),
             finding("disk.fill", "mount:/", T0 + 7200, title="Filesystem / is 95% full"),
             issue("i-6", "processes", "process:4242", T0 + 9000, title="0 / 4242 load")]
    assert candidates(items, window_s=60, limit=5) == ()


def test_a_shared_entity_group_keeps_the_six_most_severe_then_newest() -> None:
    items = [issue(f"i-{n}", "services", "unit:foo.service", T0 + n, severity)
             for n, severity in enumerate([INFO, INFO, WATCH, WARN, INFO, CRITICAL, INFO, WATCH])]
    (only,) = candidates(items, window_s=1, limit=5)
    assert len(only.members) == 6
    assert set(ids(only)) == {"issue:i-5", "issue:i-3", "issue:i-7", "issue:i-2", "issue:i-6",
                              "issue:i-4"}
    assert [m.at for m in only.members] == sorted(m.at for m in only.members)


# --- co-occurrence -------------------------------------------------------------------------------


def test_items_in_different_domains_close_in_time_co_occur() -> None:
    items = [finding("listener.new_wildcard", "listener:tcp/8080", T0),
             finding("kernel.taint_changed", "kernel:taint", T0 + 30)]
    (only,) = candidates(items, window_s=60, limit=5)
    assert only.basis == "co-occurrence"
    assert ids(only) == ("finding:listener.new_wildcard@listener:tcp/8080",
                         "finding:kernel.taint_changed@kernel:taint")


def test_co_occurrence_needs_different_domains_and_the_window() -> None:
    same_domain = [finding("unit.failed", "unit:a.service", T0),
                   finding("unit.failed", "unit:b.service", T0 + 1)]
    too_far = [finding("listener.new_wildcard", "listener:tcp/8080", T0),
               finding("kernel.taint_changed", "kernel:taint", T0 + 61)]
    assert candidates(same_domain, window_s=60, limit=5) == ()
    assert candidates(too_far, window_s=60, limit=5) == ()


def test_co_occurrence_strength_falls_with_the_gap() -> None:
    def strength(gap: float) -> float:
        items = [finding("listener.new_wildcard", "listener:tcp/8080", T0),
                 finding("kernel.taint_changed", "kernel:taint", T0 + gap)]
        return candidates(items, window_s=100, limit=5)[0].strength

    assert strength(0) > strength(40) > strength(100) > 0


def test_co_occurrence_takes_one_item_per_domain_and_windows_are_maximal() -> None:
    items = [finding("unit.failed", "unit:a.service", T0, WATCH),
             finding("unit.failed", "unit:b.service", T0 + 5, CRITICAL),
             finding("listener.new_wildcard", "listener:tcp/8080", T0 + 10),
             finding("kernel.taint_changed", "kernel:taint", T0 + 20)]
    out = [c for c in candidates(items, window_s=60, limit=10) if c.basis == "co-occurrence"]
    # one window holds everything; the later anchors' windows sit inside it and add nothing
    assert len(out) == 1
    assert set(ids(out[0])) == {"finding:unit.failed@unit:b.service",
                                "finding:listener.new_wildcard@listener:tcp/8080",
                                "finding:kernel.taint_changed@kernel:taint"}


def test_co_occurrence_caps_at_six_domains() -> None:
    rules = ["edac.corrected", "smart.wear", "cpu.temperature", "gpu.pcie_degraded",
             "unit.failed", "listener.new_wildcard", "kernel.taint_changed"]
    items = [finding(rule, f"x:{n}", T0 + n, CRITICAL if n == 6 else WARN)
             for n, rule in enumerate(rules)]
    (only,) = candidates(items, window_s=60, limit=10)
    assert len(only.members) == 6
    assert "finding:kernel.taint_changed@x:6" in ids(only)


# --- templates -----------------------------------------------------------------------------------


def test_the_crash_loop_template_needs_a_network_daemon_for_its_flood() -> None:
    items = lock_case()
    items[2] = finding("journal.flood", "unit:cups.service", T0 + 200, WATCH)
    out = candidates(items, window_s=600, limit=10)
    template = [c for c in out if c.basis == "template:crash-loop"]
    assert [set(ids(c)) for c in template] == [{
        "finding:container.crash_loop@container:shopfront-worker-1",
        "finding:net.interface_churn@net:interfaces"}]


def test_a_fuller_template_is_stronger() -> None:
    full = candidates(lock_case(), window_s=600, limit=10)[0]
    partial = candidates(lock_case()[:2], window_s=600, limit=10)[0]
    assert full.basis == partial.basis == "template:crash-loop"
    assert full.strength > partial.strength


@pytest.mark.parametrize(("name", "items"), [
    ("thermal-gpu", [finding("gpu.temperature", "gpu:0", T0),
                     finding("gpu.throttle", "gpu:1", T0 + 10)]),
    ("thermal-cpu", [finding("cpu.temperature", "cpu:k10temp", T0),
                     finding("memory.pressure", "memory:pressure", T0 + 10)]),
    ("storage", [finding("smart.media_errors", "disk:/dev/sda", T0),
                 finding("disk.fill", "mount:/srv", T0 + 10)]),
    ("memory", [finding("memory.pressure", "memory:pressure", T0),
                finding("memory.oom_kill", "memory:oom", T0 + 5),
                issue("i-9", "processes", "process:4242", T0 + 10)]),
])
def test_each_template_matches_its_pattern(name, items) -> None:
    out = candidates(items, window_s=60, limit=10)
    assert out[0].basis == f"template:{name}"
    assert set(ids(out[0])) == {i.id for i in items}


def test_an_issue_fills_a_rule_slot_through_its_reasons() -> None:
    items = [issue("i-1", "containers", "container:web", T0, reasons=("container.crash_loop",)),
             finding("net.interface_churn", "net:interfaces", T0 + 30)]
    assert candidates(items, window_s=60, limit=5)[0].basis == "template:crash-loop"


def test_a_template_is_windowed() -> None:
    items = [finding("smart.media_errors", "disk:/dev/sda", T0),
             finding("disk.fill", "mount:/srv", T0 + 61)]
    assert candidates(items, window_s=60, limit=10) == ()


def test_adding_a_template_is_one_table_entry(monkeypatch) -> None:
    items = [finding("listener.new_wildcard", "listener:tcp/22", T0),
             finding("agent.unconfined", "agent:self", T0 + 5)]
    before = candidates(items, window_s=60, limit=5)
    assert [c.basis for c in before] == ["co-occurrence"]
    monkeypatch.setitem(corr.TEMPLATES, "exposure", (Slot(rule="listener.new_wildcard"),
                                                     Slot(rule="agent.*")))
    after = candidates(items, window_s=60, limit=5)
    assert [c.basis for c in after] == ["template:exposure"]


def test_slots_match_on_rule_prefix_domain_kind_and_entity() -> None:
    item = issue("i-2", "processes", "process:openvpn", reasons=("process.cpu",))
    assert Slot(rule="process.*").matches(item)
    assert not Slot(rule="process").matches(item)
    assert Slot(domain="processes", kind="issue").matches(item)
    assert not Slot(domain="processes", kind="finding").matches(item)
    assert Slot(entity=r"^process:openvpn").matches(item)
    assert not Slot(entity=r"^unit:").matches(item)


def test_a_slot_that_matches_everything_is_refused() -> None:
    with pytest.raises(ValueError, match="slot"):
        Slot()


# --- dedup, limit, ordering ----------------------------------------------------------------------


def test_the_same_member_set_keeps_its_strongest_basis() -> None:
    # gpu:0 twice: shared-entity, co-occurrence (gpu vs gpu is one domain: no) and the template
    items = [finding("gpu.temperature", "gpu:0", T0), finding("gpu.throttle", "gpu:0", T0 + 5)]
    out = candidates(items, window_s=60, limit=10)
    assert len(out) == 1 and out[0].basis == "template:thermal-gpu"


def test_one_finding_seen_twice_is_never_a_group() -> None:
    items = [finding("disk.fill", "mount:/", T0), finding("disk.fill", "mount:/", T0 + 60)]
    assert candidates(items, window_s=600, limit=10) == ()


def test_the_newest_sighting_of_a_repeated_item_is_kept() -> None:
    items = [finding("gpu.pcie_degraded", "gpu:0", T0), issue("i-1", "gpu", "gpu:0", T0 + 10),
             finding("gpu.pcie_degraded", "gpu:0", T0 + 50)]
    (only,) = candidates(items, window_s=1, limit=5)
    assert [m.at for m in only.members] == [T0 + 10, T0 + 50]


def test_candidates_are_ranked_by_strength_then_newest_and_limited() -> None:
    items = [
        finding("gpu.temperature", "gpu:0", T0), finding("gpu.throttle", "gpu:0", T0 + 5),
        finding("unit.failed", "unit:x.service", T0 + 5000),
        issue("i-1", "services", "unit:x.service", T0 + 5001),
        finding("unit.failed", "unit:y.service", T0 + 9000),
        issue("i-2", "services", "unit:y.service", T0 + 9001),
    ]
    out = candidates(items, window_s=60, limit=10)
    assert [c.basis for c in out] == ["template:thermal-gpu", "shared-entity", "shared-entity"]
    assert "issue:i-2" in ids(out[1]) and "issue:i-1" in ids(out[2])
    assert [ids(c) for c in candidates(items, window_s=60, limit=2)] == [ids(c) for c in out[:2]]
    assert candidates(items, window_s=60, limit=0) == ()


def test_the_same_input_gives_the_same_output_in_any_order() -> None:
    items = [
        *lock_case(),
        finding("gpu.temperature", "gpu:0", T0 + 40), finding("gpu.throttle", "gpu:0", T0 + 45),
        issue("i-1", "processes", "process:1", T0 + 100, title="shopfront-worker-1 busy")]
    first = candidates(items, window_s=600, limit=10)
    assert first == candidates(list(reversed(items)), window_s=600, limit=10)
    assert first == candidates(items, window_s=600, limit=10)
    assert all(2 <= len(c.members) <= 6 for c in first)


@pytest.mark.parametrize(("window_s", "limit"), [(0, 5), (-1, 5), (float("nan"), 5),
                                                 (float("inf"), 5), (60, -1), (60, 1.5),
                                                 (60, True)])
def test_a_bad_window_or_limit_is_refused(window_s, limit) -> None:
    with pytest.raises(ValueError):
        candidates(lock_case(), window_s=window_s, limit=limit)


def test_a_candidate_has_two_to_six_distinct_members() -> None:
    a, b, _ = lock_case()
    with pytest.raises(ValueError, match="2-6"):
        Candidate((a,), "shared-entity", 0.9)
    with pytest.raises(ValueError, match="2-6"):
        Candidate((a, a), "shared-entity", 0.9)
    with pytest.raises(ValueError, match="2-6"):
        Candidate(tuple(issue(f"i-{n}", "x", "x:y") for n in range(7)), "shared-entity", 0.9)
    assert Candidate((a, b), "co-occurrence", 0.5).members == (a, b)


# --- linking -------------------------------------------------------------------------------------


async def test_all_candidates_go_to_the_judge_in_one_call() -> None:
    judge = FakeJudge()
    found = candidates([*lock_case(), finding("gpu.temperature", "gpu:0", T0 + 9000),
                        finding("gpu.throttle", "gpu:0", T0 + 9005)], window_s=600, limit=10)
    assert len(found) == 2
    await correlator(judge).link(found)
    assert len(judge.calls) == 1 and len(judge.calls[0]) == 2


async def test_no_candidates_asks_nothing() -> None:
    judge = FakeJudge()
    assert await correlator(judge).link([]) == ()
    assert judge.calls == []


async def test_a_context_carries_the_members_as_the_judge_reads_them() -> None:
    judge = FakeJudge()
    (only,) = candidates(lock_case(), window_s=600, limit=10)
    await correlator(judge).link([only])
    (ctx,) = judge.calls[0]
    assert (ctx.kind, ctx.domain) == ("correlation", "correlation")
    assert ctx.entity == f"correlation:{ctx.id}"
    members = ctx.state["members"]
    assert [m["id"] for m in members] == list(ids(only))
    assert members[0] == {"id": "finding:container.crash_loop@container:shopfront-worker-1",
                          "domain": "containers", "entity": "container:shopfront-worker-1",
                          "at": T0, "title": "Container shopfront-worker-1 is in a crash loop"}
    assert ctx.state["basis"] == "template:crash-loop"
    evidence = ctx.state["evidence"]
    assert [e["id"] for e in evidence] == list(ids(only))
    assert evidence[0]["severity"] == "warn" and evidence[0]["rule"] == "container.crash_loop"
    assert evidence[0]["detail"]["exit_code"] == 1
    assert set(ctx.state) == {"members", "basis", "evidence"}


async def test_context_ids_are_stable_hashes_of_the_member_set() -> None:
    judge = FakeJudge()
    a, b, c = lock_case()
    await correlator(judge).link([Candidate((a, b, c), "template:crash-loop", 0.9)])
    await correlator(judge).link([Candidate((c, a, b), "co-occurrence", 0.4)])
    await correlator(judge).link([Candidate((a, b), "co-occurrence", 0.4)])
    first, second, other = (call[0].id for call in judge.calls)
    assert first == second != other
    assert first.startswith("corr-") and len(first) == len("corr-") + 16


async def test_duplicate_candidates_are_asked_once() -> None:
    judge = FakeJudge()
    a, b, _ = lock_case()
    links = await correlator(judge).link([Candidate((a, b), "co-occurrence", 0.4),
                                          Candidate((b, a), "shared-entity", 0.9)])
    assert len(judge.calls[0]) == 1
    assert [link.basis for link in links] == ["co-occurrence"]


async def test_attestations_become_a_link() -> None:
    judge = FakeJudge(lambda ctx: {"same_problem": noul(0.83), "one_incident": noul(0.7),
                                   "likely_cause": choice("m2", ["m1", "m2", "m3"])},
                      confidence=0.66)
    (only,) = candidates(lock_case(), window_s=600, limit=10)
    (link,) = await correlator(judge).link([only])
    assert isinstance(link, Link)
    assert link.id == judge.calls[0][0].id
    assert link.members == ids(only)
    assert link.basis == "template:crash-loop"
    assert link.related == 0.83
    assert link.likely_cause == "finding:net.interface_churn@net:interfaces"
    assert link.confidence == 0.66
    assert link.stable is None


@pytest.mark.parametrize(("stable", "expected"), [
    ({}, None), ({"same_problem": True}, True), ({"one_incident": True}, True),
    ({"same_problem": True, "likely_cause": False}, False),
    ({"one_incident": False}, False),
])
async def test_a_link_is_stable_only_as_far_as_its_answers_held(stable, expected) -> None:
    judge = FakeJudge(stable=stable)
    (link,) = await correlator(judge).link(candidates(lock_case(), window_s=600, limit=10))
    assert link.stable is expected


@pytest.mark.parametrize(("same", "one", "linked"), [
    (0.5, 0.1, True), (0.49, 0.5, True), (0.49, 0.49, False), (0.1, None, False),
    (0.9, None, True),
])
async def test_a_link_needs_related_or_one_incident_at_the_threshold(same, one, linked) -> None:
    def script(ctx: Context) -> dict[str, Any]:
        answers = {"same_problem": noul(same)}
        if one is not None:
            answers["one_incident"] = noul(one)
        return answers

    assert corr.LINK_THRESHOLD == 0.5
    links = await correlator(FakeJudge(script)).link(
        candidates(lock_case(), window_s=600, limit=10))
    assert bool(links) is linked
    if linked:
        assert links[0].likely_cause == ""  # not answered


async def test_no_attestations_means_no_link() -> None:
    down = FakeJudge(lambda ctx: {})
    assert await correlator(down).link(candidates(lock_case(), window_s=600,
                                                  limit=10)) == ()


async def test_one_incident_alone_is_not_a_guess_at_related() -> None:
    judge = FakeJudge(lambda ctx: {"one_incident": noul(0.95),
                                   "likely_cause": choice("m1", ["m1", "m2", "m3"])})
    assert await correlator(judge).link(candidates(lock_case(), window_s=600,
                                                   limit=10)) == ()


@pytest.mark.parametrize("answer", [
    choice("m9", ["m1", "m9"]), choice("x1", ["x1", "m1"]), choice("m0", ["m0", "m1"]),
    {"type": "choice", "choice": 1}, {"type": "choice"},
])
async def test_a_likely_cause_that_names_no_member_is_empty(answer) -> None:
    judge = FakeJudge(lambda ctx: {"same_problem": noul(0.9), "likely_cause": answer})
    (link,) = await correlator(judge).link(candidates(lock_case(), window_s=600, limit=10))
    assert link.likely_cause == ""


@pytest.mark.parametrize("answer", [{"type": "noul"}, {"type": "noul", "noul": True},
                                    {"type": "noul", "noul": 1.5}, {"type": "noul", "noul": "x"}])
async def test_a_malformed_probability_yields_no_link(answer) -> None:
    judge = FakeJudge(lambda ctx: {"same_problem": answer, "one_incident": noul(0.9)})
    assert await correlator(judge).link(candidates(lock_case(), window_s=600,
                                                   limit=10)) == ()


async def test_only_the_answered_candidates_link() -> None:
    items = [*lock_case(), finding("gpu.temperature", "gpu:0", T0 + 9000),
             finding("gpu.throttle", "gpu:0", T0 + 9005)]
    found = candidates(items, window_s=600, limit=10)
    answered = None

    def script(ctx: Context) -> dict[str, Any]:
        nonlocal answered
        if answered is None:
            answered = ctx.id
            return {"same_problem": noul(0.9)}
        return {}

    links = await correlator(FakeJudge(script)).link(found)
    assert [link.id for link in links] == [answered]


async def test_attestations_about_other_contexts_are_ignored() -> None:
    class Stray(FakeJudge):
        async def attest(self, contexts):
            out = await super().attest(contexts)
            return tuple(dataclasses.replace(a, context="someone-else") for a in out)

    assert await correlator(Stray()).link(candidates(lock_case(), window_s=600,
                                                     limit=10)) == ()


async def test_linking_never_changes_a_member() -> None:
    items = lock_case()
    before = [dataclasses.replace(i) for i in items]
    found = candidates(items, window_s=600, limit=10)
    await correlator().link(found)
    assert items == before
    assert [m for c in found for m in c.members] == before


# --- the real judge, at the seam -----------------------------------------------------------------


async def test_the_real_judge_asks_likely_cause_over_the_members_and_the_link_maps_back() -> None:
    asked: list[dict[str, Any]] = []

    async def post(body: dict[str, Any]) -> dict[str, Any]:
        asked.append(body)
        answers = {}
        for qid, question in body["questions"].items():
            criteria = question["criteria"]
            if question["type"] == "noul":
                answers[qid] = noul(0.9 if qid == "same_problem" else 0.1)
            elif question["type"] == "choice":
                keys = list(criteria)
                answers[qid] = choice("m3" if qid == "likely_cause" else keys[0], keys)
            else:
                n = len(criteria)
                answers[qid] = {"type": "score", "score": 0, "confidence": 0.5,
                                "probabilities": {str(i): (1.0 if i == 0 else 0.0)
                                                  for i in range(n)}}
        return {"answers": answers}

    judge = Judge(post, Config())
    found = candidates(lock_case(), window_s=600, limit=10)
    (link,) = await Correlator(judge, Config()).link(found)
    likely = next(body["questions"]["likely_cause"] for body in asked
                  if "likely_cause" in body["questions"])
    assert list(likely["criteria"]) == ["m1", "m2", "m3"]
    assert "openvpn.service" in likely["criteria"]["m3"]
    assert link.likely_cause == "finding:journal.flood@unit:openvpn.service"
    assert link.related == 0.9
    bank = {q.id for q in bank_for(ContextKind.CORRELATION)}
    assert {corr.SAME_PROBLEM, corr.ONE_INCIDENT, corr.LIKELY_CAUSE} <= bank


def test_an_empty_entity_is_not_a_shared_one() -> None:
    items = [issue("i-1", "services", "", T0), issue("i-2", "services", "", T0 + 5)]
    assert candidates(items, window_s=60, limit=5) == ()
