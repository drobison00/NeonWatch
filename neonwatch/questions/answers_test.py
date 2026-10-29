"""An answer is only what the judge can say: a probability, one declared choice, or a scale
position."""

from __future__ import annotations

import dataclasses
import math

import pytest

from neonwatch.questions.answers import (
    AnswerError,
    AnswerKind,
    ChoiceAnswer,
    NoulAnswer,
    ScoreAnswer,
)


def test_the_three_kinds_are_the_wire_names():
    assert [k.value for k in AnswerKind] == ["noul", "choice", "score"]
    assert NoulAnswer(0.5).kind is AnswerKind.NOUL
    assert ChoiceAnswer("a", {"a": 1.0}, 0.9).kind is AnswerKind.CHOICE
    assert ScoreAnswer(1.0, 3, {"0": 0.0, "1": 1.0, "2": 0.0}, 0.8).kind is AnswerKind.SCORE


@pytest.mark.parametrize("p", [0.0, 0.0001, 0.5, 1.0, 1])
def test_a_noul_is_a_probability(p):
    assert NoulAnswer(p).p == p


@pytest.mark.parametrize("p", [-0.01, 1.01, math.nan, math.inf, True, "0.5", None])
def test_a_noul_outside_zero_to_one_is_refused(p):
    with pytest.raises(AnswerError):
        NoulAnswer(p)


def test_answers_are_frozen():
    with pytest.raises(dataclasses.FrozenInstanceError):
        NoulAnswer(0.5).p = 0.9  # type: ignore[misc]


def test_a_choice_names_one_option_of_its_distribution():
    answer = ChoiceAnswer("act_now", {"ignore": 0.1, "act_now": 0.9}, 0.7)
    assert answer.choice == "act_now" and answer.confidence == 0.7
    assert dict(answer.probabilities) == {"ignore": 0.1, "act_now": 0.9}


def test_a_choice_distribution_is_a_copy_nobody_can_edit():
    source = {"a": 0.4, "b": 0.6}
    answer = ChoiceAnswer("b", source, 0.5)
    source["c"] = 1.0
    assert "c" not in answer.probabilities
    with pytest.raises(TypeError):
        answer.probabilities["a"] = 1.0  # type: ignore[index]


@pytest.mark.parametrize("choice, probabilities, confidence", [
    ("c", {"a": 0.5, "b": 0.5}, 0.5),          # not in the distribution
    ("a", {}, 0.5),                             # no distribution at all
    ("a", {"a": 1.2}, 0.5),                     # a probability over one
    ("a", {"a": 0.9, "b": -0.1}, 0.5),          # a negative probability
    ("a", {"a": math.nan}, 0.5),
    ("a", {"a": 1.0}, 1.5),                     # confidence over one
    ("a", {"a": 1.0}, -0.1),
    ("a", {"a": 1.0}, False),
    ("", {"": 1.0}, 0.5),                       # an empty id
    (3, {3: 1.0}, 0.5),                         # a non-string id
    ("a", [("a", 1.0)], 0.5),                   # not a mapping
])
def test_a_malformed_choice_is_refused(choice, probabilities, confidence):
    with pytest.raises(AnswerError):
        ChoiceAnswer(choice, probabilities, confidence)


def test_a_score_is_a_position_on_its_own_scale():
    answer = ScoreAnswer(1.5, 4, {"0": 0.1, "1": 0.4, "2": 0.4, "3": 0.1}, 0.6)
    assert answer.normalized == pytest.approx(0.5)
    assert ScoreAnswer(0.0, 2, {"0": 1.0, "1": 0.0}, 1.0).normalized == 0.0
    assert ScoreAnswer(9.0, 10, {str(i): 0.1 for i in range(10)}, 1.0).normalized == 1.0


@pytest.mark.parametrize("score, levels", [
    (-0.1, 5), (4.01, 5), (2.0, 1), (0.0, 11), (1.0, 2.0), (1.0, True), (math.nan, 5), ("1", 5),
])
def test_a_score_off_its_scale_is_refused(score, levels):
    with pytest.raises(AnswerError):
        ScoreAnswer(score, levels, {"0": 1.0}, 0.5)


@pytest.mark.parametrize("probabilities, confidence", [
    ({"0": 1.5}, 0.5), ({}, 0.5), ({"0": 1.0}, 2.0), ({"0": 1.0}, None),
])
def test_a_score_with_a_bad_distribution_or_confidence_is_refused(probabilities, confidence):
    with pytest.raises(AnswerError):
        ScoreAnswer(1.0, 3, probabilities, confidence)
