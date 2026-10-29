"""What the judge can say back, as typed values the rest of the system can trust the shape of.

The judge does not chat. Each question it is asked has one of three types, and each answer is a
number, never prose:

- **noul**: the probability of yes, in [0, 1]. Near 0 is a strong no, not low confidence; near
  0.5 is ambiguous. There is no separate confidence.
- **choice**: one id from a closed set, the whole distribution over the set, and a confidence.
- **score**: a weighted position on N ordered levels, in [0, N-1] and usually fractional, with
  the distribution over levels and a confidence.

These are what the judge hands to `bank.interpret`. Construction validates the shape (numbers
in range, the choice inside its distribution, the score on its scale) and refuses anything else;
whether the answer fits the question that was asked is `interpret`'s check.
"""

from __future__ import annotations

import enum
import math
from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any

#: Score scales the judge accepts, in levels.
SCORE_LEVELS = (2, 10)


class AnswerError(ValueError):
    """This is not an answer, or not an answer to the question it is offered for."""


class AnswerKind(enum.Enum):
    NOUL = "noul"
    CHOICE = "choice"
    SCORE = "score"


def _unit(field: str, value: Any) -> float:
    # bool first: `isinstance(True, int)` holds, and True read as 1.0 is a probability nobody gave.
    if (isinstance(value, bool) or not isinstance(value, int | float) or math.isnan(value)
            or not 0.0 <= value <= 1.0):
        raise AnswerError(f"{field} must be a number in [0, 1], got {value!r}")
    return value


def _distribution(value: Any) -> Mapping[str, float]:
    if not isinstance(value, Mapping) or not value:
        raise AnswerError(f"probabilities must be a non-empty mapping, got {value!r}")
    for key, p in value.items():
        if not isinstance(key, str) or not key:
            raise AnswerError(f"a probability is keyed by a non-empty string, got {key!r}")
        _unit(f"probabilities[{key!r}]", p)
    return MappingProxyType(dict(value))


@dataclass(frozen=True, slots=True)
class NoulAnswer:
    #: Probability of yes.
    p: float

    def __post_init__(self) -> None:
        _unit("p", self.p)

    @property
    def kind(self) -> AnswerKind:
        return AnswerKind.NOUL


@dataclass(frozen=True, slots=True)
class ChoiceAnswer:
    choice: str
    #: Option id -> probability. A read-only copy of what was given.
    probabilities: Mapping[str, float]
    #: A second axis, not the winning probability.
    confidence: float

    def __post_init__(self) -> None:
        object.__setattr__(self, "probabilities", _distribution(self.probabilities))
        if self.choice not in self.probabilities:
            raise AnswerError(f"choice {self.choice!r} is not in its distribution "
                              f"{sorted(self.probabilities)}")
        _unit("confidence", self.confidence)

    @property
    def kind(self) -> AnswerKind:
        return AnswerKind.CHOICE


@dataclass(frozen=True, slots=True)
class ScoreAnswer:
    score: float
    #: How many levels the scale had. `score` means nothing without it.
    levels: int
    #: Level index (as a string, "0".."N-1") -> probability. A read-only copy.
    probabilities: Mapping[str, float]
    confidence: float

    def __post_init__(self) -> None:
        low, high = SCORE_LEVELS
        if (isinstance(self.levels, bool) or not isinstance(self.levels, int)
                or not low <= self.levels <= high):
            raise AnswerError(f"a score has {low}-{high} levels, got {self.levels!r}")
        if (isinstance(self.score, bool) or not isinstance(self.score, int | float)
                or math.isnan(self.score) or not 0 <= self.score <= self.levels - 1):
            raise AnswerError(f"score must be in [0, {self.levels - 1}], got {self.score!r}")
        object.__setattr__(self, "probabilities", _distribution(self.probabilities))
        _unit("confidence", self.confidence)

    @property
    def kind(self) -> AnswerKind:
        return AnswerKind.SCORE

    @property
    def normalized(self) -> float:
        """`score / (levels - 1)`: in [0, 1], so scales of different lengths compare."""
        return self.score / (self.levels - 1)


Answer = NoulAnswer | ChoiceAnswer | ScoreAnswer
