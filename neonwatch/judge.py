"""The judge adapter, and its own client.

`Judge.attest` takes contexts and returns attestations: for each context it asks the question
bank of its kind, leaving out each question whose evidence the state lacks (`needs_present`),
packed into as few requests as the budget allows, runs every request
for every context at once up to `judge.concurrency`, validates every answer against the question
that was actually asked, and re-asks where stability decides something.

**The wire.** `POST {"model", "state", "questions": {id: {"type", "instructions", "criteria"}}}`.
Criteria: a noul's are always sent as `{"true": "yes", "false": "no"}`, so the re-ask can swap
them; a choice's are `{option id: description}` in the bank's order; a score's are its level
descriptions, low to high. Key order is meaning here, so bodies are never key-sorted.

**Packing.** A request's size is the characters of its state plus the compact JSON of its
questions, and it may not exceed `judge.max_state_chars`; nor may it carry more than
`judge.max_questions_per_request` questions. The state is redacted first. When one context's state
alone leaves no room for its largest question, it is cut deterministically and sent as a string
ending in a marker that says how much there was. Questions keep bank order and fill each request
before the next opens, so the same inputs always make the same bodies.

**Stability**: a stability-checked question is re-asked only when its
first answer reads WARN or above. The re-ask reverses a choice's options, reverses a score's levels
(and maps the answer back), and swaps a noul's criteria (and inverts p). `stable` is whether the
re-ask lands on the same option (choice), the same severity (noul), or, for a score, the same
severity or within `SCORE_DRIFT` (0.5) levels of the first answer, so an answer sitting on a
threshold does not read as a flip (measured live: urgency 3.48 then 3.594, either side of 3.5).
`None` when it was not re-asked, or the re-ask failed or was refused. A context's re-asks are
packed like its first asks, and are sent as soon as that context's first answers are in.

A score's value is its weighted position (`expected` on the wire), not the argmax level.

**A judge server may answer requests serially** (measured on one): time is linear in the
total number of questions, about 80 ms each, whether they are packed into one request or spread
over concurrent ones; eight concurrent 12-question requests finished in a ~1 s staircase. Each
question is its own prompt with the state repeated (input tokens ~ questions x (state +
question)). Concurrency above 1-2 buys no throughput and only queues on a shared server; packing
costs nothing and saves round trips.

**A correlation's members.** `likely_cause` is a choice whose options come from the context. The
evaluator or correlator puts the members in `context.state["members"]`: a list of 2-6 objects,
each with a non-empty string `"id"` (`issue:i-1`, `finding:<rule>@<entity>`) and optionally
`"domain"`, `"entity"`, `"at"` and `"title"`. Option `mN` is `members[N-1]`, and its description is
those fields joined, in that order, capped at `MEMBER_SUMMARY_CHARS`. The attestation's answer says
`"choice": "mN"`; the caller maps it back by position. With no members that fit, the question is
not asked.

**Entities.** `{entity}` in a next step is filled with the bare entity: `context.entity` with
everything up to and including its first `:` removed, whatever the context kind, because rules
name entities by their own prefix (`gpu:0` -> `0`, `unit:openvpn.service` ->
`openvpn.service`, `container:shopfront-worker-1` -> `shopfront-worker-1`,
`listener:tcp/6379` -> `tcp/6379`, `process:4242` -> `4242`). An entity with no `:` is used as it
is. The attestation's own `entity` keeps the full name.

**Entity names are attacker-chosen** (security review: any local sender picks its syslog
identifier, and several steps start with sudo). The bare entity is filled as `shlex.quote(entity)`,
so it is one shell word and a safe name stays bare, and the filled step is run through
`questions.refuse_mutating`. A refused step is dropped (`next_step = ""`, the cause kept) and
counted in `health().refused_steps`; a refused step is never displayed. `refuse_mutating` refuses
`;`, `$(`, backticks and `>` even inside quotes, so such names always lose their step. Where a
template already quotes the placeholder (`grep -F 'pid={entity},'`), `shlex.quote` would close
those quotes, so a filled step is also dropped unless it parses into exactly the template's shell
words with the entity inside the placeholder's word. What quoting cannot stop is a name that is
itself an option (a leading `-`): it is refused only when the option is on `refuse_mutating`'s
list.

**Failure.** A request that fails (transport error, timeout, a reply that is not an answer to it)
yields no attestations for its questions and is counted; an answer that fails validation yields
none for its question and is counted. Neither ever becomes a guess, and `attest` never raises
for the judge's sake. It does raise, before sending anything, for a context of a kind it has no
bank for.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import math
import shlex
import time
import urllib.error
import urllib.request
from collections import deque
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

from neonwatch import redact
from neonwatch.config import Config
from neonwatch.questions import (
    Answer,
    AnswerError,
    AnswerKind,
    ChoiceAnswer,
    ContextKind,
    NoulAnswer,
    Option,
    Question,
    QuestionError,
    Reading,
    ScoreAnswer,
    bank_for,
    interpret,
    needs_present,
    needs_values,
    refuse_mutating,
)
from neonwatch.schema import Attestation, Context, Severity

#: `(body) -> reply`. Raises on anything that is not a reply; the judge counts it and moves on.
Transport = Callable[[dict[str, Any]], Awaitable[dict[str, Any]]]

NOUL_CRITERIA = {"true": "yes", "false": "no"}
NOUL_REVERSED = {"true": "no", "false": "yes"}

#: How far a distribution may sum from 1.
TOLERANCE = 0.02
#: How far, in levels, a score's re-ask may land from its first answer and still hold.
SCORE_DRIFT = 0.5
#: Latencies kept for the percentiles in `health`.
WINDOW = 256
MEMBER_SUMMARY_CHARS = 160
MEMBER_FIELDS = ("id", "domain", "entity", "at", "title")
MEMBERS = (2, 6)
#: Characters of evidence an attestation keeps (`evidence`).
EVIDENCE_CHARS = 2000
#: Largest reply read from the judge.
MAX_REPLY_BYTES = 4 << 20

TRUNCATED = " ...[truncated by neonwatch: {total} characters of state cut to {kept}]"

#: Top-level keys a reply may carry. Measured on the live server (1.2): model, answers, usage,
#: latency_s. Anything else is not a reply this version understands.
_REPLY_KEYS = frozenset({"model", "answers", "usage", "latency_s"})
#: Keys an answer of each type must and may carry. The live server adds `probability`, `value`
#: and `confidence` to a noul and `expected` (the weighted position) to a score.
_REQUIRED = {AnswerKind.NOUL: frozenset({"type", "noul"}),
             AnswerKind.CHOICE: frozenset({"type", "choice", "probabilities", "confidence"}),
             AnswerKind.SCORE: frozenset({"type", "score", "probabilities", "confidence"})}
_ALLOWED = {AnswerKind.NOUL: _REQUIRED[AnswerKind.NOUL] | {"probability", "value", "confidence"},
            AnswerKind.CHOICE: _REQUIRED[AnswerKind.CHOICE],
            AnswerKind.SCORE: _REQUIRED[AnswerKind.SCORE] | {"expected", "legend"}}


class TransportError(Exception):
    """The request did not produce a reply."""


class ReplyError(ValueError):
    """A reply came back, but it is not an answer to the request that was sent."""


@dataclass(frozen=True, slots=True)
class JudgeHealth:
    #: Whether the last request reached the judge. `None` before anything was asked.
    reachable: bool | None
    #: The most recent failure, kept after a later success. `""` if there has been none.
    last_error: str
    #: Over the last `WINDOW` requests that got a reply. `None` before there is one.
    p50_ms: float | None
    p95_ms: float | None
    in_flight: int
    #: Counts since this judge was made.
    requests: int
    refused_answers: int
    failed_requests: int
    #: Next steps dropped because the step, once filled, was not read-only.
    refused_steps: int
    #: Which judge this is: `judge.name`, `judge.model` and `judge.url` from the config.
    name: str = ""
    model: str = ""
    url: str = ""


def evidence(question: Question, cleaned: Any) -> dict[str, Any]:
    """What an answer at WATCH or above was about, kept with it: the redacted values at the
    question's `needs`,
    or, for a question that weighs the whole state, that state when it fits in
    `EVIDENCE_CHARS`. Nothing here is sent to the judge; it is what the dashboard shows of what was
    judged after the state itself has rolled over. Too large, it is kept as the start of its
    JSON (`truncated`) and its full size (`chars`); a whole state too large is not kept."""
    if question.needs:
        found: Any = needs_values(question, cleaned)
    elif isinstance(cleaned, Mapping):
        found = cleaned
    else:
        return {}
    text = dumps(found)
    if len(text) <= EVIDENCE_CHARS:
        return dict(found)
    if not question.needs:
        return {"omitted_chars": len(text)}
    return {"truncated": text[:EVIDENCE_CHARS], "chars": len(text)}


def dumps(value: Any) -> str:
    """Compact JSON, keys in the order given: how state is measured and bodies are sent."""
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False)


# --- the real client -----------------------------------------------------------------------------


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args: Any) -> None:
        return None  # a redirect is refused as an HTTP error, never followed off loopback


def _refuse_constant(name: str) -> Any:
    raise ValueError(f"{name} is not a number")


def urllib_transport(url: str, timeout_s: float) -> Transport:
    """The real transport: stdlib HTTP, in a thread, to a loopback `http://` URL only.

    Proxy settings in the environment are ignored, so a loopback URL stays on loopback.
    """
    parts = urlsplit(url)
    if parts.scheme != "http" or not parts.hostname or parts.username or parts.password:
        raise ValueError(f"The judge URL must be plain http:// to a host, got {url!r}")
    host = parts.hostname
    try:
        loopback = ipaddress.ip_address(host).is_loopback
    except ValueError:
        loopback = host == "localhost"
    if not loopback:
        raise ValueError(f"The judge URL must be loopback, got {host!r}")
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())

    def send(body: dict[str, Any]) -> dict[str, Any]:
        request = urllib.request.Request(url, data=dumps(body).encode(), method="POST",
                                         headers={"Content-Type": "application/json"})
        try:
            with opener.open(request, timeout=timeout_s) as response:
                data = response.read(MAX_REPLY_BYTES + 1)
        except urllib.error.HTTPError as bad:
            raise TransportError(f"HTTP {bad.code} from {url}") from None
        except OSError as bad:  # URLError is one
            raise TransportError(f"{url}: {bad}") from None
        if len(data) > MAX_REPLY_BYTES:
            raise TransportError(f"reply over {MAX_REPLY_BYTES} bytes")
        try:
            reply = json.loads(data, parse_constant=_refuse_constant)
        except ValueError as bad:
            raise TransportError(f"reply is not JSON: {bad}") from None
        if not isinstance(reply, dict):
            raise TransportError("reply is not a JSON object")
        return reply

    async def post(body: dict[str, Any]) -> dict[str, Any]:
        return await asyncio.to_thread(send, body)

    return post


# --- questions on the wire, answers off it -------------------------------------------------------


def wire(question: Question, *, reverse: bool) -> dict[str, Any]:
    """One question as the judge is asked it; `reverse` for the stability re-ask."""
    criteria: Any
    if question.kind is AnswerKind.NOUL:
        criteria = dict(NOUL_REVERSED if reverse else NOUL_CRITERIA)
    elif question.kind is AnswerKind.CHOICE:
        options = tuple(reversed(question.options)) if reverse else question.options
        criteria = {option.id: option.description for option in options}
    else:
        criteria = list(reversed(question.levels)) if reverse else list(question.levels)
    return {"type": question.kind.value, "instructions": question.instructions,
            "criteria": criteria}


def _number(field: str, value: Any, low: float, high: float) -> float:
    if (isinstance(value, bool) or not isinstance(value, int | float) or not math.isfinite(value)
            or not low <= value <= high):
        raise AnswerError(f"{field} must be a number in [{low}, {high}], got {value!r}")
    return value


def _distribution(value: Any, keys: Sequence[str]) -> dict[str, float]:
    if not isinstance(value, dict) or set(value) != set(keys):
        raise AnswerError(f"probabilities must cover exactly {list(keys)}, got {value!r}")
    probabilities = {key: _number(f"probabilities[{key!r}]", p, 0, 1) for key, p in value.items()}
    if abs(math.fsum(probabilities.values()) - 1) > TOLERANCE:
        raise AnswerError(f"probabilities sum to {math.fsum(probabilities.values())}, not 1")
    return probabilities


def parse_answer(question: Question, raw: Any, *, reverse: bool) -> Answer:
    """`raw` as a typed answer to `question`, read back into the bank's orientation.

    A score's value is the weighted position (`expected`) when the server sends it, else `score`.
    """
    kind = question.kind
    if not isinstance(raw, dict) or raw.get("type") != kind.value:
        raise AnswerError(f"{question.id}: expected a {kind.value} answer, got {raw!r}")
    if not _REQUIRED[kind] <= raw.keys() <= _ALLOWED[kind]:
        raise AnswerError(f"{question.id}: a {kind.value} answer has {sorted(_REQUIRED[kind])} "
                          f"and may have {sorted(_ALLOWED[kind] - _REQUIRED[kind])}, got "
                          f"{sorted(raw)}")
    if kind is AnswerKind.NOUL:
        p = _number("noul", raw["noul"], 0, 1)
        return NoulAnswer(1 - p if reverse else p)
    confidence = _number("confidence", raw["confidence"], 0, 1)
    if kind is AnswerKind.CHOICE:
        ids = [option.id for option in question.options]
        probabilities = _distribution(raw["probabilities"], ids)
        if not isinstance(raw["choice"], str) or raw["choice"] not in ids:
            raise AnswerError(f"{question.id}: choice {raw['choice']!r} is not one of {ids}")
        return ChoiceAnswer(raw["choice"], probabilities, confidence)
    top = len(question.levels) - 1
    probabilities = _distribution(raw["probabilities"], [str(i) for i in range(top + 1)])
    score = _number("score", raw["score"], 0, top)
    if "expected" in raw:
        score = _number("expected", raw["expected"], 0, top)
    if reverse:
        score = top - score
        probabilities = {str(top - int(key)): p for key, p in probabilities.items()}
    return ScoreAnswer(score, top + 1, probabilities, confidence)


# --- contexts into requests ----------------------------------------------------------------------


def _members(state: Mapping[str, Any]) -> tuple[Option, ...] | None:
    members = state.get("members")
    low, high = MEMBERS
    if not isinstance(members, list) or not low <= len(members) <= high:
        return None
    options = []
    for n, member in enumerate(members, 1):
        if not isinstance(member, Mapping) or not isinstance(member.get("id"), str) \
                or not member["id"].strip():
            return None
        summary = " | ".join(str(member[key]) for key in MEMBER_FIELDS
                             if member.get(key) not in (None, ""))
        options.append(Option(f"m{n}", summary[:MEMBER_SUMMARY_CHARS]))
    return tuple(options)


def _askable(context: Context) -> tuple[Question, ...]:
    questions = []
    for question in bank_for(ContextKind(context.kind)):
        if not needs_present(question, context.state):
            continue
        if question.dynamic_options:
            options = _members(context.state)
            if options is None:
                continue
            question = question.fill(options)
        questions.append(question)
    return tuple(questions)


def _bare(context: Context) -> str:
    return context.entity.split(":", 1)[1] if ":" in context.entity else context.entity


@dataclass(frozen=True, slots=True)
class _Prepared:
    context: Context
    questions: tuple[Question, ...]
    state: Any
    state_chars: int
    #: The redacted state before any cut: what each attestation's evidence is taken from.
    cleaned: Any = None


@dataclass(frozen=True, slots=True)
class _Request:
    questions: tuple[Question, ...]
    reverse: bool
    body: dict[str, Any]


@dataclass(frozen=True, slots=True)
class _Asked:
    raw: dict[str, Any]
    reading: Reading
    latency_ms: int


class Judge:
    """Asks the judge the bank for many contexts at once. One per process; share it."""

    def __init__(self, post: Transport, config: Config, *,
                 clock: Callable[[], float] = time.monotonic) -> None:
        self._post = post
        self._server = config.judge
        self._clock = clock
        self._semaphore = asyncio.Semaphore(config.judge.concurrency)
        self._latencies: deque[float] = deque(maxlen=WINDOW)
        self._reachable: bool | None = None
        self._last_error = ""
        self._in_flight = 0
        self._requests = 0
        self._refused = 0
        self._failed = 0
        self._refused_steps = 0

    async def attest(self, contexts: Sequence[Context]) -> tuple[Attestation, ...]:
        """Every answered question about every context, in context then bank order."""
        prepared = [self._prepare(context) for context in contexts]
        per_context = await asyncio.gather(*(self._judge(p) for p in prepared))
        return tuple(a for attestations in per_context for a in attestations)

    def health(self) -> JudgeHealth:
        ordered = sorted(self._latencies)

        def percentile(q: float) -> float | None:
            return ordered[math.ceil(q * len(ordered)) - 1] if ordered else None

        return JudgeHealth(self._reachable, self._last_error, percentile(0.5), percentile(0.95),
                           self._in_flight, self._requests, self._refused, self._failed,
                           self._refused_steps, name=self._server.name,
                           model=self._server.model, url=self._server.url)

    # --- one context ---

    def _prepare(self, context: Context) -> _Prepared:
        try:
            questions = _askable(context)
        except ValueError as bad:  # ContextKind refuses a kind with no bank
            raise QuestionError(f"context {context.id!r}: {bad}") from None
        cleaned, _ = redact.redact_mapping(context.state)
        text = dumps(cleaned)
        largest = max((len(dumps({q.id: wire(q, reverse=False)})) - 2 for q in questions),
                      default=0)
        room = self._server.max_state_chars - largest - 2
        if len(text) <= room:
            return _Prepared(context, questions, cleaned, len(text), cleaned)
        marker = TRUNCATED.format(total=len(text), kept=max(room, 0))
        state = text[:max(room - len(marker), 0)] + marker
        return _Prepared(context, questions, state, len(state), cleaned)

    def _pack(self, prepared: _Prepared, questions: Sequence[Question],
              reverse: bool) -> list[_Request]:
        budget, most = self._server.max_state_chars, self._server.max_questions_per_request
        batches: list[list[tuple[Question, dict[str, Any]]]] = []
        used = 0
        for question in questions:
            asked = wire(question, reverse=reverse)
            size = len(dumps({question.id: asked})) - 2
            if batches and len(batches[-1]) < most and used + 1 + size <= budget:
                batches[-1].append((question, asked))
                used += 1 + size
            else:
                batches.append([(question, asked)])
                used = prepared.state_chars + 2 + size
        return [_Request(tuple(q for q, _ in batch), reverse,
                         {"model": self._server.model, "state": prepared.state,
                          "questions": {q.id: asked for q, asked in batch}})
                for batch in batches]

    async def _judge(self, prepared: _Prepared) -> list[Attestation]:
        first = await self._ask_all(self._pack(prepared, prepared.questions, reverse=False))
        recheck = [q for q in prepared.questions if q.stability_check and q.id in first
                   and first[q.id].reading.severity.rank >= Severity.WARN.rank]
        again = await self._ask_all(self._pack(prepared, recheck, reverse=True))
        context, entity = prepared.context, _bare(prepared.context)
        out = []
        for question in prepared.questions:
            if question.id not in first:
                continue
            asked, stable = first[question.id], None
            if question.id in again:
                stable = _held(question, asked.reading, again[question.id].reading)
            reading = asked.reading
            out.append(Attestation(
                context=context.id, context_kind=context.kind, domain=context.domain,
                entity=context.entity, question=question.id, instructions=question.instructions,
                answer=asked.raw, severity=reading.severity, cause=reading.cause,
                next_step=self._fill(reading.next_step, entity),
                confidence=reading.confidence, stable=stable, latency_ms=asked.latency_ms,
                judge=self._server.name,
                # Only an answer that can raise or rank an issue keeps what it was about: the
                # quiet majority would double what attestations take to store, for nothing shown.
                evidence=evidence(question, prepared.cleaned)
                if reading.severity.rank >= Severity.WATCH.rank else {}))
        return out

    def _fill(self, template: str, entity: str) -> str:
        """The step with the entity as one shell word; `""` if the result is not read-only."""
        step = template.replace("{entity}", shlex.quote(entity))
        if step and (refuse_mutating(step) or not _same_words(template, step, entity)):
            self._refused_steps += 1
            return ""
        return step

    # --- requests ---

    async def _ask_all(self, requests: Sequence[_Request]) -> dict[str, _Asked]:
        replies = await asyncio.gather(*(self._send(request) for request in requests))
        return {id: asked for reply in replies for id, asked in reply.items()}

    async def _send(self, request: _Request) -> dict[str, _Asked]:
        async with self._semaphore:
            self._in_flight += 1
            self._requests += 1
            start = self._clock()
            try:
                reply = await asyncio.wait_for(self._post(request.body), self._server.timeout_s)
            except TimeoutError:
                return self._fail(f"timed out after {self._server.timeout_s}s", reachable=False)
            except Exception as bad:  # an injected transport may raise anything; count it
                return self._fail(f"{type(bad).__name__}: {bad}", reachable=False)
            finally:
                self._in_flight -= 1
            elapsed = self._clock() - start
        self._reachable = True
        self._latencies.append(elapsed * 1000)
        try:
            answers = _answers(reply, request)
        except ReplyError as bad:
            return self._fail(str(bad), reachable=True)
        out = {}
        for question in request.questions:
            try:
                answer = parse_answer(question, answers.get(question.id), reverse=request.reverse)
                reading = interpret(question, answer)
            except AnswerError:
                self._refused += 1
                continue
            out[question.id] = _Asked(answers[question.id], reading, round(elapsed * 1000))
        return out

    def _fail(self, error: str, *, reachable: bool) -> dict[str, _Asked]:
        self._failed += 1
        self._reachable = reachable
        self._last_error = error
        return {}


def _held(question: Question, first: Reading, again: Reading) -> bool:
    """Whether the re-ask agrees with the first answer (both read in the bank's orientation)."""
    if question.kind is AnswerKind.CHOICE:
        return again.value == first.value
    if question.kind is AnswerKind.SCORE and abs(float(again.value) - float(first.value)) \
            <= SCORE_DRIFT:
        return True  # a small move that happens to cross a threshold is not a flip
    return again.severity is first.severity


_SENTINEL = "NEONWATCHENTITY"


def _same_words(template: str, step: str, entity: str) -> bool:
    """Whether filling in the entity left the template's shell words as they were.

    `shlex.quote` makes the entity one word only where the placeholder stands outside quotes; in
    `grep -F 'pid={entity},'` its quotes close the template's, and a space or `|` in the name
    would split or pipe. So the filled step must parse into exactly the template's words, with
    the entity inside the words that held the placeholder.
    """
    try:
        words = shlex.split(step)
        expected = shlex.split(template.replace("{entity}", _SENTINEL))
    except ValueError:  # unbalanced quotes
        return False
    return words == [word.replace(_SENTINEL, entity) for word in expected]


def _answers(reply: Any, request: _Request) -> dict[str, Any]:
    if not isinstance(reply, dict) or not isinstance(reply.get("answers"), dict):
        raise ReplyError(f"a reply is an object with an `answers` object, got {reply!r:.200}")
    if unknown := sorted(set(reply) - _REPLY_KEYS):
        raise ReplyError(f"reply has unknown field(s) {unknown}")
    if extra := sorted(set(reply["answers"]) - {q.id for q in request.questions}):
        raise ReplyError(f"reply answers question(s) nobody asked: {extra}")
    return reply["answers"]
