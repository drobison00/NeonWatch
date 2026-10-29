"""The envelope and the typed bodies refuse everything they did not declare."""

from __future__ import annotations

import json

import pytest

from neonwatch.schema import (
    MAX_BYTES,
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
    decode_event,
    encode_event,
    from_body,
    to_body,
)


def event(**overrides) -> Event:
    fields = {"kind": Kind.OBSERVATION, "at": 1.5, "source": "agent", "subject": "obs.loadavg",
              "body": {"probe": "loadavg"}}
    fields.update(overrides)
    return Event(**fields)


def test_an_event_round_trips():
    original = event()
    assert decode_event(encode_event(original)) == original


@pytest.mark.parametrize("raw, message", [
    (b"not json", "not JSON"),
    (b"\xff", "not JSON"),
    (b"[]", "a JSON object"),
    (json.dumps({"v": 1}).encode(), "exactly"),
    (json.dumps({"v": 2, "kind": "observation", "at": 1, "source": "a", "subject": "obs.x",
                 "body": {}}).encode(), "version 2"),
    (json.dumps({"v": 1, "kind": "command", "at": 1, "source": "a", "subject": "obs.x",
                 "body": {}}).encode(), "unknown kind"),
    (json.dumps({"v": 1, "kind": "observation", "at": 1, "source": "a", "subject": "obs.x",
                 "body": {}, "extra": 1}).encode(), "exactly"),
])
def test_what_is_not_an_event_is_refused(raw, message):
    with pytest.raises(SchemaError, match=message):
        decode_event(raw)


@pytest.mark.parametrize("overrides, message", [
    ({"at": True}, "non-negative number"),
    ({"at": -1}, "non-negative number"),
    ({"source": " "}, "`source`"),
    ({"subject": ""}, "`subject`"),
    ({"subject": "issue.x"}, "starts with 'obs'"),
    ({"body": []}, "`body` must be an object"),
])
def test_a_malformed_envelope_is_refused_both_ways(overrides, message):
    with pytest.raises(SchemaError, match=message):
        encode_event(event(**overrides))


def test_oversized_events_are_refused_both_ways():
    with pytest.raises(SchemaError, match="over the"):
        encode_event(event(body={"x": "a" * MAX_BYTES}))
    with pytest.raises(SchemaError, match="over the"):
        decode_event(b" " * (MAX_BYTES + 1))


def test_typed_bodies_round_trip():
    records = [
        Observation("loadavg", {"one": 0.5}, cpu_ms=2),
        Finding("smart.critical", Severity.CRITICAL, "NVMe critical warning", "disk:/dev/nvme0",
                {"critical_warning": 4}),
        Attestation("ctx-1", "process", "processes", "pid:42", "runaway", "Is it runaway?",
                    {"noul": 0.9}, Severity.WARN, "loop", "check its log", 0.9, None, 120),
        Issue("i-1", IssueState.OPEN, Severity.WARN, "t", "processes", "pid:42", 1.0, 2.0,
              False, ("runaway",), "check its log", 0.7),
        Heartbeat(0.004, False, ("/",), ran=12, failed=1, deferred=0),
        Link("l-1", ("issue:i-1", "issue:i-2"), "shared-entity", 0.91, "issue:i-1", 0.8, True),
        Analysis("a-1", 1.0, 9.0, "openai-compatible", "m", ("issue:i-1",), "why?", "text",
                 ("journalctl -u x -n 100 --no-pager",), 1200, 300),
    ]
    for record in records:
        body = json.loads(json.dumps(to_body(record)))
        assert from_body(type(record), body) == record


@pytest.mark.parametrize("body, message", [
    ("x", "must be an object"),
    ({"probe": "p", "data": {}, "cpu_ms": 1, "surprise": 1}, "no field"),
    ({"probe": "p", "data": {}}, "missing cpu_ms"),
    ({"probe": 3, "data": {}, "cpu_ms": 1}, "expected a string"),
    ({"probe": "p", "data": [], "cpu_ms": 1}, "expected an object"),
    ({"probe": "p", "data": {}, "cpu_ms": 1.5}, "expected int"),
    ({"probe": "p", "data": {}, "cpu_ms": True}, "expected int"),
    ({"probe": "p", "data": {}, "cpu_ms": 1, "truncated": "no"}, "expected a boolean"),
])
def test_a_mistyped_observation_is_refused(body, message):
    with pytest.raises(SchemaError, match=message):
        from_body(Observation, body)


def test_enums_optionals_and_tuples_are_held_to_their_types():
    base = to_body(Heartbeat(0.1, True, (), 1, 0, 0))
    with pytest.raises(SchemaError, match="expected a list"):
        from_body(Heartbeat, {**base, "writable": "/"})
    finding = to_body(Finding("r", Severity.INFO, "t", "e"))
    with pytest.raises(SchemaError, match="is not one of"):
        from_body(Finding, {**finding, "severity": "apocalyptic"})
    attest = to_body(Attestation("c", "k", "d", "e", "q", "i", {}, Severity.INFO, "", "", 0.5,
                                 True, 1))
    assert from_body(Attestation, {**attest, "stable": None}).stable is None
    with pytest.raises(SchemaError, match="expected a boolean"):
        from_body(Attestation, {**attest, "stable": "yes"})
    # Recorded before judges had names: still readable, with no name.
    old = {k: v for k, v in attest.items() if k != "judge"}
    assert from_body(Attestation, old).judge == ""


def test_only_records_become_bodies():
    with pytest.raises(SchemaError, match="not a record"):
        to_body({"a": 1})


def test_a_heartbeat_without_a_drop_count_still_decodes():
    body = to_body(Heartbeat(0.1, True, (), 1, 0, 0))
    del body["dropped"]
    assert from_body(Heartbeat, body).dropped == 0


def test_a_finding_without_a_next_step_still_decodes():
    body = to_body(Finding("r", Severity.WARN, "t", "e", {}, "systemctl status x"))
    assert from_body(Finding, body).next_step == "systemctl status x"
    del body["next_step"]
    assert from_body(Finding, body).next_step == ""


@pytest.mark.parametrize("raw", [
    b'{"v":1,"kind":"observation","at":NaN,"source":"a","subject":"obs.x","body":{}}',
    b'{"v":1,"kind":"observation","at":Infinity,"source":"a","subject":"obs.x","body":{}}',
    b'{"v":1,"kind":"observation","at":1,"source":"a","subject":"obs.x","body":{"x":NaN}}',
    b"[" * 100000 + b"]" * 100000,
])
def test_non_strict_and_pathological_json_is_refused_not_raised(raw):
    with pytest.raises(SchemaError, match="not JSON"):
        decode_event(raw)


@pytest.mark.parametrize("body", [{"x": float("nan")}, {"x": object()}])
def test_a_body_that_is_not_strict_json_is_refused_on_encode(body):
    with pytest.raises(SchemaError, match="not strict JSON"):
        encode_event(event(body=body))


def test_a_nan_or_infinite_time_is_refused():
    for at in (float("nan"), float("inf")):
        with pytest.raises(SchemaError, match="non-negative number"):
            encode_event(event(at=at))


def test_severity_ranks_in_declared_order():
    assert [s.rank for s in Severity] == [0, 1, 2, 3]
    assert Severity.CRITICAL.rank > Severity.WARN.rank
