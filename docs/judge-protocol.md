# The judge protocol

NeonWatch's evaluator asks a **judge** closed questions about each context it builds (a process
snapshot, a container, a failing unit, a group of related issues...). The judge is any HTTP
server on loopback that answers this protocol. It is optional: without one, the deterministic
rules alone raise issues, and the dashboard's *Judge* vital reads "unreachable".

What the judge is for, and how it fits with the analyst, is in [`models.md`](models.md). The
client is `neonwatch/judge.py`; its module docstring is the normative description, and this
page is a summary for someone writing a server.

## Configuration

```toml
[judge]
name = "Qwen 7B judge (GPU 0)"               # what the dashboard and APIs call it (default "Judge")
url = "http://127.0.0.1:8200/v1/systemone"   # plain http, loopback only; redirects are refused
model = "judge"                              # sent as-is; a server may ignore it
concurrency = 2                              # requests in flight at once (1-16)
max_questions_per_request = 24
max_state_chars = 24000                      # state plus questions, per request
timeout_s = 60.0
```

`name` never goes on the wire. It is how NeonWatch labels this model at this endpoint: in the
dashboard, in `/api/health`, and on each attestation as its `judge` field.
[`configuration.md`](configuration.md#judge-the-typed-decision-model-optional) has every key.

## Request

`POST {url}` with a JSON body (the instructions here are abridged):

```json
{
  "model": "judge",
  "state": { "...": "the context's state, redacted" },
  "questions": {
    "overheating": {
      "type": "noul",
      "instructions": "Is any component running hotter than is safe for it?",
      "criteria": {"true": "yes", "false": "no"}
    },
    "likely_cause": {
      "type": "choice",
      "instructions": "Which member is most likely the cause of the others?",
      "criteria": {"m1": "finding:unit.failed | services | unit:x.service", "m2": "..."}
    },
    "urgency": {
      "type": "score",
      "instructions": "How soon does this need attention?",
      "criteria": ["it can wait", "this week", "today", "now"]
    }
  }
}
```

- `state` is usually an object. When a context's state is too large for the budget it is cut
  deterministically and sent as a **string** ending in
  `...[truncated by neonwatch: N characters of state cut to M]`.
- **Key order is meaning.** A choice's options and a score's levels are in the bank's order, and
  bodies are never key-sorted. Read them in the order they arrive.
- A question may be **re-asked** for stability with its options reversed (a choice), its levels
  reversed (a score), or its criteria swapped (a noul: `{"true": "no", "false": "yes"}`). The
  client maps the answer back; a server needs to do nothing special, only answer what it is
  given.

## Reply

```json
{
  "model": "whatever-you-are",
  "answers": {
    "overheating": {"type": "noul", "noul": 0.12},
    "likely_cause": {"type": "choice", "choice": "m1",
                     "probabilities": {"m1": 0.7, "m2": 0.3}, "confidence": 0.8},
    "urgency": {"type": "score", "score": 2, "expected": 1.6,
                "probabilities": {"0": 0.1, "1": 0.3, "2": 0.5, "3": 0.1}, "confidence": 0.7}
  },
  "usage": {"input_tokens": 1234},
  "latency_s": 0.9
}
```

- The reply's top-level keys are `answers` (required) and optionally `model`, `usage` and
  `latency_s`; any other key refuses the whole reply.
- `answers` may leave a question out (it then gets no attestation), but may not answer one that
  was not asked.
- **noul**: `noul` is the probability, in [0, 1], that the `"true"` criterion holds. It may also
  carry `probability`, `value` and `confidence`, which are ignored.
- **choice**: `choice` is one of the option ids; `probabilities` covers exactly the option ids
  and sums to 1 (within 0.02); `confidence` is in [0, 1].
- **score**: `probabilities` is keyed `"0"` to `"N-1"` for N levels and sums to 1; `score` is in
  [0, N-1]; `expected`, the weighted position, is used instead of `score` when present;
  `confidence` is in [0, 1]. `legend` is allowed and ignored. Scales have 2 to 10 levels.

An answer that fails these checks gives no attestation for its question and is counted in the
judge's health; a reply that is not an answer to its request gives none for any of its questions.
Neither ever becomes a guess.

## What an answer can do

A judge's answer is an **attestation**: it can raise an issue or rank it higher, but never clear
an issue a rule raised or hold it below the rule's severity. Suggested next steps attached to a
question are filled with the context's entity, shell-quoted, and dropped if the result could
modify the system (`questions.refuse_mutating`). The questions themselves are in
`neonwatch/questions/bank.py`; each names the evidence it needs, and is not asked of a context
that lacks it.
