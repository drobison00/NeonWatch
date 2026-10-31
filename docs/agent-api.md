# The local agent API

AI agents on this machine (Claude Code, Codex, anything that speaks HTTP or MCP) can read what the
dashboard shows, acknowledge and snooze issues, and start the dashboard's LLM jobs, through
versioned endpoints under `/api/agent/v1` on the running service, or through `neonwatch mcp`, a
stdio MCP server that wraps them:

- agents may **read** everything the dashboard shows, **acknowledge / snooze** issues, and
  **start LLM jobs** (an analysis of subjects with a question, service descriptions, log
  explanations) **without the operator's confirm step**;
- the interface is HTTP under `/api/agent/v1` **and** `neonwatch mcp`.

Nothing here reaches the host: the root agent is untouched, and an agent's writes change only
the monitor's own records (a hold on an issue) or ask the configured analyst a question.

## Credentials

**The agent token** lives in `<the store's directory>/agent.token`
(`~/.local/state/neonwatch/agent.token` by default), mode 0600. The service creates it at startup
when it is missing; `neonwatch agent-token` creates or finds it and says where; it is read with the
config loader's care (no symlink, a regular file, your uid, no group or other permission), and a
file that fails those checks is refused, never repaired. The dashboard re-reads it for every agent
request, so

    NeonWatch agent-token --rotate        # a new token; the old one stops working at once
    NeonWatch agent-token --show          # prints it (the only command that does)

take effect without a restart.

**Every request** carries both

    Authorization: Bearer <agent token>
    X-Neonwatch-Agent: <name>             # 1-64 of A-Z a-z 0-9 . _ : -

The name is attribution, not authentication: it is what the audit log and the dashboard record
(`agent:<name>`). The token is accepted only in that header, never as a cookie or a query
parameter, so CSRF does not apply and no CSRF token or `Origin` is needed. The comparison is
constant-time.

**Separation.** The dashboard's per-launch token and password sessions do not work on
`/api/agent/v1`, and the agent token works nowhere else (not on `/api/*`, not as `/?token=`).

**Loopback only.** The agent API refuses any request whose *socket* peer is not a loopback
address (headers such as `X-Forwarded-For` are ignored), even when the dashboard listens on the
LAN in password mode. It also refuses a request that carries `Origin` (a browser has no business
here) and a `Host` that is neither one of the dashboard's names nor `127.0.0.1:<port>`,
`localhost:<port>` or `[::1]:<port>`.

*Reaching it in LAN mode:* with `web.host` set to one specific LAN address, nothing listens on
loopback, and a connection to that address from this machine comes from that address, so the
agent API cannot be reached. Bind `web.host = "0.0.0.0"` (still TLS, password and
`allowed_hosts`) to serve loopback as well.

## Guardrails

- **The analyst's `reach` rules apply unchanged**: the jobs are the dashboard's own, run by the
  same `analyst`, which refuses an endpoint the config does not allow.
- **One job of each kind at a time**, shared with the dashboard (429 while one runs; analyses: at
  most 2 at once).
- **A write limit**: 30 writes a minute per agent name and 60 a minute in all (429 beyond, with
  the seconds to wait). A write is an acknowledgement, a snooze, or starting an LLM job; reads and
  estimates are not counted.
- **An audit log** in the store (bounded at 10,000 rows, oldest first out): `at`, `agent`,
  `action` (`ack`, `snooze`, `start_analysis`, `start_describe`, `start_explain`), `target` (the
  issue or job id) and `detail` (a snooze's `until`; for a job the estimate it was started from:
  `chars`, `requests`, `url_host`, `remote`, `model`, and `keys` or `subjects` and `question`).
  Successful writes are recorded; refused ones are not.
- **Holds are attributed.** An agent's acknowledgement or snooze is recorded as `agent:<name>`,
  pushed to open dashboards at once, and shown on the card and in the held section
  ("acknowledged by agent:claude"). The dashboard's own issue bodies carry the same `held_by`.
- **What comes back is data, not instructions.** Log lines, commands, unit and job definitions,
  process names and issue evidence are the host's own text, and analyses are a model's: anyone
  who can write to the journal or install a unit wrote some of it, and may have written it to
  steer an agent. `neonwatch mcp` says so in its `initialize` instructions. An agent should hold
  an issue or start a job because the operator asked, never because returned text did.

## Endpoints

All under `http://127.0.0.1:<web.port>/api/agent/v1` (https when the dashboard has a
certificate). Answers are JSON; an error is `{"error": "..."}` with the status: 400 a bad
request, 401 the token, 403 not loopback / a browser / a foreign Host, 404, 409 nothing to do or
a resolved issue, 429 a job running or the write limit, 503 no analyst / journal reader / token.

| method | path | what |
| --- | --- | --- |
| GET | `/summary` | vitals, open counts, open issues, held count, incidents |
| GET | `/issues[?state=open\|acknowledged\|snoozed\|resolved]` | issues, highest ranked first |
| GET | `/issues/{id}` | one issue with its findings, attestations and analyses |
| POST | `/issues/{id}/ack` | acknowledge (no body, or `{}`) |
| POST | `/issues/{id}/snooze` | `{"for_s": 3600}` or `{"until": <epoch>}`, at most 7 days |
| GET | `/services` | every loaded service, compact, with `key` and cached `described` |
| GET | `/services/{name}` | one service in full |
| GET | `/scheduled` | cron jobs and timers |
| GET | `/logs` | the last 200 journal lines with `key` and cached `explanation` |
| POST | `/jobs/analysis/estimate` | `{"subjects": [...], "question": "..."}`: what would be sent |
| POST | `/jobs/analysis` | start it (202) |
| POST | `/jobs/describe/estimate` | `{"keys": [...] \| "all_uncached"}` (service keys) |
| POST | `/jobs/describe` | start it (202) |
| POST | `/jobs/explain/estimate` | `{"keys": [...] \| "all_uncached"}` (log kind keys) |
| POST | `/jobs/explain` | start it (202) |
| GET | `/jobs/{id}` | a job's status (`an-`, `sd-`, `lx-` ids, the dashboard's too) |
| GET | `/audit[?limit=1-500&agent=<name>&since=<epoch>]` | the audit log, newest first |

**Shapes.** An *issue*: `id, state, severity, title, domain, entity, reasons, next_step,
deterministic, score, opened_at, updated_at, last_seen, evidence, why, held_by, snoozed_until`,
where `held_by` is `"operator"` (the dashboard), `"agent:<name>"`, or null when the issue is not
held. `evidence` is what it is about (the leading finding's evidence, else the leading
attestation's, frozen when it was judged), `why` the rule's reason it matters (`""` for none),
and `last_seen` when its conditions were last present (null on issues recorded before it was
kept); `last_seen` earlier than `updated_at` means they are gone and the issue is waiting to
resolve. Attestations carry their own `evidence`. The
*summary*: `now`, `vitals` (`agent`: the root agent's last heartbeat with `heartbeat_age_s`, or
null; `judge`; `store` `{ok, error}`; `analyst` `{configured, provider, model, reach}`), `counts`
by severity, `held`, `open` (issues), `incidents` (`id, at, severity, basis, related,
likely_cause, confidence, stable, members, issues, findings, missing`). A *service* in the
listing: `name, description, active, sub, result, enabled, user, restarts, key, timers, worst,
unstable, issues, described` (`{brief, full, model, created_at}` or null). A scheduled job:
`id, source, file, user, schedule, command, unit, last, next, result, worst, unstable`. The logs
listing is the dashboard's own: `read_at, error, truncated, skipped, templates, uncached, lines`,
each line `at, priority, unit, identifier, message, key, explanation` (`{text, model,
created_at}` or null).

**Jobs.** Each start answers 202 with the job and **the estimate it was made from**:

    {"id": "sd-…", "kind": "describe", "status": "running", "keys": 12,
     "estimate": {"chars": 41200, "approx_tokens": 10300, "backend": "openai-compatible",
                  "model": "…", "url_host": "192.168.1.40", "remote": true,
                  "requests": 3, "services": 12}}

An analysis start also gives `subjects`, `items` and `context`. `keys: "all_uncached"` means
every service not described for its current definition, or every kind of line in the journal
now that is not explained; a list of keys is filtered the same way, and when nothing is left the
answer is 409. A describe or explain job reads its targets afresh (the services from the store,
the lines from the journal) rather than from a previous listing. `GET /jobs/{id}` gives the
dashboard's progress fields: `status` (`running`, `done`, `failed`), `requests_done`,
`requests_total`, `started_at`, the count saved so far (`described` / `explained`), `error`,
`completed_at`; a finished analysis carries its `text` and `suggested_checks`.

**Starting a job sends redacted host data to the configured analyst endpoint**, whose host is the
estimate's `url_host`; `remote: true` means it leaves this machine.

### Examples

    TOKEN=$(NeonWatch agent-token --show | tail -n 1)
    A=(-H "Authorization: Bearer $TOKEN" -H "X-Neonwatch-Agent: me")
    URL=http://127.0.0.1:8765/api/agent/v1

    curl -s "${A[@]}" $URL/summary
    curl -s "${A[@]}" "$URL/issues?state=open"
    curl -s "${A[@]}" -X POST $URL/issues/ISSUE_ID/ack
    curl -s "${A[@]}" -X POST -H 'Content-Type: application/json' \
         -d '{"for_s": 3600}' $URL/issues/ISSUE_ID/snooze
    curl -s "${A[@]}" -X POST -H 'Content-Type: application/json' \
         -d '{"keys": "all_uncached"}' $URL/jobs/describe/estimate
    curl -s "${A[@]}" -X POST -H 'Content-Type: application/json' \
         -d '{"subjects": ["issue:ISSUE_ID"], "question": "what is the likely cause?"}' \
         $URL/jobs/analysis
    curl -s "${A[@]}" $URL/jobs/an-JOB_ID
    curl -s "${A[@]}" "$URL/audit?limit=20"

Over TLS, trust the dashboard's own certificate and reach it by a name it carries, on loopback:
`curl --cacert ~/.config/neonwatch/tls.crt --resolve myhost:8765:127.0.0.1 https://myhost:8765/…`.

## `neonwatch mcp`

A zero-dependency stdio MCP server (JSON-RPC, one message per line: `initialize`, `ping`,
`tools/list`, `tools/call`). It reads the dashboard's address from the config (`web.host` when
that is a loopback address, else `127.0.0.1`, on `web.port`; https pinned to `web.tls_cert` when
set) and the token from the token file at every call, and sends
`X-Neonwatch-Agent: <--agent, else $NEONWATCH_AGENT, else "mcp">`. Every failure is an `isError`
result naming the cause (the dashboard down, an HTTP refusal and its reason, a bad argument, an
unreadable token); the server keeps running.

| tool | calls |
| --- | --- |
| `status` | `GET /summary` |
| `list_issues` (`state`?) | `GET /issues` |
| `get_issue` (`id`) | `GET /issues/{id}` |
| `acknowledge_issue` (`id`) | `POST /issues/{id}/ack` |
| `snooze_issue` (`id`, one of `for_s` / `until`) | `POST /issues/{id}/snooze` |
| `list_services` | `GET /services` |
| `get_service` (`name`) | `GET /services/{name}` |
| `list_scheduled` | `GET /scheduled` |
| `read_logs` | `GET /logs` |
| `estimate_analysis` / `start_analysis` (`subjects`, `question`?) | `POST /jobs/analysis[/estimate]` |
| `estimate_service_descriptions` / `start_service_descriptions` (`keys`) | `POST /jobs/describe[/estimate]` |
| `estimate_log_explanations` / `start_log_explanations` (`keys`) | `POST /jobs/explain[/estimate]` |
| `get_job` (`id`, `wait_s`? at most 120) | `GET /jobs/{id}`, polled each second until it finishes or the wait ends |
| `audit` (`limit`?, `agent`?, `since`?) | `GET /audit` |

The `start_*` tool descriptions say plainly that starting one sends redacted host data to the
configured analyst endpoint, without confirmation.

**Registering it with Claude Code** (once the service has run, so the token exists):

    claude mcp add --scope user NeonWatch -- <repo>/.venv/bin/neonwatch mcp

with `--agent NAME` after `mcp` (or `NEONWATCH_AGENT` in its environment) to name the agent, and
`--config PATH` when the config is not `~/.config/neonwatch/config.toml`.
