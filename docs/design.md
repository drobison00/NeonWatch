# NeonWatch: design

The design as built: what each part does and why. The machine-readable physical design is
`plan.json`, which `tools/gates.py` checks (acyclic, levels computed from edges, one owner per
external surface). Probe output shapes are in `docs/probes.md`.

## What it is

A local, web-based health monitor for a Linux workstation. A read-only root agent collects
hardware, OS, log, firewall, network, process, service and container state through staggered
probes. Every few minutes an evaluator collates what changed: deterministic rules raise hard
alarms, and a local **judge** (a typed-decision model server, `POST /v1/systemone` on
`127.0.0.1:8200` by default; the wire is in `docs/judge-protocol.md`) judges what the rules
cannot. Without a judge, the rules alone raise issues. Findings bubble up as issues on a
dashboard that updates live.

## The security model

**The agent runs as root, and every action it takes is deterministic and read-only** (decided
2026-09-30). Privilege is not withheld from it. Read-only is guaranteed by what it is able to ask
for, and the one non-deterministic thing in the system, the judge, sits outside it.

1. **The agent is plain code.** It runs a fixed schedule over a fixed catalog. No model output ever
   reaches it, and it never talks to the judge. Given the same host state, it does the same thing.
2. **The catalog is closed, and it is the read-only variant of every tool.** Each probe is a fixed
   argv of a read-only invocation (`nft -j list ruleset`, `smartctl -j -a`, `systemctl list-units
   --failed -o json`, `ss -ltnupH`...), a fixed file path, or a Docker API `GET` on an allowlisted
   path. No shell, no runtime parameters, no inherited environment. Adding a probe is a code change
   that goes through the read-only gates below.
3. **`executor` is the boundary.** It runs catalog entries and refuses everything else at runtime:
   files open `O_RDONLY`, commands exec from the catalog's argv only, HTTP methods other than `GET`
   raise. `subprocess`, raw sockets and file-writing calls are importable only there, and a static
   gate forbids write calls even there.
4. **Launch is by hand or as units** (by hand decided 2026-09-30; units built 2026-10-29). By
   hand: `neonwatch broker` and `neonwatch service` as you, `sudo scripts/neonwatch-agent` as
   root, each refusing the wrong user. As units (`tools/services.py`): the broker and service as
   `systemctl --user` units, and the agent as `neonwatch-agent@<operator>.service`, running a
   root-owned copy in `/opt/neonwatch` with `--operator <operator> --require-confined`.
   **The kernel-enforced seatbelt:** the unit keeps uid 0 but sees the filesystem read-only
   (`ProtectSystem=strict`, `ProtectHome=read-only`, `PrivateTmp`, `NoNewPrivileges`), reaches only
   loopback (`IPAddressDeny=any`, `IPAddressAllow=localhost`), and holds only the capabilities its
   probes need, each named in the unit for the probe that needs it. That is a seatbelt against a
   bug, not a wall against a hostile agent. The wall is (1)-(3).
5. **The agent measures whether it can write, without writing.** At start and with every heartbeat
   it checks `/`, `/etc`, `/home`, `/var`, `/usr` and `/boot` with `statvfs` (read-only mount) and
   `access(W_OK)`; nothing is created, so the check itself cannot mutate the host. Under the unit, any success refuses the start and names the
   path. Run by hand without the seatbelt, the canary reports that the filesystem is writable, and
   the dashboard shows the agent as running unconfined.
6. **Data flows one way.** Agent → NATS on loopback (a publish-only credential) → service →
   browser. The service has no channel back, so nothing downstream can ask the agent to do
   anything.
7. **Redaction happens in the agent**, before anything leaves root. Command lines, environment, logs
   and config pass through `redact`, a shape-based floor rather than a proof. The broker, the
   judge and the default dashboard are loopback only; the analyst and a LAN dashboard leave it
   only when configured to.
8. **Only the unprivileged service is non-deterministic.** It runs as your user, with no
   capabilities, and it alone asks the judge questions.
9. **Logs are untrusted input.** Anyone can write to syslog, so a log line can carry a prompt
   injection aimed at the judge. A judgement can **raise or rank** an issue but never clear a
   deterministic alarm: a disk reporting a critical warning stays critical whatever the model says.
10. **The web UI binds 127.0.0.1** with a per-launch token, a Host-header check against DNS
    rebinding, and Bearer + same-Origin on every POST. Its writes touch only the monitor's own
    database: acknowledging or snoozing an issue, and requesting a manual analysis. Nothing it
    serves can execute anything on the host.
11. **Local AI agents get their own door** (decided 2026-10-27): `/api/agent/v1`, loopback peers
    only, with a long-lived token in a 0600 file and a named caller. Agents read what the
    dashboard shows, hold issues and start LLM jobs without the confirm step, under a write limit
    and an audit log; they can do nothing the dashboard cannot. See "The local agent API" below.

Root closes the three reads that were open questions before: the firewall ruleset, SMART and
Docker state are read directly by the agent, each through its read-only invocation.

## The event service

**NATS JetStream is the broker; SQLite is the dashboard's query index** (decided 2026-09-30).

The privileged observer publishes observations; three independent consumers read them at their own
pace: the evaluator (rules and the judge), the dashboard, and the notifier. Each has a durable consumer
that resumes where it left off, so a restart loses nothing and one slow reader holds up no other.

- **One stream, `NEONWATCH`,** holds `obs.>`, `finding.>`, `attest.>`, `issue.>` and `hb.>`, with
  retention set from the config: max age and max bytes, whichever is reached first (default 7 days
  or 10 GiB). JetStream enforces both natively.
- **Per-role credentials make the flow one-way at the broker.** The agent may publish observations
  and heartbeats and nothing else; it cannot subscribe or create streams. The evaluator reads
  observations and publishes findings, attestations and issues. The dashboard and notifier only read.
  `broker` holds this policy as data and its tests prove it against a real server.
- **The browser never talks to NATS.** The dashboard's service consumes the stream, writes its SQLite
  query index (latest values, chart series, issues, acknowledgements), and pushes to the browser with
  server-sent events.
- **Heartbeats** carry the agent's CPU spend and confinement; after a hard lock the last one says
  when the system stopped reporting.
- Estimated volume ~50 MB/day, to be measured by the budget benchmark.

Why not SQLite alone: with three consumers we would be writing our own broker. Why not Postgres:
`LISTEN/NOTIFY` is not durable, and a server with vacuum load under constant pruning buys concurrent
writers and network access we do not use.

## Attestation: many questions per context

**Measured on one judge server (the `judge` live seam):** it answered requests one after another. Each
question is its own prompt with the state repeated (~260-290 input tokens), at ~80 ms per
question, so throughput is ~12-13 questions/s however requests are arranged; concurrent requests
finish in a ~1 s staircase. So the design packs many questions into few requests (24 per
request) and keeps `judge.concurrency` at 2, rather than fanning out. A full pass of ~21
contexts is ~22 s plus stability re-asks, every 5 minutes.

1. **Contexts from what changed.** Each collation builds one context per domain (hardware, storage,
   memory, CPU, GPU, network, firewall, processes, services, containers, logs, security, kernel) and
   one per entity worth a look (a hot process, a failed unit, a crash-looping container, a new
   listener, a disk, a burst of log lines). Unchanged contexts are not re-asked until a periodic
   refresh.
2. **The whole bank at once.** `questions` holds, per context kind, every typed question worth
   asking (noul, choice, score) and what each answer means for severity, cause and next step.
   `judge` packs a context's questions into as few requests as the context budget allows and runs
   up to `judge.concurrency` requests at once (default 2; the server is serial).
3. **Stability where it matters.** A stability-checked question whose first answer lands at WARN or
   above is re-asked with its options reversed; an answer that flips is marked unstable and ranks
   lower. For scores, a move of at most half a level across a band edge still counts as stable.
4. **Percolation.** Deterministic findings come first and cannot be cleared by a judgement. Issues
   then rank by severity, urgency score, stability, and novelty (new or escalating beats standing).
5. **On the dashboard,** each issue shows what needs attention, why (the attestations behind it,
   with their probabilities and confidence, contested answers flagged), the evidence (the
   observation it came from), and the next read-only check to run. Per domain, a matrix of the key
   attestations shows at a glance where the machine stands, and stale or unanswered cells are drawn
   as unknown, never as healthy.

### An issue a person can act on (feature, 2026-10-29)

The trigger: two judge-raised criticals about a process that lived under a second. The card
showed how the judge answered and nothing about what ran, and once the snapshot rolled over
nothing could say. Four changes, none of which adds a model call or sends the judge anything
more:

- **Evidence is frozen with the judgement.** Each attestation at WATCH or above keeps `evidence`
  (a quiet answer cannot raise or rank an issue, and keeping it for the quiet majority, ~44,000
  answers a day measured, would double what attestations take to store): the redacted
  values at its question's `needs` paths, or, for a question that weighs the whole state, that
  state when it fits in `judge.EVIDENCE_CHARS` (2000). Too large, it keeps the start and the size
  (`truncated`, `chars`), or for a whole state only the size (`omitted_chars`). It is taken from
  the state already redacted for the request, so it is never more than the judge was shown.
- **What is mechanical is a rule; the judge judges the rest.** Which process runs from a tmp
  directory is a fact, so `process.runs_from_tmp` raises one finding per such process
  (`process:<pid>`) with its row as evidence, and the processes domain no longer asks
  `runs_from_tmp`. The process's own context still asks what it is and whether it is suspicious,
  and those answers join the rule's issue (rule prefix `process` is the `processes` domain).
  A pytest run's programs under `/tmp/pytest-of-<user>/` are the exception (2026-10-30): pytest
  makes that directory for its user alone, so nobody else could swap them. The parser groups
  them under their runner, `process.tests_from_tmp` raises one INFO finding per run, and a busy
  one asked about on its own carries `test_run` (the runner), so a suite is not one CRITICAL
  issue per test.
- **The issue says what happened.** An issue carries `evidence` (the leading finding's, else the
  leading attestation's) and `why` (the rule's sentence on why it matters). A judge-raised title
  is the cause in words and what it is about, named from the evidence ("CPU runaway: python3
  (pid 4242)"), not `cpu-runaway on process:4242`. The card shows a *What* line from the
  evidence (a process as its command line, pid, user, parent, age, CPU, threads); the expanded
  view leads with *why it matters* and *how sure* in words, and folds how the judge answered.
- **Time-aware checks.** An issue keeps `last_seen`, when its conditions were last present. Once
  they are gone the card says "not seen since", and labels the check as one that may find
  nothing; the tmp rule's check reads the journal around the moment it was seen and names the
  parent, so it still answers after the process has exited. An answer's check is shown only
  where it differs from the issue's own.

## Manual analysis with a backend LLM (feature, 2026-09-30)

From the dashboard you select one event, a set of events, an issue, an incident (a link), or a time
window, optionally type a question, and ask the configured backend LLM to analyse it.

- **Configurable backend.** `[analyst]` in the config: `provider` (`openai-compatible` or
  `anthropic`), `base_url`, `model`, `api_key_env` (the NAME of an environment variable read by the
  service at startup; the key is never written to the config, the store or a log), `max_input_chars`,
  `reach` (`local`, the default: loopback only; `lan`: private IP addresses too; `remote`:
  anywhere, over https) and `reasoning_effort` for a reasoning model behind an openai-compatible
  endpoint.
- **Manual and confirmed.** Nothing runs automatically. The dashboard first calls `estimate`, which
  shows how much will be sent, to which backend and model, and whether it leaves the machine; you
  confirm, then it runs.
- **Same trust rules as the judge.** It runs in the unprivileged service, never in the agent. The request
  is redacted again before it leaves. It has no tools. Its answer is advisory text, rendered as plain
  text, with suggested read-only checks shown for you to copy, never executed. It cannot change an
  issue, a link or anything on the host.
- **Context is bounded and deterministic.** Alongside your selection, `analyst` attaches the related
  observations for the same entities and a window around them, capped at `max_input_chars`, so the
  same selection always sends the same request.
- Results are stored as `Analysis` records and listed on the item they were about.

## Logs view: the last journal lines, explained on request (feature, 2026-10-27)

A **Logs** tab lists the last 200 system journal lines, every priority, with a priority filter
(all / warning and up / error and up) and, per line, a plain-language explanation of what it
means and whether it needs action. Decided:

- **The root agent is not touched.** The unprivileged service reads the journal itself, only when
  the operator clicks "Load", through `logs`: one fixed argv (`journalctl -n 200 -o json
  --output-fields=MESSAGE,PRIORITY,_SYSTEMD_UNIT,SYSLOG_IDENTIFIER,__REALTIME_TIMESTAMP
  --no-pager -q`), no shell, an empty environment, a 10 s timeout and a 4 MiB output cap, run only
  when the binary is root-owned and not group- or world-writable. The service's user reads the
  system journal through its `adm` group. `logs` is the fourth component allowed to start a
  process (`tools/gates.py` holds that, including through asyncio's subprocess API).
- **Redacted first.** Every message is redacted with `redact` before it is stored, sent or shown,
  then capped at 2000 characters.
- **Templates collapse repeats.** Numbers (pids, ports, counters), hex ids, UUIDs, MACs, IPv4 and
  IPv6 addresses and durations are masked; a line's key is a 16-hex hash of its source (syslog
  identifier, else unit) and template. Measured on one desktop: 200 lines, 56 distinct
  messages, 36 kinds of line, the most common kind 48 times.
- **Explained once, only on request.** Loading shows cached explanations and sends nothing.
  "Explain N new…" (the uncached kinds the filter shows) opens the same estimate → confirm dialog
  as manual analysis: destination host, whether it leaves the machine, size and number of
  requests. On confirm, `analyst.explain_logs` packs the kinds into as few requests as
  `max_input_chars` and the output budget allow, and asks for one JSON object keyed by template
  key. Keys it was not asked about are ignored, missing ones stay unexplained, and text is
  redacted again and cut to 600 characters. The prompt says the lines are untrusted data, not
  instructions; explanations are rendered as text only.
- **Cache.** `store.log_explanations`: key, source, template, explanation, the model that wrote
  it, created and last-seen times; at most 2000 rows, least recently seen removed first. The
  table is additive (no schema version change).
- **API.** `GET /api/logs` (lines with key and cached explanation or null, plus the uncached
  count), `POST /api/logs/estimate` and `POST /api/logs/explain` with `{"keys": [...]}` (only
  keys from the last listing that are not cached count), and `GET /api/logs/explain/{id}` to poll
  the job. Writes carry the same session, CSRF and Origin rules as every other POST.

## Services view: what each service is, described on request (feature, 2026-10-27)

The **Services** tab says what each systemd service is: hovering a row shows a one-line
description, and clicking it opens a card with the full description beside the facts the
monitor measured. Decided:

- **Only on the operator's action.** "Describe N services…" (the undescribed services the
  filters show) and "Describe with <model>" inside an undescribed service's card both open the same
  estimate → confirm dialog as the log explainer: destination host, whether it leaves the
  machine, size and number of requests. Loading the list sends nothing.
- **What is sent.** Per service: the unit name, Description=, ExecStart, the unit file, User=,
  its active and sub state, last result, enablement, restarts and the timers that start it
  (`analyst.ServiceUnit`), redacted again, packed into as few requests as `max_input_chars` and
  the output budget (`max_output_tokens // 400` per request) allow, reach rules applied. The
  prompt says unit text is untrusted data, not instructions.
- **What comes back.** One JSON object keyed by service key, each value
  `{"brief": ..., "full": ...}`; read through the same end-marker and fence handling as an
  analysis (Qwen's `<|im_end|>`). Unknown keys are ignored, a service missing either part stays
  undescribed, the brief is folded to one line and cut to 160 characters, the full text to 2400,
  both redacted again. Rendered as text only (`richText`), labelled as model output; the
  measured facts beside it (state, result, user, ExecStart, unit file, enablement, restarts,
  timers) are labelled as measured.
- **Cache.** `store.service_descriptions`: one row per unit name, holding the service key it was
  written for (`jobs.service_key`: a 16-hex hash of name, description, exec, unit file and user,
  so nothing that changes as the service runs), brief, full, model, created and last-seen times;
  at most 2000 rows, least recently seen removed first, additive like the log cache. A redefined
  service reads as undescribed and is described afresh. The two caches share one implementation.
- **API.** `GET /api/services` gives each service its `key`, `timers` and `described` (or null),
  `POST /api/services/estimate` and `POST /api/services/describe` with `{"keys": [...]}` (only
  services from the last listing not described for their current key count), and
  `GET /api/services/describe/{id}` to poll the job, one at a time, under the same session, CSRF
  and Origin rules.

## The local agent API (feature, 2026-10-27)

AI agents on this machine reach the monitor through `/api/agent/v1` on the dashboard's server,
or through `neonwatch mcp`, a stdio MCP server over it. The reference, with every endpoint, shape,
example and MCP tool, is `docs/agent-api.md`. Decided:

- **What agents may do.** Read everything the dashboard shows; acknowledge and snooze issues;
  start the three LLM jobs (an analysis of subjects with a question, service descriptions, log
  explanations) **without the operator's confirm step**. Nothing else: an agent can do nothing
  the dashboard cannot, and nothing reaches the root agent or the host.
- **Interface.** Versioned HTTP endpoints under `/api/agent/v1`, and `neonwatch mcp` wrapping
  them. Agent-shaped answers: compact, stable field names, documented.

How it is built:

- **Credential.** `agent_token` keeps one long-lived token in `<store dir>/agent.token`, 0600,
  made by the service at startup with `O_EXCL` when missing, read with the config loader's care
  (no symlink, regular, our uid, no group or other bits), rotated by `neonwatch agent-token
  --rotate` (an atomic rename that replaces a symlink rather than following it; `--show` is the
  only way to print it). The dashboard reads the file for every agent request, so rotation is
  immediate. It is accepted only as `Authorization: Bearer`, with `X-Neonwatch-Agent: <name>`
  (`[A-Za-z0-9._:-]`, at most 64) for attribution; never as a cookie or query parameter, so CSRF
  does not apply. The dashboard's token and sessions do not open the agent API, and the agent
  token opens nothing else.
- **Loopback only.** The guard reads the socket's peer address, never a header, and refuses
  anything but loopback even in password mode on the LAN; it refuses a request carrying `Origin`
  and a `Host` that is neither the dashboard's nor a loopback name for its port. (With `web.host`
  one specific LAN address nothing listens on loopback, so the agent API is unreachable until
  `web.host` is `0.0.0.0`.)
- **The dashboard's machinery.** The handlers call the same code as the dashboard's routes: the
  analysis, describe and explain jobs start through `start_analysis`, `start_describe` and
  `start_explain`, so one job of each kind runs at a time (429), the analyst's `reach` rules
  apply unchanged, and the job status carries the dashboard's progress fields. Every start
  answers with the estimate it was made from. Describe and explain targets (`keys`, or
  `"all_uncached"`) are read afresh from the store and the journal, not from a listing the
  dashboard holds.
- **Guardrails.** `agent.WriteLimit`: 30 writes a minute per agent name and 60 in all, since a
  name is self-asserted (429 beyond). `store.audit`: every successful write and job start
  (at, agent, action, target, detail; for a job the estimate: chars, requests, url_host, remote,
  model), at most 10,000 rows, additive, listed at `GET /api/agent/v1/audit`.
- **Attributed holds.** `store.ack`/`snooze` record who held an issue (`by`: "" for the operator,
  `agent:<name>`), kept while the hold stands; an additive `issues.held_by` column. The
  dashboard's issue bodies gain `held_by` ("operator", `agent:<name>`, null), an agent's hold is
  pushed to open dashboards as an issue event, and the card and held section say "acknowledged by
  agent:<name>".
- **`neonwatch mcp`** (`mcp`, level 3) imports nothing beyond the standard library, `config` and
  `agent_token` (no aiohttp, NATS or store; `tools/gates.py` gives it `http.client`). It connects
  on loopback, pins the dashboard's own certificate over TLS, and turns every failure into an
  `isError` result.

## Correlation: linking related measures (feature, 2026-09-30)

A second pass after each collation groups findings and issues that are probably one problem, so the
dashboard can show an incident with a likely cause instead of five unrelated cards.

1. **Candidates, deterministically and bounded.** `correlator.candidates` proposes groups of 2-6
   items that share an entity (the same unit, container, disk, interface or process), co-occur
   within a window, or match a known pattern (e.g. a crash-looping container, interface churn, and
   a network daemon's CPU climbing). At most `limit` candidates
   per collation.
2. **The judge judges every candidate at once.** The `CORRELATION` question bank asks whether the
   members are the same problem (stability-checked), which member is the likely cause, what kind of
   relationship it is, how confident the causal ordering is, and whether to show them as one
   incident. Parallel, like the attestation pass, and cheap enough to run every collation.
3. **Links are published as `link.>` events** and shown as incidents grouping their members. A
   link never changes a member's state or severity; a deterministic alarm still stands on its own.
4. **The robust version is manual:** "Explain this incident" or "correlate this window" on the
   dashboard sends the group or window to the backend LLM through `analyst`.

## Probes and cadence

Staggered and jittered so probes never fire together. Tiers are defaults in the config.

| tier | every | examples |
| --- | --- | --- |
| fast | 60 s | load, PSI (cpu/mem/io), memory and swap, CPU temps (hwmon), GPU temp, power and throttle (nvidia-smi), disk fill, interface counters |
| medium | 5 min | process table top-N by CPU and RSS, failed systemd units, container restart counts (Docker API, `GET` only), new journal warnings since the last cursor (capped), listening sockets, kernel taint |
| slow | 1 h | SMART/NVMe health, firewall ruleset hash and diff, pending updates and reboot-required, kernel module diff, crontabs and timers |
| daily | 24 h | unit files, the `cron.hourly`/`daily`/`weekly`/`monthly` directories, `authorized_keys` (planned: SUID/SGID diff, world-writable directories on `PATH`). `neonwatch/probes/catalog.py` is the authoritative list |

The case it is built for: a host that freezes with no kernel trace. This catalog still leaves
the crash-looping container, the veth churn rate, and the last heartbeat before the freeze.

## Load budget

The target is under 1–2% of one day's CPU, amortized. It's enforced twice:

- **A hard ceiling (the agent's unit only):** `CPUQuota=50%`, `MemoryMax=512M`, `TasksMax=64`,
  `Nice=10` and idle I/O priority. That stops a runaway; it is not the budget, which is a day's
  amortized spend. One slice for all three units, with a quota set from the budget, is planned.
- **Self-accounting:** every probe run records its CPU time. The collector keeps a rolling 24-hour
  spend and defers low-priority probes when it nears the budget. The spend is published in
  heartbeats and shown on the dashboard, so the claim is visible rather than asserted.

The judge runs on the GPU and is shared, so its cost is reported separately. The evaluator asks only
about **what changed** since the last collation, batched into one request per domain, so steady
state is a handful of calls every five minutes.

## Components

Levels are computed from the dependency edges in `plan.json`, never assigned. A component
may depend only on strictly lower levels.

| level | component | responsibility | adapter to |
| --- | --- | --- | --- |
| 1 | `config` | Loads and validates the one config file: paths, cadences, CPU budget, broker URL, the judge URL and concurrency, retention (max age and max bytes, whichever first; default 7 days / 10 GiB), notification threshold | — |
| 1 | `redact` | Removes secret-shaped text (tokens, keys, passwords, env values) from anything leaving the privileged agent | — |
| 1 | `schema` | The versioned wire types every process shares: Observation, Finding, Context, Attestation, Issue, Heartbeat, Event; strict encode/decode that refuses unknown fields and kinds | — |
| 2 | `broker` | Runs nats-server for manual mode: writes its config bound to 127.0.0.1, generates one credential per role, and holds the permission policy as data: the agent may only publish observations; the evaluator may read observations and publish judgements and issues; the dashboard and notifier may only read | nats-server process, its config and credential files |
| 2 | `bus` | The NATS JetStream adapter, and the only thing that imports a NATS client: stream and durable-consumer setup with retention from config, publish with ack, resumable subscribe | NATS JetStream (client) |
| 2 | `notifier` | Desktop notifications for issues at or above the configured severity: one per issue per state change, deduplicated, rate-limited | desktop notifications (org.freedesktop.Notifications on the session bus) |
| 2 | `probes` | The closed probe catalog: each probe's id, tier, fixed read-only argv, file reads or Docker GET path, cost class, and the parser from raw bytes to observation data | — |
| 2 | `questions` | The question bank: for each context kind (a domain snapshot, or one entity such as a process, unit, container, listener or disk), every typed question worth asking, and what each answer means for severity, cause and next step | — |
| 2 | `rules` | Deterministic hard alarms over a snapshot: MCE/EDAC, SMART critical, thermal, disk full, crash loops, interface churn, failed units, journald gaps, new 0.0.0.0 listeners, kernel taint | — |
| 2 | `logs` | The Logs view's on-demand journal read in the service: one fixed journalctl argv, redaction, templating into keyed kinds of line | the systemd journal, as the service's user |
| 2 | `store` | The dashboard's query index in SQLite: latest value per probe, rollups for charts, attestations, issues and acknowledgements (with who made them), the agent audit log | SQLite query database |
| 2 | `agent_token` | The agent API's long-lived token: one 0600 file beside the store, made, read and rotated safely | the agent token file |
| 3 | `executor` | The read-only boundary | host probe binaries (ss, systemctl, journalctl, nvidia-smi, smartctl, nft, ip), docker engine API (GET only) |
| 3 | `judge` | The judge adapter and its own client | the judge /v1/systemone at 127.0.0.1:8200 |
| 3 | `web` | Loopback HTTP with a per-launch token: read API over the store, a server-sent event stream fed from the bus, and one write, acknowledging or snoozing an issue in the monitor's own store; and the local agent API under `/api/agent/v1` | browser over HTTP on 127.0.0.1; local agents |
| 3 | `mcp` | `neonwatch mcp`: a stdio MCP server whose tools call the agent API on loopback | MCP clients over stdio |
| 4 | `collector` | The privileged observer: root, deterministic, read-only | — |
| 4 | `evaluator` | Classification | — |
| 4 | `ui` | The functional dashboard: what needs attention now, why (the attestations behind it), the evidence, and the next read-only check to run | — |
| 5 | `service` | The unprivileged composition root, run in your desktop session: wires config, bus, store, evaluator, web and notifier | — |
| 6 | `launcher` | The CLI | — |

Foundation (build and test first): `schema`, `redact`, `config`.

## Gates

Each is a directive paired with a check that runs in CI, and each is to be
seen red once before it counts:

- **Components:** every module has a sibling `_test.py`; a module without one fails.
- **Levels:** an import contract generated from `plan.json`; an upward or sideways import fails.
- **Insulation:** `sqlite3` is importable only by `bus`, `subprocess` and sockets only by
  `executor`, the judge client only by `judge`. (As built: `sqlite3` by `store`; `subprocess` by
  `executor`, `broker`, `notifier` and `logs`, and asyncio's subprocess API is held to the same
  owners; `http.client` by `executor`, `judge`, `analyst` and `mcp`.)
- **Read-only, statically:** an AST scan of `collector`, `executor`, `probes` and `launcher` refuses
  write-mode `open`, `os.remove`, `unlink`, `rename`, `chmod`, `shell=True`, any HTTP method but `GET`,
  and any catalog argv whose verb is not on the read-only list (`list`, `show`, `-a`, `status`...).
- **Read-only, at runtime (half built):** `--require-confined` is tested to refuse a start when
  the canary finds a writable path, and to check before it connects. Still planned: an
  integration test launches the agent's unit in test mode and
  asserts the write canary reports nothing writable, then drops one hardening property and asserts
  the canary refuses to start. That second half is what proves the canary can fail. A second test
  hands `executor` a spec that is not in the catalog, a `POST`, and a write-mode path, and asserts
  all three are refused.
- **Budget (planned):** a benchmark runs the full catalog and asserts the amortized daily CPU is
  under budget; the number is ratcheted.
- **Hardening as data (the agent's unit):** `tools/services_test.py` holds the unit to its
  `ExecStart` and the hardening properties above, has `systemd-analyze verify` accept it, and
  fails if `systemd-analyze security --offline` rates its exposure worse than 4.0.

## Decided

- 2026-09-30: the agent is a **privileged observer**. It runs as root, and every action it
  takes is deterministic and read-only. It emits observations; the dashboard reads and displays
  them; the judge classifies them so relevant events percolate up. The judge is a classifier
  only, and the
  firewall, SMART and Docker reads need no separate units.
- 2026-09-30: `judge` owns its own HTTP client (no dependency on any agent framework).
- 2026-09-30: retention is configurable, whichever limit is reached first; default **7
  days or 10 GiB**.
- 2026-09-30: a **plain, functional production dashboard**.
- 2026-09-30: **desktop notifications** for critical issues, via a new `notifier` component
  in the service, which runs in the desktop session.

- 2026-09-30: **NATS JetStream + SQLite query index.** **Manual launch** for now; systemd
  once the behaviour is trusted. **Use the judge's parallelism**: many attestations per context
  at once,
  shown on the dashboard so they are actionable.

## Scheduled work and services

Every cron job and systemd timer, and every loaded service, is visible on the dashboard, with an
inspection view and an optional LLM analysis. Personal crontabs are read in full, redacted; the
judge questions each job when it is new or changes, besides the manual LLM button. Before this,
the agent listed only the names of cron files, so a question about a job's payload was asked over
state that held no commands.

### Probes (root agent; catalog + gates are the trust boundary)

Measured on one desktop: `systemctl show '*.service' '*.timer' -p <20 props>` = 94 units,
49.5 KB, 0.23 s; `list-units --type=service --all -o json` 26 KB, 0.01 s. No new binary, no
template, no runtime parameter: every argv is fixed. Patterns are passed to systemctl (no shell).

| id | tier | kind | reads |
| --- | --- | --- | --- |
| `cron.system` | slow | FILE | `/etc/crontab` |
| `cron.anacron` | slow | GLOB | `/etc/anacrontab*` (absence is an answer) |
| `cron.d` | slow | GLOB (was LISTDIR) | `/etc/cron.d/*` contents |
| `cron.user` | slow | GLOB (replaces `cron.spool`) | `/var/spool/cron/crontabs/*` contents |
| `cron.hourly` `cron.daily` `cron.weekly` `cron.monthly` | daily | GLOB | `/etc/cron.<p>/*` scripts |
| `units.timers` | slow (was daily) | COMMAND | `systemctl list-timers --all -o json --no-pager` |
| `units.detail` | slow | COMMAND | `systemctl show '*.service' '*.timer' -p ... --timestamp=unix --no-pager` |

`units.detail` properties: Id, Description, User, ExecStart, ActiveState, SubState, Result,
NRestarts, ExecMainStatus, ExecMainStartTimestamp, ExecMainExitTimestamp, UnitFileState,
FragmentPath, Triggers, TriggeredBy, TimersCalendar, Unit. Output is blank-line-separated blocks,
Id anywhere in the block; ExecStart repeats once per command. Timer last/next times come from
`units.timers` JSON (epoch µs) because `--timestamp=unix` does not convert the timer USec props.
The executor's redaction applies to all of it, as to every observation.

### Contract: parsed shapes

A **job** (one per scheduled thing), from `cron.*` and `units.detail`+`units.timers`:

    {"id": str,            # cron: "cron:" + sha256(file\nuser\nschedule\ncommand)[:32]
                           # periodic: "cron:" + path ; timer: "timer:<name>.timer"
     "source": "cron" | "cron-periodic" | "anacron" | "timer",
     "file": str,          # where it is defined (crontab path, script path, unit FragmentPath)
     "user": str,          # cron: the user field / the spool file name; timer: service User or "root"
     "schedule": str,      # the cron fields or @word as written; "daily" etc; OnCalendar text
     "command": str,       # the command as written; timer: the service's ExecStart argv(s), "; "-joined
     "unit": str | None,   # timer: the service it activates
     "static": {...},      # the fields above minus id; THE the judge context state (no times)
     "last": float | None, "next": float | None,   # epoch seconds where known
     "result": str | None}  # timer: the service's Result

A **service** (every loaded `*.service`): {"name", "description", "user", "exec": [argv str],
"active", "sub", "result", "restarts", "main_status", "started", "exited", "enabled", "file"}.

Malformed lines/blocks are skipped and counted (`skipped`), never fatal; a crontab line's
environment assignments (`MAILTO=`, `PATH=`) are kept as `env` on the file, not as jobs.

### Evaluation

- New entity context kind `job` (`job:<id>`), state = the job's `static` only, so it is due
  exactly when a job is new or changed (plus the existing `REFRESH_EVERY`). Questions (all
  read-only next steps): fetches-and-runs remote content; decodes/obfuscates; runs from /tmp,
  /dev/shm, a hidden or user-writable path while running as root; disguised name (looks like a
  system job, lives somewhere unusual); every-minute or @reboot persistence by an ordinary user;
  outbound to a raw IP. Stability-checked where they can reach WARN.
- The security domain's `cron_changed` / `cron_payload` move onto a job-set diff (added/removed
  ids, with commands) instead of the old name listing.
- Deterministic rules: service restart loop (NRestarts delta across collations); a timer's
  service last Result not success; a job whose command runs from a tmp dir. Services are NOT
  asked about by the judge one by one (only failing ones, as today); they get rules + manual LLM.

### Dashboard

- **Scheduled** view: one table of all jobs — source, user, schedule (raw + plain words), next,
  last, last result, command (truncated, full on expand), judge verdict badges; sort, filter by
  source/user/text; "as of" the probe time.
- **Services** view: name, state/sub, enabled, restarts, last result, user, exec; filter for
  failed / restarting / running-as-root.
- Each row: details (full definition, its attestations, its file) and **Analyze**: the existing
  analyst path with the job or service as the item (subject `job:<id>` / `unit:<name>`), estimate
  first, CSRF and session rules unchanged.

