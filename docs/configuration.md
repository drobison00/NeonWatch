# Configuration reference

NeonWatch reads one TOML file: `~/.config/neonwatch/config.toml` when it exists, or the path given
with `--config`. **No file is a valid configuration**: every key has a default, and the defaults
run a loopback-only monitor with no judge and no analyst.

```sh
mkdir -p ~/.config/neonwatch
cp examples/config.toml ~/.config/neonwatch/config.toml     # every line in it is commented out
```

Rules that apply to the whole file:

- **Closed schema.** An unknown section or key is an error (`[web] has unknown key(s) ['hots']`),
  never a silent default.
- **A regular file you own.** It must be owned by you (or root), not a symlink, at most 64 KiB, and
  UTF-8. A dotfile manager that links the file in is refused: copy it instead.
- **Read at start.** The broker, the service and the agent each read it once when they start.
  Restart whichever you changed it for.
- **Durations** (keys ending `_s`, and `[cadence]`) take seconds or a string such as `"90s"`,
  `"5m"`, `"12h"` or `"7d"`. **Sizes** (`retention.max_bytes`) take bytes or a string such as
  `"500MiB"` or `"10GiB"`.

Every section, every key, its default, and what it is checked against:

## `[judge]`: the typed-decision model (optional)

How the judge and the analyst fit together, with diagrams and recipes, is in
[`models.md`](models.md).

The judge answers the evaluator's closed questions; the wire is in
[`judge-protocol.md`](judge-protocol.md). Without one, the rules alone raise issues, and the
dashboard's judge vital reads "unreachable".

| Key | Default | Meaning |
| --- | --- | --- |
| `name` | `"Judge"` | What the dashboard and the APIs call this judge. 1-40 characters: letters, digits, spaces and `. _ - + / ( )`, starting with a letter or digit. |
| `url` | `"http://127.0.0.1:8200/v1/systemone"` | Where requests go. Plain `http://` to a loopback address only; proxies and redirects are ignored. Checked when the service starts. |
| `model` | `"judge"` | Sent in every request, for a server that hosts several models. A server may ignore it. |
| `concurrency` | `2` | Requests in flight at once, 1-16. A server that answers serially gains nothing past 2. |
| `max_questions_per_request` | `24` | Questions packed into one request. |
| `max_state_chars` | `24000` | State plus questions per request, in characters. A context bigger than this is cut, and the request says so. |
| `timeout_s` | `60` | Per request. A request that times out yields no answers. It never yields a guess. |

**Naming the judge.** `name` labels the model *and* the endpoint you have configured, so give it
whatever tells you which one answered: a model family, a size, the GPU it runs on.

```toml
[judge]
name  = "Qwen 7B judge (GPU 0)"
url   = "http://127.0.0.1:8200/v1/systemone"
model = "qwen-7b-judge"
```

The name then shows up in these places:

- **Dashboard.** The top bar's vital is titled with it. Its tooltip reads
  `Qwen 7B judge (GPU 0): model qwen-7b-judge at http://127.0.0.1:8200/v1/systemone`. Badges read
  `JUDGED · QWEN 7B JUDGE (GPU 0)`. Issue cards head their answers "Qwen 7B judge (GPU 0)
  attestations", and the Scheduled and Services tables title their column with it.
- **`/api/health` and the agent API's summary.** The `judge` object carries `name`, `model` and
  `url`, next to `reachable`, the latency percentiles and the counts.
- **Every attestation.** Each records the `judge` that answered, as the name stood when it
  answered. If you rename or replace the judge, older answers keep their old name, and the
  dashboard marks them `by <old name>`. Answers recorded before names existed have `judge: ""`.

## `[analyst]`: an LLM that explains on request (optional)

Off until `provider` and `model` are set. In the dashboard it sends only what you selected, and
only after you have confirmed an estimate of the size and destination. **Local AI agents using
the agent API skip that confirmation** (see [`agent-api.md`](agent-api.md)).

| Key | Default | Meaning |
| --- | --- | --- |
| `provider` | `""` | `""` (off), `"openai-compatible"` or `"anthropic"`. |
| `base_url` | `""` | Required for openai-compatible: the base that `/chat/completions` hangs off, e.g. `http://127.0.0.1:8000/v1`. For anthropic, empty means `https://api.anthropic.com`. |
| `model` | `""` | Required once `provider` is set. |
| `api_key_env` | `""` | The **name** of an environment variable holding the key, never the key itself (a value that looks like a key is refused). The variable must be set in the service's environment when it starts; otherwise the service logs `analyst disabled: …` and runs without an analyst. |
| `reach` | `"local"` | How far a request may go: `"local"` (loopback only), `"lan"` (also private and link-local addresses) or `"remote"` (anywhere). A non-loopback endpoint needs https, except a keyless LAN one. Anthropic's API is remote, so it needs `reach = "remote"`. |
| `reasoning_effort` | `""` | openai-compatible only: `"low"`, `"medium"` or `"high"`, sent as `reasoning_effort`. |
| `max_input_chars` | `60000` | Characters of redacted context per request. |
| `max_output_tokens` | `2000` | |
| `timeout_s` | `120` | |

## `[web]`: the dashboard

| Key | Default | Meaning |
| --- | --- | --- |
| `host` | `"127.0.0.1"` | An IP address or `localhost`. Anything not loopback also needs `tls_cert`, `tls_key`, `password_hash` and `allowed_hosts`. |
| `port` | `8765` | 1-65535. |
| `tls_cert`, `tls_key` | `""` | Set together. The service refuses a key that group or other can read. |
| `password_hash` | `""` | The line `neonwatch hash-password` prints (scrypt). Never the password. |
| `allowed_hosts` | `[]` | The exact `name:port` values the browser sends as `Host`, in lower case, with this `port`. Required beyond loopback. |
| `session_s` | `"12h"` | How long a login lasts, 5 minutes to 7 days. |
| `board` | `"atx"` | The Board view's layout: a built-in name or a path to a TOML file ([`board-layouts.md`](board-layouts.md)). A bad layout stops the service at start. |

## `[notify]`: desktop notifications

| Key | Default | Meaning |
| --- | --- | --- |
| `enabled` | `true` | |
| `min_severity` | `"critical"` | `"info"`, `"watch"`, `"warn"` or `"critical"`. |
| `rate_limit_s` | `"5m"` | Before the same issue may notify again. |

An issue notifies once per severity it reaches, never again at the same or a lower one. What was
sent is kept in the store, so restarting the service does not repeat it.

## `[retention]`

Whichever limit is reached first. It applies to the dashboard's database and, at 1.25×, to the
broker's message store.

| Key | Default |
| --- | --- |
| `max_age_s` | `"7d"` |
| `max_bytes` | `"10GiB"` |

## `[cadence]`: how often each probe tier runs

| Key | Default | Floor |
| --- | --- | --- |
| `fast` | `"60s"` | 10 s |
| `medium` | `"5m"` | 60 s |
| `slow` | `"1h"` | 600 s |
| `daily` | `"24h"` | 3600 s |
| `collate` | `"5m"` | 60 s. How often the evaluator turns what changed into issues. |

The floors exist because the agent runs as root and never defers fast probes: a smaller value
spends root's CPU.

## `[budget]`

| Key | Default | Meaning |
| --- | --- | --- |
| `cpu_fraction` | `0.01` | The share of one CPU, averaged over a day, that the agent may spend: above 0, at most 0.05. As it nears the budget, it defers its heavier probes. |

## `[broker]`

| Key | Default | Meaning |
| --- | --- | --- |
| `url` | `"nats://127.0.0.1:4222"` | Must be `nats://127.0.0.1:<port>` with no user or password: the agent's credential and every observation travel over it. |
| `state_dir` | `"~/.local/state/neonwatch/broker"` | The broker's config, data and per-role credentials (0700 / 0600). |
| `binary` | `".tools/nats-server"` | Relative paths are taken from the directory you start `neonwatch broker` in. That is why the broker starts from the repository root. |

## `[store]`

| Key | Default | Meaning |
| --- | --- | --- |
| `path` | `"~/.local/state/neonwatch/store.sqlite3"` | The dashboard's database (0600). |
