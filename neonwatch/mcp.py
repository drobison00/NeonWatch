"""`neonwatch mcp`: a stdio MCP server over the dashboard's local agent API.

Plain JSON-RPC 2.0, one message per line on stdin and stdout (`initialize`, `tools/list`,
`tools/call`, `ping`), no SDK and no dependency beyond the standard library: no aiohttp, no NATS,
nothing of the service. Each tool is one call to `/api/agent/v1/...` (docs/agent-api.md) on the
dashboard the config names, made from loopback: `web.host` when it is a loopback address, else
127.0.0.1 on `web.port` (the agent API answers loopback clients only), over TLS when the config
gives the dashboard a certificate, which is then the one certificate trusted.

Every request carries `Authorization: Bearer <agent token>`, read from the token file
(`agent_token`) at each call so a rotation is picked up without a restart, and
`X-Neonwatch-Agent: <name>` (`--agent`, else `$NEONWATCH_AGENT`, else "mcp"). The token is never
written to stdout, stderr or a result.

A failure of any kind (a refused argument, the dashboard down, an HTTP error, an unreadable
token) is an `isError` result saying what happened; the server itself never stops on one.
"""

from __future__ import annotations

import http.client
import ipaddress
import json
import re
import ssl
import sys
import time
from collections.abc import Callable, Iterable, Mapping
from pathlib import Path
from typing import Any, TextIO
from urllib.parse import quote, urlencode

from neonwatch import agent_token
from neonwatch.config import Config

PROTOCOL = "2025-06-18"
NAME = "neonwatch"
#: Restated from `neonwatch.web.agent`, which this module must not import (it loads aiohttp).
PREFIX = "/api/agent/v1"
NAME_HEADER = "X-Neonwatch-Agent"
_AGENT_NAME = re.compile(r"[A-Za-z0-9._:-]{1,64}")
DEFAULT_AGENT = "mcp"
AGENT_ENV = "NEONWATCH_AGENT"
TIMEOUT_S = 30.0
#: Longest `get_job` waits for a job to finish, and how often it looks.
MAX_WAIT_S = 120
POLL_S = 1.0
MAX_RESPONSE = 8 * 1024 * 1024

_SENDS = ("Starting it SENDS redacted host data to the configured analyst endpoint (the "
          "estimate's url_host; remote=true means it leaves this machine). No confirmation is "
          "asked; the start is rate-limited and recorded in the audit log with its estimate.")
_KEYS = {"description": 'A list of 16-hex keys, or "all_uncached" for every one not yet done.',
         "anyOf": [{"type": "array", "items": {"type": "string"}, "minItems": 1,
                    "maxItems": 200},
                   {"type": "string", "enum": ["all_uncached"]}]}
_SUBJECTS = {"type": "array", "items": {"type": "string"}, "minItems": 1, "maxItems": 20,
             "description": "What to analyse: issue:<id>, finding:<rule>@<entity>, link:<id>, "
                            "job:<id>, unit:<name>, or window:<start>-<end> (epoch seconds)."}
_QUESTION = {"type": "string", "maxLength": 2000, "description": "Optional question."}
_ID = {"type": "string", "description": "The issue id."}


def _tool(name: str, description: str, properties: Mapping[str, Any] | None = None,
          required: Iterable[str] = ()) -> dict[str, Any]:
    return {"name": name, "description": description,
            "inputSchema": {"type": "object", "properties": dict(properties or {}),
                            "required": list(required), "additionalProperties": False}}


TOOLS = [
    _tool("status", "The host monitor's state at a glance: vitals (the root agent's heartbeat "
          "age, the judge, the store, the analyst), open issues by severity with their next "
          "read-only check, the number held, and incidents. Reads only."),
    _tool("list_issues", "Issues, highest ranked first, each with severity, entity, reasons, "
          "next_step and who holds it (held_by). Reads only.",
          {"state": {"type": "string", "enum": ["open", "acknowledged", "snoozed", "resolved"],
                     "description": "Only issues in this state; all when omitted."}}),
    _tool("get_issue", "One issue with the findings, judge attestations and LLM analyses "
          "behind it. Reads only.", {"id": _ID}, ["id"]),
    _tool("acknowledge_issue", "Acknowledge an issue as this agent: it leaves the open list "
          "(and the operator's dashboard shows who acknowledged it) until it escalates. Changes "
          "only the monitor's own record; nothing on the host.", {"id": _ID}, ["id"]),
    _tool("snooze_issue", "Snooze an issue as this agent until a time, or for a span of up to "
          "7 days; it reopens when the snooze lapses or it escalates. Give exactly one of "
          "for_s and until.",
          {"id": _ID, "for_s": {"type": "number", "description": "Seconds from now."},
           "until": {"type": "number", "description": "Epoch seconds."}}, ["id"]),
    _tool("list_services", "Every loaded systemd service: state, result, user, restarts, its "
          "key, judge verdict, open issues on it, and its cached LLM description (null when "
          "not yet described). Reads only."),
    _tool("get_service", "One systemd service in full: ExecStart, unit file, timers, "
          "attestations and cached description. Reads only.",
          {"name": {"type": "string", "description": "The unit name, e.g. cron.service."}},
          ["name"]),
    _tool("list_scheduled", "Every cron job and systemd timer: schedule, command, user, last "
          "and next run, last result, and judge verdict. Reads only."),
    _tool("read_logs", "The last 200 system journal lines (redacted), each with its kind key "
          "and cached plain-language explanation (null when not yet explained). Reads the "
          "journal; sends nothing anywhere."),
    _tool("estimate_analysis", "How much an LLM analysis of these subjects would send, to "
          "which host and model, and whether it leaves the machine. Sends nothing.",
          {"subjects": _SUBJECTS, "question": _QUESTION}, ["subjects"]),
    _tool("start_analysis", "Start an LLM analysis of these subjects, optionally with a "
          f"question; returns the job and the estimate it was made from. {_SENDS} Poll it "
          "with get_job.", {"subjects": _SUBJECTS, "question": _QUESTION}, ["subjects"]),
    _tool("estimate_service_descriptions", "How much describing these services with the LLM "
          "would send, and where. Sends nothing. Only services not yet described count.",
          {"keys": _KEYS}, ["keys"]),
    _tool("start_service_descriptions", "Start describing these services (what each is) with "
          f"the LLM; returns the job and its estimate. {_SENDS} Poll it with get_job.",
          {"keys": _KEYS}, ["keys"]),
    _tool("estimate_log_explanations", "How much explaining these kinds of journal line with "
          "the LLM would send, and where. Sends nothing. Only kinds in the journal now and not "
          "yet explained count.", {"keys": _KEYS}, ["keys"]),
    _tool("start_log_explanations", "Start explaining these kinds of journal line with the "
          f"LLM; returns the job and its estimate. {_SENDS} Poll it with get_job.",
          {"keys": _KEYS}, ["keys"]),
    _tool("get_job", "An LLM job's status: running, done or failed, with requests_done, "
          "requests_total, started_at, what it saved so far, and any error; an analysis, once "
          "done, carries its text. With wait_s, waits up to that long (at most 120) for it to "
          "finish.",
          {"id": {"type": "string", "description": "The job id a start_* returned."},
           "wait_s": {"type": "number", "minimum": 0, "maximum": MAX_WAIT_S}}, ["id"]),
    _tool("audit", "The audit log of agent writes and LLM job starts, newest first: when, "
          "which agent, what, on what, and (for a job) the estimate it was made from.",
          {"limit": {"type": "integer", "minimum": 1, "maximum": 500},
           "agent": {"type": "string", "description": "Only this agent's entries."},
           "since": {"type": "number", "description": "Only entries from this epoch time."}}),
]
_BY_NAME = {tool["name"]: tool for tool in TOOLS}


class Refused(Exception):
    """A call that cannot be made or was refused, and the one line that says why."""


def valid_name(name: str) -> bool:
    return _AGENT_NAME.fullmatch(name) is not None


def endpoint(config: Config) -> tuple[str, int, ssl.SSLContext | None]:
    """Where the agent API is reached from here: (host, port, TLS context or None)."""
    settings = config.web
    try:
        loopback = ipaddress.ip_address(settings.host).is_loopback
    except ValueError:
        loopback = settings.host == "localhost"
    host = settings.host if loopback else "127.0.0.1"
    context = None
    if settings.tls_cert:
        # The dashboard's own certificate is the one trusted; its name is not ours to check,
        # since we reach it by a loopback address.
        context = ssl.create_default_context(cafile=str(Path(settings.tls_cert).expanduser()))
        context.check_hostname = False
        context.verify_flags |= ssl.VERIFY_X509_PARTIAL_CHAIN
    return host, settings.port, context


class Client:
    """The agent API, one call at a time."""

    def __init__(self, host: str, port: int, token: Callable[[], str], agent: str, *,
                 context: ssl.SSLContext | None = None, timeout_s: float = TIMEOUT_S,
                 bound: str = "") -> None:
        self.host, self.port, self.token, self.agent = host, port, token, agent
        self.context, self.timeout_s = context, timeout_s
        #: What `web.host` says, when that is not where we connect (for the error message).
        self.bound = bound

    def call(self, method: str, path: str, body: Any = None) -> Any:
        try:
            token = self.token()
        except agent_token.TokenError as bad:
            raise Refused(str(bad)) from None
        headers = {"Authorization": f"Bearer {token}", NAME_HEADER: self.agent,
                   "Accept": "application/json"}
        data = None
        if body is not None:
            data = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
        if self.context is not None:
            connection: http.client.HTTPConnection = http.client.HTTPSConnection(
                self.host, self.port, timeout=self.timeout_s, context=self.context)
        else:
            connection = http.client.HTTPConnection(self.host, self.port,
                                                    timeout=self.timeout_s)
        try:
            connection.request(method, PREFIX + path, body=data, headers=headers)
            response = connection.getresponse()
            raw = response.read(MAX_RESPONSE + 1)
            status = response.status
        except (OSError, http.client.HTTPException) as bad:
            where = f"{self.host}:{self.port}"
            hint = (f"; the config binds the dashboard to {self.bound}, and the agent API "
                    f"answers loopback clients only") if self.bound else ""
            raise Refused(f"cannot reach the dashboard at {where} ({type(bad).__name__}: "
                          f"{bad}); is `neonwatch service` running?{hint}") from None
        finally:
            connection.close()
        if len(raw) > MAX_RESPONSE:
            raise Refused(f"the dashboard's answer is over {MAX_RESPONSE} bytes")
        try:
            answer = json.loads(raw) if raw else {}
        except ValueError:
            raise Refused(f"HTTP {status}: the dashboard did not answer JSON") from None
        if status >= 400:
            error = answer.get("error") if isinstance(answer, dict) else None
            raise Refused(f"HTTP {status}: {error or 'refused'}")
        return answer


def run_tool(client: Client, name: str, arguments: Mapping[str, Any],
             sleep: Callable[[float], None] = time.sleep,
             clock: Callable[[], float] = time.monotonic) -> Any:
    """One tool's call. Raises `Refused` for anything that is not a result."""
    tool = _BY_NAME.get(name)
    if tool is None:
        raise Refused(f"no tool named {name!r}")
    _check(tool, arguments)
    a = arguments
    if name == "status":
        return client.call("GET", "/summary")
    if name == "list_issues":
        return client.call("GET", "/issues" + _query(state=a.get("state")))
    if name == "get_issue":
        return client.call("GET", f"/issues/{_part(a['id'])}")
    if name == "acknowledge_issue":
        return client.call("POST", f"/issues/{_part(a['id'])}/ack", {})
    if name == "snooze_issue":
        body = {k: a[k] for k in ("for_s", "until") if k in a}
        if len(body) != 1:
            raise Refused("give exactly one of for_s and until")
        return client.call("POST", f"/issues/{_part(a['id'])}/snooze", body)
    if name == "list_services":
        return client.call("GET", "/services")
    if name == "get_service":
        return client.call("GET", f"/services/{_part(a['name'])}")
    if name == "list_scheduled":
        return client.call("GET", "/scheduled")
    if name == "read_logs":
        return client.call("GET", "/logs")
    if name in _JOBS:
        path, estimate = _JOBS[name]
        body = {k: a[k] for k in ("subjects", "question", "keys") if k in a}
        return client.call("POST", f"/jobs/{path}" + ("/estimate" if estimate else ""), body)
    if name == "get_job":
        return _job(client, a["id"], float(a.get("wait_s", 0)), sleep, clock)
    return client.call("GET", "/audit" + _query(limit=a.get("limit"), agent=a.get("agent"),
                                                since=a.get("since")))


#: tool -> (the job kind's path, whether it only estimates).
_JOBS = {"estimate_analysis": ("analysis", True), "start_analysis": ("analysis", False),
         "estimate_service_descriptions": ("describe", True),
         "start_service_descriptions": ("describe", False),
         "estimate_log_explanations": ("explain", True),
         "start_log_explanations": ("explain", False)}


def _job(client: Client, job: str, wait_s: float, sleep: Callable[[float], None],
         clock: Callable[[], float]) -> Any:
    deadline = clock() + min(max(wait_s, 0.0), MAX_WAIT_S)
    while True:
        status = client.call("GET", f"/jobs/{_part(job)}")
        if status.get("status") != "running" or clock() >= deadline:
            return status
        sleep(min(POLL_S, max(deadline - clock(), 0.0)))


def _elsewhere(host: str) -> str:
    """`host` when the dashboard binds only there, which loopback cannot reach; else ""."""
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return ""
    return "" if address.is_loopback or address.is_unspecified else host


def _part(value: str) -> str:
    return quote(value, safe="")


def _query(**values: Any) -> str:
    present = {k: v for k, v in values.items() if v is not None}
    return "?" + urlencode(present) if present else ""


_TYPES: dict[str, Callable[[Any], bool]] = {
    "string": lambda v: isinstance(v, str),
    "integer": lambda v: isinstance(v, int) and not isinstance(v, bool),
    "number": lambda v: isinstance(v, int | float) and not isinstance(v, bool),
    "array": lambda v: isinstance(v, list),
}


def _check(tool: Mapping[str, Any], arguments: Mapping[str, Any]) -> None:
    """Required, known and of the declared type; the dashboard checks the rest."""
    schema = tool["inputSchema"]
    if missing := [k for k in schema["required"] if k not in arguments]:
        raise Refused(f"{tool['name']} requires {', '.join(missing)}")
    if extra := sorted(set(arguments) - set(schema["properties"])):
        raise Refused(f"{tool['name']} takes no {', '.join(extra)}")
    for key, value in arguments.items():
        spec = schema["properties"][key]
        kinds = [option["type"] for option in spec.get("anyOf", [spec])]
        if not any(_TYPES[kind](value) for kind in kinds):
            raise Refused(f"{key} must be {' or '.join(kinds)}")
        if "enum" in spec and value not in spec["enum"]:
            raise Refused(f"{key} must be one of {spec['enum']}")


# --- JSON-RPC ----------------------------------------------------------------------------------


def handle(client: Client, message: Any, **options: Any) -> dict[str, Any] | None:
    """One JSON-RPC message; None for a notification or anything that is not a request."""
    if not isinstance(message, dict):
        return _failed({}, -32600, "not a JSON-RPC request")
    method = message.get("method")
    if not isinstance(method, str):
        # A response to a request we never sent is ignored; anything else is malformed.
        return None if "result" in message or "error" in message else _failed(
            message, -32600, "not a JSON-RPC request")
    if "id" not in message:
        return None  # a notification: nothing to answer
    if method == "initialize":
        return _result(message, {"protocolVersion": PROTOCOL, "capabilities": {"tools": {}},
                                 "serverInfo": {"name": NAME, "version": "1"}})
    if method == "ping":
        return _result(message, {})
    if method == "tools/list":
        return _result(message, {"tools": TOOLS})
    if method == "tools/call":
        params = message.get("params")
        params = params if isinstance(params, dict) else {}
        return _result(message, call(client, params.get("name", ""),
                                     params.get("arguments") or {}, **options))
    return _failed(message, -32601, f"no method {method!r}")


def call(client: Client, name: Any, arguments: Any, **options: Any) -> dict[str, Any]:
    """A `tools/call` result: the answer as text and structured content, or an error."""
    try:
        if not isinstance(name, str) or not isinstance(arguments, dict):
            raise Refused("a tool call names a tool and passes an object of arguments")
        reply = run_tool(client, name, arguments, **options)
    except Refused as refused:
        return _refused(str(refused))
    except Exception as unexpected:  # one bad call must not take the server down
        return _refused(f"{type(unexpected).__name__}: {unexpected}")
    structured = reply if isinstance(reply, dict) else {"result": reply}
    return {"content": [{"type": "text", "text": json.dumps(reply)}],
            "structuredContent": structured}


def serve(client: Client, lines: Iterable[str], write: Callable[[str], None],
          **options: Any) -> None:
    for line in lines:
        if not (text := line.strip()):
            continue
        try:
            message = json.loads(text)
        except ValueError as broken:
            write(json.dumps(_failed({}, -32700, f"not JSON: {broken}")))
            continue
        if (reply := handle(client, message, **options)) is not None:
            write(json.dumps(reply))


def _result(message: Mapping[str, Any], payload: Mapping[str, Any]) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": message.get("id"), "result": payload}


def _failed(message: Mapping[str, Any], code: int, text: str) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": message.get("id"), "error": {"code": code, "message": text}}


def _refused(text: str) -> dict[str, Any]:
    return {"content": [{"type": "text", "text": text}], "isError": True}


def main(config: Config, *, uid: int, agent: str | None, environ: Mapping[str, str],
         stdin: TextIO | None = None, stdout: TextIO | None = None,
         stderr: TextIO | None = None) -> int:
    """Serve MCP on stdin/stdout until stdin ends. 2 when the agent name is unusable."""
    stdin, stdout, stderr = stdin or sys.stdin, stdout or sys.stdout, stderr or sys.stderr
    name = agent if agent is not None else environ.get(AGENT_ENV) or DEFAULT_AGENT
    if not valid_name(name):
        print(f"neonwatch mcp: the agent name must be 1-64 of A-Z a-z 0-9 . _ : -; got "
              f"{name!r}", file=stderr)
        return 2
    where = agent_token.path(config)
    host, port, context = endpoint(config)
    client = Client(host, port, lambda: agent_token.read(where, uid), name, context=context,
                    bound=_elsewhere(config.web.host))

    def write(text: str) -> None:
        stdout.write(text + "\n")
        stdout.flush()

    serve(client, stdin, write)
    return 0
