#!/usr/bin/env python3
"""Render the README's screenshots from synthetic data: nothing from a real machine.

    .venv/bin/python scripts/make-screenshots.py [OUTDIR]     (default docs/images)

Builds a throwaway store of made-up events (example user `alice`, invented containers,
documentation IP addresses), serves the real dashboard over it on a free loopback port with a fake
judge health check, and captures the Attention and Board views and one issue card, in the
dashboard's dark (cyberpunk) theme, with headless Chrome (`google-chrome` on PATH). No neonwatch
process, probe or broker runs, and nothing is sent anywhere. Re-run it when the UI changes; this
file is the record of what the pictures claim.
"""

from __future__ import annotations

import asyncio
import base64
import json
import math
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

import aiohttp
from aiohttp import web

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from neonwatch.config import Config, Web  # noqa: E402
from neonwatch.config import Store as StoreConfig  # noqa: E402
from neonwatch.schema import (  # noqa: E402
    Attestation,
    Event,
    Finding,
    Heartbeat,
    Issue,
    IssueState,
    Kind,
    Link,
    Observation,
    Severity,
    to_body,
)
from neonwatch.store import Store  # noqa: E402
from neonwatch.web import make_app  # noqa: E402

JUDGE = {"name": "local-judge (7B)", "model": "judge-7b",
         "url": "http://127.0.0.1:8200/v1/systemone"}
NOW = time.time()
#: The first question each domain's snapshot is asked (`neonwatch.questions.bank_for`).
DOMAIN_QUESTIONS = {"hardware": "overheating", "cpu": "saturated", "memory": "low_available",
                    "storage": "filling", "gpu": "overheating", "network": "errors_drops",
                    "firewall": "ruleset_changed", "processes": "zombie_buildup",
                    "services": "failed_units", "containers": "restart_loop",
                    "logs": "kernel_errors", "security": "keys_changed", "kernel": "tainted"}


def event(kind: Kind, at: float, subject: str, record: Any) -> Event:
    return Event(kind, at, "demo", subject, to_body(record))


def hardware(t: float) -> list[Event]:
    """One minute of hardware readings: a CPU, two NVMe drives (one CPU-attached, one behind the
    chipset and near its limit), one GPU, with a slow wobble so the sparklines have a shape."""
    w = math.sin(t / 420)
    readings = [
        {"chip": "k10temp-pci-00c3", "label": "Tctl", "kind": "temp", "input": 61 + 6 * w},
        {"chip": "nvme-pci-0100", "label": "Composite", "kind": "temp", "input": 44 + 2 * w,
         "max": 81.85, "crit": 84.85},
        {"chip": "nvme-pci-0500", "label": "Composite", "kind": "temp", "input": 76 + 2 * w,
         "max": 81.85, "crit": 84.85},
    ]
    gpu = {"index": 0, "name": "Example GPU 24GB", "temperature_c": 63 + 4 * w,
           "power_w": 180 + 40 * w, "power_limit_w": 300, "utilization_pct": 70 + 20 * w,
           "memory_used_mib": 14000, "memory_total_mib": 24576, "pcie_width": 16,
           "pcie_width_max": 16, "throttle": []}
    ticks = int((t - NOW + 86400) * 100)
    obs = [
        Observation("sensors", {"readings": readings}, 3),
        Observation("gpu", {"gpus": [gpu]}, 20),
        Observation("load", {"load1": 3.2 + w}, 1),
        Observation("cpu.stat", {"cpus": 16, "user": ticks * 3, "nice": 0, "system": ticks,
                                 "idle": ticks * 9, "iowait": 0, "irq": 0, "softirq": 0,
                                 "steal": 0}, 1),
    ]
    return [event(Kind.OBSERVATION, t, f"obs.{o.probe}", o) for o in obs]


def static(t: float) -> list[Event]:
    links = {"nvme0n1": "../devices/pci0000:00/0000:00:01.1/0000:01:00.0/nvme/nvme0/nvme0n1",
             "nvme1n1": "../devices/pci0000:00/0000:00:01.2/0000:02:00.0/0000:03:04.0/"
                        "0000:05:00.0/nvme/nvme1/nvme1n1"}
    obs = [
        Observation("block.devices", {"entries": ["nvme0n1", "nvme1n1"], "links": links,
                                      "count": 2}, 1),
        Observation("disk.fill", {"filesystems": [
            {"source": "/dev/nvme0n1p2", "mount": "/"},
            {"source": "/dev/nvme1n1p1", "mount": "/mnt/data"}]}, 2),
        Observation("smart.nvme0n1", {"model": "Example NVMe 2TB", "passed": True,
                                      "temperature_c": 44, "percentage_used": 3,
                                      "media_errors": 0, "critical_warning": 0,
                                      "unsafe_shutdowns": 4, "power_on_hours": 3100}, 30),
        Observation("smart.nvme1n1", {"model": "Example NVMe 4TB", "passed": True,
                                      "temperature_c": 77, "percentage_used": 41,
                                      "media_errors": 0, "critical_warning": 1,
                                      "unsafe_shutdowns": 9, "power_on_hours": 21800}, 30),
    ]
    return [event(Kind.OBSERVATION, t, f"obs.{o.probe}", o) for o in obs]


def judged(t: float, issue: Issue, question: str, instructions: str, answer: dict[str, Any],
           severity: Severity, cause: str, confidence: float, stable: bool | None,
           next_step: str = "", evidence: dict[str, Any] | None = None) -> Event:
    kind = issue.entity.split(":", 1)[0]
    a = Attestation(f"{kind}:{issue.entity}", kind, issue.domain, issue.entity, question,
                    instructions, answer, severity, cause, next_step, confidence, stable, 90,
                    judge=JUDGE["name"], evidence=evidence or {})
    return event(Kind.ATTESTATION, t, f"attest.{a.context}", a)


def story(t: float) -> list[Event]:
    """The Attention view's issues: an incident (a crash-looping container named the likely
    cause of interface churn), a critical SMART warning from a rule, a judge-raised listener,
    and the expected info issue for an unconfined manual launch."""
    crash = Issue("i-crash", IssueState.OPEN, Severity.WARN,
                  "Container shopfront-worker-1 is crash-looping (14 restarts in 1 h)",
                  "containers", "container:shopfront-worker-1", t - 3000, t, True,
                  ("container.crash_loop",), "docker logs --tail 200 shopfront-worker-1", 4.0)
    churn = Issue("i-churn", IssueState.OPEN, Severity.WATCH,
                  "Network interfaces appearing and disappearing (veth churn)", "network",
                  "net:veth", t - 2900, t, True, ("net.interface_churn",),
                  "ip -br link", 2.0)
    smart = Issue("i-smart", IssueState.OPEN, Severity.CRITICAL,
                  "nvme1n1 reports a SMART critical warning", "storage", "disk:/dev/nvme1n1",
                  t - 7200, t, True, ("smart.critical_warning",),
                  "sudo smartctl -a /dev/nvme1n1", 6.0)
    listener = Issue("i-listen", IssueState.OPEN, Severity.WATCH,
                     "New wildcard listener tcp/8080 (python3)", "network", "listener:tcp/8080",
                     t - 1200, t, False, ("beyond_loopback",), "ss -ltnp 'sport = :8080'", 1.5)
    unconfined = Issue("i-unconf", IssueState.OPEN, Severity.INFO,
                       "Agent running unconfined (manual mode)", "security", "agent:neonwatch",
                       t - 9000, t, True, ("agent.unconfined",), "", 0.5)
    seen = t - 600
    tmp_ev = {"program": "/tmp/go-build4127/b001/exe/main",
              "args": "/tmp/go-build4127/b001/exe/main --serve :8080", "user": "alice",
              "pid": 3320260, "ppid": 3320257, "pid_ns": "host", "elapsed_s": 0,
              "cpu_pct": 529.0, "threads": 32, "rss_kb": 91012, "seen_at": seen}
    tmp_why = ("Anyone can write to /tmp, so a program there can be swapped before it runs, and "
               "dropped-and-run malware starts this way. Build and test runners (go run, go "
               "test) and self-extracting installers also run from there, briefly: the parent "
               "and the journal at that moment usually say which.")
    tmp_step = (f"ps -o pid,ppid,user,lstart,args -p 3320260,3320257; journalctl --since "
                f"@{int(seen) - 60} --until @{int(seen) + 10} -o short-iso --no-pager "
                f"| tail -n 40")
    tmp = Issue("i-tmp", IssueState.OPEN, Severity.WARN,
                "A program is running from /tmp: /tmp/go-build4127/b001/exe/main", "processes",
                "process:3320260", seen, t, True, ("process.runs_from_tmp", "suspicious"),
                tmp_step, 3.0, evidence=tmp_ev, why=tmp_why, last_seen=seen)
    issues = (crash, churn, smart, tmp, listener, unconfined)
    out = [event(Kind.ISSUE, t, f"issue.{i.id}", i) for i in issues]
    out += [event(Kind.FINDING, t, f"finding.{i.reasons[0]}",
                  Finding(i.reasons[0], i.severity, i.title, i.entity, {}, i.next_step))
            for i in issues if i.deterministic and i is not tmp]
    out.append(event(Kind.FINDING, seen, "finding.process.runs_from_tmp", Finding(
        "process.runs_from_tmp", Severity.WARN, tmp.title, tmp.entity, tmp_ev, tmp_step,
        tmp_why)))
    out.append(judged(seen, tmp, "suspicious",
                      "Is this process suspicious: an unusual path, a disguised name, or behaviour "
                      "that does not fit its identity?", {"type": "noul", "noul": 0.85},
                      Severity.WARN, "Runs from a build directory under /tmp.", 0.70, True,
                      "sudo ls -l /proc/3320260/exe /proc/3320260/cwd",
                      evidence={"process/args": tmp_ev["args"], "process/user": "alice"}))
    out.append(judged(t, listener, "beyond_loopback",
                      "Is it bound to 0.0.0.0, ::, or a LAN address rather than loopback?",
                      {"type": "noul", "noul": 0.97}, Severity.WATCH,
                      "Bound to 0.0.0.0, so reachable from the LAN.", 0.97, True,
                      "ss -ltnp 'sport = :8080'"))
    out.append(judged(t, listener, "service", "What service is this?",
                      {"type": "choice", "choice": "web_dev", "confidence": 0.6,
                       "probabilities": {"ssh": 0.0, "web_dev": 0.6, "database": 0.05,
                                         "model_api": 0.15, "docker_api": 0.0,
                                         "remote_desktop": 0.0, "system": 0.05,
                                         "unknown": 0.15}},
                      Severity.WATCH, "python3 started from a user shell: a dev server.", 0.6,
                      False))
    # Each domain's own snapshot, answered quietly, so the Domains matrix reads as a working
    # judge would leave it: mostly quiet, one domain stale.
    for domain, question in DOMAIN_QUESTIONS.items():
        at = t - (3 * 3600 if domain == "firewall" else 60)
        a = Attestation(f"{domain}:snapshot", domain, domain, domain, question, question,
                        {"type": "noul", "noul": 0.04}, Severity.INFO, "", "", 0.9, None, 80,
                        judge=JUDGE["name"])
        out.append(event(Kind.ATTESTATION, at, f"attest.{a.context}", a))
    out.append(event(Kind.LINK, t, "link.l-1", Link(
        "l-1", ("issue:i-crash", "issue:i-churn"), "co-occurrence", 0.86, "issue:i-crash",
        0.8, True)))
    out.append(event(Kind.HEARTBEAT, t, "hb.agent",
                     Heartbeat(0.004, False, ("/etc", "/home", "/var"), 49, 0, 0)))
    return out


def port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


class Live:
    async def subscribe(self):
        while True:
            await asyncio.sleep(3600)
            yield  # never


async def capture(out: Path) -> None:
    work = Path(tempfile.mkdtemp(prefix="neonwatch-demo-"))
    wp, cp = port(), port()
    config = Config(web=Web(port=wp), store=StoreConfig(path=str(work / "store.sqlite3")))
    store = Store(work / "store.sqlite3", config)
    for event_ in static(NOW - 600):
        store.apply(event_)
    for minute in range(60, -1, -1):
        for event_ in hardware(NOW - minute * 60 - 5):
            store.apply(event_)
    for event_ in story(NOW - 20):
        store.apply(event_)

    async def judge_health() -> dict[str, Any]:
        return {"reachable": True, "last_error": "", "p50_ms": 88.0, "p95_ms": 140.0,
                "in_flight": 0, "requests": 412, "refused_answers": 0, "failed_requests": 0,
                "refused_steps": 0, **JUDGE}

    token = base64.urlsafe_b64encode(os.urandom(12)).decode()
    app = make_app(store, Live(), token, config, judge_health=judge_health)
    runner = web.AppRunner(app)
    await runner.setup()
    await web.TCPSite(runner, "127.0.0.1", wp).start()
    profile = tempfile.mkdtemp(prefix="neonwatch-demo-chrome-")
    chrome = subprocess.Popen(["google-chrome", "--headless=new", f"--remote-debugging-port={cp}",
                               f"--user-data-dir={profile}", "--no-first-run", "--disable-gpu",
                               "--hide-scrollbars", "--force-prefers-reduced-motion",
                               "about:blank"],
                              # UTC, so the clock times in the pictures say nothing of where.
                              env={**os.environ, "TZ": "UTC"},
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        async with aiohttp.ClientSession() as http:
            for _ in range(50):
                try:
                    tabs = await (await http.get(f"http://127.0.0.1:{cp}/json")).json()
                    break
                except aiohttp.ClientError:
                    await asyncio.sleep(0.2)
            page = next(t for t in tabs if t["type"] == "page")
            ws = await http.ws_connect(page["webSocketDebuggerUrl"], max_msg_size=0)
            ids = iter(range(1, 1_000_000))

            async def send(method: str, **params: Any) -> dict[str, Any]:
                mine = next(ids)
                await ws.send_json({"id": mine, "method": method, "params": params})
                while True:
                    msg = json.loads((await ws.receive()).data)
                    if msg.get("id") == mine:
                        if "error" in msg:
                            raise RuntimeError(f"{method}: {msg['error']}")
                        return msg.get("result", {})

            async def js(expr: str) -> Any:
                r = await send("Runtime.evaluate", expression=expr, awaitPromise=True,
                               returnByValue=True)
                if r.get("exceptionDetails"):
                    raise RuntimeError(json.dumps(r["exceptionDetails"])[:500])
                return r.get("result", {}).get("value")

            async def shot(name: str, clip: list[float] | None = None) -> None:
                extra = {} if clip is None else {"clip": {"x": clip[0], "y": clip[1],
                                                          "width": clip[2], "height": clip[3],
                                                          "scale": 1}}
                data = (await send("Page.captureScreenshot", format="png",
                                   captureBeyondViewport=clip is not None, **extra))["data"]
                (out / name).write_bytes(base64.b64decode(data))
                print(f"wrote {out / name}")

            await send("Page.enable")
            await send("Emulation.setDeviceMetricsOverride", width=1440, height=900,
                       deviceScaleFactor=1, mobile=False)
            # The dashboard's own dark theme, the cyberpunk one, is the one the README shows.
            for theme in ("dark",):
                await send("Page.navigate", url=f"http://127.0.0.1:{wp}/?token={token}")
                await asyncio.sleep(1.5)
                await js(f"localStorage.setItem('neonwatch.theme', '{theme}')")
                await send("Page.reload")
                await asyncio.sleep(4)
                await shot("attention.png")
                box = await js("""(() => { const c = [...document.querySelectorAll('article.card')]
                  .find((n) => n.textContent.includes('running from /tmp'));
                  c.querySelector('button.why').click();
                  return null; })()""")
                await asyncio.sleep(2)
                box = await js("""(() => { const r = [...document.querySelectorAll('article.card')]
                  .find((n) => n.textContent.includes('running from /tmp')).getBoundingClientRect();
                  return [r.x + scrollX, r.y + scrollY, r.width, Math.min(r.height, 640)];
                  })()""")
                await shot("issue.png", clip=box)
                await js("document.querySelector('button.view-tab[data-view=board]').click()")
                await asyncio.sleep(1)
                await js("""(() => { const g = [...document.querySelectorAll('.b-live .b-disk')]
                  .find((n) => n.getAttribute('aria-label').startsWith('nvme1n1'));
                  g && g.dispatchEvent(new MouseEvent('click', {bubbles: true})); })()""")
                await asyncio.sleep(0.5)
                await shot("board.png")
            await ws.close()
    finally:
        chrome.terminate()
        chrome.wait(5)
        shutil.rmtree(profile, ignore_errors=True)
        await runner.cleanup()
        store.close()
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    target = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "docs" / "images"
    target.mkdir(parents=True, exist_ok=True)
    asyncio.run(capture(target))
