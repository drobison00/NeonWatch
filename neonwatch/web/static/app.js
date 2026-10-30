// neonwatch dashboard. No framework, no build step, no network beyond this origin.
//
// Everything shown here that came from the host (observations, logs, findings, attestations,
// analyses) is UNTRUSTED text: anyone can write to syslog. It is rendered only through
// textContent and createElement. Suggested checks are shown for copying, never run, never links.
"use strict";

(() => {
  // --- constants ------------------------------------------------------------------------------

  const SEVERITIES = ["critical", "warn", "watch", "info"]; // highest first
  const SEV = {
    critical: { glyph: "◆", label: "CRITICAL" },
    warn: { glyph: "⚠\uFE0E", label: "WARN" },
    watch: { glyph: "●", label: "WATCH" },
    info: { glyph: "○", label: "INFO" },
    unknown: { glyph: "?", label: "UNKNOWN" },
  };
  const rank = (s) => (SEVERITIES.includes(s) ? 3 - SEVERITIES.indexOf(s) : -1);

  // --- colour theme ---------------------------------------------------------------------------
  // "auto" follows the OS; the choice is remembered per browser. data-theme always holds the
  // resolved theme, which is what the stylesheet keys on.

  const THEMES = { auto: "◐ Auto", dark: "☾ Dark", light: "☀ Light" };
  const NEXT_THEME = { auto: "dark", dark: "light", light: "auto" };
  const darkQuery = window.matchMedia("(prefers-color-scheme: dark)");

  function savedTheme() {
    try {
      const t = localStorage.getItem("neonwatch.theme");
      return t in THEMES ? t : "auto";
    } catch { return "auto"; }
  }

  function applyTheme(choice) {
    const resolved = choice === "auto" ? (darkQuery.matches ? "dark" : "light") : choice;
    document.documentElement.dataset.theme = resolved;
    const button = document.getElementById("theme");
    if (button) {
      button.textContent = THEMES[choice];
      button.dataset.choice = choice;
      button.setAttribute("aria-label", `Colour theme: ${choice}`);
      button.title = `Theme: ${choice}${choice === "auto" ? ` (${resolved} from the system)` : ""}. Click to change.`;
    }
  }

  function wireTheme() {
    applyTheme(savedTheme());
    darkQuery.addEventListener("change", () => applyTheme(savedTheme()));
    document.getElementById("theme").addEventListener("click", (e) => {
      const next = NEXT_THEME[e.currentTarget.dataset.choice] || "auto";
      try { localStorage.setItem("neonwatch.theme", next); } catch { /* private mode: not kept */ }
      applyTheme(next);
    });
  }

  wireTheme();

  // The agent heartbeats once per fast period (60 s by default).
  const HEARTBEAT_STALE_S = 180;
  // An attestation older than this is drawn as unknown in the matrix.
  const ATTESTATION_STALE_S = 1800;
  // A finding in an incident counts as current when it was re-raised this recently.
  const FINDING_CURRENT_S = 900;
  // A choice whose top two options are closer than this is contested; so is a noul near 0.5.
  const CONTESTED_MARGIN = 0.15;
  const NOUL_CONTESTED = [0.35, 0.65];
  const MAX_SUBJECTS = 20;

  // The thirteen domains of the catalog. A domain with nothing held is drawn UNKNOWN.
  const DOMAINS = ["hardware", "cpu", "memory", "storage", "gpu", "network", "firewall",
    "processes", "services", "containers", "logs", "security", "kernel"];

  const SNOOZES = [["1h", 3600], ["8h", 8 * 3600], ["24h", 86400], ["7d", 7 * 86400 - 60]];

  // Series the store indexes. A list element is named by its identity (index, mount, …), so a
  // name is BUILT from the list key, the identity and the field, never split apart: a mount
  // point may itself contain dots or slashes.
  const listField = (list, identity, field) => `${list}.${identity}.${field}`;
  const SERIES = [
    { name: "Load (1 min)", probe: "load", field: "load1", unit: "", digits: 2 },
    { name: "Memory pressure 10 s", probe: "psi.memory", field: "some_avg10", unit: "%", digits: 1 },
    { name: "Memory available", probe: "memory", field: "mem_available_pct", unit: "%", digits: 1 },
    { name: "IO pressure 10 s", probe: "psi.io", field: "some_avg10", unit: "%", digits: 1 },
    { name: "GPU 0 temperature", probe: "gpu", field: listField("gpus", 0, "temperature_c"), unit: "°C", digits: 0 },
    { name: "Disk fill /", probe: "disk.fill", field: listField("filesystems", "/", "used_pct"), unit: "%", digits: 1 },
  ];
  const SERIES_WINDOW_S = 3600;
  const SERIES_STEP_S = 60;

  // --- state ----------------------------------------------------------------------------------

  const state = {
    offset: 0, // server clock minus browser clock, seconds
    overview: null,
    overviewAt: null,
    health: null,
    held: [],
    domains: new Map(), // domain -> /api/domains/{d} body, or null when the store holds nothing
    heartbeat: null,
    probes: new Map(), // probe -> {probe, at, error, truncated}
    series: new Map(),
    expanded: new Set(), // issue ids whose "why" is open
    folded: loadFolded(), // cards folded to their head line: issue:<id>, link:<id>
    details: new Map(), // issue id -> {data, fetchedAt, error}
    selected: new Set(), // analysis subjects: issue:<id>, link:<id>
    analyses: new Map(), // id -> {id, status, subjects, requested_at, record?, error?}
    csrf: null,
    live: "connecting",
    liveSince: null,
    streamOpens: 0,
    authFailed: false,
    leaving: false, // navigating to /login
    errors: [],
    view: "layout", // the shown view: layout (attention), sched, svc, logs or board
  };

  const VIEWS = ["layout", "sched", "svc", "logs", "board"];
  const now = () => Date.now() / 1000 + state.offset;
  const $ = (id) => document.getElementById(id);

  // --- DOM helpers (text only, never HTML) ----------------------------------------------------

  function el(tag, props, ...children) {
    const node = document.createElement(tag);
    if (props) {
      for (const [key, value] of Object.entries(props)) {
        if (value === undefined || value === null || value === false) continue;
        if (key === "class") node.className = value;
        else if (key === "text") node.textContent = String(value);
        else if (key === "on") for (const [ev, fn] of Object.entries(value)) node.addEventListener(ev, fn);
        else if (key === "dataset") Object.assign(node.dataset, value);
        else if (key in node && typeof value !== "string") node[key] = value;
        else node.setAttribute(key, String(value));
      }
    }
    append(node, children);
    return node;
  }

  // replaceChildren() would print a null child as the text "null"; this skips it.
  function put(node, ...children) {
    node.replaceChildren();
    return append(node, children);
  }

  function append(node, children) {
    for (const child of children.flat()) {
      if (child === null || child === undefined || child === false) continue;
      node.appendChild(child instanceof Node ? child : document.createTextNode(String(child)));
    }
    return node;
  }

  function svg(tag, attrs) {
    const node = document.createElementNS("http://www.w3.org/2000/svg", tag);
    for (const [k, v] of Object.entries(attrs || {})) node.setAttribute(k, String(v));
    return node;
  }

  function sevMark(severity, extra) {
    const s = SEV[severity] ? severity : "unknown";
    return el("span", { class: `sev sev-${s}`, title: extra || undefined },
      el("span", { class: "glyph", "aria-hidden": "true", text: SEV[s].glyph }), SEV[s].label);
  }

  // --- formatting ------------------------------------------------------------------------------

  function fmtDuration(seconds) {
    if (!Number.isFinite(seconds)) return "?";
    const s = Math.max(0, Math.round(seconds));
    if (s < 60) return `${s} s`;
    const m = Math.floor(s / 60);
    if (m < 60) return `${m} min`;
    const h = Math.floor(m / 60);
    if (h < 48) return `${h} h ${m % 60} min`;
    return `${Math.floor(h / 24)} d ${h % 24} h`;
  }
  const fmtAge = (at) => `${fmtDuration(now() - at)} ago`;
  function fmtClock(at) {
    const d = new Date((at - state.offset) * 1000);
    return d.toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit", second: "2-digit" });
  }
  function fmtNum(v, digits) {
    if (typeof v !== "number" || !Number.isFinite(v)) return "?";
    return v.toFixed(digits === undefined ? 2 : digits);
  }

  // An age that keeps itself current: the ticker rewrites every [data-at] each few seconds.
  function ageEl(at, cls) {
    return el("span", { class: cls || "age", dataset: { at: String(at) }, title: fmtClock(at), text: fmtAge(at) });
  }
  const fmtUntil = (at) => (at > now() ? `in ${fmtDuration(at - now())}` : "due now");
  function untilEl(at) {
    return el("span", { class: "age", dataset: { at: String(at), until: "1" }, title: fmtClock(at), text: fmtUntil(at) });
  }
  function fmtShort(seconds) {
    const s = Math.max(0, Math.round(seconds));
    if (s < 60) return `${s}s`;
    if (s < 3600) return `${Math.floor(s / 60)}m`;
    if (s < 172800) return `${Math.floor(s / 3600)}h`;
    return `${Math.floor(s / 86400)}d`;
  }
  function tickAges() {
    for (const node of document.querySelectorAll("[data-at]")) {
      const at = Number(node.dataset.at);
      if (!Number.isFinite(at)) continue;
      node.textContent = node.dataset.until ? fmtUntil(at) : node.dataset.short ? fmtShort(now() - at) : fmtAge(at);
    }
  }

  // --- status line: every error is shown ------------------------------------------------------

  function reportError(what, err) {
    const message = err && err.message ? err.message : String(err);
    state.errors.push({ at: Date.now(), what, message });
    if (state.errors.length > 50) state.errors.shift();
    const line = $("status-text");
    const t = new Date().toLocaleTimeString();
    line.textContent = `${t} — ${what}: ${message}` + (state.errors.length > 1 ? ` (${state.errors.length} errors since load)` : "");
    line.title = state.errors.slice(-10).map((e) => `${new Date(e.at).toLocaleTimeString()} ${e.what}: ${e.message}`).join("\n");
    $("statusline").classList.add("error");
    $("status-clear").hidden = false;
  }
  function reportOk(message) {
    if (state.errors.length) return; // an unacknowledged error stays visible until cleared
    $("status-text").textContent = message;
    $("statusline").classList.remove("error");
  }
  function clearErrors() {
    state.errors = [];
    $("statusline").classList.remove("error");
    $("status-clear").hidden = true;
    $("status-text").textContent = "Errors cleared.";
    $("status-text").title = "";
  }

  // --- HTTP -----------------------------------------------------------------------------------

  class HttpError extends Error {
    constructor(status, message) {
      super(status ? `${message} (HTTP ${status})` : message);
      this.status = status;
      this.reason = message;
    }
  }

  async function csrfToken() {
    if (state.csrf) return state.csrf;
    const body = await api("/api/session");
    if (!body || typeof body.csrf !== "string") throw new HttpError(0, "/api/session returned no csrf token");
    state.csrf = body.csrf; // memory only
    return state.csrf;
  }

  async function api(path, opts = {}) {
    const init = { credentials: "same-origin", headers: { Accept: "application/json" }, cache: "no-store" };
    if (opts.post) {
      init.method = "POST";
      init.headers["X-CSRF-Token"] = await csrfToken();
      if (opts.body !== undefined) {
        init.headers["Content-Type"] = "application/json";
        init.body = JSON.stringify(opts.body);
      }
    }
    let resp;
    try {
      resp = await fetch(path, init);
    } catch (e) {
      throw new HttpError(0, `cannot reach the service (${e.message})`);
    }
    let data = null;
    try { data = await resp.json(); } catch (_) { data = null; }
    if (resp.status === 401) showAuth();
    if (!resp.ok) {
      const reason = data && typeof data.error === "string" ? data.error : resp.statusText || "request failed";
      if (resp.status === 403 && reason === "missing or wrong CSRF token" && opts.post && !opts.retried) {
        state.csrf = null; // the service restarted with a new one: fetch it once and retry
        return api(path, { ...opts, retried: true });
      }
      throw new HttpError(resp.status, reason);
    }
    if (data === null && !opts.noBody) throw new HttpError(resp.status, "response was not JSON");
    return data;
  }

  // Password mode is the one where the server has a /login page; in token mode it is a 404.
  // Asked once per page load; a probe that cannot reach the service is asked again next time.
  let loginProbe = null;
  function passwordMode() {
    if (!loginProbe) {
      loginProbe = fetch("/login", { credentials: "same-origin", cache: "no-store" })
        .then((r) => r.status === 200, () => { loginProbe = null; return false; });
    }
    return loginProbe;
  }

  // At most one navigation per page load, whichever path asks for it first.
  function goToLogin() {
    if (state.leaving) return;
    state.leaving = true;
    if (source) source.close();
    $("status-text").textContent = "Signed out: going to the sign-in page…";
    location.assign("/login");
  }

  async function showAuth() {
    if (state.authFailed) return;
    state.authFailed = true;
    if (await passwordMode()) {
      goToLogin();
      return;
    }
    $("auth").hidden = false;
    for (const id of VIEWS) $(id).hidden = true;
    if (source) source.close();
    state.live = "closed";
    renderVitals();
    $("status-text").textContent = "Not signed in: open the URL printed by `neonwatch service`.";
    $("statusline").classList.add("error");
  }

  // --- copy -----------------------------------------------------------------------------------

  function copyButton(text, codeNode) {
    const button = el("button", { type: "button", class: "copy", text: "Copy", title: "Copy to the clipboard. Nothing is run." });
    button.addEventListener("click", async () => {
      try {
        await navigator.clipboard.writeText(text);
        button.textContent = "Copied";
        setTimeout(() => { button.textContent = "Copy"; }, 1500);
      } catch (e) {
        if (codeNode) {
          const range = document.createRange();
          range.selectNodeContents(codeNode);
          const sel = window.getSelection();
          sel.removeAllRanges();
          sel.addRange(range);
        }
        reportError("copy", new Error(`clipboard refused (${e.message}); the text is selected, press Ctrl+C`));
      }
    });
    return button;
  }

  function checkLine(text, label) {
    const code = el("code", { text });
    return el("div", { class: "check" }, label ? el("span", { class: "label muted", text: label }) : null, code, copyButton(text, code));
  }

  // --- top bar --------------------------------------------------------------------------------

  const ANALYST_OFF = "Set [analyst] provider and model in the config to enable manual analysis.";

  /** Enable an analysis button only with a configured analyst, and say why when it is off. */
  function gateAnalyse(button) {
    const off = !(state.health && state.health.analyst && state.health.analyst.configured);
    button.disabled = off;
    button.title = off ? ANALYST_OFF : "";
  }

  // The judge as `judge.name` calls it ("local-judge", "Qwen 7B judge"), once the health check says.
  function judgeName() {
    const j = state.health && state.health.judge;
    return j && typeof j.name === "string" && j.name ? j.name : "Judge";
  }

  function setVital(id, text, tone, sub, title) {
    const box = $(id);
    box.classList.remove("bad", "warn", "neutral");
    if (tone) box.classList.add(tone);
    const dd = box.querySelector("dd");
    put(dd, document.createTextNode(text));
    if (sub) dd.appendChild(el("span", { class: "sub", text: sub }));
    box.title = title || "";
  }

  function renderVitals() {
    const hb = state.heartbeat;
    const banner = $("banner");
    if (!state.overview) {
      setVital("v-agent", "…");
    } else if (!hb) {
      setVital("v-agent", "no heartbeat", "bad", "", "The store holds no heartbeat from the agent.");
      banner.hidden = false;
      banner.textContent = "No heartbeat has been received from the agent. Nothing below is known to be current.";
    } else {
      const age = now() - hb.at;
      const stale = age > HEARTBEAT_STALE_S;
      setVital("v-agent", stale ? `SILENT ${fmtDuration(age)}` : `beat ${fmtDuration(age)} ago`, stale ? "bad" : "",
        `ran ${hb.ran} · failed ${hb.failed} · deferred ${hb.deferred}`,
        `Last heartbeat ${fmtClock(hb.at)}`);
      banner.hidden = !stale;
      if (stale) {
        banner.textContent = `The agent has not reported for ${fmtDuration(age)} (last heartbeat ${fmtClock(hb.at)}). ` +
          "What you see below may be out of date; an absence of issues is not evidence of health.";
      }
      if (hb.confined) {
        setVital("v-confined", "confined", "", "", "The write canary found nothing writable.");
      } else {
        const paths = Array.isArray(hb.writable) ? hb.writable : [];
        setVital("v-confined", "unconfined (manual mode)", "neutral", paths.length ? `writable: ${paths.join(" ")}` : "",
          "Run by hand without the systemd seatbelt, the write canary finds the filesystem writable. " +
          "The agent is still read-only by construction.");
      }
      const pct = typeof hb.cpu_fraction === "number" ? hb.cpu_fraction * 100 : NaN;
      setVital("v-budget", `${fmtNum(pct, 2)}% of a core`, pct > 2 ? "warn" : "", "",
        "The agent's CPU spend from its last heartbeat. The budget itself is not exposed by the API (default 1%).");
    }
    if (hb === null && state.overview) {
      setVital("v-confined", "unknown", "neutral");
      setVital("v-budget", "unknown", "neutral");
    }

    const live = {
      connecting: ["connecting…", "warn"],
      live: ["live", ""],
      reconnecting: ["reconnecting…", "warn"],
      closed: ["disconnected", "bad"],
    }[state.live] || [state.live, "warn"];
    setVital("v-live", live[0], live[1], state.liveSince ? `since ${new Date(state.liveSince).toLocaleTimeString()}` : "");

    const h = state.health;
    if (!h) {
      setVital("v-judge", "…");
      setVital("v-store", "…");
      setVital("v-analyst", "…");
      return;
    }
    const e = h.judge;
    $("v-judge").querySelector("dt").textContent = judgeName();
    const which = e && e.url ? `${judgeName()}: model ${e.model || "?"} at ${e.url}\n` : "";
    if (e === null || e === undefined) {
      setVital("v-judge", "not wired", "neutral", "", "The service did not give the web layer a judge health check.");
    } else if (e.ok === false) {
      setVital("v-judge", "health check failed", "bad", e.error || "");
    } else {
      const p50 = typeof e.p50_ms === "number" ? `p50 ${Math.round(e.p50_ms)} ms` : "no latency yet";
      const p95 = typeof e.p95_ms === "number" ? ` · p95 ${Math.round(e.p95_ms)} ms` : "";
      const extra = typeof e.failed_requests === "number" ? `requests ${e.requests} · failed ${e.failed_requests} · refused answers ${e.refused_answers}` : "";
      if (e.reachable === false) setVital("v-judge", "unreachable", "bad", e.last_error || "", which + extra);
      else if (e.reachable === true) setVital("v-judge", "reachable", "", p50 + p95, `${which}${extra}${e.last_error ? `\nlast error: ${e.last_error}` : ""}`);
      else setVital("v-judge", "not asked yet", "neutral", p50, which + extra);
    }
    const live2 = h.live && h.live.error ? ` · live source: ${h.live.error}` : "";
    if (h.store && h.store.ok) setVital("v-store", "ok", live2 ? "warn" : "", live2);
    else setVital("v-store", "error", "bad", (h.store && h.store.error) || "");
    if (h.analyst && h.analyst.configured) setVital("v-analyst", h.analyst.model || "configured", "", h.analyst.provider || "");
    else setVital("v-analyst", "not configured", "neutral", "", ANALYST_OFF);
    for (const b of document.querySelectorAll("button.analyse")) gateAnalyse(b);
    gateAnalyse($("win-analyse"));
    updateSelectionBar();
  }

  // --- the attention column -------------------------------------------------------------------

  function openIssues() {
    const ov = state.overview;
    if (!ov) return [];
    const all = SEVERITIES.flatMap((s) => (ov.open && Array.isArray(ov.open[s]) ? ov.open[s] : []));
    return all.sort((a, b) => b.score - a.score || rank(b.severity) - rank(a.severity) || b.updated_at - a.updated_at);
  }

  // The default view shows what still needs attention: an issue that is open, or a finding that is
  // current. Resolved issues leave it; acknowledged and snoozed ones live in the held section.
  const memberShown = (i) => i.state === "open";
  const findingCurrent = (f) => now() - f.at <= FINDING_CURRENT_S;

  function incidentActive(inc) {
    return inc.issues.some(memberShown) || inc.findings.some(findingCurrent);
  }

  function incidentSeverity(inc) {
    let best = -1, sev = "unknown";
    for (const m of [...inc.issues.filter(memberShown), ...inc.findings.filter(findingCurrent)]) {
      if (rank(m.severity) > best) { best = rank(m.severity); sev = m.severity; }
    }
    return sev;
  }

  function renderAttention() {
    const ov = state.overview;
    if (!ov) return;
    const counts = $("counts");
    put(counts, ...SEVERITIES.map((s) =>
      el("span", { class: `sev sev-${s}` }, el("span", { class: "glyph", "aria-hidden": "true", text: SEV[s].glyph }),
        `${(ov.counts && ov.counts[s]) || 0} ${SEV[s].label.toLowerCase()}`)));

    const incidents = (ov.incidents || []).filter(incidentActive);
    const hiddenIncidents = (ov.incidents || []).length - incidents.length;
    const inIncident = new Set();
    for (const inc of incidents) for (const i of inc.issues) if (memberShown(i)) inIncident.add(i.id);

    reconcile($("incidents"), incidents, (inc) => `link:${inc.link.id}`, buildIncident, updateIncident);
    if (hiddenIncidents > 0) {
      $("incidents").appendChild(el("p", { class: "muted", text: `${hiddenIncidents} incident(s) with nothing open (members resolved, acknowledged or snoozed) are not shown.` }));
    }

    const standalone = openIssues().filter((i) => !inIncident.has(i.id));
    const box = $("issues");
    reconcile(box, standalone, (i) => `issue:${i.id}`, (i) => buildIssueCard(i, false), updateIssueCard);
    const nInIncidents = openIssues().length - standalone.length;
    if (nInIncidents > 0 && standalone.length) {
      box.appendChild(el("p", { class: "muted", text: `${nInIncidents} more open issue(s) are shown inside the incidents above.` }));
    }
    if (!incidents.length && !standalone.length) box.appendChild(emptyState());

    renderHeld();
    revealWanted();
  }

  function newestAttestationAt() {
    let newest = null;
    for (const body of state.domains.values()) {
      if (!body) continue;
      for (const a of body.attestations || []) if (newest === null || a.at > newest) newest = a.at;
    }
    return newest;
  }

  function emptyState() {
    const hb = state.heartbeat;
    const newest = newestAttestationAt();
    const stale = !hb || now() - hb.at > HEARTBEAT_STALE_S;
    const box = el("div", { class: stale ? "empty warn" : "empty" });
    box.appendChild(el("strong", { text: "No open issues" }));
    const parts = [];
    parts.push(newest !== null ? `latest ${judgeName()} attestation ${fmtAge(newest)}` : "no attestations held yet");
    parts.push(hb ? `last heartbeat ${fmtAge(hb.at)}` : "no heartbeat received");
    box.appendChild(document.createTextNode(` — ${parts.join("; ")}.`));
    if (stale) box.appendChild(el("div", { text: "The agent is not reporting, so this is not evidence that the machine is healthy." }));
    return box;
  }

  // Keep one element per key, in order, moving only what moved (focus and expansion survive).
  function reconcile(container, items, keyOf, build, update) {
    const existing = new Map();
    for (const child of [...container.children]) {
      if (child.dataset && child.dataset.key) existing.set(child.dataset.key, child);
      else child.remove();
    }
    items.forEach((item, index) => {
      const key = keyOf(item);
      let node = existing.get(key);
      if (node) existing.delete(key);
      else { node = build(item); node.dataset.key = key; }
      update(node, item);
      const at = container.children[index];
      if (at !== node) container.insertBefore(node, at || null);
    });
    for (const node of existing.values()) node.remove();
  }

  // --- folding ---------------------------------------------------------------------------------
  // A card folds to its head line: the chevron, or a click anywhere on the head that is not one of
  // its own controls. The fold lives in state.folded (and this browser's storage), so the
  // re-render that every live event brings keeps it.

  function loadFolded() {
    try {
      const saved = JSON.parse(localStorage.getItem("neonwatch.folded") || "[]");
      return new Set(Array.isArray(saved) ? saved.filter((k) => typeof k === "string") : []);
    } catch { return new Set(); }
  }

  function saveFolded() {
    try { localStorage.setItem("neonwatch.folded", JSON.stringify([...state.folded].slice(-500))); } catch { /* not kept */ }
  }

  function foldButton(card) {
    const folded = state.folded.has(card._foldKey);
    return el("button", { type: "button", class: "fold", "aria-expanded": String(!folded),
      "aria-label": folded ? "Expand" : "Collapse", title: folded ? "Expand" : "Collapse", text: folded ? "▸" : "▾" });
  }

  function applyFold(card) {
    const folded = state.folded.has(card._foldKey);
    card.classList.toggle("folded", folded);
    const b = card._parts.head.querySelector(":scope > .fold");
    if (b) {
      b.textContent = folded ? "▸" : "▾";
      b.setAttribute("aria-expanded", String(!folded));
      b.setAttribute("aria-label", folded ? "Expand" : "Collapse");
      b.title = folded ? "Expand" : "Collapse";
    }
  }

  function wireFold(card) {
    card._parts.head.addEventListener("click", (e) => {
      if (e.target.closest("input, select, textarea, a, button:not(.fold)")) return;
      if (state.folded.has(card._foldKey)) state.folded.delete(card._foldKey);
      else state.folded.add(card._foldKey);
      saveFolded();
      applyFold(card);
    });
  }

  // The side panels fold the same way, by their heading, under a "panel:" key.
  function wirePanels() {
    for (const section of document.querySelectorAll("#machine > section[data-fold]")) {
      section._foldKey = section.dataset.fold;
      section._parts = { head: section.querySelector(":scope > .panel-head") };
      wireFold(section);
      applyFold(section);
    }
  }

  // The side column scrolls on its own beneath the sticky top bar, whose height wraps with the
  // vitals: --topbar-h follows it, and --statusline-h the status line, which scrolls away above
  // the column (left out of its height, the column's foot starts below the window).
  function trackTopbar() {
    const root = document.documentElement.style;
    const watch = (id, name) => {
      const box = $(id);
      const set = () => root.setProperty(name, `${box.offsetHeight}px`);
      set();
      if (typeof ResizeObserver === "function") new ResizeObserver(set).observe(box);
    };
    watch("topbar", "--topbar-h");
    watch("statusline", "--statusline-h");
  }

  // --- issue cards ----------------------------------------------------------------------------

  function buildIssueCard(issue, member) {
    const card = el("article", { class: "card" });
    card._parts = {
      head: el("div", { class: "card-head" }),
      meta: el("div", { class: "card-meta" }),
      what: el("div", { class: "card-what" }),
      next: el("div", { class: "card-next" }),
      actions: buildIssueActions(issue.id, member),
      detail: el("div", { class: "detail", hidden: true }),
    };
    append(card, Object.values(card._parts));
    card._sig = "";
    wireFold(card);
    return card;
  }

  function updateIssueCard(card, issue, extra) {
    const sig = JSON.stringify([issue, extra || null]);
    card._foldKey = `issue:${issue.id}`;
    card.dataset.issue = issue.id;
    card.className = `card card-${issue.severity} state-${issue.state}${extra && extra.cause ? " cause" : ""}${card.classList.contains("targeted") ? " targeted" : ""}`;
    card.classList.toggle("folded", state.folded.has(card._foldKey));
    if (sig !== card._sig) {
      card._sig = sig;
      card._issue = issue;
      const p = card._parts;
      const box = el("input", { type: "checkbox", class: "select-box", title: "Select for a combined analysis", "aria-label": `Select ${issue.title}` });
      box.checked = state.selected.has(`issue:${issue.id}`);
      box.addEventListener("change", () => toggleSelect(`issue:${issue.id}`, box.checked));
      put(p.head, foldButton(card),
        issue.state === "resolved" ? null : box,
        sevMark(issue.severity),
        el("span", { class: "title", text: issue.title }),
        extra && extra.cause ? el("span", { class: "badge cause", text: "LIKELY CAUSE", title: `${judgeName()} rated this member the likely cause of the incident.` }) : null,
        issue.state !== "open" ? el("span", { class: "badge state", text: issue.state.toUpperCase() }) : null,
        ageEl(issue.opened_at));
      put(p.meta, 
        issue.deterministic
          ? el("span", { class: "badge rule", text: "RULE · HARD FACT", title: "A deterministic rule raised this. No model judgement can clear it." })
          : el("span", { class: "badge judged", text: `JUDGED · ${judgeName().toUpperCase()}`, title: `Raised or ranked by ${judgeName()}'s attestations: a judgement, not a measurement.` }),
        el("span", { text: issue.domain }),
        el("span", { class: "entity", text: issue.entity }),
        el("span", { title: "Percolation score: higher surfaces first", text: `score ${fmtNum(issue.score, 1)}` }),
        el("span", { text: `updated ` }, ageEl(issue.updated_at)),
        issue.reasons && issue.reasons.length ? el("span", { class: "mono", title: "Rules and attestation questions that raised or ranked it", text: issue.reasons.join(", ") }) : null);
      put(p.what, whatHappened(issue.evidence), seenLine(issue));
      p.what.hidden = !p.what.childNodes.length;
      if (issue.next_step) {
        const code = el("code", { text: issue.next_step });
        put(p.next, el("span", { class: "label", text: gone(issue) ? "Next check (it may be gone)" : "Next check" }), code, copyButton(issue.next_step, code));
        p.next.hidden = false;
      } else {
        put(p.next);
        p.next.hidden = true;
      }
      const held = issue.state !== "open";
      for (const b of p.actions.querySelectorAll("button.hold")) b.disabled = issue.state === "resolved" || (b.dataset.act === "ack" && issue.state === "acknowledged");
      // An agent's hold says which agent (`held_by` is agent:<name>); the operator's needs no name.
      const by = typeof issue.held_by === "string" && issue.held_by.startsWith("agent:") ? ` by ${issue.held_by}` : "";
      p.actions.querySelector(".held-note").textContent = held ? `${issue.state}${by}` : "";
    }
    const open = state.expanded.has(issue.id);
    card._parts.detail.hidden = !open;
    const why = card._parts.actions.querySelector("button.why");
    why.setAttribute("aria-expanded", String(open));
    why.textContent = open ? "Hide why" : "Why?";
    if (open) renderDetail(card._parts.detail, issue.id);
  }

  // What an issue is about, for a person: the evidence it was raised on, frozen when it was judged
  // or found, so it still says what ran once the snapshot has rolled over. A process reads as its
  // command line and who ran it; anything else as its first few facts.
  function whatHappened(evidence) {
    if (!evidence || typeof evidence !== "object" || !Object.keys(evidence).length) return null;
    const proc = processFacts(evidence);
    if (proc) {
      const bits = [proc.pid != null ? `pid ${proc.pid}` : null, proc.user ? `user ${proc.user}` : null,
        proc.ppid != null ? `parent ${proc.ppid}` : null,
        typeof proc.elapsed_s === "number" ? `${fmtDuration(proc.elapsed_s)} old` : null,
        typeof proc.cpu_pct === "number" ? `${fmtNum(proc.cpu_pct, 0)}% CPU` : null,
        typeof proc.threads === "number" ? `${proc.threads} threads` : null,
        proc.pid_ns === "separate" ? "in a container or sandbox" : null].filter(Boolean);
      return el("div", { class: "what" }, el("span", { class: "label", text: "What" }),
        proc.args ? el("code", { class: "what-cmd", text: proc.args }) : null,
        bits.length ? el("span", { class: "muted", text: bits.join(" · ") }) : null);
    }
    if (typeof evidence.truncated === "string" || typeof evidence.omitted_chars === "number") {
      return el("div", { class: "what" }, el("span", { class: "label", text: "What" }),
        el("span", { class: "muted", text: "the evidence was too large to keep in full; open Why? for the answers" }));
    }
    const facts = Object.entries(evidence).slice(0, 4).map(([k, v]) => `${k.split("/").pop()}: ${factText(v)}`);
    return el("div", { class: "what" }, el("span", { class: "label", text: "What" }),
      el("span", { class: "what-facts", text: facts.join(" · ") }));
  }

  function processFacts(evidence) {
    if (typeof evidence.args === "string" && "pid" in evidence) return evidence;
    if (evidence.process && typeof evidence.process === "object") return evidence.process;
    const found = {};
    for (const [k, v] of Object.entries(evidence)) if (k.startsWith("process/")) found[k.slice(8)] = v;
    return Object.keys(found).length ? found : null;
  }

  function factText(v) {
    if (v === null || v === undefined) return "—";
    if (Array.isArray(v)) return v.length === 1 && typeof v[0] !== "object" ? String(v[0]) : `${v.length} item${v.length === 1 ? "" : "s"}`;
    if (typeof v === "object") return `${Object.keys(v).length} field${Object.keys(v).length === 1 ? "" : "s"}`;
    const text = String(v);
    return text.length > 80 ? `${text.slice(0, 79)}…` : text;
  }

  // Whether the conditions behind an open issue were absent at the latest collation.
  function gone(issue) {
    return issue.state === "open" && typeof issue.last_seen === "number" && issue.last_seen > 0 && issue.last_seen < issue.updated_at - 1;
  }

  function seenLine(issue) {
    if (typeof issue.last_seen !== "number" || !issue.last_seen) return null;
    const at = new Date(issue.last_seen * 1000).toLocaleTimeString();
    return gone(issue)
      ? el("div", { class: "seen gone" }, `Not seen since ${at} (`, ageEl(issue.last_seen), "): it stays open until it has been absent three collations in a row.")
      : el("div", { class: "seen" }, `Seen at the latest collation, ${at}`);
  }

  function buildIssueActions(issueId, member) {
    const why = el("button", { type: "button", class: "why", "aria-expanded": "false", text: "Why?" });
    why.addEventListener("click", () => toggleExpanded(issueId));
    const ack = el("button", { type: "button", class: "hold", dataset: { act: "ack" }, text: "Acknowledge" });
    ack.addEventListener("click", () => hold(issueId, "ack", null, ack));
    const snooze = el("span", { class: "group", role: "group", "aria-label": "Snooze" }, el("span", { class: "group-label", text: "Snooze" }));
    for (const [label, seconds] of SNOOZES) {
      const b = el("button", { type: "button", class: "hold", dataset: { act: "snooze" }, text: label, title: `Snooze for ${label}` });
      b.addEventListener("click", () => hold(issueId, "snooze", seconds, b));
      snooze.appendChild(b);
    }
    const analyse = el("button", { type: "button", class: "analyse", text: "Analyse with LLM…" });
    gateAnalyse(analyse);
    analyse.addEventListener("click", () => openAnalysis([`issue:${issueId}`]));
    return el("div", { class: "card-actions" }, why, ack, snooze, analyse,
      el("span", { class: "spacer" }), el("span", { class: "pending held-note" }));
  }

  function toggleExpanded(issueId) {
    if (state.expanded.has(issueId)) state.expanded.delete(issueId);
    else {
      state.expanded.add(issueId);
      loadDetail(issueId);
    }
    rerenderCardsFor(issueId);
  }

  function rerenderCardsFor(issueId) {
    for (const card of document.querySelectorAll("article.card")) {
      if (card._issue && card._issue.id === issueId) updateIssueCard(card, card._issue, card._extra);
    }
  }

  async function hold(issueId, act, seconds, button) {
    const note = button.closest(".card-actions").querySelector(".held-note");
    const buttons = button.closest(".card-actions").querySelectorAll("button.hold");
    for (const b of buttons) b.disabled = true;
    note.textContent = act === "ack" ? "acknowledging…" : "snoozing…";
    try {
      const body = act === "ack"
        ? await api(`/api/issues/${encodeURIComponent(issueId)}/ack`, { post: true })
        : await api(`/api/issues/${encodeURIComponent(issueId)}/snooze`, { post: true, body: { until: Math.floor(now()) + seconds } });
      applyIssue(body.issue);
      reportOk(`${body.issue.title}: ${body.issue.state}.`);
    } catch (e) {
      note.textContent = "failed";
      for (const b of buttons) b.disabled = false;
      reportError(`${act} ${issueId}`, e);
    }
  }

  // An issue as the stream or a write returned it: move it between open and held.
  function applyIssue(issue) {
    const ov = state.overview;
    if (!ov || !issue || typeof issue.id !== "string") return;
    for (const s of SEVERITIES) ov.open[s] = (ov.open[s] || []).filter((i) => i.id !== issue.id);
    state.held = state.held.filter((i) => i.id !== issue.id);
    if (issue.state === "open") (ov.open[issue.severity] = ov.open[issue.severity] || []).push(issue);
    else if (issue.state === "acknowledged" || issue.state === "snoozed") state.held.push(issue);
    for (const s of SEVERITIES) ov.counts[s] = (ov.open[s] || []).length;
    for (const inc of ov.incidents || []) inc.issues = inc.issues.map((i) => (i.id === issue.id ? issue : i));
    scheduleRender();
    if (state.expanded.has(issue.id)) loadDetailSoon(issue.id);
  }

  // --- incidents ------------------------------------------------------------------------------

  function buildIncident() {
    const card = el("article", { class: "card incident" });
    card._parts = { head: el("div", { class: "card-head" }), meta: el("div", { class: "card-meta" }), members: el("div", { class: "members" }), actions: el("div", { class: "card-actions" }) };
    append(card, Object.values(card._parts));
    card._sig = "";
    const analyse = el("button", { type: "button", class: "analyse", text: "Explain this incident with LLM…" });
    analyse.addEventListener("click", () => openAnalysis([`link:${card._incident.link.id}`]));
    gateAnalyse(analyse);
    card._parts.actions.appendChild(analyse);
    wireFold(card);
    return card;
  }

  function updateIncident(card, inc) {
    card._incident = inc;
    const link = inc.link;
    const sev = incidentSeverity(inc);
    card._foldKey = `link:${link.id}`;
    card.className = `card incident card-${sev}`;
    card.classList.toggle("folded", state.folded.has(card._foldKey));
    const sig = JSON.stringify([link, inc.at, inc.missing]);
    if (sig !== card._sig) {
      card._sig = sig;
      const cause = link.likely_cause;
      const causeTitle = memberTitle(inc, cause);
      const box = el("input", { type: "checkbox", class: "select-box", title: "Select for a combined analysis", "aria-label": "Select this incident" });
      box.checked = state.selected.has(`link:${link.id}`);
      box.addEventListener("change", () => toggleSelect(`link:${link.id}`, box.checked));
      put(card._parts.head, foldButton(card), box, sevMark(sev), el("span", { class: "kind", text: "INCIDENT" }),
        el("span", { class: "title", text: causeTitle ? `Likely cause: ${causeTitle}` : `${link.members.length} related items (no likely cause judged)` }),
        ageEl(inc.at));
      const stable = link.stable === false
        ? el("span", { class: "badge flag", text: "UNSTABLE", title: "The judgement changed when the options were reversed." })
        : link.stable === true ? el("span", { text: "stable on re-ask" }) : el("span", { text: "not re-checked" });
      put(card._parts.meta, 
        el("span", { class: "badge judged", text: `LINK JUDGED · ${judgeName().toUpperCase()}`, title: "A link groups members; it never changes their state or severity." }),
        el("span", { class: "mono", title: "Why code proposed this group", text: `basis ${link.basis}` }),
        el("span", { title: `${judgeName()}'s probability that the members are one problem`, text: `same problem p=${fmtNum(link.related, 2)}` }),
        el("span", { text: `causal confidence ${fmtNum(link.confidence, 2)}` }), stable,
        el("span", { text: `${link.members.length} members` }));
    }
    // Members in link order, likely cause first: only those still needing attention.
    const byIssue = new Map(inc.issues.filter(memberShown).map((i) => [`issue:${i.id}`, i]));
    const byFinding = new Map(inc.findings.filter(findingCurrent).map((f) => [`finding:${f.rule}@${f.entity}`, f]));
    const ordered = [...link.members].filter((m) => byIssue.has(m) || byFinding.has(m))
      .sort((a, b) => (b === link.likely_cause) - (a === link.likely_cause));
    const hiddenMembers = link.members.length - ordered.length;
    const kindOf = (m) => (byIssue.has(m) ? "i|" : byFinding.has(m) ? "f|" : "x|");
    reconcile(card._parts.members, ordered, (m) => kindOf(m) + m, (m) => {
      if (byIssue.has(m)) return buildIssueCard(byIssue.get(m), true);
      if (byFinding.has(m)) return el("div", { class: "member-finding" });
      return el("div", { class: "member-missing" });
    }, (node, m) => {
      const isCause = m === link.likely_cause;
      if (byIssue.has(m)) {
        if (!node._parts) return;
        node._extra = { cause: isCause };
        updateIssueCard(node, byIssue.get(m), node._extra);
      } else if (byFinding.has(m)) {
        const f = byFinding.get(m);
        node.className = `member-finding${isCause ? " cause" : ""}`;
        put(node, sevMark(f.severity), el("span", { class: "title", text: f.title }),
          isCause ? el("span", { class: "badge cause", text: "LIKELY CAUSE" }) : null,
          el("span", { class: "badge rule", text: "RULE · HARD FACT" }),
          el("span", { class: "mono muted", text: `${f.rule} @ ${f.entity}` }), ageEl(f.at));
      } else {
        node.textContent = `${m} — the store holds nothing for this member (not yet arrived, or pruned).`;
      }
    });
    if (hiddenMembers > 0) {
      card._parts.members.appendChild(el("p", { class: "muted", text: `${hiddenMembers} member(s) resolved, acknowledged or snoozed are not shown.` }));
    }
  }

  function memberTitle(inc, member) {
    if (!member) return "";
    const issue = inc.issues.find((i) => `issue:${i.id}` === member);
    if (issue) return issue.title;
    const f = inc.findings.find((x) => `finding:${x.rule}@${x.entity}` === member);
    return f ? f.title : member;
  }

  // --- held issues ----------------------------------------------------------------------------

  function renderHeld() {
    const held = state.held.slice().sort((a, b) => rank(b.severity) - rank(a.severity) || b.updated_at - a.updated_at);
    $("held-summary").textContent = `Acknowledged and snoozed (${held.length})`;
    reconcile($("held-list"), held, (i) => `held:${i.id}`, (i) => buildIssueCard(i, false), (node, i) => updateIssueCard(node, i));
    if (!held.length) $("held-list").appendChild(el("p", { class: "muted", text: "Nothing is acknowledged or snoozed." }));
    else $("held-list").appendChild(el("p", { class: "muted", text: "A held issue reopens by itself if it escalates, or when its snooze lapses. The API does not report a snooze's end time." }));
  }

  // --- issue detail: why does it think so -----------------------------------------------------

  const detailTimers = new Map();
  function loadDetailSoon(issueId) {
    clearTimeout(detailTimers.get(issueId));
    detailTimers.set(issueId, setTimeout(() => loadDetail(issueId), 800));
  }

  async function loadDetail(issueId) {
    const entry = state.details.get(issueId) || {};
    entry.loading = true;
    state.details.set(issueId, entry);
    rerenderCardsFor(issueId);
    try {
      entry.data = await api(`/api/issues/${encodeURIComponent(issueId)}`);
      entry.error = null;
      entry.fetchedAt = now();
    } catch (e) {
      entry.error = e.message;
      reportError(`issue ${issueId}`, e);
    }
    entry.loading = false;
    entry.version = (entry.version || 0) + 1;
    rerenderCardsFor(issueId);
  }

  function renderDetail(container, issueId) {
    const entry = state.details.get(issueId);
    const version = entry ? `${entry.version || 0}:${entry.loading}` : "none";
    if (container._version === version) return;
    container._version = version;
    if (!entry || (!entry.data && entry.loading)) {
      put(container, el("p", { class: "muted", text: "Loading the evidence…" }));
      return;
    }
    const refresh = el("button", { type: "button", class: "linkish", text: "refresh" });
    refresh.addEventListener("click", () => loadDetail(issueId));
    const head = el("div", { class: "detail-head" },
      entry.fetchedAt ? el("span", {}, "evidence fetched ", ageEl(entry.fetchedAt)) : null,
      entry.loading ? el("span", { text: "refreshing…" }) : null,
      entry.error ? el("span", { class: "an-error", text: `last fetch failed: ${entry.error}` }) : null, refresh);
    if (!entry.data) {
      put(container, head);
      return;
    }
    const d = entry.data;
    const step = d.issue ? d.issue.next_step : "";
    put(container, head, renderSummary(d.issue, d.findings || [], d.attestations || []),
      renderFindings(d.findings || []), renderAttestations(d.attestations || [], step),
      renderObservations(d.observations || []), renderStoredAnalyses(d.analyses || []));
  }

  // What the card above does not already say: why it matters, and how sure the monitor is. (What
  // happened and what to do are on the card itself.)
  function renderSummary(issue, findings, atts) {
    if (!issue) return null;
    const top = atts.filter((a) => a.stable !== false).sort((a, b) => rank(b.severity) - rank(a.severity) || b.confidence - a.confidence)[0];
    const rows = [];
    if (issue.why) rows.push(["Why it matters", issue.why]);
    else if (top) rows.push(["Why it matters", `${judgeName()} was asked: ${top.instructions}`]);
    const sure = [];
    if (findings.length) sure.push(`a rule fired on measured data (${findings.map((f) => f.rule).filter((v, i, a) => a.indexOf(v) === i).join(", ")}): a hard fact`);
    if (top) sure.push(`${judgeName()} answered ${answerWords(top)}, ${top.stable === true ? "the same when asked again" : top.stable === false ? "differently when asked again" : "not re-checked"}`);
    rows.push(["How sure", sure.length ? sure.join("; ") : "nothing behind it is held any more"]);
    const dl = el("dl", { class: "summary" });
    for (const [k, v] of rows) {
      dl.appendChild(el("dt", { text: k }));
      dl.appendChild(el("dd", {}, ...(Array.isArray(v) ? v : [v])));
    }
    return el("section", { class: "detail-summary" }, dl);
  }

  function answerWords(a) {
    const ans = a.answer || {};
    if (ans.type === "noul" && typeof ans.noul === "number") return `${ans.noul >= 0.5 ? "yes" : "no"} (${Math.round(Math.max(ans.noul, 1 - ans.noul) * 100)}% sure)`;
    if (ans.type === "choice") return `“${ans.choice}” (${Math.round((ans.confidence || 0) * 100)}% confidence)`;
    if (ans.type === "score") return `${fmtNum(ans.expected != null ? ans.expected : ans.score, 1)} on its scale`;
    return a.severity;
  }

  function renderFindings(findings) {
    const sec = el("section", {}, el("h3", { text: `Deterministic findings (${findings.length})` }));
    if (!findings.length) {
      sec.appendChild(el("p", { class: "fact-note", text: "No rule has fired for this entity: whatever raised it is a judgement." }));
      return sec;
    }
    sec.appendChild(el("p", { class: "fact-note", text: "Each is a rule over measured data: a hard fact. A model's answer cannot clear it." }));
    for (const f of findings.slice().sort((a, b) => rank(b.severity) - rank(a.severity) || b.at - a.at)) {
      sec.appendChild(el("div", { class: "finding" },
        el("div", { class: "finding-head" }, sevMark(f.severity), el("strong", { text: f.title }),
          el("span", { class: "mono", text: f.rule }), el("span", { class: "when" }, "raised ", ageEl(f.at))),
        evidenceList(f.evidence)));
    }
    return sec;
  }

  function evidenceList(evidence) {
    if (!evidence || typeof evidence !== "object") return null;
    const entries = Object.entries(evidence);
    if (!entries.length) return null;
    const dl = el("dl", { class: "evidence" });
    for (const [k, v] of entries) {
      dl.appendChild(el("dt", { text: k }));
      const when = k.endsWith("_at") && typeof v === "number" && v > 1e9;
      dl.appendChild(el("dd", { text: when ? new Date(v * 1000).toLocaleString() : typeof v === "string" ? v : JSON.stringify(v) }));
    }
    return dl;
  }

  function renderAttestations(atts, issueStep) {
    const sorted = atts.slice().sort((a, b) => rank(b.severity) - rank(a.severity) || b.confidence - a.confidence || (a.question < b.question ? -1 : 1));
    const loud = sorted.filter((a) => rank(a.severity) >= rank("watch") || a.stable === false);
    const quiet = sorted.filter((a) => !loud.includes(a));
    if (!atts.length) {
      return el("section", {}, el("h3", { text: `${judgeName()} attestations (0)` }),
        el("p", { class: "fact-note", text: "No attestations are held for this entity or its reasons." }));
    }
    // The judge's working: what each question was, and how it answered. Behind a fold, since the
    // summary above already says what it concluded.
    const sec = el("details", { class: "judge-working" }, el("summary", {}, el("h3", { text: `How ${judgeName()} answered (${atts.length})` })));
    for (const a of loud) sec.appendChild(renderAttestation(a, issueStep));
    if (quiet.length) {
      const det = el("details", { class: "quiet-group" }, el("summary", { text: `${quiet.length} quiet answer(s) at info` }));
      for (const a of quiet) det.appendChild(renderAttestation(a, issueStep));
      sec.appendChild(det);
    }
    return sec;
  }

  function stabilityBadge(a) {
    if (a.stable === false) return el("span", { class: "badge flag", text: "UNSTABLE", title: `The answer changed when ${judgeName()} was asked again with the options reversed. It ranks lower.` });
    if (a.stable === true) return el("span", { class: "muted", text: "stable on re-ask" });
    return el("span", { class: "muted", text: "not re-checked" });
  }

  function renderAttestation(a, issueStep) {
    const answer = a.answer || {};
    const viz = renderAnswer(answer, a.severity);
    const stale = now() - a.at > ATTESTATION_STALE_S;
    return el("div", { class: "att" },
      el("div", { class: "att-head" }, sevMark(a.severity), el("span", { class: "q", text: a.question }),
        el("span", { class: "ctx", text: `${a.context_kind} · ${a.entity}` }),
        el("span", { text: `confidence ${fmtNum(a.confidence, 2)}` }), stabilityBadge(a), viz.flag,
        stale ? el("span", { class: "badge flag", text: "STALE" }) : null,
        el("span", { class: "ctx" }, ageEl(a.at), ` · ${a.latency_ms} ms`),
        // An answer from a judge since renamed or replaced keeps the name it was given under.
        a.judge && a.judge !== judgeName() ? el("span", { class: "ctx", text: `by ${a.judge}` }) : null),
      el("div", { class: "instructions", text: a.instructions }),
      viz.node,
      a.cause ? el("div", { class: "cause-text", text: a.cause }) : null,
      a.next_step && a.next_step !== issueStep ? checkLine(a.next_step, "Next check") : null);
  }

  // What an answer says, drawn on its own scale. Returns {node, flag}.
  function renderAnswer(answer, severity) {
    const type = answer.type;
    if (type === "noul" && typeof answer.noul === "number") {
      const p = answer.noul;
      const bar = el("div", { class: "bar", role: "img", "aria-label": `probability yes ${p.toFixed(2)}` });
      const fill = el("div", { class: `fill sev-${severity}` });
      fill.style.width = `${Math.max(0, Math.min(1, p)) * 100}%`;
      bar.append(fill, el("div", { class: "mid", title: "0.5" }));
      const contested = p > NOUL_CONTESTED[0] && p < NOUL_CONTESTED[1];
      return {
        node: el("div", { class: "answer" }, el("div", { class: "label", text: `yes/no: p(yes) = ${p.toFixed(2)} → ${p >= 0.5 ? "yes" : "no"}` }), bar,
          el("div", { class: "scale-labels" }, el("span", { text: "0 no" }), el("span", { text: "0.5" }), el("span", { text: "1 yes" }))),
        flag: contested ? el("span", { class: "badge flag", text: "CONTESTED", title: "p is close to 0.5" }) : null,
      };
    }
    if (type === "choice" && answer.probabilities && typeof answer.probabilities === "object") {
      const probs = Object.entries(answer.probabilities).filter(([, v]) => typeof v === "number").sort((x, y) => y[1] - x[1]);
      const margin = probs.length > 1 ? probs[0][1] - probs[1][1] : 1;
      const offArgmax = probs.length && probs[0][0] !== answer.choice;
      const dist = el("div", { class: "dist" });
      for (const [opt, p] of probs) {
        const chosen = opt === answer.choice;
        const bar = el("div", { class: "bar" });
        const fill = el("div", { class: chosen ? `fill sev-${severity}` : "fill sev-info" });
        fill.style.width = `${Math.max(0, Math.min(1, p)) * 100}%`;
        bar.appendChild(fill);
        dist.append(el("span", { class: chosen ? "opt chosen" : "opt", text: chosen ? `▸ ${opt}` : opt }), bar, el("span", { class: "p", text: p.toFixed(2) }));
      }
      return {
        node: el("div", { class: "answer" }, el("div", { class: "label", text: `choice: ${answer.choice} (margin ${margin.toFixed(2)})` }), dist),
        flag: margin < CONTESTED_MARGIN || offArgmax
          ? el("span", { class: "badge flag", text: "CONTESTED", title: `The top two options are ${margin.toFixed(2)} apart` }) : null,
      };
    }
    if (type === "score" && answer.probabilities && typeof answer.probabilities === "object") {
      const levels = Object.keys(answer.probabilities).length;
      const top = Math.max(1, levels - 1);
      const value = typeof answer.expected === "number" ? answer.expected : answer.score;
      const bar = el("div", { class: "bar", role: "img", "aria-label": `score ${fmtNum(value, 2)} of ${top}` });
      for (let i = 1; i < top; i++) {
        const tick = el("div", { class: "tick" });
        tick.style.left = `${(i / top) * 100}%`;
        bar.appendChild(tick);
      }
      const marker = el("div", { class: "marker" });
      marker.style.left = `${Math.max(0, Math.min(1, value / top)) * 100}%`;
      bar.appendChild(marker);
      const labels = el("div", { class: "scale-labels" });
      for (let i = 0; i <= top; i++) {
        const p = answer.probabilities[String(i)];
        labels.appendChild(el("span", { text: `${i}${typeof p === "number" ? ` (${p.toFixed(2)})` : ""}` }));
      }
      return {
        node: el("div", { class: "answer" }, el("div", { class: "label", text: `score: ${fmtNum(value, 2)} on 0–${top}` }), bar, labels),
        flag: null,
      };
    }
    return { node: el("pre", { class: "raw", text: JSON.stringify(answer, null, 2) }), flag: el("span", { class: "badge flag", text: "UNREADABLE ANSWER" }) };
  }

  function renderObservations(obs) {
    const sec = el("section", {}, el("h3", { text: `Latest related observations (${obs.length})` }));
    if (!obs.length) {
      sec.appendChild(el("p", { class: "fact-note", text: "No latest observation mentions this entity." }));
      return sec;
    }
    for (const o of obs) {
      const raw = JSON.stringify(o.data, null, 2);
      sec.appendChild(el("div", { class: "obs" },
        el("div", { class: "obs-head" }, el("strong", { class: "mono", text: o.probe }), el("span", { class: "when" }, ageEl(o.at)),
          o.error ? el("span", { class: "an-error", text: `error: ${o.error}` }) : null,
          o.truncated ? el("span", { class: "badge flag", text: "TRUNCATED" }) : null,
          el("span", { class: "muted", text: `${o.cpu_ms} ms CPU` })),
        el("details", {}, el("summary", { text: `raw data (${raw.length} chars, shown as text)` }), el("pre", { class: "raw", text: raw }))));
    }
    return sec;
  }

  function renderStoredAnalyses(list) {
    const sec = el("section", {}, el("h3", { text: `Analyses of this issue (${list.length})` }));
    for (const a of list) sec.appendChild(renderAnalysisRecord(a));
    if (!list.length) sec.appendChild(el("p", { class: "fact-note", text: "None yet." }));
    return sec;
  }

  // --- analyses -------------------------------------------------------------------------------

  // Model output is untrusted text. It is laid out into elements from plain text, never parsed as
  // HTML: blank-line paragraphs, "- " / "* " bullets, "1. " steps, "#" headings, `code`, **bold**.
  function richText(text) {
    const box = el("div", { class: "an-body" });
    for (const block of String(text).replace(/\r/g, "").split(/\n\s*\n/)) {
      let list = null, para = [];
      const flush = () => { if (para.length) box.appendChild(el("p", {}, inlineText(para.join(" ")))); para = []; };
      for (const line of block.split("\n").map((l) => l.trim()).filter(Boolean)) {
        const bullet = line.match(/^[-*•]\s+(.*)$/), step = line.match(/^\d+[.)]\s+(.*)$/), head = line.match(/^#{1,4}\s+(.*)$/);
        if (bullet || step) {
          flush();
          const tag = bullet ? "ul" : "ol";
          if (!list || list.tagName.toLowerCase() !== tag) { list = el(tag); box.appendChild(list); }
          list.appendChild(el("li", {}, inlineText((bullet || step)[1])));
        } else if (head) {
          flush(); list = null;
          box.appendChild(el("h4", {}, inlineText(head[1])));
        } else {
          list = null; para.push(line);
        }
      }
      flush();
    }
    return box;
  }

  function inlineText(s) {
    const out = [], re = /`([^`]+)`|\*\*([^*]+)\*\*/g;
    let at = 0, m;
    while ((m = re.exec(s))) {
      if (m.index > at) out.push(s.slice(at, m.index));
      out.push(m[1] !== undefined ? el("code", { text: m[1] }) : el("strong", { text: m[2] }));
      at = re.lastIndex;
    }
    if (at < s.length) out.push(s.slice(at));
    return out;
  }

  // An answer stored before the server dropped end markers kept its JSON as text. Recover the
  // analysis; its checks are not shown, since only the server screens checks as read-only.
  function recoveredAnalysis(text) {
    const t = String(text).replace(/<\|(?:im_end|eot_id|endoftext|end)\|>|<\/s>/g, "").trim();
    const from = t.indexOf("{"), to = t.lastIndexOf("}");
    if (from < 0 || to <= from) return null;
    try {
      const parsed = JSON.parse(t.slice(from, to + 1));
      return parsed && typeof parsed.analysis === "string" ? parsed.analysis : null;
    } catch { return null; }
  }

  function renderAnalysisRecord(a) {
    const box = el("div", { class: "an-record" });
    box.appendChild(el("div", { class: "an-head" },
      el("span", { class: "badge judged", text: "LLM · ADVISORY", title: "A model's reading of what you selected: advice, not a measurement." }),
      el("span", { class: "mono", text: `${a.model || "?"}` }), el("span", { class: "muted", text: a.backend || "" }),
      a.completed_at ? el("span", { class: "muted" }, ageEl(a.completed_at)) : null,
      el("span", { class: "muted", text: `${a.input_chars ?? "?"} chars in · ${a.output_chars ?? "?"} out` })));
    if ((a.subjects || []).length) box.appendChild(el("div", { class: "an-subjects" },
      el("span", { class: "label", text: "About" }), ...(a.subjects || []).map((s) => el("span", { class: "chip mono", text: s }))));
    if (a.question) box.appendChild(el("blockquote", { class: "an-question", text: a.question }));
    if (a.error) box.appendChild(el("div", { class: "an-error", text: `No answer: ${a.error}` }));
    let checks = Array.isArray(a.suggested_checks) ? a.suggested_checks : [];
    let text = a.text || "", recovered = false;
    if (!checks.length && text.trim().startsWith("{")) {
      const r = recoveredAnalysis(text);
      if (r !== null) { text = r; recovered = true; }
    }
    if (text) box.appendChild(richText(text));
    if (recovered) box.appendChild(el("div", { class: "an-meta", text: "Recovered from an answer stored before its format was read; its suggested checks are not shown." }));
    if (checks.length) {
      box.appendChild(el("h3", { class: "an-checks-head", text: "Suggested checks" }));
      box.appendChild(el("div", { class: "an-meta", text: "Model output: confirm each is read-only before you run it. NeonWatch never runs them." }));
      const list = el("div", { class: "an-checks" });
      for (const c of checks) list.appendChild(checkLine(String(c)));
      box.appendChild(list);
    }
    return box;
  }

  function renderAnalysesSection() {
    const list = [...state.analyses.values()].sort((a, b) => b.requested_at - a.requested_at);
    $("analyses").hidden = !list.length;
    const box = $("analyses-list");
    put(box, ...list.map((job) => {
      if (job.status === "running") {
        return el("div", { class: "an-record" }, el("div", { class: "an-meta" }, `running · requested `, ageEl(job.requested_at), ` · ${job.subjects.join(", ")}`));
      }
      if (job.record) return renderAnalysisRecord(job.record);
      return el("div", { class: "an-record" }, el("div", { class: "an-error", text: `${job.subjects.join(", ")}: ${job.error || "failed"}` }));
    }));
    const dlg = $("an-dialog");
    if (dlg._job && state.analyses.has(dlg._job)) renderDialogResult(state.analyses.get(dlg._job));
  }

  function toggleSelect(subject, on) {
    if (on) {
      if (state.selected.size >= MAX_SUBJECTS) {
        reportError("selection", new Error(`at most ${MAX_SUBJECTS} items can be analysed together`));
        scheduleRender(true);
        return;
      }
      state.selected.add(subject);
    } else state.selected.delete(subject);
    updateSelectionBar();
  }

  function updateSelectionBar() {
    const n = state.selected.size;
    const configured = !!(state.health && state.health.analyst && state.health.analyst.configured);
    $("sel-count").textContent = n ? `${n} selected` : (configured ? "Tick issues or incidents to analyse them together." : "Manual analysis is off: no backend LLM is configured.");
    $("sel-analyse").disabled = !n || !configured;
    $("sel-analyse").title = configured ? "" : ANALYST_OFF;
    $("sel-clear").disabled = !n;
  }

  const dialog = {
    subjects: [],
    estimateFor: null, // the exact {subjects, question} the shown estimate is for
  };

  function openAnalysis(subjects) {
    const dlg = $("an-dialog");
    dialog.subjects = subjects.slice(0, MAX_SUBJECTS);
    dialog.estimateFor = null;
    dlg._job = null;
    put($("an-subjects"), ...dialog.subjects.map((s) => el("li", { text: describeSubject(s) })));
    $("an-question").value = "";
    put($("an-estimate-out"));
    put($("an-result"));
    $("an-confirm").disabled = true;
    $("an-confirm").textContent = "Send";
    if (!dlg.open) dlg.showModal();
    runEstimate();
  }

  function describeSubject(s) {
    const m = /^window:(\d+(?:\.\d+)?)-(\d+(?:\.\d+)?)$/.exec(s);
    if (m) return `${s}  (${fmtClock(Number(m[1]))} → ${fmtClock(Number(m[2]))})`;
    const ov = state.overview;
    if (s.startsWith("issue:") && ov) {
      const id = s.slice(6);
      const issue = [...openIssues(), ...state.held, ...(ov.incidents || []).flatMap((i) => i.issues)].find((i) => i.id === id);
      if (issue) return `${s}  (${issue.title})`;
    }
    const listed = findListed(s);
    if (listed) return `${s}  (${listed.length > 120 ? `${listed.slice(0, 119)}…` : listed})`;
    return s;
  }

  async function runEstimate() {
    const request = { subjects: dialog.subjects, question: $("an-question").value };
    $("an-estimate-state").textContent = "estimating…";
    $("an-confirm").disabled = true;
    try {
      const body = await api("/api/analyses/estimate", { post: true, body: request });
      if (request.question !== $("an-question").value) return; // edited meanwhile
      dialog.estimateFor = request;
      const e = body.estimate || {};
      const leaves = !!e.remote;
      put($("an-estimate-out"), el("dl", { class: "estimate" },
        el("dt", { text: "Would send" }), el("dd", { text: `${e.chars} characters (≈ ${e.approx_tokens} tokens)` }),
        el("dt", { text: "Selection" }), el("dd", { text: `${body.items} item(s) plus ${body.context} related record(s) as context` }),
        el("dt", { text: "Backend" }), el("dd", { text: e.backend || "?" }),
        el("dt", { text: "Model" }), el("dd", { text: e.model || "?" }),
        el("dt", { text: "Endpoint host" }), el("dd", { text: e.url_host || "?" }),
        el("dt", { text: "Leaves this machine" }),
        el("dd", { class: `leaves ${leaves ? "yes" : "no"}`, text: leaves ? `YES — to ${e.url_host}` : "no (loopback)" })));
      $("an-estimate-state").textContent = "The request is redacted again before it is sent. Confirm to send exactly this.";
      $("an-confirm").disabled = false;
      $("an-confirm").textContent = leaves ? `Send off this machine to ${e.model}` : `Send to ${e.model}`;
    } catch (err) {
      $("an-estimate-state").textContent = "";
      put($("an-estimate-out"), el("p", { class: "an-error", text: `Estimate failed: ${err.message}` }));
      reportError("estimate", err);
    }
  }

  async function confirmAnalysis() {
    const request = dialog.estimateFor;
    if (!request || request.question !== $("an-question").value) {
      $("an-confirm").disabled = true;
      return;
    }
    $("an-confirm").disabled = true;
    $("an-estimate").disabled = true;
    try {
      const body = await api("/api/analyses", { post: true, body: request });
      const job = { id: body.id, status: "running", subjects: request.subjects, requested_at: now() };
      state.analyses.set(body.id, job);
      $("an-dialog")._job = body.id;
      renderAnalysesSection();
      pollAnalysis(body.id, 0);
    } catch (err) {
      put($("an-result"), el("p", { class: "an-error", text: `Not started: ${err.message}` }));
      reportError("analysis", err);
      $("an-confirm").disabled = false;
    } finally {
      $("an-estimate").disabled = false;
    }
  }

  function renderDialogResult(job) {
    const out = $("an-result");
    if (job.status === "running") {
      put(out, el("p", { class: "muted" }, `Running (${job.id}) — requested `, ageEl(job.requested_at), ". You can close this; the result also appears under “Analyses requested here”."));
    } else if (job.record) {
      put(out, el("h3", { text: "Result" }), renderAnalysisRecord(job.record));
    } else {
      put(out, el("p", { class: "an-error", text: `Failed: ${job.error || "unknown error"}` }));
    }
  }

  function finishAnalysis(body) {
    if (!body || typeof body.id !== "string") return;
    const job = state.analyses.get(body.id);
    if (!job) { // requested elsewhere: only refresh the issues it was about
      for (const s of body.subjects || []) if (s.startsWith("issue:") && state.expanded.has(s.slice(6))) loadDetailSoon(s.slice(6));
      return;
    }
    if (body.status === "running") return;
    if (body.status === "failed" && body.text === undefined) {
      job.status = "failed";
      job.error = body.error;
    } else {
      job.status = body.error ? "failed" : "done";
      job.record = body;
      job.error = body.error;
    }
    state.analyses.set(body.id, job);
    renderAnalysesSection();
    for (const s of job.subjects || []) if (s.startsWith("issue:") && state.expanded.has(s.slice(6))) loadDetailSoon(s.slice(6));
  }

  // The stream delivers the result; polling covers a stream that is down.
  async function pollAnalysis(id, attempt) {
    const job = state.analyses.get(id);
    if (!job || job.status !== "running") return;
    if (attempt > 0) {
      try {
        finishAnalysis(await api(`/api/analyses/${encodeURIComponent(id)}`));
      } catch (e) {
        reportError(`analysis ${id}`, e);
        if (e.status === 404) return;
      }
    }
    if (state.analyses.get(id).status === "running") setTimeout(() => pollAnalysis(id, attempt + 1), Math.min(10000, 3000 + attempt * 1000));
  }

  // --- domain matrix --------------------------------------------------------------------------

  function renderLegend() {
    const cell = (cls, glyph, text) => el("span", {}, el("span", { class: `cell ${cls}`, "aria-hidden": "true", text: glyph }), ` ${text}`);
    put($("matrix-legend"), 
      cell("sev-critical", SEV.critical.glyph, "critical"), cell("sev-warn", SEV.warn.glyph, "warn"),
      cell("sev-watch", SEV.watch.glyph, "watch"), cell("sev-info", SEV.info.glyph, "quiet"),
      cell("unknown", "?", `unknown / older than ${fmtDuration(ATTESTATION_STALE_S)}`),
      el("span", { text: "fainter = lower confidence; dashed = unstable" }));
  }

  function renderMatrix() {
    const ov = state.overview;
    if (!ov) return;
    const names = [...new Set([...DOMAINS, ...Object.keys(ov.domains || {})])];
    // Worst first, unknown ahead of quiet: something that has not reported is not fine.
    const worst = (d) => {
      const body = state.domains.get(d);
      const summary = ov.domains && ov.domains[d];
      let r = -2;
      if (summary) for (const s of SEVERITIES) if (summary.open[s]) r = Math.max(r, rank(s) + 10);
      if (!body || !(body.attestations || []).some((a) => now() - a.at <= ATTESTATION_STALE_S)) r = Math.max(r, 5);
      else for (const a of body.attestations) if (now() - a.at <= ATTESTATION_STALE_S) r = Math.max(r, rank(a.severity));
      return r;
    };
    names.sort((a, b) => worst(b) - worst(a) || (a < b ? -1 : 1));
    const box = $("matrix");
    reconcile(box, names, (d) => `d:${d}`, () => {
      const row = el("details", { class: "mrow" }, el("summary", {}), el("div", { class: "mbody" }));
      return row;
    }, (row, d) => updateMatrixRow(row, d));
  }

  function updateMatrixRow(row, d) {
    const ov = state.overview;
    const summary = ov.domains ? ov.domains[d] : null;
    const body = state.domains.get(d);
    const atts = body ? body.attestations || [] : [];
    const own = atts.filter((a) => a.context_kind === d).sort((a, b) => (a.question < b.question ? -1 : 1));
    const entities = atts.filter((a) => a.context_kind !== d);
    const newest = atts.reduce((m, a) => Math.max(m, a.at), -Infinity);
    const summaryEl = row.firstElementChild;
    const mbody = row.lastElementChild;
    // Rebuild only when what the row shows has changed. Ages keep themselves current through the
    // ticker, so time alone needs no rebuild; staleness flips are in the signature. Rebuilding the
    // summary on every event (up to ~17 times a second, measured) replaced it under the pointer.
    const sig = JSON.stringify([summary && summary.open, newest,
      atts.map((a) => [a.context_kind, a.entity, a.question, a.severity, a.at, a.confidence, a.stable,
        a.cause, now() - a.at > ATTESTATION_STALE_S])]);
    if (row._sig === sig) return;
    row._sig = sig;

    let openCell;
    const openSev = summary ? SEVERITIES.find((s) => summary.open[s] > 0) : null;
    if (openSev) {
      const n = SEVERITIES.reduce((t, s) => t + (summary.open[s] || 0), 0);
      openCell = el("span", { class: "dopen" }, sevMark(openSev), ` ${n} open`);
    } else openCell = el("span", { class: "dopen muted", text: summary ? "0 open" : "no issues held" });

    const cells = el("span", { class: "cells" });
    if (!atts.length) {
      cells.appendChild(el("span", { class: "unknown-strip", text: "UNKNOWN · none held" }));
    } else {
      for (const a of own) cells.appendChild(matrixCell(a));
      if (!own.length) cells.appendChild(el("span", { class: "unknown-strip", text: "UNKNOWN · snapshot not judged" }));
      if (entities.length) {
        const worstEnt = entities.reduce((w, a) => (rank(a.severity) > rank(w.severity) ? a : w), entities[0]);
        const n = new Set(entities.map((a) => a.entity)).size;
        cells.appendChild(el("span", { class: "ent-chip", title: "Entity contexts in this domain (a container, a unit, a disk…)" },
          `+${n} entit${n === 1 ? "y" : "ies"}`, el("span", { class: `sev sev-${worstEnt.severity}`, "aria-hidden": "true", text: SEV[worstEnt.severity] ? SEV[worstEnt.severity].glyph : "?" })));
      }
    }
    const stale = !Number.isFinite(newest) || now() - newest > ATTESTATION_STALE_S;
    put(summaryEl, el("span", { class: "dname", text: d }), openCell, cells,
      Number.isFinite(newest) ? el("span", { class: stale ? "dage stale" : "dage", dataset: { at: String(newest), short: "1" }, title: `Newest attestation ${fmtClock(newest)}`, text: fmtShort(now() - newest) })
        : el("span", { class: "dage stale", text: "never" }));

    // The open body: what is not quiet, as text.
    const notable = atts.filter((a) => rank(a.severity) >= rank("watch") || a.stable === false).sort((a, b) => rank(b.severity) - rank(a.severity));
    const staleCount = atts.filter((a) => now() - a.at > ATTESTATION_STALE_S).length;
    put(mbody, 
      el("div", { class: "muted", text: `${atts.length} attestation(s) held: ${own.length} on the domain snapshot, ${entities.length} on entities; ${staleCount} older than ${fmtDuration(ATTESTATION_STALE_S)}.` }),
      notable.length ? el("ul", {}, notable.map((a) => el("li", {}, sevMark(a.severity), ` ${a.entity} · `, el("span", { class: "mono", text: a.question }),
        a.stable === false ? el("span", { class: "badge flag", text: " UNSTABLE" }) : null, ` — ${a.cause || "(no cause given)"}`))) : el("div", { class: "muted", text: "Nothing above info." }));
  }

  function matrixCell(a) {
    const stale = now() - a.at > ATTESTATION_STALE_S;
    const sev = SEV[a.severity] ? a.severity : "unknown";
    const conf = a.confidence >= 0.75 ? "" : a.confidence >= 0.5 ? " conf-mid" : " conf-low";
    const cls = stale || sev === "unknown" ? "cell unknown" : `cell sev-${sev}${conf}${a.stable === false ? " unstable" : ""}`;
    const summary = answerSummary(a.answer);
    return el("span", {
      class: cls, role: "img",
      "aria-label": `${a.question}: ${stale ? "unknown (stale)" : SEV[sev].label}`,
      title: `${a.question} — ${stale ? `UNKNOWN (answer is ${fmtDuration(now() - a.at)} old; was ${SEV[sev].label})` : SEV[sev].label}\n${summary} · confidence ${fmtNum(a.confidence, 2)}${a.stable === false ? " · UNSTABLE" : ""}\n${a.cause || ""}`,
      text: stale ? "?" : SEV[sev].glyph,
    });
  }

  function answerSummary(answer) {
    if (!answer) return "no answer";
    if (answer.type === "noul") return `p(yes) ${fmtNum(answer.noul, 2)}`;
    if (answer.type === "choice") return `chose ${answer.choice}`;
    if (answer.type === "score") return `score ${fmtNum(typeof answer.expected === "number" ? answer.expected : answer.score, 2)}`;
    return "unreadable answer";
  }

  async function loadDomains() {
    const ov = state.overview;
    if (!ov) return;
    const held = Object.keys(ov.domains || {});
    for (const d of [...state.domains.keys()]) if (!held.includes(d)) state.domains.set(d, null);
    await Promise.all(held.map((d) => loadDomain(d)));
    scheduleRender();
  }

  async function loadDomain(d) {
    try {
      state.domains.set(d, await api(`/api/domains/${encodeURIComponent(d)}`));
    } catch (e) {
      if (e.status === 404) state.domains.set(d, null); // the store holds nothing for it: unknown
      else reportError(`domain ${d}`, e);
    }
  }

  const domainTimers = new Map();
  function loadDomainSoon(d) {
    if (typeof d !== "string" || !d) return;
    clearTimeout(domainTimers.get(d));
    domainTimers.set(d, setTimeout(async () => { await loadDomain(d); scheduleRender(); }, 2000));
  }

  // --- probes ---------------------------------------------------------------------------------

  // Freshness is the server's call: each row carries `tier`, `expected_s` and `stale`. A row with
  // no time has never reported, and a row without `stale` cannot be judged; neither reads as ok.
  function probeRow(p) {
    const every = typeof p.expected_s === "number" && p.expected_s > 0 ? `every ${fmtDuration(p.expected_s)}` : "interval unknown";
    const tier = typeof p.tier === "string" && p.tier ? `${p.tier}, ` : "";
    if (typeof p.at !== "number") return { cls: "never", order: 1, text: `UNKNOWN — never reported (${tier}${every})` };
    if (p.error) return { cls: "bad", order: 0, text: `error: ${p.error}` };
    let row;
    if (p.stale === true && !(typeof p.expected_s === "number")) row = { cls: "stale", order: 1, text: "UNKNOWN — no known cadence for this probe" };
    else if (p.stale === true) row = { cls: "stale", order: 1, text: `STALE — expected ${every}` };
    else if (p.stale === false) row = { cls: "ok", order: 3, text: `ok (${tier}${every})` };
    else row = { cls: "never", order: 2, text: "freshness UNKNOWN — the server gave no expected interval" };
    if (p.truncated) {
      row.text += " · output truncated (partial data)";
      if (row.cls === "ok") { row.cls = "partial"; row.order = 2; }
    }
    return row;
  }

  function renderProbes() {
    if (!state.overview) return;
    const rows = [...state.probes.values()].map((p) => ({ probe: p.probe, at: typeof p.at === "number" ? p.at : null, ...probeRow(p) }));
    rows.sort((a, b) => a.order - b.order || (a.probe < b.probe ? -1 : 1));
    if (!rows.length) {
      put($("probes"), el("tr", { class: "never" }, el("td", { colspan: "3", text: "UNKNOWN — no probe has reported yet." })));
      return;
    }
    put($("probes"), ...rows.map((r) => el("tr", { class: r.cls },
      el("td", { class: "pname", text: r.probe }),
      el("td", { class: "page" }, r.at === null ? "—" : ageEl(r.at)),
      el("td", { class: "pstate", text: r.text }))));
  }

  // --- sparklines -----------------------------------------------------------------------------

  async function loadSeries() {
    const since = Math.floor(now() - SERIES_WINDOW_S);
    await Promise.all(SERIES.map(async (s) => {
      const q = new URLSearchParams({ probe: s.probe, field: s.field, since: String(since), step: String(SERIES_STEP_S) });
      try {
        const body = await api(`/api/series?${q}`);
        state.series.set(`${s.probe}/${s.field}`, { since: body.since, step: body.step, points: body.points || [], until: now() });
      } catch (e) {
        state.series.set(`${s.probe}/${s.field}`, { error: e.message });
        reportError(`series ${s.probe}/${s.field}`, e);
      }
    }));
    renderTrends();
  }

  function renderTrends() {
    const box = $("trends");
    reconcile(box, SERIES, (s) => `${s.probe}/${s.field}`, () => el("div", { class: "spark" }), (node, s) => {
      const data = state.series.get(`${s.probe}/${s.field}`);
      put(node, sparkline(s, data));
    });
  }

  function sparkline(s, data) {
    const W = 180, H = 30, pad = 2;
    const frag = document.createDocumentFragment();
    const points = data && Array.isArray(data.points) ? data.points.filter((p) => typeof p.value === "number" && Number.isFinite(p.value)) : [];
    const last = points.length ? points[points.length - 1] : null;
    frag.appendChild(el("div", { class: "spark-head" }, el("span", { class: "name", text: s.name, title: `${s.probe} · ${s.field}` }),
      el("span", { class: "now", text: last ? `${fmtNum(last.value, s.digits)}${s.unit}` : "—" })));
    const g = svg("svg", { viewBox: `0 0 ${W} ${H}`, preserveAspectRatio: "none", role: "img", "aria-label": `${s.name}, last hour` });
    g.appendChild(svg("line", { x1: 0, y1: H - pad, x2: W, y2: H - pad, class: "spark-base" }));
    if (!data || data.error || !points.length) {
      const t = svg("text", { x: 4, y: H / 2 + 3, class: "spark-empty" });
      t.textContent = data && data.error ? "could not load" : "no data in the last hour";
      g.appendChild(t);
      frag.appendChild(g);
      frag.appendChild(el("div", { class: "range", text: data && data.error ? data.error : "unknown — not zero" }));
      return frag;
    }
    const t0 = data.since, t1 = Math.max(data.until, t0 + 1);
    let lo = Math.min(...points.map((p) => p.value)), hi = Math.max(...points.map((p) => p.value));
    if (hi - lo < 1e-9) { lo -= 1; hi += 1; }
    const x = (t) => ((t - t0) / (t1 - t0)) * W;
    const y = (v) => H - pad - ((v - lo) / (hi - lo)) * (H - 2 * pad);
    // A bucket missing between two present ones is a gap in the line, never a drop to zero.
    let d = "", prev = null;
    for (const p of points) {
      const cmd = prev !== null && p.t - prev.t <= data.step * 1.5 ? "L" : "M";
      d += `${cmd}${x(p.t).toFixed(1)},${y(p.value).toFixed(1)}`;
      prev = p;
    }
    g.appendChild(svg("path", { d, class: "spark-line" }));
    for (let i = 0; i < points.length; i++) {
      const before = points[i - 1], after = points[i + 1];
      const isolated = (!before || points[i].t - before.t > data.step * 1.5) && (!after || after.t - points[i].t > data.step * 1.5);
      if (isolated) g.appendChild(svg("circle", { cx: x(points[i].t).toFixed(1), cy: y(points[i].value).toFixed(1), r: 1.6, class: "spark-dot" }));
    }
    frag.appendChild(g);
    const expected = Math.round(SERIES_WINDOW_S / data.step);
    frag.appendChild(el("div", { class: "range", text: `min ${fmtNum(Math.min(...points.map((p) => p.value)), s.digits)} · max ${fmtNum(Math.max(...points.map((p) => p.value)), s.digits)} · ${points.length}/${expected} buckets` }));
    return frag;
  }

  // --- hardware: the strip on every view, and the Board ---------------------------------------
  // Both read /api/hardware: every temperature with its limit, where that limit came from, and a
  // level from the headroom (cool, warm, hot, near, over at 30, 15, 5 and 0 C). The colour is the
  // level's, so a number is never judged bare. A drive sensor with no limit of its own is held to
  // its Composite's and says so. Refetched whenever a probe it reads reports, and each minute.

  const HW_PROBES = /^(sensors|gpu|load|cpu\.stat|block\.devices|disk\.fill|smart\..+)$/;
  const LEVEL_TEXT = { cool: "cool", warm: "warm", hot: "hot", near: "near its limit", over: "at or over its limit" };
  const hw = { data: null, error: "", selected: "disk:nvme0n1", timer: null };

  async function loadHardware() {
    try {
      hw.data = await api("/api/hardware");
      hw.error = "";
    } catch (e) {
      hw.error = e.message;
      reportError("hardware", e);
    }
    renderHardware();
  }
  function loadHardwareSoon() {
    clearTimeout(hw.timer);
    hw.timer = setTimeout(loadHardware, 1500);
  }

  function hwHistory(series) {
    if (!hw.data || !series) return null;
    const found = (hw.data.history || []).find((h) => h.probe === series.probe && h.field === series.field);
    return found ? { since: hw.data.since, step: hw.data.step, points: found.points || [], until: hw.data.now } : null;
  }

  const fmtC = (v, digits) => (typeof v === "number" && Number.isFinite(v) ? `${v.toFixed(digits === undefined ? 0 : digits)}°` : "—");
  const shortModel = (m) => String(m || "").replace(/^(Samsung SSD|NVIDIA)\s+/i, "").replace(/\s+Generation$/i, "");
  // The reading with the least headroom: the one to show first.
  const hottest = (temps) => (temps || []).filter((t) => typeof t.headroom_c === "number")
    .sort((a, b) => a.headroom_c - b.headroom_c)[0] || (temps || [])[0] || null;
  const levelOf = (r) => (r && r.level) || "none";

  // What each strip tile and board part shows: a name, its hottest reading, and lines of detail.
  function hwParts() {
    const d = hw.data;
    if (!d) return [];
    const parts = [];
    const cpu = d.cpu || {};
    const util = (d.cpu_util || []).length ? d.cpu_util[d.cpu_util.length - 1].value : null;
    parts.push({ key: "cpu", kind: "cpu", name: "CPU", sub: (cpu.temps || []).length ? String(cpu.temps[0].chip).split("-")[0] : "no CPU sensors read", section: cpu, temps: cpu.temps || [],
      lines: [typeof cpu.load1 === "number" ? `load ${fmtNum(cpu.load1, 1)} of ${fmtNum(cpu.cpus, 0)}` : "load —",
        typeof util === "number" ? `${fmtNum(util, 0)}% busy` : null].filter(Boolean),
      series: [...(cpu.temps || []).map((t) => ({ name: t.label, s: t.series, unit: "°C", digits: 1 })),
        { name: "Load (1 min)", s: cpu.load_series, unit: "", digits: 2 }],
      util: { since: d.since, step: d.step, points: d.cpu_util || [], until: d.now } });
    for (const disk of d.disks || []) {
      const mounts = (disk.mounts || []).filter((m) => m === "/" || m === "/home" || m.startsWith("/mnt"));
      parts.push({ key: `disk:${disk.device}`, kind: "disk", name: disk.device, sub: [shortModel(disk.model), mounts.join(" ")].filter(Boolean).join(" · "),
        section: disk, disk, temps: disk.temps || [],
        lines: [disk.smart ? `SMART ${disk.smart.passed === true ? "passed" : disk.smart.passed === false ? "FAILED" : "?"}` : "no SMART yet",
          disk.attach ? `on the ${disk.attach}` : null].filter(Boolean),
        series: (disk.temps || []).map((t) => ({ name: t.label, s: t.series, unit: "°C", digits: 1 })) });
    }
    for (const g of d.gpus || []) {
      parts.push({ key: `gpu:${g.index}`, kind: "gpu", name: `GPU ${g.index}`, sub: `${shortModel(g.name)} · x${dash(g.pcie_width)}`,
        section: g, gpu: g, temps: [g.temperature],
        lines: [`${fmtNum(g.power_w, 0)} of ${fmtNum(g.power_limit_w, 0)} W`, `${fmtNum(g.utilization_pct, 0)}%`,
          `${fmtNum((g.memory_used_mib || 0) / 1024, 0)}/${fmtNum((g.memory_total_mib || 0) / 1024, 0)} GiB`],
        series: [{ name: "Temperature", s: g.temperature.series, unit: "°C", digits: 0 },
          { name: "Power", s: g.series.power_w, unit: " W", digits: 0 },
          { name: "Utilisation", s: g.series.utilization_pct, unit: "%", digits: 0 },
          { name: "VRAM used", s: g.series.memory_used_mib, unit: " MiB", digits: 0 }] });
    }
    return parts;
  }

  // A tile's freshness: no time is no data, never a reading of zero.
  function freshness(section) {
    if (!section || typeof section.at !== "number") return el("span", { class: "hw-stale", text: section && section.error ? `error: ${section.error}` : "no data" });
    if (section.stale) return el("span", { class: "hw-stale" }, "stale, ", ageEl(section.at));
    return null;
  }

  function miniSpark(data) {
    const W = 56, H = 16, pad = 1.5;
    const g = svg("svg", { viewBox: `0 0 ${W} ${H}`, preserveAspectRatio: "none", class: "hw-spark", "aria-hidden": "true" });
    const points = data ? data.points.filter((p) => typeof p.value === "number" && Number.isFinite(p.value)) : [];
    if (points.length < 2) return g;
    const t0 = data.since, t1 = Math.max(data.until, t0 + 1);
    let lo = Math.min(...points.map((p) => p.value)), hi = Math.max(...points.map((p) => p.value));
    if (hi - lo < 1) { lo -= 0.5; hi += 0.5; }
    let d = "", prev = null;
    for (const p of points) {
      const x = ((p.t - t0) / (t1 - t0)) * W, y = H - pad - ((p.value - lo) / (hi - lo)) * (H - 2 * pad);
      d += `${prev !== null && p.t - prev.t <= data.step * 1.5 ? "L" : "M"}${x.toFixed(1)},${y.toFixed(1)}`;
      prev = p;
    }
    g.appendChild(svg("path", { d }));
    return g;
  }

  function renderHardware() {
    renderStrip();
    if (state.view === "board") renderBoard();
  }

  function renderStrip() {
    const box = $("hw");
    if (!hw.data) {
      put(box, el("span", { class: "hw-empty", text: hw.error ? `Hardware: ${hw.error}` : "Hardware: loading…" }));
      return;
    }
    const parts = hwParts();
    const groups = [["CPU", parts.filter((p) => p.kind === "cpu")], ["Disks", parts.filter((p) => p.kind === "disk")],
      ["GPUs", parts.filter((p) => p.kind === "gpu")]];
    if (!box.querySelector(".hw-group")) put(box);
    reconcile(box, groups, (g) => g[0], (g) => el("div", { class: "hw-group", role: "group", "aria-label": g[0] }), (node, [, items]) => {
      reconcile(node, items, (p) => p.key, (p) => el("button", { type: "button", class: "hw-tile",
        on: { click: () => { hw.selected = p.key; showView("board"); } } }), (tile, p) => {
        const top = hottest(p.temps);
        const lvl = levelOf(top);
        tile.className = `hw-tile lvl-${lvl}${p.section && p.section.stale ? " stale" : ""}`;
        tile.title = `${p.name}: ${top ? `${top.label} ${fmtC(top.value_c, 1)}${typeof top.limit_c === "number" ? ` of ${fmtC(top.limit_c, 1)}${top.borrowed ? " (the drive's Composite limit)" : ""}, ${LEVEL_TEXT[lvl] || "no limit"}` : ", no limit known"}` : "no temperature"}. Open on the Board.`;
        put(tile,
          el("span", { class: "hw-head" },
            el("strong", { class: "hw-name", text: p.name }),
            el("span", { class: "hw-temp", text: top ? fmtC(top.value_c) : "—" }),
            miniSpark(top ? hwHistory(top.series) : null)),
          el("span", { class: "hw-sub", text: `${top ? `${top.label} · ` : ""}${p.sub}` }),
          el("span", { class: "hw-lines", text: p.lines.join(" · ") }),
          freshness(p.section));
      });
    });
  }

  // --- the board ------------------------------------------------------------------------------
  // A top-down schematic of the motherboard, drawn in mm from the layout the service sends
  // (`web.board`: a built-in layout or the operator's own TOML file). The positions are the
  // layout's. Which slot holds which part is the service's reading of the PCI topology
  // (`board.place`), marked assumed where software cannot tell two slots apart.
  function boardFrame(layout) {
    const W = layout.width, H = layout.height;
    const root = svg("svg", { viewBox: `-8 -8 ${W + 72} ${H + 19}`, class: "board-svg", role: "img",
      "data-layout": layout.name, "aria-label": `${layout.name}, top down, its parts coloured by temperature` });
    const defs = svg("defs");
    const hatch = svg("pattern", { id: "b-hatch", width: 4, height: 4, patternUnits: "userSpaceOnUse", patternTransform: "rotate(45)" });
    hatch.appendChild(svg("line", { x1: 0, y1: 0, x2: 0, y2: 4, class: "b-hatch-line" }));
    defs.appendChild(hatch);
    for (const lvl of ["cool", "warm", "hot", "near", "over"]) {
      const grad = svg("radialGradient", { id: `b-bloom-${lvl}` });
      grad.appendChild(svg("stop", { offset: "0%", class: `b-bloom-stop lvl-${lvl}`, "stop-opacity": 0.75 }));
      grad.appendChild(svg("stop", { offset: "100%", class: `b-bloom-stop lvl-${lvl}`, "stop-opacity": 0 }));
      defs.appendChild(grad);
    }
    root.appendChild(defs);
    root.appendChild(svg("rect", { x: 0, y: 0, width: W, height: H, rx: 3, class: "b-pcb" }));
    // Traces: a few quiet runs, for the look of a board.
    for (const d of layout.traces) root.appendChild(svg("path", { d, class: "b-trace" }));
    for (const [cx, cy] of layout.holes) root.appendChild(svg("circle", { cx, cy, r: 2.2, class: "b-hole" }));
    const statics = svg("g", { class: "b-static" });
    const items = [...layout.parts.map((p) => ({ ...p, cls: `b-${p.kind}` })),
      ...layout.slots.map((s) => ({ ...s, cls: s.kind === "m2" ? "b-slot b-m2" : "b-slot", label: s.name, slot: true, no_sensor: "" }))];
    for (const s of items) {
      const g = svg("g", { class: `b-part ${s.cls}` });
      g.appendChild(svg("rect", { x: s.x, y: s.y, width: s.w, height: s.h, rx: 1 }));
      if (s.no_sensor) g.appendChild(svg("rect", { x: s.x, y: s.y, width: s.w, height: s.h, rx: 1, class: "b-nosensor" }));
      if (s.label) {
        const t = svg("text", { x: s.slot ? s.x + 2 : s.x + s.w / 2, y: s.y + s.h / 2 + 1.4, class: `b-label${s.slot ? " left" : ""}` });
        t.textContent = s.label;
        if (s.label_at) { t.setAttribute("x", s.label_at[0]); t.setAttribute("y", s.label_at[1]); }
        else if (!s.slot && s.h > s.w * 2) t.setAttribute("transform", `rotate(-90 ${s.x + s.w / 2} ${s.y + s.h / 2})`);
        g.appendChild(t);
      }
      const title = svg("title");
      title.textContent = s.no_sensor ? `${s.label || s.kind}: no sensor. ${s.no_sensor}` : s.label || s.kind;
      g.appendChild(title);
      statics.appendChild(g);
    }
    root.appendChild(statics);
    root.appendChild(svg("g", { class: "b-blooms" }));
    root.appendChild(svg("g", { class: "b-live" }));
    return root;
  }

  // Each live part's shape, from its place on the layout.
  function boardShape(layout, kind, slot) {
    if (kind === "cpu") {
      const s = layout.socket;
      return { x: s.x, y: s.y, w: s.w, h: s.h, cx: s.x + s.w / 2, cy: s.y + s.h / 2, r: Math.max(s.w, s.h) };
    }
    const s = layout.slots.find((x) => x.name === slot);
    if (kind === "disk") return { x: s.x, y: s.y, w: s.w, h: s.h, cx: s.x + s.w / 2, cy: s.y + s.h / 2, r: Math.max(s.w, s.h) * 0.375 };
    // A dual-slot card seen from above: it covers the slot below it, and runs off the board.
    return { x: s.x - 4, y: s.y - 3, w: layout.width - s.x + 66, h: 34, cx: s.x + 96, cy: s.y + 14, r: 70 };
  }

  function renderBoard() {
    const holder = $("board-svg");
    const d = hw.data;
    const layout = d && d.board ? d.board.layout : null;
    if (!layout) {
      put(holder, el("p", { class: "muted", text: hw.error ? `No hardware data: ${hw.error}` : "No hardware data yet." }));
      put($("board-caption"), "");
      renderBoardDetail(null, new Map());
      return;
    }
    let root = holder.querySelector("svg.board-svg");
    if (!root || root.getAttribute("data-layout") !== layout.name) { root = boardFrame(layout); put(holder, root); }
    const parts = hwParts();
    const bind = new Map(Object.entries(d.board.placed || {}));
    const blooms = root.querySelector(".b-blooms"), live = root.querySelector(".b-live");
    put(blooms);
    put(live);
    // Cards first, so the drives beneath them stay visible and clickable.
    const order = [...parts].sort((a, b) => (a.kind === "gpu" ? 0 : 1) - (b.kind === "gpu" ? 0 : 1));
    for (const p of order) {
      const b = bind.get(p.key);
      if (!b) continue;
      const shape = boardShape(layout, p.kind, b.slot);
      const top = hottest(p.temps);
      const lvl = p.section && typeof p.section.at === "number" ? levelOf(top) : "none";
      const heat = top && typeof top.value_c === "number" && typeof top.limit_c === "number"
        ? Math.max(0.15, Math.min(1.25, (top.value_c - 30) / Math.max(top.limit_c - 30, 1))) : 0;
      const stale = !!(p.section && p.section.stale);
      // A stale reading keeps its colour but loses its heat: it is what was, not what is.
      if (lvl !== "none" && !stale && (p.kind !== "gpu" || heat > 0.35)) {
        blooms.appendChild(svg("ellipse", { cx: shape.cx, cy: shape.cy, rx: shape.r * (0.6 + heat * 0.6), ry: shape.r * (p.kind === "gpu" ? 0.3 : 0.45 + heat * 0.5),
          fill: `url(#b-bloom-${lvl})`, opacity: Math.min(1, heat).toFixed(2), class: "b-bloom" }));
      }
      const g = svg("g", { class: `b-part b-${p.kind} lvl-${lvl}${hw.selected === p.key ? " selected" : ""}${stale ? " stale" : ""}`,
        tabindex: 0, role: "button", "aria-label": `${p.name}, ${b.slot}: ${top ? fmtC(top.value_c, 1) : "no reading"}` });
      g.appendChild(svg("rect", { x: shape.x, y: shape.y, width: shape.w, height: shape.h, rx: p.kind === "gpu" ? 3 : 1.2, class: "b-body" }));
      if (p.kind === "cpu") {
        // The package's dies, where the layout draws them, each coloured by its own sensor.
        for (const die of layout.socket.dies) {
          const r = p.temps.find((t) => t.label === die.sensor);
          g.appendChild(svg("rect", { x: die.x, y: die.y, width: die.w, height: die.h, rx: 0.8, class: `b-die lvl-${levelOf(r)}` }));
        }
      }
      if (p.kind === "disk") {
        // The controller sits at the connector end of an M.2 drive; NAND fills the rest. The
        // hottest sensor stands for the controller: it usually is.
        g.appendChild(svg("rect", { x: shape.x + 4, y: shape.y + 2.5, width: 12, height: Math.max(shape.h - 5, 1), rx: 0.6, class: `b-die lvl-${levelOf(top)}` }));
        for (let i = 0; i < Math.floor((shape.w - 24) / 17); i++) g.appendChild(svg("rect", { x: shape.x + 24 + i * 17, y: shape.y + 2.5, width: 13, height: Math.max(shape.h - 5, 1), rx: 0.6, class: "b-nand" }));
      }
      // A card's words go where it runs off the board, clear of the drives and the chipset.
      const name = svg("text", { x: p.kind === "gpu" ? layout.width + 4 : p.kind === "cpu" ? shape.x + shape.w / 2 : shape.x + shape.w + 4,
        y: p.kind === "gpu" ? shape.y + 10 : p.kind === "cpu" ? shape.y + shape.h + 7 : shape.cy - 1.5, class: `b-name${p.kind === "cpu" ? "" : " left"}` });
      name.textContent = p.kind === "cpu" ? "CPU" : p.kind === "gpu" ? `${p.name} · ${b.slot}` : `${b.slot} · ${p.name}`;
      g.appendChild(name);
      const value = svg("text", { x: p.kind === "gpu" ? layout.width + 4 : shape.x + shape.w + 4,
        y: p.kind === "gpu" ? shape.y + 22 : p.kind === "cpu" ? shape.cy + 2.6 : shape.cy + 6.5, class: `b-value lvl-${lvl}` });
      value.textContent = top ? fmtC(top.value_c) : "—";
      g.appendChild(value);
      const title = svg("title");
      title.textContent = `${p.name} in ${b.slot}: ${p.temps.map((t) => `${t.label} ${fmtC(t.value_c, 1)}`).join(", ") || "no temperature"}` +
        (b.assumed ? `. Which slot holds this ${p.kind === "gpu" ? "card" : "drive"} cannot be read from software; drawn in PCI order.` : "");
      g.appendChild(title);
      const choose = () => { hw.selected = p.key; renderBoard(); };
      g.addEventListener("click", choose);
      g.addEventListener("keydown", (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); choose(); } });
      live.appendChild(g);
    }
    put($("board-asof"), el("span", {}, "Readings from ", d.cpu && typeof d.cpu.at === "number" ? ageEl(d.cpu.at) : "no time", ", every minute"));
    put($("board-caption"), `${layout.caption || `${layout.name}: positions from the layout file.`} Hatched parts report no temperature.`);
    renderBoardLegend();
    renderBoardDetail(parts.find((p) => p.key === hw.selected) || parts[0], bind);
  }

  function renderBoardLegend() {
    put($("board-legend"),
      el("p", { class: "legend-head", text: "Each part against its own limit" }),
      el("div", { class: "heat-scale" }, ...["cool", "warm", "hot", "near", "over"].map((lvl, i) =>
        el("span", { class: `heat-step lvl-${lvl}` }, el("span", { class: "swatch" }),
          el("span", { text: ["30° or more below", "15–30° below", "5–15° below", "within 5°", "at or over"][i] })))),
      el("p", { class: "fact-note" }, el("span", { class: "swatch hatch" }), " no sensor"));
  }

  function renderBoardDetail(p, bind) {
    const box = $("board-detail");
    if (!p) { put(box, el("p", { class: "muted", text: hw.error ? `No hardware data: ${hw.error}` : "No hardware data yet." })); return; }
    const b = bind.get(p.key) || {};
    const rows = p.temps.map((t) => el("tr", { class: `lvl-${levelOf(t)}` },
      el("th", { scope: "row", text: t.label }),
      el("td", { class: "hw-val", text: fmtC(t.value_c, 1) }),
      el("td", { text: typeof t.limit_c === "number" ? `of ${fmtC(t.limit_c, 1)}` : "no limit known",
        title: t.limit_source ? `Limit: ${t.limit_source}${t.borrowed ? " — this sensor reports none of its own" : ""}` : "" }),
      el("td", { class: "hw-lvl", text: t.level ? (t.headroom_c >= 0 ? `${fmtNum(t.headroom_c, 1)}° to spare` : `${fmtNum(-t.headroom_c, 1)}° over`) : "" })));
    const facts = [];
    if (p.disk) {
      const s = p.disk.smart;
      facts.push(["Model", dash(p.disk.model)], ["PCI", `${dash(p.disk.pci)} on the ${dash(p.disk.attach)}`],
        ["Mounts", (p.disk.mounts || []).join("  ") || "none"],
        ["SMART", s ? `${s.passed === true ? "passed" : s.passed === false ? "FAILED" : "?"}, ${dash(s.temperature_c)} °C, ${dash(s.percentage_used)}% worn, ${dash(s.media_errors)} media errors, ${dash(s.unsafe_shutdowns)} unsafe shutdowns` : "not read yet"]);
    }
    if (p.gpu) {
      const g = p.gpu;
      facts.push(["Power", `${fmtNum(g.power_w, 1)} of ${fmtNum(g.power_limit_w, 0)} W`], ["Utilisation", `${fmtNum(g.utilization_pct, 0)}%`],
        ["VRAM", `${fmtNum(g.memory_used_mib, 0)} of ${fmtNum(g.memory_total_mib, 0)} MiB`],
        ["PCIe", `x${dash(g.pcie_width)} of x${dash(g.pcie_width_max)}`], ["Throttle", (g.throttle || []).join(", ") || "none"]);
    }
    if (p.kind === "cpu") facts.push(["Load", p.lines.join(", ")]);
    const sparks = el("div", { class: "trends" }, ...p.series.filter((x) => x.s).map((x) =>
      el("div", { class: "spark" }, sparkline({ name: x.name, probe: x.s.probe, field: x.s.field, unit: x.unit, digits: x.digits }, hwHistory(x.s)))));
    if (p.util) sparks.appendChild(el("div", { class: "spark" }, sparkline({ name: "CPU busy", probe: "cpu.stat", field: "ticks", unit: "%", digits: 0 }, p.util)));
    put(box,
      el("div", { class: "detail-head" }, el("strong", { text: `${p.name} · ${b.slot || "not placed"}` }), freshness(p.section)),
      el("p", { class: "fact-note", text: p.sub }),
      b.assumed ? el("p", { class: "fact-note", text: "Which of the matching slots holds this cannot be read from software: drawn in PCI order. A slot's pin in the layout file fixes it." }) : null,
      !b.slot && p.kind !== "cpu" ? el("p", { class: "fact-note", text: "The board layout has no free slot of this kind, so it is not drawn." }) : null,
      el("table", { class: "hw-readings" }, el("tbody", {}, ...rows)),
      p.temps.some((t) => t.borrowed) ? el("p", { class: "fact-note", text: "A sensor with no limit of its own is held to the drive's Composite limit: a hot controller reading shown with no limit at all would read as fine." }) : null,
      el("dl", { class: "facts" }, ...facts.flatMap(([k, v]) => [el("dt", { text: k }), el("dd", { text: v })])),
      el("h3", { text: "Last hour" }), sparks);
  }

  // --- scheduled jobs and services ------------------------------------------------------------

  // Plain words for the common cron forms and @words; anything else is shown only as written.
  const CRON_WORDS = { reboot: "at boot", yearly: "yearly", annually: "yearly", monthly: "monthly",
    weekly: "weekly", daily: "daily", midnight: "daily", hourly: "hourly", minutely: "every minute" };
  const DAYS = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];
  function cronWords(schedule) {
    const text = String(schedule || "").trim();
    const word = CRON_WORDS[text.replace(/^@/, "").toLowerCase()];
    if (word) return word;
    const f = text.split(/\s+/);
    if (f.length !== 5 || f[3] !== "*") return "";
    const [m, h, dom, , dow] = f;
    const num = (v) => /^\d{1,2}$/.test(v);
    const mm = m.padStart(2, "0");
    const at = num(m) && num(h) ? `${h.padStart(2, "0")}:${mm}` : null;
    if (dom === "*" && dow === "*") {
      if (m === "*" && h === "*") return "every minute";
      const minutes = /^\*\/(\d+)$/.exec(m);
      if (minutes && h === "*") return `every ${minutes[1]} minutes`;
      if (num(m) && h === "*") return `hourly at :${mm}`;
      const hours = /^\*\/(\d+)$/.exec(h);
      if (num(m) && hours) return `every ${hours[1]} hours at :${mm}`;
      if (at) return `daily at ${at}`;
    }
    if (at && dom === "*" && /^[0-7](,[0-7])*$/.test(dow)) return `${dow.split(",").map((d) => DAYS[d]).join(", ")} at ${at}`;
    if (at && num(dom) && dow === "*") return `monthly on day ${dom} at ${at}`;
    return "";
  }

  const isRoot = (r) => !r.user || r.user === "root" || r.user === "0";
  const dash = (v) => (v === null || v === undefined || v === "" ? "—" : String(v));
  const timeCell = (at, future) => (typeof at === "number" ? (future ? untilEl(at) : ageEl(at)) : "—");
  const flagged = (bad, text) => el("span", { class: bad ? "bad-text" : "", text: dash(text) });
  const resultCell = (r) => (r.result ? flagged(r.result !== "success", r.result) : "—");
  const truncCode = (text) => el("code", { class: "trunc", title: text, text });
  // Older observations lack these job fields: missing is false.
  const UNREAD = "not read (symlink or not a regular file)";
  const IGNORED = "run-parts ignores this name";
  const overflow = (r) => (Number.isInteger(r.overflow) && r.overflow > 0 ? `${r.overflow} more entries not shown (crontab over the per-file cap)` : "");
  const jobMarks = (r) => [overflow(r) ? el("span", { class: "badge flag", text: overflow(r) }) : null,
    r.unread === true ? el("span", { class: "badge flag", text: UNREAD }) : null,
    r.skipped_by_run_parts === true ? el("span", { class: "muted", text: IGNORED }) : null].filter(Boolean)
    .flatMap((m, i) => (i ? [" ", m] : [m]));
  const hidesCommand = (r) => r.unread === true || (!r.command && !!overflow(r));
  const commandSort = (r) => (r.unread === true ? `(${UNREAD})` : r.command || (overflow(r) && `(${overflow(r)})`));
  const execText = (r) => (Array.isArray(r.exec) ? r.exec.join(" ; ") : dash(r.exec));

  function judgeCell(r) {
    const atts = r.attestations || [];
    if (!atts.length) return el("span", { class: "muted", text: "not asked", title: `No ${judgeName()} attestation is held: unknown, not judged fine.` });
    return [sevMark(r.worst), ` ${atts.length}`, r.unstable ? " " : null, r.unstable ? el("span", { class: "badge flag", text: "UNSTABLE", title: "An answer changed when the options were reversed." }) : null];
  }
  const judgeRank = (r) => ((r.attestations || []).length ? rank(r.worst) * 2 + (r.unstable ? 1 : 0) : null);
  const textOf = (fields) => fields.map(dash).join("\n").toLowerCase();

  // One entry per list view: where it loads from, its columns, its filter, and what is selected.
  const LISTS = {
    sched: {
      title: "scheduled jobs", url: "/api/scheduled", rowsKey: "jobs", noun: "job",
      key: (r) => r.id, subject: (r) => `job:${r.id}`, describe: (r) => r.command,
      sortBy: 3, dir: 1,
      columns: [
        { label: "Source", sort: (r) => r.source, cell: (r) => dash(r.source) },
        { label: "User", sort: (r) => r.user, cell: (r) => dash(r.user) },
        { label: "Schedule", sort: (r) => r.schedule, cell: (r) => {
          const words = cronWords(r.schedule);
          return [el("code", { text: dash(r.schedule) }), words ? el("div", { class: "muted", text: words }) : null];
        } },
        { label: "Next", sort: (r) => r.next, cell: (r) => timeCell(r.next, true) },
        { label: "Last", sort: (r) => r.last, cell: (r) => timeCell(r.last, false) },
        { label: "Last result", sort: (r) => r.result, cell: resultCell },
        { label: "Command", sort: commandSort, cell: (r) => {
          const marks = jobMarks(r);
          return [hidesCommand(r) ? null : truncCode(dash(r.command)), marks.length && !hidesCommand(r) ? " " : null, ...marks];
        } },
        { label: judgeName, sort: judgeRank, cell: judgeCell },
      ],
      keep: (r) => {
        const source = $("sched-source").value, user = $("sched-user").value;
        const q = $("sched-text").value.trim().toLowerCase();
        return (!source || r.source === source) && (!user || r.user === user)
          && (!$("sched-unread").checked || r.unread === true)
          && (!$("sched-ignored").checked || r.skipped_by_run_parts === true)
          && (!q || textOf([r.id, r.source, r.user, r.schedule, cronWords(r.schedule), r.command, r.file, r.unit, r.result,
            r.unread === true ? UNREAD : "", r.skipped_by_run_parts === true ? IGNORED : "", overflow(r)]).includes(q));
      },
      empty: () => `${judgeName()} has not been asked about this job: unknown, not judged fine.`,
    },
    svc: {
      title: "services", url: "/api/services", rowsKey: "services", noun: "service",
      key: (r) => r.name, subject: (r) => `unit:${r.name}`, describe: (r) => r.description,
      // A row whose service has a cached description reads differently from one still to do.
      rowClass: (r) => (r.described ? "described" : "undescribed"),
      sortBy: 0, dir: 1,
      columns: [
        { label: "Name", sort: (r) => r.name, cell: (r) => [el("span", { class: "mono", text: dash(r.name) }),
          isNewService(r) ? " " : null,
          isNewService(r) ? el("span", { class: "badge flag", title: `First seen ${fmtClock(r.first_seen_at)}`, text: "new" }) : null,
          r.description_outdated ? " " : null,
          r.description_outdated ? el("span", { class: "badge state", title: "Its definition changed after it was described", text: "changed" }) : null,
          (r.issues || []).length ? " " : null,
          (r.issues || []).length ? el("span", { class: "badge flag", text: `${r.issues.length} open issue(s)` }) : null] },
        { label: "Active / sub", sort: (r) => `${r.active}/${r.sub}`, cell: (r) => flagged(r.active === "failed", `${dash(r.active)} / ${dash(r.sub)}`) },
        { label: "Enabled", sort: (r) => r.enabled, cell: (r) => dash(r.enabled) },
        { label: "Restarts", sort: (r) => r.restarts, cell: (r) => flagged(r.restarts > 0, r.restarts) },
        { label: "Last result", sort: (r) => r.result, cell: resultCell },
        { label: "User", sort: (r) => r.user || "root", cell: (r) => (r.user ? r.user : el("span", { title: "No User= is set: a system service runs as root.", text: "root (default)" })) },
        { label: "Exec", sort: execText, cell: (r) => truncCode(execText(r)) },
        { label: judgeName, sort: judgeRank, cell: judgeCell },
      ],
      keep: (r) => {
        const q = $("svc-text").value.trim().toLowerCase();
        return (!$("svc-failed").checked || r.active === "failed")
          && (!$("svc-restarting").checked || r.restarts > 0)
          && (!$("svc-root").checked || isRoot(r))
          && (!$("svc-undescribed").checked || !r.described)
          && (!q || textOf([r.name, r.description, r.user, execText(r), r.file, r.active, r.sub, r.result]).includes(q));
      },
      empty: () => `${judgeName()} is asked only about failing services; none is held for this one.`,
      hover: (row, r) => wireTip(row, r),
    },
  };
  for (const list of Object.values(LISTS)) Object.assign(list, { data: null, error: null, selected: null, stale: true, timer: null });
  // The probes the lists are built from, learned from their responses.
  const jobProbes = new Set();

  // Unknown sorts last in either direction: it is not the smallest or the largest value.
  function compareBy(list) {
    const column = list.columns[list.sortBy];
    return (a, b) => {
      const x = column.sort(a), y = column.sort(b);
      const xn = x === null || x === undefined || x === "", yn = y === null || y === undefined || y === "";
      if (xn || yn) return xn - yn;
      return (typeof x === "number" && typeof y === "number" ? x - y : String(x).localeCompare(String(y))) * list.dir;
    };
  }

  function rowsOf(list) {
    return list.data && Array.isArray(list.data[list.rowsKey]) ? list.data[list.rowsKey] : [];
  }

  function renderList(name) {
    const list = LISTS[name];
    put($(`${name}-head`), el("tr", {}, list.columns.map((c, i) => el("th", {
      scope: "col", "aria-sort": list.sortBy === i ? (list.dir > 0 ? "ascending" : "descending") : "none",
    }, el("button", { type: "button", class: "sort", text: `${typeof c.label === "function" ? c.label() : c.label}${list.sortBy === i ? (list.dir > 0 ? " ▴" : " ▾") : ""}`, on: { click: () => sortList(name, i) } })))));
    const tbody = $(`${name}-rows`);
    const span = String(list.columns.length);
    if (!list.data) {
      put(tbody, el("tr", {}, el("td", { colspan: span, class: list.error ? "an-error" : "muted", text: list.error ? `Could not load the ${list.title}: ${list.error}` : "Loading…" })));
      put($(`${name}-asof`));
      return;
    }
    renderAsOf(name);
    const all = rowsOf(list);
    const shown = all.filter(list.keep).sort(compareBy(list));
    $(`${name}-count`).textContent = `${shown.length} of ${all.length} shown`;
    put(tbody, ...shown.map((r) => {
      const row = el("tr", {
        class: [list.key(r) === list.selected ? "selected" : "", list.rowClass ? list.rowClass(r) : ""].filter(Boolean).join(" "),
        tabindex: "0", dataset: { key: list.key(r) },
        title: list.hover ? undefined : "Show the detail",
        on: { click: () => selectRow(name, list.key(r)), keydown: (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); selectRow(name, list.key(r)); } } },
      }, list.columns.map((c) => el("td", {}, c.cell(r))));
      if (list.hover) list.hover(row, r);
      return row;
    }));
    if (!shown.length) {
      tbody.appendChild(el("tr", {}, el("td", { colspan: span, class: "muted", text: all.length ? "Nothing matches the filters." : `No ${list.title} in the latest observations.` })));
    }
    if (name === "svc") {
      $("svc-tip").hidden = true; // its row may be gone
      renderServiceAlert();
      updateDescribeButton();
      renderServiceCard();
    } else renderListDetail(name);
  }

  function renderAsOf(name) {
    const body = LISTS[name].data;
    const problems = Object.entries(body.probes || {}).filter(([, p]) => p.error || typeof p.at !== "number");
    put($(`${name}-asof`),
      typeof body.as_of === "number" ? el("span", {}, "as of ", ageEl(body.as_of))
        : el("span", { class: "an-error", text: "No usable observation of these probes yet: unknown, not empty." }),
      problems.map(([id, p]) => el("span", { class: "badge flag", title: p.error || "never reported", text: `${id}: ${p.error ? "failed" : "never reported"}` })),
      body.skipped ? el("span", { text: `${body.skipped} malformed line(s) or block(s) skipped` }) : null);
  }

  function sortList(name, index) {
    const list = LISTS[name];
    list.dir = list.sortBy === index ? -list.dir : 1;
    list.sortBy = index;
    renderList(name);
  }

  function selectRow(name, key) {
    LISTS[name].selected = key;
    if (name === "svc" && key !== null) openServiceCard();
    renderList(name);
  }

  const TIME_FIELDS = new Set(["last", "next", "started", "exited"]);
  const NOT_DEFINITION = new Set(["attestations", "worst", "unstable", "issues", "static"]);

  function definitionList(r) {
    const dl = el("dl", { class: "evidence defn" });
    for (const [k, v] of Object.entries(r)) {
      if (NOT_DEFINITION.has(k)) continue;
      let text;
      if (TIME_FIELDS.has(k) && typeof v === "number") text = `${fmtClock(v)} (${v > now() ? `in ${fmtDuration(v - now())}` : fmtAge(v)})`;
      else if (Array.isArray(v)) text = v.map(dash).join("\n");
      else if (v !== null && typeof v === "object") text = JSON.stringify(v, null, 2);
      else text = dash(v);
      dl.append(el("dt", { text: k }), el("dd", { text }));
    }
    return dl;
  }

  function renderListDetail(name) {
    const list = LISTS[name];
    const panel = $(`${name}-detail`);
    panel.hidden = list.selected === null;
    panel.parentElement.classList.toggle("open", !panel.hidden);
    if (panel.hidden) return;
    const close = el("button", { type: "button", class: "linkish", text: "close", on: { click: () => selectRow(name, null) } });
    const r = rowsOf(list).find((x) => list.key(x) === list.selected);
    if (!r) {
      put(panel, el("div", { class: "detail-head" }, el("strong", { class: "mono", text: list.selected }), close),
        el("p", { class: "muted", text: `This ${list.noun} is not in the latest observations (removed, or its probe has not reported).` }));
      return;
    }
    const analyse = el("button", { type: "button", class: "analyse", text: "Analyze with LLM…", on: { click: () => openAnalysis([list.subject(r)]) } });
    gateAnalyse(analyse);
    put(panel,
      el("div", { class: "detail-head" }, el("strong", { class: "mono", text: list.subject(r) }), close),
      el("div", { class: "row" }, analyse),
      jobMarks(r).length ? el("div", { class: "row" }, jobMarks(r)) : null,
      el("h3", { text: "Definition" }), definitionList(r),
      attestationsOf(r, list.empty()));
  }

  function attestationsOf(r, empty) {
    const atts = (r.attestations || []).slice().sort((a, b) => rank(b.severity) - rank(a.severity) || b.at - a.at);
    return [el("h3", { text: `${judgeName()} attestations (${atts.length})` }),
      ...(atts.length ? atts.map((a) => el("div", { class: "att" },
        el("div", { class: "att-head" }, sevMark(a.severity), el("span", { class: "q", text: a.question }),
          el("span", { text: `confidence ${fmtNum(a.confidence, 2)}` }), stabilityBadge(a), el("span", { class: "ctx" }, ageEl(a.at))),
        a.cause ? el("div", { class: "cause-text", text: a.cause }) : null,
        a.next_step ? checkLine(a.next_step, "Next check") : null))
        : [el("p", { class: "fact-note", text: empty })])];
  }

  function fillSchedSelects() {
    const rows = rowsOf(LISTS.sched);
    for (const [id, field] of [["sched-source", "source"], ["sched-user", "user"]]) {
      const select = $(id);
      const current = select.value;
      const values = [...new Set(rows.map((r) => r[field]).filter((v) => typeof v === "string" && v))].sort();
      if (current && !values.includes(current)) values.push(current);
      put(select, el("option", { value: "", text: "all" }), values.map((v) => el("option", { value: v, text: v })));
      select.value = current;
    }
  }

  async function loadList(name) {
    const list = LISTS[name];
    clearTimeout(list.timer);
    list.stale = false;
    try {
      list.data = await api(list.url);
      list.error = null;
      for (const probe of Object.keys(list.data.probes || {})) jobProbes.add(probe);
    } catch (e) {
      list.error = e.message;
      reportError(list.title, e);
    }
    if (name === "sched") fillSchedSelects();
    renderList(name);
  }

  // A list that is not shown is only marked stale, and loads when it is shown.
  function loadListSoon(name) {
    const list = LISTS[name];
    if (state.view !== name) {
      list.stale = true;
      return;
    }
    clearTimeout(list.timer);
    list.timer = setTimeout(() => loadList(name), 2000);
  }

  function showView(view, record = true) {
    if (state.authFailed) return;
    if (record && view !== state.view && NAME_OF[view]) history.pushState(null, "", `#/view/${NAME_OF[view]}`);
    state.view = view;
    for (const b of document.querySelectorAll("button.view-tab")) b.setAttribute("aria-pressed", String(b.dataset.view === view));
    for (const id of VIEWS) $(id).hidden = id !== view;
    if (LISTS[view] && LISTS[view].stale) loadList(view);
    if (view === "board") renderBoard();
  }

  function findListed(subject) {
    for (const list of Object.values(LISTS)) {
      const r = rowsOf(list).find((x) => list.subject(x) === subject);
      if (r) return list.describe(r);
    }
    return "";
  }

  // --- addresses ------------------------------------------------------------------------------
  // `#/view/<name>` opens a view and `#/issues/<id>` one issue, so a link, a notification or the
  // desktop app can point here, and back and forward move between them. The fragment survives
  // the `/?token=` sign-in redirect, since the server never sees it.
  const VIEW_NAMES = { attention: "layout", scheduled: "sched", services: "svc", logs: "logs", board: "board" };
  const NAME_OF = Object.fromEntries(Object.entries(VIEW_NAMES).map(([name, view]) => [view, name]));
  const ISSUE_ID = /^[A-Za-z0-9._:-]{1,128}$/;

  function parseAddress(hash) {
    const m = /^#\/(view|issues)\/([^/?#]+)$/.exec(hash || "");
    if (!m) return null;
    let value;
    try { value = decodeURIComponent(m[2]); } catch { return null; }
    if (m[1] === "view") return VIEW_NAMES[value] ? { view: VIEW_NAMES[value] } : null;
    return ISSUE_ID.test(value) ? { view: "layout", issue: value } : null;
  }

  function followAddress() {
    const to = parseAddress(location.hash);
    if (!to || state.authFailed) return;
    showView(to.view, false);
    if (to.issue) showIssue(to.issue);
  }

  // The issue's card wherever it is (on its own, in an incident, or held), unfolded with what
  // holds it, scrolled to and marked. The address is followed at once, before the issues have
  // loaded, so the wanted issue waits here and every render of the issues tries again; one still
  // not on the page once the open and held issues have both loaded says what became of it.
  function showIssue(id) {
    state.wantIssue = id;
    revealWanted();
  }

  async function revealWanted() {
    const id = state.wantIssue;
    if (!id) return;
    const cards = [...document.querySelectorAll("article.card")].filter((c) => c.dataset.issue === id);
    const card = cards.find((c) => !c.closest("#held")) || cards[0];
    if (!card && !(state.overview && state.heldLoaded)) return;
    state.wantIssue = null;
    if (card) {
      for (let node = card; node; node = node.parentElement) {
        if (node.tagName === "DETAILS") node.open = true;
        if (node._foldKey && state.folded.delete(node._foldKey)) applyFold(node);
      }
      saveFolded();
      for (const old of document.querySelectorAll("article.card.targeted")) old.classList.remove("targeted");
      card.classList.add("targeted");
      card.tabIndex = -1;
      card.scrollIntoView({ block: "center", behavior: "smooth" });
      card.focus({ preventScroll: true });
      setTimeout(() => card.classList.remove("targeted"), 4000);
      return;
    }
    try {
      const found = await api(`/api/issues/${encodeURIComponent(id)}`);
      const issue = found && found.issue;
      reportOk(issue ? `${issue.title}: ${issue.state}, so it is not shown with the open issues.` : `No issue ${id}.`);
    } catch (e) {
      reportOk(e.status === 404 ? `No issue ${id}: it was resolved and pruned, or never existed.` : `Issue ${id}: ${e.message}`);
    }
  }

  // --- explained on request: the flow the Logs and Services views share -----------------------
  // Each flow has a `<prefix>-estimate-state`, `-estimate-out`, `-confirm` and `-result` element.
  // The confirm button sends exactly the keys the server said it would act on, and nothing is
  // sent before it is pressed.

  const flows = { lx: { estimateFor: null }, sd: { estimateFor: null }, one: { estimateFor: null },
    lone: { estimateFor: null } };
  const analystOn = () => !!(state.health && state.health.analyst && state.health.analyst.configured);

  async function estimateFlow(prefix, path, keys, counted) {
    const flow = flows[prefix];
    flow.estimateFor = null;
    put($(`${prefix}-estimate-out`));
    put($(`${prefix}-result`));
    $(`${prefix}-confirm`).disabled = true;
    $(`${prefix}-confirm`).textContent = "Send";
    $(`${prefix}-estimate-state`).textContent = "estimating…";
    try {
      const body = await api(path, { post: true, body: { keys } });
      const e = body.estimate || {};
      const leaves = !!e.remote;
      flow.estimateFor = body.keys;
      put($(`${prefix}-estimate-out`), el("dl", { class: "estimate" },
        el("dt", { text: "Would send" }), el("dd", { text: `${e.chars} characters (≈ ${e.approx_tokens} tokens) in ${e.requests} request(s)` }),
        el("dt", { text: counted[0] }), el("dd", { text: counted[1](e) }),
        el("dt", { text: "Backend" }), el("dd", { text: e.backend || "?" }),
        el("dt", { text: "Model" }), el("dd", { text: e.model || "?" }),
        el("dt", { text: "Endpoint host" }), el("dd", { text: e.url_host || "?" }),
        el("dt", { text: "Leaves this machine" }),
        el("dd", { class: `leaves ${leaves ? "yes" : "no"}`, text: leaves ? `YES — to ${e.url_host}` : "no (loopback)" })));
      $(`${prefix}-estimate-state`).textContent = "It is redacted again before it is sent. Confirm to send exactly this.";
      $(`${prefix}-confirm`).disabled = false;
      $(`${prefix}-confirm`).textContent = leaves ? `Send off this machine to ${e.model}` : `Send to ${e.model}`;
    } catch (err) {
      $(`${prefix}-estimate-state`).textContent = "";
      put($(`${prefix}-estimate-out`), el("p", { class: "an-error", text: `Estimate failed: ${err.message}` }));
      reportError("estimate", err);
    }
  }

  // Starts the job for what was estimated; `started(body)` is told its id.
  async function confirmFlow(prefix, path, what, started) {
    const keys = flows[prefix].estimateFor;
    if (!keys) return;
    $(`${prefix}-confirm`).disabled = true;
    try {
      started(await api(path, { post: true, body: { keys } }));
    } catch (err) {
      put($(`${prefix}-result`), el("p", { class: "an-error", text: `Not started: ${err.message}` }));
      reportError(what, err);
      $(`${prefix}-confirm`).disabled = false;
    }
  }

  // Polls `<path>/<id>` until the job leaves running; `done(job)` gets it, or null when it is gone.
  async function pollFlow(path, id, attempt, what, done, onProgress) {
    let job = null;
    try {
      job = await api(`${path}/${encodeURIComponent(id)}`);
    } catch (e) {
      reportError(`${what} ${id}`, e);
      if (e.status === 404) { done(null); return; }
    }
    if (!job || job.status === "running") {
      if (job && onProgress) onProgress(job);
      setTimeout(() => pollFlow(path, id, attempt + 1, what, done, onProgress), Math.min(4000, 2000 + attempt * 250));
      return;
    }
    if (job.status !== "done") reportError(what, new Error(job.error || "failed"));
    done(job);
  }

  // A batched job's progress: requests done of all, what is saved so far, and the time left at
  // the pace of the requests that finished. Width is set through CSSOM: the CSP forbids inline
  // style attributes.
  function renderProgress(box, job, saved, noun) {
    if (!job) { put(box); box.hidden = true; return; }
    const done = job.requests_done || 0, total = job.requests_total || 0;
    const fill = el("div", { class: "fill" });
    fill.style.width = `${total ? Math.round((100 * done) / total) : 0}%`;
    let left = "timing the first request…";
    if (done > 0 && typeof job.started_at === "number") {
      left = `about ${fmtDuration(((now() - job.started_at) / done) * (total - done))} left`;
    }
    put(box,
      el("div", { class: "track", role: "progressbar", "aria-valuemin": "0", "aria-valuemax": String(total || 1),
        "aria-valuenow": String(done), "aria-label": `${noun}: ${done} of ${total} requests` }, fill),
      el("span", { class: "progress-text", text: `${done} of ${total || "?"} requests · ${saved} ${noun} saved · ${left}` }));
    box.hidden = false;
  }

  // --- service descriptions -------------------------------------------------------------------
  // Written by the backend LLM only when the operator confirms; shown from the server's cache.
  // A brief on hover, the full text in a card beside the facts the probes measured.

  const services = { job: null, from: null, saved: 0 };
  // The configured model's family for a button label: "Qwen2.5-32B-Instruct" -> "Qwen".
  const modelName = () => {
    const m = String((state.health && state.health.analyst && state.health.analyst.model) || "").match(/^[A-Za-z]+/);
    return m ? m[0] : "the backend LLM";
  };
  const llmTag = () => el("span", { class: "llm-tag", text: "LLM", title: "Written by the backend LLM: advice, not a measurement." });
  const undescribed = () => rowsOf(LISTS.svc).filter(LISTS.svc.keep).filter((r) => !r.described && r.key);

  function updateDescribeButton() {
    const button = $("svc-describe");
    const fresh = LISTS.svc.data ? undescribed() : [];
    button.textContent = services.job ? "Describing…" : fresh.length ? `Describe ${fresh.length} service${fresh.length === 1 ? "" : "s"}…` : "Describe services…";
    button.disabled = !analystOn() || !fresh.length || !!services.job;
    button.title = analystOn() ? (fresh.length ? "Estimate first; nothing is sent until you confirm." : "Every service shown is already described.") : ANALYST_OFF;
  }

  // --- services that need a look: new ones, and ones the LLM has not described ---------------
  // New: first seen after the services the monitor started with, in the last week. The alert
  // counts every service, whatever the filters show; the tab's badge carries its count.
  const NEW_FOR_S = 7 * 86400;
  const isNewService = (r) => r.new === true && typeof r.first_seen_at === "number" && now() - r.first_seen_at < NEW_FOR_S;
  const plural = (n, one, many) => `${n} ${n === 1 ? one : many}`;

  function renderServiceAlert() {
    const all = rowsOf(LISTS.svc);
    const fresh = all.filter(isNewService).sort((a, b) => b.first_seen_at - a.first_seen_at);
    const todo = all.filter((r) => !r.described);
    const changed = todo.filter((r) => r.description_outdated).length;
    const box = $("svc-alert");
    box.hidden = !fresh.length && !todo.length;
    put(box,
      fresh.length ? el("p", {}, sevMark("warn"), ` ${plural(fresh.length, "new service", "new services")} in the last 7 days: `,
        fresh.flatMap((r, i) => [i ? ", " : null,
          el("button", { type: "button", class: "linkish mono", text: r.name, title: "Show it", on: { click: () => selectRow("svc", r.name) } }),
          " (first seen ", ageEl(r.first_seen_at), r.described ? ")" : ", not described yet)"])) : null,
      todo.length ? el("p", {}, sevMark("watch"),
        ` ${plural(todo.length, "service has", "services have")} no description from the LLM yet`,
        changed ? ` (${changed} changed since ${changed === 1 ? "it was" : "they were"} described)` : "", ". ",
        el("button", { type: "button", class: "linkish", text: "Show them", on: { click: () => { $("svc-undescribed").checked = true; renderList("svc"); } } }),
        analystOn() ? " · " : null,
        analystOn() ? el("button", { type: "button", class: "linkish", text: "Describe them…", on: { click: openDescribe } }) : null) : null);
    const count = new Set([...fresh, ...todo]).size;
    const badge = $("svc-badge");
    badge.hidden = !count;
    badge.textContent = String(count);
    badge.title = [fresh.length ? plural(fresh.length, "new service", "new services") : "",
      todo.length ? `${todo.length} not described` : ""].filter(Boolean).join(", ");
  }

  // Loaded in the background for the badge, the list still loads afresh when it is opened.
  async function badgeServices() {
    await loadList("svc");
    if (state.view !== "svc") LISTS.svc.stale = true;
  }

  // The hover card: one line from the cache, or a plain "not described yet".
  function wireTip(row, r) {
    const show = () => {
      const tip = $("svc-tip");
      put(tip, r.described
        ? [llmTag(), " ", r.described.brief]
        : el("span", { class: "muted", text: "not described yet" }));
      tip.hidden = false;
      const box = row.getBoundingClientRect();
      tip.style.left = `${Math.max(8, Math.min(box.left + 12, window.innerWidth - tip.offsetWidth - 8))}px`;
      const below = box.bottom + 4;
      tip.style.top = `${below + tip.offsetHeight > window.innerHeight - 8 ? box.top - tip.offsetHeight - 4 : below}px`;
      row.setAttribute("aria-describedby", "svc-tip");
    };
    const hide = () => { $("svc-tip").hidden = true; row.removeAttribute("aria-describedby"); };
    row.addEventListener("mouseenter", show);
    row.addEventListener("focus", show);
    row.addEventListener("mouseleave", hide);
    row.addEventListener("blur", hide);
    row.addEventListener("click", hide);
  }

  async function openDescribe() {
    const keys = undescribed().map((r) => r.key).slice(0, 200);
    if (!keys.length) return;
    if (!$("sd-dialog").open) $("sd-dialog").showModal();
    await estimateFlow("sd", "/api/services/estimate", keys, ["Services", (e) => `${e.services} not yet described`]);
  }

  function startDescribe(from) {
    return (body) => {
      services.job = body.id;
      services.from = from;
      put($(`${from}-result`), el("p", { class: "muted", text: `Describing ${body.keys} service(s) (${body.id}). You can close this; descriptions fill in when it finishes.` }));
      updateDescribeButton();
      services.saved = 0;
      renderProgress($("svc-progress"), { requests_done: 0, requests_total: 0 }, 0, "described");
      pollFlow("/api/services/describe", body.id, 0, "service description", finishDescribe, (job) => {
        renderProgress($("svc-progress"), job, job.described || 0, "described");
        if ((job.described || 0) > services.saved) { services.saved = job.described; loadList("svc"); }
      });
    };
  }

  async function finishDescribe(job) {
    const from = services.from;
    services.job = null;
    renderProgress($("svc-progress"), null);
    if (job && job.status !== "done" && $("one-describe")) $("one-describe").disabled = false;
    if (job && from && $(`${from}-result`)) {
      put($(`${from}-result`), job.status === "done"
        ? el("p", { class: "muted", text: `Described ${job.described} of ${job.keys} service(s) in ${job.requests} request(s).${job.error ? ` Some were not: ${job.error}` : ""}` })
        : el("p", { class: "an-error", text: `Failed: ${job.error || "unknown error"}` }));
    }
    await loadList("svc");
  }

  function openServiceCard() {
    const dlg = $("svc-dialog");
    flows.one.estimateFor = null;
    renderServiceCard(true);
    if (!dlg.open) dlg.showModal();
  }

  function closedServiceCard() {
    const key = LISTS.svc.selected;
    LISTS.svc.selected = null;
    renderList("svc");
    const row = [...$("svc-rows").querySelectorAll("tr[data-key]")].find((tr) => tr.dataset.key === key);
    if (row) row.focus({ preventScroll: true });
  }

  const factRow = (label, value, cls) => [el("dt", { text: label }), el("dd", { class: cls || "" }, value)];

  function measuredFacts(r) {
    const timers = r.timers || [];
    return el("dl", { class: "evidence facts" },
      factRow("Active / sub", flagged(r.active === "failed", `${dash(r.active)} / ${dash(r.sub)}`)),
      factRow("Last result", resultCell(r)),
      factRow("User", r.user ? r.user : "root (no User= set)"),
      factRow("ExecStart", (Array.isArray(r.exec) && r.exec.length ? r.exec : ["—"]).map((c) => el("code", { class: "cmd", text: c }))),
      factRow("Unit file", el("code", { text: dash(r.file) })),
      factRow("Enabled", dash(r.enabled)),
      factRow("Restarts", flagged(r.restarts > 0, r.restarts)),
      factRow("Started by", timers.length ? timers.flatMap((t, i) => [i ? ", " : "", el("span", { class: "mono", text: t })]) : el("span", { class: "muted", text: "no timer" })),
      factRow("Started", typeof r.started === "number" ? [fmtClock(r.started), " (", ageEl(r.started), ")"] : "—"),
      factRow("Description=", dash(r.description)));
  }

  // The card for the selected service, rebuilt from the latest listing. `fresh` drops any
  // estimate in progress (a new card); otherwise the describe area keeps its state.
  function renderServiceCard(fresh) {
    const dlg = $("svc-dialog");
    const list = LISTS.svc;
    if (list.selected === null || (!dlg.open && !fresh)) return;
    const r = rowsOf(list).find((x) => list.key(x) === list.selected);
    $("svc-title").textContent = list.selected;
    if (!r) {
      put($("svc-brief"));
      put($("svc-desc"), el("p", { class: "muted", text: "This service is not in the latest observations (removed, or its probe has not reported)." }));
      put($("svc-facts"));
      put($("svc-more"));
      return;
    }
    const d = r.described;
    put($("svc-brief"), d ? [llmTag(), " ", d.brief] : el("span", { class: "muted", text: "not described yet" }));
    if (d) {
      put($("svc-desc"),
        el("div", { class: "an-head" },
          el("span", { class: "badge judged", text: "LLM · ADVISORY", title: "A model's description from the unit's name and definition: not a measurement." }),
          el("span", { class: "mono", text: d.model || "?" }), d.created_at ? el("span", { class: "muted" }, ageEl(d.created_at)) : null),
        richText(d.full));
    } else if (fresh || !$("one-confirm")) {
      const describe = el("button", { type: "button", id: "one-describe", class: "primary", text: `Describe with ${modelName()}`,
        on: { click: () => {
          $("one-describe").disabled = true;
          estimateFlow("one", "/api/services/estimate", [r.key], ["Services", (e) => `${e.services} (this one)`]);
        } } });
      describe.disabled = !analystOn() || !!services.job;
      describe.title = analystOn() ? (services.job ? "Services are being described; wait for that to finish." : "Estimate first; nothing is sent until you confirm.") : ANALYST_OFF;
      put($("svc-desc"),
        el("p", { class: "muted", text: "Not described yet. Nothing about this service has been sent anywhere." }),
        el("div", { class: "row" }, describe),
        el("div", { class: "row" }, el("span", { id: "one-estimate-state", class: "muted" })),
        el("div", { id: "one-estimate-out" }),
        el("div", { class: "row" }, el("button", { type: "button", id: "one-confirm", class: "primary", disabled: true, text: "Send",
          on: { click: () => confirmFlow("one", "/api/services/describe", "service description", startDescribe("one")) } })),
        el("div", { id: "one-result" }));
    }
    put($("svc-facts"), el("div", { class: "an-head" },
      el("span", { class: "badge rule", text: "MEASURED", title: "Read from systemd by the monitor's probes, not written by a model." }),
      typeof (list.data && list.data.as_of) === "number" ? el("span", { class: "muted" }, "as of ", ageEl(list.data.as_of)) : null),
      measuredFacts(r));
    const analyse = el("button", { type: "button", class: "analyse", text: "Analyze with LLM…", on: { click: () => openAnalysis([list.subject(r)]) } });
    gateAnalyse(analyse);
    const issues = r.issues || [];
    put($("svc-more"),
      el("h3", { text: `Open issues (${issues.length})` }),
      issues.length ? el("ul", {}, issues.map((i) => el("li", {}, sevMark(i.severity), ` ${i.title}`))) : el("p", { class: "fact-note", text: "None open on this unit." }),
      attestationsOf(r, list.empty()),
      el("div", { class: "row" }, analyse));
  }

  // --- the Logs view ---------------------------------------------------------------------------
  // Loaded only when the operator asks. Explanations come from the server's cache; new ones are
  // asked for only through the estimate → confirm dialog. Every journal text is shown as text.

  const PRIORITIES = ["emerg", "alert", "crit", "err", "warning", "notice", "info", "debug"];
  const prioClass = (p) => (p === null || p === undefined ? "unknown" : p <= 3 ? "critical" : p === 4 ? "warn" : p === 5 ? "watch" : p === 6 ? "info" : "debug");
  const logs = { data: null, error: null, loading: false, job: null, selected: null };

  function logsShown() {
    const max = Number($("logs-priority").value);
    const lines = logs.data && Array.isArray(logs.data.lines) ? logs.data.lines : [];
    return lines.filter((l) => max >= 7 || (typeof l.priority === "number" && l.priority <= max));
  }

  // The kinds of line on screen that the cache does not hold, once each.
  const newKeys = (lines) => [...new Set(lines.filter((l) => !l.explanation).map((l) => l.key))];

  function renderLogs() {
    const tbody = $("logs-rows");
    $("logs-load").disabled = logs.loading;
    $("logs-load").textContent = logs.loading ? "Loading…" : logs.data ? "Reload last 200 lines" : "Load last 200 lines";
    if (!logs.data) {
      put(tbody, el("tr", {}, el("td", { colspan: "5", class: logs.error ? "an-error" : "muted",
        text: logs.error ? `Could not load the journal: ${logs.error}` : "Not loaded. Nothing is read until you ask." })));
      updateExplainButton();
      put($("logs-asof"));
      return;
    }
    const d = logs.data;
    put($("logs-asof"), el("span", {}, "read ", ageEl(d.read_at)),
      d.error ? el("span", { class: "an-error", text: `journal: ${d.error}` }) : null,
      d.truncated ? el("span", { class: "badge flag", text: "output cut at the size cap" }) : null,
      d.skipped ? el("span", { text: `${d.skipped} unreadable line(s) skipped` }) : null,
      el("span", { text: `${d.templates} kind(s) of line, ${d.uncached} not explained yet` }));
    const shown = logsShown();
    const all = Array.isArray(d.lines) ? d.lines : [];
    $("logs-count").textContent = `${shown.length} of ${all.length} shown`;
    updateExplainButton();
    put(tbody, ...shown.slice().reverse().map((l) => el("tr", { class: `prio-${prioClass(l.priority)} ${l.explanation ? "explained" : "unexplained"}`,
      tabindex: "0", title: "Open this line", dataset: { line: lineId(l) },
      on: { click: () => openLogCard(l), keydown: (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); openLogCard(l); } } } },
      el("td", { class: "when", text: typeof l.at === "number" ? fmtClock(l.at) : "?" }),
      el("td", {}, el("span", { class: `prio prio-${prioClass(l.priority)}`, text: typeof l.priority === "number" ? PRIORITIES[l.priority] : "unknown" })),
      el("td", { class: "mono unit", title: l.unit || "", text: l.identifier || l.unit || "—" }),
      el("td", { class: "msg", text: l.message }),
      el("td", { class: "expl" }, l.explanation
        ? [el("div", { text: l.explanation.text }), el("div", { class: "an-meta" }, `${l.explanation.model || "?"} · `, ageEl(l.explanation.created_at))]
        : el("span", { class: "muted", text: "not explained" })))));
    if (!shown.length) tbody.appendChild(el("tr", {}, el("td", { colspan: "5", class: "muted", text: all.length ? "No line at this priority." : "The journal returned no lines." })));
    renderLogCard(false);
  }

  function updateExplainButton() {
    const explain = $("logs-explain");
    const fresh = logs.data ? newKeys(logsShown()) : [];
    const configured = !!(state.health && state.health.analyst && state.health.analyst.configured);
    explain.textContent = logs.job ? "Explaining…" : fresh.length ? `Explain ${fresh.length} new…` : "Explain new…";
    explain.disabled = !configured || !fresh.length || !!logs.job;
    explain.title = configured ? (fresh.length ? "Estimate first; nothing is sent until you confirm." : "Every kind of line shown is already explained.") : ANALYST_OFF;
  }

  async function loadLogs() {
    if (logs.loading) return;
    logs.loading = true;
    renderLogs();
    try {
      logs.data = await api("/api/logs");
      logs.error = null;
    } catch (e) {
      logs.error = e.message;
      reportError("logs", e);
    }
    logs.loading = false;
    renderLogs();
  }

  async function openExplain() {
    const keys = newKeys(logsShown()).slice(0, 200);
    if (!keys.length || logs.job) return;
    if (!$("lx-dialog").open) $("lx-dialog").showModal();
    await estimateFlow("lx", "/api/logs/estimate", keys, ["Kinds of line", (e) => `${e.templates} not yet explained`]);
  }

  // `prefix` names the flow: "lx" for the Explain dialog, "lone" for one line's card. Never wire
  // this straight to a listener: the click event would arrive as the prefix and nothing is sent.
  function confirmExplain(prefix) {
    if (logs.job) return;
    const result = (...nodes) => { const box = $(`${prefix}-result`); if (box) put(box, ...nodes); };
    confirmFlow(prefix, "/api/logs/explain", "log explanation", (body) => {
      logs.job = body.id;
      result(el("p", { class: "muted", text: `Explaining ${body.keys} kind(s) of line (${body.id}). You can close this; explanations fill in when it finishes.` }));
      renderLogs();
      let saved = 0;
      renderProgress($("logs-progress"), { requests_done: 0, requests_total: 0 }, 0, "explained");
      pollFlow("/api/logs/explain", body.id, 0, "log explanation", async (job) => {
        logs.job = null;
        renderProgress($("logs-progress"), null);
        if (job) {
          result(job.status === "done"
            ? el("p", { class: "muted", text: `Explained ${job.explained} of ${job.keys} kind(s) of line in ${job.requests} request(s).${job.error ? ` Some were not: ${job.error}` : ""}` })
            : el("p", { class: "an-error", text: `Failed: ${job.error || "unknown error"}` }));
        } else renderLogs();
        await loadLogs();
      }, (job) => {
        renderProgress($("logs-progress"), job, job.explained || 0, "explained");
        if ((job.explained || 0) > saved) { saved = job.explained; loadLogs(); }
      });
    });
  }

  // --- the log line card ----------------------------------------------------------------------
  // A click on a line opens it whole: what it means (cached, or explained on request for its
  // kind alone) beside the line as the journal gave it, and how often its kind appears in what
  // loaded. Every journal text is shown as text.

  const lineId = (l) => `${l.key}|${l.at}|${l.message}`;

  function openLogCard(l) {
    logs.selected = lineId(l);
    flows.lone.estimateFor = null;
    renderLogCard(true);
    if (!$("log-dialog").open) $("log-dialog").showModal();
  }

  function closedLogCard() {
    const id = logs.selected;
    logs.selected = null;
    const row = [...$("logs-rows").querySelectorAll("tr[data-line]")].find((tr) => tr.dataset.line === id);
    if (row) row.focus({ preventScroll: true });
  }

  function renderLogCard(fresh) {
    if (!logs.selected || (!$("log-dialog").open && !fresh)) return;
    const lines = (logs.data && logs.data.lines) || [];
    const l = lines.find((x) => lineId(x) === logs.selected);
    if (!l) {
      put($("log-brief"));
      put($("log-meaning"), el("p", { class: "muted", text: "This line is no longer in the loaded window. Load the logs again to see it." }));
      put($("log-facts"));
      return;
    }
    const kin = lines.filter((x) => x.key === l.key);
    const times = kin.map((x) => x.at).filter((t) => typeof t === "number").sort((a, b) => a - b);
    $("log-title").textContent = l.identifier || l.unit || "journal";
    put($("log-brief"),
      el("span", { class: `prio prio-${prioClass(l.priority)}`, text: typeof l.priority === "number" ? PRIORITIES[l.priority] : "unknown" }), " ",
      typeof l.at === "number" ? el("span", { class: "muted" }, fmtClock(l.at), " (", ageEl(l.at), ")") : el("span", { class: "muted", text: "time unknown" }));
    const x = l.explanation;
    if (x) {
      put($("log-meaning"),
        el("div", { class: "an-head" },
          el("span", { class: "badge judged", text: "LLM · ADVISORY", title: "A model's reading of this kind of line: advice, not a measurement." }),
          el("span", { class: "mono", text: x.model || "?" }), x.created_at ? el("span", { class: "muted" }, ageEl(x.created_at)) : null),
        richText(x.text));
    } else if (fresh || !$("lone-confirm")) {
      const explain = el("button", { type: "button", id: "lone-explain", class: "primary", text: `Explain with ${modelName()}`,
        on: { click: () => {
          $("lone-explain").disabled = true;
          estimateFlow("lone", "/api/logs/estimate", [l.key], ["Kinds of line", (e) => `${e.templates} (this one)`]);
        } } });
      explain.disabled = !analystOn() || !!logs.job;
      explain.title = analystOn() ? (logs.job ? "Lines are being explained; wait for that to finish." : "Estimate first; nothing is sent until you confirm.") : ANALYST_OFF;
      put($("log-meaning"),
        el("p", { class: "muted", text: "Not explained yet. Nothing about this line has been sent anywhere." }),
        el("div", { class: "row" }, explain),
        el("div", { class: "row" }, el("span", { id: "lone-estimate-state", class: "muted" })),
        el("div", { id: "lone-estimate-out" }),
        el("div", { class: "row" }, el("button", { type: "button", id: "lone-confirm", class: "primary", disabled: true, text: "Send",
          on: { click: () => confirmExplain("lone") } })),
        el("div", { id: "lone-result" }));
    }
    put($("log-facts"),
      el("div", { class: "an-head" }, el("span", { class: "badge rule", text: "FROM THE JOURNAL", title: "As journalctl gave it, redacted; not written by a model." })),
      el("dl", { class: "evidence facts" },
        factRow("Message", el("pre", { class: "log-message", text: l.message })),
        factRow("Unit", dash(l.unit)),
        factRow("Identifier", dash(l.identifier)),
        factRow("Same kind", `${kin.length} of the ${lines.length} lines loaded` +
          (times.length > 1 ? `, ${fmtClock(times[0])} to ${fmtClock(times[times.length - 1])}` : "")),
        factRow("Kind key", el("code", { text: l.key || "—", title: "Lines whose numbers, ids and addresses differ share this key, and one explanation." }))));
  }

  // --- loading --------------------------------------------------------------------------------

  let renderQueued = false;
  function scheduleRender() {
    if (renderQueued) return;
    renderQueued = true;
    requestAnimationFrame(() => {
      renderQueued = false;
      renderAll();
    });
  }

  function renderAll() {
    renderVitals();
    renderAttention();
    renderMatrix();
    renderProbes();
    updateSelectionBar();
  }

  async function loadOverview(reason) {
    try {
      const ov = await api("/api/overview");
      state.offset = ov.now - Date.now() / 1000;
      state.overview = ov;
      state.overviewAt = Date.now();
      state.heartbeat = ov.heartbeat;
      state.probes = new Map((ov.probes || []).map((p) => [p.probe, p]));
      reportOk(`Overview ${reason || "loaded"} at ${new Date().toLocaleTimeString()}.`);
    } catch (e) {
      reportError("overview", e);
      return;
    }
    scheduleRender();
    await Promise.all([loadHeld(), loadDomains()]);
    for (const id of state.expanded) loadDetailSoon(id);
  }

  async function loadHeld() {
    try {
      const [acked, snoozed] = await Promise.all([api("/api/issues?state=acknowledged"), api("/api/issues?state=snoozed")]);
      state.held = [...acked.issues, ...snoozed.issues];
    } catch (e) {
      reportError("held issues", e);
    }
    state.heldLoaded = true;
    scheduleRender();
  }

  async function loadHealth() {
    try {
      state.health = await api("/api/health");
    } catch (e) {
      reportError("health", e);
    }
    updateExplainButton();
    updateDescribeButton();
    scheduleRender();
  }

  let overviewTimer = null;
  function loadOverviewSoon(reason) {
    clearTimeout(overviewTimer);
    overviewTimer = setTimeout(() => loadOverview(reason), 1500);
  }

  // --- the live stream ------------------------------------------------------------------------

  let source = null;
  let retryTimer = null;

  function setLive(s) {
    if (state.live !== s) state.liveSince = Date.now();
    state.live = s;
    renderVitals();
  }

  function connect() {
    clearTimeout(retryTimer);
    if (source) source.close();
    setLive("connecting");
    source = new EventSource("/api/stream", { withCredentials: false });
    source.addEventListener("open", () => {
      state.streamOpens += 1;
      setLive("live");
      if (state.streamOpens > 1) {
        loadOverview("refetched after reconnect");
        for (const name of Object.keys(LISTS)) loadListSoon(name);
      }
    });
    source.addEventListener("error", () => {
      if (source.readyState === EventSource.CLOSED) {
        setLive("closed");
        reportError("live stream", new Error("closed by the server; retrying in 10 s"));
        // Find out whether this is a lost session rather than a restart.
        api("/api/session").then(() => {}, (e) => reportError("session", e));
        retryTimer = setTimeout(connect, 10000);
      } else {
        setLive("reconnecting");
      }
    });
    const handlers = {
      issue: (b) => {
        applyIssue(record(b));
        if (typeof b.entity === "string" && b.entity.startsWith("unit:")) loadListSoon("svc");
      },
      finding: (b) => {
        for (const id of state.expanded) {
          const d = state.details.get(id);
          if (d && d.data && d.data.issue.entity === b.entity) loadDetailSoon(id);
        }
        loadOverviewSoon("updated by a finding");
      },
      attestation: (b) => {
        loadDomainSoon(b.domain);
        if (typeof b.entity === "string" && b.entity.startsWith("job:")) loadListSoon("sched");
        if (typeof b.entity === "string" && b.entity.startsWith("unit:")) loadListSoon("svc");
        for (const id of state.expanded) {
          const d = state.details.get(id);
          if (d && d.data && d.data.issue.entity === b.entity) loadDetailSoon(id);
        }
      },
      link: () => loadOverviewSoon("updated by a link"),
      heartbeat: (b) => {
        state.heartbeat = { ...record(b), at: b.at };
        renderVitals();
      },
      observation: (b) => {
        // It just reported, so it is not stale; keep the server's tier and interval.
        if (typeof b.probe === "string") {
          const known = state.probes.get(b.probe) || {};
          state.probes.set(b.probe, { ...known, probe: b.probe, at: b.at, age_s: 0, error: b.error || "", truncated: !!b.truncated,
            stale: typeof known.expected_s === "number" ? false : known.stale });
          if (jobProbes.has(b.probe)) for (const name of Object.keys(LISTS)) loadListSoon(name);
          if (HW_PROBES.test(b.probe)) loadHardwareSoon();
        }
        scheduleRender();
      },
      analysis: (b) => finishAnalysis(record(b)),
      reset: () => {
        loadOverview("refetched on reset");
        for (const name of Object.keys(LISTS)) loadListSoon(name);
      },
    };
    for (const [kind, fn] of Object.entries(handlers)) {
      source.addEventListener(kind, (event) => {
        let body;
        try {
          body = JSON.parse(event.data);
        } catch (e) {
          reportError(`stream ${kind}`, new Error("unreadable event data"));
          return;
        }
        if (!body || typeof body !== "object") return;
        try {
          fn(body);
        } catch (e) {
          reportError(`stream ${kind}`, e);
        }
      });
    }
  }

  // The stream adds "at" (the event's time) and "subject" to each body; the records lack both.
  function record(b) {
    const { at: _at, subject: _subject, ...rest } = b;
    return rest;
  }

  // --- wiring ---------------------------------------------------------------------------------

  async function logOut() {
    $("logout").disabled = true;
    try {
      await api("/logout", { post: true, noBody: true }); // answers with a redirect to /login
      goToLogin();
    } catch (e) {
      $("logout").disabled = false;
      reportError("log out", e);
    }
  }

  function wire() {
    $("status-clear").addEventListener("click", clearErrors);
    $("logout").addEventListener("click", logOut);
    $("sel-clear").addEventListener("click", () => {
      state.selected.clear();
      for (const b of document.querySelectorAll("input.select-box")) b.checked = false;
      updateSelectionBar();
    });
    $("sel-analyse").addEventListener("click", () => openAnalysis([...state.selected]));
    $("win-analyse").addEventListener("click", () => {
      const span = Number($("win-select").value);
      const end = Math.floor(now());
      openAnalysis([`window:${end - span}-${end}`]);
    });
    for (const b of document.querySelectorAll("button.view-tab")) b.addEventListener("click", () => showView(b.dataset.view));
    for (const id of ["sched-source", "sched-user", "sched-unread", "sched-ignored", "sched-text"]) $(id).addEventListener("input", () => renderList("sched"));
    for (const id of ["svc-failed", "svc-restarting", "svc-root", "svc-undescribed", "svc-text"]) $(id).addEventListener("input", () => renderList("svc"));
    $("logs-load").addEventListener("click", loadLogs);
    $("logs-priority").addEventListener("input", renderLogs);
    $("logs-explain").addEventListener("click", openExplain);
    $("lx-confirm").addEventListener("click", () => confirmExplain("lx"));
    $("lx-close").addEventListener("click", () => $("lx-dialog").close());
    $("svc-describe").addEventListener("click", openDescribe);
    $("sd-confirm").addEventListener("click", () => confirmFlow("sd", "/api/services/describe", "service description", startDescribe("sd")));
    $("sd-close").addEventListener("click", () => $("sd-dialog").close());
    $("svc-close").addEventListener("click", () => $("svc-dialog").close());
    $("log-close").addEventListener("click", () => $("log-dialog").close());
    $("log-dialog").addEventListener("close", closedLogCard);
    $("svc-dialog").addEventListener("close", closedServiceCard);
    $("an-estimate").addEventListener("click", runEstimate);
    $("an-confirm").addEventListener("click", confirmAnalysis);
    $("an-close").addEventListener("click", () => $("an-dialog").close());
    $("an-question").addEventListener("input", () => {
      dialog.estimateFor = null;
      $("an-confirm").disabled = true;
      $("an-confirm").textContent = "Send";
      $("an-estimate-state").textContent = "The question changed: estimate again before sending.";
    });
  }

  async function start() {
    wire();
    wirePanels();
    trackTopbar();
    renderLegend();
    renderTrends();
    renderStrip();
    passwordMode().then((yes) => { $("logout").hidden = !yes; });
    followAddress();
    window.addEventListener("popstate", followAddress);
    window.addEventListener("hashchange", followAddress);
    await Promise.all([loadOverview(), loadHealth()]);
    if (state.authFailed) return;
    loadSeries();
    loadHardware();
    badgeServices(); // the Services tab's badge, before the view is ever opened
    connect();
    setInterval(tickAges, 5000);
    setInterval(renderVitals, 5000);
    setInterval(renderProbes, 15000);
    setInterval(() => loadOverview("refreshed"), 60000);
    setInterval(loadHealth, 30000);
    setInterval(loadSeries, 60000);
    setInterval(loadHardware, 60000);
    setInterval(() => { if (state.view !== "svc") badgeServices(); }, 120000);
  }

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", start);
  else start();
})();
