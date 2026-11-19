// tutut dashboard — read-only view of the audit log, updated live over SSE.
// All data is inserted with textContent / createElement, never innerHTML:
// tool arguments can contain attacker-controlled (prompt-injected) text.
(() => {
  "use strict";

  const $ = (id) => document.getElementById(id);
  const SVG = "http://www.w3.org/2000/svg";
  const DECISIONS = ["allow", "block", "cancelled"];
  const DECISION_LABEL = { allow: "Allowed", block: "Blocked", cancelled: "Cancelled" };
  const PATH_LABEL = { local: "Desktop · local", remote: "Desktop · mcp-remote", web: "claude.ai · gateway" };
  const BY_LABEL = {
    user: "you", rule: "rule", timeout: "timeout", headless: "no display",
    queue_full: "queue full", error: "error", client: "client gave up",
  };
  const WINDOW_MS = { "1h": 3600e3, "24h": 86400e3, "7d": 7 * 86400e3, all: Infinity };

  const state = {
    window: "24h",
    filters: { decision: "", path: "", server: "", q: "" },
    servers: new Set(),
    shown: 0,
    total: 0,
  };

  // ---------------------------------------------------------------- helpers
  function el(tag, props, ...children) {
    const node = document.createElement(tag);
    for (const [key, value] of Object.entries(props || {})) {
      if (key === "class") node.className = value;
      else if (key === "text") node.textContent = value;
      else if (key === "dataset") Object.assign(node.dataset, value);
      else if (value !== undefined && value !== null) node.setAttribute(key, value);
    }
    for (const child of children) {
      if (child === null || child === undefined) continue;
      node.append(child instanceof Node ? child : document.createTextNode(String(child)));
    }
    return node;
  }

  function svg(tag, attrs) {
    const node = document.createElementNS(SVG, tag);
    for (const [key, value] of Object.entries(attrs || {})) node.setAttribute(key, value);
    return node;
  }

  async function api(path) {
    const res = await fetch(path, { credentials: "same-origin", cache: "no-store" });
    if (res.status === 401) {
      document.body.replaceChildren(
        el("main", {}, el("article", { class: "card" },
          el("h2", { text: "Session expired" }),
          el("p", { class: "muted", text: "Open the link printed by `tutut dashboard` again (it contains a fresh token)." }))));
      throw new Error("unauthorized");
    }
    if (!res.ok) throw new Error(`${path}: ${res.status}`);
    return res.json();
  }

  const pad = (n) => String(n).padStart(2, "0");
  const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

  function fmtTime(iso) {
    const d = new Date(iso);
    if (Number.isNaN(d.getTime())) return iso || "";
    const hms = `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
    const today = new Date();
    return d.toDateString() === today.toDateString() ? hms : `${MONTHS[d.getMonth()]} ${d.getDate()} ${hms}`;
  }

  function fmtTick(iso, window) {
    const d = new Date(iso);
    if (window === "all") return `${MONTHS[d.getMonth()]} ${d.getDate()}`;
    if (window === "7d") return `${MONTHS[d.getMonth()]} ${d.getDate()} ${pad(d.getHours())}h`;
    return `${pad(d.getHours())}:${pad(d.getMinutes())}`;
  }

  function fmtMs(ms) {
    if (ms === null || ms === undefined) return "–";
    if (ms < 1000) return `${ms} ms`;
    if (ms < 60000) return `${(ms / 1000).toFixed(1)} s`;
    return `${Math.floor(ms / 60000)}m ${pad(Math.round((ms % 60000) / 1000))}s`;
  }

  function argsPreview(args) {
    const text = JSON.stringify(args ?? {});
    return text === "{}" ? "(no arguments)" : text;
  }

  // ------------------------------------------------------------------ stats
  function renderStats(s) {
    $("k-total").textContent = s.totals.total;
    $("k-allow").textContent = s.totals.allow;
    $("k-block").textContent = s.totals.block;
    $("k-cancelled").textContent = s.totals.cancelled;
    $("k-rate").textContent = s.block_rate === null ? "–" : `${Math.round(s.block_rate * 100)}%`;
    const w = s.user_wait_ms;
    $("k-wait").textContent = w.count ? fmtMs(w.median) : "–";
    $("k-wait-sub").textContent = w.count ? `median · p95 ${fmtMs(w.p95)} · ${w.count} answered` : "no popups answered";

    renderTimeline(s.timeline, s.window);
    renderBars($("tools"), s.top_tools.map((t) => ({
      label: `${t.server} / ${t.tool}`, total: t.total,
      segments: { allow: t.allow, block: t.block, cancelled: t.cancelled },
    })), "No tool calls in this window.");
    renderBars($("paths"), Object.entries(s.by_path)
      .sort((a, b) => b[1] - a[1])
      .map(([k, v]) => ({ label: PATH_LABEL[k] || k, total: v })), "Nothing yet.");
    renderBars($("deciders"), Object.entries(s.decided_by)
      .sort((a, b) => b[1] - a[1])
      .map(([k, v]) => ({ label: BY_LABEL[k] || k, total: v })), "Nothing yet.");

    for (const name of Object.keys(s.servers)) state.servers.add(name);
    syncServerOptions();
    $("updated").textContent = `Updated ${fmtTime(new Date().toISOString())}`;
  }

  function renderBars(container, rows, emptyText) {
    container.replaceChildren();
    if (!rows.length) {
      container.append(el("p", { class: "muted small", text: emptyText }));
      return;
    }
    const max = Math.max(...rows.map((r) => r.total), 1);
    for (const row of rows) {
      const track = el("div", { class: "bar-track", role: "img", "aria-label": `${row.label}: ${row.total}` });
      if (row.segments) {
        for (const d of DECISIONS) {
          if (!row.segments[d]) continue;
          const seg = el("span", { class: d, title: `${DECISION_LABEL[d]}: ${row.segments[d]}` });
          seg.style.width = `${(row.segments[d] / max) * 100}%`;
          track.append(seg);
        }
      } else {
        const seg = el("span", { class: "neutral" });
        seg.style.width = `${(row.total / max) * 100}%`;
        track.append(seg);
      }
      container.append(el("div", { class: "bar-row" },
        el("span", { class: "bar-label", title: row.label, text: row.label }),
        el("span", { class: "bar-count", text: row.total }),
        track));
    }
  }

  function renderTimeline(tl, window) {
    const box = $("timeline");
    box.replaceChildren();
    const buckets = tl.buckets || [];
    if (!buckets.length) {
      box.append(el("p", { class: "empty", text: "No data yet." }));
      return;
    }
    const W = Math.max(box.clientWidth, 280);
    const H = box.clientHeight || 200;
    const m = { l: 30, r: 6, t: 8, b: 22 };
    const iw = W - m.l - m.r;
    const ih = H - m.t - m.b;
    const totals = buckets.map((b) => b.allow + b.block + b.cancelled);
    const max = Math.max(...totals, 1);
    const yMax = max <= 4 ? max : Math.ceil(max / 4) * 4;
    const root = svg("svg", { viewBox: `0 0 ${W} ${H}`, role: "img", "aria-label": "Calls over time" });

    for (const frac of [0, 0.5, 1]) {
      const y = m.t + ih - ih * frac;
      root.append(svg("line", { x1: m.l, x2: W - m.r, y1: y, y2: y, class: "grid" }));
      const label = svg("text", { x: m.l - 6, y: y + 3, "text-anchor": "end", class: "axis" });
      label.textContent = Math.round(yMax * frac);
      root.append(label);
    }

    const slot = iw / buckets.length;
    const bw = Math.max(2, slot * 0.72);
    const tickEvery = Math.ceil(buckets.length / Math.max(2, Math.floor(iw / 70)));
    buckets.forEach((b, i) => {
      const x = m.l + i * slot + (slot - bw) / 2;
      let y = m.t + ih;
      const group = svg("g", {});
      const tip = svg("title", {});
      tip.textContent = `${fmtTick(b.start, window)} — allowed ${b.allow}, blocked ${b.block}, cancelled ${b.cancelled}`;
      group.append(tip);
      for (const d of DECISIONS) {
        if (!b[d]) continue;
        const h = (b[d] / yMax) * ih;
        y -= h;
        group.append(svg("rect", { x, y, width: bw, height: Math.max(h, 1), rx: 1.5, class: `seg-${d}` }));
      }
      // invisible full-height hit area so the tooltip works on empty buckets too
      group.append(svg("rect", { x: m.l + i * slot, y: m.t, width: slot, height: ih, fill: "transparent" }));
      root.append(group);
      if (i % tickEvery === 0) {
        const t = svg("text", { x: m.l + i * slot + slot / 2, y: H - 6, "text-anchor": "middle", class: "axis" });
        t.textContent = fmtTick(b.start, window);
        root.append(t);
      }
    });
    box.append(root);
  }

  // ------------------------------------------------------------------- feed
  function rowFor(e, flash) {
    const decision = DECISIONS.includes(e.decision) ? e.decision : "cancelled";
    const tr = el("tr", { class: `row${flash ? " flash" : ""}`, tabindex: "0", "aria-expanded": "false" },
      el("td", { class: "time", title: e.ts, text: fmtTime(e.ts) }),
      el("td", {}, el("span", { class: `badge ${decision}`, text: DECISION_LABEL[decision] || e.decision })),
      el("td", { class: "tool" }, el("span", { class: "muted", text: `${e.server} / ` }), el("b", { text: e.tool })),
      el("td", { class: "path", text: PATH_LABEL[e.path] || e.path || "" }),
      el("td", { text: BY_LABEL[e.decided_by] || e.decided_by || "" }),
      el("td", { class: "num", text: fmtMs(e.wait_ms) }),
      el("td", { class: "args mono", title: argsPreview(e.arguments), text: argsPreview(e.arguments) }));

    const toggle = () => {
      const next = tr.nextElementSibling;
      if (next && next.classList.contains("detail")) {
        next.remove();
        tr.setAttribute("aria-expanded", "false");
        return;
      }
      const meta = [
        `time:     ${e.ts}`,
        `source:   ${e.source || e.transport}`,
        `server:   ${e.server}`,
        `tool:     ${e.tool}`,
        `decision: ${e.decision} (by ${e.decided_by}${e.wait_ms !== undefined ? `, after ${fmtMs(e.wait_ms)}` : ""})`,
        e.request_id !== undefined ? `id:       ${JSON.stringify(e.request_id)}` : null,
        e.user_agent ? `client:   ${e.user_agent}` : null,
        "",
        "arguments:",
        JSON.stringify(e.arguments ?? {}, null, 2),
      ].filter((line) => line !== null).join("\n");
      tr.after(el("tr", { class: "detail" }, el("td", { colspan: "7" }, el("pre", { text: meta }))));
      tr.setAttribute("aria-expanded", "true");
    };
    tr.addEventListener("click", toggle);
    tr.addEventListener("keydown", (ev) => {
      if (ev.key === "Enter" || ev.key === " ") { ev.preventDefault(); toggle(); }
    });
    return tr;
  }

  function setFeedCount() {
    $("feed-empty").hidden = state.shown > 0;
    $("feed-count").textContent = state.total > state.shown
      ? `Showing the latest ${state.shown} of ${state.total} matching calls.`
      : state.total ? `${state.total} matching call${state.total === 1 ? "" : "s"}.` : "";
  }

  async function loadEvents() {
    const params = new URLSearchParams({ window: state.window, limit: "200", ...state.filters });
    const data = await api(`/api/events?${params}`);
    const body = $("feed");
    body.replaceChildren(...data.events.map((e) => rowFor(e, false)));
    state.shown = data.events.length;
    state.total = data.count;
    for (const e of data.events) state.servers.add(e.server);
    syncServerOptions();
    setFeedCount();
  }

  function matchesFilters(e) {
    const f = state.filters;
    if (f.decision && e.decision !== f.decision) return false;
    if (f.path && e.path !== f.path) return false;
    if (f.server && e.server !== f.server) return false;
    if (f.q) {
      const hay = `${e.server} ${e.tool} ${e.source} ${JSON.stringify(e.arguments ?? {})}`.toLowerCase();
      if (!hay.includes(f.q.toLowerCase())) return false;
    }
    return Date.now() - new Date(e.ts).getTime() <= WINDOW_MS[state.window];
  }

  function syncServerOptions() {
    const select = $("f-server");
    const have = new Set([...select.options].map((o) => o.value));
    for (const name of [...state.servers].sort()) {
      if (!have.has(name)) select.append(el("option", { value: name, text: name }));
    }
  }

  // ----------------------------------------------------------------- status
  function chip(text, kind, title) {
    return el("span", { class: `chip ${kind || ""}`, title: title || text, text });
  }

  function facts(container, pairs) {
    container.replaceChildren();
    for (const [term, value] of pairs) {
      const dd = el("dd", {});
      if (value instanceof Node) dd.append(value); else dd.textContent = value;
      container.append(el("dt", { text: term }), dd);
    }
  }

  function tags(names, kind) {
    const span = el("span", {});
    if (!names.length) { span.textContent = "none"; return span; }
    for (const n of names) span.append(el("span", { class: `tag ${kind || ""}`, text: n }));
    return span;
  }

  function renderStatus(st) {
    const d = st.desktop;
    const chips = [
      chip(st.watcher.running ? "Watcher running" : "Watcher stopped", st.watcher.running ? "ok" : "bad",
        st.watcher.running ? `pid ${st.watcher.pid}` : "Run `tutut install` (or `tutut watch`)"),
      chip(`Desktop: ${d.guarded.length} guarded`, d.unguarded.length ? "warn" : d.guarded.length ? "ok" : "",
        d.unguarded.length ? `Unguarded: ${d.unguarded.join(", ")}` : d.config_path),
      chip(st.gateway.running ? "Web gateway up" : "Web gateway off", st.gateway.running ? "ok" : "",
        st.gateway.running ? st.gateway.public_url : "Start with `tutut web --upstream …`"),
    ];
    const live = $("live-dot").classList.contains("on");
    chips.push(chip(live ? "Live" : "Reconnecting…", live ? "ok" : "warn"));
    $("chips").replaceChildren(...chips);

    facts($("coverage"), [
      ["Desktop servers", tags(d.guarded.filter((n) => !d.remote.includes(n)))],
      ["Via mcp-remote", tags(d.remote)],
      ["Not guarded", tags(d.unguarded, "warn")],
      ["Watcher", st.watcher.running ? `running (pid ${st.watcher.pid})` : "not running"],
      ["Autostart", st.watcher.autostart ? "enabled" : "off"],
    ]);

    const g = st.gateway;
    facts($("gateway"), g.running ? [
      ["Status", g.reachable ? "running · reachable from the internet" : "running · not reachable"],
      ["Connector URL", g.public_url || "–"],
      ["Upstream", `${g.server_name} → ${g.upstream}`],
      ["Allowed callers", g.allowlist ? g.allowlist.join(", ") : "any IP"],
      ["Tunnel", g.tunnel === "cloudflare-quick" ? "Cloudflare quick tunnel (URL changes on restart)" : "external"],
      ["Started", g.started ? fmtTime(g.started) : "–"],
    ] : [
      ["Status", "not running"],
      ["Start", "tutut web --upstream <url> --server-name <name>"],
    ]);

    const p = st.policy;
    facts($("policy"), [
      ["Popup timeout", p.popup_timeout ? `auto-block after ${p.popup_timeout} s` : "waits for you"],
      ["No display", p.block_when_headless ? "block" : "allow"],
      ["Audit log", `${st.audit.records ?? "?"} records`],
    ]);
    $("audit-path").textContent = st.audit.path;
    $("rules").replaceChildren(...p.rules.map((r, i) => el("tr", {},
      el("td", { class: "num", text: i }),
      el("td", {}, el("span", { class: `badge ${r.action === "allow" ? "allow" : r.action === "block" ? "block" : "cancelled"}`, text: r.action })),
      el("td", { class: "mono", text: r.server }),
      el("td", { class: "mono", text: r.tool }),
      el("td", { class: "muted", text: r.description || "" }))));
    $("rules-empty").hidden = p.rules.length > 0;
    $("rules-wrap").hidden = p.rules.length === 0;
  }

  // ------------------------------------------------------------ refreshing
  let statsTimer = null;
  function refreshStatsSoon(delay = 600) {
    clearTimeout(statsTimer);
    statsTimer = setTimeout(() => api(`/api/stats?window=${state.window}`).then(renderStats).catch(() => {}), delay);
  }

  async function refreshAll() {
    const [stats] = await Promise.all([
      api(`/api/stats?window=${state.window}`),
      loadEvents(),
      api("/api/status").then(renderStatus),
    ]);
    renderStats(stats);
  }

  function setLive(on) {
    $("live-dot").classList.toggle("on", on);
    $("live-dot").title = on ? "Live updates connected" : "Reconnecting…";
    api("/api/status").then(renderStatus).catch(() => {});
  }

  function connect() {
    const source = new EventSource("/api/stream");
    source.addEventListener("open", () => setLive(true));
    source.addEventListener("error", () => setLive(false)); // EventSource retries by itself
    source.addEventListener("audit", (ev) => {
      let entry;
      try { entry = JSON.parse(ev.data); } catch { return; }
      state.servers.add(entry.server);
      syncServerOptions();
      if (matchesFilters(entry)) {
        $("feed").prepend(rowFor(entry, true));
        state.shown += 1;
        state.total += 1;
        setFeedCount();
      }
      refreshStatsSoon();
    });
  }

  // ----------------------------------------------------------------- wiring
  for (const button of document.querySelectorAll("#windows button")) {
    button.addEventListener("click", () => {
      state.window = button.dataset.window;
      for (const b of document.querySelectorAll("#windows button")) {
        b.classList.toggle("active", b === button);
        b.setAttribute("aria-selected", String(b === button));
      }
      refreshAll().catch(() => {});
    });
  }

  for (const [id, key] of [["f-decision", "decision"], ["f-path", "path"], ["f-server", "server"]]) {
    $(id).addEventListener("change", () => { state.filters[key] = $(id).value; loadEvents().catch(() => {}); });
  }
  let searchTimer = null;
  $("f-q").addEventListener("input", () => {
    clearTimeout(searchTimer);
    searchTimer = setTimeout(() => { state.filters.q = $("f-q").value.trim(); loadEvents().catch(() => {}); }, 250);
  });

  let resizeTimer = null;
  window.addEventListener("resize", () => { clearTimeout(resizeTimer); resizeTimer = setTimeout(() => refreshStatsSoon(0), 150); });

  refreshAll().catch(() => {});
  connect();
  setInterval(() => api("/api/status").then(renderStatus).catch(() => {}), 10000);
  setInterval(() => refreshStatsSoon(0), 30000); // relative windows move even without new calls
})();
