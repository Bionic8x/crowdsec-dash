/* crowdsec-dash front end — plain JavaScript, no build step.
 *
 * Structure:
 *   - tiny helpers (api, formatting, tooltip)
 *   - charts (stacked bars, world map) drawn with d3
 *   - one render function per page; a hash router picks which one runs
 * Every page re-renders itself every 30 seconds.
 */
"use strict";

// ---------------------------------------------------------------------------
// state & helpers
// ---------------------------------------------------------------------------
const store = {
  get(k, d) { try { return localStorage.getItem(k) ?? d; } catch { return d; } },
  set(k, v) { try { localStorage.setItem(k, v); } catch {} },
};
const state = { range: store.get("range", "24h"), mapLayer: store.get("mapLayer", "threats"), timer: null, status: null };

const $ = (sel, root = document) => root.querySelector(sel);
const view = $("#view");

async function api(path, opts = {}) {
  // X-Dash-Request: the server refuses POST/DELETE without it (another site can't add it).
  const r = await fetch("/api/" + path, { ...opts, headers: { ...opts.headers, "X-Dash-Request": "1" } });
  if (!r.ok) throw new Error(`${r.status} ${await r.text()}`);
  return r.json();
}

const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const nf = new Intl.NumberFormat();
const num = (n) => nf.format(n ?? 0);
const compact = (n) => new Intl.NumberFormat(undefined, { notation: "compact", maximumFractionDigits: 1 }).format(n ?? 0);

function flag(cc) {
  if (!cc || cc.length !== 2) return "";
  return String.fromCodePoint(...[...cc.toUpperCase()].map((c) => 0x1f1e6 + c.charCodeAt(0) - 65));
}
function country(cc) { return cc ? `${flag(cc)} ${esc(cc)}` : '<span class="muted">—</span>'; }

// seconds -> "45s" / "12m" / "3.5h" / "2.0d"
function dur(a) {
  return a < 60 ? `${Math.round(a)}s` : a < 3600 ? `${Math.round(a / 60)}m` : a < 86400 ? `${(a / 3600).toFixed(a < 36000 ? 1 : 0)}h` : `${(a / 86400).toFixed(1)}d`;
}
function ago(iso) {
  if (!iso) return "—";
  const s = (Date.now() - Date.parse(iso)) / 1000;
  return s < 0 ? `in ${dur(-s)}` : `${dur(s)} ago`;
}
const fullTime = (iso) => (iso ? new Date(iso).toLocaleString() : "");
const when = (iso) => `<span title="${esc(fullTime(iso))}">${ago(iso)}</span>`;
const ipLink = (ip) => (ip ? `<a class="mono" href="#/ip/${encodeURIComponent(ip)}">${esc(ip)}</a>` : "—");
const statusCode = (s) => `<span class="status-code sc-${String(s)[0]}">${s}</span>`;
const scenario = (s) => esc((s || "").replace(/^crowdsecurity\//, ""));

function protectionBadge(proxied) {
  if (proxied === true) return '<span class="badge b-cf" title="Orange cloud: visitors connect to Cloudflare, not to you. OPNsense bans cannot block them."><span class="dot"></span>Cloudflare proxied</span>';
  if (proxied === false) return '<span class="badge b-good" title="Grey cloud: visitors connect straight to your WAN IP, so OPNsense bans apply."><span class="dot"></span>DNS only</span>';
  return '<span class="badge" title="Not found in Cloudflare (or no CF_API_TOKEN set)">unknown</span>';
}

// ---------------------------------------------------------------------------
// tooltip
// ---------------------------------------------------------------------------
const tip = $("#tip");
function showTip(html, ev) {
  tip.innerHTML = html;
  tip.style.display = "block";
  const pad = 14, w = tip.offsetWidth, h = tip.offsetHeight;
  let x = ev.clientX + pad, y = ev.clientY + pad;
  if (x + w > innerWidth - 8) x = ev.clientX - w - pad;
  if (y + h > innerHeight - 8) y = ev.clientY - h - pad;
  tip.style.left = x + "px"; tip.style.top = y + "px";
}
const hideTip = () => (tip.style.display = "none");

// ---------------------------------------------------------------------------
// chart: stacked bars over time
// ---------------------------------------------------------------------------
function css(name) { return getComputedStyle(document.documentElement).getPropertyValue(name).trim(); }

/**
 * @param el      container element
 * @param rows    [{t: unixSeconds, k1: n, k2: n ...}]
 * @param series  [{key, label, color: "--s1"}]  (bottom to top)
 * @param bucket  bucket size in seconds
 * @param since   ISO start of the range (so empty periods still show)
 */
function stackedBars(el, rows, series, bucket, since) {
  el.innerHTML = "";
  const W = el.clientWidth || 600, H = el.clientHeight || 190;
  const m = { t: 8, r: 8, b: 22, l: 40 };
  const start = Math.floor(Date.parse(since) / 1000 / bucket) * bucket;
  const end = Math.floor(Date.now() / 1000 / bucket) * bucket;
  const byT = new Map(rows.map((r) => [r.t, r]));
  const data = [];
  for (let t = start; t <= end; t += bucket) {
    const r = byT.get(t) || {};
    const d = { t };
    series.forEach((s) => (d[s.key] = r[s.key] || 0));
    data.push(d);
  }
  const stack = d3.stack().keys(series.map((s) => s.key))(data);
  const x = d3.scaleBand().domain(data.map((d) => d.t)).range([m.l, W - m.r]).paddingInner(0.18);
  const ymax = d3.max(data, (d) => series.reduce((a, s) => a + d[s.key], 0)) || 1;
  const y = d3.scaleLinear().domain([0, ymax]).nice(4).range([H - m.b, m.t]);
  const svg = d3.select(el).append("svg").attr("width", W).attr("height", H);

  svg.append("g").attr("class", "gridline").attr("transform", `translate(${m.l},0)`)
    .call(d3.axisLeft(y).ticks(4).tickSize(-(W - m.l - m.r)).tickFormat(""));
  svg.append("g").attr("class", "axis").attr("transform", `translate(${m.l},0)`)
    .call(d3.axisLeft(y).ticks(4).tickFormat(compact).tickSize(0).tickPadding(6)).select(".domain").remove();
  const fmt = bucket >= 86400 ? d3.timeFormat("%b %d") : bucket >= 6 * 3600 ? d3.timeFormat("%a %H:%M") : d3.timeFormat("%H:%M");
  const every = Math.max(1, Math.ceil(data.length / Math.max(2, Math.floor((W - m.l) / 70))));
  svg.append("g").attr("class", "axis").attr("transform", `translate(0,${H - m.b})`)
    .call(d3.axisBottom(x).tickValues(data.filter((_, i) => i % every === 0).map((d) => d.t))
      .tickFormat((t) => fmt(new Date(t * 1000))).tickSize(0).tickPadding(6));

  const bw = x.bandwidth();
  const rx = Math.min(4, bw / 2);
  series.forEach((s, i) => {
    const isTop = (d) => series.slice(i + 1).every((s2) => d.data[s2.key] === 0);
    svg.append("g").attr("fill", css(s.color)).selectAll("path").data(stack[i]).join("path")
      .attr("d", (d) => {
        const x0 = x(d.data.t), y0 = y(d[0]), y1 = y(d[1]);
        let h = y0 - y1;
        if (h <= 0) return "";
        const gap = i > 0 && d[0] > 0 ? 2 : 0; // 2px surface gap between stacked segments
        h = Math.max(0, h - gap);
        const r = isTop(d) ? Math.min(rx, h) : 0;
        return `M${x0},${y0 - gap}v${-(h - r)}q0,${-r} ${r},${-r}h${bw - 2 * r}q${r},0 ${r},${r}v${h - r}z`;
      });
  });
  // hover: a full-height hit target per bucket
  const hl = svg.append("rect").attr("fill", css("--ink")).attr("opacity", 0).attr("y", m.t).attr("height", H - m.t - m.b);
  svg.append("g").selectAll("rect").data(data).join("rect")
    .attr("x", (d) => x(d.t) - (x.step() - bw) / 2).attr("width", x.step()).attr("y", m.t).attr("height", H - m.t - m.b)
    .attr("fill", "transparent")
    .on("mousemove", (ev, d) => {
      hl.attr("x", x(d.t)).attr("width", bw).attr("opacity", 0.06);
      const total = series.reduce((a, s) => a + d[s.key], 0);
      const t0 = new Date(d.t * 1000), t1 = new Date((d.t + bucket) * 1000);
      showTip(`<div class="t">${t0.toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" })} – ${t1.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}</div>` +
        series.slice().reverse().map((s) => `<div class="r"><span><i style="display:inline-block;width:8px;height:8px;border-radius:2px;background:${css(s.color)};margin-right:6px"></i>${s.label}</span><b>${num(d[s.key])}</b></div>`).join("") +
        `<div class="r" style="border-top:1px solid var(--border);margin-top:4px;padding-top:4px"><span>Total</span><b>${num(total)}</b></div>`, ev);
    })
    .on("mouseleave", () => { hl.attr("opacity", 0); hideTip(); });
}

function legend(series) {
  return `<div class="legend">${series.map((s) => `<span><i style="background:var(${s.color})"></i>${s.label}</span>`).join("")}</div>`;
}

// ---------------------------------------------------------------------------
// chart: world map (d3-geo + world-atlas TopoJSON, decoded by hand below)
// ---------------------------------------------------------------------------
let worldCache = null;
async function loadWorld() {
  if (worldCache !== null) return worldCache;
  try {
    const r = await fetch("/static/vendor/countries-110m.json");
    worldCache = r.ok ? topoFeatures(await r.json(), "countries") : false;
  } catch { worldCache = false; }
  return worldCache;
}

// Minimal TopoJSON -> GeoJSON (so we don't need the topojson-client library).
// TopoJSON stores shared borders once as "arcs", quantised and delta-encoded.
function topoFeatures(topo, objName) {
  const [sx, sy] = topo.transform.scale, [tx, ty] = topo.transform.translate;
  const arcs = topo.arcs.map((arc) => {
    let x = 0, y = 0;
    return arc.map(([dx, dy]) => { x += dx; y += dy; return [x * sx + tx, y * sy + ty]; });
  });
  const line = (ids) => {
    const pts = [];
    ids.forEach((id, i) => {
      const a = id < 0 ? arcs[~id].slice().reverse() : arcs[id];
      pts.push(...(i ? a.slice(1) : a));
    });
    return pts;
  };
  const geom = (g) => g.type === "Polygon" ? { type: "Polygon", coordinates: g.arcs.map(line) }
    : g.type === "MultiPolygon" ? { type: "MultiPolygon", coordinates: g.arcs.map((p) => p.map(line)) } : null;
  return topo.objects[objName].geometries.map((g) => ({ type: "Feature", id: g.id, properties: g.properties || {}, geometry: geom(g) })).filter((f) => f.geometry);
}

async function worldMap(el, geo) {
  const world = await loadWorld();
  el.innerHTML = "";
  const W = el.clientWidth || 800, H = el.clientHeight || W / 1.9;
  const proj = d3.geoNaturalEarth1().fitExtent([[4, 4], [W - 4, H - 4]], { type: "Sphere" });
  const path = d3.geoPath(proj);
  const svg = d3.select(el).append("svg").attr("viewBox", `0 0 ${W} ${H}`);
  const g = svg.append("g");
  g.append("path").attr("class", "sphere").attr("d", path({ type: "Sphere" }));
  g.append("path").attr("class", "grat").attr("d", path(d3.geoGraticule10()));
  if (world) g.append("g").selectAll("path").data(world).join("path").attr("class", "land").attr("d", path);

  const color = css(geo.layer === "traffic" ? "--s1" : "--s2");
  const pts = geo.points.filter((p) => p.lat != null && p.lon != null);
  const r = d3.scaleSqrt().domain([0, d3.max(pts, (p) => p.n) || 1]).range([2.5, 18]);
  g.append("g").selectAll("circle").data(pts.sort((a, b) => b.n - a.n)).join("circle")
    .attr("class", "pt").attr("fill", color).attr("fill-opacity", 0.75)
    .attr("cx", (p) => proj([p.lon, p.lat])[0]).attr("cy", (p) => proj([p.lon, p.lat])[1]).attr("r", (p) => r(p.n))
    .on("mousemove", (ev, p) => showTip(`<div class="t">${flag(p.country)} ${esc(p.country || "?")} · ${p.lat}, ${p.lon}</div>
        <div class="r"><span>${geo.layer === "traffic" ? "Requests" : "Events"}</span><b>${num(p.n)}</b></div>
        <div class="r"><span>Distinct IPs</span><b>${num(p.ips)}</b></div>
        ${geo.layer === "traffic" ? `<div class="r"><span>Errors (4xx/5xx)</span><b>${num(p.err)}</b></div>` : ""}`, ev))
    .on("mouseleave", hideTip);
  svg.call(d3.zoom().scaleExtent([1, 8]).translateExtent([[0, 0], [W, H]]).on("zoom", (e) => {
    g.attr("transform", e.transform);
    g.selectAll("circle").attr("r", (p) => r(p.n) / Math.sqrt(e.transform.k)).attr("stroke-width", 1.5 / e.transform.k);
  }));
  if (!world) d3.select(el).append("div").attr("class", "muted").style("position", "absolute").style("bottom", "6px").style("left", "8px")
    .style("font-size", "11px").text("Country outlines unavailable (vendor/countries-110m.json missing)");
}

// ---------------------------------------------------------------------------
// small building blocks
// ---------------------------------------------------------------------------
// href goes in a data attribute (escaped) and is followed by the click listener at the bottom.
// Never build inline onclick JS from data: the IP page's href carries an IP taken from the URL.
function kpi(label, value, hint, href) {
  return `<div class="card kpi ${href ? "clickable" : ""}" ${href ? `data-href="${esc(href)}"` : ""}>
    <div class="label">${label}</div><div class="value">${value}</div>${hint ? `<div class="hint">${hint}</div>` : ""}</div>`;
}

function topRows(items, nameFn, valFn, cls = "") {
  if (!items.length) return '<div class="empty">Nothing yet</div>';
  const max = Math.max(...items.map(valFn)) || 1;
  return `<div class="rows">${items.map((it) => `<div class="row"><div class="name">${nameFn(it)}</div>
    <div class="val">${num(valFn(it))}</div><div class="bar ${cls}" style="width:${(valFn(it) / max) * 100}%"></div></div>`).join("")}</div>`;
}

function table(cols, rows, empty = "No rows") {
  if (!rows.length) return `<div class="empty">${empty}</div>`;
  return `<div class="tbl-wrap"><table><thead><tr>${cols.map((c) => `<th class="${c.cls || ""}">${c.h}</th>`).join("")}</tr></thead>
    <tbody>${rows.map((r) => `<tr>${cols.map((c) => `<td class="${c.cls || ""}">${c.v(r)}</td>`).join("")}</tr>`).join("")}</tbody></table></div>`;
}

function rangeLabel() { return { "1h": "last hour", "6h": "last 6 hours", "24h": "last 24 hours", "7d": "last 7 days", "30d": "last 30 days" }[state.range]; }

// ---------------------------------------------------------------------------
// pages
// ---------------------------------------------------------------------------
const pages = {};

pages.overview = async () => {
  const [o, geo] = await Promise.all([api(`overview?range=${state.range}`), api(`geo?range=${state.range}&layer=${state.mapLayer}`)]);
  const k = o.kpis;
  const trafficSeries = [
    { key: "ok", label: "2xx/3xx", color: "--s1" },
    { key: "e4", label: "4xx", color: "--s2" },
    { key: "e5", label: "5xx", color: "--s3" },
  ];
  const dropSeries = [
    { key: "other", label: "Other block rules", color: "--s1" },
    { key: "cs", label: "Source banned by CrowdSec", color: "--s2" },
  ];
  view.innerHTML = `
    ${k.via_cf ? `<div class="note bad"><b>${num(k.via_cf)} proxied requests show a Cloudflare IP as the client.</b>
      NPM isn't restoring the visitor's real IP for some Cloudflare-proxied hosts, so CrowdSec sees (and could ban) Cloudflare itself.
      See <a href="#/hosts">Hosts &amp; Cloudflare</a> for which hosts, and SETUP.md → "Real visitor IPs".</div>` : ""}
    <div class="grid g-kpi">
      ${kpi("Active bans", num(k.active_decisions), "right now", "#/decisions")}
      ${kpi("CrowdSec alerts", num(k.alerts), rangeLabel(), "#/alerts")}
      ${kpi("Firewall drops", compact(k.fw_drops), `${num(k.fw_ips)} source IPs`, "#/firewall")}
      ${kpi("…of banned IPs", compact(k.fw_crowdsec), k.fw_drops ? `${Math.round((k.fw_crowdsec / k.fw_drops) * 100)}% of drops` : "", "#/firewall")}
      ${kpi("Proxy requests", compact(k.requests), `${num(k.unique_ips)} client IPs`, "#/traffic")}
      ${kpi("Failed logins", num(k.auth_fail), "HTTP 401 / 403", "#/traffic?status=auth")}
    </div>
    <div class="grid g-map">
      <div class="card">
        <h2>Where it comes from <span class="sub">${rangeLabel()} · scroll to zoom</span>
          <span class="right seg" id="layer"><button data-l="threats">Threats</button><button data-l="traffic">Proxy traffic</button></span></h2>
        <div class="map" id="map"></div>
        <div class="muted" style="font-size:12px;margin-top:6px">${state.mapLayer === "threats"
          ? "Threats = CrowdSec alert sources + firewall-dropped packets."
          : "Proxy traffic = every request NPM handled, placed by client IP (Cloudflare edge IPs excluded)."}</div>
      </div>
      <div class="card">
        <h2>Top countries <span class="sub">${state.mapLayer === "threats" ? "threat events" : "requests"}</span></h2>
        ${topRows(geo.countries.slice(0, 12), (c) => country(c.country), (c) => c.n, state.mapLayer === "traffic" ? "s1" : "")}
      </div>
    </div>
    <div class="grid g-2">
      <div class="card"><h2>Proxy traffic <span class="sub">requests per ${bucketName(o.bucket)}</span><span class="right">${legend(trafficSeries)}</span></h2><div class="chart" id="ch-traffic"></div></div>
      <div class="card"><h2>Firewall drops <span class="sub">packets per ${bucketName(o.bucket)}</span><span class="right">${legend(dropSeries)}</span></h2><div class="chart" id="ch-drops"></div></div>
    </div>
    <div class="grid g-3">
      <div class="card"><h2>Top hostile sources <span class="sub">alerts · drops · failed requests</span></h2>
        ${table([
          { h: "IP", v: (r) => ipLink(r.ip) + (r.banned ? ' <span class="badge b-crit" title="Active CrowdSec ban">banned</span>' : "") },
          { h: "", v: (r) => country(r.country) },
          { h: "Alerts", cls: "num", v: (r) => num(r.alerts) },
          { h: "Drops", cls: "num", v: (r) => num(r.drops) },
          { h: "Errors", cls: "num", v: (r) => num(r.errs) },
        ], o.top_sources)}</div>
      <div class="card"><h2>Top scenarios</h2>${topRows(o.top_scenarios, (s) => scenario(s.scenario), (s) => s.n)}</div>
      <div class="card"><h2>Busiest hosts</h2>${topRows(o.top_hosts, (h) => `${esc(h.host)} ${h.cf_proxied ? '<span class="badge b-cf">CF</span>' : ""}
        <span class="muted" style="font-size:12px">${h.err ? `· ${num(h.err)} errors` : ""}</span>`, (h) => h.n, "s1")}</div>
    </div>`;
  document.querySelectorAll("#layer button").forEach((b) => {
    b.classList.toggle("on", b.dataset.l === state.mapLayer);
    b.onclick = () => { state.mapLayer = b.dataset.l; store.set("mapLayer", state.mapLayer); render(); };
  });
  stackedBars($("#ch-traffic"), o.timeline.traffic, trafficSeries, o.bucket, o.since);
  stackedBars($("#ch-drops"), o.timeline.drops, dropSeries, o.bucket, o.since);
  await worldMap($("#map"), geo);
};
const bucketName = (b) => ({ 300: "5 min", 900: "15 min", 3600: "hour", 21600: "6 hours", 86400: "day" }[b] || `${b}s`);

pages.decisions = async (params) => {
  const st = params.get("state") || "active", q = params.get("q") || "";
  const rows = await api(`decisions?state=${st}&q=${encodeURIComponent(q)}`);
  const write = state.status?.config?.allow_write;
  view.innerHTML = `
    <div class="note info">A <b>decision</b> is CrowdSec's verdict ("ban this IP for 4h"). Your OPNsense firewall bouncer pulls these and blocks them in pf.
      <b>FW hits</b> counts packets OPNsense dropped from that IP while banned. <b>Requests after ban</b> &gt; 0 means traffic still reached the app anyway,
      usually because the site is behind Cloudflare (Cloudflare connects to you, not the attacker). <b>blocked</b> = stopped inside NPM by the NPM bouncer.</div>
    <div class="card">
      <h2><span class="filters">
        <span class="seg" id="st"><button data-s="active">Active</button><button data-s="expired">Expired</button><button data-s="all">All</button></span>
        <input id="q" placeholder="Filter IP, scenario, country, AS…" value="${esc(q)}">
      </span>
      <span class="right">${write ? `<button class="btn" id="ban-btn">+ Ban an IP</button>` : ""}</span></h2>
      ${table([
        { h: "IP / value", v: (r) => (r.scope?.toLowerCase() === "ip" ? ipLink(r.value) : `<span class="mono">${esc(r.value)}</span> <span class="muted">${esc(r.scope)}</span>`) },
        { h: "Country", v: (r) => country(r.country) },
        { h: "AS", v: (r) => `<span class="ink2">${esc((r.as_name || "").slice(0, 28))}</span>` },
        { h: "Scenario", v: (r) => scenario(r.scenario) },
        { h: "Target", v: (r) => r.target_host ? `${esc(r.target_host)} ${r.host_proxied ? '<span class="badge b-cf">CF</span>' : ""}` : '<span class="muted">—</span>' },
        { h: "Origin", v: (r) => `<span class="badge">${esc(r.origin)}</span>` },
        { h: "Banned", v: (r) => when(r.created_at) },
        { h: "Expires", v: (r) => (r.active ? when(r.until) : `<span class="muted">${ago(r.until)}</span>`) },
        { h: "FW hits", cls: "num", v: (r) => num(r.fw_hits) },
        { h: "Requests after ban", cls: "num", v: (r) => (r.npm_after ? `<span class="badge b-warn" title="${r.host_proxied
            ? "Reached the app: this host is behind Cloudflare, so the firewall ban can't stop it. The NPM bouncer can (SETUP.md step 9)"
            : "Reached the app after the ban. If this host is DNS-only, check the firewall bouncer (or the requests came from inside your LAN)"}">${num(r.npm_after)}</span>` : "0")
            + (r.npm_blocked ? ` <span class="badge b-good" title="Stopped by NPM with a 403 before reaching the app (NPM bouncer)">+${num(r.npm_blocked)} blocked</span>` : "") },
        ...(write ? [{ h: "", v: (r) => (r.active ? `<button class="btn danger" data-unban="${r.id}">Unban</button>` : "") }] : []),
      ], rows, st === "active" ? "No active bans" : "No decisions")}
    </div>`;
  document.querySelectorAll("#st button").forEach((b) => {
    b.classList.toggle("on", b.dataset.s === st);
    b.onclick = () => (location.hash = `#/decisions?state=${b.dataset.s}&q=${encodeURIComponent($("#q").value)}`);
  });
  $("#q").onchange = () => (location.hash = `#/decisions?state=${st}&q=${encodeURIComponent($("#q").value)}`);
  view.querySelectorAll("[data-unban]").forEach((b) => (b.onclick = async () => {
    if (!confirmInline(b, "Really unban?")) return;
    await api(`decisions/${b.dataset.unban}`, { method: "DELETE" }); render();
  }));
  const bb = $("#ban-btn");
  if (bb) bb.onclick = () => banForm();
};

// two-click confirm (no browser dialogs)
function confirmInline(btn, text) {
  if (btn.dataset.armed) return true;
  btn.dataset.armed = "1"; const old = btn.textContent; btn.textContent = text;
  setTimeout(() => { delete btn.dataset.armed; btn.textContent = old; }, 3000);
  return false;
}

function banForm(ip = "") {
  const card = document.createElement("div");
  card.className = "card";
  card.innerHTML = `<h2>Ban an IP</h2><form class="filters" id="banf">
    <input name="ip" placeholder="IP address" value="${esc(ip)}" required class="mono">
    <select name="duration"><option>1h</option><option selected>4h</option><option>24h</option><option>168h</option></select>
    <input name="reason" placeholder="Reason (optional)" style="min-width:240px">
    <button class="btn primary">Ban</button> <span id="banmsg" class="muted"></span></form>`;
  view.prepend(card);
  $("#banf").onsubmit = async (e) => {
    e.preventDefault();
    const f = new FormData(e.target);
    try {
      await api("decisions", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(Object.fromEntries(f)) });
      location.hash = "#/decisions?state=active"; render();
    } catch (err) { $("#banmsg").textContent = err.message; }
  };
}

pages.alerts = async (params) => {
  const q = params.get("q") || "";
  const rows = await api(`alerts?q=${encodeURIComponent(q)}`);
  view.innerHTML = `
    <div class="note info">An <b>alert</b> is raised when a scenario matches (e.g. too many 401s from one IP). The <b>machine</b> column shows who detected it:
      the OPNsense agent, or the agent on Unraid that reads NPM's logs.</div>
    <div class="card"><h2><span class="filters"><input id="q" placeholder="Filter IP, scenario, host, machine…" value="${esc(q)}"></span>
      <span class="right sub">${rows.length} shown</span></h2>
    ${table([
      { h: "When", v: (r) => when(r.created_at) },
      { h: "Source", v: (r) => (r.ip ? ipLink(r.ip) : `<span class="mono">${esc(r.value)}</span>`) },
      { h: "Country", v: (r) => country(r.country) },
      { h: "AS", v: (r) => `<span class="ink2">${esc((r.as_name || "").slice(0, 28))}</span>` },
      { h: "Scenario", v: (r) => scenario(r.scenario) + (r.simulated ? ' <span class="badge">simulated</span>' : "") },
      { h: "Target", v: (r) => esc(r.target_host || "—") },
      { h: "Events", cls: "num", v: (r) => num(r.events_count) },
      { h: "Machine", v: (r) => `<span class="ink2">${esc(r.machine_id)}</span>` },
      { h: "Ban", v: (r) => (r.n_decisions ? '<span class="badge b-crit">yes</span>' : '<span class="muted">no</span>') },
    ], rows, "No alerts")}</div>`;
  $("#q").onchange = () => (location.hash = `#/alerts?q=${encodeURIComponent($("#q").value)}`);
};

pages.traffic = async (params) => {
  const f = { host: params.get("host") || "", status: params.get("status") || "", ip: params.get("ip") || "", q: params.get("q") || "" };
  const qs = new URLSearchParams(Object.entries(f).filter(([, v]) => v)).toString();
  const [rows, hosts] = await Promise.all([api(`requests?limit=300&${qs}`), api(`hosts?range=30d`)]);
  view.innerHTML = `
    <div class="card"><h2><form class="filters" id="tf">
      <select name="host"><option value="">All hosts</option>${hosts.filter((h) => h.n).map((h) => `<option ${h.host === f.host ? "selected" : ""}>${esc(h.host)}</option>`).join("")}</select>
      <select name="status">${[["", "Any status"], ["2xx", "2xx"], ["3xx", "3xx"], ["4xx", "4xx"], ["5xx", "5xx"], ["auth", "401/403 (auth)"], ["404", "404"]]
        .map(([v, l]) => `<option value="${v}" ${v === f.status ? "selected" : ""}>${l}</option>`).join("")}</select>
      <input name="ip" placeholder="Client IP" value="${esc(f.ip)}" class="mono">
      <input name="q" placeholder="Path or user agent contains…" value="${esc(f.q)}">
      <button class="btn">Apply</button></form><span class="right sub">latest ${rows.length}</span></h2>
    ${table([
      { h: "When", v: (r) => when(r.ts) },
      { h: "Status", v: (r) => statusCode(r.status) },
      { h: "Client", v: (r) => ipLink(r.client_ip) + (r.via_cf ? ' <span class="badge b-cf" title="This is a Cloudflare edge IP, not the visitor">CF edge</span>' : "") },
      { h: "", v: (r) => country(r.country) },
      { h: "Host", v: (r) => esc(r.host) },
      { h: "Request", v: (r) => `<span class="mono">${esc(r.method)} ${esc(r.path.slice(0, 90))}</span>` },
      { h: "User agent", v: (r) => `<span class="muted" title="${esc(r.ua)}">${esc(r.ua.slice(0, 48))}</span>` },
      { h: "Bytes", cls: "num", v: (r) => num(r.bytes) },
    ], rows, "No requests match")}</div>`;
  $("#tf").onsubmit = (e) => {
    e.preventDefault();
    const p = new URLSearchParams([...new FormData(e.target)].filter(([, v]) => v));
    location.hash = `#/traffic?${p}`;
  };
};

pages.firewall = async (params) => {
  const ip = params.get("ip") || "", cs = params.get("crowdsec") || "", port = params.get("port") || "";
  const d = await api(`firewall?range=${state.range}&limit=300&ip=${encodeURIComponent(ip)}&crowdsec=${cs}&port=${port}`);
  view.innerHTML = `
    <div class="note info">Packets OPNsense blocked, received over syslog. Rows tagged <b>CrowdSec</b> came from an IP with an active ban,
      so this is the bouncer doing its job. The rest are your normal WAN block rules (scanners knocking on closed ports).</div>
    <div class="grid g-2">
      <div class="card"><h2>Most-probed ports <span class="sub">${rangeLabel()}</span></h2>
        ${topRows(d.summary.ports, (p) => `<a href="#/firewall?port=${p.port ?? ""}">${p.port ?? "—"}/${esc(p.proto)}</a> <span class="muted">${portName(p.port)} · ${num(p.ips)} IPs</span>`, (p) => p.n)}</div>
      <div class="card"><h2>Top sources <span class="sub">${rangeLabel()}</span></h2>
        ${topRows(d.summary.sources, (s) => `${ipLink(s.ip)} ${country(s.country)} ${s.crowdsec ? '<span class="badge b-serious">CrowdSec</span>' : ""}`, (s) => s.n)}</div>
    </div>
    <div class="card"><h2><form class="filters" id="ff">
      <input name="ip" placeholder="Source IP" value="${esc(ip)}" class="mono">
      <input name="port" placeholder="Dest port" value="${esc(port)}" style="min-width:90px;width:90px">
      <label><input type="checkbox" name="crowdsec" value="1" ${cs ? "checked" : ""}> CrowdSec bans only</label>
      <button class="btn">Apply</button></form><span class="right sub">latest ${d.events.length}</span></h2>
    ${table([
      { h: "When", v: (r) => when(r.ts) },
      { h: "Source", v: (r) => ipLink(r.src_ip) },
      { h: "", v: (r) => country(r.country) },
      { h: "Port", v: (r) => `<span class="mono">${r.dst_port ?? "—"}/${esc(r.proto)}</span> <span class="muted">${portName(r.dst_port)}</span>` },
      { h: "Interface", v: (r) => `<span class="ink2">${esc(r.iface)} ${esc(r.dir)}</span>` },
      { h: "Action", v: (r) => `<span class="badge b-crit">${esc(r.action)}</span>` },
      { h: "Why", v: (r) => (r.crowdsec ? '<span class="badge b-serious">CrowdSec ban</span>' : `<span class="muted mono" title="rule label">${esc((r.label || "").slice(0, 10))}</span>`) },
    ], d.events, "No firewall events yet — is remote syslog pointed at this container?")}</div>`;
  $("#ff").onsubmit = (e) => {
    e.preventDefault();
    location.hash = `#/firewall?${new URLSearchParams([...new FormData(e.target)].filter(([, v]) => v))}`;
  };
};
const PORTS = { 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http", 110: "pop3", 123: "ntp", 135: "msrpc", 139: "netbios", 143: "imap", 443: "https", 445: "smb", 1433: "mssql", 1900: "ssdp", 2222: "ssh-alt", 3306: "mysql", 3389: "rdp", 5060: "sip", 5432: "postgres", 5900: "vnc", 6379: "redis", 8080: "http-alt", 8443: "https-alt", 8096: "jellyfin", 9200: "elastic", 27017: "mongo" };
const portName = (p) => PORTS[p] || "";

pages.hosts = async () => {
  const [rows, st] = await Promise.all([api(`hosts?range=${state.range}`), api("status")]);
  const cf = st.collectors.cloudflare;
  view.innerHTML = `
    ${!st.config.cloudflare_token ? `<div class="note">No <b>CF_API_TOKEN</b> set, so proxied / DNS-only status is unknown.
      Add a token with <b>Zone:Read</b> + <b>DNS:Read</b> to fill the Protection column.</div>` : ""}
    ${cf.last_error ? `<div class="note bad"><b>Cloudflare:</b> ${esc(cf.last_error)}</div>` : ""}
    <div class="note info"><b>Why this matters:</b> OPNsense can only block IPs that connect to your WAN directly.
      For <span class="badge b-good">DNS only</span> hosts that works. For <span class="badge b-cf">Cloudflare proxied</span> hosts, the attacker talks to Cloudflare
      and Cloudflare talks to you, so a firewall ban never applies. Those need a Cloudflare-side remediation (e.g. the CrowdSec Cloudflare bouncer or a WAF rule).</div>
    <div class="card"><h2>Proxy hosts <span class="sub">${rangeLabel()}</span></h2>
    ${table([
      { h: "Host", v: (r) => (r.n ? `<a href="#/traffic?host=${encodeURIComponent(r.host)}">${esc(r.host)}</a>` : `<span class="ink2">${esc(r.host)}</span>`) },
      { h: "Protection", v: (r) => protectionBadge(r.cf_proxied) },
      { h: "Requests", cls: "num", v: (r) => num(r.n) },
      { h: "4xx", cls: "num", v: (r) => num(r.e4) },
      { h: "5xx", cls: "num", v: (r) => num(r.e5) },
      { h: "401/403", cls: "num", v: (r) => (r.auth ? `<a href="#/traffic?host=${encodeURIComponent(r.host)}&status=auth">${num(r.auth)}</a>` : "0") },
      { h: "Client IPs", cls: "num", v: (r) => num(r.ips) },
      { h: "Alerts", cls: "num", v: (r) => num(r.alerts) },
      { h: "Real IP", v: (r) => (r.via_cf ? `<span class="badge b-crit" title="${num(r.via_cf)} requests logged a Cloudflare IP as the client">not restored (${num(r.via_cf)})</span>` : r.n ? '<span class="badge b-good">ok</span>' : "") },
      { h: "Upstream", v: (r) => `<span class="mono muted">${esc(r.upstream || "")}</span>` },
      { h: "Last seen", v: (r) => when(r.last_seen) },
    ], rows, "No hosts seen yet")}</div>
    ${st.config.cf_fetch_events ? '<div class="card"><h2>Cloudflare security events</h2><div id="cfev"></div></div>' : ""}`;
  if (st.config.cf_fetch_events) {
    const ev = await api("cloudflare/events?limit=200");
    $("#cfev").innerHTML = table([
      { h: "When", v: (r) => when(r.ts) },
      { h: "Action", v: (r) => `<span class="badge b-serious">${esc(r.action)}</span>` },
      { h: "By", v: (r) => esc(r.source) },
      { h: "Client", v: (r) => ipLink(r.ip) },
      { h: "", v: (r) => country(r.country) },
      { h: "Request", v: (r) => `<span class="mono">${esc(r.method)} ${esc(r.host)}${esc((r.path || "").slice(0, 60))}</span>` },
    ], ev, "No Cloudflare events");
  }
};

pages.status = async () => {
  const st = await api("status");
  const names = { lapi: "CrowdSec LAPI", npm: "NPM access logs", syslog: "OPNsense syslog", geoip: "GeoIP database", cloudflare: "Cloudflare", npm_bouncer: "NPM bouncer" };
  const badge = (c) => (c.ok === true ? '<span class="badge b-good"><span class="dot"></span>working</span>'
    : c.ok === false ? '<span class="badge b-crit"><span class="dot"></span>error</span>'
    : c.enabled ? '<span class="badge b-warn"><span class="dot"></span>waiting</span>' : '<span class="badge">off</span>');
  view.innerHTML = `
    <div class="grid g-3">${Object.entries(st.collectors).map(([k, c]) => `
      <div class="card collector"><div class="head">${names[k]} <span style="margin-left:auto">${badge(c)}</span></div>
        <dl class="kv">
          ${c.last_ok ? `<dt>last ok</dt><dd>${ago(c.last_ok)}</dd>` : ""}
          ${Object.entries(c.info).map(([ik, iv]) => `<dt>${esc(ik)}</dt><dd>${esc(Array.isArray(iv) ? iv.join(", ") : iv)}</dd>`).join("")}
        </dl>
        ${c.last_error ? `<div class="note bad" style="font-size:12px">${esc(c.last_error)}</div>` : ""}
      </div>`).join("")}
      <div class="card collector"><div class="head">Database rows</div><dl class="kv">
        ${Object.entries(st.counts).map(([k, v]) => `<dt>${esc(k)}</dt><dd>${num(v)}</dd>`).join("")}</dl></div>
      <div class="card collector"><div class="head">Config</div><dl class="kv">
        ${Object.entries(st.config).map(([k, v]) => `<dt>${esc(k)}</dt><dd>${esc(Array.isArray(v) ? v.join(", ") || "(all)" : v)}</dd>`).join("")}</dl></div>
    </div>`;
};

pages.ip = async (params, arg) => {
  const ip = decodeURIComponent(arg);
  $("#title").textContent = ip;
  const d = await api(`ip/${encodeURIComponent(ip)}`);
  const active = d.decisions.find((x) => x.active);
  const write = state.status?.config?.allow_write;
  const g = d.geo;
  const kindBadge = (e) => ({
    decision: '<span class="badge b-crit">ban</span>', alert: '<span class="badge b-serious">alert</span>',
    drop: `<span class="badge ${e.crowdsec ? "b-serious" : ""}">fw drop</span>`, request: `<span class="badge">${statusCode(e.status)}</span>`,
    cloudflare: '<span class="badge b-cf">cloudflare</span>' }[e.kind]);
  view.innerHTML = `
    <div class="card"><div class="ip-head">
      <div class="big">${esc(ip)}</div>
      ${active ? `<span class="badge b-crit"><span class="dot"></span>banned · expires ${ago(active.until)}</span>` : '<span class="badge">not banned</span>'}
      ${d.cloudflare_edge ? '<span class="badge b-cf">Cloudflare edge IP — not a real visitor</span>' : ""}
      ${d.private ? '<span class="badge b-good">private / LAN</span>' : ""}
      <span class="ink2">${flag(g.country)} ${esc([g.city, g.country].filter(Boolean).join(", "))} ${g.as_name ? `· AS${esc(g.asn)} ${esc(g.as_name)}` : ""}</span>
      <span style="margin-left:auto" class="filters">
        ${write && !active && !d.private && !d.cloudflare_edge ?'<button class="btn danger" id="ipban">Ban…</button>' : ""}
        <a class="btn" href="https://app.crowdsec.net/cti/${encodeURIComponent(ip)}" target="_blank" rel="noopener">CrowdSec CTI ↗</a>
        <a class="btn" href="https://www.abuseipdb.com/check/${encodeURIComponent(ip)}" target="_blank" rel="noopener">AbuseIPDB ↗</a>
      </span>
    </div></div>
    <div class="grid g-kpi">
      ${kpi("First seen", ago(d.counts.first_seen))}
      ${kpi("Proxy requests", num(d.counts.requests), `${num(d.counts.errors)} errors`, `#/traffic?ip=${encodeURIComponent(ip)}`)}
      ${kpi("Firewall drops", num(d.counts.drops), "", `#/firewall?ip=${encodeURIComponent(ip)}`)}
      ${kpi("Alerts", num(d.alerts.length))}
      ${kpi("Decisions", num(d.decisions.length))}
    </div>
    <div class="grid g-map">
      <div class="card"><h2>Timeline <span class="sub">newest first — everything this IP did, from all sources</span></h2>
        <div class="tl">${d.timeline.length ? groupTimeline(d.timeline).map((e) => `<div class="tl-item"><span class="when" title="${esc(fullTime(e.ts))}${e.n > 1 ? " … " + esc(fullTime(e.first)) : ""}">${new Date(e.ts).toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit", second: "2-digit" })}</span>
          <span>${kindBadge(e)}</span><span class="mono" style="word-break:break-all">${esc(e.text)}${e.n > 1 ? ` <span class="badge">×${e.n}${runLength(e)}</span>` : ""}</span></div>`).join("") : '<div class="empty">Nothing recorded for this IP</div>'}</div></div>
      <div class="card"><h2>Hosts it hit</h2>${topRows(d.hosts, (h) => `${esc(h.host)} <span class="muted">${num(h.err)} errors</span>`, (h) => h.n, "s1")}</div>
    </div>`;
  const b = $("#ipban");
  if (b) b.onclick = () => banForm(ip);
};

// " over 3m" = time between the first and last event of a grouped run (nothing if under a second)
function runLength(e) {
  const s = (Date.parse(e.ts) - Date.parse(e.first)) / 1000;
  return s >= 1 ? ` over ${dur(s)}` : "";
}

// Collapse runs of identical events ("tcp → :22 on igb0" ×40) so the story stays readable.
function groupTimeline(items) {
  const out = [];
  for (const e of items) {
    const last = out[out.length - 1];
    const sig = `${e.kind}|${e.text}|${e.status ?? ""}|${e.crowdsec ?? ""}`;
    if (last && last.sig === sig) { last.n++; last.first = e.ts; continue; }
    out.push({ ...e, sig, n: 1, first: e.ts });
  }
  return out;
}

// ---------------------------------------------------------------------------
// router
// ---------------------------------------------------------------------------
const TITLES = { overview: "Overview", decisions: "Decisions", alerts: "Alerts", traffic: "Proxy traffic", firewall: "Firewall drops", hosts: "Hosts & Cloudflare", status: "Status", ip: "IP" };

async function render() {
  const [pathPart, query = ""] = location.hash.replace(/^#\/?/, "").split("?");
  const [page = "overview", arg] = pathPart.split("/");
  const fn = pages[page] || pages.overview;
  document.querySelectorAll("#nav a").forEach((a) => a.classList.toggle("active", a.dataset.page === page));
  $("#title").textContent = TITLES[page] || "Overview";
  try {
    await fn(new URLSearchParams(query), arg);
  } catch (e) {
    view.innerHTML = `<div class="note bad"><b>Couldn't load this page:</b> ${esc(e.message)}</div>`;
  }
  clearTimeout(state.timer);
  state.timer = setTimeout(() => { if (!document.hidden && !document.activeElement?.matches("input,select")) render(); else state.timer = setTimeout(render, 30000); }, 30000);
}

async function refreshStatus() {
  try {
    state.status = await api("status");
    const n = state.status.collectors.lapi.info.active_decisions;
    $("#nav-dec").textContent = n != null ? num(n) : "";
  } catch {}
}

document.querySelectorAll("#range button").forEach((b) => {
  b.classList.toggle("on", b.dataset.r === state.range);
  b.onclick = () => {
    state.range = b.dataset.r; store.set("range", state.range);
    document.querySelectorAll("#range button").forEach((x) => x.classList.toggle("on", x === b));
    render();
  };
});
$("#search").onsubmit = (e) => {
  e.preventDefault();
  const v = $("#search-input").value.trim();
  if (v) location.hash = `#/ip/${encodeURIComponent(v)}`;
};
$("#theme").onclick = () => {
  const cur = document.documentElement.dataset.theme || (matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark");
  const next = cur === "light" ? "dark" : "light";
  document.documentElement.dataset.theme = next; store.set("theme", next); render();
};
{ const t = store.get("theme", ""); if (t) document.documentElement.dataset.theme = t; }

view.addEventListener("click", (e) => {
  const card = e.target.closest("[data-href]");
  if (card && card.dataset.href.startsWith("#/")) location.hash = card.dataset.href;
});

let resizeT;
addEventListener("resize", () => { clearTimeout(resizeT); resizeT = setTimeout(render, 250); });
addEventListener("hashchange", render);
refreshStatus().then(render);
setInterval(refreshStatus, 30000);
