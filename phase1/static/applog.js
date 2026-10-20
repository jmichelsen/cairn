// applog 0.1.7 (5616008) (vendored from applog; change it there and sync, don't edit this copy).
//
// The web half of an app's debug log. Two parts, both on window.applog:
//   1. report(kind, data): what only the page knows (script errors, failed requests with the server's request id),
//      queued and sent to the app's /events a moment later, and on the way out with sendBeacon.
//   2. renderLog(el, report, opts): the metrics page for GET /log (counts, failures, p95, by action and day, search).
//      Plain DOM, its own applog-* classes (applog.css), themed by the app's CSS variables.
//
//   applog.init({ endpoint: "/api/v1/events", ready: () => Boolean(state.user),
//                 path: () => location.hash.replace(/^#\/reset\/.*/, "#/reset/…") });
//   applog.failed("GET", "/positions", res, data.error)   // after a fetch that came back >= 500
//   applog.failed("POST", "/settings", err)                // after a fetch that threw (offline)
//
// Never report contents: no form values, message text, search words. Kinds, ids, statuses, outcomes.
(function () {
  "use strict";
  const queue = [];
  let timer = null;
  // path: where the page is, as reported. The default drops the fragment's query (search words); an app whose
  // fragment carries a token (#/reset/<token>) passes its own, masking it.
  let opts = { endpoint: "/api/events", ready: () => true, delay: 2000,
    path: () => (location.hash || location.pathname).replace(/\?.*$/, "") };

  function init(o) {
    opts = Object.assign(opts, o || {});
    window.addEventListener("error", e => report("error", {
      message: e.message, at: `${e.filename}:${e.lineno}:${e.colno}`, stack: e.error && e.error.stack }));
    window.addEventListener("unhandledrejection", e => report("error", {
      message: String((e.reason && e.reason.message) || e.reason), stack: e.reason && e.reason.stack }));
    document.addEventListener("visibilitychange", () => { if (document.visibilityState === "hidden") flush(true); });
  }

  function report(kind, data) {
    if (queue.length >= 50) queue.shift();
    queue.push({ kind, at: new Date().toISOString(), path: opts.path(), data: data || {} });
    clearTimeout(timer);
    timer = setTimeout(flush, opts.delay);
  }

  function failed(method, path, resOrErr, message) {
    const save = method !== "GET" && method !== "HEAD";
    const kind = save ? "save-failed" : "load-failed";
    if (resOrErr && typeof resOrErr.status === "number") {
      report(kind, { request: `${method} ${path}`, status: resOrErr.status,
        rid: resOrErr.headers && resOrErr.headers.get("X-Request-Id"), message: message || "" });
    } else {
      if (resOrErr && resOrErr.name === "AbortError") return;  // a cancelled request isn't a failure
      report(kind, { request: `${method} ${path}`, message: String(resOrErr) });
    }
  }

  function flush(leaving) {
    if (!queue.length || !opts.ready()) return;
    const body = JSON.stringify({ events: queue.splice(0, queue.length) });
    if (leaving && navigator.sendBeacon && navigator.sendBeacon(opts.endpoint, new Blob([body], { type: "application/json" }))) return;
    fetch(opts.endpoint, { method: "POST", credentials: "same-origin", keepalive: true,
      headers: { "Content-Type": "application/json" }, body }).catch(() => { /* offline: dropped, never retried in a loop */ });
  }

  // ---- the metrics page ----
  const RANGES = { 1: "Today", 7: "7 days", 30: "30 days", 90: "90 days", all: "Everything" };
  const esc = s => String(s == null ? "" : s).replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  const ms = v => v == null ? "–" : v >= 1000 ? (v / 1000).toFixed(1) + " s" : v + " ms";
  function when(at) {  // the log's UTC stamp (or a date alone, for anonymous rows) in this browser's time
    if (at.length === 10) return at;
    return new Date(at.replace(" ", "T") + "Z").toLocaleString(undefined,
      { month: "short", day: "numeric", hour: "numeric", minute: "2-digit", second: "2-digit" });
  }
  function client(c) {  // "Chrome 149 on Android" from a user agent; an app's "app 0.1.2" as it is
    if (!c || c.startsWith("app ")) return c || "";
    const b = c.match(/(Edg|Firefox|Chrome|Version)\/(\d+)/);
    const os = (c.match(/Android|iPhone|iPad|Windows|Mac OS|Linux/) || [""])[0].replace("Mac OS", "Mac");
    const name = b ? ({ Edg: "Edge", Version: "Safari" }[b[1]] || b[1]) + " " + b[2] : "a browser";
    return os ? `${name} on ${os}` : name;
  }
  function entry(e) {
    const st = e.status ? `<span class="applog-pill ${e.status >= 500 ? "bad" : e.status >= 400 ? "warn" : ""}">${e.status}</span>` : "";
    const form = e.form && Object.keys(e.form).length ? `<div class="applog-label">Sent</div><pre>${esc(JSON.stringify(e.form, null, 1))}</pre>` : "";
    const changes = e.changes ? `<div class="applog-label">Wrote</div><pre>${esc([].concat(e.changes).join("\n"))}</pre>` : "";
    const error = e.error ? `<div class="applog-label">Error</div><pre>${esc(e.error)}</pre>` : "";
    const bits = [when(e.at), e.source, e.who, e.rid, e.client_at ? "phone " + e.client_at : ""].filter(Boolean).map(esc);
    if (e.client) bits.push(`<span title="${esc(e.client)}">${esc(client(e.client))}</span>`);
    const head = `<div class="applog-row"><strong class="applog-grow">${esc(e.kind)}</strong>${st}<span class="applog-muted">${ms(e.ms)}</span></div>
      <div class="applog-muted">${bits.join(" · ")}</div>`;
    const detail = form || changes || error;
    return `<div class="applog-entry ${e.problem ? "problem" : ""}">${detail ? `<details><summary>${head}</summary>${form}${changes}${error}</details>` : head}</div>`;
  }

  // r: the GET /log response. o: {days, q, kind, problems, link(over) -> href, onFilter({days, q, problems})}
  function renderLog(el, r, o) {
    const s = r.stats;
    const link = o.link;
    el.innerHTML = `<div class="applog">
      <form class="applog-filter">
        <select name="days" aria-label="Range">${Object.entries(RANGES).map(([k, v]) => `<option value="${k}" ${k === String(o.days) ? "selected" : ""}>${v}</option>`).join("")}</select>
        <input name="q" value="${esc(o.q)}" placeholder="Search: an id, a request id, a word" aria-label="Search the log">
        <label><input type="checkbox" name="problems" value="1" ${o.problems ? "checked" : ""}> Problems only</label>
        <button>Show</button>
      </form>
      ${o.kind ? `<p>Only <strong>${esc(o.kind)}</strong> · <a href="${link({ kind: "" })}">show all</a></p>` : ""}
      <dl class="applog-stats">
        <dt>Requests</dt><dd>${s.requests} <span class="applog-muted">${s.changes} changes</span></dd>
        <dt>Speed</dt><dd>${ms(s.p95)} <span class="applog-muted">95% faster than this · slowest ${ms(s.slowest)}</span></dd>
        <dt>Failed</dt><dd>${s.failed ? `<a href="${link({ problems: "1" })}">${s.failed}</a>` : 0} <span class="applog-muted">${s.refused} refused (400s)</span></dd>
        <dt>Reported</dt><dd>${s.reported} <span class="applog-muted">problems the site or app sent</span></dd>
        <dt>Jobs failed</dt><dd>${s.jobs_failed}</dd>
      </dl>
      <h2>By action</h2>
      <div class="applog-table"><table><thead><tr><th>Action</th><th class="num">Count</th><th class="num">Failed</th><th class="num p95">95%</th><th class="num">Max</th></tr></thead>
        <tbody>${r.kinds.map(k => `<tr><td><a href="${link({ kind: k.kind })}">${esc(k.kind)}</a></td><td class="num">${k.n}</td>
          <td class="num">${k.failed || ""}</td><td class="num p95">${ms(k.p95)}</td><td class="num">${ms(k.slowest)}</td></tr>`).join("") || `<tr><td colspan="5" class="applog-muted">Nothing logged.</td></tr>`}</tbody></table></div>
      <h2>By day</h2>
      <div class="applog-days">${r.by_day.map(d => `<div class="applog-row"><span class="applog-grow">${esc(d.day)}</span>${d.n}${d.failed ? ` <span class="applog-pill bad">${d.failed}</span>` : ""}<span class="applog-muted">${ms(d.p95)}</span></div>`).join("") || `<span class="applog-muted">Nothing logged.</span>`}</div>
      <h2>Entries</h2>
      ${r.entries.map(entry).join("") || `<p class="applog-muted">Nothing matches.</p>`}
      ${r.next_before ? `<p><a href="${link({ before: r.next_before })}">Older</a></p>` : ""}
      <p class="applog-muted">Kept ${r.keep_days} days; daily totals for good. applog ${esc(r.version || "")}</p>
    </div>`;
    el.querySelector(".applog-filter").addEventListener("submit", e => {
      e.preventDefault();
      const fd = new FormData(e.target);
      o.onFilter({ days: fd.get("days"), q: String(fd.get("q") || "").trim(), problems: fd.get("problems") ? "1" : "" });
    });
  }

  window.applog = { init, report, failed, flush, renderLog, RANGES };
})();
