// Live alert feed: polls the JSON API and refreshes the table in place, newest first.
// Progressive enhancement — the server already rendered the current rows; without this file
// the page is simply static. Security: served from 'self' (CSP unchanged); every value is
// inserted with textContent or via DOM APIs, never innerHTML, so alert data can't become HTML.
(() => {
  "use strict";
  const body = document.getElementById("feed-body");
  const statusEl = document.getElementById("live-status");
  if (!body || !window.fetch) return;
  const endpoint = body.dataset.endpoint + window.location.search;  // keep the page's filters
  const POLL_MS = 10000;
  const seen = new Set([...body.querySelectorAll("tr[data-id]")].map((tr) => tr.dataset.id));
  let lastUpdate = Date.now();

  const PRIOS = new Set(["low", "medium", "high", "critical"]);
  const td = (cls) => { const c = document.createElement("td"); if (cls) c.className = cls; return c; };

  function entityLink(type, value, scope) {
    const a = document.createElement("a");
    a.className = "elink";
    a.href = "/entity?" + new URLSearchParams({ type, value }).toString();
    const code = document.createElement("code");
    code.textContent = value;
    a.appendChild(code);
    if (scope) {
      const s = document.createElement("span");
      s.className = "scope sc-" + (PRIOS.has(scope) ? "" : scope.replace(/[^a-z]/gi, ""));
      s.textContent = scope;
      const frag = document.createDocumentFragment();
      frag.append(a, document.createTextNode(" "), s);
      return frag;
    }
    return a;
  }

  function dash() { const s = document.createElement("span"); s.className = "muted"; s.textContent = "–"; return s; }

  function rowFor(a) {
    const tr = document.createElement("tr");
    tr.dataset.id = a.id;
    const time = td("mono"); time.textContent = a.ts; tr.appendChild(time);
    const sev = td(); const b = document.createElement("span");
    b.className = "badge b-" + (PRIOS.has(a.priority) ? a.priority : "low"); b.textContent = a.priority; sev.appendChild(b); tr.appendChild(sev);
    const src = td(); const st = document.createElement("span"); st.className = "sensor-tag"; st.textContent = a.sensor || ""; src.appendChild(st); tr.appendChild(src);
    const rule = td("mono"); rule.textContent = a.rule_id; tr.appendChild(rule);
    const host = td(); host.appendChild(a.agent ? entityLink("host", a.agent) : dash()); tr.appendChild(host);
    const user = td(); user.appendChild(a.user ? entityLink("user", a.user) : dash()); tr.appendChild(user);
    const ip = td(); ip.appendChild(a.src_ip ? entityLink("ip", a.src_ip, a.scope) : dash()); tr.appendChild(ip);
    const desc = td("desc"); desc.textContent = a.description; tr.appendChild(desc);
    if (!seen.has(a.id)) tr.classList.add("row-new");
    return tr;
  }

  function setStatus(text, live) {
    if (!statusEl) return;
    statusEl.textContent = text;
    statusEl.classList.toggle("on", !!live);
  }

  function ago() {
    const s = Math.round((Date.now() - lastUpdate) / 1000);
    setStatus(`live • updated ${s < 2 ? "just now" : s + "s ago"}`, true);
  }

  async function poll() {
    if (document.visibilityState !== "visible") return;
    try {
      const resp = await fetch(endpoint, { credentials: "same-origin", headers: { "Accept": "application/json" } });
      if (!resp.ok) throw new Error("HTTP " + resp.status);
      const { alerts } = await resp.json();
      const frag = document.createDocumentFragment();
      const incoming = [];
      for (const a of alerts) { frag.appendChild(rowFor(a)); incoming.push(a.id); }
      body.replaceChildren(frag);
      incoming.forEach((id) => seen.add(id));
      lastUpdate = Date.now();
      ago();
    } catch (err) {
      setStatus("live: paused (" + err.message + ")", false);
    }
  }

  setStatus("live • on", true);
  setInterval(ago, 1000);
  setInterval(poll, POLL_MS);
  document.addEventListener("visibilitychange", () => { if (document.visibilityState === "visible") poll(); });
  poll();
})();
