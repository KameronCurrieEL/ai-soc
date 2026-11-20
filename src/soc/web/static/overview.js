// Live overview: refreshes the KPI tiles and severity counts in place, without a full reload.
// Progressive enhancement; served from 'self' (CSP unchanged); numbers set via textContent only.
(() => {
  "use strict";
  const live = document.getElementById("ov-live");
  if (!live || !window.fetch) return;
  const endpoint = live.dataset.endpoint;
  const POLL_MS = 15000;
  let lastUpdate = Date.now();

  const set = (el, val) => {
    if (!el || el.textContent === String(val)) return;
    el.textContent = val;
    el.classList.remove("just-changed");
    void el.offsetWidth;            // restart the flash animation
    el.classList.add("just-changed");
  };

  function apply(data) {
    for (const [k, v] of Object.entries(data.kpis || {})) set(document.querySelector(`[data-kpi="${k}"]`), v);
    for (const [k, v] of Object.entries(data.counts || {})) set(document.querySelector(`[data-sev="${k}"]`), v);
    lastUpdate = Date.now();
  }

  function ago() {
    const s = Math.round((Date.now() - lastUpdate) / 1000);
    live.textContent = `live • ${s < 2 ? "just now" : s + "s ago"}`;
    live.classList.add("on");
  }

  async function poll() {
    if (document.visibilityState !== "visible") return;
    try {
      const resp = await fetch(endpoint, { credentials: "same-origin", headers: { "Accept": "application/json" } });
      if (!resp.ok) throw new Error("HTTP " + resp.status);
      apply(await resp.json());
      ago();
    } catch (err) {
      live.textContent = "live: paused";
      live.classList.remove("on");
    }
  }

  live.textContent = "live • on";
  live.classList.add("on");
  setInterval(ago, 1000);
  setInterval(poll, POLL_MS);
  document.addEventListener("visibilitychange", () => { if (document.visibilityState === "visible") poll(); });
})();
