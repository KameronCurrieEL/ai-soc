// Streams the red-team responder's output into the incident page as it generates.
// Progressive enhancement: without this file the form still works (POST, wait ~2-3 min, reload).
// Security: served from 'self' (CSP unchanged); model output is shown with textContent, never innerHTML.
(() => {
  "use strict";
  const form = document.getElementById("responder-form");
  const panel = document.getElementById("responder-progress");
  if (!form || !panel || !window.fetch || !window.TextDecoder) return;
  const out = panel.querySelector(".rp-out");
  const statusEl = panel.querySelector(".rp-status");
  const button = form.querySelector("button");
  const DONE = "\u0004";   // server sentinel: "<DONE>OK ..." or "<DONE>ERR ..."

  form.addEventListener("submit", async (ev) => {
    ev.preventDefault();
    panel.hidden = false;
    out.textContent = "";
    button.disabled = true;
    const started = Date.now();
    const secs = () => Math.round((Date.now() - started) / 1000);
    statusEl.textContent = "Analyzing… (the model is reasoning through the incident)";
    const timer = setInterval(() => {
      if (!statusEl.textContent.startsWith("Analyzing")) return;
      statusEl.textContent = `Analyzing… ${secs()}s (red-team responder, runs on CPU)`;
    }, 1000);

    try {
      const resp = await fetch(form.action, {
        method: "POST", credentials: "same-origin", headers: { "X-Stream": "1" },
        body: new FormData(form),
      });
      if (!resp.ok || !resp.body) throw new Error((await resp.text()).slice(0, 200) || `HTTP ${resp.status}`);
      const reader = resp.body.getReader();
      const decoder = new TextDecoder();
      let buf = "";
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        buf += decoder.decode(value, { stream: true });
        const cut = buf.indexOf(DONE);
        out.textContent = cut === -1 ? buf : buf.slice(0, cut);
        out.scrollTop = out.scrollHeight;
        if (cut !== -1) {
          const trailer = buf.slice(cut + 1);
          clearInterval(timer);
          if (trailer.startsWith("OK")) {
            statusEl.textContent = "Done — saving assessment and suggested actions…";
            window.location.reload();          // re-render with the parsed result + new proposals
          } else {
            statusEl.textContent = "Responder could not produce a valid answer. " + trailer.replace(/^ERR\s*/, "");
          }
          return;
        }
      }
      // stream ended without a sentinel (e.g. "[responder unavailable: …]")
      clearInterval(timer);
      statusEl.textContent = out.textContent.includes("[responder unavailable")
        ? "Responder unavailable — is Ollama running?" : "Responder finished unexpectedly.";
    } catch (err) {
      clearInterval(timer);
      statusEl.textContent = "Responder error: " + err.message;
    } finally {
      button.disabled = false;
    }
  });
})();
