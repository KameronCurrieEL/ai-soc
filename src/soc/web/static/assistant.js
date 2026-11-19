// Streams the AI assistant's answer into the panel as the model writes it.
// Progressive enhancement: without this file the form still works (POST, then reload).
// Security: served from 'self' (CSP unchanged, no inline script). All text is inserted with
// textContent, never innerHTML, so model output and log data can't become HTML (XSS).
(() => {
  "use strict";
  const form = document.querySelector("form.as-form");
  const log = document.getElementById("as-log");
  if (!form || !log || !window.fetch || !window.TextDecoder) return;
  const textarea = form.querySelector("textarea");
  const buttons = form.querySelectorAll("button");

  const scrollDown = () => { log.scrollTop = log.scrollHeight; };
  scrollDown();

  function addMessage(role, label) {
    log.querySelector(".as-empty")?.remove();
    const msg = document.createElement("div");
    msg.className = "msg msg-" + role;
    const who = document.createElement("div");
    who.className = "who";
    who.textContent = label;
    const text = document.createElement("div");
    text.className = "text";
    msg.append(who, text);
    log.append(msg);
    scrollDown();
    return { msg, who, text };
  }

  function setBusy(busy) {
    buttons.forEach((b) => { b.disabled = busy; });
    textarea.disabled = busy;
    form.classList.toggle("busy", busy);
  }

  textarea.addEventListener("keydown", (ev) => {
    if (ev.key === "Enter" && !ev.shiftKey) { ev.preventDefault(); form.requestSubmit(); }
  });

  form.addEventListener("submit", async (ev) => {
    ev.preventDefault();
    const chip = ev.submitter && ev.submitter.classList.contains("chip") ? ev.submitter.value : "";
    const question = (chip || textarea.value).trim();
    if (!question) { textarea.focus(); return; }

    const body = new FormData(form);
    body.delete("question");
    body.set("question", question);

    addMessage("user", "You · now").text.textContent = question;
    textarea.value = "";
    const answer = addMessage("assistant", "Assistant · thinking…");
    answer.msg.classList.add("pending");
    setBusy(true);
    const started = Date.now();
    const secs = () => Math.round((Date.now() - started) / 1000);
    const timer = setInterval(() => { answer.who.textContent = `Assistant · thinking… ${secs()}s`; }, 1000);

    try {
      const resp = await fetch(form.action, {
        method: "POST", body, credentials: "same-origin", headers: { "X-Stream": "1" },
      });
      if (!resp.ok || !resp.body) throw new Error((await resp.text()).slice(0, 200) || `HTTP ${resp.status}`);
      const reader = resp.body.getReader();
      const decoder = new TextDecoder();
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        answer.text.textContent += decoder.decode(value, { stream: true });
        answer.msg.classList.remove("pending");
        scrollDown();
      }
      if (answer.text.textContent.includes("[assistant unavailable:")) answer.msg.classList.add("msg-error");
      answer.who.textContent = `Assistant · ${secs()}s`;
    } catch (err) {
      answer.msg.classList.add("msg-error");
      answer.text.textContent = "Assistant unavailable: " + err.message;
      answer.who.textContent = "Assistant";
    } finally {
      clearInterval(timer);
      answer.msg.classList.remove("pending");
      setBusy(false);
      textarea.focus();
    }
  });
})();
