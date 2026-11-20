// Queue triage helpers: select-all + live selected count for bulk actions.
// Served from 'self' (CSP unchanged); no inline handlers.
(() => {
  "use strict";
  const form = document.getElementById("bulk-form");
  if (!form) return;
  const all = document.getElementById("chk-all");
  const count = document.getElementById("chk-count");
  const boxes = () => [...form.querySelectorAll('input[name="ids"]')];
  const update = () => { if (count) count.textContent = boxes().filter((b) => b.checked).length; };
  if (all) all.addEventListener("change", () => { boxes().forEach((b) => { b.checked = all.checked; }); update(); });
  form.addEventListener("change", (e) => { if (e.target.name === "ids") update(); });
  update();
})();
