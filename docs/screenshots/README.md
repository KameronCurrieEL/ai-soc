# Screenshots

Capture these 7 from the running dashboard, save them here with the exact filenames below
(the main README embeds them). Use a clean demo login so no real hostnames/accounts appear.

**Log in:** http://localhost:8765 — user `demo` · password `demo-pass` (tenant `demo`, analyst).
Everything you'll see is sanitized sample data.

| Filename | Page | What to capture |
|---|---|---|
| `overview.png` | Overview (`/`) | KPI tiles, 24h activity chart, severity bar, Sources (wazuh-hq + wazuh-branch2), top entities |
| `live-alerts.png` | Live alerts (`/alerts`) | the streaming feed with the "live • on" indicator and the Source column |
| `incident.png` | the open incident | summary, Where, Involved, rule reasons + AI notes, timeline |
| `responder.png` | same incident, after clicking **Run AI responder** | the red-team responder streaming / its assessment + next-steps |
| `approval.png` | same incident | a proposal with the command + rollback and the Approve/Reject buttons |
| `metrics.png` | Detection quality (`/metrics`) | the verdict table (the closed incident shows as benign) |
| `users.png` | Users (`/users`, admin only) | the roles + tenants table — log in as an admin for this one |

Tips: use a ~1200px-wide window; Win+Shift+S to snip; dark theme looks best. Crop out the
OS chrome. After dropping the files here, tell Claude and it will confirm the README renders them.
