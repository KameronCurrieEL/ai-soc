# Writeup: the brute force Wazuh didn't correlate

## Setup
Wazuh ships correlation rule **60204**, "Multiple Windows Logon Failures" (level 10, MITRE T1110). It fires when enough single failed-logon alerts (rule 60122, Windows event 4625) arrive from the same source within a time window.

To generate test data safely, I made failed logons on my own Windows host against a **non-existent** user. That gives NTSTATUS `0xC0000064` ("user does not exist"). Using my real account would risk locking it out; Windows 11 locks after about 10 failures by default.

## What happened
- **20 attempts, 1 second apart:** 60204 fired 3 times, as expected.
- **10 attempts sent in the same millisecond:** 60204 did **not** fire. The individual 60122 alerts arrived, but their `firedtimes` counters were out of order. Wazuh processes events in parallel, and its frequency counting didn't add up a burst that dense.

An attacker running a fast automated tool would produce exactly that pattern.

## What I built
My own correlator in the decision engine (`src/soc/decision/correlate.py`):
- groups failed logons by **source** (IP, or the Wazuh agent when the IP is missing)
- sliding window: **5 or more failures within 5 minutes** → one synthetic "burst" alert with the count and time span
- sorts by parsed timestamp itself, so arrival order doesn't matter (same-millisecond and out-of-order input are both tested)

On live data it caught **27 failures between 19:43:36 and 19:46:13 from `::1`**, which Wazuh hadn't fully correlated. The burst joins the same incident as Wazuh's own 60204 alerts (grouping key: rule family + source + host). The analyst sees one incident with 4 alerts, not 4 separate tickets.

## The local-origin twist
The source was `::1`, meaning the attempts came from the machine itself. The decision engine's guards never propose blocking loopback or private addresses. Blocking yourself is a classic way to turn a detection into an outage. Instead it proposes **investigate**: find the process or user behind the attempts. The event data shows who started them, in the `requested_by` field, and the incident page says so in plain English.

## Takeaway
Don't treat a SIEM's built-in correlation as ground truth. Test it with the patterns attackers actually use (fast, automated), and keep a simple, tested correlation of your own for the detections that matter most.
