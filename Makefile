PY := .venv/bin/python
export PYTHONPATH := src

.PHONY: venv check test

venv:
	python3 -m venv .venv && .venv/bin/pip install -q -r requirements-dev.txt

check:
	$(PY) -m soc.checks

test:
	$(PY) -m pytest -q

.PHONY: wazuh-check
wazuh-check:
	$(PY) -m soc.wazuh.auth && $(PY) -m soc.wazuh.indexer

.PHONY: wazuh-up
wazuh-up:
	./infra/setup_wazuh.sh

.PHONY: agents
agents:
	$(PY) -m soc.wazuh.agents

.PHONY: alerts
alerts:  ## usage: make alerts ARGS="--last 1h --min-level 5"
	$(PY) -m soc.wazuh.alerts $(ARGS)

# Copy the public certs we trust out of the running containers (re-run if Wazuh certs are regenerated).
.PHONY: wazuh-certs
wazuh-certs:
	mkdir -p infra/certs
	docker cp ai-soc-wazuh-wazuh.manager-1:/etc/ssl/root-ca.pem infra/certs/root-ca.pem
	docker cp ai-soc-wazuh-wazuh.manager-1:/var/ossec/api/configuration/ssl/server.crt infra/certs/wazuh-api.pem

.PHONY: eval
eval:  ## score the AI analyst on data/eval/cases.json (~10 min on CPU)
	$(PY) -m soc.ai.evaluate

.PHONY: decide
decide:  ## usage: make decide ARGS="--last 24h [--ai] [--eval]"
	$(PY) -m soc.decision.engine $(ARGS)

.PHONY: soc
soc:  ## analyst console, e.g. make soc ARGS="queue"
	$(PY) -m soc.agent $(ARGS)

.PHONY: web
web:  ## local dashboard on http://localhost:8765
	$(PY) -m soc.web

.PHONY: geoip
geoip:  ## download the offline IP -> country database (DB-IP Lite, monthly)
	./infra/get_geoip.sh

.PHONY: serve
serve:  ## production server (waitress). Expose via a tunnel; keep bind on 127.0.0.1.
	SOC_PROD=1 $(PY) -m soc.web
