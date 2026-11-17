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
