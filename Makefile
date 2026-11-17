PY := .venv/bin/python
export PYTHONPATH := src

.PHONY: venv check test

venv:
	python3 -m venv .venv && .venv/bin/pip install -q -r requirements-dev.txt

check:
	$(PY) -m soc.checks

test:
	$(PY) -m pytest -q
