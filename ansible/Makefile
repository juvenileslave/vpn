SYSTEM_PYTHON ?= python3
VENV := ../.venv
PYTHON := $(VENV)/bin/python
ANSIBLE_INVENTORY := $(VENV)/bin/ansible-inventory
INVENTORY := inventories/example/hosts.yml
EXPECTED_STATE ?= ../artifacts/state/expected.json
# Drift is meaningless against the synthetic example: require the real
# inventory explicitly for state/drift only.
STATE_INVENTORY ?=

.DEFAULT_GOAL := help
.PHONY: help bootstrap validate test state drift

help:
	@printf '%s\n' \
	  'make -C ansible bootstrap — установка закреплённого ansible-core в общую ../.venv.' \
	  'make -C ansible validate  — разбор example inventory через ansible-inventory и проверка контракта.' \
	  'make -C ansible test      — unit-тесты валидатора, drift и рендера; сеть не используется.' \
	  'make -C ansible state     — записать ожидаемое managed state; нужен STATE_INVENTORY=/abs/hosts.yml.' \
	  'make -C ansible drift STATE=/abs/observed.json — нужны STATE_INVENTORY и STATE (observed snapshot).'

bootstrap:
	$(SYSTEM_PYTHON) -c 'import sys; sys.exit("Требуется Python >=3.11") if sys.version_info < (3, 11) else None'
	test -x $(PYTHON) || $(SYSTEM_PYTHON) -m venv $(VENV)
	$(PYTHON) -m pip install --requirement requirements-ansible.txt

validate:
	@test -x $(ANSIBLE_INVENTORY) || { printf '%s\n' 'Сначала выполните make -C ansible bootstrap.'; exit 1; }
	$(ANSIBLE_INVENTORY) -i $(INVENTORY) --list > /dev/null
	$(PYTHON) scripts/validate_inventory.py --inventory $(INVENTORY)

test:
	@test -x $(PYTHON) || { printf '%s\n' 'Сначала выполните make -C ansible bootstrap.'; exit 1; }
	$(PYTHON) -m unittest discover --start-directory scripts/tests --verbose

# GNU make returns 2 for any failed recipe. The documented 0/1/2/64 codes are
# observable only when calling scripts/validate_inventory.py directly.
# Expected state derived from the inventory; this is the drift baseline.
state:
	@test -x $(PYTHON) || { printf '%s\n' 'Сначала выполните make -C ansible bootstrap.'; exit 1; }
	@test -n "$(STATE_INVENTORY)" || { printf '%s\n' 'Задайте STATE_INVENTORY=/abs/path/hosts.yml; example не является drift-базой.'; exit 64; }
	$(PYTHON) scripts/validate_inventory.py --inventory $(STATE_INVENTORY) \
	  --write-expected $(EXPECTED_STATE)

# Observed snapshot is operator-supplied; no host is contacted here.
drift:
	@test -x $(PYTHON) || { printf '%s\n' 'Сначала выполните make -C ansible bootstrap.'; exit 1; }
	@test -n "$(STATE_INVENTORY)" || { printf '%s\n' 'Задайте STATE_INVENTORY=/abs/path/hosts.yml.'; exit 64; }
	@test -n "$(STATE)" || { printf '%s\n' 'Задайте STATE=/abs/path/observed.json (schema 1).'; exit 64; }
	$(PYTHON) scripts/validate_inventory.py --inventory $(STATE_INVENTORY) --state $(STATE)
