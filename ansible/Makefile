SYSTEM_PYTHON ?= python3
VENV := ../.venv
PYTHON := $(VENV)/bin/python
ANSIBLE_INVENTORY := $(VENV)/bin/ansible-inventory
INVENTORY := inventories/example/hosts.yml

.DEFAULT_GOAL := help
.PHONY: help bootstrap validate test

help:
	@printf '%s\n' \
	  'make -C ansible bootstrap — установка закреплённого ansible-core в общую ../.venv.' \
	  'make -C ansible validate  — разбор example inventory через ansible-inventory и проверка контракта.' \
	  'make -C ansible test      — unit-тесты валидатора; сеть не используется.'

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
