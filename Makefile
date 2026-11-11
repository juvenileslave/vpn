PYTHON ?= python3
VENV := .venv
PRE_COMMIT := $(VENV)/bin/pre-commit

.DEFAULT_GOAL := help
.PHONY: help bootstrap check hooks vpnctl-test vpnctl-build

help:
	@printf '%s\n' \
	  'make bootstrap — Python >=3.11 + venv/pip, Git, make; загрузка закреплённых инструментов в .venv.' \
	  'make check     — проверки публичных tracked/staged файлов; работает на master.' \
	  'make hooks     — установка локального pre-commit hook, запрещающего commit на master/main.' \
	  'make vpnctl-test  — gofmt, go vet и go test для vpnctl/; нужен Go из vpnctl/go.mod, тесты без сети.' \
	  'make vpnctl-build — сборка vpnctl/bin/vpnctl. Go не входит в make bootstrap и make check.' \
	  'check: publication policy, YAML/JSON, конфликты, размер, приватные ключи, whitespace/EOF, actionlint.' \
	  'Whitespace/EOF hooks исправляют файлы, кроме неизменяемого docs/ARCHITECTURE_PLAN.md.' \
	  'Новые файлы проверяются после git add; приватные untracked-файлы не читаются.' \
	  'Локальный detect-private-key не заменяет поиск остальных секретов.' \
	  'CI Secret scan отдельно проверяет Git-историю, а не пустой staged index; локального gitleaks hook нет.'

bootstrap:
	$(PYTHON) -c 'import sys; sys.exit("Требуется Python >=3.11") if sys.version_info < (3, 11) else None'
	$(PYTHON) -m venv $(VENV)
	$(VENV)/bin/python -m pip install --requirement requirements-dev.txt

check:
	@test -x $(PRE_COMMIT) || { printf '%s\n' 'Сначала выполните make bootstrap.'; exit 1; }
	SKIP=no-commit-to-branch $(PRE_COMMIT) run --all-files

hooks:
	@test -x $(PRE_COMMIT) || { printf '%s\n' 'Сначала выполните make bootstrap.'; exit 1; }
	$(PRE_COMMIT) install --hook-type pre-commit --install-hooks

vpnctl-test:
	cd vpnctl && test -z "$$(gofmt -l .)" || { gofmt -l .; exit 1; }
	cd vpnctl && go vet ./... && go test ./...

vpnctl-build:
	cd vpnctl && go build -o bin/vpnctl ./cmd/vpnctl
