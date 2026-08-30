# =============================================================================
# server-ip-rotation — standalone.
#
# Extracted from the shikoonet Ansible repo on 2026-08-27. The DNS half still
# lives there: `ansible.repo_dir` in rotation.yml points at a checkout of it,
# and the `ansible_done` step shells `make ip-change HOST=<alias>` inside it.
# Everything else here runs on its own.
# =============================================================================
SHELL   := /bin/bash
YELLOW  := \033[33m
RESET   := \033[0m

ROTATE        := python3 rotate.py
ROTATE_CONFIG ?= rotation.yml

# `make lint` runs yamllint and ansible-lint from a project-local venv
# at .lint-venv/bin/ (created by `make lint-bootstrap`). Override
# LINT_BIN from the env to point at a different location.
LINT_BIN ?= $(CURDIR)/.lint-venv/bin

.DEFAULT_GOAL := help

.PHONY: help
help:
	@printf "$(YELLOW)server-ip-rotation$(RESET)\n"
	@printf "  make test                          — offline suite + contract. No network, no cost\n"
	@printf "  make test-cloudflare-playbook      — runs the real Cloudflare playbook against a local fake API server\n"
	@printf "  make lint                          — ansible-lint + yamllint + syntax-check\n"
	@printf "  make ip-rotate-plan                — read everything, change nothing\n"
	@printf "  make ip-rotate-apply   SERVER_ID=n — do it. SERVER_ID must equal server.id in the config\n"
	@printf "  make ip-rotate-swap    SERVER_ID=n — the provider half only, stops before the inventory edit\n"
	@printf "  make ip-rotate-resume  TXID=t SERVER_ID=n — continue an interrupted or paused rotation\n"
	@printf "  make ip-rotate-rollback TXID=t SERVER_ID=n — put the old address back\n"
	@printf "  make ip-rotate-status  TXID=t      — print a checkpoint\n"
	@printf "\n  HCLOUD_TOKEN must be exported for the rotation. It is never passed as an argument.\n"
	@printf "  CONFIRM must equal HOST exactly. FP comes from the PROVIDER CONSOLE, not the network.\n"

.PHONY: require-server-id
require-server-id:
	@test -n "$(SERVER_ID)" || { printf "$(YELLOW)SERVER_ID is required and must equal server.id in $(ROTATE_CONFIG).\n  make ip-rotate-plan prints it. 'true' is not a spelling of a specific server.$(RESET)\n"; exit 1; }

.PHONY: require-txid
require-txid:
	@test -n "$(TXID)" || { printf "$(YELLOW)TXID is required. state/ holds one JSON file per transaction.$(RESET)\n"; exit 1; }

# -- checks -------------------------------------------------------------------
.PHONY: test
test:
	python3 -m unittest discover -s tests -t .
	python3 rotate.py --self-test
	ansible-playbook tests/contract.yml

.PHONY: test-cloudflare-playbook
test-cloudflare-playbook:
	python3 -m unittest tests.test_cloudflare_playbook -v

.PHONY: lint
lint:
	# Cloudflare workstream lint — the scope of THIS repo's active task.
	# The Node-onboarding roles / monitoring-doctor.yml are NOT in scope
	# for this lint run; they live under a separate lint target so a
	# Milestone-A regression does not block the Cloudflare merge gate.
	ansible-playbook --syntax-check hcloud_step.yml cloudflare_replace_ip_step.yml tests/contract.yml
	# cf_record_pages.yml is a task-list file, not a Play. The Play-level
	# `--syntax-check` cannot consume it; yamllint + ansible-lint below
	# cover the task shape. The contract tests prove the include flow
	# actually runs end-to-end.
	@if [ ! -x "$(LINT_BIN)/yamllint" ]; then \
	  echo "yamllint missing at $(LINT_BIN)/yamllint — run 'make lint-bootstrap' first."; \
	  exit 127; \
	fi
	@if [ ! -x "$(LINT_BIN)/ansible-lint" ]; then \
	  echo "ansible-lint missing at $(LINT_BIN)/ansible-lint — run 'make lint-bootstrap' first."; \
	  exit 127; \
	fi
	$(LINT_BIN)/yamllint hcloud_step.yml cloudflare_replace_ip_step.yml cf_record_pages.yml tests/contract.yml rotation.example.yml
	$(LINT_BIN)/ansible-lint hcloud_step.yml cloudflare_replace_ip_step.yml
	python3 -m compileall -q rotate.py providers.py ansible_adapter.py cloudflare_adapter.py

.PHONY: lint-bootstrap
lint-bootstrap:
	# One-shot setup. Run this once on a fresh machine; subsequent `make
	# lint` invocations use the project-local venv at .lint-venv/.
	test -d .lint-venv || python3 -m venv .lint-venv
	.lint-venv/bin/pip install --quiet --upgrade pip
	.lint-venv/bin/pip install --quiet yamllint ansible-lint
	@echo "lint venv ready: .lint-venv/ (yamllint + ansible-lint)"

# -- the rotation -------------------------------------------------------------
# ⚠ Between `stop` and `start` the node is unreachable and has no public
# address. Read the plan output first — it names every step and every address.
.PHONY: ip-rotate-plan
ip-rotate-plan:
	$(ROTATE) plan --config $(ROTATE_CONFIG)

.PHONY: ip-rotate-apply
ip-rotate-apply: require-server-id
	$(ROTATE) apply --config $(ROTATE_CONFIG) --confirm-server-id $(SERVER_ID)

# The provider half alone. Stops at connectivity_ok — the node is up on the new
# address, the inventory and DNS still point at the old one. This is the
# boundary the CD pipeline splits on, and it is resumable.
.PHONY: ip-rotate-swap
ip-rotate-swap: require-server-id
	$(ROTATE) apply --config $(ROTATE_CONFIG) --confirm-server-id $(SERVER_ID) --until connectivity_ok

.PHONY: ip-rotate-resume
ip-rotate-resume: require-txid require-server-id
	$(ROTATE) resume --config $(ROTATE_CONFIG) --txid $(TXID) --confirm-server-id $(SERVER_ID)

.PHONY: ip-rotate-rollback
ip-rotate-rollback: require-txid require-server-id
	$(ROTATE) rollback --config $(ROTATE_CONFIG) --txid $(TXID) --confirm-server-id $(SERVER_ID)

.PHONY: ip-rotate-status
ip-rotate-status: require-txid
	$(ROTATE) status --config $(ROTATE_CONFIG) --txid $(TXID)
