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

.DEFAULT_GOAL := help

.PHONY: help
help:
	@printf "$(YELLOW)server-ip-rotation$(RESET)\n"
	@printf "  make test                          — offline suite + contract. No network, no cost\n"
	@printf "  make lint                          — ansible-lint + yamllint + syntax-check\n"
	@printf "  make ip-rotate-plan                — read everything, change nothing\n"
	@printf "  make ip-rotate-apply   SERVER_ID=n — do it. SERVER_ID must equal server.id in the config\n"
	@printf "  make ip-rotate-swap    SERVER_ID=n — the provider half only, stops before the inventory edit\n"
	@printf "  make ip-rotate-resume  TXID=t SERVER_ID=n — continue an interrupted or paused rotation\n"
	@printf "  make ip-rotate-rollback TXID=t SERVER_ID=n — put the old address back\n"
	@printf "  make ip-rotate-status  TXID=t      — print a checkpoint\n"
	@printf "\n  HCLOUD_TOKEN must be exported. It is never passed as an argument.\n"

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

.PHONY: lint
lint:
	ansible-playbook --syntax-check hcloud_step.yml tests/contract.yml
	-yamllint hcloud_step.yml tests/contract.yml rotation.example.yml
	-ansible-lint hcloud_step.yml
	python3 -m compileall -q rotate.py providers.py ansible_adapter.py

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
