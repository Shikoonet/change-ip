# =============================================================================
# server-ip-rotation — standalone.
#
# Extracted from the shikoonet Ansible repo on 2026-08-27. The DNS half still
# lives there: `ansible.repo_dir` in rotation.yml points at a checkout of it,
# and the `ansible_done` step shells `make ip-change HOST=<alias>` inside it.
# Everything else here runs on its own.
#
# Every recipe uses `set -euo pipefail` so a non-zero exit anywhere
# halts the recipe with the SAME non-zero status. No `|| true`. No
# `continue-on-error`. The regression test
# `tests/test_make_failure_propagation.py` proves this for `test`
# and `ci-fast`. Adding a new gate that swallows a failure must be
# caught by that test.
# =============================================================================
SHELL   := /bin/bash
.SHELLFLAGS := -eu -o pipefail -c
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
	@printf "  make test-dataforest               — DataForest-only behavioural suite (fake HTTP server)\n"
	@printf "  make test-provider-all             — both provider suites\n"
	@printf "  make lint                          — ansible-lint + yamllint + syntax-check\n"
	@printf "  make ip-rotate-plan                — read everything, change nothing\n"
	@printf "  make ip-rotate-apply   SERVER_ID=n — do it. SERVER_ID must equal server.id in the config\n"
	@printf "  make ip-rotate-swap    SERVER_ID=n — the provider half only, stops before the inventory edit\n"
	@printf "  make ip-rotate-resume  TXID=t SERVER_ID=n — continue an interrupted or paused rotation\n"
	@printf "  make ip-rotate-finalize TXID=t SERVER_ID=n — DataForest only: release OLD_IP (point of no return)\n"
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
# The `test`, `ci-fast`, `ci-provider`, `ci-full`, and
# `test-provider-all` targets are defined below the lint target
# to keep Makefile parsing simple.

.PHONY: test-cloudflare-playbook
test-cloudflare-playbook:
	# Two suites, both real-playbook coverage against a guarded loopback:
	#   tests.test_cloudflare_playbook — single-account apply/rollback/verify
	#                                    on a loopback fake API server.
	#   tests.test_cloudflare_real_playbook_multi_account
	#                                  — multi-account apply/rollback + the
	#                                    partial-B-then-real-rollback path,
	#                                    with a server-restart that proves
	#                                    the mutation counter survives
	#                                    process boundaries.
	# Discover/verify scenarios use GET only; apply/rollback scenarios
	# drive the loopback server with real PUT/PATCH mutations. The
	# fake server binds 127.0.0.1 only; nothing here can reach the
	# real Cloudflare API.
	python3 -m unittest tests.test_cloudflare_playbook tests.test_cloudflare_real_playbook_multi_account -v

.PHONY: test-dataforest
test-dataforest:
	python3 -m unittest tests.test_dataforest -v

.PHONY: test-dataforest-playbook
test-dataforest-playbook:
	# Actually invokes `ansible-playbook dataforest_step.yml` against a
	# temp tree of fake system binaries — no /etc touched, no real
	# network. Syntax-check alone is insufficient: this proves every
	# manager path (netplan, systemd-networkd, networkmanager, ifupdown),
	# every op (detect/configure/verify/remove/restore), and every
	# failure mode the playbook can produce.
	python3 -m unittest tests.test_dataforest_playbook -v

.PHONY: ci-fast
# Docs-only / workflow-only / config-only PRs: ONLY structural
# checks. No Python unittest suite. No real-playbook integration.
# No behavioural contract. No lint. Target: < 1 runner minute.
# The CI workflow's path-routing step selects this target when
# the diff is docs-only.
#
# `tests/structural.yml` reads the YAML shape of every step
# playbook, every CI workflow, and `rotation.example.yml` —
# nothing that requires a live API or a long suite. Combined
# with `tests.test_workflow_structure.py` (Python-side structural
# checks), this is the only thing ci-fast does.
ci-fast:
	@echo "ci-fast: structural playbook (covers both Python structural tests and YAML shape)"
	# tests/structural.yml itself runs `python3 -m unittest
	# tests.test_workflow_structure` (the lightweight structural
	# checks) AND every step playbook's `--syntax-check` AND every
	# CI workflow's trigger map. Running the Python unittest here
	# in addition would execute the same suite twice; one
	# invocation is the contract.
	ANSIBLE_PLAYBOOK_BIN=$(LINT_BIN)/ansible-playbook \
	ansible-playbook tests/structural.yml

.PHONY: ci-provider
# Provider / rotation / workflow / Makefile / test PRs: complete
# offline coverage — every unit, every staged test, every real-
# playbook test against a local loopback API, the behavioural
# contract, and rotate.py --self-test. Lint is NOT in ci-provider:
# ci-full is the lint gate. This keeps provider PRs fast while
# still exercising every behaviour.
ci-provider:
	@echo "ci-provider: complete offline unit + staged + real-playbook suite"
	# The unittest suite and `rotate.py --self-test` are NOT invoked here.
	# tests/contract.yml runs both as its first two tasks, so calling them
	# directly ran all 462 tests twice — about six minutes of a fifteen
	# minute CI budget, which is what finally tipped the job over its
	# timeout. One invocation, and it is the contract's. Same rule the
	# ci-fast target already documents for tests/structural.yml.
	#
	# Invoke the contract playbook WITHOUT overriding
	# `ANSIBLE_PLAYBOOK_BIN` — the contract only reads the
	# playbooks as text and runs the Python suite, so the
	# PATH-resolved `ansible-playbook` is the right binary. An
	# inherited override would force the adapter's
	# `ROTATION_TEST_MODE is not set` guard to fire on the
	# subprocesses the unittest exercise.
	ansible-playbook tests/contract.yml

.PHONY: ci-full
# Push to main: ci-provider (full offline regression) +
# blocking lint. ci-full ADDS lint without re-running the
# provider tests; lint is included in ci-provider above as
# best-effort, but in ci-full it is a hard gate.
ci-full: ci-provider
	@echo "ci-full: ci-provider + blocking lint"
	@if [ ! -x "$(LINT_BIN)/yamllint" ]; then \
		echo "yamllint missing at $(LINT_BIN)/yamllint"; exit 127; \
	fi
	@if [ ! -x "$(LINT_BIN)/ansible-lint" ]; then \
		echo "ansible-lint missing at $(LINT_BIN)/ansible-lint"; exit 127; \
	fi
	$(LINT_BIN)/yamllint -c .yamllint.yml \
		hcloud_step.yml cloudflare_replace_ip_step.yml dataforest_step.yml \
		cf_record_pages.yml tests/contract.yml tests/structural.yml \
		rotation.example.yml
	$(LINT_BIN)/ansible-lint \
		hcloud_step.yml cloudflare_replace_ip_step.yml dataforest_step.yml
	ansible-playbook --syntax-check \
		hcloud_step.yml cloudflare_replace_ip_step.yml dataforest_step.yml \
		tests/contract.yml tests/structural.yml
	python3 -m compileall -q rotate.py providers.py ansible_adapter.py \
		cloudflare_adapter.py dataforest_adapter.py \
		dataforest_guest_adapter.py

.PHONY: test
# Convenience: the full offline regression in one target. Used
# by the `ci-provider` and `ci-full` Make entry points.
test:
	python3 -m unittest discover -s tests -t .
	python3 rotate.py --self-test
	ansible-playbook tests/contract.yml

.PHONY: test-provider-all
# Provider-only suites (LOCAL convenience target, NOT on the
# CI path). Runs BOTH provider suites; the dependency graph
# proves this at test time. Used to iterate on the provider
# half without re-running the full offline suite.
test-provider-all: test-dataforest test-dataforest-playbook

.PHONY: lint
lint:
	# Cloudflare workstream lint — the scope of THIS repo's active task.
	# The Node-onboarding roles / monitoring-doctor.yml are NOT in scope
	# for this lint run; they live under a separate lint target so a
	# Milestone-A regression does not block the Cloudflare merge gate.
	ansible-playbook --syntax-check hcloud_step.yml cloudflare_replace_ip_step.yml dataforest_step.yml tests/contract.yml
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
	$(LINT_BIN)/yamllint -c .yamllint.yml hcloud_step.yml cloudflare_replace_ip_step.yml dataforest_step.yml cf_record_pages.yml tests/contract.yml rotation.example.yml
	$(LINT_BIN)/ansible-lint hcloud_step.yml cloudflare_replace_ip_step.yml dataforest_step.yml
	python3 -m compileall -q rotate.py providers.py ansible_adapter.py cloudflare_adapter.py dataforest_adapter.py dataforest_guest_adapter.py

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

# DataForest only: releases OLD_IP from the Seed. Point of no return —
# DataForest does not guarantee reacquisition of a released IPv4.
.PHONY: ip-rotate-finalize
ip-rotate-finalize: require-txid require-server-id
	$(ROTATE) finalize --config $(ROTATE_CONFIG) --txid $(TXID) --confirm-server-id $(SERVER_ID)

.PHONY: ip-rotate-rollback
ip-rotate-rollback: require-txid require-server-id
	$(ROTATE) rollback --config $(ROTATE_CONFIG) --txid $(TXID) --confirm-server-id $(SERVER_ID)

.PHONY: ip-rotate-status
ip-rotate-status: require-txid
	$(ROTATE) status --config $(ROTATE_CONFIG) --txid $(TXID)
