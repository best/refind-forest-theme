override SHELL := /bin/bash
override .SHELLFLAGS := -eu -o pipefail -c
.DEFAULT_GOAL := help
.DELETE_ON_ERROR:
.NOTPARALLEL:

SYSTEM_PYTHON ?= python3
VENV ?= .venv
PYTHON ?= $(VENV)/bin/python
SUDO ?= sudo
INSTALL ?= /usr/bin/install

THEME_OUTPUT ?= build/refind-theme
ESP_LABEL ?= SYSTEM
ESP ?= /boot/efi
THEME_BACKUP_ROOT ?= backups
VARIANT ?= a
BACKUP_PATH ?=

LOADER_OUTPUT ?= build/refind-loader
LOADER_CACHE ?= .cache/refind-loader
LOADER_IMAGE ?= $(LOADER_OUTPUT)/refind_x64.efi
SIGNED_LOADER_IMAGE ?= $(LOADER_OUTPUT)/refind_x64.signed.efi
LOADER_BACKUP_ROOT ?= /var/lib/refind-forest/loader-backups
QEMU_OUTPUT ?= build/qemu-refind-smoke

TEST_ARGS ?= discover -s tests -v
CONFIRM ?=

# MAKEFLAGS assignments look like command-line values, so also inspect make's argv.
override confirm_argument = $(shell \
	confirmed=; \
	while IFS= read -r -d '' argument; do \
		if [[ "$$argument" == CONFIRM=YES ]]; then confirmed=YES; break; fi; \
	done < "/proc/$$PPID/cmdline" 2>/dev/null; \
	printf '%s' "$$confirmed")

override define assert-confirm
$(if $(filter command line,$(origin CONFIRM)),,$(error CONFIRM=YES must be supplied on this make command line))
$(if $(filter xYESx,x$(CONFIRM)x),,$(error CONFIRM=YES is required for this target))
$(if $(filter YES,$(confirm_argument)),,$(error CONFIRM=YES must be an explicit argument to this make process))
endef

override define assert-value
$(if $(strip $($(1))),,$(error $(1) is required))
endef

override define assert-variant
$(if $(filter xax,x$(VARIANT)x),,$(if $(filter xbx,x$(VARIANT)x),,$(error VARIANT must be exactly a or b)))
endef

override resolve_python = python=$$(command -v -- "$(PYTHON)"); python=$$(realpath -- "$$python")

.PHONY: \
	help setup test audit whitespace deterministic check ci clean distclean \
	build theme-build theme-install theme-verify theme-switch theme-rollback \
	loader-backup-init loader-build loader-verify loader-sign loader-smoke \
	loader-stage loader-status loader-boot-next loader-promote loader-rollback \
	require-env

help: ## Show the supported Make targets and variables.
	@awk 'BEGIN {FS = ":.*## "; printf "Usage: make <target> [VARIABLE=value]\n\nTargets:\n"} /^[a-zA-Z0-9_.-]+:.*## / {printf "  %-22s %s\n", $$1, $$2}' $(MAKEFILE_LIST)
	@printf '\nCommon variables:\n'
	@printf '  %-22s %s\n' 'SYSTEM_PYTHON=$(SYSTEM_PYTHON)' 'Interpreter used to create VENV'
	@printf '  %-22s %s\n' 'VENV=$(VENV)' 'Managed virtual environment'
	@printf '  %-22s %s\n' 'PYTHON=$(PYTHON)' 'Interpreter used by project targets'
	@printf '  %-22s %s\n' 'SUDO=$(SUDO)' 'sudo-compatible privilege command'
	@printf '  %-22s %s\n' 'ESP=$(ESP)' 'Mounted EFI System Partition'
	@printf '  %-22s %s\n' 'ESP_LABEL=$(ESP_LABEL)' 'FAT label embedded in a built package'
	@printf '  %-22s %s\n' 'VARIANT=$(VARIANT)' 'Theme variant: a or b'
	@printf '  %-22s %s\n' 'BACKUP_PATH=...' 'Theme or loader transaction backup'
	@printf '  %-22s %s\n' 'THEME_OUTPUT=$(THEME_OUTPUT)' 'Generated theme package'
	@printf '  %-22s %s\n' 'THEME_BACKUP_ROOT=$(THEME_BACKUP_ROOT)' 'Theme backup directory'
	@printf '  %-22s %s\n' 'LOADER_OUTPUT=$(LOADER_OUTPUT)' 'Generated loader directory'
	@printf '  %-22s %s\n' 'LOADER_CACHE=$(LOADER_CACHE)' 'Pinned loader input cache'
	@printf '  %-22s %s\n' 'LOADER_IMAGE=$(LOADER_IMAGE)' 'Loader image to verify or sign'
	@printf '  %-22s %s\n' 'SIGNED_LOADER_IMAGE=$(SIGNED_LOADER_IMAGE)' 'Signed loader to stage or smoke-test'
	@printf '  %-22s %s\n' 'LOADER_BACKUP_ROOT=$(LOADER_BACKUP_ROOT)' 'Root-only loader transaction directory'
	@printf '  %-22s %s\n' 'QEMU_OUTPUT=$(QEMU_OUTPUT)' 'Fresh QEMU smoke-test output directory'
	@printf '  %-22s %s\n' 'TEST_ARGS=$(TEST_ARGS)' 'unittest arguments for make test'
	@printf '  %-22s %s\n' 'CONFIRM=YES' 'Required exact acknowledgement for writes'
	@printf '\nSafety: targets that write to the ESP, NVRAM, signing outputs, or root state require CONFIRM=YES.\n'

setup: ## Create .venv and install the project in editable mode.
	@venv=$$(realpath -m -- "$(VENV)"); root=$$(pwd -P); \
	if [[ "$$venv" != "$$root/"* || "$$venv" == "$$root" ]]; then \
		echo "refusing to create VENV outside the project: $$venv" >&2; \
		exit 2; \
	fi; \
	if [[ ! -x "$(VENV)/bin/python" ]]; then \
		"$(SYSTEM_PYTHON)" -m venv "$(VENV)"; \
	fi
	@"$(VENV)/bin/python" -m pip install -e .

test: require-env ## Run the complete unit suite with warnings as errors.
	@PYTHONPATH=src "$(PYTHON)" -W error -m unittest $(TEST_ARGS)

audit: require-env ## Audit the public tree for private or generated artifacts.
	@"$(PYTHON)" tools/check_public_tree.py .

# The canonical CC legal text has a tested hash and an intentional blank EOF line.
whitespace: ## Check committed, staged, and unstaged tracked content.
	@empty_tree=$$(git hash-object -t tree /dev/null); \
	git diff --check "$$empty_tree" HEAD -- . \
		':(exclude)LICENSES/CC-BY-SA-4.0.txt'; \
	git diff --cached --check; \
	git diff --check

deterministic: require-env ## Build twice and compare every package byte.
	$(call assert-value,ESP_LABEL)
	@temporary=$$(mktemp -d -t refind-forest-make-XXXXXX); \
	trap 'rm -rf -- "$$temporary"' EXIT; \
	"$(PYTHON)" ./bin/refind-forest build --output "$$temporary/a" --esp-label "$(ESP_LABEL)"; \
	"$(PYTHON)" ./bin/refind-forest build --output "$$temporary/b" --esp-label "$(ESP_LABEL)"; \
	diff -qr "$$temporary/a" "$$temporary/b"; \
	sha256sum "$$temporary/a/manifest.json"

check: test audit deterministic whitespace ## Run the full local quality gate.

ci: test theme-build audit whitespace ## Run the same gates used by GitHub Actions.

build: theme-build ## Build the default Forest theme package.

theme-build: require-env ## Build both theme variants without privileged writes.
	$(call assert-value,THEME_OUTPUT)
	$(call assert-value,ESP_LABEL)
	@"$(PYTHON)" ./bin/refind-forest build --output "$(THEME_OUTPUT)" --esp-label "$(ESP_LABEL)"

theme-install: require-env ## Install the theme and print its backup path.
	$(call assert-confirm)
	$(call assert-value,ESP)
	$(call assert-value,THEME_BACKUP_ROOT)
	@$(resolve_python); "$(SUDO)" -- "$$python" ./bin/refind-forest install --esp "$(ESP)" --backup-root "$(THEME_BACKUP_ROOT)"

theme-verify: require-env ## Verify the installed theme without changing it.
	$(call assert-value,ESP)
	@$(resolve_python); "$(SUDO)" -- "$$python" ./bin/refind-forest verify --esp "$(ESP)"

theme-switch: require-env ## Activate theme variant VARIANT=a or VARIANT=b.
	$(call assert-confirm)
	$(call assert-value,ESP)
	$(call assert-variant)
	@$(resolve_python); "$(SUDO)" -- "$$python" ./bin/refind-forest switch-theme "$(VARIANT)" --esp "$(ESP)"

theme-rollback: require-env ## Restore the theme backup at BACKUP_PATH.
	$(call assert-confirm)
	$(call assert-value,ESP)
	$(call assert-value,BACKUP_PATH)
	@$(resolve_python); "$(SUDO)" -- "$$python" ./bin/refind-forest rollback "$(BACKUP_PATH)" --esp "$(ESP)"

loader-backup-init: ## Create the root-only loader transaction directory.
	$(call assert-confirm)
	$(call assert-value,LOADER_BACKUP_ROOT)
	@"$(SUDO)" -- "$(INSTALL)" -d -m 0700 -o root -g root -- "$(LOADER_BACKUP_ROOT)"

loader-build: require-env ## Build and audit the patched loader.
	$(call assert-value,LOADER_OUTPUT)
	$(call assert-value,LOADER_CACHE)
	@"$(PYTHON)" ./bin/refind-loader build --output "$(LOADER_OUTPUT)" --cache "$(LOADER_CACHE)"

loader-verify: require-env ## Verify LOADER_IMAGE without privileged writes.
	$(call assert-value,LOADER_IMAGE)
	@"$(PYTHON)" ./bin/refind-loader verify "$(LOADER_IMAGE)"

loader-sign: require-env ## Sign and verify LOADER_IMAGE with the root-owned local key.
	$(call assert-confirm)
	$(call assert-value,LOADER_IMAGE)
	$(call assert-value,SIGNED_LOADER_IMAGE)
	@$(resolve_python); "$(SUDO)" -- "$$python" ./bin/refind-loader sign "$(LOADER_IMAGE)" --output "$(SIGNED_LOADER_IMAGE)"

loader-smoke: ## Boot the signed loader in isolated QEMU/OVMF.
	$(call assert-value,SIGNED_LOADER_IMAGE)
	$(call assert-value,QEMU_OUTPUT)
	@./tools/qemu_refind_smoke.sh "$(SIGNED_LOADER_IMAGE)" "$(QEMU_OUTPUT)"

loader-stage: require-env ## Stage the signed loader in an alternate boot slot.
	$(call assert-confirm)
	$(call assert-value,ESP)
	$(call assert-value,SIGNED_LOADER_IMAGE)
	$(call assert-value,LOADER_BACKUP_ROOT)
	@$(resolve_python); "$(SUDO)" -- "$$python" ./bin/refind-loader stage "$(SIGNED_LOADER_IMAGE)" --esp "$(ESP)" --backup-root "$(LOADER_BACKUP_ROOT)"

loader-status: require-env ## Read the loader transaction state at BACKUP_PATH.
	$(call assert-value,ESP)
	$(call assert-value,BACKUP_PATH)
	@$(resolve_python); "$(SUDO)" -- "$$python" ./bin/refind-loader status "$(BACKUP_PATH)" --esp "$(ESP)"

loader-boot-next: require-env ## Select the staged candidate for the next boot only.
	$(call assert-confirm)
	$(call assert-value,BACKUP_PATH)
	@$(resolve_python); "$(SUDO)" -- "$$python" ./bin/refind-loader boot-next "$(BACKUP_PATH)"

loader-promote: require-env ## Promote a candidate after a validated candidate boot.
	$(call assert-confirm)
	$(call assert-value,ESP)
	$(call assert-value,BACKUP_PATH)
	@$(resolve_python); "$(SUDO)" -- "$$python" ./bin/refind-loader promote "$(BACKUP_PATH)" --esp "$(ESP)"

loader-rollback: require-env ## Restore the loader transaction at BACKUP_PATH.
	$(call assert-confirm)
	$(call assert-value,ESP)
	$(call assert-value,BACKUP_PATH)
	@$(resolve_python); "$(SUDO)" -- "$$python" ./bin/refind-loader rollback "$(BACKUP_PATH)" --esp "$(ESP)"

clean: ## Remove build output and Python-generated metadata; keep venv and downloads.
	@rm -rf -- build dist
	@find src tests tools bin -type d -name __pycache__ -prune -exec rm -rf -- {} + 2>/dev/null || true
	@find src -type d -name '*.egg-info' -prune -exec rm -rf -- {} + 2>/dev/null || true

distclean: clean ## Also remove the managed venv and loader download cache.
	@venv=$$(realpath -m -- "$(VENV)"); root=$$(pwd -P); \
	if [[ "$$venv" != "$$root/"* || "$$venv" == "$$root" ]]; then \
		echo "refusing to remove VENV outside the project: $$venv" >&2; \
		exit 2; \
	fi; \
	rm -rf -- "$$venv" .cache

require-env:
	@command -v "$(PYTHON)" >/dev/null 2>&1 || { \
		echo "Python environment not found; run 'make setup' first" >&2; \
		exit 2; \
	}
