.PHONY: setup restore build test lint format verify security-tools security crypto-restore crypto-test crypto-spike crypto-browser

setup:
	bash scripts/install-hooks.sh
	dotnet restore AMDN.sln --locked-mode

restore:
	dotnet restore AMDN.sln --locked-mode

build: restore
	dotnet build AMDN.sln --no-restore --configuration Release

test: build
	dotnet test AMDN.sln --no-build --configuration Release
	python3 -m unittest discover -s tests/Repository -v
	$(MAKE) crypto-test

lint: restore
	dotnet format AMDN.sln --verify-no-changes --no-restore
	git diff --check
	python3 scripts/check-docs.py
	bash -n scripts/install-hooks.sh scripts/install-security-tools.sh .githooks/pre-commit .githooks/pre-push

format:
	dotnet format AMDN.sln

verify: test lint

security-tools:
	bash scripts/install-security-tools.sh

security:
	.tools/actionlint -shellcheck= -pyflakes=
	.tools/gitleaks git --redact --no-banner --log-opts=--all

crypto-restore:
	npm ci --prefix clients/crypto --ignore-scripts --no-fund --no-audit
	npm ls --all --prefix clients/crypto

crypto-test:
	npm test --prefix clients/crypto

crypto-spike:
	npm run spike --prefix clients/crypto

crypto-browser:
	python3 clients/crypto/browser-smoke.py
