.PHONY: setup restore build test lint format verify

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

lint: restore
	dotnet format AMDN.sln --verify-no-changes --no-restore
	git diff --check
	python3 scripts/check-docs.py
	bash -n scripts/install-hooks.sh .githooks/pre-commit .githooks/pre-push

format:
	dotnet format AMDN.sln

verify: test lint
