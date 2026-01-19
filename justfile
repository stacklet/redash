# private npm configuration - available within stacklet org
pkg_domain := "stacklet"
pkg_repo := "stacklet.client.ui"
pkg_owner := "653993915282"
pkg_region := "us-east-1"

_:
	@just --list --unsorted

# Install dependencies
install:
	poetry install --with dev
	yarn install --frozen-lockfile

# Run frontend unit tests
frontend-test:
	@echo "Running frontend unit tests..."
	yarn test
	@echo ""
	@echo "Running viz-lib tests..."
	cd viz-lib && yarn test
	@echo ""
	@echo "✓ All frontend tests passed!"

# Run backend tests locally using CI configuration
backend-test *flags:
	#!/usr/bin/env bash
	set -euo pipefail

	export COMPOSE_FILE=.ci/compose.ci.yaml
	export COMPOSE_PROJECT_NAME=redash
	export COMPOSE_DOCKER_CLI_BUILD=1
	export DOCKER_BUILDKIT=1

	echo "Building Docker images..."
	docker compose build --build-arg install_groups="main,all_ds,dev" --build-arg skip_frontend_build=true

	echo "Starting services..."
	docker compose up -d
	sleep 10

	echo "Creating test database and schema..."
	docker compose exec postgres psql -U postgres -c "CREATE DATABASE tests;" 2>/dev/null || echo "Database 'tests' already exists"
	docker compose exec postgres psql -U postgres -c "CREATE SCHEMA IF NOT EXISTS redash;" tests

	echo "Running tests..."
	docker compose run --rm redash tests --junitxml=junit.xml --cov-report=xml --cov=redash --cov-config=.coveragerc {{ flags }} tests/

	echo "Cleaning up..."
	docker compose down -v

pkg-login:
	#!/usr/bin/env bash
	set -euo pipefail

	# yarn auth will fail with private repos unless we will always send
	# auth information for private repo
	if [ -e "${HOME}/.npmrc" ]; then
		# delete any existing option for always-auth (cleaner)
		echo "Delete exisiting always-auth option/value in ~/.npmrc";
		npm config delete always-auth || true;
		# npm config set always-auth true won't work anymore as it's not a supported
		# options, so prepend always-auth = true to the top of the file
		if [ "$(uname)" = "Darwin" ]; then
			echo "Add always-auth = true to ~/.npmrc (on macOS)";
		  printf "1i\nalways-auth = true\n.\nw\n" | /bin/ed -s "${HOME}/.npmrc"
		else
			echo "Add always-auth = true to ~/.npmrc (on GNU/Linux)";
		   sed -i "1ialways-auth = true" "${HOME}/.npmrc";
		fi
	else
		# if no .npmrc then just make one with always-auth in it
		echo "Add always-auth = true to ~/.npmrc";
		echo "always-auth = true" > "${HOME}/.npmrc";
	fi

	# add npm repository
	aws codeartifact login \
		--tool npm \
		--domain {{pkg_domain}} \
		--domain-owner {{pkg_owner}} \
		--repository {{pkg_repo}} \
		--region {{pkg_region}} \
	;
