.PHONY: smoke smoke-negative smoke-cleanup tidy test check-imports check

# Run the smoke test. Expected: prints OK.
smoke:
	@bash -c 'set -a; [ -f .env.local ] && source .env.local; set +a; \
	  if [ -z "$$DATABASE_URL" ]; then echo "ENV: DATABASE_URL missing -- copy .env.local.example to .env.local"; exit 1; fi; \
	  go run ./cmd/smoketest'

# Negative test: drop the table, run smoke, expect "PG: insert ... relation ... does not exist".
# Proves the insert path is genuinely exercised, not stubbed.
# Auto-recreates the table afterwards so smoke is re-runnable.
smoke-negative:
	@bash -c 'set -a; [ -f .env.local ] && source .env.local; set +a; \
	  echo "--- dropping table ---"; \
	  psql "$$DATABASE_URL" -c "DROP TABLE credentials_smoketest" >/dev/null; \
	  echo "--- expecting failure ---"; \
	  go run ./cmd/smoketest; echo "exit=$$?"; \
	  echo "--- recreating table ---"; \
	  psql "$$DATABASE_URL" -f db/smoketest.sql >/dev/null; \
	  echo "ready: re-run \`make smoke\` -- expect OK"'

# Clear accumulated smoke-test rows. Cosmetic; not a test.
smoke-cleanup:
	@bash -c 'set -a; [ -f .env.local ] && source .env.local; set +a; \
	  psql "$$DATABASE_URL" -c "TRUNCATE credentials_smoketest"'

tidy:
	go mod tidy

# Run all Go tests. No infra required.
test:
	go test ./...

# Enforce hexagonal one-way imports (ADR 0010 §1):
# internal/vault is the core and must not import from internal/adapters
# or internal/transport. Fails non-zero on any match.
check-imports:
	@matches=$$(grep -rE 'github.com/tumultousRamen/coffer/internal/(adapters|transport)' internal/vault || true); \
	if [ -n "$$matches" ]; then \
	  echo "FAIL: internal/vault imports forbidden package:"; \
	  echo "$$matches"; \
	  exit 1; \
	fi; \
	echo "imports OK: internal/vault is clean"

# Aggregate gate run by the PR template.
check: test check-imports
