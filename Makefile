.PHONY: smoke smoke-negative smoke-cleanup tidy test integration migrate-up migrate-down check-imports check proto run

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
	go test -race ./...

# Run integration tests against real infra. Each adapter is
# self-gating:
#   * awskms — t.Skip if AWS_PROFILE is unset
#   * postgres — TestMain prints "DATABASE_URL not set; skipping" and
#     exits 0 if DATABASE_URL is unset
# So you can run a subset by exporting just one env var, or run both
# with .env.local sourced below.
integration:
	@bash -c 'set -a; [ -f .env.local ] && source .env.local; set +a; \
	  go test -tags integration -race ./internal/adapters/awskms/... ./internal/adapters/postgres/... ./internal/adapters/providers/...'

# Apply embedded migrations (creates tenants + credentials tables).
migrate-up:
	@bash -c 'set -a; [ -f .env.local ] && source .env.local; set +a; \
	  if [ -z "$$DATABASE_URL" ]; then echo "ENV: DATABASE_URL missing"; exit 1; fi; \
	  go run ./cmd/migrate up'

# Roll back the most recent migration.
migrate-down:
	@bash -c 'set -a; [ -f .env.local ] && source .env.local; set +a; \
	  if [ -z "$$DATABASE_URL" ]; then echo "ENV: DATABASE_URL missing"; exit 1; fi; \
	  go run ./cmd/migrate down'

# Enforce hexagonal one-way imports (ADR 0010 §1):
# internal/vault must not import from internal/adapters or internal/transport.
# internal/transport must not import from internal/adapters (composition root
# in cmd/vault is the only place both layers may be wired together).
# Fails non-zero on any match.
check-imports:
	@vault_matches=$$(grep -rE 'github.com/tumultousRamen/coffer/internal/(adapters|transport)' internal/vault || true); \
	if [ -n "$$vault_matches" ]; then \
	  echo "FAIL: internal/vault imports forbidden package:"; \
	  echo "$$vault_matches"; \
	  exit 1; \
	fi; \
	transport_matches=$$(grep -rE 'github.com/tumultousRamen/coffer/internal/adapters' internal/transport || true); \
	if [ -n "$$transport_matches" ]; then \
	  echo "FAIL: internal/transport imports forbidden package:"; \
	  echo "$$transport_matches"; \
	  exit 1; \
	fi; \
	echo "imports OK: internal/vault + internal/transport are clean"

# Regenerate the Go bindings from the protobuf source. Requires
# `protoc` plus the protoc-gen-go / protoc-gen-go-grpc plugins on PATH.
# CI does not regenerate; the committed .pb.go files are the artifact.
proto:
	@PATH="$$(go env GOPATH)/bin:$$PATH" protoc -I api --go_out=. --go-grpc_out=. api/coffer/v1/vault.proto
	@rm -rf internal/transport/grpc/pb
	@mkdir -p internal/transport/grpc/pb
	@mv github.com/tumultousRamen/coffer/internal/transport/grpc/pb/* internal/transport/grpc/pb/
	@rm -rf github.com
	@echo "proto: regenerated internal/transport/grpc/pb/"

# Boot the vault binary against .env.local. Expects all COFFER_*
# env vars to be set (see cmd/vault/config.go for the full list).
run:
	@bash -c 'set -a; [ -f .env.local ] && source .env.local; set +a; \
	  go run ./cmd/vault'

# Aggregate gate run by the PR template.
check: test check-imports
