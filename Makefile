.PHONY: smoke smoke-negative smoke-cleanup tidy test integration migrate-up migrate-down check-imports check proto run keygen gen-keys mint-grant sanity-test docker-build docker-run demo-s3 demo-worker demo-oauth-dropbox demo-oauth-box demo-oauth-gdrive demo-oauth

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

# Generate an ed25519 keypair for trial-mode capability-token signing.
# PUBLIC half → COFFER_GRANT_PUBKEY_PEM (vault verifies). PRIVATE half
# → wherever the demo / control plane mints tokens. Production keys
# come from the control plane; this target is dev-only.
keygen:
	@go run ./cmd/keygen

# Alias for `make keygen`. PRD 0008.5 / local-sanity runbook refer to
# this name; keep both so older docs and the runbook both work.
gen-keys: keygen

# Mint a capability token via cmd/mint-grant. Wraps vault.MintGrant
# (see docs/runbook/local-sanity.md §5). Reads COFFER_GRANT_PRIVKEY_PEM
# from .env.local; flags pin user-id, credential-ids, ttl. Prints the
# JWT to stdout with no trailing newline so it pipes cleanly:
#
#   TOKEN=$$(make mint-grant USER=divya-test IDS=01928abc... TTL=15m)
#
mint-grant:
	@if [ -z "$$USER" ] || [ -z "$$IDS" ]; then \
	  echo "Usage: make mint-grant USER=<user-id> IDS=<id1,id2,...> [TTL=15m]"; exit 1; fi
	@bash -c 'set -a; [ -f .env.local ] && source .env.local; set +a; \
	  go run ./cmd/mint-grant --user-id "$$USER" --ids "$$IDS" --ttl "$${TTL:-15m}"'

# Walk the full REST lifecycle against a running `make run`. Reads
# real S3 keys from COFFER_TEST_AWS_* env vars (see runbook). Prints
# PASS/FAIL per step; exits non-zero on first failure.
sanity-test:
	@bash -c 'set -a; [ -f .env.local ] && source .env.local; set +a; \
	  bash scripts/sanity-test.sh'

# Aggregate gate run by the PR template.
check: test check-imports

# Build the production Docker image (PRD 0009). Distroless final
# stage; ~25-30 MB. Same artifact the GH Actions deploy workflow
# pushes to ECR; building locally verifies the Dockerfile before
# pushing to main.
docker-build:
	docker build -t coffer-vault:latest .

# Run the just-built image against .env.local. Maps the same ports
# as `make run` so scripts/sanity-test.sh works against it
# unchanged. Requires AWS credentials reachable from the container:
# the simplest path is to mount ~/.aws read-only.
docker-run:
	@bash -c 'set -a; [ -f .env.local ] && source .env.local; set +a; \
	  docker run --rm -it \
	    -p 8080:8080 -p 8443:8443 \
	    -e COFFER_PG_URL \
	    -e COFFER_AWS_REGION \
	    -e COFFER_AWS_KMS_KEY_ID \
	    -e COFFER_GRANT_PUBKEY_PEM \
	    -e AWS_ACCESS_KEY_ID \
	    -e AWS_SECRET_ACCESS_KEY \
	    -e AWS_SESSION_TOKEN \
	    -e AWS_PROFILE \
	    -v $$HOME/.aws:/home/nonroot/.aws:ro \
	    coffer-vault:latest'

# ────────────────────────────────────────────────────────────────────
# Demo runners — see demo.md (gitignored) for the patter.
# All accept HOST=<url> override; default is http://localhost:8080.
# Set GRPC=<host:port> override for the worker-fetch demo; default
# is localhost:8443. Deployed: GRPC=<nlb-dns>:443.
# ────────────────────────────────────────────────────────────────────

# Phase 2-3: S3 lifecycle (POST/GET/PUT/DELETE, valid + garbage creds).
demo-s3:
	@bash scripts/demo/01-s3-lifecycle.sh $(if $(HOST),--host $(HOST))

# Phase 4-5: worker gRPC fetch + end-to-end S3 access via returned plaintext.
demo-worker:
	@COFFER_GRPC_HOST=$(or $(GRPC),localhost:8443) bash scripts/demo/02-worker-fetch.sh $(if $(HOST),--host $(HOST))

# Phase 6 slices: each OAuth provider's broker-mode lifecycle.
demo-oauth-dropbox:
	@bash scripts/demo/03-oauth-dropbox.sh $(if $(HOST),--host $(HOST))

demo-oauth-box:
	@COFFER_GRPC_HOST=$(or $(GRPC),localhost:8443) bash scripts/demo/04-oauth-box-rotation.sh $(if $(HOST),--host $(HOST))

demo-oauth-gdrive:
	@bash scripts/demo/05-oauth-gdrive.sh $(if $(HOST),--host $(HOST))

# Run all three OAuth demos in sequence.
demo-oauth: demo-oauth-dropbox demo-oauth-gdrive demo-oauth-box
