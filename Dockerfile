# syntax=docker/dockerfile:1.7
#
# Multi-stage build for cmd/vault (PRD 0009).
#
# Build stage uses the official golang image to compile a fully static
# binary (CGO_ENABLED=0). Final stage is distroless/static (no shell,
# no package manager) running as a non-root user.
#
# Embedded migrations live in internal/adapters/postgres (ADR 0010 §3);
# they ship inside the binary, so the final image only needs /vault.
#
# Both REST (8080) and gRPC (8443) ports are EXPOSEd; ALB target groups
# wire to these in Terraform.

FROM golang:1.26-alpine AS build
WORKDIR /src

# Cache go mod downloads in a separate layer so source changes don't
# bust the dependency cache.
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath -ldflags="-s -w" -o /out/vault ./cmd/vault

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/vault /vault
USER nonroot:nonroot
EXPOSE 8080 8443
ENTRYPOINT ["/vault"]
