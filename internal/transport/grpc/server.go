// Package grpc — VaultServer is the gRPC transport adapter for the
// worker-facing read path. It implements the generated VaultServer
// interface by delegating to vault.Service.FetchForWorker.
//
// The transport layer's job is narrow: parse the request, perform
// fast pre-checks that don't need to enter the domain (bound on
// number of IDs; token signature/expiry), invoke the service, map
// returned errors to gRPC status codes. Per-ID scope checks happen
// here AND in the service (defense in depth) — a misconfigured
// transport that bypasses scope cannot bypass the service.
//
// No retry logic server-side (per ADR 0008 §3); retries are the
// client SDK's responsibility.
package grpc

import (
	"context"
	"errors"
	"fmt"

	"github.com/tumultousRamen/coffer/internal/transport/grpc/pb"
	"github.com/tumultousRamen/coffer/internal/vault"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"
)

// maxRequestedIDs is the per-request bound on credential_ids (ADR
// 0007 §1). Real transfer jobs use exactly 2; we allow up to 8 to
// leave headroom for future job shapes.
const maxRequestedIDs = 8

// VaultServer wires the generated VaultServer interface onto a
// vault.Service + GrantVerifier. Both collaborators are required.
type VaultServer struct {
	pb.UnimplementedVaultServer
	svc      *vault.Service
	verifier *vault.GrantVerifier
}

// NewVaultServer constructs a VaultServer. svc handles the
// orchestration; verifier is held separately because the transport
// pre-checks need to inspect token claims before the service is
// invoked.
func NewVaultServer(svc *vault.Service, verifier *vault.GrantVerifier) *VaultServer {
	return &VaultServer{svc: svc, verifier: verifier}
}

// GetCredentials implements coffer.v1.Vault/GetCredentials.
//
// Pre-checks before invoking the service:
//  1. len(credential_ids) > maxRequestedIDs → InvalidArgument
//  2. token verify → Unauthenticated on any grant sentinel
//  3. any requested ID not in allowed claim → PermissionDenied
//
// Service errors are mapped per the table in the PRD:
//
//	ErrGrant* → Unauthenticated
//	ErrUnauthorized → PermissionDenied
//	ErrNotFound → NotFound (whole request)
//	ErrTenantNotProvisioned → FailedPrecondition
//	(other) → Internal
//
// Error messages elide internal detail (no row IDs, no SQL).
func (s *VaultServer) GetCredentials(
	ctx context.Context,
	req *pb.GetCredentialsRequest,
) (*pb.GetCredentialsResponse, error) {
	if len(req.GetCredentialIds()) == 0 {
		return nil, status.Error(codes.InvalidArgument, "credential_ids required")
	}
	if len(req.GetCredentialIds()) > maxRequestedIDs {
		return nil, status.Errorf(codes.InvalidArgument, "credential_ids: too many (max %d)", maxRequestedIDs)
	}

	_, allowedIDs, err := s.verifier.Verify(req.GetGrantToken())
	if err != nil {
		return nil, mapStatus(err)
	}
	allowed := make(map[string]struct{}, len(allowedIDs))
	for _, id := range allowedIDs {
		allowed[id] = struct{}{}
	}
	for _, id := range req.GetCredentialIds() {
		if _, ok := allowed[id]; !ok {
			return nil, status.Error(codes.PermissionDenied, "credential_id not authorized by grant")
		}
	}

	creds, err := s.svc.FetchForWorker(ctx, req.GetGrantToken(), req.GetCredentialIds())
	if err != nil {
		return nil, mapStatus(err)
	}

	resp := &pb.GetCredentialsResponse{
		Credentials: make([]*pb.Credential, 0, len(creds)),
	}
	for _, c := range creds {
		md, err := structpb.NewStruct(c.Metadata)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "marshal metadata for %s: unmarshalable", c.ID)
		}
		resp.Credentials = append(resp.Credentials, &pb.Credential{
			Id:       c.ID,
			Provider: c.Provider,
			Label:    c.Label,
			Secret:   c.Secret.Reveal(),
			Metadata: md,
		})
	}
	return resp, nil
}

// mapStatus narrows vault sentinels to gRPC status errors per the
// PRD table. Internal detail is elided; the worker only sees the
// status code and a generic message.
func mapStatus(err error) error {
	switch {
	case errors.Is(err, vault.ErrGrantExpired):
		return status.Error(codes.Unauthenticated, "grant expired")
	case errors.Is(err, vault.ErrGrantSignature):
		return status.Error(codes.Unauthenticated, "grant signature invalid")
	case errors.Is(err, vault.ErrGrantWrongAudience):
		return status.Error(codes.Unauthenticated, "grant audience mismatch")
	case errors.Is(err, vault.ErrGrantWrongIssuer):
		return status.Error(codes.Unauthenticated, "grant issuer mismatch")
	case errors.Is(err, vault.ErrGrantMissingClaim):
		return status.Error(codes.Unauthenticated, "grant missing required claim")
	case errors.Is(err, vault.ErrGrantMalformed):
		return status.Error(codes.Unauthenticated, "grant malformed")
	case errors.Is(err, vault.ErrUnauthorized):
		return status.Error(codes.PermissionDenied, "credential_id not authorized")
	case errors.Is(err, vault.ErrNotFound):
		return status.Error(codes.NotFound, "credential not found")
	case errors.Is(err, vault.ErrTenantNotProvisioned):
		return status.Error(codes.FailedPrecondition, "tenant not provisioned")
	case errors.Is(err, context.DeadlineExceeded):
		return status.Error(codes.DeadlineExceeded, "deadline exceeded")
	case errors.Is(err, context.Canceled):
		return status.Error(codes.Canceled, "canceled")
	}
	return status.Error(codes.Internal, fmt.Sprintf("internal: %v", err))
}
