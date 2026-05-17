package grpc

import (
	"context"
	"fmt"
	"log/slog"
	"runtime/debug"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// deadlineSafetyBelt wraps the inbound context with a server-side
// timeout if the caller did not set one. Workers normally set 75ms
// per ADR 0008 §3; this protects against misconfigured clients.
const deadlineSafetyBelt = 250 * time.Millisecond

// RecoveryInterceptor turns a panic in the handler into a gRPC
// Internal status, with the panic value + stack captured in a log
// line. Mounted first in the chain so it catches panics in any
// subsequent interceptor or in the handler itself.
func RecoveryInterceptor(logger *slog.Logger) grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (resp interface{}, err error) {
		defer func() {
			if r := recover(); r != nil {
				logger.ErrorContext(ctx, "grpc panic",
					"method", info.FullMethod,
					"panic", fmt.Sprintf("%v", r),
					"stack", string(debug.Stack()),
				)
				err = status.Error(codes.Internal, "internal server error")
			}
		}()
		return handler(ctx, req)
	}
}

// DeadlineInterceptor enforces a server-side deadline budget. If the
// caller already set a deadline (the worker SDK should), the
// interceptor is a no-op. Otherwise it bounds the handler at
// deadlineSafetyBelt so a misbehaving client cannot tie up a
// goroutine indefinitely.
func DeadlineInterceptor() grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (interface{}, error) {
		if _, ok := ctx.Deadline(); ok {
			return handler(ctx, req)
		}
		ctx, cancel := context.WithTimeout(ctx, deadlineSafetyBelt)
		defer cancel()
		return handler(ctx, req)
	}
}

// LoggingInterceptor emits one structured log line per request with
// method, duration, and status code. It DOES NOT touch req/resp
// bodies — credential payloads are not inspected, so no risk of
// secret material reaching the log surface.
func LoggingInterceptor(logger *slog.Logger) grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (interface{}, error) {
		start := time.Now()
		resp, err := handler(ctx, req)
		code := status.Code(err)
		logger.InfoContext(ctx, "grpc request",
			"method", info.FullMethod,
			"code", code.String(),
			"duration_ms", time.Since(start).Milliseconds(),
		)
		return resp, err
	}
}
