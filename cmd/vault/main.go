// cmd/vault is the composition root: load config from env, run
// embedded migrations on boot (ADR 0010 §3), wire every adapter,
// serve gRPC on :8443 + HTTP health endpoints on :8080. Graceful
// shutdown on SIGINT / SIGTERM.
//
// This is the first runnable artifact in the project. Every future
// binary (cmd/gateway, cmd/coffer-migrate) is expected to follow
// the same shape — config → migrate → wire → serve.
//
// TODO(future): mTLS on the gRPC listener (ADR 0002). Trial scope
// ships plaintext gRPC bound to localhost; production adds TLS
// material loading at boot.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"

	"github.com/tumultousRamen/coffer/internal/adapters/awskms"
	"github.com/tumultousRamen/coffer/internal/adapters/postgres"
	s3provider "github.com/tumultousRamen/coffer/internal/adapters/providers/s3"
	cgrpc "github.com/tumultousRamen/coffer/internal/transport/grpc"
	"github.com/tumultousRamen/coffer/internal/transport/grpc/pb"
	"github.com/tumultousRamen/coffer/internal/transport/rest"
	"github.com/tumultousRamen/coffer/internal/vault"

	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
)

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

	cfg, err := loadConfig()
	if err != nil {
		logger.Error("config", "err", err)
		os.Exit(2)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	if err := run(ctx, logger, cfg); err != nil {
		logger.Error("vault: fatal", "err", err)
		os.Exit(1)
	}
	logger.Info("vault: stopped cleanly")
}

func run(ctx context.Context, logger *slog.Logger, cfg *Config) error {
	// 1. Postgres + embedded migrations.
	db, err := postgres.Open(ctx, cfg.PGURL)
	if err != nil {
		return fmt.Errorf("postgres open: %w", err)
	}
	defer db.Close()
	if err := postgres.Up(ctx, db); err != nil {
		return fmt.Errorf("migrate up: %w", err)
	}
	logger.Info("postgres ready; migrations applied")

	// 2. AWS KMS.
	awsCfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(cfg.AWSRegion))
	if err != nil {
		return fmt.Errorf("aws config: %w", err)
	}
	kmsClient := kms.NewFromConfig(awsCfg)
	km := awskms.New(kmsClient, cfg.KMSKeyID)

	// 3. Vault wiring.
	tenants := postgres.NewTenantStore(db)
	store := postgres.NewCredentialStore(db)
	cache := vault.NewDEKCache(cfg.DEKCacheMaxItems, cfg.DEKCacheTTL)
	cryptor := vault.NewCryptor(km, cache)
	verifier := vault.NewGrantVerifier(cfg.GrantPubKey)

	// Provider registry: one Register call per known provider, all
	// wired here at the composition root. Adding Dropbox / GDrive /
	// Box later is one new import + one Register line. ADR 0001's
	// per-provider mode discrimination lives inside each adapter's
	// NeedsScheduledRefresh().
	providers := vault.NewProviderRegistry()
	providers.Register("s3", s3provider.New())

	svc := vault.NewService(store, tenants, cryptor, verifier, providers)
	logger.Info("vault service ready", "providers", []string{"s3"})

	// 4. gRPC server.
	grpcSrv := grpc.NewServer(
		grpc.MaxRecvMsgSize(1<<20),
		grpc.ChainUnaryInterceptor(
			cgrpc.RecoveryInterceptor(logger),
			cgrpc.DeadlineInterceptor(),
			cgrpc.LoggingInterceptor(logger),
		),
	)
	pb.RegisterVaultServer(grpcSrv, cgrpc.NewVaultServer(svc, verifier))

	// Standard gRPC health service so the ALB target group can probe
	// the gRPC listener directly (PRD 0009 — the gRPC target group
	// can't health-check via HTTP /healthz on the REST port). Empty
	// service name = overall server health.
	hsrv := health.NewServer()
	hsrv.SetServingStatus("", healthpb.HealthCheckResponse_SERVING)
	healthpb.RegisterHealthServer(grpcSrv, hsrv)

	grpcLis, err := net.Listen("tcp", cfg.GRPCListen)
	if err != nil {
		return fmt.Errorf("grpc listen %s: %w", cfg.GRPCListen, err)
	}

	// 5. HTTP server: /healthz + /readyz + REST credential lifecycle
	// (ADR 0007 §2; PRD 0007). All routes share one ServeMux, one
	// listener, one graceful-shutdown path. Trial-mode REST auth is
	// the X-User-Id header — production gateway will JWT-verify and
	// inject this. mTLS on this listener is the same follow-on PRD
	// as gRPC mTLS (see TODO at file head).
	httpMux := http.NewServeMux()
	httpMux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	httpMux.HandleFunc("/readyz", readyzHandler(db, kmsClient, cfg.KMSKeyID))
	rest.NewHandler(svc, logger).Register(httpMux)
	httpSrv := &http.Server{
		Addr:              cfg.HTTPListen,
		Handler:           httpMux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	// 6. Serve both, shut down on context cancel.
	g, gCtx := errgroup.WithContext(ctx)
	g.Go(func() error {
		logger.Info("grpc serving", "addr", cfg.GRPCListen)
		return grpcSrv.Serve(grpcLis)
	})
	g.Go(func() error {
		logger.Info("http serving", "addr", cfg.HTTPListen)
		if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			return err
		}
		return nil
	})
	g.Go(func() error {
		<-gCtx.Done()
		logger.Info("shutdown signal received")
		grpcSrv.GracefulStop()
		shutCtx, shutCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer shutCancel()
		_ = httpSrv.Shutdown(shutCtx)
		return nil
	})
	if err := g.Wait(); err != nil && err != context.Canceled {
		return err
	}
	return nil
}

// readyzHandler runs the dependency checks in parallel: PG ping + KMS
// DescribeKey. Either failure → 503 with a one-line body naming the
// dep. Refresh-worker heartbeat is not checked because the refresh
// worker doesn't exist yet (TODO: provider PRD).
func readyzHandler(db pinger, kmsClient *kms.Client, keyAlias string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 1*time.Second)
		defer cancel()

		g, gCtx := errgroup.WithContext(ctx)
		g.Go(func() error { return db.PingContext(gCtx) })
		g.Go(func() error {
			_, err := kmsClient.DescribeKey(gCtx, &kms.DescribeKeyInput{KeyId: aws.String(keyAlias)})
			return err
		})
		if err := g.Wait(); err != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			fmt.Fprintf(w, "readyz: %v\n", err)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	}
}

// pinger is the slice of *sql.DB this binary needs for readyz.
// Declared so main_test.go can substitute a fake.
type pinger interface {
	PingContext(ctx context.Context) error
}
