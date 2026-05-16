// Smoke test for coffer foundation infra.
// Round-trip: KMS encrypt -> Postgres insert -> Postgres select -> KMS decrypt -> assert.
// Throwaway. Superseded by PRD 0002+ hexagonal scaffold.
package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"os"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
)

const (
	keyAlias  = "alias/coffer-dev-master"
	plaintext = "hello-coffer"
)

func main() {
	ctx := context.Background()

	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		log.Fatal("ENV: DATABASE_URL not set (source .env.local first, or run via `make smoke`)")
	}

	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		log.Fatalf("KMS: load AWS config (is AWS_PROFILE set and `aws sso login` fresh?): %v", err)
	}
	kmsClient := kms.NewFromConfig(cfg)

	encOut, err := kmsClient.Encrypt(ctx, &kms.EncryptInput{
		KeyId:     aws.String(keyAlias),
		Plaintext: []byte(plaintext),
	})
	if err != nil {
		log.Fatalf("KMS: encrypt with %s: %v", keyAlias, err)
	}

	// Supabase transaction-mode pooler (port 6543) breaks pgx's default
	// prepared-statement cache: queries land on different backend sessions,
	// stmt cache thinks the statement isn't registered, server says it is.
	// QueryExecModeExec skips the cache and uses simple Exec/Query.
	pgxCfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		log.Fatalf("PG: parse DSN: %v", err)
	}
	pgxCfg.DefaultQueryExecMode = pgx.QueryExecModeExec
	db := stdlib.OpenDB(*pgxCfg)
	defer db.Close()

	if err := db.PingContext(ctx); err != nil {
		log.Fatalf("PG: ping (wrong DSN, pooler port, or password?): %v", err)
	}

	var id string
	err = db.QueryRowContext(ctx,
		"INSERT INTO credentials_smoketest (ciphertext) VALUES ($1) RETURNING id",
		encOut.CiphertextBlob,
	).Scan(&id)
	if err != nil {
		log.Fatalf("PG: insert (does table credentials_smoketest exist?): %v", err)
	}

	var got []byte
	err = db.QueryRowContext(ctx,
		"SELECT ciphertext FROM credentials_smoketest WHERE id = $1",
		id,
	).Scan(&got)
	if errors.Is(err, sql.ErrNoRows) {
		log.Fatalf("ASSERT: row %s missing after insert -- read path broken", id)
	}
	if err != nil {
		log.Fatalf("PG: select: %v", err)
	}

	decOut, err := kmsClient.Decrypt(ctx, &kms.DecryptInput{
		CiphertextBlob: got,
		KeyId:          aws.String(keyAlias),
	})
	if err != nil {
		log.Fatalf("KMS: decrypt: %v", err)
	}

	if string(decOut.Plaintext) != plaintext {
		log.Fatalf("ASSERT: roundtrip mismatch -- want %q got %q", plaintext, string(decOut.Plaintext))
	}

	fmt.Println("OK")
}
