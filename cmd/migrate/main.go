// migrate is a thin CLI around internal/adapters/postgres migrations.
// It exists so ops have a single command pre-service-binary; once the
// service binary lands it imports the same postgres.Up function on
// boot (per ADR 0010 §3) so there's exactly one migration code path.
package main

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/tumultousRamen/coffer/internal/adapters/postgres"
)

func main() {
	if len(os.Args) != 2 {
		usage()
	}
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		log.Fatal("ENV: DATABASE_URL not set (source .env.local first)")
	}

	ctx := context.Background()
	db, err := postgres.Open(ctx, dsn)
	if err != nil {
		log.Fatalf("open: %v", err)
	}
	defer db.Close()

	switch os.Args[1] {
	case "up":
		if err := postgres.Up(ctx, db); err != nil {
			log.Fatalf("up: %v", err)
		}
		fmt.Println("migrate up: OK")
	case "down":
		if err := postgres.Down(ctx, db); err != nil {
			log.Fatalf("down: %v", err)
		}
		fmt.Println("migrate down: OK")
	default:
		usage()
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: migrate up | migrate down")
	os.Exit(2)
}
