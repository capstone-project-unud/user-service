package main

import (
	"capstone/user-service/internal/httpapi"
	"capstone/user-service/internal/store"
	"context"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/joho/godotenv"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	_ = godotenv.Load()
	if os.Getenv("DATABASE_URL") == "" || os.Getenv("AUTH_SERVICE_URL") == "" || len(os.Getenv("AUTH_INTERNAL_TOKEN")) < 32 || len(os.Getenv("USER_INTERNAL_TOKEN")) < 32 {
		log.Fatal("Database, auth service URL and internal tokens (32+ characters) are required")
	}
	port := os.Getenv("PORT")
	if port == "" {
		port = "8082"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	pc, err := pgxpool.ParseConfig(os.Getenv("DATABASE_URL"))
	if err != nil {
		log.Fatal("Invalid database configuration")
	}
	pc.MaxConns = 5
	db, err := pgxpool.NewWithConfig(ctx, pc)
	if err != nil {
		log.Fatal("Cannot initialize database")
	}
	defer db.Close()
	if db.Ping(ctx) != nil {
		log.Fatal("Cannot connect to database")
	}
	app := httpapi.New(store.Store{DB: db})
	stop, done := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer done()
	go func() { <-stop.Done(); _ = app.ShutdownWithTimeout(10 * time.Second) }()
	host := os.Getenv("BIND_HOST")
	if host == "" {
		host = "127.0.0.1"
	}
	if err = app.Listen(host + ":" + port); err != nil {
		log.Fatal(err)
	}
}
