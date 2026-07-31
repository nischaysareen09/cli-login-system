// Command cli-login-system is the entrypoint for the containerized CLI
// login system: connects to the database, applies migrations, starts the
// bonus web UI in the background, and runs the interactive shell in the
// foreground (the shell is the primary, required interface).
package main

import (
	"database/sql"
	"log"
	"net/http"
	"os"
	"path/filepath"

	"cli-login-system/internal/auth"
	"cli-login-system/internal/cli"
	"cli-login-system/internal/db"
	"cli-login-system/internal/httpapi"
	"cli-login-system/internal/session"
)

func main() {
	dbPath := os.Getenv("DB_PATH")
	if dbPath == "" {
		dbPath = "./app.db"
	}

	conn, err := db.Connect(dbPath)
	if err != nil {
		log.Fatalf("failed to connect to database: %v", err)
	}
	defer conn.Close()

	if err := db.Migrate(conn); err != nil {
		log.Fatalf("failed to migrate database: %v", err)
	}

	startWebUI(conn)

	// Keep command history alongside the database file so it persists
	// across container restarts too, but it's not critical if this ends
	// up empty (":memory:" DB path, or a read-only mount) — history is a
	// convenience, not a requirement.
	historyFile := ""
	if dbPath != ":memory:" {
		historyFile = filepath.Join(filepath.Dir(dbPath), ".cli_history")
	}

	shell, err := cli.New(conn, historyFile)
	if err != nil {
		log.Fatalf("failed to start CLI: %v", err)
	}
	defer shell.Close()

	if err := shell.Run(); err != nil {
		log.Fatalf("cli error: %v", err)
	}
}

// startWebUI launches the bonus web UI in a background goroutine, sharing
// the same database (and therefore the same users/sessions) as the CLI.
// It never blocks or crashes the required CLI: if the port is unavailable,
// this logs a warning and the CLI continues to run normally on its own.
// Set WEB_UI_ENABLED=false to turn it off entirely.
func startWebUI(conn *sql.DB) {
	if os.Getenv("WEB_UI_ENABLED") == "false" {
		return
	}

	port := os.Getenv("WEB_UI_PORT")
	if port == "" {
		port = "8080"
	}

	handler := httpapi.NewHandler(conn, auth.DefaultLockoutConfig(), session.DefaultConfig())

	go func() {
		addr := ":" + port
		if err := http.ListenAndServe(addr, handler); err != nil {
			log.Printf("web UI not started (port %s): %v", port, err)
		}
	}()
}
