// Package db handles the SQLite connection and schema migrations for the
// CLI login system.
package db

import (
	"database/sql"
	_ "embed"
	"fmt"

	_ "github.com/mattn/go-sqlite3"
)

// migrationSQL is embedded at compile time so the binary doesn't depend on
// finding the .sql file on disk at runtime (still copied into the image by
// the Dockerfile for clarity/inspection, but not required for it to work).
//
//go:embed migrations/init.sql
var migrationSQL string

// Connect opens (and creates, if missing) the SQLite database at dbPath and
// returns a ready-to-use *sql.DB. It also enables foreign key enforcement,
// which SQLite disables by default.
func Connect(dbPath string) (*sql.DB, error) {
	if dbPath == "" {
		return nil, fmt.Errorf("db: dbPath must not be empty")
	}

	// _foreign_keys=on is required because SQLite ignores FOREIGN KEY
	// constraints unless explicitly turned on per-connection.
	dsn := fmt.Sprintf("file:%s?_foreign_keys=on", dbPath)

	conn, err := sql.Open("sqlite3", dsn)
	if err != nil {
		return nil, fmt.Errorf("db: failed to open database at %q: %w", dbPath, err)
	}

	// SQLite only supports one writer at a time; capping open connections
	// avoids "database is locked" errors under concurrent access.
	conn.SetMaxOpenConns(1)

	if err := conn.Ping(); err != nil {
		return nil, fmt.Errorf("db: failed to connect to database at %q: %w", dbPath, err)
	}

	return conn, nil
}

// Migrate applies the schema in migrations/init.sql. It is idempotent and
// safe to call every time the application starts.
func Migrate(conn *sql.DB) error {
	if _, err := conn.Exec(migrationSQL); err != nil {
		return fmt.Errorf("db: migration failed: %w", err)
	}
	return nil
}
