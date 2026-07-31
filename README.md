# CLI Login System

A containerized command-line authentication system with user registration,
password login, optional TOTP-based 2FA (Google Authenticator compatible),
account lockout, and session management — built in Go, backed by SQLite,
and packaged to run entirely in Docker.

## Features

- **Registration & login** with bcrypt-hashed passwords (never stored or
  logged in plaintext)
- **Optional TOTP 2FA**, compatible with Google Authenticator and similar
  apps — enabling it requires confirming a real code first, so you can't
  lock yourself out with a half-finished setup
- **Account lockout** after too many failed login attempts, with a
  configurable threshold and cooldown
- **Session management** with a configurable timeout; sessions are
  validated (and expired ones cleaned up) on every protected command
- **Interactive shell** with command history and tab-completion
  (via [chzyer/readline](https://github.com/chzyer/readline)), with
  different commands available before vs. after login
- **A real terminal UI, not a bare prompt**: a styled startup banner,
  color-coded success/error/info messages, boxed account details, and —
  when setting up 2FA — an actual scannable QR code rendered directly in
  the terminal (via [mdp/qrterminal](https://github.com/mdp/qrterminal)),
  not just a raw secret string. Colors auto-disable when output isn't a
  real terminal (e.g. piped to a file) or when `NO_COLOR` is set.
- **Persistent storage**: SQLite database file lives in a Docker volume,
  so your data survives container restarts

## Requirements

- [Docker](https://docs.docker.com/get-docker/) and Docker Compose (v2,
  the `docker compose` subcommand — or `docker-compose` v1 also works)
- To build/run outside Docker instead: Go 1.22+ and a C compiler (gcc),
  since the SQLite driver uses cgo

## Quick start (Docker)

```bash
git clone <this-repo-url>
cd cli-login-system

docker-compose build
docker-compose run --rm app
```

**Important:** use `docker-compose run --rm app`, not `docker-compose up`.
This is an interactive terminal application, not a background service —
`run` is what allocates a real terminal for it. `up` would start it
detached with no way to type into it.

You'll land in the shell:

```
=== CLI Login System ===
Type 'help' to see available commands.
login>
```

Type `help` at any point to see the commands available in your current
state (logged out vs. logged in). Your data persists in a Docker volume
(`dbdata`) across restarts — running `docker-compose run --rm app` again
will remember users you already registered.

To wipe all data and start fresh:

```bash
docker-compose down -v
```

## Usage guide

### Before logging in

| Command    | What it does                                             |
|------------|-----------------------------------------------------------|
| `register` | Create a new account (prompts for username + password)    |
| `login`    | Log in with username/password (+ a 2FA code, if enabled) |
| `help`     | Show available commands                                   |
| `exit`     | Quit the program                                           |

### After logging in

| Command       | What it does                                        |
|---------------|------------------------------------------------------|
| `whoami`      | Show your account details                             |
| `enable-2fa`  | Turn on TOTP-based two-factor authentication          |
| `disable-2fa` | Turn off two-factor authentication                     |
| `logout`      | End your session and return to the login prompt       |
| `help`        | Show available commands                                |

Passwords and TOTP secrets are never echoed to the terminal while typing.

### Example session

```
login> register
New username: alice
New password:
Confirm password:
Account "alice" created successfully. You can now 'login'.

login> login
Username: alice
Password:

Welcome, alice!
--- Account details ---
Username:           alice
Registered on:      2026-07-31 10:00:00 UTC
2FA status:         disabled
Session expires at: 2026-07-31 10:15:00 UTC
Last login:         2026-07-31 10:00:00 UTC

alice> enable-2fa
Scan this URL into Google Authenticator (or a compatible app):
  otpauth://totp/CLI-Login-System:alice?algorithm=SHA1&digits=6&issuer=CLI-Login-System&period=30&secret=ABCD...
Or enter this secret manually:
  ABCD...
Enter the 6-digit code from your app to confirm: 123456
Two-factor authentication is now enabled.

alice> logout
Logged out. Goodbye, alice!
```

On the next `login`, since 2FA is now enabled, you'll be prompted for a
6-digit code after your password.

## Bonus: Web UI

The CLI is the required, primary interface — but a small web UI also runs
alongside it automatically, sharing the exact same database, users, and
sessions. It's not a separate product; it's the same backend logic
(`internal/auth`, `internal/session`) exposed a second way, through
`internal/httpapi`.

With the container running (`docker-compose run --rm app`), open:

```
http://localhost:8080
```

It supports the full flow: register, login, 2FA setup with a real
scannable QR code, whoami-equivalent account details, and logout. A user
registered in the CLI can log in on the web UI and vice versa — they're
the same accounts.

To disable it entirely, set `WEB_UI_ENABLED=false`. It never blocks or
crashes the CLI — if the port can't be bound, it logs a warning and the
CLI keeps running normally on its own.

**Scope note:** this is a bonus feature layered on top of the required
CLI, not a hardened production web service. It has no TLS and only a
lightweight CSRF mitigation (requiring `Content-Type: application/json`,
which a plain HTML form can't send cross-site). A real deployment would
add HTTPS, CSRF tokens, and rate limiting at the HTTP layer in addition to
the account lockout already enforced by the shared `auth` package.

## Configuration

Set these as environment variables (already wired up in
`docker-compose.yml`; see `.env.example` for a template):

| Variable                   | Default | Meaning                                              |
|-----------------------------|---------|-------------------------------------------------------|
| `DB_PATH`                   | `/data/app.db` | Path to the SQLite database file             |
| `SESSION_TIMEOUT_MINUTES`   | `15`    | How long a login session stays valid                  |
| `MAX_FAILED_ATTEMPTS`       | `5`     | Failed logins before an account locks                 |
| `LOCKOUT_DURATION_MINUTES`  | `5`     | How long an account stays locked after too many fails |
| `WEB_UI_ENABLED`            | `true`  | Turn the bonus web UI on/off                          |
| `WEB_UI_PORT`               | `8080`  | Port the web UI listens on inside the container        |

## Architecture

```
cmd/main.go              Entrypoint: connects DB, runs migrations, starts the web UI
                          in the background, then runs the shell in the foreground
internal/
  auth/                   Password hashing, registration, login + lockout, TOTP
  session/                Session creation, validation, expiry, logout
  db/                     SQLite connection, schema migration, all SQL queries
  models/                 User and Session data structs
  cli/                    Readline shell, command dispatch, pre/post-login commands
  httpapi/                Bonus web UI: JSON API + embedded static page, built on
                          top of the same auth/session packages the CLI uses
```

Each package has a single responsibility and depends only on the layers
below it: `cli` and `httpapi` are two independent frontends over the exact
same `auth` + `session` logic, which both use `db` for persistence.
`models` is shared data structures with no logic of its own. Neither
frontend duplicates any authentication logic — a bug fix or security
change in `internal/auth` automatically applies to both the CLI and the
web UI.

### Database schema

Two tables, created automatically on first run
(`internal/db/migrations/init.sql`):

```sql
CREATE TABLE users (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    username        TEXT NOT NULL UNIQUE,
    password_hash   TEXT NOT NULL,
    totp_secret     TEXT,
    totp_enabled    INTEGER NOT NULL DEFAULT 0,
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    locked_until    TEXT,
    created_at      TEXT NOT NULL,
    last_login_at   TEXT
);

CREATE TABLE sessions (
    token       TEXT PRIMARY KEY,
    user_id     INTEGER NOT NULL,
    created_at  TEXT NOT NULL,
    expires_at  TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
```

## Security notes

- Passwords are hashed with **bcrypt** (cost factor 12) — the plaintext
  password is never stored, logged, or transmitted anywhere after the
  initial input.
- Failed-login and "wrong username" cases both return the same generic
  error message, so the system doesn't reveal whether a username exists.
- A locked account rejects **even the correct password** until the
  lockout window passes, and lock-status is checked before password
  verification so a lockout can't be used to infer whether a guessed
  password was right.
- 2FA secrets are only activated after the user proves they've correctly
  set up their authenticator app by submitting a real generated code.
- Session tokens are random UUIDs, stored server-side with an expiry;
  expired sessions are actively cleaned up on next use rather than
  trusted client-side.

## Running tests

```bash
# Requires CGO (the SQLite driver uses it)
CGO_ENABLED=1 go test ./... -v
```

Tests run against real in-memory SQLite databases (not mocks), and cover:
- Password hashing/verification (`internal/auth/password_test.go`)
- Registration and login, including duplicate usernames, weak passwords,
  and invalid credentials (`internal/auth/auth_test.go`)
- Account lockout: locking after N failures, staying locked even with the
  correct password, auto-unlocking after the window passes, and counter
  reset on success (`internal/auth/lockout_test.go`)
- TOTP 2FA: secret generation, confirm-to-activate flow, rejecting wrong
  codes, and disable (`internal/auth/totp_test.go`)
- Sessions: creation, validation, real timing-based expiry, and logout
  (`internal/session/session_test.go`)

The interactive CLI itself (`internal/cli`) was verified by scripting the
compiled binary through a real pseudo-terminal end-to-end, including a
full 2FA setup using a genuinely computed TOTP code — not just unit tests
against the underlying logic.

## Running locally without Docker

```bash
export CGO_ENABLED=1
export DB_PATH=./app.db
go run ./cmd
```

## Project layout notes

- `go.mod` / `go.sum` — Go module files; `go-sqlite3` requires cgo, so a
  C compiler must be available wherever this is built (already handled
  in the Dockerfile).
- The database schema is embedded into the compiled binary at build time
  (`//go:embed migrations/init.sql`), so the binary is fully
  self-contained — no separate SQL file needs to ship alongside it.
