// Package cli implements the interactive command-line shell for the login
// system: the readline loop, tab completion, and command dispatch for both
// the pre-login and post-login command sets.
package cli

import (
	"database/sql"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/chzyer/readline"

	"cli-login-system/internal/auth"
	"cli-login-system/internal/models"
	"cli-login-system/internal/session"
)

var preLoginCommands = []string{"register", "login", "help", "exit"}
var postLoginCommands = []string{"whoami", "enable-2fa", "disable-2fa", "logout", "help"}

var errNotLoggedIn = fmt.Errorf("not logged in; use 'login' first")

// CLI holds all state for one running session of the shell: the DB
// connection, configured security policies, the readline instance, and
// (once logged in) the current user and their session token.
type CLI struct {
	conn       *sql.DB
	lockoutCfg auth.LockoutConfig
	sessionCfg session.Config
	rl         *readline.Instance

	currentUser      *models.User
	sessionToken     string
	sessionExpiresAt time.Time
}

// New builds a CLI ready to Run(). historyFile may be empty, in which case
// command history is kept in memory only for the life of the process.
func New(conn *sql.DB, historyFile string) (*CLI, error) {
	c := &CLI{
		conn:       conn,
		lockoutCfg: auth.DefaultLockoutConfig(),
		sessionCfg: session.DefaultConfig(),
	}

	rl, err := readline.NewEx(&readline.Config{
		Prompt:          style(ansiCyan+ansiBold, "vault ▸ "),
		HistoryFile:     historyFile,
		AutoComplete:    &cliCompleter{cli: c},
		InterruptPrompt: "^C",
		EOFPrompt:       "exit",
	})
	if err != nil {
		return nil, fmt.Errorf("cli: failed to initialize readline: %w", err)
	}
	c.rl = rl
	return c, nil
}

// Close releases the readline instance's resources (terminal state, history
// file handle, etc). Callers should defer this after New succeeds.
func (c *CLI) Close() error {
	return c.rl.Close()
}

// cliCompleter provides tab-completion that changes based on login state:
// only commands valid right now are suggested.
type cliCompleter struct {
	cli *CLI
}

func (comp *cliCompleter) Do(line []rune, pos int) (newLine [][]rune, length int) {
	typed := string(line[:pos])

	cmds := preLoginCommands
	if comp.cli.currentUser != nil {
		cmds = postLoginCommands
	}

	var suggestions [][]rune
	for _, cmd := range cmds {
		if strings.HasPrefix(cmd, typed) {
			suggestions = append(suggestions, []rune(cmd[len(typed):]))
		}
	}
	return suggestions, len(typed)
}

// Run starts the interactive loop. It returns nil on a clean exit (the
// "exit" command, or EOF/Ctrl-D) and a non-nil error only for unexpected
// failures.
func (c *CLI) Run() error {
	printBanner()

	for {
		line, err := c.rl.Readline()
		if err == readline.ErrInterrupt {
			// Ctrl-C: clear the current line and keep going, matching
			// familiar shell behavior, rather than exiting outright.
			continue
		} else if err == io.EOF {
			fmt.Println()
			printInfo("Goodbye!")
			return nil
		} else if err != nil {
			return fmt.Errorf("cli: readline error: %w", err)
		}

		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		exit, err := c.dispatch(line)
		if err != nil {
			printError("%s", err)
		}
		if exit {
			printInfo("Goodbye!")
			return nil
		}
	}
}

// dispatch routes a single command line to its handler. The returned bool
// is true only when the shell should exit entirely.
func (c *CLI) dispatch(command string) (exit bool, err error) {
	loggedIn := c.currentUser != nil

	switch command {
	case "help":
		c.printHelp()
		return false, nil

	case "register":
		if loggedIn {
			return false, fmt.Errorf("already logged in; log out first")
		}
		return false, c.handleRegister()

	case "login":
		if loggedIn {
			return false, fmt.Errorf("already logged in as %s; log out first", c.currentUser.Username)
		}
		return false, c.handleLogin()

	case "exit":
		if loggedIn {
			return false, fmt.Errorf("please log out before exiting")
		}
		return true, nil

	case "whoami":
		if !loggedIn {
			return false, errNotLoggedIn
		}
		return false, c.handleWhoami()

	case "enable-2fa":
		if !loggedIn {
			return false, errNotLoggedIn
		}
		return false, c.handleEnable2FA()

	case "disable-2fa":
		if !loggedIn {
			return false, errNotLoggedIn
		}
		return false, c.handleDisable2FA()

	case "logout":
		if !loggedIn {
			return false, errNotLoggedIn
		}
		return false, c.handleLogout()

	default:
		return false, fmt.Errorf("unknown command %q (type 'help' for a list of commands)", command)
	}
}

func (c *CLI) printHelp() {
	fmt.Println(style(ansiBold+ansiCyan, "Available commands:"))
	if c.currentUser == nil {
		printHelpRow("register", "Create a new user account")
		printHelpRow("login", "Log in with username and password (+2FA if enabled)")
		printHelpRow("help", "Show this help message")
		printHelpRow("exit", "Quit the program")
		return
	}
	printHelpRow("whoami", "Show your account details")
	printHelpRow("enable-2fa", "Turn on TOTP-based two-factor authentication")
	printHelpRow("disable-2fa", "Turn off two-factor authentication")
	printHelpRow("logout", "End your session")
	printHelpRow("help", "Show this help message")
}

func printHelpRow(cmd, desc string) {
	padded := cmd + strings.Repeat(" ", 13-len(cmd))
	fmt.Println("  " + style(ansiGreen+ansiBold, padded) + style(ansiDim, desc))
}
