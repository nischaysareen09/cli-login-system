package cli

import (
	"errors"
	"fmt"
	"strings"

	"cli-login-system/internal/auth"
	"cli-login-system/internal/session"
)

// readLine prompts for a single line of visible input.
func (c *CLI) readLine(prompt string) (string, error) {
	c.rl.SetPrompt(prompt)
	line, err := c.rl.Readline()
	c.rl.SetPrompt(c.currentPrompt())
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(line), nil
}

// readPassword prompts for a line of masked (non-echoed) input.
func (c *CLI) readPassword(prompt string) (string, error) {
	b, err := c.rl.ReadPassword(prompt)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

// currentPrompt returns the shell prompt appropriate to the current login
// state: "vault ▸ " when logged out, "<username> ● " once logged in.
func (c *CLI) currentPrompt() string {
	if c.currentUser == nil {
		return style(ansiCyan+ansiBold, "vault ▸ ")
	}
	return style(ansiGreen+ansiBold, c.currentUser.Username+" ● ")
}

// handleRegister walks the user through creating a new account.
func (c *CLI) handleRegister() error {
	username, err := c.readLine("New username: ")
	if err != nil {
		return err
	}

	password, err := c.readPassword("New password: ")
	if err != nil {
		return err
	}
	confirm, err := c.readPassword("Confirm password: ")
	if err != nil {
		return err
	}
	if password != confirm {
		return fmt.Errorf("passwords do not match")
	}

	user, err := auth.Register(c.conn, username, password)
	if err != nil {
		return err
	}

	printSuccess("Account %q created successfully. You can now 'login'.", user.Username)
	return nil
}

// handleLogin walks the user through logging in: username, password, and
// (if the account has it enabled) a TOTP code. On success it creates a
// session and auto-displays the user's account details.
func (c *CLI) handleLogin() error {
	username, err := c.readLine("Username: ")
	if err != nil {
		return err
	}
	password, err := c.readPassword("Password: ")
	if err != nil {
		return err
	}

	user, err := auth.Login(c.conn, c.lockoutCfg, username, password)
	if err != nil {
		var lockErr *auth.AccountLockedError
		if errors.As(err, &lockErr) {
			return fmt.Errorf("account locked due to too many failed attempts; try again after %s",
				lockErr.Until.Local().Format("3:04PM"))
		}
		return err
	}

	if user.TOTPEnabled {
		code, err := c.readLine("2FA code: ")
		if err != nil {
			return err
		}
		if !auth.VerifyTOTPCode(user.TOTPSecret, code) {
			return auth.ErrInvalidTOTPCode
		}
	}

	sess, err := session.Create(c.conn, c.sessionCfg, user.ID)
	if err != nil {
		return err
	}

	c.currentUser = user
	c.sessionToken = sess.Token
	c.sessionExpiresAt = sess.ExpiresAt
	c.rl.SetPrompt(c.currentPrompt())

	fmt.Println()
	printSuccess("Welcome, %s!", user.Username)
	c.printUserDetails()
	return nil
}
