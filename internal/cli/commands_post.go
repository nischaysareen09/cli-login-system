package cli

import (
	"fmt"
	"os"

	"github.com/mdp/qrterminal/v3"

	"cli-login-system/internal/auth"
	"cli-login-system/internal/session"
)

// printUserDetails shows the current user's details: username, registration
// date, MFA status, session expiration, and last login time. Used both for
// the auto-display right after login and for the whoami command.
func (c *CLI) printUserDetails() {
	u := c.currentUser

	mfaStatus := style(ansiRed, "disabled")
	if u.TOTPEnabled {
		mfaStatus = style(ansiGreen, "enabled")
	}

	lastLogin := style(ansiDim, "never (first login)")
	if u.LastLoginAt != nil {
		lastLogin = u.LastLoginAt.Local().Format("2006-01-02 15:04:05 MST")
	}

	printBox("Account details", [][2]string{
		{"Username:", u.Username},
		{"Registered on:", u.CreatedAt.Local().Format("2006-01-02 15:04:05 MST")},
		{"2FA status:", mfaStatus},
		{"Session expires at:", c.sessionExpiresAt.Local().Format("2006-01-02 15:04:05 MST")},
		{"Last login:", lastLogin},
	})
}

// handleWhoami prints the current user's details on demand.
func (c *CLI) handleWhoami() error {
	c.printUserDetails()
	return nil
}

// handleEnable2FA walks the user through TOTP setup: generate a secret,
// render it as a real scannable QR code right in the terminal (plus the
// otpauth URL and raw secret as fallbacks), then require a correct code
// before actually turning 2FA on.
func (c *CLI) handleEnable2FA() error {
	key, err := auth.StartEnableTOTP(c.conn, c.currentUser.ID, c.currentUser.Username)
	if err != nil {
		return err
	}

	fmt.Println()
	printInfo("Scan this with your authenticator app:")
	fmt.Println()
	qrterminal.GenerateWithConfig(key.URL(), qrterminal.Config{
		Level:     qrterminal.M,
		Writer:    os.Stdout,
		BlackChar: qrterminal.BLACK,
		WhiteChar: qrterminal.WHITE,
		QuietZone: 1,
	})
	fmt.Println()
	fmt.Println(style(ansiDim, "  Can't scan? Enter this secret manually:"))
	fmt.Println("  " + style(ansiBold, key.Secret()))
	fmt.Println()

	code, err := c.readLine("Enter the 6-digit code from your app to confirm: ")
	if err != nil {
		return err
	}

	if err := auth.ConfirmEnableTOTP(c.conn, c.currentUser.ID, code); err != nil {
		return err
	}

	// Refresh local state so whoami reflects the change immediately.
	c.currentUser.TOTPEnabled = true

	printSuccess("Two-factor authentication is now enabled.")
	return nil
}

// handleDisable2FA turns 2FA off for the current user.
func (c *CLI) handleDisable2FA() error {
	if err := auth.DisableTOTP(c.conn, c.currentUser.ID); err != nil {
		return err
	}

	c.currentUser.TOTPEnabled = false
	c.currentUser.TOTPSecret = ""

	printSuccess("Two-factor authentication is now disabled.")
	return nil
}

// handleLogout ends the current session and returns the shell to the
// pre-login state.
func (c *CLI) handleLogout() error {
	if err := session.End(c.conn, c.sessionToken); err != nil {
		// Logout should still succeed from the user's point of view even
		// if the underlying delete had trouble — clearing local state
		// below is what actually matters, so a stale session can't be
		// reused from this shell.
		printError("failed to clean up session record: %s", err)
	}

	username := c.currentUser.Username
	c.currentUser = nil
	c.sessionToken = ""
	c.rl.SetPrompt(c.currentPrompt())

	printInfo("Logged out. Goodbye, %s!", username)
	return nil
}
