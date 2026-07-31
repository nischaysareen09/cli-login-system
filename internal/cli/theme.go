package cli

import (
	"fmt"
	"os"
	"strings"

	"golang.org/x/term"
)

// colorEnabled is decided once at startup: only colorize when actually
// talking to a real terminal (not when piped/redirected), and respect the
// NO_COLOR convention (https://no-color.org) if the user has set it.
var colorEnabled = term.IsTerminal(int(os.Stdout.Fd())) && os.Getenv("NO_COLOR") == ""

const (
	ansiReset   = "\033[0m"
	ansiBold    = "\033[1m"
	ansiDim     = "\033[2m"
	ansiCyan    = "\033[36m"
	ansiGreen   = "\033[32m"
	ansiRed     = "\033[31m"
	ansiYellow  = "\033[33m"
	ansiMagenta = "\033[35m"
)

// style wraps s in the given ANSI code(s), or returns it unchanged if
// colorEnabled is false.
func style(code, s string) string {
	if !colorEnabled {
		return s
	}
	return code + s + ansiReset
}

// printBanner shows the app's startup identity — deliberately not just a
// plain "=== Some Generic Title ===" line.
func printBanner() {
	const width = 48
	title := "V A U L T   S H E L L"
	subtitle := "secure account access · terminal edition"

	top := "╔" + strings.Repeat("═", width) + "╗"
	bottom := "╚" + strings.Repeat("═", width) + "╝"

	fmt.Println(style(ansiCyan, top))
	fmt.Println(style(ansiCyan, "║") + centered(title, width, ansiBold+ansiCyan) + style(ansiCyan, "║"))
	fmt.Println(style(ansiCyan, "║") + centered(subtitle, width, ansiDim) + style(ansiCyan, "║"))
	fmt.Println(style(ansiCyan, bottom))
	fmt.Println()
	fmt.Println(style(ansiDim, "  Type ") + style(ansiBold, "help") + style(ansiDim, " to see available commands."))
	fmt.Println()
}

// centered pads s to fill exactly `width` columns, centered, styled with
// the given ANSI code.
func centered(s string, width int, code string) string {
	if len(s) >= width {
		return style(code, s[:width])
	}
	left := (width - len(s)) / 2
	right := width - len(s) - left
	return strings.Repeat(" ", left) + style(code, s) + strings.Repeat(" ", right)
}

func printSuccess(format string, a ...interface{}) {
	fmt.Println(style(ansiGreen, "✓ ") + fmt.Sprintf(format, a...))
}

func printError(format string, a ...interface{}) {
	fmt.Println(style(ansiRed, "✗ ") + fmt.Sprintf(format, a...))
}

func printInfo(format string, a ...interface{}) {
	fmt.Println(style(ansiYellow, "› ") + fmt.Sprintf(format, a...))
}

// printBox renders a bordered key/value panel, e.g. for account details.
// Labels are right-padded to align every value in the same column.
func printBox(title string, rows [][2]string) {
	labelWidth := 0
	for _, r := range rows {
		if len(r[0]) > labelWidth {
			labelWidth = len(r[0])
		}
	}

	contentWidth := labelWidth + 2 + maxValueWidth(rows)
	if len(title) > contentWidth {
		contentWidth = len(title)
	}
	contentWidth += 2 // inner padding

	fmt.Println(style(ansiMagenta, "┌─ "+title+" "+strings.Repeat("─", max(0, contentWidth-len(title)-2))+"┐"))
	for _, r := range rows {
		label := r[0] + strings.Repeat(" ", labelWidth-len(r[0]))
		line := fmt.Sprintf(" %s  %s", style(ansiBold, label), r[1])
		fmt.Println(style(ansiMagenta, "│") + line)
	}
	fmt.Println(style(ansiMagenta, "└" + strings.Repeat("─", contentWidth+1) + "┘"))
}

func maxValueWidth(rows [][2]string) int {
	m := 0
	for _, r := range rows {
		if len(r[1]) > m {
			m = len(r[1])
		}
	}
	return m
}
