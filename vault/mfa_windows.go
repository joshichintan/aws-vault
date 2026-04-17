//go:build windows
// +build windows

package vault

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
)

func executeMFACommand(processCmd string) (string, error) {
	// On windows, its quite involved to launch a process if the binary involved is in a path with spaces
	// See https://github.com/golang/go/issues/17149 for details and workaround proposals
	shell := os.Getenv("SystemRoot") + "\\System32\\cmd.exe"
	cmd := exec.Command(shell)
	cmd.SysProcAttr = &syscall.SysProcAttr{CmdLine: "/C \"" + processCmd + "\""}
	// Connect stdin to the console so that interactive prompts (e.g. OATH
	// password) work even when aws-vault's stdin is a pipe (e.g. docker
	// credential helper receiving JSON on stdin).
	inFile, _ := os.OpenFile("CONIN$", os.O_RDONLY, 0)
	defer inFile.Close()
	if inFile != nil {
		cmd.Stdin = inFile
	}
	// Connect stderr to the console so interactive prompts (e.g. "Touch your
	// YubiKey...") are visible even when aws-vault's stderr is captured by the
	// parent process.
	outFile, _ := os.OpenFile("CONOUT$", os.O_WRONLY, 0)
	defer outFile.Close()
	if outFile != nil {
		cmd.Stderr = outFile
	} else {
		cmd.Stderr = os.Stderr
	}

	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("process provider: %w", err)
	}

	return strings.TrimSpace(string(out)), nil
}
