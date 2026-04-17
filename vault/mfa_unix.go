//go:build linux || darwin || freebsd || openbsd
// +build linux darwin freebsd openbsd

package vault

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

func executeMFACommand(processCmd string) (string, error) {
	cmd := exec.Command("/bin/sh", "-c", processCmd)

	// Open the controlling TTY read-write so that:
	//   - Stderr: interactive prompts (e.g. "Touch your YubiKey...") are
	//     visible even when aws-vault's stderr is captured by the parent
	//     process (e.g. aws CLI or kubectl using credential_process).
	//   - Stdin: subprocess gets a real TTY as stdin so that tools like ykman
	//     see sys.stdin.isatty() == True and can display interactive prompts
	//     (e.g. OATH password) even when aws-vault's stdin is a pipe
	//     (e.g. docker credential helper receiving JSON on stdin).
	ttyFile, _ := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	defer ttyFile.Close()
	if ttyFile != nil {
		cmd.Stdin = ttyFile
		cmd.Stderr = ttyFile
	} else {
		cmd.Stderr = os.Stderr
	}

	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("process provider: %w", err)
	}

	return strings.TrimSpace(string(out)), nil
}
