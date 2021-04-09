package tools

import (
	"bytes"
	"log"
	"os/exec"
)

func RunShellCommand(command string, arguments []string) (string, string) {
	cmd := exec.Command(command, arguments...)
	fullCommand := cmd.String()
	stdoutReader, err := cmd.StdoutPipe()
	stderrReader, err := cmd.StderrPipe()

	if err != nil {
		log.Printf("Unexpected error initializing context `%s`: %s", fullCommand, err)
		return "", ""
	}
	if err := cmd.Start(); err != nil {
		log.Printf("Unexpected error starting command `%s`: %s", fullCommand, err)
		return "", ""
	}

	stdoutBuf := new(bytes.Buffer)
	stderrBuf := new(bytes.Buffer)

	stdoutBuf.ReadFrom(stdoutReader)
	stderrBuf.ReadFrom(stderrReader)

	if err := cmd.Wait(); err != nil && stderrBuf.String() != "" {
		log.Printf("Unexpected error executing command `%s`: %s, Err: %s", fullCommand, err, stderrBuf.String())
		return "", ""
	}

	return stdoutBuf.String(), stderrBuf.String()
}
