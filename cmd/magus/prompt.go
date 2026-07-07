package main

import (
	"bufio"
	"fmt"
	"io"
	"strings"
)

// confirmAction prints prompt to out and reads a yes/no answer from in. It is
// the single confirm helper behind apply/adopt/reclaim (UX7).
func confirmAction(in io.Reader, out io.Writer, prompt string) bool {
	fmt.Fprint(out, prompt)
	return readYesNo(in)
}

// readYesNo reads one line from in and reports whether it is affirmative.
// Anything other than "y"/"yes" (case-insensitive) is a decline; EOF (e.g.
// piped input with nothing to read) is also a decline — magus never proceeds
// without explicit consent.
func readYesNo(in io.Reader) bool {
	line, err := bufio.NewReader(in).ReadString('\n')
	if err != nil && line == "" {
		return false
	}
	answer := strings.ToLower(strings.TrimSpace(line))
	return answer == "y" || answer == "yes"
}
