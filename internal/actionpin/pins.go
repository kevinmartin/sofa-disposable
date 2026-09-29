// Package actionpin compares candidate workflow commands with the trusted
// main-branch version while allowing existing full-SHA action pins to move.
package actionpin

import (
	"bytes"
	"regexp"
)

var linePattern = regexp.MustCompile(`(?m)^([ \t]*(?:- )?uses: [A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)@[0-9a-f]{40} # v[0-9]+\.[0-9]+\.[0-9]+$`)

// Equivalent reports whether only the commit SHA and version comment on an
// existing action line differ. Other bytes, including the action name, match.
func Equivalent(base, candidate []byte) bool {
	if len(base) == 0 || len(base) > 128<<10 || len(candidate) == 0 || len(candidate) > 128<<10 {
		return false
	}
	normalize := func(data []byte) []byte {
		return linePattern.ReplaceAll(data, []byte("${1}@<sha> # <version>"))
	}
	return bytes.Equal(normalize(base), normalize(candidate))
}
