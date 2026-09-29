// Package actionpin compares candidate workflow commands with the trusted
// main-branch version while allowing existing full-SHA action pins to move.
package actionpin

import (
	"regexp"
	"strings"
)

var linePattern = regexp.MustCompile(`^([ \t]*(?:- )?uses: [A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)@[0-9a-f]{40} # v[0-9]+\.[0-9]+\.[0-9]+\n?$`)

// Equivalent reports whether only the commit SHA and version comment on an
// existing action line differ. Other bytes, including the action name, match.
func Equivalent(base, candidate []byte) bool {
	if len(base) == 0 || len(base) > 128<<10 || len(candidate) == 0 || len(candidate) > 128<<10 {
		return false
	}
	before, after := strings.SplitAfter(string(base), "\n"), strings.SplitAfter(string(candidate), "\n")
	if len(before) != len(after) {
		return false
	}
	for i, line := range before {
		if line == after[i] {
			continue
		}
		old, next := linePattern.FindStringSubmatch(line), linePattern.FindStringSubmatch(after[i])
		if old == nil || next == nil || old[1] != next[1] || strings.HasSuffix(line, "\n") != strings.HasSuffix(after[i], "\n") {
			return false
		}
	}
	return true
}
