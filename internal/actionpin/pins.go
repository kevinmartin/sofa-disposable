// Package actionpin restricts a candidate workflow change to official action
// release pins while preserving every other workflow byte.
package actionpin

import (
	"errors"
	"regexp"
	"strings"
)

type Pin struct {
	Name string
	SHA  string
	Tag  string
}

var linePattern = regexp.MustCompile(`^([ \t]*(?:- )?uses: )(actions/(?:checkout|setup-go|setup-node))@([0-9a-f]{40}) # (v[0-9]+\.[0-9]+\.[0-9]+)\n?$`)

func Changes(base, candidate []byte) ([]Pin, error) {
	if len(base) == 0 || len(base) > 128<<10 || len(candidate) == 0 || len(candidate) > 128<<10 {
		return nil, errors.New("candidate workflow size invalid")
	}
	before, after := strings.SplitAfter(string(base), "\n"), strings.SplitAfter(string(candidate), "\n")
	if len(before) != len(after) {
		return nil, errors.New("candidate workflow changed beyond action pins")
	}
	var pins []Pin
	seen := make(map[Pin]bool)
	for i, oldLine := range before {
		if oldLine == after[i] {
			continue
		}
		old, next := linePattern.FindStringSubmatch(oldLine), linePattern.FindStringSubmatch(after[i])
		if old == nil || next == nil || old[1] != next[1] || old[2] != next[2] || strings.HasSuffix(oldLine, "\n") != strings.HasSuffix(after[i], "\n") {
			return nil, errors.New("candidate workflow changed beyond action pins")
		}
		pin := Pin{Name: next[2], SHA: next[3], Tag: next[4]}
		if !seen[pin] {
			pins = append(pins, pin)
			seen[pin] = true
		}
	}
	if len(pins) == 0 {
		return nil, errors.New("candidate workflow has no action pin changes")
	}
	return pins, nil
}
