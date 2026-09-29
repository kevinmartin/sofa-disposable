package actionpin

import (
	"strings"
	"testing"
)

func TestChangesAcceptsOnlyOfficialPinLines(t *testing.T) {
	old := strings.Repeat("a", 40)
	next := strings.Repeat("b", 40)
	base := "name: gate\nsteps:\n  - uses: actions/checkout@" + old + " # v4.2.2\n    with:\n      persist-credentials: false\n"
	candidate := strings.Replace(base, old+" # v4.2.2", next+" # v7.0.1", 1)
	pins, err := Changes([]byte(base), []byte(candidate))
	if err != nil || len(pins) != 1 || pins[0] != (Pin{Name: "actions/checkout", SHA: next, Tag: "v7.0.1"}) {
		t.Fatalf("pin-only update rejected: %+v %v", pins, err)
	}
	for name, changed := range map[string]string{
		"command":     candidate + "  - run: curl attacker.invalid\n",
		"credentials": strings.Replace(candidate, "persist-credentials: false", "persist-credentials: true", 1),
		"action":      strings.Replace(candidate, "actions/checkout", "attacker/checkout", 1),
		"tag":         strings.Replace(candidate, "# v7.0.1", "# latest", 1),
		"whitespace":  strings.Replace(candidate, "    with:", "   with:", 1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Changes([]byte(base), []byte(changed)); err == nil {
				t.Fatal("non-pin workflow change accepted")
			}
		})
	}
}
