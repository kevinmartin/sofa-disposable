package actionpin

import (
	"strings"
	"testing"
)

func TestEquivalentPreservesWorkflowCommands(t *testing.T) {
	base := "name: gate\nsteps:\n  - uses: actions/checkout@" + strings.Repeat("a", 40) + " # v4.2.2\n    with:\n      persist-credentials: false\n"
	candidate := strings.Replace(base, strings.Repeat("a", 40)+" # v4.2.2", strings.Repeat("b", 40)+" # v999.0.0", 1)
	if !Equivalent([]byte(base), []byte(candidate)) || !Equivalent([]byte(base), []byte(base)) {
		t.Fatal("existing full-SHA action pin rejected")
	}
	for name, changed := range map[string]string{
		"command":     candidate + "  - run: echo bypass\n",
		"credentials": strings.Replace(candidate, "persist-credentials: false", "persist-credentials: true", 1),
		"action":      strings.Replace(candidate, "actions/checkout", "attacker/checkout", 1),
		"placeholder": strings.Replace(candidate, "actions/checkout@"+strings.Repeat("b", 40)+" # v999.0.0", "actions/checkout@<sha> # <version>", 1),
		"version":     strings.Replace(candidate, "# v999.0.0", "# latest", 1),
		"whitespace":  strings.Replace(candidate, "    with:", "   with:", 1),
	} {
		t.Run(name, func(t *testing.T) {
			if Equivalent([]byte(base), []byte(changed)) {
				t.Fatal("non-pin workflow change accepted")
			}
		})
	}
}
