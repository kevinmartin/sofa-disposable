package fixture

import "strings"

// Greeting returns a short welcome for the supplied name. It trims leading
// and trailing whitespace, then replaces each run of interior whitespace,
// including tabs and newlines, with one ASCII space. An empty or
// whitespace-only name returns "Hello, friend".
func Greeting(name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return "Hello, friend"
	}
	return "Hello, " + strings.Join(strings.Fields(name), " ")
}
