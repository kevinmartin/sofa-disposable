package fixture

import "strings"

// Greeting returns a short welcome for the supplied name.
func Greeting(name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return "Hello, friend"
	}
	return "Hello, " + name
}
