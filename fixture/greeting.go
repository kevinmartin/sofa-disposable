package fixture

import "strings"

// Greeting returns a short welcome for the supplied name, trimming leading and
// trailing whitespace and collapsing repeated whitespace between words. If the
// name is blank after trimming, Greeting returns "Hello, friend".
func Greeting(name string) string {
    name = strings.TrimSpace(name)
    if name == "" {
        return "Hello, friend"
    }
    return "Hello, " + strings.Join(strings.Fields(name), " ")
}
