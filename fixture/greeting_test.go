package fixture

import "testing"

func TestGreeting(t *testing.T) {
	tests := []struct {
		name string
		want string
	}{
		{"Ada", "Hello, Ada"},
		{"  Ada  ", "Hello, Ada"},
		{" ", "Hello, friend"},
	}
	for _, tt := range tests {
		if got := Greeting(tt.name); got != tt.want {
			t.Errorf("Greeting(%q) = %q, want %q", tt.name, got, tt.want)
		}
	}
}
