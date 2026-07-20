package scanner

import "testing"

func TestNormalizeHostname(t *testing.T) {
	t.Parallel()
	tests := []struct {
		input string
		want  string
		ok    bool
	}{
		{" Example.COM. ", "example.com", true},
		{"sub-domain.example", "sub-domain.example", true},
		{"https://example.com", "", false},
		{"example.com:8443", "", false},
		{"127.0.0.1", "", false},
		{"[::1]", "", false},
		{"localhost", "", false},
		{"-bad.example", "", false},
		{"bad_.example", "", false},
	}
	for _, test := range tests {
		test := test
		t.Run(test.input, func(t *testing.T) {
			t.Parallel()
			got, err := NormalizeHostname(test.input)
			if (err == nil) != test.ok || got != test.want {
				t.Fatalf("NormalizeHostname(%q) = %q, %v; want %q, ok=%v", test.input, got, err, test.want, test.ok)
			}
		})
	}
}
