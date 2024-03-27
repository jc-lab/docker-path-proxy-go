package realmlogin

import (
	"github.com/likexian/gokit/assert"
	"testing"
)

func Test(t *testing.T) {
	tests := []struct {
		input    string
		expected map[string]string
	}{
		{
			"Bearer realm=\"https://gitlab.com/jwt/auth\",service=\"container_registry\",scope=\"repository:andrew18/container-test:pull\"",
			map[string]string{
				"realm":   "https://gitlab.com/jwt/auth",
				"service": "container_registry",
				"scope":   "repository:andrew18/container-test:pull",
			},
		},
		{
			"Bearer realm=\"https://gitlab.com/jwt/auth\", service=\"container_registry\", scope=\"repository:andrew18/container-test:pull\"",
			map[string]string{
				"realm":   "https://gitlab.com/jwt/auth",
				"service": "container_registry",
				"scope":   "repository:andrew18/container-test:pull",
			},
		},
		{
			"Bearer realm=\"https://gitlab.com  /jwt/auth\", service=\"container_registry\", scope=\"repository:andrew18/container-test:pull\"",
			map[string]string{
				"realm":   "https://gitlab.com  /jwt/auth",
				"service": "container_registry",
				"scope":   "repository:andrew18/container-test:pull",
			},
		},
	}
	for _, test := range tests {
		t.Run(test.input, func(t *testing.T) {
			out, err := ParseBearer(test.input)
			if err != nil {
				t.Fatal(err)
			} else {
				assert.Equal(t, out, test.expected)
			}
		})
	}
}
