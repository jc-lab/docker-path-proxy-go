package realmlogin

import (
	"fmt"
	"regexp"
	"strings"
)

var (
	regexParseItem = regexp.MustCompile("^([^,=]+)=([^\",]+|\"[^\"]+\")(?:,\\s*|$)")
)

// ParseBearer
// This function parses the Www-Authenticate header provided in the challenge
// It has the following format
// Bearer realm="https://gitlab.com/jwt/auth",service="container_registry",scope="repository:andrew18/container-test:pull"
func ParseBearer(bearer string) (map[string]string, error) {
	out := make(map[string]string)

	pos := strings.Index(bearer, " ")
	if pos < 0 {
		return nil, fmt.Errorf("cannot found Bearer")
	}
	prefix := strings.ToLower(bearer[:pos])
	if prefix != "bearer" {
		return nil, fmt.Errorf("invalid prefix name: %s", prefix)
	}
	bearer = bearer[pos+1:]

	for {
		found := regexParseItem.FindStringSubmatchIndex(bearer)
		if len(found) <= 0 {
			break
		}

		key := bearer[found[2]:found[3]]
		value := bearer[found[4]:found[5]]
		bearer = bearer[found[1]:]

		if value[0] == '"' {
			value = value[1 : len(value)-1]
		}

		out[key] = value
	}

	return out, nil
}
