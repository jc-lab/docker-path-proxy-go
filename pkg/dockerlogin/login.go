package dockerlogin

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/jc-lab/docker-path-proxy-go/pkg/realmlogin"
	"io"
	"net/http"
	"net/url"
)

type TokenResponseBody struct {
	Token string `json:"token"`
}

func LoginRequest(httpClient *http.Client, wwwAuthenticate string, username string, password string) (*TokenResponseBody, error) {
	realmInfo, err := realmlogin.ParseBearer(wwwAuthenticate)
	if err != nil {
		return nil, err
	}

	realmUrl, ok := realmInfo["realm"]
	if !ok {
		return nil, fmt.Errorf("no realm in www-authenticate: %s", wwwAuthenticate)
	}

	realmUrlBuilder, err := url.Parse(realmUrl)
	if err != nil {
		return nil, err
	}

	query := realmUrlBuilder.Query()
	for k, v := range realmInfo {
		query.Set(k, v)
	}
	realmUrlBuilder.RawQuery = query.Encode()

	req, err := http.NewRequest("GET", realmUrlBuilder.String(), nil)
	if err != nil {
		return nil, err
	}
	if username != "" {
		req.Header.Set("authorization", "basic "+base64.StdEncoding.EncodeToString([]byte(username+":"+password)))
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	respRaw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("login failed status=%s: %s", resp.StatusCode, string(respRaw))
	}
	responseBody := &TokenResponseBody{}
	if err := json.Unmarshal(respRaw, responseBody); err != nil {
		return nil, err
	}
	return responseBody, nil
}
