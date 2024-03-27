package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"flag"
	"fmt"
	"github.com/jc-lab/docker-path-proxy-go/model"
	"github.com/jc-lab/docker-path-proxy-go/pkg/dockerlogin"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
)

var (
	regexRepoName = regexp.MustCompile("([^/]+)/([^/]+)")
)

type RepoAuthCache struct {
	Token string
}

func getEnvOrDefault(name string, def string) string {
	value := os.Getenv(name)
	if value == "" {
		return def
	}
	return value
}

func getEnvAsBool(name string) bool {
	value := strings.ToLower(os.Getenv(name))
	return value == "true"
}

func WrapHandler(f http.Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		log.Println("URL: ", r.RequestURI)
		f.ServeHTTP(w, r)
	}
}

func main() {
	var flagConfig string
	var flagPort int
	var flagUseDoh = getEnvAsBool("USE_DOH")

	defaultPort, err := strconv.Atoi(getEnvOrDefault("PORT", "8000"))
	if err != nil {
		log.Fatalln("parse PORT env failed: ", err)
	}

	flag.IntVar(&flagPort, "port", defaultPort, "listen port (env: PORT)")
	flag.StringVar(&flagConfig, "config", os.Getenv("CONFIG_FILE"), "config file path (env: CONFIG_FILE)")
	flag.BoolVar(&flagUseDoh, "use-doh", flagUseDoh, "use dns over https")
	flag.Parse()

	config := &model.Config{}
	if flagConfig != "" {
		raw, err := os.ReadFile(flagConfig)
		if err != nil {
			log.Fatalln("config read failed: ", err)
		}
		config, err = model.ReadConfig(raw)
		if err != nil {
			log.Fatalln("config read failed: ", err)
		}
	}

	registries := map[string]*model.Registry{}
	for _, registry := range config.Registries {
		registries[registry.Path] = registry
	}

	var mutex sync.Mutex
	repoAuthCaches := map[string]*RepoAuthCache{}

	rootCAs, err := x509.SystemCertPool()
	if err != nil {
		log.Println("x509.SystemCertPool failed: ", err)
		rootCAs = x509.NewCertPool()
	}
	for i, certificate := range config.CaCertificates {
		ok := rootCAs.AppendCertsFromPEM([]byte(certificate))
		if !ok {
			log.Printf("CaCertificates[%d] failed", i)
		}
	}

	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		TLSClientConfig: &tls.Config{
			RootCAs: rootCAs,
		},
	}
	client := &http.Client{
		Transport: transport,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/_/health", func(writer http.ResponseWriter, request *http.Request) {
		responseBody := []byte("{\"status\": \"OK\"}")
		writer.Header().Add("content-type", "application/json")
		writer.Header().Add("content-length", strconv.Itoa(len(responseBody)))
		writer.WriteHeader(200)
		writer.Write(responseBody)
	})
	mux.HandleFunc("/v2/", func(writer http.ResponseWriter, request *http.Request) {
		path, _ := strings.CutPrefix(request.RequestURI, "/v2/")
		pos := strings.Index(path, "/")
		if pos < 0 {
			writer.WriteHeader(http.StatusOK)
			return
		}

		domain := path[:pos]
		suffix := path[pos+1:]
		matches := regexRepoName.FindStringSubmatch(suffix)
		repoCacheName := ""
		if len(matches) > 2 {
			repoCacheName = domain + "/" + matches[1] + "/" + matches[2]
		}

		var baseUrl string
		registry := registries[domain]
		if registry == nil {
			if config.DefaultBackend.Disabled {
				log.Printf("%s %d", request.RequestURI, http.StatusNotFound)
				http.Error(writer, "not defined registry", http.StatusNotFound)
			} else {
				baseUrl = "https://" + domain + "/v2"
			}
		} else {
			baseUrl = strings.TrimSuffix(registry.Endpoint, "/")
		}

		fullUri := baseUrl + "/" + suffix

		mutex.Lock()
		repoCache, has := repoAuthCaches[repoCacheName]
		if !has {
			repoCache = &RepoAuthCache{}
			repoAuthCaches[repoCacheName] = repoCache
		}
		mutex.Unlock()

		prepareRequest := func() (*http.Request, error) {
			newRequest, err := http.NewRequest(request.Method, fullUri, request.Body)
			if err != nil {
				return nil, err
			}

			if repoCache.Token != "" {
				newRequest.Header.Set("Authorization", "bearer "+repoCache.Token)
			}

			for key, values := range request.Header {
				for _, value := range values {
					newRequest.Header.Add(key, value)
				}
			}

			if registry != nil && registry.Username != "" {
				newRequest.Header.Set("authorization", "basic "+base64.StdEncoding.EncodeToString([]byte(registry.Username+":"+registry.Password)))
			}

			return newRequest, nil
		}

		newRequest, err := prepareRequest()
		if err != nil {
			log.Printf("%s %d: %v", request.RequestURI, http.StatusInternalServerError, err)
			http.Error(writer, "server error: "+err.Error(), http.StatusInternalServerError)
			return
		}

		response, err := client.Do(newRequest)
		if err != nil {
			log.Printf("%s %d: %v", request.RequestURI, http.StatusInternalServerError, err)
			http.Error(writer, "server error: "+err.Error(), http.StatusInternalServerError)
			return
		}
		if response.StatusCode == 401 {
			io.ReadAll(response.Body)

			var wwwAuthenticate = response.Header.Get("www-authenticate")
			if wwwAuthenticate != "" {
				log.Printf("try login with www-authenticate: %s", wwwAuthenticate)
				var username string
				var password string
				if registry != nil && registry.Username != "" {
					username = registry.Username
					password = registry.Password
				}
				tokenBody, err := dockerlogin.LoginRequest(client, wwwAuthenticate, username, password)
				if err != nil {
					log.Printf("login failed: %v", err)
				} else {
					repoCache.Token = tokenBody.Token

					newRequest, err = prepareRequest()
					if err != nil {
						log.Printf("%s %d: %v", request.RequestURI, http.StatusInternalServerError, err)
						http.Error(writer, "server error: "+err.Error(), http.StatusInternalServerError)
						return
					}

					response, err = client.Do(newRequest)
					if err != nil {
						log.Printf("%s %d: %v", request.RequestURI, http.StatusInternalServerError, err)
						http.Error(writer, "server error: "+err.Error(), http.StatusInternalServerError)
						return
					}
				}
			}
		}

		for key, values := range response.Header {
			for _, value := range values {
				writer.Header().Add(key, value)
			}
		}

		writer.WriteHeader(response.StatusCode)

		body, err := io.ReadAll(response.Body)
		if err != nil {
			log.Printf("%s %d: %v", request.RequestURI, http.StatusInternalServerError, err)
			http.Error(writer, "server error: "+err.Error(), http.StatusInternalServerError)
			return
		}
		writer.Write(body)

		log.Printf("%s %d upstream=%s, bytes=%d", request.RequestURI, response.StatusCode, fullUri, len(body))
	})

	address := fmt.Sprintf("0.0.0.0:%d", flagPort)
	listener, err := net.Listen("tcp", address)
	if err != nil {
		log.Fatalf("listen on %s failed", address)
	}
	defer listener.Close()

	log.Printf("listen on %s started", address)

	if err := http.Serve(listener, WrapHandler(mux)); err != nil {
		log.Fatalln(err)
	}
}
