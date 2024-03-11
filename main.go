package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"flag"
	"fmt"
	"github.com/jc-lab/docker-path-proxy-go/model"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
)

func main() {
	var flagConfig string
	var flagPort int
	flag.IntVar(&flagPort, "port", 8000, "listen port")
	flag.StringVar(&flagConfig, "config", os.Getenv("CONFIG_FILE"), "config file path")
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
			http.NotFound(writer, request)
			return
		}

		domain := path[:pos]
		suffix := path[pos+1:]
		_ = suffix

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

		newRequest, err := http.NewRequest(request.Method, fullUri, request.Body)
		if err != nil {
			log.Printf("%s %d: %v", request.RequestURI, http.StatusInternalServerError, err)
			http.Error(writer, "server error: "+err.Error(), http.StatusInternalServerError)
			return
		}

		if registry != nil && registry.Username != "" {
			newRequest.Header.Set("authorization", "basic "+base64.StdEncoding.EncodeToString([]byte(registry.Username+":"+registry.Password)))
		}

		response, err := client.Do(newRequest)
		if err != nil {
			log.Printf("%s %d: %v", request.RequestURI, http.StatusInternalServerError, err)
			http.Error(writer, "server error: "+err.Error(), http.StatusInternalServerError)
			return
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

	if err := http.Serve(listener, mux); err != nil {
		log.Fatalln(err)
	}
}