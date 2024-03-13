package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"flag"
	"fmt"
	"github.com/jc-lab/docker-path-proxy-go/model"
	"github.com/jclab-joseph/doh-go"
	"github.com/jclab-joseph/doh-go/bootstrapclient"
	"github.com/jclab-joseph/doh-go/dns"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
)

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

type DohApp struct {
	ctx        context.Context
	c          *doh.DoH
	httpClient *http.Client
}

func (a *DohApp) DohDialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host := addr
	p := strings.LastIndex(addr, ":")
	suffix := ""
	if p >= 0 {
		host = addr[:p]
		suffix = addr[p:]
	}
	rsp, err := a.c.Query(ctx, a.httpClient, dns.Domain(host), dns.TypeA)
	if err != nil {
		return nil, err
	}
	if len(rsp.Answer) <= 0 {
		return nil, fmt.Errorf("resolve failed: " + host)
	}
	return net.Dial(network, rsp.Answer[0].Data+suffix)
}

func main() {
	var app DohApp
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

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	app.ctx = ctx

	if flagUseDoh {
		app.c = doh.Use(doh.CloudflareProvider, doh.GoogleProvider)
		transport := bootstrapclient.StaticDnsTransport()
		transport.Proxy = http.ProxyFromEnvironment
		app.httpClient = &http.Client{
			Transport: transport,
		}

		defer app.c.Close()
	}

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
		Proxy: http.ProxyFromEnvironment,
		TLSClientConfig: &tls.Config{
			RootCAs: rootCAs,
		},
	}
	if flagUseDoh {
		transport.DialContext = app.DohDialContext
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

		for key, values := range request.Header {
			for _, value := range values {
				newRequest.Header.Add(key, value)
			}
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
