package http2mux

import (
	"crypto/tls"
	"net/http"
	"time"

	"golang.org/x/net/http2"
)

// ClientHTTP2ComProxy retorna um cliente HTTP/2 com TLS fingerprint pseudo-customizada
// simulando comportamento de navegadores modernos (ex: Chrome).
func ClientHTTP2ComProxy(_ string) (*http.Client, error) {
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
		CurvePreferences: []tls.CurveID{
			tls.X25519,
			tls.CurveP256,
		},
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		},
	}

	transport := &http2.Transport{
		TLSClientConfig: tlsConfig,
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   20 * time.Second,
	}

	return client, nil
}
