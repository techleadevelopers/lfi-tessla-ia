package utlsmux

import (
	"crypto/tls"
	"net"
	"net/http"
	"time"

	utls "github.com/refraction-networking/utls"
)

// ClientHTTP2ComUTLS retorna um cliente com TLS fingerprint Chrome via uTLS
func ClientHTTP2ComUTLS(targetAddr string) (*http.Client, error) {
	dialTLS := func(network, addr string) (net.Conn, error) {
		rawConn, err := net.DialTimeout(network, addr, 10*time.Second)
		if err != nil {
			return nil, err
		}

		config := &utls.Config{
			ServerName:         addr,
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS12,
		}

		// HelloChrome_Auto escolhe automaticamente a melhor versão de fingerprint
		uConn := utls.UClient(rawConn, config, utls.HelloChrome_Auto)
		if err := uConn.Handshake(); err != nil {
			return nil, err
		}

		return uConn, nil
	}

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
		DialTLS: dialTLS,
	}

	client := &http.Client{
		Transport: tr,
		Timeout:   20 * time.Second,
	}
	return client, nil
}
