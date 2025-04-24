
package http2utlsmux

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/http2"
)

// ClientHTTP2ComUTLS retorna um cliente HTTP/2 com handshake furtivo via uTLS (Chrome-like)
func ClientHTTP2ComUTLS(proxyAddr string) (*http.Client, error) {
	proxyURL, err := url.Parse(proxyAddr)
	if err != nil {
		return nil, fmt.Errorf("erro ao parsear proxy: %w", err)
	}

	dialer := &net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 30 * time.Second,
	}

	transport := &http2.Transport{
		AllowHTTP: false,
		DialTLS: func(network, addr string, _ *tls.Config) (net.Conn, error) {
			// Etapa 1: Conecta no proxy via TCP
			conn, err := dialer.DialContext(context.Background(), "tcp", proxyURL.Host)
			if err != nil {
				return nil, fmt.Errorf("erro ao conectar no proxy: %w", err)
			}

			// Etapa 2: Envia CONNECT para abrir túnel
			connectReq := &http.Request{
				Method: "CONNECT",
				URL:    &url.URL{Opaque: addr},
				Host:   addr,
				Header: make(http.Header),
			}
			connectReq.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) TESSLA/2050")
			if err := connectReq.Write(conn); err != nil {
				return nil, fmt.Errorf("erro ao enviar CONNECT: %w", err)
			}

			resp, err := http.ReadResponse(bufio.NewReader(conn), connectReq)
			if err != nil {
				return nil, fmt.Errorf("erro na resposta CONNECT: %w", err)
			}
			if resp.StatusCode != http.StatusOK {
				return nil, fmt.Errorf("proxy CONNECT falhou: %v", resp.Status)
			}

			// Etapa 3: Envia handshake uTLS com fingerprint Chrome real
			utlsConf := &utls.Config{
				ServerName:         addr,
				InsecureSkipVerify: true,
			}
			utlsConn := utls.UClient(conn, utlsConf, utls.HelloChrome_Auto)
			if err := utlsConn.Handshake(); err != nil {
				return nil, fmt.Errorf("handshake uTLS falhou: %w", err)
			}

			return utlsConn, nil
		},
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   25 * time.Second,
	}
	return client, nil
}
