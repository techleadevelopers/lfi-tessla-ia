package headers

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	mathrand "math/rand"
	"math/big"
	"net/http"
	"time"
)

var userAgents = []string{
	// desktop
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/115.0.5790.170 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 13_4) AppleWebKit/605.1.15 Version/16.5 Safari/605.1.15",
	"Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/116.0",
	// mobile
	"Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 Chrome/115.0.5790.170 Mobile Safari/537.36",
	"Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 Version/17.0 Mobile/15E148 Safari/604.1",
}

var referers = []string{
	"https://www.google.com/search?q=%s",
	"https://www.bing.com/search?q=%s",
	"https://duckduckgo.com/?q=%s",
	"https://search.brave.com/search?q=%s",
	"https://yandex.com/search/?text=%s",
}

var acceptLanguages = []string{
	"en-US,en;q=0.9",
	"pt-BR,pt;q=0.8,en-US;q=0.5,en;q=0.3",
	"es-ES,es;q=0.9,en;q=0.7",
	"de-DE,de;q=0.9,en-US;q=0.6,en;q=0.4",
}

func init() {
	mathrand.Seed(time.Now().UnixNano())
}

// GerarHeadersRealistas retorna headers furtivos realistas simulando tráfego legítimo
func GerarHeadersRealistas() http.Header {
	h := http.Header{}

	// User-Agent aleatório
	h.Set("User-Agent", userAgents[mathrand.Intn(len(userAgents))])

	// X-Forwarded-For: IPv4 ou IPv6 random
	if mathrand.Float64() < 0.3 {
		h.Set("X-Forwarded-For", gerarIPv6Fake())
	} else {
		h.Set("X-Forwarded-For", gerarIPFake())
	}

	// Referer variado
	term := []string{"oficial", "produto", "compras", "review", "tutorial"}[mathrand.Intn(5)]
	ref := fmt.Sprintf(referers[mathrand.Intn(len(referers))], term)
	h.Set("Referer", ref)

	// Accept-Language
	h.Set("Accept-Language", acceptLanguages[mathrand.Intn(len(acceptLanguages))])

	// Cabeçalhos padrão de navegador
	h.Set("DNT", "1")
	h.Set("Upgrade-Insecure-Requests", "1")
	h.Set("Sec-Fetch-Site", "none")
	h.Set("Sec-Fetch-Mode", "navigate")
	h.Set("Sec-Fetch-Dest", "document")
	h.Set("Sec-Ch-Ua", fmt.Sprintf(`"Chromium";v="%d"`, mathrand.Intn(20)+100))
	h.Set("Sec-Ch-Ua-Mobile", "?0")

	// Headers de performance e cache
	h.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	h.Set("Cache-Control", "max-age=0")
	h.Set("Pragma", "no-cache")

	// Cabeçalhos “quânticos” / tracing
	if mathrand.Float64() < 0.5 {
		h.Set("traceparent", gerarTraceparent())
	}
	if mathrand.Float64() < 0.3 {
		h.Set("X-Cloud-Trace-Context", gerarCloudTrace())
	}
	if mathrand.Float64() < 0.2 {
		h.Set("X-Quantum-Nonce", gerarQuantumNonce(16))
	}

	// Simula overrides de proxy / método
	if mathrand.Float64() < 0.2 {
		h.Set("X-HTTP-Method-Override", []string{"GET", "POST", "HEAD"}[mathrand.Intn(3)])
	}
	if mathrand.Float64() < 0.2 {
		h.Set("X-Forwarded-Host", fmt.Sprintf("srv-%d.internal.local", mathrand.Intn(1000)))
	}

	// Manter conexão viva
	h.Set("Connection", "keep-alive")

	return h
}

func gerarIPFake() string {
	return fmt.Sprintf("%d.%d.%d.%d",
		mathrand.Intn(254)+1,
		mathrand.Intn(256),
		mathrand.Intn(256),
		mathrand.Intn(254)+1,
	)
}

func gerarIPv6Fake() string {
	// simples hextet random
	return fmt.Sprintf("%x:%x:%x:%x:%x:%x:%x:%x",
		mathrand.Intn(0xffff), mathrand.Intn(0xffff),
		mathrand.Intn(0xffff), mathrand.Intn(0xffff),
		mathrand.Intn(0xffff), mathrand.Intn(0xffff),
		mathrand.Intn(0xffff), mathrand.Intn(0xffff),
	)
}

func gerarQuantumNonce(length int) string {
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		return ""
	}
	return hex.EncodeToString(b)
}

func gerarTraceparent() string {
	// versão-00 | trace-id (16 bytes) | span-id (8 bytes) | flags
	traceID := gerarQuantumNonce(16)
	spanID := gerarQuantumNonce(8)
	return fmt.Sprintf("00-%s-%s-01", traceID, spanID)
}

func gerarCloudTrace() string {
	// cria limite = 2^63 como *big.Int
	limit := new(big.Int).Lsh(big.NewInt(1), 63)
	id, err := rand.Int(rand.Reader, limit)
	if err != nil {
		id = big.NewInt(0)
	}
	ts := time.Now().Unix()
	return fmt.Sprintf("%x/%d;o=1", id, ts)
}
