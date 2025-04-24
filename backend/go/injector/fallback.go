package injector

import (
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type FallbackResult struct {
	Success bool
	Body    string
	Canal   string
}

// TentarFallback tenta múltiplos canais de injeção se o método padrão falhar (ex: bloqueado por WAF)
func TentarFallback(baseURL, payload string) FallbackResult {
	canais := []string{"HEADER", "COOKIE", "POST", "FRAGMENT"}

	for _, canal := range canais {
		req, _ := http.NewRequest("GET", baseURL, nil)
		InjectInChannel(req, payload, canal)

		client := &http.Client{Timeout: 10 * time.Second}
		resp, err := client.Do(req)
		if err != nil || resp.StatusCode >= 500 {
			continue
		}

		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			continue
		}

		return FallbackResult{
			Success: true,
			Body:    string(body),
			Canal:   canal,
		}
	}
	return FallbackResult{Success: false}
}

// AutoAdapt ajusta a requisição com base no tipo de WAF detectado
func AutoAdapt(req *http.Request, waf string) *http.Request {
	if strings.Contains(strings.ToLower(waf), "cloudflare") {
		req.Header.Del("X-LFI-Scan")
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
	}
	return req
}

// InjectInChannel injeta o payload de forma furtiva em diferentes canais
func InjectInChannel(req *http.Request, payload string, canal string) {
	switch canal {
	case "HEADER":
		req.Header.Set("X-Injection-Test", payload)
	case "COOKIE":
		req.AddCookie(&http.Cookie{Name: "session_payload", Value: payload})
	case "POST":
		req.Method = "POST"
		req.Body = io.NopCloser(strings.NewReader("data=" + url.QueryEscape(payload)))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	case "FRAGMENT":
		req.URL.Fragment = payload
	}
}
