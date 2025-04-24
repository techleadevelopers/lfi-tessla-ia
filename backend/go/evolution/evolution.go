package evolution

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"
)

type Gene struct {
	Payload string `json:"payload"`
	Fitness int    `json:"fitness"`
}

type Population struct {
	Target string `json:"target"`
	Genes  []Gene `json:"genes"`
}

// LoadPopulation carrega a população para o domínio alvo
func LoadPopulation(target string) *Population {
	path := popPath(target)
	data, err := os.ReadFile(path)
	if err != nil {
		return &Population{Target: target}
	}
	var pop Population
	err = json.Unmarshal(data, &pop)
	if err != nil {
		return &Population{Target: target}
	}
	return &pop
}

// RecordSuccess aumenta a fitness do payload
func RecordSuccess(pop *Population, payload string) {
	for i := range pop.Genes {
		if pop.Genes[i].Payload == payload {
			pop.Genes[i].Fitness++
			_ = savePopulation(pop)
			return
		}
	}
	pop.Genes = append(pop.Genes, Gene{Payload: payload, Fitness: 1})
	_ = savePopulation(pop)
}

// GenerateNextPopulation faz mutações e crossovers
func GenerateNextPopulation(pop *Population) {
	top := SelecionarTop(pop.Genes, 5)
	var novos []Gene
	for _, pai := range top {
		for _, mae := range top {
			if pai.Payload != mae.Payload {
				child := Crossover(pai, mae)
				novos = append(novos, child)
				novos = append(novos, Mutate(child))
			}
		}
	}
	pop.Genes = append(top, novos...)
	_ = savePopulation(pop)
}

// Seleciona os top N genes da população
func SelecionarTop(populacao []Gene, n int) []Gene {
	sort.Slice(populacao, func(i, j int) bool {
		return populacao[i].Fitness > populacao[j].Fitness
	})
	if len(populacao) < n {
		return populacao
	}
	return populacao[:n]
}

// Crossover entre dois genes
func Crossover(p1, p2 Gene) Gene {
	mid := len(p1.Payload) / 2
	child := p1.Payload[:mid] + p2.Payload[mid:]
	return Gene{Payload: child, Fitness: 0}
}

// Mutação aleatória
func Mutate(g Gene) Gene {
	mutations := []string{"%2f", "%252f", "%00", ".jpg", "//", "%c0%af"}
	m := mutations[time.Now().UnixNano()%int64(len(mutations))]
	pos := int(time.Now().UnixNano() % int64(len(g.Payload)))
	newPayload := g.Payload[:pos] + m + g.Payload[pos:]
	return Gene{Payload: newPayload, Fitness: 0}
}

// Caminho do arquivo de população
func popPath(target string) string {
	dir := ".tessla-cache"
	_ = os.MkdirAll(dir, 0700)
	filename := filepath.Join(dir, fmt.Sprintf("%x.json", hash(target)))
	return filename
}

// Salva população no disco
func savePopulation(pop *Population) error {
	data, err := json.MarshalIndent(pop, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(popPath(pop.Target), data, 0600)
}

// Hash simples (placeholder seguro)
func hash(s string) uint32 {
	var h uint32 = 2166136261
	for i := 0; i < len(s); i++ {
		h ^= uint32(s[i])
		h *= 16777619
	}
	return h
}
