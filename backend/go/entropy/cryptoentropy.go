// Package entropy fornece um arsenal completo de funções para geração,
// análise e perfilamento de entropia em dados binários, projetado para
// cenários ofensivos/red-team, pós-exploit, fuzzing evasivo e pipelines ML.
package entropy

import (
	"bytes"
	"compress/gzip"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	mathrand "math/rand"
	"math/big"
	"strings"
	"time"
	"unicode"
)

// RandInt gera um número aleatório criptograficamente forte [0, n).
// Fallback para clock-based em caso de erro.
func RandInt(n int) int {
	if n <= 0 {
		return 0
	}
	max := big.NewInt(int64(n))
	r, err := rand.Int(rand.Reader, max)
	if err != nil {
		return int(time.Now().UnixNano() % int64(n))
	}
	return int(r.Int64())
}

// RandSeed retorna uma seed 64-bit segura, para math/rand ou jitter.
func RandSeed() int64 {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return time.Now().UnixNano()
	}
	return int64(binary.LittleEndian.Uint64(b[:]))
}

// RandFloat retorna um float64 em [0.0,1.0).
func RandFloat() float64 {
	return float64(RandInt(1_000_000)) / 1_000_000.0
}

// RandDelay retorna um delay aleatório entre minMs e maxMs milissegundos.
func RandDelay(minMs, maxMs int) time.Duration {
	if maxMs <= minMs {
		return time.Duration(minMs) * time.Millisecond
	}
	return time.Duration(RandInt(maxMs-minMs)+minMs) * time.Millisecond
}

// RandCryptoDelay modela delays exponenciais (Poisson) para simular
// comportamento humano/bot evasivo. λ é a taxa (ex: 0.1 → média 10s).
func RandCryptoDelay(lambda float64) time.Duration {
	u := RandFloat()
	d := -math.Log(1-u) / lambda
	return time.Duration(d*1000) * time.Millisecond
}

// RandGaussianDelay modela delays pela distribuição normal com média
// meanMs e desvio stddevMs, retorna valor absoluto.
func RandGaussianDelay(meanMs, stddevMs float64) time.Duration {
	mathrand.Seed(RandSeed())
	d := mathrand.NormFloat64()*stddevMs + meanMs
	if d < 0 {
		d = -d
	}
	return time.Duration(d) * time.Millisecond
}

// Shannon calcula a entropia de Shannon em bits por símbolo.
func Shannon(data []byte) float64 {
	N := float64(len(data))
	if N == 0 {
		return 0
	}
	var freq [256]float64
	for _, b := range data {
		freq[b]++
	}
	var H float64
	for _, f := range freq {
		if f > 0 {
			p := f / N
			H -= p * math.Log2(p)
		}
	}
	return H
}

// KLDivergence calcula D(P‖U) para distribuição uniforme U em 256 símbolos.
// Ajuda a distinguir ruído real de padrões sesgados.
func KLDivergence(data []byte) float64 {
	N := float64(len(data))
	if N == 0 {
		return 0
	}
	var freq [256]float64
	for _, b := range data {
		freq[b]++
	}
	var kl float64
	for _, f := range freq {
		if f == 0 {
			continue
		}
		p := f / N
		kl += p * math.Log2(p*256)
	}
	return kl
}

// EntropyProfile agrupa métricas de entropia e heurísticas.
type EntropyProfile struct {
	Length        int     `json:"length"`
	Shannon       float64 `json:"shannon"`
	KL            float64 `json:"kl"`
	IsUniform     bool    `json:"is_uniform"`
	IsMostlyPrint bool    `json:"is_mostly_print"`
	Base64Score   float64 `json:"base64_score"`
	HexScore      float64 `json:"hex_score"`
}

// AnalyzeEntropy gera EntropyProfile completo, incluindo base64/hex scoring.
func AnalyzeEntropy(data []byte) EntropyProfile {
	H := Shannon(data)
	kl := KLDivergence(data)
	return EntropyProfile{
		Length:        len(data),
		Shannon:       H,
		KL:            kl,
		IsUniform:     H > 7.8 && kl < 0.5,
		IsMostlyPrint: printableRatio(data) > 0.9,
		Base64Score:   base64CharRatio(data),
		HexScore:      hexCharRatio(data),
	}
}

// DeltaEntropy descreve diferença entre dois perfis de entropia.
type DeltaEntropy struct {
	DeltaShannon float64 `json:"delta_shannon"`
	DeltaKL      float64 `json:"delta_kl"`
	Changed      bool    `json:"changed"`
}

// EntropyDeltaProfile compara dois blobs e sinaliza mudanças significativas.
func EntropyDeltaProfile(old, new []byte) DeltaEntropy {
	bef := AnalyzeEntropy(old)
	aft := AnalyzeEntropy(new)
	ds := aft.Shannon - bef.Shannon
	dk := aft.KL - bef.KL
	return DeltaEntropy{
		DeltaShannon: ds,
		DeltaKL:      dk,
		Changed:      math.Abs(ds) > 0.3 || math.Abs(dk) > 0.2,
	}
}

// printableRatio retorna proporção de bytes ASCII imprimíveis.
func printableRatio(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}
	var cnt int
	for _, b := range data {
		if unicode.IsPrint(rune(b)) {
			cnt++
		}
	}
	return float64(cnt) / float64(len(data))
}

// base64CharRatio retorna proporção de caracteres válidos base64.
func base64CharRatio(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}
	var cnt int
	for _, b := range data {
		c := rune(b)
		if ('A' <= c && c <= 'Z') ||
			('a' <= c && c <= 'z') ||
			('0' <= c && c <= '9') ||
			c == '+' || c == '/' || c == '=' {
			cnt++
		}
	}
	return float64(cnt) / float64(len(data))
}

// hexCharRatio retorna proporção de caracteres válidos hexadecimais.
func hexCharRatio(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}
	var cnt int
	for _, b := range data {
		c := rune(b)
		if ('0' <= c && c <= '9') ||
			('a' <= c && c <= 'f') ||
			('A' <= c && c <= 'F') {
			cnt++
		}
	}
	return float64(cnt) / float64(len(data))
}

// RandPayload gera blob de tamanho length com entropia aproximada entropyLevel [0–8].
func RandPayload(entropyLevel float64, length int) []byte {
	if length <= 0 {
		return nil
	}
	mathrand.Seed(RandSeed())
	out := make([]byte, length)
	for i := range out {
		switch {
		case entropyLevel >= 7.5:
			out[i] = byte(RandInt(256))
		case entropyLevel >= 5.0:
			out[i] = byte('a' + RandInt(26))
		case entropyLevel >= 2.0:
			if RandFloat() < 0.5 {
				out[i] = byte('A' + RandInt(26))
			} else {
				out[i] = ' '
			}
		default:
			out[i] = ' '
		}
	}
	return out
}

// FingerprintEntropy classifica blob: jwt, zlib, crypto, base64, zip, elf, pe.
func FingerprintEntropy(data []byte) string {
	s := string(data)
	switch {
	case strings.HasPrefix(s, "eyJ"):
		return "jwt"
	case len(data) > 2 && data[0] == 0x78 && (data[1] == 0x9C || data[1] == 0xDA):
		return "zlib"
	case Shannon(data) > 7.5:
		return "likely-crypto"
	case isBase64(s):
		return "base64"
	case strings.HasPrefix(s, "PK"):
		return "zip"
	case len(data) > 4 && string(data[:4]) == "\x7fELF":
		return "elf"
	case len(data) > 2 && string(data[:2]) == "MZ":
		return "pe"
	default:
		return "unknown"
	}
}

// isBase64 valida comprimento múltiplo de 4 e charset base64.
func isBase64(s string) bool {
	if len(s)%4 != 0 {
		return false
	}
	for _, c := range s {
		if !(('A' <= c && c <= 'Z') ||
			('a' <= c && c <= 'z') ||
			('0' <= c && c <= '9') ||
			c == '+' || c == '/' || c == '=') {
			return false
		}
	}
	return true
}

// EntropyWindow contém início e valor de entropia de uma janela.
type EntropyWindow struct {
	Start   int     `json:"start"`
	Entropy float64 `json:"entropy"`
}

// SlidingWindowEntropy retorna entropias por janela de tamanho win.
func SlidingWindowEntropy(data []byte, win int) []float64 {
	n := len(data)
	if win <= 0 || n < win {
		return nil
	}
	out := make([]float64, n-win+1)
	for i := 0; i <= n-win; i++ {
		out[i] = Shannon(data[i : i+win])
	}
	return out
}

// SlidingWindowEntropyDetailed retorna entropias com posições iniciais.
func SlidingWindowEntropyDetailed(data []byte, win int) []EntropyWindow {
	n := len(data)
	if win <= 0 || n < win {
		return nil
	}
	out := make([]EntropyWindow, n-win+1)
	for i := 0; i <= n-win; i++ {
		out[i] = EntropyWindow{Start: i, Entropy: Shannon(data[i : i+win])}
	}
	return out
}

// VisualizeEntropy desenha heatmap ASCII de entropia por janela.
func VisualizeEntropy(data []byte, win int) string {
	lines := SlidingWindowEntropy(data, win)
	var sb strings.Builder
	for _, h := range lines {
		bar := int((h/8.0)*10 + 0.5)
		if bar < 0 {
			bar = 0
		}
		if bar > 10 {
			bar = 10
		}
		sb.WriteString(fmt.Sprintf("%.2f %s\n", h, strings.Repeat("█", bar)))
	}
	return sb.String()
}

// AutoEntropyAdapt recomenda mutação/ação com base em perfil.
func AutoEntropyAdapt(data []byte) string {
	p := AnalyzeEntropy(data)
	switch {
	case p.Shannon > 7.5 && p.KL < 0.3:
		return "encrypted-or-strongly-random"
	case p.Shannon < 4.0 && p.IsMostlyPrint:
		return "plaintext"
	default:
		return "structured-or-obfuscated"
	}
}

// EntropyLabel fornece rótulo ML-aware para um perfil.
func EntropyLabel(p EntropyProfile) string {
	switch {
	case p.Shannon > 7.9 && p.KL < 0.2:
		return "crypto"
	case p.IsMostlyPrint && p.Shannon < 3.5:
		return "plaintext"
	case p.Shannon > 6.0 && p.Base64Score > 0.8:
		return "base64"
	default:
		return "unknown"
	}
}

// MatchPayloadToEntropy verifica se Shannon(data) ≈ target ±0.1.
func MatchPayloadToEntropy(data []byte, target float64) bool {
	h := Shannon(data)
	return math.Abs(h-target) <= 0.1
}

// EncodeEntropyAware escolhe hex/base64 segundo entropia.
func EncodeEntropyAware(data []byte) string {
	H := Shannon(data)
	if H > 7.0 {
		return hex.EncodeToString(data)
	}
	return base64.StdEncoding.EncodeToString(data)
}

// EntropyAnomalyScore compara diferenças entre dois blobs.
func EntropyAnomalyScore(ref, test []byte) float64 {
	a := AnalyzeEntropy(ref)
	b := AnalyzeEntropy(test)
	return math.Abs(a.Shannon-b.Shannon) + math.Abs(a.KL-b.KL)
}

// GenerateMimicData cria blob que imita EntropyProfile dado.
func GenerateMimicData(profile EntropyProfile) []byte {
	return RandPayload(profile.Shannon, profile.Length)
}

// ToJSON serializa EntropyProfile em JSON.
func (p EntropyProfile) ToJSON() string {
	j, _ := json.Marshal(p)
	return string(j)
}

// ToCSV serializa EntropyProfile em CSV:
// length,shannon,kl,is_uniform,is_mostly_print,base64_score,hex_score
func (p EntropyProfile) ToCSV() string {
	return fmt.Sprintf("%d,%.6f,%.6f,%t,%t,%.6f,%.6f",
		p.Length, p.Shannon, p.KL, p.IsUniform, p.IsMostlyPrint,
		p.Base64Score, p.HexScore)
}

// --- NOVAS FUNÇÕES / SUGESTÕES DE EXTENSÃO FUTURA -------------------------

// compressData aplica gzip a data e retorna o buffer resultante.
func compressData(data []byte) ([]byte, error) {
	var b bytes.Buffer
	w := gzip.NewWriter(&b)
	_, err := w.Write(data)
	w.Close()
	return b.Bytes(), err
}

// NCD calcula Normalized Compression Distance entre x e y.
func NCD(x, y []byte) float64 {
	cx, _ := compressData(x)
	cy, _ := compressData(y)
	cxy, _ := compressData(append(x, y...))
	lenX, lenY, lenXY := float64(len(cx)), float64(len(cy)), float64(len(cxy))
	return (lenXY - math.Min(lenX, lenY)) / math.Max(lenX, lenY)
}

// EntropyBinning conta quantas janelas de tamanho win caem em cada um dos bins.
func EntropyBinning(data []byte, win, bins int) []int {
	if bins <= 0 || win <= 0 || len(data) < win {
		return nil
	}
	counts := make([]int, bins)
	total := len(data) - win + 1
	for i := 0; i < total; i++ {
		h := Shannon(data[i : i+win])
		idx := int(h/8.0*float64(bins)) // normaliza H∈[0,8] para [0,bins)
		if idx < 0 {
			idx = 0
		}
		if idx >= bins {
			idx = bins - 1
		}
		counts[idx]++
	}
	return counts
}

// MaxEntropyWindow retorna a janela de tamanho win com maior entropia.
func MaxEntropyWindow(data []byte, win int) EntropyWindow {
	wins := SlidingWindowEntropyDetailed(data, win)
	if len(wins) == 0 {
		return EntropyWindow{}
	}
	max := wins[0]
	for _, w := range wins {
		if w.Entropy > max.Entropy {
			max = w
		}
	}
	return max
}

// EntropyVisualSVG gera um gráfico SVG interativo das entropias por janela.
func EntropyVisualSVG(data []byte, win, width, height int) string {
	ent := SlidingWindowEntropy(data, win)
	n := len(ent)
	if n == 0 || width <= 0 || height <= 0 {
		return ""
	}
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf(`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 %d %d">`, width, height))
	sb.WriteString(`<polyline fill="none" stroke="red" stroke-width="1" points="`)
	for i, h := range ent {
		x := float64(i) / float64(n-1) * float64(width)
		y := float64(height) - (h/8.0*float64(height))
		sb.WriteString(fmt.Sprintf("%.2f,%.2f ", x, y))
	}
	sb.WriteString(`"/>`)
	sb.WriteString(`</svg>`)
	return sb.String()
}

// BatchAnalyzeEntropy processa em lote múltiplos blobs e retorna seus perfis.
func BatchAnalyzeEntropy(dataset [][]byte) []EntropyProfile {
	out := make([]EntropyProfile, len(dataset))
	for i, data := range dataset {
		out[i] = AnalyzeEntropy(data)
	}
	return out
}