package entropy

import (
	"crypto/rand"
	"encoding/binary"
	"math"
	"math/big"
	"time"
)

// RandInt gera um número aleatório criptograficamente forte entre 0 e n-1.
func RandInt(n int) int {
	if n <= 0 {
		return 0
	}
	max := big.NewInt(int64(n))
	r, err := rand.Int(rand.Reader, max)
	if err != nil {
		return int(time.Now().UnixNano() % int64(n)) // fallback clock-based
	}
	return int(r.Int64())
}

// RandSeed gera uma seed segura para shuffles e jitter.
func RandSeed() int64 {
	var b [8]byte
	_, err := rand.Read(b[:])
	if err != nil {
		return time.Now().UnixNano()
	}
	return int64(binary.LittleEndian.Uint64(b[:]))
}

// RandFloat retorna um valor aleatório entre 0.0 e 1.0
func RandFloat() float64 {
	return float64(RandInt(1000000)) / 1000000.0
}

// RandDelay entre min e max em milissegundos.
func RandDelay(minMs, maxMs int) time.Duration {
	if maxMs <= minMs {
		return time.Duration(minMs) * time.Millisecond
	}
	return time.Duration(RandInt(maxMs-minMs)+minMs) * time.Millisecond
}

// Shannon calcula entropia de Shannon do conteúdo
func Shannon(data []byte) float64 {
	if len(data) == 0 {
		return 0.0
	}
	var freq [256]int
	for _, b := range data {
		freq[b]++
	}
	var entropy float64
	for _, f := range freq {
		if f > 0 {
			p := float64(f) / float64(len(data))
			entropy -= p * math.Log2(p)
		}
	}
	return entropy
}
