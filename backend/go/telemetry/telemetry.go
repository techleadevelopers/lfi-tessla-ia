package telemetry

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"time"
)

// Estrutura dos dados de telemetria
type TelemetryData struct {
	Payload    string    `json:"payload"`
	StatusCode int       `json:"status"`
	LatencyMs  int64     `json:"time_ms"`
	WAF        string    `json:"waf"`
	Snippet    string    `json:"snippet"`
	Timestamp  time.Time `json:"timestamp"`
	Success    bool      `json:"success"` // indica se o ataque obteve sucesso
}

// canal interno para envio assíncrono
var telemetryChan = make(chan TelemetryData, 100)

// init dispara o worker uma única vez
func init() {
	go telemetryWorker()
}

// worker consome o canal e envia cada TelemetryData
func telemetryWorker() {
	for data := range telemetryChan {
		EnviarTelemetry(data)
	}
}

// ProcessarDados enfileira uma telemetria para envio assíncrono
func ProcessarDados(payload string, statusCode int, latencyMs int64, waf string, snippet string, success bool) {
	data := ColetarDados(payload, statusCode, latencyMs, waf, snippet, success)
	select {
	case telemetryChan <- data:
		// enfileirado com sucesso, exibe resumo
		logResumo(data)
	default:
		// canal cheio: salva localmente para não perder
		log.Printf("⚠️ Canal cheio, salvando telemetria localmente: payload=%s", data.Payload)
		salvarTelemetriaLocalmente(data)
	}
}

// ColetarDados monta o TelemetryData
func ColetarDados(payload string, statusCode int, latencyMs int64, waf, snippet string, success bool) TelemetryData {
	return TelemetryData{
		Payload:    payload,
		StatusCode: statusCode,
		LatencyMs:  latencyMs,
		WAF:        waf,
		Snippet:    snippet,
		Timestamp:  time.Now(),
		Success:    success,
	}
}

// EnviarTelemetry envia o JSON por TCP com retries, timeouts e backoff
func EnviarTelemetry(data TelemetryData) {
	const (
		addr         = "127.0.0.1:8088"
		maxRetries   = 3
		dialTimeout  = 5 * time.Second
		writeTimeout = 3 * time.Second
		backoff      = 2 * time.Second
	)

	// serializa uma vez
	jsonData, err := json.Marshal(data)
	if err != nil {
		log.Printf("❌ Falha ao serializar telemetria: %v", err)
		return
	}

	for attempt := 1; attempt <= maxRetries; attempt++ {
		conn, err := net.DialTimeout("tcp", addr, dialTimeout)
		if err != nil {
			log.Printf("❌ Tentativa %d conectar %s falhou: %v", attempt, addr, err)
		} else {
			_ = conn.SetWriteDeadline(time.Now().Add(writeTimeout))
			_, err = conn.Write(jsonData)
			conn.Close()
			if err != nil {
				log.Printf("❌ Erro no envio (tent %d): %v", attempt, err)
			} else {
				logTelemetriaSucessoFalha(data)
				return
			}
		}
		if attempt < maxRetries {
			time.Sleep(backoff)
		} else {
			log.Printf("💥 Todas tentativas falharam. Salvando localmente.")
			salvarTelemetriaLocalmente(data)
		}
	}
}

// salvarTelemetriaLocalmente grava um arquivo JSON com timestamp nanosegundos
func salvarTelemetriaLocalmente(data TelemetryData) {
	ts := time.Now().Format("2006-01-02_15-04-05.000000000")
	fileName := fmt.Sprintf("telemetria_falha_%s.json", ts)
	f, err := os.OpenFile(fileName, os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Printf("❌ Não conseguiu criar %s: %v", fileName, err)
		return
	}
	defer f.Close()

	js, _ := json.Marshal(data)
	_, _ = f.Write(js)
	_, _ = f.Write([]byte("\n"))
	log.Printf("📂 Telemetria salva localmente em %s", fileName)
}

// logTelemetriaSucessoFalha exibe resumo amigável no console
func logTelemetriaSucessoFalha(data TelemetryData) {
	mark := "⚠️"
	if data.Success {
		mark = "✅"
	}
	// resumo: Payload, status, latência, WAF
	log.Printf("%s %s  status:%d  lat:%dms  waf:%s",
		mark, data.Payload, data.StatusCode, data.LatencyMs, data.WAF)
}

// logResumo exibe breve resumo no enfileiramento
func logResumo(data TelemetryData) {
	log.Printf("⏳ Enfileirado: %s  status:%d  lat:%dms",
		data.Payload, data.StatusCode, data.LatencyMs)
}
