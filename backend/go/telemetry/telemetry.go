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
	Success    bool      `json:"success"` // Novo campo para sucesso/falha do ataque
}

// EnviarTelemetry envia os dados de ataque para um servidor TCP (ou WebSocket futuramente)
func EnviarTelemetry(data TelemetryData) {
	maxRetries := 3
	for attempt := 1; attempt <= maxRetries; attempt++ {
		conn, err := net.Dial("tcp", "127.0.0.1:8088")
		if err != nil {
			log.Printf("❌ Tentativa %d de conectar no socket de telemetria falhou: %v", attempt, err)
			if attempt == maxRetries {
				log.Printf("💥 Falha de conexão. Salvando telemetria localmente...")
				salvarTelemetriaLocalmente(data) // Salvar localmente após falhas
				return
			}
			time.Sleep(2 * time.Second) // Espera antes de tentar novamente
			continue
		}
		defer conn.Close()

		jsonData, err := json.Marshal(data)
		if err != nil {
			log.Printf("❌ Falha ao serializar dados de telemetria: %v", err)
			return
		}

		_, err = conn.Write(jsonData)
		if err != nil {
			log.Printf("❌ Erro ao enviar telemetria: %v", err)
			if attempt == maxRetries {
				log.Printf("💥 Falha no envio após múltiplas tentativas. Salvando localmente...")
				salvarTelemetriaLocalmente(data) // Salvar localmente em caso de falha final
			}
			continue
		}
		break // Sai do loop caso o envio tenha sido bem-sucedido
	}
}

// ColetarDados coleta dados de telemetria sobre o ataque
func ColetarDados(payload string, statusCode int, latencyMs int64, waf string, snippet string, success bool) TelemetryData {
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

// ProcessarDados processa os dados de telemetria e envia para o servidor
func ProcessarDados(payload string, statusCode int, latencyMs int64, waf string, snippet string, success bool) {
	data := ColetarDados(payload, statusCode, latencyMs, waf, snippet, success)
	EnviarTelemetry(data)
}

// salvarTelemetriaLocalmente salva os dados de telemetria localmente em caso de falha
func salvarTelemetriaLocalmente(data TelemetryData) {
	// Cria um nome de arquivo único com timestamp para evitar sobrescrita de falhas antigas
	timestamp := time.Now().Format("2006-01-02_15-04-05")
	fileName := fmt.Sprintf("telemetria_falha_%s.json", timestamp)
	file, err := os.OpenFile(fileName, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Printf("❌ Erro ao salvar telemetria localmente: %v", err)
		return
	}
	defer file.Close()

	jsonData, err := json.Marshal(data)
	if err != nil {
		log.Printf("❌ Erro ao serializar dados de telemetria para salvar localmente: %v", err)
		return
	}

	_, err = file.Write(jsonData)
	if err != nil {
		log.Printf("❌ Erro ao escrever dados de telemetria no arquivo local: %v", err)
		return
	}
	file.Write([]byte("\n"))
	log.Printf("📂 Telemetria salva localmente em %s", fileName) // Log informando que foi salvo localmente
}

// Log da Telemetria com sucesso/falha do ataque
func logTelemetriaSucessoFalha(data TelemetryData) {
	if data.Success {
		log.Printf("✅ Telemetria enviada com sucesso: %v", data)
	} else {
		log.Printf("⚠️ Telemetria falhou: %v", data)
	}
}
