package telemetry

import (
	"encoding/json"
	"log"
	"net"
)

// Estrutura dos dados de telemetria
type TelemetryData struct {
	Payload    string `json:"payload"`
	StatusCode int    `json:"status"`
	LatencyMs  int64  `json:"time_ms"`
	WAF        string `json:"waf"`
	Snippet    string `json:"snippet"` // ← campo necessário para o main.go
}

// EnviarTelemetry envia os dados de ataque para um servidor TCP (ou WebSocket futuramente)
func EnviarTelemetry(data TelemetryData) {
	conn, err := net.Dial("tcp", "127.0.0.1:8088") // Endereço do servidor de dashboard
	if err != nil {
		log.Printf("❌ Falha ao conectar no socket de telemetria: %v", err)
		return
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
	}
}
