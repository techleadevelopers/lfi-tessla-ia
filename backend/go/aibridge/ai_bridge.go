package aibridge

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"time"
)

// Structs para geração via IA
type AIPayloadRequest struct {
	BasePayload string `json:"base_payload"`
	Context     string `json:"context"`
	WAF         string `json:"waf,omitempty"`
}

type AIPayloadResponse struct {
	Variants []string `json:"variants"`
}

// Structs para Reinforcement Learning
type RLFeedback struct {
	Payload     string `json:"payload"`
	StatusCode  int    `json:"status_code"`
	LatencyMs   int64  `json:"latency_ms"`
	WAFDetected string `json:"waf_detected"`
}

// Geração IA (ex: GAN, LLM local) com base no payload e contexto (stack/waf)
func GerarPayloadIA(basePayload string, context string) ([]string, error) {
	reqBody := AIPayloadRequest{BasePayload: basePayload, Context: context}
	jsonData, err := json.Marshal(reqBody)
	if err != nil {
		return nil, err
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Post("http://127.0.0.1:5000/gen", "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var response AIPayloadResponse
	err = json.Unmarshal(bodyBytes, &response)
	if err != nil {
		return nil, err
	}

	return response.Variants, nil
}

// Feedback pós-scan para ajuste IA em modo Reinforcement Learning
func EnviarFeedbackReforco(payload string, status int, latency int64, waf string) error {
	feedback := RLFeedback{
		Payload:     payload,
		StatusCode:  status,
		LatencyMs:   latency,
		WAFDetected: waf,
	}
	jsonData, err := json.Marshal(feedback)
	if err != nil {
		return err
	}

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Post("http://127.0.0.1:5000/feedback", "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return nil
}

// LoadContext pode recuperar memória anterior de contexto (stub brutal real)
func LoadContext(baseURL string) {
	// futuramente: carregar histórico da IA para domínio
}
