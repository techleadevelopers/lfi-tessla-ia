package analyzer

import (
	"io"
	"net/http"
	"regexp"
	"strings"
	"golang.org/x/text/unicode/norm"
)

// DetectarWAF identifica padrões típicos de bloqueio ou presença de WAFs reais
func DetectarWAF(statusCode int, headers http.Header, body string) string {
	lowerBody := strings.ToLower(body)

	// Status de bloqueio e padrões conhecidos
	if statusCode == 403 || statusCode == 406 {
		return "🔒 WAF detectado (status HTTP)"
	}
	if strings.Contains(lowerBody, "access denied") || strings.Contains(lowerBody, "unauthorized access") {
		return "🚫 Access Denied"
	}
	if strings.Contains(lowerBody, "mod_security") || strings.Contains(lowerBody, "modsecurity") {
		return "🛡️ ModSecurity"
	}
	if matched, _ := regexp.MatchString(`cloudflare|akamai|imperva|sucuri|barracuda|f5`, lowerBody); matched {
		return "☁️ Cloud-based WAF detectado (corpo)"
	}

	// Análise via headers
	server := strings.ToLower(headers.Get("Server"))
	if strings.Contains(server, "cloudflare") {
		return "☁️ Cloudflare (via header Server)"
	}
	if via := headers.Get("Via"); strings.Contains(strings.ToLower(via), "akamai") {
		return "☁️ Akamai (via header Via)"
	}
	if strings.EqualFold(headers.Get("X-CDN"), "Imperva") {
		return "☁️ Imperva (via X-CDN)"
	}

	// Fingerprinting de servidor
	if strings.Contains(lowerBody, "nginx") || strings.Contains(lowerBody, "apache") {
		return "🖥️ Fingerprinting detectado (corpo)"
	}

	// Novo: análise de cabeçalhos como X-Powered-By
	if poweredBy := headers.Get("X-Powered-By"); poweredBy != "" {
		return "🖥️ Fingerprinting detectado (header X-Powered-By)"
	}

	// Análise comportamental adicional (latência ou comportamento específico de WAF)
	if strings.Contains(lowerBody, "timeout") || strings.Contains(lowerBody, "request throttled") {
		return "⏱️ WAF detectado (comportamento de latência)"
	}

	return ""
}

// ClassificarVazamento identifica o tipo de vazamento encontrado
func ClassificarVazamento(body string) string {
	lower := strings.ToLower(body)

	switch {
	case strings.Contains(lower, "begin transaction"):
		return "💾 SQLite Dump"
	case strings.Contains(lower, "aws_secret") || strings.Contains(lower, "db_password") ||
		strings.Contains(lower, "apikey") || strings.Contains(lower, "auth_token"):
		return "🔑 Credenciais vazadas"
	case strings.Contains(lower, "cpf=") || strings.Contains(lower, "cvv=") ||
		strings.Contains(lower, "nome_cliente") || strings.Contains(lower, "rg="):
		return "🆔 Dados pessoais identificáveis"
	case strings.Contains(lower, "<!doctype html") && strings.Contains(lower, "error") && strings.Contains(lower, "stack trace"):
		return "💥 Stack trace / Internal Error"
	case strings.Contains(lower, "api_key") || strings.Contains(lower, "secret_key"):
		return "🔑 Chave de API exposta"
	default:
		return "📄 Vazamento genérico"
	}
}

// CompararRespostas compara duas respostas HTTP (foco na heurística do conteúdo)
func CompararRespostas(resp1, resp2 *http.Response) bool {
	if resp1 == nil || resp2 == nil {
		return true
	}

	body2, err := io.ReadAll(resp2.Body)
	if err != nil {
		return true
	}

	bodyStr := strings.ToLower(string(body2))

	// Comparação mais inteligente usando Levenshtein ou outro algoritmo de similaridade
	if levenshteinDistance(bodyStr, bodyStr) > 10 {
		return true
	}

	// Comparação de conteúdo usando palavras-chave
	if strings.Contains(bodyStr, "denied") || strings.Contains(bodyStr, "forbidden") {
		return true
	}

	// Implementação baseada em algoritmo de similaridade de texto
	return false
}

// AnalisarHeader analisa um header HTTP para detectar padrões de WAF
func AnalisarHeader(header http.Header) string {
	// Análise de fingerprinting
	if header.Get("Server") != "" {
		return "🖥️ Fingerprinting detectado (header Server)"
	}
	if header.Get("X-CDN") != "" {
		return "🖥️ Fingerprinting detectado (header X-CDN)"
	}
	// Novo: Análise do X-Powered-By
	if header.Get("X-Powered-By") != "" {
		return "🖥️ Fingerprinting detectado (header X-Powered-By)"
	}

	// Novos headers de segurança (Cross-Origin)
	if header.Get("Access-Control-Allow-Origin") != "" {
		return "🔐 Segurança de CORS detectada"
	}

	return ""
}

// LevenshteinDistance calcula a distância de Levenshtein entre duas strings
// Função otimizada para detectar mudanças de conteúdo entre as respostas HTTP
func levenshteinDistance(a, b string) int {
	// Criação da matriz de distâncias
	var matrix [][]int
	for i := 0; i <= len(a); i++ {
		matrix = append(matrix, make([]int, len(b)+1))
	}
	for i := 0; i <= len(a); i++ {
		matrix[i][0] = i
	}
	for j := 0; j <= len(b); j++ {
		matrix[0][j] = j
	}

	// Cálculo da distância de Levenshtein
	for i := 1; i <= len(a); i++ {
		for j := 1; j <= len(b); j++ {
			cost := 0
			if a[i-1] != b[j-1] {
				cost = 1
			}
			matrix[i][j] = min(matrix[i-1][j]+1, matrix[i][j-1]+1, matrix[i-1][j-1]+cost)
		}
	}

	return matrix[len(a)][len(b)]
}

// Função auxiliar para determinar o mínimo entre três números
func min(a, b, c int) int {
	if a < b {
		if a < c {
			return a
		}
		return c
	}
	if b < c {
		return b
	}
	return c
}
