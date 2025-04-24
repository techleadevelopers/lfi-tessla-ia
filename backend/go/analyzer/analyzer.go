package analyzer

import (
	"io"
	"net/http"
	"regexp"
	"strings"
)

// DetectarWAF identifica padrões típicos de bloqueio ou presença de WAFs reais
func DetectarWAF(statusCode int, headers http.Header, body string) string {
	lowerBody := strings.ToLower(body)

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
	if strings.Contains(bodyStr, "denied") || strings.Contains(bodyStr, "forbidden") {
		return true
	}

	return false
}
