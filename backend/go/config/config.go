package config

// Lista de proxies disponíveis para rotação furtiva
var ProxyList = []string{
	"socks5://127.0.0.1:9050",
	"http://proxy1:8080",
}

// Endpoint para geração de payload por IA
const IAEndpoint = "http://localhost:5000/gen"

// Nome do modelo IA para bypass de WAF
const WAFBypassModel = "MAML-v2"

// Habilita/desabilita log local de transportadores (HTTP2/uTLS) usados
const LogStealthRouter = true
