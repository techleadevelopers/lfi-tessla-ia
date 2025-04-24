
# 📚 Documentação Técnica - LFI TESSLA (Módulos em Go)

Este documento descreve **em detalhes** todos os módulos Go implementados até agora para o projeto **LFI TESSLA**, explicando suas funções, integração e propósito no fluxo de ataque furtivo assistido por IA.

---

## 🔹 1. `main.go`

### ✨ Função:
Controla a execução geral do ataque LFI, rodando múltiplos payloads contra URLs com parâmetros vulneráveis, detectando vazamentos e coletando os resultados.

### 🔗 Integrações:
- Utiliza `mutator.MutarPayload()` para gerar múltiplas variações evasivas de cada payload.
- Usa `headers.GerarHeadersRealistas()` para montar headers furtivos e realistas.
- Usa `proxy.CriarClienteComProxy()` para enviar requisições através de proxies SOCKS5 (ex: Tor).
- Usa `analyzer.DetectarWAF()` para analisar a resposta do alvo e classificar possíveis bloqueios por WAF.
- Usa `analyzer.ClassificarVazamento()` para categorizar o tipo de vazamento encontrado.
- Futuramente pode usar `aibridge.GerarPayloadIA()` para gerar novos payloads dinâmicos baseados no feedback.

---

## 🔹 2. `headers.go`

### ✨ Função:
Gera headers HTTP altamente realistas e dinâmicos, simulando requisições legítimas de navegadores reais, dificultando a detecção por WAFs baseados em fingerprinting.

### 🔧 O que inclui:
- Geração aleatória de `User-Agent`
- Headers adicionais como `Referer`, `DNT`, `Sec-Fetch`, etc.
- Simulação de IP falso com `X-Forwarded-For`

---

## 🔹 3. `proxy.go`

### ✨ Função:
Permite que o ataque passe por um proxy SOCKS5 (exemplo: rede Tor ou proxy rotativo), ocultando o IP real do scanner e contornando sistemas de rate-limiting.

### 🔧 O que inclui:
- Cliente HTTP configurado com `http.Transport` via `http.ProxyURL`
- Timeout e gerenciamento de conexões ajustados para stealth

---

## 🔹 4. `mutator.go`

### ✨ Função:
Gera automaticamente variantes obfuscadas de payloads LFI para burlar mecanismos de pattern matching e regex em WAFs.

### 🔧 O que inclui:
- `MutarPayload()`: retorna variações com double encoding, null byte, UTF-8 bypass, etc.
- `MutarComTemplates()`: gera payloads com base em estrutura tipo template (ex: `../../%DIR%/%TARGET%.%EXT%`)

---

## 🔹 5. `analyzer.go`

### ✨ Função:
Analisa respostas dos servidores e tenta identificar se há um WAF em ação, além de classificar o tipo de vazamento detectado com base no conteúdo textual da resposta.

### 🔧 O que inclui:
- `DetectarWAF(status, body)`: retorna mensagens como "🔒 WAF bloqueando", "ModSecurity", etc.
- `ClassificarVazamento(body)`: classifica entre vazamento genérico, dados sensíveis, banco SQLite, etc.

---

## 🔹 6. `ai_bridge.go`

### ✨ Função:
Integra o backend Go com o gerador IA escrito em Python (via API REST), permitindo que novos payloads adaptativos sejam gerados em tempo real com base em feedback do alvo.

### 🔧 O que inclui:
- Structs `AIPayloadRequest` e `AIPayloadResponse`
- Função `GerarPayloadIA()` que envia `basePayload` + `context` para `http://127.0.0.1:5000/gen` e retorna múltiplos payloads

---

## 🧠 Fluxo Operacional Atual

1. `main.go` carrega os payloads brutos.
2. `mutator.go` gera múltiplas versões para cada payload.
3. Cada versão é usada em uma requisição via proxy (opcional via `proxy.go`).
4. Headers são aplicados via `headers.go`.
5. A resposta é inspecionada por `analyzer.go`.
6. Se necessário, `ai_bridge.go` gera novos payloads IA com base no feedback.

---

## 🛠️ Requisitos

- Go 1.19+
- Proxy SOCKS5 (ex: Tor rodando em `127.0.0.1:9050`)
- Python Flask rodando o serviço IA em `localhost:5000`

---

## ✅ Próximo passo sugerido:
- Integração contínua dos módulos via REST
- Interface frontend em React para visualizar as fases do ataque

© 2025 - LFI TESSLA Offensive Security Framework



