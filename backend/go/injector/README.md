🧩 Visão Geral do Módulo injector.go
Este módulo executa injeção multi-canal de payloads em URLs de alvo usando estratégias adaptativas, incluindo:

Mutação de payloads baseada em canal

Prioridade dinâmica com base em fingerprint de WAF

Feedback de modelo de ML leve para reordenar canais

Fallback direto e logging estruturado para corpus de telemetria

🔧 Principais Componentes Técnicos

Componente	Descrição
InjectPayload()	Função principal de ataque, tenta múltiplos canais com backoff
tryCanal()	Executa requisição específica por canal e registra métricas
MutatePayload()	Altera payload com base no tipo de canal (ex: base64, JSON, escape)
RandomFuzz()	Aplica fuzzing simples (ex: %2f, %252f)
MLModel	Modelo de aprendizado leve que pontua canais por sucesso histórico
EnviarTelemetry()	Emite telemetria para monitoramento e aprendizado
logAttack()	Persiste logs estruturados em arquivo attack_corpus.log
TentarFallback()	Última tentativa via GET direto com payload puro
🔄 Ciclo de Injeção – InjectPayload()
Parsing: Valida a URL de entrada e extrai o host.

Fingerprint de WAF: Detecta WAF simulado (DetectWAF) e ordena canais por preferência.

ML Model Sorting: Ordena canais com base em pontuação histórica (mlModel.Score).

Execução concorrente:

Até 2 tentativas por canal

Segunda tentativa aplica mutação (MutatePayload) e fuzz (RandomFuzz)

Timeout adaptativo: Reage a latência + código 403

Logging estruturado: TelemetryData salvo + feedback no modelo

Encerramento antecipado: cancela todas as goroutines após sucesso

🛠️ Canais de Injeção Suportados
HEADER: headers padrão e esotéricos (X-Original-URL, etc)

COOKIE: via cookie authz (base64)

POST: form URL-encoded

FRAGMENT: fragmento #payload

QUERY: injeção em query string ?injection=

MULTIPART: payload como campo de upload

JSON: corpo JSON { "injected": payload }

TRACE / OPTIONS: métodos HTTP com payload embutido

BODY_RAW: corpo bruto octet-stream

XML: formato XML básico com payload

GRAPHQL: wrapper GraphQL mínimo

🧠 Inteligência Adaptativa
🧪 Mutação Específica por Canal
HEADER → base64

COOKIE → URL-encoded

JSON → {"kNNNN": "payload"}

QUERY → escape unicode %uHHHH

Outros → reverso do payload

🧬 Fuzzing
Substituições como / → %2f e variantes

📈 Modelo de Aprendizado Leve (MLModel)
Mantém pontuação por canal

Aumenta score em sucesso, reduz em falha

Usado para reordenar tentativas

📦 Logs e Telemetria
Todos os ataques geram um TelemetryData com:

Canal, payload, status HTTP, tempo de resposta, erro (se houver)

Mutação usada, fuzzing aplicado, WAF detectado

Logs escritos em attack_corpus.log

Pronto para alimentar pipelines de ML offline

🧨 Fallback Final – TentarFallback()
Executa um simples GET <url+payload>

Usado quando todas tentativas por canal falham

Retorna FallbackResult{Success, Body, Reward}

🧰 Outros Utilitários
prioritizeCanais(): ordena canais com base em WAF

DetectWAF(): stub fixo (ex: retorna "cloudflare")

reverseSlice(): inverte slice de canais para segunda tentativa

errString(): conversão segura de erro para string

🔄 Execução Concorrente
Usa goroutines e sync.WaitGroup para atacar todos os canais em paralelo

Mecanismo de context.WithCancel para parar ao primeiro sucesso

📎 Extensibilidade Sugerida
Reforço de DetectWAF com integração real (ex: analyzer.go)

Integração com utlslocal.NewHTTPClient real com spoofing

Exportação de telemetria para bancos externos (ex: Kafka, Clickhouse)

Aprendizado contínuo com ML real (ex: XGBoost por canal)