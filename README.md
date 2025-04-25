# 🔥 LFI TESSLA - Next-Generation AI-driven LFI Tester

## 🚀 Objetivo do Projeto

O **LFI TESSLA** é uma ferramenta avançada de testes de segurança cibernética projetada para simular ataques sofisticados de **Local File Inclusion (LFI)** e **Directory Traversal**. Equipada com tecnologia de Inteligência Artificial (IA) embarcada, a ferramenta adapta automaticamente seus ataques para burlar sistemas defensivos modernos, como Web Application Firewalls (WAFs).

Este projeto é destinado ao uso em ambientes controlados (labs de segurança cibernética) para testar, avaliar e reforçar defesas contra ataques emergentes baseados em técnicas avançadas de exploração.

---

## 🧬 Por que o LFI TESSLA é inovador?

- **Payloads gerados por IA:** Utiliza modelos modernos GPT (Mistral-7B, GPT-NeoX, Llama), que criam automaticamente payloads exclusivos para cada tentativa de ataque.
- **Fuzzing de alto desempenho:** Backend híbrido Python-Go proporciona a combinação perfeita entre lógica avançada de IA e performance de fuzzing extremamente rápida.
- **Mutação Adaptativa (Adaptive Fuzzing):** IA aprende em tempo real como burlar novas regras de segurança implementadas por WAFs.

---

## 💡 Recursos Avançados

- ✅ **Automação Completa:** Basta inserir a URL e iniciar o teste para simular ataques em tempo real.
- ✅ **Prompt estilo CMD no Frontend:** Interface visual que simula ataques reais diretamente na tela.
- ✅ **Payload Obfuscation com IA:** Gerador automático de payloads com encoding avançado.
- ✅ **Dashboard Interativo:** ReactJS para monitoramento intuitivo e visualização clara dos resultados.

---

## 📂 Estrutura do Projeto

```
backend/
└── go/
    ├── ai_bridge/
    │   └── ai_bridge.go                   # Módulo para interações com IA
    ├── analyzer/
    │   └── analyzer.go                    # Funções de análise de respostas
    ├── browserexec/
    │   └── browser_exec.go                # Execução de código em browsers headless
    ├── cmd/
    │   └── main.go                        # Arquivo principal da execução do scanner e ataque
    ├── config/
    │   └── config.go                      # Arquivo de configuração global do projeto
    ├── cryptentropy/
    │   └── cryptentropy.go                # Manipulação de entropia criptográfica
    ├── evolution/
    │   └── evolution.go                   # Estratégias de evolução de payloads
    ├── headers/
    │   └── headers.go                     # Manipulação de cabeçalhos HTTP
    ├── http2mux/
    │   ├── http2mux.go                    # Conexões HTTP/2 com multiplexação
    │   └── http2utsmux.go                 # Manipulação de multiplexação de HTTP/2 com TLS
    ├── injector/
    │   └── injector.go                    # Injeção de código/payloads em requisições
    ├── mutador/
    │   └── mutador.go                     # Mutação de payloads
    ├── pkg/
    │   └── pkg.go                         # Pacotes auxiliares compartilhados
    ├── proxy/
    │   └── proxy.go                       # Manipulação de proxies
    ├── strategies/
    │   └── strategies.go                  # Estratégias de ataque e evasão
    ├── telemetry/
    │   └── telemetry.go                   # Coleta e envio de dados de telemetria
    ├── stealthrouter/
    │   └── stealthrouter.go               # Roteamento furtivo e técnicas de evasão
    ├── utils/
    │   └── utils.go                       # Funções auxiliares gerais
    ├── utlslocal/
    │   └── fingerprint.go                 # Manipulação de fingerprints TLS locais
    ├── utlsmux/
    │   └── utlsmux.go                     # Manipulação de multiplexação TLS
    ├── wscontrol/
    │   └── wscontrol.go                   # Controle de WebSockets
    ├── go.mod                             # Arquivo de dependências do Go
    ├── go.sum                             # Arquivo de checksum de dependências
    ├── logs/                              # Diretório de logs do sistema
    │   └── detection_log.txt              # Arquivo de logs contendo WAFs e vazamentos

└── frontend
    ├── public
    ├── src
    │   ├── components
    │   │   ├── AttackForm.jsx
    │   │   └── Terminal.jsx
    │   ├── pages
    │   │   └── Dashboard.jsx
    │   ├── api
    │   │   └── api.js
    │   ├── App.jsx
    │   ├── main.jsx
    │   └── index.css
    ├── package.json
    └── tailwind.config.js
```

---

## 🛠 Tecnologias Utilizadas

### Backend
- **Python**: IA para payload generation.
- **Go**: Fuzzing rápido e paralelizado com FFUF.
- **Modelos GPT**: Mistral-7B, GPT-NeoX, Llama integrados via HuggingFace.

### Frontend
- **ReactJS** com Tailwind CSS
- Next.js (Opcional)

---


mustParseURL(u string) *url.URL

logToFile(message string)

📡 Conexões TLS com spoofing
NewRandomUTLSConfig(targetHost string) *UTLSConfig

(*UTLSConfig) DialUTLS(ctx context.Context, network, addr string) (net.Conn, error)

NewHTTPClient(targetHost string) *http.Client

🔄 Spoofing de headers HTTP
(*SpoofTransport) RoundTrip(req *http.Request) (*http.Response, error)

(*SpoofTransport) dialRaw(req *http.Request) (net.Conn, error)

🔍 Fingerprinting
PassiveFingerprint(url string) FingerprintInfo

ActiveFingerprint(url string) FingerprintInfo

FingerprintTLS(url string) FingerprintInfo

🛡 Evasão de WAF
EvasaoWAFs(url string)

🔬 Fragmentação / Técnicas avançadas de evasão
FragmentedClientHelloDial(ctx context.Context, network, addr string) (net.Conn, error)

(*InterleavedConn) Write(p []byte) (n int, err error)

🧱 Tipos definidos
type UTLSConfig struct

type HeaderPair struct

type SpoofTransport struct

type FingerprintInfo struct

type InterleavedConn struct

✅ Funções globais e estruturas do arquivo injector.go
📤 Injeção principal
InjectPayload(targetURL, payload string) error – entry point principal

tryCanal(ctx, parsed, canal, payload string) (contentType string, statusCode int, err error) – executor de requisições

🧠 IA/ML e feedback
LoadMLModel() *MLModel

(*MLModel) Score(canal string) float64

(*MLModel) Feedback(canal string, success bool)

🧬 Mutação e fuzzing
MutatePayload(payload, canal string) (string, string)

RandomFuzz(payload string) string

📑 Logging e telemetria
EnviarTelemetry(d TelemetryData)

logAttack(d TelemetryData)

📊 WAF e priorização de canais
DetectWAF(host string) string – stub que retorna "cloudflare"

prioritizeCanais(canais []string, waf string) []string

🔁 Auxiliares
errString(err error) string

reverseSlice(s []string)

🚨 Fallback
TentarFallback(url, payload string) FallbackResult

🧱 Tipos definidos
type TelemetryData struct

type AttackLogEntry = TelemetryData

type MLModel struct

type FallbackResult struct

✅ Conclusão: Estrutura clara e coerente
Ambas as unidades (utlslocal e injector) estão agora estruturalmente completas, com as dependências corretas.

A função TentarFallback agora existe e tem retorno compatível com o que o scanner.go espera (Success, Reward, etc.).

A lógica de spoofing, evasão e fingerprinting está bem encapsulada e modularizada.

Se quiser, posso agora:

📄 Gerar documentação de todas essas funções (com descrições).

🧪 Criar testes unitários.

🧠 Sugerir melhorias de desempenho/segurança.




🧩 Visão Geral do Arquivo main.go
Este arquivo é o ponto de entrada da ferramenta de automação ofensiva "RedBot", que executa ataques LFI/RFI com mutação genética de payloads, medição de entropia, evasão de WAF e exportação de dados analíticos para dashboard. Utiliza Go + Cobra CLI + GA (Genetic Algorithms) e manipulação de entropia.

⚙️ Funcionalidades Principais

Bloco	Finalidade
CLI com Cobra	Interface de linha de comando com múltiplas flags de execução
Ataque Genético	Loop evolutivo com seleção, mutação, crossover e avaliação de entropia
Multi-Canal	Injeção de payloads por diferentes canais: URL, header, cookie, JSON, XML
Heurísticas de RL	Tabela de reforço associada a canais e payloads
Dashboard Export	Exportação de estatísticas como CSV/JSON e renderização via Chart.js
Fallback de Payload	Estratégia de fallback com mutações simples para garantir robustez
🧬 Algoritmos e Técnicas Aplicadas
Algoritmo Genético

População inicial gerada com MutarParaEntropiaTarget.

Crossover entre indivíduos.

Mutações:

Randômica (MutateGene)

Focada na janela de maior entropia (MutateInMaxEntropyWindow)

Entropy-aware encoding (MutarEncodeEntropyAware)

Avaliação de fitness baseada em entropia e compressão.

Seleção elitista com filtro por diversidade (via NCD implícito na mutador).

Estatísticas evolutivas acumuladas por geração.

Reinforcement Learning Simples

Tabela rlTable[RLState]float64 para associar sucesso por canal.

Incremento de reward condicionado a vazamento identificado.

Medição de Entropia

Calculada para orientar mutações e definir "fitness" dos payloads.

Shannon, KL Divergence, Base64Score, HexScore.

Injeção Multi-Canal

Payloads são injetados em diferentes partes da requisição HTTP:

URL

Header (X-Inject)

Cookie (session_id)

JSON ({"input": ...})

XML (<input>...</input>)

Fallback Simples

Utiliza MutarPayload (obfuscadores + sufixos) quando o GA não gera bons resultados.

Leitura e Escrita de Arquivos

Leitura de payloads de um arquivo .txt

Escrita de respostas suspeitas com dados sensíveis em txt

Exportação de dados evolutivos em CSV e JSON

Dashboard HTML com Chart.js.

🛠️ Funções Globais e Suporte

Função	Propósito
main()	Inicializa CLI, parseia flags, chama run()
run()	Setup geral, paralelismo, execução de ataques por alvo
carregarPayloads()	Carrega payloads do disco para memória
executarAtaque()	Execução completa de GA, injeção multi-canal, fallback
injectXMLPayload()	Injeção específica para XML com Content-Type: application/xml
executarFallback()	Estratégia final com mutações básicas para aumentar cobertura
runGAWithStats()	Loop genético completo com coleta de estatísticas
containsLeak()	Detecta possíveis vazamentos por regexes sensíveis
salvarResposta()	Armazena resposta suspeita com metadados
saveCSVStats()	Exporta estatísticas em formato CSV
exportResults()	Salva rewards e stats em JSON, gera dashboard HTML
generateDashboard()	Gera o HTML do dashboard com Chart.js embutido
openBrowser()	Abre dashboard automaticamente no navegador local
safeFilename()	Sanitiza nomes para uso em arquivos
📊 Estrutura de Dados Notável
RLState: identifica combinações de payload, canal e WAF.

EvolutionStats: métricas por geração (fitness, entropia).

Alvo: representa o endpoint alvo com método HTTP e corpo.

🧠 Integrações Estratégicas
mutador: geração e avaliação de payloads com heurísticas evolutivas.

entropy: análise e manipulação de entropia de payloads.

injector / headers: geração de requisições e cabeçalhos realistas.

strategies: seleção de transporte HTTP (ex: proxy-aware).

proxy: gerenciamento de proxies e marcação de falhas.

🧩 Visão Geral do Pacote utlslocal
O pacote utlslocal é responsável por realizar manipulações no nível do handshake TLS com uTLS, simulando clientes reais (ex: Chrome, Firefox, iOS) para evadir WAFs e firewalls com fingerprint TLS alterado. Ele também realiza fingerprinting passivo/ativo e técnicas de evasão avançada.

⚙️ Funcionalidades-Chave

Área Funcional	Finalidade
uTLS Spoofing	Simula handshakes de navegadores reais com ClientHelloID modificados
Fingerprinting HTTP/TLS	Identifica características do servidor para adaptar ataques
Header Order Spoofing	Envia cabeçalhos em ordem customizada para bypasses
Evasão de WAFs	Envia requisições com SNI, headers, User-Agent, ALPN alterados
Proxy-aware Dialer	Suporte a proxies via http.ProxyFromEnvironment()
🔧 Configuração Dinâmica: UTLSConfig
Esta estrutura encapsula uma configuração de handshake TLS modificada, contendo:

HelloID: Identidade do navegador (Chrome, Firefox, etc.)

NextProtos: Protocolos ALPN (ex: http/1.1, h2)

ServerName: SNI real ou fake CDN

CipherSuites: Lista de cipher suites

SignatureAlgorithms: Algoritmos de assinatura

👉 Essa configuração é aleatoriamente gerada por NewRandomUTLSConfig(targetHost).

🌐 Estabelecimento de Conexões com TLS Customizado
DialUTLS(): estabelece conexão TLS com utls.UClient, usando ClientHelloID spoofado.

NewHTTPClient(): retorna um *http.Client configurado com transporte spoofado, útil para todas as requisições automatizadas.

📑 Manipulação de Headers HTTP (Ordem Customizada)
SpoofTransport: um http.RoundTripper customizado que:

Escreve os headers manualmente via conn.Write().

Preserva a ordem dos headers.

Ignora internamente o comportamento padrão do http.Transport.

🧠 Fingerprinting de Servidores
PassiveFingerprint()

Usa uma requisição HEAD para inferir:

Sistema operacional (ex: windows, unix)

Stack da aplicação (ex: php, asp.net, waf-locked)

ActiveFingerprint()

Estende o passivo com payloads comuns (/etc/passwd, etc).

Detecta respostas 403 → indica WAF ativo.

FingerprintTLS()

Extração de:

Versão TLS (1.2 / 1.3)

Cipher Suite (formato 0xXXXX)

Ideal para logging ou fingerprint JA3 manual (em parte comentado).

🔓 Evasão de WAFs – Função EvasaoWAFs()
Executa uma requisição forjada com:

Header spoofado (ordem, user-agent).

SNI falso (Cloudflare, Akamai, etc.).

Transporte uTLS + SpoofTransport.

🧠 Ideal para detectar bloqueios em tempo real e adaptar payloads em sistemas evolutivos.

🔢 Helpers e Utilitários
ExtractHost(): extrai o host de uma URL.

randomUA(): retorna User-Agent realista (hardcoded).

hexUint16(): formata uint16 como string hexadecimal.

logToFile(): salva erros ou fingerprints localmente com timestamp.

🧬 Avançado – Técnicas Futuras / Experimentais
Fragmentação de TLS Records: envia dados TLS em pacotes menores com jitter (simula handshake "quebrado").

InterleavedConn: estrutura que implementa fragmentação controlada no nível TCP.

ClientHelloSpec: montagem manual de mensagens ClientHello (ex: com padding e extensões).

JA3 Fingerprinting (comentado): suporte a JA3 removido por erro de import.

🛡️ Resumo Técnico
O utlslocal fornece:

Spoofing de handshake e fingerprint com uTLS.

Conexão segura e evasiva a WAFs.

Integração com http.Client e headers ordenados.

Suporte embutido a proxy HTTP.

Técnicas preparadas para evolução (fragmentação, JA3, padding...).

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

📦 Resumo do Pacote mutador
O pacote mutador implementa algoritmos evolutivos e heurísticas de entropia para gerar, obfuscar, e evoluir payloads ofensivos em ataques de LFI/RFI e outras injeções estruturais. Ele combina:

Genética computacional (crossover, mutação)

Avaliação de fitness baseada em entropia

Visualização e scoring massivo

Resistência evasiva a WAFs via entropia alta e NCD

🧬 Modelos de Dados

Tipo	Descrição
GenePayload	Representa um payload com histórico de mutações, fitness e perfil de entropia
EvolutionStats	(Integrável) Dados estatísticos por geração para dashboards
🔧 Funções-Chave

ID	Função	Finalidade
1	MutarPayload()	Gera variações obfuscadas básicas de um payload
2	MutarComTemplates()	Usa templates estruturais para compor payloads
3	MutarParaEntropiaTarget()	Filtra payloads com entropia próxima do alvo
4	Crossover()	Combina dois payloads geneticamente
5	MutateGene()	Insere mutações randômicas no payload
6	AvaliarFitness()	Calcula escore baseado em entropia, KL e diffs
7	SelecionarPayloads()	Seleciona elites com NCD para diversidade
8	MutateInMaxEntropyWindow()	Mutação localizada onde a entropia é mais alta
9	MutarComTemplatesAdaptive()	Templates filtrados por heurísticas de entropia
10	MutarEncodeEntropyAware()	Codifica payload em base64/hex conforme perfil
11	BatchAnalyzeFitness()	Avalia um conjunto de payloads de forma paralela
12	EntropyVisualDebug()	Gera visualização SVG de entropia
13	LabelByEntropy()	Classifica payload para ML
14	RunGeneticLoop()	Executa ciclo genético completo
🎯 Lógica Evolutiva (RunGeneticLoop)
Inicialização da população com payloads mutados

Loop de gerações:

Seleção de pares aleatórios

Crossover

Mutação (genérica, por janela, codificação)

Avaliação por entropia (Shannon, KL)

Seleção por fitness + NCD (diversidade)

Métricas exibidas: fitness máximo e médio por geração

🧠 Avaliação de Fitness (AvaliarFitness)
Fatores que influenciam o fitness:

Alta entropia Shannon

Baixa divergência KL

Presença de padrões base64

Mudança significativa entre perfis antigos/atuais

📈 Funções de Diagnóstico
EntropyVisualDebug() → SVG com gráfico da entropia

LabelByEntropy() → classifica como plaintext, crypto, base64, etc.

BatchAnalyzeFitness() → análise paralela + perfil

🧩 Táticas de Mutação Usadas

Técnica	Exemplo de Aplicação
Substituição/Obfuscador	/ → %2f, %252f, //, %c0%af
Sufixos de terminação	%00, .jpg, .png
Templates estruturais	../../dir/file.ext, %2f entre diretórios
Encoding adaptativo	Base64 ou hex conforme entropia
Inserção localizada	Mutação no ponto de maior entropia
Crossover genético	Divide e junta payloads diferentes
🚀 Extensões Sugeridas

Recurso	Vantagem Técnica
Histórico completo de mutações	Explicabilidade + RL
Tracking de evolução por geração	Dashboards e comparação de estratégias
Função InjectLoopElite()	Loop de ataque com a elite genética
Feedback Reinforcement Learning	Pontuação de canais ou operadores
Exportação JSON/CSV	Para dashboards interativos ou análise ML
🧠 Integrações Estratégicas
🔗 entropy – usa completamente o pacote para scoring e visualização

🔗 injector – pode enviar elites geradas automaticamente

🔗 aibridge – apto para acoplamento com reforço online

✅ Conclusão Técnica

Aspecto	Avaliação
Engenharia evolutiva real	✅ Robusta
Diversidade garantida via NCD	✅ Alta
Modularidade e clareza	✅ Elevada
Pronto para ML	✅ Total
Pronto para evasão prática	✅ Absoluta

📦 Pacote entropy — Análise e Engenharia de Entropia
🧠 Objetivo
Este pacote fornece funções para:

Calcular métricas de entropia (Shannon, KL)

Classificar conteúdo (e.g., base64, jwt, binário)

Gerar e adaptar payloads conforme perfis de entropia

Suportar análise visual, dashboards e integração com fuzzers genéticos

🔢 Métricas Fundamentais

Função	Finalidade
Shannon(data)	Entropia de Shannon
KLDivergence(data)	Divergência de Kullback-Leibler (P‖U)
printableRatio(data)	Proporção de caracteres imprimíveis
base64CharRatio(data)	Proporção de chars válidos Base64
hexCharRatio(data)	Proporção de chars válidos hexadecimal
🧬 Perfil de Entropia e Classificação

Estrutura/Função	Descrição
EntropyProfile	Struct com Shannon, KL, scores base64/hex, flags semânticas
AnalyzeEntropy(data)	Retorna EntropyProfile completo
AutoEntropyAdapt(data)	Sugere ação evasiva baseada no perfil
EntropyLabel(profile)	Classifica como plaintext, base64, crypto etc.
FingerprintEntropy(data)	Detecta tipo: JWT, zlib, ELF, PE, etc.
🔍 Análise Diferencial

Função	Objetivo
EntropyDeltaProfile(old, new)	Compara dois blobs e identifica mudanças significativas
EntropyAnomalyScore(a, b)	Escore quantitativo de mudança de perfil
NCD(x, y)	Normalized Compression Distance entre dois blobs
🧰 Geração e Transformação de Dados

Função	Descrição
RandPayload(entropy, len)	Gera dado com entropia aproximada desejada
GenerateMimicData(profile)	Gera blob que imita um EntropyProfile
EncodeEntropyAware(data)	Decide entre hex/base64 conforme entropia
MatchPayloadToEntropy(data,t)	Confere se Shannon ≈ alvo ± 0.1
⏱️ Delays e Randomização

Função	Objetivo
RandInt(n)	Inteiro aleatório seguro
RandSeed()	Seed aleatória para math/rand
RandFloat()	Float entre 0.0 e 1.0
RandDelay(min, max)	Delay aleatório linear
RandCryptoDelay(λ)	Delay com distribuição exponencial (Poisson)
RandGaussianDelay(μ,σ)	Delay com distribuição normal
🖼️ Visualização e Debug

Função	Descrição
VisualizeEntropy(data, win)	Heatmap ASCII
EntropyVisualSVG(data, win, w, h)	Gráfico SVG interativo
SlidingWindowEntropy(data, win)	Retorna entropia por janelas deslizantes
MaxEntropyWindow(data, win)	Janela com maior entropia detectada
EntropyBinning(data, win, bins)	Conta janelas por faixas de entropia
🧪 Batch e Exportação

Função	Descrição
BatchAnalyzeEntropy([][]byte)	Processa múltiplos blobs e retorna perfis
ToJSON()	Serializa EntropyProfile
ToCSV()	Serializa EntropyProfile para planilha
✨ Casos de Uso Estratégicos

Cenário	Funções-Chave
Evasão de WAF via entropia	RandPayload(), AutoEntropyAdapt()
Fuzzing genético com heurísticas	AnalyzeEntropy(), MutarEncodeEntropyAware()
Filtragem de payloads	MatchPayloadToEntropy()
Visualização/debug de geração	EntropyVisualSVG(), VisualizeEntropy()
Classificação ML-aware	EntropyLabel(), EntropyProfile
💡 Extensões Recomendadas (Futuro)

Ideia	Descrição técnica
Embed de JA3/TLS fingerprint	Combinar entropia + fingerprint evasivo
Treinamento supervisionado	Exportar CSV com EntropyLabel
RL-feedback	Penalizar payloads com baixa evasividade entropia
Detecção de mudanças evasivas	Usar EntropyDeltaProfile em GA/loop
Streaming e análise contínua	Buffer com SlidingWindowEntropy live
✅ Conclusão Técnica

Critério	Avaliação
Robustez matemática	✅ Alta
Cobertura heurística	✅ Completa
Integração com ML/fuzzers	✅ Ideal
Clareza estrutural	✅ Elevada
Pronto para dashboard	✅ Total


Scanner Package

The scanner package provides a comprehensive framework to perform automated security scans against LFI/RFI targets. It integrates WebSocket-based logging, entropy and fingerprint analysis, dynamic payload injection, and fallback mutation strategies.

Features

WebSocket Control: Real-time scan events sent to a control server via wscontrol.

Fingerprinting: Passive and active fingerprint collection using utlslocal.

Genetic Population: Initializes an evolutionary population (evolution.LoadPopulation) for adaptive payload success tracking.

Timing Analysis: Measures response time variance to detect side-channel vulnerabilities.

Content Analysis: Detects high entropy, LFI patterns (root:...:0:0:), reflected output, and WAF presence.

Fallback Mutations: Applies simple LFI payload mutations when primary scan fails.

Integration Hooks: Sends reinforcement feedback via aibridge and logs to analyzer and browserexec modules.

Installation

go get lfitessla/scanner

Ensure your project also includes the required dependencies:

go get lfitessla/aibridge lfitessla/analyzer lfitessla/entropy lfitessla/evolution \
    lfitessla/headers lfitessla/http2mux lfitessla/mutador lfitessla/proxy \
    lfitessla/utlslocal lfitessla/wscontrol

Usage

Import the package and call the main orchestration function from your CLI or application:

import "lfitessla/scanner"

func main() {
    alvo := scanner.Alvo{
        URL:    "https://example.com/vuln.php?file=",
        Method: "GET",
        Body:   "",
    }
    payload := "../../../../etc/passwd"

    success := scanner.ExecutarAtaque(alvo, payload)
    if success {
        fmt.Println("Target appears vulnerable")
    } else {
        fmt.Println("No vulnerability detected")
    }
}

API Reference

Types

type Alvo

Alvo struct {
    URL    string // Base URL to test (e.g. https://host/path?param=)
    Method string // HTTP method (GET, POST)
    Body   string // Request body for POST
}

Functions

func ScanAlvoCompleto(fullURL string) bool

Performs the primary WebSocket-based scan on the given fullURL + payload. Returns true if the WebSocket handshake and logging completed.

func ExecutarAtaque(alvo Alvo, payload string) bool

High-level orchestrator. Executes:

ScanAlvoCompleto (WebSocket, fingerprint, evolution init)

executarSonda (timing and content analysis) if initial scan succeeded

executarFallback (simple mutations) if initial scan failed

Returns true if the primary scan succeeded.

func ScanListCompleto(filePath string)

Reads URLs from a file (one per line) and runs ScanAlvoCompleto on each.

Extension Points

Customize fingerprint heuristics in utlslocal.

Hook into aibridge.EnviarFeedbackReforco for RL integration.

Adjust threshold values (entropy, timing variance) in analisarResposta and executarSonda.

Extend executarFallback with more mutation strategies from the mutador package.

Logging & Monitoring

All scan events are emitted via WebSocket to wss://control.tessla.local/scan. Events include:

start-scan, fingerprint, attack-started, time-variance

high-entropy, lfi-detected, reflected-output, waf-detected

Monitor these in your control dashboard for real-time insights.

License

This code is provided under the MIT License. See LICENSE file for details.


 evolution

O pacote **evolution** implementa um mecanismo simples de evolução genética para geração e refinamento de payloads (ou quaisquer strings) através de mutação, crossover e seleção baseada em fitness. Ele mantém o estado da “população” em disco para permitir aprendizado incremental entre execuções.

---

## Funcionalidades

- **Gene**  
  Representa um indivíduo com um `Payload` (string) e uma pontuação de `Fitness` (int).

- **Population**  
  Conjunto de genes visando um determinado `Target` (domínio, URL, etc.), persistido em cache (`.tessla-cache/*.json`).

- **Carregamento e salvamento automático**  
  - `LoadPopulation(target string) *Population` — recupera do cache ou inicia nova população.  
  - `RecordSuccess(pop *Population, payload string)` — incrementa fitness de um payload vencedor e salva no disco.  

- **Evolução**  
  - `GenerateNextPopulation(pop *Population)` — seleciona os top N genes, aplica crossover e mutação para compor a próxima geração, e salva.  
  - Seleção por fitness: `SelecionarTop(genes []Gene, n int) []Gene`  
  - Operadores genéticos:  
    - `Crossover(p1, p2 Gene) Gene`  
    - `Mutate(g Gene) Gene`  

---

## Instalação

No módulo raiz da sua aplicação Go:

```bash
go get github.com/seu-usuario/lfitessla/evolution
Em go.mod aparecerá:

bash
Copiar
Editar
require github.com/seu-usuario/lfitessla/evolution v0.0.0
Uso
go
Copiar
Editar
import "lfitessla/evolution"

func main() {
  // 1) Carrega (ou inicializa) população para um alvo
  pop := evolution.LoadPopulation("https://example.com")

  // 2) Registre sucessos quando encontrar um payload eficaz:
  evolution.RecordSuccess(pop, "../etc/passwd")

  // 3) Gere a próxima geração com base nos melhores:
  evolution.GenerateNextPopulation(pop)

  // 4) Itere conforme necessário:
  for i := 0; i < 10; i++ {
    evolution.GenerateNextPopulation(pop)
  }
}
API
Tipos
go
Copiar
Editar
type Gene struct {
  Payload string `json:"payload"`
  Fitness int    `json:"fitness"`
}

type Population struct {
  Target string `json:"target"`
  Genes  []Gene `json:"genes"`
}
Funções principais
LoadPopulation(target string) *Population
Retorna uma Population carregada do cache ou vazia se não existir.

RecordSuccess(pop *Population, payload string)
Incrementa Fitness do gene correspondente (ou adiciona novo) e salva.

GenerateNextPopulation(pop *Population)
Substitui pop.Genes pelos top genes + offspring gerado por crossover e mutação.

Helpers
SelecionarTop(genes []Gene, n int) []Gene

Crossover(p1, p2 Gene) Gene

Mutate(g Gene) Gene

Arquitetura de Persistência
Cache em disco em ./.tessla-cache/<hash-do-target>.json

Permissões seguras (0600) para confidencialidade

Formato JSON indentado para inspeção manual




## ⚙️ Como Rodar (Instruções Básicas)

### Backend Python (IA)
```bash
cd backend/python/ia_payload_gen
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python payload_generator.py
```

### Backend Go (Performance)
```bash
cd backend/go
go mod tidy
go run cmd/main.go
```

### Frontend ReactJS
```bash
cd frontend
npm install
npm run dev
```

---

## 🔒 Aviso de Segurança

**⚠️ Esta ferramenta deve ser usada exclusivamente em ambientes autorizados de testes de segurança. O uso indevido ou não autorizado é estritamente proibido e sujeito às leis aplicáveis.**

---

## 📜 Licença

Este projeto é disponibilizado sob licença MIT. Consulte o arquivo `LICENSE.md` para mais detalhes.

---

© 2025 LFI TESSLA Cybersecurity Labs

