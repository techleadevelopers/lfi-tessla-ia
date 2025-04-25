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