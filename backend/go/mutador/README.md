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
