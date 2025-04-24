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

