#!/bin/bash

clear
echo -e "\e[1;32m"
echo "╔════════════════════════════════════════════════════════════════╗"
echo "║                  🔥 LFI TESSLA 2050 - HUD.EXE                 ║"
echo "║     IA • Furtivo • Adaptativo • Reinforcement AI Payloads     ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo -e "\e[0m"

echo -e "\e[36m🚀 IA embarcada: Mistral 7B  |  Reinforcement AI Payload Loop\e[0m"
echo -e "\e[36m🧠 Execução: stealth, evasivo, adaptativo, modo shadow-network\e[0m"
echo -e "\e[36m⚙️  Framework: Go + Flask + Transformers\e[0m"
echo

# 🔧 Ativar ambiente virtual Python
echo -e "\e[33m🔧 [1/5] Ativando ambiente Python (venv)...\e[0m"
cd backend/python/ia_payload_gen || { echo "❌ Caminho inválido."; exit 1; }
if [ ! -f venv/bin/activate ]; then
    echo -e "\e[31m❌ Ambiente virtual não encontrado.\e[0m"
    exit 1
fi
source venv/bin/activate
sleep 1

# 🧠 Subindo Flask
echo -e "\e[33m🧬 [2/5] Iniciando IA ofensiva (Flask Service)...\e[0m"
python app.py > ../../../logs/flask_output.log 2>&1 &
FLASK_PID=$!
sleep 3

# 🧪 Verificar se Flask respondeu
echo -e "\e[34m🌐 [3/5] Aguardando resposta da IA...\e[0m"
for i in {1..10}; do
    if curl --silent http://127.0.0.1:5000/healthz | grep -q "ok"; then
        echo -e "\e[32m✅ IA operacional: http://127.0.0.1:5000\e[0m"
        break
    fi
    sleep 1
    if [ "$i" -eq 10 ]; then
        echo -e "\e[31m❌ Flask não respondeu. Abortando...\e[0m"
        kill $FLASK_PID
        exit 1
    fi
done
sleep 1

# ⚙️ Rodar Scanner Go
echo -e "\e[33m⚙️ [4/5] Executando scanner ofensivo LFI TESSLA (Go)...\e[0m"
cd ../../../go/cmd || { echo "❌ Caminho Go inválido."; kill $FLASK_PID; exit 1; }
go run main.go
if [ $? -ne 0 ]; then
    echo -e "\e[31m❌ Scanner Go retornou erro!\e[0m"
    kill $FLASK_PID
    exit 1
fi

# 🧼 Encerrar Flask
echo -e "\e[36m🧼 Finalizando IA embarcada (Flask)...\e[0m"
kill $FLASK_PID

# ✅ Fim
echo -e "\e[35m🎯 Scanner finalizado. Vazamentos salvos em /vazamentos\e[0m"
echo -e "\e[32m🚨 Status: OPERAÇÃO COMPLETA — SHADOW MODE FINALIZADO\e[0m"
