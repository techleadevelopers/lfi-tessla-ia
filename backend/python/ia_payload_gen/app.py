from flask import Flask, request, jsonify
from payload_generator import gerar_payloads

app = Flask(__name__)

@app.route("/gen", methods=["POST"])
def gerar():
    data = request.get_json()
    base = data.get("base_payload", "")
    contexto = data.get("context", "")

    gerado = gerar_payloads(base, n_variantes=5)
    variantes = [linha.strip() for linha in gerado.split("\n") if linha and not linha.startswith("---")]

    return jsonify({"variants": variantes})


# 🫀 Endpoint de saúde para integração com o script bash/powershell
@app.route("/healthz")
def health_check():
    return "ok", 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
