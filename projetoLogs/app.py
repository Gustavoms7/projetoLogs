from flask import Flask, render_template, request, jsonify
import json
import os
from werkzeug.utils import secure_filename
from utils.logsUtils import parse_log_line, is_relevant, is_outlier, count_url_parameters, is_suspicious_url

UPLOAD_FOLDER = "uploads"
CLEANED_LOGS_FILE = "logs/logsLimpos.json"

app = Flask(__name__)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

# Certifique-se de que os diretórios necessários existem
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(os.path.dirname(CLEANED_LOGS_FILE), exist_ok=True)

@app.route("/")
def index():
    """Página principal."""
    try:
        with open(CLEANED_LOGS_FILE, "r") as file:
            logs = [json.loads(line) for line in file]
    except FileNotFoundError:
        logs = []
    return render_template("index.html", logs=logs, total=len(logs))

@app.route("/upload", methods=["POST"])
def upload_file():
    """Endpoint para upload de arquivo."""
    if "file" not in request.files:
        return jsonify({"status": "error", "message": "Nenhum arquivo enviado"}), 400

    file = request.files["file"]
    if file.filename == "":
        return jsonify({"status": "error", "message": "Nenhum arquivo selecionado"}), 400

    filename = secure_filename(file.filename)
    filepath = os.path.join(app.config["UPLOAD_FOLDER"], filename)
    file.save(filepath)

    try:
        process_logs(filepath)  # Processar o arquivo enviado
        return jsonify({"status": "success", "message": "Arquivo processado com sucesso"}), 200
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route("/api/logs")
def api_logs():
    """API para retornar os logs processados."""
    try:
        with open(CLEANED_LOGS_FILE, "r") as file:
            logs = [json.loads(line) for line in file]
    except FileNotFoundError:
        logs = []
    return jsonify(logs)

def process_logs(filepath):
    """Processa o arquivo de logs enviado."""
    try:
        with open(filepath, "r") as file:
            with open(CLEANED_LOGS_FILE, "w") as cleaned_file:
                for line in file:
                    data = parse_log_line(line)
                    if data and is_relevant(data, (".png", ".jpg", ".jpeg", ".gif", ".css", ".js", ".ico")):
                        # Remover outliers
                        if is_outlier(data):
                            continue
                        
                        # Adicionar novos atributos
                        data["num_parametros"] = count_url_parameters(data["url"])
                        data["url_suspeita"] = is_suspicious_url(data["url"], data["metodo"])
                        data["tamanho"] = int(data["tamanho"])  # Converte para inteiro
                        
                        # Salvar no arquivo final
                        json.dump(data, cleaned_file)
                        cleaned_file.write("\n")
        print(f"Logs processados e salvos em {CLEANED_LOGS_FILE}")
    except Exception as e:
        print(f"Erro ao processar logs: {e}")
        raise e

if __name__ == "__main__":
    app.run(debug=True)
