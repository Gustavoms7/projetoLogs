import re
from collections import defaultdict

# Configuração do formato do log
LOG_FORMAT = r'(?P<ip>\S+) \S+ \S+ \[(?P<datahora>[^\]]+)\] "(?P<metodo>\S+) (?P<url>\S+) (?P<protocolo>\S+)" (?P<status>\d+) (?P<tamanho>\d+)'

# Critérios de remoção de outliers
MAX_REQUEST_SIZE = 10_000_000  # Tamanho máximo da requisição em bytes

# Lista de URLs permitidas (Allowlist)
ALLOWLIST_URLS = [
    "/wp-login.php",  # URL de login padrão do WordPress
    "/wp-content/",   # Diretórios legítimos do WordPress
    "/wp-admin/",     # Diretórios administrativos do WordPress
    "/robots.txt",    # Arquivo padrão de exclusão de rastreamento
    "/favicon.ico"    # Favicon padrão
]

# Padrões maliciosos unificados
MALICIOUS_PATTERNS = [
    r'\.\./',              # Diretórios acima
    r'exec',               # Comando exec
    r'cmd',                # Comando cmd
    r'eval',               # Função eval
    r'\.php\?cmd',        # PHP com comandos suspeitos
    r'\.php\?.*exec',     # PHP com parâmetros suspeitos
    r'\.php\?.*eval',     # PHP com código malicioso
    r'\.sh',               # Scripts shell
    r'%00',                # Null byte
    r'<script>',           # Tentativas de XSS
    r'UNION SELECT',       # SQL Injection
    r'OR 1=1',             # SQL Injection
    r'drop\s+table',       # SQL Injection
    r'passwd',             # Acesso a arquivos sensíveis
    r'\.env',              # Tentativas de acesso ao arquivo .env
    r'login.php\?cmd',     # Tentativas de login automatizadas
    r'base64_decode',      # Decodificação maliciosa
    r'bot|spider|crawler', # Robôs automatizados
    r'alert',              # XSS básico
    r'onerror',            # XSS com eventos
]

def parse_log_line(line):
    """Processa cada linha do log e retorna um dicionário com os dados."""
    match = re.match(LOG_FORMAT, line)
    if match:
        return match.groupdict()
    return None

def is_relevant(data, ignored_extensions):
    """Verifica se a entrada é relevante."""
    if not data:
        return False

    # Filtrar URLs com extensões ignoradas
    url = data.get("url", "").lower()
    if any(url.endswith(ext) for ext in ignored_extensions):
        return False

    # Filtrar status HTTP inválidos
    status = int(data.get("status", 0))
    if status < 200 or status >= 600:  # Status HTTP válidos estão entre 200 e 599
        return False

    return True

def is_outlier(data):
    """Verifica se a requisição é um outlier."""
    size = int(data.get("tamanho", 0))
    return size > MAX_REQUEST_SIZE  # Remover requisições muito grandes

def count_url_parameters(url):
    """Conta o número de parâmetros em uma URL."""
    return url.count('?') + url.count('&')

def is_suspicious_url(url, metodo):
    """
    Função refinada para detectar URLs maliciosas.
    Prioriza a allowlist e aplica padrões de detecção maliciosos unificados.
    """
    # Allowlist: Ignorar URLs conhecidas como legítimas
    if any(url.startswith(allow) for allow in ALLOWLIST_URLS):
        return False

    # Verificar padrões maliciosos
    for pattern in MALICIOUS_PATTERNS:
        if re.search(pattern, url):  # Usar regex para maior flexibilidade
            return True

    # Heurísticas adicionais
    if metodo == "POST" and "?" in url:  # Requisições POST com parâmetros
        query_params = url.split("?")[1]
        if len(query_params.split("&")) > 5:  # Mais de 5 parâmetros
            return True

    # Se nenhuma condição foi atendida, a URL não é suspeita
    return False

