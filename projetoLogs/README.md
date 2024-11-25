
# Projeto de Monitoramento e Visualização de Logs

Este projeto processa e visualiza logs de servidores web, com funcionalidades de análise e identificação de padrões suspeitos.

## Funcionalidades

- **Upload de Logs:** Permite o upload de arquivos de log para análise.
- **Pré-processamento Avançado:**
  - Filtra entradas irrelevantes, como arquivos estáticos.
  - Remove outliers com base no tamanho da requisição.
  - Adiciona atributos relevantes, como número de parâmetros e detecção de URLs suspeitas.
- **Análise de Logs:** Identifica padrões maliciosos em URLs (e.g., tentativas de XSS, SQL Injection, acesso a arquivos sensíveis).
- **Interface Web Dinâmica:**
  - Exibe logs processados em uma tabela interativa.
  - Oferece filtros para atributos como URL suspeita, método HTTP, número de parâmetros e status.
- **Detecção de Ameaças:** Sinaliza possíveis tentativas de ataque com base em regras definidas.

## Estrutura do Projeto

### Diretórios

- **`coletor/`:** Scripts para o pré-processamento e análise de logs.
  - **`logsUtils.py`:** Contém funções para processamento de logs.
  - **`coletorLogs.py`:** Script principal para monitoramento e upload.
- **`logs/`:** Armazena os logs processados no formato JSON (`logsLimpos.json`).
- **`uploads/`:** Armazena os arquivos de log enviados pela interface.
- **`templates/`:** Contém os arquivos HTML da interface web.
  - **`index.html`:** Página principal com tabela de logs e filtros.
- **`static/`:** Contém arquivos estáticos, como CSS e JavaScript.
  - **`style.css`:** Estilização da interface.

## Pré-requisitos

- Python 3.9 ou superior.
- Dependências listadas no arquivo `requirements.txt`.

### Instalação de Dependências:

```bash
pip install -r requirements.txt
```

## Como Executar

### 1. Subir o Servidor Web:

```bash
python3 app.py
```

Acesse a interface web no navegador em: [http://127.0.0.1:5000](http://127.0.0.1:5000)

### 2. Fazer Upload de Logs:

1. Acesse a interface web.
2. Use o formulário para selecionar e enviar arquivos de log.
3. Após o processamento, os logs serão exibidos na tabela.

## Funcionalidades Avançadas

- **Filtros Dinâmicos:**
  - Filtre logs por URL suspeita, método HTTP, número de parâmetros ou status HTTP.
- **Detecção de Ameaças:**
  - Identifica padrões maliciosos em URLs com base em uma lista de regras (`MALICIOUS_PATTERNS`).
- **Allowlist:**
  - URLs conhecidas como seguras são ignoradas (e.g., `/wp-login.php`, `/robots.txt`).
