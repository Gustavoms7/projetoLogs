# Projeto de Monitoramento e Visualização de Logs

Este projeto processa e visualiza logs de servidores web, com funcionalidades de análise e identificação de padrões suspeitos.

---

## **Funcionalidades**

- **Upload de Logs**: Permite o upload de arquivos de log para análise.
- **Pré-processamento Avançado**: 
  - Filtra entradas irrelevantes, como arquivos estáticos.
  - Remove outliers com base no tamanho da requisição.
  - Adiciona atributos relevantes, como número de parâmetros e detecção de URLs suspeitas.
- **Análise de Logs**: Identifica padrões maliciosos em URLs (e.g., tentativas de XSS, SQL Injection, acesso a arquivos sensíveis).
- **Interface Web Dinâmica**: 
  - Exibe logs processados em uma tabela interativa.
  - Oferece filtros para atributos como URL suspeita, método HTTP, número de parâmetros e status.
- **Detecção de Ameaças**: Sinaliza possíveis tentativas de ataque com base em regras definidas.

---

## **Estrutura do Projeto**

### **Diretórios**
- **`coletor/`**:
  Scripts para o pré-processamento e análise de logs.
  - `logsUtils.py`: Contém funções para processamento de logs.
  - `coletorLogs.py`: Script principal para monitoramento e upload.
- **`logs/`**:
  Armazena os logs processados no formato JSON (`logsLimpos.json`).
- **`uploads/`**:
  Armazena os arquivos de log enviados pela interface.
- **`templates/`**:
  Contém os arquivos HTML da interface web.
  - `index.html`: Página principal com tabela de logs e filtros.
- **`static/`**:
  Contém arquivos estáticos, como CSS e JavaScript.
  - `style.css`: Estilização da interface.
  
---

## **Pré-requisitos**
- Python 3.9 ou superior.
- Dependências listadas no arquivo `requirements.txt`.

### Instalação de Dependências:
```bash
pip install -r requirements.txt
