# Projeto de Monitoramento e Visualização de Logs

Este projeto monitora logs do servidor Apache, realiza pré-processamento para filtrar entradas relevantes e exibe os dados em uma interface web.

## Funcionalidades
- **Coleta de Logs**: Monitora o arquivo de log do Apache em tempo real.
- **Pré-processamento**: Remove entradas irrelevantes (ex.: arquivos estáticos).
- **Interface Web**: Exibe logs processados e estatísticas básicas.

## Estrutura
- `coletor/`: Scripts de monitoramento e pré-processamento.
- `logs/`: Armazena os logs processados.
- `templates/` e `static/`: Interface web.

## Como Executar
1. Execute o coletor:
   ```bash
   python3 coletor/coletor_logs.py
