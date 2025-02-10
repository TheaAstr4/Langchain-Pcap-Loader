# Document Loader para Arquivos PCAP e PCAPNG no LangChain

## 📌 Descrição

Este projeto implementa um **Document Loader** para o [LangChain](https://www.langchain.com/) que permite a leitura e processamento de arquivos no formato **PCAP** e **PCAPNG**. O objetivo é extrair informações relevantes do tráfego de rede capturado nesses arquivos e torná-las acessíveis para consultas e análises com modelos de linguagem.

Além disso, inclui um **módulo nativo em C++** para realizar a análise dos pacotes diretamente via Node.js, garantindo alto desempenho e eficiência no processamento dos dados de rede.

## 🚀 Funcionalidades

- 🔹 Suporte a arquivos **.pcap** e **.pcapng**
- 🔹 Extração de metadados de pacotes (IP de origem/destino, portas e payload)
- 🔹 Conversão de payloads para formato ASCII
- 🔹 Integração com LangChain para consultas inteligentes
- 🔹 Módulo nativo em C++ para análise eficiente

## 📄 Uso

Exemplo de uso do módulo para análise de pacotes:

```javascript

const { parsePcap } = require('./index');

const pcapData = parsePcap("file.pcap");

console.log(JSON.stringify(pcapData, null, 2));
```

## 📦 Dependências

- `langchain`
- `node-addon-api`
- `libpcap`

## 🔨 Compilação Manual

Se necessário, você pode compilar o módulo nativo manualmente usando:

```bash
node-gyp rebuild
```

Certifique-se de ter as bibliotecas necessárias instaladas:

```bash
sudo apt-get install libpcap-dev  # Para Linux
brew install libpcap               # Para macOS
```

## 📜 Licença

Este projeto está licenciado sob a **MIT License**.

