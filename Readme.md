<div align="center">

# 🛡️ GolpeScanner BR

### Detector de Golpes Digitais Brasileiros

**Uma ferramenta de linha de comando, 100% Python puro e sem custo, para identificar e se proteger das fraudes mais comuns do Brasil — Pix, phishing, boletos falsos, WhatsApp clonado e mais.**

[![Versão](https://img.shields.io/badge/versão-1.0.0-00b4d8?style=flat-square)](https://github.com/kalyel473)
[![Python](https://img.shields.io/badge/Python-3.9%2B-3776ab?style=flat-square&logo=python&logoColor=white)](https://www.python.org/)
[![Plataforma](https://img.shields.io/badge/plataforma-Windows%20%7C%20Linux%20%7C%20macOS-555?style=flat-square)](#)
[![Licença](https://img.shields.io/badge/licença-Educacional-2a9d8f?style=flat-square)](#-aviso-legal)

`@kalyel473` · [github.com/kalyel473](https://github.com/kalyel473) 

</div>

---

## 📑 Índice

- [Sobre o projeto](#-sobre-o-projeto)
- [Por que isso importa](#-por-que-isso-importa)
- [Funcionalidades](#-funcionalidades)
- [Instalação](#-instalação)
- [Como usar](#-como-usar)
  - [Modo interativo (menu)](#modo-interativo-menu)
  - [Modo linha de comando (CLI)](#modo-linha-de-comando-cli)
  - [Modo batch](#modo-batch-em-lote)
- [Os 6 módulos de análise](#-os-6-módulos-de-análise)
- [Saídas e relatórios](#-saídas-e-relatórios)
- [Como funciona o cálculo de risco](#-como-funciona-o-cálculo-de-risco)
- [Estrutura do projeto](#-estrutura-do-projeto)
- [FAQ](#-faq)
- [Aviso legal](#-aviso-legal)

---

## 📖 Sobre o projeto

O **GolpeScanner BR** é uma ferramenta educacional de cibersegurança feita para o contexto brasileiro. Ela analisa mensagens, links, chaves Pix, boletos e padrões de conversa para identificar **sinais de fraude**, atribuir um **nível de risco** e ainda entregar um **plano de ação** com os canais oficiais de denúncia e recuperação (MED do Bacen, Boletim de Ocorrência, ANPD, Procon...).

Tudo roda **localmente**, **sem API key**, **sem enviar seus dados para lugar nenhum**. As únicas conexões de rede são consultas DNS opcionais (para validar domínios), e somente se a biblioteca `dnspython` estiver instalada.

> 💡 Pensado para **pessoas comuns, familiares mais velhos, criadores de conteúdo e profissionais de segurança** que querem uma triagem rápida e explicável de algo suspeito.

---

## 🚨 Por que isso importa

O Brasil tem o **maior crescimento de fraudes digitais do mundo**. Alguns números que a própria ferramenta exibe (fontes: ADDP, FBSP, Banco Central):

| Indicador | Valor | Fonte |
|---|---|---|
| Fraudes Pix (jan–set/2025) | **28 milhões** de casos | ADDP |
| Fraudes via WhatsApp (2025) | **1,6 milhão** de casos | ADDP |
| Phishing por e-mail (2025) | **1,5 milhão** de casos | ADDP |
| Prejuízo Pix + boleto (12 meses) | **R$ 29 bilhões** | FBSP |
| Perda média por vítima | **R$ 6.311** | FBSP |
| Tentativas de golpe por hora | **4.600/hora** | FBSP |
| Crescimento 2024 → 2025 | **+65%** | Banco Central |
| Faixa etária mais afetada | **+50 anos (53%)** | ADDP |

> Projeção de perdas só com Pix: **R$ 11 bilhões até 2028** (ACI Worldwide).

---

## ✨ Funcionalidades

- 🔎 **6 módulos de análise** — mensagens, Pix, links, boletos, WhatsApp clonado e classificador de phishing.
- 🧠 **Classificador de phishing** baseado em ~26 features heurísticas, com score normalizado 0–100 e bônus por combinação de categorias suspeitas.
- 📚 **Enciclopédia de 20 tipos de golpe** brasileiros mapeados (bancário, Pix, engenharia social, falso emprego, sextorsão, etc.), com gatilhos, descrição e alerta.
- ⚖️ **Direitos legais + recursos** — MED do Bacen, como registrar B.O., denúncia na ANPD, Procon e mais.
- 📊 **Estatísticas de fraude no Brasil** com dados 2025/2026.
- ✅ **Validação real de algoritmos** — dígitos verificadores de CPF, CNPJ e linha digitável de boleto (módulo 10 e módulo 11).
- 🌐 **Checagem de domínio opcional** via DNS (registros MX para chaves Pix de e-mail).
- 💾 **Histórico local em JSON** + **relatórios `.txt`** exportáveis por análise.
- 📂 **Modo batch** para analisar arquivos `.txt` ou `.csv` em lote.
- 🎨 **Interface de terminal colorida** (com `colorama`) e degradação elegante sem cores.
- 🪶 **Zero dependências obrigatórias** — funciona só com a biblioteca padrão do Python.

---

## 🔧 Instalação

### Pré-requisitos

- **Python 3.9 ou superior** ([python.org/downloads](https://www.python.org/downloads/))

### Passo a passo

```bash
# 1. Clone o repositório (ou baixe o Golpescanner.py)
git clone https://github.com/kalyel473/golpescanner.git
cd golpescanner-br

# 2. (Opcional, recomendado) instale as dependências para a melhor experiência
pip install colorama dnspython requests

# 3. Pronto! Rode a ferramenta
python Golpescanner.py
```

### Dependências

A ferramenta funciona **sem nada instalado além do Python**. As bibliotecas abaixo são **opcionais** e apenas melhoram a experiência:

| Pacote | Para que serve | Se faltar... |
|---|---|---|
| `colorama` | Cores no terminal | Roda em preto e branco |
| `dnspython` | Validar domínios (registros MX) | Pula a checagem DNS |
| `requests` | Reservado para checagens de rede | Pula essas checagens |

Instale tudo de uma vez:

```bash
pip install colorama dnspython requests
```

---

## 🚀 Como usar

### Modo interativo (menu)

Basta executar sem argumentos para abrir o menu navegável:

```bash
python Golpescanner.py
```

```
━━━━ Menu Principal — GolpeScanner BR ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  ANÁLISE DE CONTEÚDO
    1. Analisar mensagem suspeita    (WhatsApp, SMS, e-mail, etc.)
    2. Verificar chave Pix           (CPF/CNPJ/telefone/e-mail/EVP)
    3. Analisar link/URL suspeita    (phishing, typosquatting)
    4. Validar boleto bancário       (linha digitável + dígitos)
    5. Detectar WhatsApp clonado     (padrões de sequestro de conta)
    6. Classificador ML de phishing  (26 features heurísticas)

  CONHECIMENTO E REFERÊNCIA
    7. Enciclopédia de golpes        (20 tipos mapeados)
    8. Direitos legais + recursos    (MED, B.O., ANPD, Procon...)
    9. Estatísticas de fraude no BR  (dados 2025/2026)
   10. Histórico de análises         (últimas análises realizadas)
   11. Modo batch                    (analisa arquivo .txt ou .csv)

    0. Sair
```

### Modo linha de comando (CLI)

Ideal para automação ou análise rápida de um único alvo:

```bash
# Analisar uma mensagem suspeita
python Golpescanner.py -m "Banco informou bloqueio da conta, clique aqui"

# Verificar uma chave Pix (CPF, CNPJ, e-mail, telefone ou EVP)
python Golpescanner.py -p 12345678901
python Golpescanner.py -p contato@empresa.com.br -v 1500.00 -n "João Silva"

# Analisar um link suspeito
python Golpescanner.py -u "http://bradesco-seguranca.xyz/login"

# Validar a linha digitável de um boleto
python Golpescanner.py -b "33590000000 10557956500 62082503000 17700820241"

# Detectar padrões de WhatsApp clonado
python Golpescanner.py -w "Oi, mudei de número, pode me emprestar R$300?"

# Classificar phishing via heurísticas (ML leve)
python Golpescanner.py --phishing "Sua conta foi bloqueada urgente clique aqui"

# Referência e dados
python Golpescanner.py --base --filtro whatsapp   # enciclopédia filtrada
python Golpescanner.py --lgpd                      # direitos e recursos legais
python Golpescanner.py --stats                     # estatísticas de fraude
python Golpescanner.py --historico                 # últimas análises
python Golpescanner.py --versao                    # versão
```

#### Tabela de argumentos

| Argumento | Atalho | Descrição |
|---|---|---|
| `--mensagem` | `-m` | Analisar mensagem suspeita |
| `--pix` | `-p` | Verificar chave Pix |
| `--valor` | `-v` | Valor da transação Pix (combina com `-p`) |
| `--nome` | `-n` | Nome do destinatário Pix (combina com `-p`) |
| `--url` | `-u` | Analisar link/URL |
| `--boleto` | `-b` | Validar linha digitável de boleto |
| `--whatsapp` | `-w` | Detectar WhatsApp clonado |
| `--phishing` | — | Classificar phishing via heurísticas |
| `--base` | — | Abrir a enciclopédia de golpes |
| `--filtro` | — | Filtrar a base por palavra-chave |
| `--lgpd` | — | Direitos e recursos legais |
| `--stats` | — | Estatísticas de fraude no Brasil |
| `--historico` | — | Histórico de análises |
| `--batch` | — | Analisar arquivo `.txt` ou `.csv` |
| `--versao` | — | Mostrar a versão |

### Modo batch (em lote)

Analise muitos alvos de uma vez a partir de um arquivo:

```bash
python Golpescanner.py --batch mensagens.txt
python Golpescanner.py --batch alvos.csv
```

---

## 🧩 Os 6 módulos de análise

| # | Módulo | O que detecta |
|---|--------|---------------|
| **1** | **Analisador de Mensagens** | Phishing e engenharia social: urgência, ameaças, pedidos de dados, links embutidos, spoofing de instituições e valores monetários suspeitos. |
| **2** | **Verificador de Chave Pix** | Identifica o tipo (CPF/CNPJ/telefone/e-mail/EVP), valida dígitos de CPF/CNPJ, estima região do CPF, alerta sobre nomes de bancos/órgãos como destinatário, valores de teste e domínios de e-mail sem MX. |
| **3** | **Scanner de Links/URLs** | Phishing, typosquatting, palavras-isca, domínios suspeitos e redirecionamentos. |
| **4** | **Validador de Boleto** | Confere a linha digitável com **módulo 10 e módulo 11**, valida dígitos verificadores e o código do banco/cedente. |
| **5** | **Detector de WhatsApp Clonado** | Reconhece padrões clássicos de sequestro de conta ("mudei de número", pedidos de empréstimo urgente, etc.). |
| **6** | **Classificador de Phishing (ML leve)** | ~26 features heurísticas com score 0–100, nível de confiança e bônus por combinação de categorias (urgência + ameaça + dados...). |

---

## 📂 Saídas e relatórios

A ferramenta cria automaticamente uma pasta `output_golpescanner/`:

```
output_golpescanner/
├── historico.json     # log de todas as análises realizadas
├── debug.log          # log técnico (nível WARNING+)
└── relatorio_*.txt    # relatórios individuais exportados
```

- **`historico.json`** — registro local de cada análise (consultável via `--historico`).
- **`relatorio_*.txt`** — relatório legível de uma análise específica, com evidências, score e plano de ação.

> 🔒 Todos os dados ficam **somente na sua máquina**. Nada é enviado a servidores externos.

---

## 🧮 Como funciona o cálculo de risco

Cada análise produz um **score de 0 a 100** somando pesos das **evidências** encontradas. O classificador de phishing normaliza o score e aplica um **bônus por combinação**:

- ✅ **2 categorias suspeitas** detectadas → +8 pontos
- ✅ **3 ou mais categorias** → +15 pontos

E então classifica:

| Score final | Classificação | Significado |
|---|---|---|
| **≥ 55** | 🔴 PHISHING CONFIRMADO | Confiança 70–99% |
| **35–54** | 🟠 ALTO RISCO DE PHISHING | Trate com extrema cautela |
| **18–34** | 🟡 SUSPEITO | Vale verificar por outro canal |
| **< 18** | 🟢 BAIXO RISCO | Sem sinais fortes (mas continue atento) |

> ⚠️ O score é uma **triagem heurística**, não um veredito. Use o bom senso e os canais oficiais antes de qualquer decisão financeira.

---

## 🗂️ Estrutura do projeto

```
Golpescanner/
├── Golpescanner.py          # toda a ferramenta (script único)
├── Readme.md                # este arquivo
└── output_golpescanner/     # gerado em tempo de execução
    ├── historico.json
    ├── debug.log
    └── relatorio_*.txt
```

---

## ❓ FAQ

**A ferramenta envia meus dados para algum servidor?**
Não. Tudo é processado localmente. A única conexão externa possível é uma consulta DNS opcional (registros MX) e só se `dnspython` estiver instalado.

**Preciso instalar alguma coisa?**
Não obrigatoriamente — só o Python 3.9+. As bibliotecas `colorama`, `dnspython` e `requests` são opcionais e melhoram a experiência.

**O resultado "BAIXO RISCO" garante que é seguro?**
Não. Nenhuma ferramenta automática substitui o bom senso. Golpes novos surgem o tempo todo; sempre confirme por um canal oficial.

**Funciona no Windows, Linux e Mac?**
Sim. É Python puro e multiplataforma.

**Caí em um golpe. E agora?**
Use o módulo **8 (Direitos legais + recursos)** ou rode `--lgpd`: ele lista o MED do Banco Central, como registrar B.O., denúncia na ANPD, Procon e outros caminhos de recuperação.

---

## ⚖️ Aviso legal

> Esta é uma **ferramenta educacional**. Foi criada para **identificar e ajudar pessoas a se protegerem de golpes digitais**.
>
> - O resultado é uma **avaliação heurística de risco**, não uma prova judicial nem garantia absoluta.
> - O autor **não se responsabiliza** por decisões tomadas com base nas análises.
> - **Não use** esta ferramenta para fins ilícitos.
> - Em caso de fraude, **procure os canais oficiais**: seu banco, o Banco Central (MED), a polícia (B.O.) e a ANPD.

---

<div align="center">

</div>
