#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# ── stdlib ────────────────────────────────────────────────────────────────
import sys, os, re, json, math, time, datetime, hashlib, argparse, getpass
import socket, urllib.parse, unicodedata, textwrap, csv, logging
from pathlib import Path
from collections import Counter
from typing import Optional

# ── dependências opcionais ────────────────────────────────────────────────
try:
    from colorama import init as _cinit, Fore, Back, Style
    _cinit(autoreset=True)
    HAS_COLOR = True
except ImportError:
    HAS_COLOR = False

try:
    import dns.resolver
    HAS_DNS = True
except ImportError:
    HAS_DNS = False

try:
    import requests as _req
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

# ═══════════════════════════════════════════════════════════════════════════
# SISTEMA DE CORES
# ═══════════════════════════════════════════════════════════════════════════
class C:
    if HAS_COLOR:
        R  = Fore.RED;       G  = Fore.GREEN;   Y  = Fore.YELLOW
        CY = Fore.CYAN;      MG = Fore.MAGENTA; W  = Fore.WHITE
        BL = Fore.BLUE;      BD = Style.BRIGHT; RS = Style.RESET_ALL
        BGR= Back.RED;       BGG= Back.GREEN;   BGY= Back.YELLOW
        BGC= Back.CYAN;      BGM= Back.MAGENTA; BGW= Back.WHITE
    else:
        R=G=Y=CY=MG=W=BL=BD=RS=BGR=BGG=BGY=BGC=BGM=BGW=""

# ═══════════════════════════════════════════════════════════════════════════
# CONSTANTES GLOBAIS
# ═══════════════════════════════════════════════════════════════════════════
VERSION  = "1.0.0"
AUTHOR   = "@kalyel473"
GITHUB   = "github.com/kalyel473"
DISCORD  = "discord.gg/kbMyJPbF"
OUT_DIR  = Path("output_golpescanner")
LOG_FILE = OUT_DIR / "historico.json"
OUT_DIR.mkdir(exist_ok=True)

# Logging silencioso para depuração
logging.basicConfig(
    filename=str(OUT_DIR / "debug.log"),
    level=logging.WARNING,
    format="%(asctime)s %(levelname)s %(message)s"
)

# ═══════════════════════════════════════════════════════════════════════════
# BASE DE CONHECIMENTO — GOLPES BRASILEIROS
# ═══════════════════════════════════════════════════════════════════════════

# ── Padrões textuais de golpe ─────────────────────────────────────────────
PADROES_GOLPE: list[dict] = [
    # ── Golpes bancários / Pix ────────────────────────────────────────────
    {
        "id": "G001", "nome": "Falsa central de atendimento",
        "categoria": "Bancário",
        "gatilhos": [
            r"central\s+de\s+atendimento",
            r"banco\s+(ligou|entrando\s+em\s+contato|informa)",
            r"confirme\s+(seus\s+)?dados\s+bancários",
            r"bloqueio\s+(preventivo|temporário|da\s+conta)",
            r"sua\s+conta\s+(será|foi|está)\s+(bloqueada?|suspensa?)",
            r"operação\s+(suspeita|irregular|fraudulenta)",
        ],
        "peso": 35,
        "descricao": "Criminosos se passam por funcionários do banco para obter dados ou convencer a vítima a transferir dinheiro.",
        "alerta": "Bancos NUNCA ligam pedindo senha, token ou transferência por telefone.",
    },
    {
        "id": "G002", "nome": "Pix errado / estorno falso",
        "categoria": "Pix",
        "gatilhos": [
            r"pix\s+(enviado\s+)?por\s+engano",
            r"estorn(o|e|ar)\s+(o\s+)?pix",
            r"transferência\s+(indevida|errada|equivocada)",
            r"me\s+devolv(a|e|er)\s+(o\s+)?(valor|dinheiro|pix)",
            r"pix\s+caiu\s+na\s+conta\s+errada",
        ],
        "peso": 40,
        "descricao": "Golpista envia Pix e pede devolução imediata, mas o valor original vem de conta roubada ou nunca foi enviado.",
        "alerta": "Nunca devolva Pix sem verificar no app do banco. Use o MED (Mecanismo de Devolução) do Bacen.",
    },
    {
        "id": "G003", "nome": "Golpe do falso funcionário",
        "categoria": "Engenharia Social",
        "gatilhos": [
            r"sou\s+(o\s+)?(gerente|funcionário|atendente|supervisor|analista)\s+d[oa]",
            r"departamento\s+de\s+(fraude|segurança|prevenção)",
            r"estamos\s+(verificando|investigando|analisando)\s+(uma\s+)?(fraude|irregularidade)",
            r"para\s+sua\s+segurança\s+(precisamos?|solicitamos?|pedimos?)",
            r"cancelar?\s+a\s+(fraude|operação)\s+precis",
        ],
        "peso": 38,
        "descricao": "Golpista imita funcionário de banco, Correios, Anatel, INSS ou empresa para extrair dados ou dinheiro.",
        "alerta": "Desligue e ligue você mesmo para o número oficial da instituição.",
    },
    {
        "id": "G004", "nome": "Phishing bancário por link",
        "categoria": "Phishing",
        "gatilhos": [
            r"clique\s+(aqui|no\s+link|abaixo)\s+para\s+(atualizar|confirmar|validar)",
            r"(acesse|entre\s+em)\s+(nosso\s+)?(portal|site|sistema)\s+(seguro|exclusivo)",
            r"token\s+(expirando?|expirou|inválido|incorreto)",
            r"recadastr(e|ar|amento)\s+(seus?\s+)?(dados|conta|chave)",
            r"link\s+(exclusivo|único|personalizado|temporário)",
            r"seu\s+(cadastro|conta|acesso)\s+(expira|vence|será\s+cancelad)",
        ],
        "peso": 42,
        "descricao": "Mensagem com link falso que imita site bancário para roubar credenciais e dados sensíveis.",
        "alerta": "Acesse o app ou site do banco sempre digitando o endereço manualmente. Nunca por link.",
    },
    {
        "id": "G005", "nome": "Golpe do falso leilão / oferta",
        "categoria": "Compra/Venda",
        "gatilhos": [
            r"leilão\s+(da\s+)?(receita|federal|detran|banco|caixa)",
            r"veículo?\s+(apreendido|recuperado|leiloado)\s+por\s+R\$",
            r"produto\s+(abaixo\s+do\s+custo|com\s+desconto\s+exclusivo|único\s+no\s+brasil)",
            r"(iphone|samsung|notebook|tv)\s+por\s+R\$\s*[1-9]\d{0,2}[,\.]?\d{0,2}\b",
            r"(ganhou?|você\s+foi\s+selecionado|sorteado)\s+(um?|uma?)\s+(iphone|prêmio|viagem)",
        ],
        "peso": 30,
        "descricao": "Oferta irreal de produto ou leilão falso para obter pagamento antecipado via Pix ou boleto.",
        "alerta": "Preços muito abaixo do mercado são sempre sinal de golpe. Pesquise antes de pagar.",
    },
    {
        "id": "G006", "nome": "Golpe do WhatsApp clonado / sequestrado",
        "categoria": "WhatsApp",
        "gatilhos": [
            r"estou\s+(com\s+um\s+)?(problema|imprevisto|emergência)",
            r"(mudei?\s+de\s+número|número\s+novo|salvou?\s+o\s+contato)",
            r"pode\s+me\s+emprestar\s+(R\$|dinheiro|um\s+valor)",
            r"preciso\s+(muito|urgente|com\s+urgência)\s+de\s+(R\$|dinheiro|ajuda\s+financeira)",
            r"devolvo\s+(amanhã|semana\s+que\s+vem|depois\s+de\s+amanhã|quando\s+puder)",
            r"por\s+(favor|gentileza)\s+não\s+coment(e|a)\s+com\s+(ninguém|a\s+família)",
        ],
        "peso": 45,
        "descricao": "Conta clonada ou número falso imita familiar/amigo pedindo dinheiro urgente.",
        "alerta": "Ligue para o número original da pessoa antes de qualquer transferência.",
    },
    {
        "id": "G007", "nome": "Golpe do falso emprego / trabalho home office",
        "categoria": "Emprego",
        "gatilhos": [
            r"trabalhe\s+(de\s+casa|em\s+casa|pelo\s+celular|home\s+office)",
            r"ganhe\s+(até\s+)?R\$\s*[\d\.]+\s*(por\s+dia|por\s+hora|semanalmente)",
            r"(contrat|selecionar?|chamar)\s+(você\s+para|para\s+trabalhar)",
            r"sem\s+experiência\s+(necessária|exigida|precisa)",
            r"(curtir?|like|avaliar?|comentar?)\s+(post|foto|produto|vídeo)\s+e\s+ganha",
            r"vaga\s+(imediata|urgente|disponível)\s+para\s+trabalh",
        ],
        "peso": 33,
        "descricao": "Oferta de trabalho fácil com alta remuneração para atrair vítimas, exigindo pagamento inicial ou dados.",
        "alerta": "Trabalhos legítimos nunca pedem depósito antecipado para 'liberação de cadastro'.",
    },
    {
        "id": "G008", "nome": "Golpe do falso prêmio / sorteio",
        "categoria": "Premiação",
        "gatilhos": [
            r"parabéns[,!]?\s+(você\s+)?(foi\s+selecionado|ganhou|é\s+o\s+ganhador)",
            r"(premio|prêmio)\s+(de\s+R\$|no\s+valor\s+de)",
            r"(resgate|retirar?|liberar?)\s+(seu|o)\s+(premio|prêmio|brinde|vale)",
            r"taxa\s+de\s+(liberação|retirada|entrega|administração)\s+do\s+(prêmio|vale|brinde)",
            r"promoção\s+(encerra\s+hoje|válida\s+por|últimas?\s+horas?)",
            r"(loteria|mega.?sena|quina|lotomania)\s+(premiou|sorteou|anunciou)",
        ],
        "peso": 38,
        "descricao": "Falsa notificação de prêmio para induzir pagamento de 'taxas' ou coleta de dados pessoais.",
        "alerta": "Prêmios legítimos não cobram taxa de liberação. Se você não participou, não ganhou.",
    },
    {
        "id": "G009", "nome": "Golpe do investimento / pirâmide",
        "categoria": "Financeiro",
        "gatilhos": [
            r"(rendimento|retorno|lucro)\s+de\s+\d{1,3}[%％]\s+(ao\s+dia|por\s+dia|diário)",
            r"(cripto|bitcoin|investimento)\s+(seguro|garantido|sem\s+risco)",
            r"(multiplique?|dobre?|triplique?)\s+(seu|o)\s+(dinheiro|investimento|capital)",
            r"plataforma\s+de\s+investimento\s+(exclusiva|nova|revolucionária)",
            r"indique\s+(amigos?|pessoas?)\s+e\s+(ganhe|receba|lucre)",
            r"robô\s+(trader|de\s+investimento|automático)\s+(lucra|ganha|opera)",
        ],
        "peso": 45,
        "descricao": "Esquemas de pirâmide ou investimentos fraudulentos prometendo retornos impossíveis.",
        "alerta": "Retornos acima de 1% ao mês com 'garantia' são ilegais. Consulte sempre a CVM.",
    },
    {
        "id": "G010", "nome": "Boleto falso / malware por boleto",
        "categoria": "Bancário",
        "gatilhos": [
            r"boleto\s+(atualizado|vencido|segunda\s+via|revisado|corrigido)",
            r"(pagar|efetuar\s+pagamento)\s+com\s+o\s+novo\s+boleto",
            r"linha\s+digitável\s+(atualizada|corrigida|nova)",
            r"vencimento\s+(alterado|mudou|foi\s+alterado)\s+para",
            r"(conta\s+de\s+)?energia\s+(elétrica|enel|cemig|copel|light)\s+(segunda\s+via|boleto)",
        ],
        "peso": 35,
        "descricao": "Golpista substitui boleto legítimo por falso, redirecionando pagamento para conta própria.",
        "alerta": "Sempre verifique os 3 primeiros dígitos da linha digitável com o CNPJ do credor.",
    },
    {
        "id": "G011", "nome": "Golpe do falso familiar em apuros",
        "categoria": "Engenharia Social",
        "gatilhos": [
            r"(sou|é)\s+(seu|sua)\s+(filho[a]?|mã[ei]|pai|irmã[o]?|sobrinho[a]?|neto[a]?)",
            r"(sofri|tive|aconteceu)\s+(um\s+)?(acidente|assalto|batida|problema)",
            r"(preso|detido|hospital|delegacia)\s+(precis|socorro|urgent)",
            r"não\s+(conta|fala|coment[ae])\s+para\s+(o\s+)?(seu\s+)?pai\s+(ou|e)\s+sua\s+mãe",
            r"(advogado|fiança|hospital)\s+cobr(a|ou|ando)\s+R\$",
        ],
        "peso": 42,
        "descricao": "Imita familiar em situação de emergência para forçar transferência imediata.",
        "alerta": "Sempre ligue diretamente para o número do familiar antes de qualquer ação.",
    },
    {
        "id": "G012", "nome": "Golpe do motoboy / falso policial",
        "categoria": "Presencial",
        "gatilhos": [
            r"motoboy\s+(buscar|coletar|pegar|retirar)\s+(o\s+)?(cartão|dinheiro|cheque)",
            r"(policial|delegado|detetive|investigador)\s+(ligou|informou|confirmou)",
            r"entregu[e\s]+o\s+(cartão|dinheiro)\s+(para\s+o\s+motoboy|ao\s+mensageiro)",
            r"cartão\s+(clonado|comprometido|bloqueado)\s+(precisamos?|vamos?)\s+substituir",
            r"nunca\s+(entregue|passe)\s+(seu|o)\s+cartão\s+para\s+ninguém",
        ],
        "peso": 48,
        "descricao": "Criminoso liga fingindo ser banco ou policial e manda motoboy buscar cartão e senha.",
        "alerta": "Bancos e polícia NUNCA mandam buscar seu cartão. Destrua e cancele imediatamente.",
    },
    {
        "id": "G013", "nome": "Golpe do INSS / benefício falso",
        "categoria": "Governo",
        "gatilhos": [
            r"(inss|previdência)\s+(social\s+)?(informa|comunica|entra\s+em\s+contato)",
            r"(benefício|aposentadoria|pensão)\s+(bloqueado|suspenso|cancelado|irregular)",
            r"(recadastr|atualiz|regulariz)\s+(seu|o)\s+(benefício|cadastro|cpf)\s+(no|pelo)\s+inss",
            r"perícia\s+(médica\s+)?(agendada|marcada|obrigatória)\s+urgente",
            r"(taxa|tarifa)\s+de\s+(regularização|atualização)\s+do\s+(benefício|cpf|inss)",
        ],
        "peso": 40,
        "descricao": "Falsos comunicados do INSS para roubar dados previdenciários ou cobrar taxas inexistentes.",
        "alerta": "INSS nunca cobra taxas e não liga pedindo dados. Acesse apenas pelo gov.br.",
    },
    {
        "id": "G014", "nome": "Golpe do amor / relacionamento",
        "categoria": "Romance",
        "gatilhos": [
            r"(encontrei|achei|descobri)\s+(uma\s+)?(oportunidade|investimento)\s+incrível",
            r"(meu\s+)?(uncle|tio|pai)\s+(é|trabalha\s+como)\s+(petróleo|militar|diplomata)",
            r"preciso\s+de\s+(ajuda\s+financeira|dinheiro)\s+para\s+(vir|me\s+encontrar|viagem)",
            r"(passagem|visto|alfândega|hospital)\s+(me\s+)?(cobr|pedi|exigiu|pag)",
            r"amor\s+(único|verdadeiro|eterno)\s+(encontrei|achei|você\s+é)",
        ],
        "peso": 36,
        "descricao": "Golpe romântico onde criminoso cria relacionamento virtual para extorquir dinheiro.",
        "alerta": "Pessoas que pedem dinheiro sem se conhecerem pessoalmente são sempre golpistas.",
    },
    {
        "id": "G015", "nome": "Phishing por e-mail / SMS",
        "categoria": "Phishing",
        "gatilhos": [
            r"(sua\s+conta|o\s+acesso)\s+(será|foi)\s+(suspens|bloqueado|encerrado)\s+em\s+\d+\s*h",
            r"atividade\s+(suspeita|incomum|não\s+reconhecida)\s+(detectada|identificada)",
            r"(confirme|valide|verifique)\s+sua\s+(identidade|conta|senha)\s+(agora|urgente)",
            r"http[s]?://[^\s]{0,15}\.(xyz|top|online|site|click|gq|ml|cf|tk)",
            r"(atualiz|confirmação\s+de)\s+(cadastro|dados)\s+(obrigatório|necessário)",
        ],
        "peso": 40,
        "descricao": "E-mails ou SMS falsos imitando empresas legítimas para capturar credenciais.",
        "alerta": "Jamais clique em links recebidos por e-mail ou SMS. Acesse o site diretamente.",
    },
    {
        "id": "G016", "nome": "Golpe da portabilidade / cancelamento forçado",
        "categoria": "Telecomunicações",
        "gatilhos": [
            r"portabilidade\s+(do\s+número|foi\s+solicitada|em\s+andamento)",
            r"(cancelamento|bloqueio)\s+da\s+(linha|chip|número)\s+(em\s+\d+|urgente)",
            r"(anatel|claro|vivo|tim|oi)\s+(informa|comunica|alerta)",
            r"chip\s+(clonado|duplicado|comprometido|irregular)",
            r"código\s+de\s+(verificação|confirmação|portabilidade)\s+(enviado|recebido)",
        ],
        "peso": 35,
        "descricao": "Golpe para tomar controle do número de telefone via portabilidade ou clonagem de chip.",
        "alerta": "Nunca compartilhe código de verificação recebido por SMS com ninguém.",
    },
    {
        "id": "G017", "nome": "Golpe do QR Code falso",
        "categoria": "Pix",
        "gatilhos": [
            r"qr\s*code\s+(atualizado|novo|corrigido|gerado)",
            r"escane?ie?\s+(o\s+)?(qr\s*code|código\s+qr)\s+(abaixo|aqui|anexo)",
            r"pague?\s+(via\s+|pelo\s+)?qr\s*code\s+(para\s+receber|para\s+garantir)",
            r"qr\s*code\s+(de\s+)?(desconto|brinde|prêmio|liberação)",
        ],
        "peso": 38,
        "descricao": "QR Code falso redirecionando pagamentos Pix para conta do golpista.",
        "alerta": "Sempre confira o nome e CPF/CNPJ do destinatário antes de confirmar o Pix.",
    },
    {
        "id": "G018", "nome": "Golpe do suporte técnico falso",
        "categoria": "Tecnologia",
        "gatilhos": [
            r"(microsoft|apple|google|suporte)\s+(detectou|identificou|encontrou)\s+(vírus|ameaça|erro)",
            r"(ligue|contate|fale)\s+com\s+(o\s+)?suporte\s+(técnico|especializado)\s+(agora|urgente)",
            r"seu\s+(computador|dispositivo|celular)\s+(está|foi)\s+(infectado|comprometido|hackeado)",
            r"não\s+(desligue|feche|saia)\s+desta\s+(tela|página|janela)",
            r"acesso\s+remoto\s+(necessário|obrigatório)\s+para\s+(resolver|corrigir|limpar)",
        ],
        "peso": 36,
        "descricao": "Imita suporte de grandes empresas para obter acesso remoto ao dispositivo ou dados bancários.",
        "alerta": "Microsoft, Apple e Google NUNCA ligam proativamente para o usuário sobre vírus.",
    },
    {
        "id": "G019", "nome": "Deepfake / Identidade falsa",
        "categoria": "Tecnologia Avançada",
        "gatilhos": [
            r"áudio\s+(do|do\s+seu)\s+(chefe|diretor|ceo|gerente)\s+(pediu|solicitou|mandou)",
            r"vídeo\s+(de\s+verificação|de\s+identidade)\s+(comprova|confirma)",
            r"inteligência\s+artificial\s+(confirmou|verificou|autenticou)",
            r"(voz|foto|vídeo)\s+(autenticada|verificada|confirmada)\s+(pelo\s+sistema|automaticamente)",
        ],
        "peso": 50,
        "descricao": "Uso de deepfake de voz ou vídeo para enganar funcionários ou familiares.",
        "alerta": "Implemente sempre uma palavra-código de segurança com familiares e empresa.",
    },
    {
        "id": "G020", "nome": "Golpe da Taxa de Importação falsa",
        "categoria": "Compra/Venda",
        "gatilhos": [
            r"(encomenda|pacote|produto)\s+(retido|parado|bloqueado)\s+na\s+(alfândega|receita\s+federal|correios)",
            r"taxa\s+de\s+(importação|desembaraço|liberação|alfândega)\s+(de\s+R\$|no\s+valor)",
            r"(correios|sedex|fedex|dhl)\s+(informa|comunica|alerta)\s+(encomenda|pacote)",
            r"pague?\s+a\s+taxa\s+para\s+(liberar|receber|despachar)\s+(o\s+)?produto",
        ],
        "peso": 32,
        "descricao": "Falsa cobrança de taxa de importação para liberar encomenda inexistente.",
        "alerta": "Taxas legítimas de importação são pagas no site dos Correios ou Receita Federal, nunca por link de e-mail.",
    },
]

# ── Palavras de urgência e pressão psicológica ────────────────────────────
PALAVRAS_URGENCIA: list[tuple[str, int]] = [
    (r"\b(urgente|urgência|imediato|agora\s+mesmo|neste\s+momento)\b", 8),
    (r"\b(última\s+chance|última\s+oportunidade|últ(ima|imo)s?\s+\d+\s+(hora|minuto)s?)\b", 10),
    (r"\b(prazo\s+(encerra|vence|acaba)\s+(hoje|agora|em\s+breve))\b", 9),
    (r"\b(não\s+(perca|deixe\s+de|espere|demore|perca\s+tempo))\b", 6),
    (r"\b(bloqueio\s+em\s+\d+\s+(minutos?|horas?))\b", 12),
    (r"\b(conta\s+será\s+(encerrada|bloqueada|cancelada)\s+(em\s+)?\d+)\b", 12),
    (r"\b(responda?\s+(imediatamente|agora|urgente))\b", 8),
    (r"\b(antes\s+que\s+seja\s+tarde|antes\s+do\s+prazo)\b", 7),
    (r"\b(ação\s+(imediata|urgente|necessária)\s+requerida?)\b", 9),
    (r"\bATENÇÃO\b", 5),
    (r"\bIMPORTANTE\b", 4),
    (r"\bALERTA\b", 4),
]

# ── Palavras de ameaça / coerção ──────────────────────────────────────────
PALAVRAS_AMEACA: list[tuple[str, int]] = [
    (r"\b(processo\s+judicial|ação\s+judicial|ser\s+processado)\b", 10),
    (r"\b(nome\s+no\s+spc|negativado|serasa|cpf\s+bloqueado)\b", 8),
    (r"\b(penhora\s+(de\s+bens?|do\s+(imóvel|carro|conta)))\b", 12),
    (r"\b(boletim\s+de\s+ocorrência|b\.?o\.?\s+registrado?)\b", 7),
    (r"\b(crime\s+(de\s+estelionato|financeiro|virtual))\b", 8),
    (r"\b(mandado\s+de\s+(prisão|busca|apreensão))\b", 15),
    (r"\b(investigação\s+(criminal|policial|federal))\b", 10),
]

# ── Ofertas impossíveis ───────────────────────────────────────────────────
PALAVRAS_OFERTA: list[tuple[str, int]] = [
    (r"\b(grátis|gratuito|sem\s+custo|de\s+graça)\b", 3),
    (r"\b(ganhe?\s+R\$\s*[\d\.]+\s+por\s+(dia|hora|semana))\b", 10),
    (r"\b(\d{1,3}%\s*(de\s+)?desconto)\b", 2),
    (r"\b(100%\s+(garantido|seguro|sem\s+risco))\b", 8),
    (r"\b(rend(imento|a)\s+(diário|garantido))\b", 10),
    (r"\b(dinheiro\s+fácil|renda\s+extra\s+de)\b", 9),
    (r"\b(apenas\s+R\$\s*[1-9]\d?\b)", 4),
    (r"\br\$\s*0[,\.]00\b", 6),
]

# ── Solicitações suspeitas ────────────────────────────────────────────────
PALAVRAS_SOLICITACAO: list[tuple[str, int]] = [
    (r"\b(informe|passe|envie|mande|compartilhe)\s+(sua|o)\s+(senha|token|código)", 15),
    (r"\b(dados?\s+(do\s+)?(cartão|bancários?|pessoais?))\b", 8),
    (r"\b(número\s+do\s+(cartão|conta|cpf))\b", 6),
    (r"\b(código\s+de\s+(verificação|segurança|autenticação))\b", 10),
    (r"\binstale?\s+(aplicativo|app|software|programa)\b", 7),
    (r"\b(acesso\s+remoto|team\s*viewer|anydesk|controle\s+remoto)\b", 14),
    (r"\b(foto|selfie|documento)\s+(do\s+)?(rg|cpf|cnh|passaporte)\b", 8),
    (r"\bpix\s+(para|de)\s+R\$\s*[\d\.]+\b", 5),
    (r"\btransfer(ência|ir)\s+(R\$\s*[\d\.]+|dinheiro|valor)\b", 8),
]

# ── TLDs de alto risco ────────────────────────────────────────────────────
TLDS_RISCO: set[str] = {
    ".xyz", ".top", ".club", ".online", ".site", ".tech", ".click",
    ".link", ".gq", ".ml", ".cf", ".ga", ".tk", ".work", ".loan",
    ".win", ".bid", ".trade", ".webcam", ".racing", ".accountant",
    ".download", ".review", ".stream", ".party", ".cricket", ".science",
    ".faith", ".men", ".date", ".country", ".kim", ".accountants",
}

# ── Bancos brasileiros — nomes para detecção de spoofing ─────────────────
BANCOS_BR: set[str] = {
    "bradesco", "itau", "itaú", "caixa", "cef", "banco do brasil",
    "bb", "santander", "nubank", "inter", "c6bank", "c6", "btg",
    "safra", "sicredi", "sicoob", "cooperativa", "banrisul", "original",
    "neon", "pagbank", "mercado pago", "picpay", "next", "bs2",
    "modal", "btg pactual", "votorantim", "bndes", "banco central",
    "bacen", "bcb",
}

# ── Órgãos governamentais — spoofing ─────────────────────────────────────
ORGAOS_GOV: set[str] = {
    "receita federal", "inss", "detran", "denatran", "anatel", "anpd",
    "procon", "polícia federal", "pf", "policia civil", "mp", "mpf",
    "tribunal", "trf", "stj", "stf", "tcu", "cgu", "cvm", "bacen",
    "banco central", "correios", "serasa", "spc", "boa vista",
}

# ── Domínios legítimos vs suspeitos de bancos BR ─────────────────────────
DOMINIOS_LEGITIMOS_BANCOS: dict[str, list[str]] = {
    "bradesco":    ["bradesco.com.br", "bradesconetempresa.com.br"],
    "itau":        ["itau.com.br", "itauunibanco.com.br"],
    "caixa":       ["caixa.gov.br", "caixaeconomicafederal.gov.br"],
    "bb":          ["bb.com.br", "bancodobrasil.com.br"],
    "santander":   ["santander.com.br"],
    "nubank":      ["nubank.com.br"],
    "inter":       ["bancointer.com.br", "inter.co"],
    "c6bank":      ["c6bank.com.br"],
    "picpay":      ["picpay.com"],
    "pagbank":     ["pagbank.com.br", "pagseguro.com.br"],
    "neon":        ["neon.com.br"],
    "mercadopago": ["mercadopago.com.br", "mercadolivre.com.br"],
}

# ── Chaves Pix — tipos e padrões ─────────────────────────────────────────
TIPOS_CHAVE_PIX: dict[str, str] = {
    "CPF":      r"^\d{11}$",
    "CNPJ":     r"^\d{14}$",
    "Telefone": r"^\+?55?\d{10,11}$",
    "E-mail":   r"^[\w\.\+\-]+@[\w\-]+\.[a-z]{2,}$",
    "EVP":      r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
}

# ── Prefixos de boleto → banco cedente ───────────────────────────────────
PREFIXOS_BOLETO: dict[str, str] = {
    "001": "Banco do Brasil",
    "033": "Santander",
    "041": "Banrisul",
    "077": "Banco Inter",
    "084": "Uniprime",
    "085": "AILOS",
    "097": "Credisis",
    "099": "Uniprime Norte",
    "104": "Caixa Econômica Federal",
    "133": "Cresol",
    "136": "Unicred",
    "212": "Banco Original",
    "237": "Bradesco",
    "246": "Banco ABC Brasil",
    "260": "Nu Pagamentos (Nubank)",
    "290": "PagBank",
    "318": "Banco BMG",
    "336": "C6 Bank",
    "341": "Itaú Unibanco",
    "389": "Banco Mercantil do Brasil",
    "422": "Banco Safra",
    "505": "Credit Suisse",
    "633": "Banco Rendimento",
    "634": "Banco Triângulo",
    "652": "Itaú Unibanco Holding",
    "655": "Banco Votorantim",
    "707": "Banco Daycoval",
    "735": "Banco Neon",
    "745": "Citibank",
    "748": "Sicredi",
    "756": "Sicoob",
    "001": "Banco do Brasil",
}

# ── Recursos legais pós-golpe ─────────────────────────────────────────────
RECURSOS_LEGAIS: list[dict] = [
    {
        "titulo": "MED — Mecanismo Especial de Devolução (Bacen)",
        "desc": "Solicite devolução de Pix fraudulento em até 80 dias.",
        "url": "bcb.gov.br/maquinadeintegracao/med",
        "prazo": "80 dias",
        "tipo": "pix",
    },
    {
        "titulo": "Boletim de Ocorrência Online",
        "desc": "Registre o crime de estelionato ou fraude eletrônica.",
        "url": "delegaciaeletronica.pc.sp.gov.br (SP) / site do BO do seu estado",
        "prazo": "Imediato",
        "tipo": "todos",
    },
    {
        "titulo": "Procon — Denúncia de Fraude Comercial",
        "desc": "Registre quando o golpe envolve empresa ou loja.",
        "url": "procon.sp.gov.br / procon do seu estado",
        "prazo": "Imediato",
        "tipo": "compra_venda",
    },
    {
        "titulo": "ANPD — Violação de Dados Pessoais",
        "desc": "Denuncie quando seus dados pessoais forem coletados ilegalmente.",
        "url": "gov.br/anpd",
        "prazo": "Imediato",
        "tipo": "dados",
    },
    {
        "titulo": "Banco Central — Denúncia de Fraude",
        "desc": "Denuncie instituições financeiras irregulares.",
        "url": "bcb.gov.br/acessoinformacao/faleconosco",
        "prazo": "Imediato",
        "tipo": "bancário",
    },
    {
        "titulo": "CVM — Pirâmide Financeira / Investimento Ilegal",
        "desc": "Denuncie esquemas de pirâmide e investimentos não autorizados.",
        "url": "cvm.gov.br/denuncia",
        "prazo": "Imediato",
        "tipo": "investimento",
    },
    {
        "titulo": "SaferNet Brasil — Crimes na Internet",
        "desc": "Denuncie crimes na internet à Polícia Federal.",
        "url": "new.safernet.org.br/denuncie",
        "prazo": "Imediato",
        "tipo": "internet",
    },
    {
        "titulo": "Registrato Bacen — Bloqueio Preventivo",
        "desc": "Monitore contas e chaves Pix abertas no seu CPF.",
        "url": "registrato.bcb.gov.br",
        "prazo": "Preventivo",
        "tipo": "prevenção",
    },
]

# ═══════════════════════════════════════════════════════════════════════════
# UTILITÁRIOS DE EXIBIÇÃO
# ═══════════════════════════════════════════════════════════════════════════

def banner() -> None:
    print(f"""{C.CY}{C.BD}
  ██████╗  ██████╗ ██╗     ██████╗ ███████╗    ███████╗ ██████╗ █████╗ ███╗   ██╗███╗   ██╗███████╗██████╗
 ██╔════╝ ██╔═══██╗██║     ██╔══██╗██╔════╝    ██╔════╝██╔════╝██╔══██╗████╗  ██║████╗  ██║██╔════╝██╔══██╗
 ██║  ███╗██║   ██║██║     ██████╔╝█████╗      ███████╗██║     ███████║██╔██╗ ██║██╔██╗ ██║█████╗  ██████╔╝
 ██║   ██║██║   ██║██║     ██╔═══╝ ██╔══╝      ╚════██║██║     ██╔══██║██║╚██╗██║██║╚██╗██║██╔══╝  ██╔══██╗
 ╚██████╔╝╚██████╔╝███████╗██║     ███████╗    ███████║╚██████╗██║  ██║██║ ╚████║██║ ╚████║███████╗██║  ██║
  ╚═════╝  ╚═════╝ ╚══════╝╚═╝     ╚══════╝    ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝{C.RS}
{C.Y}                    B R  —  Detector de Golpes Digitais Brasileiros  v{VERSION}{C.RS}
{C.MG}              {AUTHOR}  ·  {GITHUB}  ·  {DISCORD}{C.RS}
{C.R}    ⚠  Ferramenta educacional. Use para identificar e se proteger de golpes.{C.RS}
""")

def sep(char: str = "─", n: int = 72) -> None:
    print(f"{C.CY}{char * n}{C.RS}")

def linha(char: str = "─", n: int = 72) -> None:
    sep(char, n)

def titulo(t: str) -> None:
    pad = max(0, 62 - len(t))
    print(f"\n{C.BD}{C.Y}{'━' * 4} {t} {'━' * pad}{C.RS}")

def secao(t: str) -> None:
    print(f"\n  {C.BD}{C.CY}▸ {t}{C.RS}")

def ok(m: str)    -> None: print(f"  {C.G}[✔]{C.RS} {m}")
def erro(m: str)  -> None: print(f"  {C.R}[✘]{C.RS} {m}")
def info(m: str)  -> None: print(f"  {C.CY}[ℹ]{C.RS} {m}")
def aviso(m: str) -> None: print(f"  {C.Y}[!]{C.RS} {m}")
def dado(k, v)    -> None: print(f"    {C.Y}{k:<22}{C.RS} {v}")
def item(n, m)    -> None: print(f"  {C.CY}{n:02d}.{C.RS} {m}")

def barra_risco(score: int, cor: str = "") -> str:
    filled = int(score / 5)
    return f"{cor}{'█' * filled}{C.RS}{'░' * (20 - filled)} {C.BD}{score}/100{C.RS}"

def nivel_cor(score: int) -> tuple[str, str, str]:
    """Retorna (nível, cor, emoji)"""
    if score == 0:    return "SEGURO",       C.G,         "✅"
    if score < 20:    return "SUSPEITO",     C.G,         "🟡"
    if score < 40:    return "PROVÁVEL GOLPE", C.Y,       "⚠️ "
    if score < 65:    return "ALTO RISCO",   C.R,         "🔴"
    return               "GOLPE CONFIRMADO", C.R + C.BD,  "🚨"

def wrap(texto: str, largura: int = 66, prefixo: str = "    ") -> str:
    return textwrap.fill(texto, width=largura, subsequent_indent=prefixo)

def normalizar(texto: str) -> str:
    """Remove acentos e normaliza para lowercase."""
    return unicodedata.normalize("NFD", texto.lower()).encode("ascii", "ignore").decode()

# ═══════════════════════════════════════════════════════════════════════════
# MÓDULO A — CLASSIFICADOR DE TEXTOS / MENSAGENS
# ═══════════════════════════════════════════════════════════════════════════

class ResultadoAnalise:
    """Encapsula o resultado de qualquer análise."""
    def __init__(self, tipo: str, alvo: str):
        self.tipo          = tipo
        self.alvo          = alvo
        self.score         = 0
        self.nivel         = "SEGURO"
        self.cor           = C.G
        self.emoji         = "✅"
        self.golpes        : list[dict]  = []
        self.alertas       : list[str]   = []
        self.infos         : list[str]   = []
        self.evidencias    : list[tuple] = []   # (desc, peso)
        self.plano_acao    : list[str]   = []
        self.recursos      : list[dict]  = []
        self.ts            = datetime.datetime.now()

    def finalizar(self) -> None:
        self.score = min(self.score, 100)
        self.nivel, self.cor, self.emoji = nivel_cor(self.score)

    def to_dict(self) -> dict:
        return {
            "tipo":      self.tipo,
            "alvo":      self.alvo[:120],
            "score":     self.score,
            "nivel":     self.nivel,
            "golpes":    [g["id"] for g in self.golpes],
            "alertas":   self.alertas,
            "ts":        self.ts.isoformat(),
        }


def _checar_padroes_texto(texto: str, res: ResultadoAnalise) -> None:
    """Aplica todos os padrões da base de golpes ao texto normalizado."""
    texto_norm = normalizar(texto)

    for golpe in PADROES_GOLPE:
        hits = 0
        for pat in golpe["gatilhos"]:
            if re.search(pat, texto_norm, re.I):
                hits += 1
        if hits >= 1:
            peso = golpe["peso"] if hits == 1 else min(golpe["peso"] + (hits - 1) * 5, 55)
            res.golpes.append(golpe)
            res.evidencias.append((f"Padrão detectado: {golpe['nome']} ({hits} gatilho(s))", peso))
            res.score += peso

    # Urgência / pressão psicológica
    for pat, peso in PALAVRAS_URGENCIA:
        if re.search(pat, texto_norm, re.I):
            res.evidencias.append((f"Gatilho de urgência/pressão psicológica", peso))
            res.score += peso
            break

    # Ameaça / coerção
    for pat, peso in PALAVRAS_AMEACA:
        if re.search(pat, texto_norm, re.I):
            res.evidencias.append((f"Linguagem de coerção/ameaça detectada", peso))
            res.score += peso
            break

    # Ofertas impossíveis
    oferta_hits = 0
    for pat, peso in PALAVRAS_OFERTA:
        if re.search(pat, texto_norm, re.I):
            oferta_hits += peso
    if oferta_hits > 0:
        res.evidencias.append(("Oferta financeira suspeita / impossível", min(oferta_hits, 20)))
        res.score += min(oferta_hits, 20)

    # Solicitações suspeitas
    for pat, peso in PALAVRAS_SOLICITACAO:
        if re.search(pat, texto_norm, re.I):
            res.evidencias.append(("Solicitação de dado sensível ou ação de risco", peso))
            res.score += peso


def _checar_links_no_texto(texto: str, res: ResultadoAnalise) -> None:
    """Extrai e avalia links presentes no texto."""
    urls = re.findall(r"https?://[^\s\"'><]+", texto, re.I)
    urls += re.findall(r"(?<!\S)(www\.[^\s\"'><]+)", texto, re.I)
    for url in urls[:5]:
        r_link = analisar_link(url, silencioso=True)
        if r_link.score > 0:
            res.evidencias.append((f"Link suspeito detectado: {url[:60]}", min(r_link.score // 2, 25)))
            res.score += min(r_link.score // 2, 25)
            res.alertas.extend(r_link.alertas[:2])


def _checar_spoofing_institucional(texto: str, res: ResultadoAnalise) -> None:
    """Detecta se mensagem finge ser de banco ou órgão governamental."""
    texto_norm = normalizar(texto)
    for banco in BANCOS_BR:
        if banco in texto_norm:
            # Verifica se tem tom institucional suspeito
            if re.search(r"(informa|comunica|alerta|solicita|pede|exige|requer)", texto_norm):
                res.evidencias.append((f"Possível spoofing de instituição bancária: '{banco}'", 15))
                res.score += 15
                res.alertas.append(f"Mensagem cita '{banco}' com tom institucional — verifique pela central oficial.")
                break
    for orgao in ORGAOS_GOV:
        if orgao in texto_norm:
            if re.search(r"(informa|comunica|alerta|solicita|multa|taxa|cobr)", texto_norm):
                res.evidencias.append((f"Possível spoofing de órgão governamental: '{orgao}'", 18))
                res.score += 18
                res.alertas.append(f"Mensagem cita '{orgao}' com cobrança/solicitação — acesse apenas canais oficiais.")
                break


def _checar_valores_monetarios(texto: str, res: ResultadoAnalise) -> None:
    """Analisa valores monetários no texto."""
    valores = re.findall(r"R\$\s*([\d\.]+(?:,\d{2})?)", texto, re.I)
    for v_str in valores:
        try:
            v = float(v_str.replace(".", "").replace(",", "."))
            if v < 5:
                res.evidencias.append((f"Valor muito baixo (R${v_str}) — oferta irreal?", 5))
                res.score += 5
            elif v > 50000:
                res.evidencias.append((f"Valor elevado (R${v_str}) — risco alto de fraude", 8))
                res.score += 8
        except ValueError:
            pass


def _gerar_plano_acao(res: ResultadoAnalise) -> None:
    """Gera plano de ação personalizado baseado nos golpes detectados."""
    cats = {g["categoria"] for g in res.golpes}
    plano = []

    if res.score == 0:
        plano.append("Nenhum sinal de golpe detectado. Continue com cautela.")
        res.plano_acao = plano
        return

    plano.append("⛔ PARE — Não execute nenhuma ação solicitada na mensagem.")
    plano.append("📵 BLOQUEIE — Bloqueie o contato no WhatsApp/telefone.")

    if "Pix" in cats or "Bancário" in cats:
        plano.append("🏦 BANCO — Ligue para sua agência pelo número no verso do cartão.")
        plano.append("🔒 PIX — Se já transferiu, acione o MED no app do banco IMEDIATAMENTE.")
        res.recursos = [r for r in RECURSOS_LEGAIS if r["tipo"] in ("pix", "bancário", "todos")]

    if "WhatsApp" in cats:
        plano.append("📱 WHATSAPP — Ligue para o número original da pessoa (não pelo WhatsApp).")
        plano.append("🔐 CONTA — Ative verificação em duas etapas no WhatsApp: Config → Conta → Verificação em duas etapas.")

    if "Phishing" in cats or "Tecnologia" in cats:
        plano.append("🔗 LINK — Não clique em nenhum link da mensagem.")
        plano.append("🦠 VÍRUS — Se clicou, escaneie o dispositivo com antivírus e mude todas as senhas.")

    if "Investimento" in cats or "Financeiro" in cats:
        plano.append("💰 INVESTIMENTO — Pesquise a empresa na CVM (cvmweb.cvm.gov.br/SWB/Sistemas/SCW/CPublica/CiaAb/FormBuscaCiaAb.aspx).")
        res.recursos = [r for r in RECURSOS_LEGAIS if r["tipo"] in ("investimento", "todos")]

    if "Engenharia Social" in cats or "Romance" in cats:
        plano.append("👥 IDENTIDADE — Confirme a identidade da pessoa por videochamada ou ligação direta.")

    if "Governo" in cats:
        plano.append("🏛️  GOV — Acesse o serviço apenas pelo portal gov.br ou pelo site oficial do órgão.")

    plano.append("📋 B.O. — Registre boletim de ocorrência (presencial ou online) mesmo que não haja prejuízo.")
    plano.append("📢 ALERTE — Avise familiares e amigos sobre este golpe para que não caiam.")

    if not res.recursos:
        res.recursos = [r for r in RECURSOS_LEGAIS if r["tipo"] == "todos"]

    res.plano_acao = plano


def analisar_mensagem(texto: str) -> ResultadoAnalise:
    """Analisa texto completo de uma mensagem suspeita."""
    res = ResultadoAnalise("mensagem", texto[:80] + "..." if len(texto) > 80 else texto)

    if len(texto.strip()) < 10:
        res.alertas.append("Texto muito curto para análise significativa.")
        res.finalizar()
        return res

    _checar_padroes_texto(texto, res)
    _checar_links_no_texto(texto, res)
    _checar_spoofing_institucional(texto, res)
    _checar_valores_monetarios(texto, res)

    # Análise de características linguísticas
    erros_ortograficos = len(re.findall(r"\b(vc|vcs|pq|oq|naum|nao|c|d|td|tdos|tbm|blz|flw)\b", texto.lower()))
    if erros_ortograficos >= 3:
        res.infos.append(f"Linguagem informal/erros ortográficos detectados ({erros_ortograficos}) — pode ser automatizado.")

    # CAPS LOCK excessivo
    maiusculas = sum(1 for c in texto if c.isupper())
    if len(texto) > 20 and maiusculas / len(texto) > 0.4:
        res.evidencias.append(("Uso excessivo de CAPS LOCK — técnica de pressão", 6))
        res.score += 6

    # Quantidade de pontos de exclamação
    exclamacoes = texto.count("!")
    if exclamacoes >= 3:
        res.evidencias.append((f"Excesso de exclamações ({exclamacoes}) — alarme artificial", 5))
        res.score += 5

    _gerar_plano_acao(res)
    res.finalizar()
    return res


# ═══════════════════════════════════════════════════════════════════════════
# MÓDULO B — VERIFICADOR DE CHAVE PIX
# ═══════════════════════════════════════════════════════════════════════════

def _validar_cpf(cpf: str) -> bool:
    n = re.sub(r"\D", "", cpf)
    if len(n) != 11 or n == n[0] * 11: return False
    for i in range(9, 11):
        s = sum(int(n[j]) * ((i + 1) - j) for j in range(i))
        if int(n[i]) != (s * 10 % 11) % 10: return False
    return True

def _validar_cnpj(cnpj: str) -> bool:
    n = re.sub(r"\D", "", cnpj)
    if len(n) != 14 or n == n[0] * 14: return False
    pesos1 = [5,4,3,2,9,8,7,6,5,4,3,2]
    pesos2 = [6,5,4,3,2,9,8,7,6,5,4,3,2]
    for d_idx, pesos in enumerate([pesos1, pesos2], 12):
        s = sum(int(n[i]) * pesos[i] for i in range(d_idx))
        dig = 11 - (s % 11)
        if int(n[d_idx]) != (0 if dig >= 10 else dig): return False
    return True

def _identificar_tipo_pix(chave: str) -> tuple[str, bool]:
    """Retorna (tipo, é_valida)."""
    chave_limpa = re.sub(r"[\s\-\.\(\)/]", "", chave)
    # EVP (UUID)
    if re.match(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", chave, re.I):
        return "EVP (Chave Aleatória)", True
    # E-mail
    if re.match(r"^[\w\.\+\-]+@[\w\-]+\.[a-z]{2,}$", chave, re.I):
        return "E-mail", True
    # CPF
    if re.match(r"^\d{11}$", chave_limpa):
        return "CPF", _validar_cpf(chave_limpa)
    # CNPJ
    if re.match(r"^\d{14}$", chave_limpa):
        return "CNPJ", _validar_cnpj(chave_limpa)
    # Telefone
    tel = re.sub(r"\D", "", chave)
    if re.match(r"^(\+?55)?\d{10,11}$", tel):
        return "Telefone", True
    return "Desconhecido", False


def analisar_chave_pix(chave: str, valor: Optional[float] = None,
                       nome_destinatario: Optional[str] = None) -> ResultadoAnalise:
    res = ResultadoAnalise("chave_pix", chave)
    chave = chave.strip()

    tipo, valida = _identificar_tipo_pix(chave)
    res.infos.append(f"Tipo de chave: {tipo}")

    if not valida:
        res.alertas.append(f"Chave inválida para o tipo '{tipo}' — dígitos verificadores não batem.")
        res.evidencias.append(("Chave Pix com formato ou dígito inválido", 40))
        res.score += 40
    else:
        res.infos.append(f"Formato validado ✔")

    # Chave CPF — análise adicional
    if tipo == "CPF":
        cpf_limpo = re.sub(r"\D", "", chave)
        regioes = {0:"RS",1:"DF/GO/MS/MT/TO",2:"AM/PA/RR/AP/RO/AC",
                   3:"CE/MA/PI",4:"PB/PE/AL/RN",5:"BA/SE",
                   6:"MG",7:"RJ/ES",8:"SP",9:"PR/SC"}
        res.infos.append(f"Região de emissão estimada: {regioes.get(int(cpf_limpo[8]),'?')}")
        res.infos.append("CPF como chave Pix significa transação para pessoa física.")

    # Chave CNPJ — empresa
    if tipo == "CNPJ":
        res.infos.append("CNPJ como chave Pix indica transação para pessoa jurídica (empresa).")
        res.infos.append("Verifique a empresa em: receita.fazenda.gov.br/Aplicacoes/ATCTA/CPFCNPJ")

    # Chave EVP — aleatória
    if tipo == "EVP (Chave Aleatória)":
        res.infos.append("Chave aleatória — mais difícil rastrear o titular. Verifique o nome antes de confirmar.")
        res.evidencias.append(("Chave aleatória (EVP) — rastreabilidade reduzida", 5))
        res.score += 5

    # Nome do destinatário suspeito
    if nome_destinatario:
        nome_norm = normalizar(nome_destinatario)
        for banco in BANCOS_BR:
            if banco in nome_norm:
                res.alertas.append(f"Nome do destinatário contém '{banco}' — bancos não recebem Pix diretamente de clientes para reembolso.")
                res.evidencias.append(("Nome de banco como destinatário — golpe típico", 35))
                res.score += 35
                break
        for orgao in ORGAOS_GOV:
            if orgao in nome_norm:
                res.alertas.append(f"Destinatário com nome de órgão governamental ('{orgao}') — verifique com muito cuidado.")
                res.evidencias.append(("Órgão governamental como destinatário", 20))
                res.score += 20
                break

    # Valor suspeito
    if valor is not None:
        if valor < 1.0:
            res.evidencias.append(("Valor muito baixo (teste de conta ativa?)", 8))
            res.score += 8
            res.infos.append("Valores abaixo de R$ 1,00 são usados para testar se a chave é válida.")
        elif valor > 10000:
            res.evidencias.append((f"Valor elevado R${valor:,.2f} — requer verificação extra", 10))
            res.score += 10
            res.alertas.append(f"Valor R${valor:,.2f} — confirme a identidade do destinatário por outro canal.")

    # Checagem DNS para chave e-mail
    if tipo == "E-mail" and HAS_DNS:
        dominio = chave.split("@")[1].lower()
        try:
            dns.resolver.resolve(dominio, "MX")
            res.infos.append(f"Domínio do e-mail '{dominio}' possui registros MX ✔")
        except Exception:
            res.alertas.append(f"Domínio '{dominio}' não possui servidor de e-mail ativo.")
            res.evidencias.append(("Domínio de e-mail sem MX (possível chave falsa)", 20))
            res.score += 20

    _gerar_plano_acao(res)
    res.finalizar()
    return res


# ═══════════════════════════════════════════════════════════════════════════
# MÓDULO C — SCANNER DE LINKS / URLS
# ═══════════════════════════════════════════════════════════════════════════

PALAVRAS_PHISHING_URL: list[str] = [
    "login","conta","banco","seguranca","verificar","atualizar","confirmar",
    "bradesco","itau","caixa","santander","nubank","inter","bb","pagbank",
    "paypal","amazon","mercadolivre","shopee","ifood","receita","inss",
    "cpf","cnpj","senha","acesso","bloqueio","cancelamento","regularizar",
    "suporte","atendimento","central","cliente","usuario","premio","ganhou",
    "pix","boleto","cobranca","fatura","debito","credito","cartao",
]


def analisar_link(url: str, silencioso: bool = False) -> ResultadoAnalise:
    res = ResultadoAnalise("link", url[:100])
    url_orig = url.strip()

    if not re.match(r"https?://", url_orig, re.I):
        url_teste = "http://" + url_orig
    else:
        url_teste = url_orig

    try:
        p = urllib.parse.urlparse(url_teste)
    except Exception:
        res.alertas.append("URL malformada — não foi possível analisar.")
        res.score += 20
        res.finalizar()
        return res

    dominio = p.netloc.lower().split(":")[0]
    path    = p.path.lower()
    query   = p.query.lower()
    res.infos.append(f"Domínio: {dominio}")

    # ── Sem HTTPS ────────────────────────────────────────────────────────
    if p.scheme == "http":
        res.evidencias.append(("Sem HTTPS — conexão insegura", 15))
        res.score += 15
        res.alertas.append("Sem HTTPS: dados trafegam em texto claro. Sites bancários sempre usam HTTPS.")

    # ── IP direto ────────────────────────────────────────────────────────
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", dominio):
        res.evidencias.append(("URL com IP direto — phishing típico", 40))
        res.score += 40
        res.alertas.append("IP direto em URL bancária é sempre fraude — sites legítimos usam domínios.")

    # ── Punycode / homógrafo ─────────────────────────────────────────────
    if "xn--" in dominio:
        res.evidencias.append(("Punycode detectado — possível ataque homógrafo", 35))
        res.score += 35
        res.alertas.append("Domínio usa caracteres de outros idiomas para imitar domínio real.")

    # ── Subdomínios excessivos ───────────────────────────────────────────
    partes    = dominio.split(".")
    tld       = ".".join(partes[-2:]) if len(partes) >= 2 else dominio
    dom_base  = partes[-2] if len(partes) >= 2 else dominio
    subdominios = partes[:-2]
    if len(subdominios) >= 3:
        res.evidencias.append((f"Excesso de subdomínios ({len(subdominios)}) — typosquatting", 25))
        res.score += 25
        res.alertas.append("Muitos subdomínios escondem o domínio real (ex: bradesco.seguranca.xyz → dono é .xyz).")

    # ── TLD suspeito ─────────────────────────────────────────────────────
    for ts in TLDS_RISCO:
        if dominio.endswith(ts):
            res.evidencias.append((f"TLD de alto risco: '{ts}'", 20))
            res.score += 20
            res.alertas.append(f"TLD '{ts}' é amplamente usado em campanhas de phishing e spam.")
            break

    # ── Palavras de phishing no domínio ──────────────────────────────────
    dom_clean = dominio.replace("-", "").replace(".", "")
    matches = [w for w in PALAVRAS_PHISHING_URL if w in dom_clean]
    if matches:
        peso = min(len(matches) * 10, 35)
        res.evidencias.append((f"Palavras de phishing no domínio: {', '.join(matches[:4])}", peso))
        res.score += peso
        if len(matches) >= 2:
            res.alertas.append(f"Domínio combina múltiplas palavras-chave de phishing: {', '.join(matches[:4])}.")

    # ── Verificação contra domínios legítimos de bancos ──────────────────
    for banco, dominios_ok in DOMINIOS_LEGITIMOS_BANCOS.items():
        if banco in dom_clean and dominio not in dominios_ok:
            res.evidencias.append((f"Domínio imita '{banco}' mas não é o oficial", 40))
            res.score += 40
            res.alertas.append(f"Domínio cita '{banco}' mas não é o site oficial. Domínios legítimos: {', '.join(dominios_ok)}.")
            break

    # ── URL muito longa ──────────────────────────────────────────────────
    if len(url_orig) > 150:
        res.evidencias.append(("URL excessivamente longa — oculta destino real", 10))
        res.score += 10

    # ── Parâmetros de redirecionamento ────────────────────────────────────
    q_lower = query.lower()
    redirect_params = ["redirect", "url=", "goto=", "next=", "return=", "dest=", "redir="]
    for rp in redirect_params:
        if rp in q_lower:
            res.evidencias.append(("Parâmetro de open redirect detectado", 15))
            res.score += 15
            res.alertas.append("Open redirect: URL pode redirecionar para site malicioso após clique.")
            break

    # ── Palavras de phishing no path ──────────────────────────────────────
    path_matches = [w for w in PALAVRAS_PHISHING_URL if w in path]
    if len(path_matches) >= 2:
        res.evidencias.append((f"Path contém palavras suspeitas: {', '.join(path_matches[:3])}", 10))
        res.score += 10

    # ── Hifens excessivos no domínio base ────────────────────────────────
    if dom_base.count("-") >= 3:
        res.evidencias.append((f"Excesso de hífens ({dom_base.count('-')}) no domínio base", 12))
        res.score += 12

    # ── DNS check ─────────────────────────────────────────────────────────
    if HAS_DNS and not re.match(r"^\d{1,3}(\.\d{1,3}){3}$", dominio):
        try:
            ips = dns.resolver.resolve(dominio, "A")
            res.infos.append(f"DNS resolve → {str(list(ips)[0])}")
        except dns.resolver.NXDOMAIN:
            res.evidencias.append(("Domínio não existe (NXDOMAIN) — URL falsa", 45))
            res.score += 45
            res.alertas.append("Domínio não existe — URL completamente falsa.")
        except Exception:
            res.infos.append("DNS: não foi possível resolver (timeout ou erro).")

    if not silencioso:
        _gerar_plano_acao(res)
    res.finalizar()
    return res


# ═══════════════════════════════════════════════════════════════════════════
# MÓDULO D — VALIDADOR DE BOLETO BANCÁRIO
# ═══════════════════════════════════════════════════════════════════════════

def _calcular_modulo10(numero: str) -> int:
    soma = 0
    for i, d in enumerate(reversed(numero)):
        n = int(d) * (2 if i % 2 == 0 else 1)
        soma += n // 10 + n % 10
    return (10 - soma % 10) % 10

def _calcular_modulo11_boleto(numero: str) -> int:
    pesos = list(range(2, 10)) * 10
    soma  = sum(int(d) * p for d, p in zip(reversed(numero), pesos))
    resto = soma % 11
    if resto in (0, 1): return 1
    return 11 - resto

def analisar_boleto(linha_digitavel: str) -> ResultadoAnalise:
    res   = ResultadoAnalise("boleto", linha_digitavel[:60])
    linha = re.sub(r"[\s\.\-]", "", linha_digitavel.strip())

    # Comprimento
    if len(linha) not in (47, 48):
        res.alertas.append(f"Linha digitável inválida — esperado 47 ou 48 dígitos, recebido {len(linha)}.")
        res.evidencias.append(("Comprimento da linha digitável incorreto", 50))
        res.score += 50
        res.finalizar()
        return res

    # Somente dígitos
    if not linha.isdigit():
        res.alertas.append("Linha digitável contém caracteres não numéricos.")
        res.evidencias.append(("Caracteres inválidos na linha digitável", 30))
        res.score += 30
        res.finalizar()
        return res

    # Identificação do banco
    prefixo = linha[:3]
    banco = PREFIXOS_BOLETO.get(prefixo)
    if banco:
        res.infos.append(f"Banco cedente identificado: {C.BD}{banco}{C.RS} (código {prefixo})")
    else:
        res.alertas.append(f"Código de banco desconhecido: {prefixo} — verifique se o cedente está correto.")
        res.evidencias.append(("Código de banco não mapeado", 15))
        res.score += 15

    # Moeda (posição 3)
    if linha[3] != "9":
        res.alertas.append(f"Código de moeda inválido: '{linha[3]}' (esperado '9' para Real).")
        res.evidencias.append(("Código de moeda inválido", 20))
        res.score += 20
    else:
        res.infos.append("Moeda: Real (BRL) ✔")

    # Extração de campos (boleto bancário padrão 47 dígitos)
    if len(linha) == 47:
        campo1 = linha[0:9]
        campo2 = linha[9:20]
        campo3 = linha[20:31]
        fator  = linha[31:35]
        valor  = linha[35:47]

        # Validação Módulo 10 campos
        for nome, campo in [("Campo 1", campo1), ("Campo 2", campo2), ("Campo 3", campo3)]:
            d_calculado = _calcular_modulo10(campo[:-1])
            d_boleto    = int(campo[-1])
            if d_calculado != d_boleto:
                res.alertas.append(f"{nome}: dígito verificador incorreto ({d_boleto} ≠ {d_calculado}) — boleto pode ser falso!")
                res.evidencias.append((f"{nome} com dígito verificador inválido", 40))
                res.score += 40

        # Valor
        if valor.isdigit():
            v = int(valor) / 100
            res.infos.append(f"Valor do boleto: R$ {v:,.2f}")
            if v == 0:
                res.infos.append("Boleto sem valor (título em aberto — valor será preenchido pelo cedente).")
            elif v > 100000:
                res.evidencias.append((f"Valor muito elevado: R${v:,.2f}", 8))
                res.score += 8
                res.alertas.append(f"Boleto de alto valor (R${v:,.2f}) — confirme o cedente com muito cuidado.")

        # Fator de vencimento (fator 1000 = 03/07/2000)
        if fator.isdigit() and int(fator) > 1000:
            data_base = datetime.date(2000, 7, 3)
            vencimento = data_base + datetime.timedelta(days=int(fator) - 1000)
            res.infos.append(f"Vencimento: {vencimento.strftime('%d/%m/%Y')}")
            hoje = datetime.date.today()
            if vencimento < hoje:
                dias_venc = (hoje - vencimento).days
                res.alertas.append(f"Boleto vencido há {dias_venc} dia(s) — não é possível pagar normalmente.")
                res.evidencias.append(("Boleto vencido", 10))
                res.score += 10
            elif (vencimento - hoje).days > 365:
                res.alertas.append(f"Boleto com vencimento muito distante ({vencimento}) — verifique autenticidade.")
                res.evidencias.append(("Vencimento suspeito (>1 ano)", 10))
                res.score += 10
        elif fator == "0000":
            res.infos.append("Fator de vencimento zerado — boleto sem vencimento definido.")

    # Resumo de autenticidade
    if res.score == 0:
        res.infos.append("Nenhuma inconsistência detectada nos dígitos verificadores ✔")
        res.infos.append("Sempre confirme o CNPJ do cedente com quem emitiu o boleto.")
    else:
        res.alertas.append("ATENÇÃO: inconsistências detectadas — NÃO PAGUE antes de confirmar com o credor pelo canal oficial.")

    res.plano_acao = [
        "📞 Ligue para o credor no número oficial (não no boleto) para confirmar a autenticidade.",
        "🔢 Compare os 3 primeiros dígitos da linha digitável com o código do banco do credor.",
        "🏦 Acesse o internetbanking do seu banco e confirme o nome do beneficiário antes de pagar.",
        "🚫 Nunca pague boleto recebido por link — acesse sempre o site original da empresa.",
        "📋 Registre B.O. se suspeitar de boleto falso, mesmo sem efetuar pagamento.",
    ]
    res.recursos = [r for r in RECURSOS_LEGAIS if r["tipo"] in ("bancário", "todos")]
    res.finalizar()
    return res


# ═══════════════════════════════════════════════════════════════════════════
# MÓDULO E — DETECTOR DE WHATSAPP CLONADO
# ═══════════════════════════════════════════════════════════════════════════

SINAIS_WPP_CLONADO: list[tuple[str, int, str]] = [
    (r"(mudei?\s+de\s+número|novo\s+número|número\s+novo|salvou?\s+o\s+novo)",
     20, "Aviso de 'novo número' — clonagem típica começa assim."),
    (r"(não\s+(ligo|ligue|ligu[ae])\s+(pra\s+mim|para\s+mim))",
     25, "Pede que não ligue — evita que você descubra que é golpe."),
    (r"(por\s+(favor|gentileza)\s+)?não\s+(coment[ae]|fal[ae]|cont[ae])\s+(com|para|pra)\s+(o\s+)?(pai|mãe|família|ninguém)",
     35, "Pede segredo — isolamento social clássico de golpistas."),
    (r"(precis[oa]\s+de\s+|me\s+empresta?\s+|me\s+manda?\s+)\s*(R\$|dinheiro|um\s+valor|uma\s+grana)",
     40, "Solicitação de dinheiro — objetivo final do golpe."),
    (r"(emergência|urgente|apuro|problema\s+sério|situação\s+difícil)",
     15, "Criação de senso de urgência — pressão psicológica."),
    (r"devolv[oa]\s+(amanhã|logo|depois|rapidinho|semana\s+que\s+vem)",
     18, "Promessa de devolução — reduz a resistência da vítima."),
    (r"(pix|transferência|manda\s+pelo\s+pix|transfere\s+pra\s+mim)",
     22, "Método de pagamento especificado — fase final do golpe."),
    (r"(estou\s+sem\s+crédito|celular\s+quebrou|trocou?\s+o\s+chip|chip\s+novo)",
     18, "Justificativa para número diferente — explicação de cobertura."),
    (r"(meu\s+whatsapp\s+(foi\s+hackeado|clonaram|roubaram)|roubaram?\s+meu\s+whatsapp)",
     20, "Relato de clonagem — pode ser verdadeiro ou mais uma manobra."),
    (r"(conta\s+bloqueada|sem\s+acesso\s+ao\s+banco|meu\s+cartão\s+(foi\s+)?(bloqueado|cancelado))",
     15, "Justificativa financeira — explica por que precisa de ajuda."),
]

def analisar_whatsapp_clonado(mensagem: str) -> ResultadoAnalise:
    res = ResultadoAnalise("whatsapp_clonado", mensagem[:80])
    texto_norm = normalizar(mensagem)

    for pat, peso, explicacao in SINAIS_WPP_CLONADO:
        if re.search(pat, texto_norm, re.I):
            res.evidencias.append((explicacao, peso))
            res.score += peso
            res.alertas.append(explicacao)

    # Análise adicional do padrão geral
    _checar_padroes_texto(mensagem, res)
    _checar_valores_monetarios(mensagem, res)

    # Plano específico para WhatsApp clonado
    res.plano_acao = [
        "📞 LIGUE agora para o número original da pessoa (não responda no WhatsApp).",
        "🔴 NÃO envie nenhum Pix ou transferência antes de confirmar a identidade por voz.",
        "👥 AVISE a família que o WhatsApp pode ter sido clonado — proteja outros membros.",
        "🔐 PEÇA ao familiar para ativar verificação em 2 etapas: Configurações → Conta → Verificação.",
        "📵 BLOQUEIE o número suspeito e denuncie para o WhatsApp.",
        "📋 REGISTRE B.O. — golpe de WhatsApp clonado é crime (Lei 12.737/2012).",
        "🏦 Se já enviou dinheiro: acione o MED no app do banco IMEDIATAMENTE.",
    ]
    res.recursos = [r for r in RECURSOS_LEGAIS if r["tipo"] in ("pix", "todos")]
    res.finalizar()
    return res


# ═══════════════════════════════════════════════════════════════════════════
# MÓDULO F — CLASSIFICADOR HEURÍSTICO DE PHISHING (ML leve)
# ═══════════════════════════════════════════════════════════════════════════

class ClassificadorPhishing:
    """
    Classificador leve baseado em features binárias e pesos calibrados.
    Opera sem bibliotecas de ML — implementa regressão logística simplificada
    com features extraídas por heurísticas linguísticas.
    """

    FEATURES: list[tuple[str, int]] = [
        # Urgência temporal
        (r"\b(urgente|imediato|agora|imediatamente|hoje\s+mesmo|nesta\s+hora)\b",      8),
        (r"\b(expira?|vence?|encerra?)\s+(em\s+)?\d+\s*(hora|minuto|segundo)",         10),
        (r"\bprazo\s+(final|limite|máximo)\b",                                          7),
        # Ameaças
        (r"\b(bloqueado?|suspens[ao]|cancelado?|encerrado?)\b",                         6),
        (r"\b(processo|ação\s+judicial|mandado|penhora|negativado)\b",                  9),
        (r"\b(fraude|irregular|ilegal|suspeito)\s+(detectad|identificad|encontrad)\b",  8),
        # Solicitações de dados
        (r"\b(senha|token|código\s+de\s+(verificação|segurança))\b",                   12),
        (r"\b(dados?\s+do\s+cartão|número\s+do\s+cartão|cvv|cvc)\b",                  15),
        (r"\b(clique|acesse|entre\s+em)\s+(aqui|no\s+link|no\s+site)\b",               8),
        (r"\b(atualiz|recadastr|confirmar?|validar?)\s+(seus?\s+)?dados\b",             9),
        # Promessas impossíveis
        (r"\b(ganhou?|prêmio|sorteado?|selecionado?|contemplado?)\b",                   7),
        (r"\bR\$\s*[\d\.]+\s+(grátis|gratuito|sem\s+custo)\b",                         8),
        (r"\b\d{2,3}%\s+(de\s+)?retorno\s+(diário|garantido)\b",                      14),
        (r"\b(dobre?|triplique?|multiplique?)\s+(seu|o)\s+(dinheiro|capital)\b",       12),
        # Identificadores de phishing técnico
        (r"https?://[^\s]{0,20}\.(xyz|top|online|site|click|gq|ml|cf|ga|tk)",         14),
        (r"http://(?!localhost)",                                                        6),
        (r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",                                      10),
        (r"xn--[a-z0-9\-]+",                                                           12),
        # Engenharia social
        (r"\b(segredo|confidencial|não\s+comente|não\s+fale\s+com\s+ninguém)\b",      10),
        (r"\b(emergência|apuros?|dificuldade|desespero)\b",                              6),
        (r"\b(emprest(e|ar)|me\s+ajuda?|preciso\s+de\s+(dinheiro|grana))\b",           8),
        (r"\b(motoboy|buscar?\s+o\s+cartão|entregar?\s+o\s+cartão)\b",                18),
        # Instituições falsas
        (r"\b(banco\s+central|bacen|receita\s+federal|policia\s+federal)\s+(informa|liga|solicit)\b", 15),
        (r"\b(inss|previdência)\s+(cobra|solicita|informa|requer)\s+(taxa|atualiz|recadastr)\b", 14),
        # Pressão psicológica
        (r"(!!|!!!|\?\?)",                                                               4),
        (r"[A-Z]{4,}",                                                                   3),
        (r"\bATENÇÃO\b",                                                                 5),
    ]

    def __init__(self) -> None:
        self._threshold_confirmado = 55
        self._threshold_alto       = 35
        self._threshold_provavel   = 18

    def classificar(self, texto: str) -> dict:
        texto_norm = normalizar(texto)
        features_ativas: list[tuple[str, int]] = []
        score_bruto = 0

        for pat, peso in self.FEATURES:
            if re.search(pat, texto_norm, re.I):
                features_ativas.append((pat[:50], peso))
                score_bruto += peso

        # Normalizar score para 0–100
        max_score   = sum(p for _, p in self.FEATURES)
        score_norm  = min(int((score_bruto / max_score) * 100), 100)

        # Bônus por combinação de categorias suspeitas
        bonus = 0
        cats_detectadas = set()
        if any(re.search(p, texto_norm, re.I) for p, _ in self.FEATURES[0:3]):   cats_detectadas.add("urgencia")
        if any(re.search(p, texto_norm, re.I) for p, _ in self.FEATURES[3:6]):   cats_detectadas.add("ameaca")
        if any(re.search(p, texto_norm, re.I) for p, _ in self.FEATURES[6:10]):  cats_detectadas.add("dados")
        if any(re.search(p, texto_norm, re.I) for p, _ in self.FEATURES[10:14]): cats_detectadas.add("promessa")
        if any(re.search(p, texto_norm, re.I) for p, _ in self.FEATURES[19:22]): cats_detectadas.add("social")

        if len(cats_detectadas) >= 3:
            bonus = 15
        elif len(cats_detectadas) == 2:
            bonus = 8

        score_final = min(score_norm + bonus, 100)

        if score_final >= self._threshold_confirmado:
            classificacao = "PHISHING CONFIRMADO"
            confianca     = min(70 + (score_final - self._threshold_confirmado) * 0.5, 99)
        elif score_final >= self._threshold_alto:
            classificacao = "ALTO RISCO DE PHISHING"
            confianca     = 55 + (score_final - self._threshold_alto) * 0.6
        elif score_final >= self._threshold_provavel:
            classificacao = "SUSPEITO"
            confianca     = 35 + (score_final - self._threshold_provavel) * 1.0
        else:
            classificacao = "BAIXO RISCO"
            confianca     = max(5.0, float(score_final))

        return {
            "classificacao":    classificacao,
            "score":            score_final,
            "confianca":        round(confianca, 1),
            "features_ativas":  features_ativas,
            "categorias":       list(cats_detectadas),
            "bonus_combinacao": bonus,
        }

_CLASSIFICADOR = ClassificadorPhishing()


def classificar_phishing(texto: str) -> ResultadoAnalise:
    res     = ResultadoAnalise("phishing_ml", texto[:80])
    saida   = _CLASSIFICADOR.classificar(texto)
    res.score = saida["score"]
    res.infos.append(f"Classificação: {C.BD}{saida['classificacao']}{C.RS}")
    res.infos.append(f"Confiança:     {saida['confianca']}%")
    res.infos.append(f"Score bruto:   {saida['score']}/100")
    if saida["categorias"]:
        res.infos.append(f"Categorias:    {', '.join(saida['categorias'])}")
    if saida["bonus_combinacao"]:
        res.infos.append(f"Bônus combinação de categorias: +{saida['bonus_combinacao']}pt")
    for pat, peso in saida["features_ativas"]:
        res.evidencias.append((f"Feature: {pat[:55]}", peso))
    _gerar_plano_acao(res)
    res.finalizar()
    return res


# ═══════════════════════════════════════════════════════════════════════════
# MÓDULO G — HISTÓRICO DE ANÁLISES
# ═══════════════════════════════════════════════════════════════════════════

def salvar_historico(res: ResultadoAnalise) -> None:
    try:
        historico: list[dict] = []
        if LOG_FILE.exists():
            historico = json.loads(LOG_FILE.read_text(encoding="utf-8"))
        historico.append(res.to_dict())
        historico = historico[-500:]  # mantém últimas 500 entradas
        LOG_FILE.write_text(json.dumps(historico, ensure_ascii=False, indent=2), encoding="utf-8")
    except Exception as e:
        logging.warning(f"Erro ao salvar histórico: {e}")

def exibir_historico(n: int = 10) -> None:
    titulo("Histórico de Análises")
    if not LOG_FILE.exists():
        info("Nenhuma análise registrada ainda.")
        return
    try:
        historico = json.loads(LOG_FILE.read_text(encoding="utf-8"))
        if not historico:
            info("Histórico vazio.")
            return
        recentes = historico[-n:][::-1]
        for i, r in enumerate(recentes, 1):
            ts   = r.get("ts", "?")[:16].replace("T", " ")
            tipo = r.get("tipo", "?").upper()
            alvo = r.get("alvo", "?")[:50]
            sc   = r.get("score", 0)
            nv   = r.get("nivel", "?")
            _, cor, em = nivel_cor(sc)
            print(f"  {C.CY}{i:02d}.{C.RS} [{ts}] {C.BD}{tipo:<18}{C.RS} {em} {cor}{nv:<20}{C.RS} Alvo: {alvo}")
        sep()
        info(f"Total de análises: {len(historico)} | Exibindo as {min(n, len(historico))} mais recentes.")
    except Exception as e:
        erro(f"Erro ao ler histórico: {e}")


# ═══════════════════════════════════════════════════════════════════════════
# MÓDULO H — RELATÓRIO COMPLETO
# ═══════════════════════════════════════════════════════════════════════════

def gerar_relatorio_txt(res: ResultadoAnalise) -> Path:
    ts   = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    nome = re.sub(r"[^\w]", "_", res.alvo)[:30]
    arq  = OUT_DIR / f"golpescanner_{res.tipo}_{nome}_{ts}.txt"
    lin  = "=" * 72

    linhas: list[str] = [
        lin,
        "  GOLPESCANNER BR v1.0 — RELATÓRIO DE ANÁLISE",
        f"  Data/hora: {res.ts.strftime('%d/%m/%Y %H:%M:%S')}",
        f"  Tipo de análise: {res.tipo.upper()}",
        f"  Alvo: {res.alvo}",
        f"  {AUTHOR} | {GITHUB} | {DISCORD}",
        lin, "",
        f"  RESULTADO: {res.nivel}",
        f"  Score de risco: {res.score}/100",
        lin, "",
    ]

    if res.golpes:
        linhas += ["  GOLPES DETECTADOS", lin]
        for g in res.golpes:
            linhas += [
                f"  [{g['id']}] {g['nome']} ({g['categoria']})",
                f"  Descrição: {g['descricao']}",
                f"  Alerta: {g['alerta']}", "",
            ]

    if res.evidencias:
        linhas += [lin, "  EVIDÊNCIAS", lin]
        for desc, peso in res.evidencias:
            linhas.append(f"  +{peso:3d}pt  {desc}")
        linhas.append("")

    if res.alertas:
        linhas += [lin, "  ALERTAS ESPECÍFICOS", lin]
        for a in res.alertas:
            linhas.append(f"  ⚠  {a}")
        linhas.append("")

    if res.plano_acao:
        linhas += [lin, "  PLANO DE AÇÃO", lin]
        for i, p in enumerate(res.plano_acao, 1):
            linhas.append(f"  {i:02d}. {p}")
        linhas.append("")

    if res.recursos:
        linhas += [lin, "  RECURSOS LEGAIS E CANAIS OFICIAIS", lin]
        for r in res.recursos:
            linhas += [f"  [{r['titulo']}]", f"  URL: {r['url']}", f"  {r['desc']}", ""]

    linhas += [
        lin,
        "  AVISO LEGAL",
        lin,
        "  Esta ferramenta é apenas para fins educacionais e de proteção do usuário.",
        "  Não utilize para fins ilícitos. Consulte sempre canais oficiais.",
        "  Direitos reservados — @kalyel473 | MIT License",
        lin,
    ]

    arq.write_text("\n".join(linhas), encoding="utf-8")
    return arq


# ═══════════════════════════════════════════════════════════════════════════
# MÓDULO I — MODO BATCH (arquivo CSV / TXT)
# ═══════════════════════════════════════════════════════════════════════════

def processar_batch(arquivo: str) -> None:
    titulo(f"Modo Batch — {arquivo}")
    caminho = Path(arquivo)
    if not caminho.exists():
        erro(f"Arquivo não encontrado: {arquivo}")
        return

    linhas: list[str] = []
    if caminho.suffix.lower() == ".csv":
        with open(caminho, newline="", encoding="utf-8", errors="ignore") as f:
            reader = csv.reader(f)
            for row in reader:
                if row: linhas.append(row[0].strip())
    else:
        linhas = [l.strip() for l in caminho.read_text(encoding="utf-8", errors="ignore").splitlines() if l.strip()]

    info(f"Total de entradas: {len(linhas)}")
    resultados: list[dict] = []

    for i, linha in enumerate(linhas, 1):
        if not linha or linha.startswith("#"):
            continue
        # Auto-detectar tipo
        if linha.startswith(("http://", "https://", "www.")):
            res = analisar_link(linha)
        elif "@" in linha and "." in linha.split("@")[-1]:
            pix_res = analisar_chave_pix(linha)
            if pix_res.score > 20:
                res = pix_res
            else:
                res = analisar_link(linha)
        elif re.match(r"^\d{47,48}$", re.sub(r"[\s\.\-]", "", linha)):
            res = analisar_boleto(linha)
        else:
            res = analisar_mensagem(linha)

        salvar_historico(res)
        resultados.append(res.to_dict())
        _, cor, em = nivel_cor(res.score)
        print(f"  {i:04d}. {em} {cor}{res.nivel:<20}{C.RS} {res.score:3d}/100  {res.alvo[:55]}")

    # Salvar resultados em JSON
    ts  = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    arq = OUT_DIR / f"batch_resultado_{ts}.json"
    arq.write_text(json.dumps(resultados, ensure_ascii=False, indent=2), encoding="utf-8")
    sep()
    ok(f"Análise batch concluída. Resultados em: {C.BD}{arq}{C.RS}")

    # Estatísticas
    scores = [r["score"] for r in resultados]
    if scores:
        criticos = sum(1 for s in scores if s >= 65)
        altos    = sum(1 for s in scores if 40 <= s < 65)
        print(f"\n  {C.BD}Estatísticas:{C.RS}")
        dado("Total analisado:", str(len(scores)))
        dado("Score médio:",     f"{sum(scores)/len(scores):.1f}/100")
        dado("Críticos (≥65):",  f"{C.R}{criticos}{C.RS}")
        dado("Alto risco (40-64):", f"{C.Y}{altos}{C.RS}")
        dado("Baixo risco:",     str(len(scores) - criticos - altos))


# ═══════════════════════════════════════════════════════════════════════════
# MÓDULO J — BASE DE GOLPES CONHECIDOS (Enciclopédia)
# ═══════════════════════════════════════════════════════════════════════════

def exibir_base_golpes(filtro: Optional[str] = None) -> None:
    titulo("Enciclopédia de Golpes Digitais Brasileiros")
    cats_count: Counter = Counter(g["categoria"] for g in PADROES_GOLPE)
    info(f"Total mapeado: {C.BD}{len(PADROES_GOLPE)}{C.RS} tipos | "
         f"Categorias: {C.BD}{len(cats_count)}{C.RS}")
    print()

    filtrados = PADROES_GOLPE
    if filtro:
        filtro_norm = normalizar(filtro)
        filtrados = [g for g in PADROES_GOLPE
                     if filtro_norm in normalizar(g["nome"])
                     or filtro_norm in normalizar(g["categoria"])
                     or filtro_norm in normalizar(g["descricao"])]
        if not filtrados:
            aviso(f"Nenhum golpe encontrado para: '{filtro}'")
            return

    for g in filtrados:
        print(f"  {C.CY}{g['id']}{C.RS} {C.BD}{g['nome']}{C.RS}")
        print(f"       {C.Y}Categoria:{C.RS} {g['categoria']}  "
              f"{C.Y}Peso de risco:{C.RS} {g['peso']}/55")
        print(f"       {C.Y}Descrição:{C.RS} {wrap(g['descricao'], 62, '                  ')}")
        print(f"       {C.R}Alerta:{C.RS}    {wrap(g['alerta'], 62, '                  ')}")
        print()

    sep()
    info("Categorias: " + " | ".join(f"{k} ({v})" for k, v in cats_count.most_common()))


# ═══════════════════════════════════════════════════════════════════════════
# APRESENTAÇÃO DE RESULTADOS
# ═══════════════════════════════════════════════════════════════════════════

def exibir_resultado(res: ResultadoAnalise, salvar: bool = True) -> None:
    """Exibe resultado formatado de qualquer análise."""
    sep("═")
    print(f"\n  {res.emoji}  {res.cor}{C.BD}{res.nivel}{C.RS}   "
          f"Score: {barra_risco(res.score, res.cor)}")
    sep()

    if res.golpes:
        secao(f"Golpes Detectados ({len(res.golpes)})")
        for g in res.golpes:
            print(f"\n    {C.R}[{g['id']}]{C.RS} {C.BD}{g['nome']}{C.RS} — {g['categoria']}")
            print(f"    {wrap(g['descricao'], 68, '    ')}")
            print(f"    {C.Y}⚠{C.RS}  {wrap(g['alerta'], 68, '       ')}")

    if res.evidencias:
        secao(f"Evidências ({len(res.evidencias)})")
        # Ordenar por peso decrescente
        for desc, peso in sorted(res.evidencias, key=lambda x: -x[1])[:12]:
            print(f"    {C.R}+{peso:3d}pt{C.RS}  {desc}")

    if res.alertas:
        secao(f"Alertas Específicos")
        for a in res.alertas[:8]:
            aviso(a)

    if res.infos:
        secao("Informações")
        for i in res.infos[:8]:
            info(i)

    if res.plano_acao:
        secao("Plano de Ação Imediato")
        for i, p in enumerate(res.plano_acao, 1):
            print(f"    {C.G}{i:02d}.{C.RS} {p}")

    if res.recursos:
        secao("Recursos Legais e Canais Oficiais")
        for r in res.recursos[:4]:
            print(f"\n    {C.BD}{r['titulo']}{C.RS}")
            print(f"    {C.CY}URL:{C.RS} {r['url']}")
            print(f"    {r['desc']}")
            if r.get("prazo"):
                print(f"    {C.Y}Prazo:{C.RS} {r['prazo']}")

    if salvar:
        arq = gerar_relatorio_txt(res)
        salvar_historico(res)
        sep()
        ok(f"Relatório salvo em: {C.BD}{arq}{C.RS}")
    sep("═")


# ═══════════════════════════════════════════════════════════════════════════
# FLUXOS INTERATIVOS
# ═══════════════════════════════════════════════════════════════════════════

def _ler_multiplas_linhas(prompt: str) -> str:
    """Lê texto multilinha até linha vazia."""
    print(prompt)
    print(f"  {C.Y}(Cole o texto abaixo. Pressione Enter duas vezes para finalizar){C.RS}")
    linhas: list[str] = []
    vazio_consecutivo = 0
    while True:
        try:
            linha = input()
            if linha == "":
                vazio_consecutivo += 1
                if vazio_consecutivo >= 2:
                    break
            else:
                vazio_consecutivo = 0
                linhas.append(linha)
        except EOFError:
            break
    return "\n".join(linhas)


def modo_mensagem() -> None:
    titulo("Analisar Mensagem Suspeita")
    info("Cole a mensagem recebida por WhatsApp, SMS, e-mail ou qualquer canal.")
    linha()
    texto = _ler_multiplas_linhas(f"\n  {C.BD}Mensagem:{C.RS}")
    if not texto.strip():
        erro("Nenhum texto fornecido.")
        return
    print()
    info("Analisando...")
    res = analisar_mensagem(texto)
    exibir_resultado(res)


def modo_pix() -> None:
    titulo("Verificar Chave Pix")
    linha()
    chave = input(f"  {C.BD}Chave Pix (CPF/CNPJ/e-mail/telefone/EVP):{C.RS} ").strip()
    if not chave:
        erro("Nenhuma chave fornecida.")
        return

    valor_str = input(f"  {C.BD}Valor da transação (ex: 150.00 ou Enter para pular):{C.RS} ").strip()
    valor: Optional[float] = None
    if valor_str:
        try:
            valor = float(valor_str.replace(",", "."))
        except ValueError:
            aviso("Valor inválido — ignorado.")

    nome = input(f"  {C.BD}Nome do destinatário mostrado no app (Enter para pular):{C.RS} ").strip() or None
    print()
    info("Analisando...")
    res = analisar_chave_pix(chave, valor, nome)
    exibir_resultado(res)


def modo_link() -> None:
    titulo("Analisar Link / URL Suspeita")
    linha()
    url = input(f"  {C.BD}URL ou link (com ou sem http://):{C.RS} ").strip()
    if not url:
        erro("Nenhuma URL fornecida.")
        return
    print()
    info("Analisando...")
    res = analisar_link(url)
    exibir_resultado(res)


def modo_boleto() -> None:
    titulo("Validar Boleto Bancário")
    info("Cole a linha digitável do boleto (com ou sem pontos e espaços).")
    linha()
    ld = input(f"  {C.BD}Linha digitável:{C.RS} ").strip()
    if not ld:
        erro("Nenhuma linha digitável fornecida.")
        return
    print()
    info("Analisando...")
    res = analisar_boleto(ld)
    exibir_resultado(res)


def modo_whatsapp() -> None:
    titulo("Detector de WhatsApp Clonado")
    info("Cole a mensagem recebida de um contato suspeito.")
    linha()
    texto = _ler_multiplas_linhas(f"\n  {C.BD}Mensagem:{C.RS}")
    if not texto.strip():
        erro("Nenhum texto fornecido.")
        return
    print()
    info("Analisando padrões de clonagem...")
    res = analisar_whatsapp_clonado(texto)
    exibir_resultado(res)


def modo_phishing_ml() -> None:
    titulo("Classificador de Phishing (ML Heurístico)")
    info("Insira qualquer texto para classificação automática de phishing.")
    info("O classificador usa 26 features linguísticas calibradas.")
    linha()
    texto = _ler_multiplas_linhas(f"\n  {C.BD}Texto para classificar:{C.RS}")
    if not texto.strip():
        erro("Nenhum texto fornecido.")
        return
    print()
    info("Classificando...")
    res = classificar_phishing(texto)

    # Exibir detalhes do classificador
    titulo("Resultado do Classificador")
    saida = _CLASSIFICADOR.classificar(texto)
    dado("Classificação:",  f"{res.cor}{C.BD}{saida['classificacao']}{C.RS}")
    dado("Score:",          f"{saida['score']}/100")
    dado("Confiança:",      f"{saida['confianca']}%")
    dado("Categorias:",     ", ".join(saida["categorias"]) or "nenhuma")
    if saida["bonus_combinacao"]:
        dado("Bônus:",      f"+{saida['bonus_combinacao']}pt (múltiplas categorias)")
    if saida["features_ativas"]:
        secao(f"Features Ativadas ({len(saida['features_ativas'])})")
        for pat, peso in sorted(saida["features_ativas"], key=lambda x: -x[1])[:10]:
            print(f"    {C.R}+{peso:3d}pt{C.RS}  {pat[:60]}")

    exibir_resultado(res, salvar=True)


def modo_lgpd_recursos() -> None:
    titulo("Direitos e Recursos Legais Anti-Golpe")
    info("O que fazer se você for vítima de um golpe digital no Brasil.")
    linha()

    secao("Seus Direitos Fundamentais")
    direitos = [
        ("LGPD — Art. 18",    "Acesso, correção e exclusão dos seus dados pessoais"),
        ("CDC — Art. 42",     "Proibição de cobrança vexatória ou constrangedora"),
        ("CP — Art. 171",     "Estelionato punível com 1 a 5 anos de reclusão"),
        ("Lei 12.737/2012",   "Crime de invasão de dispositivo e fraude informática"),
        ("Lei 14.155/2021",   "Fraude eletrônica com pena de 4 a 8 anos"),
        ("Res. BCB 6/2023",   "Mecanismo Especial de Devolução (MED) do Pix"),
    ]
    for d, desc in direitos:
        print(f"  {C.MG}{d:<22}{C.RS} {desc}")

    secao("Canais para Denúncia e Recuperação")
    for i, r in enumerate(RECURSOS_LEGAIS, 1):
        print(f"\n  {C.CY}{i:02d}.{C.RS} {C.BD}{r['titulo']}{C.RS}")
        print(f"       {C.Y}URL:{C.RS}   {r['url']}")
        print(f"       {r['desc']}")
        if r.get("prazo"): print(f"       {C.Y}Prazo:{C.RS} {r['prazo']}")

    secao("Passos Imediatos em Caso de Golpe")
    passos = [
        "Não envie mais dinheiro — pare imediatamente qualquer transação em andamento.",
        "Bloqueie o contato no WhatsApp/telefone para evitar mais danos.",
        "Acione o MED no app do banco em até 80 dias (para Pix).",
        "Ligue para o banco pelo número no verso do cartão e relate a fraude.",
        "Registre B.O. pelo site do BO eletrônico do seu estado.",
        "Documente tudo: prints, áudios, transferências — guarde as evidências.",
        "Informe a família e amigos para evitar que mais pessoas caiam no mesmo golpe.",
        "Consulte um advogado se o valor for significativo — bancos respondem civilmente.",
    ]
    for i, p in enumerate(passos, 1):
        item(i, p)


def modo_estatisticas() -> None:
    titulo("Estatísticas — Base de Conhecimento GolpeScanner")
    info("Dados sobre golpes digitais no Brasil (fontes: ADDP, FBSP, Banco Central)")
    sep()

    stats = [
        ("Fraudes Pix (jan–set/2025)",   "28.000.000 casos",     "ADDP"),
        ("Fraudes WhatsApp (2025)",       "1.600.000 casos",      "ADDP"),
        ("Fraudes e-mail phishing (2025)","1.500.000 casos",      "ADDP"),
        ("Compras online fraudulentas",   "2.700.000 casos",      "ADDP"),
        ("Prejuízo Pix+boleto (12 meses)","R$ 29 bilhões",        "FBSP"),
        ("Perda média por vítima",        "R$ 6.311",             "FBSP"),
        ("Tentativas por hora no BR",     "4.600/hora",           "FBSP"),
        ("Crescimento de golpes 2024→25", "+65%",                 "Banco Central"),
        ("Prejuízo só com Pix (2024)",    "R$ 4,9 bilhões",       "Banco Central"),
        ("Faixa etária mais afetada",     "+50 anos (53%)",       "ADDP"),
        ("% fraudes financeiras/total",   "47%",                  "ADDP"),
        ("Golpes mapeados na ferramenta", str(len(PADROES_GOLPE)), "GolpeScanner BR"),
    ]

    print(f"  {'INDICADOR':<42} {'VALOR':<22} {'FONTE'}")
    sep("-", 72)
    for indicador, valor, fonte in stats:
        print(f"  {indicador:<42} {C.BD}{valor:<22}{C.RS} {C.Y}{fonte}{C.RS}")

    sep()
    print(f"\n  {C.R}{C.BD}O Brasil tem o MAIOR crescimento de fraudes digitais do mundo.{C.RS}")
    print(f"  {C.Y}Projeção de perdas com Pix: R$ 11 bilhões até 2028 (ACI Worldwide).{C.RS}")
    print()


def modo_interativo() -> None:
    titulo("Menu Principal — GolpeScanner BR")
    print(f"""
  {C.BD}{C.CY}ANÁLISE DE CONTEÚDO{C.RS}
  {C.CY}  1.{C.RS} Analisar mensagem suspeita    (WhatsApp, SMS, e-mail, etc.)
  {C.CY}  2.{C.RS} Verificar chave Pix           (CPF/CNPJ/telefone/e-mail/EVP)
  {C.CY}  3.{C.RS} Analisar link/URL suspeita    (phishing, typosquatting)
  {C.CY}  4.{C.RS} Validar boleto bancário       (linha digitável + dígitos)
  {C.CY}  5.{C.RS} Detectar WhatsApp clonado     (padrões de sequestro de conta)
  {C.CY}  6.{C.RS} Classificador ML de phishing  (26 features heurísticas)

  {C.BD}{C.CY}CONHECIMENTO E REFERÊNCIA{C.RS}
  {C.CY}  7.{C.RS} Enciclopédia de golpes        ({len(PADROES_GOLPE)} tipos mapeados)
  {C.CY}  8.{C.RS} Direitos legais + recursos    (MED, B.O., ANPD, Procon...)
  {C.CY}  9.{C.RS} Estatísticas de fraude no BR  (dados 2025/2026)
  {C.CY} 10.{C.RS} Histórico de análises         (últimas análises realizadas)
  {C.CY} 11.{C.RS} Modo batch                    (analisa arquivo .txt ou .csv)

  {C.CY}  0.{C.RS} Sair
""")
    op = input(f"  {C.BD}Escolha [0-11]: {C.RS}").strip()

    if   op == "1":  modo_mensagem()
    elif op == "2":  modo_pix()
    elif op == "3":  modo_link()
    elif op == "4":  modo_boleto()
    elif op == "5":  modo_whatsapp()
    elif op == "6":  modo_phishing_ml()
    elif op == "7":
        f = input(f"  {C.BD}Filtrar por nome/categoria (Enter para ver todos):{C.RS} ").strip() or None
        exibir_base_golpes(f)
    elif op == "8":  modo_lgpd_recursos()
    elif op == "9":  modo_estatisticas()
    elif op == "10": exibir_historico(20)
    elif op == "11":
        arq = input(f"  {C.BD}Caminho do arquivo (.txt ou .csv):{C.RS} ").strip()
        processar_batch(arq)
    elif op == "0":
        info("Saindo... Fique seguro!")
        sys.exit(0)
    else:
        aviso("Opção inválida. Escolha entre 0 e 11.")


# ═══════════════════════════════════════════════════════════════════════════
# CLI — ARGPARSE
# ═══════════════════════════════════════════════════════════════════════════

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="golpescanner",
        description=f"GolpeScanner BR v{VERSION} — Detector de Golpes Digitais Brasileiros",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
Exemplos:
  python golpescanner.py -m "Banco informou bloqueio da conta, clique aqui"
  python golpescanner.py -p 12345678901
  python golpescanner.py -p contato@empresa.com.br -v 1500.00 -n "João Silva"
  python golpescanner.py -u "http://bradesco-seguranca.xyz/login"
  python golpescanner.py -b "33590000000 10557956500 62082503000 17700820241"
  python golpescanner.py -w "Oi, mudei de número, pode me emprestar R$300?"
  python golpescanner.py --phishing "Sua conta foi bloqueada urgente clique aqui"
  python golpescanner.py --base --filtro whatsapp
  python golpescanner.py --historico
  python golpescanner.py --stats
  python golpescanner.py --batch mensagens.txt
  python golpescanner.py           (menu interativo)

{AUTHOR} | {GITHUB} | {DISCORD}
        """
    )
    g = p.add_argument_group("Análise de conteúdo")
    g.add_argument("-m", "--mensagem",  help="Analisar mensagem suspeita")
    g.add_argument("-p", "--pix",       help="Verificar chave Pix",        metavar="CHAVE")
    g.add_argument("-v", "--valor",     type=float, help="Valor da transação Pix", metavar="R$")
    g.add_argument("-n", "--nome",      help="Nome do destinatário Pix",   metavar="NOME")
    g.add_argument("-u", "--url",       help="Analisar link/URL suspeita")
    g.add_argument("-b", "--boleto",    help="Validar linha digitável de boleto", metavar="LINHA")
    g.add_argument("-w", "--whatsapp",  help="Detectar WhatsApp clonado",  metavar="MSG")
    g.add_argument("--phishing",        help="Classificar phishing via ML", metavar="TEXTO")

    r = p.add_argument_group("Referência e dados")
    r.add_argument("--base",            action="store_true", help="Enciclopédia de golpes")
    r.add_argument("--filtro",          help="Filtrar base por palavra-chave", metavar="TERMO")
    r.add_argument("--lgpd",            action="store_true", help="Direitos e recursos legais")
    r.add_argument("--stats",           action="store_true", help="Estatísticas de fraude no Brasil")
    r.add_argument("--historico",       action="store_true", help="Histórico de análises")
    r.add_argument("--batch",           help="Analisar arquivo .txt ou .csv", metavar="ARQUIVO")
    r.add_argument("--versao",          action="store_true", help="Versão")
    return p.parse_args()


def checar_deps() -> None:
    miss: list[str] = []
    if not HAS_COLOR:    miss.append("colorama")
    if not HAS_DNS:      miss.append("dnspython")
    if miss:
        aviso(f"Dependências opcionais ausentes: {', '.join(miss)}")
        aviso(f"Instale com: pip install {' '.join(miss)}\n")


def main() -> None:
    banner()
    checar_deps()
    args = parse_args()

    if args.versao:
        print(f"GolpeScanner BR v{VERSION} — {AUTHOR}")
        sys.exit(0)
    elif args.mensagem:
        exibir_resultado(analisar_mensagem(args.mensagem))
    elif args.pix:
        exibir_resultado(analisar_chave_pix(args.pix, args.valor, args.nome))
    elif args.url:
        exibir_resultado(analisar_link(args.url))
    elif args.boleto:
        exibir_resultado(analisar_boleto(args.boleto))
    elif args.whatsapp:
        exibir_resultado(analisar_whatsapp_clonado(args.whatsapp))
    elif args.phishing:
        exibir_resultado(classificar_phishing(args.phishing))
    elif args.base:
        exibir_base_golpes(args.filtro)
    elif args.lgpd:
        modo_lgpd_recursos()
    elif args.stats:
        modo_estatisticas()
    elif args.historico:
        exibir_historico(20)
    elif args.batch:
        processar_batch(args.batch)
    else:
        while True:
            try:
                modo_interativo()
                print()
            except KeyboardInterrupt:
                print(f"\n\n  {C.Y}[!]{C.RS} Interrompido. Até mais!")
                sys.exit(0)

    sep()
    print(f"\n  {C.MG}★{C.RS} Gostou? Deixa o like e segue o canal!")
    print(f"  {C.CY}GitHub:{C.RS}  {GITHUB}")
    print(f"  {C.CY}Discord:{C.RS} {DISCORD}\n")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n  {C.Y}[!]{C.RS} Interrompido pelo usuário. Até mais!")
        sys.exit(0)
