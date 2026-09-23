> **Nota:** Versao portfolio — credenciais e conteudo academico removidos. Codigo ofensivo mantido para fins educacionais.

# CyberLab Dashboard

**Plataforma completa de treinamento ofensivo em ciberseguranca** com 22 modulos integrados, cobrindo todo o ciclo de um pentest — do reconhecimento a exfiltracao — com mapeamento MITRE ATT&CK, integracao C2, scanner de rede, captura de pacotes e sistema de gamificacao.

Desenvolvido como projeto de TCC em Seguranca da Informacao.

## Arquitetura

```
┌─────────────────────────────────────────────────────────┐
│                    CyberLab (React 19)                  │
│  22 modulos · Tailwind CSS 4 · Vite 8 · SPA ~6500 LOC  │
└──────────────┬──────────────────────┬───────────────────┘
               │ REST API             │ Realtime / Auth
                                     
┌──────────────────────┐   ┌─────────────────────────────┐
│  Bridge (FastAPI)    │   │  Supabase                   │
│  · Port scanner      │   │  · PostgreSQL (sessoes,     │
│  · Packet capture    │   │    tecnicas, VMs, creds,    │
│  · SSE streaming     │   │    IOCs, scans, loot)       │
│  · Sliver gRPC proxy │   │  · Auth (email/password)    │
└──────────┬───────────┘   │  · Realtime subscriptions   │
           │ gRPC          └─────────────────────────────┘
           
┌──────────────────────┐
│  Sliver C2 Server    │
│  · Sessions/Beacons  │
│  · Implant generation│
│  · Remote execution  │
└──────────────────────┘
```

## Stack Tecnica

| Camada | Tecnologia | Detalhe |
|---|---|---|
| Frontend | React 19, Tailwind CSS 4, Vite 8 | SPA com ~6500 linhas, 22 modulos, dark theme, responsivo |
| Backend | Supabase (PostgreSQL + Realtime) | 10+ tabelas, auth, subscriptions em tempo real |
| Bridge | FastAPI (Python) | Proxy REST-to-gRPC, raw sockets, asyncio, SSE |
| C2 | Sliver (Go) | Command & Control via gRPC, beacons e sessions |
| Relatorios | jsPDF + AutoTable | Export de writeups e cobertura MITRE em PDF |
| Linter | oxlint | Analise estatica do codigo |

## Funcionalidades Principais

### Gestao de Lab (4 modulos)
- **Overview** — dashboard central com metricas: sessoes, tecnicas, taxa de sucesso, horas, cobertura MITRE e CVE feed (NVD)
- **Sessoes** — CRUD de sessoes de lab com objetivo, checklist das 14 fases MITRE e status
- **Tecnicas** — registro de cada tecnica executada mapeada para MITRE ATT&CK (tatica, ID, resultado, notas de deteccao)
- **Timeline** — visualizacao cronologica de todas as acoes

### Infraestrutura (4 modulos)
- **VMs** — cadastro de maquinas do lab (atacante/vitima/infra) com link automatico para sessoes Sliver via hostname
- **Credenciais** — cofre de creds capturadas (senhas, NTLM hashes, Kerberos tickets, SSH keys, tokens)
- **Mapa de Rede** — topologia visual com cores por role e conexoes entre VMs
- **Lab Check** — checklist pre-lab que valida bridge, Sliver, listeners, VMs e Supabase

### Ferramentas Ofensivas (9 modulos)
- **MITRE ATT&CK Matrix** — heatmap completo das 14 taticas com cobertura pessoal
- **Google Dorks** — templates de reconhecimento passivo organizados por categoria
- **CyberScan** — port scanner com 3 perfis (Quick/Default/Full), banner grabbing e OS fingerprinting via asyncio
- **Beacon Lab** — construtor visual de implants Sliver C2 (Windows/Linux/macOS, HTTP/HTTPS/mTLS, jitter)
- **VirusTotal** — consulta de hashes, IPs, dominios e URLs na API do VT (70+ engines)
- **IOC Tracker** — gestao de indicadores de compromisso (hashes, IPs, dominios, regras Sigma/YARA)
- **Script Arsenal** — 55+ scripts em 8 categorias com analise de detectabilidade e Obfuscation Lab
- **Playbooks** — 4 metodologias completas (External, Internal/AD, Web App, Wireless) com comandos copiaveis
- **Net Monitor** — packet capture em tempo real via raw sockets + SSE, interface estilo Wireshark

### Estudo e Documentacao (5 modulos)
- **Ranking** — gamificacao com XP, 6 ranks (Script Kiddie a Shadow Broker) e achievements
- **Flashcards** — quiz multipla escolha estilo Anki com 4 opcoes por pergunta, criacao de cards customizados e persistencia local
- **Comparar Sessoes** — diff lado a lado de duas sessoes (tecnicas, sucesso, taticas, ferramentas, duracao)
- **Writeup** — gerador automatico de relatorio em Markdown por sessao
- **ATT&CK Export** — export JSON compativel com MITRE ATT&CK Navigator

### Sliver C2 (1 modulo, opcional)
- Painel integrado: sessoes/beacons ativos, execucao remota, upload/download, screenshots, processos, conexoes de rede
- Arquitetura: `React <-> FastAPI (REST) <-> Sliver (gRPC)`

## Script Arsenal

55+ scripts prontos em 8 categorias, cada um com explicacao tecnica, pre-requisitos e analise de detectabilidade em duas camadas (estatica + comportamental):

| Categoria | Qtd | Linguagens |
|---|---|---|
| Reverse Shells | 13 | Bash, Python, PowerShell, PHP, Netcat, Socat, Perl, Ruby, Lua, Java |
| Enumeracao Linux | 6 | Bash |
| Enumeracao Windows | 6 | PowerShell |
| Privilege Escalation | 6 | Bash, PowerShell |
| Persistencia | 5 | Bash, PowerShell |
| Lateral Movement | 6 | Bash |
| Exfiltracao | 6 | Bash, PowerShell, CMD |
| Evasion & Stealth | 7 | Bash, Python |

**Detectabilidade:** cada script classifica o risco de deteccao considerando assinaturas estaticas (hash, YARA, AV) e monitoramento comportamental (syscalls, EDR, HIDS). Escala de 4 niveis: Baixa, Media, Alta, Muito Alta.

**Obfuscation Lab:** gera 6 variantes ofuscadas de qualquer comando — Base64, Hex, Reversed, XOR, CharCode (PS), EncodedCommand (PS).

## Competencias Demonstradas

| Area | Habilidades |
|---|---|
| **Frontend** | React 19 (hooks, state management, componentes), Tailwind CSS 4, Vite 8, SPA architecture |
| **Backend** | Supabase (PostgreSQL, Row Level Security, Realtime), FastAPI, REST APIs |
| **Seguranca Ofensiva** | MITRE ATT&CK (14 taticas, kill chain), pentest methodology, C2 operations, evasion techniques |
| **Seguranca Defensiva** | Analise de detectabilidade (estatica vs comportamental), EDR/SIEM awareness, IOC management |
| **Networking** | Port scanning (asyncio), packet capture (raw sockets), SSE streaming, banner grabbing |
| **DevOps** | Vite build pipeline, environment variables, API proxy architecture |
| **UX** | Dark theme, gamificacao, responsivo, multiplos modulos integrados em SPA |

## Setup

```bash
npm install
npm run dev
```

Acesse `http://localhost:5173`.

### Variaveis de Ambiente

```env
VITE_SUPABASE_URL=https://seu-projeto.supabase.co
VITE_SUPABASE_ANON_KEY=sua-anon-key
VITE_SLIVER_BRIDGE_URL=http://localhost:8000    # opcional
VITE_SLIVER_BRIDGE_API_KEY=sua-api-key          # opcional
VITE_VT_API_KEY=sua-virustotal-key              # opcional
```

## Comandos

```bash
npm run dev       # Dev server com HMR
npm run build     # Build de producao
npm run preview   # Preview do build
npm run lint      # Linter (oxlint)
```

## Licenca

Projeto academico — desenvolvido para TCC em Seguranca da Informacao.
