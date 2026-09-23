# CyberLab Dashboard

**Plataforma completa de treinamento ofensivo em cibersegurança** com 22 módulos integrados, cobrindo todo o ciclo de um pentest — do reconhecimento à exfiltração — com mapeamento MITRE ATT&CK, integração C2, scanner de rede, captura de pacotes e sistema de gamificação.

> **Aviso:** Este repositório contém ferramentas ofensivas para fins **exclusivamente educacionais**. Leia o [SECURITY.md](SECURITY.md) antes de utilizar. Uso contra sistemas sem autorização é ilegal.

Desenvolvido como projeto de TCC em Segurança da Informação (Senac).

## Arquitetura

```
+-----------------------------------------------------------+
|                    CyberLab (React 19)                    |
|  22 módulos  -  Tailwind CSS 4  -  Vite 8  -  SPA ~7k LOC |
+---------------+----------------------+--------------------+
                | REST API             | Realtime / Auth
                v                      v
+------------------------+   +-----------------------------+
|  Bridge (FastAPI)      |   |  Supabase                   |
|  - Port scanner        |   |  - PostgreSQL (sessões,     |
|  - Packet capture      |   |    técnicas, VMs, creds,    |
|  - SSE streaming       |   |    IOCs, scans, loot)       |
|  - Sliver gRPC proxy   |   |  - Auth (email/password)    |
+----------+-------------+   |  - Realtime subscriptions   |
           | gRPC             +-----------------------------+
           v
+------------------------+
|  Sliver C2 Server      |
|  - Sessions/Beacons    |
|  - Implant generation  |
|  - Remote execution    |
+------------------------+
```

## Stack Técnica

| Camada | Tecnologia | Detalhe |
|---|---|---|
| Frontend | React 19, Tailwind CSS 4, Vite 8 | SPA com ~7000 linhas, 22 módulos, dark theme, responsivo |
| Backend | Supabase (PostgreSQL + Realtime) | 10+ tabelas, auth, subscriptions em tempo real |
| Bridge | FastAPI (Python) | Proxy REST-to-gRPC, raw sockets, asyncio, SSE |
| C2 | Sliver (Go) | Command & Control via gRPC, beacons e sessions |
| Relatórios | jsPDF + AutoTable | Export de writeups e cobertura MITRE em PDF |
| Linter | oxlint | Análise estática do código |

## Módulos

### Gestão de Lab (4 módulos)
- **Overview** — dashboard central com métricas: sessões, técnicas, taxa de sucesso, horas, cobertura MITRE e CVE feed (NVD)
- **Sessões** — CRUD de sessões de lab com objetivo, checklist das 14 fases MITRE e status
- **Técnicas** — registro de cada técnica executada mapeada para MITRE ATT&CK (tática, ID, resultado, notas de detecção)
- **Timeline** — visualização cronológica de todas as ações

### Infraestrutura (4 módulos)
- **VMs** — cadastro de máquinas do lab (atacante/vítima/infra) com link automático para sessões Sliver via hostname
- **Credenciais** — cofre de creds capturadas (senhas, NTLM hashes, Kerberos tickets, SSH keys, tokens)
- **Mapa de Rede** — topologia visual com cores por role e conexões entre VMs
- **Lab Check** — checklist pré-lab que valida bridge, Sliver, listeners, VMs e Supabase

### Ferramentas Ofensivas (9 módulos)
- **MITRE ATT&CK Matrix** — heatmap completo das 14 táticas com cobertura pessoal
- **Google Dorks** — templates de reconhecimento passivo organizados por categoria
- **CyberScan** — port scanner com 3 perfis (Quick/Default/Full), banner grabbing e OS fingerprinting via asyncio
- **Beacon Lab** — construtor visual de implants Sliver C2 (Windows/Linux/macOS, HTTP/HTTPS/mTLS, jitter)
- **VirusTotal** — consulta de hashes, IPs, domínios e URLs na API do VT (70+ engines)
- **IOC Tracker** — gestão de indicadores de compromisso (hashes, IPs, domínios, regras Sigma/YARA)
- **Script Arsenal** — 55+ scripts em 8 categorias com análise de detectabilidade e Obfuscation Lab
- **Playbooks** — 4 metodologias completas (External, Internal/AD, Web App, Wireless) com comandos copiáveis
- **Net Monitor** — packet capture em tempo real via raw sockets + SSE, interface estilo Wireshark

### Estudo e Documentação (5 módulos)
- **Ranking** — gamificação com XP, 6 ranks (Script Kiddie a Shadow Broker) e achievements
- **Flashcards** — quiz múltipla escolha com 4 opções por pergunta, criação de cards customizados e persistência local
- **Comparar Sessões** — diff lado a lado de duas sessões (técnicas, sucesso, táticas, ferramentas, duração)
- **Writeup** — gerador automático de relatório em Markdown por sessão
- **ATT&CK Export** — export JSON compatível com MITRE ATT&CK Navigator

### Sliver C2 (1 módulo, opcional)
- Painel integrado: sessões/beacons ativos, execução remota, upload/download, screenshots, processos, conexões de rede
- Arquitetura: `React <-> FastAPI (REST) <-> Sliver (gRPC)`

## Script Arsenal

55+ scripts prontos em 8 categorias, cada um com explicação técnica, pré-requisitos e análise de detectabilidade em duas camadas (estática + comportamental):

| Categoria | Qtd | Linguagens |
|---|---|---|
| Reverse Shells | 13 | Bash, Python, PowerShell, PHP, Netcat, Socat, Perl, Ruby, Lua, Java |
| Enumeração Linux | 6 | Bash |
| Enumeração Windows | 6 | PowerShell |
| Privilege Escalation | 6 | Bash, PowerShell |
| Persistência | 5 | Bash, PowerShell |
| Lateral Movement | 6 | Bash |
| Exfiltração | 6 | Bash, PowerShell, CMD |
| Evasion & Stealth | 7 | Bash, Python |

**Detectabilidade:** cada script classifica o risco de detecção considerando assinaturas estáticas (hash, YARA, AV) e monitoramento comportamental (syscalls, EDR, HIDS). Escala de 4 níveis: Baixa, Média, Alta, Muito Alta.

**Obfuscation Lab:** gera 6 variantes ofuscadas de qualquer comando — Base64, Hex, Reversed, XOR, CharCode (PS), EncodedCommand (PS).

## Competências Demonstradas

| Área | Habilidades |
|---|---|
| **Frontend** | React 19 (hooks, state management, componentes), Tailwind CSS 4, Vite 8, SPA architecture |
| **Backend** | Supabase (PostgreSQL, Row Level Security, Realtime), FastAPI, REST APIs |
| **Segurança Ofensiva** | MITRE ATT&CK (14 táticas, kill chain), pentest methodology, C2 operations, evasion techniques |
| **Segurança Defensiva** | Análise de detectabilidade (estática vs comportamental), EDR/SIEM awareness, IOC management |
| **Networking** | Port scanning (asyncio), packet capture (raw sockets), SSE streaming, banner grabbing |
| **DevOps** | Vite build pipeline, environment variables, API proxy architecture |
| **UX** | Dark theme, gamificação, responsivo, múltiplos módulos integrados em SPA |

## Setup

```bash
git clone https://github.com/Meng0la/cyberlab-portfolio.git
cd cyberlab-portfolio
npm install
npm run dev
```

Acesse `http://localhost:5173`.

### Variáveis de Ambiente

Copie `.env.example` para `.env` e configure:

```bash
cp .env.example .env
```

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
npm run build     # Build de produção
npm run preview   # Preview do build
npm run lint      # Linter (oxlint)
```

## Segurança

Consulte [SECURITY.md](SECURITY.md) para:
- Política de uso responsável e princípios éticos
- Escopo e classificação dos componentes ofensivos
- Medidas de proteção implementadas (credenciais, ofuscação, isolamento)
- Como reportar vulnerabilidades
- Frameworks e referências (MITRE, OWASP, PTES, NIST)

## Licença

[MIT License](LICENSE) — com cláusula de uso responsável.

Este software contém ferramentas ofensivas destinadas **exclusivamente** a fins educacionais, testes de penetração autorizados e pesquisa em segurança da informação. O uso contra sistemas sem autorização explícita é ilegal.

---

Desenvolvido como TCC em Segurança da Informação — Senac (2026).
