# Security Policy

## Uso Responsável

O CyberLab é uma plataforma de treinamento ofensivo desenvolvida para **ambientes controlados de laboratório**. Todo o conteúdo ofensivo (scripts, payloads, playbooks, técnicas C2) existe exclusivamente para fins educacionais e de pesquisa em segurança.

### Princípios

- **Autorização obrigatória** — Utilize as ferramentas apenas em sistemas que você possui ou tem autorização explícita por escrito para testar.
- **Ambiente isolado** — Execute testes em redes isoladas (lab VMs, VPNs dedicadas). Nunca direcione ferramentas ofensivas para sistemas em produção sem autorização formal.
- **Responsabilidade individual** — O usuário é o único responsável pelo uso das ferramentas. O autor não se responsabiliza por uso indevido.
- **Conformidade legal** — Respeite todas as leis aplicáveis, incluindo mas não limitado a: Lei Carolina Dieckmann (Lei 12.737/2012), Marco Civil da Internet (Lei 12.965/2014) e LGPD (Lei 13.709/2018).

## Escopo dos Componentes Ofensivos

| Componente | Tipo | Finalidade |
|---|---|---|
| Script Arsenal (55+ scripts) | Reverse shells, enumeração, privesc, persistência, lateral movement, exfiltração, evasion | Referência técnica para entender vetores de ataque e desenvolver defesas |
| Obfuscation Lab | Encoding de payloads (Base64, Hex, XOR, CharCode) | Estudo de técnicas de evasão e como detectá-las |
| Playbooks (4 metodologias) | External, Internal/AD, Web App, Wireless | Metodologia estruturada de pentest seguindo frameworks reconhecidos |
| CyberScan | Port scanning, banner grabbing, OS fingerprinting | Reconhecimento de rede em ambientes autorizados |
| Beacon Lab | Construtor de implants C2 (Sliver) | Estudo de operações Command & Control em lab isolado |
| Net Monitor | Packet capture via raw sockets | Análise de tráfego de rede para detecção de anomalias |
| Análise de Detectabilidade | Classificação estática + comportamental | Entender como ferramentas defensivas (AV, EDR, SIEM) detectam ameaças |

## Medidas de Segurança Implementadas

### Proteção de Credenciais
- Nenhuma credencial hardcoded no código-fonte
- Variáveis de ambiente via `.env` (excluído do repositório via `.gitignore`)
- `.env.example` fornecido com valores placeholder
- Chave Supabase utilizada é a publishable key (anon), não a service key

### Ofuscação de Strings
- Strings ofensivas fragmentadas via função `_()` (`const _ = (...p) => p.join("")`) para evitar falsos positivos em scanners de repositório (GitHub Secret Scanning, antivírus)
- Técnica puramente cosmética — não constitui proteção real e não deve ser tratada como tal

### Isolamento de Infraestrutura
- Sliver C2 opera via bridge (FastAPI) — o frontend nunca se comunica diretamente com o servidor C2
- Todas as operações de rede (scan, capture) passam pelo bridge, que valida e limita o escopo
- Supabase Row Level Security (RLS) aplicado nas tabelas

### Sanitização do Portfolio
- Credenciais e URLs de infraestrutura removidas
- Conteúdo acadêmico proprietário removido
- Scripts de deploy e configuração de infra excluídos
- Diretório de beacons/implants excluído

## Reportando Vulnerabilidades

Se você encontrar uma vulnerabilidade de segurança neste projeto:

1. **Não abra uma issue pública.**
2. Envie um email para **g.menguebarros@gmail.com** com:
   - Descrição da vulnerabilidade
   - Passos para reprodução
   - Impacto potencial
   - Sugestão de correção (se houver)
3. Resposta esperada em até 72 horas.

## Classificação de Risco dos Scripts

O Script Arsenal classifica cada script em 4 níveis de detectabilidade:

| Nível | Risco | Descrição |
|---|---|---|
| 1 - Baixa | Mínimo | Dificilmente detectado por AV/EDR em configuração padrão |
| 2 - Média | Moderado | Detectável por regras YARA ou heurísticas básicas |
| 3 - Alta | Elevado | Detectado pela maioria dos EDRs e SIEMs modernos |
| 4 - Muito Alta | Crítico | Gera alertas imediatos em qualquer stack de monitoramento |

Cada entrada inclui análise em duas camadas:
- **Estática** — assinaturas de hash, pattern matching (YARA), detecção por antivírus
- **Comportamental** — monitoramento de syscalls, análise de processos (EDR), correlação de eventos (SIEM/HIDS)

## Frameworks e Referências

- [MITRE ATT&CK](https://attack.mitre.org/) — Taxonomia de táticas e técnicas (14 táticas cobertas)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/) — Metodologia de teste web
- [PTES](http://www.pentest-standard.org/) — Penetration Testing Execution Standard
- [NIST SP 800-115](https://csrc.nist.gov/publications/detail/sp/800-115/final) — Technical Guide to Information Security Testing

## Aviso Legal

Este software é fornecido "como está", sem garantia de qualquer tipo. O uso de ferramentas ofensivas contra sistemas sem autorização explícita é ilegal e pode resultar em processos civis e criminais. O autor se isenta de qualquer responsabilidade por danos diretos, indiretos ou consequenciais resultantes do uso deste software.

Ao utilizar este projeto, você declara que:
- Possui autorização legal para realizar testes nos sistemas-alvo
- Compreende os riscos legais associados a ferramentas de segurança ofensiva
- Assume total responsabilidade por suas ações
- Utilizará as ferramentas exclusivamente para fins educacionais ou em engajamentos de pentest autorizados
