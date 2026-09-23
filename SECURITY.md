# Security Policy

## Uso Responsavel

O CyberLab e uma plataforma de treinamento ofensivo desenvolvida para **ambientes controlados de laboratorio**. Todo o conteudo ofensivo (scripts, payloads, playbooks, tecnicas C2) existe exclusivamente para fins educacionais e de pesquisa em seguranca.

### Principios

- **Autorizacao obrigatoria** — Utilize as ferramentas apenas em sistemas que voce possui ou tem autorizacao explicita por escrito para testar.
- **Ambiente isolado** — Execute testes em redes isoladas (lab VMs, VPNs dedicadas). Nunca direcione ferramentas ofensivas para sistemas em producao sem autorizacao formal.
- **Responsabilidade individual** — O usuario e o unico responsavel pelo uso das ferramentas. O autor nao se responsabiliza por uso indevido.
- **Conformidade legal** — Respeite todas as leis aplicaveis, incluindo mas nao limitado a: Lei Carolina Dieckmann (Lei 12.737/2012), Marco Civil da Internet (Lei 12.965/2014) e LGPD (Lei 13.709/2018).

## Escopo dos Componentes Ofensivos

| Componente | Tipo | Finalidade |
|---|---|---|
| Script Arsenal (55+ scripts) | Reverse shells, enumeracao, privesc, persistencia, lateral movement, exfiltracao, evasion | Referencia tecnica para entender vetores de ataque e desenvolver defesas |
| Obfuscation Lab | Encoding de payloads (Base64, Hex, XOR, CharCode) | Estudo de tecnicas de evasao e como detecta-las |
| Playbooks (4 metodologias) | External, Internal/AD, Web App, Wireless | Metodologia estruturada de pentest seguindo frameworks reconhecidos |
| CyberScan | Port scanning, banner grabbing, OS fingerprinting | Reconhecimento de rede em ambientes autorizados |
| Beacon Lab | Construtor de implants C2 (Sliver) | Estudo de operacoes Command & Control em lab isolado |
| Net Monitor | Packet capture via raw sockets | Analise de trafego de rede para deteccao de anomalias |
| Analise de Detectabilidade | Classificacao estatica + comportamental | Entender como ferramentas defensivas (AV, EDR, SIEM) detectam ameacas |

## Medidas de Seguranca Implementadas

### Protecao de Credenciais
- Nenhuma credencial hardcoded no codigo-fonte
- Variaveis de ambiente via `.env` (excluido do repositorio via `.gitignore`)
- `.env.example` fornecido com valores placeholder
- Chave Supabase utilizada e a publishable key (anon), nao a service key

### Ofuscacao de Strings
- Strings ofensivas fragmentadas via funcao `_()` (`const _ = (...p) => p.join("")`) para evitar falsos positivos em scanners de repositorio (GitHub Secret Scanning, antivirus)
- Tecnica puramente cosmetica — nao constitui protecao real e nao deve ser tratada como tal

### Isolamento de Infraestrutura
- Sliver C2 opera via bridge (FastAPI) — o frontend nunca se comunica diretamente com o servidor C2
- Todas as operacoes de rede (scan, capture) passam pelo bridge, que valida e limita o escopo
- Supabase Row Level Security (RLS) aplicado nas tabelas

### Sanitizacao do Portfolio
- Credenciais e URLs de infraestrutura removidas
- Conteudo academico proprietario removido
- Scripts de deploy e configuracao de infra excluidos
- Diretorio de beacons/implants excluido

## Reportando Vulnerabilidades

Se voce encontrar uma vulnerabilidade de seguranca neste projeto:

1. **Nao abra uma issue publica.**
2. Envie um email para **g.menguebarros@gmail.com** com:
   - Descricao da vulnerabilidade
   - Passos para reproducao
   - Impacto potencial
   - Sugestao de correcao (se houver)
3. Resposta esperada em ate 72 horas.

## Classificacao de Risco dos Scripts

O Script Arsenal classifica cada script em 4 niveis de detectabilidade:

| Nivel | Risco | Descricao |
|---|---|---|
| 1 - Baixa | Minimo | Dificilmente detectado por AV/EDR em configuracao padrao |
| 2 - Media | Moderado | Detectavel por regras YARA ou heuristicas basicas |
| 3 - Alta | Elevado | Detectado pela maioria dos EDRs e SIEMs modernos |
| 4 - Muito Alta | Critico | Gera alertas imediatos em qualquer stack de monitoramento |

Cada entrada inclui analise em duas camadas:
- **Estatica** — assinaturas de hash, pattern matching (YARA), deteccao por antivirus
- **Comportamental** — monitoramento de syscalls, analise de processos (EDR), correlacao de eventos (SIEM/HIDS)

## Frameworks e Referencias

- [MITRE ATT&CK](https://attack.mitre.org/) — Taxonomia de taticas e tecnicas (14 taticas cobertas)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/) — Metodologia de teste web
- [PTES](http://www.pentest-standard.org/) — Penetration Testing Execution Standard
- [NIST SP 800-115](https://csrc.nist.gov/publications/detail/sp/800-115/final) — Technical Guide to Information Security Testing

## Aviso Legal

Este software e fornecido "como esta", sem garantia de qualquer tipo. O uso de ferramentas ofensivas contra sistemas sem autorizacao explicita e ilegal e pode resultar em processos civis e criminais. O autor se isenta de qualquer responsabilidade por danos diretos, indiretos ou consequenciais resultantes do uso deste software.

Ao utilizar este projeto, voce declara que:
- Possui autorizacao legal para realizar testes nos sistemas-alvo
- Compreende os riscos legais associados a ferramentas de seguranca ofensiva
- Assume total responsabilidade por suas acoes
- Utilizara as ferramentas exclusivamente para fins educacionais ou em engajamentos de pentest autorizados
