// Dicas curadas manualmente para as técnicas MITRE ATT&CK mais comuns em labs de
// Red Team. Cobre a base (ex: T1082), então subtécnicas como T1082.001 caem na
// mesma dica. Não é o dataset completo do MITRE — é um resumo prático.
export const MITRE_HINTS = {
  T1033: {
    name: "System Owner/User Discovery",
    meaning: "Descobrir qual usuário está logado ou é dono do sistema comprometido.",
    howExecuted: "Comandos nativos como whoami, id, query user, ou leitura de variáveis de ambiente/registro.",
  },
  T1082: {
    name: "System Information Discovery",
    meaning: "Levantar informações sobre o sistema: versão do SO, hardware, hostname, patches instalados.",
    howExecuted: "systeminfo (Windows), uname -a (Linux), hostname, ou consultas ao WMI/registro.",
  },
  T1016: {
    name: "System Network Configuration Discovery",
    meaning: "Mapear a configuração de rede da máquina comprometida (interfaces, rotas, DNS).",
    howExecuted: "ipconfig /all (Windows), ifconfig/ip a (Linux), route print, arp -a.",
  },
  T1059: {
    name: "Command and Scripting Interpreter",
    meaning: "Executar comandos ou scripts para rodar código arbitrário no sistema.",
    howExecuted: "Via interpretadores como cmd.exe, PowerShell, bash, Python — geralmente o primeiro passo após ganhar execução no alvo.",
  },
  T1003: {
    name: "OS Credential Dumping",
    meaning: "Extrair credenciais armazenadas no sistema (hashes, senhas em texto claro, tickets Kerberos).",
    howExecuted: "Dump da LSASS (Mimikatz), leitura do SAM/NTDS.dit, ou /etc/shadow em Linux.",
  },
  T1055: {
    name: "Process Injection",
    meaning: "Injetar código em um processo legítimo já em execução, para rodar disfarçado e evitar detecção.",
    howExecuted: "Técnicas como DLL injection, process hollowing, ou APC injection.",
  },
  T1078: {
    name: "Valid Accounts",
    meaning: "Usar credenciais legítimas (roubadas ou obtidas de outra forma) para se autenticar sem explorar vulnerabilidade.",
    howExecuted: "Login normal com usuário/senha ou hash capturado, aproveitando contas já existentes no ambiente.",
  },
  T1105: {
    name: "Ingress Tool Transfer",
    meaning: "Transferir ferramentas/arquivos adicionais para dentro do ambiente comprometido.",
    howExecuted: "Download via HTTP(S), SMB, FTP, ou comandos como certutil, curl, iwr (Invoke-WebRequest).",
  },
  T1071: {
    name: "Application Layer Protocol",
    meaning: "Usar protocolos de aplicação comuns (HTTP, HTTPS, DNS) como canal de C2, para se misturar ao tráfego normal.",
    howExecuted: "Beacon do implante se comunica com o teamserver via HTTPS/DNS, imitando tráfego legítimo.",
  },
  T1027: {
    name: "Obfuscated Files or Information",
    meaning: "Ofuscar payloads/comandos para dificultar detecção por AV/EDR e análise humana.",
    howExecuted: "Encoding (Base64), criptografia, packers, ou ofuscação de scripts PowerShell.",
  },
  T1021: {
    name: "Remote Services",
    meaning: "Mover lateralmente usando serviços remotos legítimos do próprio ambiente.",
    howExecuted: "RDP, SSH, WinRM, ou SMB (PsExec-style) usando credenciais válidas.",
  },
  T1547: {
    name: "Boot or Logon Autostart Execution",
    meaning: "Garantir persistência fazendo o payload rodar automaticamente na inicialização/login.",
    howExecuted: "Chaves de Run no registro, pasta Startup, serviços, ou cron/systemd em Linux.",
  },
  T1140: {
    name: "Deobfuscate/Decode Files or Information",
    meaning: "Decodificar ou desofuscar conteúdo previamente ofuscado para uso em tempo de execução.",
    howExecuted: "Rotinas de decode (Base64, XOR) embutidas no próprio payload antes de executar o código real.",
  },
  T1593: {
    name: "Search Open Websites/Domains",
    meaning: "Buscar informações publicamente disponíveis sobre o alvo antes de qualquer comprometimento — arquivos expostos, painéis, subdomínios.",
    howExecuted: "Google Dorking (site:, filetype:, inurl:, intitle:) e outras buscas em motores de busca públicos.",
  },
};

export function mitreHint(id) {
  if (!id) return null;
  const base = id.trim().split(".")[0].toUpperCase();
  return MITRE_HINTS[base] || null;
}
