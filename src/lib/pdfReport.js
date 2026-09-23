import jsPDF from "jspdf";
import autoTable from "jspdf-autotable";

const TACTICS = [
  "Reconnaissance", "Resource Development", "Initial Access", "Execution",
  "Persistence", "Privilege Escalation", "Defense Evasion", "Credential Access",
  "Discovery", "Lateral Movement", "Collection", "Command and Control",
  "Exfiltration", "Impact"
];

function tacticLabelPt(tactic) {
  const labels = {
    "Reconnaissance": "Reconhecimento", "Resource Development": "Desenvolvimento de Recursos",
    "Initial Access": "Acesso Inicial", "Execution": "Execução", "Persistence": "Persistência",
    "Privilege Escalation": "Escalação de Privilégios", "Defense Evasion": "Evasão de Defesa",
    "Credential Access": "Acesso a Credenciais", "Discovery": "Descoberta",
    "Lateral Movement": "Movimento Lateral", "Collection": "Coleta",
    "Command and Control": "Comando e Controle", "Exfiltration": "Exfiltração", "Impact": "Impacto",
  };
  return labels[tactic] || tactic;
}

export function generateLabReport({ sessions, techniques, vms }) {
  const doc = new jsPDF();
  const fmtDate = (d) => new Date(d).toLocaleDateString("pt-BR");

  doc.setFontSize(18);
  doc.text("CyberLab — Relatório do Lab", 14, 18);
  doc.setFontSize(10);
  doc.setTextColor(120);
  doc.text(`Gerado em ${new Date().toLocaleString("pt-BR")}`, 14, 25);
  doc.setTextColor(0);

  const total = techniques.length;
  const successCount = techniques.filter(t => t.success).length;
  const successRate = total ? Math.round((successCount / total) * 100) : 0;
  const tacticsStudied = TACTICS.filter(tac => techniques.some(t => t.tactic === tac)).length;

  doc.setFontSize(11);
  doc.text(
    `Sessões: ${sessions.length}   |   Técnicas: ${total}   |   Taxa de sucesso: ${successRate}%   |   Táticas cobertas: ${tacticsStudied}/14`,
    14, 34
  );

  let nextY = 42;

  doc.setFontSize(13);
  doc.text("Sessões de Lab", 14, nextY);
  autoTable(doc, {
    startY: nextY + 3,
    head: [["Título", "Status", "Objetivo", "Data"]],
    body: sessions.map(s => [s.title, s.status, s.objective || "-", fmtDate(s.created_at)]),
    styles: { fontSize: 8 },
    headStyles: { fillColor: [220, 38, 38] },
  });
  nextY = doc.lastAutoTable.finalY + 10;

  doc.setFontSize(13);
  doc.text("Técnicas Registradas", 14, nextY);
  autoTable(doc, {
    startY: nextY + 3,
    head: [["MITRE ID", "Técnica", "Tática", "Ferramenta", "Resultado", "Data"]],
    body: techniques.map(t => [
      t.mitre_id || "-",
      t.technique_name,
      tacticLabelPt(t.tactic),
      t.tool_used || "-",
      t.success ? "Sucesso" : "Falhou",
      fmtDate(t.created_at),
    ]),
    styles: { fontSize: 8 },
    headStyles: { fillColor: [220, 38, 38] },
  });
  nextY = doc.lastAutoTable.finalY + 10;

  if (vms?.length) {
    doc.setFontSize(13);
    doc.text("VMs do Lab", 14, nextY);
    autoTable(doc, {
      startY: nextY + 3,
      head: [["Nome", "Papel", "SO", "IP"]],
      body: vms.map(v => [v.name, v.role, v.os || "-", v.ip_address || "-"]),
      styles: { fontSize: 8 },
      headStyles: { fillColor: [220, 38, 38] },
    });
    nextY = doc.lastAutoTable.finalY + 10;
  }

  doc.setFontSize(13);
  doc.text("Cobertura MITRE ATT&CK", 14, nextY);
  autoTable(doc, {
    startY: nextY + 3,
    head: [["Tática", "Técnicas Registradas"]],
    body: TACTICS.map(tac => [tacticLabelPt(tac), String(techniques.filter(t => t.tactic === tac).length)]),
    styles: { fontSize: 8 },
    headStyles: { fillColor: [220, 38, 38] },
  });

  doc.save(`cyberlab-relatorio-${new Date().toISOString().slice(0, 10)}.pdf`);
}
