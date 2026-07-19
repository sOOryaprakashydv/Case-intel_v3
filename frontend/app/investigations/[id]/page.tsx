"use client";

import { useEffect, useState } from "react";
import { useParams } from "next/navigation";
import { api } from "@/lib/api";
import RiskBadge from "@/components/RiskBadge";
import CorrelationCard, { NoMatchCard } from "@/components/CorrelationCard";
import AccelerationCard from "@/components/AccelerationCard";
import { FileText, Download, MessageSquarePlus } from "lucide-react";

export default function CaseDetailPage() {
  const { id } = useParams<{ id: string }>();
  const [caseData, setCaseData] = useState<any>(null);
  const [correlations, setCorrelations] = useState<any>(null);
  const [acceleration, setAcceleration] = useState<any>(null);
  const [notes, setNotes] = useState<any[]>([]);
  const [noteText, setNoteText] = useState("");
  const [analyst, setAnalyst] = useState("");

  const load = () => {
    api.getCase(id).then(setCaseData).catch(() => {});
    api.getCorrelations(id).then(setCorrelations).catch(() => {});
    api.getAcceleration(id).then(setAcceleration).catch(() => {});
    api.listNotes(id).then(setNotes).catch(() => {});
  };

  useEffect(load, [id]);

  const submitNote = async () => {
    if (!noteText || !analyst) return;
    await api.addNote(id, analyst, noteText);
    setNoteText("");
    load();
  };

  const downloadReport = async (fmt: "pdf" | "html" | "csv") => {
    const report = await api.generateReport(id, fmt, analyst || "analyst");
    window.open(`/api/reports/${report.id}/download`, "_blank");
  };

  if (!caseData) {
    return <div className="h-64 rounded-xl2 bg-ink-900/60 animate-pulse" />;
  }

  return (
    <div className="space-y-8">
      <header className="flex flex-col sm:flex-row sm:items-center gap-4 justify-between">
        <div>
          <h1 className="text-2xl font-bold text-slate-100">
            {caseData.case_number} {caseData.label ? `— ${caseData.label}` : ""}
          </h1>
          <p className="text-xs text-slate-500 font-mono mt-1 break-all">{caseData.sha256}</p>
        </div>
        <RiskBadge level={caseData.risk_level} score={caseData.risk_score} />
      </header>

      {/* Structured Investigation Summary — Section 7.6 */}
      <section className="rounded-xl2 border border-ink-700 bg-ink-900/60 p-5 shadow-card">
        <h2 className="font-semibold text-slate-200 mb-3">Investigation Summary</h2>
        <p className="text-slate-300 mb-4">{caseData.executive_summary || "—"}</p>
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 mb-4">
          <div>
            <p className="text-xs text-slate-500 mb-1">Key Findings</p>
            <ul className="text-sm text-slate-300 space-y-1 list-disc list-inside">
              {(caseData.key_findings || []).map((k: string) => <li key={k}>{k}</li>)}
            </ul>
          </div>
          <div>
            <p className="text-xs text-slate-500 mb-1">Recommendation</p>
            <p className="text-sm font-medium text-slate-200">{caseData.recommendation || "—"}</p>
          </div>
          <div>
            <p className="text-xs text-slate-500 mb-1">Confidence</p>
            <p className="text-sm font-medium text-slate-200">{caseData.confidence ?? "—"}%</p>
          </div>
        </div>
        <details>
          <summary className="text-sm text-accent-400 cursor-pointer">Full narrative</summary>
          <p className="text-sm text-slate-400 mt-2">{caseData.narrative}</p>
        </details>
      </section>

      {/* Correlation — the core differentiator */}
      <section>
        <h2 className="font-semibold text-slate-200 mb-3">Correlation</h2>
        {correlations?.no_match ? (
          <NoMatchCard data={correlations.no_match} />
        ) : correlations?.matches ? (
          <CorrelationCard matches={correlations.matches} />
        ) : (
          <div className="h-40 rounded-xl2 bg-ink-900/60 animate-pulse" />
        )}
      </section>

      {/* Investigation Acceleration */}
      <section>
        <h2 className="font-semibold text-slate-200 mb-3">Investigation Acceleration</h2>
        {acceleration ? <AccelerationCard data={acceleration} /> : <div className="h-24 rounded-xl2 bg-ink-900/60 animate-pulse" />}
      </section>

      {/* Risk breakdown */}
      <section className="rounded-xl2 border border-ink-700 bg-ink-900/60 p-5 shadow-card">
        <h2 className="font-semibold text-slate-200 mb-3">Risk Score Breakdown</h2>
        <div className="space-y-2">
          {Object.entries(caseData.risk_contributions || {}).map(([rule, info]: [string, any]) => (
            <div key={rule} className="flex items-center justify-between text-sm">
              <span className={info.counted ? "text-slate-300" : "text-slate-600"}>
                {rule.replace(/_/g, " ")}
                {!info.counted && <span className="text-[10px] ml-2 text-slate-600">(redundant evidence)</span>}
              </span>
              <span className={`font-mono ${info.counted ? "text-slate-200" : "text-slate-600"}`}>+{info.weight}</span>
            </div>
          ))}
        </div>
      </section>

      {/* MITRE */}
      <section className="rounded-xl2 border border-ink-700 bg-ink-900/60 p-5 shadow-card">
        <h2 className="font-semibold text-slate-200 mb-3">MITRE ATT&amp;CK Mapping</h2>
        {(caseData.mitre_techniques || []).length === 0 ? (
          <p className="text-sm text-slate-600">No techniques mapped from available (static) signals.</p>
        ) : (
          <div className="overflow-x-auto -mx-5 px-5">
            <table className="w-full text-sm min-w-[480px]">
              <thead>
                <tr className="text-left text-slate-500 border-b border-ink-800">
                  <th className="pb-2 pr-4">ID</th><th className="pb-2 pr-4">Name</th><th className="pb-2">Confidence</th>
                </tr>
              </thead>
              <tbody>
                {caseData.mitre_techniques.map((t: any) => (
                  <tr key={t.id} className="border-b border-ink-800/50">
                    <td className="py-2 pr-4 font-mono text-accent-300">{t.id}</td>
                    <td className="py-2 pr-4 text-slate-300">{t.name}</td>
                    <td className="py-2 text-slate-400">{t.confidence}%</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      {/* Analyst notes — never merged or hidden, most recent first */}
      <section className="rounded-xl2 border border-ink-700 bg-ink-900/60 p-5 shadow-card">
        <h2 className="font-semibold text-slate-200 mb-3 flex items-center gap-2">
          <MessageSquarePlus size={17} /> Analyst Notes
        </h2>
        <div className="space-y-3 mb-4">
          {notes.length === 0 && <p className="text-sm text-slate-600">No notes yet.</p>}
          {notes.map((n, i) => (
            <div key={n.id} className="rounded-lg bg-ink-800/60 p-3 text-sm">
              <div className="flex items-center gap-2 mb-1">
                <span className="font-medium text-slate-200">{n.analyst}</span>
                {i === 0 && <span className="text-[10px] uppercase bg-accent-500/15 text-accent-300 px-1.5 py-0.5 rounded-full">Latest</span>}
                <span className="text-xs text-slate-600 ml-auto">{new Date(n.created_at).toLocaleString()}</span>
              </div>
              <p className="text-slate-300">{n.note}</p>
            </div>
          ))}
        </div>
        <div className="flex flex-col sm:flex-row gap-2">
          <input
            value={analyst}
            onChange={(e) => setAnalyst(e.target.value)}
            placeholder="Your name"
            className="sm:w-40 rounded-lg bg-ink-900 border border-ink-700 px-3 py-2 text-sm outline-none focus:border-accent-400 min-h-[44px]"
          />
          <input
            value={noteText}
            onChange={(e) => setNoteText(e.target.value)}
            placeholder="Add a note…"
            className="flex-1 rounded-lg bg-ink-900 border border-ink-700 px-3 py-2 text-sm outline-none focus:border-accent-400 min-h-[44px]"
          />
          <button onClick={submitNote} className="rounded-lg bg-accent-500 hover:bg-accent-400 text-white px-4 py-2 text-sm font-medium min-h-[44px]">
            Add
          </button>
        </div>
      </section>

      {/* Reports */}
      <section className="rounded-xl2 border border-ink-700 bg-ink-900/60 p-5 shadow-card">
        <h2 className="font-semibold text-slate-200 mb-3 flex items-center gap-2">
          <FileText size={17} /> Export Report
        </h2>
        <div className="flex flex-wrap gap-2">
          {(["pdf", "html", "csv"] as const).map((fmt) => (
            <button
              key={fmt}
              onClick={() => downloadReport(fmt)}
              className="inline-flex items-center gap-2 rounded-lg border border-ink-700 hover:border-accent-400 hover:text-accent-300 px-4 py-2.5 text-sm font-medium min-h-[44px]"
            >
              <Download size={15} /> {fmt.toUpperCase()}
            </button>
          ))}
        </div>
      </section>
    </div>
  );
}
