"use client";

import { Link2, Search, CheckCircle2, XCircle } from "lucide-react";
import Link from "next/link";

const CONFIDENCE_COLOR: Record<string, string> = {
  high: "text-emerald-400",
  medium: "text-yellow-400",
  low: "text-slate-400",
};

const FEATURE_LABELS: Record<string, string> = {
  sha256: "SHA256 Hash",
  certificate: "Certificate",
  infrastructure: "C2 / Domain / IP",
  embedded_config: "Embedded Config",
  family: "Malware Family",
  permission: "Permission Similarity",
  mitre_overlap: "MITRE Technique Overlap",
};

export function NoMatchCard({ data }: { data: any }) {
  return (
    <div className="rounded-xl2 border border-ink-700 bg-ink-900/60 p-5 shadow-card">
      <div className="flex items-center gap-2 mb-3">
        <Link2 size={18} className="text-slate-500" />
        <h3 className="font-semibold text-slate-200">Correlation Analysis</h3>
      </div>
      <div className="flex items-baseline gap-2 mb-4">
        <span className="text-3xl font-bold text-slate-300">0%</span>
        <span className="text-sm text-slate-500">overall similarity</span>
      </div>
      <p className="text-sm text-slate-400 mb-4">
        Compared against <strong className="text-slate-300">{data.compared_against}</strong> previous investigations. {data.conclusion}
      </p>
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
        {data.reasons.map((r: string) => (
          <div key={r} className="flex items-center gap-2 text-xs text-slate-500">
            <XCircle size={14} className="text-slate-600 shrink-0" />
            {r}
          </div>
        ))}
      </div>
      <p className="text-[11px] text-slate-600 mt-4 border-t border-ink-800 pt-3">
        A 0% result is a result — the engine ran against the criteria above, not a missing feature.
      </p>
    </div>
  );
}

export default function CorrelationCard({ matches }: { matches: any[] }) {
  if (!matches || matches.length === 0) return null;
  const top = matches[0];

  return (
    <div className="rounded-xl2 border border-accent-500/30 bg-gradient-to-br from-ink-900 to-ink-800/60 p-5 shadow-card">
      <div className="flex items-center gap-2 mb-3">
        <Link2 size={18} className="text-accent-400" />
        <h3 className="font-semibold text-slate-200">Correlation Analysis</h3>
        <span className="ml-auto text-[10px] font-semibold uppercase tracking-wide bg-accent-500/15 text-accent-300 px-2 py-0.5 rounded-full">
          {matches.length} match{matches.length > 1 ? "es" : ""}
        </span>
      </div>

      <div className="flex items-baseline gap-3 mb-1">
        <span className="text-4xl font-bold text-accent-300">{top.similarity_score}%</span>
        <span className={`text-sm font-medium ${CONFIDENCE_COLOR[top.confidence_bucket]}`}>
          {top.confidence_bucket} confidence
        </span>
      </div>
      <Link
        href={`/investigations/${top.matched_case_id}`}
        className="text-sm text-slate-400 hover:text-accent-300 transition-colors"
      >
        Matched Case {top.matched_case_number} {top.matched_case_label ? `— ${top.matched_case_label}` : ""} →
      </Link>

      <div className="mt-4 space-y-1.5">
        {top.matched_features.map((f: string) => (
          <div key={f} className="flex items-center gap-2 text-sm">
            <CheckCircle2 size={15} className="text-emerald-400 shrink-0" />
            <span className="text-slate-300">{FEATURE_LABELS[f] || f}</span>
            <span className="ml-auto text-xs font-mono text-slate-500">
              +{top.feature_breakdown[f] ?? top.feature_breakdown["infrastructure"] ?? ""}
            </span>
          </div>
        ))}
      </div>

      {matches.length > 1 && (
        <details className="mt-4 group">
          <summary className="text-xs text-slate-500 cursor-pointer hover:text-slate-300 list-none flex items-center gap-1">
            <Search size={13} /> View {matches.length - 1} more correlated case{matches.length > 2 ? "s" : ""}
          </summary>
          <div className="mt-3 space-y-2 border-t border-ink-800 pt-3">
            {matches.slice(1).map((m) => (
              <Link
                key={m.matched_case_id}
                href={`/investigations/${m.matched_case_id}`}
                className="flex items-center justify-between text-sm text-slate-400 hover:text-slate-200 rounded-lg px-2 py-1.5 hover:bg-ink-800/60"
              >
                <span>{m.matched_case_number} — {m.matched_case_label || "Untitled"}</span>
                <span className="font-mono text-xs">{m.similarity_score}%</span>
              </Link>
            ))}
          </div>
        </details>
      )}

      <p className="text-[11px] text-slate-600 mt-4 border-t border-ink-800 pt-3">
        Similarity, not attribution. This is never presented as "same actor" or "confirmed related."
      </p>
    </div>
  );
}
