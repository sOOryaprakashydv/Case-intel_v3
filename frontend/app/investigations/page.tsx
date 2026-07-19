"use client";

import { useEffect, useState } from "react";
import { api } from "@/lib/api";
import RiskBadge from "@/components/RiskBadge";
import Link from "next/link";
import { Search } from "lucide-react";

export default function InvestigationsPage() {
  const [cases, setCases] = useState<any[]>([]);
  const [query, setQuery] = useState("");
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    api.listCases().then((c) => { setCases(c); setLoading(false); }).catch(() => setLoading(false));
  }, []);

  const filtered = cases.filter((c) =>
    `${c.case_number} ${c.label || ""} ${c.sha256}`.toLowerCase().includes(query.toLowerCase())
  );

  return (
    <div className="space-y-6">
      <header className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-slate-100">Investigations</h1>
          <p className="text-slate-500 text-sm mt-1">Every completed analysis, stored in the Knowledge Base.</p>
        </div>
        <div className="relative w-full sm:w-72">
          <Search size={16} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
          <input
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Search case, label, hash…"
            className="w-full rounded-lg bg-ink-900 border border-ink-700 pl-9 pr-3 py-2.5 text-sm focus:border-accent-400 outline-none min-h-[44px]"
          />
        </div>
      </header>

      {loading && (
        <div className="space-y-2">
          {Array.from({ length: 5 }).map((_, i) => <div key={i} className="h-16 rounded-xl bg-ink-900/60 animate-pulse" />)}
        </div>
      )}

      {!loading && filtered.length === 0 && (
        <p className="text-slate-600 text-sm">No investigations found.</p>
      )}

      <div className="grid grid-cols-1 gap-3">
        {filtered.map((c) => (
          <Link
            key={c.id}
            href={`/investigations/${c.id}`}
            className="rounded-xl2 border border-ink-700 bg-ink-900/50 hover:bg-ink-900 hover:border-ink-600 transition-colors p-4 sm:p-5 flex flex-col sm:flex-row sm:items-center gap-3"
          >
            <div className="min-w-0 flex-1">
              <div className="flex items-center gap-2 flex-wrap">
                <span className="font-semibold text-slate-200">{c.case_number}</span>
                {c.label && <span className="text-slate-500 text-sm">— {c.label}</span>}
              </div>
              <p className="text-xs text-slate-600 font-mono mt-1 truncate">{c.sha256}</p>
            </div>
            <div className="flex items-center gap-3 shrink-0">
              <RiskBadge level={c.risk_level} score={c.risk_score} />
              <span className="text-xs text-slate-500 hidden sm:inline">
                {new Date(c.upload_timestamp).toLocaleDateString()}
              </span>
            </div>
          </Link>
        ))}
      </div>
    </div>
  );
}
