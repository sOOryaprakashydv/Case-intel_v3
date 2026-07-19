"use client";

import { useEffect, useState } from "react";
import { api } from "@/lib/api";
import Link from "next/link";
import { Database } from "lucide-react";
import RiskBadge from "@/components/RiskBadge";

export default function KnowledgeBasePage() {
  const [cases, setCases] = useState<any[]>([]);

  useEffect(() => {
    api.listCases().then(setCases).catch(() => {});
  }, []);

  return (
    <div className="space-y-6">
      <header>
        <h1 className="text-2xl font-bold text-slate-100 flex items-center gap-2">
          <Database className="text-yellow-500" size={24} /> Case Knowledge Base
        </h1>
        <p className="text-slate-500 text-sm mt-1">
          Every past case, browsable and searchable. This is the platform's core differentiator — each case here makes the next one faster.
        </p>
      </header>

      <div className="rounded-xl2 border border-ink-700 bg-ink-900/60 shadow-card overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-sm min-w-[560px]">
            <thead className="bg-ink-800/60">
              <tr className="text-left text-slate-500">
                <th className="px-5 py-3">Case</th>
                <th className="px-5 py-3">Label</th>
                <th className="px-5 py-3">Verdict</th>
                <th className="px-5 py-3">Risk</th>
              </tr>
            </thead>
            <tbody>
              {cases.map((c) => (
                <tr key={c.id} className="border-t border-ink-800 hover:bg-ink-800/40">
                  <td className="px-5 py-3">
                    <Link href={`/investigations/${c.id}`} className="text-accent-300 font-medium hover:underline">
                      {c.case_number}
                    </Link>
                  </td>
                  <td className="px-5 py-3 text-slate-300">{c.label || "—"}</td>
                  <td className="px-5 py-3 text-slate-400 capitalize">{c.verdict}</td>
                  <td className="px-5 py-3"><RiskBadge level={c.risk_level} score={c.risk_score} /></td>
                </tr>
              ))}
              {cases.length === 0 && (
                <tr><td colSpan={4} className="px-5 py-8 text-center text-slate-600">No cases in the Knowledge Base yet.</td></tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
