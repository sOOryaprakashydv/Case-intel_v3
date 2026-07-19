"use client";

import { useEffect, useState } from "react";
import { api } from "@/lib/api";
import { Download, FileText } from "lucide-react";

export default function ReportsPage() {
  const [reports, setReports] = useState<any[]>([]);

  useEffect(() => {
    api.reportHistory().then(setReports).catch(() => {});
  }, []);

  return (
    <div className="space-y-6">
      <header>
        <h1 className="text-2xl font-bold text-slate-100">Report History</h1>
        <p className="text-slate-500 text-sm mt-1">Every generated report, re-downloadable.</p>
      </header>

      <div className="rounded-xl2 border border-ink-700 bg-ink-900/60 shadow-card divide-y divide-ink-800">
        {reports.length === 0 && (
          <p className="px-5 py-8 text-center text-slate-600 text-sm">No reports generated yet.</p>
        )}
        {reports.map((r) => (
          <div key={r.id} className="flex items-center gap-4 px-5 py-4">
            <FileText size={18} className="text-accent-400 shrink-0" />
            <div className="min-w-0 flex-1">
              <p className="text-sm font-medium text-slate-200 truncate">{r.file_name}</p>
              <p className="text-xs text-slate-500">
                {r.generated_by} · {r.version} · {new Date(r.generated_at).toLocaleString()}
              </p>
            </div>
            <a
              href={`/api/reports/${r.id}/download`}
              target="_blank"
              className="inline-flex items-center gap-1.5 text-sm text-accent-300 hover:text-accent-200 shrink-0"
            >
              <Download size={15} /> Download
            </a>
          </div>
        ))}
      </div>
    </div>
  );
}
