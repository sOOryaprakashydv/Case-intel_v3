"use client";

import { useEffect, useState } from "react";
import { api } from "@/lib/api";
import StatCard from "@/components/StatCard";
import { Activity, Crosshair, Gauge, Fingerprint, Globe2, Link2, Repeat2, AlertCircle } from "lucide-react";
import Link from "next/link";

export default function DashboardPage() {
  const [stats, setStats] = useState<any>(null);
  const [error, setError] = useState("");

  useEffect(() => {
    api.dashboardStats().then(setStats).catch((e) => setError(e.message));
  }, []);

  return (
    <div className="space-y-8">
      <header>
        <h1 className="text-2xl font-bold text-slate-100">Dashboard</h1>
        <p className="text-slate-500 text-sm mt-1">
          Cross-case analytics from the Case Knowledge Base — reflects current state, no manual refresh needed.
        </p>
      </header>

      {error && (
        <div className="rounded-xl border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-300 flex items-center gap-2">
          <AlertCircle size={16} /> {error}
        </div>
      )}

      {!stats && !error && (
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
          {Array.from({ length: 8 }).map((_, i) => (
            <div key={i} className="h-24 rounded-xl2 bg-ink-900/60 animate-pulse" />
          ))}
        </div>
      )}

      {stats && (
        <>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            <StatCard label="Total Cases" value={stats.total_cases} icon={Activity} />
            <StatCard label="Average Risk Score" value={stats.average_risk_score} icon={Gauge} accent="yellow" />
            <StatCard label="Most Common MITRE Technique" value={stats.most_common_mitre_technique || "—"} icon={Crosshair} />
            <StatCard label="Top Malware Family" value={stats.top_malware_family || "—"} icon={Fingerprint} />
            <StatCard label="Most Common IOC" value={stats.most_common_ioc || "—"} icon={Fingerprint} />
            <StatCard label="Top Domain" value={stats.top_domain || "—"} icon={Globe2} />
            <StatCard label="Correlation Engine Runs" value={`${stats.correlation_engine_runs} / ${stats.total_cases}`} icon={Link2} accent="green" />
          </div>

          <section className="grid grid-cols-1 lg:grid-cols-2 gap-5">
            <div className="rounded-xl2 border border-accent-500/30 bg-ink-900/60 p-5 shadow-card">
              <h2 className="font-semibold text-slate-200 mb-1 flex items-center gap-2">
                <Link2 size={17} className="text-accent-400" /> Top Correlated Cases
              </h2>
              <p className="text-xs text-slate-500 mb-4">
                Cases most frequently matched by the Correlation Engine — the ones being reused as investigation context most often.
              </p>
              {stats.top_correlated_cases.length === 0 ? (
                <p className="text-sm text-slate-600">No correlations recorded yet.</p>
              ) : (
                <div className="space-y-2">
                  {stats.top_correlated_cases.map((c: any) => (
                    <Link
                      key={c.case_id}
                      href={`/investigations/${c.case_id}`}
                      className="flex items-center justify-between rounded-lg px-3 py-2 hover:bg-ink-800/60 text-sm"
                    >
                      <span className="text-slate-300">{c.case_number} {c.label ? `— ${c.label}` : ""}</span>
                      <span className="text-accent-300 font-mono text-xs">{c.times_matched}× matched</span>
                    </Link>
                  ))}
                </div>
              )}
            </div>

            <div className="rounded-xl2 border border-emerald-500/30 bg-ink-900/60 p-5 shadow-card">
              <h2 className="font-semibold text-slate-200 mb-1 flex items-center gap-2">
                <Repeat2 size={17} className="text-emerald-400" /> Most Reused Investigation Technique
              </h2>
              <p className="text-xs text-slate-500 mb-4">
                The recommended query/technique followed most often across all cases, with its aggregate success rate.
              </p>
              {!stats.most_reused_investigation_technique ? (
                <p className="text-sm text-slate-600">No recorded outcomes yet.</p>
              ) : (
                <div>
                  <p className="text-lg font-semibold text-slate-100">
                    {stats.most_reused_investigation_technique.technique}
                  </p>
                  <p className="text-sm text-slate-400 mt-1">
                    Used {stats.most_reused_investigation_technique.times_used} times ·{" "}
                    <span className="text-emerald-400">{stats.most_reused_investigation_technique.success_rate}% success rate</span>
                  </p>
                </div>
              )}
            </div>
          </section>
        </>
      )}
    </div>
  );
}
