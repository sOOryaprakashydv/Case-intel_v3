import { Zap, Compass } from "lucide-react";

export default function AccelerationCard({ data }: { data: any }) {
  if (!data || (!data.recommended_next_step && !data.suggested_investigation)) {
    return (
      <div className="rounded-xl2 border border-ink-700 bg-ink-900/60 p-5 shadow-card text-sm text-slate-500">
        No qualifying prior-case outcome exists yet — recommendation omitted rather than guessed.
      </div>
    );
  }

  return (
    <div className="space-y-4">
      {data.recommended_next_step && (
        <div className="rounded-xl2 border border-emerald-500/30 bg-emerald-500/5 p-5 shadow-card">
          <div className="flex items-center gap-2 mb-3">
            <Zap size={18} className="text-emerald-400" />
            <h3 className="font-semibold text-slate-200">Recommended Next Step</h3>
          </div>
          <p className="text-lg font-semibold text-slate-100 mb-1">
            Run: <span className="text-emerald-300">{data.recommended_next_step.run}</span>
          </p>
          {data.recommended_next_step.detail && (
            <p className="text-sm font-mono text-slate-400 mb-2 break-all">{data.recommended_next_step.detail}</p>
          )}
          <p className="text-sm text-slate-400">{data.recommended_next_step.reason}</p>
          {data.recommended_next_step.result && (
            <p className="text-sm text-emerald-400 mt-1">Result: {data.recommended_next_step.result}</p>
          )}
          <div className="mt-3 h-1.5 rounded-full bg-ink-800 overflow-hidden">
            <div
              className="h-full bg-emerald-400"
              style={{ width: `${data.recommended_next_step.confidence}%` }}
            />
          </div>
        </div>
      )}

      {data.suggested_investigation && (
        <div className="rounded-xl2 border border-ink-700 bg-ink-900/60 p-5 shadow-card">
          <div className="flex items-center gap-2 mb-3">
            <Compass size={18} className="text-accent-400" />
            <h3 className="font-semibold text-slate-200">Suggested Investigation</h3>
          </div>
          <p className="text-lg font-semibold text-slate-100 mb-1">
            Check: <span className="text-accent-300">{data.suggested_investigation.check}</span>
          </p>
          <p className="text-sm text-slate-400">{data.suggested_investigation.reason}</p>
        </div>
      )}
    </div>
  );
}
