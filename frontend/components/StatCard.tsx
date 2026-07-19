import { LucideIcon } from "lucide-react";

export default function StatCard({
  label, value, icon: Icon, accent = "accent",
}: { label: string; value: string | number; icon: LucideIcon; accent?: "accent" | "yellow" | "green" }) {
  const accentColor = {
    accent: "text-accent-400 bg-accent-500/10",
    yellow: "text-yellow-400 bg-yellow-500/10",
    green: "text-emerald-400 bg-emerald-500/10",
  }[accent];

  return (
    <div className="rounded-xl2 border border-ink-700 bg-ink-900/60 p-4 sm:p-5 shadow-card flex items-center gap-4 min-w-0">
      <div className={`shrink-0 h-11 w-11 rounded-xl flex items-center justify-center ${accentColor}`}>
        <Icon size={20} />
      </div>
      <div className="min-w-0">
        <p className="text-xs text-slate-500 truncate">{label}</p>
        <p className="text-lg sm:text-xl font-semibold text-slate-100 truncate">{value ?? "—"}</p>
      </div>
    </div>
  );
}
