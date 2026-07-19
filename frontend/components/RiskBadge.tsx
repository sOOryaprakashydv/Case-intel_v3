import clsx from "clsx";

const STYLES: Record<string, string> = {
  critical: "bg-red-500/15 text-red-400 border-red-500/30",
  high: "bg-orange-500/15 text-orange-400 border-orange-500/30",
  medium: "bg-yellow-500/15 text-yellow-400 border-yellow-500/30",
  low: "bg-emerald-500/15 text-emerald-400 border-emerald-500/30",
};

export default function RiskBadge({ level, score }: { level: string; score?: number }) {
  return (
    <span
      className={clsx(
        "inline-flex items-center gap-1.5 rounded-full border px-2.5 py-1 text-xs font-semibold uppercase tracking-wide",
        STYLES[level] || STYLES.low
      )}
    >
      {typeof score === "number" && <span className="font-mono">{score}</span>}
      {level}
    </span>
  );
}
