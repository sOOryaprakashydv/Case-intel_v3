"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useState } from "react";
import {
  LayoutDashboard, Upload, FolderSearch, Database, FileBarChart2, Menu, X, ShieldHalf,
} from "lucide-react";
import clsx from "clsx";

const NAV = [
  { href: "/", label: "Dashboard", icon: LayoutDashboard },
  { href: "/upload", label: "Upload", icon: Upload },
  { href: "/investigations", label: "Investigations", icon: FolderSearch },
  { href: "/knowledge-base", label: "Knowledge Base", icon: Database, highlight: true },
  { href: "/reports", label: "Reports", icon: FileBarChart2 },
];

export default function Sidebar() {
  const pathname = usePathname();
  const [open, setOpen] = useState(false);

  const NavLinks = (
    <nav className="flex flex-col gap-1 px-3">
      {NAV.map(({ href, label, icon: Icon, highlight }) => {
        const active = pathname === href;
        return (
          <Link
            key={href}
            href={href}
            onClick={() => setOpen(false)}
            className={clsx(
              "flex items-center gap-3 rounded-xl px-3 py-2.5 text-sm font-medium transition-colors",
              "min-h-[44px]", // touch-target-size
              active
                ? "bg-accent-500/15 text-accent-300 border border-accent-500/30"
                : "text-slate-400 hover:bg-ink-800 hover:text-slate-200"
            )}
          >
            <Icon size={18} className={clsx(highlight && !active && "text-yellow-500/80")} />
            <span>{label}</span>
            {highlight && (
              <span className="ml-auto text-[10px] font-semibold uppercase tracking-wide text-yellow-500/90 bg-yellow-500/10 px-1.5 py-0.5 rounded-full">
                Core
              </span>
            )}
          </Link>
        );
      })}
    </nav>
  );

  return (
    <>
      {/* Mobile top bar */}
      <div className="lg:hidden sticky top-0 z-40 flex items-center justify-between px-4 py-3 bg-ink-950/90 backdrop-blur border-b border-ink-800">
        <div className="flex items-center gap-2">
          <ShieldHalf className="text-accent-400" size={22} />
          <span className="font-semibold tracking-tight">CaseIntel</span>
        </div>
        <button
          aria-label={open ? "Close menu" : "Open menu"}
          onClick={() => setOpen(!open)}
          className="p-2 rounded-lg hover:bg-ink-800 min-h-[44px] min-w-[44px] flex items-center justify-center"
        >
          {open ? <X size={22} /> : <Menu size={22} />}
        </button>
      </div>

      {/* Mobile drawer */}
      {open && (
        <div className="lg:hidden fixed inset-0 z-30 bg-black/50" onClick={() => setOpen(false)}>
          <div
            className="absolute top-[57px] left-0 right-0 bg-ink-900 border-b border-ink-800 py-3 shadow-card"
            onClick={(e) => e.stopPropagation()}
          >
            {NavLinks}
          </div>
        </div>
      )}

      {/* Desktop sidebar */}
      <aside className="hidden lg:flex lg:flex-col lg:w-64 lg:shrink-0 lg:h-screen lg:sticky lg:top-0 border-r border-ink-800 bg-ink-900/50 py-6">
        <div className="flex items-center gap-2 px-6 mb-8">
          <ShieldHalf className="text-accent-400" size={26} />
          <div>
            <p className="font-semibold tracking-tight leading-none">CaseIntel</p>
            <p className="text-[11px] text-slate-500 mt-1">v3.0 · Static + Correlation</p>
          </div>
        </div>
        {NavLinks}
        <div className="mt-auto mx-3 px-3 py-3 rounded-xl bg-ink-800/60 text-[11px] text-slate-500 leading-relaxed">
          Dynamic sandbox analysis is not active in this deployment. Risk &amp; MITRE signals reflect static + threat-intel data only.
        </div>
      </aside>
    </>
  );
}
