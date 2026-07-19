"use client";

import { useCallback, useRef, useState } from "react";
import { UploadCloud, FileWarning, Loader2 } from "lucide-react";
import { api } from "@/lib/api";
import { useRouter } from "next/navigation";

export default function UploadDropzone() {
  const [dragOver, setDragOver] = useState(false);
  const [file, setFile] = useState<File | null>(null);
  const [examiner, setExaminer] = useState("");
  const [status, setStatus] = useState<"idle" | "uploading" | "error">("idle");
  const [errorMsg, setErrorMsg] = useState("");
  const inputRef = useRef<HTMLInputElement>(null);
  const router = useRouter();

  const onDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setDragOver(false);
    if (e.dataTransfer.files?.[0]) setFile(e.dataTransfer.files[0]);
  }, []);

  const submit = async () => {
    if (!file) return;
    setStatus("uploading");
    setErrorMsg("");
    try {
      const result = await api.uploadSample(file, examiner || "Unassigned");
      router.push(`/investigations/${result.id}`);
    } catch (err: any) {
      setStatus("error");
      setErrorMsg(err.message || "Upload failed");
    }
  };

  return (
    <div className="max-w-2xl">
      <div
        onDragOver={(e) => { e.preventDefault(); setDragOver(true); }}
        onDragLeave={() => setDragOver(false)}
        onDrop={onDrop}
        onClick={() => inputRef.current?.click()}
        role="button"
        tabIndex={0}
        onKeyDown={(e) => { if (e.key === "Enter") inputRef.current?.click(); }}
        className={`rounded-xl2 border-2 border-dashed p-8 sm:p-12 text-center cursor-pointer transition-colors
          min-h-[220px] flex flex-col items-center justify-center gap-3
          ${dragOver ? "border-accent-400 bg-accent-500/5" : "border-ink-700 bg-ink-900/40 hover:border-ink-600"}`}
      >
        <input
          ref={inputRef}
          type="file"
          className="hidden"
          onChange={(e) => e.target.files?.[0] && setFile(e.target.files[0])}
        />
        <UploadCloud size={40} className="text-accent-400" />
        <div>
          <p className="font-medium text-slate-200">
            {file ? file.name : "Drag & drop a Windows PE file, or tap to browse"}
          </p>
          <p className="text-sm text-slate-500 mt-1">
            {file ? `${(file.size / 1024).toFixed(1)} KB` : `Max ${50}MB · .exe, .dll`}
          </p>
        </div>
      </div>

      <div className="mt-4">
        <label className="block text-sm text-slate-400 mb-1.5" htmlFor="examiner">
          Examiner name
        </label>
        <input
          id="examiner"
          value={examiner}
          onChange={(e) => setExaminer(e.target.value)}
          placeholder="e.g. Analyst A"
          className="w-full rounded-lg bg-ink-900 border border-ink-700 px-3 py-2.5 text-sm
                     focus:border-accent-400 outline-none min-h-[44px]"
        />
      </div>

      {status === "error" && (
        <div className="mt-4 flex items-start gap-2 rounded-lg bg-red-500/10 border border-red-500/30 px-3 py-2.5 text-sm text-red-300">
          <FileWarning size={16} className="mt-0.5 shrink-0" />
          <span>{errorMsg}</span>
        </div>
      )}

      <button
        onClick={submit}
        disabled={!file || status === "uploading"}
        className="mt-5 w-full sm:w-auto inline-flex items-center justify-center gap-2 rounded-xl
                   bg-accent-500 hover:bg-accent-400 disabled:opacity-40 disabled:cursor-not-allowed
                   text-white font-medium px-6 py-3 min-h-[44px] transition-colors"
      >
        {status === "uploading" && <Loader2 size={18} className="animate-spin" />}
        {status === "uploading" ? "Analyzing…" : "Upload & Analyze"}
      </button>

      <p className="text-xs text-slate-600 mt-3">
        Runs static analysis, VirusTotal lookup, IOC extraction, risk scoring, and correlation against the full Case Knowledge Base.
        Dynamic sandbox execution is not active in this deployment.
      </p>
    </div>
  );
}
