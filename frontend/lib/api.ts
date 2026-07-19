const BASE = "/api";

// NOTE ON AUTH: this sends a shared API key from a public env var, which
// means it's visible to anyone inspecting network requests from the
// deployed frontend. That's an acceptable stopgap for a single-team
// pilot (it blocks anonymous internet bots from hitting the API
// directly) but is NOT real per-analyst authentication. Before this
// handles actual case data beyond a pilot, replace with proper
// login-based auth (see backend/app/auth.py for the current placeholder).
const API_KEY = process.env.NEXT_PUBLIC_API_KEY || "";
const authHeaders = API_KEY ? { "X-Api-Key": API_KEY } : {};

async function handle<T>(res: Response): Promise<T> {
  if (!res.ok) {
    const body = await res.text().catch(() => "");
    throw new Error(`API ${res.status}: ${body || res.statusText}`);
  }
  return res.json();
}

export const api = {
  health: () => fetch(`${BASE}/health`).then((r) => handle<any>(r)),

  listCases: () => fetch(`${BASE}/cases`, { cache: "no-store" }).then((r) => handle<any[]>(r)),
  getCase: (id: string) => fetch(`${BASE}/cases/${id}`, { cache: "no-store" }).then((r) => handle<any>(r)),
  getCorrelations: (id: string) =>
    fetch(`${BASE}/cases/${id}/correlations`, { cache: "no-store" }).then((r) => handle<any>(r)),
  getAcceleration: (id: string) =>
    fetch(`${BASE}/cases/${id}/acceleration`, { cache: "no-store" }).then((r) => handle<any>(r)),
  listNotes: (id: string) => fetch(`${BASE}/cases/${id}/notes`, { cache: "no-store" }).then((r) => handle<any[]>(r)),
  addNote: (id: string, analyst: string, note: string) =>
    fetch(`${BASE}/cases/${id}/notes`, {
      method: "POST",
      headers: { "Content-Type": "application/json", ...authHeaders },
      body: JSON.stringify({ analyst, note }),
    }).then((r) => handle<any>(r)),

  dashboardStats: () => fetch(`${BASE}/dashboard/stats`, { cache: "no-store" }).then((r) => handle<any>(r)),

  uploadSample: (file: File, examiner: string) => {
    const form = new FormData();
    form.append("file", file);
    form.append("examiner", examiner);
    return fetch(`${BASE}/upload`, { method: "POST", headers: authHeaders, body: form }).then((r) => handle<any>(r));
  },

  reportHistory: () => fetch(`${BASE}/reports/history`, { cache: "no-store" }).then((r) => handle<any[]>(r)),
  generateReport: (caseId: string, fmt: "pdf" | "html" | "csv", generatedBy = "analyst") =>
    fetch(`${BASE}/reports/${caseId}/generate/${fmt}?generated_by=${encodeURIComponent(generatedBy)}`, {
      method: "POST",
      headers: authHeaders,
    }).then((r) => handle<any>(r)),
};
