const API_BASE = process.env.NEXT_PUBLIC_API_BASE || "http://localhost:8000";

async function handle(res) {
  if (!res.ok) {
    let detail;
    try {
      detail = (await res.json()).detail;
    } catch {
      detail = res.statusText;
    }
    throw new Error(detail || `Request failed (${res.status})`);
  }
  return res.json();
}

export const api = {
  // The only endpoint this site uses: one call returns the entire scored
  // demo timeline (no accounts, no session state to manage client-side).
  async demoStart() {
    const res = await fetch(`${API_BASE}/demo/start`, { method: "POST" });
    return handle(res);
  },
};
