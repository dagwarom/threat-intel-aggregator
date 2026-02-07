// src/api.js
// Update API_BASE if your backend runs somewhere else
export const API_BASE = "http://127.0.0.1:5000";

export async function checkIOC(ioc) {
  const res = await fetch(`${API_BASE}/check`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ ioc }),
  });
  return res.json();
}

export async function bulkCheckFile(file) {
  const form = new FormData();
  form.append("file", file);
  const res = await fetch(`${API_BASE}/bulk-check`, {
    method: "POST",
    body: form,
  });
  return res.json();
}
