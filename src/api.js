export const API_BASE =
  process.env.REACT_APP_API_BASE_URL || "http://127.0.0.1:5000";

async function parseResponse(res) {
  const data = await res.json().catch(() => ({}));

  if (!res.ok) {
    const message = data.error || "Request failed";
    const error = new Error(message);
    error.detail = data;
    throw error;
  }

  return data;
}

export async function checkIOC(ioc) {
  const res = await fetch(`${API_BASE}/check`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ ioc }),
  });

  return parseResponse(res);
}

export async function getNews() {
  const res = await fetch(`${API_BASE}/news`);
  return parseResponse(res);
}

export async function getIOCFeed() {
  const res = await fetch(`${API_BASE}/ioc-feed`);
  return parseResponse(res);
}
