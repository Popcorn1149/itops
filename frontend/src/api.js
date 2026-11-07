const KEY = "itops_token";

export const auth = {
  get token() { try { return localStorage.getItem(KEY) || ""; } catch { return ""; } },
  set(t) { try { localStorage.setItem(KEY, t); } catch {} },
  clear() { try { localStorage.removeItem(KEY); } catch {} },
};

async function req(method, path, body) {
  const res = await fetch(`/api${path}`, {
    method,
    headers: { "Content-Type": "application/json", Authorization: `Bearer ${auth.token}` },
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  if (res.status === 401 && !path.startsWith("/auth/login")) {
    auth.clear();
    window.dispatchEvent(new Event("itops:logout"));
  }
  const text = await res.text();
  let data;
  try { data = text ? JSON.parse(text) : null; } catch { data = text; }
  if (!res.ok) {
    const msg = (data && data.detail) ? (typeof data.detail === "string" ? data.detail : JSON.stringify(data.detail)) : `Lỗi ${res.status}`;
    throw new Error(msg);
  }
  return data;
}

export const api = {
  get: (p) => req("GET", p),
  post: (p, b = {}) => req("POST", p, b),
  put: (p, b) => req("PUT", p, b),
  del: (p) => req("DELETE", p),
};

export const SECRET = "__SECRET__";
