// Phiên đăng nhập nằm trong cookie HttpOnly do server đặt → JavaScript (kể cả mã độc XSS) không đọc được.
// Mọi request gửi kèm X-Requested-With: itops (server dùng để chống CSRF với request ghi dữ liệu).

let pendingReason = null;   // lý do nhập ở hộp thoại xác nhận → gửi kèm request ghi KẾ TIẾP (audit "Tại sao")
export function setAuditReason(reason) {
  pendingReason = reason && reason.trim() ? { text: reason.trim(), at: Date.now() } : null;
}

async function req(method, path, body, opts = {}) {
  const headers = { "Content-Type": "application/json", "X-Requested-With": "itops" };
  if (opts.background) headers["X-Background"] = "1";      // tự làm mới số liệu: không tính là "đang thao tác"
  if (method !== "GET" && pendingReason) {
    if (Date.now() - pendingReason.at < 15000) headers["X-Audit-Reason"] = encodeURIComponent(pendingReason.text);
    pendingReason = null;
  }
  const res = await fetch(`/api${path}`, {
    method,
    credentials: "same-origin",
    headers,
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  const text = await res.text();
  let data;
  try { data = text ? JSON.parse(text) : null; } catch { data = text; }
  const detail = data && data.detail;
  if (res.status === 401 && !path.startsWith("/auth/login")) {
    document.cookie = "itops_auth=; Max-Age=0; path=/; SameSite=Strict";   // phiên đã hết → bỏ cookie gợi ý
    window.dispatchEvent(new CustomEvent("itops:logout", { detail: typeof detail === "string" ? detail : "" }));
  }
  if (res.status === 403 && detail && detail.code === "2fa_required") {
    window.dispatchEvent(new Event("itops:need2fa"));
  }
  if (!res.ok) {
    const msg = detail ? (typeof detail === "string" ? detail : detail.msg || JSON.stringify(detail)) : `Lỗi ${res.status}`;
    const e = new Error(msg);
    e.status = res.status;
    e.detail = detail;
    throw e;
  }
  return data;
}

export const api = {
  get: (p, opts) => req("GET", p, undefined, opts),
  post: (p, b = {}, opts) => req("POST", p, b, opts),
  put: (p, b, opts) => req("PUT", p, b, opts),
  del: (p, opts) => req("DELETE", p, undefined, opts),
};

export const SECRET = "__SECRET__";
