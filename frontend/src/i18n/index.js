import vi from "./vi";
import en from "./en";

const dictionaries = { vi, en };
const STORAGE_KEY = "itops_language";

export function getInitialLanguage() {
  try {
    const saved = localStorage.getItem(STORAGE_KEY);
    return saved === "vi" ? "vi" : "en";
  } catch {
    return "en";
  }
}

export function saveLanguage(language) {
  const next = language === "vi" ? "vi" : "en";
  try { localStorage.setItem(STORAGE_KEY, next); } catch { /* Storage may be unavailable. */ }
  return next;
}

// Resolve a dotted key with English as the canonical fallback.
export function translate(language, key, params = {}) {
  const lang = language === "vi" ? "vi" : "en";
  const read = (obj, path) => path.split(".").reduce((value, part) => value?.[part], obj);
  const value = read(dictionaries[lang], key) ?? read(en, key) ?? key;
  if (typeof value !== "string") return key;
  return value.replace(/\{(\w+)\}/g, (_, name) => String(params[name] ?? `{${name}}`));
}

export function getDateLocale(language) {
  return language === "en" ? "en-US" : "vi-VN";
}
