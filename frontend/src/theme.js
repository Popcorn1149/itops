// Appearance: Light / Dark / System, with a pinnable sidebar. Preferences are saved in this browser.
import { useSyncExternalStore } from "react";

const KEY_THEME = "itops_theme";            // "light" | "dark" | "system"
const KEY_PIN = "itops_sidebar_pinned";      // "1" | "0"
const listeners = new Set();
const mql = typeof window !== "undefined" && window.matchMedia ? window.matchMedia("(prefers-color-scheme: dark)") : null;

function load(key, def) { try { return localStorage.getItem(key) ?? def; } catch { return def; } }
function save(key, v) { try { localStorage.setItem(key, v); } catch { /* browser storage is blocked; this applies to the current session only */ } }

let state = { pref: load(KEY_THEME, "system"), pinned: load(KEY_PIN, "1") !== "0" };
const resolve = (pref) => (pref === "dark" || (pref === "system" && mql && mql.matches) ? "dark" : "light");
state.theme = resolve(state.pref);

function apply() {
  const el = document.documentElement;
  el.dataset.theme = state.theme;
  el.style.colorScheme = state.theme;          // the browser scrollbar, form controls, and date picker follow the selected theme
}
function emit(next) { state = { ...state, ...next }; state.theme = resolve(state.pref); apply(); listeners.forEach((l) => l()); }

if (typeof document !== "undefined") apply();
if (mql) mql.addEventListener?.("change", () => state.pref === "system" && emit({}));

export function setThemePref(pref) { save(KEY_THEME, pref); emit({ pref }); }
export function setPinned(pinned) { save(KEY_PIN, pinned ? "1" : "0"); emit({ pinned }); }

const subscribe = (l) => { listeners.add(l); return () => listeners.delete(l); };
export function useUi() {
  return useSyncExternalStore(subscribe, () => state);
}

// ECharts chart colors (CSS variables are not directly readable) — read from the current theme variables
export function chartColors() {
  const cs = getComputedStyle(document.documentElement);
  const v = (n) => cs.getPropertyValue(n).trim();
  return {
    dark: state.theme === "dark",
    text: v("--text"), text2: v("--text-2"), muted: v("--muted"), faint: v("--faint"),
    line: v("--line"), edge: v("--border-strong"), panel: v("--panel"), accent: v("--accent"), failInk: v("--fail-ink"),
    tooltip: { backgroundColor: v("--panel"), borderColor: v("--border"), textStyle: { color: v("--text"), fontSize: 12 } },
    axis: { axisLabel: { color: v("--muted"), fontSize: 10 }, axisLine: { lineStyle: { color: v("--border-strong") } } },
  };
}
