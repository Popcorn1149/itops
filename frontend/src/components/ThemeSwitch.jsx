import React from "react";
import { Sun, Moon, Laptop } from "lucide-react";
import { useUi, setThemePref } from "../theme";

const THEMES = [["light", Sun, "Sáng"], ["dark", Moon, "Tối"], ["system", Laptop, "Theo hệ thống"]];

export default function ThemeSwitch() {
  const { pref } = useUi();
  return (
    <div className="theme-seg" role="radiogroup" aria-label="Giao diện">
      {THEMES.map(([k, I, label]) => (
        <button key={k} className={pref === k ? "on" : ""} title={`Giao diện: ${label}`} aria-label={label} aria-checked={pref === k} role="radio"
          onClick={() => setThemePref(k)}><I size={15} /></button>
      ))}
    </div>
  );
}

