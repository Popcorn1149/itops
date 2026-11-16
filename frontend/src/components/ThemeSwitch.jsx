import React from "react";
import { Sun, Moon, Laptop } from "lucide-react";
import { useUi, setThemePref } from "../theme";

const THEMES = [["light", Sun, "Light"], ["dark", Moon, "Dark"], ["system", Laptop, "System"]];

export default function ThemeSwitch() {
  const { pref } = useUi();
  return (
    <div className="theme-seg" role="radiogroup" aria-label="Appearance">
      {THEMES.map(([k, I, label]) => (
        <button key={k} className={pref === k ? "on" : ""} title={`Appearance: ${label}`} aria-label={label} aria-checked={pref === k} role="radio"
          onClick={() => setThemePref(k)}><I size={15} /></button>
      ))}
    </div>
  );
}

