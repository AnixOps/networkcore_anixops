import { getCurrentWindow } from "@tauri-apps/api/window";
import { useEffect, useState } from "react";

// Colors live in styles.css as CSS variables; they mirror apps/ios/Design/tokens.json.
export type Appearance = "system" | "light" | "dark" | "oled";
export type Theme = "light" | "dark" | "oled";

export const appearances: Array<{ value: Appearance; label: string }> = [
  { value: "system", label: "跟随系统" },
  { value: "light", label: "浅色" },
  { value: "dark", label: "深色" },
  { value: "oled", label: "纯黑" },
];

const storageKey = "anixops.appearance";

export function resolveTheme(appearance: Appearance, prefersDark: boolean): Theme {
  if (appearance === "system") return prefersDark ? "dark" : "light";
  return appearance;
}

function loadAppearance(): Appearance {
  try {
    const stored = window.localStorage.getItem(storageKey);
    if (stored && appearances.some((option) => option.value === stored)) return stored as Appearance;
  } catch {
    // Storage can be unavailable; fall back to the system appearance.
  }
  return "system";
}

/** Keeps the page theme and the native title bar in step with the chosen appearance and the system setting. */
export function useAppearance(): [Appearance, (next: Appearance) => void, Theme] {
  const [appearance, setAppearance] = useState<Appearance>(loadAppearance);
  const [prefersDark, setPrefersDark] = useState(() => window.matchMedia("(prefers-color-scheme: dark)").matches);
  const theme = resolveTheme(appearance, prefersDark);

  useEffect(() => {
    const query = window.matchMedia("(prefers-color-scheme: dark)");
    const update = (event: MediaQueryListEvent) => setPrefersDark(event.matches);
    query.addEventListener("change", update);
    return () => query.removeEventListener("change", update);
  }, []);

  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    const native = appearance === "system" ? null : appearance === "light" ? "light" : "dark";
    void getCurrentWindow().setTheme(native).catch(() => undefined);
  }, [theme, appearance]);

  const choose = (next: Appearance) => {
    setAppearance(next);
    try {
      window.localStorage.setItem(storageKey, next);
    } catch {
      // The choice still applies for this session.
    }
  };

  return [appearance, choose, theme];
}
