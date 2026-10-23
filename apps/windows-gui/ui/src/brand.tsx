import type { ConnectPhase } from "./labels";

// The route-line "N" from the app icon: (30,72) → (30,28) → (70,72) → (70,28) on a 100-unit grid.
const routePath = "M30 72 L30 28 L70 72 L70 28";

/** The app icon at small sizes: teal tile, light route line, amber destination dot. */
export function BrandMark({ size = 22 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 100 100" aria-hidden="true">
      <rect width="100" height="100" rx="22" fill="#0F766E" />
      <path d={routePath} fill="none" stroke="#F0FDFA" strokeWidth="11" strokeLinecap="round" strokeLinejoin="round" />
      <circle cx="70" cy="28" r="7" fill="#FBBF24" />
    </svg>
  );
}

export function Wordmark() {
  return (
    <span className="wordmark">
      <BrandMark />
      <span>AnixOps <em>Net</em></span>
    </span>
  );
}

/**
 * The connect button's route line: dashed when off, drawing in a loop while connecting,
 * solid with the amber dot lit when connected. Reduced motion stops the loop (see styles.css).
 */
export function RouteLine({ phase, size = 76 }: { phase: ConnectPhase; size?: number }) {
  const on = phase === "on";
  const moving = phase === "connecting" || phase === "disconnecting";
  return (
    <svg className={`route-line ${phase}`} width={size} height={size} viewBox="0 0 100 100" aria-hidden="true">
      <path d={routePath} className="route-track" />
      <path d={routePath} className={`route-stroke ${moving ? "drawing" : on ? "" : "dashed"}`} />
      <circle cx="30" cy="72" r="7.5" className="route-origin" />
      <circle cx="70" cy="28" r="7.5" className={`route-dot ${on ? "lit" : ""}`} />
    </svg>
  );
}
