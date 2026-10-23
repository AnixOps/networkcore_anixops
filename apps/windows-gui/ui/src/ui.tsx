import { LoaderCircle } from "lucide-react";
import type { LucideIcon } from "lucide-react";
import type { ReactNode } from "react";
import type { Tone } from "./bridge";

/** Runs one named operation, shows its result message and refreshes the runtime state. */
export type Run = (operation: string, task: () => Promise<{ message: string }>) => Promise<void>;

export function Card({ title, description, actions, children, className = "" }: {
  title?: string;
  description?: string;
  actions?: ReactNode;
  children?: ReactNode;
  className?: string;
}) {
  return (
    <section className={`card ${className}`}>
      {(title || actions) && (
        <header className="card-header">
          <div>
            {title && <h2>{title}</h2>}
            {description && <p>{description}</p>}
          </div>
          {actions && <div className="card-actions">{actions}</div>}
        </header>
      )}
      {children}
    </section>
  );
}

export function StatusDot({ tone }: { tone: Tone | string }) {
  return <i className={`status-dot ${tone}`} aria-hidden="true" />;
}

export function StatusPill({ label, tone }: { label: string; tone: Tone | string }) {
  return <span className={`status-pill ${tone}`}><StatusDot tone={tone} />{label}</span>;
}

export function IconButton({ label, children, onClick, disabled = false }: {
  label: string;
  children: ReactNode;
  onClick: () => void;
  disabled?: boolean;
}) {
  return <button className="icon-button" title={label} aria-label={label} onClick={onClick} disabled={disabled}>{children}</button>;
}

export function ToggleRow({ label, hint, checked, onChange, disabled = false }: {
  label: string;
  hint?: string;
  checked: boolean;
  onChange: () => void;
  disabled?: boolean;
}) {
  return (
    <label className="toggle-row">
      <span><strong>{label}</strong>{hint && <small>{hint}</small>}</span>
      <input type="checkbox" role="switch" checked={checked} onChange={onChange} disabled={disabled} />
      <i aria-hidden="true" />
    </label>
  );
}

export function Segmented<T extends string>({ label, options, value, onChange, disabled = false, className = "" }: {
  label: string;
  options: Array<{ value: T; label: string }>;
  value: T | undefined;
  onChange: (value: T) => void;
  disabled?: boolean;
  className?: string;
}) {
  return (
    <div className={`segmented ${className}`} role="radiogroup" aria-label={label} style={{ gridTemplateColumns: `repeat(${options.length}, minmax(0, 1fr))` }}>
      {options.map((option) => (
        <button
          key={option.value}
          role="radio"
          aria-checked={value === option.value}
          className={value === option.value ? "selected" : ""}
          disabled={disabled}
          onClick={() => onChange(option.value)}
        >
          {option.label}
        </button>
      ))}
    </div>
  );
}

export function Field({ label, children }: { label: string; children: ReactNode }) {
  return <label className="field"><span>{label}</span>{children}</label>;
}

export function EmptyState({ icon: Icon, title, message, children }: {
  icon: LucideIcon;
  title: string;
  message: string;
  children?: ReactNode;
}) {
  return (
    <div className="empty-state">
      <div className="empty-icon"><Icon size={26} strokeWidth={1.6} /></div>
      <strong>{title}</strong>
      <p>{message}</p>
      {children}
    </div>
  );
}

export function Loading() {
  return <div className="loading"><LoaderCircle className="spin" size={20} />正在读取客户端状态</div>;
}

export function Detail({ term, value }: { term: string; value: string }) {
  return <div><dt>{term}</dt><dd>{value}</dd></div>;
}
