import { Activity, CheckCircle2, CircleAlert, Globe, House, Puzzle, RefreshCw, Route, SlidersHorizontal, X } from "lucide-react";
import type { LucideIcon } from "lucide-react";
import { useCallback, useEffect, useRef, useState } from "react";
import { desktop, NodeSummary, RuntimeSnapshot } from "./bridge";
import { Wordmark } from "./brand";
import { connectionTitle, connectPhase } from "./labels";
import { ActivityPage } from "./pages/ActivityPage";
import { ExtensionsPage } from "./pages/ExtensionsPage";
import { HomePage } from "./pages/HomePage";
import { ProxiesPage } from "./pages/ProxiesPage";
import { RulesPage } from "./pages/RulesPage";
import { SettingsPage } from "./pages/SettingsPage";
import { useAppearance } from "./theme";
import { IconButton, StatusDot } from "./ui";
import { t, useLanguage } from "./i18n";

export type Page = "home" | "proxies" | "rules" | "extensions" | "activity" | "settings";

const navigation: Array<{ page: Page; label: string; icon: LucideIcon }> = [
  { page: "home", label: "概览", icon: House },
  { page: "proxies", label: "代理", icon: Globe },
  { page: "rules", label: "规则", icon: Route },
  { page: "extensions", label: "扩展", icon: Puzzle },
  { page: "activity", label: "活动", icon: Activity },
  { page: "settings", label: "设置", icon: SlidersHorizontal },
];

interface Notice {
  text: string;
  tone: "success" | "danger";
}

export function App() {
  const [page, setPage] = useState<Page>("home");
  const [snapshot, setSnapshot] = useState<RuntimeSnapshot | null>(null);
  const [nodes, setNodes] = useState<NodeSummary[]>([]);
  const [busy, setBusy] = useState<string | null>(null);
  const [notice, setNotice] = useState<Notice | null>(null);
  const [appearance, setAppearance] = useAppearance();
  const [language, setLanguage] = useLanguage();
  const noticeTimer = useRef<number>();

  const show = useCallback((text: string, tone: Notice["tone"]) => {
    window.clearTimeout(noticeTimer.current);
    setNotice({ text, tone });
    // Results fade on their own; errors stay until dismissed.
    if (tone === "success") noticeTimer.current = window.setTimeout(() => setNotice(null), 5000);
  }, []);
  const showError = useCallback((error: unknown) => show(error instanceof Error ? error.message : String(error), "danger"), [show]);

  const refresh = useCallback(async () => {
    const [nextSnapshot, nextNodes] = await Promise.all([desktop.snapshot(), desktop.nodes()]);
    setSnapshot(nextSnapshot);
    setNodes(nextNodes);
  }, []);

  useEffect(() => {
    void refresh().catch(showError);
    const timer = window.setInterval(() => void refresh().catch(showError), 2000);
    return () => window.clearInterval(timer);
  }, [refresh, showError]);

  const run = useCallback(async (operation: string, task: () => Promise<{ message: string }>) => {
    setBusy(operation);
    try {
      const result = await task();
      show(result.message, "success");
      await refresh();
    } catch (error) {
      showError(error);
    } finally {
      setBusy(null);
    }
  }, [refresh, show, showError]);

  const phase = connectPhase(snapshot?.connection, busy);
  const toggleConnection = useCallback(() => {
    if (busy || phase === "loading" || phase === "connecting" || phase === "disconnecting") return;
    if (phase === "on") void run("disconnect", desktop.disconnect);
    else void run("connect", desktop.connect);
  }, [busy, phase, run]);

  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      if (event.ctrlKey && event.shiftKey && event.key.toLowerCase() === "c") {
        event.preventDefault();
        toggleConnection();
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [toggleConnection]);

  const title = t(navigation.find((item) => item.page === page)?.label ?? "");
  const dotTone = phase === "on" ? "success" : phase === "failed" ? "danger" : phase === "connecting" || phase === "disconnecting" ? "warning" : "neutral";

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="sidebar-brand"><Wordmark /></div>
        <nav aria-label={t("主导航")}>
          {navigation.map(({ page: item, label, icon: Icon }) => (
            <button
              className={`nav-item ${page === item ? "active" : ""}`}
              key={item}
              aria-current={page === item ? "page" : undefined}
              onClick={() => setPage(item)}
            >
              <Icon size={18} strokeWidth={1.8} /><span>{t(label)}</span>
            </button>
          ))}
        </nav>
        <button className="sidebar-status" onClick={() => setPage("home")}>
          <StatusDot tone={dotTone} />
          <span>
            <strong>{connectionTitle(snapshot?.connection, phase)}</strong>
            <small>{snapshot?.runtimeMode === "service" ? t("Windows 服务模式") : t("桌面模式")}</small>
          </span>
        </button>
      </aside>
      <main className="workspace">
        <header className="topbar">
          <h1>{title}</h1>
          <IconButton label={t("刷新状态")} onClick={() => void refresh().catch(showError)}><RefreshCw size={17} /></IconButton>
        </header>
        {notice && (
          <div className={`notice ${notice.tone}`} role={notice.tone === "danger" ? "alert" : "status"}>
            {notice.tone === "danger" ? <CircleAlert size={17} /> : <CheckCircle2 size={17} />}
            <span>{notice.text}</span>
            <button aria-label={t("关闭提示")} onClick={() => setNotice(null)}><X size={15} /></button>
          </div>
        )}
        <div className="page" key={page}>
          {page === "home" && <HomePage snapshot={snapshot} nodes={nodes} phase={phase} busy={busy} run={run} toggle={toggleConnection} goTo={setPage} />}
          {page === "proxies" && <ProxiesPage snapshot={snapshot} nodes={nodes} busy={busy} run={run} />}
          {page === "rules" && <RulesPage snapshot={snapshot} busy={busy} run={run} />}
          {page === "extensions" && <ExtensionsPage snapshot={snapshot} busy={busy} run={run} />}
          {page === "activity" && <ActivityPage snapshot={snapshot} busy={busy} run={run} />}
          {page === "settings" && <SettingsPage snapshot={snapshot} busy={busy} run={run} appearance={appearance} setAppearance={setAppearance} language={language} setLanguage={setLanguage} />}
        </div>
      </main>
    </div>
  );
}
