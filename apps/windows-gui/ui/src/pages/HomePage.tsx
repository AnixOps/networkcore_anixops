import { Cable, ChevronRight, CloudDownload, Cpu, Gauge, Layers, ShieldCheck } from "lucide-react";
import type { LucideIcon } from "lucide-react";
import { useEffect, useState } from "react";
import type { Page } from "../App";
import { desktop, NativeGroupSummary, NodeSummary, RuntimeSnapshot, StatusFact } from "../bridge";
import { RouteLine } from "../brand";
import { ConnectPhase, connectionTitle, factLabel, routingLabel, routingModes } from "../labels";
import { Card, Run, StatusDot } from "../ui";
import { t } from "../i18n";

export function HomePage({ snapshot, nodes, phase, busy, run, toggle, goTo }: {
  snapshot: RuntimeSnapshot | null;
  nodes: NodeSummary[];
  phase: ConnectPhase;
  busy: string | null;
  run: Run;
  toggle: () => void;
  goTo: (page: Page) => void;
}) {
  const [groups, setGroups] = useState<NativeGroupSummary[]>([]);
  useEffect(() => {
    void desktop.nativeGroups().then(setGroups).catch(() => setGroups([]));
  }, [snapshot?.subscription]);

  const node = nodes.find((item) => item.id === snapshot?.selectedNode);
  const nodeName = node?.label ?? snapshot?.selectedNode;
  const unconfigured = snapshot !== null && !snapshot.subscription && nodes.length === 0;

  const subtitle = (() => {
    if (unconfigured) return t("先在“代理”里导入订阅或配置文件");
    switch (phase) {
      case "on":
        return [nodeName, routingLabel(snapshot?.routingMode), snapshot?.runtimeMode === "service" ? t("Windows 服务") : t("系统代理")].filter(Boolean).join(" · ");
      case "connecting":
        return t("正在建立安全隧道");
      case "disconnecting":
        return t("正在恢复系统代理设置");
      case "failed":
        return snapshot?.configurationError ?? snapshot?.lastError ?? t("查看“活动”了解原因");
      case "loading":
        return " ";
      default:
        return t("点击左侧按钮连接 · Ctrl+Shift+C");
    }
  })();

  const linux = snapshot?.platform === "linux";
  const label = phase === "on" ? t("断开，当前已连接") : phase === "connecting" ? t("正在连接") : unconfigured ? t("导入第一个订阅") : t("连接，当前未连接");

  return (
    <div className="page-stack">
      <section className={`hero ${phase}`}>
        <button
          className="connect-button"
          aria-label={label}
          disabled={phase === "loading" || phase === "connecting" || phase === "disconnecting"}
          onClick={unconfigured ? () => goTo("proxies") : toggle}
        >
          <RouteLine phase={phase} />
        </button>
        <div className="hero-text" aria-live="polite">
          <div className="hero-title">{connectionTitle(snapshot?.connection, phase)}</div>
          <div className="hero-subtitle">{subtitle}</div>
        </div>
        {!linux && <div className="hero-modes" role="radiogroup" aria-label={t("分流模式")}>
          {routingModes.map((mode) => (
            <button
              key={mode.value}
              role="radio"
              aria-checked={snapshot?.routingMode === mode.value}
              title={t(mode.hint)}
              className={snapshot?.routingMode === mode.value ? "selected" : ""}
              disabled={Boolean(busy) || !snapshot}
              onClick={() => void run("routing", () => desktop.setRoutingMode(mode.value))}
            >
              {t(mode.label)}
            </button>
          ))}
        </div>}
      </section>

      <div className="fact-grid">
        <FactCard icon={Gauge} title={t("当前节点")} fact={{ label: nodeName ?? t("未选择"), detail: node?.protocol, tone: node ? "success" : "neutral" }} raw onClick={() => goTo("proxies")} />
        <FactCard icon={Cpu} title={t("代理内核")} fact={snapshot ? { ...snapshot.core, detail: undefined } : undefined} />
        <FactCard icon={ShieldCheck} title={t("系统代理")} fact={snapshot?.proxy} />
        {linux
          ? <FactCard icon={Cable} title={t("本地代理")} fact={snapshot ? { label: snapshot.core.detail ?? t("未启动"), detail: t("SOCKS5 / HTTP"), tone: snapshot.core.detail ? "success" : "neutral" } : undefined} raw />
          : <FactCard icon={Cable} title={t("Windows 服务")} fact={snapshot ? { ...snapshot.service, detail: snapshot.runtimeMode === "desktop" ? t("桌面模式不需要服务") : snapshot.service.detail } : undefined} />}
      </div>

      <div className="two-column">
        {!linux && <Card title={t("策略组")} actions={<button className="link-button" onClick={() => goTo("rules")}>{t("管理")}<ChevronRight size={15} /></button>}>
          {groups.length === 0
            ? <p className="muted">{t("当前配置里没有策略组。")}</p>
            : <ul className="list">{groups.slice(0, 4).map((group) => (
              <li key={group.tag}>
                <Layers size={16} className="list-icon" />
                <span className="list-main"><strong>{group.tag}</strong><small>{group.groupType === "selector" ? t("手动选择") : group.groupType === "urltest" ? t("自动测速") : group.groupType}</small></span>
                {group.selected && <span className="chip">{group.selected}</span>}
              </li>
            ))}</ul>}
        </Card>}
        <Card title={t("订阅")} actions={<button className="link-button" onClick={() => goTo("proxies")}>{t("管理")}<ChevronRight size={15} /></button>}>
          {snapshot?.subscription
            ? <ul className="list">
              <li>
                <CloudDownload size={16} className="list-icon" />
                <span className="list-main"><strong className="truncate">{snapshot.subscription}</strong><small>{snapshot.subscriptionLastUpdated ? t("上次更新 {time}", { time: snapshot.subscriptionLastUpdated }) : t("尚未成功更新")}</small></span>
              </li>
              <li>
                <span className="list-main"><strong>{t("{count} 个节点", { count: nodes.length })}</strong><small>{snapshot.autoSubscriptionRefresh ? t("每小时自动更新") : t("自动更新已关闭")}</small></span>
                {snapshot.subscription.startsWith("http") && (
                  <button className="secondary compact" disabled={Boolean(busy)} onClick={() => void run("subscription", desktop.updateSubscription)}>{t("立即更新")}</button>
                )}
              </li>
            </ul>
            : <p className="muted">{t("还没有订阅。导入后节点会出现在“代理”里。")}</p>}
        </Card>
      </div>
    </div>
  );
}

function FactCard({ icon: Icon, title, fact, raw = false, onClick }: {
  icon: LucideIcon;
  title: string;
  fact?: StatusFact;
  raw?: boolean;
  onClick?: () => void;
}) {
  const content = (
    <>
      <div className="fact-head"><Icon size={16} /><span>{title}</span><StatusDot tone={fact?.tone ?? "neutral"} /></div>
      <strong className="truncate">{raw ? fact?.label : factLabel(fact?.label)}</strong>
      {fact?.detail && <small className="truncate" title={fact.detail}>{fact.detail}</small>}
    </>
  );
  return onClick
    ? <button className="fact-card interactive" onClick={onClick}>{content}</button>
    : <section className="fact-card">{content}</section>;
}
