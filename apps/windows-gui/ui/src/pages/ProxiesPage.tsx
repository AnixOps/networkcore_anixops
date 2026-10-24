import { Activity, CloudDownload, Globe, Search, Trash2, Zap } from "lucide-react";
import { useEffect, useState } from "react";
import { desktop, NodeSummary, RuntimeSnapshot, SubscriptionSummary } from "../bridge";
import { protocolAbbreviation } from "../labels";
import { filterNodes } from "../node-filter";
import { Card, EmptyState, IconButton, Run, StatusPill } from "../ui";
import { t } from "../i18n";

export function ProxiesPage({ snapshot, nodes, busy, run }: {
  snapshot: RuntimeSnapshot | null;
  nodes: NodeSummary[];
  busy: string | null;
  run: Run;
}) {
  const [query, setQuery] = useState("");
  const [protocol, setProtocol] = useState("All");
  const protocols = ["All", ...new Set(nodes.map((node) => node.protocol))];
  const visible = filterNodes(nodes, query, protocol);

  return (
    <div className="page-stack">
      {nodes.length > 0 && (
        <Card
          title={t("节点")}
          description={t("切换节点会先校验生成的配置，再应用到当前连接。")}
          actions={<button className="secondary" disabled={Boolean(busy)} onClick={() => void run("fastest node", desktop.selectFastestNode)}><Zap size={15} />{t("选择最快")}</button>}
        >
          <div className="toolbar">
            <label className="search">
              <Search size={15} aria-hidden="true" />
              <input aria-label={t("搜索节点")} placeholder={t("搜索节点")} value={query} onChange={(event) => setQuery(event.target.value)} />
            </label>
            <div className="chips" role="radiogroup" aria-label={t("按协议筛选")}>
              {protocols.map((value) => (
                <button key={value} role="radio" aria-checked={protocol === value} className={`chip-button ${protocol === value ? "selected" : ""}`} onClick={() => setProtocol(value)}>
                  {value === "All" ? t("全部") : protocolAbbreviation(value)}
                </button>
              ))}
            </div>
            <span className="count">{visible.length} / {nodes.length}</span>
          </div>
          <div className="node-grid">
            {visible.map((node) => (
              <div className={`node-card ${node.selected ? "selected" : ""}`} key={node.id}>
                <button
                  className="node-pick"
                  aria-pressed={node.selected}
                  disabled={Boolean(busy) || node.selected}
                  onClick={() => void run("switch", () => desktop.switchNode(node.id))}
                >
                  <span className="node-name">{node.label}</span>
                  <span className="node-meta"><span className="protocol-badge">{protocolAbbreviation(node.protocol)}</span>{node.selected && <span className="current-dot" aria-label={t("当前节点")} />}</span>
                </button>
                <IconButton label={t("测试 {node} 的延迟", { node: node.label })} disabled={Boolean(busy)} onClick={() => void run("delay", () => desktop.testDelay(node.id, delayUrl))}>
                  <Activity size={15} />
                </IconButton>
              </div>
            ))}
          </div>
          {visible.length === 0 && <p className="muted center">{t("没有符合条件的节点。")}</p>}
        </Card>
      )}
      <Subscriptions snapshot={snapshot} empty={nodes.length === 0} busy={busy} run={run} />
    </div>
  );
}

const delayUrl = "https://www.gstatic.com/generate_204";

function Subscriptions({ snapshot, empty, busy, run }: { snapshot: RuntimeSnapshot | null; empty: boolean; busy: string | null; run: Run }) {
  const [location, setLocation] = useState("");
  const [sources, setSources] = useState<SubscriptionSummary[]>([]);
  const refreshSources = () => void desktop.subscriptions().then(setSources).catch(() => setSources([]));
  useEffect(refreshSources, [snapshot?.subscription]);

  const importSource = () => void run("subscription", async () => {
    const result = await desktop.importSubscription(location.trim());
    setLocation("");
    refreshSources();
    return result;
  });

  const refreshDetail = snapshot?.subscriptionError
    ?? (snapshot?.subscriptionLastAttempt
      ? [
        t("上次尝试 {time}", { time: snapshot.subscriptionLastAttempt }),
        t("新增 {count}", { count: snapshot.subscriptionAddedNodeCount }),
        t("移除 {count}", { count: snapshot.subscriptionRemovedNodeCount }),
        t("变更 {count}", { count: snapshot.subscriptionChangedNodeCount }),
        snapshot.subscriptionNextAttempt ? t("下次 {time}", { time: snapshot.subscriptionNextAttempt }) : null,
      ].filter(Boolean).join(" · ")
      : null);

  const form = (
    <div className="import-row">
      <input
        aria-label={t("订阅链接或配置文件路径")}
        placeholder={t("https:// 订阅链接，或本地配置文件路径")}
        value={location}
        onChange={(event) => setLocation(event.target.value)}
        onKeyDown={(event) => { if (event.key === "Enter" && location.trim() && !busy) importSource(); }}
      />
      <button className="primary" disabled={Boolean(busy) || !location.trim()} onClick={importSource}><CloudDownload size={16} />{t("导入")}</button>
    </div>
  );

  if (empty && sources.length === 0) {
    return (
      <Card>
        <EmptyState icon={Globe} title={t("还没有节点")} message={t("粘贴订阅链接，或填写本地配置文件的路径。导入后可以在这里切换节点和测速。")}>
          {form}
        </EmptyState>
      </Card>
    );
  }

  return (
    <Card
      title={t("订阅")}
      description={refreshDetail ?? t("支持 HTTPS 订阅链接和本地配置文件。")}
      actions={<>
        <button className="secondary" disabled={Boolean(busy) || !snapshot?.subscription?.startsWith("http")} onClick={() => void run("subscription", desktop.updateSubscription)}>{t("更新当前订阅")}</button>
        <button className="secondary" disabled={Boolean(busy) || !snapshot?.subscription} onClick={() => void run("selector", desktop.checkProfileRuntime)}>{t("检查配置")}</button>
      </>}
    >
      {form}
      {sources.length > 0 && (
        <ul className="list sources">
          {sources.map((source) => (
            <li key={source.id}>
              <CloudDownload size={16} className="list-icon" />
              <span className="list-main">
                <strong className="truncate" title={source.location}>{source.location}</strong>
                <small>{source.lastSuccessfulUpdate ? t("更新于 {time}", { time: source.lastSuccessfulUpdate }) : source.lastAttempt ? t("尝试于 {time}", { time: source.lastAttempt }) : t("从未更新")}{source.lastUpdateError ? ` · ${source.lastUpdateError}` : ""}</small>
              </span>
              <StatusPill label={source.selected ? t("使用中") : source.result === "failed" ? t("更新失败") : t("已保存")} tone={source.selected ? "success" : source.result === "failed" ? "danger" : "neutral"} />
              <button className="secondary compact" disabled={Boolean(busy) || source.selected} onClick={() => void run("subscription", () => desktop.selectSubscription(source.id))}>{t("使用")}</button>
              <IconButton label={t("删除 {name}", { name: source.location })} disabled={Boolean(busy)} onClick={() => void run("subscription", async () => {
                const result = await desktop.removeSubscription(source.id);
                refreshSources();
                return result;
              })}><Trash2 size={15} /></IconButton>
            </li>
          ))}
        </ul>
      )}
    </Card>
  );
}
