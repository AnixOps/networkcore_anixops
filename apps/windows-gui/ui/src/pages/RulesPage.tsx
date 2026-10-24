import { Check, Layers, RefreshCw, Route } from "lucide-react";
import { useEffect, useState } from "react";
import { desktop, NativeGroupSummary, RuntimeSnapshot } from "../bridge";
import { routingModes } from "../labels";
import { Card, EmptyState, Run, StatusPill } from "../ui";
import { t } from "../i18n";

export function RulesPage({ snapshot, busy, run }: { snapshot: RuntimeSnapshot | null; busy: string | null; run: Run }) {
  if (snapshot?.platform === "linux") {
    return (
      <Card>
        <EmptyState icon={Route} title={t("分流规则还没开放")} message={t("Linux 版目前把全部流量交给所选节点；分流模式、策略组和 DNS 会在后续版本提供。")} />
      </Card>
    );
  }
  return (
    <div className="page-stack">
      <Card
        title={t("分流模式")}
        description={t("规则资源从公开来源缓存到本机，下次连接时生效。")}
        actions={<button className="secondary" disabled={Boolean(busy)} onClick={() => void run("routing rules", desktop.refreshRoutingRules)}><RefreshCw size={15} />{t("刷新规则资源")}</button>}
      >
        <div className="mode-grid" role="radiogroup" aria-label={t("分流模式")}>
          {routingModes.map((mode) => {
            const selected = snapshot?.routingMode === mode.value;
            return (
              <button
                key={mode.value}
                role="radio"
                aria-checked={selected}
                className={`mode-card ${selected ? "selected" : ""}`}
                disabled={Boolean(busy) || !snapshot}
                onClick={() => void run("routing", () => desktop.setRoutingMode(mode.value))}
              >
                <span className="mode-title">{t(mode.label)}{selected && <Check size={16} />}</span>
                <small>{t(mode.hint)}</small>
              </button>
            );
          })}
        </div>
      </Card>
      <PolicyGroups busy={busy} run={run} />
      <DnsCard snapshot={snapshot} busy={busy} run={run} />
    </div>
  );
}

/** The profile's native outbound groups: pick a selector's default, or edit one group's JSON. */
function PolicyGroups({ busy, run }: { busy: string | null; run: Run }) {
  const [groups, setGroups] = useState<NativeGroupSummary[]>([]);
  const [editing, setEditing] = useState<string | null>(null);
  const [json, setJson] = useState("");

  useEffect(() => {
    void desktop.nativeGroups().then(setGroups).catch(() => setGroups([]));
  }, []);

  return (
    <Card
      title={t("策略组")}
      description={t("为手动选择的策略组设定默认出口，或单独编辑某个策略组，不会替换整个配置。")}
      actions={<StatusPill label={groups.length ? t("{count} 个策略组", { count: groups.length }) : t("没有策略组")} tone={groups.length ? "success" : "neutral"} />}
    >
      {groups.length === 0
        ? <p className="muted">{t("当前配置里没有策略组。")}</p>
        : <ul className="list groups">
          {groups.map((group) => (
            <li key={group.tag}>
              <Layers size={16} className="list-icon" />
              <span className="list-main"><strong>{group.tag}</strong><small>{group.groupType === "selector" ? t("手动选择") : group.groupType === "urltest" ? t("自动测速") : group.groupType}{group.selected ? ` · ${group.selected}` : ""}</small></span>
              <div className="group-options">
                {group.groupType === "selector" && group.outbounds.map((outbound) => (
                  <button
                    key={outbound}
                    className={`chip-button ${group.selected === outbound ? "selected" : ""}`}
                    aria-pressed={group.selected === outbound}
                    disabled={Boolean(busy) || group.selected === outbound}
                    onClick={() => void run("native selector", async () => {
                      const result = await desktop.selectNativeGroupOutbound(group.tag, outbound);
                      setGroups((current) => current.map((item) => item.tag === group.tag ? { ...item, selected: outbound } : item));
                      return result;
                    })}
                  >
                    {outbound}
                  </button>
                ))}
                <button className="secondary compact" disabled={Boolean(busy)} onClick={() => { setEditing(group.tag); setJson(group.json); }}>{t("编辑 JSON")}</button>
              </div>
            </li>
          ))}
        </ul>}
      {editing && (
        <div className="editor">
          <label className="field"><span>{t("策略组 {name} 的 JSON", { name: editing })}</span>
            <textarea spellCheck={false} value={json} onChange={(event) => setJson(event.target.value)} />
          </label>
          <div className="button-row">
            <button className="primary" disabled={Boolean(busy) || !json.trim()} onClick={() => void run("native group", async () => {
              const result = await desktop.replaceNativeGroup(editing, json);
              const next = await desktop.nativeGroups();
              setGroups(next);
              setJson(next.find((group) => group.tag === editing)?.json ?? json);
              return result;
            })}>{t("保存")}</button>
            <button className="secondary" disabled={Boolean(busy)} onClick={() => { setEditing(null); setJson(""); }}>{t("关闭")}</button>
          </div>
        </div>
      )}
    </Card>
  );
}

function DnsCard({ snapshot, busy, run }: { snapshot: RuntimeSnapshot | null; busy: string | null; run: Run }) {
  const [dns, setDns] = useState("");
  return (
    <Card
      title="DNS"
      description={t("为已停止的当前配置写入自定义 DNS 段。")}
      actions={<StatusPill label={snapshot?.dnsConfigured ? t("已配置") : t("未配置")} tone={snapshot?.dnsConfigured ? "success" : "neutral"} />}
    >
      <label className="field"><span>DNS JSON</span>
        <textarea spellCheck={false} placeholder='{ "servers": [ ... ] }' value={dns} onChange={(event) => setDns(event.target.value)} />
      </label>
      <div className="button-row">
        <button className="primary" disabled={Boolean(busy) || !dns.trim()} onClick={() => void run("dns", () => desktop.configureDns(dns))}>{t("保存 DNS")}</button>
        <button className="secondary" disabled={Boolean(busy)} onClick={() => void run("dns", desktop.clearDns)}>{t("清除 DNS")}</button>
      </div>
    </Card>
  );
}
