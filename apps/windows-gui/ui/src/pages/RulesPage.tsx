import { Check, Layers, RefreshCw } from "lucide-react";
import { useEffect, useState } from "react";
import { desktop, NativeGroupSummary, RuntimeSnapshot } from "../bridge";
import { availableRoutingModes, groupMemberLabel } from "../labels";
import { Card, Run, StatusPill } from "../ui";
import { t } from "../i18n";

export function RulesPage({ snapshot, busy, run }: { snapshot: RuntimeSnapshot | null; busy: string | null; run: Run }) {
  return (
    <div className="page-stack">
      <Card
        title={t("分流模式")}
        description={t("规则资源从公开来源缓存到本机，下次连接时生效。")}
        actions={<button className="secondary" disabled={Boolean(busy)} onClick={() => void run("routing rules", desktop.refreshRoutingRules)}><RefreshCw size={15} />{t("刷新规则资源")}</button>}
      >
        <div className="mode-grid" role="radiogroup" aria-label={t("分流模式")}>
          {availableRoutingModes(snapshot).map((mode) => {
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
      <DnsCard />
    </div>
  );
}

/** The profile's policy groups: pick a selector's default. */
function PolicyGroups({ busy, run }: { busy: string | null; run: Run }) {
  const [groups, setGroups] = useState<NativeGroupSummary[]>([]);

  useEffect(() => {
    void desktop.nativeGroups().then(setGroups).catch(() => setGroups([]));
  }, []);

  return (
    <Card
      title={t("策略组")}
      description={t("为手动选择的策略组设定默认出口。")}
      actions={<StatusPill label={groups.length ? t("{count} 个策略组", { count: groups.length }) : t("没有策略组")} tone={groups.length ? "success" : "neutral"} />}
    >
      {groups.length === 0
        ? <p className="muted">{t("当前配置里没有策略组。")}</p>
        : <ul className="list groups">
          {groups.map((group) => (
            <li key={group.tag}>
              <Layers size={16} className="list-icon" />
              <span className="list-main"><strong>{group.tag}</strong><small>{group.groupType === "selector" ? t("手动选择") : group.groupType === "urltest" ? t("自动测速") : group.groupType}{group.selected ? ` · ${groupMemberLabel(group, group.selected)}` : ""}</small></span>
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
                    {groupMemberLabel(group, outbound)}
                  </button>
                ))}
              </div>
            </li>
          ))}
        </ul>}
    </Card>
  );
}

function DnsCard() {
  return (
    <Card title="DNS" actions={<StatusPill label={t("系统 DNS")} tone="success" />}>
      <p className="muted">{t("内置引擎用系统 DNS 解析规则里需要 IP 的域名；经节点的连接由节点服务器解析域名。")}</p>
    </Card>
  );
}
