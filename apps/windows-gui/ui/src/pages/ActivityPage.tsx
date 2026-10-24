import { ClipboardList, ListTree } from "lucide-react";
import { desktop, RuntimeSnapshot } from "../bridge";
import { Card, Detail, EmptyState, Run } from "../ui";
import { t } from "../i18n";

export function ActivityPage({ snapshot, busy, run }: { snapshot: RuntimeSnapshot | null; busy: string | null; run: Run }) {
  const refresh = snapshot?.subscriptionLastAttempt
    ? [snapshot.subscriptionRefreshResult || t("等待中"), snapshot.subscriptionLastAttempt, snapshot.subscriptionRefreshErrorCode].filter(Boolean).join(" · ")
    : t("还没有自动更新记录");

  return (
    <div className="page-stack">
      <Card title={t("当前会话")} description={t("只有独立核实过的运行状态才会显示为已连接。")}>
        <dl className="details">
          <Detail term={t("运行状态")} value={snapshot?.connectionLabel ?? t("读取中")} />
          <Detail term={t("最近错误")} value={snapshot?.lastError ?? t("无")} />
          <Detail term={t("配置校验")} value={snapshot?.configurationError ?? t("通过")} />
          <Detail term={t("订阅自动更新")} value={snapshot?.subscriptionError ?? refresh} />
        </dl>
      </Card>

      <Card
        title={t("诊断报告")}
        description={t("从受管的运行状态和日志生成一份有大小限制的报告，不包含节点密码。")}
        actions={<button className="primary" disabled={Boolean(busy)} onClick={() => void run("diagnostics", desktop.diagnostics)}><ClipboardList size={16} />{t("生成诊断报告")}</button>}
      />

      <Card>
        <EmptyState icon={ListTree} title={t("请求记录还没开放")} message={t("每条连接命中的规则、策略和插件标记需要内核提供数据，会在后续版本显示在这里。")} />
      </Card>
    </div>
  );
}
