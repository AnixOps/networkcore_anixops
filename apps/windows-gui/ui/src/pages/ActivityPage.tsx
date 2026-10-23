import { ClipboardList, ListTree } from "lucide-react";
import { desktop, RuntimeSnapshot } from "../bridge";
import { Card, Detail, EmptyState, Run } from "../ui";

export function ActivityPage({ snapshot, busy, run }: { snapshot: RuntimeSnapshot | null; busy: string | null; run: Run }) {
  const refresh = snapshot?.subscriptionLastAttempt
    ? `${snapshot.subscriptionRefreshResult || "等待中"} · ${snapshot.subscriptionLastAttempt}${snapshot.subscriptionRefreshErrorCode ? ` · ${snapshot.subscriptionRefreshErrorCode}` : ""}`
    : "还没有自动更新记录";

  return (
    <div className="page-stack">
      <Card title="当前会话" description="只有独立核实过的运行状态才会显示为已连接。">
        <dl className="details">
          <Detail term="运行状态" value={snapshot?.connectionLabel ?? "读取中"} />
          <Detail term="最近错误" value={snapshot?.lastError ?? "无"} />
          <Detail term="配置校验" value={snapshot?.configurationError ?? "通过"} />
          <Detail term="订阅自动更新" value={snapshot?.subscriptionError ?? refresh} />
        </dl>
      </Card>

      <Card
        title="诊断报告"
        description="从受管的运行状态和日志生成一份有大小限制的报告，不包含节点密码。"
        actions={<button className="primary" disabled={Boolean(busy)} onClick={() => void run("diagnostics", desktop.diagnostics)}><ClipboardList size={16} />生成诊断报告</button>}
      />

      <Card>
        <EmptyState icon={ListTree} title="请求记录还没开放" message="每条连接命中的规则、策略和插件标记需要内核提供数据，会在后续版本显示在这里。" />
      </Card>
    </div>
  );
}
