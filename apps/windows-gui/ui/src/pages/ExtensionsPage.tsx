import { FileCode2, KeyRound, ShieldAlert } from "lucide-react";
import { useState } from "react";
import { desktop, preferencesFrom, RuntimeSnapshot } from "../bridge";
import { Card, Field, Run, StatusPill, ToggleRow } from "../ui";

export function ExtensionsPage({ snapshot, busy, run }: { snapshot: RuntimeSnapshot | null; busy: string | null; run: Run }) {
  const [certificatePath, setCertificatePath] = useState("");
  const [scriptRuntime, setScriptRuntime] = useState("");

  return (
    <div className="page-stack">
      <Card
        className="caution"
        title="HTTPS 解密"
        description="让当前配置经过本机的 HTTPS 代理，插件才能改写网页请求。原配置会保留，关闭后恢复。"
        actions={<ShieldAlert size={20} className="caution-icon" />}
      >
        <ToggleRow
          label="屏蔽哔哩哔哩网页版推广请求（试用）"
          hint="改动后需要重新开启 HTTPS 解密才会生效"
          checked={Boolean(snapshot?.bilibiliWebAdBlockEnabled)}
          disabled={Boolean(busy) || !snapshot}
          onChange={() => void run("Bilibili web trial", async () => {
            if (!snapshot) throw new Error("还没有读取到客户端状态。");
            await desktop.savePreferences(preferencesFrom(snapshot, { bilibiliWebAdBlockEnabled: !snapshot.bilibiliWebAdBlockEnabled }));
            return { message: "已保存。重新开启 HTTPS 解密后生效。" };
          })}
        />
        <div className="button-row">
          <button className="primary" disabled={Boolean(busy)} onClick={() => void run("mitm", desktop.enableHttpsMitm)}>开启 HTTPS 解密</button>
          <button className="secondary" disabled={Boolean(busy)} onClick={() => void run("mitm", desktop.disableHttpsMitm)}>关闭</button>
        </div>
      </Card>

      <div className="two-column">
        <Card title="根证书" description="HTTPS 解密需要系统信任本机生成的根证书。只填写你自己的证书文件路径。" actions={<KeyRound size={20} className="muted-icon" />}>
          <Field label="证书 PEM 路径">
            <input placeholder={"C:\\certs\\ca.pem"} value={certificatePath} onChange={(event) => setCertificatePath(event.target.value)} />
          </Field>
          <div className="button-row">
            <button className="secondary" disabled={Boolean(busy) || !certificatePath.trim()} onClick={() => void run("certificate", () => desktop.installCertificate(certificatePath.trim()))}>安装证书</button>
            <button className="secondary" disabled={Boolean(busy)} onClick={() => void run("certificate", desktop.removeCertificate)}>移除证书</button>
          </div>
        </Card>

        <Card
          title="脚本"
          description="把插件脚本地址映射到本机脚本文件，供 HTTPS 解密时运行。"
          actions={<StatusPill label={snapshot?.scriptRuntimeConfigured ? "已配置" : "未配置"} tone={snapshot?.scriptRuntimeConfigured ? "success" : "neutral"} />}
        >
          <Field label="脚本运行时 JSON">
            <textarea spellCheck={false} value={scriptRuntime} onChange={(event) => setScriptRuntime(event.target.value)} />
          </Field>
          <div className="button-row">
            <button className="primary" disabled={Boolean(busy) || !scriptRuntime.trim()} onClick={() => void run("script runtime", () => desktop.configureScriptRuntime(scriptRuntime))}>保存</button>
            <button className="secondary" disabled={Boolean(busy)} onClick={() => void run("script runtime", desktop.clearScriptRuntime)}>清除</button>
          </div>
        </Card>
      </div>

      <p className="footnote"><FileCode2 size={14} />插件市场和一键导入插件会在后续版本开放。</p>
    </div>
  );
}
