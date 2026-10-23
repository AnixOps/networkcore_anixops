import { BadgeCheck, CheckCircle2, CloudDownload, Cpu, RotateCcw } from "lucide-react";
import { useState } from "react";
import { desktop, Preferences, preferencesFrom, RuntimeSnapshot } from "../bridge";
import { Appearance, appearances } from "../theme";
import { Card, Field, Loading, Run, Segmented, ToggleRow } from "../ui";

type StartupKey = "startAfterLogin" | "autoConnect" | "autoRecoverCore" | "autoSubscriptionRefresh" | "autoSelectFastestNode";

const startupOptions: Array<{ key: StartupKey; label: string; hint?: string }> = [
  { key: "startAfterLogin", label: "登录 Windows 后启动" },
  { key: "autoConnect", label: "启动后自动连接" },
  { key: "autoRecoverCore", label: "内核意外退出时自动恢复一次", hint: "只恢复由本应用启动的内核" },
  { key: "autoSubscriptionRefresh", label: "每小时自动更新订阅" },
  { key: "autoSelectFastestNode", label: "每 30 分钟自动选择最快节点" },
];

export function SettingsPage({ snapshot, busy, run, appearance, setAppearance }: {
  snapshot: RuntimeSnapshot | null;
  busy: string | null;
  run: Run;
  appearance: Appearance;
  setAppearance: (value: Appearance) => void;
}) {
  if (!snapshot) return <Loading />;
  const save = (changes: Partial<Preferences>) => void run("preferences", () => desktop.savePreferences(preferencesFrom(snapshot, changes)));

  return (
    <div className="page-stack">
      <div className="two-column">
        <Card title="外观" description="纯黑主题适合 OLED 屏幕。">
          <Segmented label="外观" options={appearances} value={appearance} onChange={setAppearance} />
        </Card>
        <Card title="运行方式" description="桌面模式只为当前用户运行内核；TUN、附加协议内核和 HTTPS 解密需要 Windows 服务模式。">
          <Segmented
            label="运行方式"
            options={[{ value: "desktop", label: "桌面模式" }, { value: "service", label: "Windows 服务" }]}
            value={snapshot.runtimeMode}
            disabled={Boolean(busy)}
            onChange={(runtimeMode) => save({ runtimeMode })}
          />
        </Card>
      </div>

      <Card title="启动与自动化">
        {startupOptions.map((option) => (
          <ToggleRow
            key={option.key}
            label={option.label}
            hint={option.hint}
            checked={snapshot[option.key]}
            disabled={Boolean(busy)}
            onChange={() => save({ [option.key]: !snapshot[option.key] } as Partial<Preferences>)}
          />
        ))}
      </Card>

      <div className="two-column">
        <Card title="代理内核" description="安装并校验内核后再导入配置。">
          <div className="button-row">
            <button className="primary" disabled={Boolean(busy)} onClick={() => void run("core", desktop.installCore)}><Cpu size={16} />安装内核</button>
            <button className="secondary" disabled={Boolean(busy)} onClick={() => void run("validate", desktop.validate)}><BadgeCheck size={16} />校验配置</button>
            <button className="secondary" disabled={Boolean(busy)} onClick={() => void run("restart", desktop.restart)}><RotateCcw size={16} />重启{snapshot.runtimeMode === "desktop" ? "内核" : "服务"}</button>
          </div>
        </Card>
        <ServiceCard busy={busy} run={run} />
      </div>

      <ExternalCoreCard busy={busy} run={run} />
      <SystemCard busy={busy} run={run} />
    </div>
  );
}

function ServiceCard({ busy, run }: { busy: string | null; run: Run }) {
  return (
    <Card title="Windows 服务" description="管理已安装的 AnixOps Net 服务。">
      <div className="button-row">
        <button className="secondary" disabled={Boolean(busy)} onClick={() => void run("service", desktop.installService)}>安装</button>
        <button className="secondary" disabled={Boolean(busy)} onClick={() => void run("service", desktop.startService)}>启动</button>
        <button className="secondary" disabled={Boolean(busy)} onClick={() => void run("service", desktop.stopService)}>停止</button>
      </div>
    </Card>
  );
}

/** The optional external Mieru core, installed from an official release asset and pinned by digest. */
function ExternalCoreCard({ busy, run }: { busy: string | null; run: Run }) {
  const [url, setUrl] = useState("");
  const [path, setPath] = useState("");
  const [sha256, setSha256] = useState("");
  return (
    <Card title="附加协议内核" description="Mieru 节点需要单独的内核。填写官方发布页的下载地址和 SHA-256，校验通过才会安装。">
      <div className="field-grid">
        <Field label="官方下载地址"><input value={url} onChange={(event) => setUrl(event.target.value)} /></Field>
        <Field label="安装位置"><input value={path} onChange={(event) => setPath(event.target.value)} /></Field>
        <Field label="SHA-256"><input spellCheck={false} value={sha256} onChange={(event) => setSha256(event.target.value)} /></Field>
      </div>
      <div className="button-row">
        <button className="primary" disabled={Boolean(busy) || !url || !path || !sha256} onClick={() => void run("mieru install", () => desktop.installMieru(url, path, sha256))}><CloudDownload size={16} />下载并安装</button>
        <button className="secondary" disabled={Boolean(busy) || !path || !sha256} onClick={() => void run("mieru verify", () => desktop.verifyMieru(path, sha256))}><CheckCircle2 size={16} />校验已安装的文件</button>
      </div>
    </Card>
  );
}

function SystemCard({ busy, run }: { busy: string | null; run: Run }) {
  const [driverPath, setDriverPath] = useState("");
  const [tunnel, setTunnel] = useState("");
  return (
    <Card className="caution" title="系统与网络" description="这些操作会改动系统设置，只填写你确认过的本地文件。">
      <Field label="驱动 INF 路径"><input value={driverPath} onChange={(event) => setDriverPath(event.target.value)} /></Field>
      <div className="button-row">
        <button className="secondary" disabled={Boolean(busy) || !driverPath.trim()} onClick={() => void run("driver", () => desktop.installDriver(driverPath.trim()))}>安装驱动</button>
        <button className="secondary" disabled={Boolean(busy)} onClick={() => void run("driver", desktop.removeDriver)}>移除驱动</button>
      </div>
      <Field label="TUN 配置 JSON">
        <textarea spellCheck={false} value={tunnel} onChange={(event) => setTunnel(event.target.value)} />
      </Field>
      <div className="button-row">
        <button className="primary" disabled={Boolean(busy) || !tunnel.trim()} onClick={() => void run("tunnel", () => desktop.configureTunnel(tunnel))}>保存 TUN 配置</button>
        <button className="secondary" disabled={Boolean(busy)} onClick={() => void run("tunnel", desktop.clearTunnel)}>清除</button>
      </div>
      <div className="divider" />
      <div className="inline-action">
        <span><strong>恢复网络设置</strong><small>只恢复本应用这次改过、且仍归它管理的代理设置。</small></span>
        <button className="secondary" disabled={Boolean(busy)} onClick={() => void run("network recovery", desktop.restoreNetworkSettings)}>恢复</button>
      </div>
    </Card>
  );
}
