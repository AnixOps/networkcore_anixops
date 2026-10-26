import { BadgeCheck, RotateCcw } from "lucide-react";
import { useState } from "react";
import { desktop, Preferences, preferencesFrom, RuntimeSnapshot } from "../bridge";
import { Appearance, appearances } from "../theme";
import { Card, Field, Loading, Run, Segmented, ToggleRow } from "../ui";
import { LanguageChoice, languages, t } from "../i18n";

type StartupKey = "startAfterLogin" | "autoConnect" | "autoRecoverCore" | "autoSubscriptionRefresh" | "autoSelectFastestNode";

const startupOptions: Array<{ key: StartupKey; label: string; hint?: string }> = [
  { key: "startAfterLogin", label: "登录 Windows 后启动" },
  { key: "autoConnect", label: "启动后自动连接" },
  { key: "autoRecoverCore", label: "内核意外退出时自动恢复一次", hint: "只恢复由本应用启动的内核" },
  { key: "autoSubscriptionRefresh", label: "每小时自动更新订阅" },
  { key: "autoSelectFastestNode", label: "每 30 分钟自动选择最快节点" },
];

export function SettingsPage({ snapshot, busy, run, appearance, setAppearance, language, setLanguage }: {
  snapshot: RuntimeSnapshot | null;
  busy: string | null;
  run: Run;
  appearance: Appearance;
  setAppearance: (value: Appearance) => void;
  language: LanguageChoice;
  setLanguage: (value: LanguageChoice) => void;
}) {
  if (!snapshot) return <Loading />;
  const save = (changes: Partial<Preferences>) => void run("preferences", () => desktop.savePreferences(preferencesFrom(snapshot, changes)));
  // The Linux client runs the engine in-process and has no service or driver.
  const linux = snapshot.platform === "linux";
  const startup = linux
    ? startupOptions.filter((option) => option.key === "startAfterLogin" || option.key === "autoConnect")
    : startupOptions;

  return (
    <div className="page-stack">
      <div className="two-column">
        <Card title={t("外观与语言")} description={t("纯黑主题适合 OLED 屏幕。")}>
          <Segmented label={t("外观")} options={appearances.map((option) => ({ ...option, label: t(option.label) }))} value={appearance} onChange={setAppearance} />
          <div className="setting-label">{t("语言")}</div>
          <Segmented label={t("语言")} options={languages.map((option) => ({ ...option, label: t(option.label) }))} value={language} onChange={setLanguage} />
        </Card>
        {linux ? <LinuxProxyCard busy={busy} run={run} /> : <Card title={t("运行方式")} description={t("桌面模式只为当前用户运行内核；HTTPS 解密需要 Windows 服务模式。")}>
          <Segmented
            label={t("运行方式")}
            options={[{ value: "desktop", label: t("桌面模式") }, { value: "service", label: t("Windows 服务") }]}
            value={snapshot.runtimeMode}
            disabled={Boolean(busy)}
            onChange={(runtimeMode) => save({ runtimeMode })}
          />
        </Card>}
      </div>

      <Card title={t("启动与自动化")}>
        {startup.map((option) => (
          <ToggleRow
            key={option.key}
            label={linux && option.key === "startAfterLogin" ? t("登录后启动") : t(option.label)}
            hint={option.hint && t(option.hint)}
            checked={snapshot[option.key]}
            disabled={Boolean(busy)}
            onChange={() => save({ [option.key]: !snapshot[option.key] } as Partial<Preferences>)}
          />
        ))}
      </Card>

      <div className="two-column">
        <Card title={t("代理内核")} description={t("内核随应用一起运行，无需单独安装。")}>
          <div className="button-row">
            <button className="secondary" disabled={Boolean(busy)} onClick={() => void run("validate", desktop.validate)}><BadgeCheck size={16} />{t("校验配置")}</button>
            <button className="secondary" disabled={Boolean(busy)} onClick={() => void run("restart", desktop.restart)}><RotateCcw size={16} />{snapshot.runtimeMode === "desktop" ? t("重启内核") : t("重启服务")}</button>
          </div>
        </Card>
        {!linux && <ServiceCard busy={busy} run={run} />}
      </div>

      {!linux && <SystemCard busy={busy} run={run} />}
    </div>
  );
}

/** Linux: the desktop's proxy settings, which connecting points at the local listener. */
function LinuxProxyCard({ busy, run }: { busy: string | null; run: Run }) {
  return (
    <Card title={t("系统代理")} description={t("连接时把 GNOME 或 KDE 的系统代理指向本地端口，断开或退出时改回原来的设置。")}>
      <div className="inline-action">
        <span><strong>{t("恢复网络设置")}</strong><small>{t("只恢复本应用这次改过、且仍归它管理的代理设置。")}</small></span>
        <button className="secondary" disabled={Boolean(busy)} onClick={() => void run("network recovery", desktop.restoreNetworkSettings)}>{t("恢复")}</button>
      </div>
    </Card>
  );
}

function ServiceCard({ busy, run }: { busy: string | null; run: Run }) {
  return (
    <Card title={t("Windows 服务")} description={t("管理已安装的 AnixOps Net 服务。")}>
      <div className="button-row">
        <button className="secondary" disabled={Boolean(busy)} onClick={() => void run("service", desktop.installService)}>{t("安装")}</button>
        <button className="secondary" disabled={Boolean(busy)} onClick={() => void run("service", desktop.startService)}>{t("启动")}</button>
        <button className="secondary" disabled={Boolean(busy)} onClick={() => void run("service", desktop.stopService)}>{t("停止")}</button>
      </div>
    </Card>
  );
}

function SystemCard({ busy, run }: { busy: string | null; run: Run }) {
  const [driverPath, setDriverPath] = useState("");
  return (
    <Card className="caution" title={t("系统与网络")} description={t("这些操作会改动系统设置，只填写你确认过的本地文件。")}>
      <Field label={t("驱动 INF 路径")}><input value={driverPath} onChange={(event) => setDriverPath(event.target.value)} /></Field>
      <div className="button-row">
        <button className="secondary" disabled={Boolean(busy) || !driverPath.trim()} onClick={() => void run("driver", () => desktop.installDriver(driverPath.trim()))}>{t("安装驱动")}</button>
        <button className="secondary" disabled={Boolean(busy)} onClick={() => void run("driver", desktop.removeDriver)}>{t("移除驱动")}</button>
      </div>
      <div className="divider" />
      <div className="inline-action">
        <span><strong>{t("恢复网络设置")}</strong><small>{t("只恢复本应用这次改过、且仍归它管理的代理设置。")}</small></span>
        <button className="secondary" disabled={Boolean(busy)} onClick={() => void run("network recovery", desktop.restoreNetworkSettings)}>{t("恢复")}</button>
      </div>
    </Card>
  );
}
