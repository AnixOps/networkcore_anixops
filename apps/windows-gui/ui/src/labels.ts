import type { RuntimeSnapshot } from "./bridge";

export type ConnectPhase = "loading" | "off" | "connecting" | "on" | "disconnecting" | "failed";

/** Maps the runtime's connection label and any running operation to the phase the connect button shows. */
export function connectPhase(connection: string | undefined, busy: string | null): ConnectPhase {
  if (busy === "connect") return "connecting";
  if (busy === "disconnect") return "disconnecting";
  switch (connection) {
    case undefined:
      return "loading";
    case "Connected":
      return "on";
    case "Connecting":
      return "connecting";
    case "Disconnecting":
      return "disconnecting";
    case "Connection failed":
    case "Core error":
    case "Configuration error":
      return "failed";
    default:
      return "off";
  }
}

export const phaseTitles: Record<ConnectPhase, string> = {
  loading: "正在读取状态",
  off: "未连接",
  connecting: "正在连接…",
  on: "已连接",
  disconnecting: "正在断开…",
  failed: "连接出错",
};

const connectionTitles: Record<string, string> = {
  "Connection failed": "连接失败",
  "Core error": "内核出错",
  "Configuration error": "配置有误",
};

export function connectionTitle(connection: string | undefined, phase: ConnectPhase): string {
  return (connection && connectionTitles[connection]) || phaseTitles[phase];
}

export const routingModes: Array<{ value: RuntimeSnapshot["routingMode"]; label: string; hint: string }> = [
  { value: "bypass_china", label: "绕过大陆", hint: "大陆网站直连，其余走代理" },
  { value: "gfw_list", label: "GFW 列表", hint: "只有列表内的网站走代理" },
  { value: "return_china", label: "回国", hint: "大陆网站走代理，适合在海外使用" },
  { value: "direct", label: "直连", hint: "所有流量直连，不经过节点" },
];

export function routingLabel(mode: RuntimeSnapshot["routingMode"] | undefined): string {
  return routingModes.find((item) => item.value === mode)?.label ?? routingModes[0].label;
}

const exactFacts: Record<string, string> = {
  "Not used": "未使用",
  Running: "运行中",
  Stopped: "已停止",
  Starting: "正在启动",
  StartPending: "正在启动",
  StopPending: "正在停止",
  Paused: "已暂停",
  NotInstalled: "未安装",
  Unknown: "未知",
  Enabled: "已开启",
  Disabled: "已关闭",
  Unavailable: "不可用",
  "Not configured": "未配置",
};

/** Translates the short status labels the Rust side reports; anything unknown is shown as is. */
export function factLabel(label: string | undefined): string {
  if (!label) return "读取中";
  if (exactFacts[label]) return exactFacts[label];
  if (label.startsWith("Running (")) return "运行中";
  if (label.startsWith("Mieru running")) return "运行中";
  if (label.startsWith("Exited")) return "已退出";
  if (label.startsWith("Status unavailable")) return "状态不可用";
  return label;
}

const protocolAbbreviations: Record<string, string> = {
  shadowsocks: "SS",
  vless: "VLESS",
  vmess: "VMess",
  trojan: "Trojan",
  wireguard: "WG",
  hysteria2: "HY2",
  tuic: "TUIC",
};

export function protocolAbbreviation(protocol: string): string {
  return protocolAbbreviations[protocol.toLowerCase()] ?? protocol;
}
