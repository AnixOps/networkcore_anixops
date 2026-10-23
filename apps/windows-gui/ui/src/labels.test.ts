import { describe, expect, it } from "vitest";
import { connectionTitle, connectPhase, factLabel, protocolAbbreviation, routingLabel } from "./labels";

describe("connectPhase", () => {
  it("prefers a running connect or disconnect operation over the reported state", () => {
    expect(connectPhase("Not connected", "connect")).toBe("connecting");
    expect(connectPhase("Connected", "disconnect")).toBe("disconnecting");
  });

  it("maps the runtime's connection labels", () => {
    expect(connectPhase(undefined, null)).toBe("loading");
    expect(connectPhase("Connected", null)).toBe("on");
    expect(connectPhase("Not connected", null)).toBe("off");
    expect(connectPhase("Core error", null)).toBe("failed");
    expect(connectPhase("Connected", "routing")).toBe("on");
  });

  it("names failures specifically", () => {
    expect(connectionTitle("Configuration error", "failed")).toBe("配置有误");
    expect(connectionTitle("Connected", "on")).toBe("已连接");
  });
});

describe("labels", () => {
  it("translates known status labels and keeps unknown ones", () => {
    expect(factLabel("Running (PID 42)")).toBe("运行中");
    expect(factLabel("NotInstalled")).toBe("未安装");
    expect(factLabel("Exited (PID 7, exit 1)")).toBe("已退出");
    expect(factLabel("Something new")).toBe("Something new");
    expect(factLabel(undefined)).toBe("读取中");
  });

  it("abbreviates protocols and names routing modes", () => {
    expect(protocolAbbreviation("Shadowsocks")).toBe("SS");
    expect(protocolAbbreviation("WireGuard")).toBe("WG");
    expect(protocolAbbreviation("Custom")).toBe("Custom");
    expect(routingLabel("return_china")).toBe("回国");
    expect(routingLabel(undefined)).toBe("绕过大陆");
  });
});
