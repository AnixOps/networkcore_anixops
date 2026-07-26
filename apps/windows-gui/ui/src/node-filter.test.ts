import { describe, expect, it } from "vitest";
import { filterNodes } from "./node-filter";

const nodes = [
  { id: "a", label: "Tokyo Primary", protocol: "Shadowsocks", selected: true },
  { id: "b", label: "Berlin Edge", protocol: "VLESS", selected: false },
];

describe("filterNodes", () => {
  it("combines the text and protocol filters without changing selection", () => {
    expect(filterNodes(nodes, "tokyo", "All")).toEqual([nodes[0]]);
    expect(filterNodes(nodes, "", "VLESS")).toEqual([nodes[1]]);
    expect(filterNodes(nodes, "primary", "VLESS")).toEqual([]);
  });
});
