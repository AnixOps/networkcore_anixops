import type { NodeSummary } from "./bridge";

export function filterNodes(nodes: NodeSummary[], query: string, protocol: string): NodeSummary[] {
  const normalizedQuery = query.trim().toLowerCase();
  return nodes.filter((node) => {
    const searchable = `${node.label} ${node.protocol}`.toLowerCase();
    return (!normalizedQuery || searchable.includes(normalizedQuery))
      && (protocol === "All" || node.protocol === protocol);
  });
}
