import { invoke } from "@tauri-apps/api/core";

export type Tone = "success" | "warning" | "danger" | "neutral";

export interface StatusFact {
  label: string;
  detail?: string;
  tone: Tone;
}

export interface RuntimeSnapshot {
  /** Sent by the Linux client; the Windows client leaves it out. */
  platform?: "windows" | "linux";
  connection: string;
  connectionLabel: string;
  service: StatusFact;
  core: StatusFact;
  proxy: StatusFact;
  selectedNode?: string;
  subscription?: string;
  subscriptionLastUpdated?: string;
  subscriptionLastAttempt?: string;
  subscriptionNextAttempt?: string;
  subscriptionRefreshResult: string;
  subscriptionAddedNodeCount: number;
  subscriptionRemovedNodeCount: number;
  subscriptionChangedNodeCount: number;
  subscriptionRefreshErrorCode?: string;
  subscriptionError?: string;
  lastError?: string;
  configurationError?: string;
  startAfterLogin: boolean;
  autoConnect: boolean;
  autoRecoverCore: boolean;
  autoSubscriptionRefresh: boolean;
  autoSelectFastestNode: boolean;
  bilibiliWebAdBlockEnabled: boolean;
  scriptRuntimeConfigured: boolean;
  darkTheme: boolean;
  runtimeMode: "desktop" | "service";
  routingMode: "bypass_china" | "gfw_list" | "direct" | "return_china" | "rule";
  /** The imported profile runs on the embedded engine (Windows). */
  embeddedEngine?: boolean;
}

export interface NodeSummary {
  id: string;
  label: string;
  protocol: string;
  selected: boolean;
}

export interface NativeGroupSummary {
  tag: string;
  groupType: string;
  selected?: string;
  outbounds: string[];
  /** Display names for `outbounds`; empty when they are the names. */
  outboundLabels?: string[];
}

export interface OperationResult {
  message: string;
}

export interface SubscriptionSummary {
  id: string;
  location: string;
  selected: boolean;
  lastSuccessfulUpdate?: string;
  lastAttempt?: string;
  nextAttempt?: string;
  result: string;
  addedNodeCount: number;
  removedNodeCount: number;
  changedNodeCount: number;
  errorCode?: string;
  lastUpdateError?: string;
}

export type Preferences = Pick<RuntimeSnapshot, "startAfterLogin" | "autoConnect" | "autoRecoverCore" | "autoSubscriptionRefresh" | "autoSelectFastestNode" | "bilibiliWebAdBlockEnabled" | "darkTheme" | "runtimeMode">;

/** The saved preferences from a snapshot with some of them changed. */
export function preferencesFrom(snapshot: RuntimeSnapshot, changes: Partial<Preferences>): Preferences {
  return {
    startAfterLogin: snapshot.startAfterLogin,
    autoConnect: snapshot.autoConnect,
    autoRecoverCore: snapshot.autoRecoverCore,
    autoSubscriptionRefresh: snapshot.autoSubscriptionRefresh,
    autoSelectFastestNode: snapshot.autoSelectFastestNode,
    bilibiliWebAdBlockEnabled: snapshot.bilibiliWebAdBlockEnabled,
    darkTheme: snapshot.darkTheme,
    runtimeMode: snapshot.runtimeMode,
    ...changes,
  };
}

export const desktop = {
  snapshot: () => invoke<RuntimeSnapshot>("runtime_snapshot"),
  nodes: () => invoke<NodeSummary[]>("list_nodes"),
  nativeGroups: () => invoke<NativeGroupSummary[]>("list_native_groups"),
  subscriptions: () => invoke<SubscriptionSummary[]>("list_subscriptions"),
  connect: () => invoke<OperationResult>("connect"),
  disconnect: () => invoke<OperationResult>("disconnect"),
  restart: () => invoke<OperationResult>("restart_service"),
  validate: () => invoke<OperationResult>("validate_configuration"),
  switchNode: (nodeId: string) => invoke<OperationResult>("switch_node", { nodeId }),
  selectNativeGroupOutbound: (groupTag: string, outboundTag: string) =>
    invoke<OperationResult>("select_native_group_outbound", { groupTag, outboundTag }),
  testDelay: (nodeId: string, url: string) =>
    invoke<OperationResult>("test_node_delay", { nodeId, url }),
  selectFastestNode: () => invoke<OperationResult>("select_fastest_node"),
  savePreferences: (preferences: Preferences) =>
    invoke<OperationResult>("save_preferences", {
      preferences,
    }),
  diagnostics: () => invoke<OperationResult>("create_diagnostics"),
  importSubscription: (location: string) =>
    invoke<OperationResult>("import_subscription", { location }),
  updateSubscription: () => invoke<OperationResult>("update_subscription"),
  selectSubscription: (id: string) => invoke<OperationResult>("select_subscription", { id }),
  removeSubscription: (id: string) => invoke<OperationResult>("remove_subscription", { id }),
  checkProfileRuntime: () => invoke<OperationResult>("check_profile_runtime"),
  installService: () => invoke<OperationResult>("install_service"),
  startService: () => invoke<OperationResult>("start_service"),
  stopService: () => invoke<OperationResult>("stop_service"),
  restoreNetworkSettings: () => invoke<OperationResult>("restore_network_settings"),
  configureTunnel: (configJson: string) => invoke<OperationResult>("configure_tunnel", { configJson }),
  clearTunnel: () => invoke<OperationResult>("clear_tunnel"),
  setRoutingMode: (mode: RuntimeSnapshot["routingMode"]) => invoke<OperationResult>("set_routing_mode", { mode }),
  refreshRoutingRules: () => invoke<OperationResult>("refresh_routing_rules"),
  configureScriptRuntime: (scriptRuntimeJson: string) =>
    invoke<OperationResult>("configure_script_runtime", { scriptRuntimeJson }),
  clearScriptRuntime: () => invoke<OperationResult>("clear_script_runtime"),
  enableHttpsMitm: () => invoke<OperationResult>("enable_https_mitm"),
  disableHttpsMitm: () => invoke<OperationResult>("disable_https_mitm"),
  installCertificate: (path: string) => invoke<OperationResult>("install_certificate", { path }),
  removeCertificate: () => invoke<OperationResult>("remove_certificate"),
  installDriver: (path: string) => invoke<OperationResult>("install_driver", { path }),
  removeDriver: () => invoke<OperationResult>("remove_driver"),
};
