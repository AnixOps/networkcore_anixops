import { invoke } from "@tauri-apps/api/core";

export type Tone = "success" | "warning" | "danger" | "neutral";

export interface StatusFact {
  label: string;
  detail?: string;
  tone: Tone;
}

export interface RuntimeSnapshot {
  connection: string;
  connectionLabel: string;
  service: StatusFact;
  core: StatusFact;
  proxy: StatusFact;
  selectedNode?: string;
  subscription?: string;
  subscriptionLastUpdated?: string;
  subscriptionError?: string;
  lastError?: string;
  configurationError?: string;
  startAfterLogin: boolean;
  autoConnect: boolean;
  autoRecoverCore: boolean;
  autoSubscriptionRefresh: boolean;
  autoSelectFastestNode: boolean;
  dnsConfigured: boolean;
  scriptRuntimeConfigured: boolean;
  darkTheme: boolean;
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
  json: string;
}

export interface OperationResult {
  message: string;
}

export interface SubscriptionSummary {
  id: string;
  location: string;
  selected: boolean;
  lastSuccessfulUpdate?: string;
  lastUpdateError?: string;
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
  replaceNativeGroup: (groupTag: string, groupJson: string) =>
    invoke<OperationResult>("replace_native_group", { groupTag, groupJson }),
  testDelay: (nodeId: string, url: string) =>
    invoke<OperationResult>("test_node_delay", { nodeId, url }),
  selectFastestNode: () => invoke<OperationResult>("select_fastest_node"),
  savePreferences: (preferences: Pick<RuntimeSnapshot, "startAfterLogin" | "autoConnect" | "autoRecoverCore" | "autoSubscriptionRefresh" | "autoSelectFastestNode" | "darkTheme">) =>
    invoke<OperationResult>("save_preferences", {
      startAfterLogin: preferences.startAfterLogin,
      autoConnect: preferences.autoConnect,
      autoRecoverCore: preferences.autoRecoverCore,
      autoSubscriptionRefresh: preferences.autoSubscriptionRefresh,
      autoSelectFastestNode: preferences.autoSelectFastestNode,
      darkTheme: preferences.darkTheme,
    }),
  diagnostics: () => invoke<OperationResult>("create_diagnostics"),
  importSubscription: (location: string) =>
    invoke<OperationResult>("import_subscription", { location }),
  updateSubscription: () => invoke<OperationResult>("update_subscription"),
  selectSubscription: (id: string) => invoke<OperationResult>("select_subscription", { id }),
  removeSubscription: (id: string) => invoke<OperationResult>("remove_subscription", { id }),
  checkProfileRuntime: () => invoke<OperationResult>("check_profile_runtime"),
  installCore: () => invoke<OperationResult>("install_core"),
  installService: () => invoke<OperationResult>("install_service"),
  startService: () => invoke<OperationResult>("start_service"),
  stopService: () => invoke<OperationResult>("stop_service"),
  restoreNetworkSettings: () => invoke<OperationResult>("restore_network_settings"),
  configureTunnel: (configJson: string) => invoke<OperationResult>("configure_tunnel", { configJson }),
  clearTunnel: () => invoke<OperationResult>("clear_tunnel"),
  configureDns: (dnsJson: string) => invoke<OperationResult>("configure_dns", { dnsJson }),
  clearDns: () => invoke<OperationResult>("clear_dns"),
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
