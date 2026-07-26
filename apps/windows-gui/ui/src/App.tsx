import {
  Activity, BadgeCheck, Cable, ChevronRight, CircleAlert, ClipboardList, CloudDownload,
  Cpu, Gauge, HeartPulse, LayoutDashboard, LoaderCircle, Moon, Network,
  RefreshCw, Settings, ShieldCheck, SlidersHorizontal, Sun, TerminalSquare, Wifi,
} from "lucide-react";
import type { ReactNode } from "react";
import { useEffect, useState } from "react";
import { desktop, NativeGroupSummary, NodeSummary, RuntimeSnapshot, StatusFact, SubscriptionSummary } from "./bridge";
import { filterNodes } from "./node-filter";

type Page = "Home" | "Nodes" | "Subscriptions" | "Settings" | "Diagnostics" | "Advanced";

const navigation: Array<{ page: Page; icon: typeof LayoutDashboard }> = [
  { page: "Home", icon: LayoutDashboard },
  { page: "Nodes", icon: Network },
  { page: "Subscriptions", icon: CloudDownload },
  { page: "Settings", icon: Settings },
  { page: "Diagnostics", icon: ClipboardList },
  { page: "Advanced", icon: SlidersHorizontal },
];

const delayUrl = "https://www.gstatic.com/generate_204";

export function App() {
  const [page, setPage] = useState<Page>("Home");
  const [snapshot, setSnapshot] = useState<RuntimeSnapshot | null>(null);
  const [nodes, setNodes] = useState<NodeSummary[]>([]);
  const [query, setQuery] = useState("");
  const [protocol, setProtocol] = useState("All");
  const [busy, setBusy] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  const refresh = async () => {
    const [nextSnapshot, nextNodes] = await Promise.all([desktop.snapshot(), desktop.nodes()]);
    setSnapshot(nextSnapshot);
    setNodes(nextNodes);
  };

  useEffect(() => {
    void refresh().catch(showError);
    const timer = window.setInterval(() => void refresh().catch(showError), 2000);
    return () => window.clearInterval(timer);
  }, []);

  useEffect(() => {
    document.documentElement.dataset.theme = snapshot?.darkTheme ? "dark" : "light";
  }, [snapshot?.darkTheme]);

  const run = async (operation: string, task: () => Promise<{ message: string }>) => {
    setBusy(operation);
    try {
      const result = await task();
      setNotice(result.message);
      await refresh();
    } catch (error) {
      showError(error);
    } finally {
      setBusy(null);
    }
  };

  const showError = (error: unknown) => setNotice(error instanceof Error ? error.message : String(error));
  const filteredNodes = filterNodes(nodes, query, protocol);
  const protocols = ["All", ...new Set(nodes.map((node) => node.protocol))];

  return (
    <main className="app-shell">
      <aside className="sidebar">
        <div className="brand"><div className="brand-mark"><Network size={19} /></div><span>ANIXOPS</span></div>
        <div className="product-name">NetworkCore</div>
        <nav aria-label="Primary navigation">
          {navigation.map(({ page: item, icon: Icon }) => (
            <button className={`nav-item ${page === item ? "active" : ""}`} key={item} onClick={() => setPage(item)}>
              <Icon size={18} /><span>{item}</span>
            </button>
          ))}
        </nav>
        <div className="sidebar-footer"><StatusDot tone={snapshot?.connection === "Connected" ? "success" : "neutral"} />
          <span>{snapshot?.connection ?? "Loading status"}</span></div>
      </aside>
      <section className="workspace">
        <header className="topbar">
          <div><div className="eyebrow">WINDOWS CLIENT</div><h1>{page}</h1></div>
          <div className="topbar-actions">
            <StatusPill label={snapshot?.connection ?? "Loading"} tone={snapshot?.connection === "Connected" ? "success" : "warning"} />
            <IconButton label="Refresh status" onClick={() => void refresh().catch(showError)}><RefreshCw size={18} /></IconButton>
            <IconButton label="Toggle theme" onClick={() => snapshot && void run("preferences", () => desktop.savePreferences({ ...snapshot, darkTheme: !snapshot.darkTheme }))}>
              {snapshot?.darkTheme ? <Sun size={18} /> : <Moon size={18} />}
            </IconButton>
          </div>
        </header>
        {notice && <div className="notice" role="status"><CircleAlert size={17} /><span>{notice}</span><button aria-label="Dismiss notification" onClick={() => setNotice(null)}>x</button></div>}
        {page === "Home" && <Home snapshot={snapshot} busy={busy} run={run} />}
        {page === "Nodes" && <Nodes nodes={filteredNodes} protocols={protocols} query={query} protocol={protocol} busy={busy} setQuery={setQuery} setProtocol={setProtocol} run={run} />}
        {page === "Subscriptions" && <Subscriptions snapshot={snapshot} busy={busy} run={run} />}
        {page === "Settings" && <Preferences snapshot={snapshot} busy={busy} run={run} />}
        {page === "Diagnostics" && <Diagnostics busy={busy} run={run} />}
        {page === "Advanced" && <Advanced snapshot={snapshot} busy={busy} run={run} />}
      </section>
    </main>
  );
}

function Home({ snapshot, busy, run }: { snapshot: RuntimeSnapshot | null; busy: string | null; run: (name: string, task: () => Promise<{ message: string }>) => Promise<void> }) {
  const connected = snapshot?.connection === "Connected";
  return <div className="page-grid home-grid">
    <section className="connection-panel"><div><div className="eyebrow">CURRENT SESSION</div><h2>{snapshot?.connection ?? "Reading runtime"}</h2><p>{snapshot?.connectionLabel ?? "NetworkCore is checking service, core, and proxy state."}</p></div>
      <div className="connection-actions"><button className="primary" disabled={Boolean(busy) || connected} onClick={() => void run("connect", desktop.connect)}><Wifi size={18} />{busy === "connect" ? "Connecting" : "Connect"}</button>
        <button className="secondary" disabled={Boolean(busy) || !connected} onClick={() => void run("disconnect", desktop.disconnect)}>Disconnect</button></div>
    </section>
    <section className="fact-grid">
      <FactCard icon={Cable} title="Windows service" fact={snapshot?.service} />
      <FactCard icon={Cpu} title="sing-box core" fact={snapshot?.core} />
      <FactCard icon={ShieldCheck} title="System proxy" fact={snapshot?.proxy} />
      <FactCard icon={Gauge} title="Selected node" fact={{ label: snapshot?.selectedNode ?? "No node selected", tone: "neutral" }} />
    </section>
    <section className="panel span-2"><div className="panel-header"><div><h3>Session details</h3><p>Only independently verified runtime state is shown as connected.</p></div><button className="icon-text" onClick={() => void run("restart", desktop.restart)} disabled={Boolean(busy)}><RefreshCw size={16} />Restart service</button></div>
      <dl className="details"><Detail term="Subscription" value={snapshot?.subscription ?? "No profile imported"} /><Detail term="Last transition" value={snapshot?.lastError ?? "No active runtime error"} /><Detail term="Configuration" value={snapshot?.configurationError ?? "Validated"} /></dl>
    </section>
  </div>;
}

function Nodes({ nodes, protocols, query, protocol, busy, setQuery, setProtocol, run }: { nodes: NodeSummary[]; protocols: string[]; query: string; protocol: string; busy: string | null; setQuery: (value: string) => void; setProtocol: (value: string) => void; run: (name: string, task: () => Promise<{ message: string }>) => Promise<void> }) {
  return <div className="page-grid"><section className="panel span-2"><div className="panel-header"><div><h3>Nodes</h3><p>Switching writes the generated selector only after runtime validation.</p></div><div className="row-actions"><span className="count">{nodes.length} nodes</span><button className="secondary compact" disabled={Boolean(busy) || nodes.length === 0} onClick={() => void run("fastest node", desktop.selectFastestNode)}>Select fastest</button></div></div>
    <div className="toolbar"><input aria-label="Search nodes" placeholder="Search nodes" value={query} onChange={(event) => setQuery(event.target.value)} /><select aria-label="Filter by protocol" value={protocol} onChange={(event) => setProtocol(event.target.value)}>{protocols.map((value) => <option key={value}>{value}</option>)}</select></div>
    <div className="node-table"><div className="node-head"><span>Node</span><span>Protocol</span><span>State</span><span /></div>{nodes.map((node) => <div className="node-row" key={node.id}><div><strong>{node.label}</strong><small>{node.id}</small></div><span>{node.protocol}</span><StatusPill label={node.selected ? "Active" : "Available"} tone={node.selected ? "success" : "neutral"} /><div className="row-actions"><IconButton label={`Test ${node.label}`} disabled={Boolean(busy)} onClick={() => void run("delay", () => desktop.testDelay(node.id, delayUrl))}><Activity size={16} /></IconButton><button className="secondary compact" disabled={Boolean(busy) || node.selected} onClick={() => void run("switch", () => desktop.switchNode(node.id))}>Select</button></div></div>)}{nodes.length === 0 && <div className="empty-state">Import a compatible NodeCatalog profile to manage nodes.</div>}</div>
  </section></div>;
}

function Subscriptions({ snapshot, busy, run }: { snapshot: RuntimeSnapshot | null; busy: string | null; run: (name: string, task: () => Promise<{ message: string }>) => Promise<void> }) { const [location, setLocation] = useState(snapshot?.subscription ?? ""); const [sources, setSources] = useState<SubscriptionSummary[]>([]); const refreshSources = () => void desktop.subscriptions().then(setSources); useEffect(() => { setLocation(snapshot?.subscription ?? ""); refreshSources(); }, [snapshot?.subscription]); return <div className="page-grid"><section className="panel span-2"><div className="panel-header"><div><h3>Subscriptions</h3><p>Import a local profile or an explicit HTTP(S) URL.</p></div><StatusPill label={snapshot?.subscription ? "Configured" : "No source"} tone={snapshot?.subscription ? "success" : "neutral"} /></div><div className="subscription-card"><CloudDownload size={26} /><div><strong>{snapshot?.subscription ?? "No subscription configured"}</strong><p>{snapshot?.subscriptionError ?? (snapshot?.subscriptionLastUpdated ? `Last updated ${snapshot.subscriptionLastUpdated}` : "Generated NodeCatalog profiles enable selection and delay testing.")}</p></div><ChevronRight size={20} /></div><div className="toolbar subscription-toolbar"><input aria-label="Profile path or subscription URL" placeholder="Profile path or HTTPS subscription URL" value={location} onChange={(event) => setLocation(event.target.value)} /><button className="primary" disabled={Boolean(busy) || !location.trim()} onClick={() => void run("subscription", async () => { const result = await desktop.importSubscription(location); refreshSources(); return result; })}>Import profile</button><button className="secondary" disabled={Boolean(busy) || !snapshot?.subscription?.startsWith("http")} onClick={() => void run("subscription", desktop.updateSubscription)}>Update saved URL</button><button className="secondary" disabled={Boolean(busy) || !snapshot?.subscription} onClick={() => void run("selector", desktop.checkProfileRuntime)}>Check selector</button></div><div className="node-table"><div className="node-head"><span>Saved source</span><span>Updated</span><span>State</span><span /></div>{sources.map((source) => <div className="node-row" key={source.id}><strong>{source.location}</strong><span>{source.lastSuccessfulUpdate ?? "Never"}</span><StatusPill label={source.selected ? "Active" : (source.lastUpdateError ? "Error" : "Saved")} tone={source.selected ? "success" : (source.lastUpdateError ? "danger" : "neutral")} /><div className="row-actions"><button className="secondary compact" disabled={Boolean(busy) || source.selected} onClick={() => void run("subscription", () => desktop.selectSubscription(source.id))}>Select</button><IconButton label={`Remove ${source.location}`} disabled={Boolean(busy)} onClick={() => void run("subscription", async () => { const result = await desktop.removeSubscription(source.id); refreshSources(); return result; })}><CircleAlert size={16} /></IconButton></div></div>)}</div></section></div>; }

function Preferences({ snapshot, busy, run }: { snapshot: RuntimeSnapshot | null; busy: string | null; run: (name: string, task: () => Promise<{ message: string }>) => Promise<void> }) {
  const [values, setValues] = useState(snapshot);
  useEffect(() => setValues(snapshot), [snapshot]);
  if (!values) return <Loading />;
  const toggle = (key: "startAfterLogin" | "autoConnect" | "autoRecoverCore" | "autoSubscriptionRefresh" | "autoSelectFastestNode") => setValues({ ...values, [key]: !values[key] });
  return <div className="page-grid"><section className="panel"><div className="panel-header"><div><h3>Daily startup</h3><p>Preferences are stored with the desktop-owned runtime state.</p></div></div>{(["startAfterLogin", "autoConnect", "autoRecoverCore", "autoSubscriptionRefresh", "autoSelectFastestNode"] as const).map((key) => <ToggleRow key={key} label={{ startAfterLogin: "Start after sign-in", autoConnect: "Connect after startup", autoRecoverCore: "Recover one GUI-started core failure", autoSubscriptionRefresh: "Refresh saved subscription hourly", autoSelectFastestNode: "Select fastest node every 30 minutes" }[key]} checked={values[key]} onChange={() => toggle(key)} />)}<button className="primary" disabled={Boolean(busy)} onClick={() => void run("preferences", () => desktop.savePreferences(values))}>Save preferences</button></section><section className="panel"><div className="panel-header"><div><h3>Managed configuration</h3><p>Install the supported core, then preflight the managed configuration.</p></div></div><div className="stack-actions"><button className="primary" disabled={Boolean(busy)} onClick={() => void run("core", desktop.installCore)}><Cpu size={17} />Install sing-box</button><button className="secondary" disabled={Boolean(busy)} onClick={() => void run("validate", desktop.validate)}><BadgeCheck size={17} />Validate configuration</button></div></section></div>;
}

function Diagnostics({ busy, run }: { busy: string | null; run: (name: string, task: () => Promise<{ message: string }>) => Promise<void> }) { return <div className="page-grid"><section className="panel span-2"><div className="panel-header"><div><h3>Diagnostics</h3><p>Generate a bounded report from managed runtime state and logs.</p></div><TerminalSquare size={22} /></div><button className="primary" disabled={Boolean(busy)} onClick={() => void run("diagnostics", desktop.diagnostics)}><ClipboardList size={17} />Create diagnostics report</button></section></div>; }

function Advanced({ snapshot, busy, run }: { snapshot: RuntimeSnapshot | null; busy: string | null; run: (name: string, task: () => Promise<{ message: string }>) => Promise<void> }) {
  const [certificatePath, setCertificatePath] = useState("");
  const [driverPath, setDriverPath] = useState("");
  const [tunnelConfig, setTunnelConfig] = useState("");
  const [dnsConfig, setDnsConfig] = useState("");
  const [scriptRuntimeConfig, setScriptRuntimeConfig] = useState("");
  const [nativeGroups, setNativeGroups] = useState<NativeGroupSummary[]>([]);
  const [nativeGroupTag, setNativeGroupTag] = useState<string | null>(null);
  const [nativeGroupJson, setNativeGroupJson] = useState("");

  useEffect(() => {
    void desktop.nativeGroups().then(setNativeGroups).catch(() => setNativeGroups([]));
  }, []);

  return <div className="page-grid">
    <section className="panel">
      <div className="panel-header"><div><h3>Windows service</h3><p>Manage the installed NetworkCore service.</p></div><HeartPulse size={22} /></div>
      <div className="stack-actions">
        <button className="secondary" disabled={Boolean(busy)} onClick={() => void run("service", desktop.installService)}>Install service</button>
        <button className="secondary" disabled={Boolean(busy)} onClick={() => void run("service", desktop.startService)}>Start service</button>
        <button className="secondary" disabled={Boolean(busy)} onClick={() => void run("service", desktop.stopService)}>Stop service</button>
      </div>
    </section>
    <section className="panel danger-panel">
      <div className="panel-header"><div><h3>Certificates and driver</h3><p>Use explicit local paths for system changes.</p></div><ShieldCheck size={22} /></div>
      <input placeholder="Certificate PEM path" value={certificatePath} onChange={(event) => setCertificatePath(event.target.value)} />
      <div className="stack-actions">
        <button className="secondary" disabled={Boolean(busy) || !certificatePath} onClick={() => void run("certificate", () => desktop.installCertificate(certificatePath))}>Install certificate</button>
        <button className="secondary" disabled={Boolean(busy)} onClick={() => void run("certificate", desktop.removeCertificate)}>Remove certificate</button>
      </div>
      <input placeholder="Driver INF path" value={driverPath} onChange={(event) => setDriverPath(event.target.value)} />
      <div className="stack-actions">
        <button className="secondary" disabled={Boolean(busy) || !driverPath} onClick={() => void run("driver", () => desktop.installDriver(driverPath))}>Install driver</button>
        <button className="secondary" disabled={Boolean(busy)} onClick={() => void run("driver", desktop.removeDriver)}>Remove driver</button>
      </div>
    </section>
    <section className="panel span-2">
      <div className="panel-header"><div><h3>Managed TUN</h3><p>Supply the verified EasyTier tunnel configuration for the Windows service.</p></div><Network size={22} /></div>
      <textarea aria-label="Managed TUN JSON" placeholder="Managed TUN JSON" value={tunnelConfig} onChange={(event) => setTunnelConfig(event.target.value)} />
      <div className="stack-actions">
        <button className="primary" disabled={Boolean(busy) || !tunnelConfig.trim()} onClick={() => void run("tunnel", () => desktop.configureTunnel(tunnelConfig))}>Save TUN configuration</button>
        <button className="secondary" disabled={Boolean(busy)} onClick={() => void run("tunnel", desktop.clearTunnel)}>Clear TUN configuration</button>
      </div>
    </section>
    <section className="panel span-2">
      <div className="panel-header"><div><h3>Managed DNS</h3><p>Apply a sing-box DNS block to the stopped active profile.</p></div><StatusPill label={snapshot?.dnsConfigured ? "Configured" : "Not configured"} tone={snapshot?.dnsConfigured ? "success" : "neutral"} /></div>
      <textarea aria-label="Managed DNS JSON" placeholder="Managed DNS JSON" value={dnsConfig} onChange={(event) => setDnsConfig(event.target.value)} />
      <div className="stack-actions">
        <button className="primary" disabled={Boolean(busy) || !dnsConfig.trim()} onClick={() => void run("dns", () => desktop.configureDns(dnsConfig))}>Save DNS configuration</button>
        <button className="secondary" disabled={Boolean(busy)} onClick={() => void run("dns", desktop.clearDns)}>Clear DNS configuration</button>
      </div>
    </section>
    <section className="panel span-2">
      <div className="panel-header"><div><h3>Native outbound groups</h3><p>Choose selector defaults or edit one native group without replacing the profile.</p></div><StatusPill label={nativeGroups.length ? `${nativeGroups.length} groups` : "No groups"} tone={nativeGroups.length ? "success" : "neutral"} /></div>
      {nativeGroups.length === 0 ? <div className="empty-state">No native outbound groups are available in the active profile.</div> : <div className="node-table native-group-table">
        {nativeGroups.map((group) => <div className="native-group-row" key={group.tag}>
          <div><strong>{group.tag}</strong><small>{group.groupType}{group.selected ? `: ${group.selected}` : ""}</small></div>
          <div className="row-actions">{group.groupType === "selector" && group.outbounds.map((outbound) => <button className="secondary compact" disabled={Boolean(busy) || group.selected === outbound} key={outbound} onClick={() => void run("native selector", async () => {
            const result = await desktop.selectNativeGroupOutbound(group.tag, outbound);
            setNativeGroups((groups) => groups.map((current) => current.tag === group.tag ? { ...current, selected: outbound } : current));
            return result;
          })}>{outbound}</button>)}<button className="secondary compact" disabled={Boolean(busy)} onClick={() => { setNativeGroupTag(group.tag); setNativeGroupJson(group.json); }}>Edit JSON</button></div>
        </div>)}
      </div>}
      {nativeGroupTag && <><textarea aria-label="Native outbound group JSON" placeholder="Native outbound group JSON" value={nativeGroupJson} onChange={(event) => setNativeGroupJson(event.target.value)} /><div className="stack-actions"><button className="primary" disabled={Boolean(busy) || !nativeGroupJson.trim()} onClick={() => void run("native group", async () => {
        const result = await desktop.replaceNativeGroup(nativeGroupTag, nativeGroupJson);
        const groups = await desktop.nativeGroups();
        setNativeGroups(groups);
        setNativeGroupJson(groups.find((group) => group.tag === nativeGroupTag)?.json ?? nativeGroupJson);
        return result;
      })}>Save group JSON</button><button className="secondary" disabled={Boolean(busy)} onClick={() => { setNativeGroupTag(null); setNativeGroupJson(""); }}>Close editor</button></div></>}
    </section>
    <section className="panel span-2 danger-panel">
      <div className="panel-header"><div><h3>Script dispatch</h3><p>Map plugin script URLs to local Node assets for the native MITM runtime.</p></div><StatusPill label={snapshot?.scriptRuntimeConfigured ? "Configured" : "Not configured"} tone={snapshot?.scriptRuntimeConfigured ? "success" : "neutral"} /></div>
      <textarea aria-label="Script runtime JSON" placeholder="Script runtime JSON" value={scriptRuntimeConfig} onChange={(event) => setScriptRuntimeConfig(event.target.value)} />
      <div className="stack-actions">
        <button className="primary" disabled={Boolean(busy) || !scriptRuntimeConfig.trim()} onClick={() => void run("script runtime", () => desktop.configureScriptRuntime(scriptRuntimeConfig))}>Save script runtime</button>
        <button className="secondary" disabled={Boolean(busy)} onClick={() => void run("script runtime", desktop.clearScriptRuntime)}>Clear script runtime</button>
      </div>
    </section>
    <section className="panel span-2">
      <div className="panel-header"><div><h3>Network recovery</h3><p>Restore only proxy settings still owned by this GUI session.</p></div><ShieldCheck size={22} /></div>
      <button className="secondary" disabled={Boolean(busy)} onClick={() => void run("network recovery", desktop.restoreNetworkSettings)}>Restore network settings</button>
    </section>
    <section className="panel span-2 danger-panel">
      <div className="panel-header"><div><h3>HTTPS MITM</h3><p>Routes the imported profile through the local native HTTPS proxy and keeps the original sing-box JSON for rollback.</p></div><ShieldCheck size={22} /></div>
      <div className="stack-actions">
        <button className="primary" disabled={Boolean(busy)} onClick={() => void run("mitm", desktop.enableHttpsMitm)}>Enable HTTPS MITM</button>
        <button className="secondary" disabled={Boolean(busy)} onClick={() => void run("mitm", desktop.disableHttpsMitm)}>Disable HTTPS MITM</button>
      </div>
    </section>
  </div>;
}

function FactCard({ icon: Icon, title, fact }: { icon: typeof Cpu; title: string; fact?: StatusFact }) { return <section className="fact-card"><div className="fact-icon"><Icon size={19} /></div><div><span>{title}</span><strong>{fact?.label ?? "Loading"}</strong>{fact?.detail && <small>{fact.detail}</small>}</div><StatusDot tone={fact?.tone ?? "neutral"} /></section>; }
function Detail({ term, value }: { term: string; value: string }) { return <div><dt>{term}</dt><dd>{value}</dd></div>; }
function StatusDot({ tone }: { tone: string }) { return <i className={`status-dot ${tone}`} />; }
function StatusPill({ label, tone }: { label: string; tone: string }) { return <span className={`status-pill ${tone}`}><StatusDot tone={tone} />{label}</span>; }
function IconButton({ label, children, onClick, disabled = false }: { label: string; children: ReactNode; onClick: () => void; disabled?: boolean }) { return <button className="icon-button" title={label} aria-label={label} onClick={onClick} disabled={disabled}>{children}</button>; }
function ToggleRow({ label, checked, onChange }: { label: string; checked: boolean; onChange: () => void }) { return <label className="toggle-row"><span>{label}</span><input type="checkbox" checked={checked} onChange={onChange} /><i /></label>; }
function Loading() { return <div className="loading"><LoaderCircle className="spin" size={22} />Loading desktop state</div>; }
