import { useEffect, useMemo, useRef, useState } from "react";

import { clearSession, invoke } from "./desktopRuntime";
import { DesktopTabBar } from "./desktopChrome.mjs";
import { Icon } from "./iconSystem.mjs";
import {
  canOperateFleet,
  chooseRunHost,
  FLEET_SECTIONS,
  fleetContainerRows,
  fleetHostState,
  isFleetSessionExpired,
  normalizeFleetSnapshot,
  shouldShowFleetRefreshError,
} from "./fleetView.mjs";
import type { FleetRole, FleetSection } from "./fleetView.mjs";
import { tabKeyboardTarget } from "./forgeShell.mjs";

type FleetHost = {
  node_id: string;
  endpoint: string;
  enrollment_state: string;
  revocation_reason?: string | null;
  last_seen_unix?: number | null;
  version?: string | null;
  health?: string | null;
  doctor_summary?: string | null;
  containers?: Array<Record<string, unknown>>;
  acknowledged_revision?: number | null;
  connected: boolean;
};

type FleetDeploy = {
  deployment_id: string;
  revision: number;
  name: string;
  image: string;
  node_ids: string[];
  previous_deployment_id?: string | null;
  status: string;
  progress: Record<string, unknown>;
  created_at: number;
  rolled_back_at?: number | null;
};

type FleetSnapshot = {
  cluster_epoch: number;
  hosts: FleetHost[];
  deploys: FleetDeploy[];
};

type LoginResponse = { token: string; role: FleetRole; principal: string; expires_at: number };

const ROLE_KEY = "ferrocrate.fleetRole";
const TOKEN_KEY = "ferrocrate.webBridgeToken";

function unixTime(value?: number | null): string {
  return value ? new Date(value * 1000).toLocaleString() : "Never";
}

function commandArray(value: string): string[] {
  const parsed: unknown = JSON.parse(value || "[]");
  if (!Array.isArray(parsed) || parsed.some((part) => typeof part !== "string")) {
    throw new Error("Command must be a JSON array of strings.");
  }
  return parsed;
}

export function FleetApp(): JSX.Element {
  const [snapshot, setSnapshot] = useState<FleetSnapshot | null>(null);
  const [section, setSection] = useState<FleetSection>("hosts");
  const [role, setRole] = useState<FleetRole | null>(() => {
    const saved = sessionStorage.getItem(ROLE_KEY);
    return saved === "view" || saved === "operate" ? saved : null;
  });
  const [credential, setCredential] = useState("");
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [result, setResult] = useState("");
  const [runHost, setRunHost] = useState("");
  const [runName, setRunName] = useState("fleet-demo");
  const [runImage, setRunImage] = useState("alpine:latest");
  const [runCommand, setRunCommand] = useState('["sh","-c","echo fleet-ready"]');
  const [deployName, setDeployName] = useState("fleet-rollout");
  const [deployImage, setDeployImage] = useState("alpine:latest");
  const [deployCommand, setDeployCommand] = useState('["sh","-c","echo rollout-ready"]');
  const [deployHosts, setDeployHosts] = useState<string[]>([]);

  const session = useRef({ active: true, generation: 0 });
  const deploymentInitialized = useRef(false);
  const pollTimer = useRef<number>();

  const operate = canOperateFleet(role);
  const hosts = snapshot?.hosts ?? [];
  const containers = useMemo(() => fleetContainerRows(hosts), [hosts]);

  async function refresh(): Promise<void> {
    if (!session.current.active) return;
    const generation = session.current.generation;
    try {
      const next = normalizeFleetSnapshot(await invoke<unknown>("get_fleet_snapshot", {}));
      if (!session.current.active || generation !== session.current.generation) return;
      setSnapshot(next as FleetSnapshot);
      setError("");
      setRunHost((current) => chooseRunHost(current, next.hosts as FleetHost[]));
      if (!deploymentInitialized.current) {
        deploymentInitialized.current = true;
        const nextHosts = next.hosts as FleetHost[];
        setDeployHosts(nextHosts.filter((host) => host.connected).map((host) => host.node_id));
      }
    } catch (nextError) {
      if (!session.current.active || generation !== session.current.generation) return;
      if (isFleetSessionExpired(nextError)) {
        // A first visit has no stored token, so "expired" would be wrong: there
        // was never a session. Only say expired when one is actually being
        // discarded; otherwise the sign-in form speaks for itself.
        const hadSession = sessionStorage.getItem(TOKEN_KEY) !== null;
        signOut();
        setError(hadSession ? "Session expired — sign in again" : "");
      } else if (shouldShowFleetRefreshError(role)) {
        setError(String(nextError));
      }
      setSnapshot(null);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    session.current.active = true;
    void refresh();
    pollTimer.current = window.setInterval(() => void refresh(), 5_000);
    return () => {
      window.clearInterval(pollTimer.current);
      session.current.active = false;
      session.current.generation += 1;
    };
  }, []);

  async function login(event: React.FormEvent): Promise<void> {
    event.preventDefault();
    setBusy(true);
    setError("");
    try {
      const response = await fetch("/fleet/login", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ credential: credential.trim() }),
      });
      const body = await response.text();
      let payload: LoginResponse & { error?: string } = {} as LoginResponse & { error?: string };
      if (body.trim()) {
        try {
          payload = JSON.parse(body) as LoginResponse & { error?: string };
        } catch {
          // The login surface only reports a response error after explicit submission.
        }
      }
      if (!response.ok) throw new Error(payload.error || "Login rejected");
      sessionStorage.setItem(ROLE_KEY, payload.role);
      window.location.hash = new URLSearchParams({ token: payload.token }).toString();
      window.location.reload();
    } catch (nextError) {
      setError(String(nextError));
      setBusy(false);
    }
  }

  async function runOperation(command: string, argumentsValue: Record<string, unknown>): Promise<void> {
    if (!session.current.active) return;
    const generation = session.current.generation;
    setBusy(true);
    setError("");
    try {
      const response = await invoke<Record<string, unknown>>(command, argumentsValue, { timeoutMs: 65_000 });
      if (!session.current.active || generation !== session.current.generation) return;
      setResult(JSON.stringify(response, null, 2));
      await refresh();
    } catch (nextError) {
      if (!session.current.active || generation !== session.current.generation) return;
      const message = String(nextError);
      setError(message);
      if (/unauthorized|command .* failed/i.test(message)) {
        sessionStorage.removeItem(TOKEN_KEY);
      }
    } finally {
      setBusy(false);
    }
  }

  function signOut(): void {
    session.current.active = false;
    session.current.generation += 1;
    window.clearInterval(pollTimer.current);
    clearSession();
    setResult("");
    setDeployHosts([]);
    deploymentInitialized.current = false;
    setLoading(false);
    sessionStorage.removeItem(TOKEN_KEY);
    sessionStorage.removeItem(ROLE_KEY);
    setRole(null);
    setSnapshot(null);
  }

  if (!snapshot) {
    return (
      <div className="forge-shell fleet-shell">
        <header className="titlebar"><div className="logo">Ferrocrate <em>Fleet</em></div></header>
        <main className="fleet-login-wrap">
          <form className="panel fleet-login" onSubmit={(event) => void login(event)}>
            <span className="empty-state-icon" aria-hidden="true"><Icon name="servers" size={24} /></span>
            <p className="eyebrow">Certificate-bound access</p>
            <h1>{loading ? "Connecting to fleet" : "Sign in to Fleet"}</h1>
            <p>Use the short-lived login credential minted from the enrolled operator identity.</p>
            <label htmlFor="fleet-login-credential">Login credential</label>
            <input id="fleet-login-credential" type="password" autoComplete="one-time-code" value={credential} onChange={(event) => setCredential(event.target.value)} />
            {error ? <p className="fleet-error" role="alert">{error}</p> : null}
            <button className="btn btn-primary" type="submit" disabled={busy || !credential.trim()}>{busy ? "Signing in…" : "Sign in"}</button>
          </form>
        </main>
      </div>
    );
  }

  return (
    <div className="forge-shell fleet-shell">
      <header className="titlebar">
        <div className="logo">Ferrocrate <em>Fleet</em></div>
        <div className="fleet-cluster-summary">Epoch {snapshot.cluster_epoch} · {hosts.filter((host) => host.connected).length}/{hosts.length} online</div>
        <span className={`fleet-role role-${role}`}>{role === "operate" ? "Operate" : "View"}</span>
        <button className="btn btn-ghost" onClick={signOut}>Sign out</button>
      </header>
      <DesktopTabBar
        activeSection="fleet"
        counts={{ containers: 0, images: 0, builds: 0, compose: 0, volumes: 0, networks: 0, fleet: hosts.length }}
        onSelect={(target) => { if (target !== "fleet") setError("This listener serves the Fleet surface."); }}
      />
      <div className="fleet-subnav" role="tablist" aria-label="Fleet views">
        {FLEET_SECTIONS.map((target) => (
          <button
            key={target}
            id={`fleet-tab-${target}`}
            role="tab"
            aria-selected={section === target}
            aria-controls={`fleet-panel-${target}`}
            tabIndex={section === target ? 0 : -1}
            className={section === target ? "active" : ""}
            onClick={() => setSection(target)}
            onKeyDown={(event) => {
              const next = tabKeyboardTarget(FLEET_SECTIONS, target, event.key);
              if (!next || next === target) return;
              event.preventDefault();
              setSection(next as FleetSection);
              document.getElementById(`fleet-tab-${next}`)?.focus();
            }}
          >{target[0].toUpperCase() + target.slice(1)}</button>
        ))}
      </div>
      <main className="main-area fleet-main" id={`fleet-panel-${section}`} role="tabpanel" aria-labelledby={`fleet-tab-${section}`}>
        <div className="page-header">
          <div><p className="eyebrow">Fleet control plane</p><h1>{section[0].toUpperCase() + section.slice(1)}</h1></div>
          <button className="btn btn-secondary" onClick={() => void refresh()} disabled={busy}><Icon name="refresh" size={16} />Refresh</button>
        </div>
        {error ? <div className="error-banner" role="alert"><span>{error}</span><button aria-label="Dismiss error" onClick={() => setError("")}>×</button></div> : null}
        <div className="page-content fleet-content">
          {section === "hosts" ? (
            <section className="panel table-panel" aria-label="Fleet hosts">
              <div className="table-scroll"><table>
                <thead><tr><th>Host</th><th>Enrollment</th><th>Last seen</th><th>Version</th><th>Health</th><th>Revision</th><th aria-label="Actions" /></tr></thead>
                <tbody>{hosts.map((host) => {
                  const state = fleetHostState(host);
                  return <tr key={host.node_id}>
                    <td><strong>{host.node_id}</strong><div className="mono muted-cell">{host.endpoint}</div></td>
                    <td><span className={`fleet-state state-${state}`}><i />{host.enrollment_state}</span></td>
                    <td>{unixTime(host.last_seen_unix)}</td><td className="mono">{host.version || "Unknown"}</td>
                    <td><span className={`fleet-state state-${state}`}><i />{state}</span></td><td>{host.acknowledged_revision ?? "-"}</td>
                    <td>{operate && host.enrollment_state !== "revoked" ? <button className="btn btn-danger" disabled={busy} onClick={() => void runOperation("fleet_revoke", { node_id: host.node_id, reason: "operator revocation" })}>Revoke</button> : null}</td>
                  </tr>;
                })}</tbody>
              </table></div>
            </section>
          ) : null}

          {section === "containers" ? <>
            {operate ? <section className="panel fleet-form" aria-labelledby="fleet-run-title">
              <div><p className="eyebrow">Direct host action</p><h2 id="fleet-run-title">Run a container</h2></div>
              <label>Host<select value={runHost} onChange={(event) => setRunHost(event.target.value)}>{hosts.filter((host) => host.connected).map((host) => <option key={host.node_id}>{host.node_id}</option>)}</select></label>
              <label>Name<input value={runName} onChange={(event) => setRunName(event.target.value)} /></label>
              <label>Image<input value={runImage} onChange={(event) => setRunImage(event.target.value)} /></label>
              <label className="fleet-command-field">Command JSON<input value={runCommand} onChange={(event) => setRunCommand(event.target.value)} /></label>
              <button className="btn btn-primary" disabled={busy || !runHost || !runName || !runImage} onClick={() => {
                try { void runOperation("fleet_command", { node_id: runHost, action: "run_container", arguments: { name: runName, image: runImage, command: commandArray(runCommand) } }); }
                catch (nextError) { setError(String(nextError)); }
              }}><Icon name="play" size={16} />Run container</button>
            </section> : null}
            <section className="panel table-panel" aria-label="Fleet containers">
              <div className="table-scroll"><table>
                <thead><tr><th>Host</th><th>Name</th><th>Image</th><th>Status</th><th>Container ID</th><th aria-label="Actions" /></tr></thead>
                <tbody>{containers.map((container) => <tr key={`${container.hostId}:${container.id}`}>
                  <td>{container.hostId}</td><td><strong>{container.name}</strong></td><td className="mono">{container.image}</td><td>{container.status}</td><td className="mono muted-cell">{container.id}</td>
                  <td className="fleet-inline-actions"><button className="btn btn-secondary" disabled={busy} onClick={() => void runOperation("fleet_command", { node_id: container.hostId, action: "inspect_container", arguments: { container: container.id } })}>Inspect</button><button className="btn btn-secondary" disabled={busy} onClick={() => void runOperation("fleet_command", { node_id: container.hostId, action: "container_logs", arguments: { container: container.id } })}>Logs</button></td>
                </tr>)}</tbody>
              </table></div>
            </section>
            {result ? <section className="panel fleet-output" aria-live="polite"><h2>Command output</h2><pre>{result}</pre></section> : null}
          </> : null}

          {section === "deploys" ? <>
            {operate ? <section className="panel fleet-form deploy-form" aria-labelledby="fleet-deploy-title">
              <div><p className="eyebrow">Desired state</p><h2 id="fleet-deploy-title">Roll out a generation</h2></div>
              <label>Name<input value={deployName} onChange={(event) => setDeployName(event.target.value)} /></label>
              <label>Image<input value={deployImage} onChange={(event) => setDeployImage(event.target.value)} /></label>
              <label className="fleet-command-field">Command JSON<input value={deployCommand} onChange={(event) => setDeployCommand(event.target.value)} /></label>
              <fieldset><legend>Target hosts</legend>{hosts.filter((host) => host.connected).map((host) => <label key={host.node_id}><input type="checkbox" checked={deployHosts.includes(host.node_id)} onChange={(event) => setDeployHosts((current) => event.target.checked ? [...current, host.node_id] : current.filter((id) => id !== host.node_id))} />{host.node_id}</label>)}</fieldset>
              <button className="btn btn-primary" disabled={busy || !deployHosts.length} onClick={() => {
                try { void runOperation("fleet_deploy", { name: deployName, image: deployImage, command: commandArray(deployCommand), node_ids: deployHosts }); }
                catch (nextError) { setError(String(nextError)); }
              }}><Icon name="refresh" size={16} />Roll out</button>
            </section> : null}
            <section className="panel table-panel" aria-label="Fleet deploys"><div className="table-scroll"><table>
              <thead><tr><th>Revision</th><th>Name</th><th>Image</th><th>Hosts</th><th>Progress</th><th>Status</th><th aria-label="Actions" /></tr></thead>
              <tbody>{snapshot.deploys.map((deploy) => <tr key={deploy.deployment_id}><td>{deploy.revision}</td><td><strong>{deploy.name}</strong><div className="mono muted-cell">{deploy.deployment_id}</div></td><td className="mono">{deploy.image}</td><td>{deploy.node_ids.join(", ")}</td><td>{Object.values(deploy.progress).join(", ")}</td><td>{deploy.status}</td><td>{operate && deploy.status === "succeeded" && deploy.previous_deployment_id ? <button className="btn btn-secondary" disabled={busy} onClick={() => void runOperation("fleet_rollback", { deployment_id: deploy.deployment_id })}>Rollback</button> : null}</td></tr>)}</tbody>
            </table></div></section>
          </> : null}

          {section === "health" ? <section className="fleet-health-grid" aria-label="Host health summaries">
            {hosts.map((host) => <article className="panel fleet-health-card" key={host.node_id}><div><span className={`fleet-state state-${fleetHostState(host)}`}><i />{fleetHostState(host)}</span><h2>{host.node_id}</h2></div><dl><div><dt>Last seen</dt><dd>{unixTime(host.last_seen_unix)}</dd></div><div><dt>Version</dt><dd>{host.version || "Unknown"}</dd></div><div><dt>Applied revision</dt><dd>{host.acknowledged_revision ?? "-"}</dd></div></dl><details><summary>Doctor summary</summary><pre>{host.doctor_summary || "No Doctor report received."}</pre></details></article>)}
          </section> : null}
        </div>
      </main>
      <footer className="statusbar"><span><b>{hosts.length}</b> hosts · <b>{containers.length}</b> containers</span><span className="status-right">Refresh interval 5 seconds</span></footer>
    </div>
  );
}
