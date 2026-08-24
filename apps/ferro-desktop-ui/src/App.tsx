import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { useEffect, useMemo, useState } from "react";
import type {
  CommandResult,
  DesktopAction,
  DesktopSnapshot,
  DoctorSummary,
  InstallerRunSummary,
  PaidAuthState,
} from "./types";

const EMPTY = "No data yet";
const THEME_KEY = "ferro_desktop_theme";
type ThemeMode = "dark" | "light";

function formatUnix(value: number | null): string {
  if (!value) return "-";
  return new Date(value * 1000).toLocaleString();
}

function App(): JSX.Element {
  const [snapshot, setSnapshot] = useState<DesktopSnapshot | null>(null);
  const [authState, setAuthState] = useState<PaidAuthState | null>(null);
  const [loading, setLoading] = useState(false);
  const [authLoading, setAuthLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [theme, setTheme] = useState<ThemeMode>("dark");
  const [imageTarget, setImageTarget] = useState("alpine:latest");
  const [containerTarget, setContainerTarget] = useState("");
  const [lastAction, setLastAction] = useState<CommandResult | null>(null);
  const [actionLabel, setActionLabel] = useState("");
  const [logLines, setLogLines] = useState<string[]>([]);
  const [logFilter, setLogFilter] = useState("");
  const [logsFollowing, setLogsFollowing] = useState(false);
  const [logsPaused, setLogsPaused] = useState(false);
  const [pausedLogCount, setPausedLogCount] = useState(0);

  const [releaseBaseUrl, setReleaseBaseUrl] = useState("");
  const [tokenEndpoint, setTokenEndpoint] = useState("");
  const [issuanceEndpoint, setIssuanceEndpoint] = useState("");
  const [customerId, setCustomerId] = useState("");
  const [accessToken, setAccessToken] = useState("");
  const [sessionTokenInput, setSessionTokenInput] = useState("");
  const [installerResult, setInstallerResult] = useState<InstallerRunSummary | null>(null);
  const [doctorResult, setDoctorResult] = useState<DoctorSummary | null>(null);

  const [doctorFix, setDoctorFix] = useState(true);
  const [doctorBootstrap, setDoctorBootstrap] = useState(false);
  const [doctorDryRun, setDoctorDryRun] = useState(true);
  const [doctorConfirm, setDoctorConfirm] = useState(false);

  useEffect(() => {
    const saved = localStorage.getItem(THEME_KEY);
    if (saved === "dark" || saved === "light") {
      setTheme(saved);
      return;
    }
    const prefersDark = window.matchMedia("(prefers-color-scheme: dark)").matches;
    setTheme(prefersDark ? "dark" : "light");
  }, []);

  useEffect(() => {
    document.documentElement.setAttribute("data-theme", theme);
    localStorage.setItem(THEME_KEY, theme);
  }, [theme]);

  async function refresh(): Promise<void> {
    setLoading(true);
    setError(null);
    try {
      const next = await invoke<DesktopSnapshot>("get_desktop_snapshot");
      setSnapshot(next);
    } catch (err) {
      setError(String(err));
    } finally {
      setLoading(false);
    }
  }

  async function refreshAuthState(): Promise<void> {
    setAuthLoading(true);
    setError(null);
    try {
      const next = await invoke<PaidAuthState>("get_paid_auth_state");
      setAuthState(next);
      setReleaseBaseUrl(next.config?.release_base_url ?? "");
      setTokenEndpoint(next.config?.token_endpoint ?? "");
      setIssuanceEndpoint(next.config?.issuance_endpoint ?? "");
      setSessionTokenInput("");
    } catch (err) {
      setError(String(err));
    } finally {
      setAuthLoading(false);
    }
  }

  useEffect(() => {
    void refresh();
    void refreshAuthState();
  }, []);

  useEffect(() => {
    let disposed = false;
    let unlistenLine: (() => void) | undefined;
    let unlistenError: (() => void) | undefined;
    let unlistenEnded: (() => void) | undefined;

    void (async () => {
      const stopLine = await listen<string>("container-log-line", (event) => {
        setLogLines((lines) => [...lines, event.payload]);
      });
      const stopError = await listen<string>("container-log-error", (event) => {
        setError(event.payload);
      });
      const stopEnded = await listen<boolean>("container-log-ended", (event) => {
        setLogsFollowing(false);
        setLogsPaused(false);
        if (!event.payload) setError("Container log stream ended unexpectedly");
      });
      if (disposed) {
        stopLine();
        stopError();
        stopEnded();
        return;
      }
      unlistenLine = stopLine;
      unlistenError = stopError;
      unlistenEnded = stopEnded;
    })();

    return () => {
      disposed = true;
      unlistenLine?.();
      unlistenError?.();
      unlistenEnded?.();
    };
  }, []);

  async function runAction(action: DesktopAction, label: string, target?: string): Promise<void> {
    setActionLabel(label);
    const result = await invoke<CommandResult>("run_desktop_action", { action, target });
    setLastAction(result);
    await refresh();
  }

  async function startLogFollow(): Promise<void> {
    setError(null);
    setLogLines([]);
    setLogsPaused(false);
    setPausedLogCount(0);
    try {
      await invoke("start_log_follow", { target: containerTarget });
      setLogsFollowing(true);
    } catch (err) {
      setError(String(err));
    }
  }

  async function stopLogFollow(): Promise<void> {
    try {
      await invoke("stop_log_follow");
      setLogsFollowing(false);
      setLogsPaused(false);
    } catch (err) {
      setError(String(err));
    }
  }

  function toggleLogPause(): void {
    if (logsPaused) {
      setLogsPaused(false);
      return;
    }
    setPausedLogCount(logLines.length);
    setLogsPaused(true);
  }

  async function saveBackendConfig(): Promise<void> {
    setError(null);
    try {
      await invoke("save_paid_backend_config", {
        release_base_url: releaseBaseUrl,
        token_endpoint: tokenEndpoint,
        issuance_endpoint: issuanceEndpoint.trim() ? issuanceEndpoint : null,
      });
      await refreshAuthState();
    } catch (err) {
      setError(String(err));
    }
  }

  async function saveSessionToken(): Promise<void> {
    setError(null);
    try {
      await invoke("set_paid_session_token", { token: sessionTokenInput });
      setSessionTokenInput("");
      await refreshAuthState();
    } catch (err) {
      setError(String(err));
    }
  }

  async function acquireSessionToken(): Promise<void> {
    setError(null);
    try {
      await invoke("acquire_paid_session", {
        customer_id: customerId,
        access_token: accessToken.trim() ? accessToken : null,
      });
      setSessionTokenInput("");
      await refreshAuthState();
    } catch (err) {
      setError(String(err));
    }
  }

  async function clearSessionToken(): Promise<void> {
    setError(null);
    try {
      await invoke("clear_paid_session");
      await refreshAuthState();
    } catch (err) {
      setError(String(err));
    }
  }

  async function runInstaller(dryRun: boolean, confirm: boolean): Promise<void> {
    setError(null);
    try {
      const result = await invoke<InstallerRunSummary>("run_paid_full_stack_install", {
        dry_run: dryRun,
        confirm,
      });
      setInstallerResult(result);
      await refresh();
      await refreshAuthState();
    } catch (err) {
      setError(String(err));
    }
  }

  async function runDoctor(): Promise<void> {
    setError(null);
    try {
      const result = await invoke<DoctorSummary>("run_doctor_action", {
        fix: doctorFix,
        bootstrap: doctorBootstrap,
        dry_run: doctorDryRun,
        confirm: doctorConfirm,
      });
      setDoctorResult(result);
      await refresh();
    } catch (err) {
      setError(String(err));
    }
  }

  const sessionSummary = useMemo(() => authState?.session, [authState]);
  const visibleLogText = useMemo(() => {
    const visibleLines = logsPaused ? logLines.slice(0, pausedLogCount) : logLines;
    const filter = logFilter.trim();
    return (filter ? visibleLines.filter((line) => line.includes(filter)) : visibleLines).join("");
  }, [logFilter, logLines, logsPaused, pausedLogCount]);

  async function copyLogs(): Promise<void> {
    try {
      await navigator.clipboard.writeText(visibleLogText);
    } catch (err) {
      setError(`Failed to copy logs: ${String(err)}`);
    }
  }

  function exportLogs(): void {
    const file = new Blob([visibleLogText], { type: "text/plain" });
    const url = URL.createObjectURL(file);
    const link = document.createElement("a");
    link.href = url;
    link.download = `${containerTarget.trim() || "container"}-logs.txt`;
    link.click();
    URL.revokeObjectURL(url);
  }

  return (
    <main className="app-shell">
      <header className="app-header">
        <h1>FerroCrate Desktop</h1>
        <div className="actions">
          <button
            className="btn btn-secondary"
            onClick={() => setTheme(theme === "dark" ? "light" : "dark")}
          >
            Theme: {theme === "dark" ? "Dark" : "Light"}
          </button>
          <button className="btn btn-primary" onClick={() => void refresh()} disabled={loading}>
            {loading ? "Refreshing..." : "Refresh Runtime"}
          </button>
          <button className="btn btn-secondary" onClick={() => void refreshAuthState()} disabled={authLoading}>
            {authLoading ? "Refreshing..." : "Refresh Auth"}
          </button>
        </div>
      </header>

      {error ? <p className="error">{error}</p> : null}

      <section className="grid">
        <article className="panel panel-wide">
          <h2>Paid Auth</h2>
          <p className="muted">
            Configure issuance backend endpoints, then set a short-lived paid session token.
          </p>
          <div className="field-row">
            <input
              value={releaseBaseUrl}
              onChange={(event) => setReleaseBaseUrl(event.target.value)}
              placeholder="release base URL (e.g. https://gateway.example.com/v1/releases/{tag})"
            />
          </div>
          <div className="field-row">
            <input
              value={tokenEndpoint}
              onChange={(event) => setTokenEndpoint(event.target.value)}
              placeholder="token endpoint (e.g. https://gateway.example.com/v1/token)"
            />
          </div>
          <div className="field-row">
            <input
              value={issuanceEndpoint}
              onChange={(event) => setIssuanceEndpoint(event.target.value)}
              placeholder="session issuance endpoint (e.g. https://issuer.example.com/v1/desktop/session)"
            />
          </div>
          <div className="panel-actions">
            <button className="btn btn-secondary" onClick={() => void saveBackendConfig()}>
              Save Backend Config
            </button>
          </div>
          <div className="field-row">
            <input
              value={customerId}
              onChange={(event) => setCustomerId(event.target.value)}
              placeholder="customer id (for backend session issuance)"
            />
          </div>
          <div className="field-row">
            <input
              value={accessToken}
              onChange={(event) => setAccessToken(event.target.value)}
              placeholder="optional access token for issuance backend"
            />
          </div>
          <div className="panel-actions">
            <button className="btn btn-secondary" onClick={() => void acquireSessionToken()}>
              Acquire Session Token
            </button>
          </div>
          <div className="field-row">
            <input
              value={sessionTokenInput}
              onChange={(event) => setSessionTokenInput(event.target.value)}
              placeholder="paste session JWT"
            />
          </div>
          <div className="panel-actions">
            <button className="btn btn-secondary" onClick={() => void saveSessionToken()}>
              Save Session Token
            </button>
            <button className="btn btn-danger" onClick={() => void clearSessionToken()}>
              Clear Session Token
            </button>
          </div>
          <pre>
{`token_present=${sessionSummary?.token_present ? "yes" : "no"}
subject=${sessionSummary?.subject ?? "-"}
plan=${sessionSummary?.plan ?? "-"}
expires_at=${formatUnix(sessionSummary?.expires_at ?? null)}
expired=${sessionSummary?.expired == null ? "-" : sessionSummary?.expired ? "yes" : "no"}`}
          </pre>
          <pre>
{`entitlement_status=${authState?.entitlement?.status ?? "-"}
entitlement_plan=${authState?.entitlement?.plan ?? "-"}
entitlement_expires=${formatUnix(authState?.entitlement?.expires_at ?? null)}
entitlement_message=${authState?.entitlement?.message ?? "-"}`}
          </pre>
        </article>

        <article className="panel panel-wide">
          <h2>Install + Bootstrap</h2>
          <p className="muted">
            Full paid install path uses saved backend config and session token.
          </p>
          <div className="panel-actions">
            <button className="btn btn-secondary" onClick={() => void runInstaller(true, false)}>
              Dry-Run Install
            </button>
            <button className="btn btn-primary" onClick={() => void runInstaller(false, true)}>
              Run Full Install
            </button>
          </div>
          <pre>{installerResult ? JSON.stringify(installerResult, null, 2) : EMPTY}</pre>
        </article>

        <article className="panel panel-wide">
          <h2>Doctor</h2>
          <div className="check-row">
            <label>
              <input
                type="checkbox"
                checked={doctorFix}
                onChange={(event) => setDoctorFix(event.target.checked)}
              />
              Fix
            </label>
            <label>
              <input
                type="checkbox"
                checked={doctorBootstrap}
                onChange={(event) => setDoctorBootstrap(event.target.checked)}
              />
              Bootstrap
            </label>
            <label>
              <input
                type="checkbox"
                checked={doctorDryRun}
                onChange={(event) => setDoctorDryRun(event.target.checked)}
              />
              Dry-Run
            </label>
            <label>
              <input
                type="checkbox"
                checked={doctorConfirm}
                onChange={(event) => setDoctorConfirm(event.target.checked)}
              />
              Confirm (--yes)
            </label>
          </div>
          <div className="panel-actions">
            <button className="btn btn-secondary" onClick={() => void runDoctor()}>
              Run Doctor
            </button>
          </div>
          <pre>{doctorResult ? JSON.stringify(doctorResult.raw, null, 2) : EMPTY}</pre>
        </article>

        <article className="panel">
          <h2>Runtime Status</h2>
          <div className="panel-actions">
            <button className="btn btn-secondary" onClick={() => void runAction("vm_start", "VM Start")}>
              VM Start
            </button>
            <button className="btn btn-secondary" onClick={() => void runAction("vm_stop", "VM Stop")}>
              VM Stop
            </button>
          </div>
          <pre>{snapshot?.runtime.stdout || EMPTY}</pre>
          {snapshot?.runtime.stderr ? <p className="muted">{snapshot.runtime.stderr}</p> : null}
        </article>

        <article className="panel panel-wide">
          <h2>Containers</h2>
          <div className="field-row">
            <input
              value={containerTarget}
              onChange={(event) => setContainerTarget(event.target.value)}
              placeholder="container name/id"
            />
          </div>
          <div className="panel-actions">
            <button
              className="btn btn-secondary"
              onClick={() => void runAction("start_container", "Container Start", containerTarget)}
              disabled={logsFollowing}
            >
              Start
            </button>
            <button
              className="btn btn-secondary"
              onClick={() => void runAction("stop_container", "Container Stop", containerTarget)}
              disabled={logsFollowing}
            >
              Stop
            </button>
            <button
              className="btn btn-secondary"
              onClick={() => void startLogFollow()}
              disabled={logsFollowing}
            >
              {logsFollowing ? "Following Logs" : "Follow Logs"}
            </button>
            <button
              className="btn btn-danger"
              onClick={() => void runAction("remove_container", "Container Remove", containerTarget)}
              disabled={logsFollowing}
            >
              Remove
            </button>
          </div>
          <div className="field-row">
            <input
              value={logFilter}
              onChange={(event) => setLogFilter(event.target.value)}
              placeholder="filter streamed logs"
            />
          </div>
          <div className="panel-actions">
            <button className="btn btn-secondary" onClick={toggleLogPause} disabled={!logsFollowing}>
              {logsPaused ? "Resume Logs" : "Pause Logs"}
            </button>
            <button className="btn btn-secondary" onClick={() => void copyLogs()} disabled={!visibleLogText}>
              Copy Logs
            </button>
            <button className="btn btn-secondary" onClick={exportLogs} disabled={!visibleLogText}>
              Export Logs
            </button>
            <button className="btn btn-danger" onClick={() => void stopLogFollow()} disabled={!logsFollowing}>
              Stop Following
            </button>
          </div>
          <pre>{visibleLogText || (logsFollowing ? "Waiting for log lines..." : EMPTY)}</pre>
          <pre>{snapshot?.containers.stdout || EMPTY}</pre>
          {snapshot?.containers.stderr ? <p className="muted">{snapshot.containers.stderr}</p> : null}
        </article>

        <article className="panel">
          <h2>Images</h2>
          <div className="field-row">
            <input
              value={imageTarget}
              onChange={(event) => setImageTarget(event.target.value)}
              placeholder="image:tag"
            />
          </div>
          <div className="panel-actions">
            <button
              className="btn btn-secondary"
              onClick={() => void runAction("pull_image", "Image Pull", imageTarget)}
            >
              Pull
            </button>
            <button
              className="btn btn-danger"
              onClick={() => void runAction("remove_image", "Image Remove", imageTarget)}
            >
              Remove
            </button>
            <button className="btn btn-secondary" onClick={() => void runAction("image_prune", "Image Prune")}>
              Prune
            </button>
          </div>
          <pre>{snapshot?.images.stdout || EMPTY}</pre>
          {snapshot?.images.stderr ? <p className="muted">{snapshot.images.stderr}</p> : null}
        </article>

        <article className="panel">
          <h2>Last Action: {actionLabel || "none"}</h2>
          <pre>{lastAction?.stdout || EMPTY}</pre>
          {lastAction?.stderr ? <p className="muted">{lastAction.stderr}</p> : null}
        </article>
      </section>
    </main>
  );
}

export default App;
