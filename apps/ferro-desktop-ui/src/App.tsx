import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { open } from "@tauri-apps/plugin-dialog";
import { Terminal } from "@xterm/xterm";
import "@xterm/xterm/css/xterm.css";
import { useEffect, useMemo, useRef, useState } from "react";
import type {
  CommandResult,
  BuildProgressFrame,
  ComposeAction,
  ComposeServiceSummary,
  ComposeSnapshot,
  ContainerDetailSummary,
  DesktopAction,
  DesktopSnapshot,
  DoctorSummary,
  InstallerRunSummary,
  PaidAuthState,
  RegistryAuthStatus,
  NetworkAction,
  NetworkSummary,
  VolumeAction,
  VolumeSummary,
} from "./types";
import { composeLogTarget, composeStatusClass } from "./composeView.mjs";
import { maskEnvironment, parseOptionalLimit } from "./containerDetail.mjs";
import { buildStepText } from "./imageBuild.mjs";
import { ImageEmptyState, ImagePagePullAction, parseImageRows, PullImageDialog, pullFailurePresentation } from "./imageView.mjs";
import { formatNetworkAttachment, networkIsRemovable } from "./networkView.mjs";
import { RegistryAccountControl, registryStatusText } from "./registryAuth.mjs";
import {
  applyRemoteTerminalResize,
  applyTerminalResize,
  DEFAULT_TERMINAL_ENV,
} from "./terminalResize.mjs";
import { formatVolumeMount, volumeIsInUse } from "./volumeView.mjs";
import { daemonIsAvailable, filterContainers, parseContainerRows, shellKeyboardCommand, statusTone } from "./forgeShell.mjs";

const EMPTY = "No data yet";
const THEME_KEY = "ferro_desktop_theme";
type ThemeMode = "dark" | "light";
type AppSection = "containers" | "images" | "volumes" | "compose" | "networks" | "doctor" | "settings";
type DetailTab = "logs" | "terminal" | "inspect" | "stats";
type LogBatch = { text: string; truncated: boolean };
type TerminalOutput = { data: number[]; stderr: boolean };
type PullFailure = ReturnType<typeof pullFailurePresentation>;

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
  const [activeSection, setActiveSection] = useState<AppSection>("containers");
  const [detailTab, setDetailTab] = useState<DetailTab>("logs");
  const [globalSearch, setGlobalSearch] = useState("");
  const [imageTarget, setImageTarget] = useState("alpine:latest");
  const [pullImageDialogOpen, setPullImageDialogOpen] = useState(false);
  const [buildImageDialogOpen, setBuildImageDialogOpen] = useState(false);
  const [registryDialogOpen, setRegistryDialogOpen] = useState(false);
  const [pullProgress, setPullProgress] = useState("");
  const [pullFailure, setPullFailure] = useState<PullFailure | null>(null);
  const [containerTarget, setContainerTarget] = useState("");
  const [lastAction, setLastAction] = useState<CommandResult | null>(null);
  const [actionLabel, setActionLabel] = useState("");
  const [logOutput, setLogOutput] = useState("");
  const [logFilter, setLogFilter] = useState("");
  const [logsFollowing, setLogsFollowing] = useState(false);
  const [logsPaused, setLogsPaused] = useState(false);
  const [pausedLogOutput, setPausedLogOutput] = useState("");
  const [runtimeActionBusy, setRuntimeActionBusy] = useState(false);
  const runtimeActionRef = useRef(false);
  const logFollowRef = useRef(false);
  const terminalHostRef = useRef<HTMLDivElement | null>(null);
  const globalSearchRef = useRef<HTMLInputElement | null>(null);
  const terminalRef = useRef<Terminal | null>(null);
  const terminalActiveRef = useRef(false);
  const [terminalActive, setTerminalActive] = useState(false);
  const [terminalShell, setTerminalShell] = useState("sh");
  const [terminalEnv, setTerminalEnv] = useState(DEFAULT_TERMINAL_ENV);
  const [terminalUser, setTerminalUser] = useState("");
  const [terminalWorkdir, setTerminalWorkdir] = useState("");
  const [volumes, setVolumes] = useState<VolumeSummary[]>([]);
  const [volumeName, setVolumeName] = useState("");
  const [volumesLoading, setVolumesLoading] = useState(false);
  const [networks, setNetworks] = useState<NetworkSummary[]>([]);
  const [networkName, setNetworkName] = useState("");
  const [networkSubnet, setNetworkSubnet] = useState("");
  const [networksLoading, setNetworksLoading] = useState(false);
  const [composeFile, setComposeFile] = useState("");
  const [composeSnapshot, setComposeSnapshot] = useState<ComposeSnapshot | null>(null);
  const [composeLoading, setComposeLoading] = useState(false);
  const [buildContext, setBuildContext] = useState("");
  const [buildTag, setBuildTag] = useState("local/build:latest");
  const [buildSteps, setBuildSteps] = useState<BuildProgressFrame[]>([]);
  const [containerDetail, setContainerDetail] = useState<ContainerDetailSummary | null>(null);
  const [showEnvironment, setShowEnvironment] = useState(false);
  const [detailMemory, setDetailMemory] = useState("");
  const [detailCpuQuota, setDetailCpuQuota] = useState("");
  const [detailCpuPeriod, setDetailCpuPeriod] = useState("");
  const [runDialogOpen, setRunDialogOpen] = useState(false);
  const [newContainerImage, setNewContainerImage] = useState("alpine:latest");
  const [newContainerName, setNewContainerName] = useState("");
  const [newContainerEnvironment, setNewContainerEnvironment] = useState("");
  const [newContainerMemory, setNewContainerMemory] = useState("");
  const [newContainerCpuQuota, setNewContainerCpuQuota] = useState("");
  const [newContainerCpuPeriod, setNewContainerCpuPeriod] = useState("");
  const [registryTarget, setRegistryTarget] = useState("registry-1.docker.io");
  const [registryUsername, setRegistryUsername] = useState("");
  const [registryPassword, setRegistryPassword] = useState("");
  const [registryStatus, setRegistryStatus] = useState<RegistryAuthStatus | null>(null);
  const [registryLoading, setRegistryLoading] = useState(false);

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
    let disposed = false;
    let unlisten: (() => void) | undefined;
    void listen<BuildProgressFrame>("image-build-progress", (event) => {
      setBuildSteps((steps) => [...steps, event.payload]);
    }).then((stop) => {
      if (disposed) stop(); else unlisten = stop;
    });
    return () => { disposed = true; unlisten?.(); };
  }, []);

  useEffect(() => {
    const host = terminalHostRef.current;
    if (!host || terminalRef.current) return;
    const terminal = new Terminal({
      cursorBlink: true,
      convertEol: true,
      fontFamily: '"JetBrains Mono", "Fira Code", monospace',
      fontSize: 13,
      rows: 18,
      theme: theme === "dark"
        ? { background: "#16120f", foreground: "#e7ecef", cursor: "#f0691f" }
        : { background: "#16120f", foreground: "#e8e2db", cursor: "#f59e0b" },
    });
    terminal.open(host);
    terminal.onData((data) => {
      if (!terminalActiveRef.current) return;
      void invoke("write_terminal", { data: Array.from(new TextEncoder().encode(data)) }).catch((err) => {
        setError(String(err));
      });
    });
    terminal.writeln("Select a running container and open a shell.");
    terminalRef.current = terminal;

    const observer = new ResizeObserver(([entry]) => {
      if (!entry) return;
      applyTerminalResize(
        entry.contentRect.width,
        entry.contentRect.height,
        terminalActiveRef.current,
        (columns, rows) => terminal.resize(columns, rows),
        (columns, rows) => {
          void invoke("resize_terminal", { columns, rows }).catch((err) => setError(String(err)));
        },
      );
    });
    observer.observe(host);
    return () => {
      observer.disconnect();
      terminal.dispose();
      terminalRef.current = null;
    };
  }, []);

  useEffect(() => {
    const terminal = terminalRef.current;
    if (!terminal) return;
    terminal.options.theme = theme === "dark"
      ? { background: "#16120f", foreground: "#e7ecef", cursor: "#f0691f" }
      : { background: "#16120f", foreground: "#e8e2db", cursor: "#f59e0b" };
  }, [theme]);

  useEffect(() => {
    let disposed = false;
    let unlistenOutput: (() => void) | undefined;
    let unlistenError: (() => void) | undefined;
    let unlistenEnded: (() => void) | undefined;
    void (async () => {
      const stopOutput = await listen<TerminalOutput>("terminal-output", (event) => {
        terminalRef.current?.write(new Uint8Array(event.payload.data));
      });
      const stopError = await listen<string>("terminal-error", (event) => setError(event.payload));
      const stopEnded = await listen<boolean>("terminal-ended", (event) => {
        terminalActiveRef.current = false;
        setTerminalActive(false);
        terminalRef.current?.writeln(event.payload ? "\r\n[exec exited]" : "\r\n[exec failed]");
      });
      if (disposed) {
        stopOutput();
        stopError();
        stopEnded();
        return;
      }
      unlistenOutput = stopOutput;
      unlistenError = stopError;
      unlistenEnded = stopEnded;
    })();
    return () => {
      disposed = true;
      unlistenOutput?.();
      unlistenError?.();
      unlistenEnded?.();
    };
  }, []);

  useEffect(() => {
    document.documentElement.setAttribute("data-theme", theme);
    localStorage.setItem(THEME_KEY, theme);
  }, [theme]);

  useEffect(() => {
    const onKeyDown = (event: KeyboardEvent) => {
      const command = shellKeyboardCommand(event);
      if (command === "focus-search") {
        event.preventDefault();
        globalSearchRef.current?.focus();
      } else if (command === "close-dialog" && runDialogOpen) {
        setRunDialogOpen(false);
      }
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [runDialogOpen]);

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

  async function refreshRegistryAuth(target = registryTarget): Promise<void> {
    setRegistryLoading(true);
    setError(null);
    try {
      setRegistryStatus(await invoke<RegistryAuthStatus>("get_registry_auth_status", {
        registry: target,
      }));
    } catch (err) {
      setError(String(err));
    } finally {
      setRegistryLoading(false);
    }
  }

  async function refreshVolumes(): Promise<void> {
    setVolumesLoading(true);
    try {
      setVolumes(await invoke<VolumeSummary[]>("get_volumes"));
    } catch (err) {
      setError(String(err));
    } finally {
      setVolumesLoading(false);
    }
  }

  async function refreshNetworks(): Promise<void> {
    setNetworksLoading(true);
    try {
      setNetworks(await invoke<NetworkSummary[]>("get_networks"));
    } catch (err) {
      setError(String(err));
    } finally {
      setNetworksLoading(false);
    }
  }

  async function readComposeSnapshot(file: string): Promise<void> {
    setComposeLoading(true);
    try {
      setComposeSnapshot(await invoke<ComposeSnapshot>("get_compose_snapshot", { file }));
    } finally {
      setComposeLoading(false);
    }
  }

  async function chooseComposeFile(): Promise<void> {
    try {
      const selected = await open({
        multiple: false,
        directory: false,
        filters: [{ name: "Compose files", extensions: ["yml", "yaml"] }],
      });
      if (typeof selected !== "string") return;
      setComposeFile(selected);
      setError(null);
      await readComposeSnapshot(selected);
    } catch (err) {
      setError(String(err));
    }
  }

  async function chooseBuildContext(): Promise<void> {
    try {
      const selected = await open({ multiple: false, directory: true });
      if (typeof selected === "string") setBuildContext(selected);
    } catch (err) {
      setError(String(err));
    }
  }

  useEffect(() => {
    void refresh();
    void refreshAuthState();
    void refreshVolumes();
    void refreshNetworks();
    void refreshRegistryAuth("registry-1.docker.io");
  }, []);

  useEffect(() => {
    let disposed = false;
    let unlistenBatch: (() => void) | undefined;
    let unlistenError: (() => void) | undefined;
    let unlistenEnded: (() => void) | undefined;

    void (async () => {
      const stopBatch = await listen<LogBatch>("container-log-batch", (event) => {
        setLogOutput(event.payload.text);
      });
      const stopError = await listen<string>("container-log-error", (event) => {
        setError(event.payload);
      });
      const stopEnded = await listen<boolean>("container-log-ended", (event) => {
        logFollowRef.current = false;
        setLogsFollowing(false);
        setLogsPaused(false);
        if (!event.payload) setError("Container log stream ended unexpectedly");
      });
      if (disposed) {
        stopBatch();
        stopError();
        stopEnded();
        return;
      }
      unlistenBatch = stopBatch;
      unlistenError = stopError;
      unlistenEnded = stopEnded;
    })();

    return () => {
      disposed = true;
      unlistenBatch?.();
      unlistenError?.();
      unlistenEnded?.();
    };
  }, []);

  function beginRuntimeAction(allowWhileStreaming = false): boolean {
    if (
      runtimeActionRef.current
      || ((logFollowRef.current || terminalActiveRef.current) && !allowWhileStreaming)
    ) {
      return false;
    }
    runtimeActionRef.current = true;
    setRuntimeActionBusy(true);
    return true;
  }

  function finishRuntimeAction(): void {
    runtimeActionRef.current = false;
    setRuntimeActionBusy(false);
  }

  async function runAction(action: DesktopAction, label: string, target?: string): Promise<void> {
    if (!beginRuntimeAction()) return;
    setActionLabel(label);
    try {
      const result = await invoke<CommandResult>("run_desktop_action", { action, target });
      setLastAction(result);
      await refresh();
    } catch (err) {
      setError(String(err));
    } finally {
      finishRuntimeAction();
    }
  }

  async function pullImage(): Promise<void> {
    if (!beginRuntimeAction()) return;
    setLastAction(null);
    setActionLabel("Image Pull");
    setPullFailure(null);
    setPullProgress("Pull in progress. This may take a moment.");
    try {
      const result = await invoke<CommandResult>("run_desktop_action", { action: "pull_image", target: imageTarget });
      if (result.ok) {
        setLastAction(result);
        setPullProgress("Pull completed.");
      } else {
        setPullProgress("");
        setPullFailure(pullFailurePresentation(result.stderr));
      }
      await refresh();
    } catch (err) {
      setPullProgress("");
      setPullFailure(pullFailurePresentation(err));
    } finally {
      finishRuntimeAction();
    }
  }

  function openPullImageDialog(): void {
    setPullProgress("");
    setPullFailure(null);
    setPullImageDialogOpen(true);
  }

  async function startFerrocrate(): Promise<void> {
    if (!beginRuntimeAction()) return;
    setLastAction(null);
    setPullFailure(null);
    setPullProgress("Starting Ferrocrate…");
    try {
      const result = await invoke<CommandResult>("run_desktop_action", { action: "vm_start" });
      if (result.ok) {
        setLastAction(result);
        setPullProgress("Ferrocrate is starting. Try the pull again in a moment.");
      } else {
        setPullProgress("");
        setPullFailure(pullFailurePresentation(result.stderr));
      }
      await refresh();
    } catch (err) {
      setPullProgress("");
      setPullFailure(pullFailurePresentation(err));
    } finally {
      finishRuntimeAction();
    }
  }

  async function startLogFollow(target = containerTarget): Promise<void> {
    if (!beginRuntimeAction()) return;
    setError(null);
    setLogOutput("");
    setLogsPaused(false);
    setPausedLogOutput("");
    try {
      await invoke("start_log_follow", { target });
      logFollowRef.current = true;
      setLogsFollowing(true);
    } catch (err) {
      setError(String(err));
    } finally {
      finishRuntimeAction();
    }
  }

  async function stopLogFollow(): Promise<void> {
    if (!logFollowRef.current || !beginRuntimeAction(true)) return;
    try {
      await invoke("stop_log_follow");
      logFollowRef.current = false;
      setLogsFollowing(false);
      setLogsPaused(false);
    } catch (err) {
      setError(String(err));
    } finally {
      finishRuntimeAction();
    }
  }

  function toggleLogPause(): void {
    if (logsPaused) {
      setLogsPaused(false);
      return;
    }
    setPausedLogOutput(logOutput);
    setLogsPaused(true);
  }

  async function startTerminal(): Promise<void> {
    if (!beginRuntimeAction()) return;
    setError(null);
    terminalRef.current?.clear();
    try {
      await invoke("start_terminal", {
        target: containerTarget,
        shell: terminalShell,
        env: terminalEnv.split("\n").map((value) => value.trim()).filter(Boolean),
        user: terminalUser.trim() || null,
        workdir: terminalWorkdir.trim() || null,
      });
      terminalActiveRef.current = true;
      setTerminalActive(true);
      const terminal = terminalRef.current;
      if (terminal) {
        applyRemoteTerminalResize(terminal.cols, terminal.rows, true, (columns, rows) => {
          void invoke("resize_terminal", { columns, rows }).catch((err) => setError(String(err)));
        });
        terminal.focus();
      }
    } catch (err) {
      setError(String(err));
    } finally {
      finishRuntimeAction();
    }
  }

  async function closeTerminal(): Promise<void> {
    if (!terminalActiveRef.current || !beginRuntimeAction(true)) return;
    try {
      await invoke("close_terminal");
      terminalActiveRef.current = false;
      setTerminalActive(false);
      terminalRef.current?.writeln("\r\n[detached; container left running]");
    } catch (err) {
      setError(String(err));
    } finally {
      finishRuntimeAction();
    }
  }

  async function runVolumeAction(
    action: VolumeAction,
    label: string,
    target?: string,
  ): Promise<void> {
    if (!beginRuntimeAction()) return;
    setError(null);
    setActionLabel(label);
    try {
      const result = await invoke<CommandResult>("run_volume_action", { action, target });
      setLastAction(result);
      if (!result.ok) {
        setError(result.stderr || `${label} failed with status ${result.code}`);
        return;
      }
      if (action === "create") setVolumeName("");
      await Promise.all([refreshVolumes(), refresh()]);
    } catch (err) {
      setError(String(err));
    } finally {
      finishRuntimeAction();
    }
  }

  async function runNetworkAction(
    action: NetworkAction,
    label: string,
    target: string,
  ): Promise<void> {
    if (!beginRuntimeAction()) return;
    setError(null);
    setActionLabel(label);
    try {
      const result = await invoke<CommandResult>("run_network_action", {
        action,
        target,
        subnet: action === "create" ? networkSubnet.trim() || null : null,
      });
      setLastAction(result);
      if (!result.ok) {
        setError(result.stderr || `${label} failed with status ${result.code}`);
        return;
      }
      if (action === "create") {
        setNetworkName("");
        setNetworkSubnet("");
      }
      await Promise.all([refreshNetworks(), refresh()]);
    } catch (err) {
      setError(String(err));
    } finally {
      finishRuntimeAction();
    }
  }

  async function inspectContainer(target = containerTarget): Promise<void> {
    if (!beginRuntimeAction()) return;
    setError(null);
    try {
      const detail = await invoke<ContainerDetailSummary>("get_container_detail", { target });
      setContainerTarget(target);
      setContainerDetail(detail);
      setShowEnvironment(false);
      setDetailMemory(String(detail.resources.memory));
      setDetailCpuQuota(String(detail.resources.cpu_quota));
      setDetailCpuPeriod(String(detail.resources.cpu_period));
    } catch (err) {
      setError(String(err));
    } finally {
      finishRuntimeAction();
    }
  }

  async function updateContainerResources(): Promise<void> {
    if (!containerDetail || !beginRuntimeAction()) return;
    setError(null);
    setActionLabel("Container Update");
    try {
      const result = await invoke<CommandResult>("update_container_resources", {
        target: containerDetail.id,
        memory: parseOptionalLimit(detailMemory),
        cpuQuota: parseOptionalLimit(detailCpuQuota),
        cpuPeriod: parseOptionalLimit(detailCpuPeriod),
      });
      setLastAction(result);
      if (!result.ok) {
        setError(result.stderr || `Container update failed with status ${result.code}`);
        return;
      }
      const detail = await invoke<ContainerDetailSummary>("get_container_detail", {
        target: containerDetail.id,
      });
      setContainerDetail(detail);
      setDetailMemory(String(detail.resources.memory));
      setDetailCpuQuota(String(detail.resources.cpu_quota));
      setDetailCpuPeriod(String(detail.resources.cpu_period));
    } catch (err) {
      setError(String(err));
    } finally {
      finishRuntimeAction();
    }
  }

  async function runNewContainer(): Promise<void> {
    if (!beginRuntimeAction()) return;
    setError(null);
    setActionLabel("Container Run");
    try {
      const result = await invoke<CommandResult>("run_new_container", {
        image: newContainerImage,
        name: newContainerName.trim() || null,
        environment: newContainerEnvironment
          .split("\n")
          .map((value) => value.trim())
          .filter(Boolean),
        memory: parseOptionalLimit(newContainerMemory),
        cpuQuota: parseOptionalLimit(newContainerCpuQuota),
        cpuPeriod: parseOptionalLimit(newContainerCpuPeriod),
      });
      setLastAction(result);
      if (!result.ok) {
        setError(result.stderr || `Container run failed with status ${result.code}`);
        return;
      }
      setRunDialogOpen(false);
      setNewContainerName("");
      setNewContainerEnvironment("");
      await Promise.all([refresh(), refreshNetworks(), refreshVolumes()]);
    } catch (err) {
      setError(String(err));
    } finally {
      finishRuntimeAction();
    }
  }

  async function loginRegistry(): Promise<void> {
    if (!beginRuntimeAction()) return;
    setError(null);
    setActionLabel("Registry Login");
    setRegistryLoading(true);
    try {
      const result = await invoke<CommandResult>("login_registry", {
        registry: registryTarget,
        username: registryUsername,
        password: registryPassword,
      });
      setLastAction(result);
      if (!result.ok) {
        setError(result.stderr || `Registry login failed with status ${result.code}`);
        return;
      }
      setRegistryPassword("");
      setRegistryStatus(await invoke<RegistryAuthStatus>("get_registry_auth_status", {
        registry: registryTarget,
      }));
    } catch (err) {
      setError(String(err));
    } finally {
      setRegistryLoading(false);
      finishRuntimeAction();
    }
  }

  async function logoutRegistry(): Promise<void> {
    if (!beginRuntimeAction()) return;
    setError(null);
    setActionLabel("Registry Logout");
    setRegistryLoading(true);
    try {
      const result = await invoke<CommandResult>("logout_registry", {
        registry: registryTarget,
      });
      setLastAction(result);
      if (!result.ok) {
        setError(result.stderr || `Registry logout failed with status ${result.code}`);
        return;
      }
      setRegistryPassword("");
      setRegistryStatus(await invoke<RegistryAuthStatus>("get_registry_auth_status", {
        registry: registryTarget,
      }));
    } catch (err) {
      setError(String(err));
    } finally {
      setRegistryLoading(false);
      finishRuntimeAction();
    }
  }

  async function validateCompose(): Promise<void> {
    if (!beginRuntimeAction()) return;
    setError(null);
    setActionLabel("Compose Config");
    try {
      await readComposeSnapshot(composeFile);
      setLastAction({ ok: true, code: 0, stdout: "Compose configuration is valid.", stderr: "" });
    } catch (err) {
      setError(String(err));
    } finally {
      finishRuntimeAction();
    }
  }

  async function runComposeAction(action: ComposeAction, label: string): Promise<void> {
    if (!beginRuntimeAction()) return;
    setError(null);
    setActionLabel(label);
    try {
      const result = await invoke<CommandResult>("run_compose_action", {
        file: composeFile,
        action,
      });
      setLastAction(result);
      if (!result.ok) {
        setError(result.stderr || `${label} failed with status ${result.code}`);
        return;
      }
      await Promise.all([readComposeSnapshot(composeFile), refresh(), refreshVolumes()]);
    } catch (err) {
      setError(String(err));
    } finally {
      finishRuntimeAction();
    }
  }

  async function showComposeLogs(service: ComposeServiceSummary): Promise<void> {
    const target = composeLogTarget(service);
    setContainerTarget(target);
    await startLogFollow(target);
  }

  async function buildImage(): Promise<void> {
    if (!beginRuntimeAction()) return;
    setError(null);
    setActionLabel("Image Build");
    setBuildSteps([]);
    try {
      const result = await invoke<CommandResult>("build_image", {
        context: buildContext,
        tag: buildTag,
      });
      setLastAction(result);
      if (!result.ok) setError(result.stderr || `Image build failed with status ${result.code}`);
      await refresh();
    } catch (err) {
      setError(String(err));
    } finally {
      finishRuntimeAction();
    }
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
    if (!beginRuntimeAction()) return;
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
    } finally {
      finishRuntimeAction();
    }
  }

  async function runDoctor(): Promise<void> {
    if (!beginRuntimeAction()) return;
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
    } finally {
      finishRuntimeAction();
    }
  }

  const sessionSummary = useMemo(() => authState?.session, [authState]);
  const visibleLogText = useMemo(() => {
    const visibleOutput = logsPaused ? pausedLogOutput : logOutput;
    const filter = logFilter.trim();
    return filter
      ? visibleOutput
          .split("\n")
          .filter((line) => line.includes(filter))
          .join("\n")
      : visibleOutput;
  }, [logFilter, logOutput, logsPaused, pausedLogOutput]);

  const runtimeBusy = runtimeActionBusy || logsFollowing || terminalActive;

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

  const containerRows = useMemo(
    () => parseContainerRows(snapshot?.containers.stdout ?? ""),
    [snapshot?.containers.stdout],
  );
  const visibleContainers = useMemo(
    () => filterContainers(containerRows, globalSearch),
    [containerRows, globalSearch],
  );
  const imageRows = useMemo(() => parseImageRows(snapshot?.images.stdout ?? ""), [snapshot?.images.stdout]);
  const imagesInUse = useMemo(() => new Set(containerRows.map((row) => row.image)), [containerRows]);
  const runningContainers = containerRows.filter((row) => row.state === "running").length;
  const selectedRow = containerRows.find((row) => row.id === containerTarget || row.name === containerTarget) ?? null;
  const imageCount = imageRows.length;
  const daemonRunning = daemonIsAvailable(snapshot);
  const registryAccountName = registryStatus ? registryStatusText(registryStatus) : "Sign in";
  const sectionTitles: Record<AppSection, string> = {
    containers: "Containers",
    images: "Images",
    volumes: "Volumes",
    compose: "Compose",
    networks: "Networks",
    doctor: "Doctor",
    settings: "Settings",
  };

  return (
    <div className="forge-shell">
      <header className="titlebar">
        <div className="traffic" aria-hidden="true"><span /><span /><span /></div>
        <div className="logo">Ferrocrate <em>Desktop</em></div>
        <label className="global-search">
          <span aria-hidden="true">⌕</span>
          <input
            ref={globalSearchRef}
            value={globalSearch}
            onChange={(event) => setGlobalSearch(event.target.value)}
            placeholder="Search containers, images, volumes…"
            aria-label="Global search"
          />
          <kbd>⌘K</kbd>
        </label>
        <button className="theme-toggle" onClick={() => setTheme(theme === "dark" ? "light" : "dark")} aria-label={`Use ${theme === "dark" ? "light" : "dark"} theme`}>
          {theme === "dark" ? "☀" : "☾"}
        </button>
        <div className={`daemon-pill ${daemonRunning ? "is-running" : "is-stopped"}`}>
          <span className="daemon-dot" /> {daemonRunning ? "daemon running" : "daemon offline"}
        </div>
        <RegistryAccountControl status={registryStatus} onOpen={() => { setRegistryDialogOpen(true); void refreshRegistryAuth(); }} />
      </header>

      <div className="workspace">
        <nav className="sidebar" aria-label="Primary">
          <p className="nav-label">Manage</p>
          {([
            ["containers", "▣", "Containers", containerRows.length],
            ["images", "▧", "Images", imageCount],
            ["volumes", "▤", "Volumes", volumes.length],
            ["compose", "◇", "Compose", composeSnapshot?.services.length ?? 0],
            ["networks", "◎", "Networks", networks.length],
          ] as const).map(([section, icon, label, count]) => (
            <button key={section} className={`nav-item ${activeSection === section ? "active" : ""}`} onClick={() => setActiveSection(section)}>
              <span className="nav-icon" aria-hidden="true">{icon}</span>{label}<span className="nav-count">{count}</span>
            </button>
          ))}
          <p className="nav-label system-label">System</p>
          <button className={`nav-item ${activeSection === "doctor" ? "active" : ""}`} onClick={() => setActiveSection("doctor")}>
            <span className="nav-icon" aria-hidden="true">✚</span>Doctor
            {doctorResult ? <span className="nav-count">{doctorResult.raw.checks.filter((check) => !check.ok).length}</span> : null}
          </button>
          <button className={`nav-item ${activeSection === "settings" ? "active" : ""}`} onClick={() => setActiveSection("settings")}>
            <span className="nav-icon" aria-hidden="true">⚙</span>Settings
          </button>
          <div className="sidebar-foot">Ferrocrate v0.1.0<br />native daemon · VM optional</div>
        </nav>

        <main className="main-area">
          <div className="page-header">
            <div>
              <p className="eyebrow">Local runtime</p>
              <div className="title-line">
                <h1>{sectionTitles[activeSection]}</h1>
                {activeSection === "containers" ? <span className="status-chip">{runningContainers} running</span> : null}
              </div>
            </div>
            <div className="actions">
              {activeSection === "containers" ? (
                <>
                  <button className="btn btn-secondary" onClick={() => void runAction("container_prune", "Container Prune")} disabled={runtimeBusy}>Prune stopped</button>
                  <button className="btn btn-primary" onClick={() => setRunDialogOpen(true)} disabled={runtimeBusy}>▶ Run container</button>
                </>
              ) : activeSection === "images" ? (
                <ImagePagePullAction hasImages={imageRows.length > 0} disabled={runtimeBusy} onOpen={openPullImageDialog} />
              ) : (
                <button className="btn btn-secondary" onClick={() => void Promise.all([refresh(), refreshVolumes(), refreshNetworks()])} disabled={loading || volumesLoading || networksLoading}>
                  {loading ? "Refreshing…" : "↻ Refresh runtime"}
                </button>
              )}
            </div>
          </div>

          {error ? <div className="error-banner" role="alert"><strong>Runtime error</strong><span>{error}</span><button onClick={() => setError(null)} aria-label="Dismiss error">×</button></div> : null}

          <div className={`page-content ${activeSection === "containers" ? "container-layout" : ""}`}>
            {activeSection === "containers" ? (
              <>
                <section className="panel table-panel" aria-label="Containers">
                  <div className="mobile-target">
                    <input value={containerTarget} onChange={(event) => setContainerTarget(event.target.value)} placeholder="Container name or ID" />
                    <button className="btn btn-secondary" onClick={() => void inspectContainer()} disabled={runtimeBusy || !containerTarget.trim()}>Open</button>
                  </div>
                  <div className="table-scroll">
                    <table>
                      <thead><tr><th>Status</th><th>Name</th><th>Image</th><th>Ports</th><th>Actions</th></tr></thead>
                      <tbody>
                        {visibleContainers.map((row) => {
                          const tone = statusTone(row);
                          const selected = selectedRow?.id === row.id;
                          return (
                            <tr key={row.id} className={selected ? "selected" : ""} onClick={() => void inspectContainer(row.id)}>
                              <td><span className={`container-status ${tone}`}><i />{tone === "unhealthy" ? "Unhealthy" : row.status}</span></td>
                              <td className="container-name">{row.name}</td>
                              <td className="mono muted-cell">{row.image}</td>
                              <td className="mono muted-cell">{row.ports}</td>
                              <td className="row-actions">
                                <button className="icon-btn" title={row.state === "running" ? "Stop container" : "Start container"} onClick={(event) => { event.stopPropagation(); void runAction(row.state === "running" ? "stop_container" : "start_container", row.state === "running" ? "Container Stop" : "Container Start", row.id); }}>{row.state === "running" ? "■" : "▶"}</button>
                                <button className="icon-btn" title="Follow logs" onClick={(event) => { event.stopPropagation(); setContainerTarget(row.id); setDetailTab("logs"); void startLogFollow(row.id); }}>▤</button>
                                <button className="icon-btn terminal-icon" title="Open terminal" onClick={(event) => { event.stopPropagation(); setContainerTarget(row.id); setDetailTab("terminal"); }}>&gt;_</button>
                                <button className="icon-btn danger-icon" title="Remove container" onClick={(event) => { event.stopPropagation(); void runAction("remove_container", "Container Remove", row.id); }}>×</button>
                              </td>
                            </tr>
                          );
                        })}
                      </tbody>
                    </table>
                  </div>
                  {visibleContainers.length === 0 ? <div className="empty-state"><strong>No containers found</strong><span>{globalSearch ? "Try a different search." : "Run a container to see it here."}</span></div> : null}
                </section>

                <aside className="panel detail-panel" aria-label="Container detail drawer">
                  <div className="detail-head">
                    <span className={`container-status ${selectedRow ? statusTone(selectedRow) : "stopped"}`}><i /></span>
                    <div className="detail-identity"><strong>{selectedRow?.name || containerDetail?.name || "Select a container"}</strong><span>{selectedRow?.image || containerDetail?.image || "Choose a row to view details"}</span></div>
                    {selectedRow ? <span className="detail-meta">{selectedRow.status}</span> : null}
                  </div>
                  <div className="detail-tabs" role="tablist">
                    {(["logs", "terminal", "inspect", "stats"] as DetailTab[]).map((tab) => (
                      <button key={tab} role="tab" aria-selected={detailTab === tab} className={detailTab === tab ? "active" : ""} onClick={() => setDetailTab(tab)}>{tab[0].toUpperCase() + tab.slice(1)}</button>
                    ))}
                  </div>

                  <div className={`detail-pane logs-pane ${detailTab === "logs" ? "active" : ""}`}>
                    <div className="log-toolbar"><input value={logFilter} onChange={(event) => setLogFilter(event.target.value)} placeholder="Filter log stream" /></div>
                    <pre className="log-output">{visibleLogText || (logsFollowing ? "Waiting for log lines…" : "Select a container and start following logs.")}</pre>
                    <div className="detail-foot">
                      <button className="btn btn-secondary" onClick={toggleLogPause} disabled={!logsFollowing}>{logsPaused ? "▶ Resume" : "Ⅱ Pause"}</button>
                      <button className="btn btn-secondary" onClick={() => selectedRow && void startLogFollow(selectedRow.id)} disabled={!selectedRow || runtimeBusy}>{logsFollowing ? "Following ✓" : "Follow"}</button>
                      <button className="btn btn-ghost" onClick={() => void copyLogs()} disabled={!visibleLogText}>Copy</button>
                      <button className="btn btn-ghost" onClick={exportLogs} disabled={!visibleLogText}>Export</button>
                      <button className="btn btn-danger" onClick={() => void stopLogFollow()} disabled={!logsFollowing || runtimeActionBusy}>Stop</button>
                      <span className="detail-meta">{logsFollowing ? "streaming" : "idle"} · {visibleLogText ? visibleLogText.split("\n").length : 0} lines</span>
                    </div>
                  </div>

                  <div className={`detail-pane terminal-pane ${detailTab === "terminal" ? "active" : ""}`}>
                    <div className="terminal-config">
                      <input value={terminalShell} onChange={(event) => setTerminalShell(event.target.value)} placeholder="shell (sh)" />
                      <input value={terminalUser} onChange={(event) => setTerminalUser(event.target.value)} placeholder="user (optional)" />
                      <input value={terminalWorkdir} onChange={(event) => setTerminalWorkdir(event.target.value)} placeholder="workdir (optional)" />
                      <textarea value={terminalEnv} onChange={(event) => setTerminalEnv(event.target.value)} placeholder="KEY=value, one per line" rows={3} />
                    </div>
                    <div className="terminal-host" ref={terminalHostRef} aria-label="Interactive container terminal" />
                    <div className="detail-foot">
                      <button className="btn btn-primary" onClick={() => void startTerminal()} disabled={runtimeBusy || !containerTarget.trim()}>Open shell</button>
                      <button className="btn btn-danger" onClick={() => void closeTerminal()} disabled={!terminalActive || runtimeActionBusy}>Detach</button>
                      <span className="detail-meta">{terminalActive ? "attached" : "detached"}</span>
                    </div>
                  </div>

                  <div className={`detail-pane inspect-pane ${detailTab === "inspect" ? "active" : ""}`}>
                    {containerDetail ? (
                      <>
                        <dl className="detail-grid">
                          <div><dt>Status</dt><dd>{containerDetail.status}</dd></div><div><dt>Image</dt><dd>{containerDetail.image}</dd></div>
                          <div><dt>User</dt><dd>{containerDetail.user || "default"}</dd></div><div><dt>Working directory</dt><dd>{containerDetail.working_dir || "/"}</dd></div>
                          <div className="detail-span"><dt>Command</dt><dd>{containerDetail.command.join(" ") || "image default"}</dd></div>
                          <div className="detail-span"><dt>Restart policy</dt><dd>{containerDetail.restart_policy.name || "no"}</dd></div>
                        </dl>
                        <section className="drawer-section"><div className="drawer-section-header"><h3>Environment</h3><button className="btn btn-ghost" onClick={() => setShowEnvironment((visible) => !visible)}>{showEnvironment ? "Mask values" : "Reveal values"}</button></div><pre>{(showEnvironment ? containerDetail.environment : maskEnvironment(containerDetail.environment)).join("\n") || EMPTY}</pre></section>
                        <section className="drawer-section"><h3>Mounts</h3>{containerDetail.mounts.length ? <ul className="mount-list">{containerDetail.mounts.map((mount, index) => <li key={`${mount.destination}:${index}`}>{mount.kind} · {mount.source || "daemon-managed"} → {mount.destination} ({mount.access})</li>)}</ul> : <p className="muted">No mounts.</p>}</section>
                      </>
                    ) : <div className="empty-state"><strong>No inspection loaded</strong><span>Select a container row.</span></div>}
                  </div>

                  <div className={`detail-pane stats-pane ${detailTab === "stats" ? "active" : ""}`}>
                    {containerDetail ? (
                      <>
                        <div className="stat-cards"><div><span>Memory limit</span><strong>{containerDetail.resources.memory || "Unlimited"}</strong></div><div><span>CPU quota</span><strong>{containerDetail.resources.cpu_quota || "Unlimited"}</strong></div><div><span>CPU period</span><strong>{containerDetail.resources.cpu_period || "Default"}</strong></div></div>
                        <section className="drawer-section"><h3>Resource limits</h3><div className="editor-grid"><label><span>Memory bytes</span><input inputMode="numeric" value={detailMemory} onChange={(event) => setDetailMemory(event.target.value)} /></label><label><span>CPU quota</span><input inputMode="numeric" value={detailCpuQuota} onChange={(event) => setDetailCpuQuota(event.target.value)} /></label><label><span>CPU period</span><input inputMode="numeric" value={detailCpuPeriod} onChange={(event) => setDetailCpuPeriod(event.target.value)} /></label></div><button className="btn btn-primary" onClick={() => void updateContainerResources()} disabled={runtimeBusy}>Apply limits</button></section>
                        <section className="drawer-section"><h3>Health history</h3>{containerDetail.health ? <><p className="muted">{containerDetail.health.status} · failing streak {containerDetail.health.failing_streak}</p>{containerDetail.health.log.length ? <ol className="health-list">{containerDetail.health.log.map((entry, index) => <li key={`${entry.start}:${index}`}><strong>Exit {entry.exit_code}</strong><span>{entry.start} → {entry.end}</span><code>{entry.output || "No output"}</code></li>)}</ol> : <p className="muted">No health checks recorded.</p>}</> : <p className="muted">No health check configured.</p>}</section>
                      </>
                    ) : <div className="empty-state"><strong>No stats loaded</strong><span>Select a container row.</span></div>}
                  </div>
                </aside>
              </>
            ) : null}

            {activeSection === "images" ? (
              <section className="panel table-panel image-table-panel" aria-label="Images">
                <div className="table-toolbar">
                  <span className="count-badge">{imageCount}</span>
                  <details className="image-toolbar-overflow">
                    <summary aria-label="More image actions">•••</summary>
                    <div className="overflow-menu">
                      <button onClick={() => void refresh()} disabled={loading}>Refresh images</button>
                      <button onClick={() => void runAction("image_prune", "Image Prune")} disabled={runtimeBusy}>Prune unused images</button>
                      <button onClick={() => setBuildImageDialogOpen(true)} disabled={runtimeBusy}>Build image</button>
                    </div>
                  </details>
                </div>
                {imageRows.length ? (
                  <div className="table-scroll">
                    <table>
                      <thead><tr><th>Repository</th><th>Size</th><th>Created</th><th>In use</th><th aria-label="Actions" /></tr></thead>
                      <tbody>{imageRows.map((image) => (
                        <tr key={image.id}>
                          <td className="container-name mono">{image.reference}</td>
                          <td className="muted">{image.size}</td>
                          <td className="muted">{image.created}</td>
                          <td>{imagesInUse.has(image.reference) ? <span className="status-chip">In use</span> : <span className="muted">Not in use</span>}</td>
                          <td className="row-actions"><details className="row-menu"><summary aria-label={`Actions for ${image.reference}`}>•••</summary><div className="overflow-menu"><button className="danger-action" onClick={() => void runAction("remove_image", "Image Remove", image.reference)} disabled={runtimeBusy}>Remove image</button></div></details></td>
                        </tr>
                      ))}</tbody>
                    </table>
                  </div>
                ) : <ImageEmptyState hasImages={imageRows.length > 0} disabled={runtimeBusy} onOpen={openPullImageDialog} />}
              </section>
            ) : null}

            {activeSection === "volumes" ? <section className="panel section-panel"><div className="panel-heading"><div><p className="eyebrow">Persistent storage</p><h2>Named volumes</h2></div><span className="count-badge">{volumes.length}</span></div><div className="field-row"><input value={volumeName} onChange={(event) => setVolumeName(event.target.value)} placeholder="named volume" /><button className="btn btn-primary" onClick={() => void runVolumeAction("create", "Volume Create", volumeName)} disabled={runtimeBusy || volumesLoading || !volumeName.trim()}>Create</button><button className="btn btn-secondary" onClick={() => void refreshVolumes()} disabled={runtimeBusy || volumesLoading}>{volumesLoading ? "Refreshing…" : "Refresh"}</button><button className="btn btn-danger" onClick={() => void runVolumeAction("prune", "Volume Prune")} disabled={runtimeBusy || volumesLoading}>Prune unused</button></div><div className="resource-list">{volumes.map((volume) => <div className="resource-row" key={volume.name}><div><strong>{volume.name}</strong><p className="muted">{volume.driver} · {volume.mountpoint}</p>{volume.mounts.length ? <ul className="mount-list">{volume.mounts.map((mount) => <li key={`${mount.container_id}:${mount.destination}`}>{formatVolumeMount(mount)}</li>)}</ul> : <p className="muted">Unused</p>}</div><button className="btn btn-danger" onClick={() => void runVolumeAction("remove", "Volume Remove", volume.name)} disabled={runtimeBusy || volumesLoading || volumeIsInUse(volume)}>Remove</button></div>)}</div>{volumes.length === 0 ? <div className="empty-state"><strong>No named volumes</strong><span>Create one to persist container data.</span></div> : null}</section> : null}

            {activeSection === "networks" ? <section className="panel section-panel"><div className="panel-heading"><div><p className="eyebrow">Connectivity</p><h2>Networks</h2></div><span className="count-badge">{networks.length}</span></div><div className="field-row network-fields"><input value={networkName} onChange={(event) => setNetworkName(event.target.value)} placeholder="network name" /><input value={networkSubnet} onChange={(event) => setNetworkSubnet(event.target.value)} placeholder="subnet (optional)" /><button className="btn btn-primary" onClick={() => void runNetworkAction("create", "Network Create", networkName)} disabled={runtimeBusy || networksLoading || !networkName.trim()}>Create bridge</button><button className="btn btn-secondary" onClick={() => void refreshNetworks()} disabled={runtimeBusy || networksLoading}>{networksLoading ? "Refreshing…" : "Refresh"}</button></div><div className="resource-list">{networks.map((network) => <div className="resource-row" key={network.name}><div><strong>{network.name}</strong><p className="muted">{network.driver} · {network.subnets.length ? network.subnets.join(", ") : "daemon-managed subnet"}</p>{network.containers.length ? <ul className="mount-list">{network.containers.map((attachment) => <li key={`${network.name}:${attachment.container_id}`}>{formatNetworkAttachment(attachment)}</li>)}</ul> : <p className="muted">No attached containers</p>}</div><button className="btn btn-danger" onClick={() => void runNetworkAction("remove", "Network Remove", network.name)} disabled={runtimeBusy || networksLoading || !networkIsRemovable(network) || network.containers.length > 0}>Remove</button></div>)}</div>{networks.length === 0 ? <div className="empty-state"><strong>No networks</strong><span>Create a bridge network for isolated workloads.</span></div> : null}</section> : null}

            {activeSection === "compose" ? <section className="panel section-panel"><div className="panel-heading"><div><p className="eyebrow">Application stacks</p><h2>Compose</h2></div><span className="count-badge">{composeSnapshot?.services.length ?? 0}</span></div><p className="muted">Choose a Compose YAML file, validate it, and manage project services.</p><div className="field-row compose-file-row"><input value={composeFile} onChange={(event) => { setComposeFile(event.target.value); setComposeSnapshot(null); }} placeholder="compose.yml" /><button className="btn btn-secondary" onClick={() => void chooseComposeFile()} disabled={runtimeBusy || composeLoading}>Choose file</button></div><div className="panel-actions"><button className="btn btn-secondary" onClick={() => void validateCompose()} disabled={runtimeBusy || composeLoading || !composeFile.trim()}>{composeLoading ? "Validating…" : "Validate config"}</button><button className="btn btn-primary" onClick={() => void runComposeAction("up", "Compose Up")} disabled={runtimeBusy || composeLoading || !composeFile.trim()}>Up</button><button className="btn btn-secondary" onClick={() => void runComposeAction("start", "Compose Start")} disabled={runtimeBusy || composeLoading || !composeFile.trim()}>Start</button><button className="btn btn-secondary" onClick={() => void runComposeAction("stop", "Compose Stop")} disabled={runtimeBusy || composeLoading || !composeFile.trim()}>Stop</button><button className="btn btn-danger" onClick={() => void runComposeAction("down", "Compose Down")} disabled={runtimeBusy || composeLoading || !composeFile.trim()}>Down</button></div>{composeSnapshot?.services.length ? <div className="resource-list compose-services">{composeSnapshot.services.map((service) => <div className="resource-row" key={service.name}><div><strong>{service.name}</strong><p className={`service-status ${composeStatusClass(service.status)}`}>{service.status.replaceAll("_", " ")}</p>{service.container_id ? <p className="mono muted">{service.container_id}</p> : null}</div><button className="btn btn-secondary" onClick={() => { void showComposeLogs(service); setActiveSection("containers"); setDetailTab("logs"); }} disabled={runtimeBusy || service.status === "not_created"}>Follow logs</button></div>)}</div> : <div className="empty-state"><strong>No Compose project loaded</strong><span>Choose and validate a Compose file.</span></div>}<details className="compose-config"><summary>Validated configuration</summary><pre>{composeSnapshot?.config || EMPTY}</pre></details></section> : null}

            {activeSection === "doctor" ? <div className="section-grid"><section className="panel section-panel full-span"><div className="panel-heading"><div><p className="eyebrow">Diagnostics</p><h2>System doctor</h2></div>{doctorResult ? <span className={`count-badge ${doctorResult.ok ? "ok" : "bad"}`}>{doctorResult.ok ? "Healthy" : "Needs attention"}</span> : null}</div><div className="check-row"><label><input type="checkbox" checked={doctorFix} onChange={(event) => setDoctorFix(event.target.checked)} />Fix</label><label><input type="checkbox" checked={doctorBootstrap} onChange={(event) => setDoctorBootstrap(event.target.checked)} />Bootstrap</label><label><input type="checkbox" checked={doctorDryRun} onChange={(event) => setDoctorDryRun(event.target.checked)} />Dry-run</label><label><input type="checkbox" checked={doctorConfirm} onChange={(event) => setDoctorConfirm(event.target.checked)} />Confirm (--yes)</label></div><div className="panel-actions"><button className="btn btn-primary" onClick={() => void runDoctor()} disabled={runtimeBusy}>Run doctor</button></div><pre className="data-output">{doctorResult ? JSON.stringify(doctorResult.raw, null, 2) : EMPTY}</pre></section><section className="panel section-panel"><div className="panel-heading"><div><p className="eyebrow">Optional VM</p><h2>Runtime controls</h2></div></div><div className="panel-actions"><button className="btn btn-secondary" onClick={() => void runAction("vm_start", "VM Start")} disabled={runtimeBusy}>Start VM</button><button className="btn btn-secondary" onClick={() => void runAction("vm_stop", "VM Stop")} disabled={runtimeBusy}>Stop VM</button></div><pre className="data-output">{snapshot?.runtime.stdout || EMPTY}</pre>{snapshot?.runtime.stderr ? <p className="muted">{snapshot.runtime.stderr}</p> : null}</section></div> : null}

            {activeSection === "settings" ? <div className="section-grid"><section className="panel section-panel"><div className="panel-heading"><div><p className="eyebrow">Paid services</p><h2>Authentication</h2></div></div><p className="muted">Configure issuance endpoints and a short-lived paid session token.</p><div className="form-stack"><input value={releaseBaseUrl} onChange={(event) => setReleaseBaseUrl(event.target.value)} placeholder="release base URL" /><input value={tokenEndpoint} onChange={(event) => setTokenEndpoint(event.target.value)} placeholder="token endpoint" /><input value={issuanceEndpoint} onChange={(event) => setIssuanceEndpoint(event.target.value)} placeholder="session issuance endpoint" /></div><div className="panel-actions"><button className="btn btn-secondary" onClick={() => void saveBackendConfig()}>Save backend config</button></div><div className="form-stack"><input value={customerId} onChange={(event) => setCustomerId(event.target.value)} placeholder="customer id" /><input value={accessToken} onChange={(event) => setAccessToken(event.target.value)} placeholder="optional access token" /></div><div className="panel-actions"><button className="btn btn-secondary" onClick={() => void acquireSessionToken()}>Acquire session token</button></div><div className="field-row"><input value={sessionTokenInput} onChange={(event) => setSessionTokenInput(event.target.value)} placeholder="paste session JWT" /></div><div className="panel-actions"><button className="btn btn-primary" onClick={() => void saveSessionToken()}>Save token</button><button className="btn btn-danger" onClick={() => void clearSessionToken()}>Clear token</button><button className="btn btn-ghost" onClick={() => void refreshAuthState()} disabled={authLoading}>{authLoading ? "Refreshing…" : "Refresh auth"}</button></div><pre className="data-output">{`token_present=${sessionSummary?.token_present ? "yes" : "no"}\nsubject=${sessionSummary?.subject ?? "-"}\nplan=${sessionSummary?.plan ?? "-"}\nexpires_at=${formatUnix(sessionSummary?.expires_at ?? null)}\nexpired=${sessionSummary?.expired == null ? "-" : sessionSummary.expired ? "yes" : "no"}`}</pre><pre className="data-output">{`entitlement_status=${authState?.entitlement?.status ?? "-"}\nentitlement_plan=${authState?.entitlement?.plan ?? "-"}\nentitlement_expires=${formatUnix(authState?.entitlement?.expires_at ?? null)}\nentitlement_message=${authState?.entitlement?.message ?? "-"}`}</pre></section><section className="panel section-panel"><div className="panel-heading"><div><p className="eyebrow">Provisioning</p><h2>Install + bootstrap</h2></div></div><p className="muted">The paid install path uses the saved backend config and session token.</p><div className="panel-actions"><button className="btn btn-secondary" onClick={() => void runInstaller(true, false)} disabled={runtimeBusy}>Dry-run install</button><button className="btn btn-primary" onClick={() => void runInstaller(false, true)} disabled={runtimeBusy}>Run full install</button></div><pre className="data-output">{installerResult ? JSON.stringify(installerResult, null, 2) : EMPTY}</pre></section></div> : null}

            {lastAction ? <section className="last-action"><strong>{actionLabel}</strong><span className={lastAction.ok ? "ok-text" : "bad-text"}>{lastAction.ok ? "completed" : `failed (${lastAction.code})`}</span>{lastAction.stderr ? <span>{lastAction.stderr}</span> : null}</section> : null}
          </div>
        </main>
      </div>

      <footer className="statusbar">
        <span><b>{containerRows.length}</b> containers · <b>{runningContainers}</b> running</span>
        <span><b>{imageCount}</b> images</span>
        <span>engine <b>native</b> — VM optional</span>
        <div className="status-right"><span>CPU <b>—</b></span><span>MEM <b>—</b></span><span>v0.1.0</span></div>
      </footer>

      {runDialogOpen ? (
        <div className="modal-backdrop" role="presentation"><section className="run-dialog" role="dialog" aria-modal="true" aria-labelledby="run-dialog-title"><div className="drawer-header"><div><p className="eyebrow">New workload</p><h2 id="run-dialog-title">Run container</h2></div><button className="btn btn-secondary" onClick={() => setRunDialogOpen(false)}>Cancel</button></div><div className="editor-grid"><label><span>Image</span><input value={newContainerImage} onChange={(event) => setNewContainerImage(event.target.value)} placeholder="alpine:latest" /></label><label><span>Name</span><input value={newContainerName} onChange={(event) => setNewContainerName(event.target.value)} placeholder="optional name" /></label><label><span>Memory bytes</span><input inputMode="numeric" value={newContainerMemory} onChange={(event) => setNewContainerMemory(event.target.value)} placeholder="unlimited" /></label><label><span>CPU quota</span><input inputMode="numeric" value={newContainerCpuQuota} onChange={(event) => setNewContainerCpuQuota(event.target.value)} placeholder="unlimited" /></label><label><span>CPU period</span><input inputMode="numeric" value={newContainerCpuPeriod} onChange={(event) => setNewContainerCpuPeriod(event.target.value)} placeholder="100000" /></label><label className="detail-span"><span>Environment (one KEY=value per line)</span><textarea value={newContainerEnvironment} onChange={(event) => setNewContainerEnvironment(event.target.value)} rows={6} /></label></div><div className="panel-actions dialog-actions"><button className="btn btn-primary" onClick={() => void runNewContainer()} disabled={runtimeBusy || !newContainerImage.trim()}>Run detached</button></div></section></div>
      ) : null}

      {pullImageDialogOpen ? (
        <PullImageDialog open={pullImageDialogOpen} imageTarget={imageTarget} progress={pullProgress} failure={pullFailure} busy={runtimeBusy} onCancel={() => setPullImageDialogOpen(false)} onImageTargetChange={(event) => setImageTarget(event.target.value)} onPull={() => void pullImage()} onStart={() => void startFerrocrate()} onReviewLicensing={() => { setPullImageDialogOpen(false); setActiveSection("settings"); }} />
      ) : null}

      {buildImageDialogOpen ? (
        <div className="modal-backdrop" role="presentation"><section className="run-dialog" role="dialog" aria-modal="true" aria-labelledby="build-image-dialog-title"><div className="drawer-header"><div><p className="eyebrow">Build pipeline</p><h2 id="build-image-dialog-title">Build image</h2></div><button className="btn btn-secondary" onClick={() => setBuildImageDialogOpen(false)}>Cancel</button></div><div className="editor-grid"><label className="detail-span"><span>Build context directory</span><div className="field-row"><input value={buildContext} onChange={(event) => setBuildContext(event.target.value)} placeholder="build context directory" /><button className="btn btn-secondary" onClick={() => void chooseBuildContext()} disabled={runtimeBusy}>Choose directory</button></div></label><label className="detail-span"><span>Image reference</span><input value={buildTag} onChange={(event) => setBuildTag(event.target.value)} placeholder="image:tag" /></label>{buildSteps.length ? <ol className="build-steps detail-span">{buildSteps.map((step, index) => <li className={step.stream === "stderr" ? "build-step-error" : ""} key={`${index}:${step.stream}`}><span>{step.stream}</span><code>{buildStepText(step.text)}</code></li>)}</ol> : <p className="muted detail-span">Build progress will appear here.</p>}</div><div className="panel-actions dialog-actions"><button className="btn btn-primary" onClick={() => void buildImage()} disabled={runtimeBusy || !buildContext.trim() || !buildTag.trim()}>Build image</button></div></section></div>
      ) : null}

      {registryDialogOpen ? (
        <div className="modal-backdrop" role="presentation"><section className="run-dialog" role="dialog" aria-modal="true" aria-labelledby="registry-dialog-title"><div className="drawer-header"><div><p className="eyebrow">Credentials</p><h2 id="registry-dialog-title">Registry access</h2></div><button className="btn btn-secondary" onClick={() => setRegistryDialogOpen(false)}>Cancel</button></div><div className="editor-grid"><label className="detail-span"><span>Registry server</span><input value={registryTarget} onChange={(event) => { setRegistryTarget(event.target.value); setRegistryStatus(null); }} placeholder="registry.example.com" /></label><label><span>Username</span><input value={registryUsername} onChange={(event) => setRegistryUsername(event.target.value)} placeholder="username" autoComplete="username" /></label><label><span>Password or token</span><input type="password" value={registryPassword} onChange={(event) => setRegistryPassword(event.target.value)} placeholder="password or token" autoComplete="current-password" /></label><p className={`registry-status detail-span ${registryStatus?.logged_in ? "status-running" : ""}`}>{registryStatus ? registryStatus.logged_in ? `Signed in to ${registryStatus.registry} as ${registryAccountName}` : `Not signed in to ${registryStatus.registry}` : "Check this registry to load keyring status"}</p></div><div className="panel-actions dialog-actions"><button className="btn btn-secondary" onClick={() => void refreshRegistryAuth()} disabled={runtimeBusy || registryLoading || !registryTarget.trim()}>Check status</button><button className="btn btn-danger" onClick={() => void logoutRegistry()} disabled={runtimeBusy || registryLoading || !registryStatus?.logged_in}>Logout</button><button className="btn btn-primary" onClick={() => void loginRegistry()} disabled={runtimeBusy || registryLoading || !registryTarget.trim() || !registryUsername.trim() || !registryPassword}>{registryLoading ? "Working…" : "Login"}</button></div></section></div>
      ) : null}
    </div>
  );

}

export default App;
