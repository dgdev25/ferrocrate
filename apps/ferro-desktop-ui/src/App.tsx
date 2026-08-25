import { dialogAvailable, invoke, listen, open } from "./desktopRuntime";
import { Terminal } from "@xterm/xterm";
import "@xterm/xterm/css/xterm.css";
import { Fragment, useEffect, useMemo, useRef, useState } from "react";
import type {
  CommandResult,
  BuildProgressFrame,
  ComposeAction,
  ComposeServiceSummary,
  ComposeSnapshot,
  ContainerDetailSummary,
  ContainerStatsResponse,
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
import { ComposeFileDialog, composeChooserMode, composeLogTarget, composeStatusClass } from "./composeView.mjs";
import { loadContainerSelection, maskEnvironment, parseOptionalLimit } from "./containerDetail.mjs";
import { DesktopTabBar, showGlobalRunAction } from "./desktopChrome.mjs";
import { productSurfaceLabel } from "./surfaceLabel.mjs";
import type { AppSection } from "./desktopChrome.mjs";
import { AccountDialog, BuildImageDialog, DoctorDialog, InstallDialog, RegistryDialog, RunContainerDialog } from "./dialogForms.mjs";
import type { RunContainerDraft, RunContainerInvokeArgs } from "./dialogForms.mjs";
import { Icon } from "./iconSystem.mjs";
import { errorForSection, navigationTransientState, resourceActionStartState, resourceActionState, setSectionError } from "./errorScopes.mjs";
import { appendBuildProgress, buildInvokeArgs, BuildHistoryList, BuildLicensingDialog } from "./imageBuild.mjs";
import { formatImageCreated, imageIsUsed, ImagePagePullAction, parseImageRows, PullImageDialog, pullCompletionState, pullFailurePresentation } from "./imageView.mjs";
import { customNetworkCreateAvailable, formatNetworkAttachment, NetworkCapabilityNotice, networkIsRemovable } from "./networkView.mjs";
import { RegistryAccountControl, registryStatusText } from "./registryAuth.mjs";
import { completeDoctorRun, DoctorPage, SettingsPage } from "./systemPages.mjs";
import {
  ActionErrorNotice,
  applyRuntimeSurfaceTransition,
  containerContentState,
  filterNamedResources,
  FirstRunState,
  hostPathError,
  LicensingDialog,
  ResourceCreateDialog,
  ResourceEmptyState,
  resourcePageState,
  runFirstRunRecovery,
  RuntimeLoadingState,
  runtimeSurfaceState,
  snapshotFailureDetail,
} from "./resourcePages.mjs";
import type { ResourceDialog } from "./resourcePages.mjs";
import { runtimeActionAvailability } from "./runtimeActions.mjs";
import { submitRunContainer } from "./runContainer.mjs";
import {
  applyRemoteTerminalResize,
  applyTerminalResize,
  DEFAULT_TERMINAL_ENV,
} from "./terminalResize.mjs";
import { mountTerminalHost, writeTerminalOutput } from "./terminalLifecycle.mjs";
import { formatVolumeMount, volumeIsInUse } from "./volumeView.mjs";
import {
  beginContainerStatsPoll,
  daemonStatusPresentation,
  containerRemoveAvailability,
  containerStatsUnavailableMessage,
  filterContainers,
  filterContainersByStatus,
  formatBytes,
  groupContainers,
  mergeContainerStats,
  parseContainerStats,
  parseContainerRows,
  resourceTotalsForSurface,
  shellKeyboardCommand,
  shouldPollContainerStats,
  statusLabel,
  statusTone,
} from "./forgeShell.mjs";
import type { ContainerStatusFilter } from "./forgeShell.mjs";

const EMPTY = "Nothing to show.";
const THEME_KEY = "ferro_desktop_theme";
type ThemeMode = "dark" | "light";
type DetailTab = "logs" | "terminal" | "inspect" | "stats";
type LogBatch = { text: string; truncated: boolean };
type TerminalOutput = { data: number[]; stderr: boolean };
type PullFailure = ReturnType<typeof pullFailurePresentation>;
type BuildHistoryEntry = {
  id: string;
  image: string;
  status: "building" | "succeeded" | "failed";
  durationMs: number | null;
  progress: BuildProgressFrame[];
  error?: string;
};

function formatUnix(value: number | null): string {
  if (!value) return "-";
  return formatImageCreated(value);
}

function commandMessage(result: CommandResult, fallback: string): string {
  return result.message || result.stderr || fallback;
}

function App(): JSX.Element {
  const [snapshot, setSnapshot] = useState<DesktopSnapshot | null>(null);
  const [containerStats, setContainerStats] = useState<ContainerStatsResponse | null>(null);
  const [documentVisible, setDocumentVisible] = useState(document.visibilityState === "visible");
  const [authState, setAuthState] = useState<PaidAuthState | null>(null);
  const [loading, setLoading] = useState(false);
  const [authLoading, setAuthLoading] = useState(false);
  const [sectionErrors, setSectionErrors] = useState<Partial<Record<AppSection, string>>>({});
  const [licensingDialogOpen, setLicensingDialogOpen] = useState(false);
  const [licensingDetail, setLicensingDetail] = useState("");
  const [theme, setTheme] = useState<ThemeMode>("dark");
  const [activeSection, setActiveSection] = useState<AppSection>("containers");
  const [containerStatusFilter, setContainerStatusFilter] = useState<ContainerStatusFilter>("all");
  const [detailTab, setDetailTab] = useState<DetailTab>("logs");
  const [globalSearch, setGlobalSearch] = useState("");
  const [imageTarget, setImageTarget] = useState("alpine:latest");
  const [pullImageDialogOpen, setPullImageDialogOpen] = useState(false);
  const [buildImageDialogOpen, setBuildImageDialogOpen] = useState(false);
  const [buildLicensingDialogOpen, setBuildLicensingDialogOpen] = useState(false);
  const [buildLicensingDetail, setBuildLicensingDetail] = useState("");
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
  const containerStatsPollOwnerRef = useRef({ inFlight: false });
  const logFollowRef = useRef(false);
  const [terminalHost, setTerminalHost] = useState<HTMLDivElement | null>(null);
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
  const [composeFileDialogOpen, setComposeFileDialogOpen] = useState(false);
  const [composeSnapshot, setComposeSnapshot] = useState<ComposeSnapshot | null>(null);
  const [composeLoading, setComposeLoading] = useState(false);
  const [buildContext, setBuildContext] = useState("");
  const [buildTag, setBuildTag] = useState("local/build:latest");
  const [buildHistory, setBuildHistory] = useState<BuildHistoryEntry[]>([]);
  const buildSequenceRef = useRef(0);
  const [containerDetail, setContainerDetail] = useState<ContainerDetailSummary | null>(null);
  const [inspectorError, setInspectorError] = useState<string | null>(null);
  const [showEnvironment, setShowEnvironment] = useState(false);
  const [detailMemory, setDetailMemory] = useState("");
  const [detailCpuQuota, setDetailCpuQuota] = useState("");
  const [detailCpuPeriod, setDetailCpuPeriod] = useState("");
  const [runDialogOpen, setRunDialogOpen] = useState(false);
  const [runDialogError, setRunDialogError] = useState<string | null>(null);
  const [resourceDialog, setResourceDialog] = useState<ResourceDialog>(null);
  const [resourceDialogError, setResourceDialogError] = useState<string | null>(null);
  const resourceDialogGenerationRef = useRef(0);
  const [newContainerDraft, setNewContainerDraft] = useState<RunContainerDraft>({
    image: "alpine:latest",
    name: "",
    command: "",
    pullIfMissing: true,
    ports: [{ host: "", container: "" }],
    volumes: [{ source: "", target: "" }],
    environment: "",
    memoryMb: "",
    cpus: "",
  });
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
  const [doctorDialogOpen, setDoctorDialogOpen] = useState(false);
  const doctorResultsTableRef = useRef<HTMLTableElement>(null);
  const doctorResultsFocusPendingRef = useRef(false);
  const [settingsDialog, setSettingsDialog] = useState<"account" | "install" | null>(null);

  const [doctorFix, setDoctorFix] = useState(true);
  const [doctorBootstrap, setDoctorBootstrap] = useState(false);
  const [doctorDryRun, setDoctorDryRun] = useState(true);
  const [doctorConfirm, setDoctorConfirm] = useState(false);

  const error = errorForSection(sectionErrors, activeSection);
  function setError(next: unknown): void {
    setSectionErrors((current) => setSectionError(current, activeSection, next));
  }

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
    if (!doctorDialogOpen && doctorResult && doctorResultsFocusPendingRef.current) {
      doctorResultsFocusPendingRef.current = false;
      doctorResultsTableRef.current?.focus();
    }
  }, [doctorDialogOpen, doctorResult]);

  useEffect(() => {
    let disposed = false;
    let unlisten: (() => void) | undefined;
    void listen<BuildProgressFrame>("image-build-progress", (event) => {
      setBuildHistory((history) => appendBuildProgress(history, event.payload));
    }).then((stop) => {
      if (disposed) stop(); else unlisten = stop;
    });
    return () => { disposed = true; unlisten?.(); };
  }, []);

  useEffect(() => {
    return mountTerminalHost(terminalHost, terminalRef, (host) => {
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
      return {
        terminal,
        dispose() {
          observer.disconnect();
          terminal.dispose();
        },
      };
    });
  }, [terminalHost]);

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
        writeTerminalOutput(terminalRef, event.payload);
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
    const onVisibilityChange = () => setDocumentVisible(document.visibilityState === "visible");
    document.addEventListener("visibilitychange", onVisibilityChange);
    return () => document.removeEventListener("visibilitychange", onVisibilityChange);
  }, []);

  useEffect(() => {
    setSectionErrors((current) => navigationTransientState(current).sectionErrors);
    setLastAction(null);
    setActionLabel("");
  }, [activeSection]);

  function openResourceDialog(kind: Exclude<ResourceDialog, null>): void {
    resourceDialogGenerationRef.current += 1;
    setError(null);
    setResourceDialogError(null);
    setResourceDialog(kind);
  }

  function closeResourceDialog(): void {
    resourceDialogGenerationRef.current += 1;
    setResourceDialog(null);
    setResourceDialogError(null);
  }

  function dismissDialogs(): void {
    setRunDialogOpen(false);
    setRunDialogError(null);
    setPullImageDialogOpen(false);
    setPullFailure(null);
    setBuildImageDialogOpen(false);
    setBuildLicensingDialogOpen(false);
    setRegistryDialogOpen(false);
    closeResourceDialog();
    setLicensingDialogOpen(false);
    setDoctorDialogOpen(false);
    setSettingsDialog(null);
  }

  function selectSection(section: AppSection): void {
    const next = navigationTransientState(sectionErrors);
    setSectionErrors(next.sectionErrors);
    setLastAction(next.actionResult);
    setActionLabel(next.actionLabel);
    if (next.dismissDialogs) dismissDialogs();
    setActiveSection(section);
  }

  useEffect(() => {
    const onKeyDown = (event: KeyboardEvent) => {
      const command = shellKeyboardCommand(event);
      if (command === "focus-search") {
        event.preventDefault();
        globalSearchRef.current?.focus();
      } else if (command === "close-dialog") {
        dismissDialogs();
      }
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, []);

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

  function openComposeChooser(): void {
    setError(null);
    if (composeChooserMode(dialogAvailable) === "native-dialog") {
      void chooseComposeFile();
      return;
    }
    setComposeFileDialogOpen(true);
  }

  async function loadComposeHostPath(): Promise<void> {
    const file = composeFile.trim();
    const validationError = hostPathError(file, "file");
    if (validationError) {
      setError(validationError);
      return;
    }
    setComposeFile(file);
    setError(null);
    try {
      await readComposeSnapshot(file);
      setComposeFileDialogOpen(false);
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

  function beginRuntimeAction(): boolean {
    const availability = runtimeActionAvailability({
      actionBusy: runtimeActionRef.current,
      logsFollowing: logFollowRef.current,
      terminalActive: terminalActiveRef.current,
    });
    if (!availability.allowed) {
      setError(availability.reason);
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
    setError(null);
    setActionLabel(label);
    try {
      const result = await invoke<CommandResult>("run_desktop_action", { action, target });
      setLastAction(result);
      if (!result.ok) {
        setError(commandMessage(result, `${label} did not complete successfully (status ${result.code}).`));
      } else {
        await refresh();
      }
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
      const result = await invoke<CommandResult>(
        "run_desktop_action",
        { action: "pull_image", target: imageTarget },
        { timeoutMs: 10 * 60_000 },
      );
      if (result.ok) {
        setLastAction(result);
      }
      await refresh();
      const completion = pullCompletionState(result);
      setPullImageDialogOpen(completion.open);
      setPullProgress(completion.progress);
      setPullFailure(completion.failure);
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

  async function recoverFirstRun(): Promise<void> {
    if (!beginRuntimeAction()) return;
    setError(null);
    setActionLabel("Ferrocrate Start");
    try {
      const result = await runFirstRunRecovery({
        start: () => invoke<CommandResult>("run_desktop_action", { action: "vm_start" }),
        refreshSnapshot: refresh,
        refreshVolumes,
        refreshNetworks,
        refreshCompose: composeFile ? () => readComposeSnapshot(composeFile) : undefined,
      });
      setLastAction(result);
      if (!result.ok) setError(commandMessage(result, `Ferrocrate did not start (status ${result.code}).`));
    } catch (err) {
      setError(String(err));
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
    if (!logFollowRef.current || !beginRuntimeAction()) return;
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
    if (!terminalActiveRef.current || !beginRuntimeAction()) return;
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
    const requestGeneration = action === "create" ? resourceDialogGenerationRef.current : null;
    if (!beginRuntimeAction()) return;
    setError(null);
    if (action === "create") setResourceDialogError(null);
    setLastAction((current) => resourceActionStartState(action, current).actionResult);
    setActionLabel(label);
    try {
      const result = await invoke<CommandResult>("run_volume_action", { action, target });
      const next = resourceActionState(action, result, commandMessage(result, `${label} failed with status ${result.code}`), requestGeneration ?? undefined, resourceDialogGenerationRef.current);
      if (!next) return;
      setLastAction(next.actionResult);
      if (!result.ok) {
        if (next.dialogError) setResourceDialogError(next.dialogError);
        if (next.pageError) setError(next.pageError);
        return;
      }
      if (action === "create") {
        setVolumeName("");
        closeResourceDialog();
      }
      await Promise.all([refreshVolumes(), refresh()]);
    } catch (err) {
      if (action === "create") {
        if (requestGeneration === resourceDialogGenerationRef.current) setResourceDialogError(String(err));
      } else setError(String(err));
    } finally {
      finishRuntimeAction();
    }
  }

  async function runNetworkAction(
    action: NetworkAction,
    label: string,
    target: string,
  ): Promise<void> {
    if (action === "create" && !customNetworkCreateAvailable(snapshot?.daemon)) {
      setResourceDialogError("Custom networks need a privileged (rootful) daemon, or the Ferrocrate AppArmor profile. Open Doctor for guided setup.");
      return;
    }
    const requestGeneration = action === "create" ? resourceDialogGenerationRef.current : null;
    if (!beginRuntimeAction()) return;
    setError(null);
    if (action === "create") setResourceDialogError(null);
    setLastAction((current) => resourceActionStartState(action, current).actionResult);
    setActionLabel(label);
    try {
      const result = await invoke<CommandResult>("run_network_action", {
        action,
        target,
        subnet: action === "create" ? networkSubnet.trim() || null : null,
      });
      const next = resourceActionState(action, result, commandMessage(result, `${label} failed with status ${result.code}`), requestGeneration ?? undefined, resourceDialogGenerationRef.current);
      if (!next) return;
      setLastAction(next.actionResult);
      if (!result.ok) {
        if (next.dialogError) setResourceDialogError(next.dialogError);
        if (next.pageError) setError(next.pageError);
        return;
      }
      if (action === "create") {
        setNetworkName("");
        setNetworkSubnet("");
        closeResourceDialog();
      }
      await Promise.all([refreshNetworks(), refresh()]);
    } catch (err) {
      if (action === "create") {
        if (requestGeneration === resourceDialogGenerationRef.current) setResourceDialogError(String(err));
      } else setError(String(err));
    } finally {
      finishRuntimeAction();
    }
  }

  async function inspectContainer(target = containerTarget): Promise<void> {
    const selectedTarget = target.trim();
    if (!selectedTarget || !beginRuntimeAction()) return;
    setContainerTarget(selectedTarget);
    setContainerDetail(null);
    setInspectorError(null);
    try {
      const selection = await loadContainerSelection(selectedTarget, (selected) => (
        invoke<ContainerDetailSummary>("get_container_detail", { target: selected })
      ));
      setContainerTarget(selection.target);
      setContainerDetail(selection.detail);
      setInspectorError(selection.error);
      if (!selection.detail) return;
      const detail = selection.detail;
      setShowEnvironment(false);
      setDetailMemory(String(detail.resources.memory));
      setDetailCpuQuota(String(detail.resources.cpu_quota));
      setDetailCpuPeriod(String(detail.resources.cpu_period));
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
        setError(commandMessage(result, `Container update failed with status ${result.code}`));
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

  async function runNewContainer(payload: RunContainerInvokeArgs): Promise<void> {
    await submitRunContainer<CommandResult>({
      invoke,
      payload,
      begin: beginRuntimeAction,
      onBegin: () => {
        setError(null);
        setRunDialogError(null);
        setActionLabel("Container Run");
      },
      onResult: setLastAction,
      onError: setRunDialogError,
      onSuccess: async () => {
        setRunDialogOpen(false);
        setNewContainerDraft((current) => ({ ...current, name: "", command: "", environment: "" }));
        await Promise.all([refresh(), refreshNetworks(), refreshVolumes()]);
      },
      finish: finishRuntimeAction,
    });
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
        setError(commandMessage(result, `Registry login failed with status ${result.code}`));
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
        setError(commandMessage(result, `Registry logout failed with status ${result.code}`));
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
        setError(commandMessage(result, `${label} failed with status ${result.code}`));
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
    const buildId = `build-${Date.now()}-${++buildSequenceRef.current}`;
    const startedAt = Date.now();
    const context = buildContext.trim();
    const tag = buildTag.trim();
    setError(null);
    setLastAction(null);
    setActionLabel("Image Build");
    setBuildImageDialogOpen(false);
    setBuildHistory((history) => [{
      id: buildId,
      image: tag,
      status: "building",
      durationMs: null,
      progress: [],
    }, ...history]);
    try {
      const result = await invoke<CommandResult>(
        "build_image",
        buildInvokeArgs(context, tag, buildId),
        { timeoutMs: 30 * 60_000 },
      );
      if (result.ok) setLastAction(result);
      setBuildHistory((history) => history.map((build) => build.id === buildId ? {
        ...build,
        status: result.ok ? "succeeded" : "failed",
        durationMs: Date.now() - startedAt,
        error: result.ok ? undefined : commandMessage(result, `The build command ended unsuccessfully (status ${result.code}).`),
      } : build));
      await refresh();
    } catch (err) {
      setBuildHistory((history) => history.map((build) => build.id === buildId ? {
        ...build,
        status: "failed",
        durationMs: Date.now() - startedAt,
        error: String(err),
      } : build));
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
    await completeDoctorRun({
      execute: () => invoke<DoctorSummary>("run_doctor_action", {
        fix: doctorFix,
        bootstrap: doctorBootstrap,
        dry_run: doctorDryRun,
        confirm: doctorConfirm,
      }),
      refresh,
      setResult: setDoctorResult,
      setError,
      close: () => setDoctorDialogOpen(false),
      scheduleResultsFocus: () => { doctorResultsFocusPendingRef.current = true; },
      finish: finishRuntimeAction,
    });
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

  const runtimeBusy = runtimeActionBusy;

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

  const snapshotContainerRows = useMemo(
    () => parseContainerRows(snapshot?.containers.stdout ?? ""),
    [snapshot?.containers.stdout],
  );
  const containerRows = useMemo(
    () => containerStats == null ? snapshotContainerRows : mergeContainerStats(snapshotContainerRows, parseContainerStats(containerStats)),
    [containerStats, snapshotContainerRows],
  );
  const runningContainerIds = snapshotContainerRows.filter((row) => row.state === "running").map((row) => row.id);
  const runningContainerKey = runningContainerIds.join("\u0000");

  useEffect(() => {
    let disposed = false;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const visibilityState = documentVisible ? "visible" : "hidden";

    const schedule = () => {
      if (!disposed && shouldPollContainerStats(activeSection, visibilityState)) {
        timer = setTimeout(() => void poll(), 2000);
      }
    };
    const poll = async () => {
      if (disposed) return;
      if (!beginContainerStatsPoll(containerStatsPollOwnerRef.current, activeSection, visibilityState)) {
        schedule();
        return;
      }
      try {
        const response = await invoke<ContainerStatsResponse>("get_container_stats", { ids: runningContainerIds });
        if (!disposed) setContainerStats(response);
      } catch {
        if (!disposed) {
          setContainerStats({ samples: runningContainerIds.map((id) => ({ id, available: false, cpu_percent: null, memory_usage: null, memory_limit: null })) });
        }
      } finally {
        containerStatsPollOwnerRef.current.inFlight = false;
        schedule();
      }
    };

    if (shouldPollContainerStats(activeSection, visibilityState)) {
      void poll();
    } else {
      setContainerStats(null);
    }
    return () => {
      disposed = true;
      if (timer) clearTimeout(timer);
    };
  }, [activeSection, documentVisible, runningContainerKey]);
  const visibleContainers = useMemo(() => filterContainersByStatus(
    filterContainers(containerRows, globalSearch),
    containerStatusFilter,
  ), [containerRows, containerStatusFilter, globalSearch]);
  const containerGroups = useMemo(() => groupContainers(visibleContainers), [visibleContainers]);
  const imageRows = useMemo(() => parseImageRows(snapshot?.images.stdout ?? ""), [snapshot?.images.stdout]);
  const visibleImages = useMemo(() => filterNamedResources(imageRows, globalSearch, (image) => image.reference), [imageRows, globalSearch]);
  const visibleVolumes = useMemo(() => filterNamedResources(volumes, globalSearch), [volumes, globalSearch]);
  const visibleNetworks = useMemo(() => filterNamedResources(networks, globalSearch), [networks, globalSearch]);
  const containerImageReferences = useMemo(() => containerRows.map((row) => row.image), [containerRows]);
  const runningContainers = containerRows.filter((row) => row.state === "running").length;
  const resourceUsage = resourceTotalsForSurface(containerRows, activeSection, documentVisible ? "visible" : "hidden");
  const selectedRow = containerRows.find((row) => row.id === containerTarget || row.name === containerTarget) ?? null;
  const liveStatsUnavailable = containerRows.some((row) => row.state === "running" && row.statsAvailable === false);
  const imageCount = imageRows.length;
  const daemonPresentation = daemonStatusPresentation(snapshot?.daemon);
  const containerViewState = containerContentState(
    containerRows.length,
    visibleContainers.length,
    `${globalSearch} ${containerStatusFilter === "all" ? "" : containerStatusFilter}`,
  );
  const imagePage = resourcePageState("images", imageRows.length);
  const volumePage = resourcePageState("volumes", volumes.length);
  const networkPage = resourcePageState("networks", networks.length);
  const customNetworksAvailable = customNetworkCreateAvailable(snapshot?.daemon);
  const composePage = resourcePageState("compose", composeSnapshot?.services.length ?? 0, { loaded: composeSnapshot != null });
  const runtimeSurface = runtimeSurfaceState(snapshot, activeSection);
  const surfaceError = error ?? snapshotFailureDetail(snapshot, activeSection);
  const registryAccountName = registryStatus ? registryStatusText(registryStatus) : "Sign in";
  const sectionTitles: Record<AppSection, string> = {
    containers: "Containers",
    images: "Images",
    builds: "Builds",
    volumes: "Volumes",
    compose: "Compose",
    networks: "Networks",
    doctor: "Doctor",
    settings: "Settings",
  };

  useEffect(() => {
    applyRuntimeSurfaceTransition(runtimeSurface, {
      closeRun: () => { setRunDialogOpen(false); setRunDialogError(null); },
      closePull: () => setPullImageDialogOpen(false),
      closeBuild: () => { setBuildImageDialogOpen(false); setBuildLicensingDialogOpen(false); },
      closeRegistry: () => setRegistryDialogOpen(false),
      closeResource: closeResourceDialog,
      closeLicensing: () => setLicensingDialogOpen(false),
    });
  }, [runtimeSurface]);

  return (
    <div className="forge-shell">
      <header className="titlebar">
        <div className="traffic" aria-hidden="true"><span /><span /><span /></div>
        <div className="logo">Ferrocrate <em>{productSurfaceLabel()}</em></div>
        <label className="global-search">
          <Icon name="search" size={16} />
          <input
            ref={globalSearchRef}
            value={globalSearch}
            onChange={(event) => setGlobalSearch(event.target.value)}
            placeholder="Filter containers, images, volumes, networks…"
            aria-label="Global search"
          />
          <kbd>⌘K</kbd>
        </label>
        <button className="theme-toggle" onClick={() => setTheme(theme === "dark" ? "light" : "dark")} aria-label={`Use ${theme === "dark" ? "light" : "dark"} theme`}>
          <Icon name={theme === "dark" ? "sun" : "moon"} size={16} />
        </button>
        <div className={`daemon-pill is-${daemonPresentation.tone}`} title={daemonPresentation.title}>
          <span className="daemon-dot" /> {daemonPresentation.label}
        </div>
        <RegistryAccountControl status={registryStatus} onOpen={() => { setRegistryDialogOpen(true); void refreshRegistryAuth(); }} />
        {showGlobalRunAction(activeSection) ? <button className="btn btn-primary titlebar-primary" onClick={() => { setRunDialogError(null); setRunDialogOpen(true); }} disabled={runtimeBusy}>
          <Icon name="play" size={16} /> Run container
        </button> : null}
      </header>

      <DesktopTabBar
        activeSection={activeSection}
        counts={{
          containers: containerRows.length,
          images: imageCount,
          builds: buildHistory.length,
          compose: composeSnapshot?.services.length ?? 0,
          volumes: volumes.length,
          networks: networks.length,
        }}
        doctorIssues={doctorResult?.raw.checks.filter((check) => !check.ok).length ?? 0}
        onSelect={selectSection}
      />

      <div className="workspace">
        <main className="main-area">
          {runtimeSurface === "loading" ? (
            <div className="page-content first-run-page"><RuntimeLoadingState /></div>
          ) : runtimeSurface === "first-run" ? (
            <div className="page-content first-run-page">
              <FirstRunState
                busy={runtimeBusy}
                error={error}
                onStart={() => void recoverFirstRun()}
                onDoctor={() => { setError(null); setActiveSection("doctor"); }}
              />
            </div>
          ) : (
          <>
          <div className="page-header">
            <div>
              <p className="eyebrow">Local runtime</p>
              <div className="title-line">
                <h1>{sectionTitles[activeSection]}</h1>
                {activeSection === "containers" ? <span className="status-chip">{runningContainers} running</span> : null}
              </div>
            </div>
            {activeSection === "containers" ? (
              <div className="status-filters" role="group" aria-label="Filter containers by status">
                {(["all", "running", "degraded", "unhealthy", "exited"] as ContainerStatusFilter[]).map((filter) => (
                  <button
                    key={filter}
                    className={`status-filter ${containerStatusFilter === filter ? "active" : ""}`}
                    aria-pressed={containerStatusFilter === filter}
                    onClick={() => setContainerStatusFilter(filter)}
                  >{filter[0].toUpperCase() + filter.slice(1)}</button>
                ))}
              </div>
            ) : null}
            <div className="actions">
              {activeSection === "containers" ? (
                null
              ) : activeSection === "images" ? (
                <ImagePagePullAction hasImages={imageRows.length > 0} disabled={runtimeBusy} onOpen={openPullImageDialog} />
              ) : activeSection === "volumes" ? (
                volumePage.primaryAction ? <button className="btn btn-primary" onClick={() => openResourceDialog("volume")} disabled={runtimeBusy || volumesLoading}>Create volume</button> : null
              ) : activeSection === "networks" ? (
                networkPage.primaryAction ? <button className="btn btn-primary" onClick={() => openResourceDialog("network")} disabled={runtimeBusy || networksLoading || !customNetworksAvailable}>Create network</button> : null
              ) : activeSection === "compose" ? (
                composePage.primaryAction ? <button className="btn btn-primary" onClick={openComposeChooser} disabled={runtimeBusy || composeLoading}>Choose file</button> : null
              ) : activeSection === "builds" ? (
                null
              ) : activeSection === "doctor" || activeSection === "settings" ? (
                null
              ) : (
                <button className="btn btn-secondary" onClick={() => void Promise.all([refresh(), refreshVolumes(), refreshNetworks()])} disabled={loading || volumesLoading || networksLoading}>
                  {!loading ? <Icon name="refresh" size={16} /> : null}{loading ? "Refreshing…" : "Refresh runtime"}
                </button>
              )}
            </div>
          </div>

          {surfaceError ? <ActionErrorNotice error={surfaceError} humanMessage={error && lastAction && !lastAction.ok && error === lastAction.message ? lastAction.message : undefined} technicalDetail={error && lastAction && !lastAction.ok && error === lastAction.message ? `${lastAction.stderr || "No error output was returned."}\nStatus ${lastAction.code}` : undefined} onDismiss={() => setError(null)} onStart={() => void recoverFirstRun()} onReviewLicensing={(detail) => { setLicensingDetail(detail); setLicensingDialogOpen(true); }} onDoctor={() => setActiveSection("doctor")} /> : null}

          <div className={`page-content ${activeSection === "containers" && containerViewState === "table" ? "container-layout" : ""}`}>
            {activeSection === "containers" ? (
              containerViewState === "empty" ? (
                <section className="panel empty-page-panel" aria-label="Containers">
                  <ResourceEmptyState section="containers" disabled={runtimeBusy} onAction={() => setRunDialogOpen(true)} />
                </section>
              ) : containerViewState === "filtered-empty" ? (
                <section className="panel empty-page-panel" aria-label="No matching containers">
                  <div className="empty-state resource-empty-state">
                    <span className="empty-state-icon" aria-hidden="true"><Icon name="search" size={20} /></span>
                    <span className="empty-state-copy">No containers match the current search and status filters.</span>
                    <button className="btn btn-secondary" onClick={() => { setGlobalSearch(""); setContainerStatusFilter("all"); }}>Clear filters</button>
                  </div>
                </section>
              ) : (
              <>
                <section className="panel table-panel" aria-label="Containers">
                  <div className="table-toolbar">
                    <span className="count-badge">{containerRows.length}</span>
                    <details className="image-toolbar-overflow">
                      <summary aria-label="More container actions"><Icon name="more" size={16} /></summary>
                      <div className="overflow-menu">
                        <button onClick={() => void refresh()} disabled={loading}>Refresh containers</button>
                        <button className="danger-action" onClick={() => void runAction("container_prune", "Container Prune")} disabled={runtimeBusy}>Prune stopped containers</button>
                      </div>
                    </details>
                  </div>
                  {liveStatsUnavailable ? <p className="muted" role="status">{containerStatsUnavailableMessage()}</p> : null}
                  <div className="mobile-target">
                    <input value={containerTarget} onChange={(event) => setContainerTarget(event.target.value)} placeholder="Container name or ID" />
                    <button className="btn btn-secondary" onClick={() => void inspectContainer()} disabled={runtimeBusy || !containerTarget.trim()}>Open</button>
                  </div>
                  <div className="table-scroll">
                    <table>
                      <thead><tr><th>Name</th><th>Image</th><th>Status</th><th>Ports</th><th>Started</th><th>CPU</th><th>Memory</th><th aria-label="Actions" /></tr></thead>
                      <tbody>
                        {containerGroups.map((group) => (
                          <Fragment key={group.name}>
                            <tr className="container-group-row">
                              <td colSpan={8}>
                                <strong>{group.name}</strong>
                                <span>{group.compose ? "Compose project" : "Not managed by Compose"}</span>
                                <span className="group-summary">{group.rows.length} container{group.rows.length === 1 ? "" : "s"} · {group.running} running</span>
                              </td>
                            </tr>
                            {group.rows.map((row) => {
                              const tone = statusTone(row);
                              const selected = selectedRow?.id === row.id;
                              const remove = containerRemoveAvailability(row);
                              return (
                                <tr key={row.id} className={selected ? "selected" : ""} onClick={() => void inspectContainer(row.id)}>
                                  <td><div className="container-name">{row.composeService || row.name}</div>{row.composeService ? <div className="container-runtime-name mono">{row.name}</div> : null}</td>
                                  <td className="mono muted-cell">{row.image}</td>
                                  <td><span className={`container-status ${tone}`}><i />{statusLabel(row)}</span></td>
                                  <td className="mono muted-cell">{row.ports}</td>
                                  <td className="mono muted-cell">{formatUnix(row.startedAt)}</td>
                                  <td className="mono muted-cell">{row.cpu}</td>
                                  <td className="mono muted-cell">{row.memory}</td>
                                  <td className="row-actions">
                                    <details className="row-menu" onClick={(event) => event.stopPropagation()}>
                                      <summary aria-label={`Actions for ${row.name}`}><Icon name="more" size={16} /></summary>
                                      <div className="overflow-menu">
                                        <button onClick={() => void runAction(row.state === "running" ? "stop_container" : "start_container", row.state === "running" ? "Container Stop" : "Container Start", row.id)}><Icon name={row.state === "running" ? "stop" : "play"} size={16} />{row.state === "running" ? "Stop container" : "Start container"}</button>
                                        <button onClick={() => { setContainerTarget(row.id); setDetailTab("logs"); void startLogFollow(row.id); }}><Icon name="terminal" size={16} />Follow logs</button>
                                        <button onClick={() => { setContainerTarget(row.id); setDetailTab("terminal"); void inspectContainer(row.id); }}><Icon name="terminal" size={16} />Open terminal</button>
                                        <button className="danger-action" onClick={() => void runAction("remove_container", "Container Remove", row.id)} disabled={!remove.allowed} title={remove.reason || undefined}><Icon name="trash" size={16} />{remove.allowed ? "Remove container" : "Stop before removing"}</button>
                                      </div>
                                    </details>
                                  </td>
                                </tr>
                              );
                            })}
                          </Fragment>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </section>

                <section className="panel detail-panel bottom-inspector" aria-label="Container inspector">
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
                  {inspectorError ? <ActionErrorNotice error={inspectorError} onDismiss={() => setInspectorError(null)} onStart={() => void recoverFirstRun()} onDoctor={() => setActiveSection("doctor")} /> : null}

                  <div className={`detail-pane logs-pane ${detailTab === "logs" ? "active" : ""}`}>
                    <div className="log-toolbar"><input value={logFilter} onChange={(event) => setLogFilter(event.target.value)} placeholder="Filter log stream" /></div>
                    <pre className="log-output">{visibleLogText || (logsFollowing ? "Waiting for log lines…" : "Select a container and start following logs.")}</pre>
                    <div className="detail-foot">
                      <button className="btn btn-secondary" onClick={toggleLogPause} disabled={!logsFollowing}><Icon name={logsPaused ? "play" : "pause"} size={16} />{logsPaused ? "Resume" : "Pause"}</button>
                      <button className="btn btn-secondary" onClick={() => selectedRow && void startLogFollow(selectedRow.id)} disabled={!selectedRow || runtimeBusy || logsFollowing}><Icon name="terminal" size={16} />{logsFollowing ? "Following" : "Follow"}</button>
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
                    <div className="terminal-host" ref={setTerminalHost} aria-label="Interactive container terminal" />
                    <div className="detail-foot">
                      <button className="btn btn-primary" onClick={() => void startTerminal()} disabled={runtimeBusy || terminalActive || !containerTarget.trim()}>Open shell</button>
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
                        {selectedRow?.statsAvailable === false ? null : <div className="stat-cards"><div><span>CPU usage</span><strong>{selectedRow?.cpu || "Waiting for live stats…"}</strong></div><div><span>Memory usage</span><strong>{selectedRow?.memoryUsage == null ? "Waiting for live stats…" : formatBytes(selectedRow.memoryUsage)}</strong></div><div><span>Memory limit</span><strong>{selectedRow?.memoryLimit == null ? "Unlimited" : formatBytes(selectedRow.memoryLimit)}</strong></div><div><span>Health</span><strong>{containerDetail.health?.status || "Not configured"}</strong></div></div>}
                        <section className="drawer-section"><h3>Resource limits</h3><div className="editor-grid"><label><span>Memory bytes</span><input inputMode="numeric" value={detailMemory} onChange={(event) => setDetailMemory(event.target.value)} /></label><label><span>CPU quota</span><input inputMode="numeric" value={detailCpuQuota} onChange={(event) => setDetailCpuQuota(event.target.value)} /></label><label><span>CPU period</span><input inputMode="numeric" value={detailCpuPeriod} onChange={(event) => setDetailCpuPeriod(event.target.value)} /></label></div><button className="btn btn-primary" onClick={() => void updateContainerResources()} disabled={runtimeBusy}>Apply limits</button></section>
                        <section className="drawer-section"><h3>Health history</h3>{containerDetail.health ? <><p className="muted">{containerDetail.health.status} · failing streak {containerDetail.health.failing_streak}</p>{containerDetail.health.log.length ? <ol className="health-list">{containerDetail.health.log.map((entry, index) => <li key={`${entry.start}:${index}`}><strong>Exit {entry.exit_code}</strong><span>{entry.start} → {entry.end}</span><code>{entry.output || "No output"}</code></li>)}</ol> : <p className="muted">No health checks recorded.</p>}</> : <p className="muted">No health check configured.</p>}</section>
                      </>
                    ) : <div className="empty-state"><strong>No stats loaded</strong><span>Select a container row.</span></div>}
                  </div>
                </section>
              </>
              )
            ) : null}

            {activeSection === "images" ? (
              imagePage.content === "empty" ? (
                <section className="panel empty-page-panel" aria-label="Images">
                  <ResourceEmptyState section="images" disabled={runtimeBusy} onAction={openPullImageDialog} />
                </section>
              ) : (
                <section className="panel table-panel image-table-panel" aria-label="Images">
                  <div className="table-toolbar">
                    <span className="count-badge">{visibleImages.length}</span>
                    <details className="image-toolbar-overflow">
                      <summary aria-label="More image actions"><Icon name="more" size={16} /></summary>
                      <div className="overflow-menu">
                        <button onClick={() => void refresh()} disabled={loading}>Refresh images</button>
                        <button className="danger-action" onClick={() => void runAction("image_prune", "Image Prune")} disabled={runtimeBusy}>Prune unused images</button>
                      </div>
                    </details>
                  </div>
                  <div className="table-scroll">
                    <table>
                      <thead><tr><th>Repository</th><th>Size</th><th>Created</th><th>In use</th><th aria-label="Actions" /></tr></thead>
                      <tbody>{visibleImages.map((image) => (
                        <tr key={image.id}>
                          <td className="container-name mono" title={image.fullReference}>{image.reference}</td>
                          <td className="muted">{image.size}</td>
                          <td className="muted">{image.created}</td>
                          <td>{imageIsUsed(image, containerImageReferences) ? <span className="status-chip">In use</span> : <span className="muted">Not in use</span>}</td>
                          <td className="row-actions"><details className="row-menu"><summary aria-label={`Actions for ${image.reference}`}><Icon name="more" size={16} /></summary><div className="overflow-menu"><button className="danger-action" onClick={() => void runAction("remove_image", "Image Remove", image.fullReference)} disabled={runtimeBusy}><Icon name="trash" size={16} />Remove image</button></div></details></td>
                        </tr>
                      ))}</tbody>
                    </table>
                  </div>
                </section>
              )
            ) : null}

            {activeSection === "builds" ? (
              <BuildHistoryList
                builds={buildHistory}
                disabled={runtimeBusy}
                onNewBuild={() => setBuildImageDialogOpen(true)}
                onStart={() => void startFerrocrate()}
                onReviewLicensing={(detail) => { setBuildLicensingDetail(detail); setBuildLicensingDialogOpen(true); }}
                onDoctor={() => setActiveSection("doctor")}
              />
            ) : null}

            {activeSection === "volumes" ? (
              volumePage.content === "empty" ? (
                <section className="panel empty-page-panel" aria-label="Volumes">
                  <ResourceEmptyState section="volumes" disabled={runtimeBusy || volumesLoading} onAction={() => openResourceDialog("volume")} />
                </section>
              ) : (
                <section className="panel table-panel resource-table-panel" aria-label="Volumes">
                  <div className="table-toolbar">
                    <span className="count-badge">{visibleVolumes.length}</span>
                    <details className="image-toolbar-overflow">
                      <summary aria-label="More volume actions"><Icon name="more" size={16} /></summary>
                      <div className="overflow-menu">
                        <button onClick={() => void refreshVolumes()} disabled={runtimeBusy || volumesLoading}>{volumesLoading ? "Refreshing…" : "Refresh volumes"}</button>
                        <button className="danger-action" onClick={() => void runVolumeAction("prune", "Volume Prune")} disabled={runtimeBusy || volumesLoading}>Prune unused volumes</button>
                      </div>
                    </details>
                  </div>
                  <div className="table-scroll"><table><thead><tr><th>Name</th><th>Driver</th><th>Mountpoint</th><th>Usage</th><th aria-label="Actions" /></tr></thead><tbody>
                    {visibleVolumes.map((volume) => <tr key={volume.name}><td className="container-name">{volume.name}</td><td>{volume.driver}</td><td className="mono muted-cell">{volume.mountpoint}</td><td>{volume.mounts.length ? <ul className="mount-list compact-list">{volume.mounts.map((mount) => <li key={`${mount.container_id}:${mount.destination}`}>{formatVolumeMount(mount)}</li>)}</ul> : <span className="muted">Unused</span>}</td><td className="row-actions"><details className="row-menu"><summary aria-label={`Actions for ${volume.name}`}><Icon name="more" size={16} /></summary><div className="overflow-menu"><button className="danger-action" onClick={() => void runVolumeAction("remove", "Volume Remove", volume.name)} disabled={runtimeBusy || volumesLoading || volumeIsInUse(volume)}><Icon name="trash" size={16} />Remove volume</button></div></details></td></tr>)}
                  </tbody></table></div>
                </section>
              )
            ) : null}

            {activeSection === "networks" ? (
              <>
              <NetworkCapabilityNotice customNetworks={customNetworksAvailable} onDoctor={() => setActiveSection("doctor")} />
              {networkPage.content === "empty" ? (
                <section className="panel empty-page-panel" aria-label="Networks">
                  <ResourceEmptyState section="networks" disabled={runtimeBusy || networksLoading || !customNetworksAvailable} onAction={() => openResourceDialog("network")} />
                </section>
              ) : (
                <section className="panel table-panel resource-table-panel" aria-label="Networks">
                  <div className="table-toolbar">
                    <span className="count-badge">{visibleNetworks.length}</span>
                    <details className="image-toolbar-overflow">
                      <summary aria-label="More network actions"><Icon name="more" size={16} /></summary>
                      <div className="overflow-menu"><button onClick={() => void refreshNetworks()} disabled={runtimeBusy || networksLoading}>{networksLoading ? "Refreshing…" : "Refresh networks"}</button></div>
                    </details>
                  </div>
                  <div className="table-scroll"><table><thead><tr><th>Name</th><th>Driver</th><th>Subnet</th><th>Containers</th><th aria-label="Actions" /></tr></thead><tbody>
                    {visibleNetworks.map((network) => <tr key={network.name}><td className="container-name">{network.name}</td><td>{network.driver}</td><td className="mono muted-cell">{network.subnets.length ? network.subnets.join(", ") : "Managed automatically"}</td><td>{network.containers.length ? <ul className="mount-list compact-list">{network.containers.map((attachment) => <li key={`${network.name}:${attachment.container_id}`}>{formatNetworkAttachment(attachment)}</li>)}</ul> : <span className="muted">None attached</span>}</td><td className="row-actions"><details className="row-menu"><summary aria-label={`Actions for ${network.name}`}><Icon name="more" size={16} /></summary><div className="overflow-menu"><button className="danger-action" onClick={() => void runNetworkAction("remove", "Network Remove", network.name)} disabled={runtimeBusy || networksLoading || !networkIsRemovable(network) || network.containers.length > 0}><Icon name="trash" size={16} />Remove network</button></div></details></td></tr>)}
                  </tbody></table></div>
                </section>
              )}
              </>
            ) : null}

            {activeSection === "compose" ? (
              composePage.content === "empty" ? (
                <section className="panel empty-page-panel" aria-label="Compose">
                  <ResourceEmptyState section="compose" disabled={runtimeBusy || composeLoading} onAction={openComposeChooser} />
                </section>
              ) : (
                <section className="panel table-panel resource-table-panel" aria-label="Compose services">
                  <div className="table-toolbar">
                    <span className="toolbar-label mono" title={composeFile}>{composeFile}</span>
                    <span className="count-badge">{composeSnapshot?.services.length ?? 0}</span>
                    <details className="image-toolbar-overflow">
                      <summary aria-label="More Compose actions"><Icon name="more" size={16} /></summary>
                      <div className="overflow-menu">
                        <button onClick={() => void validateCompose()} disabled={runtimeBusy || composeLoading}>{composeLoading ? "Validating…" : "Validate configuration"}</button>
                        <button onClick={() => void runComposeAction("up", "Compose Up")} disabled={runtimeBusy || composeLoading}>Create and start services</button>
                        <button onClick={() => void runComposeAction("start", "Compose Start")} disabled={runtimeBusy || composeLoading}>Start services</button>
                        <button onClick={() => void runComposeAction("stop", "Compose Stop")} disabled={runtimeBusy || composeLoading}>Stop services</button>
                        <button className="danger-action" onClick={() => void runComposeAction("down", "Compose Down")} disabled={runtimeBusy || composeLoading}>Remove project</button>
                      </div>
                    </details>
                  </div>
                  <div className="table-scroll"><table><thead><tr><th>Service</th><th>Status</th><th>Container</th><th aria-label="Actions" /></tr></thead><tbody>
                    {composeSnapshot?.services.map((service) => <tr key={service.name}><td className="container-name">{service.name}</td><td><span className={`service-status ${composeStatusClass(service.status)}`}>{service.status.replace(/_/g, " ")}</span></td><td className="mono muted-cell">{service.container_id || "Not created"}</td><td className="row-actions"><details className="row-menu"><summary aria-label={`Actions for ${service.name}`}><Icon name="more" size={16} /></summary><div className="overflow-menu"><button onClick={() => { void showComposeLogs(service); setActiveSection("containers"); setDetailTab("logs"); }} disabled={runtimeBusy || service.status === "not_created"}><Icon name="terminal" size={16} />Follow logs</button></div></details></td></tr>)}
                  </tbody></table></div>
                  <details className="compose-config"><summary>Validated configuration</summary><pre>{composeSnapshot?.config}</pre></details>
                </section>
              )
            ) : null}

            {activeSection === "doctor" ? <DoctorPage result={doctorResult} busy={runtimeBusy} resultsTableRef={doctorResultsTableRef} onRun={() => setDoctorDialogOpen(true)} onStart={() => void runAction("vm_start", "Ferrocrate Start")} onStop={() => void runAction("vm_stop", "Ferrocrate Stop")} /> : null}

            {activeSection === "settings" ? <SettingsPage authState={authState} installerResult={installerResult} nativeLinux={snapshot?.daemon.platform === "linux-native"} daemonStatus={snapshot?.daemon} onOpenAccount={() => setSettingsDialog("account")} onOpenInstall={() => setSettingsDialog("install")} /> : null}

            {lastAction ? <section className="last-action"><strong>{actionLabel}</strong><span className={lastAction.ok ? "ok-text" : "bad-text"}>{lastAction.ok ? "completed" : "did not complete"}</span>{lastAction.stderr || !lastAction.ok ? <details><summary>Technical details</summary><pre>{`${lastAction.stderr || "No error output was returned."}\nStatus ${lastAction.code}`}</pre></details> : null}</section> : null}
          </div>
          </>
          )}
        </main>
      </div>

      <footer className="statusbar">
        <span><b>{containerRows.length}</b> containers · <b>{runningContainers}</b> running</span>
        <span><b>{imageCount}</b> images</span>
        <span>engine <b>native</b> — VM optional</span>
        <div className="status-right">{resourceUsage.cpu ? <span>CPU <b>{resourceUsage.cpu}</b></span> : null}{resourceUsage.memory ? <span>MEM <b>{resourceUsage.memory}</b></span> : null}<span>v0.1.0</span></div>
      </footer>

      <DoctorDialog open={doctorDialogOpen} fix={doctorFix} bootstrap={doctorBootstrap} dryRun={doctorDryRun} confirm={doctorConfirm} busy={runtimeBusy} onFixChange={(event) => setDoctorFix(event.target.checked)} onBootstrapChange={(event) => setDoctorBootstrap(event.target.checked)} onDryRunChange={(event) => setDoctorDryRun(event.target.checked)} onConfirmChange={(event) => setDoctorConfirm(event.target.checked)} onCancel={() => setDoctorDialogOpen(false)} onRun={() => void runDoctor()} />

      <AccountDialog open={settingsDialog === "account"} releaseBaseUrl={releaseBaseUrl} tokenEndpoint={tokenEndpoint} issuanceEndpoint={issuanceEndpoint} customerId={customerId} accessToken={accessToken} sessionToken={sessionTokenInput} authLoading={authLoading} accountConnected={Boolean(sessionSummary?.token_present)} plan={sessionSummary?.plan ?? null} expiresText={sessionSummary?.expires_at ? `Session expires ${formatUnix(sessionSummary.expires_at)}` : null} entitlement={authState?.entitlement ?? {}} onReleaseBaseUrlChange={(event) => setReleaseBaseUrl(event.target.value)} onTokenEndpointChange={(event) => setTokenEndpoint(event.target.value)} onIssuanceEndpointChange={(event) => setIssuanceEndpoint(event.target.value)} onCustomerIdChange={(event) => setCustomerId(event.target.value)} onAccessTokenChange={(event) => setAccessToken(event.target.value)} onSessionTokenChange={(event) => setSessionTokenInput(event.target.value)} onClose={() => setSettingsDialog(null)} onSaveBackend={() => void saveBackendConfig()} onConnect={() => void acquireSessionToken()} onDisconnect={() => void clearSessionToken()} onRefresh={() => void refreshAuthState()} onSaveSession={() => void saveSessionToken()} />

      <InstallDialog open={settingsDialog === "install"} installerResult={installerResult} busy={runtimeBusy} onClose={() => setSettingsDialog(null)} onPreview={() => void runInstaller(true, false)} onInstall={() => void runInstaller(false, true)} />

      <RunContainerDialog open={runDialogOpen} draft={newContainerDraft} busy={runtimeBusy} error={runDialogError} onDraftChange={setNewContainerDraft} onCancel={() => { setRunDialogError(null); setRunDialogOpen(false); }} onRun={(payload) => void runNewContainer(payload)} onInvalid={(error) => setRunDialogError(String(error))} onStart={() => void recoverFirstRun()} onReviewLicensing={(detail) => { setRunDialogOpen(false); setLicensingDetail(detail); setLicensingDialogOpen(true); }} onDoctor={() => { setRunDialogOpen(false); setActiveSection("doctor"); }} />

      <ResourceCreateDialog
        kind={resourceDialog}
        name={resourceDialog === "network" ? networkName : volumeName}
        subnet={networkSubnet}
        busy={runtimeActionBusy || volumesLoading || networksLoading}
        error={resourceDialogError}
        onNameChange={(event) => resourceDialog === "network" ? setNetworkName(event.target.value) : setVolumeName(event.target.value)}
        onSubnetChange={(event) => setNetworkSubnet(event.target.value)}
        onCancel={closeResourceDialog}
        onCreate={() => resourceDialog === "network"
          ? void runNetworkAction("create", "Network Create", networkName)
          : void runVolumeAction("create", "Volume Create", volumeName)}
        onStart={() => void recoverFirstRun()}
        onReviewLicensing={(detail) => { closeResourceDialog(); setLicensingDetail(detail); setLicensingDialogOpen(true); }}
      />

      {pullImageDialogOpen ? (
        <PullImageDialog open={pullImageDialogOpen} imageTarget={imageTarget} progress={pullProgress} failure={pullFailure} busy={runtimeBusy} onCancel={() => setPullImageDialogOpen(false)} onImageTargetChange={(event) => setImageTarget(event.target.value)} onPull={() => void pullImage()} onStart={() => void startFerrocrate()} onReviewLicensing={() => { setPullImageDialogOpen(false); setActiveSection("settings"); }} onDoctor={() => { setPullImageDialogOpen(false); setActiveSection("doctor"); }} />
      ) : null}
      <ComposeFileDialog open={composeFileDialogOpen} value={composeFile} busy={runtimeBusy || composeLoading} onChange={(event) => { setComposeFile(event.target.value); setError(null); }} onSubmit={() => void loadComposeHostPath()} onCancel={() => setComposeFileDialogOpen(false)} />

      <BuildImageDialog open={buildImageDialogOpen} context={buildContext} tag={buildTag} dialogAvailable={dialogAvailable} busy={runtimeBusy} onContextChange={(event) => setBuildContext(event.target.value)} onChooseContext={() => void chooseBuildContext()} onTagChange={(event) => setBuildTag(event.target.value)} onCancel={() => setBuildImageDialogOpen(false)} onBuild={() => void buildImage()} />

      <BuildLicensingDialog
        open={buildLicensingDialogOpen}
        detail={buildLicensingDetail}
        onClose={() => setBuildLicensingDialogOpen(false)}
        onOpenSettings={() => { setBuildLicensingDialogOpen(false); setActiveSection("settings"); }}
      />

      <LicensingDialog
        open={licensingDialogOpen}
        detail={licensingDetail}
        onClose={() => setLicensingDialogOpen(false)}
        onOpenSettings={() => { setLicensingDialogOpen(false); setActiveSection("settings"); }}
      />

      <RegistryDialog open={registryDialogOpen} target={registryTarget} username={registryUsername} password={registryPassword} status={registryStatus} accountName={registryAccountName} busy={runtimeBusy} loading={registryLoading} onTargetChange={(event) => { setRegistryTarget(event.target.value); setRegistryStatus(null); }} onUsernameChange={(event) => setRegistryUsername(event.target.value)} onPasswordChange={(event) => setRegistryPassword(event.target.value)} onCancel={() => setRegistryDialogOpen(false)} onCheck={() => void refreshRegistryAuth()} onLogout={() => void logoutRegistry()} onLogin={() => void loginRegistry()} />
    </div>
  );

}

export default App;
