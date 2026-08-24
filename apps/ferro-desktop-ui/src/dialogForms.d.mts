import type { ReactElement } from "react";
import type { MappingRow, PortRow } from "./runContainer.mjs";

type ControlEvent = { target: { value: string; checked: boolean } };
type ControlHandler = (event: ControlEvent) => void;
type Action = () => void;

export type RunContainerInvokeArgs = {
  image: string;
  name: string | null;
  command: string[];
  ports: string[];
  volumes: string[];
  pullIfMissing: boolean;
  environment: string[];
  memory: number | null;
  cpuQuota: number | null;
  cpuPeriod: number | null;
};

export type RunContainerDraft = {
  image: string; name: string; command: string; pullIfMissing: boolean; ports: PortRow[]; volumes: MappingRow[];
  environment: string; memoryMb: string; cpus: string;
};

export function DoctorDialog(props: {
  open: boolean; fix: boolean; bootstrap: boolean; dryRun: boolean; confirm: boolean; busy: boolean;
  onFixChange: ControlHandler; onBootstrapChange: ControlHandler; onDryRunChange: ControlHandler; onConfirmChange: ControlHandler;
  onCancel: Action; onRun: Action;
}): ReactElement | null;

export function AccountDialog(props: {
  open: boolean; releaseBaseUrl: string; tokenEndpoint: string; issuanceEndpoint: string; customerId: string; accessToken: string; sessionToken: string;
  authLoading: boolean; accountConnected: boolean; plan: string | null; expiresText: string | null; entitlement: unknown;
  onReleaseBaseUrlChange: ControlHandler; onTokenEndpointChange: ControlHandler; onIssuanceEndpointChange: ControlHandler;
  onCustomerIdChange: ControlHandler; onAccessTokenChange: ControlHandler; onSessionTokenChange: ControlHandler;
  onClose: Action; onSaveBackend: Action; onConnect: Action; onDisconnect: Action; onRefresh: Action; onSaveSession: Action;
}): ReactElement | null;

export function InstallDialog(props: {
  open: boolean; installerResult: unknown; busy: boolean; onClose: Action; onPreview: Action; onInstall: Action;
}): ReactElement | null;

export function RunContainerDialog(props: {
  open: boolean; draft: RunContainerDraft; busy: boolean; error: string | null;
  onDraftChange: (draft: RunContainerDraft) => void; onCancel: Action; onRun: (payload: RunContainerInvokeArgs) => void | Promise<void>; onInvalid: (error: unknown) => void;
  onStart: Action; onReviewLicensing: (detail: string) => void; onDoctor: Action;
}): ReactElement | null;

export function BuildImageDialog(props: {
  open: boolean; context: string; tag: string; dialogAvailable: boolean; busy: boolean;
  onContextChange: ControlHandler; onChooseContext: Action; onTagChange: ControlHandler; onCancel: Action; onBuild: Action;
}): ReactElement | null;

export function RegistryDialog(props: {
  open: boolean; target: string; username: string; password: string;
  status: { logged_in: boolean; registry: string } | null; accountName: string; busy: boolean; loading: boolean;
  onTargetChange: ControlHandler; onUsernameChange: ControlHandler; onPasswordChange: ControlHandler;
  onCancel: Action; onCheck: Action; onLogout: Action; onLogin: Action;
}): ReactElement | null;
