import type { AppSection } from "./desktopChrome.mjs";
import type { CommandResult, NetworkAction, VolumeAction } from "./types";
export type SectionErrors = Partial<Record<AppSection, string>>;
export type ResourceActionState = {
  actionResult: CommandResult | null;
  dialogError: string | null;
  pageError: string | null;
};
export function setSectionError(errors: SectionErrors, section: AppSection, error: unknown): SectionErrors;
export function errorForSection(errors: SectionErrors, section: AppSection): string | null;
export function clearErrorsForNavigation(errors: SectionErrors): SectionErrors;
export function resourceActionState(action: NetworkAction | VolumeAction, result: CommandResult, detail: string): ResourceActionState;
export function resourceActionStartState(action: NetworkAction | VolumeAction, actionResult: CommandResult | null): {
  actionResult: CommandResult | null;
};
export function navigationTransientState(sectionErrors: SectionErrors): {
  actionLabel: "";
  actionResult: null;
  sectionErrors: SectionErrors;
};
