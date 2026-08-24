import type { AppSection } from "./desktopChrome.mjs";
export type SectionErrors = Partial<Record<AppSection, string>>;
export function setSectionError(errors: SectionErrors, section: AppSection, error: unknown): SectionErrors;
export function errorForSection(errors: SectionErrors, section: AppSection): string | null;
export function clearErrorsForNavigation(errors: SectionErrors): SectionErrors;
