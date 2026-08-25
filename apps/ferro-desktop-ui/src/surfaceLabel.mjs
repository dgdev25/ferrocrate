export function productSurfaceLabel(target = globalThis) {
  return target.__FERROCRATE_DASHBOARD__ ? "Dashboard" : "Desktop";
}
