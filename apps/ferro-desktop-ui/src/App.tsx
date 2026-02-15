import { invoke } from "@tauri-apps/api/core";
import { useEffect, useState } from "react";
import type { DesktopSnapshot } from "./types";

const EMPTY = "No data yet";
const THEME_KEY = "ferro_desktop_theme";
type ThemeMode = "dark" | "light";

function App(): JSX.Element {
  const [snapshot, setSnapshot] = useState<DesktopSnapshot | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [theme, setTheme] = useState<ThemeMode>("dark");

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

  useEffect(() => {
    void refresh();
  }, []);

  return (
    <main className="app-shell">
      <header className="app-header">
        <h1>FerroCrate Desktop MVP</h1>
        <div className="actions">
          <button
            className="btn btn-secondary"
            onClick={() => setTheme(theme === "dark" ? "light" : "dark")}
          >
            Theme: {theme === "dark" ? "Dark" : "Light"}
          </button>
          <button className="btn btn-primary" onClick={() => void refresh()} disabled={loading}>
            {loading ? "Refreshing..." : "Refresh"}
          </button>
        </div>
      </header>

      {error ? <p className="error">{error}</p> : null}

      <section className="grid">
        <article className="panel">
          <h2>Runtime Status</h2>
          <pre>{snapshot?.runtime.stdout || EMPTY}</pre>
          {snapshot?.runtime.stderr ? <p className="muted">{snapshot.runtime.stderr}</p> : null}
        </article>

        <article className="panel">
          <h2>Containers</h2>
          <pre>{snapshot?.containers.stdout || EMPTY}</pre>
          {snapshot?.containers.stderr ? <p className="muted">{snapshot.containers.stderr}</p> : null}
        </article>

        <article className="panel">
          <h2>Images</h2>
          <pre>{snapshot?.images.stdout || EMPTY}</pre>
          {snapshot?.images.stderr ? <p className="muted">{snapshot.images.stderr}</p> : null}
        </article>
      </section>
    </main>
  );
}

export default App;
