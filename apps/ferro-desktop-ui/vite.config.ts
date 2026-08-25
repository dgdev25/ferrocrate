import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  clearScreen: false,
  build: {
    rollupOptions: {
      output: {
        manualChunks(id) {
          if (id.includes("node_modules/@xterm/")) return "terminal";
          if (id.includes("node_modules/@tauri-apps/")) return "tauri";
          if (id.includes("node_modules/react")) return "react";
        }
      }
    }
  },
  server: {
    port: 1420,
    strictPort: true
  }
});
