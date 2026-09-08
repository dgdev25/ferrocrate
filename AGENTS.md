# FerroCrate Agent Standing Instructions (AGENTS.md)

This file contains standing design and implementation instructions for AI agents working on the FerroCrate Desktop UI and CLI tooling.

## UI/UX Standing Instructions

When designing, updating, or implementing modifications to the FerroCrate Desktop UI (Tauri application), always adhere to the following principles:

1. **Workspace-Centric Views:** Group all containers, volumes, and network mappings under their parent project workspaces (e.g. Compose Projects) instead of displaying flat lists.
2. **Auto-Associated Resources:** Place volumes and network interfaces directly inside the workspace card that created them so developers instantly understand resource relationships.
3. **One-Click Row/Service Controls:** Put simple, explicit action buttons (e.g. Start/Stop, Logs, Terminal) directly beside the services in the lists. Avoid burying primary actions inside deeply nested settings menus.
4. **Slide-Out Details (Drawer):** Use a collapsible right-hand slide-out drawer for inspecting logs or running interactive container terminal shells (`docker exec`). Do not use large bottom drawers that compress the layout.
5. **Zero-Config Launcher Presets:** When launching new containers, use presets that automatically suggest free host ports, allocate named volumes, and preset standard container ports to eliminate manual configuration.
6. **Intelligent Port Conflict Resolution:** If a port conflict is detected, intercept it and show an actionable resolution modal offering to either auto-assign an alternative free host port or replace the conflicting container.
