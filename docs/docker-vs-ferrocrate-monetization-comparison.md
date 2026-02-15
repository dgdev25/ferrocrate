# Docker vs FerroCrate Monetization Comparison

| Area | Docker (current) | FerroCrate (current code) | FerroCrate (intended in docs) | Gap / implication |
|---|---|---|---|---|
| Core free offering | Personal plan free; core tooling included in Desktop plan matrix | CLI/runtime code is open and buildable from source | OSS core is intended free | Similar high-level shape |
| Paid tiers | Pro, Team, Business with per-user pricing | No enforced paid tiers in code | Pro and Enterprise defined | Not implemented yet |
| Pricing model | Seat-based + consumption add-ons (Build Cloud/Testcontainers/Scout etc.) | No billing hooks | Pro/Enterprise seat pricing + cloud usage model planned | Not implemented |
| Desktop monetization | Desktop is part of subscription plans | Desktop UI scaffold exists; no auth/license checks | Desktop app planned as Pro feature | Branch `feature/desktop-app-next` currently ungated |
| Feature gating mechanism | Plan-based entitlements | No entitlement service, license key, token validation, or plan checks found | Strategy implies paid-only features for Pro/Enterprise | Critical missing layer |
| OSS vs proprietary split | Open-source engine upstream + commercial desktop/cloud/services | Workspace and desktop UI crates are Apache-licensed in repo | Proprietary components described in strategy docs | Current repo does not reflect proprietary split in enforcement |
| AI monetization | Commercial differentiated features across plans | AI commands exposed in CLI; only env toggles like `FERROCRATE_AI` and degrade behavior | Advanced AI intended for Pro | No paid gating today |
| Distribution channel | Official installers + subscriptions | Install scripts pull public release artifacts (CLI + desktop) | You stated “CLI public, others paid” | Current release/install path does not enforce that policy |
