# FerroCrate Actors and Personas

## Overview

This document defines the primary actors (personas) who interact with FerroCrate, their motivations, pain points, and specific needs. These personas drive product decisions and help prioritize features.

---

## Actor Taxonomy

```
                    ┌─────────────────────────────────────┐
                    │         FerroCrate Users            │
                    └─────────────────────────────────────┘
                                      │
           ┌──────────────────────────┼──────────────────────────┐
           │                          │                          │
    ┌──────▼──────┐           ┌───────▼───────┐          ┌───────▼───────┐
    │  Platform   │           │   Developer   │          │   Security    │
    │  Engineers  │           │               │          │   Engineers   │
    └──────┬──────┘           └───────┬───────┘          └───────┬───────┘
           │                          │                          │
    ┌──────┴──────┐           ┌───────┴───────┐          ┌───────┴───────┐
    │ • DevOps    │           │ • Full-Stack  │          │ • Security    │
    │   Dana      │           │   Steve       │          │   Sarah       │
    │ • ML Marcus │           │               │          │               │
    └─────────────┘           └───────────────┘          └───────────────┘
                                      │
                              ┌───────▼───────┐
                              │  Edge/IoT     │
                              │  Engineers    │
                              └───────┬───────┘
                                      │
                              ┌───────▼───────┐
                              │ • Edge Elena  │
                              └───────────────┘
```

---

## Persona 1: DevOps Dana - Platform Engineer

### Profile

| Attribute | Detail |
|-----------|--------|
| **Role** | Senior Platform Engineer |
| **Organization** | 500-person SaaS company |
| **Experience** | 8+ years in infrastructure, 5+ years with containers |
| **Team Size** | Manages platform team of 5, serves 80 developers |
| **Work Context** | On-call rotation, handles production incidents |

### Motivations

1. **Cost Optimization**: Reduce tooling and infrastructure costs
2. **Reliability**: Eliminate "works on my machine" incidents
3. **Efficiency**: Spend less time on repetitive debugging
4. **Consistency**: Same tooling from development to production

### Pain Points

| Pain Point | Current State | Impact |
|------------|---------------|--------|
| Docker Desktop licensing | $15/user/month x 80 users = $14,400/year | Budget drain, license compliance overhead |
| Dev/prod drift | Docker in dev, containerd in prod | 2-4 "works on my machine" incidents per month |
| Repetitive debugging | 20% of time on container issues | Lost productivity, burnout risk |
| Resource waste | 120MB+ idle memory per Docker daemon | Hundreds of MB wasted on CI runners |

### Needs from FerroCrate

| Need | Requirement | Priority |
|------|-------------|----------|
| Single runtime | Dev and prod use identical runtime | P0 |
| Cost savings | No per-user licensing | P0 |
| Automated remediation | AI diagnoses common issues | P1 |
| Drop-in replacement | Docker CLI compatibility | P0 |
| CI/CD integration | Works in GitHub Actions, GitLab CI | P0 |
| Monitoring | Prometheus metrics, structured logs | P1 |

### Usage Patterns

```bash
# Daily workflow
ferrocrate compose up                    # Start local dev environment
ferrocrate logs -f api                   # Debug service issue
ferrocrate exec -it db psql              # Database access
ferrocrate compose down                  # Clean up

# Production operations
ferrocrate ps --format json              # Container status for monitoring
ferrocrate stats                         # Resource usage
ferrocrate ask "why did api crash?"      # AI diagnostics
ferrocrate fleet status                  # Multi-host overview
```

### Success Metrics

- 50% reduction in Docker-related licensing costs
- 80% reduction in dev/prod mismatch incidents
- 10+ hours/week saved on container debugging
- 40% memory reduction on CI runners

---

## Persona 2: ML Marcus - AI Infrastructure Lead

### Profile

| Attribute | Detail |
|-----------|--------|
| **Role** | ML Platform Lead |
| **Organization** | AI startup with 50+ GPU containers |
| **Experience** | 6+ years in ML infrastructure, moderate container knowledge |
| **Team Size** | Leads team of 3 ML engineers |
| **Work Context** | Manages GPU cluster, optimizes inference latency |

### Motivations

1. **GPU Efficiency**: Maximize GPU/VRAM utilization
2. **Cold Start Speed**: Minimize model loading time
3. **Resource Optimization**: Right-size containers for ML workloads
4. **Automation**: Reduce manual tuning of GPU containers

### Pain Points

| Pain Point | Current State | Impact |
|------------|---------------|--------|
| VRAM waste | 30-40% allocated VRAM unused | Expensive GPU resources underutilized |
| Cold starts | 45-90 seconds for LLM inference containers | Poor user experience, wasted compute |
| Model caching | No container runtime support for model persistence | Every restart reloads multi-GB models |
| Manual tuning | Hours spent adjusting memory limits | Engineering time drain |

### Needs from FerroCrate

| Need | Requirement | Priority |
|------|-------------|----------|
| GPU/VRAM awareness | Detect and allocate GPU resources | P2 |
| Lazy pulling | Start before full image download | P1 |
| Model caching | Persist model data across restarts | P2 |
| Resource prediction | AI predicts memory needs | P1 |
| Large image handling | Efficient 15GB+ image management | P1 |

### Usage Patterns

```bash
# Model serving
ferrocrate run --gpus all --memory 32g llm-inference:latest
ferrocrate run --gpus 2 --memory 16g whisper-api:latest

# Resource optimization
ferrocrate stats --gpu                    # GPU utilization
ferrocrate predict --container llm-1      # Forecast resource needs
ferrocrate auto-tune --container llm-1    # Adjust limits automatically

# Debugging
ferrocrate ask "why is inference slow?"   # Performance analysis
ferrocrate logs --since 1h llm-1          # Recent logs
```

### Success Metrics

- 25% reduction in VRAM waste
- 5x faster LLM container cold starts (<10 seconds)
- 50% reduction in manual tuning time
- Zero OOM kills on production inference

---

## Persona 3: Edge Elena - IoT Platform Architect

### Profile

| Attribute | Detail |
|-----------|--------|
| **Role** | Lead Architect, Edge Computing |
| **Organization** | Fleet of 10,000 edge devices |
| **Experience** | 10+ years embedded systems, moderate container knowledge |
| **Team Size** | Leads team of 8 embedded/firmware engineers |
| **Work Context** | Manages diverse hardware, limited connectivity |

### Motivations

1. **Resource Constraints**: Run on minimal hardware
2. **Autonomy**: Operate without cloud connectivity
3. **Reliability**: OTA updates must not brick devices
4. **Scalability**: Manage 10,000+ heterogeneous devices

### Pain Points

| Pain Point | Current State | Impact |
|------------|---------------|--------|
| Docker bloat | 150MB+ Docker footprint | Won't fit on 512MB devices |
| ARM support | Docker ARM images inconsistent | Device-specific workarounds |
| Disconnected operation | Requires periodic cloud sync | Fails in offline scenarios |
| OTA fragility | Failed container updates require site visit | Expensive field service calls |

### Needs from FerroCrate

| Need | Requirement | Priority |
|------|-------------|----------|
| Small footprint | <20MB runtime binary | P0 |
| ARM support | Native aarch64, armv7 | P0 |
| Offline operation | Full functionality without network | P0 |
| Atomic updates | Transactional container updates | P1 |
| Resource limits | Strict memory enforcement | P0 |

### Usage Patterns

```bash
# Edge deployment
ferrocrate pull sensor-app:edge-v2       # Download update
ferrocrate run --rm --memory 256m sensor-app:edge-v2

# Update workflow
ferrocrate compose pull                  # Pre-download images
ferrocrate compose up --no-pull          # Atomic update

# Monitoring
ferrocrate stats --memory-only           # Minimal overhead
ferrocrate inspect sensor-app --format json | jq .State.Status
```

### Success Metrics

- <20MB runtime on ARM devices
- 99.9% OTA update success rate
- Full functionality on 512MB RAM devices
- 50% reduction in field service calls

---

## Persona 4: Startup Steve - Full-Stack Developer

### Profile

| Attribute | Detail |
|-----------|--------|
| **Role** | Solo developer / small team lead |
| **Organization** | 1-5 person startup |
| **Experience** | 5+ years full-stack, basic Docker knowledge |
| **Team Size** | Solo or team of 2-3 |
| **Work Context** | Building SaaS product, wears many hats |

### Motivations

1. **Simplicity**: Easy to learn and use
2. **Performance**: Fast development loop
3. **Compatibility**: Works with existing tools/images
4. **Low overhead**: Minimal resource impact on development machine

### Pain Points

| Pain Point | Current State | Impact |
|------------|---------------|--------|
| Docker Desktop bloat | 2-4GB RAM consumed on MacBook | Machine slowdown, fan noise |
| Slow compose | 30-60 second startup | Disrupts flow, context switching |
| Learning curve | Docker complexity overwhelming | Avoids advanced features |
| Licensing confusion | Docker Desktop terms unclear | Compliance uncertainty |

### Needs from FerroCrate

| Need | Requirement | Priority |
|------|-------------|----------|
| Easy CLI | Docker-compatible commands | P0 |
| Low memory | <50MB idle | P0 |
| Fast startup | <5 second compose up | P0 |
| Shell completion | Tab completion | P0 |
| Friendly output | Colors, progress bars | P0 |

### Usage Patterns

```bash
# Development workflow
ferrocrate compose up -d                  # Start services
ferrocrate logs -f app                    # Watch logs
ferrocrate exec app npm test              # Run tests
ferrocrate compose down                   # Stop

# Image building
ferrocrate build -t myapp:dev .           # Build image
ferrocrate run -p 3000:3000 myapp:dev     # Test locally

# Migration
ferrocrate migrate                        # Convert Docker setup
```

### Success Metrics

- <50MB RAM when idle
- <5 second compose up for typical app
- Zero learning curve (Docker compatibility)
- 2+ hours/week saved on container management

---

## Persona 5: Security Sarah - CISO / Security Architect

### Profile

| Attribute | Detail |
|-----------|--------|
| **Role** | Security Lead / CISO |
| **Organization** | Financial services company |
| **Experience** | 12+ years security, moderate container knowledge |
| **Team Size** | Security team of 6, serves 200+ developers |
| **Work Context** | Compliance-focused, audit preparation |

### Motivations

1. **Security by default**: Containers secure out of the box
2. **Memory safety**: No GC pauses or memory corruption
3. **Auditability**: Complete audit trail
4. **Compliance**: Meet regulatory requirements

### Pain Points

| Pain Point | Current State | Impact |
|------------|---------------|--------|
| Root daemon | Docker daemon runs as root | Container escape = root compromise |
| Go memory model | GC pauses, potential CGO corruption | Unpredictable behavior, security risk |
| Limited visibility | No runtime security intelligence | Reactive, not proactive |
| Audit gaps | Incomplete container audit logs | Compliance findings |

### Needs from FerroCrate

| Need | Requirement | Priority |
|------|-------------|----------|
| Rootless default | No root required | P0 |
| Rust memory safety | No GC, memory-safe | P0 |
| Seccomp/AppArmor | Mandatory access control | P0 |
| Audit logging | Complete audit trail | P1 |
| Anomaly detection | AI-powered security monitoring | P2 |
| Image signing | Cosign/Sigstore verification | P1 |

### Usage Patterns

```bash
# Security configuration
ferrocrate run --security-opt seccomp=custom.json app
ferrocrate run --security-opt apparmor=ferrocrate app
ferrocrate run --read-only --cap-drop=ALL app

# Audit
ferrocrate audit list --since 24h          # Recent events
ferrocrate audit export --format json      # Compliance export
ferrocrate alerts list --severity high     # Security alerts

# Verification
ferrocrate verify --signature image:latest # Check signature
ferrocrate scan image:latest               # CVE scan
```

### Success Metrics

- Zero root-required operations
- 100% container operations audited
- 80% anomaly detection accuracy
- Pass SOC2, PCI-DSS container audits

---

## Persona Comparison Matrix

| Attribute | Dana | Marcus | Elena | Steve | Sarah |
|-----------|------|--------|-------|-------|-------|
| **Technical Depth** | Expert | High | High | Medium | Medium |
| **Container Expertise** | Expert | Medium | Medium | Basic | Medium |
| **Scale** | Medium | Medium | Large | Small | Large |
| **Primary Concern** | Efficiency | Performance | Resources | Simplicity | Security |
| **AI Interest** | High | High | Low | Medium | Medium |
| **CLI Reliance** | Heavy | Heavy | Medium | Light | Medium |
| **Automation Need** | High | High | High | Low | Medium |

## Feature-Persona Mapping

| Feature | Dana | Marcus | Elena | Steve | Sarah |
|---------|------|--------|-------|-------|-------|
| Docker CLI compatibility | X | X | - | X | - |
| Rootless by default | X | X | X | X | X |
| Zero idle memory | X | - | X | X | - |
| AI diagnostics | X | X | - | X | X |
| GPU/VRAM support | - | X | - | - | - |
| Small binary | - | - | X | X | - |
| Audit logging | X | - | - | - | X |
| Compose support | X | X | X | X | - |
| Image signing | X | - | X | - | X |
| Shell completion | X | - | - | X | - |

---

## Actor Interaction Summary

| Actor | Primary Interface | Secondary Interface | Frequency |
|-------|-------------------|---------------------|-----------|
| Dana | CLI, Compose | API socket, Metrics | Hourly |
| Marcus | CLI, Compose | GPU tools | Daily |
| Elena | CLI (minimal) | OTA system | Weekly |
| Steve | CLI, Compose | - | Daily |
| Sarah | CLI (audit), API | SIEM integration | Weekly |
