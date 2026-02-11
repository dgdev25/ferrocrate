# Rootless Isolation Verification

This checklist validates rootless prerequisites and basic isolation configuration.

## Preconditions
- Linux kernel supports user namespaces (recommended 5.10+).
- `unprivileged_userns_clone` enabled if your distro gates it.
- `/etc/subuid` and `/etc/subgid` configured for the current user.

## Automated Check

```bash
scripts/verify-rootless.sh
```

## Expected Output

- `rootless verification checks passed`
- Warnings only if subordinate ID ranges are missing (fallback mapping used).

## Manual Validation

- Ensure `RootlessConfig::from_system()` resolves a mapping.
- Verify capability dropping (all caps removed) during container exec.
- Ensure containers cannot write outside permitted host paths.
