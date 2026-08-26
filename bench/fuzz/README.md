# Differential fuzzer

Source B of `docs/testing/TEST-PROGRAM-PLAN.md`. Generates command sequences,
runs each on Docker and on Ferrocrate from a clean state, and compares after
every step: exit status, normalised stdout, and the observable state
(`ps -a`, `images`, `volume ls`). The first divergence is shrunk by
delete-one reduction to the shortest sequence that still diverges and saved as a
seed, so a fixed bug stays covered.

```bash
bench/fuzz/fuzz.py --sequences 50            # a batch
bench/fuzz/fuzz.py --seed-file seeds/x.json  # replay one recorded sequence
bench/fuzz/fuzz.py --soak 8h --audit         # soak with the cleanup audit
```

`--audit` records cleanup counters every 100 sequences — helper processes,
listening ports, container directories, mounts — and reports any that do not
return to baseline. That is what proves a leak class (S10) is really gone,
which a single test cannot show.

Docker is the oracle; both engines must have the fuzz image pulled. Ids,
timestamps, sizes, paths and the engine's own name are masked before stdout is
compared, so only real differences surface.
