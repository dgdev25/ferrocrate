# Docker vs FerroCrate parity benchmark

Generated from paired command samples. Raw evidence: `samples.tsv`; environment: `metadata.txt`.

| Operation | Docker median (s) | FerroCrate median (s) | Delta | Winner |
|---|---:|---:|---:|---|
| run to exit (attached, /bin/true) | 0.163909 | 0.364158 | +122.2% | Docker |
| start detached | 0.113811 | 0.007697 | -93.2% | FerroCrate |
| stop (t=1) | 1.115112 | 0.031791 | -97.1% | FerroCrate |
| exec /bin/true | 0.063719 | 0.015754 | -75.3% | FerroCrate |
| logs (1000 lines) | 0.015500 | 0.007418 | -52.1% | FerroCrate |
| ps -a | 0.031658 | 0.007494 | -76.3% | FerroCrate |
| images list | 0.113854 | 0.007546 | -93.4% | FerroCrate |
| volume create | 0.015546 | 0.007546 | -51.5% | FerroCrate |
| pull alpine:3.19 (cold) | n/a | n/a | n/a | n/a |
| build, COPY-only, no cache | 0.264022 | 0.007510 | -97.2% | FerroCrate |
| build, COPY-only, cached | 0.764819 | 0.007487 | -99.0% | FerroCrate |
