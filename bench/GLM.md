# Running the bench loop with GLM

GLM is used through `claude-glm` (Claude Code pointed at Z.AI's
Anthropic-compatible endpoint). The launcher is `~/.local/bin/claude-glm`;
it reads the key from `~/.config/zai/.env` (or `ZAI_API_KEY`).

Models (Z.AI GLM Coding Plan, verified 2026-08-20):
- `glm-5.3` — Opus tier, 1M context, reasoning always on; use `--effort max` for fixes.
- `glm-4.7` — Sonnet tier default; fine for bench runs and triage.
- `glm-4.7-flashx` — Haiku tier; cheap, for scoreboard summaries only.

Headless invocation (one loop iteration, no prompts, exits when done):

```bash
claude-glm --model glm-5.3 --effort max -- \
  -p "$(cat bench/prompts/fix-ticket.txt | sed "s/<id>/S2/")" \
  --dangerously-skip-permissions --max-turns 200 --output-format text \
  > /path/to/ferrocrate-lab/logs/glm-fix-S2.log 2>&1
```

- Everything after `--` goes to Claude Code unchanged; `-p` is the headless
  prompt mode. `--max-turns` bounds one session; the chain driver relaunches.
- Sentinel lines end a session: `TICKET-<id>-CLOSED`, `TICKET-<id>-BLOCKED`,
  `BENCH-RUN-COMPLETE`. The lab chain driver
  (`/path/to/ferrocrate-lab/chain.sh <name> <clone> <prompt-file> <SENTINEL> <max-runs>`)
  works unchanged if `codex exec` is replaced by the `claude-glm ... -p` line
  above; make a copy `chain-glm.sh` rather than editing the Codex driver.
- One session per ticket or per bench run. Fresh clone per fix chain
  (`git clone /data/dev/ferrocrate /data/dev/ferrocrate-glm-<id>`), branch
  from `origin/main`, small commits, never force-push.
- Token budget is not a constraint; wall-clock and host CPU are. Keep one
  cargo build at a time (`pgrep -fc '^cargo'` must be 0 before starting one)
  and never run the bench while a fix chain compiles.
- Test the connection first: `claude-glm --test`.

Prompts live in `bench/prompts/`: `bootstrap.txt`, `add-app.txt`,
`fix-ticket.txt`, `full-run.txt`. Each states the done condition and the
sentinel line.
