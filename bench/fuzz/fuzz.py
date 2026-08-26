#!/usr/bin/env python3
"""Differential fuzzer: run the same command sequence on Docker and Ferrocrate and
compare every step. Source B of docs/testing/TEST-PROGRAM-PLAN.md.

A step passes when both engines agree on exit status, on normalised stdout, and on
the observable state afterwards. A divergence is shrunk to the shortest sequence
that still diverges, then written as a ticket candidate.

  bench/fuzz/fuzz.py --sequences 50                  # random sequences, both engines
  bench/fuzz/fuzz.py --seed-file seeds/S10.json      # replay one recorded sequence
  bench/fuzz/fuzz.py --soak 8h --audit               # soak with the cleanup audit

No dependencies beyond python3 and the two CLIs.
"""
from __future__ import annotations
import argparse, json, os, random, re, shutil, subprocess, sys, time, uuid
from pathlib import Path

BENCH = Path(__file__).resolve().parent.parent
FERRO = os.environ.get("FERROCRATE_BIN", "/data/dev/ferrocrate/target/release/ferro-cli")
ADAPTER = str(BENCH / "ferro-adapter.sh")
IMAGE = os.environ.get("FUZZ_IMAGE", "alpine:3.20")
STEP_TIMEOUT = int(os.environ.get("FUZZ_STEP_TIMEOUT", "90"))

# Values that legitimately differ between engines: ids, timestamps, digests, paths,
# sizes and the engine's own name. Masked before stdout is compared.
NOISE = [
    (re.compile(r"\b[0-9a-f]{12,64}\b"), "<id>"),
    (re.compile(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}[^\s\"]*"), "<time>"),
    (re.compile(r"\b(\d+(\.\d+)?\s?(seconds?|minutes?|hours?|days?|ms|s)\s+ago)\b"), "<age>"),
    (re.compile(r"\b\d+(\.\d+)?\s?[KMGT]?i?B\b"), "<size>"),
    (re.compile(r"(?i)\b(docker|ferrocrate|ferro-cli)\b"), "<engine>"),
    (re.compile(r"/(run|home|tmp|var)/[^\s\"',]+"), "<path>"),
    (re.compile(r"\b(\d{1,3}\.){3}\d{1,3}\b"), "<ip>"),
    (re.compile(r"\s+"), " "),
]


def normalise(text: str) -> str:
    for pattern, repl in NOISE:
        text = pattern.sub(repl, text)
    return text.strip().lower()


class Engine:
    """One engine under test, with its own container and volume namespace."""

    def __init__(self, name: str, argv: list[str]):
        self.name, self.argv = name, argv

    def run(self, args: list[str], timeout: int = STEP_TIMEOUT) -> tuple[int, str, str]:
        try:
            p = subprocess.run(self.argv + args, capture_output=True, text=True, timeout=timeout)
            return p.returncode, p.stdout, p.stderr
        except subprocess.TimeoutExpired:
            return 124, "", f"timeout after {timeout}s"

    def state(self, tag: str) -> dict:
        """The observable state both engines must agree on after every step."""
        out = {}
        for key, args in (
            ("containers", ["ps", "-a", "--format", "{{.Names}} {{.State}}"]),
            ("images", ["images", "--format", "{{.Repository}}:{{.Tag}}"]),
            ("volumes", ["volume", "ls", "--format", "{{.Name}}"]),
        ):
            code, stdout, _ = self.run(args, timeout=30)
            lines = [l.strip() for l in stdout.splitlines() if l.strip() and tag in l]
            out[key] = sorted(lines)
        return out


DOCKER = Engine("docker", ["docker"])
FERROCRATE = Engine("ferrocrate", [ADAPTER])


# --- the grammar -----------------------------------------------------------------
# Each generator returns (label, args) for a tag-scoped resource. Sequences always
# start with a create so later steps have something to act on.

def gen_sequence(rng: random.Random, tag: str, length: int) -> list[tuple[str, list[str]]]:
    c, v = f"fz-{tag}", f"fzv-{tag}"
    seq: list[tuple[str, list[str]]] = [("run-detached", ["run", "-d", "--name", c, IMAGE, "sleep", "300"])]
    pool = [
        ("ps", ["ps", "-a"]),
        ("inspect", ["inspect", c]),
        ("logs", ["logs", c]),
        ("exec", ["exec", c, "sh", "-c", "echo fuzz-ok"]),
        ("stop", ["stop", "-t", "1", c]),
        ("start", ["start", c]),
        ("restart", ["restart", "-t", "1", c]),
        ("pause", ["pause", c]),
        ("unpause", ["unpause", c]),
        ("kill", ["kill", c]),
        ("wait", ["wait", c]),
        ("rename", ["rename", c, f"{c}-r"]),
        ("rename-back", ["rename", f"{c}-r", c]),
        ("commit", ["commit", c, f"fzimg-{tag}:latest"]),
        ("diff", ["diff", c]),
        ("top", ["top", c]),
        ("stats", ["stats", "--no-stream", c]),
        ("volume-create", ["volume", "create", v]),
        ("volume-inspect", ["volume", "inspect", v]),
        ("volume-rm", ["volume", "rm", v]),
        ("images", ["images"]),
        ("rmi", ["rmi", f"fzimg-{tag}:latest"]),
        # error cases: both engines must refuse, and the message must name the cause
        ("err-missing-container", ["exec", f"fz-nope-{tag}", "ls"]),
        ("err-missing-image", ["run", "--rm", f"fz-nope-{tag}:1"]),
        ("err-dup-name", ["run", "-d", "--name", c, IMAGE, "true"]),
    ]
    seq += [rng.choice(pool) for _ in range(length)]
    seq.append(("rm-force", ["rm", "-f", c]))
    return seq


def cleanup(tag: str) -> None:
    for engine in (DOCKER, FERROCRATE):
        for name in (f"fz-{tag}", f"fz-{tag}-r"):
            engine.run(["rm", "-f", name], timeout=30)
        engine.run(["volume", "rm", f"fzv-{tag}"], timeout=30)
        engine.run(["rmi", f"fzimg-{tag}:latest"], timeout=30)


def run_sequence(seq: list[tuple[str, list[str]]], tag: str) -> dict | None:
    """Run one sequence on both engines. Return the first divergence, or None."""
    cleanup(tag)
    for index, (label, args) in enumerate(seq):
        d_code, d_out, d_err = DOCKER.run(args)
        f_code, f_out, f_err = FERROCRATE.run(args)
        # Both refusing is agreement, whatever the wording.
        agree_status = (d_code == 0) == (f_code == 0)
        agree_stdout = normalise(d_out) == normalise(f_out) if d_code == 0 and f_code == 0 else True
        d_state, f_state = DOCKER.state(tag), FERROCRATE.state(tag)
        agree_state = d_state == f_state
        if not (agree_status and agree_stdout and agree_state):
            cleanup(tag)
            return {
                "step": index, "label": label, "args": args,
                "docker": {"exit": d_code, "stdout": d_out[-400:], "stderr": d_err[-400:], "state": d_state},
                "ferrocrate": {"exit": f_code, "stdout": f_out[-400:], "stderr": f_err[-400:], "state": f_state},
                "reason": ("status" if not agree_status else "stdout" if not agree_stdout else "state"),
            }
    cleanup(tag)
    return None


def shrink(seq: list[tuple[str, list[str]]], tag: str) -> list[tuple[str, list[str]]]:
    """Delete-one reduction: the shortest prefix-preserving sequence that still diverges."""
    current = seq
    changed = True
    while changed and len(current) > 2:
        changed = False
        for i in range(1, len(current) - 1):        # keep the first create and the final rm
            candidate = current[:i] + current[i + 1:]
            if run_sequence(candidate, tag):
                current, changed = candidate, True
                break
    return current


def audit() -> dict:
    """Cleanup counters that must return to baseline after a soak."""
    def count(cmd: str) -> int:
        p = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        return int(p.stdout.strip() or 0)
    state = Path(os.environ.get("FERROCRATE_HOME", str(Path.home() / ".ferrocrate")))
    return {
        "slirp4netns": count("pgrep -c slirp4netns || echo 0"),
        "ferro_daemons": count("pgrep -fc 'ferro-cli daemon' || echo 0"),
        "listening_ports": count("ss -ltn 2>/dev/null | tail -n +2 | wc -l"),
        "container_dirs": len(list((state / "containers").glob("*"))) if (state / "containers").is_dir() else 0,
        "mounts": count("grep -c ferrocrate /proc/self/mountinfo || echo 0"),
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--sequences", type=int, default=20)
    ap.add_argument("--length", type=int, default=8)
    ap.add_argument("--seed", type=int, default=None)
    ap.add_argument("--seed-file", type=Path, default=None)
    ap.add_argument("--soak", type=str, default=None, help="run for a duration, e.g. 8h or 30m")
    ap.add_argument("--audit", action="store_true", help="record cleanup counters every 100 sequences")
    ap.add_argument("--out", type=Path, default=BENCH / "results" / time.strftime("%Y-%m-%d") / "fuzz.jsonl")
    args = ap.parse_args()

    if not shutil.which("docker"):
        print("docker is required as the oracle", file=sys.stderr); return 2
    args.out.parent.mkdir(parents=True, exist_ok=True)
    rng = random.Random(args.seed)
    deadline = None
    if args.soak:
        unit = args.soak[-1]
        deadline = time.time() + int(args.soak[:-1]) * {"h": 3600, "m": 60, "s": 1}[unit]

    for engine in (DOCKER, FERROCRATE):
        engine.run(["pull", IMAGE], timeout=300)

    baseline = audit() if args.audit else None
    if baseline:
        print(f"baseline: {baseline}")

    findings, done = 0, 0
    with args.out.open("a") as log:
        while True:
            tag = uuid.uuid4().hex[:8]
            if args.seed_file:
                seq = [(s["label"], s["args"]) for s in json.loads(args.seed_file.read_text())["sequence"]]
            else:
                seq = gen_sequence(rng, tag, args.length)
            divergence = run_sequence(seq, tag)
            done += 1
            if divergence:
                findings += 1
                minimal = shrink(seq, tag) if not args.seed_file else seq
                record = {
                    "run": time.strftime("%Y-%m-%dT%H:%MZ", time.gmtime()),
                    "source": "fuzz", "reason": divergence["reason"], "label": divergence["label"],
                    "sequence": [{"label": l, "args": a} for l, a in minimal],
                    "divergence": divergence,
                }
                log.write(json.dumps(record) + "\n"); log.flush()
                seed = BENCH / "fuzz" / "seeds" / f"{time.strftime('%Y%m%d')}-{divergence['label']}-{tag}.json"
                seed.write_text(json.dumps(record, indent=1))
                print(f"DIVERGENCE {divergence['reason']} at step {divergence['step']} ({divergence['label']}); "
                      f"minimal sequence {len(minimal)} steps -> {seed.name}")
            if args.audit and done % 100 == 0:
                now = audit()
                drift = {k: now[k] - baseline[k] for k in now if now[k] != baseline[k]}
                log.write(json.dumps({"source": "fuzz-audit", "sequences": done, "counters": now, "drift": drift}) + "\n")
                log.flush()
                print(f"audit after {done}: {now}" + (f" DRIFT {drift}" if drift else " (clean)"))
            if deadline is None and done >= args.sequences:
                break
            if deadline is not None and time.time() >= deadline:
                break
            if args.seed_file:
                break

    print(f"fuzz: {done} sequences, {findings} divergences -> {args.out}")
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
