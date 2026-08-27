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

Comparison model: stdout is compared only for commands whose output is data
(logs, exec, wait). Ferrocrate prints human-formatted "verb: key=value" lines for
the remaining verbs (run -d, inspect, top, stats, ps, images, ...) — that class of
output-format divergence is ticketed, not compared; behaviour is verified through
exit status and the state snapshot instead.

Set FERROCRATE_HOME before running. Several agents share this host; each must use
its own runtime store or they terminate each other's containers and builds.
"""
from __future__ import annotations
import argparse, json, os, random, re, shutil, subprocess, sys, time, uuid
from pathlib import Path

BENCH = Path(__file__).resolve().parent.parent
FERRO = os.environ.get("FERROCRATE_BIN", "/data/dev/ferrocrate/target/release/ferro-cli")
ADAPTER = str(BENCH / "ferro-adapter.sh")
IMAGE = os.environ.get("FUZZ_IMAGE", "alpine:3.20")
STEP_TIMEOUT = int(os.environ.get("FUZZ_STEP_TIMEOUT", "90"))
WAIT_TIMEOUT = int(os.environ.get("FUZZ_WAIT_TIMEOUT", "10"))

# Values that legitimately differ between engines: ids, timestamps, digests, paths,
# sizes, colour codes and the engine's own name. Masked before stdout is compared.
NOISE = [
    (re.compile(r"\x1b\[[0-9;]*m"), ""),
    (re.compile(r"\b[0-9a-f]{12,64}\b"), "<id>"),
    (re.compile(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}[^\s\"]*"), "<time>"),
    (re.compile(r"\b(\d+(\.\d+)?\s?(seconds?|minutes?|hours?|days?|ms|s)\s+ago)\b"), "<age>"),
    (re.compile(r"\b\d+(\.\d+)?\s?[KMGT]?i?B\b"), "<size>"),
    (re.compile(r"(?i)\b(docker|ferrocrate|ferro-cli)\b"), "<engine>"),
    (re.compile(r"/(run|home|tmp|var|data|dev)/[^\s\"',]+"), "<path>"),
    (re.compile(r"\b(\d{1,3}\.){3}\d{1,3}\b"), "<ip>"),
    (re.compile(r"\s+"), " "),
]


def normalise(text: str) -> str:
    for pattern, repl in NOISE:
        text = pattern.sub(repl, text)
    return text.strip().lower()


def is_crash(code: int) -> bool:
    """A timeout, a signal death (negative returncode) or a shell 128+exit."""
    return code == 124 or code < 0 or code >= 128


class Engine:
    """One engine under test, with its own container and volume namespace."""

    # State queries use --format json on both engines; Go templates are not
    # accepted by ferro-cli, and a failed query used to read as an empty state.
    STATE_ARGS = {
        "containers": ["ps", "-a", "--format", "json"],
        "images": ["images", "--format", "json"],
        "volumes": ["volume", "ls", "--format", "json"],
        "networks": ["network", "ls", "--format", "json"],
    }

    def __init__(self, name: str, argv: list[str]):
        self.name, self.argv = name, argv

    def run(self, args: list[str], timeout: int = STEP_TIMEOUT) -> tuple[int, str, str]:
        try:
            p = subprocess.run(self.argv + args, capture_output=True, text=True, timeout=timeout)
            return p.returncode, p.stdout, p.stderr
        except subprocess.TimeoutExpired:
            return 124, "", f"timeout after {timeout}s"

    def _records(self, stdout: str) -> list:
        """Docker prints one JSON object per line; ferro-cli prints one JSON document."""
        text = stdout.strip()
        if not text:
            return []
        try:
            doc = json.loads(text)
        except ValueError:
            return []
        return doc if isinstance(doc, list) else [doc]

    def _fields(self, key: str, record: dict) -> list[str]:
        raise NotImplementedError

    def state(self, tag: str) -> dict:
        """The observable state both engines must agree on after every step."""
        out = {}
        for key, args in self.STATE_ARGS.items():
            code, stdout, _ = self.run(args, timeout=30)
            names = []
            for record in self._records(stdout):
                try:
                    names += self._fields(key, record)
                except (KeyError, TypeError):
                    pass
            out[key] = sorted(n for n in names if tag in n)
        return out


class DockerEngine(Engine):
    def _records(self, stdout: str) -> list:
        return [json.loads(l) for l in stdout.splitlines() if l.strip()]

    def _fields(self, key: str, record: dict) -> list[str]:
        if key == "containers":
            return [f'{record["Names"]} {record["State"]}']
        if key == "images":
            return [f'{record["Repository"]}:{record["Tag"]}']
        return [record["Name"]]


class FerroEngine(Engine):
    # ferro-cli reports "killed" after a kill and "stopped" after a stop; docker's
    # State vocabulary is created/running/paused/restarting/removing/exited/dead,
    # and both paths leave "exited". Mapped so the vocabulary gap does not mask
    # later steps in a sequence; the gap itself is ticketed (S41).
    STATUS_MAP = {"killed": "exited", "stopped": "exited"}

    def _fields(self, key: str, record: dict) -> list[str]:
        if key == "containers":
            status = self.STATUS_MAP.get(record["status"], record["status"])
            return [f'{record["name"]} {status}']
        if key == "images":
            # RepoTags are fully qualified (registry-1.docker.io/library/alpine:3.20);
            # docker reports the short form. Keep the last path segment.
            return [r.split("/")[-1] for r in record.get("RepoTags") or []]
        if key == "volumes" and "Volumes" in record:          # {"Volumes": [...]}
            return [v["Name"] for v in record["Volumes"] or []]
        return [record["Name"]]


DOCKER = DockerEngine("docker", ["docker"])
FERROCRATE = FerroEngine("ferrocrate", [ADAPTER])


# --- the grammar -----------------------------------------------------------------
# Each generator returns (label, args) for a tag-scoped resource. Sequences always
# start with a create so later steps have something to act on.

def scratch_dir(tag: str) -> Path:
    return Path(f"/tmp/fzscratch-{tag}")


def prepare_scratch(tag: str) -> None:
    d = scratch_dir(tag)
    d.mkdir(parents=True, exist_ok=True)
    (d / "in.txt").write_text(f"fuzz-data-{tag}\n")


def gen_sequence(rng: random.Random, tag: str, length: int) -> list[tuple[str, list[str]]]:
    c, c2, v = f"fz-{tag}", f"fz2-{tag}", f"fzv-{tag}"
    net, img, img2 = f"fzn-{tag}", f"fzimg-{tag}:latest", f"fzimg2-{tag}:copy"
    d = scratch_dir(tag)
    seq: list[tuple[str, list[str]]] = [("run-detached", ["run", "-d", "--name", c, IMAGE, "sleep", "300"])]
    pool = [
        ("ps", ["ps", "-a"]),
        ("inspect", ["inspect", c]),
        ("logs", ["logs", c]),
        ("exec", ["exec", c, "sh", "-c", "echo fuzz-ok"]),
        ("stop", ["stop", "--timeout", "1", c]),          # ferro-cli rejects docker's -t short flag
        ("start", ["start", c]),
        ("restart", ["restart", "--timeout", "1", c]),
        ("pause", ["pause", c]),
        ("unpause", ["unpause", c]),
        ("kill", ["kill", c]),
        ("wait", ["wait", c]),
        ("rename", ["rename", c, f"{c}-r"]),
        ("rename-back", ["rename", f"{c}-r", c]),
        ("commit", ["commit", c, img]),
        ("diff", ["diff", c]),
        ("top", ["top", c]),
        ("stats", ["stats", "--no-stream", c]),
        ("volume-create", ["volume", "create", v]),
        ("volume-inspect", ["volume", "inspect", v]),
        ("volume-rm", ["volume", "rm", v]),
        ("images", ["images"]),
        ("rmi", ["rmi", img]),
        # image operations
        ("image-tag", ["tag", IMAGE, img2]),
        ("image-history", ["history", IMAGE]),
        ("image-save", ["save", "-o", str(d / f"{tag}.tar"), IMAGE]),
        ("image-load", ["load", "-i", str(d / f"{tag}.tar")]),
        ("image-rm-tagged", ["rmi", img2]),
        # the label filter keeps docker's shared daemon from pruning other agents'
        # dangling images; the adapter drops it on the ferrocrate side, whose store
        # is isolated anyway
        ("image-prune", ["image", "prune", "--filter", f"label=fz-{tag}", "-f"]),
        # networks
        ("network-create", ["network", "create", net]),
        ("network-ls", ["network", "ls"]),
        ("network-inspect", ["network", "inspect", net]),
        ("network-rm", ["network", "rm", net]),
        ("network-connect", ["network", "connect", net, c]),
        ("network-disconnect", ["network", "disconnect", net, c]),
        ("run-net", ["run", "-d", "--name", c2, "--network", net, IMAGE, "sleep", "300"]),
        # copy in both directions
        ("cp-in", ["cp", str(d / "in.txt"), f"{c}:/tmp/fz-{tag}.txt"]),
        ("cp-out", ["cp", f"{c}:/tmp/fz-{tag}.txt", str(d / "out.txt")]),
        # error cases: both engines must refuse, and the message must name the cause
        ("err-missing-container", ["exec", f"fz-nope-{tag}", "ls"]),
        ("err-missing-image", ["run", "--rm", f"fz-nope-{tag}:1"]),
        ("err-dup-name", ["run", "-d", "--name", c, IMAGE, "true"]),
    ]
    seq += [rng.choice(pool) for _ in range(length)]
    seq.append(("rm-force", ["rm", "-f", c]))
    return seq


def ensure_base_image() -> None:
    """Keep the base image in the ferrocrate store.

    ferro-cli's image prune removes every unused image including the base
    (S49/S50); without this check the next sequence's run re-pulls from the
    registry, and Docker Hub's unauthenticated rate limit then turns an
    environmental failure into false divergences.
    """
    code, out, _ = FERROCRATE.run(["images", "--format", "json"], timeout=30)
    refs = []
    for record in FERROCRATE._records(out):
        refs += FERROCRATE._fields("images", record)
    if IMAGE.split("/")[-1] not in refs:
        FERROCRATE.run(["pull", IMAGE], timeout=300)


def cleanup(tag: str) -> None:
    for engine in (DOCKER, FERROCRATE):
        for name in (f"fz-{tag}", f"fz-{tag}-r", f"fz2-{tag}"):
            engine.run(["rm", "-f", name], timeout=30)
        engine.run(["network", "rm", f"fzn-{tag}"], timeout=30)
        engine.run(["volume", "rm", f"fzv-{tag}"], timeout=30)
        engine.run(["rmi", f"fzimg-{tag}:latest"], timeout=30)
        engine.run(["rmi", f"fzimg2-{tag}:copy"], timeout=30)
    # docker's `rm -f` on a container whose process just died can return before
    # the name is released (the container lingers in "dead" state); the next
    # `run --name` then conflicts on docker only and reads as a divergence.
    # Poll until the name is actually gone on both engines before continuing.
    for _ in range(5):
        left = [c for e in (DOCKER, FERROCRATE) for c in e.state(tag)["containers"]]
        if not left:
            break
        time.sleep(2)
        for engine in (DOCKER, FERROCRATE):
            for name in (f"fz-{tag}", f"fz-{tag}-r", f"fz2-{tag}"):
                engine.run(["rm", "-f", name], timeout=30)
    ensure_base_image()
    shutil.rmtree(scratch_dir(tag), ignore_errors=True)


# Labels whose stdout is data produced inside the container or by the workload,
# not an engine-formatted report. Compared after masking. Everything else is
# verified through exit status and state: ferrocrate's "verb: key=value" output
# format for those verbs is a known, ticketed divergence class.
COMPARE_STDOUT = {"logs", "exec", "wait", "diff"}


def diff_changes(text: str) -> set[str]:
    """Parse `diff` output into a set of "<kind> <path>" strings.

    docker prints "A /etc/resolv.conf", ferro "A etc/resolv.conf"; the leading
    slash and the line order differ legitimately, the set of changes does not.
    """
    changes = set()
    for line in text.splitlines():
        m = re.match(r"^([ACD])\s+/?(\S+)", line.strip())
        if m:
            changes.add(f"{m.group(1)} {m.group(2)}")
    return changes

# Commands that legitimately block while the container runs; capped so a `wait`
# on a live container does not burn the full step timeout on both engines.
BLOCKING = {"wait"}


def run_sequence(seq: list[tuple[str, list[str]]], tag: str) -> dict | None:
    """Run one sequence on both engines. Return the first divergence, or None."""
    cleanup(tag)
    prepare_scratch(tag)
    for index, (label, args) in enumerate(seq):
        timeout = WAIT_TIMEOUT if label in BLOCKING else STEP_TIMEOUT
        d_code, d_out, d_err = DOCKER.run(args, timeout=timeout)
        f_code, f_out, f_err = FERROCRATE.run(args, timeout=timeout)
        # Both refusing is agreement, whatever the wording. A crash is not a
        # refusal: one engine timing out or dying by signal while the other
        # returns is a divergence; both crashing the same way is agreement.
        d_crash, f_crash = is_crash(d_code), is_crash(f_code)
        if d_crash or f_crash:
            agree_status = d_crash and f_crash and d_code == f_code
        else:
            agree_status = (d_code == 0) == (f_code == 0)
        if label == "diff" and d_code == 0 and f_code == 0:
            agree_stdout = diff_changes(d_out) == diff_changes(f_out)
        elif label in COMPARE_STDOUT and d_code == 0 and f_code == 0:
            agree_stdout = normalise(d_out) == normalise(f_out)
        else:
            agree_stdout = True
        d_state, f_state = DOCKER.state(tag), FERROCRATE.state(tag)
        agree_state = d_state == f_state
        if not (agree_status and agree_stdout and agree_state):
            cleanup(tag)
            shutil.rmtree(scratch_dir(tag), ignore_errors=True)
            return {
                "step": index, "label": label, "args": args,
                "docker": {"exit": d_code, "stdout": d_out[-400:], "stderr": d_err[-400:], "state": d_state},
                "ferrocrate": {"exit": f_code, "stdout": f_out[-400:], "stderr": f_err[-400:], "state": f_state},
                "reason": ("crash" if not agree_status and (d_crash or f_crash)
                           else "status" if not agree_status
                           else "stdout" if not agree_stdout else "state"),
            }
    cleanup(tag)
    return None


def shrink(seq: list[tuple[str, list[str]]], tag: str) -> tuple[list[tuple[str, list[str]]], dict]:
    """Delete-one reduction: the shortest prefix-preserving sequence that still diverges.

    The reduction can land on a different divergence than the one that stopped the
    full sequence; the returned divergence is the one the minimal sequence produces.
    """
    current, divergence = seq, run_sequence(seq, tag)
    changed = True
    while changed and len(current) > 2:
        changed = False
        for i in range(1, len(current) - 1):        # keep the first create and the final rm
            candidate = current[:i] + current[i + 1:]
            result = run_sequence(candidate, tag)
            if result:
                current, divergence, changed = candidate, result, True
                break
    return current, divergence


def audit() -> dict:
    """Cleanup counters that must return to baseline after a soak.

    Counters are attributed to this run's FERROCRATE_HOME via /proc/<pid>/environ:
    other agents work on the same host, and system-wide pgrep/ss/mountinfo would
    report their daemons and slirp4netns processes as this run's drift.
    """
    home = os.environ.get("FERROCRATE_HOME", str(Path.home() / ".ferrocrate"))

    def mine(pid: str) -> bool:
        try:
            env = Path(f"/proc/{pid}/environ").read_bytes().split(b"\0")
            return f"FERROCRATE_HOME={home}".encode() in env
        except OSError:
            return False

    def count_procs(pattern: str) -> int:
        p = subprocess.run(["pgrep", "-f", pattern], capture_output=True, text=True)
        return sum(1 for pid in p.stdout.split() if mine(pid))

    def count_ports() -> int:
        p = subprocess.run(["ss", "-ltnp"], capture_output=True, text=True)
        total = 0
        for line in p.stdout.splitlines()[1:]:
            pids = re.findall(r"pid=(\d+)", line)
            if pids and sum(1 for pid in pids if mine(pid)) != len(pids):
                continue
            total += 1 if pids else 0
        return total

    state = Path(home)
    return {
        "slirp4netns": count_procs("slirp4netns"),
        "ferro_daemons": count_procs(r"ferro-cli daemon"),
        "listening_ports": count_ports(),
        "container_dirs": len(list((state / "containers").glob("*"))) if (state / "containers").is_dir() else 0,
        "mounts": subprocess.run(
            f"grep -c '{home}/' /proc/self/mountinfo || echo 0", shell=True,
            capture_output=True, text=True).stdout.strip(),
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
                # A divergence that does not survive a re-run is flaky, not a
                # finding: shrink() returns None for it and would otherwise
                # crash the run on the record build below. Re-confirm once,
                # then log it as flaky and keep going.
                if not args.seed_file and run_sequence(seq, tag) is None:
                    log.write(json.dumps({"run": time.strftime("%Y-%m-%dT%H:%MZ", time.gmtime()),
                                          "source": "fuzz", "reason": "flaky", "label": divergence["label"],
                                          "sequence": [{"label": l, "args": a} for l, a in seq]}) + "\n")
                    log.flush()
                    print(f"FLAKY divergence at step {divergence['step']} ({divergence['label']}); "
                          f"did not reproduce on re-run", flush=True)
                    divergence = None
            if divergence:
                findings += 1
                if args.seed_file:
                    minimal, divergence = seq, divergence
                else:
                    minimal, divergence = shrink(seq, tag)
                record = {
                    "run": time.strftime("%Y-%m-%dT%H:%MZ", time.gmtime()),
                    "source": "fuzz", "reason": divergence["reason"], "label": divergence["label"],
                    "sequence": [{"label": l, "args": a} for l, a in minimal],
                    "divergence": divergence,
                }
                log.write(json.dumps(record) + "\n"); log.flush()
                seed = BENCH / "fuzz" / "seeds" / f"{time.strftime('%Y%m%d')}-{divergence['label']}-{tag}.json"
                seed.parent.mkdir(parents=True, exist_ok=True)
                seed.write_text(json.dumps(record, indent=1))
                print(f"DIVERGENCE {divergence['reason']} at step {divergence['step']} ({divergence['label']}); "
                      f"minimal sequence {len(minimal)} steps -> {seed.name}", flush=True)
            if done % 10 == 0:
                print(f"progress: {done} sequences, {findings} divergences", flush=True)
            if args.audit and done % 100 == 0:
                now = audit()
                drift = {k: now[k] - baseline[k] for k in now if now[k] != baseline[k]}
                log.write(json.dumps({"source": "fuzz-audit", "sequences": done, "counters": now, "drift": drift}) + "\n")
                log.flush()
                print(f"audit after {done}: {now}" + (f" DRIFT {drift}" if drift else " (clean)"), flush=True)
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
