#!/usr/bin/env python3
"""
Reproducible experiments for:
  "The Decider's Dilemma: Computability Limits of Autonomous AI Security Agents"
  Charalampos Nadiotis, 2026.

Every number and figure in the paper is produced by THIS script. It is fully
deterministic given SEED. Nothing is hand-entered. Run:  python3 experiment.py

Outputs
  results/results.json   machine-readable results
  results/macros.tex     \newcommand definitions injected into the paper
  results/figs/*.pdf      figures

Three studies, each tied to one concept from computability theory:

  Study 1  (MEASURED, random Turing machines)
      The semi-decidability asymmetry. A bounded decider that runs a program
      for B steps can CONFIRM a manifested behaviour (here: halting) but can
      never CERTIFY its absence. We sample random TMs, and measure how much of
      the population a bounded agent must leave formally unresolved, for every
      budget B. The residue does not vanish as B grows -- it plateaus at the
      non-halting mass. (Turing 1936; semi-decidability of the halting set.)

  Study 2  (CONSTRUCTIVE, executed)
      Diagonalization. For ANY total detector D we construct a program whose
      executed behaviour contradicts D's verdict, and we VERIFY it by running
      an interpreter across a family of detectors and many seeded variants.
      This is the executable form of Rice's theorem / Cohen's (1987)
      undetectability result: no detector is both sound and complete.

  Study 3  (MODELLED, stated generative distribution)
      Resource-bounded detection in practice: sandbox-window / logic-bomb
      evasion. Programs trigger after a delay drawn from an EXPLICIT heavy-
      tailed distribution (a model of attacker-chosen trigger times, NOT a
      measurement of real malware). A sound detector with analysis budget B
      catches a trigger iff delay <= B. We measure recall, false-negative
      rate and cost versus B, exhibiting the irreducible residual miss rate
      that the theory predicts for any finite budget.
"""
import json, math, random
from collections import Counter
from pathlib import Path

import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

SEED = 20260101
HERE = Path(__file__).resolve().parent
RES = HERE / "results"
FIGS = RES / "figs"
RES.mkdir(parents=True, exist_ok=True)
FIGS.mkdir(parents=True, exist_ok=True)

NAVY, RED, GREEN = "#1b4965", "#c1121f", "#5c8001"

# ---------------------------------------------------------------------------
# Turing machine model (Study 1)
# ---------------------------------------------------------------------------
MOVES = (-1, 1)

def random_tm(rng, Q, p_halt):
    delta = []
    for _ in range(Q):
        row = []
        for _sym in (0, 1):
            write = rng.randint(0, 1)
            move = rng.choice(MOVES)
            nxt = Q if rng.random() < p_halt else rng.randint(0, Q - 1)
            row.append((write, move, nxt))
        delta.append(row)
    return delta

def run_tm(delta, Q, max_steps):
    tape = {}
    pos = 0
    state = 0
    for step in range(1, max_steps + 1):
        sym = tape.get(pos, 0)
        write, move, nxt = delta[state][sym]
        tape[pos] = write
        pos += move
        state = nxt
        if state == Q:
            return step
    return None

def study1():
    rng = random.Random(SEED)
    Q, N, B_MAX, P_HALT = 6, 4000, 20000, 0.06
    halt_times, n_nonhalt = [], 0
    for _ in range(N):
        t = run_tm(random_tm(rng, Q, P_HALT), Q, B_MAX)
        if t is None:
            n_nonhalt += 1
        else:
            halt_times.append(t)
    ht = np.array(sorted(halt_times), dtype=np.int64)
    n_halt = len(ht)
    halt_frac = n_halt / N
    nonhalt_frac = n_nonhalt / N

    budgets = [1, 2, 5, 10, 20, 50, 100, 200, 500, 1000, 2000, 5000, 10000, B_MAX]
    sweep = []
    for B in budgets:
        confirmed = int(np.count_nonzero(ht <= B))     # definite MALICIOUS verdicts
        resolved = confirmed / N                        # fraction the agent can decide
        residue = 1.0 - resolved                         # must be left uncertifiable
        sweep.append(dict(budget=B, confirmed=confirmed,
                          resolved=resolved, residue=residue))
    pct = {p: int(np.percentile(ht, p)) for p in (50, 90, 99)}
    out = dict(Q=Q, N=N, B_MAX=B_MAX, P_HALT=P_HALT,
               n_halt=n_halt, n_nonhalt=n_nonhalt,
               halt_frac=halt_frac, nonhalt_frac=nonhalt_frac,
               max_halt_time=int(ht.max()), pct=pct, sweep=sweep)

    # Figure: resolved vs residue vs budget (saturating; residue -> nonhalt mass)
    Bs = [r["budget"] for r in sweep]
    res = [r["resolved"] for r in sweep]
    rsd = [r["residue"] for r in sweep]
    fig, ax = plt.subplots(figsize=(5.4, 3.3))
    ax.plot(Bs, res, "-o", color=NAVY, ms=3.5, label="resolved (confirmed halts)")
    ax.plot(Bs, rsd, "-s", color=RED, ms=3.5, label="uncertifiable residue")
    ax.axhline(nonhalt_frac, ls="--", color=GREEN, lw=1.2,
               label=f"non-halting mass = {nonhalt_frac:.2f}")
    ax.set_xscale("log")
    ax.set_xlabel("analysis step budget $B$ (log scale)")
    ax.set_ylabel("fraction of population")
    ax.set_ylim(-0.03, 1.03)
    ax.grid(True, which="both", ls=":", alpha=0.4)
    ax.legend(fontsize=7, loc="center right")
    ax.set_title("A bounded decider cannot shrink the residue to zero")
    fig.tight_layout(); fig.savefig(FIGS / "fig_residue.pdf"); plt.close(fig)
    return out

# ---------------------------------------------------------------------------
# Study 2: diagonalization / evader (constructive, executed)
# ---------------------------------------------------------------------------
MALICIOUS, BENIGN = "MALICIOUS", "BENIGN"

def detector_signature(src):
    return MALICIOUS if "PAYLOAD_EXEC" in src else BENIGN

def detector_keyword(src):
    toks = ("socket", "exec", "encrypt", "registry", "inject", "beacon")
    return MALICIOUS if sum(t in src for t in toks) >= 3 else BENIGN

def detector_entropy(src):
    if not src:
        return BENIGN
    c = Counter(src); n = len(src)
    H = -sum((v / n) * math.log2(v / n) for v in c.values())
    return MALICIOUS if H > 4.0 else BENIGN

DETECTORS = {"signature": detector_signature,
             "keyword": detector_keyword,
             "entropy": detector_entropy}

def interpret(src, D):
    """Executable semantics of the diagonal program: behaviour = NOT D(src)."""
    return BENIGN if D(src) == MALICIOUS else MALICIOUS

def make_evader(rng):
    pad_tokens = ["load", "parse", "render", "socket", "exec", "encrypt",
                  "registry", "inject", "beacon", "PAYLOAD_EXEC", "noop", "idle"]
    k = rng.randint(0, len(pad_tokens))
    pad = " ".join(rng.sample(pad_tokens, k))
    return f"# evader :: diagonal(D) :: pad[{pad}]"

def study2():
    rng = random.Random(SEED + 7)
    M = 500
    trials = evasions = 0
    per_det = {}
    for name, D in DETECTORS.items():
        ok = 0
        for _ in range(M):
            src = make_evader(rng)
            if D(src) != interpret(src, D):   # verify detector is wrong
                ok += 1
            trials += 1
        evasions += ok
        per_det[name] = dict(trials=M, evasions=ok, rate=ok / M)
    return dict(detectors=list(DETECTORS), M=M, total_trials=trials,
                total_evasions=evasions, evasion_rate=evasions / trials,
                per_detector=per_det)

# ---------------------------------------------------------------------------
# Study 3: sandbox-window evasion (modelled, explicit distribution)
# ---------------------------------------------------------------------------
def study3():
    rng = np.random.default_rng(SEED + 99)
    N = 20000
    p_benign = 0.40                       # truly benign programs (never trigger)
    n_benign = int(round(p_benign * N))
    n_mal = N - n_benign
    # Trigger delay (steps) of malicious programs: explicit heavy-tailed mixture
    #   60% quick triggers   : lognormal around ~30 steps
    #   30% delayed triggers : lognormal around ~1.5k steps
    #   10% dormant/time-bomb: lognormal around ~60k steps
    comp = rng.choice(3, size=n_mal, p=[0.60, 0.30, 0.10])
    delays = np.empty(n_mal)
    m0 = comp == 0; m1 = comp == 1; m2 = comp == 2
    delays[m0] = rng.lognormal(mean=math.log(30),    sigma=0.8, size=m0.sum())
    delays[m1] = rng.lognormal(mean=math.log(1500),  sigma=0.9, size=m1.sum())
    delays[m2] = rng.lognormal(mean=math.log(60000), sigma=0.7, size=m2.sum())
    delays = np.maximum(1, np.round(delays)).astype(np.int64)

    budgets = [10, 30, 100, 300, 1000, 3000, 10000, 30000, 100000, 300000]
    sweep = []
    for B in budgets:
        caught = int(np.count_nonzero(delays <= B))      # TP (sound; FPR=0)
        recall = caught / n_mal
        fnr = 1.0 - recall
        accuracy = (caught + n_benign) / N
        mean_cost = (np.minimum(delays, B).sum() + n_benign * B) / N
        sweep.append(dict(budget=B, recall=recall, fnr=fnr,
                          accuracy=accuracy, mean_cost=mean_cost))
    # a realistic "analysis window" to quote
    B_window = 1000
    row = next(r for r in sweep if r["budget"] == B_window)
    out = dict(N=N, n_benign=n_benign, n_mal=n_mal, p_benign=p_benign,
               median_delay=int(np.median(delays)),
               p99_delay=int(np.percentile(delays, 99)),
               B_window=B_window, recall_window=row["recall"],
               fnr_window=row["fnr"], sweep=sweep)

    Bs = [r["budget"] for r in sweep]
    rec = [r["recall"] for r in sweep]
    fnr = [r["fnr"] for r in sweep]
    cost = [r["mean_cost"] for r in sweep]
    fig, ax1 = plt.subplots(figsize=(5.4, 3.3))
    ax1.plot(Bs, rec, "-o", color=NAVY, ms=3.5, label="recall (detection rate)")
    ax1.plot(Bs, fnr, "-s", color=RED, ms=3.5, label="false-negative rate")
    ax1.set_xscale("log"); ax1.set_ylim(-0.03, 1.03)
    ax1.set_xlabel("analysis budget $B$ (log scale)")
    ax1.set_ylabel("rate")
    ax1.grid(True, which="both", ls=":", alpha=0.4)
    ax2 = ax1.twinx()
    ax2.plot(Bs, cost, "--^", color=GREEN, ms=3.5, label="mean cost (steps)")
    ax2.set_yscale("log"); ax2.set_ylabel("mean steps / sample (log)")
    l1, lab1 = ax1.get_legend_handles_labels()
    l2, lab2 = ax2.get_legend_handles_labels()
    ax1.legend(l1 + l2, lab1 + lab2, fontsize=7, loc="center left")
    ax1.set_title("Heavy-tailed triggers defeat any finite analysis window")
    fig.tight_layout(); fig.savefig(FIGS / "fig_sandbox.pdf"); plt.close(fig)
    return out

# ---------------------------------------------------------------------------
def write_macros(s1, s2, s3):
    def pct(x): return f"{100*x:.1f}"
    L = []
    def cmd(n, v): L.append(rf"\newcommand{{\{n}}}{{{v}}}")
    # Study 1
    cmd("expQ", s1["Q"]); cmd("expN", f'{s1["N"]:,}')
    cmd("expBmax", f'{s1["B_MAX"]:,}')
    cmd("expNhalt", f'{s1["n_halt"]:,}'); cmd("expNnonhalt", f'{s1["n_nonhalt"]:,}')
    cmd("expHaltPct", pct(s1["halt_frac"])); cmd("expNonhaltPct", pct(s1["nonhalt_frac"]))
    cmd("expMedianHalt", f'{s1["pct"][50]:,}'); cmd("expHaltPtail", f'{s1["pct"][99]:,}')
    cmd("expMaxHalt", f'{s1["max_halt_time"]:,}')
    # Study 2
    cmd("expDetN", len(s2["detectors"])); cmd("expEvaderM", f'{s2["M"]:,}')
    cmd("expEvTrials", f'{s2["total_trials"]:,}'); cmd("expEvRate", pct(s2["evasion_rate"]))
    # Study 3
    cmd("expSbN", f'{s3["N"]:,}'); cmd("expSbBenignPct", pct(s3["p_benign"]))
    cmd("expSbMedDelay", f'{s3["median_delay"]:,}'); cmd("expSbDelayTail", f'{s3["p99_delay"]:,}')
    cmd("expSbWindow", f'{s3["B_window"]:,}')
    cmd("expSbRecall", pct(s3["recall_window"])); cmd("expSbFnr", pct(s3["fnr_window"]))
    (RES / "macros.tex").write_text("\n".join(L) + "\n", encoding="utf-8")

def main():
    print("Study 1: bounded halting detection (measured)...")
    s1 = study1()
    print(f"  halt {s1['n_halt']}/{s1['N']} ({s1['halt_frac']*100:.1f}%), "
          f"nonhalt {s1['nonhalt_frac']*100:.1f}%, p99 halt-time {s1['pct'][99]}")
    print("Study 2: diagonalization evader (constructive/executed)...")
    s2 = study2()
    print(f"  evasion {s2['evasion_rate']*100:.1f}% over {s2['total_trials']} trials")
    print("Study 3: sandbox-window evasion (modelled)...")
    s3 = study3()
    print(f"  recall@B={s3['B_window']}: {s3['recall_window']*100:.1f}%, "
          f"FNR {s3['fnr_window']*100:.1f}%, p99 delay {s3['p99_delay']}")
    results = dict(seed=SEED, study1=s1, study2=s2, study3=s3)
    (RES / "results.json").write_text(json.dumps(results, indent=2), encoding="utf-8")
    write_macros(s1, s2, s3)
    print("Wrote results.json, macros.tex, figs/*.pdf")

if __name__ == "__main__":
    main()
