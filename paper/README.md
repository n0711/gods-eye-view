# The Decider's Dilemma — reproducible paper

**Author:** Charalampos Nadiotis, 2026
**Paper:** *The Decider's Dilemma: Computability Limits of Autonomous AI Security Agents*

Every number and figure in the PDF is produced by `experiment.py` (fixed seed
`20260101`) and injected into the LaTeX via `results/macros.tex`. No result is
entered by hand.

## Files
- `experiment.py` — runs all three studies, writes `results/results.json`,
  `results/macros.tex`, and the figures in `results/figs/`.
- `main.tex` — the paper (XeLaTeX). Reads `results/macros.tex`.
- `results/` — generated outputs (JSON, macros, figures).
- `main.pdf` — the compiled paper.

## Reproduce from scratch
```bash
# 1. dependencies
python3 -m pip install numpy matplotlib          # add --break-system-packages if needed
#    plus a TeX Live with XeLaTeX (texlive-xetex)

# 2. regenerate all numbers + figures
python3 experiment.py

# 3. build the PDF (run twice so cross-references resolve)
xelatex main.tex
xelatex main.tex
```

## What is measured vs. modelled (honesty contract)
- **Study 1 (measured):** direct simulation of 4,000 random Turing machines;
  the resolved/uncertifiable-residue fractions are observations of that
  population.
- **Study 2 (constructive, executed):** an interpreter actually runs each
  constructed evader and the detector's verdict is checked against the
  executed behaviour — the 100% evasion rate is verified, not asserted.
- **Study 3 (modelled):** trigger delays are drawn from an explicitly stated
  heavy-tailed distribution representing attacker-chosen timings. The numbers
  are exact properties of that model and are **not** measurements of real
  malware.

Change `SEED` in `experiment.py` to confirm the qualitative results are not an
artefact of one seed.
