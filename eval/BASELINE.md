# Detection baseline — deterministic layer

Snapshot: 2026-10-25 (commit with eval/ introduced). Dataset: `dataset.jsonl`, 87 cases
(71 deterministic, 16 llm_required).

## How to reproduce

```bash
python eval/run_eval.py             # offline, free
python eval/run_eval.py --with-llm  # full pipeline, spends API credits
```

## Results (offline, deterministic layer only)

| Metric   | Value |
|----------|-------|
| Accuracy | **97.2%** (69/71) |
| Precision| **100%** (tp=35, fp=0) |
| Recall   | **94.6%** (tp=35, fn=2) |

An eval-driven fix shipped with this baseline: whitelisted bank domains no longer
flag as typosquats of other whitelisted banks (`nbu.uz` vs `xb..uz` short-name
collisions produced 3 false positives before the fix; precision was 92.1%).

## LLM layer status (full-pipeline run, 2026-10-26)

`python eval/run_eval.py --with-llm` was executed against the configured
Fireworks key and **could not produce LLM verdicts**: the provider returned
`401 The API key you provided is invalid` on the models endpoint and
`404 model not found` on chat completions (both the primary gemma-4-31b-it and
the deepseek-v4-flash fallback). Every full-pipeline case therefore degraded
to the graceful path.

Consequences, stated plainly:
- The numbers above measure the **deterministic layer only**. Full-pipeline
  (LLM) accuracy is currently UNMEASURED — it requires a valid provider key
  (Fireworks, Gemini or Anthropic) before `--with-llm` is meaningful.
- Runtime behaviour with a dead key is graceful, not silent: text cases with
  URLs still get heuristic findings and an elevated risk; cases with no
  deterministic signal return `unknown` with an explanatory summary.
- Action item: replace `FIREWORKS_API_KEY` in `.env` (or set `GEMINI_API_KEY` /
  `ANTHROPIC_API_KEY`), then re-run `--with-llm` and record the numbers here.

## LSB stego detector calibration

The detector was rebuilt from a naive ratio window (0.499–0.501) into a
block-wise statistical test: over SMOOTH 16×16 regions of a compressed image
(std ≤ 4.0), a natural LSB plane is correlated while a random embedded payload
is white noise. Thresholds were set by measurement, not intuition:

```
python eval/calibrate_stego.py     # JPEG-realistic clean vs embedded scenes
clean: autocorr[median]=+0.9362  flagged=0/24
stego: autocorr[median]=-0.0001  flagged=24/24
FPR=0.00%  TPR=100.00%   (document/receipt/screenshot-like scenes)
```

Documented scope limit: on sensor-noisy photographs a clean LSB plane and a
random payload are statistically indistinguishable, so the detector is silent
there (verified by `tests/test_lsb_detector.py::test_noisy_photo_is_not_flagged`).
It targets ScamShield's real artifacts — screenshots, receipts, documents.

## Known limitations (the 2 misses)

- `typ-020` — `ofbank.uz` vs `ofb.uz`: the length-difference guard (≤2) skips
  the comparison; short bank domains with suffix-padding evade the heuristic.
- `enm-003` — `agrobunk.uzConfirm` (domain glued to a word): the URL regex
  treats `uzConfirm` as the TLD, so the domain check sees a different host.

## LLM-required cases (16)

Social engineering without URLs, shortener links and raw-IP links cannot be
judged offline. They are exercised by `--with-llm` and by the prompt-injection
test suite (`tests/test_prompt_injection.py`).
