# Imprint evaluation harness

Calls the repo's real `classify.py` / `advisor.py` (no Docker, MongoDB, Splunk or ModSecurity needed).

## Run on the VM
```bash
git clone <repo> && cd Imprint && git pull          # get the eval/ folder
python3 -m venv .venv && source .venv/bin/activate
pip install anthropic matplotlib                    # matplotlib optional (Fig. 4 PNG)
export ANTHROPIC_API_KEY='sk-ant-...'               # never commit this
# optional: export IMPRINT_CLASSIFIER_MODEL=claude-haiku-4-5   (default; record what you used)

cd eval
python3 generate_scenarios.py                       # (re)build scenarios.json after label review
python3 run_llm.py --mock --k 2 && python3 evaluate.py --mock   # 1. free pipeline smoke test (fake LLM)
python3 run_llm.py --ids A01 L01 --k 1              # 2. real-API smoke test, 2 calls
python3 run_llm.py --k 5                            # 3. full run: 79 x 5 = 395 calls (resumable)
python3 evaluate.py                                 # 4. offline, free, repeatable
```
Outputs in `eval/out/`: `table_vii.md` (Table VII), `per_group.md`, `guardrail_impact.md`,
`per_scenario.csv` (pick misclassifications), `fig4_data.csv` / `fig4.png`, `results.json`,
`llm_runs.jsonl` (raw cache), `classifier_audit.jsonl`.

## Before the real run
1. Team reviews every label in `generate_scenarios.py` (label = malicious, category, severity bucket).
2. **Freeze `baselines.py`** (B0 points/threshold, B1 weights) with a git commit BEFORE running.
3. Confirm `run_llm.py` prints fallbacks = 0. Any fallback means the API call failed and that run
   measured the fail-safe, not the LLM. Re-run the same command to retry.
4. Check current token prices and pass `--price-in/--price-out` to `evaluate.py`.
5. Record: model string (shown in table header), k, run date, VM region.

## Design notes (state these in the paper)
- B0 is IP-keyed CRS-style scoring (critical=5, threshold 5). Which alert names earn CRS points is an
  assumption in `baselines.py`; verify against real ModSecurity logs from the PoC.
- Group C (returning attackers) sends the new request from a fresh IP with no alert. B0 sees nothing;
  Imprint/B1 apply the stored device decision. Report C separately from overall recall.
- Ablation reuses Imprint's LLM outputs (paired comparison), so its latency/cost are shared.
- Expected action for a malicious scenario = repo's own matrix applied to the analyst label.
  Benign scenarios are correct if the action is <= CAPTCHA.
- Positive mitigation = action stronger than CAPTCHA. Severe FPR = benign sent to HONEYPOT/BLOCK.
- Some benign cases (J05, J07, K1 xss/sqli) are upstream WAF false positives; confirmed signals will
  still escalate them by design. This is a real limitation (see "Dependence on detection quality").
- N=79 (16 benign) is small: report mean ± sd over k runs and avoid over-claiming.
