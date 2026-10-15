#!/usr/bin/env python3
"""Step 2 (offline, free): score B0, B1, Imprint and Ablation from the cached LLM runs.

  python3 evaluate.py                # reads out/llm_runs.jsonl
  python3 evaluate.py --mock         # reads out_mock/ (pipeline test only)

Imprint is scored by calling the repo's real advisor.update_actions with the cached
classification, so guardrails, matrix and tier-1 ceiling are the production code.
Ablation = the SAME LLM classification mapped through the matrix with no guardrails and
no tier-1 ceiling (paired comparison; it shares Imprint's API calls and cost).
"""
import argparse
import csv
import json
import os
import statistics as st
import sys
import threading
from collections import Counter, defaultdict
from pathlib import Path

if "--mock" in sys.argv:
    os.environ.setdefault("EVAL_OUT", str(Path(__file__).resolve().parent / "out_mock"))
import common  # noqa: E402

common.setup_env()
import advisor  # noqa: E402
import baselines  # noqa: E402
import classify  # noqa: E402

SYSTEMS = ["B0", "B1", "Imprint", "Ablation"]
tls = threading.local()


def load_cache():
    path = common.OUT / "llm_runs.jsonl"
    if not path.exists():
        sys.exit(f"{path} not found - run run_llm.py first")
    latest = {}
    for line in path.read_text().splitlines():
        r = json.loads(line)
        latest[(r["id"], r["run"])] = r  # later lines override (retries)
    return latest


def key(actions):
    return tuple(sorted(actions))


def score_run(scen, cache_run, matrix, signals):
    """-> {system: [per-scenario result]} for one LLM run."""
    out = {s: [] for s in SYSTEMS}
    advisor.audit_log = lambda e: setattr(tls, "entry", e)
    for s in scen:
        doc, fp = common.build_doc(s), common.build_fp(s)
        n, tier = s["distinct_full_hashes"], common.decision_tier(s)
        fr = advisor.build_feature_record(doc, fp, n, s["match_tier"])
        confirmed = advisor.match_confirmed_signal(s["trigger_alert"], signals)
        corr = bool(confirmed) and advisor.TIER1_CORROBORATION_MIN_DISTINCT <= n <= advisor.TIER1_CORROBORATION_MAX_DISTINCT

        # B0
        acts, score = baselines.b0_actions(s)
        out["B0"].append({"actions": acts[tier], "category": None, "severity": None, "has_cls": False})

        # B1: static score -> same guardrails -> same matrix
        c1 = baselines.b1_classify(fr)
        adj1, _ = advisor.apply_guardrails(c1, confirmed)
        a1 = advisor.apply_matrix(adj1, tier, matrix, corr)
        out["B1"].append({"actions": a1, "category": adj1["category"], "severity": adj1["severity"], "has_cls": True})

        # Imprint: real update_actions with the cached LLM answer
        cached = cache_run[s["id"]]

        def fake_classify(_fr, cached=cached):
            if cached["error"] or cached["classification"] is None:
                raise classify.ClassifierUnavailable(cached["error"] or "no classification")
            return cached["classification"]
        advisor.classify = fake_classify
        actions = advisor.update_actions(common.FakeCol(doc, n), doc["full_hash"], doc["tier1_hash"], fp,
                                         s["trigger_alert"], common.insert_status(s))
        e = tls.entry
        adj = e["adjusted"]
        out["Imprint"].append({"actions": actions[tier], "category": adj["category"] if adj else None,
                               "severity": adj["severity"] if adj else None, "has_cls": True,
                               "fired": e["guardrails_fired"], "fallback": e["classification"] is None})

        # Ablation: raw LLM output, no guardrails, no tier-1 ceiling
        raw = e["classification"]
        if raw is None:
            ab = {"actions": list(advisor.FAILSAFE_ACTIONS), "category": None, "severity": None, "has_cls": True}
        else:
            ab = {"actions": advisor.apply_matrix(raw, "full", matrix), "category": raw["category"],
                  "severity": raw["severity"], "has_cls": True}
        out["Ablation"].append(ab)
    return out


def metrics(scen, res, expected):
    tp = fp = fn = tn = sev_fp = ben = 0
    cat_ok = cat_n = ex = w1 = agree = 0
    for s, r, exp in zip(scen, res, expected):
        mal, lv = s["label"]["malicious"], common.level(r["actions"])
        pos = lv >= 2
        tp += mal and pos
        fp += (not mal) and pos
        fn += mal and not pos
        tn += (not mal) and not pos
        if not mal:
            ben += 1
            sev_fp += lv >= 4
        agree += (key(r["actions"]) == key(exp)) if mal else (lv <= 1)
        if r["has_cls"]:
            cat_n += 1
            cat_ok += r["category"] == s["label"]["category"]
            if r["severity"] is not None:
                d = abs(common.BUCKETS.index(advisor.severity_bucket(r["severity"])) - common.BUCKETS.index(s["label"]["severity_bucket"]))
                ex += d == 0
                w1 += d <= 1
    N = len(scen)
    div = lambda a, b: a / b if b else None
    return {"precision": div(tp, tp + fp), "recall": div(tp, tp + fn), "fpr": div(fp, fp + tn),
            "severe_fpr": div(sev_fp, ben), "category_acc": div(cat_ok, cat_n) if cat_n else None,
            "bucket_exact": div(ex, cat_n) if cat_n else None, "bucket_within1": div(w1, cat_n) if cat_n else None,
            "action_agreement": div(agree, N)}


def percentile(xs, q):
    xs = sorted(xs)
    return xs[min(len(xs) - 1, round(q * (len(xs) - 1)))] if xs else None


def agg(vals):
    v = [x for x in vals if x is not None]
    if not v:
        return None, None
    return st.mean(v), (st.pstdev(v) if len(v) > 1 else 0.0)


def fmt(m, sd=None, digits=2):
    if m is None:
        return "–"
    return f"{m:.{digits}f}" + (f" ±{sd:.2f}" if sd else "")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--k", type=int, default=0, help="use first k runs (default: all complete runs)")
    ap.add_argument("--price-in", type=float, default=1.0, help="USD per million input tokens (CHECK current pricing)")
    ap.add_argument("--price-out", type=float, default=5.0, help="USD per million output tokens (CHECK current pricing)")
    ap.add_argument("--mock", action="store_true")
    a = ap.parse_args()

    scen = common.load_scenarios()
    matrix, signals = advisor.load_decision_matrix(), advisor.load_confirmed_signals()
    cache = load_cache()
    runs = sorted({r for (_, r) in cache})
    runs = [r for r in runs if all((s["id"], r) in cache for s in scen)]
    if a.k:
        runs = runs[:a.k]
    if not runs:
        sys.exit("no run has results for every scenario - finish run_llm.py first")
    expected = [common.expected_actions(s, advisor, matrix, signals) for s in scen]

    per_run = [score_run(scen, {s["id"]: cache[(s["id"], r)] for s in scen}, matrix, signals) for r in runs]
    calls = [cache[(s["id"], r)] for r in runs for s in scen]
    models = sorted({c["model"] for c in calls if c.get("model")})
    fallbacks = sum(bool(c["error"]) for c in calls)

    # ---- Table VII ----
    table = {}
    for sysn in SYSTEMS:
        ms = [metrics(scen, pr[sysn], expected) for pr in per_run]
        row = {k: agg([m[k] for m in ms]) for k in ms[0]}
        cons = []
        for i in range(len(scen)):
            c = Counter(key(pr[sysn][i]["actions"]) for pr in per_run)
            cons.append(c.most_common(1)[0][1] / len(per_run))
        row["consistency"] = (st.mean(cons), None)
        table[sysn] = row
    lat = [c["latency_ms"] for c in calls if not c["error"]]
    toks = [(c["usage"] or {}).get("input_tokens", 0) * a.price_in / 1e6 + (c["usage"] or {}).get("output_tokens", 0) * a.price_out / 1e6
            for c in calls if not c["error"]]
    llm_row = {"latency": f"{percentile(lat, .5):.0f} / {percentile(lat, .95):.0f}" if lat else "–",
               "cost": f"${st.mean(toks):.5f}" if toks else "–", "fallback": fallbacks / len(calls)}

    rows = [("Precision", "precision"), ("Recall", "recall"), ("False-positive rate", "fpr"),
            ("Severe FPR (benign → HONEYPOT/BLOCK)", "severe_fpr"), ("Category accuracy", "category_acc"),
            ("Bucket agreement (exact)", "bucket_exact"), ("Bucket agreement (±1)", "bucket_within1"),
            ("Action agreement", "action_agreement"), ("Consistency (k runs)", "consistency")]
    md = [f"Scenarios: {len(scen)} ({sum(s['label']['malicious'] for s in scen)} malicious) | runs used: k={len(runs)} | "
          f"model(s): {', '.join(models) or 'n/a'} | LLM calls: {len(calls)}\n",
          "| Metric | B0 | B1 | Imprint | Ablation |", "|---|---|---|---|---|"]
    for label, k in rows:
        md.append(f"| {label} | " + " | ".join(fmt(*table[s][k]) for s in SYSTEMS) + " |")
    md.append("| Latency p50 / p95 (ms) | <1 | <1 | " + llm_row["latency"] + " | " + llm_row["latency"] + " (shared) |")
    md.append("| Fallback rate | 0 | 0 | " + f"{llm_row['fallback']:.3f}" + " | " + f"{llm_row['fallback']:.3f}" + " |")
    md.append("| Cost / classification | $0 | $0 | " + llm_row["cost"] + " | " + llm_row["cost"] + " (shared) |")
    md.append("\n± = std-dev across the k LLM runs. Positive mitigation = action stronger than CAPTCHA.")
    (common.OUT / "table_vii.md").write_text("\n".join(md), encoding="utf-8")

    # ---- per-group breakdown (this is where the story is) ----
    groups = sorted({s["group"] for s in scen})
    gl = ["| Group | n | " + " | ".join(SYSTEMS) + " |", "|---|---|" + "---|" * len(SYSTEMS)]
    for g in groups:
        idx = [i for i, s in enumerate(scen) if s["group"] == g]
        mal = scen[idx[0]]["label"]["malicious"]
        cells = []
        for sysn in SYSTEMS:
            vals = []
            for pr in per_run:
                lv = [common.level(pr[sysn][i]["actions"]) for i in idx]
                vals.append(sum(x >= 2 for x in lv) / len(idx))
            cells.append(fmt(st.mean(vals), st.pstdev(vals) if len(vals) > 1 else 0))
        gl.append(f"| {g} ({'recall' if mal else 'FP rate'}) | {len(idx)} | " + " | ".join(cells) + " |")
    (common.OUT / "per_group.md").write_text(
        "Fraction of the group mitigated (action stronger than CAPTCHA). Malicious groups: higher is better; "
        "benign groups (J, K1): lower is better.\nA=single injection B=persistent injection C=returning attacker "
        "D=cred stuffing E=scraping F=recon G=exploitation H=multi-label I=unrecognised alert names J=benign "
        "K1=tier-1 bystanders K2=corroborated attackers L=prompt injection\n\n" + "\n".join(gl), encoding="utf-8")

    # ---- guardrail impact: Imprint vs Ablation ----
    changed, fired_ct = defaultdict(list), Counter()
    for pr in per_run:
        for i, s in enumerate(scen):
            changed[s["id"]].append(key(pr["Imprint"][i]["actions"]) != key(pr["Ablation"][i]["actions"]))
            for f in pr["Imprint"][i].get("fired", []):
                fired_ct[f.split(":")[0]] += 1
    n_changed = sum(st.mean(v) for v in changed.values())
    gr = [f"Scenarios where guardrails changed the action vs ablation (mean over runs): {n_changed:.1f} / {len(scen)}",
          "Guardrail firings (all runs): " + json.dumps(dict(fired_ct)), "", "| Scenario | group | changed in runs | Imprint modal | Ablation modal |", "|---|---|---|---|---|"]
    for i, s in enumerate(scen):
        v = changed[s["id"]]
        if any(v):
            im = Counter(key(pr["Imprint"][i]["actions"]) for pr in per_run).most_common(1)[0][0]
            ab = Counter(key(pr["Ablation"][i]["actions"]) for pr in per_run).most_common(1)[0][0]
            gr.append(f"| {s['id']} | {s['group']} | {sum(v)}/{len(v)} | {'+'.join(im)} | {'+'.join(ab)} |")
    (common.OUT / "guardrail_impact.md").write_text("\n".join(gr), encoding="utf-8")

    # ---- per-scenario CSV (pick your 'instructive misclassifications' from here) ----
    with open(common.OUT / "per_scenario.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["id", "group", "malicious", "label_category", "label_bucket", "expected", "B0", "B1", "Imprint_modal",
                    "Imprint_action_stable", "Imprint_category_modal", "Ablation_modal", "Imprint_correct_all_runs", "B1_correct", "description"])
        for i, s in enumerate(scen):
            def modal(sysn):
                c = Counter(key(pr[sysn][i]["actions"]) for pr in per_run).most_common(1)[0]
                return "+".join(c[0]), c[1] / len(per_run)
            mal = s["label"]["malicious"]
            ok = lambda r: (key(r["actions"]) == key(expected[i])) if mal else common.level(r["actions"]) <= 1
            cats = Counter(pr["Imprint"][i]["category"] for pr in per_run).most_common(1)[0][0]
            w.writerow([s["id"], s["group"], mal, s["label"]["category"], s["label"]["severity_bucket"],
                        "+".join(expected[i]) if expected[i] else "<=CAPTCHA", "+".join(per_run[0]["B0"][i]["actions"]),
                        "+".join(per_run[0]["B1"][i]["actions"]), modal("Imprint")[0], f"{modal('Imprint')[1]:.2f}", cats,
                        modal("Ablation")[0], all(ok(pr["Imprint"][i]) for pr in per_run), ok(per_run[0]["B1"][i]), s["description"]])

    # ---- Fig. 4 data (+ PNG if matplotlib is installed) ----
    with open(common.OUT / "fig4_data.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["system", "precision", "recall", "fpr"])
        for sysn in SYSTEMS:
            w.writerow([sysn] + [table[sysn][k][0] for k in ("precision", "recall", "fpr")])
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        fig, ax = plt.subplots(figsize=(6.5, 3.2))
        width = 0.2
        for j, (lab, k) in enumerate([("Precision", "precision"), ("Recall", "recall"), ("FPR", "fpr")]):
            ax.bar([i + (j - 1) * width * 1.1 for i in range(len(SYSTEMS))], [table[s][k][0] or 0 for s in SYSTEMS], width, label=lab)
        ax.set_xticks(range(len(SYSTEMS)), SYSTEMS)
        ax.set_ylim(0, 1.05)
        ax.legend(ncol=3, frameon=False)
        fig.tight_layout()
        fig.savefig(common.OUT / "fig4.png", dpi=200)
    except ImportError:
        print("matplotlib not installed - skipped fig4.png (fig4_data.csv written)")

    (common.OUT / "results.json").write_text(json.dumps({"table": table, "llm": llm_row, "models": models, "k": len(runs)}, indent=1, default=str))
    print("\n".join(md))
    print("\n" + (common.OUT / "per_group.md").read_text().split("\n\n", 1)[1])
    print("\n" + gr[0] + "\n" + gr[1])
    print(f"\nFiles in {common.OUT}: table_vii.md per_group.md guardrail_impact.md per_scenario.csv fig4_data.csv results.json")


if __name__ == "__main__":
    main()
