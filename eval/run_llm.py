#!/usr/bin/env python3
"""Step 1: call the real Imprint classifier k times per scenario and cache the results.

  python3 run_llm.py --k 5            # real API (needs ANTHROPIC_API_KEY)
  python3 run_llm.py --mock --k 3     # offline pipeline test, fake LLM -> eval/out_mock (NEVER report these)

Resumable: finished (scenario, run) pairs in out/llm_runs.jsonl are skipped.
"""
import argparse
import json
import os
import random
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

if "--mock" in sys.argv:
    os.environ.setdefault("EVAL_OUT", str(Path(__file__).resolve().parent / "out_mock"))
import common  # noqa: E402

common.setup_env()
import advisor  # noqa: E402
import classify  # noqa: E402

tls = threading.local()
lock = threading.Lock()


def install_capture():
    orig = classify._PROVIDERS["anthropic"]

    def wrapped(fr):
        raw, meta = orig(fr)
        tls.meta = meta
        return raw, meta
    classify._PROVIDERS["anthropic"] = wrapped


def install_mock():
    """Fake provider so the pipeline can be tested without an API key. Not a result."""
    cat_of = [("sqli", "injection_attack"), ("xss", "injection_attack"), ("rce", "injection_attack"), ("phpi", "injection_attack"),
              ("brute", "credential_stuffing"), ("scrap", "bot_scraping"), ("crawl", "bot_scraping"),
              ("scan", "reconnaissance"), ("enum", "reconnaissance"), ("recon", "reconnaissance"), ("exploit", "automated_exploitation")]

    def provider(fr):
        text = json.dumps(fr)
        rng = random.Random(text + str(time.time_ns()))
        time.sleep(rng.uniform(0.05, 0.2))
        label = (fr["current_event"]["reported_attack_label"] or "").lower()
        cat = "injection_attack" if label in ("sqli", "xss", "rce", "phpi") else next((c for k, c in cat_of[4:] if k in label), "unknown")
        sev = min(100, 30 + 8 * fr["history"]["distinct_ip_count"] + 10 * fr["meta"]["total_observations"] + rng.randint(-10, 10))
        conf = 85 if cat != "unknown" else 40
        if "IGNORE ALL PREVIOUS" in text or "SYSTEM OVERRIDE" in text or "note to classifier" in text:
            cat, sev, conf = "unknown", 0, 100  # pretend the mock model fell for the injection
        return {"category": cat, "confidence": conf, "severity": sev, "evidence": ["mock"]}, \
               {"model": "mock", "stop_reason": "tool_use", "usage": {"input_tokens": 900, "output_tokens": 60}}
    classify._PROVIDERS["anthropic"] = provider


def one(s, run):
    doc, fp = common.build_doc(s), common.build_fp(s)
    fr = advisor.build_feature_record(doc, fp, s["distinct_full_hashes"], s["match_tier"])
    tls.meta = None
    t = time.monotonic()
    try:
        res, err = classify.classify(fr), None
    except classify.ClassifierUnavailable as e:
        res, err = None, str(e)
    lat = (time.monotonic() - t) * 1000
    meta = getattr(tls, "meta", None) or {}
    return {"id": s["id"], "run": run, "classification": res, "error": err, "latency_ms": round(lat, 1),
            "model": meta.get("model"), "usage": meta.get("usage"), "ts": time.strftime("%Y-%m-%dT%H:%M:%S%z")}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--k", type=int, default=5)
    ap.add_argument("--workers", type=int, default=4)
    ap.add_argument("--ids", nargs="*", help="only these scenario ids")
    ap.add_argument("--mock", action="store_true")
    a = ap.parse_args()

    if a.mock:
        install_mock()
        print("MOCK MODE: fake LLM, results go to", common.OUT, "- do not report these numbers")
    else:
        if not os.environ.get("ANTHROPIC_API_KEY"):
            sys.exit("ANTHROPIC_API_KEY is not set (export it or put it in the repo .env). "
                     "Without it every call falls back and you would measure only the fail-safe.")
        install_capture()
        print("model:", classify.ANTHROPIC_MODEL, "| timeout:", classify.TIMEOUT_SECONDS, "s")

    cache = common.OUT / "llm_runs.jsonl"
    done = set()
    if cache.exists():
        for line in cache.read_text().splitlines():
            r = json.loads(line)
            if not r["error"]:
                done.add((r["id"], r["run"]))
    scen = [s for s in common.load_scenarios() if not a.ids or s["id"] in a.ids]
    todo = [(s, r) for r in range(a.k) for s in scen if (s["id"], r) not in done]
    print(f"{len(scen)} scenarios x k={a.k}: {len(todo)} calls to make ({len(done)} already cached)")

    cnt = {"n": 0, "err": 0}

    def work(item):
        out = one(*item)
        with lock:
            with open(cache, "a", encoding="utf-8") as f:
                f.write(json.dumps(out) + "\n")
            cnt["n"] += 1
            cnt["err"] += bool(out["error"])
            if cnt["n"] % 20 == 0 or out["error"]:
                print(f"  {cnt['n']}/{len(todo)} done, {cnt['err']} fallbacks" + (f" (last: {out['error'][:80]})" if out["error"] else ""))
    with ThreadPoolExecutor(a.workers) as ex:
        list(ex.map(work, todo))
    print(f"finished: {cnt['n']} calls, {cnt['err']} fallbacks -> {cache}")
    if cnt["err"]:
        print("Re-run the same command to retry failed calls before analysing.")


if __name__ == "__main__":
    main()
