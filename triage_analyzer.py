#!/usr/bin/env python3
"""
PS2Recomp Triage Analyzer — CLI Query Tool + Full Report Generator
===================================================================
Reads triage_map.json and produces interactive queries OR a full text report.

Usage:
  python triage_analyzer.py triage_map.json report
  python triage_analyzer.py triage_map.json report --output my_report.txt
  python triage_analyzer.py triage_map.json stats
  python triage_analyzer.py triage_map.json coverage
  python triage_analyzer.py triage_map.json top fpu_ops 20
  python triage_analyzer.py triage_map.json tag SAFE_LEAF
  python triage_analyzer.py triage_map.json category VECTORS
  python triage_analyzer.py triage_map.json filter --category STATE_MACHINES --tag MULTI_RETURN
  python triage_analyzer.py triage_map.json filter --min-fpu 10 --min-size 200
  python triage_analyzer.py triage_map.json disposition STUB
  python triage_analyzer.py triage_map.json export SAFE_LEAF safe_leaf_funcs.csv
"""

import json, sys, argparse
from pathlib import Path
from datetime import datetime

try:
    import pandas as pd
    HAS_PANDAS = True
except ImportError:
    HAS_PANDAS = False

def load_triage(path):
    with open(path) as f:
        return json.load(f)

def flatten_functions(data):
    rows = []
    for func in data["functions"]:
        row = {
            "address": func["address"],
            "name": func["name"],
            "category": func["category"],
            "disposition": func["disposition"],
            "size": func["size"],
            "tags": ", ".join(func.get("tags", [])),
            "tag_list": func.get("tags", []),
        }
        for k, v in func.get("metrics", {}).items():
            row[k] = v
        for k, v in func.get("hardware", {}).items():
            row[k] = v
        rows.append(row)
    return rows

# =========================================================
# FULL REPORT GENERATOR
# =========================================================

def generate_report(data, rows, output_path):
    lines = []
    w = lines.append

    def sep():
        w("=" * 90)
    def subsep():
        w("-" * 90)

    stats = data.get("statistics", {})
    total_all = stats.get("total_functions", len(rows))
    total_enriched = stats.get("enriched_count", len(rows))
    total_size = sum(r["size"] for r in rows)

    # ---- SECTION 1: BINARY OVERVIEW ----
    sep()
    w("PS2Recomp TRIAGE REPORT")
    w(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    sep()
    w("")
    w("SECTION 1: BINARY OVERVIEW")
    subsep()
    w(f"  ELF Hash             : {data.get('elf_hash', 'N/A')}")
    w(f"  Schema Version       : {data.get('schema_version', 'N/A')}")
    tr = data.get("text_range", {})
    if tr:
        w(f"  Code Range           : {tr.get('start','?')} - {tr.get('end','?')}")
    w(f"  Total Functions (ELF): {total_all}")
    w(f"  Enriched (our scope) : {total_enriched}")
    w(f"  Total Code Size      : {total_size:,} bytes ({total_size/1024:.1f} KB)")
    w("")

    cat_counts, cat_sizes = {}, {}
    for r in rows:
        c = r["category"]
        cat_counts[c] = cat_counts.get(c, 0) + 1
        cat_sizes[c] = cat_sizes.get(c, 0) + r["size"]
    w("  Category Distribution:")
    for c, count in sorted(cat_counts.items(), key=lambda x: -x[1]):
        pct = (count / len(rows)) * 100
        w(f"    {c:20s}: {count:5d} ({pct:5.1f}%)  {cat_sizes[c]/1024:8.1f} KB")
    w("")

    disp_counts = {}
    for r in rows:
        disp_counts[r["disposition"]] = disp_counts.get(r["disposition"], 0) + 1
    w("  Disposition:")
    for d, count in sorted(disp_counts.items(), key=lambda x: -x[1]):
        w(f"    {d:12s}: {count:5d} ({count*100/len(rows):.1f}%)")
    w("")

    tag_counts = {}
    for r in rows:
        for t in r["tag_list"]:
            tag_counts[t] = tag_counts.get(t, 0) + 1
    w("  Tag Distribution:")
    for t, count in sorted(tag_counts.items(), key=lambda x: -x[1]):
        w(f"    {t:25s}: {count}")
    w("")

    # ---- SECTION 2: COVERAGE ----
    w("SECTION 2: AUTO-TRANSLATION COVERAGE")
    subsep()

    safe_rows = [r for r in rows if "SAFE_LEAF" in r["tag_list"]]
    safe_size = sum(r["size"] for r in safe_rows)
    hazard_tags = ["ACC_PRECISION_HAZARD", "VIF_DMA_UPLOAD", "SMC_HAZARD",
                   "SPR_SYNC_HAZARD", "BUSY_WAIT_HAZARD"]
    hazard_rows = [r for r in rows if any(h in r["tag_list"] for h in hazard_tags)]
    hazard_size = sum(r["size"] for r in hazard_rows)

    w(f"  SAFE_LEAF (auto-translate):")
    w(f"    Functions : {len(safe_rows):,} / {len(rows):,} ({len(safe_rows)*100/len(rows):.1f}%)")
    w(f"    Code Size : {safe_size:,} / {total_size:,} bytes ({safe_size*100/total_size:.1f}%)")
    w("")
    w(f"  HAZARD (manual HLE override):")
    w(f"    Functions : {len(hazard_rows):,}")
    w(f"    Code Size : {hazard_size:,} bytes ({hazard_size*100/total_size:.1f}%)")
    w("")
    w(f"  STUB (runtime handler) : {disp_counts.get('STUB', 0):,}")
    w(f"  SKIP (excluded)        : {disp_counts.get('SKIP', 0):,}")
    w("")

    bar_total = 60
    bar_safe = max(1, int(safe_size / total_size * bar_total)) if total_size else 0
    bar_haz = max(0, int(hazard_size / total_size * bar_total)) if total_size else 0
    bar_rest = bar_total - bar_safe - bar_haz
    w(f"  [{'#' * bar_safe}{'!' * bar_haz}{'.' * bar_rest}]")
    w(f"   # = SAFE ({safe_size*100/total_size:.1f}%)  ! = HAZARD ({hazard_size*100/total_size:.1f}%)  . = Other")
    w("")

    # ---- SECTION 3: SAFE FUNCTIONS ----
    w("SECTION 3: SAFE FUNCTIONS — Auto-translate list")
    subsep()
    w(f"  Total: {len(safe_rows)} functions ({safe_size:,} bytes)")
    w(f"  Leaf functions: call nothing, no complex side effects.")
    w("")
    w(f"  {'Address':>12s}  {'Size':>6s}  {'Category':>16s}  Name")
    subsep()
    for r in sorted(safe_rows, key=lambda x: -x["size"]):
        w(f"  {r['address']:>12s}  {r['size']:>6d}  {r['category']:>16s}  {r['name']}")
    w("")

    # ---- SECTION 4: MANUAL OVERRIDE LIST ----
    w("SECTION 4: FUNCTIONS REQUIRING MANUAL OVERRIDE")
    subsep()
    w("  Detailed reasons per function. Sorted by severity then size.")
    w("")

    risk_tags_all = hazard_tags + ["MULTI_RETURN", "VU0_VECTORS", "USES_SPR"]
    override_rows = [r for r in rows if any(t in r["tag_list"] for t in risk_tags_all)]
    override_rows.sort(key=lambda r: (-len([t for t in r["tag_list"] if t in risk_tags_all]), -r["size"]))

    w(f"  Total: {len(override_rows)} functions")
    w("")

    for r in override_rows:
        w(f"  {r['address']}  {r['name']}")
        reasons = []

        if "ACC_PRECISION_HAZARD" in r["tag_list"]:
            reasons.append(
                f"ACC_PRECISION_HAZARD: {r.get('acc_ops',0)} accumulator ops (madda.s/vmadd/vmsub). "
                f"PS2 FPU is non-IEEE-754 (no NaN/Inf, different rounding). "
                f"C++ float translation causes precision drift that breaks physics/animation over frames. "
                f"Needs SIMD override with PS2-accurate rounding.")

        if "VIF_DMA_UPLOAD" in r["tag_list"]:
            reasons.append(
                "VIF_DMA_UPLOAD: Writes to VIF0/VIF1 MMIO (0x10003800-0x10003C30). "
                "Uploads VU1 microcode/geometry via DMA chain. "
                "Cannot be statically translated — needs HLE graphics API reimplementation.")

        if "SMC_HAZARD" in r["tag_list"]:
            reasons.append(
                "SMC_HAZARD: Writes to executable code addresses (self-modifying code). "
                "Static translation assumes immutable code. Needs runtime interpreter or patch-out.")

        if "SPR_SYNC_HAZARD" in r["tag_list"]:
            reasons.append(
                "SPR_SYNC_HAZARD: Uses Scratchpad RAM (0x70000000) + sync barriers. "
                "PC DMA emulation timing mismatch can cause deadlocks. "
                "Needs careful HLE or sync removal.")

        if "BUSY_WAIT_HAZARD" in r["tag_list"]:
            reasons.append(
                "BUSY_WAIT_HAZARD: MMIO read in tight loop (hardware polling). "
                "Burns CPU on PC. Replace with yield/sleep or event callback.")

        if "VU0_VECTORS" in r["tag_list"]:
            reasons.append(
                f"VU0_VECTORS: COP2 instructions present. FPU={r.get('fpu_ops',0)}, ACC={r.get('acc_ops',0)}. "
                f"PS2Recomp handles basic COP2 but VU0 macro mode flag register edge cases may slip. "
                f"Verify output correctness against hardware.")

        if "USES_SPR" in r["tag_list"] and "SPR_SYNC_HAZARD" not in r["tag_list"]:
            reasons.append(
                "USES_SPR: Accesses Scratchpad RAM (0x70000000-0x70003FFF). "
                "Ensure runtime maps this 16KB region. Performance-critical on PS2, trivial on PC.")

        if "MULTI_RETURN" in r["tag_list"]:
            reasons.append(
                f"MULTI_RETURN: {r.get('return_paths',0)} return paths. "
                f"Multiple exits increase control flow translation errors. "
                f"Verify all paths reachable and return values correct.")

        fpu = r.get("fpu_ops", 0)
        branch = r.get("branch_ops", 0)
        callee = r.get("callee_count", 0)
        size = r["size"]

        if fpu > 30:
            reasons.append(
                f"HIGH_FPU_DENSITY: {fpu} float ops in {size} bytes. "
                f"Precision-sensitive — compare against PS2 hardware output.")
        if callee > 15:
            reasons.append(
                f"HIGH_FAN_OUT: Calls {callee} functions. Manager/orchestrator pattern. "
                f"Bug here propagates to all callees — test thoroughly.")
        if branch > 20:
            reasons.append(
                f"HIGH_COMPLEXITY: {branch} branches. Complex control flow increases "
                f"translation error risk. Review decompiled C++ output manually.")

        for reason in reasons:
            w(f"    -> {reason}")
        w("")

    # ---- SECTION 5: ARCHITECTURE WARNINGS ----
    w("SECTION 5: ARCHITECTURE WARNINGS")
    subsep()

    w("  5a. HIGH FAN-IN FUNCTIONS (callee_count > 10)")
    w("      A bug in these propagates across the game.")
    w("")
    high_fanin = sorted([r for r in rows if r.get("callee_count", 0) > 10],
                        key=lambda x: -x.get("callee_count", 0))
    if high_fanin:
        w(f"  {'Address':>12s}  {'Callees':>8s}  {'Size':>6s}  {'Category':>16s}  Name")
        subsep()
        for r in high_fanin[:40]:
            w(f"  {r['address']:>12s}  {r.get('callee_count',0):>8d}  {r['size']:>6d}  "
              f"{r['category']:>16s}  {r['name'][:45]}")
    else:
        w("  None found.")
    w("")

    w("  5b. MULTI-RETURN FUNCTIONS (3+ exit paths)")
    w("")
    multi_ret = [r for r in rows if "MULTI_RETURN" in r["tag_list"]]
    if multi_ret:
        for r in sorted(multi_ret, key=lambda x: -x.get("return_paths", 0)):
            w(f"  {r['address']}  returns={r.get('return_paths',0):2d}  "
              f"size={r['size']:5d}  {r['name'][:50]}")
    else:
        w("  None found.")
    w("")

    w("  5c. GLOBAL WRITERS WITHOUT STACK FRAME")
    w("      Likely interrupt handlers or compiler artifacts.")
    w("")
    no_frame = [r for r in rows if r.get("writes_global") and not r.get("has_stack_frame") and r["size"] > 20]
    if no_frame:
        for r in sorted(no_frame, key=lambda x: -x["size"]):
            w(f"  {r['address']}  size={r['size']:5d}  {r['category']:>16s}  {r['name'][:45]}")
    else:
        w("  None found.")
    w("")

    # ---- SECTION 6: GLOBAL CONTEXT ----
    w("SECTION 6: GLOBAL CONTEXT — Critical Runtime Configuration")
    subsep()

    gp = data.get("global_pointer")
    if gp:
        w(f"  Global Pointer ($gp): {gp}")
        w(f"")
        w(f"  *** CRITICAL: Set ctx->gp = {gp} in PS2Recomp runtime BEFORE any")
        w(f"  recompiled code executes. MIPS $gp-relative addressing covers all")
        w(f"  .sdata/.sbss globals. Wrong GP = thousands of functions crash on")
        w(f"  Memory Access Violation. This is the #1 configuration priority. ***")
    else:
        w("  Global Pointer ($gp): NOT FOUND")
        w("  *** WARNING: No _gp symbol. Determine GP manually from crt0/ELF header.")
        w("  Without it, all GP-relative loads/stores will segfault. ***")
    w("")

    w(f"  ELF Fingerprint: {data.get('elf_hash', 'N/A')}")
    w(f"  All addresses are build-specific. Do NOT use with different region/version.")
    w("")

    spr_funcs = [r for r in rows if "USES_SPR" in r["tag_list"]]
    if spr_funcs:
        w(f"  Scratchpad RAM: {len(spr_funcs)} functions access 0x70000000-0x70003FFF")
        w(f"  Runtime must map this 16KB region.")
        for r in spr_funcs:
            w(f"    {r['address']}  {r['name'][:50]}")
    w("")

    # ---- SECTION 7: TRIAGE PRIORITY ----
    w("SECTION 7: TRIAGE PRIORITY — Top 20 Targets for Week 1")
    subsep()
    w("  Largest, most FPU/VU0-heavy non-SAFE functions.")
    w("  Score = size + (fpu_ops * 10) + (acc_ops * 50) + hazard bonuses")
    w("")

    hle_candidates = [r for r in rows
                      if "SAFE_LEAF" not in r["tag_list"]
                      and r["category"] != "GETTER"
                      and r["disposition"] == "RECOMPILE"]

    for r in hle_candidates:
        r["_priority"] = (r["size"]
                          + r.get("fpu_ops", 0) * 10
                          + r.get("acc_ops", 0) * 50
                          + (500 if "ACC_PRECISION_HAZARD" in r["tag_list"] else 0)
                          + (300 if "VU0_VECTORS" in r["tag_list"] else 0)
                          + (200 if "USES_SPR" in r["tag_list"] else 0))

    hle_candidates.sort(key=lambda x: -x["_priority"])

    w(f"  {'#':>3s}  {'Address':>12s}  {'Score':>7s}  {'Size':>6s}  {'FPU':>4s}  "
      f"{'ACC':>4s}  {'Br':>4s}  {'Cat':>14s}  Name")
    subsep()
    for i, r in enumerate(hle_candidates[:20], 1):
        flags = ""
        if "ACC_PRECISION_HAZARD" in r["tag_list"]: flags += "[ACC!] "
        if "VU0_VECTORS" in r["tag_list"]: flags += "[VU0] "
        if "USES_SPR" in r["tag_list"]: flags += "[SPR] "
        if "MULTI_RETURN" in r["tag_list"]: flags += "[MR] "
        w(f"  {i:>3d}  {r['address']:>12s}  {r['_priority']:>7d}  {r['size']:>6d}  "
          f"{r.get('fpu_ops',0):>4d}  {r.get('acc_ops',0):>4d}  "
          f"{r.get('branch_ops',0):>4d}  {r['category']:>14s}  {flags}{r['name'][:38]}")
    w("")

    top20_size = sum(r["size"] for r in hle_candidates[:20])
    w(f"  Top 20 total: {top20_size:,} bytes ({top20_size/1024:.1f} KB)")
    w(f"  Completing these covers the most critical complex code paths.")
    w("")
    sep()
    w("END OF REPORT")
    sep()

    report_text = "\n".join(lines)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(report_text)
    print(f"Report written to: {output_path}")
    print(f"  Lines: {len(lines)} | Safe: {len(safe_rows)} | Override: {len(override_rows)} | Priority: {min(20, len(hle_candidates))}")


# =========================================================
# CLI COMMANDS (unchanged)
# =========================================================

def print_header(data):
    print(f"ELF Hash       : {data.get('elf_hash', 'N/A')}")
    print(f"Schema Version : {data.get('schema_version', 'N/A')}")
    print(f"Global Pointer : {data.get('global_pointer', 'N/A')}")
    tr = data.get("text_range", {})
    if tr: print(f"Code Range     : {tr.get('start','?')} - {tr.get('end','?')}")
    print()

def cmd_stats(data, rows):
    print_header(data)
    stats = data.get("statistics", {})
    print("=== PIPELINE STATISTICS ===")
    for k, v in stats.items(): print(f"  {k:35s}: {v}")
    print("\n=== CATEGORY DISTRIBUTION ===")
    cc = {}
    for r in rows: cc[r["category"]] = cc.get(r["category"], 0) + 1
    for c, n in sorted(cc.items(), key=lambda x: -x[1]): print(f"  {c:20s}: {n:5d}")
    print("\n=== TAG DISTRIBUTION ===")
    tc = {}
    for r in rows:
        for t in r["tag_list"]: tc[t] = tc.get(t, 0) + 1
    for t, n in sorted(tc.items(), key=lambda x: -x[1]): print(f"  {t:25s}: {n}")

def cmd_top(data, rows, metric, n):
    valid = sorted([r for r in rows if metric in r], key=lambda r: -r.get(metric, 0))
    if not valid: print(f"Unknown metric: {metric}"); return
    print(f"=== TOP {n} BY {metric.upper()} ===")
    print(f"{'Address':>12s}  {metric:>10s}  {'Size':>6s}  {'Category':>16s}  Name")
    for r in valid[:n]:
        print(f"  {r['address']:>10s}  {r.get(metric,0):>10d}  {r['size']:>6d}  {r['category']:>16s}  {r['name'][:45]}")

def cmd_tag(data, rows, tag_name):
    matched = [r for r in rows if tag_name in r["tag_list"]]
    if not matched: print(f"No functions with tag: {tag_name}"); return
    print(f"=== TAG: {tag_name} ({len(matched)}) ===")
    for r in sorted(matched, key=lambda x: -x["size"]):
        print(f"  {r['address']:>10s}  {r['size']:>6d}  {r['category']:>16s}  {r['name'][:45]}")

def cmd_category(data, rows, cat):
    matched = [r for r in rows if r["category"].upper() == cat.upper()]
    if not matched: print(f"No functions in category: {cat}"); return
    print(f"=== {cat.upper()} ({len(matched)}) ===")
    for r in sorted(matched, key=lambda x: -x["size"])[:50]:
        print(f"  {r['address']:>10s}  {r['size']:>6d}  fpu={r.get('fpu_ops',0):3d}  {r['name'][:45]}")
    if len(matched) > 50: print(f"  ... +{len(matched)-50} more")

def cmd_disposition(data, rows, disp):
    matched = [r for r in rows if r["disposition"].upper() == disp.upper()]
    if not matched: print(f"No functions: {disp}"); return
    print(f"=== {disp.upper()} ({len(matched)}) ===")
    for r in sorted(matched, key=lambda x: x["address"]):
        print(f"  {r['address']:>10s}  {r['size']:>6d}  {r['category']:>16s}  {r['name'][:40]}")

def cmd_filter(data, rows, args):
    m = rows
    if args.filter_category: m = [r for r in m if r["category"].upper() == args.filter_category.upper()]
    if args.filter_tag: m = [r for r in m if args.filter_tag in r["tag_list"]]
    if args.min_fpu is not None: m = [r for r in m if r.get("fpu_ops", 0) >= args.min_fpu]
    if args.min_size is not None: m = [r for r in m if r["size"] >= args.min_size]
    if args.min_acc is not None: m = [r for r in m if r.get("acc_ops", 0) >= args.min_acc]
    if not m: print("No matches."); return
    print(f"=== FILTER ({len(m)}) ===")
    for r in sorted(m, key=lambda x: -x["size"]):
        print(f"  {r['address']:>10s}  {r['size']:>6d}  fpu={r.get('fpu_ops',0):3d}  acc={r.get('acc_ops',0):3d}  {r['category']:>16s}  {r['name'][:38]}")

def cmd_export(data, rows, tag, path):
    matched = [r for r in rows if tag in r["tag_list"]]
    if not matched: print(f"No functions with tag: {tag}"); return
    with open(path, "w") as f:
        keys = [k for k in matched[0] if k != "tag_list"]
        f.write(",".join(keys) + "\n")
        for r in matched: f.write(",".join(str(r.get(k, "")) for k in keys) + "\n")
    print(f"Exported {len(matched)} to {path}")

# =========================================================
# MAIN
# =========================================================

def main():
    p = argparse.ArgumentParser(description="PS2Recomp Triage Analyzer",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("json_file")
    p.add_argument("command", choices=["stats","coverage","top","tag","category",
                                        "disposition","filter","export","report"])
    p.add_argument("args", nargs="*")
    p.add_argument("--output", "-o", default=None)
    p.add_argument("--category", dest="filter_category", default=None)
    p.add_argument("--tag", dest="filter_tag", default=None)
    p.add_argument("--min-fpu", type=int, default=None)
    p.add_argument("--min-size", type=int, default=None)
    p.add_argument("--min-acc", type=int, default=None)
    args = p.parse_args()

    data = load_triage(args.json_file)
    rows = flatten_functions(data)

    if args.command == "report":
        out = args.output or f"{Path(args.json_file).stem}_report.txt"
        generate_report(data, rows, out)
    elif args.command == "stats": cmd_stats(data, rows)
    elif args.command == "coverage":
        print_header(data)
        ts = sum(r["size"] for r in rows)
        sl = [r for r in rows if "SAFE_LEAF" in r["tag_list"]]
        ss = sum(r["size"] for r in sl)
        print(f"SAFE_LEAF: {len(sl)} funcs ({ss:,}B = {ss*100/ts:.1f}%)")
    elif args.command == "top":
        if not args.args: print("Usage: top <metric> [n]"); return
        cmd_top(data, rows, args.args[0], int(args.args[1]) if len(args.args)>1 else 20)
    elif args.command == "tag":
        if not args.args: print("Usage: tag <NAME>"); return
        cmd_tag(data, rows, args.args[0])
    elif args.command == "category":
        if not args.args: print("Usage: category <NAME>"); return
        cmd_category(data, rows, args.args[0])
    elif args.command == "disposition":
        if not args.args: print("Usage: disposition <STUB|SKIP|RECOMPILE>"); return
        cmd_disposition(data, rows, args.args[0])
    elif args.command == "filter": cmd_filter(data, rows, args)
    elif args.command == "export":
        if len(args.args)<2: print("Usage: export <TAG> <out.csv>"); return
        cmd_export(data, rows, args.args[0], args.args[1])

if __name__ == "__main__":
    main()
