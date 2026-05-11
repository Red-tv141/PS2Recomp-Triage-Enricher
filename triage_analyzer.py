#!/usr/bin/env python3
"""
PS2Recomp Triage Analyzer v3 — Schema v3 + DC2 Phase F13 Aware
================================================================
Double-click (no arguments) → scans triage_map.json in same folder,
generates 7 phase + 4 Additional MD files with embedded Claude instructions.

v3 changes (matching TriageEnricher.java v3 schema_version=3):
  • New phase MD:  phase_gifpk.md      — sceGifPk*/sceVif1Pk* packet builders
  • New phase MD:  phase_iop_rpc.md    — IOP_RPC_DISPATCH functions
  • New phase MD:  phase_archive_io.md — ARCHIVE_IO functions
  • New section:   game_override_addresses shown in summary
  • New tag columns in all tables: CONV_VIOLATION, INIT_LARGE, DMA_TTE,
                                   IOP_RPC, ARCHIVE_IO, PAD_POLL
  • Phase 6 (MMIO) now has DMA_CHAIN_TTE_RISK sub-section
  • Phase 4b now has PAD_POLL_LOOP sub-section
  • F13 stub:  sceDmaSync non-blocking pattern included in phase instructions
  • Summary MD:  shows game_override_imported count + known_iop_sids table
  • classify_phases: v3 tags route correctly before fallback categories

CLI usage (unchanged):
  python triage_analyzer.py triage_map.json stats
  python triage_analyzer.py triage_map.json top fpu_ops 20
  python triage_analyzer.py triage_map.json report --output my_report.txt
  python triage_analyzer.py triage_map.json query --tag BUSY_WAIT_HAZARD
  python triage_analyzer.py triage_map.json query --tag PAD_POLL_LOOP
  python triage_analyzer.py triage_map.json query --tag DMA_CHAIN_TTE_RISK
  python triage_analyzer.py triage_map.json query --tag IOP_RPC_DISPATCH
  python triage_analyzer.py triage_map.json query --tag INIT_LARGE_FUNC
  python triage_analyzer.py triage_map.json query --disposition RECOMPILE
"""

import json, sys, argparse, os
from pathlib import Path
from datetime import datetime

try:
    import pandas as pd
    HAS_PANDAS = True
except ImportError:
    HAS_PANDAS = False

# =========================================================
# DATA LOADING
# =========================================================

def load_triage(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)

def flatten_functions(data):
    rows = []
    for func in data.get("functions", []):
        row = {
            "address":      func["address"],
            "name":         func["name"],
            "category":     func["category"],
            "disposition":  func["disposition"],
            "size":         func["size"],
            "tags":         ", ".join(func.get("tags", [])),
            "tag_list":     func.get("tags", []),
            "callee_list":  func.get("callees", []),
        }
        for k, v in func.get("metrics", {}).items():
            row[k] = v
        for k, v in func.get("hardware", {}).items():
            row[k] = v
        rows.append(row)
    return rows

def compute_priority_score(r):
    """Weighted score: higher = more complex / higher priority."""
    return (
        r["size"]
        + r.get("fpu_ops", 0) * 10
        + r.get("acc_ops", 0) * 50
        + (500 if "ACC_PRECISION_HAZARD"  in r["tag_list"] else 0)
        + (300 if "VU0_VECTORS"           in r["tag_list"] else 0)
        + (200 if "USES_SPR"              in r["tag_list"] else 0)
        + (150 if "DMA_CHAIN_TTE_RISK"    in r["tag_list"] else 0)
        + (100 if "INIT_LARGE_FUNC"       in r["tag_list"] else 0)
        + (100 if "CONVENTION_VIOLATION"  in r["tag_list"] else 0)
    )

# =========================================================
# DEPENDENCY SORT
# =========================================================

def dependency_sort(funcs):
    """Sort functions so callees appear before callers (bottom-up).
    Uses address as the unique key to handle overloaded names."""
    if not funcs:
        return funcs

    from collections import defaultdict

    by_addr = {}
    for r in funcs:
        r["_score"] = compute_priority_score(r)
        by_addr[r["address"]] = r

    name_to_addrs = defaultdict(set)
    for r in funcs:
        name_to_addrs[r["name"]].add(r["address"])

    phase_addrs = set(by_addr.keys())

    deps = {addr: set() for addr in phase_addrs}
    for r in funcs:
        for callee_name in r.get("callee_list", []):
            for callee_addr in name_to_addrs.get(callee_name, ()):
                if callee_addr != r["address"]:
                    deps[r["address"]].add(callee_addr)

    # [FIX] reverse must be a set per node, not a list.
    # A list allows duplicate entries when two callee slots map to the same
    # caller address (overloaded names / multiple callees with same name),
    # causing in_degree to go negative and breaking topological order.
    reverse = {addr: set() for addr in phase_addrs}
    for caller_addr, callee_addrs in deps.items():
        for callee_addr in callee_addrs:
            reverse[callee_addr].add(caller_addr)

    in_degree = {addr: len(callees) for addr, callees in deps.items()}

    queue = sorted(
        [a for a in phase_addrs if in_degree[a] == 0],
        key=lambda a: -by_addr[a]["_score"]
    )

    result = []
    while queue:
        addr = queue.pop(0)
        result.append(by_addr[addr])
        for caller_addr in reverse.get(addr, []):
            if caller_addr in in_degree:
                in_degree[caller_addr] -= 1
                if in_degree[caller_addr] == 0:
                    queue.append(caller_addr)
        queue.sort(key=lambda a: -by_addr[a]["_score"])

    seen = {r["address"] for r in result}
    for r in sorted(funcs, key=lambda x: -x["_score"]):
        if r["address"] not in seen:
            result.append(r)

    return result

# =========================================================
# PHASE CLASSIFICATION  (v3: routes on new tags first)
# =========================================================

# Known sceGifPk* / sceVif1Pk* function name prefixes (from ps2_stubs_gifpk.inl)
GIFPK_PREFIXES = (
    "sceGifPkInit","sceGifPkReset","sceGifPkTerminate","sceGifPkEnd",
    "sceGifPkOpenGifTag","sceGifPkCnt","sceGifPkCloseGifTag",
    "sceGifPkAddGsAD","sceGifPkAddGsData","sceGifPkReserve",
    "sceGifPkRef","sceGifPkRefLoadImage",
    "sceVif1PkInit","sceVif1PkReset","sceVif1PkTerminate","sceVif1PkCnt",
    "sceVif1PkCall","sceVif1PkEnd","sceVif1PkOpenDirectCode",
    "sceVif1PkCloseDirectCode","sceVif1PkOpenGifTag","sceVif1PkCloseGifTag",
    "sceVif1PkAddGsAD","sceVif1PkReserve","sceVif1PkAlign",
)

def is_gifpk(r):
    name = r["name"]
    return any(name.startswith(p) or name == p for p in GIFPK_PREFIXES)

def classify_phases(rows):
    phases = {
        "phase1_safe_leaf":      [],
        "phase2_wrappers":       [],
        "phase3_math":           [],
        "phase4a_game_logic":    [],
        "phase4b_state_machines":[],
        "phase5_acc_hazard":     [],
        "phase6_mmio":           [],
        "phase7_vu0_microcode":  [],
        # v3 new buckets
        "phase_gifpk":           [],
        "phase_iop_rpc":         [],
        "phase_archive_io":      [],
        "orphan_code":           [],
    }

    for r in rows:
        if r["disposition"] != "RECOMPILE":
            continue

        tags = r["tag_list"]
        cat  = r["category"]

        # Orphan first
        if "ORPHAN_CODE" in tags:
            phases["orphan_code"].append(r)
            continue

        # v3 NEW: GifPk packet builders — own phase
        if is_gifpk(r):
            phases["phase_gifpk"].append(r)
            continue

        # v3 NEW: IOP RPC dispatch — own phase
        if "IOP_RPC_DISPATCH" in tags:
            phases["phase_iop_rpc"].append(r)
            continue

        # v3 NEW: Archive I/O — own phase
        if "ARCHIVE_IO" in tags:
            phases["phase_archive_io"].append(r)
            continue

        # Phase 7 — VU0 microcode
        if "VU0_MICROCODE" in tags:
            phases["phase7_vu0_microcode"].append(r)

        # Phase 5 — ACC hazard (highest priority after VU0)
        elif "ACC_PRECISION_HAZARD" in tags:
            phases["phase5_acc_hazard"].append(r)

        # Phase 6 — MMIO access (includes DMA_CHAIN_TTE_RISK)
        elif "ACCESSES_MMIO" in tags or "DMA_CHAIN_TTE_RISK" in tags:
            phases["phase6_mmio"].append(r)

        # Phase 1 — Safe leaf
        elif "SAFE_LEAF" in tags:
            phases["phase1_safe_leaf"].append(r)

        # Phase 4b sub: PAD_POLL_LOOP → state machines
        elif "PAD_POLL_LOOP" in tags or "BUSY_WAIT_HAZARD" in tags:
            phases["phase4b_state_machines"].append(r)

        # Phase 2 — Wrappers / getters
        elif cat in ("WRAPPER", "GETTER_OR_STUB"):
            phases["phase2_wrappers"].append(r)

        # Phase 3 — Math/vectors
        elif cat == "MATH_VECTORS":
            phases["phase3_math"].append(r)

        # Phase 4a — Game logic
        elif cat == "GAME_LOGIC":
            phases["phase4a_game_logic"].append(r)

        else:
            phases["phase4b_state_machines"].append(r)

    for key in phases:
        phases[key] = dependency_sort(phases[key])

    return phases

# =========================================================
# FUNCTION TABLE FORMATTER  (v3: extra tag columns)
# =========================================================

# v3 tag abbreviation map (shown in Tags column)
TAG_ABBREVS = [
    ("ACC_PRECISION_HAZARD",  "ACC!"),
    ("VU0_VECTORS",           "VU0"),
    ("VU0_MICROCODE",         "uVU0"),
    ("USES_SPR",              "SPR"),
    ("MULTI_RETURN",          "MR"),
    ("WRITES_GLOBAL",         "WG"),
    ("COMPLEX_CONTROL_FLOW",  "JT"),
    ("BUSY_WAIT_HAZARD",      "BW"),
    ("SMC_HAZARD",            "SMC"),
    # v3 new
    ("DMA_CHAIN_TTE_RISK",    "TTE!"),
    ("CONVENTION_VIOLATION",  "ARG!"),
    ("INIT_LARGE_FUNC",       "INI!"),
    ("IOP_RPC_DISPATCH",      "RPC"),
    ("ARCHIVE_IO",            "ARC"),
    ("PAD_POLL_LOOP",         "PAD!"),
]

def format_tag_flags(tag_list):
    flags = [abbr for tag, abbr in TAG_ABBREVS if tag in tag_list]
    return ", ".join(flags) if flags else "-"

def format_function_table(funcs, include_fpu=True):
    lines = []
    if include_fpu:
        header = (f"| {'#':>4s} | {'Address':>12s} | {'Score':>6s} | {'Size':>6s} | "
                  f"{'FPU':>4s} | {'ACC':>4s} | {'Br':>4s} | {'Calls':>5s} | "
                  f"{'Xref':>4s} | {'Category':>16s} | Name | Tags |")
        sep    = (f"|{'-'*5}:|{'-'*13}:|{'-'*7}:|{'-'*7}:|{'-'*5}:|{'-'*5}:|"
                  f"{'-'*5}:|{'-'*6}:|{'-'*5}:|{'-'*17}:|{'-'*42}|{'-'*22}|")
        lines += [header, sep]
        for i, r in enumerate(funcs, 1):
            name = r["name"]
            if len(name) > 40:
                name = name[:22] + ".." + name[-16:]
            lines.append(
                f"| {i:>4d} | {r['address']:>12s} | {r['_score']:>6d} | {r['size']:>6d} | "
                f"{r.get('fpu_ops',0):>4d} | {r.get('acc_ops',0):>4d} | "
                f"{r.get('branch_ops',0):>4d} | {r.get('callee_count',0):>5d} | "
                f"{r.get('xref_to_count',0):>4d} | {r['category']:>16s} | "
                f"{name:<40s} | {format_tag_flags(r['tag_list'])} |"
            )
    else:
        header = f"| {'#':>4s} | {'Address':>12s} | {'Size':>6s} | {'Category':>16s} | Name | Tags |"
        sep    = f"|{'-'*5}:|{'-'*13}:|{'-'*7}:|{'-'*17}:|{'-'*45}|{'-'*22}|"
        lines += [header, sep]
        for i, r in enumerate(funcs, 1):
            name = r["name"]
            if len(name) > 43:
                name = name[:25] + ".." + name[-16:]
            lines.append(
                f"| {i:>4d} | {r['address']:>12s} | {r['size']:>6d} | "
                f"{r['category']:>16s} | {name:<43s} | {format_tag_flags(r['tag_list'])} |"
            )
    return "\n".join(lines)

# =========================================================
# PHASE MD GENERATORS
# =========================================================

def _header(title, data, extra_lines=""):
    gp = data.get("global_pointer", "UNKNOWN — MUST SET BEFORE RUNNING")
    ov = data.get("game_override_imported", 0)
    sv = data.get("schema_version", 1)
    return (
        f"# {title}\n\n"
        f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  \n"
        f"**ELF Hash:** {data.get('elf_hash','N/A')}  \n"
        f"**Global Pointer ($gp):** `{gp}`  \n"
        f"**Schema version:** {sv}  \n"
        f"**Game override functions pre-bound:** {ov}  \n"
        + extra_lines +
        "\n---\n"
    )

def _std_transition(next_phase_file, next_phase_section):
    return f"""
## Phase Transition

When ALL functions compile:
1. Write `phase_lessons.md` appending a section for this phase — only surprises a future Claude
   wouldn't know from reading `{next_phase_file}` alone.
2. Open `{next_phase_file}` and paste relevant notes into its **"Lessons from Previous Phase"** section.
3. Report completion to the user.
"""

def generate_phase1(funcs, data, output_dir):
    total_size = sum(r["size"] for r in funcs)
    md = _header("Phase 1: SAFE_LEAF — Auto-Translate", data) + f"""
## Overview

- **Total functions:** {len(funcs):,}
- **Total code size:** {total_size:,} bytes ({total_size/1024:.1f} KB)
- **What these are:** Leaf functions — they call nothing and have no complex side effects.
- **Expected difficulty:** LOW.

---

## Instructions for Claude

1. `cmake --build build64/` (incremental). Functions that compile clean → skip.
2. Open the `.cpp` file in `/auto_Recomp/`. Fix compile errors only.
3. Keep all `goto` labels intact.
4. Add brief comments where logic is non-obvious.

**Do NOT:** read assembly.txt or triage_map.json in full. Use `grep -A 50 "ADDR" assembly.txt`.  
**Do NOT:** extract helpers, restructure control flow, or process the next batch before the current compiles.

**Batch strategy:** groups of 10–20. `open → fix → build → verify zero errors → next`.

---

## Lessons from Previous Phase

<!-- paste notes here before starting -->

---

## Function List ({len(funcs):,} functions)

{format_function_table(funcs, include_fpu=False)}

{_std_transition("phase2_wrappers.md", "Phase 2")}"""
    path = output_dir / "phase1_safe_leaf.md"
    path.write_text(md, encoding="utf-8")
    return path, len(funcs)


def generate_phase2(funcs, data, output_dir):
    total_size = sum(r["size"] for r in funcs)
    gp = data.get("global_pointer", "UNKNOWN")
    md = _header("Phase 2: Wrappers & Getters — Thin Delegation Functions", data) + f"""
## Overview

- **Total functions:** {len(funcs):,}
- **Total code size:** {total_size:,} bytes ({total_size/1024:.1f} KB)
- **Expected difficulty:** LOW-MEDIUM.

---

## Instructions for Claude

1. `cmake --build build64/`. Functions that compile clean → skip.
2. Fix type mismatches, missing casts, wrong arg counts in wrapped calls.
3. `$gp`-relative loads: ensure `ctx->gp = {gp}`.
4. Preserve all `goto` labels.

**Key patterns:**
- `INIT_LARGE_FUNC` (tagged `INI!`) — these must RECOMPILE, never nop. If you see one here, do not stub it.
- `CONVENTION_VIOLATION` (tagged `ARG!`) — check arg order carefully; a0/a1 may be swapped vs. the callee's actual signature.

---

## Lessons from Previous Phase

<!-- paste notes here before starting -->

---

## Function List ({len(funcs):,} functions)

{format_function_table(funcs, include_fpu=False)}

{_std_transition("phase3_math.md", "Phase 3")}"""
    path = output_dir / "phase2_wrappers.md"
    path.write_text(md, encoding="utf-8")
    return path, len(funcs)


def generate_phase3(funcs, data, output_dir):
    total_size  = sum(r["size"] for r in funcs)
    vu0_count   = sum(1 for r in funcs if "VU0_VECTORS" in r["tag_list"])
    high_fpu    = sum(1 for r in funcs if r.get("fpu_ops", 0) > 30)
    md = _header("Phase 3: MATH_VECTORS — FPU & Vector Operations", data) + f"""
## Overview

- **Total functions:** {len(funcs):,}
- **Total code size:** {total_size:,} bytes ({total_size/1024:.1f} KB)
- **VU0/COP2 functions:** {vu0_count}
- **High FPU density (>30 ops):** {high_fpu}
- **Expected difficulty:** MEDIUM-HIGH.

---

## Instructions for Claude

1. `cmake --build build64/`. Functions that compile clean → skip.
2. COP2/VU0 — replace inline asm with project's existing math types.
3. Cross-reference: `grep -A 80 "ADDR" assembly.txt`
4. PS2 FPU quirks: no NaN/Inf, truncates toward zero. Add `// TODO: VERIFY — PS2 precision` where drift matters.

| PS2 Instruction | C++ Equivalent |
|-----------------|----------------|
| `vmul.xyzw vfD,vfA,vfB` | per-component multiply |
| `vadd.xyzw vfD,vfA,vfB` | per-component add |
| `vdiv Q, vfA.x,vfB.y` | `Q = vfA.x / vfB.y` |
| `vsqrt Q, vfA.x` | `Q = sqrtf(vfA.x)` |
| `vftoi0 vfD,vfA` | truncate to int, per component |

---

## Lessons from Previous Phase

<!-- paste notes here before starting -->

---

## Function List ({len(funcs):,} functions)

{format_function_table(funcs, include_fpu=True)}

{_std_transition("phase4a_game_logic.md", "Phase 4a")}"""
    path = output_dir / "phase3_math.md"
    path.write_text(md, encoding="utf-8")
    return path, len(funcs)


def generate_phase4a(funcs, data, output_dir):
    total_size    = sum(r["size"] for r in funcs)
    gp            = data.get("global_pointer", "UNKNOWN")
    writes_global = sum(1 for r in funcs if "WRITES_GLOBAL"  in r["tag_list"])
    high_xref     = sum(1 for r in funcs if r.get("xref_to_count", 0) > 10)
    large_init    = sum(1 for r in funcs if "INIT_LARGE_FUNC" in r["tag_list"])
    md = _header("Phase 4a: Game Logic — Global State & Function Calls", data) + f"""
## Overview

- **Total functions:** {len(funcs):,}
- **Total code size:** {total_size:,} bytes ({total_size/1024:.1f} KB)
- **Global writers:** {writes_global}
- **High fan-in (>10 callers):** {high_xref}
- **INIT_LARGE_FUNC (must recompile):** {large_init}
- **Expected difficulty:** MEDIUM-HIGH.

---

## ⚠️ INIT_LARGE_FUNC Warning

Functions tagged `INI!` are large init functions (many callees or >2000 bytes).
They **must be fully recompiled** — do NOT stub or nop them.
If `init__Fv` or similar appears here, implement all side effects (global writes, thread spawns) before moving on.

---

## Instructions for Claude

1. `cmake --build build64/`. Functions that compile clean → skip.
2. `$gp`-relative stores: ensure `ctx->gp = {gp}`.
3. High fan-in functions (many callers): test thoroughly before proceeding.
4. Sorted callees-first: fix B before A if A calls B.

---

## Lessons from Previous Phase

<!-- paste notes here before starting -->

---

## Function List ({len(funcs):,} functions)

{format_function_table(funcs, include_fpu=True)}

{_std_transition("phase4b_state_machines.md", "Phase 4b")}"""
    path = output_dir / "phase4a_game_logic.md"
    path.write_text(md, encoding="utf-8")
    return path, len(funcs)


def generate_phase4b(funcs, data, output_dir):
    total_size  = sum(r["size"] for r in funcs)
    gp          = data.get("global_pointer", "UNKNOWN")
    high_branch = sum(1 for r in funcs if r.get("branch_ops", 0) > 50)
    multi_ret   = sum(1 for r in funcs if "MULTI_RETURN"         in r["tag_list"])
    jump_tables = sum(1 for r in funcs if "COMPLEX_CONTROL_FLOW" in r["tag_list"])
    pad_poll    = sum(1 for r in funcs if "PAD_POLL_LOOP"         in r["tag_list"])
    busy_wait   = sum(1 for r in funcs if "BUSY_WAIT_HAZARD"      in r["tag_list"])

    pad_section = ""
    pad_funcs   = [r for r in funcs if "PAD_POLL_LOOP" in r["tag_list"]]
    if pad_funcs:
        pad_section = f"""
### PAD_POLL_LOOP Functions ({len(pad_funcs)}) — ⚠️ Phase F3.5 lesson

These functions contain a backward branch + call to `scePadGetState`/`sceGsSyncV`.
On the real PS2 they are busy-wait loops; in the recompiler they must NOT spin forever.

**Pattern to apply (from dc2_game_override.cpp):**
- `scePadGetState` stub must return a *changing* value (sequence 1→1→2→5→6→6…).
- If the loop condition is `beqz v0, loop`, the stub must eventually return non-zero.
- Register a `bindAddressHandler` shim for each function below if it still infinite-loops.

| Address | Name |
|---------|------|
""" + "\n".join(f"| `{r['address']}` | `{r['name']}` |" for r in pad_funcs) + "\n"

    md = _header("Phase 4b: State Machines — Complex Control Flow", data) + f"""
## Overview

- **Total functions:** {len(funcs):,}
- **Total code size:** {total_size:,} bytes ({total_size/1024:.1f} KB)
- **High branch count (>50):** {high_branch}
- **Multi-return functions:** {multi_ret}
- **Jump table functions:** {jump_tables}
- **PAD_POLL_LOOP (busy-wait hazard):** {pad_poll}
- **BUSY_WAIT_HAZARD (general):** {busy_wait}
- **Expected difficulty:** HIGH.

---
{pad_section}
---

## Instructions for Claude

1. `cmake --build build64/`. Functions that compile clean → skip.
2. Control flow is sacred — every `goto` label, every branch target matters.
3. `COMPLEX_CONTROL_FLOW` (`JT`) = indirect jump / switch table. Check `flowchart.txt`.
4. `WRITES_GLOBAL` (`WG`) = `$gp`-relative store, ensure `ctx->gp = {gp}`.
5. `BUSY_WAIT_HAZARD` (`BW`) = polling loop. If it spins forever in runner, add a
   `runtime->registerFunction(addr, shim)` in `dc2_game_override.cpp`.

**Do NOT:** restructure switch/case, reorder labels, extract state handlers.

---

## Lessons from Previous Phase

<!-- paste notes here before starting -->

---

## Function List ({len(funcs):,} functions)

{format_function_table(funcs, include_fpu=True)}

{_std_transition("phase5_acc_hazard.md", "Phase 5")}"""
    path = output_dir / "phase4b_state_machines.md"
    path.write_text(md, encoding="utf-8")
    return path, len(funcs)


def generate_phase5(funcs, data, output_dir):
    total_size = sum(r["size"] for r in funcs)
    md = _header("Phase 5: ACC_PRECISION_HAZARD — VU0 Accumulator Functions", data) + f"""
## Overview

- **Total functions:** {len(funcs):,}
- **Total code size:** {total_size:,} bytes ({total_size/1024:.1f} KB)
- **Expected difficulty:** VERY HIGH.
- **Skill file required:** YES — read `/ps2-recomp-Agent-SKILL-0.4.3/` first.

---

## Instructions for Claude

⚠️ Read the Skill file BEFORE touching any function.

1. `cmake --build build64/`. Functions that compile clean → skip.
2. Add `// HAZARD: ACC precision` as the first comment.
3. Translate ACC ops using the Skill-file pattern.
4. Mark every ACC translation with a comment showing the original instruction.
5. Do NOT use `double` — PS2-accurate behavior, not IEEE-accurate.

| PS2 Instruction | Meaning |
|-----------------|---------|
| `vmadda.xyzw ACC,vfA,vfB` | `ACC += vfA * vfB` |
| `vmsuba.xyzw ACC,vfA,vfB` | `ACC -= vfA * vfB` |
| `vmula.xyzw ACC,vfA,vfB` | `ACC = vfA * vfB` |
| `vopmsub vfD,vfA,vfB` | `vfD = ACC - vfA ×_outer vfB` |
| `vmadd vfD,vfA,vfB` | `vfD = ACC + vfA * vfB` |

---

## Lessons from Previous Phase

<!-- paste notes here before starting -->

---

## Function List ({len(funcs):,} functions)

{format_function_table(funcs, include_fpu=True)}

{_std_transition("phase6_mmio.md", "Phase 6")}"""
    path = output_dir / "phase5_acc_hazard.md"
    path.write_text(md, encoding="utf-8")
    return path, len(funcs)


def generate_phase6(funcs, data, output_dir):
    total_size = sum(r["size"] for r in funcs)
    tte_funcs  = [r for r in funcs if "DMA_CHAIN_TTE_RISK" in r["tag_list"]]

    tte_section = ""
    if tte_funcs:
        tte_section = f"""
### DMA_CHAIN_TTE_RISK Sub-group ({len(tte_funcs)}) — ⚠️ Phase F7 lesson

These functions both call a `sceDmaSend*` variant AND access the VIF1 DMA channel
MMIO range (`0x10009000`). DC2 embeds meaningful VIFcodes in DMA-tag upper 64 bits
even when `CHCR.TTE = 0` (bit 6 clear). The runtime's chain walker must force-inject
`tagHi64` into the VIF1 stream when non-zero — even without TTE.

**Checklist before fixing:**
- Confirm `ps2_memory.cpp` L~950: VIF1 channel force-injects `tagHi64` when non-zero.
- If DMA submission produces zero GS register writes, add `[TTE:inject]` trace around the injection.
- Do NOT set TTE bit in guest CHCR — that changes game-visible state.

| Address | Name |
|---------|------|
""" + "\n".join(f"| `{r['address']}` | `{r['name']}` |" for r in tte_funcs) + "\n"

    # F13 lesson: sceDmaSync
    dma_sync_section = """
### sceDmaSync — Phase F13 lesson (non-blocking stub)

`sceDmaSync_0x104b60` (and any other `sceDmaSync` variant) must return **immediately**.
All DMA transfers in the runtime are synchronous — by the time the game calls sceDmaSync,
the channel has already finished.

**Correct stub pattern** (in `dc2_game_override.cpp` or the `.cpp` recomp file):
```cpp
// sceDmaSync — non-blocking. All DMA is synchronous in the runtime.
// $a0 = channel number (ignored). Returns 0 (success).
setReturnS32(ctx, 0);
```

If the current stub spins on a channel-status register poll, replace the entire body with the
one-liner above. If it is bound via `registerFunction`, update that binding to a `nop_stub`
or a zero-return shim.
"""

    md = _header("Phase 6: MMIO — Hardware Register Access Functions", data) + f"""
## Overview

- **Total functions:** {len(funcs):,}
- **Total code size:** {total_size:,} bytes ({total_size/1024:.1f} KB)
- **DMA_CHAIN_TTE_RISK:** {len(tte_funcs)}
- **Expected difficulty:** VERY HIGH.
- **Skill file required:** YES — read `/ps2-recomp-Agent-SKILL-0.4.3/` first.

---
{tte_section}
{dma_sync_section}
---

## General Instructions

1. `cmake --build build64/`. Functions that compile clean → skip.
2. Identify registers accessed: `grep -A 100 "ADDR" assembly.txt`
3. Strategies per access:
   - **Stub (no-op):** DMA sync waits, polling loops → return 0.
   - **HLE:** Texture uploads, GS state writes → translate to runtime API.
   - **Flag:** `// TODO: MMIO — 0xADDR — needs HLE implementation`

| Range | Hardware |
|-------|----------|
| `0x10000000-0x10001FFF` | EE Timers, INTC, SIF |
| `0x10003000-0x10003FFF` | GIF |
| `0x10008000-0x1000EFFF` | DMA channels |
| `0x10009000-0x1000903F` | VIF1 channel ← TTE risk zone |
| `0x12000000-0x12001FFF` | GS privileged |
| `0x70000000-0x70003FFF` | Scratchpad RAM |

---

## Lessons from Previous Phase

<!-- paste notes here before starting -->

---

## Function List ({len(funcs):,} functions)

{format_function_table(funcs, include_fpu=True)}

{_std_transition("phase7_vu0_microcode.md", "Phase 7")}"""
    path = output_dir / "phase6_mmio.md"
    path.write_text(md, encoding="utf-8")
    return path, len(funcs)


def generate_phase7(funcs, data, output_dir):
    total_size = sum(r["size"] for r in funcs)
    md = _header("Phase 7: VU0 Microcode — vcallms/vcallmsr Functions", data) + f"""
## Overview

- **Total functions:** {len(funcs):,}
- **Total code size:** {total_size:,} bytes ({total_size/1024:.1f} KB)
- **Expected difficulty:** EXTREME.
- **Skill files required:** `/ps2-recomp-Agent-SKILL-0.4.3/` AND `db-vu-instructions.md`

---

## Instructions for Claude

⚠️ Read BOTH skill files before touching any function.

1. `cmake --build build64/`. Functions that compile clean → skip.
2. For each `vcallms`: find the target address → determine what the microprogram does.
3. Known patterns → replace with C++ math. Unknown → stub with TODO.
4. A stubbed function counts as done.

```cpp
// vcallms 0x0000 — VU0 microprogram: matrix multiply
// Replaces VU0 micro mode execution with C++ equivalent
result = matrix * vector;
```

---

## Lessons from Previous Phase

<!-- paste notes here before starting -->

---

## Function List ({len(funcs):,} functions)

{format_function_table(funcs, include_fpu=True)}

---

## Project Completion

When all Phase 7 functions compile:
1. Write `phase7_lessons.md` — document VU0 patterns found.
2. Write `project_summary.md` — all phases, total functions, remaining TODOs.
3. Report completion to the user.
"""
    path = output_dir / "phase7_vu0_microcode.md"
    path.write_text(md, encoding="utf-8")
    return path, len(funcs)


# =========================================================
# v3 NEW: PHASE_GIFPK
# =========================================================

def generate_phase_gifpk(funcs, data, output_dir):
    """sceGifPk* / sceVif1Pk* packet-builder functions — from ps2_stubs_gifpk.inl."""
    total_size = sum(r["size"] for r in funcs)

    # Context-struct layouts (copied from ps2_stubs_gifpk.inl header)
    gifpk_layout = """
### sceGifPkContext layout (16 bytes, 64-byte aligned in guest RAM)

| Offset | Field  | Type     | Meaning                        |
|--------|--------|----------|--------------------------------|
| +0     | buf    | uint32_t | Buffer start PS2 address       |
| +4     | ptr    | uint32_t | Current write position         |
| +8     | ptag   | uint32_t | Open GIFtag PS2 addr (0=none)  |
| +12    | nloop  | uint32_t | NLOOP accumulator              |

### sceVif1PkContext layout (28 bytes, 64-byte aligned)

| Offset | Field       | Type     | Meaning                               |
|--------|-------------|----------|---------------------------------------|
| +0     | buf         | uint32_t | Buffer start PS2 address              |
| +4     | ptr         | uint32_t | Current write position                |
| +8     | dmatag      | uint32_t | Open DMA CNT tag addr (0=none)        |
| +12    | qwc         | uint32_t | QWC accumulator for open DMA tag      |
| +16    | gif_ptag    | uint32_t | Open GIFtag addr inside DIRECT block  |
| +20    | gif_nloop   | uint32_t | NLOOP accumulator for open GIFtag     |
| +24    | direct_vif  | uint32_t | Open DIRECT VIFcode addr (0=none)     |
"""

    md = _header("Phase GifPk: sceGifPk* / sceVif1Pk* Packet Builders", data) + f"""
## Overview

- **Total functions:** {len(funcs):,}
- **Total code size:** {total_size:,} bytes ({total_size/1024:.1f} KB)
- **What these are:** The GIF/VIF1 packet-builder library (`ps2_stubs_gifpk.inl`).
  These assemble DMA chains + GIF packets in guest RAM that are later kicked to VIF1/GIF.
- **Expected difficulty:** MEDIUM — context-struct layout must match exactly.
- **Reference file:** `ps2_stubs_gifpk.inl` — read the header comment block before touching
  any function. The struct layouts are the contract between the game and the builders.

---

## Critical: Context Struct Layout

{gifpk_layout}

---

## Instructions for Claude

### Before touching any function
1. Read the header of `ps2_stubs_gifpk.inl` (first 75 lines) for field offsets.
2. Confirm `pkRead32` / `pkWrite32` helpers are present in the `.inl` — these do
   plain `Ps2FastRead32/Ps2FastWrite32` on `(base + field_offset)`.

### Verification workflow (F10 acceptance criteria)
After implementing or correcting any builder:
1. Run the game for 10 seconds.
2. In stderr, look for:
   - `mscal > 0`  — VU1 microcode kicked (builders assembled a valid MSCAL).
   - `gif > 0`    — GIF DMA channel fired.
   - `XYZ2 > 0`  — GS received vertex data.
3. If `dma > 3` but `gif = 0`, the DIRECT VIFcode IMMED is still 0 — check
   `sceVif1PkCloseDirectCode` backpatch logic.
4. If `gif > 0` but `XYZ2 = 0`, the GIFtag REGS nibble-list is zeroed — check
   `sceVif1PkOpenGifTag` tag-word construction.

### Common mistakes
| Mistake | Symptom | Fix |
|---------|---------|-----|
| Wrong field offset for `ptr` | ptr never advances → packet overwritten | Check `kGifPk_ptr = 4u`, `kVif1Pk_ptr = 4u` |
| `NLOOP` not backpatched | GIF receives NLOOP=0 → no draw | `sceGifPkCloseGifTag` must call `pkPatchNloop` |
| DIRECT VIFcode IMMED=0 | GIF receives zero qwords | `sceVif1PkCloseDirectCode` backpatch: `(ptr - vifAddr - 16) / 16` |
| DMA CNT QWC not patched | DMA chain sends 0 qwords | `vif1CloseDmaTag` must patch `lo32 = (1u<<24)|qwc` |
| `sceGifPkRefLoadImage` delegates to wrong callee | texture upload silently dropped | Must delegate to `sceGsExecLoadImage` |

### Function call order in a typical frame
```
sceVif1PkInit         → set up context
sceVif1PkCnt          → open DMA CNT tag
sceVif1PkOpenDirectCode → open DIRECT VIFcode
sceVif1PkOpenGifTag   → open GIFtag (A+D format)
sceVif1PkAddGsAD      → add GS register + data pairs   (×N)
sceVif1PkCloseGifTag  → backpatch NLOOP
sceVif1PkCloseDirectCode → backpatch DIRECT IMMED
sceVif1PkEnd          → backpatch CNT QWC, write END tag
sceDmaSend            → kick the assembled chain to VIF1
```

---

## Lessons from Previous Phase

<!-- paste notes here before starting -->

---

## Function List ({len(funcs):,} functions)

{format_function_table(funcs, include_fpu=False)}

{_std_transition("phase_iop_rpc.md", "Phase IOP RPC")}"""
    path = output_dir / "phase_gifpk.md"
    path.write_text(md, encoding="utf-8")
    return path, len(funcs)


# =========================================================
# v3 NEW: PHASE_IOP_RPC
# =========================================================

def generate_phase_iop_rpc(funcs, data, output_dir):
    total_size = sum(r["size"] for r in funcs)
    known_sids = data.get("known_iop_sids", {})

    sid_table = ""
    if known_sids:
        sid_table = "### Known IOP SIDs (from ps2_iop.h)\n\n| SID | Name |\n|-----|------|\n"
        for sid, name in known_sids.items():
            sid_table += f"| `{sid}` | `{name}` |\n"

    md = _header("Phase IOP RPC: sceSifCallRpc / sceSifBindRpc Dispatch Functions", data) + f"""
## Overview

- **Total functions:** {len(funcs):,}
- **Total code size:** {total_size:,} bytes ({total_size/1024:.1f} KB)
- **What these are:** Functions that call into the IOP via SIF RPC. They call `sceSifBindRpc`
  (bind a service) or `sceSifCallRpc` (call a bound service) and block until the IOP responds.
- **Expected difficulty:** HIGH — requires matching each SID to a handler in `ps2_iop.cpp`.

---

## Architecture

```
Game EE code
  → sceSifCallRpc(sid=0xXXXX, rpcNum=0xYYYY, sendBuf, sendSize, recvBuf, recvSize)
  → ps2_iop::handleRPC(sid, rpcNum, ...)
      → handleEzMidiRpc(sid, rpcNum, ...)   if sid == DC2_EzMidi_rpcSid (0x00012346)
      → handleSoundDriverRpcService(...)     if sid == IOP_SID_SNDDRV_*
      → handleLibSdRpc(...)                  if sid == IOP_SID_LIBSD (0x80000701)
```

{sid_table}

---

## Instructions for Claude

1. For each function, search for the SID constant:
   ```bash
   grep -A 30 "FUNCTION_ADDR" assembly.txt | grep -iE "lui|addiu|li"
   ```
2. Match the SID to `known_iop_sids` above.
3. If the SID is already handled in `ps2_iop.cpp::handleRPC`: the function just needs
   to compile — the dispatch is in the runtime.
4. If the SID is **unknown**: add it to `known_iop_sids` in the Java script AND add a
   new `case` in `handleRPC`.
5. Check `detected_rpc_sid` field in `triage_map.json`:
   ```bash
   grep -B2 -A5 "FUNCTION_NAME" triage_map.json | grep detected_rpc_sid
   ```
   A non-null value means the Java script already found the SID literal.

### EzMIDI lesson (Phase F9/F12)
- `kEzMidiCmdInit` reply buffer word[0] **must be non-zero** (`0x00100000` is used in DC2).
  If `iopMSINBuffAddr = 0` appears in stderr, the init reply is missing.
- `kEzMidiCmdGetStatus` reply: word[0]=status, word[1]=loaded, word[2]=dataSize.
- All 18 EzMidi command families are handled in `ps2_iop.cpp::handleEzMidiRpc`.

---

## Lessons from Previous Phase

<!-- paste notes here before starting -->

---

## Function List ({len(funcs):,} functions)

{format_function_table(funcs, include_fpu=False)}

{_std_transition("phase_archive_io.md", "Phase Archive IO")}"""
    path = output_dir / "phase_iop_rpc.md"
    path.write_text(md, encoding="utf-8")
    return path, len(funcs)


# =========================================================
# v3 NEW: PHASE_ARCHIVE_IO
# =========================================================

def generate_phase_archive_io(funcs, data, output_dir):
    total_size = sum(r["size"] for r in funcs)
    md = _header("Phase Archive IO: DATA.DAT / DATA.HD2 Archive-Backed Functions", data) + f"""
## Overview

- **Total functions:** {len(funcs):,}
- **Total code size:** {total_size:,} bytes ({total_size/1024:.1f} KB)
- **What these are:** Functions that reference `DATA.DAT` or `DATA.HD2` strings.
  These open files that live inside the game's archive, not at the ISO root.
- **Expected difficulty:** MEDIUM — the archive reader in `ps2_syscalls_fileio.inl`
  must be working before these functions can be tested.

---

## Architecture (Phase F6 lesson)

```
fioOpen("meswin/system_1.mes")
  → isoFindFileForFio miss (not at ISO root)
  → DATA.HD2 index lookup (32-byte entries: nameOffset@+0, byteOffset@+0x10, size@+0x14)
  → IsoFdEntry with baseOffset pointing into DATA.DAT
  → fioRead/fioLseek via sector-aligned reads into DATA.DAT
```

**Entry count** = `firstNameOffset / 32` = 6692 entries for DC2.  
**String table** follows the index array inside DATA.HD2.

---

## Instructions for Claude

1. Confirm `fioOpen` archive fallback is working: look for `[Phase F6:archive]` lines in stderr.
   If absent, the index loader hasn't fired — fix `ps2_syscalls_fileio.inl` first.
2. For each function: compile normally. Archive lookup is transparent to the function itself.
3. If a function opens a path with `GetFullPath__FPcPc`: ensure the shim in
   `dc2_game_override.cpp` prepends `"cdrom0:\\"` to bare filenames (Phase F5 fix).

### Common mistake — args reversed (Phase F5)
`GetFullPath__FPcPc` had `$a0` / `$a1` swapped: output buffer was never written → `fioOpen("")`.
If you see any function with `CONVENTION_VIOLATION` tag (`ARG!`) that also has
`ARCHIVE_IO` tag (`ARC`), check arg order in the call to `GetFullPath` carefully.

---

## Lessons from Previous Phase

<!-- paste notes here before starting -->

---

## Function List ({len(funcs):,} functions)

{format_function_table(funcs, include_fpu=False)}

{_std_transition("phase1_safe_leaf.md", "Phase 1 (cycle back if needed)")}"""
    path = output_dir / "phase_archive_io.md"
    path.write_text(md, encoding="utf-8")
    return path, len(funcs)


def generate_orphan(funcs, data, output_dir):
    total_size = sum(r["size"] for r in funcs)
    md = _header("Orphan Code — Zero-Reference Functions", data) + f"""
## Overview

- **Total functions:** {len(funcs):,}
- **Total code size:** {total_size:,} bytes ({total_size/1024:.1f} KB)
- **What these are:** Functions with zero incoming references — likely dead code,
  debug utilities, or functions reachable only via unresolved jump tables.

---

## Instructions

Do NOT fix these proactively. Come here only when:
- A compilation error in another phase references one of these.
- The game crashes and a stack trace lands on one of these addresses.
- A function name here suggests it is critical (`init`, `main`, `update`, `callback`).

---

## Function List ({len(funcs):,} functions)

{format_function_table(funcs, include_fpu=False) if funcs else "*(No orphan functions in this build.)*"}
"""
    path = output_dir / "orphan_code.md"
    path.write_text(md, encoding="utf-8")
    return path, len(funcs)


# =========================================================
# MAIN PHASE GENERATION ENTRY POINT
# =========================================================

def generate_phases(data, rows, output_dir):
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    phases = classify_phases(rows)

    generators = {
        "phase1_safe_leaf":       generate_phase1,
        "phase2_wrappers":        generate_phase2,
        "phase3_math":            generate_phase3,
        "phase4a_game_logic":     generate_phase4a,
        "phase4b_state_machines": generate_phase4b,
        "phase5_acc_hazard":      generate_phase5,
        "phase6_mmio":            generate_phase6,
        "phase7_vu0_microcode":   generate_phase7,
        # v3 new
        "phase_gifpk":            generate_phase_gifpk,
        "phase_iop_rpc":          generate_phase_iop_rpc,
        "phase_archive_io":       generate_phase_archive_io,
        "orphan_code":            generate_orphan,
    }

    results = {}
    for key, gen_fn in generators.items():
        func_list = phases.get(key, [])
        path, count = gen_fn(func_list, data, output_dir)
        results[key] = (path, count)
        print(f"  [{count:>5d} funcs] → {path.name}")

    return results


# =========================================================
# SUMMARY MD  (v3: shows game_override, known_iop_sids, new tags)
# =========================================================

def generate_summary(data, rows, phases_results, output_dir):
    stats      = data.get("statistics", {})
    ov_addrs   = data.get("game_override_addresses", [])
    known_sids = data.get("known_iop_sids", {})
    text_range = data.get("text_range", {})

    stub_rows  = [r for r in rows if r["disposition"] == "STUB"]
    skip_rows  = [r for r in rows if r["disposition"] == "SKIP"]
    recomp_rows= [r for r in rows if r["disposition"] == "RECOMPILE"]

    # v3 tag counts from rows (in case stats block is missing)
    def tag_count(tag):
        return sum(1 for r in rows if tag in r["tag_list"])

    sid_table = ""
    if known_sids:
        sid_table = "\n### Known IOP SIDs\n\n| SID | Name |\n|-----|------|\n"
        for sid, name in known_sids.items():
            sid_table += f"| `{sid}` | `{name}` |\n"

    ov_table = ""
    if ov_addrs:
        shown = ov_addrs[:20]
        ov_table = f"\n### Game Override Pre-bound Addresses (first {len(shown)} of {len(ov_addrs)})\n\n"
        ov_table += "| Address | Bound Name |\n|---------|------------|\n"
        for entry in shown:
            ov_table += f"| `{entry.get('address','')}` | `{entry.get('bound_name','')}` |\n"
        if len(ov_addrs) > 20:
            ov_table += f"\n*(… and {len(ov_addrs)-20} more — see triage_map.json `game_override_addresses`)*\n"

    phase_summary = ""
    for key, (path, count) in phases_results.items():
        phase_summary += f"| `{path.name}` | {count:,} |\n"

    md = f"""# PS2Recomp Triage Summary

**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  
**ELF Hash:** {data.get('elf_hash','N/A')}  
**Schema version:** {data.get('schema_version', 1)}  
**Global Pointer:** `{data.get('global_pointer','unknown')}`  
**Text range:** `{text_range.get('start','?')}` – `{text_range.get('end','?')}`  

---

## Disposition Breakdown

| Disposition | Count |
|-------------|------:|
| RECOMPILE   | {len(recomp_rows):,} |
| STUB        | {len(stub_rows):,} |
| SKIP        | {len(skip_rows):,} |
| **Total**   | **{len(rows):,}** |

---

## Tag Breakdown (v2 + v3)

| Tag | Count |
|-----|------:|
| SAFE_LEAF | {stats.get('safe_leaf', tag_count('SAFE_LEAF')):,} |
| ACC_PRECISION_HAZARD | {stats.get('acc_hazard', tag_count('ACC_PRECISION_HAZARD')):,} |
| ACCESSES_MMIO | {stats.get('mmio_access', tag_count('ACCESSES_MMIO')):,} |
| SMC_HAZARD | {stats.get('smc_hazard', tag_count('SMC_HAZARD')):,} |
| SPR_SYNC_HAZARD | {stats.get('spr_sync', tag_count('SPR_SYNC_HAZARD')):,} |
| BUSY_WAIT_HAZARD | {stats.get('busy_wait', tag_count('BUSY_WAIT_HAZARD')):,} |
| VU0_MICROCODE | {stats.get('vcallms', tag_count('VU0_MICROCODE')):,} |
| COMPLEX_CONTROL_FLOW | {stats.get('jump_tables', tag_count('COMPLEX_CONTROL_FLOW')):,} |
| ORPHAN_CODE | {stats.get('orphan_code', tag_count('ORPHAN_CODE')):,} |
| CONVENTION_VIOLATION *(v3)* | {stats.get('convention_violation', tag_count('CONVENTION_VIOLATION')):,} |
| INIT_LARGE_FUNC *(v3)* | {stats.get('init_large_func', tag_count('INIT_LARGE_FUNC')):,} |
| DMA_CHAIN_TTE_RISK *(v3)* | {stats.get('dma_tte_risk', tag_count('DMA_CHAIN_TTE_RISK')):,} |
| IOP_RPC_DISPATCH *(v3)* | {stats.get('iop_rpc_dispatch', tag_count('IOP_RPC_DISPATCH')):,} |
| ARCHIVE_IO *(v3)* | {stats.get('archive_io', tag_count('ARCHIVE_IO')):,} |
| PAD_POLL_LOOP *(v3)* | {stats.get('pad_poll_loop', tag_count('PAD_POLL_LOOP')):,} |

---

## Phase Files Generated

| File | Functions |
|------|----------:|
{phase_summary}

---

## Game Override Status

**Pre-bound by dc2_game_override.cpp:** {data.get('game_override_imported', 0)}  
*(These addresses are excluded from triage — they already have runtime bindings.)*
{ov_table}
{sid_table}

---

## Top 20 Most Complex RECOMPILE Functions

{format_function_table(sorted(recomp_rows, key=lambda r: r.get('_score', compute_priority_score(r)), reverse=True)[:20], include_fpu=True)}

---

## Top 10 CONVENTION_VIOLATION Functions (check arg order)

{format_function_table([r for r in rows if 'CONVENTION_VIOLATION' in r['tag_list']][:10], include_fpu=False)}

---

## Top 10 INIT_LARGE_FUNC (must not be nop-stubbed)

{format_function_table([r for r in rows if 'INIT_LARGE_FUNC' in r['tag_list']][:10], include_fpu=False)}

---

## Phase F13 Readiness Checklist

- [ ] `sceDmaSync` stub returns 0 immediately (non-blocking)
- [ ] Debug instrumentation removed from TTY.cpp, LibC.cpp, sceGsSwapDBuff, WaitVSync
- [ ] `sceGsSwapDBuff` called ≥ 3 times in a 10-second run
- [ ] `mgEndFrame` frame loop not stalling after first swap
- [ ] `init__Fv_0x15C160` (INIT_LARGE_FUNC) deferred until frame loop confirmed at 60 Hz
"""
    path = output_dir / "summary.md"
    path.write_text(md, encoding="utf-8")
    return path


# =========================================================
# CLI COMMANDS (unchanged API, v3 adds new --tag values)
# =========================================================

def cmd_stats(data, rows):
    stats = data.get("statistics", {})
    print(f"\n=== PS2Recomp Triage Stats (schema v{data.get('schema_version',1)}) ===")
    print(f"ELF hash          : {data.get('elf_hash','N/A')}")
    print(f"Total functions   : {stats.get('total_functions', len(rows)):,}")
    print(f"Enriched (triage) : {stats.get('enriched_count', len(rows)):,}")
    print(f"Game override     : {data.get('game_override_imported', 0)}")
    print()
    for key, val in stats.items():
        if key not in ("total_functions","enriched_count","uncategorized_from_step1"):
            print(f"  {key:<30s}: {val:,}")
    by_disp = {}
    for r in rows:
        by_disp[r["disposition"]] = by_disp.get(r["disposition"], 0) + 1
    print()
    for d, c in sorted(by_disp.items()):
        print(f"  {d:<12s}: {c:,}")


def cmd_top(data, rows, field, n):
    scored = []
    for r in rows:
        val = r.get(field)
        if val is None:
            val = r.get("metrics", {}).get(field) or r.get("hardware", {}).get(field) or 0
        scored.append((val, r))
    scored.sort(reverse=True, key=lambda x: x[0])
    print(f"\nTop {n} by '{field}':")
    for val, r in scored[:n]:
        print(f"  {val:>8} | {r['address']:>12s} | {r['disposition']:>10s} | {r['name']}")


def cmd_query(data, rows, tag=None, disposition=None, name_contains=None, min_size=None):
    results = rows
    if tag:
        results = [r for r in results if tag in r["tag_list"]]
    if disposition:
        results = [r for r in results if r["disposition"] == disposition]
    if name_contains:
        results = [r for r in results if name_contains.lower() in r["name"].lower()]
    if min_size:
        results = [r for r in results if r["size"] >= min_size]
    print(f"\nQuery results: {len(results)} functions")
    for r in sorted(results, key=lambda x: -x["size"])[:50]:
        print(f"  {r['address']:>12s} | {r['disposition']:>10s} | {r['size']:>6d} | "
              f"{', '.join(r['tag_list'])[:50]:50s} | {r['name']}")
    if len(results) > 50:
        print(f"  ... and {len(results)-50} more.")


def cmd_report(data, rows, output_path=None):
    lines = [
        f"PS2Recomp Triage Report — {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"ELF Hash: {data.get('elf_hash','N/A')} | Schema v{data.get('schema_version',1)}",
        "=" * 80,
    ]
    by_disp = {}
    for r in rows:
        by_disp.setdefault(r["disposition"], []).append(r)
    for disp, funcs in sorted(by_disp.items()):
        lines.append(f"\n--- {disp} ({len(funcs):,} functions) ---")
        for r in sorted(funcs, key=lambda x: -x["size"])[:100]:
            lines.append(
                f"  {r['address']:>12s} | {r['size']:>6d}B | "
                f"{', '.join(r['tag_list'])[:40]:40s} | {r['name']}"
            )
        if len(funcs) > 100:
            lines.append(f"  ... and {len(funcs)-100} more.")
    text = "\n".join(lines)
    if output_path:
        Path(output_path).write_text(text, encoding="utf-8")
        print(f"Report written to {output_path}")
    else:
        print(text)


# =========================================================
# DOUBLE-CLICK / NO-ARG ENTRY POINT
# =========================================================

def run_double_click_mode(script_dir):
    candidates = list(Path(script_dir).glob("triage_map.json"))
    if not candidates:
        candidates = list(Path(".").glob("triage_map.json"))
    if not candidates:
        print("ERROR: triage_map.json not found next to triage_analyzer.py")
        input("Press Enter to exit.")
        return

    json_path = candidates[0]
    print(f"Loading: {json_path}")
    data = load_triage(json_path)
    rows = flatten_functions(data)

    sv = data.get("schema_version", 1)
    print(f"Schema version: {sv} | Functions: {len(rows):,} | "
          f"Override pre-bound: {data.get('game_override_imported',0)}")
    if sv < 3:
        print("WARNING: schema_version < 3. Run PS2Recomp_TriageEnricher.java v3 to get "
              "CONVENTION_VIOLATION / INIT_LARGE_FUNC / DMA_CHAIN_TTE_RISK / "
              "IOP_RPC_DISPATCH / ARCHIVE_IO / PAD_POLL_LOOP tags.")

    output_dir = json_path.parent / "phase_docs"
    print(f"Output dir: {output_dir}")

    phases_results = generate_phases(data, rows, output_dir)
    summary_path   = generate_summary(data, rows, phases_results, output_dir)
    print(f"\n[DONE] Summary: {summary_path}")
    print(f"       {len(phases_results)} phase files in: {output_dir}")
    input("\nPress Enter to exit.")


# =========================================================
# MAIN
# =========================================================

def main():
    if len(sys.argv) < 2:
        run_double_click_mode(os.path.dirname(os.path.abspath(__file__)))
        return

    parser = argparse.ArgumentParser(description="PS2Recomp Triage Analyzer v3")
    parser.add_argument("json", help="Path to triage_map.json")
    sub = parser.add_subparsers(dest="cmd")

    sub.add_parser("stats", help="Print statistics")

    p_top = sub.add_parser("top", help="Top N functions by field")
    p_top.add_argument("field", help="Field name (e.g. fpu_ops, size, acc_ops, xref_to_count)")
    p_top.add_argument("n", type=int, nargs="?", default=20)

    p_q = sub.add_parser("query", help="Filter functions")
    p_q.add_argument("--tag",           help="Filter by tag (e.g. BUSY_WAIT_HAZARD, PAD_POLL_LOOP, DMA_CHAIN_TTE_RISK, IOP_RPC_DISPATCH, INIT_LARGE_FUNC, CONVENTION_VIOLATION)")
    p_q.add_argument("--disposition",   help="Filter by disposition (RECOMPILE/STUB/SKIP)")
    p_q.add_argument("--name-contains", help="Filter by name substring")
    p_q.add_argument("--min-size",      type=int, help="Minimum function size in bytes")

    p_r = sub.add_parser("report", help="Generate text report")
    p_r.add_argument("--output", help="Output file path (default: stdout)")

    p_ph = sub.add_parser("phases", help="Generate all phase MD files")
    p_ph.add_argument("--output-dir", default="phase_docs")

    args = parser.parse_args()

    data = load_triage(args.json)
    rows = flatten_functions(data)

    sv = data.get("schema_version", 1)
    if sv < 3 and args.cmd not in (None, "stats"):
        print(f"Note: schema_version={sv}. Re-run TriageEnricher v3 for full v3 tag support.")

    if args.cmd == "stats":
        cmd_stats(data, rows)
    elif args.cmd == "top":
        cmd_top(data, rows, args.field, args.n)
    elif args.cmd == "query":
        cmd_query(data, rows,
                  tag=args.tag,
                  disposition=args.disposition,
                  name_contains=args.name_contains,
                  min_size=args.min_size)
    elif args.cmd == "report":
        cmd_report(data, rows, args.output)
    elif args.cmd == "phases":
        phases_results = generate_phases(data, rows, args.output_dir)
        generate_summary(data, rows, phases_results, args.output_dir)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
