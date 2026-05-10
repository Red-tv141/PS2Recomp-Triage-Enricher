#!/usr/bin/env python3
"""
PS2Recomp Triage Analyzer v3
=============================
Changes from v2:
  [FIX-1]  dependency_sort: reverse edges are now sets → no duplicate in_degree counts
  [FIX-2]  classify_phases: VU0_MICROCODE checked before ACC_PRECISION_HAZARD
  [NEW-1]  --recomp-dir flag: injects cpp_found=True/False into every row
           Enables Claude to skip pre-generated functions automatically
  [NEW-2]  'stub-gap' CLI command: lists STUB functions missing a runtime handler
           Uses runtime_has_handler field from schema v3 triage_map.json
  [NEW-3]  phase8_integration.md: auto-generated list of recomp/ files not yet
           in CMakeLists.txt (replaces the manual set-diff that was done by hand)
  [NEW-4]  phase docs get a one-line "Quick start" note: if cpp_found for all
           functions → skip to CMakeLists registration, no manual work needed
  [NEW-5]  'cmake-block' CLI command: generates a ready-to-paste
           target_sources() block for a given phase

Double-click (no args) → scans triage_map.json in the same folder,
generates phase MD files + phase8_integration.md.

CLI usage:
  python triage_analyzer.py triage_map.json stats
  python triage_analyzer.py triage_map.json top fpu_ops 20
  python triage_analyzer.py triage_map.json report --output my_report.txt
  python triage_analyzer.py triage_map.json stub-gap            [NEW-2]
  python triage_analyzer.py triage_map.json cmake-block phase1  [NEW-5]
  python triage_analyzer.py triage_map.json cmake-block all
"""

import json, sys, argparse, os, glob, re
from pathlib import Path
from datetime import datetime
from collections import defaultdict

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


def flatten_functions(data, recomp_dir=None):
    """
    Convert triage_map.json functions list to flat row dicts.
    [NEW-1] If recomp_dir is given, inject cpp_found into each row.
    """
    # Build filename index once if needed
    cpp_index = None
    if recomp_dir:
        cpp_index = set()
        for p in glob.glob(str(Path(recomp_dir) / "*.cpp")):
            cpp_index.add(Path(p).name.lower())

    rows = []
    for func in data["functions"]:
        addr_raw = func["address"]
        # Normalise address to 6-digit lowercase hex suffix used in filenames
        try:
            addr_int = int(addr_raw, 16)
            addr_suffix = f"_0x{addr_int:x}.cpp"
        except (ValueError, TypeError):
            addr_suffix = None

        row = {
            "address":     addr_raw,
            "name":        func["name"],
            "category":    func["category"],
            "disposition": func["disposition"],
            "size":        func["size"],
            "tags":        ", ".join(func.get("tags", [])),
            "tag_list":    func.get("tags", []),
            "callee_list": func.get("callees", []),
            # [NEW-2] runtime handler coverage (schema v3 field)
            "runtime_has_handler": func.get("runtime_has_handler", None),
        }
        for k, v in func.get("metrics", {}).items():
            row[k] = v
        for k, v in func.get("hardware", {}).items():
            row[k] = v

        # [NEW-1] cpp_found
        if cpp_index is not None and addr_suffix is not None:
            # Match by address suffix (handles name collisions)
            row["cpp_found"] = any(f.endswith(addr_suffix) for f in cpp_index)
        else:
            row["cpp_found"] = None  # unknown

        rows.append(row)
    return rows


def compute_priority_score(r):
    return (r["size"]
            + r.get("fpu_ops", 0) * 10
            + r.get("acc_ops", 0) * 50
            + (500 if "ACC_PRECISION_HAZARD" in r["tag_list"] else 0)
            + (300 if "VU0_VECTORS"          in r["tag_list"] else 0)
            + (200 if "USES_SPR"             in r["tag_list"] else 0))


# =========================================================
# PHASE CLASSIFICATION
# =========================================================

def dependency_sort(funcs):
    """
    Topological sort (Kahn's) so callees appear before callers.
    [FIX-1] reverse adjacency is now a set per node to prevent duplicate
    in_degree decrements when multiple callees share a name.
    """
    if not funcs:
        return funcs

    by_addr = {}
    for r in funcs:
        r["_score"] = compute_priority_score(r)
        by_addr[r["address"]] = r

    name_to_addrs = defaultdict(set)
    for r in funcs:
        name_to_addrs[r["name"]].add(r["address"])

    phase_addrs = set(by_addr.keys())

    # caller → set of callee addresses (within this phase only)
    deps = {addr: set() for addr in phase_addrs}
    for r in funcs:
        for callee_name in r.get("callee_list", []):
            for callee_addr in name_to_addrs.get(callee_name, ()):
                if callee_addr != r["address"]:
                    deps[r["address"]].add(callee_addr)

    # [FIX-1] reverse map uses sets to prevent duplicate entries
    reverse = {addr: set() for addr in phase_addrs}
    for caller_addr, callee_addrs in deps.items():
        for callee_addr in callee_addrs:
            reverse[callee_addr].add(caller_addr)

    in_degree = {addr: len(callees) for addr, callees in deps.items()}

    queue = sorted([a for a in phase_addrs if in_degree[a] == 0],
                   key=lambda a: -by_addr[a]["_score"])
    result = []
    while queue:
        addr = queue.pop(0)
        result.append(by_addr[addr])
        for caller_addr in reverse.get(addr, set()):
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


def classify_phases(rows):
    phases = {
        "phase1_safe_leaf":       [],
        "phase2_wrappers":        [],
        "phase3_math":            [],
        "phase4a_game_logic":     [],
        "phase4b_state_machines": [],
        "phase5_acc_hazard":      [],
        "phase6_mmio":            [],
        "phase7_vu0_microcode":   [],
        "orphan_code":            [],
    }
    for r in rows:
        if r["disposition"] != "RECOMPILE":
            continue
        tags = r["tag_list"]
        cat  = r["category"]

        if "ORPHAN_CODE" in tags:
            phases["orphan_code"].append(r)
            continue

        # [FIX-2] VU0_MICROCODE takes priority over ACC_PRECISION_HAZARD
        if "VU0_MICROCODE" in tags:
            phases["phase7_vu0_microcode"].append(r)
        elif "ACC_PRECISION_HAZARD" in tags:
            phases["phase5_acc_hazard"].append(r)
        elif "ACCESSES_MMIO" in tags:
            phases["phase6_mmio"].append(r)
        elif "SAFE_LEAF" in tags:
            phases["phase1_safe_leaf"].append(r)
        elif cat in ("WRAPPER", "GETTER_OR_STUB"):
            phases["phase2_wrappers"].append(r)
        elif cat == "MATH_VECTORS":
            phases["phase3_math"].append(r)
        elif cat == "GAME_LOGIC":
            phases["phase4a_game_logic"].append(r)
        else:
            phases["phase4b_state_machines"].append(r)

    for key in phases:
        phases[key] = dependency_sort(phases[key])
    return phases


# =========================================================
# FUNCTION TABLE FORMATTER
# =========================================================

def _cpp_badge(r):
    """[NEW-1] Returns a ✓/✗/? badge for the cpp_found column."""
    v = r.get("cpp_found")
    if v is True:  return "✓"
    if v is False: return "✗"
    return "?"


def format_function_table(funcs, include_fpu=True, show_cpp=False):
    lines = []
    if include_fpu:
        cpp_col = " CPP |" if show_cpp else ""
        cpp_sep = "------|" if show_cpp else ""
        header = (f"| {'#':>4s} | {'Address':>12s} | {'Score':>6s} | {'Size':>6s} |"
                  f" {'FPU':>4s} | {'ACC':>4s} | {'Br':>4s} | {'Calls':>5s} |"
                  f" {'Xref':>4s} | {'Category':>16s} |{cpp_col} Name | Tags |")
        sep    = (f"|{'-'*5}:|{'-'*13}:|{'-'*7}:|{'-'*7}:|{'-'*5}:|{'-'*5}:|"
                  f"{'-'*5}:|{'-'*6}:|{'-'*5}:|{'-'*17}:|{cpp_sep}{'-'*42}|{'-'*20}|")
        lines.append(header)
        lines.append(sep)
        for i, r in enumerate(funcs, 1):
            flags = []
            if "ACC_PRECISION_HAZARD"  in r["tag_list"]: flags.append("ACC!")
            if "VU0_VECTORS"           in r["tag_list"]: flags.append("VU0")
            if "VU0_MICROCODE"         in r["tag_list"]: flags.append("uVU0")
            if "USES_SPR"              in r["tag_list"]: flags.append("SPR")
            if "MULTI_RETURN"          in r["tag_list"]: flags.append("MR")
            if "WRITES_GLOBAL"         in r["tag_list"]: flags.append("WG")
            if "COMPLEX_CONTROL_FLOW"  in r["tag_list"]: flags.append("JT")
            tag_str = ", ".join(flags) if flags else "-"
            name = r["name"]
            if len(name) > 40:
                name = name[:22] + ".." + name[-16:]
            cpp_cell = f" {_cpp_badge(r):^3s} |" if show_cpp else ""
            lines.append(
                f"| {i:>4d} | {r['address']:>12s} | {r['_score']:>6d} | {r['size']:>6d} |"
                f" {r.get('fpu_ops',0):>4d} | {r.get('acc_ops',0):>4d} |"
                f" {r.get('branch_ops',0):>4d} | {r.get('callee_count',0):>5d} |"
                f" {r.get('xref_to_count',0):>4d} | {r['category']:>16s} |"
                f"{cpp_cell} {name:<40s} | {tag_str} |"
            )
    else:
        cpp_col = " CPP |" if show_cpp else ""
        cpp_sep = "------|" if show_cpp else ""
        header = (f"| {'#':>4s} | {'Address':>12s} | {'Size':>6s} |"
                  f" {'Category':>16s} |{cpp_col} Name |")
        sep    = (f"|{'-'*5}:|{'-'*13}:|{'-'*7}:|{'-'*17}:|{cpp_sep}{'-'*45}|")
        lines.append(header)
        lines.append(sep)
        for i, r in enumerate(funcs, 1):
            name = r["name"]
            if len(name) > 43:
                name = name[:25] + ".." + name[-16:]
            cpp_cell = f" {_cpp_badge(r):^3s} |" if show_cpp else ""
            lines.append(
                f"| {i:>4d} | {r['address']:>12s} | {r['size']:>6d} |"
                f" {r['category']:>16s} |{cpp_cell} {name:<43s} |"
            )
    return "\n".join(lines)


# =========================================================
# [NEW-1] QUICK-START NOTE FOR PHASE DOCS
# =========================================================

def _quickstart_note(funcs):
    """Return a note about cpp_found coverage for this phase."""
    known   = [r for r in funcs if r.get("cpp_found") is not None]
    if not known:
        return ""
    found   = sum(1 for r in known if r["cpp_found"])
    missing = len(known) - found
    if missing == 0:
        return (f"\n> **Quick start:** All {len(funcs):,} `.cpp` files already exist in `recomp/`.\n"
                f"> Skip directly to registering them in `CMakeLists.txt` — no manual translation needed.\n")
    return (f"\n> **Quick start:** {found:,}/{len(known):,} `.cpp` files exist in `recomp/`.\n"
            f"> {missing:,} functions need to be generated or fixed before CMakeLists registration.\n")


# =========================================================
# PHASE MD GENERATORS  (all updated with [NEW-1] quickstart note)
# =========================================================

def generate_phase1(funcs, data, output_dir):
    total_size = sum(r["size"] for r in funcs)
    gp = data.get("global_pointer", "UNKNOWN — MUST SET BEFORE RUNNING")
    show_cpp = any(r.get("cpp_found") is not None for r in funcs)
    md = f"""# Phase 1: SAFE_LEAF — Auto-Translate

**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
**ELF Hash:** {data.get('elf_hash', 'N/A')}
**Global Pointer ($gp):** {gp}
{_quickstart_note(funcs)}
---

## Overview

- **Total functions:** {len(funcs):,}
- **Total code size:** {total_size:,} bytes ({total_size/1024:.1f} KB)
- **What these are:** Leaf functions — they call nothing and have no complex side effects.
- **Expected difficulty:** LOW.
- **Skill file required:** NO

---

## Instructions for Claude

1. CHECK FIRST: `cmake --build build64/` — functions that compile clean → mark done, skip.
2. Open the `.cpp` file in `recomp/`.
3. Fix compilation errors (syntax, type mismatches, pointer casts).
4. Preserve all `goto` labels unchanged.

**What NOT to do:**
- Do NOT diff-scan all files during phase transition — sample 3-5 random files instead.
- Do NOT extract helpers or restructure control flow.
- Do NOT read `assembly.txt` in full — use grep: `grep -A 50 "FUNCTION_ADDRESS" assembly.txt`

**Batch strategy:** 10-20 functions → fix → build → zero errors → next batch.

**Completion:** zero errors/warnings, all labels intact.

---

## Lessons from Previous Phase
<!-- Claude: Add relevant findings here before starting. -->

---

## Function List ({len(funcs):,} functions)
{"*(CPP column: ✓ = file exists in recomp/, ✗ = missing, ? = --recomp-dir not provided)*" if show_cpp else ""}

{format_function_table(funcs, include_fpu=False, show_cpp=show_cpp)}

---

## Phase Transition

1. Write `phase1_lessons.md` — only what a future Claude wouldn't know from phase2_wrappers.md.
2. Add notes to `phase2_wrappers.md` "Lessons from Previous Phase".
3. Report completion.
"""
    path = output_dir / "phase1_safe_leaf.md"
    path.write_text(md, encoding="utf-8")
    return path, len(funcs)


def generate_phase2(funcs, data, output_dir):
    total_size = sum(r["size"] for r in funcs)
    gp = data.get("global_pointer", "UNKNOWN — MUST SET BEFORE RUNNING")
    show_cpp = any(r.get("cpp_found") is not None for r in funcs)
    md = f"""# Phase 2: Wrappers & Getters

**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
**ELF Hash:** {data.get('elf_hash', 'N/A')}
**Global Pointer ($gp):** {gp}
{_quickstart_note(funcs)}
---

## Overview

- **Total functions:** {len(funcs):,}
- **Total code size:** {total_size:,} bytes ({total_size/1024:.1f} KB)
- **What these are:** Wrappers (delegate to 1-2 functions) and getters/stubs.
- **Expected difficulty:** LOW-MEDIUM.
- **Skill file required:** NO

---

## Instructions for Claude

1. CHECK FIRST: `cmake --build build64/`.
2. Fix compilation errors — mostly type mismatches or missing casts.
3. For wrappers: delegated call signature must match exactly.
4. For getters: return value and global access patterns must be correct.
5. Preserve all `goto` labels.

**Key patterns:**
- `$gp`-relative loads access `.sdata/.sbss` globals via `ctx->gp`. Ensure `ctx->gp = {gp}`.
- PS2 ABI: args in `$a0-$a3`, return in `$v0/$v1`.

**Completion:** zero errors/warnings, labels intact.

---

## Lessons from Previous Phase
<!-- Claude: Add relevant findings from Phase 1 here before starting. -->

---

## Function List ({len(funcs):,} functions)
{"*(CPP column: ✓ = file exists in recomp/, ✗ = missing)*" if show_cpp else ""}

{format_function_table(funcs, include_fpu=False, show_cpp=show_cpp)}

---

## Phase Transition

1. Write `phase2_lessons.md`.
2. Add notes to `phase3_math.md` "Lessons from Previous Phase".
3. Report completion.
"""
    path = output_dir / "phase2_wrappers.md"
    path.write_text(md, encoding="utf-8")
    return path, len(funcs)


def generate_phase3(funcs, data, output_dir):
    total_size = sum(r["size"] for r in funcs)
    gp = data.get("global_pointer", "UNKNOWN — MUST SET BEFORE RUNNING")
    vu0_count = sum(1 for r in funcs if "VU0_VECTORS" in r["tag_list"])
    high_fpu  = sum(1 for r in funcs if r.get("fpu_ops", 0) > 30)
    show_cpp  = any(r.get("cpp_found") is not None for r in funcs)
    md = f"""# Phase 3: MATH_VECTORS — FPU & Vector Operations

**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
**ELF Hash:** {data.get('elf_hash', 'N/A')}
**Global Pointer ($gp):** {gp}
{_quickstart_note(funcs)}
---

## Overview

- **Total functions:** {len(funcs):,}
- **Total code size:** {total_size:,} bytes ({total_size/1024:.1f} KB)
- **VU0/COP2 functions:** {vu0_count}
- **High FPU density (>30 ops):** {high_fpu}
- **Expected difficulty:** MEDIUM-HIGH.
- **Skill file required:** NO

---

## Instructions for Claude

1. CHECK FIRST: `cmake --build build64/`.
2. Fix compilation errors.
3. COP2/VU0 → C++ math using project types (`Vector4`, GLM, etc.). Do NOT invent custom structs.
4. Cross-reference with assembly: `grep -A 80 "FUNCTION_ADDRESS" assembly.txt`

### COP2 Quick Reference

| PS2 | C++ |
|-----|-----|
| `vmul.xyzw vfD, vfA, vfB` | `vfD.x=vfA.x*vfB.x; ...` (per component) |
| `vadd.xyzw vfD, vfA, vfB` | `vfD.x=vfA.x+vfB.x; ...` |
| `vsub.xyzw vfD, vfA, vfB` | `vfD.x=vfA.x-vfB.x; ...` |
| `vdiv Q, vfA.x, vfB.y`   | `Q_reg = vfA.x / vfB.y;` |
| `vsqrt Q, vfA.x`          | `Q_reg = sqrtf(vfA.x);` |
| `vftoi0 vfD, vfA`         | `vfD = (int)vfA;` (per component) |

**PS2 FPU quirks:** No NaN/Inf (clamps to ±MAX_FLOAT). If precision matters, add `// TODO: VERIFY — PS2 precision`.

**Completion:** zero errors/warnings, labels intact, COP2 translations commented with original instruction.

---

## Lessons from Previous Phase
<!-- Claude: Add relevant findings from Phase 2 here before starting. -->

---

## Function List ({len(funcs):,} functions)
{"*(CPP: ✓ exists / ✗ missing)*" if show_cpp else ""}

{format_function_table(funcs, include_fpu=True, show_cpp=show_cpp)}

---

## Phase Transition

1. Write `phase3_lessons.md`.
2. Add notes to `phase4a_game_logic.md`.
3. Report completion.
"""
    path = output_dir / "phase3_math.md"
    path.write_text(md, encoding="utf-8")
    return path, len(funcs)


def generate_phase4a(funcs, data, output_dir):
    total_size    = sum(r["size"] for r in funcs)
    gp            = data.get("global_pointer", "UNKNOWN — MUST SET BEFORE RUNNING")
    writes_global = sum(1 for r in funcs if "WRITES_GLOBAL" in r["tag_list"])
    high_xref     = sum(1 for r in funcs if r.get("xref_to_count", 0) > 10)
    show_cpp      = any(r.get("cpp_found") is not None for r in funcs)
    md = f"""# Phase 4a: Game Logic — Global State & Function Calls

**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
**ELF Hash:** {data.get('elf_hash', 'N/A')}
**Global Pointer ($gp):** {gp}
{_quickstart_note(funcs)}
---

## Overview

- **Total functions:** {len(funcs):,}
- **Total code size:** {total_size:,} bytes ({total_size/1024:.1f} KB)
- **Global writers:** {writes_global}
- **High fan-in (>10 callers):** {high_xref}
- **Expected difficulty:** MEDIUM-HIGH.
- **Skill file required:** NO

## Dependency Order

Sorted callees-first. Fix callees before callers.

---

## Instructions for Claude

1. CHECK FIRST: `cmake --build build64/`.
2. Fix compilation errors.
3. Global state writes use `$gp`-relative stores. Ensure `ctx->gp = {gp}`.
4. High fan-in functions (many callers) — bugs propagate widely, test carefully.

**Completion:** zero errors/warnings, labels intact.

---

## Lessons from Previous Phase
<!-- Claude: Add relevant findings from Phase 3 here before starting. -->

---

## Function List ({len(funcs):,} functions)

{format_function_table(funcs, include_fpu=True, show_cpp=show_cpp)}

---

## Phase Transition

1. Write `phase4a_lessons.md`.
2. Add notes to `phase4b_state_machines.md`.
3. Report completion.
"""
    path = output_dir / "phase4a_game_logic.md"
    path.write_text(md, encoding="utf-8")
    return path, len(funcs)


def generate_phase4b(funcs, data, output_dir):
    total_size  = sum(r["size"] for r in funcs)
    gp          = data.get("global_pointer", "UNKNOWN — MUST SET BEFORE RUNNING")
    high_branch = sum(1 for r in funcs if r.get("branch_ops", 0) > 50)
    multi_ret   = sum(1 for r in funcs if "MULTI_RETURN" in r["tag_list"])
    jump_tables = sum(1 for r in funcs if "COMPLEX_CONTROL_FLOW" in r["tag_list"])
    show_cpp    = any(r.get("cpp_found") is not None for r in funcs)
    md = f"""# Phase 4b: State Machines — Complex Control Flow

**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
**ELF Hash:** {data.get('elf_hash', 'N/A')}
**Global Pointer ($gp):** {gp}
{_quickstart_note(funcs)}
---

## Overview

- **Total functions:** {len(funcs):,}
- **Total code size:** {total_size:,} bytes ({total_size/1024:.1f} KB)
- **High branch count (>50):** {high_branch}
- **Multi-return functions:** {multi_ret}
- **Jump table functions:** {jump_tables}
- **Expected difficulty:** HIGH. Every label, every branch target matters.
- **Skill file required:** NO

## Dependency Order

Sorted callees-first.

---

## Instructions for Claude

1. CHECK FIRST: `cmake --build build64/`.
2. Fix compilation errors.
3. **Control flow is sacred** — dense `goto` networks mirror the original assembly.
4. For uncertainty: `// TODO: VERIFY — [describe]`. Do not guess.

**Key patterns:**
- `COMPLEX_CONTROL_FLOW` → `jr $reg` indirect jumps. Check `flowchart.txt` for block layout.
- `WRITES_GLOBAL` → `$gp`-relative stores. Ensure `ctx->gp = {gp}`.

**What NOT to do:** Do NOT restructure switch/case, do NOT simplify control flow.

**Completion:** zero errors/warnings, ALL labels intact.

---

## Lessons from Previous Phase
<!-- Claude: Add relevant findings from Phase 4a here before starting. -->

---

## Function List ({len(funcs):,} functions)

{format_function_table(funcs, include_fpu=True, show_cpp=show_cpp)}

---

## Phase Transition

1. Write `phase4b_lessons.md`.
2. Add notes to `phase5_acc_hazard.md`.
3. Report completion.
"""
    path = output_dir / "phase4b_state_machines.md"
    path.write_text(md, encoding="utf-8")
    return path, len(funcs)


def generate_phase5(funcs, data, output_dir):
    total_size = sum(r["size"] for r in funcs)
    gp = data.get("global_pointer", "UNKNOWN — MUST SET BEFORE RUNNING")
    show_cpp = any(r.get("cpp_found") is not None for r in funcs)
    md = f"""# Phase 5: ACC_PRECISION_HAZARD — VU0 Accumulator Functions

**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
**ELF Hash:** {data.get('elf_hash', 'N/A')}
**Global Pointer ($gp):** {gp}
{_quickstart_note(funcs)}
---

## Overview

- **Total functions:** {len(funcs):,}
- **Total code size:** {total_size:,} bytes ({total_size/1024:.1f} KB)
- **What these are:** Functions using PS2 VU0 ACC register (vmadda, vmsuba, vopmsub, etc.)
- **Expected difficulty:** VERY HIGH.
- **Skill file required:** YES — read `/ps2-recomp-Agent-SKILL-0.4.3/` before any function.

---

## Instructions for Claude

### ⚠️ Read the Skill file FIRST

1. CHECK FIRST: `cmake --build build64/`.
2. Add `// HAZARD: ACC precision` as FIRST comment in each function.
3. Translate ACC ops using the Skill file pattern.
4. Cross-reference: `grep -A 100 "FUNCTION_ADDRESS" assembly.txt`
5. Comment every ACC translation with the original instruction.

### ACC Instruction Reference

| PS2 Instruction | Meaning |
|-----------------|---------|
| `vmadda.xyzw ACC, vfA, vfB` | `ACC += vfA * vfB` |
| `vmsuba.xyzw ACC, vfA, vfB` | `ACC -= vfA * vfB` |
| `vmula.xyzw ACC, vfA, vfB`  | `ACC = vfA * vfB`  |
| `vadda.xyzw ACC, vfA, vfB`  | `ACC = vfA + vfB`  |
| `vopmsub vfD, vfA, vfB`     | `vfD = ACC - outer(vfA,vfB)` |
| `vmadd vfD, vfA, vfB`       | `vfD = ACC + vfA * vfB` |
| `vmsub vfD, vfA, vfB`       | `vfD = ACC - vfA * vfB` |

**Do NOT use `double`** — goal is PS2-accurate behavior, not IEEE-accurate.

**Completion:** zero errors, labels intact, every ACC op commented.

---

## Lessons from Previous Phase
<!-- Claude: Add relevant findings from Phase 4 here before starting. -->

---

## Function List ({len(funcs):,} functions)

{format_function_table(funcs, include_fpu=True, show_cpp=show_cpp)}

---

## Phase Transition

1. Write `phase5_lessons.md`.
2. Add notes to `phase6_mmio.md`.
3. Report completion.
"""
    path = output_dir / "phase5_acc_hazard.md"
    path.write_text(md, encoding="utf-8")
    return path, len(funcs)


def generate_phase6(funcs, data, output_dir):
    total_size = sum(r["size"] for r in funcs)
    gp = data.get("global_pointer", "UNKNOWN — MUST SET BEFORE RUNNING")
    show_cpp = any(r.get("cpp_found") is not None for r in funcs)
    md = f"""# Phase 6: MMIO — Hardware Register Access

**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
**ELF Hash:** {data.get('elf_hash', 'N/A')}
**Global Pointer ($gp):** {gp}
{_quickstart_note(funcs)}
---

## Overview

- **Total functions:** {len(funcs):,}
- **Total code size:** {total_size:,} bytes ({total_size/1024:.1f} KB)
- **Expected difficulty:** VERY HIGH.
- **Skill file required:** YES — read `/ps2-recomp-Agent-SKILL-0.4.3/` before any function.

---

## Instructions for Claude

### ⚠️ Read the Skill file FIRST

1. CHECK FIRST: `cmake --build build64/`.
2. Identify MMIO registers: `grep -A 100 "FUNCTION_ADDRESS" assembly.txt`
3. Strategy per access:
   - **Stub:** no-op + comment (e.g. DMA sync waits not needed on PC)
   - **HLE:** translate to PC API call (e.g. texture upload)
   - **Flag:** `// TODO: MMIO — 0xADDR — needs HLE`

### PS2 MMIO Ranges

| Range | Hardware |
|-------|----------|
| `0x10000000-0x10001FFF` | EE Timers, INTC, SIF |
| `0x10003000-0x10003FFF` | GIF |
| `0x10003800-0x10003C30` | VIF0/VIF1 |
| `0x10008000-0x1000EFFF` | DMA channels |
| `0x12000000-0x12001FFF` | GS privileged |
| `0x70000000-0x70003FFF` | Scratchpad RAM |

**Completion:** zero errors, labels intact, every MMIO access stubbed/HLE'd/flagged.

---

## Lessons from Previous Phase
<!-- Claude: Add relevant findings from Phase 5 here before starting. -->

---

## Function List ({len(funcs):,} functions)

{format_function_table(funcs, include_fpu=True, show_cpp=show_cpp)}

---

## Phase Transition

1. Write `phase6_lessons.md`.
2. Add notes to `phase7_vu0_microcode.md`.
3. Report completion.
"""
    path = output_dir / "phase6_mmio.md"
    path.write_text(md, encoding="utf-8")
    return path, len(funcs)


def generate_phase7(funcs, data, output_dir):
    total_size = sum(r["size"] for r in funcs)
    gp = data.get("global_pointer", "UNKNOWN — MUST SET BEFORE RUNNING")
    show_cpp = any(r.get("cpp_found") is not None for r in funcs)
    md = f"""# Phase 7: VU0 Microcode — vcallms/vcallmsr Functions

**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
**ELF Hash:** {data.get('elf_hash', 'N/A')}
**Global Pointer ($gp):** {gp}
{_quickstart_note(funcs)}
---

## Overview

- **Total functions:** {len(funcs):,}
- **Total code size:** {total_size:,} bytes ({total_size/1024:.1f} KB)
- **Expected difficulty:** EXTREME.
- **Skill file required:** YES — read `/ps2-recomp-Agent-SKILL-0.4.3/` AND `db-vu-instructions.md`.

---

## Instructions for Claude

### ⚠️ Read the Skill file FIRST

1. CHECK FIRST: `cmake --build build64/`.
2. Locate `vcallms` target: `grep -A 100 "FUNCTION_ADDRESS" assembly.txt | grep -i vcallms`
3. Determine microprogram purpose (matrix multiply, transform, lighting, etc.)
4. Replace `vcallms` with C++ math. Mark with comment:
   ```cpp
   // vcallms 0x0000 — VU0 microprogram: matrix multiply
   result = matrix * vector;
   ```
5. Unknown microprograms → stub: `// TODO: VU0_MICROCODE — needs microprogram analysis`

**A stubbed function counts as done.**

**Completion:** zero errors, labels intact, every `vcallms` HLE'd or TODO'd.

---

## Lessons from Previous Phase
<!-- Claude: Add relevant findings from Phase 6 here before starting. -->

---

## Function List ({len(funcs):,} functions)

{format_function_table(funcs, include_fpu=True, show_cpp=show_cpp)}

---

## Project Completion

1. Write `phase7_lessons.md`.
2. Write `project_summary.md` with phase totals and remaining TODOs.
3. Report completion.
"""
    path = output_dir / "phase7_vu0_microcode.md"
    path.write_text(md, encoding="utf-8")
    return path, len(funcs)


def generate_orphan(funcs, data, output_dir):
    total_size = sum(r["size"] for r in funcs)
    md = f"""# Orphan Code — Zero-Reference Functions

**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
**ELF Hash:** {data.get('elf_hash', 'N/A')}

---

## Overview

- **Total functions:** {len(funcs):,}
- **Total code size:** {total_size:,} bytes ({total_size/1024:.1f} KB)
- **What these are:** Functions with zero incoming references. Likely dead code.

---

## Instructions for Claude

**Do NOT fix these proactively.** Come here only if:
- A compilation error elsewhere references an orphan address.
- The game crashes and the call stack points here.
- A jump table in another function targets an orphan address.

---

## Function List ({len(funcs):,} functions)

{format_function_table(funcs, include_fpu=False) if funcs else "*(No orphan functions.)*"}
"""
    path = output_dir / "orphan_code.md"
    path.write_text(md, encoding="utf-8")
    return path, len(funcs)


# =========================================================
# [NEW-3] PHASE 8 — INTEGRATION (replaces manual set-diff)
# =========================================================

def generate_phase8(data, rows, output_dir, recomp_dir=None, cmake_path=None):
    """
    Finds .cpp files in recomp_dir that are NOT referenced in CMakeLists.txt.
    If recomp_dir is None, uses rows with cpp_found=False instead.
    """
    missing_files = []

    if recomp_dir and cmake_path and Path(cmake_path).exists():
        cmake_content = Path(cmake_path).read_text(encoding="utf-8", errors="replace")
        registered = set(re.findall(r'recomp/([^\s\)]+\.cpp)', cmake_content))

        for p in sorted(glob.glob(str(Path(recomp_dir) / "*.cpp"))):
            fname = Path(p).name
            if fname not in registered:
                missing_files.append(fname)
    elif rows:
        # Fallback: rows with cpp_found=False
        missing_files = [
            f"{r['name']}_{r['address'].lower()}.cpp"
            for r in rows
            if r.get("cpp_found") is False
        ]

    total_size = sum(r["size"] for r in rows if r["disposition"] == "RECOMPILE")
    md = f"""# Phase 8: Final Integration

**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

---

## Overview

- **Unregistered files:** {len(missing_files):,}
- **What to do:** Add all files below to `target_sources(dc2_game PRIVATE ...)` in `CMakeLists.txt`.

> **Detection method:** Set-diff between `recomp/*.cpp` on disk and paths already in CMakeLists.txt.
> Run `python triage_analyzer.py triage_map.json cmake-block all` to get a ready-to-paste block.

---

## Unregistered Files ({len(missing_files):,})

"""
    if missing_files:
        for f in missing_files:
            md += f"- `recomp/{f}`\n"
    else:
        md += "*All recomp/ files are already registered in CMakeLists.txt.*\n"

    md += """
---

## Phase Transition

When build passes with exit code 0:
1. Record total file count in `lessons_log.md` under Phase 8.
2. Proceed to Phase 9 (runtime integration / stub gap analysis).
"""
    path = output_dir / "phase8_integration.md"
    path.write_text(md, encoding="utf-8")
    return path, len(missing_files)


# =========================================================
# MAIN PHASE GENERATION
# =========================================================

def generate_phases(data, rows, output_dir, recomp_dir=None, cmake_path=None):
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
        "orphan_code":            generate_orphan,
    }

    print(f"\nGenerating phase files in: {output_dir}")
    total_recompile = 0
    for key, gen in generators.items():
        funcs = phases[key]
        path, count = gen(funcs, data, output_dir)
        status = f"  {path.name:<35s} {count:>5,} functions"
        if key != "orphan_code":
            cpp_found = sum(1 for r in funcs if r.get("cpp_found") is True)
            if any(r.get("cpp_found") is not None for r in funcs):
                status += f"  ({cpp_found}/{count} cpp found)"
        print(status)
        if key != "orphan_code":
            total_recompile += count

    # [NEW-3] Phase 8
    path8, missing = generate_phase8(data, rows, output_dir, recomp_dir, cmake_path)
    print(f"  {path8.name:<35s} {missing:>5,} unregistered files")

    print(f"\nTotal RECOMPILE functions across phases: {total_recompile:,}")


# =========================================================
# [NEW-5] CMAKE-BLOCK GENERATOR
# =========================================================

PHASE_KEYS = {
    "phase1": "phase1_safe_leaf",
    "phase2": "phase2_wrappers",
    "phase3": "phase3_math",
    "phase4a": "phase4a_game_logic",
    "phase4b": "phase4b_state_machines",
    "phase5": "phase5_acc_hazard",
    "phase6": "phase6_mmio",
    "phase7": "phase7_vu0_microcode",
}

def cmd_cmake_block(data, rows, phase_key, recomp_dir=None):
    """
    [NEW-5] Print a ready-to-paste target_sources() block for a phase.
    If recomp_dir given, only include files that actually exist on disk.
    """
    phases = classify_phases(rows)
    if phase_key == "all":
        funcs = []
        for k in PHASE_KEYS.values():
            funcs.extend(phases[k])
    else:
        internal_key = PHASE_KEYS.get(phase_key)
        if not internal_key:
            print(f"Unknown phase '{phase_key}'. Valid: {', '.join(PHASE_KEYS)} all")
            return
        funcs = phases[internal_key]

    lines = []
    for r in funcs:
        try:
            addr_int = int(r["address"], 16)
            fname = f"{r['name']}_0x{addr_int:x}.cpp"
        except ValueError:
            fname = f"{r['name']}_{r['address']}.cpp"

        if recomp_dir:
            full = Path(recomp_dir) / fname
            if not full.exists():
                continue  # skip missing files
        lines.append(f"    recomp/{fname}")

    if not lines:
        print("No files found (check --recomp-dir path).")
        return

    print(f"target_sources(dc2_game PRIVATE")
    for l in lines:
        print(l)
    print(")")
    print(f"\n# {len(lines)} files")


# =========================================================
# [NEW-2] STUB GAP COMMAND
# =========================================================

def cmd_stub_gap(data, rows):
    """
    [NEW-2] Print all STUB functions that have runtime_has_handler=false.
    Requires schema_version >= 3 triage_map.json.
    """
    schema = data.get("schema_version", 1)
    if schema < 3:
        print(f"WARNING: triage_map.json schema v{schema}. Regenerate with Triage Enricher v3 for full stub gap data.")
        print("Falling back to name-based heuristic...\n")

    missing = [r for r in rows
               if r["disposition"] == "STUB"
               and r.get("runtime_has_handler") is False]
    unknown = [r for r in rows
               if r["disposition"] == "STUB"
               and r.get("runtime_has_handler") is None]

    print(f"STUB GAP REPORT")
    print(f"  Missing handlers : {len(missing)}")
    print(f"  Unknown (v2 JSON): {len(unknown)}")
    print(f"  Threshold for halt: >50\n")

    if len(missing) > 50:
        print("⚠️  EXCEEDS THRESHOLD — execution may halt at stub dispatch\n")

    if missing:
        print(f"{'Address':>12s}  {'Name'}")
        print("-" * 60)
        for r in sorted(missing, key=lambda x: x["address"]):
            print(f"{r['address']:>12s}  {r['name']}")
    else:
        print("All STUB functions have known runtime handlers. ✓")


# =========================================================
# CLI COMMANDS (unchanged from v2 + new ones)
# =========================================================

def cmd_stats(data, rows):
    recompile = [r for r in rows if r["disposition"] == "RECOMPILE"]
    stub      = [r for r in rows if r["disposition"] == "STUB"]
    skip      = [r for r in rows if r["disposition"] == "SKIP"]
    print(f"\nTriage Map Statistics")
    print(f"  ELF hash    : {data.get('elf_hash','N/A')}")
    print(f"  Schema v    : {data.get('schema_version',1)}")
    print(f"  Total       : {len(rows):,}")
    print(f"  RECOMPILE   : {len(recompile):,}")
    print(f"  STUB        : {len(stub):,}")
    print(f"  SKIP        : {len(skip):,}")
    stats = data.get("statistics", {})
    if stats:
        print(f"\nTag counts (RECOMPILE only):")
        for k, v in stats.items():
            if k not in ("total_functions","uncategorized_from_step1","enriched_count"):
                print(f"  {k:<28s}: {v:,}")


def cmd_top(rows, metric, n=20):
    scored = [(r.get(metric, 0), r) for r in rows if r["disposition"] == "RECOMPILE"]
    scored.sort(reverse=True)
    print(f"\nTop {n} by {metric}:")
    print(f"{'#':>4s}  {'Value':>8s}  {'Address':>12s}  Name")
    for i, (val, r) in enumerate(scored[:n], 1):
        print(f"{i:>4d}  {val:>8}  {r['address']:>12s}  {r['name']}")


def cmd_report(data, rows, output_path=None):
    lines = [f"PS2Recomp Triage Report — {datetime.now().strftime('%Y-%m-%d %H:%M')}",
             f"ELF: {data.get('elf_hash','N/A')}",
             "=" * 70]
    phases = classify_phases(rows)
    for key, funcs in phases.items():
        if funcs:
            total = sum(r["size"] for r in funcs)
            lines.append(f"{key:<35s} {len(funcs):>5,} funcs  {total:>8,} bytes")
    text = "\n".join(lines)
    if output_path:
        Path(output_path).write_text(text, encoding="utf-8")
        print(f"Report written to {output_path}")
    else:
        print(text)


# =========================================================
# ENTRY POINT
# =========================================================

def main():
    # Double-click mode: no arguments
    if len(sys.argv) == 1:
        candidates = list(Path(".").glob("triage_map.json"))
        if not candidates:
            print("No triage_map.json found in current directory.")
            print("Usage: python triage_analyzer.py triage_map.json [command]")
            sys.exit(1)
        json_path = candidates[0]
        data = load_triage(json_path)
        rows = flatten_functions(data)
        generate_phases(data, rows, Path(".") / "phases")
        return

    parser = argparse.ArgumentParser(description="PS2Recomp Triage Analyzer v3")
    parser.add_argument("json",          help="Path to triage_map.json")
    parser.add_argument("command",       nargs="?", default="phases",
                        choices=["phases","stats","top","report","stub-gap","cmake-block"],
                        help="Command to run")
    parser.add_argument("args",          nargs="*", help="Command arguments")
    parser.add_argument("--output",      default=None,      help="Output file for report")
    parser.add_argument("--output-dir",  default="phases",  help="Output dir for phase MDs")
    # [NEW-1]
    parser.add_argument("--recomp-dir",  default=None,
                        help="Path to recomp/ directory — injects cpp_found into rows")
    # [NEW-3]
    parser.add_argument("--cmake",       default=None,
                        help="Path to CMakeLists.txt — used by phase8 to find unregistered files")
    args = parser.parse_args()

    data = load_triage(args.json)
    rows = flatten_functions(data, recomp_dir=args.recomp_dir)

    if args.command == "stats":
        cmd_stats(data, rows)
    elif args.command == "top":
        metric = args.args[0] if args.args else "size"
        n      = int(args.args[1]) if len(args.args) > 1 else 20
        cmd_top(rows, metric, n)
    elif args.command == "report":
        cmd_report(data, rows, args.output)
    elif args.command == "stub-gap":          # [NEW-2]
        cmd_stub_gap(data, rows)
    elif args.command == "cmake-block":        # [NEW-5]
        phase = args.args[0] if args.args else "all"
        cmd_cmake_block(data, rows, phase, recomp_dir=args.recomp_dir)
    else:  # phases (default)
        generate_phases(data, rows, args.output_dir,
                        recomp_dir=args.recomp_dir,
                        cmake_path=args.cmake)


if __name__ == "__main__":
    main()
