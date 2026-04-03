#!/usr/bin/env python3
"""
PS2Recomp Triage Analyzer — Phase-Based MD Generator + CLI Query Tool
======================================================================
Double-click (no arguments) → scans triage_map.json in same folder,
generates 7 phase + 2 Additionals MD files with embedded Claude instructions.

CLI usage (unchanged):
  python triage_analyzer.py triage_map.json stats
  python triage_analyzer.py triage_map.json top fpu_ops 20
  python triage_analyzer.py triage_map.json report --output my_report.txt
  ... etc.
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
            "callee_list": func.get("callees", []),
        }
        for k, v in func.get("metrics", {}).items():
            row[k] = v
        for k, v in func.get("hardware", {}).items():
            row[k] = v
        rows.append(row)
    return rows

def compute_priority_score(r):
    """Weighted score: higher = more complex / higher priority."""
    return (r["size"]
            + r.get("fpu_ops", 0) * 10
            + r.get("acc_ops", 0) * 50
            + (500 if "ACC_PRECISION_HAZARD" in r["tag_list"] else 0)
            + (300 if "VU0_VECTORS" in r["tag_list"] else 0)
            + (200 if "USES_SPR" in r["tag_list"] else 0))

# =========================================================
# PHASE CLASSIFICATION
# =========================================================

def dependency_sort(funcs):
    """Sort functions so callees appear before callers (bottom-up dependency order).
    Falls back to priority score for functions without dependency relationships.
    Uses address as the unique key to handle overloaded/static function names."""
    if not funcs:
        return funcs

    # Build address→function lookup and compute scores
    by_addr = {}
    for r in funcs:
        r["_score"] = compute_priority_score(r)
        by_addr[r["address"]] = r

    # Build name→set-of-addresses index (one name may map to many addresses)
    from collections import defaultdict
    name_to_addrs = defaultdict(set)
    for r in funcs:
        name_to_addrs[r["name"]].add(r["address"])

    phase_addrs = set(by_addr.keys())

    # Build adjacency: caller address → set of callee addresses (only within this phase)
    deps = {addr: set() for addr in phase_addrs}
    for r in funcs:
        for callee_name in r.get("callee_list", []):
            for callee_addr in name_to_addrs.get(callee_name, ()):
                if callee_addr != r["address"]:
                    deps[r["address"]].add(callee_addr)

    # Topological sort (Kahn's algorithm) with score-based tiebreaking
    reverse = {addr: [] for addr in phase_addrs}
    for caller_addr, callee_addrs in deps.items():
        for callee_addr in callee_addrs:
            reverse[callee_addr].append(caller_addr)
    in_degree = {addr: len(callees) for addr, callees in deps.items()}

    # Start with functions that have no in-phase dependencies
    queue = sorted([a for a in phase_addrs if in_degree[a] == 0],
                   key=lambda a: -by_addr[a]["_score"])
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

    # Add any remaining (cycles) sorted by score
    seen = {r["address"] for r in result}
    for r in sorted(funcs, key=lambda x: -x["_score"]):
        if r["address"] not in seen:
            result.append(r)

    return result


def classify_phases(rows):
    """Assign each RECOMPILE function to exactly one phase. Returns dict of phase→list."""
    phases = {
        "phase1_safe_leaf": [],
        "phase2_wrappers": [],
        "phase3_math": [],
        "phase4a_game_logic": [],
        "phase4b_state_machines": [],
        "phase5_acc_hazard": [],
        "phase6_mmio": [],
        "phase7_vu0_microcode": [],
        "orphan_code": [],
    }

    for r in rows:
        if r["disposition"] != "RECOMPILE":
            continue

        tags = r["tag_list"]
        cat = r["category"]

        # Extract callee list from JSON (new field from enriched Java output)
        r["callee_list"] = r.get("callee_list", [])

        # Orphan functions — zero incoming references, likely dead code
        if "ORPHAN_CODE" in tags:
            phases["orphan_code"].append(r)
            continue

        # Phase 7 — VU0 microcode (vcallms) — needs special HLE, cannot auto-translate
        if "VU0_MICROCODE" in tags:
            phases["phase7_vu0_microcode"].append(r)
        # Phase 5 — ACC hazard takes highest priority (special handling)
        elif "ACC_PRECISION_HAZARD" in tags:
            phases["phase5_acc_hazard"].append(r)
        # Phase 6 — MMIO access (hardware registers)
        elif "ACCESSES_MMIO" in tags:
            phases["phase6_mmio"].append(r)
        # Phase 1 — Safe leaf functions (auto-translate candidates)
        elif "SAFE_LEAF" in tags:
            phases["phase1_safe_leaf"].append(r)
        # Phase 2 — Wrappers and getters/stubs
        elif cat in ("WRAPPER", "GETTER_OR_STUB"):
            phases["phase2_wrappers"].append(r)
        # Phase 3 — Math/vector functions
        elif cat == "MATH_VECTORS":
            phases["phase3_math"].append(r)
        # Phase 4a — Game logic (global state mutations + calls)
        elif cat == "GAME_LOGIC":
            phases["phase4a_game_logic"].append(r)
        # Phase 4b — State machines + everything else
        else:
            phases["phase4b_state_machines"].append(r)

    # Apply dependency-aware sorting to each phase
    for key in phases:
        phases[key] = dependency_sort(phases[key])

    return phases


# =========================================================
# FUNCTION TABLE FORMATTER
# =========================================================

def format_function_table(funcs, include_fpu=True):
    """Returns a markdown table string for a list of functions."""
    lines = []

    if include_fpu:
        header = f"| {'#':>4s} | {'Address':>12s} | {'Score':>6s} | {'Size':>6s} | {'FPU':>4s} | {'ACC':>4s} | {'Br':>4s} | {'Calls':>5s} | {'Xref':>4s} | {'Category':>16s} | Name | Tags |"
        sep    = f"|{'-'*5}:|{'-'*13}:|{'-'*7}:|{'-'*7}:|{'-'*5}:|{'-'*5}:|{'-'*5}:|{'-'*6}:|{'-'*5}:|{'-'*17}:|{'-'*42}|{'-'*20}|"
        lines.append(header)
        lines.append(sep)
        for i, r in enumerate(funcs, 1):
            flags = []
            if "ACC_PRECISION_HAZARD" in r["tag_list"]: flags.append("ACC!")
            if "VU0_VECTORS" in r["tag_list"]: flags.append("VU0")
            if "VU0_MICROCODE" in r["tag_list"]: flags.append("uVU0")
            if "USES_SPR" in r["tag_list"]: flags.append("SPR")
            if "MULTI_RETURN" in r["tag_list"]: flags.append("MR")
            if "WRITES_GLOBAL" in r["tag_list"]: flags.append("WG")
            if "COMPLEX_CONTROL_FLOW" in r["tag_list"]: flags.append("JT")
            tag_str = ", ".join(flags) if flags else "-"
            name = r['name']
            if len(name) > 40:
                name = name[:22] + ".." + name[-16:]
            lines.append(
                f"| {i:>4d} | {r['address']:>12s} | {r['_score']:>6d} | {r['size']:>6d} | "
                f"{r.get('fpu_ops',0):>4d} | {r.get('acc_ops',0):>4d} | "
                f"{r.get('branch_ops',0):>4d} | {r.get('callee_count',0):>5d} | "
                f"{r.get('xref_to_count',0):>4d} | {r['category']:>16s} | "
                f"{name:<40s} | {tag_str} |"
            )
    else:
        header = f"| {'#':>4s} | {'Address':>12s} | {'Size':>6s} | {'Category':>16s} | Name |"
        sep    = f"|{'-'*5}:|{'-'*13}:|{'-'*7}:|{'-'*17}:|{'-'*45}|"
        lines.append(header)
        lines.append(sep)
        for i, r in enumerate(funcs, 1):
            name = r['name']
            if len(name) > 43:
                name = name[:25] + ".." + name[-16:]
            lines.append(
                f"| {i:>4d} | {r['address']:>12s} | {r['size']:>6d} | "
                f"{r['category']:>16s} | {name:<43s} |"
            )

    return "\n".join(lines)


# =========================================================
# PHASE MD GENERATORS
# =========================================================

def generate_phase1(funcs, data, output_dir):
    """Phase 1: SAFE_LEAF — auto-translate candidates."""
    total_size = sum(r["size"] for r in funcs)
    gp = data.get("global_pointer", "UNKNOWN — MUST SET BEFORE RUNNING")

    md = f"""# Phase 1: SAFE_LEAF — Auto-Translate
**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
**ELF Hash:** {data.get('elf_hash', 'N/A')}
**Global Pointer ($gp):** {gp}

---

## Overview
- **Total functions:** {len(funcs):,}
- **Total code size:** {total_size:,} bytes ({total_size/1024:.1f} KB)
- **What these are:** Leaf functions — they call nothing and have no complex side effects.
- **Expected difficulty:** LOW. These are the simplest functions in the binary.

---

## Instructions for Claude

### What to do
These functions are pre-approved for straightforward translation. For each function:
1. CHECK FIRST: Run `cmake --build build64/` (incremental build).
   Functions that compile clean → mark done, skip.
   Only fix functions with actual errors.
2. Open the corresponding `.cpp` file in `/auto_Recomp/`.
3. Fix any compilation errors (syntax, type mismatches, pointer casts).
4. Ensure all `goto` labels remain intact and unchanged.
5. Add brief comments where the logic is non-obvious.

### What NOT to do
- Do NOT run a massive `diff` across all files to extract lessons during phase transition.** Sample a maximum of 3-5 random `.cpp` files instead.
- Do NOT extract helpers or create new functions.
- Do NOT restructure the control flow or rename labels.
- Do NOT read `assembly.txt` or `triage_map.json` in full — use `grep` if you need context:
  ```bash
  grep -A 50 "FUNCTION_ADDRESS" assembly.txt
  ```

### Batch strategy
These are small, independent functions. Process them in batches of 10-20. After each batch, verify compilation before moving on.

### Completion criteria
A function is **done** when it compiles with zero errors/warnings, all `goto` labels are preserved, and no new dependencies were introduced.

---

## Function List ({len(funcs):,} functions)

{format_function_table(funcs, include_fpu=False)}

---

## Phase Transition
When ALL functions compile:
1. Write `phase1_lessons.md` — its sole purpose is to prepare Claude for the next phase.
   Include only what was surprising or non-obvious that a future Claude wouldn't know from 
   reading phase2_wrappers.md alone. Skip anything already documented there.
2. Open `phase2_wrappers.md` and add relevant notes to its "Lessons from Previous Phase" section.
3. Report completion to the user.
"""
    path = output_dir / "phase1_safe_leaf.md"
    path.write_text(md, encoding="utf-8")
    return path, len(funcs)


def generate_phase2(funcs, data, output_dir):
    """Phase 2: WRAPPER + GETTER_OR_STUB."""
    total_size = sum(r["size"] for r in funcs)
    gp = data.get("global_pointer", "UNKNOWN — MUST SET BEFORE RUNNING")

    md = f"""# Phase 2: Wrappers & Getters — Thin Delegation Functions
**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
**ELF Hash:** {data.get('elf_hash', 'N/A')}
**Global Pointer ($gp):** {gp}

---

## Overview
- **Total functions:** {len(funcs):,}
- **Total code size:** {total_size:,} bytes ({total_size/1024:.1f} KB)
- **What these are:** Wrappers (delegate to one or two other functions) and getters/stubs (return a value or do minimal work).
- **Expected difficulty:** LOW-MEDIUM. Most are trivial, but some wrappers may need correct calling conventions.

---

## Instructions for Claude

### What to do
1. CHECK FIRST: Run `cmake --build build64/` (incremental build).
   Functions that compile clean → mark done, skip.
   Only fix functions with actual errors.
2. Open the `.cpp` file in `/auto_Recomp/`.
3. Fix compilation errors — most will be type mismatches or missing casts.
4. For wrappers: ensure the delegated call signature matches exactly (argument count, types, return type).
5. For getters: ensure the return value and global access patterns are correct.
6. Preserve all `goto` labels.

### What NOT to do
- Do NOT inline the wrapped function's body into the wrapper.
- Do NOT extract helpers or change structure.
- Do NOT read large reference files in full — use `grep`:
  ```bash
  grep -B 2 -A 20 "FUNCTION_NAME" triage_map.json
  ```

### Key patterns to watch for
- **$gp-relative loads:** These access `.sdata/.sbss` globals via `ctx->gp`. Ensure `ctx->gp = {gp}` is set.
- **Calling convention:** PS2 uses MIPS o32/n32 ABI. Arguments in `$a0-$a3`, return in `$v0/$v1`.
- **Void wrappers:** Some wrappers return void but the callee returns a value — don't add a return where there isn't one.

### Completion criteria
Same as Phase 1: zero errors/warnings, labels intact, no new dependencies.

---

## Lessons from Previous Phase
<!-- Claude: Add relevant findings from Phase 1 here before starting. -->

---

## Function List ({len(funcs):,} functions)

{format_function_table(funcs, include_fpu=False)}

---

## Phase Transition
When ALL functions compile:
1. Write `phase2_lessons.md` — its sole purpose is to prepare Claude for the next phase.
   Include only what was surprising or non-obvious that a future Claude wouldn't know from
   reading phase3_math.md alone. Skip anything already documented there.
2. Open `phase3_math.md` and add notes to its "Lessons from Previous Phase" section.
3. Report completion to the user.
"""
    path = output_dir / "phase2_wrappers.md"
    path.write_text(md, encoding="utf-8")
    return path, len(funcs)


def generate_phase3(funcs, data, output_dir):
    """Phase 3: MATH_VECTORS — FPU-heavy vector math."""
    total_size = sum(r["size"] for r in funcs)
    gp = data.get("global_pointer", "UNKNOWN — MUST SET BEFORE RUNNING")
    vu0_count = sum(1 for r in funcs if "VU0_VECTORS" in r["tag_list"])
    high_fpu = sum(1 for r in funcs if r.get("fpu_ops", 0) > 30)

    md = f"""# Phase 3: MATH_VECTORS — FPU & Vector Operations
**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
**ELF Hash:** {data.get('elf_hash', 'N/A')}
**Global Pointer ($gp):** {gp}

---

## Overview
- **Total functions:** {len(funcs):,}
- **Total code size:** {total_size:,} bytes ({total_size/1024:.1f} KB)
- **VU0/COP2 functions:** {vu0_count}
- **High FPU density (>30 ops):** {high_fpu}
- **What these are:** The computational core — physics, animation, collision, camera, effects.
- **Expected difficulty:** MEDIUM-HIGH. FPU precision and COP2 translation are the main challenges.

---

## Instructions for Claude

### What to do
1. CHECK FIRST: Run `cmake --build build64/` (incremental build).
   Functions that compile clean → mark done, skip.
   Only fix functions with actual errors.
2. Open the `.cpp` file in `/auto_Recomp/`.
3. Fix compilation errors.
4. **COP2/VU0 translation:** Replace inline assembly with C++ math using the project's standard types (`Vector4`, GLM, or whatever the headers define). **Do NOT invent custom math structs.**
5. Search `assembly.txt` for the function's MIPS code to verify your translation:
   ```bash
   grep -A 80 "FUNCTION_ADDRESS" assembly.txt
   ```
6. Check `triage_map.json` for hardware flags:
   ```bash
   grep -B 2 -A 20 "FUNCTION_NAME" triage_map.json
   ```

### COP2 Translation Reference
| PS2 Instruction | C++ Equivalent |
|-----------------|---------------|
| `vmul.xyzw vfD, vfA, vfB` | `vfD.x = vfA.x * vfB.x; ...` (per component) |
| `vadd.xyzw vfD, vfA, vfB` | `vfD.x = vfA.x + vfB.x; ...` |
| `vsub.xyzw vfD, vfA, vfB` | `vfD.x = vfA.x - vfB.x; ...` |
| `vmulq vfD, vfA, Q` | `vfD = vfA * Q_register;` |
| `vdiv Q, vfA.x, vfB.y` | `Q_register = vfA.x / vfB.y;` |
| `vsqrt Q, vfA.x` | `Q_register = sqrtf(vfA.x);` |
| `vftoi0 vfD, vfA` | `vfD = (int)vfA;` (truncate, per component) |
| `vitof0 vfD, vfA` | `vfD = (float)vfA;` (per component) |

### PS2 FPU Quirks
- **No NaN/Inf:** PS2 EE FPU clamps to ±MAX_FLOAT instead. Standard C++ `float` produces NaN/Inf which breaks PS2 logic.
- **Non-IEEE rounding:** PS2 truncates toward zero; x86 defaults to round-to-nearest. This can cause drift in physics over many frames.
- **If precision matters:** Add `// TODO: VERIFY — PS2 precision` comment. Do not try to emulate PS2 rounding unless the Skill file provides a pattern.

### What NOT to do
- Do NOT extract helpers, change structure, rename labels.
- Do NOT invent `struct Vec4 {{ float x,y,z,w; }}` — use what already exists in the headers.
- Do NOT "optimize" the math — keep it 1:1 with the assembly.

### Completion criteria
Zero errors/warnings, all labels intact, no new dependencies. COP2 translations marked with comment showing original instruction.

---

## Lessons from Previous Phase
<!-- Claude: Add relevant findings from Phase 2 here before starting. -->

---

## Function List ({len(funcs):,} functions)

{format_function_table(funcs, include_fpu=True)}

---

## Phase Transition
When ALL functions compile:
1. Write `phase3_lessons.md` — its sole purpose is to prepare Claude for the next phase.
   Include only what was surprising or non-obvious that a future Claude wouldn't know from
   reading phase4a_game_logic.md alone. Skip anything already documented there.
2. Open `phase4a_game_logic.md` and add notes to "Lessons from Previous Phase".
3. Report completion to the user.
"""
    path = output_dir / "phase3_math.md"
    path.write_text(md, encoding="utf-8")
    return path, len(funcs)


def generate_phase4a(funcs, data, output_dir):
    """Phase 4a: GAME_LOGIC — functions that modify global state with calls."""
    total_size = sum(r["size"] for r in funcs)
    gp = data.get("global_pointer", "UNKNOWN — MUST SET BEFORE RUNNING")
    writes_global = sum(1 for r in funcs if "WRITES_GLOBAL" in r["tag_list"])
    high_xref = sum(1 for r in funcs if r.get("xref_to_count", 0) > 10)

    md = f"""# Phase 4a: Game Logic — Global State & Function Calls
**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
**ELF Hash:** {data.get('elf_hash', 'N/A')}
**Global Pointer ($gp):** {gp}

---

## Overview
- **Total functions:** {len(funcs):,}
- **Total code size:** {total_size:,} bytes ({total_size/1024:.1f} KB)
- **Global writers:** {writes_global}
- **High fan-in (>10 callers):** {high_xref}
- **What these are:** Game logic functions — they read/write global state and call other functions. Includes initialization, update loops, resource management, and game subsystem code.
- **Expected difficulty:** MEDIUM-HIGH. The challenge is ensuring correct global access patterns and calling conventions.

---

## Dependency Order
Functions in this list are sorted **callees-first**: if function A calls function B and both are in this phase, B appears before A. Fix B first so A's call is correct.

---

## Instructions for Claude

### What to do
1. CHECK FIRST: Run `cmake --build build64/` (incremental build).
   Functions that compile clean → mark done, skip.
   Only fix functions with actual errors.
2. Open the `.cpp` file in `/auto_Recomp/`.
3. Fix compilation errors.
4. **Global state writes:** These functions modify game state through `$gp`-relative stores. Ensure the global pointer is correct (`ctx->gp = {gp}`).
5. **High fan-in functions** (many callers) are marked in the Tags column. A bug here propagates widely — test thoroughly.
6. Search for context when needed:
   ```bash
   grep -B 2 -A 20 "FUNCTION_NAME" triage_map.json
   grep -A 100 "FUNCTION_ADDRESS" assembly.txt
   ```

### What NOT to do
- Do NOT restructure control flow or rename labels.
- Do NOT extract helpers or change function boundaries.
- Do NOT "simplify" global access patterns.

### Completion criteria
Zero errors/warnings, all labels intact, no new dependencies.

---

## Lessons from Previous Phase
<!-- Claude: Add relevant findings from Phase 3 here before starting. -->

---

## Function List ({len(funcs):,} functions)

{format_function_table(funcs, include_fpu=True)}

---

## Phase Transition
When ALL functions compile:
1. Write `phase4a_lessons.md` — its sole purpose is to prepare Claude for the next phase.
   Include only what was surprising or non-obvious that a future Claude wouldn't know from
   reading phase4b_state_machines.md alone.
2. Open `phase4b_state_machines.md` and add notes to "Lessons from Previous Phase".
3. Report completion to the user.
"""
    path = output_dir / "phase4a_game_logic.md"
    path.write_text(md, encoding="utf-8")
    return path, len(funcs)


def generate_phase4b(funcs, data, output_dir):
    """Phase 4b: STATE_MACHINES + UNCATEGORIZED — complex control flow."""
    total_size = sum(r["size"] for r in funcs)
    gp = data.get("global_pointer", "UNKNOWN — MUST SET BEFORE RUNNING")
    high_branch = sum(1 for r in funcs if r.get("branch_ops", 0) > 50)
    multi_ret = sum(1 for r in funcs if "MULTI_RETURN" in r["tag_list"])
    jump_tables = sum(1 for r in funcs if "COMPLEX_CONTROL_FLOW" in r["tag_list"])

    md = f"""# Phase 4b: State Machines — Complex Control Flow
**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
**ELF Hash:** {data.get('elf_hash', 'N/A')}
**Global Pointer ($gp):** {gp}

---

## Overview
- **Total functions:** {len(funcs):,}
- **Total code size:** {total_size:,} bytes ({total_size/1024:.1f} KB)
- **High branch count (>50):** {high_branch}
- **Multi-return functions:** {multi_ret}
- **Jump table functions:** {jump_tables}
- **What these are:** State machines, menu logic, event handlers, AI, and uncategorized functions with complex branching.
- **Expected difficulty:** HIGH. Dense `goto` networks mirror the original assembly. Every label, every branch target matters.

---

## Dependency Order
Functions in this list are sorted **callees-first**: if function A calls function B and both are in this phase, B appears before A. Fix B first.

---

## Instructions for Claude

### What to do
1. CHECK FIRST: Run `cmake --build build64/` (incremental build).
   Functions that compile clean → mark done, skip.
   Only fix functions with actual errors.
2. Open the `.cpp` file in `/auto_Recomp/`.
3. Fix compilation errors.
4. **Control flow is sacred:** These functions have dense `goto` networks. Every label, every branch target matters.
5. Search for context when needed:
   ```bash
   grep -B 2 -A 20 "FUNCTION_NAME" triage_map.json
   grep -A 10 "FUNCTION_NAME" flowchart.txt
   grep -A 100 "FUNCTION_ADDRESS" assembly.txt
   ```

### Key patterns
- **Switch/case via jump tables:** The decompiler may produce `goto *` or computed jumps. Functions tagged `COMPLEX_CONTROL_FLOW` use `jr $reg` (indirect jumps). Check `flowchart.txt` for block layout.
- **Global state writes:** Functions tagged `WRITES_GLOBAL` modify game state through `$gp`-relative stores. Ensure the global pointer is correct (`ctx->gp = {gp}`).
- **Tight loops:** Some state machines contain polling loops flagged as `BUSY_WAIT_HAZARD`.

### What NOT to do
- Do NOT restructure switch/case logic — even if it looks ugly with `goto`, keep it.
- Do NOT extract state handler functions.
- Do NOT change label order or branch targets.
- Do NOT "simplify" the control flow.

### Handling uncertainty
If you're not sure about a branch target or a global write, add:
```cpp
// TODO: VERIFY — [describe what's uncertain]
```
Do not guess.

### Completion criteria
Zero errors/warnings, ALL labels intact (this is critical for state machines), no new dependencies.

---

## Lessons from Previous Phase
<!-- Claude: Add relevant findings from Phase 4a here before starting. -->

---

## Function List ({len(funcs):,} functions)

{format_function_table(funcs, include_fpu=True)}

---

## Phase Transition
When ALL functions compile:
1. Write `phase4b_lessons.md` — its sole purpose is to prepare Claude for the next phase.
   Include only what was surprising or non-obvious that a future Claude wouldn't know from
   reading phase5_acc_hazard.md alone.
2. Open `phase5_acc_hazard.md` and add notes to "Lessons from Previous Phase".
3. Report completion to the user.
"""
    path = output_dir / "phase4b_state_machines.md"
    path.write_text(md, encoding="utf-8")
    return path, len(funcs)


def generate_phase5(funcs, data, output_dir):
    """Phase 5: ACC_PRECISION_HAZARD — accumulator precision issues."""
    total_size = sum(r["size"] for r in funcs)
    gp = data.get("global_pointer", "UNKNOWN — MUST SET BEFORE RUNNING")

    md = f"""# Phase 5: ACC_PRECISION_HAZARD — VU0 Accumulator Functions
**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
**ELF Hash:** {data.get('elf_hash', 'N/A')}
**Global Pointer ($gp):** {gp}

---

## Overview
- **Total functions:** {len(funcs):,}
- **Total code size:** {total_size:,} bytes ({total_size/1024:.1f} KB)
- **What these are:** Functions that use the PS2 VU0 accumulator register (ACC) via instructions like `vmadda`, `vmsuba`, `vopmsub`, etc.
- **Expected difficulty:** VERY HIGH. The ACC register has no direct C++ equivalent, and precision behavior differs from IEEE-754.

---

## Instructions for Claude

### ⚠️ CRITICAL: Read the Skill file FIRST
Before touching ANY function in this phase, you MUST read `/ps2-recomp-Agent-SKILL-0.4.3/` for the recommended ACC emulation pattern. This is not optional.

### What to do
1. CHECK FIRST: Run `cmake --build build64/` (incremental build).
   Functions that compile clean → mark done, skip.
   Only fix functions with actual errors.
2. Add `// HAZARD: ACC precision` as the FIRST comment in each function.
3. Open the `.cpp` file and fix compilation errors.
4. Translate ACC operations using the pattern from the Skill file.
5. **Always** cross-reference with assembly:
   ```bash
   grep -A 100 "FUNCTION_ADDRESS" assembly.txt
   ```
6. Mark every ACC translation with a comment showing the original instruction:
   ```cpp
   // ACC = vf01 * vf02 (vmulа.xyzw ACC, vf01, vf02)
   acc.x = vf01.x * vf02.x;
   acc.y = vf01.y * vf02.y;
   // vf03 = ACC + vf04 * vf05 (vmadda.xyzw vf03, vf04, vf05)
   vf03.x = acc.x + vf04.x * vf05.x;
   vf03.y = acc.y + vf04.y * vf05.y;
   ```

### ACC Instruction Quick Reference
| PS2 Instruction | Meaning |
|-----------------|---------|
| `vmadda.xyzw ACC, vfA, vfB` | `ACC += vfA * vfB` |
| `vmsuba.xyzw ACC, vfA, vfB` | `ACC -= vfA * vfB` |
| `vmula.xyzw ACC, vfA, vfB` | `ACC = vfA * vfB` |
| `vadda.xyzw ACC, vfA, vfB` | `ACC = vfA + vfB` |
| `vopmsub vfD, vfA, vfB` | Cross product: `vfD = ACC - vfA ×_outer vfB` |
| `vmadd vfD, vfA, vfB` | `vfD = ACC + vfA * vfB` |
| `vmsub vfD, vfA, vfB` | `vfD = ACC - vfA * vfB` |

### PS2 ACC Precision Rules
- ACC is a 32-bit float register per component (x, y, z, w).
- PS2 truncates toward zero (not IEEE round-to-nearest).
- Accumulated multiply-add chains drift differently than C++ `float` chains.
- **Do NOT use `double` to "improve" precision** — the goal is PS2-accurate behavior, not IEEE-accurate.

### What NOT to do
- Do NOT skip the Skill file read.
- Do NOT invent your own ACC emulation pattern.
- Do NOT use `double` or extended precision.
- Do NOT extract helpers or change structure.

### Completion criteria
Zero errors/warnings, all labels intact, every ACC operation commented with original instruction, `// HAZARD: ACC precision` at function top.

---

## Lessons from Previous Phase
<!-- Claude: Add relevant findings from Phase 4 here before starting. -->

---

## Function List ({len(funcs):,} functions)

{format_function_table(funcs, include_fpu=True)}

---

## Phase Transition
When ALL functions compile:
1. Write `phase5_lessons.md` — its sole purpose is to prepare Claude for the next phase.
   Include only what was surprising or non-obvious that a future Claude wouldn't know from
   reading reading phase6_mmio.md alone. Skip anything already documented there.
2. Open `phase6_mmio.md` and add notes to "Lessons from Previous Phase".
3. Report completion to the user.
"""
    path = output_dir / "phase5_acc_hazard.md"
    path.write_text(md, encoding="utf-8")
    return path, len(funcs)


def generate_phase6(funcs, data, output_dir):
    """Phase 6: ACCESSES_MMIO — hardware register access."""
    total_size = sum(r["size"] for r in funcs)
    gp = data.get("global_pointer", "UNKNOWN — MUST SET BEFORE RUNNING")

    md = f"""# Phase 6: MMIO — Hardware Register Access Functions
**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
**ELF Hash:** {data.get('elf_hash', 'N/A')}
**Global Pointer ($gp):** {gp}

---

## Overview
- **Total functions:** {len(funcs):,}
- **Total code size:** {total_size:,} bytes ({total_size/1024:.1f} KB)
- **What these are:** Functions that directly read/write PS2 hardware registers (GS, VIF, DMA, timers, etc.)
- **Expected difficulty:** VERY HIGH. These interact with hardware that doesn't exist on PC. Most will need HLE (High-Level Emulation) stubs or runtime hooks.

---

## Instructions for Claude

### ⚠️ CRITICAL: Read the Skill file FIRST
These functions touch PS2 hardware. You MUST read `/ps2-recomp-Agent-SKILL-0.4.3/` before proceeding.

### What to do
1. CHECK FIRST: Run `cmake --build build64/` (incremental build).
   Functions that compile clean → mark done, skip.
   Only fix functions with actual errors.
2. Open the `.cpp` file in `/auto_Recomp/`.
3. Identify which MMIO registers are accessed by searching assembly:
   ```bash
   grep -A 100 "FUNCTION_ADDRESS" assembly.txt
   ```
4. Check `triage_map.json` for hardware flags:
   ```bash
   grep -B 2 -A 30 "FUNCTION_NAME" triage_map.json
   ```
5. For each MMIO access, determine the correct strategy:
   - **Stub it:** If the hardware interaction is not needed on PC (e.g., DMA sync wait), replace with a no-op and comment.
   - **HLE it:** If the function does something observable (e.g., uploads a texture), translate to PC API calls.
   - **Flag it:** If uncertain, add `// TODO: MMIO — [register address] — needs HLE implementation`.

### PS2 MMIO Address Ranges
| Range | Hardware |
|-------|----------|
| `0x10000000-0x10001FFF` | EE Timers, INTC, SIF |
| `0x10002000-0x10002FFF` | IPU (Image Processing Unit) |
| `0x10003000-0x10003FFF` | GIF (Graphics Interface) |
| `0x10003800-0x10003C30` | VIF0/VIF1 |
| `0x10008000-0x1000EFFF` | DMA channels |
| `0x12000000-0x12001FFF` | GS (Graphics Synthesizer) privileged |
| `0x70000000-0x70003FFF` | Scratchpad RAM (16KB, must be mapped) |

### What NOT to do
- Do NOT try to emulate full hardware behavior — that's what PCSX2 does. We want HLE.
- Do NOT remove MMIO code entirely — stub it with a comment so it can be revisited.
- Do NOT change function structure or labels.

### Completion criteria
Zero errors/warnings, all labels intact, every MMIO access either stubbed/HLE'd/flagged with `// TODO: MMIO`.

---

## Lessons from Previous Phase
<!-- Claude: Add relevant findings from Phase 5 here before starting. -->

---

## Function List ({len(funcs):,} functions)

{format_function_table(funcs, include_fpu=True)}

---

## Phase Transition
When ALL functions compile:
1. Write `phase6_lessons.md` — its sole purpose is to document MMIO patterns
   that were surprising or non-obvious. Skip anything already in the Skill file.
2. Open `phase7_vu0_microcode.md` and add notes to "Lessons from Previous Phase".
3. Report completion to the user.
"""
    path = output_dir / "phase6_mmio.md"
    path.write_text(md, encoding="utf-8")
    return path, len(funcs)


def generate_phase7(funcs, data, output_dir):
    """Phase 7: VU0_MICROCODE — functions using vcallms/vcallmsr (VU0 micro mode)."""
    total_size = sum(r["size"] for r in funcs)
    gp = data.get("global_pointer", "UNKNOWN — MUST SET BEFORE RUNNING")

    md = f"""# Phase 7: VU0 Microcode — vcallms/vcallmsr Functions
**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
**ELF Hash:** {data.get('elf_hash', 'N/A')}
**Global Pointer ($gp):** {gp}

---

## Overview
- **Total functions:** {len(funcs):,}
- **Total code size:** {total_size:,} bytes ({total_size/1024:.1f} KB)
- **What these are:** Functions that call VU0 microprograms via `vcallms` or `vcallmsr` instructions. These execute code on the Vector Unit 0 coprocessor.
- **Expected difficulty:** EXTREME. VU0 micro mode runs a separate instruction stream on dedicated hardware. Static recompilation cannot auto-translate these — they need hand-written HLE or complete VU0 microprogram reimplementation.

---

## Instructions for Claude

### CRITICAL: Read the Skill file FIRST
You MUST read `/ps2-recomp-Agent-SKILL-0.4.3/` resources on VU0 architecture before proceeding.
Also load `db-vu-instructions.md` for the VU instruction reference.

### What to do
1. CHECK FIRST: Run `cmake --build build64/` (incremental build).
   Functions that compile clean → mark done, skip.
   Only fix functions with actual errors.
2. For each function:
   a. Search the assembly for the `vcallms` instruction and its target address:
      ```bash
      grep -A 100 "FUNCTION_ADDRESS" assembly.txt | grep -i vcallms
      ```
   b. The `vcallms` operand is the VU0 microprogram entry address (in VU0 micro memory).
   c. Determine what the microprogram does (typically: matrix multiply, transform, lighting).
   d. Replace the `vcallms` call with equivalent C++ math operations.
3. Mark every translation with a comment showing the original VU0 call:
   ```cpp
   // vcallms 0x0000 — VU0 microprogram: matrix multiply
   // Replaces VU0 micro mode execution with C++ equivalent
   result = matrix * vector;
   ```

### VU0 Micro Mode Reference
- `vcallms imm`: Call VU0 microprogram at address `imm` (in VU micro memory, not EE memory).
- `vcallmsr`: Call VU0 microprogram at address stored in CMSAR0 register.
- The VU0 microprogram reads/writes VU0 registers (vf00-vf31, vi00-vi15).
- Data is passed via VU0 data memory and COP2 register transfers (`ctc2`/`cfc2`/`qmtc2`/`qmfc2`).

### Strategy per function
1. **If the microprogram is a known pattern** (matrix multiply, vector normalize, dot product): replace with C++ math.
2. **If the microprogram is unknown**: stub the function with `// TODO: VU0_MICROCODE — needs microprogram analysis` and move on.
3. **Do NOT try to emulate VU0 execution** — that's what PCSX2 does. We want HLE.

### What NOT to do
- Do NOT skip the Skill file read.
- Do NOT try to interpret VU0 microcode from the EE assembly alone — the microprogram lives in VU memory.
- Do NOT change function structure or labels.

### Completion criteria
Zero errors/warnings, all labels intact, every `vcallms` either HLE'd or stubbed with TODO comment.

---

## Lessons from Previous Phase
<!-- Claude: Add relevant findings from Phase 6 here before starting. -->

---

## Function List ({len(funcs):,} functions)

{format_function_table(funcs, include_fpu=True)}

---

## Project Completion
When all Phase 7 functions compile:
1. Write `phase7_lessons.md` — document VU0 microcode patterns found.
2. Write `project_summary.md` summarizing all phases, total functions completed,
   and remaining TODO items (especially unresolved VU0 microprograms).
3. Report completion to the user.
"""
    path = output_dir / "phase7_vu0_microcode.md"
    path.write_text(md, encoding="utf-8")
    return path, len(funcs)


def generate_orphan(funcs, data, output_dir):
    """Orphan Code — zero-reference functions, likely dead code."""
    total_size = sum(r["size"] for r in funcs)

    md = f"""# Orphan Code — Zero-Reference Functions
**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
**ELF Hash:** {data.get('elf_hash', 'N/A')}

---

## Overview
- **Total functions:** {len(funcs):,}
- **Total code size:** {total_size:,} bytes ({total_size/1024:.1f} KB)
- **What these are:** Functions with ZERO incoming references — nothing in the binary calls them.
- **Likely explanation:** Dead code, debug functions, or functions called only via jump tables not resolved by Ghidra.

---

## Instructions for Claude

### What to do
1. **Do NOT fix these proactively.** These functions are likely dead code.
2. If a compilation error in another phase mentions an orphan function, come here to fix it.
3. If after all other phases are done, the game still doesn't work correctly, check if any orphan functions are actually needed (called via indirect jumps or function pointers).

### When to investigate
- A function here has a name that suggests it's important (e.g., contains "init", "main", "update").
- The game crashes and the call stack points to an orphan function address.
- A jump table in another function targets an orphan function's address.

### What NOT to do
- Do NOT spend time fixing these unless there's evidence they're needed.
- Do NOT delete them from the build — they may be reached via indirect calls.

---

## Function List ({len(funcs):,} functions)

{format_function_table(funcs, include_fpu=False)}
"""
    path = output_dir / "orphan_code.md"
    path.write_text(md, encoding="utf-8")
    return path, len(funcs)


# =========================================================
# MAIN PHASE GENERATION ENTRY POINT
# =========================================================

def generate_phases(data, rows, output_dir):
    """Generate all phase MD files (7 phases + orphan report)."""
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    phases = classify_phases(rows)

    generators = {
        "phase1_safe_leaf": generate_phase1,
        "phase2_wrappers": generate_phase2,
        "phase3_math": generate_phase3,
        "phase4a_game_logic": generate_phase4a,
        "phase4b_state_machines": generate_phase4b,
        "phase5_acc_hazard": generate_phase5,
        "phase6_mmio": generate_phase6,
        "phase7_vu0_microcode": generate_phase7,
        "orphan_code": generate_orphan,
    }

    phase_order = [
        "phase1_safe_leaf", "phase2_wrappers", "phase3_math",
        "phase4a_game_logic", "phase4b_state_machines",
        "phase5_acc_hazard", "phase6_mmio", "phase7_vu0_microcode",
        "orphan_code",
    ]

    print("=" * 70)
    print("PS2Recomp Phase Generator")
    print(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"ELF Hash: {data.get('elf_hash', 'N/A')}")
    print("=" * 70)
    print()

    total_funcs = 0
    orphan_count = 0
    for phase_key in phase_order:
        funcs = phases[phase_key]
        gen_func = generators[phase_key]
        path, count = gen_func(funcs, data, output_dir)
        if phase_key == "orphan_code":
            orphan_count = count
        else:
            total_funcs += count
        size = sum(r["size"] for r in funcs)
        print(f"  {path.name:35s}  {count:>5,} functions  {size/1024:>8.1f} KB")

    # Count functions not assigned to any phase (SKIP, STUB)
    recompile_count = sum(1 for r in rows if r["disposition"] == "RECOMPILE")
    skip_count = sum(1 for r in rows if r["disposition"] == "SKIP")
    stub_count = sum(1 for r in rows if r["disposition"] == "STUB")

    print()
    print(f"  Active phases:    {total_funcs:>5,} / {recompile_count:,} RECOMPILE functions")
    print(f"  Orphan (deferred):{orphan_count:>5,}")
    print(f"  Skipped (SKIP):   {skip_count:>5,}")
    print(f"  Stubbed (STUB):   {stub_count:>5,}")
    print()

    expected = total_funcs + orphan_count
    if expected != recompile_count:
        diff = recompile_count - expected
        print(f"  WARNING: {diff} RECOMPILE functions were not assigned to any phase.")
        print(f"    Check classification logic if this is unexpected.")
    else:
        print(f"  All RECOMPILE functions assigned. No gaps.")

    print()
    print(f"Output directory: {output_dir.resolve()}")
    print("=" * 70)


# =========================================================
# FULL REPORT GENERATOR (original, preserved)
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
        r["_priority"] = compute_priority_score(r)

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
    # Double-click mode: no arguments → auto-find triage_map.json and generate phases
    if len(sys.argv) == 1:
        script_dir = Path(__file__).parent
        json_path = script_dir / "triage_map.json"
        if not json_path.exists():
            # Try common variations
            for name in ["triage_map.json", "triage.json"]:
                candidate = script_dir / name
                if candidate.exists():
                    json_path = candidate
                    break
            else:
                print("ERROR: triage_map.json not found in script directory.")
                print(f"  Looked in: {script_dir}")
                print(f"  Place triage_map.json next to this script, or use CLI mode:")
                print(f"  python {Path(__file__).name} <triage_map.json> <command>")
                input("\nPress Enter to exit...")
                sys.exit(1)

        print(f"Found: {json_path}")
        data = load_triage(str(json_path))
        rows = flatten_functions(data)

        output_dir = script_dir / "phases"
        generate_phases(data, rows, output_dir)

        input("\nDone! Press Enter to exit...")
        return

    # CLI mode: original argument parsing
    p = argparse.ArgumentParser(description="PS2Recomp Triage Analyzer",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("json_file")
    p.add_argument("command", choices=["stats","coverage","top","tag","category",
                                        "disposition","filter","export","report","phases"])
    p.add_argument("args", nargs="*")
    p.add_argument("--output", "-o", default=None)
    p.add_argument("--output-dir", default=None)
    p.add_argument("--category", dest="filter_category", default=None)
    p.add_argument("--tag", dest="filter_tag", default=None)
    p.add_argument("--min-fpu", type=int, default=None)
    p.add_argument("--min-size", type=int, default=None)
    p.add_argument("--min-acc", type=int, default=None)
    args = p.parse_args()

    data = load_triage(args.json_file)
    rows = flatten_functions(data)

    if args.command == "phases":
        out_dir = args.output_dir or str(Path(args.json_file).parent / "phases")
        generate_phases(data, rows, out_dir)
    elif args.command == "report":
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
        if not args.args: print("Usage: tag <n>"); return
        cmd_tag(data, rows, args.args[0])
    elif args.command == "category":
        if not args.args: print("Usage: category <n>"); return
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
