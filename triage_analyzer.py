#!/usr/bin/env python3
"""
PS2Recomp Triage Analyzer — Phase-Based MD Generator + CLI Query Tool
======================================================================
Double-click (no arguments) → scans triage_map.json in same folder,
generates 6 phase MD files with embedded Claude instructions.

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

def classify_phases(rows):
    """Assign each RECOMPILE function to exactly one phase. Returns dict of phase→list."""
    phases = {
        "phase1_safe_leaf": [],
        "phase2_wrappers": [],
        "phase3_math": [],
        "phase4_state_machines": [],
        "phase5_acc_hazard": [],
        "phase6_mmio": [],
    }

    for r in rows:
        if r["disposition"] != "RECOMPILE":
            continue

        tags = r["tag_list"]
        cat = r["category"]

        # Phase 5 — ACC hazard takes highest priority (special handling)
        if "ACC_PRECISION_HAZARD" in tags:
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
        # Phase 4 — State machines + everything else
        else:
            phases["phase4_state_machines"].append(r)

    # Sort each phase by priority score descending
    for key in phases:
        for r in phases[key]:
            r["_score"] = compute_priority_score(r)
        phases[key].sort(key=lambda x: -x["_score"])

    return phases


# =========================================================
# FUNCTION TABLE FORMATTER
# =========================================================

def format_function_table(funcs, include_fpu=True):
    """Returns a markdown table string for a list of functions."""
    lines = []

    if include_fpu:
        header = f"| {'#':>4s} | {'Address':>12s} | {'Score':>6s} | {'Size':>6s} | {'FPU':>4s} | {'ACC':>4s} | {'Br':>4s} | {'Category':>16s} | Name | Tags |"
        sep    = f"|{'-'*5}:|{'-'*13}:|{'-'*7}:|{'-'*7}:|{'-'*5}:|{'-'*5}:|{'-'*5}:|{'-'*17}:|{'-'*40}|{'-'*20}|"
        lines.append(header)
        lines.append(sep)
        for i, r in enumerate(funcs, 1):
            flags = []
            if "ACC_PRECISION_HAZARD" in r["tag_list"]: flags.append("ACC!")
            if "VU0_VECTORS" in r["tag_list"]: flags.append("VU0")
            if "USES_SPR" in r["tag_list"]: flags.append("SPR")
            if "MULTI_RETURN" in r["tag_list"]: flags.append("MR")
            if "WRITES_GLOBAL" in r["tag_list"]: flags.append("WG")
            tag_str = ", ".join(flags) if flags else "-"
            lines.append(
                f"| {i:>4d} | {r['address']:>12s} | {r['_score']:>6d} | {r['size']:>6d} | "
                f"{r.get('fpu_ops',0):>4d} | {r.get('acc_ops',0):>4d} | "
                f"{r.get('branch_ops',0):>4d} | {r['category']:>16s} | "
                f"{r['name'][:38]} | {tag_str} |"
            )
    else:
        header = f"| {'#':>4s} | {'Address':>12s} | {'Size':>6s} | {'Category':>16s} | Name |"
        sep    = f"|{'-'*5}:|{'-'*13}:|{'-'*7}:|{'-'*17}:|{'-'*45}|"
        lines.append(header)
        lines.append(sep)
        for i, r in enumerate(funcs, 1):
            lines.append(
                f"| {i:>4d} | {r['address']:>12s} | {r['size']:>6d} | "
                f"{r['category']:>16s} | {r['name'][:43]} |"
            )

    return "\n".join(lines)


# =========================================================
# PHASE MD GENERATORS
# =========================================================

def generate_phase1(funcs, data, output_dir):
    """Phase 1: SAFE_LEAF — auto-translate candidates."""
    total_size = sum(r["size"] for r in funcs)
    gp = data.get("global_pointer", "0x0037E4F0")

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
1. CHECK CURRENT STATE FIRST: If the user prompt indicates that Phase 1 is complete, skip steps 2-5 entirely and jump directly to the "Phase Transition" section at the bottom.
2. Open the corresponding `.cpp` file in `/auto_Recomp/`.
3. Fix any compilation errors (syntax, type mismatches, pointer casts).
4. Ensure all `goto` labels remain intact and unchanged.
5. Add brief comments where the logic is non-obvious.

### What NOT to do
- Do NOT translate, compile, or modify any code if the phase is already complete.
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
When ALL functions in this list compile successfully:
1. Write `phase1_lessons.md` with any patterns, common fixes, or discoveries.
2. Open `phase2_wrappers.md` and add relevant notes to its "Lessons from Previous Phase" section.
3. Report completion to the user.
"""
    path = output_dir / "phase1_safe_leaf.md"
    path.write_text(md, encoding="utf-8")
    return path, len(funcs)


def generate_phase2(funcs, data, output_dir):
    """Phase 2: WRAPPER + GETTER_OR_STUB."""
    total_size = sum(r["size"] for r in funcs)
    gp = data.get("global_pointer", "0x0037E4F0")

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
1. Open the `.cpp` file in `/auto_Recomp/`.
2. Fix compilation errors — most will be type mismatches or missing casts.
3. For wrappers: ensure the delegated call signature matches exactly (argument count, types, return type).
4. For getters: ensure the return value and global access patterns are correct.
5. Preserve all `goto` labels.

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
1. Write `phase2_lessons.md` summarizing patterns and common fixes.
2. Open `phase3_math.md` and add notes to its "Lessons from Previous Phase" section.
3. Report completion to the user.
"""
    path = output_dir / "phase2_wrappers.md"
    path.write_text(md, encoding="utf-8")
    return path, len(funcs)


def generate_phase3(funcs, data, output_dir):
    """Phase 3: MATH_VECTORS — FPU-heavy vector math."""
    total_size = sum(r["size"] for r in funcs)
    gp = data.get("global_pointer", "0x0037E4F0")
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
1. Open the `.cpp` file in `/auto_Recomp/`.
2. Fix compilation errors.
3. **COP2/VU0 translation:** Replace inline assembly with C++ math using the project's standard types (`Vector4`, GLM, or whatever the headers define). **Do NOT invent custom math structs.**
4. Search `assembly.txt` for the function's MIPS code to verify your translation:
   ```bash
   grep -A 80 "FUNCTION_ADDRESS" assembly.txt
   ```
5. Check `triage_map.json` for hardware flags:
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
1. Write `phase3_lessons.md` with FPU/COP2 patterns and fixes discovered.
2. Open `phase4_state_machines.md` and add notes to "Lessons from Previous Phase".
3. Report completion to the user.
"""
    path = output_dir / "phase3_math.md"
    path.write_text(md, encoding="utf-8")
    return path, len(funcs)


def generate_phase4(funcs, data, output_dir):
    """Phase 4: STATE_MACHINES + GAME_LOGIC + UNCATEGORIZED."""
    total_size = sum(r["size"] for r in funcs)
    gp = data.get("global_pointer", "0x0037E4F0")
    high_branch = sum(1 for r in funcs if r.get("branch_ops", 0) > 50)
    multi_ret = sum(1 for r in funcs if "MULTI_RETURN" in r["tag_list"])
    writes_global = sum(1 for r in funcs if "WRITES_GLOBAL" in r["tag_list"])

    md = f"""# Phase 4: State Machines & Game Logic — Complex Control Flow
**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
**ELF Hash:** {data.get('elf_hash', 'N/A')}
**Global Pointer ($gp):** {gp}

---

## Overview
- **Total functions:** {len(funcs):,}
- **Total code size:** {total_size:,} bytes ({total_size/1024:.1f} KB)
- **High branch count (>50):** {high_branch}
- **Multi-return functions:** {multi_ret}
- **Global writers:** {writes_global}
- **What these are:** Game state machines, menu logic, event handlers, AI, and misc game logic.
- **Expected difficulty:** HIGH. Complex control flow with many branches, switch/case patterns, and global state mutations.

---

## Instructions for Claude

### What to do
1. Open the `.cpp` file in `/auto_Recomp/`.
2. Fix compilation errors.
3. **Control flow is sacred:** These functions have dense `goto` networks that mirror the original assembly. Every label, every branch target matters.
4. Search for context when needed:
   ```bash
   grep -B 2 -A 20 "FUNCTION_NAME" triage_map.json
   grep -A 10 "FUNCTION_NAME" flowchart.txt
   grep -A 100 "FUNCTION_ADDRESS" assembly.txt
   ```

### Key patterns
- **Switch/case via jump tables:** The decompiler may produce `goto *` or computed jumps. Check `triage_map.json` for `jump_tables` field — it tells you the table address and entry count.
- **Global state writes:** Functions tagged `WRITES_GLOBAL` modify game state through `$gp`-relative stores. Ensure the global pointer is correct (`ctx->gp = {gp}`).
- **Tight loops:** Some state machines contain polling loops that may be `BUSY_WAIT_HAZARD` on PS2 — these will be flagged in the Tags column.

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
<!-- Claude: Add relevant findings from Phase 3 here before starting. -->

---

## Function List ({len(funcs):,} functions)

{format_function_table(funcs, include_fpu=True)}

---

## Phase Transition
When ALL functions compile:
1. Write `phase4_lessons.md` with patterns for control flow, jump tables, global writes.
2. Open `phase5_acc_hazard.md` and add notes to "Lessons from Previous Phase".
3. Report completion to the user.
"""
    path = output_dir / "phase4_state_machines.md"
    path.write_text(md, encoding="utf-8")
    return path, len(funcs)


def generate_phase5(funcs, data, output_dir):
    """Phase 5: ACC_PRECISION_HAZARD — accumulator precision issues."""
    total_size = sum(r["size"] for r in funcs)
    gp = data.get("global_pointer", "0x0037E4F0")

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
1. Add `// HAZARD: ACC precision` as the FIRST comment in each function.
2. Open the `.cpp` file and fix compilation errors.
3. Translate ACC operations using the pattern from the Skill file.
4. **Always** cross-reference with assembly:
   ```bash
   grep -A 100 "FUNCTION_ADDRESS" assembly.txt
   ```
5. Mark every ACC translation with a comment showing the original instruction:
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
1. Write `phase5_lessons.md` with ACC emulation patterns and edge cases.
2. Open `phase6_mmio.md` and add notes to "Lessons from Previous Phase".
3. Report completion to the user.
"""
    path = output_dir / "phase5_acc_hazard.md"
    path.write_text(md, encoding="utf-8")
    return path, len(funcs)


def generate_phase6(funcs, data, output_dir):
    """Phase 6: ACCESSES_MMIO — hardware register access."""
    total_size = sum(r["size"] for r in funcs)
    gp = data.get("global_pointer", "0x0037E4F0")

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
1. Open the `.cpp` file in `/auto_Recomp/`.
2. Identify which MMIO registers are accessed by searching assembly:
   ```bash
   grep -A 100 "FUNCTION_ADDRESS" assembly.txt
   ```
3. Check `triage_map.json` for hardware flags:
   ```bash
   grep -B 2 -A 30 "FUNCTION_NAME" triage_map.json
   ```
4. For each MMIO access, determine the correct strategy:
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

## Project Completion
When all Phase 6 functions compile:
1. Write `phase6_lessons.md` with MMIO patterns discovered.
2. Write `project_summary.md` summarizing all phases, total functions completed, and remaining TODO items.
3. Report completion to the user.
"""
    path = output_dir / "phase6_mmio.md"
    path.write_text(md, encoding="utf-8")
    return path, len(funcs)


# =========================================================
# MAIN PHASE GENERATION ENTRY POINT
# =========================================================

def generate_phases(data, rows, output_dir):
    """Generate all 6 phase MD files."""
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    phases = classify_phases(rows)

    generators = {
        "phase1_safe_leaf": generate_phase1,
        "phase2_wrappers": generate_phase2,
        "phase3_math": generate_phase3,
        "phase4_state_machines": generate_phase4,
        "phase5_acc_hazard": generate_phase5,
        "phase6_mmio": generate_phase6,
    }

    print("=" * 70)
    print("PS2Recomp Phase Generator")
    print(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"ELF Hash: {data.get('elf_hash', 'N/A')}")
    print("=" * 70)
    print()

    total_funcs = 0
    for phase_key in ["phase1_safe_leaf", "phase2_wrappers", "phase3_math",
                       "phase4_state_machines", "phase5_acc_hazard", "phase6_mmio"]:
        funcs = phases[phase_key]
        gen_func = generators[phase_key]
        path, count = gen_func(funcs, data, output_dir)
        total_funcs += count
        size = sum(r["size"] for r in funcs)
        print(f"  {path.name:30s}  {count:>5,} functions  {size/1024:>8.1f} KB")

    # Count functions not assigned to any phase (SKIP, STUB)
    recompile_count = sum(1 for r in rows if r["disposition"] == "RECOMPILE")
    skip_count = sum(1 for r in rows if r["disposition"] == "SKIP")
    stub_count = sum(1 for r in rows if r["disposition"] == "STUB")

    print()
    print(f"  Total in phases:  {total_funcs:>5,} / {recompile_count:,} RECOMPILE functions")
    print(f"  Skipped (SKIP):   {skip_count:>5,}")
    print(f"  Stubbed (STUB):   {stub_count:>5,}")
    print()

    if total_funcs != recompile_count:
        diff = recompile_count - total_funcs
        print(f"  ⚠ {diff} RECOMPILE functions were not assigned to any phase.")
        print(f"    Check classification logic if this is unexpected.")
    else:
        print(f"  ✓ All RECOMPILE functions assigned. No gaps.")

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
