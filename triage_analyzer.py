#!/usr/bin/env python3
"""
PS2Recomp Triage Analyzer v6 — Schema v6 + community-bullseye routing
================================================================
Double-click (no arguments) → scans triage_map.json in same folder,
generates phase + summary MD files with embedded Claude instructions.

v6 additions (match TriageEnricher.java schema_version=6):
  • Routes TOP_PRIORITY_FIX (focus_set) to phase_top_priority_fix.md first.
  • New phase buckets:
      phase_top_priority_fix   — community-bullseye consolidation
      phase_gif_path3          — GIF_PATH3_HAZARD / PATH3_INITIATOR / GIF_PATH3_REG_TOUCHER
      phase_z_buffer_alias     — Z_BUFFER_ALIAS_RISK / PSMT4HH_REFERENCE
      phase_mpeg_decoder       — WRITES_IPU_CMD / MPEG_DECODER_TRAP / ACCESSES_IPU_MMIO
      phase_vif_microcode      — VIF_MPG_OPCODE_BUILDER / MICROCODE_UPLOADER / VU_MICROMEM
      phase_dispfb             — DISPFB_WRITER (DBuff Reset Mystery hunt)
      phase_audio              — AUDIO_RPC_HANDLER
      phase_meswin             — MESWIN_LOADER (text/dialogue pipeline)
      phase_libgcc             — LIBGCC_INTRINSIC
      phase_safety_ctor        — CTOR_FIELD_WRITER / VTABLE_SETTER / A0_PASS / TERMINATOR
      phase_mc_gate            — MC_TRANSITION_GATE
      phase_dma_chain          — DMA_TAG_BUILDER / DMA_KICK_PATTERN
  • flatten_functions extracts callers, literal_refs, all v4/v5/v6 fields.
  • format_function_table optional Callers + Top-Refs columns.
  • Summary MD now shows focus_set, known_dc2_globals, known_gs_priv_regs,
    vif_opcode_constants, dma_tag_ids, pcsx2_baseline status.

v3 changes (matching TriageEnricher.java v3 schema_version=3):
  New phase MD:  phase_gifpk.md       sceGifPk*/sceVif1Pk* packet builders
  New phase MD:  phase_iop_rpc.md     IOP_RPC_DISPATCH functions
  New phase MD:  phase_archive_io.md  ARCHIVE_IO functions
  New section:   game_override_addresses shown in summary
  New tag columns in all tables: CONV_VIOLATION, INIT_LARGE, DMA_TTE,
                                   IOP_RPC, ARCHIVE_IO, PAD_POLL
  Phase 6 (MMIO) now has DMA_CHAIN_TTE_RISK sub-section
  Phase 4b now has PAD_POLL_LOOP sub-section
  F13 stub:  sceDmaSync non-blocking pattern included in phase instructions
  Summary MD:  shows game_override_imported count + known_iop_sids table
  classify_phases: v3 tags route correctly before fallback categories

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
            # v4/v5/v6 graph + index fields
            "callers":      func.get("callers", []),
            "literal_refs": func.get("literal_refs", []),
            "archive_io_callers": func.get("archive_io_callers", []),
            "mainloop_depth":   func.get("mainloop_depth", -1),
            "init_chain_depth": func.get("init_chain_depth", -1),
        }
        for k, v in func.get("metrics", {}).items():
            row[k] = v
        for k, v in func.get("hardware", {}).items():
            row[k] = v
        rows.append(row)
    return rows


def top_callers_str(row, n=3):
    cs = row.get("callers", [])
    if not cs:
        return "-"
    names = [(c.get("name") or c.get("address","?")) for c in cs[:n]]
    extra = f" +{len(cs)-n}" if len(cs) > n else ""
    return ", ".join(names) + extra


def top_literal_refs_str(row, n=3):
    lrs = row.get("literal_refs", [])
    if not lrs:
        return "-"
    # Prioritize gp-relative + uncommon offsets first; otherwise just first n.
    pri = [lr for lr in lrs if (lr.get("base_reg") or "").lower() == "gp"]
    rest = [lr for lr in lrs if (lr.get("base_reg") or "").lower() != "gp"]
    pick = (pri + rest)[:n]
    parts = []
    for lr in pick:
        base = lr.get("base_reg","?")
        off  = lr.get("offset","?")
        mn   = lr.get("mnem","?")
        parts.append(f"{mn} {off}({base})")
    extra = f" +{len(lrs)-n}" if len(lrs) > n else ""
    return ", ".join(parts) + extra

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

    import heapq

    # Use a min-heap with negated scores to get max-score priority
    queue = [(-by_addr[a]["_score"], a) for a in phase_addrs if in_degree[a] == 0]
    heapq.heapify(queue)

    result = []
    while queue:
        _, addr = heapq.heappop(queue)
        result.append(by_addr[addr])
        for caller_addr in reverse.get(addr, []):
            if caller_addr in in_degree:
                in_degree[caller_addr] -= 1
                if in_degree[caller_addr] == 0:
                    heapq.heappush(queue, (-by_addr[caller_addr]["_score"], caller_addr))

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
        # v6 NEW (highest priority routing — community bullseye)
        "phase_top_priority_fix":  [],
        "phase_gif_path3":         [],
        "phase_z_buffer_alias":    [],
        "phase_mpeg_decoder":      [],
        "phase_vif_microcode":     [],
        "phase_dispfb":            [],
        "phase_audio":             [],
        "phase_meswin":            [],
        "phase_libgcc":            [],
        "phase_safety_ctor":       [],
        "phase_mc_gate":           [],
        "phase_dma_chain":         [],
        # v3 buckets
        "phase_gifpk":             [],
        "phase_iop_rpc":           [],
        "phase_archive_io":        [],
        # v2 baseline
        "phase1_safe_leaf":        [],
        "phase2_wrappers":         [],
        "phase3_math":             [],
        "phase4a_game_logic":      [],
        "phase4b_state_machines":  [],
        "phase5_acc_hazard":       [],
        "phase6_mmio":             [],
        "phase7_vu0_microcode":    [],
        "orphan_code":             [],
    }

    for r in rows:
        if r["disposition"] != "RECOMPILE":
            continue

        tags = r["tag_list"]
        cat  = r["category"]

        # Orphan first (always orphan even if also bullseye, so reviewer knows it's unreferenced)
        if "ORPHAN_CODE" in tags:
            phases["orphan_code"].append(r)
            continue

        # === v6 routing: community-bullseye phases run FIRST ===
        # Top-priority consolidates the focus_set; reviewer should start here.
        if "TOP_PRIORITY_FIX" in tags:
            phases["phase_top_priority_fix"].append(r)
            continue
        if ("GIF_PATH3_HAZARD" in tags or "PATH3_INITIATOR" in tags or
            "GIF_PATH3_REG_TOUCHER" in tags or "IS_SCE_GIF_PK_REF_LOAD_IMAGE" in tags):
            phases["phase_gif_path3"].append(r)
            continue
        if "Z_BUFFER_ALIAS_RISK" in tags or "PSMT4HH_REFERENCE" in tags:
            phases["phase_z_buffer_alias"].append(r)
            continue
        if ("WRITES_IPU_CMD" in tags or "MPEG_DECODER_TRAP" in tags or
            "ACCESSES_IPU_MMIO" in tags):
            phases["phase_mpeg_decoder"].append(r)
            continue
        if ("VIF_MPG_OPCODE_BUILDER" in tags or "MICROCODE_UPLOADER" in tags or
            "ACCESSES_VU_MICROMEM" in tags):
            phases["phase_vif_microcode"].append(r)
            continue
        if "DISPFB_WRITER" in tags:
            phases["phase_dispfb"].append(r)
            continue
        if "AUDIO_RPC_HANDLER" in tags:
            phases["phase_audio"].append(r)
            continue
        if "MESWIN_LOADER" in tags:
            phases["phase_meswin"].append(r)
            continue
        if "LIBGCC_INTRINSIC" in tags:
            phases["phase_libgcc"].append(r)
            continue
        if ("CTOR_FIELD_WRITER" in tags or "VTABLE_SETTER" in tags or
            "A0_PASSTHROUGH_RETURNER" in tags or "PROCESS_TERMINATOR" in tags):
            phases["phase_safety_ctor"].append(r)
            continue
        if "MC_TRANSITION_GATE" in tags:
            phases["phase_mc_gate"].append(r)
            continue
        if ("DMA_TAG_BUILDER" in tags or "DMA_KICK_PATTERN" in tags or
            "DMA_QWC_TADR_WRITER" in tags or "DMA_CHAIN_TTE_RISK" in tags):
            phases["phase_dma_chain"].append(r)
            continue

        # === v3 buckets ===
        if is_gifpk(r) or "SCE_GIF_PK_FAMILY" in tags:
            phases["phase_gifpk"].append(r)
            continue
        if "IOP_RPC_DISPATCH" in tags:
            phases["phase_iop_rpc"].append(r)
            continue
        if "ARCHIVE_IO" in tags:
            phases["phase_archive_io"].append(r)
            continue

        # === v2 baseline ===
        if "VU0_MICROCODE" in tags:
            phases["phase7_vu0_microcode"].append(r)
        elif "ACC_PRECISION_HAZARD" in tags:
            phases["phase5_acc_hazard"].append(r)
        elif "ACCESSES_MMIO" in tags:
            phases["phase6_mmio"].append(r)
        elif "SAFE_LEAF" in tags:
            phases["phase1_safe_leaf"].append(r)
        elif "PAD_POLL_LOOP" in tags or "THREAD_SYNC_POINT" in tags or "BUSY_WAIT_HAZARD" in tags:
            phases["phase4b_state_machines"].append(r)
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
# FUNCTION TABLE FORMATTER  (v3: extra tag columns)
# =========================================================

# v3/v4/v5/v6 tag abbreviation map (shown in Tags column)
TAG_ABBREVS = [
    # Bullseye first
    ("TOP_PRIORITY_FIX",          "PRI*"),
    ("IS_SCE_GIF_PK_REF_LOAD_IMAGE", "REFLD"),
    # v6 — PCSX2-grounded HW
    ("GIF_PATH3_REG_TOUCHER",     "P3REG"),
    ("WRITES_IPU_CMD",            "IPU!"),
    ("ACCESSES_IPU_MMIO",         "IPU"),
    ("GIF_FIFO_DIRECT_WRITER",    "GIFf"),
    ("VIF1_FIFO_DIRECT_WRITER",   "VIF1f"),
    ("VIF0_FIFO_DIRECT_WRITER",   "VIF0f"),
    ("ACCESSES_VU_MICROMEM",      "VUmi"),
    ("ACCESSES_VU_DATAMEM",       "VUda"),
    ("VIF_MPG_OPCODE_BUILDER",    "MPG!"),
    ("VIF_MSCAL_OPCODE_BUILDER",  "MSCAL!"),
    ("VIF_DIRECT_OPCODE_BUILDER", "DIR"),
    ("VIF_UNPACK_OPCODE_BUILDER", "UNPK"),
    ("VIF_OPCODE_BUILDER",        "VIFOP"),
    ("DMA_TAG_BUILDER",           "DMATG"),
    ("PSMT4HH_REFERENCE",         "4HH!"),
    ("SBUS_IOP_COMM_TOUCHER",     "SBUS"),
    # v5
    ("PATH3_INITIATOR",           "P3IN"),
    ("SCE_GIF_PK_FAMILY",         "PKfam"),
    ("TEX0_REG_WRITER",           "TEX0"),
    ("PRIM_REG_READER",           "PRIM?"),
    ("RGBAQ_WRITER",              "RGBA"),
    ("DMA_KICK_PATTERN",          "DKICK"),
    ("DMA_QWC_TADR_WRITER",       "DQWC"),
    ("MICROCODE_UPLOADER",        "MCUP"),
    ("AUDIO_RPC_HANDLER",         "AUD"),
    ("MESWIN_LOADER",             "MES"),
    ("MC_TRANSITION_GATE",        "MCG"),
    # v4
    ("CTOR_FIELD_WRITER",         "CTOR"),
    ("VTABLE_SETTER",             "VT!"),
    ("A0_PASSTHROUGH_RETURNER",   "A0pa"),
    ("POLL_RETURN_CONSUMER",      "POLL"),
    ("PROCESS_TERMINATOR",        "TERM"),
    ("LIBGCC_INTRINSIC",          "LIBG"),
    ("GIF_PATH3_HAZARD",          "P3HZ"),
    ("Z_BUFFER_ALIAS_RISK",       "ZBA!"),
    ("MPEG_DECODER_TRAP",         "MPEG"),
    ("DISPFB_WRITER",             "DISP"),
    ("VIF1_TAGHI_BUILDER",        "TGHI"),
    ("TAIL_CALL_INDIRECT",        "TAIL"),
    ("INDIRECT_CALL_T9",          "JLR9"),
    # v2/v3 baseline
    ("ACC_PRECISION_HAZARD",  "ACC!"),
    ("VU0_VECTORS",           "VU0"),
    ("VU0_MICROCODE",         "uVU0"),
    ("USES_SPR",              "SPR"),
    ("MULTI_RETURN",          "MR"),
    ("WRITES_GLOBAL",         "WG"),
    ("COMPLEX_CONTROL_FLOW",  "JT"),
    ("BUSY_WAIT_HAZARD",      "BW"),
    ("SMC_HAZARD",            "SMC"),
    ("DMA_CHAIN_TTE_RISK",    "TTE!"),
    ("CONVENTION_VIOLATION",  "ARG!"),
    ("INIT_LARGE_FUNC",       "INI!"),
    ("IOP_RPC_DISPATCH",      "RPC"),
    ("ARCHIVE_IO",            "ARC"),
    ("PAD_POLL_LOOP",         "PAD!"),
    ("THREAD_SYNC_POINT",     "TSP!"),
]

def format_tag_flags(tag_list):
    flags = [abbr for tag, abbr in TAG_ABBREVS if tag in tag_list]
    return ", ".join(flags) if flags else "-"

def format_function_table(funcs, include_fpu=True, include_graph=False):
    """include_graph=True appends Callers + Top-Refs columns (v6).
    Other_Notes says: phase MD should show reverse call-graph without jq."""
    lines = []
    if include_fpu and not include_graph:
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
                f"| {i:>4d} | {r['address']:>12s} | {r.get('_score',0):>6d} | {r['size']:>6d} | "
                f"{r.get('fpu_ops',0):>4d} | {r.get('acc_ops',0):>4d} | "
                f"{r.get('branch_ops',0):>4d} | {r.get('callee_count',0):>5d} | "
                f"{r.get('xref_to_count',0):>4d} | {r['category']:>16s} | "
                f"{name:<40s} | {format_tag_flags(r['tag_list'])} |"
            )
    elif include_graph:
        # v6: graph-aware table — Address | Size | ML-depth | Name | Tags | Callers | Top Refs
        header = (f"| {'#':>4s} | {'Address':>12s} | {'Size':>6s} | {'ML':>3s} | "
                  f"Name | Tags | Callers | Top Refs |")
        sep    = (f"|{'-'*5}:|{'-'*13}:|{'-'*7}:|{'-'*4}:|"
                  f"{'-'*40}|{'-'*22}|{'-'*36}|{'-'*30}|")
        lines += [header, sep]
        for i, r in enumerate(funcs, 1):
            name = r["name"]
            if len(name) > 40:
                name = name[:22] + ".." + name[-16:]
            mld = r.get("mainloop_depth", -1)
            mld_str = "-" if mld < 0 else str(mld)
            lines.append(
                f"| {i:>4d} | {r['address']:>12s} | {r['size']:>6d} | {mld_str:>3s} | "
                f"{name:<40s} | {format_tag_flags(r['tag_list']):<22s} | "
                f"{top_callers_str(r):<36s} | {top_literal_refs_str(r):<30s} |"
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
    gp = data.get("global_pointer", "UNKNOWN ג€” MUST SET BEFORE RUNNING")
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
1. Write `phase_lessons.md` appending a section for this phase ג€” only surprises a future Claude
   wouldn't know from reading `{next_phase_file}` alone.
2. Open `{next_phase_file}` and paste relevant notes into its **"Lessons from Previous Phase"** section.
3. Report completion to the user.
"""

def generate_phase1(funcs, data, output_dir):
    total_size = sum(r["size"] for r in funcs)
    
    dict_md = _header("Phase 1: SAFE_LEAF ג€” Auto-Translate (DICTIONARY)", data) + f"""
## Function List ({len(funcs):,} functions)

{format_function_table(funcs, include_fpu=False)}
"""
    dict_path = output_dir / "phase1_safe_leaf_dict.md"
    dict_path.write_text(dict_md, encoding="utf-8")

    md = _header("Phase 1: SAFE_LEAF ג€” Auto-Translate (PROMPT)", data) + f"""
> **Recommended model:** claude-sonnet-4-6

## Overview

- **Total functions:** {len(funcs):,}
- **Total code size:** {total_size:,} bytes ({total_size/1024:.1f} KB)
- **What these are:** Leaf functions ג€” they call nothing and have no complex side effects.
- **Expected difficulty:** LOW.

- **Function Dictionary:** Please refer to `phase1_safe_leaf_dict.md` for the list of functions to process.

---

## Technical Context

2. Open the `.cpp` file in `/auto_Recomp/`. Fix compile errors only.
3. Keep all `goto` labels intact.
4. Add brief comments where logic is non-obvious.



---


{_std_transition("phase2_wrappers_prompt.md", "Phase Transition")}"""
    path = output_dir / "phase1_safe_leaf_prompt.md"
    path.write_text(md, encoding="utf-8")
    return path, len(funcs)


def generate_phase2(funcs, data, output_dir):
    total_size = sum(r["size"] for r in funcs)
    gp = data.get("global_pointer", "UNKNOWN")
    
    dict_md = _header("Phase 2: Wrappers & Getters ג€” Thin Delegation Functions (DICTIONARY)", data) + f"""
## Function List ({len(funcs):,} functions)

{format_function_table(funcs, include_fpu=False)}
"""
    dict_path = output_dir / "phase2_wrappers_dict.md"
    dict_path.write_text(dict_md, encoding="utf-8")

    md = _header("Phase 2: Wrappers & Getters ג€” Thin Delegation Functions (PROMPT)", data) + f"""
> **Recommended model:** claude-sonnet-4-6

## Overview

- **Total functions:** {len(funcs):,}
- **Total code size:** {total_size:,} bytes ({total_size/1024:.1f} KB)
- **Expected difficulty:** LOW-MEDIUM.

- **Function Dictionary:** Please refer to `phase2_wrappers_dict.md` for the list of functions to process.

---

## Technical Context

2. Fix type mismatches, missing casts, wrong arg counts in wrapped calls.
3. `$gp`-relative loads: ensure `ctx->gp = {gp}`.
4. Preserve all `goto` labels.

**Key patterns:**
- `INIT_LARGE_FUNC` (tagged `INI!`) ג€” these must RECOMPILE, never nop. If you see one here, do not stub it.
- `CONVENTION_VIOLATION` (tagged `ARG!`) ג€” check arg order carefully; a0/a1 may be swapped vs. the callee's actual signature.

---


{_std_transition("phase3_math_prompt.md", "Phase Transition")}"""
    path = output_dir / "phase2_wrappers_prompt.md"
    path.write_text(md, encoding="utf-8")
    return path, len(funcs)


def generate_phase3(funcs, data, output_dir):
    total_size  = sum(r["size"] for r in funcs)
    vu0_count   = sum(1 for r in funcs if "VU0_VECTORS" in r["tag_list"])
    high_fpu    = sum(1 for r in funcs if r.get("fpu_ops", 0) > 30)
    
    dict_md = _header("Phase 3: MATH_VECTORS ג€” FPU & Vector Operations (DICTIONARY)", data) + f"""
## Function List ({len(funcs):,} functions)

{format_function_table(funcs, include_fpu=True)}
"""
    dict_path = output_dir / "phase3_math_dict.md"
    dict_path.write_text(dict_md, encoding="utf-8")

    md = _header("Phase 3: MATH_VECTORS ג€” FPU & Vector Operations (PROMPT)", data) + f"""
> **Recommended model:** claude-sonnet-4-6

## Overview

- **Total functions:** {len(funcs):,}
- **Total code size:** {total_size:,} bytes ({total_size/1024:.1f} KB)
- **VU0/COP2 functions:** {vu0_count}
- **High FPU density (>30 ops):** {high_fpu}
- **Expected difficulty:** MEDIUM-HIGH.

- **Function Dictionary:** Please refer to `phase3_math_dict.md` for the list of functions to process.

---

## Technical Context

2. COP2/VU0 ג€” replace inline asm with project's existing math types.
3. Cross-reference: `grep -A 80 "ADDR" assembly.txt`
4. PS2 FPU quirks: no NaN/Inf, truncates toward zero. Add `// TODO: VERIFY ג€” PS2 precision` where drift matters.

| PS2 Instruction | C++ Equivalent |
|-----------------|----------------|
| `vmul.xyzw vfD,vfA,vfB` | per-component multiply |
| `vadd.xyzw vfD,vfA,vfB` | per-component add |
| `vdiv Q, vfA.x,vfB.y` | `Q = vfA.x / vfB.y` |
| `vsqrt Q, vfA.x` | `Q = sqrtf(vfA.x)` |
| `vftoi0 vfD,vfA` | truncate to int, per component |

---


{_std_transition("phase4a_game_logic_prompt.md", "Phase Transition")}"""
    path = output_dir / "phase3_math_prompt.md"
    path.write_text(md, encoding="utf-8")
    return path, len(funcs)


def generate_phase4a(funcs, data, output_dir):
    total_size    = sum(r["size"] for r in funcs)
    gp            = data.get("global_pointer", "UNKNOWN")
    writes_global = sum(1 for r in funcs if "WRITES_GLOBAL"  in r["tag_list"])
    high_xref     = sum(1 for r in funcs if r.get("xref_to_count", 0) > 10)
    large_init    = sum(1 for r in funcs if "INIT_LARGE_FUNC" in r["tag_list"])
    
    dict_md = _header("Phase 4a: Game Logic ג€” Global State & Function Calls (DICTIONARY)", data) + f"""
## Function List ({len(funcs):,} functions)

{format_function_table(funcs, include_fpu=True)}
"""
    dict_path = output_dir / "phase4a_game_logic_dict.md"
    dict_path.write_text(dict_md, encoding="utf-8")

    md = _header("Phase 4a: Game Logic ג€” Global State & Function Calls (PROMPT)", data) + f"""
> **Recommended model:** claude-sonnet-4-6

## Overview

- **Total functions:** {len(funcs):,}
- **Total code size:** {total_size:,} bytes ({total_size/1024:.1f} KB)
- **Global writers:** {writes_global}
- **High fan-in (>10 callers):** {high_xref}
- **INIT_LARGE_FUNC (must recompile):** {large_init}
- **Expected difficulty:** MEDIUM-HIGH.

- **Function Dictionary:** Please refer to `phase4a_game_logic_dict.md` for the list of functions to process.

---

## ג ן¸ INIT_LARGE_FUNC Warning

Functions tagged `INI!` are large init functions (many callees or >2000 bytes).
They **must be fully recompiled** ג€” do NOT stub or nop them.
If `init__Fv` or similar appears here, implement all side effects (global writes, thread spawns) before moving on.

---

## Technical Context

2. `$gp`-relative stores: ensure `ctx->gp = {gp}`.
2. High fan-in functions (many callers): test thoroughly before proceeding.
3. Sorted callees-first: fix B before A if A calls B.

---


{_std_transition("phase4b_state_machines_prompt.md", "Phase Transition")}"""
    path = output_dir / "phase4a_game_logic_prompt.md"
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
    tsp_funcs   = [r for r in funcs if "THREAD_SYNC_POINT"        in r["tag_list"]]

    pad_section = ""
    pad_funcs   = [r for r in funcs if "PAD_POLL_LOOP" in r["tag_list"]]
    if pad_funcs:
        pad_section = f"""
### PAD_POLL_LOOP Functions ({len(pad_funcs)}) ג€” ג ן¸ Phase F3.5 lesson

These functions contain a backward branch + call to `scePadGetState`/`sceGsSyncV`.
On the real PS2 they are busy-wait loops; in the recompiler they must NOT spin forever.

**Pattern to apply (from dc2_game_override.cpp):**
- `scePadGetState` stub must return a *changing* value (sequence 1ג†’1ג†’2ג†’5ג†’6ג†’6ג€¦).
- If the loop condition is `beqz v0, loop`, the stub must eventually return non-zero.
- Register a `bindAddressHandler` shim for each function below if it still infinite-loops.

| Address | Name |
|---------|------|
""" + "\n".join(f"| `{r['address']}` | `{r['name']}` |" for r in pad_funcs) + "\n"

    tsp_section = ""
    if tsp_funcs:
        tsp_section = f"""
### THREAD_SYNC_POINT Functions ({len(tsp_funcs)}) ג€” גš ן¸  Phase F blocker lesson

These functions contain a `syscall` instruction inside a backward branch (spin loop)
and are small (< 300 bytes). They are EE-side thread synchronization primitives ג€”
the EE thread spins calling a kernel syscall (WaitSema / SleepThread / etc.) until
the IOP or another thread signals completion.

**Phase F root cause:** `pc=0x100008` stall was the EE main thread parked in exactly
this pattern waiting on IOP sync. The thread never woke because the IOP response
stub returned immediately without signalling the semaphore.

**Rules:**
- Do NOT nop-stub these functions. The thread scheduler depends on the syscall.
- Do NOT add a `registerFunction` shim that returns 0 ג€” it bypasses the wait.
- The fix is in the IOP-side response: the stub for the IOP command that this thread
  is waiting on must call `iSignalSema` / `iWakeupThread` after completing.
- If a function here still stalls: add `[TSP] <name> spinning` stderr trace inside
  the syscall stub it calls, confirm the IOP response fires, then signal.

| Address | Name |
|---------|------|
""" + "\n".join(f"| `{r['address']}` | `{r['name']}` |" for r in tsp_funcs) + "\n"

    
    dict_md = _header("Phase 4b: State Machines ג€” Complex Control Flow (DICTIONARY)", data) + f"""
## Function List ({len(funcs):,} functions)

{format_function_table(funcs, include_fpu=True)}
"""
    dict_path = output_dir / "phase4b_state_machines_dict.md"
    dict_path.write_text(dict_md, encoding="utf-8")

    md = _header("Phase 4b: State Machines ג€” Complex Control Flow (PROMPT)", data) + f"""
> **Recommended model:** claude-sonnet-4-6

## Overview

- **Total functions:** {len(funcs):,}
- **Total code size:** {total_size:,} bytes ({total_size/1024:.1f} KB)
- **High branch count (>50):** {high_branch}
- **Multi-return functions:** {multi_ret}
- **Jump table functions:** {jump_tables}
- **PAD_POLL_LOOP (busy-wait hazard):** {pad_poll}
- **BUSY_WAIT_HAZARD (general):** {busy_wait}
- **THREAD_SYNC_POINT (IOP sync stall risk):** {len(tsp_funcs)}
- **Expected difficulty:** HIGH.

- **Function Dictionary:** Please refer to `phase4b_state_machines_dict.md` for the list of functions to process.

---
{pad_section}
{tsp_section}
---

## Technical Context

1. Control flow is sacred ג€” every `goto` label, every branch target matters.
3. `COMPLEX_CONTROL_FLOW` (`JT`) = indirect jump / switch table. Check `flowchart.txt`.
4. `WRITES_GLOBAL` (`WG`) = `$gp`-relative store, ensure `ctx->gp = {gp}`.
5. `BUSY_WAIT_HAZARD` (`BW`) = polling loop. If it spins forever in runner, add a
   `runtime->registerFunction(addr, shim)` in `dc2_game_override.cpp`.
6. `THREAD_SYNC_POINT` (`TSP!`) = EE thread blocked on IOP response. See section above ג€”
   fix is on the IOP side, NOT in this function.

**Do NOT:** restructure switch/case, reorder labels, extract state handlers.

---


{_std_transition("phase5_acc_hazard_prompt.md", "Phase Transition")}"""
    path = output_dir / "phase4b_state_machines_prompt.md"
    path.write_text(md, encoding="utf-8")
    return path, len(funcs)


def generate_phase5(funcs, data, output_dir):
    total_size = sum(r["size"] for r in funcs)
    
    dict_md = _header("Phase 5: ACC_PRECISION_HAZARD ג€” VU0 Accumulator Functions (DICTIONARY)", data) + f"""
## Function List ({len(funcs):,} functions)

{format_function_table(funcs, include_fpu=True)}
"""
    dict_path = output_dir / "phase5_acc_hazard_dict.md"
    dict_path.write_text(dict_md, encoding="utf-8")

    md = _header("Phase 5: ACC_PRECISION_HAZARD ג€” VU0 Accumulator Functions (PROMPT)", data) + f"""
> **Recommended model:** claude-opus-4-6

## Overview

- **Total functions:** {len(funcs):,}
- **Total code size:** {total_size:,} bytes ({total_size/1024:.1f} KB)
- **Expected difficulty:** VERY HIGH.
- **Skill file required:** YES ג€” read `/ps2-recomp-Agent-SKILL-0.4.3/` first.

- **Function Dictionary:** Please refer to `phase5_acc_hazard_dict.md` for the list of functions to process.

---

## Technical Context

ג ן¸ Read the Skill file BEFORE touching any function.

2. Add `// HAZARD: ACC precision` as the first comment.
2. Translate ACC ops using the Skill-file pattern.
3. Mark every ACC translation with a comment showing the original instruction.
5. Do NOT use `double` ג€” PS2-accurate behavior, not IEEE-accurate.

| PS2 Instruction | Meaning |
|-----------------|---------|
| `vmadda.xyzw ACC,vfA,vfB` | `ACC += vfA * vfB` |
| `vmsuba.xyzw ACC,vfA,vfB` | `ACC -= vfA * vfB` |
| `vmula.xyzw ACC,vfA,vfB` | `ACC = vfA * vfB` |
| `vopmsub vfD,vfA,vfB` | `vfD = ACC - vfA ֳ—_outer vfB` |
| `vmadd vfD,vfA,vfB` | `vfD = ACC + vfA * vfB` |

---


{_std_transition("phase6_mmio_prompt.md", "Phase Transition")}"""
    path = output_dir / "phase5_acc_hazard_prompt.md"
    path.write_text(md, encoding="utf-8")
    return path, len(funcs)


def generate_phase6(funcs, data, output_dir):
    total_size = sum(r["size"] for r in funcs)
    tte_funcs  = [r for r in funcs if "DMA_CHAIN_TTE_RISK" in r["tag_list"]]

    tte_section = ""
    if tte_funcs:
        tte_section = f"""
### DMA_CHAIN_TTE_RISK Sub-group ({len(tte_funcs)}) ג€” ג ן¸ Phase F7 lesson

These functions both call a `sceDmaSend*` variant AND access the VIF1 DMA channel
MMIO range (`0x10009000`). DC2 embeds meaningful VIFcodes in DMA-tag upper 64 bits
even when `CHCR.TTE = 0` (bit 6 clear). The runtime's chain walker must force-inject
`tagHi64` into the VIF1 stream when non-zero ג€” even without TTE.

**Checklist before fixing:**
- Confirm `ps2_memory.cpp` L~950: VIF1 channel force-injects `tagHi64` when non-zero.
- If DMA submission produces zero GS register writes, add `[TTE:inject]` trace around the injection.
- Do NOT set TTE bit in guest CHCR ג€” that changes game-visible state.

| Address | Name |
|---------|------|
""" + "\n".join(f"| `{r['address']}` | `{r['name']}` |" for r in tte_funcs) + "\n"

    # F13 lesson: sceDmaSync
    dma_sync_section = """
### sceDmaSync ג€” Phase F13 lesson (non-blocking stub)

`sceDmaSync_0x104b60` (and any other `sceDmaSync` variant) must return **immediately**.
All DMA transfers in the runtime are synchronous ג€” by the time the game calls sceDmaSync,
the channel has already finished.

**Correct stub pattern** (in `dc2_game_override.cpp` or the `.cpp` recomp file):
```cpp
// sceDmaSync ג€” non-blocking. All DMA is synchronous in the runtime.
// $a0 = channel number (ignored). Returns 0 (success).
setReturnS32(ctx, 0);
```

If the current stub spins on a channel-status register poll, replace the entire body with the
one-liner above. If it is bound via `registerFunction`, update that binding to a `nop_stub`
or a zero-return shim.
"""

    
    dict_md = _header("Phase 6: MMIO ג€” Hardware Register Access Functions (DICTIONARY)", data) + f"""
## Function List ({len(funcs):,} functions)

{format_function_table(funcs, include_fpu=True)}
"""
    dict_path = output_dir / "phase6_mmio_dict.md"
    dict_path.write_text(dict_md, encoding="utf-8")

    md = _header("Phase 6: MMIO ג€” Hardware Register Access Functions (PROMPT)", data) + f"""
> **Recommended model:** claude-opus-4-6

## Overview

- **Total functions:** {len(funcs):,}
- **Total code size:** {total_size:,} bytes ({total_size/1024:.1f} KB)
- **DMA_CHAIN_TTE_RISK:** {len(tte_funcs)}
- **Expected difficulty:** VERY HIGH.
- **Skill file required:** YES ג€” read `/ps2-recomp-Agent-SKILL-0.4.3/` first.

- **Function Dictionary:** Please refer to `phase6_mmio_dict.md` for the list of functions to process.

---
{tte_section}
{dma_sync_section}
---

## General Instructions

2. Identify registers accessed: `grep -A 100 "ADDR" assembly.txt`
3. Strategies per access:
   - **Stub (no-op):** DMA sync waits, polling loops ג†’ return 0.
   - **HLE:** Texture uploads, GS state writes ג†’ translate to runtime API.
   - **Flag:** `// TODO: MMIO ג€” 0xADDR ג€” needs HLE implementation`

| Range | Hardware |
|-------|----------|
| `0x10000000-0x10001FFF` | EE Timers, INTC, SIF |
| `0x10003000-0x10003FFF` | GIF |
| `0x10008000-0x1000EFFF` | DMA channels |
| `0x10009000-0x1000903F` | VIF1 channel ג† TTE risk zone |
| `0x12000000-0x12001FFF` | GS privileged |
| `0x70000000-0x70003FFF` | Scratchpad RAM |

---


{_std_transition("phase7_vu0_microcode_prompt.md", "Phase Transition")}"""
    path = output_dir / "phase6_mmio_prompt.md"
    path.write_text(md, encoding="utf-8")
    return path, len(funcs)


def generate_phase7(funcs, data, output_dir):
    total_size = sum(r["size"] for r in funcs)
    
    dict_md = _header("Phase 7: VU0 Microcode ג€” vcallms/vcallmsr Functions (DICTIONARY)", data) + f"""
## Function List ({len(funcs):,} functions)

{format_function_table(funcs, include_fpu=True)}
"""
    dict_path = output_dir / "phase7_vu0_microcode_dict.md"
    dict_path.write_text(dict_md, encoding="utf-8")

    md = _header("Phase 7: VU0 Microcode ג€” vcallms/vcallmsr Functions (PROMPT)", data) + f"""
> **Recommended model:** claude-opus-4-6

## Overview

- **Total functions:** {len(funcs):,}
- **Total code size:** {total_size:,} bytes ({total_size/1024:.1f} KB)
- **Expected difficulty:** EXTREME.
- **Skill files required:** `/ps2-recomp-Agent-SKILL-0.4.3/` AND `db-vu-instructions.md`

- **Function Dictionary:** Please refer to `phase7_vu0_microcode_dict.md` for the list of functions to process.

---

## Technical Context

ג ן¸ Read BOTH skill files before touching any function.

2. For each `vcallms`: find the target address ג†’ determine what the microprogram does.
2. Known patterns ג†’ replace with C++ math. Unknown ג†’ stub with TODO.
3. A stubbed function counts as done.

```cpp
// vcallms 0x0000 ג€” VU0 microprogram: matrix multiply
// Replaces VU0 micro mode execution with C++ equivalent
result = matrix * vector;
```

---



## Project Completion

When all Phase 7 functions compile:
1. Write `phase7_lessons.md` ג€” document VU0 patterns found.
2. Write `project_summary.md` ג€” all phases, total functions, remaining TODOs.
3. Report completion to the user.
"""
    path = output_dir / "phase7_vu0_microcode_prompt.md"
    path.write_text(md, encoding="utf-8")
    return path, len(funcs)


# =========================================================
# v3 NEW: PHASE_GIFPK
# =========================================================

def generate_phase_gifpk(funcs, data, output_dir):
    """sceGifPk* / sceVif1Pk* packet-builder functions ג€” from ps2_stubs_gifpk.inl."""
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

    
    dict_md = _header("Phase GifPk: sceGifPk* / sceVif1Pk* Packet Builders (DICTIONARY)", data) + f"""
## Function List ({len(funcs):,} functions)

{format_function_table(funcs, include_fpu=False)}
"""
    dict_path = output_dir / "phase_gifpk_dict.md"
    dict_path.write_text(dict_md, encoding="utf-8")

    md = _header("Phase GifPk: sceGifPk* / sceVif1Pk* Packet Builders (PROMPT)", data) + f"""
> **Recommended model:** claude-opus-4-6

## Overview

- **Total functions:** {len(funcs):,}
- **Total code size:** {total_size:,} bytes ({total_size/1024:.1f} KB)
- **What these are:** The GIF/VIF1 packet-builder library (`ps2_stubs_gifpk.inl`).
  These assemble DMA chains + GIF packets in guest RAM that are later kicked to VIF1/GIF.
- **Expected difficulty:** MEDIUM ג€” context-struct layout must match exactly.
- **Reference file:** `ps2_stubs_gifpk.inl` ג€” read the header comment block before touching
  any function. The struct layouts are the contract between the game and the builders.

- **Function Dictionary:** Please refer to `phase_gifpk_dict.md` for the list of functions to process.

---

## Critical: Context Struct Layout

{gifpk_layout}

---

## Technical Context

### Before touching any function
1. Read the header of `ps2_stubs_gifpk.inl` (first 75 lines) for field offsets.
2. Confirm `pkRead32` / `pkWrite32` helpers are present in the `.inl` ג€” these do
   plain `Ps2FastRead32/Ps2FastWrite32` on `(base + field_offset)`.

### Verification workflow (F10 acceptance criteria)
After implementing or correcting any builder:
1. Run the game for 10 seconds.
2. In stderr, look for:
   - `mscal > 0`  ג€” VU1 microcode kicked (builders assembled a valid MSCAL).
   - `gif > 0`    ג€” GIF DMA channel fired.
   - `XYZ2 > 0`  ג€” GS received vertex data.
3. If `dma > 3` but `gif = 0`, the DIRECT VIFcode IMMED is still 0 ג€” check
   `sceVif1PkCloseDirectCode` backpatch logic.
4. If `gif > 0` but `XYZ2 = 0`, the GIFtag REGS nibble-list is zeroed ג€” check
   `sceVif1PkOpenGifTag` tag-word construction.

### Common mistakes
| Mistake | Symptom | Fix |
|---------|---------|-----|
| Wrong field offset for `ptr` | ptr never advances ג†’ packet overwritten | Check `kGifPk_ptr = 4u`, `kVif1Pk_ptr = 4u` |
| `NLOOP` not backpatched | GIF receives NLOOP=0 ג†’ no draw | `sceGifPkCloseGifTag` must call `pkPatchNloop` |
| DIRECT VIFcode IMMED=0 | GIF receives zero qwords | `sceVif1PkCloseDirectCode` backpatch: `(ptr - vifAddr - 16) / 16` |
| DMA CNT QWC not patched | DMA chain sends 0 qwords | `vif1CloseDmaTag` must patch `lo32 = (1u<<24)|qwc` |
| `sceGifPkRefLoadImage` delegates to wrong callee | texture upload silently dropped | Must delegate to `sceGsExecLoadImage` |

### Function call order in a typical frame
```
sceVif1PkInit         ג†’ set up context
sceVif1PkCnt          ג†’ open DMA CNT tag
sceVif1PkOpenDirectCode ג†’ open DIRECT VIFcode
sceVif1PkOpenGifTag   ג†’ open GIFtag (A+D format)
sceVif1PkAddGsAD      ג†’ add GS register + data pairs   (ֳ—N)
sceVif1PkCloseGifTag  ג†’ backpatch NLOOP
sceVif1PkCloseDirectCode ג†’ backpatch DIRECT IMMED
sceVif1PkEnd          ג†’ backpatch CNT QWC, write END tag
sceDmaSend            ג†’ kick the assembled chain to VIF1
```

---


{_std_transition("phase_iop_rpc_prompt.md", "Phase Transition")}"""
    path = output_dir / "phase_gifpk_prompt.md"
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

    
    dict_md = _header("Phase IOP RPC: sceSifCallRpc / sceSifBindRpc Dispatch Functions (DICTIONARY)", data) + f"""
## Function List ({len(funcs):,} functions)

{format_function_table(funcs, include_fpu=False)}
"""
    dict_path = output_dir / "phase_iop_rpc_dict.md"
    dict_path.write_text(dict_md, encoding="utf-8")

    md = _header("Phase IOP RPC: sceSifCallRpc / sceSifBindRpc Dispatch Functions (PROMPT)", data) + f"""
> **Recommended model:** claude-opus-4-6

## Overview

- **Total functions:** {len(funcs):,}
- **Total code size:** {total_size:,} bytes ({total_size/1024:.1f} KB)
- **What these are:** Functions that call into the IOP via SIF RPC. They call `sceSifBindRpc`
  (bind a service) or `sceSifCallRpc` (call a bound service) and block until the IOP responds.
- **Expected difficulty:** HIGH ג€” requires matching each SID to a handler in `ps2_iop.cpp`.

- **Function Dictionary:** Please refer to `phase_iop_rpc_dict.md` for the list of functions to process.

---

## Architecture

```
Game EE code
  ג†’ sceSifCallRpc(sid=0xXXXX, rpcNum=0xYYYY, sendBuf, sendSize, recvBuf, recvSize)
  ג†’ ps2_iop::handleRPC(sid, rpcNum, ...)
      ג†’ handleEzMidiRpc(sid, rpcNum, ...)   if sid == DC2_EzMidi_rpcSid (0x00012346)
      ג†’ handleSoundDriverRpcService(...)     if sid == IOP_SID_SNDDRV_*
      ג†’ handleLibSdRpc(...)                  if sid == IOP_SID_LIBSD (0x80000701)
```

{sid_table}

---

## Technical Context

1. For each function, search for the SID constant:
   ```bash
   grep -A 30 "FUNCTION_ADDR" assembly.txt | grep -iE "lui|addiu|li"
   ```
2. Match the SID to `known_iop_sids` above.
3. If the SID is already handled in `ps2_iop.cpp::handleRPC`: the function just needs
   to compile ג€” the dispatch is in the runtime.
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


{_std_transition("phase_archive_io_prompt.md", "Phase Transition")}"""
    path = output_dir / "phase_iop_rpc_prompt.md"
    path.write_text(md, encoding="utf-8")
    return path, len(funcs)


# =========================================================
# v3 NEW: PHASE_ARCHIVE_IO
# =========================================================

def generate_phase_archive_io(funcs, data, output_dir):
    total_size = sum(r["size"] for r in funcs)
    
    dict_md = _header("Phase Archive IO: DATA.DAT / DATA.HD2 Archive-Backed Functions (DICTIONARY)", data) + f"""
## Function List ({len(funcs):,} functions)

{format_function_table(funcs, include_fpu=False)}
"""
    dict_path = output_dir / "phase_archive_io_dict.md"
    dict_path.write_text(dict_md, encoding="utf-8")

    md = _header("Phase Archive IO: DATA.DAT / DATA.HD2 Archive-Backed Functions (PROMPT)", data) + f"""
> **Recommended model:** claude-haiku-4-5-20251001

## Overview

- **Total functions:** {len(funcs):,}
- **Total code size:** {total_size:,} bytes ({total_size/1024:.1f} KB)
- **What these are:** Functions that reference `DATA.DAT` or `DATA.HD2` strings.
  These open files that live inside the game's archive, not at the ISO root.
- **Expected difficulty:** MEDIUM ג€” the archive reader in `ps2_syscalls_fileio.inl`
  must be working before these functions can be tested.

- **Function Dictionary:** Please refer to `phase_archive_io_dict.md` for the list of functions to process.

---

## Architecture (Phase F6 lesson)

```
fioOpen("meswin/system_1.mes")
  ג†’ isoFindFileForFio miss (not at ISO root)
  ג†’ DATA.HD2 index lookup (32-byte entries: nameOffset@+0, byteOffset@+0x10, size@+0x14)
  ג†’ IsoFdEntry with baseOffset pointing into DATA.DAT
  ג†’ fioRead/fioLseek via sector-aligned reads into DATA.DAT
```

**Entry count** = `firstNameOffset / 32` = 6692 entries for DC2.  
**String table** follows the index array inside DATA.HD2.

---

## Technical Context

1. Confirm `fioOpen` archive fallback is working: look for `[Phase F6:archive]` lines in stderr.
   If absent, the index loader hasn't fired ג€” fix `ps2_syscalls_fileio.inl` first.
2. For each function: compile normally. Archive lookup is transparent to the function itself.
3. If a function opens a path with `GetFullPath__FPcPc`: ensure the shim in
   `dc2_game_override.cpp` prepends `"cdrom0:\"` to bare filenames (Phase F5 fix).

### Common mistake ג€” args reversed (Phase F5)
`GetFullPath__FPcPc` had `$a0` / `$a1` swapped: output buffer was never written ג†’ `fioOpen("")`.
If you see any function with `CONVENTION_VIOLATION` tag (`ARG!`) that also has
`ARCHIVE_IO` tag (`ARC`), check arg order in the call to `GetFullPath` carefully.

---


{_std_transition("phase1_safe_leaf_prompt.md", "Phase Transition")}"""
    path = output_dir / "phase_archive_io_prompt.md"
    path.write_text(md, encoding="utf-8")
    return path, len(funcs)


# =========================================================
# v6 NEW: BULLSEYE / COMMUNITY-LESSON PHASES
# =========================================================

def _v6_dict_and_prompt(title, key, funcs, data, output_dir, body_md):
    """Common helper: write `<key>_dict.md` + `<key>_prompt.md`."""
    dict_md = _header(f"{title} (DICTIONARY)", data) + f"""
## Function List ({len(funcs):,} functions)

{format_function_table(funcs, include_fpu=False, include_graph=True) if funcs else "*(none)*"}
"""
    dpath = output_dir / f"{key}_dict.md"
    dpath.write_text(dict_md, encoding="utf-8")

    md = _header(f"{title} (PROMPT)", data) + body_md
    ppath = output_dir / f"{key}_prompt.md"
    ppath.write_text(md, encoding="utf-8")
    return ppath, len(funcs)


def generate_phase_top_priority_fix(funcs, data, output_dir):
    focus = data.get("focus_set", [])
    body = f"""> **Recommended model:** claude-opus-4-7
> **START HERE.** This is the community-bullseye consolidation.

## Overview

- **Total functions:** {len(funcs):,}
- **What these are:** Every function tagged with at least one of:
  `IS_SCE_GIF_PK_REF_LOAD_IMAGE`, `PATH3_INITIATOR`, `GIF_PATH3_REG_TOUCHER`,
  `Z_BUFFER_ALIAS_RISK`, `PSMT4HH_REFERENCE`, `WRITES_IPU_CMD`,
  `MPEG_DECODER_TRAP`, `VIF_MPG_OPCODE_BUILDER`, writes GS PRIM reg, touches GIF CTRL.
- **Expected difficulty:** SURGICAL — these are the exact 5–20 functions the community
  lessons say need rewriting to fix the RGB=0 / Path3 / 4HH / MPEG blockers.

- **Dictionary:** see `phase_top_priority_fix_dict.md`.
- **JSON shortlist:** `triage_map.json → focus_set` (length: {len(focus)}).

---

## Community Lessons (the WHY)

1. **4HH Z-Buffer aliasing:** Dialogue fonts hide in upper 8 bits of 24-bit Z-buffer
   using PSM=PSMT4HH (44 / 0x2C). Functions tagged `PSMT4HH_REFERENCE` construct
   that constant.
2. **GIF Path3 leak:** Font upload via `sceGifPkRefLoadImage` miscounts an A+D
   packet length → payload spills into PRIM register (offset 0x00) → all later
   3D primitives lose color. Functions tagged `IS_SCE_GIF_PK_REF_LOAD_IMAGE`
   and `PATH3_INITIATOR` are the exact spill candidates.
3. **MPEG decoder trap:** Memory-Card → video decoder stall. Functions tagged
   `WRITES_IPU_CMD` write to IPU_CMD (0x10002000) — that is the MPEG kick.
4. **Path1 / MSCAL starvation:** VU1 microcode uploads work but never get kicked.
   `VIF_MPG_OPCODE_BUILDER` = the upload-construct sites.

---

## Next Step

Apply the community-prescribed fix:

> Intercept GIF Path 3 transfers (specifically `sceGifPkRefLoadImage`) and
> implement a strict sanity check to prevent aborted 4HH font uploads from
> leaking payload data into the PRIM register, thereby preserving the 3D
> primitive render state.

For each function in the dictionary:
1. Read the recomp `.cpp` file at `recomp/<name>_0x<addr>.cpp`.
2. Cross-ref `triage_map.json[].callers` (shown in Callers column) — these
   are the wrappers that must also be patched if the fix changes the ABI.
3. If a function is tagged `IS_SCE_GIF_PK_REF_LOAD_IMAGE`:
   - Implement a host-side `bindAddressHandler` in `dc2_game_override.cpp`
     that wraps the recomp call.
   - Validate the A+D packet length against the source buffer's actual size.
   - On length mismatch: terminate the transfer early, log `[GIF:P3LEAK:guarded]`.
4. If tagged `PSMT4HH_REFERENCE`: it constructs PSM=44 (the font alias). When
   the GIF guard above fires, also redirect the texture upload to a non-Z
   shadow buffer so the 4HH alias still loads the font glyphs.

---

{_std_transition("phase_gif_path3_prompt.md", "Phase Transition")}"""
    return _v6_dict_and_prompt("Phase TOP PRIORITY — Community Bullseye Fix",
                                "phase_top_priority_fix", funcs, data, output_dir, body)


def generate_phase_gif_path3(funcs, data, output_dir):
    body = f"""> **Recommended model:** claude-opus-4-7

## Overview

- **Total functions:** {len(funcs):,}
- **What these are:** Functions touching GIF Path3 control surface — CHCR
  (0x1000A000), CTRL (0x10003000), P3CNT (0x10003090), P3TAG (0x100030A0),
  or writing to GS PRIM reg (offset 0x00).
- **Expected difficulty:** HIGH.

- **Dictionary:** see `phase_gif_path3_dict.md`.

---

## Community Root Cause (RGB=0 mystery)

`sceGifPkRefLoadImage` builds an A+D packet for font upload via GIF Path 3.
The packet's NLOOP / NREG count is miscalculated → the GIF arbiter reads past
the intended end → next packet's payload spills into PRIM register (offset 0).
PRIM gets garbage value → subsequent 3D draws inherit broken state → all
primitives untextured / RGB=0.

## What to look for in each function

| Tag | Means |
|-----|-------|
| `IS_SCE_GIF_PK_REF_LOAD_IMAGE` | The exact community bullseye. Top priority. |
| `PATH3_INITIATOR` | Writes GIF CHCR — starts a Path3 transfer. |
| `GIF_PATH3_REG_TOUCHER` | Touches P3CNT / P3TAG. Inspects Path3 state mid-flight. |
| `GIF_PATH3_HAZARD` | Writes GIF CTRL or PRIM offset directly. |

## Fix pattern

```cpp
// In dc2_game_override.cpp (Path F32-style guard):
static void sce_gif_pk_ref_load_image_guarded(...) {{
    uint32_t expectedLen = computeExpectedAdLen(args);
    if (suppliedLen != expectedLen) {{
        std::fprintf(stderr, "[GIF:P3:guard] len mismatch exp=%u got=%u\\n",
                     expectedLen, suppliedLen);
        // Truncate — never let payload bytes flow into PRIM offset 0.
        suppliedLen = expectedLen;
    }}
    delegateToReal(args);
}}
runtime.registerFunction(0x00106958u, sce_gif_pk_ref_load_image_guarded);
```

---

{_std_transition("phase_z_buffer_alias_prompt.md", "Phase Transition")}"""
    return _v6_dict_and_prompt("Phase GIF PATH3 Guard — sceGifPkRefLoadImage Bullseye",
                                "phase_gif_path3", funcs, data, output_dir, body)


def generate_phase_z_buffer_alias(funcs, data, output_dir):
    body = f"""> **Recommended model:** claude-opus-4-7

## Overview

- **Total functions:** {len(funcs):,}
- **What these are:** Functions that load PSMT4HH (44 / 0x2C), PSMT4HL (36),
  or PSMT8H (27) constants, OR write the ZBUF reg with 24-bit shift patterns.
  These are the font/dialogue glyph carriers — they hide image data in the
  unused upper 8 bits of the Z-buffer.
- **Expected difficulty:** HIGH.

- **Dictionary:** see `phase_z_buffer_alias_dict.md`.

---

## Community Lesson

> The mystery of the invisible dialogue is solved. The game does not allocate
> standard VRAM for the font texture. Instead, it hides the font data in the
> upper 8 unmapped bits of the 24-bit Z-buffer using the `4HH` format.

This phase identifies every function that participates in that alias. They
must NOT be auto-stubbed; the alias is intentional.

## Fix approach

1. Cross-ref with `phase_gif_path3` — overlap = the exact font upload pipeline.
2. The GIF Path3 guard (`phase_gif_path3_prompt.md`) protects the upload; this
   phase ensures the upload PATH is implemented correctly host-side.
3. In the host GS rasterizer: when TEX0 selects PSMT4HH, read the upper 8
   bits of each 32-bit Z-buffer slot as the font glyph index.

---

{_std_transition("phase_mpeg_decoder_prompt.md", "Phase Transition")}"""
    return _v6_dict_and_prompt("Phase Z-BUFFER ALIAS (4HH Font Hunt)",
                                "phase_z_buffer_alias", funcs, data, output_dir, body)


def generate_phase_mpeg_decoder(funcs, data, output_dir):
    body = f"""> **Recommended model:** claude-opus-4-7

## Overview

- **Total functions:** {len(funcs):,}
- **What these are:** Functions touching IPU (Image Processing Unit) MMIO
  (0x10002000-0x10003000) or calling `sceIpu*` / `sceMpeg*` / `sceDvd*`.
  The `WRITES_IPU_CMD` sub-tag flags writes to IPU_CMD (0x10002000) — the
  actual MPEG decoder kick.
- **Expected difficulty:** HIGH (or just bypass for development).

- **Dictionary:** see `phase_mpeg_decoder_dict.md`.

---

## Community Lesson

> The black screen after the Memory Card check is a known video decoder stall.
> Our `FinishForMC` handoff bypass is the vastly superior method for reaching
> the core rendering loops during development.

## Fix strategy

For development build: bypass. For production: implement IPU HLE.

**Bypass (recommended now):**
For each `WRITES_IPU_CMD` function:
```cpp
// In dc2_game_override.cpp:
runtime.registerFunction(0x<ADDR>u, nop_stub);  // skip MPEG cinematic
```

Combined with the existing F21 `FinishForMC` → `nop_stub` binding, this gets
the game through the title→menu→3D handoff without rendering any video.

**Production:** ingest the MPEG ES, decode via libavcodec, blit YUV→GS.

---

{_std_transition("phase_vif_microcode_prompt.md", "Phase Transition")}"""
    return _v6_dict_and_prompt("Phase MPEG DECODER (IPU Trap Bypass)",
                                "phase_mpeg_decoder", funcs, data, output_dir, body)


def generate_phase_vif_microcode(funcs, data, output_dir):
    body = f"""> **Recommended model:** claude-opus-4-7

## Overview

- **Total functions:** {len(funcs):,}
- **What these are:** VU1 microcode uploaders. Tagged via:
  - `VIF_MPG_OPCODE_BUILDER` — function constructs the MPG VIFcode (0x4A) via lui constant.
  - `MICROCODE_UPLOADER` — VIF1 MMIO touched + ≥4 pic-style payload loads.
  - `ACCESSES_VU_MICROMEM` — directly touches VU0/VU1 micro-mem ranges.
- **Expected difficulty:** EXTREME — VU microcode = parallel pipeline asm.

- **Dictionary:** see `phase_vif_microcode_dict.md`.

---

## Why this matters (Path1 / MSCAL Starvation mystery)

`vifWriteCount=0` despite `sceDmaSend` firing means: microcode uploads
happen at boot (F26a confirms 7 MPG uploads) but per-frame MSCAL kicks
never fire → VU1 never runs → no XGKICK → no Path1 vertices → no 3D draws.

This phase identifies every function that COULD emit MPG / MSCAL. Cross-ref
their `mainloop_depth` (`ML` column) — depth > 0 means reachable from
MainLoop; depth = -1 means boot-only.

Functions with `mainloop_depth >= 1` AND `VIF_MPG_OPCODE_BUILDER` =
per-frame microcode uploaders. If any exist and yet `vifWriteCount=0`,
the upload path is broken between this function and VIF1.

---

{_std_transition("phase_dispfb_prompt.md", "Phase Transition")}"""
    return _v6_dict_and_prompt("Phase VIF MICROCODE (Path1 / MSCAL Hunt)",
                                "phase_vif_microcode", funcs, data, output_dir, body)


def generate_phase_dispfb(funcs, data, output_dir):
    globals_map = data.get("known_dc2_globals", {})
    mg_dbuff = ""
    for off, name in globals_map.items():
        if name == "mgDBuffID":
            mg_dbuff = off
            break
    body = f"""> **Recommended model:** claude-opus-4-6

## Overview

- **Total functions:** {len(funcs):,}
- **What these are:** Functions that write to GS_DISPFB1 (0x12000070) or
  GS_DISPFB2 (0x12000090) — the privileged registers that select which VRAM
  page the CRT reads. F30 spent a whole tier locating these.
- **Expected difficulty:** MEDIUM.

- **Dictionary:** see `phase_dispfb_dict.md`.

---

## Why this matters (DBuff Reset Mystery)

F30 found CRT reading fbp=0 (empty page) while game drew to fbp=0x68.
`mgDBuffID` (DC2 global at `{mg_dbuff or '$gp - 0x77E8'}`) randomly resets
to 0 before the dual-buffer swap. This phase lists every DISPFB writer so
you can audit which one writes the bad value.

## Workflow

1. For each function: check `gs_priv_reg_hits` in `triage_map.json`. If it
   contains "DISPFB1" or "DISPFB2", it directly writes the CRT source.
2. Check the `Top Refs` column for gp-relative reads of `mgDBuffID` offset
   ({mg_dbuff or '0xFFFF8818'}) — those are the writers that pick the swap slot.
3. If any DISPFB writer has `is_mc_transition_gate` true → it's the F21
   FinishForMC area; the workaround may need extending.

---

{_std_transition("phase_audio_prompt.md", "Phase Transition")}"""
    return _v6_dict_and_prompt("Phase DISPFB (DBuff Reset Mystery)",
                                "phase_dispfb", funcs, data, output_dir, body)


def generate_phase_audio(funcs, data, output_dir):
    body = f"""> **Recommended model:** claude-sonnet-4-6

## Overview

- **Total functions:** {len(funcs):,}
- **What these are:** Audio handlers — call sceSd*/sceSpu2*/sceLibSd*/sceMSIn*
  or reference `audsrv.irx`/`libsd.irx`/`sdrdrv.irx`/`modmidi.irx` strings.
- **Expected difficulty:** MEDIUM.

- **Dictionary:** see `phase_audio_dict.md`.

---

## Goal: Real BG_048.SND playback

Currently silent. Need host audio path.

Per-function workflow:
1. Identify which IOP module/SID the function targets (cross-ref `known_iop_sids`).
2. If `sceSd*` (SPU2 sound driver): route to host SDL audio via `ps2_iop.cpp`.
3. If `sceMSIn*` (MIDI input): already nop-stubbed safely. Leave.

---

{_std_transition("phase_meswin_prompt.md", "Phase Transition")}"""
    return _v6_dict_and_prompt("Phase AUDIO (BG_048.SND silent)",
                                "phase_audio", funcs, data, output_dir, body)


def generate_phase_meswin(funcs, data, output_dir):
    body = f"""> **Recommended model:** claude-sonnet-4-6

## Overview

- **Total functions:** {len(funcs):,}
- **What these are:** Functions referencing strings `meswin`, `FontTex`,
  `sysmes`, `fonttbl`, `font2`. These are the dialogue/text → GS pipeline.
- **Expected difficulty:** HIGH (depends on `phase_z_buffer_alias` resolution).

- **Dictionary:** see `phase_meswin_dict.md`.

---

## Goal: Visible dialogue text

`meswin/*.mes` files load successfully, but text never reaches GS as visible
primitives. Community lesson says fonts use 4HH Z-buffer aliasing (see
`phase_z_buffer_alias`). This phase identifies the `.mes` parser + glyph
emitter functions that drive the rendering.

Workflow:
1. Run `phase_z_buffer_alias` first — confirms 4HH font upload path.
2. Run `phase_gif_path3` — confirms PRIM register isn't corrupted at draw time.
3. THEN this phase — the meswin code can render once the font is intact.

---

{_std_transition("phase_libgcc_prompt.md", "Phase Transition")}"""
    return _v6_dict_and_prompt("Phase MESWIN (Text & Dialogue Pipeline)",
                                "phase_meswin", funcs, data, output_dir, body)


def generate_phase_libgcc(funcs, data, output_dir):
    body = f"""> **Recommended model:** claude-sonnet-4-6

## Overview

- **Total functions:** {len(funcs):,}
- **What these are:** libgcc 64-bit / FP conversion helpers
  (`__umoddi3`, `__moddi3`, `__divdi3`, `__udivdi3`, `__muldi3`, `__fixdfdi`,
  `__floatdidf`, etc.). Force-RECOMPILE — auto-stub halts on first call.
- **Expected difficulty:** MEDIUM. Already done for the seven Phase F23a-c
  helpers; this phase covers any newly-detected ones.

---

## ABI (Phase F23c lesson)

DC2's libgcc-ps2 uses **one 64-bit value per GPR**, NOT paired-register o32:
- Arg 1 = full 64-bit in `$a0` (load via `ld a0,…`)
- Arg 2 = full 64-bit in `$a1`
- Return = full 64-bit in `$v0` (host helper writes `$v1` high half too)

Pattern (port from `dc2_game_override.cpp`):
```cpp
static uint64_t dc2_get_reg_u64(const R5900Context *ctx, int reg) {{
    return static_cast<uint64_t>(_mm_extract_epi64(ctx->r[reg], 0));
}}
static void XX_stub(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime) {{
    uint64_t a = dc2_get_reg_u64(ctx, 4);
    uint64_t b = dc2_get_reg_u64(ctx, 5);
    setReturnU64(ctx, host_op(a, b));
    ctx->pc = getRegU32(ctx, 31);
}}
```

---

{_std_transition("phase_safety_ctor_prompt.md", "Phase Transition")}"""
    return _v6_dict_and_prompt("Phase LIBGCC (64-bit / FP Helpers)",
                                "phase_libgcc", funcs, data, output_dir, body)


def generate_phase_safety_ctor(funcs, data, output_dir):
    body = f"""> **Recommended model:** claude-sonnet-4-6

## Overview

- **Total functions:** {len(funcs):,}
- **What these are:** Auto-stub safety net. Tagged via:
  - `CTOR_FIELD_WRITER` — ctor writes `*(this+K)` (small K), e.g. vtable slot.
  - `VTABLE_SETTER` — high-confidence ctor writing vtable from constant.
  - `A0_PASSTHROUGH_RETURNER` — tail `move $v0,$a0` — auto-stub returning 0 breaks chained calls.
  - `PROCESS_TERMINATOR` — `_Exit`/`abort`/`TerminateLibrary`. Auto-stub loops forever.
- **Expected difficulty:** LOW per function, but CATASTROPHIC if left auto-stubbed.

---

## Why this matters

F22 `mgCCamera` ctor was auto-stubbed → null vtable → `jr 0` → `dispatch:pc-zero`
crash. Cost a whole phase to diagnose. This phase lists every analogue so
nothing else slips through.

For each function:
1. Confirm the recomp `.cpp` is real (not `setReturnS32(ctx, 0)` placeholder).
2. If it's an A0_PASSTHROUGH_RETURNER, ensure the recomp returns `$a0`.
3. If it's a PROCESS_TERMINATOR, point it to `std::exit(0)` via override.

---

{_std_transition("phase_mc_gate_prompt.md", "Phase Transition")}"""
    return _v6_dict_and_prompt("Phase SAFETY CTOR (Auto-Stub Hazards)",
                                "phase_safety_ctor", funcs, data, output_dir, body)


def generate_phase_mc_gate(funcs, data, output_dir):
    body = f"""> **Recommended model:** claude-haiku-4-5-20251001

## Overview

- **Total functions:** {len(funcs):,}
- **What these are:** Memory-card transition gates. Name matches `*ForMC`,
  `*McCheck*`, `*McError*`, `FinishForMC`, `mcDelay`, `mcHear`. Small (<200 bytes).
- **Expected difficulty:** LOW — most just need `nop_stub` binding (F21 pattern).

---

## F21 lesson

`FinishForMC` blocked the title→menu transition. Bound to `nop_stub` →
unblocked. This phase rosters every similar gate so they can all be
audited and bound up-front instead of one-by-one as runtime stalls.

Default fix:
```cpp
runtime.registerFunction(0x<ADDR>u, nop_stub);  // MC transition gate
```

---

{_std_transition("phase_dma_chain_prompt.md", "Phase Transition")}"""
    return _v6_dict_and_prompt("Phase MC GATE (Memory-Card Transition)",
                                "phase_mc_gate", funcs, data, output_dir, body)


def generate_phase_dma_chain(funcs, data, output_dir):
    body = f"""> **Recommended model:** claude-opus-4-6

## Overview

- **Total functions:** {len(funcs):,}
- **What these are:** DMA chain assembly + kick functions. Tagged via:
  - `DMA_TAG_BUILDER` — lui constant matches DMAtag ID (CNT/REF/REFS/CALL/RET/END/REFE).
  - `DMA_KICK_PATTERN` — writes any DMA channel CHCR base (+0x00).
  - `DMA_QWC_TADR_WRITER` — writes channel +0x20 (QWC) or +0x30 (TADR).
  - `DMA_CHAIN_TTE_RISK` — DMA_send + VIF1 MMIO (F7 TTE hidden codes).
- **Expected difficulty:** HIGH.

---

## VIF DMA Flatline Mystery

`sceDmaSend` fires but `vifWriteCount=0`. This phase lists every kicker
and chain-builder so you can trace WHICH channel actually feeds VIF1.

Cross-ref `dma_kick_channels` field in `triage_map.json` per function.
Functions writing CHCR of channel `VIF1` are the ones to inspect first.

---

{_std_transition("phase_gifpk_prompt.md", "Phase Transition")}"""
    return _v6_dict_and_prompt("Phase DMA CHAIN (VIF DMA Flatline Hunt)",
                                "phase_dma_chain", funcs, data, output_dir, body)


def generate_orphan(funcs, data, output_dir):
    total_size = sum(r["size"] for r in funcs)
    
    dict_md = _header("Orphan Code — Zero-Reference Functions (DICTIONARY)", data) + f"""
## Function List ({len(funcs):,} functions)

{format_function_table(funcs, include_fpu=False) if funcs else "*(No orphan functions in this build.)*"}
"""
    dict_path = output_dir / "orphan_code_dict.md"
    dict_path.write_text(dict_md, encoding="utf-8")

    md = _header("Orphan Code — Zero-Reference Functions (PROMPT)", data) + f"""
## Overview

- **Total functions:** {len(funcs):,}
- **Total code size:** {total_size:,} bytes ({total_size/1024:.1f} KB)
- **What these are:** Functions with zero incoming references — likely dead code,
  debug utilities, or functions reachable only via unresolved jump tables.
- **Function Dictionary:** Please refer to `orphan_code_dict.md` for the list of functions.

---

## Instructions

Do NOT fix these proactively. Come here only when:
- A compilation error in another phase references one of these.
- The game crashes and a stack trace lands on one of these addresses.
- A function name here suggests it is critical (`init`, `main`, `update`, `callback`).
"""
    path = output_dir / "orphan_code_prompt.md"
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
        # v6 bullseye — run first so user lands here
        "phase_top_priority_fix": generate_phase_top_priority_fix,
        "phase_gif_path3":        generate_phase_gif_path3,
        "phase_z_buffer_alias":   generate_phase_z_buffer_alias,
        "phase_mpeg_decoder":     generate_phase_mpeg_decoder,
        "phase_vif_microcode":    generate_phase_vif_microcode,
        "phase_dispfb":           generate_phase_dispfb,
        "phase_audio":            generate_phase_audio,
        "phase_meswin":           generate_phase_meswin,
        "phase_libgcc":           generate_phase_libgcc,
        "phase_safety_ctor":      generate_phase_safety_ctor,
        "phase_mc_gate":          generate_phase_mc_gate,
        "phase_dma_chain":        generate_phase_dma_chain,
        # v3 buckets
        "phase_gifpk":            generate_phase_gifpk,
        "phase_iop_rpc":          generate_phase_iop_rpc,
        "phase_archive_io":       generate_phase_archive_io,
        # v2 baseline
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

    results = {}
    for key, gen_fn in generators.items():
        func_list = phases.get(key, [])
        path, count = gen_fn(func_list, data, output_dir)
        results[key] = (path, count)
        print(f"  [{count:>5d} funcs] ג†’ {path.name}")

    return results


# =========================================================
# SUMMARY MD  (v3: shows game_override, known_iop_sids, new tags)
# =========================================================

def generate_summary(data, rows, phases_results, output_dir):
    output_dir = Path(output_dir)
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
            ov_table += f"\n*(ג€¦ and {len(ov_addrs)-20} more ג€” see triage_map.json `game_override_addresses`)*\n"

    phase_summary = ""
    for key, (path, count) in phases_results.items():
        phase_summary += f"| `{path.name}` | {count:,} |\n"

    md = f"""# PS2Recomp Triage Summary

**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  
**ELF Hash:** {data.get('elf_hash','N/A')}  
**Schema version:** {data.get('schema_version', 1)}  
**Global Pointer:** `{data.get('global_pointer','unknown')}`  
**Text range:** `{text_range.get('start','?')}` ג€“ `{text_range.get('end','?')}`  

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
| THREAD_SYNC_POINT *(v3)* | {stats.get('thread_sync_point', tag_count('THREAD_SYNC_POINT')):,} |

---

## Phase Files Generated

| File | Functions |
|------|----------:|
{phase_summary}

---

## Game Override Status

**Pre-bound by dc2_game_override.cpp:** {data.get('game_override_imported', 0)}  
*(These addresses are excluded from triage ג€” they already have runtime bindings.)*
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

---

## v6 Community-Bullseye Tag Counts

| Tag | Count |
|-----|------:|
| TOP_PRIORITY_FIX (focus_set) | {stats.get('top_priority_fix', tag_count('TOP_PRIORITY_FIX')):,} |
| IS_SCE_GIF_PK_REF_LOAD_IMAGE | {stats.get('is_sce_gif_pk_ref_load_image', tag_count('IS_SCE_GIF_PK_REF_LOAD_IMAGE')):,} |
| PATH3_INITIATOR | {stats.get('path3_initiator', tag_count('PATH3_INITIATOR')):,} |
| GIF_PATH3_REG_TOUCHER | {stats.get('gif_path3_reg', tag_count('GIF_PATH3_REG_TOUCHER')):,} |
| GIF_PATH3_HAZARD | {stats.get('gif_path3_hazard', tag_count('GIF_PATH3_HAZARD')):,} |
| Z_BUFFER_ALIAS_RISK | {stats.get('z_buffer_alias_risk', tag_count('Z_BUFFER_ALIAS_RISK')):,} |
| PSMT4HH_REFERENCE | {stats.get('psmt4hh_reference', tag_count('PSMT4HH_REFERENCE')):,} |
| WRITES_IPU_CMD | {stats.get('writes_ipu_cmd', tag_count('WRITES_IPU_CMD')):,} |
| MPEG_DECODER_TRAP | {stats.get('mpeg_decoder_trap', tag_count('MPEG_DECODER_TRAP')):,} |
| ACCESSES_IPU_MMIO | {stats.get('ipu_mmio', tag_count('ACCESSES_IPU_MMIO')):,} |
| VIF_MPG_OPCODE_BUILDER | {stats.get('vif_mpg_builder', tag_count('VIF_MPG_OPCODE_BUILDER')):,} |
| VIF_MSCAL_OPCODE_BUILDER | {stats.get('vif_mscal_builder', tag_count('VIF_MSCAL_OPCODE_BUILDER')):,} |
| VIF_DIRECT_OPCODE_BUILDER | {stats.get('vif_direct_builder', tag_count('VIF_DIRECT_OPCODE_BUILDER')):,} |
| VIF_UNPACK_OPCODE_BUILDER | {stats.get('vif_unpack_builder', tag_count('VIF_UNPACK_OPCODE_BUILDER')):,} |
| MICROCODE_UPLOADER | {stats.get('microcode_uploader', tag_count('MICROCODE_UPLOADER')):,} |
| ACCESSES_VU_MICROMEM | {stats.get('vu_micromem', tag_count('ACCESSES_VU_MICROMEM')):,} |
| DMA_TAG_BUILDER | {stats.get('dma_tag_builder', tag_count('DMA_TAG_BUILDER')):,} |
| DMA_KICK_PATTERN | {stats.get('dma_kick_pattern', tag_count('DMA_KICK_PATTERN')):,} |
| GIF_FIFO_DIRECT_WRITER | {stats.get('gif_fifo_writer', tag_count('GIF_FIFO_DIRECT_WRITER')):,} |
| VIF1_FIFO_DIRECT_WRITER | {stats.get('vif1_fifo_writer', tag_count('VIF1_FIFO_DIRECT_WRITER')):,} |
| DISPFB_WRITER | {stats.get('dispfb_writer', tag_count('DISPFB_WRITER')):,} |
| AUDIO_RPC_HANDLER | {stats.get('audio_rpc_handler', tag_count('AUDIO_RPC_HANDLER')):,} |
| MESWIN_LOADER | {stats.get('meswin_loader', tag_count('MESWIN_LOADER')):,} |
| LIBGCC_INTRINSIC | {stats.get('libgcc_intrinsic', tag_count('LIBGCC_INTRINSIC')):,} |
| MC_TRANSITION_GATE | {stats.get('mc_transition_gate', tag_count('MC_TRANSITION_GATE')):,} |
| CTOR_FIELD_WRITER | {stats.get('ctor_field_writer', tag_count('CTOR_FIELD_WRITER')):,} |
| VTABLE_SETTER | {stats.get('vtable_setter', tag_count('VTABLE_SETTER')):,} |
| A0_PASSTHROUGH_RETURNER | {stats.get('a0_passthrough_returner', tag_count('A0_PASSTHROUGH_RETURNER')):,} |
| PROCESS_TERMINATOR | {stats.get('process_terminator', tag_count('PROCESS_TERMINATOR')):,} |
| TAIL_CALL_INDIRECT | {stats.get('tail_call_indirect', tag_count('TAIL_CALL_INDIRECT')):,} |
| INDIRECT_CALL_T9 (funcs) | {stats.get('indirect_call_t9_funcs', tag_count('INDIRECT_CALL_T9')):,} |

---

## Focus Set (top-priority bullseye — community shortlist)

{_format_focus_set(data)}

---

## Known DC2 GP-Relative Globals

{_format_kv_map(data.get('known_dc2_globals', {}))}

---

## Known GS Privileged Registers (PCSX2-grounded)

{_format_kv_map(data.get('known_gs_priv_regs', {}))}

---

## VIF Opcode Constants (from PCSX2 Vif_Codes.cpp)

{_format_kv_map(data.get('vif_opcode_constants', {}))}

---

## DMAtag IDs (from PCSX2 Dmac.h)

{_format_kv_map(data.get('dma_tag_ids', {}))}

---

## PCSX2 Runtime Baseline

{_format_pcsx2_baseline(data.get('pcsx2_baseline', {}))}
"""
    path = output_dir / "summary.md"
    path.write_text(md, encoding="utf-8")
    return path


def _format_focus_set(data):
    fs = data.get("focus_set", [])
    if not fs:
        return "*(empty — no functions met the bullseye criteria)*"
    lines = ["| Address | Name | ML-depth | Callers | Tags |",
             "|---------|------|---------:|--------:|------|"]
    for r in fs[:50]:
        tags = ", ".join(r.get("tags", []))
        if len(tags) > 60:
            tags = tags[:57] + "..."
        lines.append(f"| `{r.get('address','?')}` | `{r.get('name','?')}` | "
                     f"{r.get('mainloop_depth',-1):>4d} | {r.get('caller_count',0):>4d} | {tags} |")
    if len(fs) > 50:
        lines.append(f"\n*(... and {len(fs)-50} more — see triage_map.json `focus_set`)*")
    return "\n".join(lines)


def _format_kv_map(m):
    if not m:
        return "*(none)*"
    lines = ["| Key | Label |", "|-----|-------|"]
    for k, v in m.items():
        lines.append(f"| `{k}` | `{v}` |")
    return "\n".join(lines)


def _format_pcsx2_baseline(b):
    if not b:
        return "*(no PCSX2 baseline captures)*"
    lines = []
    for cp in ("sce_logo", "title_screen", "menu_main"):
        val = b.get(cp)
        status = "captured" if val else "empty"
        lines.append(f"- **{cp}**: {status}")
    note = b.get("_note", "")
    if note:
        lines.append(f"\n> {note}")
    return "\n".join(lines)


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


def cmd_validate(data, rows):
    print(f"\n=== Validation Report ===")
    
    recomp_rows = [r for r in rows if r["disposition"] == "RECOMPILE"]
    phases = classify_phases(rows)
    phased_funcs = sum(len(f_list) for f_list in phases.values())
    
    missing = len(recomp_rows) - phased_funcs
    if missing > 0:
        print(f"FAIL: {missing} RECOMPILE functions were not classified into any phase!")
        phased_addrs = {f["address"] for f_list in phases.values() for f in f_list}
        for r in recomp_rows:
            if r["address"] not in phased_addrs:
                print(f"  Unclassified: {r['address']} {r['name']}")
    elif missing < 0:
        print(f"FAIL: Overlap detected! Sum of phases ({phased_funcs}) > total RECOMPILE functions ({len(recomp_rows)}).")
    else:
        print("PASS: All RECOMPILE functions are mapped to exactly one phase.")
        
    print(f"Validated {len(rows)} total enriched functions (Schema v{data.get('schema_version', 1)}).")


def cmd_report(data, rows, output_path=None):
    lines = [
        f"PS2Recomp Triage Report ג€” {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
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
          f"Override pre-bound: {data.get('game_override_imported',0)} | "
          f"Focus-set: {len(data.get('focus_set', []))}")
    if sv < 6:
        print(f"WARNING: schema_version={sv} < 6. Re-run TriageEnricher.java v6 for full "
              "community-bullseye routing (Path3, 4HH, MPEG, VIF microcode, DISPFB...).")

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

    parser = argparse.ArgumentParser(description="PS2Recomp Triage Analyzer v6")
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

    p_v = sub.add_parser("validate", help="Validate JSON completeness and correctness")

    args = parser.parse_args()

    data = load_triage(args.json)
    rows = flatten_functions(data)

    sv = data.get("schema_version", 1)
    if sv < 6 and args.cmd not in (None, "stats"):
        print(f"Note: schema_version={sv}. Re-run TriageEnricher v6 for full community-bullseye routing.")

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
    elif args.cmd == "validate":
        cmd_validate(data, rows)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()

