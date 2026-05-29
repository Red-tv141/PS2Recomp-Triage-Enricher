// PS2Recomp Triage Enricher v9 (DC2 Edition) - Ghidra Script (Step 2 of Pipeline)
// ==================================================================
// Run AFTER ExportPS2Functions.java on the same Ghidra project.
//
// WHAT'S NEW IN v9 (DC2-targeted; folds in General v11/v12 detectors +
// DC2 PROJECT_STATE.md F21-F46.6 knowledge):
//   Rule 113 GIF_TAG_INLINE_BUILDER         4-stride store cluster (0/8/0x10/0x18)
//          to a common base, with stored constants whose upper byte encodes a
//          GIFtag REGS/FLG field. Catches mgEndFrame / drawing-prim packet
//          builders that the v8 raw-MMIO detectors miss.
//   Rule 114 BITBLTBUF_MACRO_SEQUENCE       Function stores const 0x50/0x51/0x52/0x53
//          (BITBLTBUF / TRXPOS / TRXREG / TRXDIR) — a complete upload macro
//          regardless of dpsm. Auto-sets writesBitbltbufReg.
//   Rule 115 DMA_CHCR_START_KICK            Loads const 0x101 (STR | TIE) AND
//          writes to a known DMA channel CHCR (Path3 starter detection).
//   Rule 116 DMA_SOURCE_CHAIN_TAG_BUILDER   Stores composite const with high
//          nibble 0x10/0x30/0x40/0x50/0x60/0x70 at offset 0 of any base —
//          CNT/REF/REFS/CALL/RET/END source-chain DMA tags.
//   Rule 117 VIF_TAG_STORED_IMMEDIATE       Any store of const-tracked reg
//          whose upper byte matches VIF_OPCODES — captures MPG/MSCAL/UNPACK
//          built ahead of DMA kick (Rule 67 detected lui only).
//   Rule 118 DMA_TAG_STORED_IMMEDIATE       Same for high-nibble DMA tag ids.
//   Rule 119 COMPOSITE_MMIO_RECOVERY        Tracks lui+ori|addiu|or composite
//          values per reg and matches against every EE peripheral range. Fixes
//          MMIO miss when Ghidra doesn't ref-flag the synthesised addr (the
//          F26 vu_micromem=0 / F31 vif1 chunk class of false negatives).
//   Rule 120 SYSCALL_TRAMPOLINE             addiu $v1,$zero,N; syscall; jr ra
//          stub — names the function from EE_SYSCALL_NAMES (db-syscalls.md).
//   Rule 121 BACKWARD_BRANCH_SYNC_WAIT      Small body, backward branch, polls
//          a load/syscall in body — F24 / F27 / F28 host-wait blocker class.
//          Tagged DC2_HOST_WAIT_CANDIDATE when also in mainLoopShield.
//   Rule 122 INFINITE_SPIN_LOOP             1-2 BB function whose only branch
//          targets its entry. Same family as F24's never-returning dispatch
//          path; quietly retired by the F23c libgcc unblock.
//   Rule 123 INFINITE_FAIL_LOOP             Backward branch into a `break`/
//          `syscall` / `nop`-only block — assertion / panic loops.
//   Rule 124 IRX_LOADER                     >=2 calls to sceSifLoadModule, or
//          1 call + IRX path string ref. IOP-side init function.
//   Rule 125 IOP_REBOOT_HANDLER             Calls sceSifRebootIop.
//   Rule 126 RENDER_FRAME_ENTRY             Name match against the DC2 render
//          frame entry list (mgEndFrame*, mgEndDraw*, mgBeginFrame*,
//          BeginDrawing*, EndDrawing*).
//   Rule 127 STRUCT_INITIALIZER             Non-ctor func that writes >=4
//          distinct +K($a0) slots. Catches mgInit-style initializers the
//          ctor demangler misses.
//   Rule 128 FUNCTION_POINTER_TABLES        Scans non-.text initialized
//          blocks for runs of >=3 valid function entry pointers (tag-tolerant
//          for boxed pointers). Discovers vtables Ghidra didn't auto-create.
//          Tags entries DISPATCH_TABLE_TARGET and table-reading funcs
//          TABLE_DISPATCH_CALL. Anonymous classes named Class_0xADDR / slot N.
//   Rule 129 MODULE_CLUSTERS                Connected components on jal
//          edges. Each function gets module_id; module addr lists emitted at
//          top level. Useful for grouping mg*/mgC*/CScene/CMap/CMenu code.
//   Rule 130 NAME_PREFIX_MODULES            Prefixes of length 2-6 occurring
//          >=5 times — surfaces engineer-visible subsystems independent of
//          callgraph.
//   Rule 131 DC2_KNOWN_FUNCTION_ADDRESSES   Hardcoded address -> {name,phase,
//          role,criticality} map from PROJECT_STATE.md so the report tool
//          can lay out priority lists without re-deriving them.
//   Rule 132 DC2_KNOWN_TBP_LABELS           VRAM heatmap labels per memory
//          invariants doc (T8_map=0x2720, font_4HH=0x10E0, CLUT_T4HH=0x3FDC,
//          mgDBuff_fbp=0x68, HUD_font_cache=16284..16316).
//   Rule 133 DC2_RUNTIME_INVARIANTS         Top-level section listing every
//          invariant confirmed across all 9 GS dumps (Path1/2 dead, REGLIST/
//          IMAGE2 never used, IMR=0x7F00, PMODE=0x7F23, FRAME PSM=0, ZBUF
//          PSM=1, HUD pages 16324..16348). Lets the report tool gray-out
//          functions whose only output is into a confirmed-dead pipe.
//   Rule 134 DC2_CALL_CHAINS                Pre-computed forward callgraphs
//          for the 5 critical chains: save_to_map_load / title_to_menu /
//          texture_upload / frame_loop / render_chain.
//   Rule 135 DC2_PAD_INPUT_SCRIPTS          Working DC2_PAD_INPUT scripts
//          from F40/F42/F46 fix logs — embedded so the runtime side can
//          re-use them as headless input templates.
//   Rule 136 SCORE_FOCUS_SYNTH              Fallback for focus_set when zero
//          bullseyes fire — picks top-32 by static score.
//   Rule 137 TRIAGE_ADVISORY_TOML           New TOML appendix [triage_advisory]
//          with nop / patch / force_recompile categorised lists, each line
//          carrying a 4-tag prioritised comment.
//   Rule 138 STUB_TOML_TAG_COMMENTS         Every spliced stub/skip entry
//          gets ` # TAG1,TAG2,TAG3` so ps2recomp.exe operators can triage
//          at a glance.
//   Rule 139 DISCOVERED_IOP_SIDS_SECTION    Aggregated map of every detected
//          SID with its caller list — captures ezMIDI / save data / loader
//          RPCs the hardcoded KNOWN_IOP_SIDS table misses.
//   Schema version bumped to 9.0.
//
// WHAT'S NEW IN v8 (DC2 Phase F36-F49 retrospective + forward F47):
//   Tier 0 — Broken-counter fixes
//   Rule 86 VIF_BUILDER counter wiring   counters now incremented; per-func
//          vif_opcodes_built[] retained.
//   Rule 87 PSMT constant — expand match Now also matches addiu/li-zero, ori-zero,
//          single-imm li for 0x2C/0x24/0x1B/0x13/0x2D (T4HH/T4HL/T8H/PSMCT16/T4).
//   Rule 88 LIBGCC_INTRINSIC exact-name  Hardcoded list (__divdi3 etc.) wired
//          alongside regex; PS2 64-bit single-reg ABI tag.
//   Rule 89 JALR_T9 accept-any-flow      Counter no longer gated on flow type;
//          tail_call_indirect splits direct vs $t9.
//   Rule 90 SPR_SYNC split fields        uses_spr / has_sync_instr / spr_sync_combined
//          emitted separately.
//   Rule 91 BITBLTBUF_T4HH depth-2       Caller of an uploader also tagged via
//          asset_upload_traces post-pass; runtime menu_only no longer suppresses.
//
//   Tier 1 — New detectors (F36/F42/F46.5/F46.6/F49 root causes)
//   Rule 92 CTOR class+global+vtable     Demangled __ct__ class name, vtable
//          install offset, vtable target addr, caller mode (direct_only /
//          indirect_only / dual / unobserved), assigned-to-global flag, sibling
//          ctor calls, ctor_risk_tier (CRITICAL / HIGH / MEDIUM / LOW).
//   Rule 93 CLASS_REGISTRY top-level     classes section grouping ctors / dtor /
//          methods / vtable_addr / has_virtual_draw / instantiation_sites.
//   Rule 94 VIRTUAL_DISPATCH_SITES       Per-func list of `lw $rX,K($a0); lw $rY,K2($rX); jalr $rY`
//          dispatch sites; slot offset captured.
//   Rule 95 GLOBAL_RETURN_TRACKING       For every jal site, look ahead for
//          `sw $v0, +imm($gp)` to discover ctor->global bindings. Catches F46.5
//          TitleCamera null-deref class of bugs. Auto-extends known_dc2_globals.
//   Rule 96 GIF_NLOOP_DOUBLE_COUNT_RISK  Function that calls both
//          makeGiftagAplusD/MakeGiftagAplusD and closePacketGifTag (Rule 86 F37).
//   Rule 97 PAD_BUTTON_MASK_CONSUMER     andi/and against a known PS2 pad mask
//          constant. Emits pad_masks_tested[] with friendly names.
//   Rule 98 OVERRIDE_CLASSIFICATION      Parses dc2_game_override.cpp helper
//          bodies; tags each binding as nop_stub / constant_return / state_machine
//          / probe / real_shim; flags retire_candidate.
//   Rule 99 FILE_PATH_SPRINTF_SOURCE     Caller of LoadFile2/sceCdRead/sceOpen
//          whose $a0 argument was set by sprintf with %s format; emits the
//          format string when resolvable.
//   Rule 100 FRAME_CLOCK_DRIVER          Function calls sceGsSyncV / WaitVSync /
//          mgEndFrame; emit per-func + collect frame_clock_drivers[].
//   Rule 101 SIF_CALL_RPC_FID            Capture the constant passed in $a1
//          to sceSifCallRpc (function-id) alongside SID.
//   Rule 102 SCEVU0_HELPER_MUSTIMPL      Whitelist sceVu0* matrix/vector
//          helpers; never auto-stubbed; emitted with vu0_helper_family.
//
//   Tier 2 — Top-level schema additions
//   Rule 103 ASSET_UPLOAD_TRACES         Cross-references gs_runtime_evidence
//          vram_upload_tbps_union and bitbltbuf_dpsms_union against per-func
//          ori/li constants + writes_bitbltbuf_reg. Back-solves which ELF
//          func should emit the missing T8 dbp=0x2720 dpsm=0x13 upload.
//   Rule 104 CURRENT_PHASE_INPUTS        Expected upload manifest (dpsm/dbp
//          pairs per phase) consumed by asset_upload_traces.
//   Rule 105 CALL_CHAINS                 save_to_map_load / title_to_menu /
//          texture_upload — pre-computed forward callgraphs to bullseye sinks.
//   Rule 106 BUILD_INVARIANTS            Build cmd + do-not-modify list emitted
//          for downstream tools.
//   Rule 107 PHASE_TRACE_FLAGS           Inventory of DC2_TRACE_* env flags.
//
//   Tier 3 — Quality of life
//   Rule 108 C++ DEMANGLER               Itanium-style __ct__<digits><name>F<args>,
//          __dt__, __vt__, method-mangled names. Adds class_name+method_name to
//          per-func record.
//   Rule 109 DIFF MODE                   If prior triage_map.json sits next to
//          output, emit `delta` section listing new/changed/removed funcs.
//   Rule 110 OVERRIDE_COVERAGE_REPORT    For every game_override binding, flag
//          retire_candidate based on current static signals.
//   Rule 111 SDK_CALLER_DEDUP_COUNT      Companion *_via_sdk_caller depth-1
//          metric for every count-zero raw-MMIO detector.
//   Rule 112 SCHEMA_VERSION              8.0.
//
// OUTPUTS:
//   1. config_auto_recomp.toml - UNIFIED config ready for ps2recomp.exe
//      (merges Step 1 config.toml + our triage additions)
//   2. triage_map.json - full DNA map with tags for the report tool
//
// WHAT'S NEW IN v4 (learned from DC2 Phase F22-F31):
//   Rule 26 CTOR_FIELD_WRITER       __ct__ that writes *(this+K); never nop-stub
//   Rule 27 VTABLE_SETTER           CTOR + lui+addiu constant -> *(this+K) (vtable)
//   Rule 28 POLL_RETURN_CONSUMER    Tiny returner polled by a backward-branching caller
//   Rule 29 A0_PASSTHROUGH_RETURNER move $v0,$a0/$a1 — auto-stub returning 0 breaks chains
//   Rule 30 PROCESS_TERMINATOR      _Exit/abort/TerminateLibrary — never nop_stub
//   Rule 31 LIBGCC_INTRINSIC        __[u]div/mod/mul/fix/floatXXdiYY libgcc helpers
//   Rule 32 GIF_PATH3_HAZARD        Touches GIF CTRL/CHCR or GS PRIM offset (0x00)
//   Rule 33 Z_BUFFER_ALIAS_RISK     ZBUF reg + dsll32/dsrl32 shift-24 pattern (4HH font)
//   Rule 34 MPEG_DECODER_TRAP       Calls sceIpu*/sceMpeg*/sceDvd* or refs mpeg.irx
//   Rule 35 DISPFB_WRITER           Writes GS reg 0x59/0x5B (DISPFB1/DISPFB2)
//   Rule 36 VIF1_TAGHI_BUILDER      VIF1 channel MMIO + dsll32/dsrl32 (DMAtag tag-high)
//   Rule 37 TAIL_CALL_INDIRECT      Terminal jr $reg (reg!=ra) as a call/computed flow
//   Rule 38 INDIRECT_CALL_T9        jalr $t9 count > 0 (vtable / PIC dispatch)
//   Rule 39 mainloop_depth          BFS depth from MainLoop (-1 if unreachable)
//   Rule 40 init_chain_depth        BFS depth from entry/_start
//   Rule 41 archive_io_callers      Per ARCHIVE_IO function, named caller list
//   Rule 42 jalSites dedup          Set semantics on (callSitePc,target) — fixes 3-count anomaly
//   Plus:   known_gs_registers map + extended IOP module string list
//
// WHAT'S NEW IN v5 (community gap closure + DC2 next-step bullseye):
//   Rule 43 IS_SCE_GIF_PK_REF_LOAD_IMAGE  Bullseye for the 4HH/Path3 guard
//   Rule 44 PATH3_INITIATOR        Writes to GIF CHCR (0x1000A000) — Path3 starters
//   Rule 45 SCE_GIF_PK_FAMILY      sceGifPk*/sceVif1Pk* roster
//   Rule 46 TEX0_REG_WRITER        GS reg 0x06/0x07 writers (TEX state corruption hunt)
//   Rule 47 PRIM_REG_READER        Reads GS reg 0x00 (PRIM corruption witnesses)
//   Rule 48 RGBAQ_WRITER           Writes GS reg 0x01 (vertex color setters)
//   Rule 49 DMA_KICK_PATTERN       Writes any DMA channel CHCR base (+0x00)
//   Rule 50 DMA_QWC_TADR_WRITER    Writes any DMA channel +0x20 (QWC) / +0x30 (TADR)
//   Rule 51 MICROCODE_UPLOADER     VIF1 MMIO + load from .text/.data (MPG payload)
//   Rule 52 AUDIO_RPC_HANDLER      sceSd*/sceSpu2*/libsd.irx audio path
//   Rule 53 MESWIN_LOADER          Refs string "meswin" — dialogue rendering pipeline
//   Rule 54 MC_TRANSITION_GATE     *ForMC/*McCheck*/*McError* small gates (FinishForMC pattern)
//   Rule 55 known_dc2_globals      JSON map of known DC2 gp-relative offsets
//   Rule 56 is_top_priority_fix    Derived: any community-bullseye tag is set
//   Rule 57 focus_set              Top-level array of every top-priority function
//
// WHAT'S NEW IN v6 (PCSX2 source-grounded):
//   Rule 58 CORRECTED GS privileged MMIO map (0x12000070=DISPFB1, 0x12000090=DISPFB2, ...)
//   Rule 59 ACCESSES_IPU_MMIO      0x10002000-0x10003000 — MPEG decoder hardware
//   Rule 60 WRITES_IPU_CMD         0x10002000 — the MPEG kick (sub-MPEG_DECODER_TRAP)
//   Rule 61 GIF_PATH3_REG_TOUCHER  GIF_P3CNT (0x10003090) or GIF_P3TAG (0x100030A0)
//   Rule 62 GIF_FIFO_DIRECT_WRITER 0x10006000 — bypass-DMA GIF write
//   Rule 63 VIF1_FIFO_DIRECT_WRITER 0x10005000 — bypass-DMA VIF1 write
//   Rule 64 VIF0_FIFO_DIRECT_WRITER 0x10004000
//   Rule 65 ACCESSES_VU_MICROMEM   VU0/VU1 micro-mem ranges (0x11000000/0x11008000)
//   Rule 66 ACCESSES_VU_DATAMEM    VU0/VU1 data-mem ranges
//   Rule 67 VIF_OPCODE_BUILDER     lui constant matches MPG/MSCAL/DIRECT/UNPACK opcode
//   Rule 68 VIF_MPG_OPCODE_BUILDER lui 0x4A__ pattern (microcode upload)
//   Rule 69 VIF_MSCAL_OPCODE_BUILDER lui 0x14__/0x15__ (kick)
//   Rule 70 VIF_DIRECT_OPCODE_BUILDER lui 0x50__/0x51__ (GIF inline)
//   Rule 71 VIF_UNPACK_OPCODE_BUILDER lui 0x60__-0x7F__ (vertex upload)
//   Rule 72 DMA_TAG_BUILDER        lui constant matches CNT/REF/REFS/CALL/RET/END/REFE
//   Rule 73 PSMT4HH_REFERENCE      lui/ori constant == 0x2C (font Z-buffer alias PSM)
//   Rule 74 SBUS_IOP_COMM_TOUCHER  0x1000F200 (MSCOM) / 0x1000F210 (SMCOM)
//   Plus: known_gs_priv_regs, vif_opcode_constants, dma_tag_ids, pcsx2_baseline metadata
//
// WHAT'S NEW IN v7 (GS-dump runtime corroboration):
//   Input: optional folder of `*.gs.summary.json` produced by
//          gs_dump_to_summary.py from PCSX2 .gs dumps. One per checkpoint
//          (SCE_Logo / Title / 3D_Scene / Inventory / Pause / Cutscene / ...).
//          Merged into runtime evidence used to corroborate static rules.
//   Rule 75 DISPFB_SDK_WRITER       Callee in {sceGsPutDispEnv,sceGsSetDispEnv,
//                                   sceGsSetCRTC,mgSetDispEnv,sceGsResetGraph}
//                                   — picks up SDK-routed DISPFB writers that
//                                   the raw-MMIO Rule 35/58 misses.
//   Rule 76 PATH3_KICK_VIA_DMA_API  Caller of sceDmaSend*/sceGifSendChain*/
//                                   sceGsSwapDBuff/sceGsExecStoreImage — the
//                                   SDK-routed Path3 starters (raw-CHCR
//                                   Rule 44 misses them).
//   Rule 78 VRAM_TBP_OVERLAY        Constants (lui/ori/addiu/li) matching
//                                   runtime-witnessed tex0_tbps or
//                                   vram_upload_tbps; emitted as
//                                   `tbp_constants_loaded` + intersection
//                                   with merged runtime as
//                                   `tbp_runtime_confirmed`.
//   Rule 79 GS_IRQ_HANDLER_SAFE_STUB Name matches Signal/Finish/Label/Intc/
//                                   sceGsSyncH/V handler shape AND all
//                                   loaded GS-dump captures show IMR fully
//                                   masking GS IRQs → tag as safe-stub
//                                   candidate (decoration; no auto disposition flip).
//   Rule 80 runtime_corroboration   Per-function block cross-checking
//                                   static bullseye predictions against the
//                                   merged runtime evidence. Adds tags:
//                                   RUNTIME_CONFIRMED         — at least one
//                                       bullseye prediction has a witness.
//                                   RUNTIME_DORMANT_GLOBAL    — bullseye
//                                       predictions but zero runtime witness
//                                       across loaded checkpoints.
//                                   RUNTIME_MENU_ONLY         — PSMT4HH_REFERENCE
//                                       only witnessed in UI checkpoints
//                                       (Inventory/Pause/Character/UI scenes),
//                                       not in 3D-scene captures.
//   Rule 81 focus_set re-rank       Confirmed entries first, dormant last.
//   Plus: gs_runtime_evidence top-level JSON block with per-checkpoint
//         facts + merged unions; auto-populated pcsx2_baseline checkpoints.
//
// WHAT'S NEW IN v7.1 (F32-F34 retrospective):
//   Rule 82 CTOR_MULTI_FIELD_INITIALIZER  Ctor / Initialize that writes
//          >= 5 distinct this+K slots in first 40 instructions. F33 caught
//          __ct__11mgCDrawPrimFv nop-stubbed → manager/PRIM/Q/Z slots all
//          garbage → entire Begin/Texture/Color chain dead. Firewalled
//          against STUB classification (forceRecompile).
//   Rule 83 DRAWING_CHAIN_DEPTH         BFS from GS-bullseye roots
//          (sceGifPk family, PATH3_INITIATOR, mgEndFrame, Begin__11mgCDrawPrim).
//          Functions with chain_depth <= 6 firewalled against STUB. Locks in
//          F33's TitleModeDraw -> PrimQuad -> SetSpriteEnv -> Begin chain.
//   Rule 84 LIFECYCLE_LAZY_INIT_GUARD   Initialize* / Begin__ / Open* / Acquire*
//          whose first instructions read this+0x00 and branch on zero, with
//          byteSize > 50. The "if (manager==null) { install manager; }"
//          pattern that F33 had to manually override. Firewalled.
//   Rule 85 BITBLTBUF_T4HH_UPLOADER     Function writes BITBLTBUF (GIF reg 0x50)
//          AND loads PSMT4HH/4HL/8H constant. The F32 BITBLTBUF.dpsm=0x2C
//          upload bullseye. Tagged separately from generic PSMT4HH_REFERENCE
//          (which is sampler-side TEX0.psm) so runtime menu_only does not
//          deprioritize these.
//   Plus: RUNTIME_MENU_ONLY refinement — skip the tag when the function is
//         a BITBLTBUF_T4HH_UPLOADER or drawing_chain_depth <= 3.
//
// RULES IMPLEMENTED (17 + tags):
//   1.  No DANGEROUS_KEYWORDS (removed - was killing game logic)
//   2.  IOP_MODULE_STRINGS: only .IRX/.irx + specific module names (no .BIN/.DAT)
//   3.  referencesIopModule: size cap 800 bytes (larger = game logic)
//   4.  accessesHardware: DATA references only (not CALL/FLOW)
//   5.  accessesHardware - ACCESSES_MMIO tag only (not disposition)
//   6.  KSEG1 masking in all address checks (addr & 0x1FFFFFFF)
//   7.  isKernelInternal replaces isRadarBehaviorallyDangerous (syscall+COP0 only)
//   8.  IOP refs - STUB, kernel internals - SKIP
//   9.  TOML parser: handles name-only AND name@address entries
//   10. Whitelist: entry/_start exempt from all firewalls
//   11. MainLoop shield: ML + depth-1 callees exempt (manual or auto-detect)
//   12. $gp fallback: lui+addiu scan in entry point for stripped binaries
//   13. SMC detection: function boundaries + instruction-at-target check
//   14. No lui scanner for VIF (didn't work, removed)
//   15. No VIF_DMA_UPLOAD tag (ACCESSES_MMIO covers it)
//   16. vcallms - VU0_MICROCODE - forced STUB
//   17. jr $reg (reg!=ra) - COMPLEX_CONTROL_FLOW tag
//   +   ORPHAN_CODE tag for zero-xref functions
//   +   Unified config output (ready for ps2recomp.exe)
//
// WHAT'S NEW IN v3 (learned from DC2 Phase F3-F12 triage):
//
//  Rule 18 - DC2 GAME OVERRIDE PARSER
//      Reads a dc2_game_override.cpp (or any *_game_override.cpp) and
//      imports every bindAddressHandler / registerFunction address as
//      already-classified. Prevents re-stubbing functions that the
//      runtime has already manually bound.
//
//  Rule 19 - CONVENTION_VIOLATION tag
//      Detects functions where Ghidra's decompiler reports a0/a1 arg
//      aliasing or where the function writes to $a1 as if it were a
//      return buffer (pattern from GetFullPath__FPcPc bug in Phase F5).
//
//  Rule 20 - INIT_LARGE_FUNC guard
//      Functions named *init* / *Init* / *__ct__* / *__sinit_* that
//      have calleeCount > 10 OR byteSize > 2000 are tagged
//      INIT_LARGE_FUNC and forced to RECOMPILE (not nop-stubbed).
//      Prevents the Phase F4 bug where init__Fv (large, spawns threads)
//      was silently nop'd.
//
//  Rule 21 - DMA_CHAIN_TTE_RISK tag
//      Functions that call both a DMA Send variant AND touch VIF1-range
//      MMIO (0x10009000) are tagged DMA_CHAIN_TTE_RISK. Flags potential
//      TTE=0 + embedded VIFcodes patterns (Phase F7 root cause).
//
//  Rule 22 - IOP_RPC_DISPATCH tag
//      Detects the sceSifCallRpc / sceSifBindRpc pattern + sid constant
//      scan. Extracts the SID literal if found, emits it into JSON for
//      cross-referencing with ps2_iop.cpp known SIDs.
//
//  Rule 23 - ARCHIVE_IO tag
//      Detects DATA.DAT / DATA.HD2 string references inside I/O
//      wrapper functions (from Phase F6). Tags for human review;
//      these are game-specific archive stubs that need real
//      implementations, not nop returns.
//
//  Rule 24 - PAD_POLL_LOOP tag
//      Detects the busy-wait pattern: small function, calls
//      scePadGetState (or has a loop branch + jal), byteSize < 200.
//      Phase F3.5 lesson: always flag pad-state polling loops early.
//
//  Improved BUSY_WAIT_HAZARD (Rule 10 refinement):
//      Now also fires when function contains a backward branch AND
//      a jal to a known syscall stub (sceGsSyncV pattern from F3.5).
//
//  Improved STUB classification (Rule 3 refinement):
//      `sceDevFont`, `sceDevCons`, `sceMSIn`, `sceSifAllocSysMemory`,
//      `sceSifLoad*`, `sceSifUnload*`, `InitTLB`, `_InitTLB`,
//      `SetTLBEntry`, `GetTLBEntry`, `InitAlarm`, `ReleaseAlarm`
//      added to RADAR_FIREWALL_PREFIXES (all appear in dc2_game_override.cpp
//      Group D as confirmed safe stubs).
//
//  OUTPUTS (unchanged filenames):
//      config_auto_recomp.toml  - unified config for ps2recomp.exe
//      triage_map.json          - full DNA map with new tags
//      assembly.txt / decompiled.txt / flowchart.txt  (unchanged)
//
// @author Puggsy + Claude (v3: DC2 Phase F3-F12 knowledge integration)
// @category PS2Recomp

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.block.*;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.mem.*;
import java.util.*;
import java.io.*;
import java.security.MessageDigest;

public class PS2Recomp_TriageEnricher extends GhidraScript {

    // =========================================================
    // PS2 ARCHITECTURE CONSTANTS
    // =========================================================
    private static final long PS2_BASE      = 0x00100000L;
    private static final long MMIO_START    = 0x10000000L;
    private static final long MMIO_END      = 0x1000FFFFL;
    private static final long KSEG1_START   = 0x20000000L;
    private static final long SPR_START     = 0x70000000L;
    private static final long SPR_END       = 0x70003FFFL;
    private static final long GLOBAL_ADDR_MIN = 0x00100000L;
    private static final long MMIO_GS_START = 0x12000000L;
    private static final long MMIO_GS_END   = 0x12002000L;

    // RULE 21: VIF1 DMA channel MMIO base
    private static final long VIF1_CHANNEL_BASE = 0x10009000L;
    private static final long VIF1_CHANNEL_END  = 0x1000903FL;

    // v4 Rule 32: GIF MMIO (CTRL + CHCR) — Path3 hazard hunt
    private static final long GIF_CTRL_BASE     = 0x10003000L;
    private static final long GIF_CTRL_END      = 0x100030FFL;
    private static final long GIF_CHCR_BASE     = 0x1000A000L;
    private static final long GIF_CHCR_END      = 0x1000A03FL;

    // v4 Rule 32/33/35: GS privileged register addresses that matter for triage.
    // PRIM=0x00 leak is the 4HH/Path3 corruption signature. Map kept for emit too.
    private static final long GS_PRIM_REG       = 0x00L;
    private static final long GS_RGBAQ_REG      = 0x01L;
    private static final long GS_TEX0_1         = 0x06L;
    private static final long GS_BITBLTBUF      = 0x50L;
    private static final long GS_TRXPOS         = 0x51L;
    private static final long GS_TRXREG         = 0x52L;
    private static final long GS_TRXDIR         = 0x53L;
    private static final long GS_ZBUF_1         = 0x4EL;
    private static final long GS_ZBUF_2         = 0x4FL;
    private static final long GS_DISPFB1        = 0x59L;
    private static final long GS_DISPFB2        = 0x5BL;
    // v9.1: complete GIF A+D register table from pcsx2/pcsx2/GS/GSRegs.h
    // (line 76-130, GIF_A_D_REG_*). Map: A+D id -> friendly name.
    private static final Map<Long,String> KNOWN_GS_REGS = new LinkedHashMap<>();
    static {
        KNOWN_GS_REGS.put(0x00L, "PRIM");
        KNOWN_GS_REGS.put(0x01L, "RGBAQ");
        KNOWN_GS_REGS.put(0x02L, "ST");
        KNOWN_GS_REGS.put(0x03L, "UV");
        KNOWN_GS_REGS.put(0x04L, "XYZF2");
        KNOWN_GS_REGS.put(0x05L, "XYZ2");
        KNOWN_GS_REGS.put(0x06L, "TEX0_1");
        KNOWN_GS_REGS.put(0x07L, "TEX0_2");
        KNOWN_GS_REGS.put(0x08L, "CLAMP_1");
        KNOWN_GS_REGS.put(0x09L, "CLAMP_2");
        KNOWN_GS_REGS.put(0x0AL, "FOG");
        KNOWN_GS_REGS.put(0x0CL, "XYZF3");
        KNOWN_GS_REGS.put(0x0DL, "XYZ3");
        KNOWN_GS_REGS.put(0x0FL, "NOP");
        KNOWN_GS_REGS.put(0x14L, "TEX1_1");
        KNOWN_GS_REGS.put(0x15L, "TEX1_2");
        KNOWN_GS_REGS.put(0x16L, "TEX2_1");
        KNOWN_GS_REGS.put(0x17L, "TEX2_2");
        KNOWN_GS_REGS.put(0x18L, "XYOFFSET_1");
        KNOWN_GS_REGS.put(0x19L, "XYOFFSET_2");
        KNOWN_GS_REGS.put(0x1AL, "PRMODECONT");
        KNOWN_GS_REGS.put(0x1BL, "PRMODE");
        KNOWN_GS_REGS.put(0x1CL, "TEXCLUT");
        KNOWN_GS_REGS.put(0x22L, "SCANMSK");
        KNOWN_GS_REGS.put(0x34L, "MIPTBP1_1");
        KNOWN_GS_REGS.put(0x35L, "MIPTBP1_2");
        KNOWN_GS_REGS.put(0x36L, "MIPTBP2_1");
        KNOWN_GS_REGS.put(0x37L, "MIPTBP2_2");
        KNOWN_GS_REGS.put(0x3BL, "TEXA");
        KNOWN_GS_REGS.put(0x3DL, "FOGCOL");
        KNOWN_GS_REGS.put(0x3FL, "TEXFLUSH");
        KNOWN_GS_REGS.put(0x40L, "SCISSOR_1");
        KNOWN_GS_REGS.put(0x41L, "SCISSOR_2");
        KNOWN_GS_REGS.put(0x42L, "ALPHA_1");
        KNOWN_GS_REGS.put(0x43L, "ALPHA_2");
        KNOWN_GS_REGS.put(0x44L, "DIMX");
        KNOWN_GS_REGS.put(0x45L, "DTHE");
        KNOWN_GS_REGS.put(0x46L, "COLCLAMP");
        KNOWN_GS_REGS.put(0x47L, "TEST_1");
        KNOWN_GS_REGS.put(0x48L, "TEST_2");
        KNOWN_GS_REGS.put(0x49L, "PABE");
        KNOWN_GS_REGS.put(0x4AL, "FBA_1");
        KNOWN_GS_REGS.put(0x4BL, "FBA_2");
        KNOWN_GS_REGS.put(0x4CL, "FRAME_1");
        KNOWN_GS_REGS.put(0x4DL, "FRAME_2");
        KNOWN_GS_REGS.put(0x4EL, "ZBUF_1");
        KNOWN_GS_REGS.put(0x4FL, "ZBUF_2");
        KNOWN_GS_REGS.put(0x50L, "BITBLTBUF");
        KNOWN_GS_REGS.put(0x51L, "TRXPOS");
        KNOWN_GS_REGS.put(0x52L, "TRXREG");
        KNOWN_GS_REGS.put(0x53L, "TRXDIR");
        KNOWN_GS_REGS.put(0x54L, "HWREG");
        KNOWN_GS_REGS.put(0x59L, "DISPFB1");
        KNOWN_GS_REGS.put(0x5BL, "DISPFB2");
        KNOWN_GS_REGS.put(0x60L, "SIGNAL");
        KNOWN_GS_REGS.put(0x61L, "FINISH");
        KNOWN_GS_REGS.put(0x62L, "LABEL");
    }

    // =========================================================
    // FIREWALL LISTS
    // Rule 1:  No DANGEROUS_KEYWORDS (removed in v2, kept removed)
    // Rule 2:  IOP_MODULE_STRINGS - .IRX/.irx + specific module names
    // v3 adds: Group D confirmed-safe prefixes from dc2_game_override.cpp
    // =========================================================
    private static final String[] RADAR_FIREWALL_PREFIXES = {
        // Original SDK prefixes
        "sceCd","sceMc","scePad","sceSif","sceDma",
        // sceVif split: low-level HW control stubs are safe; sceVif1Pk* must RECOMPILE.
        "sceVif0","sceVif1Cmd","sceVif1Stop","sceVif1Mark","sceVif1Flush",
        "sceVif1Wait","sceVif1Reset","sceVifCode",
        "sceIpu","sceGs","sceVu1",
        "malloc","free","realloc","calloc","memcpy","memset","memmove",
        "printf","sprintf","vsprintf","strcpy","strlen","strcmp","strcat",
        "sin","cos","tan","atan","atan2","sqrt","pow","exp","log","fabs","floor","ceil",
        "__builtin_new","__builtin_vec_new","__builtin_delete",
        "__sti","__std","_GLOBAL_","__gnu_","__cxa_","_Z",
        "sceOpen","sceClose","sceRead","sceWrite","sceLseek",
        "sceSifCallRpc","sceSifBindRpc",
        // v3: DC2 Group D confirmed-safe stubs (from dc2_game_override.cpp)
        "sceDevFont","sceDevCons",         // debug console - nop safe
        "sceMSIn",                         // MIDI input - nop safe
        "sceSifAllocSysMemory","sceSifFreeSysMemory",
        "sceSifUnloadModule","sceSifSearchModule",
        "sceSifLoadStart",
        "InitTLB","_InitTLB","SetTLBEntry","GetTLBEntry",
        "InitAlarm","ReleaseAlarm",
        "_sceCd_","_sceFsIob","_sceFsWait","_sceFs_",
        "scePowerOffHandler","sceIoctl",
        "sceDopen","sceDclose","sceDread","sceGetstat","sceChstat",
        "sceRename","sceChdir","sceSync","sceMount","sceUmount",
        "sceSymlink","sceReadlink","sceRemove","sceMkdir","sceRmdir",
        "sceFormat","sceAddDrv","sceDelDrv","sceDevctl",
        "sceMcEnd","mcHearAlarm","mcDelayThread","sceMcUdCheckNewCard",
        "_sceCd_cd_callback","_sceCd_cd_read_intr","sceCdPOffCallback",
        "_sceCd_Poff_Intr","_sceCd_ncmd_prechk","_sceCd_scmd_prechk",
        "printfloat","_system_header","dmaRefImage","EnableCache","DisableCache",
        "isceSifSetDma","isceSifSetDChain","_sceCallCode"
    };

    private static final String[] BIOS_FIREWALL_PREFIXES = {
        "CreateThread","StartThread","ExitThread","SleepThread",
        "WakeupThread","iWakeupThread","RotateThreadReadyQueue",
        "CreateSema","WaitSema","SignalSema","DeleteSema",
        "iWaitSema","iSignalSema","PollSema","iPollSema",
        "AddIntcHandler","RemoveIntcHandler","EnableIntc","DisableIntc",
        "AddDmacHandler","RemoveDmacHandler","EnableDmac","DisableDmac",
        "SetVSyncFlag","SetSyscall","SetVBlankHandler","SetHBlankHandler",
        "FlushCache","AllocSysMemory","FreeSysMemory"
    };

    // Rule 2: IOP module string detection
    // v4: added mpeg/dvd/sndstrm/mpu module names (Rule 34 MPEG_DECODER_TRAP cross-ref)
    private static final String[] IOP_MODULE_STRINGS = {
        "loadcore","iopmac","iopheap","threadman","sysclib","sifman","sifcmd",
        "cdvdman","cdvdfsv","mcman","xmcman","mcserv","atad","hdd","pfs",
        "sio2man","padman","xpadman","mtapman","libsd","sdrdrv","audsrv","modmidi",
        "usbd","dev9","smap","ps2smap","ps2ip",".IRX",".irx",
        // v4 additions — IOP video / audio streaming modules. Relevant for
        // MPEG_DECODER_TRAP (Rule 34) and future audio-routing work.
        "mpeg.irx","libmpeg.irx","scedvd.irx","sndstrm.irx","mpu.irx"
    };

    // v4 Rule 34: MPEG / IPU / DVD callee prefixes
    private static final String[] MPEG_CALLEE_PREFIXES = {
        "sceIpu","sceMpeg","sceDvd","sceCdvdStream"
    };

    // v4 Rule 30: process-terminator names. Auto-stub returning 0 either looped
    // forever (F5 _Exit) or skipped real cleanup. Never nop_stub.
    private static final Set<String> PROCESS_TERMINATOR_NAMES = new HashSet<>(Arrays.asList(
        "_Exit","exit","_exit","abort","TerminateLibrary","_ExitDeleteThread",
        "ExitDeleteThread","ExitThread"
    ));

    // ===== v5 constants =====
    // Rule 43: the bullseye function for the 4HH/Path3 community fix.
    // Match either bare name or *_0xADDR Ghidra mangled variants.
    private static final String SCE_GIF_PK_REF_LOAD_IMAGE = "sceGifPkRefLoadImage";

    // Rule 45: sceGifPk* / sceVif1Pk* family roster (Python already filters on
    // these; expose at Java level so graph queries can pivot on the field).
    private static final String[] SCE_GIF_PK_PREFIXES = {
        "sceGifPk","sceVif1Pk"
    };

    // Rule 49/50: all DMA channel CHCR bases. Channel layout = base+0x00 CHCR,
    // base+0x10 MADR, base+0x20 QWC, base+0x30 TADR, base+0x40 ASR0, +0x50 ASR1.
    // Channels: 0x10008000 VIF0, 0x10009000 VIF1, 0x1000A000 GIF, 0x1000B000
    // fromIPU, 0x1000B400 toIPU, 0x1000C000 SIF0, 0x1000C400 SIF1, 0x1000C800
    // SIF2, 0x1000D000 fromSPR, 0x1000D400 toSPR.
    private static final long[] DMA_CHANNEL_BASES = {
        0x10008000L, 0x10009000L, 0x1000A000L, 0x1000B000L, 0x1000B400L,
        0x1000C000L, 0x1000C400L, 0x1000C800L, 0x1000D000L, 0x1000D400L
    };
    private static final String[] DMA_CHANNEL_NAMES = {
        "VIF0","VIF1","GIF","fromIPU","toIPU","SIF0","SIF1","SIF2","fromSPR","toSPR"
    };

    // Rule 52: audio callee / module-string roster.
    private static final String[] AUDIO_CALLEE_PREFIXES = {
        "sceSd","sceSpu2","sceLibSd","sceAudio","sceMSIn","sceLibsd"
    };
    private static final String[] AUDIO_MODULE_STRINGS = {
        "audsrv.irx","libsd.irx","libsd","sdrdrv.irx","sdrdrv","modmidi.irx"
    };

    // Rule 53: dialogue/menu text source path.
    private static final String[] MESWIN_STRINGS = {
        "meswin","FontTex","sysmes","fonttbl","font2"
    };

    // Rule 54: memory-card transition gates that historically had to be no-op'd
    // (F21 FinishForMC, F-future McError). Small + name match.
    private static final String[] MC_GATE_NAME_FRAGMENTS = {
        "ForMC","McCheck","McError","FinishForMC","McUd","mcDelay","mcHear"
    };

    // Rule 55: known DC2 gp-relative globals (signed 16-bit offset OR 32-bit
    // unsigned encoding as it appears in addiu). Emitted as a labelled map so
    // the report tool can decode literal_refs base=$gp hits without humans
    // memorising offsets. Confirmed values pulled from dc2_game_override.cpp
    // probes. Extend as further offsets are confirmed.
    // ===== v6 PCSX2-grounded HW maps =====
    // PCSX2 Hw.h: GS PRIVILEGED registers live at 0x12000000+ with these REAL
    // offsets. v4's GS register map confused these with GIF A+D reg numbers
    // (which are payload encodings, not MMIO offsets). v6 separates the two.
    private static final long GS_PRIV_START = 0x12000000L;
    private static final long GS_PRIV_END   = 0x12001100L;
    private static final Map<Long,String> KNOWN_GS_PRIV_REGS = new LinkedHashMap<>();
    static {
        KNOWN_GS_PRIV_REGS.put(0x00L, "PMODE");
        KNOWN_GS_PRIV_REGS.put(0x10L, "SMODE1");
        KNOWN_GS_PRIV_REGS.put(0x20L, "SMODE2");
        KNOWN_GS_PRIV_REGS.put(0x30L, "SRFSH");
        KNOWN_GS_PRIV_REGS.put(0x40L, "SYNCH1");
        KNOWN_GS_PRIV_REGS.put(0x50L, "SYNCH2");
        KNOWN_GS_PRIV_REGS.put(0x60L, "SYNCV");
        KNOWN_GS_PRIV_REGS.put(0x70L, "DISPFB1");      // CORRECT addr (was 0x59 in v4)
        KNOWN_GS_PRIV_REGS.put(0x80L, "DISPLAY1");
        KNOWN_GS_PRIV_REGS.put(0x90L, "DISPFB2");      // CORRECT addr (was 0x5B in v4)
        KNOWN_GS_PRIV_REGS.put(0xA0L, "DISPLAY2");
        KNOWN_GS_PRIV_REGS.put(0xB0L, "EXTBUF");
        KNOWN_GS_PRIV_REGS.put(0xC0L, "EXTDATA");
        KNOWN_GS_PRIV_REGS.put(0xD0L, "EXTWRITE");
        KNOWN_GS_PRIV_REGS.put(0xE0L, "BGCOLOR");
        KNOWN_GS_PRIV_REGS.put(0x1000L, "CSR");
        KNOWN_GS_PRIV_REGS.put(0x1010L, "IMR");
        KNOWN_GS_PRIV_REGS.put(0x1040L, "BUSDIR");
        KNOWN_GS_PRIV_REGS.put(0x1080L, "SIGLBLID");
    }

    // PCSX2 EEMemoryMap: IPU MMIO + GIF Path3 control + FIFO direct writes.
    private static final long IPU_MMIO_START      = 0x10002000L;
    private static final long IPU_MMIO_END        = 0x10003000L;
    private static final long IPU_CMD             = 0x10002000L;
    private static final long IPU_CTRL            = 0x10002010L;
    private static final long IPU_BP              = 0x10002020L;
    private static final long IPU_TOP             = 0x10002030L;

    private static final long GIF_REG_CTRL        = 0x10003000L;
    private static final long GIF_REG_MODE        = 0x10003010L;
    private static final long GIF_REG_STAT        = 0x10003020L;
    private static final long GIF_P3CNT           = 0x10003090L;   // Path3 transfer counter
    private static final long GIF_P3TAG           = 0x100030A0L;   // Path3 active tag

    private static final long VIF0_FIFO_START     = 0x10004000L;
    private static final long VIF0_FIFO_END       = 0x10004FFFL;
    private static final long VIF1_FIFO_START     = 0x10005000L;
    private static final long VIF1_FIFO_END       = 0x10005FFFL;
    private static final long GIF_FIFO_START      = 0x10006000L;
    private static final long GIF_FIFO_END        = 0x10006FFFL;
    private static final long IPU_FIFO_START      = 0x10007000L;
    private static final long IPU_FIFO_END        = 0x10007FFFL;

    // VU memory ranges (EE side mapping)
    private static final long VU0_MICRO_START     = 0x11000000L;
    private static final long VU0_MICRO_END       = 0x11000FFFL;
    private static final long VU0_DATA_START      = 0x11004000L;
    private static final long VU0_DATA_END        = 0x11004FFFL;
    private static final long VU1_MICRO_START     = 0x11008000L;
    private static final long VU1_MICRO_END       = 0x1100BFFFL;
    private static final long VU1_DATA_START      = 0x1100C000L;
    private static final long VU1_DATA_END        = 0x1100FFFFL;

    // EE-EE SBUS comm regs (kernel/IOP cross-talk)
    private static final long SBUS_MSCOM          = 0x1000F200L;
    private static final long SBUS_SMCOM          = 0x1000F210L;

    // PCSX2 Vif_Codes.cpp: VIFcode opcode (upper byte of 32-bit VIFcode word).
    // Functions that build VIFcodes via `lui $rN, 0xOPCC` will reveal which
    // command they emit. Map: opcode -> friendly name.
    private static final Map<Long,String> VIF_OPCODES = new LinkedHashMap<>();
    static {
        VIF_OPCODES.put(0x00L, "NOP");
        VIF_OPCODES.put(0x01L, "STCYCL");
        VIF_OPCODES.put(0x02L, "OFFSET");
        VIF_OPCODES.put(0x03L, "BASE");
        VIF_OPCODES.put(0x04L, "ITOP");
        VIF_OPCODES.put(0x05L, "STMOD");
        VIF_OPCODES.put(0x06L, "MSKPATH3");
        VIF_OPCODES.put(0x07L, "MARK");
        VIF_OPCODES.put(0x10L, "FLUSHE");
        VIF_OPCODES.put(0x11L, "FLUSH");
        VIF_OPCODES.put(0x13L, "FLUSHA");
        VIF_OPCODES.put(0x14L, "MSCAL");
        VIF_OPCODES.put(0x15L, "MSCALF");
        VIF_OPCODES.put(0x17L, "MSCNT");
        VIF_OPCODES.put(0x20L, "STMASK");
        VIF_OPCODES.put(0x30L, "STROW");
        VIF_OPCODES.put(0x31L, "STCOL");
        VIF_OPCODES.put(0x4AL, "MPG");        // Microcode upload — Path1 bullseye
        VIF_OPCODES.put(0x50L, "DIRECT");     // Inline GIF via VIF1
        VIF_OPCODES.put(0x51L, "DIRECTHL");
        // UNPACK family 0x60..0x7F handled as a range below
    }

    // PCSX2 Dmac.h: DMAtag ID lives in bits[30:28] of the upper 32-bit word.
    // Constructed via `lui $rN, 0x10__` (CNT), `0x30__` (REF), etc.
    private static final Map<Long,String> DMA_TAG_IDS = new LinkedHashMap<>();
    static {
        DMA_TAG_IDS.put(0x00L, "REFE");   // Transfer + clear STR + end
        DMA_TAG_IDS.put(0x10L, "CNT");    // Transfer QWC after tag
        DMA_TAG_IDS.put(0x20L, "NEXT");
        DMA_TAG_IDS.put(0x30L, "REF");
        DMA_TAG_IDS.put(0x40L, "REFS");
        DMA_TAG_IDS.put(0x50L, "CALL");
        DMA_TAG_IDS.put(0x60L, "RET");
        DMA_TAG_IDS.put(0x70L, "END");
    }

    // PCSX2 GSRegs.h: PSMT4HH = 44 (0x2C). Constant load in a function that
    // also writes TEX0 / a TEX0 packet is a strong FONT 4HH alias signal.
    // Also PSMT4HL=36 (0x24), PSMT8H=27 (0x1B) — other Z-buffer aliases.
    private static final long PSMT4HH = 0x2CL;
    private static final long PSMT4HL = 0x24L;
    private static final long PSMT8H  = 0x1BL;

    private static final Map<Long,String> KNOWN_DC2_GP_OFFSETS = new LinkedHashMap<>();
    static {
        KNOWN_DC2_GP_OFFSETS.put(0xFFFF8818L, "mgDBuffID");        // F30 dual-buffer slot
        KNOWN_DC2_GP_OFFSETS.put(0xFFFF8774L, "mgVif1Packet");     // F29 packet base
        KNOWN_DC2_GP_OFFSETS.put(0xFFFF997CL, "TitleInfo");        // F29 title state struct
        KNOWN_DC2_GP_OFFSETS.put(0xFFFF99A8L, "TitlePhase");
        KNOWN_DC2_GP_OFFSETS.put(0xFFFF99C4L, "Tex_Chronicle");
        KNOWN_DC2_GP_OFFSETS.put(0xFFFF99C8L, "Tex_Logo");
        KNOWN_DC2_GP_OFFSETS.put(0xFFFF8ADCL, "LoopNo");
        KNOWN_DC2_GP_OFFSETS.put(0xFFFF8AE0L, "NextLoopNo");
        KNOWN_DC2_GP_OFFSETS.put(0xFFFF94F4L, "CGamePad_ptr");     // F21 chain
        // v9 additions from PROJECT_STATE.md session log (F40-F46.6)
        KNOWN_DC2_GP_OFFSETS.put(0xFFFF9948L, "TitleCamera");      // F46.5 null-deref slot (0x00377838 abs)
        KNOWN_DC2_GP_OFFSETS.put(0xFFFF994CL, "TitleCamera2");     // F46.5 secondary camera slot
        KNOWN_DC2_GP_OFFSETS.put(0xFFFF8AE4L, "FrameCount");       // mgEndFrame counter
        KNOWN_DC2_GP_OFFSETS.put(0xFFFF94F8L, "CGamePad_Port1");   // Pad slot mirror
        KNOWN_DC2_GP_OFFSETS.put(0xFFFF8820L, "mgDrawEnvCurrent"); // Companion to mgDBuffID
        KNOWN_DC2_GP_OFFSETS.put(0xFFFF8824L, "mgDrawEnvNext");
        KNOWN_DC2_GP_OFFSETS.put(0xFFFF8778L, "mgVif1PacketEnd");
        KNOWN_DC2_GP_OFFSETS.put(0xFFFF8780L, "mgVif1PacketCurrent");
        KNOWN_DC2_GP_OFFSETS.put(0xFFFF8AE8L, "MapPhase");         // post-title progression
        KNOWN_DC2_GP_OFFSETS.put(0xFFFF99B0L, "MenuPhase");
        KNOWN_DC2_GP_OFFSETS.put(0xFFFF99B4L, "MenuItem");
        KNOWN_DC2_GP_OFFSETS.put(0xFFFF8B00L, "mapMap_ptr");
        KNOWN_DC2_GP_OFFSETS.put(0xFFFF8B04L, "mapStack_ptr");
        KNOWN_DC2_GP_OFFSETS.put(0xFFFF8B08L, "mapAddMode");
        KNOWN_DC2_GP_OFFSETS.put(0xFFFF8B0CL, "mapNowMapId");
        KNOWN_DC2_GP_OFFSETS.put(0xFFFF8B10L, "mapNowMapType");
        KNOWN_DC2_GP_OFFSETS.put(0xFFFF8B14L, "mapCameraMainIdx");
        KNOWN_DC2_GP_OFFSETS.put(0xFFFF8B18L, "mapCameraSubIdx");
        KNOWN_DC2_GP_OFFSETS.put(0xFFFF8B1CL, "mapFuncPointIdx");
        KNOWN_DC2_GP_OFFSETS.put(0xFFFF8B20L, "mapPtsFunc");
        KNOWN_DC2_GP_OFFSETS.put(0xFFFF8B28L, "CScene_ptr");       // F43 LoadMapFromMemory target
        KNOWN_DC2_GP_OFFSETS.put(0xFFFF8B2CL, "CSave_ptr");
        KNOWN_DC2_GP_OFFSETS.put(0xFFFF8B30L, "CMemoryCardMgr_ptr");
        KNOWN_DC2_GP_OFFSETS.put(0xFFFF8B40L, "mgCTextureManager_ptr"); // F43 ReloadTexture
        KNOWN_DC2_GP_OFFSETS.put(0xFFFF8B44L, "mgCDrawManager_ptr");
        KNOWN_DC2_GP_OFFSETS.put(0xFFFF8B50L, "EzMidi_rpcClient");  // F12/F27 sceSifCallRpc client
        KNOWN_DC2_GP_OFFSETS.put(0xFFFF8B54L, "EzMidi_lastResult");
        // Same offsets in signed-16 form (Ghidra sometimes emits negative scalar)
        KNOWN_DC2_GP_OFFSETS.put(-0x77E8L & 0xFFFFFFFFL, "mgDBuffID");
        KNOWN_DC2_GP_OFFSETS.put(-0x788CL & 0xFFFFFFFFL, "mgVif1Packet");
        KNOWN_DC2_GP_OFFSETS.put(-0x6684L & 0xFFFFFFFFL, "TitleInfo");
        KNOWN_DC2_GP_OFFSETS.put(-0x66B8L & 0xFFFFFFFFL, "TitleCamera");      // F46.5 alias
        KNOWN_DC2_GP_OFFSETS.put(-0x66B4L & 0xFFFFFFFFL, "TitleCamera2");
        KNOWN_DC2_GP_OFFSETS.put(-0x6650L & 0xFFFFFFFFL, "MenuPhase");
        KNOWN_DC2_GP_OFFSETS.put(-0x751CL & 0xFFFFFFFFL, "FrameCount");
        KNOWN_DC2_GP_OFFSETS.put(-0x7520L & 0xFFFFFFFFL, "NextLoopNo");
        KNOWN_DC2_GP_OFFSETS.put(-0x7524L & 0xFFFFFFFFL, "LoopNo");
        KNOWN_DC2_GP_OFFSETS.put(-0x7518L & 0xFFFFFFFFL, "MapPhase");
        KNOWN_DC2_GP_OFFSETS.put(-0x7500L & 0xFFFFFFFFL, "mapMap_ptr");
        KNOWN_DC2_GP_OFFSETS.put(-0x74D8L & 0xFFFFFFFFL, "CScene_ptr");
        KNOWN_DC2_GP_OFFSETS.put(-0x74C0L & 0xFFFFFFFFL, "mgCTextureManager_ptr");
        KNOWN_DC2_GP_OFFSETS.put(-0x74B0L & 0xFFFFFFFFL, "EzMidi_rpcClient");
    }

    // v9 Rule 131: DC2 known function addresses from PROJECT_STATE.md fix logs.
    // Each entry: address -> {name, phase, role, criticality}.
    // criticality: BLOCKER (active phase blocker), HIGH (frequently referenced
    // in fix logs), MEDIUM (component fixed in a closed phase), LOW (utility).
    private static final Object[][] KNOWN_DC2_FUNCTION_ADDRESSES = {
        // {addr,         name,                                              phase,        role,                criticality}
        { 0x00100008L, "entry_0x100008",                                     "boot",       "main_inlined_main_loop",  "BLOCKER" },
        { 0x00190CB0L, "MainLoop_0x190cb0",                                  "F28",        "main_loop_never_returns", "BLOCKER" },
        { 0x001425B0L, "mgEndFrame",                                         "F40",        "frame_clock_driver",      "HIGH"    },
        { 0x002A1220L, "TitleModeKey__Fv",                                   "F41",        "title_input_consumer",    "HIGH"    },
        { 0x002A2280L, "TitleMapDraw__Fv",                                   "F46.5",      "title_render_chain",      "HIGH"    },
        { 0x00131A90L, "__ct__18mgCCameraFollowFv",                          "F42",        "ctor_critical",           "HIGH"    },
        { 0x0012E850L, "ReloadTexture__17mgCTextureManagerFiP13sceVif1Packet","F43",       "texture_upload_entry",    "BLOCKER" },
        { 0x0012E600L, "mgLoadImage__FPUiiiiP1iiiii",                        "F43",        "texture_upload_path",     "BLOCKER" },
        { 0x00145400L, "mgLoadTextureZ__FiP8TM2_head",                       "F37/F39",    "t4hh_font_z_alias_loader","HIGH"    },
        { 0x00284768L, "LoadMapFromMemory__6CSceneFP14CMapPathParamsP9mgCMemory","F43",    "map_load_entry",          "BLOCKER" },
        { 0x00284902L, "LoadMapFromMemory_alt",                              "F43",        "map_load_entry_alt",      "BLOCKER" },
        { 0x00164480L, "LoadMapFile__4CMapFPciP9mgCMemoryi",                 "F39",        "cfg_script_interpreter",  "MEDIUM"  },
        { 0x001600D0L, "CreateMap__4CMapFP11CMdsListSetP9mgCMemory",         "F39",        "map_create_root",         "MEDIUM"  },
        { 0x00149370L, "LoadFile2__FPcPvPii",                                "F25/F39",    "file_open_with_empty_stem","HIGH"   },
        { 0x00149688L, "LoadFile2_caller_ra",                                "F25",        "fioOpen_emit_site",       "LOW"     },
        { 0x00234540L, "MenuCamInit",                                        "F22",        "menu_camera_init",        "MEDIUM"  },
        { 0x001343A0L, "__ct__11mgCDrawPrimFv",                              "F33",        "ctor_critical",           "MEDIUM"  },
        { 0x00138850L, "__ct__10mgCDrawEnvFv",                               "F33",        "ctor_critical",           "MEDIUM"  },
        { 0x0012C480L, "__ct__9mgCTextureFv",                                "F33",        "ctor_critical",           "MEDIUM"  },
        { 0x0013D260L, "__ct__14mgCTextureAnimeFv",                          "F36",        "ctor_critical",           "MEDIUM"  },
        { 0x0012C6D0L, "__ct__14mgCTextureBlockFv",                          "F36",        "ctor_critical",           "MEDIUM"  },
        { 0x0012C7E0L, "__ct__16mgCTextureManagerFv",                        "F36",        "ctor_critical",           "MEDIUM"  },
        { 0x0017D1F0L, "__ct__10mgC3DSpriteFv",                              "F36",        "ctor_critical",           "MEDIUM"  },
        { 0x00135180L, "__ct__13mgCDrawManagerFv",                           "F36",        "ctor_critical",           "MEDIUM"  },
        { 0x00136490L, "__ct__7mgCFrameFv",                                  "F36",        "ctor_critical",           "MEDIUM"  },
        { 0x00135B60L, "__ct__11mgCFrameAttrFv",                             "F36",        "ctor_critical",           "MEDIUM"  },
        { 0x002F19A0L, "FinishForMC__18CMemoryCardManagerFv",                "F38",        "mc_transition_gate",      "MEDIUM"  },
        { 0x0014A3D0L, "pad_button_read_stub",                               "F40",        "pad_input_consumer",      "MEDIUM"  },
        { 0x0014A490L, "read_pad",                                           "F40",        "pad_input_consumer",      "MEDIUM"  },
        { 0x00033130L, "MenuCheckPushButton",                                "F41",        "title_confirm_decoder",   "HIGH"    },
        { 0x00033230L, "ConvertCheckPushButton",                             "F41",        "pad_bit_translator",      "HIGH"    },
        { 0x00377838L, "g_TitleCamera_global_abs",                           "F46.5",      "global_pointer_target",   "HIGH"    },
        { 0x00033137L, "BadJump_0x33313237",                                 "F40-F46",    "pre_existing_bad_pc",     "BLOCKER" },
        { 0x002A22FCL, "BadJump_0x2a22fc",                                   "F40-F46",    "pre_existing_bad_pc",     "BLOCKER" },
    };

    // v9 Rule 132: DC2 VRAM TBP labels per dc2_runtime_invariants memory + F37/F43/F44 fix logs.
    // dbp -> human label so report tools can decode tex0_tbps_union /
    // vram_upload_tbps_union without re-deriving the mapping.
    private static final Map<Long,String> KNOWN_DC2_TBP_LABELS = new LinkedHashMap<>();
    static {
        KNOWN_DC2_TBP_LABELS.put(0x68L,    "mgDBuff_FBP_back");      // F30/F33 host-presentation source
        KNOWN_DC2_TBP_LABELS.put(0x42L,    "Path3_upload_target_0");
        KNOWN_DC2_TBP_LABELS.put(0x3C2L,   "Path3_upload_target_1");
        KNOWN_DC2_TBP_LABELS.put(0x7C2L,   "Path3_upload_target_2");
        KNOWN_DC2_TBP_LABELS.put(0x10E0L,  "Font_4HH_alias");        // F32/F37 PSMT4HH upload
        KNOWN_DC2_TBP_LABELS.put(0x2720L,  "Map_T8_texture");        // F43 unreached upload (active blocker)
        KNOWN_DC2_TBP_LABELS.put(0x3FDCL,  "CLUT_T4HH");             // F37 companion to font 4HH
        KNOWN_DC2_TBP_LABELS.put(0x280L,   "Misc_PSMCT32_upload");
        KNOWN_DC2_TBP_LABELS.put(0x3FD4L,  "Pre_CLUT_PSMCT32");
        // HUD/font cache - stable 24-page block across all 9 captured GS dumps
        for (long p = 16284L; p <= 16348L; p += 4L)
            KNOWN_DC2_TBP_LABELS.put(p, "HUD_font_cache_page_" + p);
    }

    // v9 Rule 133: confirmed-across-9-GS-dumps runtime invariants (DC2 only).
    // The report tool can deprioritise any function whose only hardware reach
    // is one of these confirmed-dead pipes.
    private static final String[][] DC2_RUNTIME_INVARIANTS = {
        { "PATH1_DEAD",            "PATH1 transfer count == 0 in all 9 GS dumps. VU1 microcode never kicked." },
        { "PATH2_DEAD",            "PATH2 transfer count == 0 in all 9 GS dumps. VIF1 DIRECT never used in steady state." },
        { "REGLIST_DEAD",          "GIF REGLIST flg count == 0 in all 9 GS dumps. REGLIST decode paths unreachable." },
        { "IMAGE2_DEAD",           "GIF IMAGE2 flg count == 0 in all 9 GS dumps." },
        { "READFIFO2_DEAD",        "ReadFIFO2 call count == 0 in all 9 GS dumps. GS readback handlers safe to stub." },
        { "PRIM_GARBAGE_DEAD",     "PRIM distinct values <= 0x1D6, malformed_tags == 0 across all 9 GS dumps." },
        { "IMR_FULLY_MASKED",      "IMR == 0x7F00 in every checkpoint. All GS IRQs masked - safe to stub Signal/Finish/Label handlers." },
        { "PMODE_STABLE",          "PMODE == 0x7F23 always. Interlaced field flip via DISPFB.dby toggle, not classic double-buffer." },
        { "FRAME_PSM_PSMCT32",     "FRAME PSM == 0 (PSMCT32) always." },
        { "ZBUF_PSM_PSMZ24",       "ZBUF PSM == 1 (PSMZ24) always." },
        { "CONTEXT_2_DEAD",        "Only context_1 A+D regs ever GIF-written. Context-2 setup is via priv MMIO or stale state." },
        { "HUD_FONT_PAGES_STABLE", "VRAM pages 16284..16316 uploaded in every scene - HUD/font cache stable 24-page block." },
        { "PSMT4HH_UI_ONLY",       "PSMT4HH only in UI scenes (Character_Select, First_Gameplay, Inventory, Pause_Menu)." },
        { "PSMCT24_CUTSCENE_ONLY", "PSMCT24 only in First_Cutscene + First_Gameplay (24-bit textures)." },
        { "PSMT4_PAUSE_INV_ONLY",  "PSMT4 (PSM 20) only in Inventory + Pause_Menu (regular 4bpp CLUT, not Z-alias)." },
        { "EZMIDI_RPC_BURST_ONLY", "ezMidi rpcNum=0x20 fires ~77 times in first 5s then 5 in next 25s - finite boot burst, not idle loop." },
        { "PATH3_PRIMARY_PIPE",    "Path3 is the only active GIF pipe. Every kick must originate from CHCR write or sceDmaSend SDK wrapper." },
        { "GAME_DISPATCHER_ONE_FN","Game-thread dispatcher fires entry_0x100008 exactly once and never returns. CPU-bound inside inlined MainLoop." },
    };

    // v9 Rule 134: pre-computed forward callgraphs to bullseye sinks. Each
    // chain: {tag, [stations]} where stations are name fragments. Report tool
    // can mark every intermediate function with the chain it participates in.
    private static final Object[][] DC2_CALL_CHAINS = {
        // tag,                      stations (in order, name fragments)
        { "save_to_map_load", new String[]{
            "TitleModeKey","MenuCheckPushButton","ConvertCheckPushButton",
            "MenuMain","MenuNewGame","CSave","CMemoryCardManager",
            "CreateMap","LoadMapFile","LoadFile2","LoadMapFromMemory",
            "ReloadTexture","mgLoadImage","sceGifPkRefLoadImage"
        }},
        { "title_to_menu", new String[]{
            "TitleInit","TitleModeKey","MenuCheckPushButton","ConvertCheckPushButton",
            "TitlePhase","TitleMapDraw","mgCCameraFollow","sceVu0CameraMatrix"
        }},
        { "texture_upload", new String[]{
            "ReloadTexture","mgLoadImage","sceGifPkRefLoadImage",
            "makeGiftagAplusD","closePacketGifTag","sceGifSendChain","sceDmaSend"
        }},
        { "frame_loop", new String[]{
            "entry","main","MainLoop","sceGsSyncV","WaitForNextVSyncTick",
            "UpDate","RunScript","mgEndFrame","sceGsSwapDBuff","mgFlipDrawEnv"
        }},
        { "render_chain", new String[]{
            "TitleModeDraw","TitleMapDraw","PrimQuad","SetSpriteEnv",
            "Begin__11mgCDrawPrim","Texture__11mgCDrawPrim","Color__11mgCDrawPrim",
            "End__11mgCDrawPrim","mgEndFrame"
        }},
        { "ipu_mpeg_fmv", new String[]{
            "sceMpeg","sceIpu","dmaRefImage","sceMpegInit","sceIpuSetThreshold"
        }},
        { "iop_ezmidi_rpc", new String[]{
            "sceSifBindRpc","sceSifCallRpc","handleEzMidiRpc","sceSifInitRpc"
        }},
    };

    // v9 Rule 135: working DC2_PAD_INPUT scripts from F40/F42/F46 fix logs.
    // Format: {tag, script, frame_anchor, observed_effect}.
    private static final String[][] DC2_PAD_INPUT_SCRIPTS = {
        { "F40_baseline_smoke",       "1:Start",                                                   "mgEndFrame=1",   "single inject at boot frame; baseline only" },
        { "F41_R1_title_confirm",     "30..39:R1",                                                 "mgEndFrame=30",  "R1 -> MenuCheckPushButton ret=0x10 -> TitlePhase 0->1; 3x PPM brightness" },
        { "F42_menu_progression",     "200:R1;320:R1;440:R1;560:R1;680:R1;800:R1",                 "mgEndFrame=200", "drives TitleModeKey->MenuMain->MenuNewGame; [F39:lf2] count=41; map/map1.cfg + def.sky hits" },
        { "F46_canonical_sweep",      "30..39:R1;120..129/160..169/190..199/220..229/260..269:Cross", "mgEndFrame=30","canonical menu sequence; [F40:inject]=10 frames 30-39 only" },
        { "F46_calibration_probe",    "1..120:R1",                                                 "mgEndFrame=1",   "verifies injector fires; only frame 1 reachable in 30s window" },
    };

    // v9 Rule 124 / 125: IRX loader detection callees.
    private static final Set<String> IRX_LOAD_CALLEES = new HashSet<>(Arrays.asList(
        "sceSifLoadModule","sceSifLoadStartModule","sceSifLoadFileEx",
        "SifLoadModule","SifLoadStartModule"
    ));
    private static final Set<String> IOP_REBOOT_CALLEES = new HashSet<>(Arrays.asList(
        "sceSifRebootIop","SifRebootIop","sceSifInitIopHeap"
    ));

    // v9 Rule 126: DC2 render frame entry name fragments.
    private static final String[] RENDER_FRAME_ENTRY_FRAGMENTS = {
        "mgEndFrame","mgBeginFrame","mgEndDraw","mgBeginDraw",
        "mgFlipDrawEnv","mgVSyncWait","mgSwapDBuff","mgEndDrawReload"
    };

    // v9 Rule 119 / extended MMIO ranges (E1-E3 from General v11).
    private static final long SBUS_MSFLG          = 0x1000F220L;
    private static final long SBUS_SMFLG          = 0x1000F230L;
    private static final long RCNT_RANGE_START    = 0x10000000L;
    private static final long RCNT_RANGE_END      = 0x10001FFFL;
    private static final long VIF0_CTRL_START     = 0x10003800L;
    private static final long VIF0_CTRL_END       = 0x10003BFFL;
    private static final long VIF1_CTRL_START     = 0x10003C00L;
    private static final long VIF1_CTRL_END       = 0x10003FFFL;
    private static final long DMAC_GLOBAL_START   = 0x1000E000L;
    private static final long DMAC_GLOBAL_END     = 0x1000E0FFL;
    private static final long INTC_STAT_ADDR      = 0x1000F000L;
    private static final long INTC_MASK_ADDR      = 0x1000F010L;
    private static final long SIO_RANGE_START     = 0x1000F100L;
    private static final long SIO_RANGE_END       = 0x1000F1FFL;
    private static final long DMAC_EXT_START      = 0x1000F500L;
    private static final long DMAC_EXT_END        = 0x1000F5FFL;
    private static final long DMA_CHCR_START_CONST = 0x101L; // STR | TIE

    // v9 Rule 120: EE syscall imm -> canonical name (db-syscalls.md / ps2tek).
    private static final Map<Long,String> EE_SYSCALL_NAMES = new HashMap<>();
    static {
        EE_SYSCALL_NAMES.put(0x01L, "ResetEE");
        EE_SYSCALL_NAMES.put(0x02L, "SetGsCrt");
        EE_SYSCALL_NAMES.put(0x04L, "Exit");
        EE_SYSCALL_NAMES.put(0x06L, "LoadExecPS2");
        EE_SYSCALL_NAMES.put(0x07L, "ExecPS2");
        EE_SYSCALL_NAMES.put(0x10L, "AddIntcHandler");
        EE_SYSCALL_NAMES.put(0x11L, "RemoveIntcHandler");
        EE_SYSCALL_NAMES.put(0x12L, "AddDmacHandler");
        EE_SYSCALL_NAMES.put(0x13L, "RemoveDmacHandler");
        EE_SYSCALL_NAMES.put(0x14L, "_EnableIntc");
        EE_SYSCALL_NAMES.put(0x15L, "_DisableIntc");
        EE_SYSCALL_NAMES.put(0x16L, "_EnableDmac");
        EE_SYSCALL_NAMES.put(0x17L, "_DisableDmac");
        EE_SYSCALL_NAMES.put(0x18L, "SetAlarm");
        EE_SYSCALL_NAMES.put(0x19L, "ReleaseAlarm");
        EE_SYSCALL_NAMES.put(0x20L, "CreateThread");
        EE_SYSCALL_NAMES.put(0x21L, "DeleteThread");
        EE_SYSCALL_NAMES.put(0x22L, "StartThread");
        EE_SYSCALL_NAMES.put(0x23L, "ExitThread");
        EE_SYSCALL_NAMES.put(0x24L, "ExitDeleteThread");
        EE_SYSCALL_NAMES.put(0x25L, "TerminateThread");
        EE_SYSCALL_NAMES.put(0x29L, "ChangeThreadPriority");
        EE_SYSCALL_NAMES.put(0x2BL, "RotateThreadReadyQueue");
        EE_SYSCALL_NAMES.put(0x2DL, "ReleaseWaitThread");
        EE_SYSCALL_NAMES.put(0x2FL, "GetThreadId");
        EE_SYSCALL_NAMES.put(0x30L, "ReferThreadStatus");
        EE_SYSCALL_NAMES.put(0x32L, "SleepThread");
        EE_SYSCALL_NAMES.put(0x33L, "WakeupThread");
        EE_SYSCALL_NAMES.put(0x34L, "iWakeupThread");
        EE_SYSCALL_NAMES.put(0x35L, "CancelWakeupThread");
        EE_SYSCALL_NAMES.put(0x37L, "SuspendThread");
        EE_SYSCALL_NAMES.put(0x38L, "iSuspendThread");
        EE_SYSCALL_NAMES.put(0x39L, "ResumeThread");
        EE_SYSCALL_NAMES.put(0x3CL, "InitMainThread");
        EE_SYSCALL_NAMES.put(0x3DL, "InitHeap");
        EE_SYSCALL_NAMES.put(0x3EL, "EndOfHeap");
        EE_SYSCALL_NAMES.put(0x40L, "CreateSema");
        EE_SYSCALL_NAMES.put(0x41L, "DeleteSema");
        EE_SYSCALL_NAMES.put(0x42L, "SignalSema");
        EE_SYSCALL_NAMES.put(0x43L, "iSignalSema");
        EE_SYSCALL_NAMES.put(0x44L, "WaitSema");
        EE_SYSCALL_NAMES.put(0x45L, "PollSema");
        EE_SYSCALL_NAMES.put(0x46L, "iPollSema");
        EE_SYSCALL_NAMES.put(0x47L, "ReferSemaStatus");
        EE_SYSCALL_NAMES.put(0x48L, "iReferSemaStatus");
        EE_SYSCALL_NAMES.put(0x64L, "FlushCache");
        EE_SYSCALL_NAMES.put(0x66L, "GsGetIMR");
        EE_SYSCALL_NAMES.put(0x67L, "GsPutIMR");
        EE_SYSCALL_NAMES.put(0x68L, "SetVSyncFlag");
        EE_SYSCALL_NAMES.put(0x70L, "GsGetIMR");
        EE_SYSCALL_NAMES.put(0x71L, "GsPutIMR");
        EE_SYSCALL_NAMES.put(0x73L, "SetSyscall");
        EE_SYSCALL_NAMES.put(0x76L, "SifDmaStat");
        EE_SYSCALL_NAMES.put(0x77L, "SifSetDma");
        EE_SYSCALL_NAMES.put(0x78L, "SifSetDChain");
        EE_SYSCALL_NAMES.put(0x79L, "SifSetReg");
        EE_SYSCALL_NAMES.put(0x7AL, "SifGetReg");
        EE_SYSCALL_NAMES.put(0x7BL, "ExecOSD");
        EE_SYSCALL_NAMES.put(0x7CL, "Deci2Call");
        EE_SYSCALL_NAMES.put(0x7DL, "PSMode");
        EE_SYSCALL_NAMES.put(0x7EL, "MachineType");
        EE_SYSCALL_NAMES.put(0x7FL, "GetMemorySize");
    }

    // v9 Rule 137: tag priority for TOML comment generation (higher = printed first).
    private static final Map<String,Integer> TAG_PRIORITY = new HashMap<>();
    static {
        // Tier-0 blocker tags
        TAG_PRIORITY.put("TOP_PRIORITY_FIX", 1000);
        TAG_PRIORITY.put("BITBLTBUF_T4HH_UPLOADER", 950);
        TAG_PRIORITY.put("CTOR_RISK_CRITICAL", 940);
        TAG_PRIORITY.put("DRAWING_CHAIN_NEAR_ROOT", 930);
        TAG_PRIORITY.put("CTOR_MULTI_FIELD_INITIALIZER", 920);
        TAG_PRIORITY.put("LIFECYCLE_LAZY_INIT_GUARD", 910);
        TAG_PRIORITY.put("ASSET_UPLOAD_BULLSEYE", 900);
        TAG_PRIORITY.put("RENDER_FRAME_ENTRY", 890);
        TAG_PRIORITY.put("PATH3_INITIATOR", 880);
        TAG_PRIORITY.put("PATH3_KICK_VIA_DMA_API", 870);
        TAG_PRIORITY.put("IS_SCE_GIF_PK_REF_LOAD_IMAGE", 860);
        TAG_PRIORITY.put("DMA_CHCR_START_KICK", 850);
        TAG_PRIORITY.put("GIF_NLOOP_DOUBLE_COUNT_RISK", 840);
        TAG_PRIORITY.put("DC2_HOST_WAIT_CANDIDATE", 830);
        TAG_PRIORITY.put("VTABLE_SETTER", 820);
        TAG_PRIORITY.put("CTOR_RISK_HIGH", 810);
        TAG_PRIORITY.put("LIBGCC_INTRINSIC", 800);
        TAG_PRIORITY.put("MICROCODE_UPLOADER", 790);
        TAG_PRIORITY.put("FRAME_CLOCK_DRIVER", 780);
        TAG_PRIORITY.put("BACKWARD_BRANCH_SYNC_WAIT", 770);
        TAG_PRIORITY.put("INFINITE_FAIL_LOOP", 760);
        TAG_PRIORITY.put("INFINITE_SPIN_LOOP", 750);
        TAG_PRIORITY.put("Z_BUFFER_ALIAS_RISK", 740);
        TAG_PRIORITY.put("GIF_PATH3_HAZARD", 730);
        TAG_PRIORITY.put("BITBLTBUF_MACRO_SEQUENCE", 720);
        TAG_PRIORITY.put("GIF_TAG_INLINE_BUILDER", 710);
        TAG_PRIORITY.put("DMA_SOURCE_CHAIN_TAG_BUILDER", 700);
        TAG_PRIORITY.put("VIF_MPG_OPCODE_BUILDER", 690);
        TAG_PRIORITY.put("VIF_MSCAL_OPCODE_BUILDER", 685);
        TAG_PRIORITY.put("VIF_DIRECT_OPCODE_BUILDER", 680);
        TAG_PRIORITY.put("VIF_UNPACK_OPCODE_BUILDER", 670);
        TAG_PRIORITY.put("DMA_TAG_BUILDER", 660);
        TAG_PRIORITY.put("PSMT4HH_REFERENCE", 650);
        TAG_PRIORITY.put("DISPFB_WRITER", 640);
        TAG_PRIORITY.put("DISPFB_SDK_WRITER", 635);
        TAG_PRIORITY.put("INDIRECT_CALL_T9", 600);
        TAG_PRIORITY.put("TAIL_CALL_INDIRECT", 580);
        TAG_PRIORITY.put("MPEG_DECODER_TRAP", 560);
        TAG_PRIORITY.put("IOP_RPC_DISPATCH", 540);
        TAG_PRIORITY.put("IRX_LOADER", 520);
        TAG_PRIORITY.put("ARCHIVE_IO", 500);
        TAG_PRIORITY.put("MC_TRANSITION_GATE", 480);
        TAG_PRIORITY.put("PAD_BUTTON_MASK_CONSUMER", 460);
        TAG_PRIORITY.put("PAD_POLL_LOOP", 440);
        TAG_PRIORITY.put("THREAD_SYNC_POINT", 420);
        TAG_PRIORITY.put("SBUS_IOP_COMM_TOUCHER", 400);
        TAG_PRIORITY.put("MESWIN_LOADER", 380);
        TAG_PRIORITY.put("DMA_KICK_PATTERN", 360);
        TAG_PRIORITY.put("DMA_QWC_TADR_WRITER", 340);
    }

    // Rule 23: Archive I/O string patterns (Phase F6)
    private static final String[] ARCHIVE_IO_STRINGS = {
        "DATA.DAT","DATA.HD2","data.dat","data.hd2",".dat",".hd2"
    };

    // Rule 22: Known IOP SIDs from ps2_iop.h (for cross-referencing)
    private static final Map<Long, String> KNOWN_IOP_SIDS = new HashMap<>();
    static {
        KNOWN_IOP_SIDS.put(0x00000000L, "IOP_SID_SNDDRV_COMMAND");
        KNOWN_IOP_SIDS.put(0x00000001L, "IOP_SID_SNDDRV_STATE");
        KNOWN_IOP_SIDS.put(0x80000701L, "IOP_SID_LIBSD");
        KNOWN_IOP_SIDS.put(0x00012346L, "DC2_EzMidi_rpcSid");
    }

    // Rule 10: Absolute whitelist - immune to ALL firewalls
    private static final String[] WHITELIST_NAMES = {
        "entry","_start","crt0","topThread","cmd_sem_init"
    };

    // Rule 24: Known pad-polling syscall names (for PAD_POLL_LOOP detection)
    private static final Set<String> PAD_POLL_CALLEES = new HashSet<>(Arrays.asList(
        "scePadGetState","scePadGetReqState","scePadRead",
        "sceGsSyncV","sceGsSyncVCallback","WaitVSync"
    ));

    // ===== v7 (GS-dump runtime corroboration) =====
    // Rule 75: SDK-routed DISPFB writers. Direct-MMIO Rule 35/58 only catches
    // raw writes to 0x12000070/0x12000090; real games usually call the SDK
    // wrapper sceGsPutDispEnv etc., which then writes the priv reg from kernel.
    private static final String[] DISPFB_SDK_CALLEES = {
        "sceGsPutDispEnv","sceGsSetDispEnv","sceGsSetCRTC",
        "sceGsResetGraph","mgSetDispEnv","sceGsSetDispMask",
        "sceGsSwapDBuff"
    };

    // Rule 76: SDK-routed Path3 kicks. Raw-CHCR Rule 44 only matches direct
    // writes to 0x1000A000; SDK uses sceDmaSend/sceGifSendChain wrappers.
    private static final String[] PATH3_KICK_API_CALLEES = {
        "sceDmaSend","sceDmaSendN","sceDmaSendChain","sceDmaSendChainN",
        "sceGifSendChain","sceGifSendPacket","sceGsExecStoreImage",
        "sceGsExecLoadImage","sceDmaChain"
    };

    // Rule 79: GS IRQ handler names. IMR (priv reg 0x1010) controls which GS
    // IRQs reach the EE. When every loaded checkpoint shows IMR=0x7F00
    // (all GS IRQs masked) these handlers can never fire — safe-stub label.
    private static final String[] GS_IRQ_HANDLER_NAME_FRAGMENTS = {
        "GsSignal","GsFinish","GsLabel","SignalHandler","FinishHandler",
        "LabelHandler","sceGsSyncH","sceGsSyncV"
    };

    // PSM code constants (PCSX2 GSRegs.h) for VRAM/Z-alias decoding.
    private static final int PSM_PSMT4HH = 44;   // 0x2C — UI/font Z-buffer alias
    private static final int PSM_PSMT4HL = 36;   // 0x24
    private static final int PSM_PSMT8H  = 27;   // 0x1B

    // Checkpoint name fragments treated as "menu/UI" for RUNTIME_MENU_ONLY
    // classification. Lowercase comparison.
    private static final String[] MENU_CHECKPOINT_FRAGMENTS = {
        "menu","inventory","pause","character","title","select","ui","hud"
    };

    // ===== v8 constants =====
    // Rule 88: exact libgcc / runtime helper names (not just regex matches).
    private static final Set<String> LIBGCC_EXACT_NAMES = new HashSet<>(Arrays.asList(
        "__divdi3","__udivdi3","__moddi3","__umoddi3","__muldi3",
        "__fixdfdi","__fixunsdfdi","__floatdidf","__pack_d","__unpack_d",
        "__pack_f","__unpack_f","__fpcmp_parts_d","__fpcmp_parts_f",
        "__negdf2","__negsf2","__make_dp","__make_fp",
        "__divsi3","__udivsi3","__modsi3","__umodsi3",
        "__addsf3","__subsf3","__mulsf3","__divsf3",
        "__adddf3","__subdf3","__muldf3","__divdf3",
        "__cmpdf2","__cmpsf2","__fixsfdi","__floatdisf","__floatsisf","__floatsidf"
    ));

    // Rule 96: GIF packet helpers — NLOOP double-count hazard pair.
    private static final Set<String> GIF_PACKET_NLOOP_HELPERS = new HashSet<>(Arrays.asList(
        "makeGiftagAplusD","MakeGiftagAplusD","makeGifTagAplusD",
        "sceGifPkOpenGifTag","sceVif1PkOpenGifTag","openGifTag"
    ));
    private static final Set<String> GIF_PACKET_CLOSE_HELPERS = new HashSet<>(Arrays.asList(
        "closePacketGifTag","ClosePacketGifTag","sceGifPkCloseGifTag",
        "sceVif1PkCloseGifTag","closeGifTag"
    ));

    // Rule 97: PS2 DUALSHOCK button mask constants (active-low; absolute bit
    // values seen in masking sites). Mapping = bit -> friendly name.
    private static final Map<Long,String> PAD_BUTTON_MASKS = new LinkedHashMap<>();
    static {
        PAD_BUTTON_MASKS.put(0x0001L, "Select");
        PAD_BUTTON_MASKS.put(0x0002L, "L3");
        PAD_BUTTON_MASKS.put(0x0004L, "R3");
        PAD_BUTTON_MASKS.put(0x0008L, "Start");
        PAD_BUTTON_MASKS.put(0x0010L, "Up");
        PAD_BUTTON_MASKS.put(0x0020L, "Right");
        PAD_BUTTON_MASKS.put(0x0040L, "Down");
        PAD_BUTTON_MASKS.put(0x0080L, "Left");
        PAD_BUTTON_MASKS.put(0x0100L, "L2");
        PAD_BUTTON_MASKS.put(0x0200L, "R2");
        PAD_BUTTON_MASKS.put(0x0400L, "L1");
        PAD_BUTTON_MASKS.put(0x0800L, "R1");
        PAD_BUTTON_MASKS.put(0x1000L, "Triangle");
        PAD_BUTTON_MASKS.put(0x2000L, "Circle");
        PAD_BUTTON_MASKS.put(0x4000L, "Cross");
        PAD_BUTTON_MASKS.put(0x8000L, "Square");
    }

    // Rule 99: file-open callee names — caller sprintf-source check anchors here.
    private static final Set<String> FILE_OPEN_CALLEES = new HashSet<>(Arrays.asList(
        "LoadFile2","LoadFile","LoadFileEx","sceCdRead","sceOpen","sceRead",
        "sceCdSearchFile","fopen","sceCdStRead"
    ));

    // Rule 100: frame-clock advance callees.
    private static final Set<String> FRAME_CLOCK_CALLEES = new HashSet<>(Arrays.asList(
        "sceGsSyncV","sceGsSyncH","sceGsSyncVCallback","WaitVSync",
        "SetVSyncFlag","mgEndFrame","mgFlipDrawEnv","mgVSyncWait"
    ));

    // Rule 102: VU0 helper whitelist (must be implemented, never auto-stub).
    private static final String[] SCEVU0_HELPER_PREFIXES = {
        "sceVu0","_sceVu0"
    };

    // Rule 107: phase-trace env flags inventory (emitted into JSON for tools).
    private static final String[] PHASE_TRACE_FLAGS = {
        "DC2_PHASE_TRACE","DC2_TRACE_TITLE_PATH","DC2_TRACE_T8_UPLOAD",
        "DC2_HUD","DC2_FRAME_DUMP","DC2_PAD_INPUT","DC2_TRACE_PAD",
        "DC2_TRACE_VTABLE","DC2_TRACE_CTOR","DC2_TRACE_MAP_LOAD",
        "DC2_TRACE_SAVE","DC2_TRACE_DRAW","DC2_TRACE_BITBLTBUF"
    };

    // Rule 104: expected GS uploads per phase (current blocker: T8 dbp=0x2720
    // dpsm=0x13 inside CScene::LoadMapFromMemory). Extend as new phases land.
    // Each entry: {tag, dpsm, dbp, phase, hint}.
    private static final Object[][] EXPECTED_UPLOADS = {
        // tag,             dpsm, dbp,     phase,          hint
        { "T8_TEXTURE",     0x13, 0x2720L, "F43_T8",       "CScene::LoadMapFromMemory map texture - ACTIVE BLOCKER" },
        { "FONT_T4HH",      0x2CL,0x10E0L, "F32_FONT_4HH", "sceGifPkRefLoadImage font upload - F37 fixed NLOOP" },
        { "CLUT_T4HH",      0x00, 0x3FDCL, "F37_CLUT",     "PSMCT32 CLUT companion to font 4HH" },
        // Per dc2_runtime_invariants: PSMT4 is regular 4bpp (not Z-alias) in Inventory + Pause only
        { "INV_PAUSE_T4",   0x14, 0x10E0L, "F46_INV",      "Inventory/Pause PSMT4 CLUT-indexed texture" },
        // PSMCT24 only in First_Cutscene + First_Gameplay
        { "CUTSCENE_24BPP", 0x01, 0x2720L, "F47_CUT",      "PSMCT24 cutscene texture upload (post-map-load)" },
        // HUD/font cache - stable 24-page block in every scene
        { "HUD_FONT_CACHE", 0x13, 0x3F9CL, "F47_HUD",      "HUD font cache base page 16284 (T8)" },
    };
    // Sets derived from EXPECTED_UPLOADS for cheap membership tests in scan.
    private static final Set<Long> EXPECTED_DBP_SET = new LinkedHashSet<>();
    private static final Set<Integer> EXPECTED_DPSM_SET = new LinkedHashSet<>();
    static {
        for (Object[] row : EXPECTED_UPLOADS) {
            EXPECTED_DBP_SET.add(((Number)row[2]).longValue() & 0xFFFFFFFFL);
            EXPECTED_DPSM_SET.add(((Number)row[1]).intValue());
        }
    }

    // Rule 106: emitted build invariants for downstream tools.
    private static final String BUILD_CMD = "cmake --build D:/ps2r/dc2/build64 --config Release --target ps2_runtime";
    private static final String[] BUILD_DO_NOT_MODIFY = {
        "runner/*.cpp"
    };

    // =========================================================
    // v7: GS RUNTIME EVIDENCE MODEL
    // =========================================================
    /** Per-checkpoint snapshot loaded from gs_dump_to_summary.py output. */
    static class GsCheckpoint {
        String name;                       // e.g. "Inventory", "3D_Scene"
        boolean path1Active, path2Active, path3Active;
        boolean psmt4hhUsed, psmt4hlUsed, psmt8hUsed;
        // F32 retro: BITBLTBUF.dpsm witnesses (upload-side PSM).
        boolean psmt4hhUpload, psmt4hlUpload, psmt8hUpload;
        Set<Integer> bitbltbufDpsms = new LinkedHashSet<>();
        boolean primGarbage;
        boolean ipuActive;                 // derived: any IPU MMIO would show; here
                                           // we don't see it in summary_for_enricher
                                           // but readfifo2_calls is a proxy.
        boolean readfifo2Active;
        boolean signalFinishLabelSeen;     // SIGNAL/FINISH/LABEL in a_d_regs_written_named
        boolean reglistUsed, image2Used;
        Set<Integer> psmTex0    = new LinkedHashSet<>();
        Set<Integer> psmFrame   = new LinkedHashSet<>();
        Set<Integer> psmZbuf    = new LinkedHashSet<>();
        Set<String>  adRegs     = new LinkedHashSet<>();
        Set<Long>    tex0Tbps   = new LinkedHashSet<>();
        Set<Long>    vramTbps   = new LinkedHashSet<>();
        Set<Long>    primValues = new LinkedHashSet<>();
        long imr = -1L;                    // -1 == unknown / not loaded
        long pmode = -1L;
        int  gifTagCount, packedCount, imageCount, reglistCount, image2Count;
        int  malformedTags;
        int  vsyncs;
        int  path1Count, path2Count, path3Count;
        long path1Bytes, path2Bytes, path3Bytes;
        Integer frameFbp, frameFbw, framePsm;
        Integer zbufZbp, zbufPsm, zbufZmsk;
        Integer dispfb1Fbp, dispfb2Fbp;
        String  sourceFile;
        long stateSizeBytes;
        int  stateVersion;
        String serial, crc;
    }

    /** Merged union across all loaded checkpoints. */
    static class GsRuntimeEvidence {
        List<GsCheckpoint> checkpoints = new ArrayList<>();
        // Union flags
        boolean anyPath1, anyPath2, anyPath3;
        boolean anyPsmt4hh, anyPsmt4hl, anyPsmt8h;
        boolean anyPsmt4hhUpload, anyPsmt4hlUpload, anyPsmt8hUpload;
        Set<Integer> bitbltbufDpsmsUnion = new LinkedHashSet<>();
        boolean anyPrimGarbage;
        boolean anyReadfifo2;
        boolean anyReglist, anyImage2;
        boolean anySignalFinishLabel;
        Set<Integer> psmTex0Union  = new LinkedHashSet<>();
        Set<Integer> psmFrameUnion = new LinkedHashSet<>();
        Set<Integer> psmZbufUnion  = new LinkedHashSet<>();
        Set<String>  adRegsUnion   = new LinkedHashSet<>();
        Set<Long>    tex0TbpsUnion = new LinkedHashSet<>();
        Set<Long>    vramTbpsUnion = new LinkedHashSet<>();
        Set<Long>    primUnion     = new LinkedHashSet<>();
        long imrIntersection = -1L;        // bit-AND of every checkpoint's IMR
        boolean imrAllMaskedGsIrqs;        // all loaded checkpoints had IMR & 0x7F00 == 0x7F00
        // Per-PSM-witness which checkpoints saw it (lower-cased name list)
        Map<Integer, Set<String>> psmTex0Witnesses = new LinkedHashMap<>();
        // Path3 confirmation strength: total path3 transfers across all checkpoints
        long totalPath3Count = 0L;
        long totalPath3Bytes = 0L;
        // True if no captures loaded — disables corroboration tags.
        boolean empty() { return checkpoints.isEmpty(); }
    }

    private GsRuntimeEvidence gsEvidence = new GsRuntimeEvidence();

    // =========================================================
    // DNA ANALYSIS: FuncTraits
    // =========================================================
    class FuncTraits {
        int floatOps=0, branchOps=0, mathOps=0, loadOps=0, returnPaths=0;
        long byteSize=0;
        int calleeCount=0;
        int xrefToCount=0;
        List<String> calleeNames=new ArrayList<>();
        boolean isThunk=false;
        boolean writesToGlobal=false, usesCop1=false, usesCop2=false;
        boolean usesSPR=false, hasStackFrame=false, hasMutatingInstructions=false;
        int quadwordVU=0, accOps=0, callOps=0;
        boolean writesToText=false;
        boolean hasSyncInstr=false;
        boolean hasBusyWait=false;
        boolean hasVcallms=false;
        boolean hasJumpTable=false;
        boolean accessesMMIO=false;
        // v3 new fields
        boolean accessesVif1MMIO=false;     // Rule 21
        boolean callsDmaSend=false;          // Rule 21
        boolean callsSifRpc=false;           // Rule 22
        long detectedRpcSid=0L;             // Rule 22: SID literal found near sceSifBindRpc
        boolean refsArchiveStrings=false;    // Rule 23
        boolean callsPadPollCallee=false;    // Rule 24
        boolean hasBackwardBranch=false;     // improved BUSY_WAIT
        boolean writesToA1Buffer=false;      // Rule 19: convention violation detector
        boolean isLargeInitFunc=false;       // Rule 20
        // Rule 25: Thread sync point - syscall + backward branch + small size, NOT IOP module.
        // Phase F blocker: EE thread parked at pc=0x100008 waiting on IOP response.
        // These functions spin on a syscall (WaitSema/SleepThread/etc.) until IOP replies.
        // They must NOT be nop-stubbed - the thread scheduler depends on them.
        boolean isThreadSyncPoint=false;
        // [FIX v4] Folded from containsSyscall/containsCOP0 into main instruction loop
        boolean hasSyscall=false;
        boolean hasCOP0=false;
        // [FIX v4] Folded from referencesIopModule into main instruction loop
        boolean refsIopModuleString=false;
        // F21-prep: outgoing JAL records — pairs of (callSitePc, calleeTargetAddr).
        // Collected during the instruction scan; consumed in a post-pass to
        // build the reverse call-graph that lands in JSON as "callers".
        List<long[]> jalSites = new ArrayList<>();
        // F21-prep: incoming-call records populated by buildReverseCallGraph()
        // after all functions are scanned. Each entry is [callerAddr, callSitePc].
        List<long[]> callers = new ArrayList<>();
        // F21-prep: memory-access literal references. Each entry is
        // [pcHex, mnem, baseReg, offsetHex, destReg] — captured for load/store
        // opcodes that have a constant displacement so consumers can grep by
        // offset (e.g. "every read of +0x45C from a CGamePad pointer").
        List<String[]> literalRefs = new ArrayList<>();

        // ===== v4 fields =====
        // Rule 26/27: constructor that writes through $a0 to small offsets.
        // ctor name AND we observed `sw $rN, +K($a0)` (K<0x100) near entry.
        // VTABLE_SETTER additionally requires the stored value came from a lui/addiu constant.
        boolean ctorWritesA0Slot=false;
        boolean ctorWritesVTablePointer=false;
        // Rule 28: tiny returner whose result is polled by a caller's backward
        // branch. Computed post-scan after reverse call-graph is built.
        boolean isLikelyPollTarget=false;
        // Rule 29: function whose tail does `move $v0, $a0` (or $a1) — passthrough.
        // Auto-stub returning 0 would break chained calls like `f(g(x))` where
        // g forwards x. Detected via last-10 instructions scan.
        boolean returnsA0=false;
        boolean returnsA1=false;
        // Rule 30: name-based — process terminator
        boolean isProcessTerminator=false;
        // Rule 31: libgcc 64-bit / FP intrinsic
        boolean isLibgccIntrinsic=false;
        // Rule 32: GIF Path3 hazard — CTRL/CHCR/PRIM-offset signals
        boolean touchesGifCtrl=false;
        boolean writesGsPrimReg=false;
        // Rule 33: Z-buffer alias risk — ZBUF reg + 24-bit shift
        boolean writesZbufReg=false;
        boolean hasShift24Pattern=false;
        // Rule 34: MPEG decoder
        boolean callsMpegFamily=false;
        // Rule 35: DISPFB writer
        boolean writesDispfbReg=false;
        // Rule 36: VIF1 DMAtag tag-high builder pattern (Rule 21 already tracks
        // accessesVif1MMIO; this is the additional dsll32/dsrl32 indicator).
        boolean hasDsll32OrDsrl32=false;
        // Rule 37: terminal jr $reg as a call/computed flow (NOT jr $ra)
        boolean tailCallIndirect=false;
        // Rule 38: jalr $t9 (PIC / vtable indirect call)
        int    indirectCallT9Count=0;
        // Rule 39/40: BFS-derived
        int    mainLoopDepth=-1;
        int    initChainDepth=-1;
        // Last few "GS register address" hits keyed by name, for the report tool.
        Set<String> gsRegHits = new LinkedHashSet<>();

        // ===== v5 fields =====
        boolean isSceGifPkRefLoadImage=false;   // Rule 43
        boolean path3Initiator=false;            // Rule 44
        boolean isSceGifPkFamily=false;          // Rule 45
        boolean writesTex0Reg=false;             // Rule 46
        boolean readsPrimReg=false;              // Rule 47
        boolean writesRgbaqReg=false;            // Rule 48
        Set<String> dmaKickChannels = new LinkedHashSet<>();   // Rule 49: channel names
        Set<String> dmaQwcTadrChannels = new LinkedHashSet<>(); // Rule 50: channel names
        boolean isMicrocodeUploader=false;       // Rule 51
        boolean isAudioRpcHandler=false;         // Rule 52
        boolean refsMeswinStrings=false;         // Rule 53
        boolean isMcTransitionGate=false;        // Rule 54
        // Rule 55: hits against KNOWN_DC2_GP_OFFSETS (labels only).
        Set<String> dc2GlobalsTouched = new LinkedHashSet<>();
        // Rule 56: derived after tag pass.
        boolean isTopPriorityFix=false;

        // ===== v6 fields (PCSX2-grounded) =====
        boolean accessesIpuMmio=false;          // Rule 59
        boolean writesIpuCmd=false;             // Rule 60
        boolean touchesGifP3Reg=false;          // Rule 61 (P3CNT or P3TAG)
        boolean writesGifFifo=false;            // Rule 62
        boolean writesVif1Fifo=false;           // Rule 63
        boolean writesVif0Fifo=false;           // Rule 64
        boolean writesIpuFifo=false;
        boolean accessesVuMicromem=false;       // Rule 65 (VU0 or VU1)
        boolean accessesVuDatamem=false;        // Rule 66
        boolean touchesSbus=false;              // Rule 74
        boolean loadsPsm4hhConstant=false;      // Rule 73
        // Real GS privileged MMIO hits (PMODE/DISPFB1/DISPFB2/CSR/IMR/...).
        // Distinct from gsRegHits (which was the broken v4 A+D-reg lookup).
        Set<String> gsPrivRegHits = new LinkedHashSet<>();
        // VIF opcodes constructed via lui constant scan.
        Set<String> vifOpcodesBuilt = new LinkedHashSet<>();
        // DMAtag IDs constructed via lui constant scan.
        Set<String> dmaTagIdsBuilt = new LinkedHashSet<>();

        // ===== v7 fields (GS-dump runtime corroboration) =====
        // Rule 75: callee in DISPFB_SDK_CALLEES set
        boolean writesDispfbViaSdk=false;
        // Rule 76: callee in PATH3_KICK_API_CALLEES set
        boolean path3KickViaDmaApi=false;
        // Rule 79: name matches GS_IRQ_HANDLER_NAME_FRAGMENTS
        boolean isGsIrqHandlerName=false;
        // Rule 78: lui/ori/addiu/li constants observed in this function (tracks
        // 14-bit TBP-shape values, i.e. < 0x4000 with non-trivial bit pattern).
        // Filled in instruction-scan; intersected against runtime later.
        Set<Long> tbpConstantsLoaded = new LinkedHashSet<>();
        // Rule 80: runtime corroboration outputs (post-pass).
        Set<String> runtimeBullseyePredictions = new LinkedHashSet<>();
        Map<String,Boolean> runtimeWitness = new LinkedHashMap<>();
        Set<Long> tbpRuntimeConfirmed = new LinkedHashSet<>();
        Set<String> runtimeAdRegMatch = new LinkedHashSet<>();
        String runtimeStatus = "INDETERMINATE";   // CONFIRMED / DORMANT / MENU_ONLY / INDETERMINATE
        boolean runtimeConfirmed=false;
        boolean runtimeDormantGlobal=false;
        boolean runtimeMenuOnly=false;
        boolean gsIrqSafeStubCandidate=false;

        // ===== v7.1 fields (F32-F34 retrospective) =====
        // Rule 82: distinct this+K offsets a ctor / initializer writes in its
        // first 40 instructions. F33 root cause: __ct__11mgCDrawPrimFv (7+
        // slots) was nop-stubbed.
        Set<Long> ctorSlotsWritten = new LinkedHashSet<>();
        boolean isCtorMultiFieldInit=false;       // Rule 82
        // Rule 83: BFS depth from GS-bullseye render roots (sceGifPk*, mgEndFrame,
        // Begin__11mgCDrawPrim, PATH3_INITIATOR). -1 == not reachable.
        int drawingChainDepth=-1;
        // Rule 84: lifecycle method with lazy-init pattern (lw $rN,0($a0); beq/bne $zero).
        boolean isLifecycleLazyInit=false;
        // Rule 85: BITBLTBUF reg writer (any of GIF A+D reg 0x50). Combined with
        // loadsPsm4hhConstant -> BITBLTBUF_T4HH_UPLOADER.
        boolean writesBitbltbufReg=false;
        boolean isBitbltbufT4hhUploader=false;

        // ===== v8 fields =====
        // Rule 92 / 108: demangled ctor classification.
        String  ctorClassName = null;           // e.g. "mgCCameraFollow"
        boolean isCtor = false;
        boolean isDtor = false;
        String  methodClassName = null;         // demangled class for methods
        String  methodName = null;              // demangled simple method name
        boolean isVirtualDrawMethod = false;    // Draw__ / Step__ / Update__ within a class
        // Vtable install: addr stored to *(this+0) when ctor body opens with
        // `lui $rN, hi; addiu $rN, $rN, lo; sw $rN, 0($a0)` pattern.
        long    ctorVtableAddr = 0L;
        boolean ctorInstallsVtable = false;
        boolean ctorAssignedToGlobal = false;   // any caller does `sw $v0, +imm($gp)` after jal
        Set<Long> ctorGlobalAddresses = new LinkedHashSet<>();
        Set<Long> ctorSiblingCtorCalls = new LinkedHashSet<>();
        boolean calledViaDirectJal = false;     // observed direct jal caller
        boolean calledViaJrT9 = false;          // observed jalr $t9 caller (indirect)
        String  ctorCallMode = "unobserved";    // direct_only | indirect_only | dual | unobserved
        String  ctorRiskTier = "LOW";           // CRITICAL | HIGH | MEDIUM | LOW
        // Rule 94: virtual dispatch sites — entries [pcHex, slotOffsetHex, objReg].
        List<String[]> virtualDispatchSites = new ArrayList<>();
        // Rule 95: any return value of a `jal <this>` site that was subsequently
        // stored to a $gp-rooted global. Populated post-scan.
        Set<Long> returnWrittenToGlobals = new LinkedHashSet<>();
        // Rule 97: andi/and immediates that look like PS2 pad button masks.
        Set<String> padMasksTested = new LinkedHashSet<>();
        boolean isPadButtonMaskConsumer = false;
        // Rule 96: GIF NLOOP double-count hazard — function calls both open+close
        // helpers; flag for human review.
        boolean callsGifPacketOpen = false;
        boolean callsGifPacketClose = false;
        boolean gifNloopDoubleCountRisk = false;
        // Rule 99: file-open callee + format-string source for $a0 path argument.
        boolean callsFileOpen = false;
        Set<String> filePathSprintfFormats = new LinkedHashSet<>();
        boolean filePathHasPercentS = false;
        // Rule 100: frame-clock driver — calls vsync / mgEndFrame
        boolean isFrameClockDriver = false;
        // Rule 101: SIF RPC fid (function id) literal — captured alongside SID.
        Set<Long> detectedRpcFids = new LinkedHashSet<>();
        // Rule 102: sceVu0 family — must-implement whitelist.
        boolean isSceVu0Helper = false;
        String  vu0HelperFamily = null;         // matrix / vector / transform
        boolean mustBeImplemented = false;
        // Rule 88: libgcc exact-name match (in addition to regex).
        // Rule 90: split SPR_SYNC into separate emit fields (existing usesSPR /
        // hasSyncInstr suffice for split).
        // Rule 103: tagged when func writes BITBLTBUF + loads dbp constant from
        // EXPECTED_DBP_SET. Includes which expected tags it satisfies.
        Set<String> assetUploadTagsHit = new LinkedHashSet<>();
        // Rule 91: caller of an uploader (depth 1 or 2). Filled post-scan.
        boolean uploaderCallerDepth1 = false;
        boolean uploaderCallerDepth2 = false;
        // Rule 98: override classification (filled from parseGameOverrideFile v8).
        String  overrideKind = null;            // nop_stub | constant_return | state_machine | probe | real_shim
        boolean overrideRetireCandidate = false;
        // Rule 111: companion SDK-caller depth-1 flags (used for *_via_sdk_caller
        // statistics so SDK-wrapped accesses still show in counts).
        boolean dispfbWriterViaSdkCallerDepth1 = false;
        boolean dmaKickViaSdkCallerDepth1 = false;

        // ===== v9 fields (DC2 retrospective + General v11/v12 ports) =====
        // Rule 113
        boolean gifTagInlineBuilder = false;
        Set<Long>   gifTagRegsFields = new LinkedHashSet<>();
        Set<Long>   gifTagNloops     = new LinkedHashSet<>();
        Set<String> gifTagFlags      = new LinkedHashSet<>();
        // Rule 114
        boolean bitbltbufMacroSequence = false;
        // Rule 115
        boolean loadsChcrStartConst = false;
        boolean dmaChcrStartKick    = false;
        // Rule 116
        boolean dmaSourceChainTagBuilder = false;
        Set<String> dmaSourceChainTagIds = new LinkedHashSet<>();
        // Rule 117 / 118
        Set<String> storedVifOpcodes  = new LinkedHashSet<>();
        Set<String> storedDmaTagIds   = new LinkedHashSet<>();
        // Rule 119
        Set<String> compositeMmioRangesHit = new LinkedHashSet<>();
        boolean accessesRcnt        = false;
        boolean accessesVifCtrl     = false;
        boolean accessesDmacGlobal  = false;
        boolean writesIntcMask      = false;
        boolean readsIntcStat       = false;
        boolean accessesSio         = false;
        boolean writesDmacEnable    = false;
        boolean touchesSbusFlags    = false;
        // Rule 120
        String  inferredName        = null;
        long    inferredSyscallImm  = -1L;
        // Rule 121
        boolean isSyncWaitLoop      = false;
        boolean dc2HostWaitCandidate = false;
        // Rule 122 / 123
        boolean isInfiniteSpinLoop  = false;
        boolean containsInfiniteFailLoop = false;
        // Rule 124 / 125
        int     sifLoadModuleCallCount = 0;
        boolean isIrxLoader         = false;
        boolean isIopRebootHandler  = false;
        Set<String> irxModulePaths  = new LinkedHashSet<>();
        // Rule 126
        boolean isRenderFrameEntry  = false;
        // Rule 127
        boolean isStructInitializer = false;
        // Rule 128
        String  inferredClassName   = null;
        int     inferredVtableSlot  = -1;
        Set<String> tableDispatchSites = new LinkedHashSet<>();
        // Rule 129
        int     moduleId            = -1;
        // Rule 131
        String  dc2KnownRole        = null;
        String  dc2KnownPhase       = null;
        String  dc2KnownCriticality = null;
        // Rule 134: tags marking participation in pre-computed DC2 call chains
        Set<String> dc2CallChainsTagged = new LinkedHashSet<>();
        // Rule 139: SIDs / FIDs discovered via composite lui+ori before sceSifCallRpc
        Set<Long> discoveredRpcSids  = new LinkedHashSet<>();
        Set<Long> discoveredRpcFids2 = new LinkedHashSet<>();
        // const loads captured for table-dispatch resolution (Rule 128)
        List<long[]> constLoads = new ArrayList<>();
        // R20: patch candidate PCs (BACKWARD_BRANCH_SYNC_WAIT / INFINITE_FAIL_LOOP)
        List<Long> patchCandidatePcs = new ArrayList<>();
    }

    // =========================================================
    // STATE
    // =========================================================
    private FunctionManager funcManager;
    private ReferenceManager refManager;
    private Memory memory;
    private Map<Address, FuncTraits> cache = new HashMap<>();
    private Map<Address, Boolean> staticFwCache = new HashMap<>();
    private Map<Address, Boolean> iopFwCache = new HashMap<>();
    private Map<Address, Boolean> behavFwCache = new HashMap<>();

    // Rule 9: Step 1 config tracking
    private Set<Long> step1StubAddresses = new HashSet<>();
    private Set<Long> step1SkipAddresses = new HashSet<>();
    private Set<String> step1StubNames = new HashSet<>();
    private Set<String> step1SkipNames = new HashSet<>();

    // Rule 18: Game override import (v3 NEW)
    private Set<Long> gameOverrideAddresses = new HashSet<>();
    private Map<Long, String> gameOverrideNames = new HashMap<>();

    // Rule 11: MainLoop shield
    private Set<Long> mainLoopShield = new HashSet<>();

    private long textStart=0, textEnd=0;

    // Counters
    private int radarNewStubs=0, radarNewSkips=0;
    private int safeLeafCount=0, accHazardCount=0, mmioCount=0;
    private int smcHazardCount=0, sprSyncCount=0, busyWaitCount=0;
    private int vcallmsCount=0, jumpTableCount=0, orphanCount=0;
    // v3 counters
    private int conventionViolationCount=0, initLargeFuncCount=0;
    private int dmaTteRiskCount=0, iopRpcCount=0;
    private int archiveIoCount=0, padPollLoopCount=0;
    private int gameOverrideImportedCount=0;
    private int threadSyncCount=0; // Rule 25

    // v4 counters
    private int ctorFieldWriterCount=0, vtableSetterCount=0;
    private int pollTargetCount=0, a0PassthroughCount=0;
    private int procTerminatorCount=0, libgccIntrinsicCount=0;
    private int gifPath3HazardCount=0, zBufferAliasCount=0;
    private int mpegTrapCount=0, dispfbWriterCount=0;
    private int vif1TagHiBuilderCount=0, tailCallIndirectCount=0;
    private int indirectCallT9Funcs=0;

    // v5 counters
    private int isSceGifPkRefLoadImageCount=0, path3InitiatorCount=0;
    private int sceGifPkFamilyCount=0;
    private int tex0WriterCount=0, primReaderCount=0, rgbaqWriterCount=0;
    private int dmaKickCount=0, dmaQwcTadrCount=0, microcodeUploaderCount=0;
    private int audioRpcCount=0, meswinLoaderCount=0, mcGateCount=0;
    private int topPriorityFixCount=0;

    // v6 counters
    private int ipuMmioCount=0, writesIpuCmdCount=0;
    private int gifP3RegCount=0, gifFifoWriteCount=0;
    private int vif1FifoWriteCount=0, vif0FifoWriteCount=0;
    private int vuMicromemCount=0, vuDatamemCount=0;
    private int sbusCount=0, psm4hhCount=0;
    private int vifOpcodeBuilderCount=0, vifMpgBuilderCount=0;
    private int vifMscalBuilderCount=0, vifDirectBuilderCount=0;
    private int vifUnpackBuilderCount=0, dmaTagBuilderCount=0;

    // v7 counters (GS runtime corroboration)
    private int dispfbSdkWriterCount=0, path3KickViaApiCount=0;
    private int gsIrqHandlerCount=0, gsIrqSafeStubCount=0;
    private int runtimeConfirmedCount=0, runtimeDormantCount=0;
    private int runtimeMenuOnlyCount=0;
    private int tbpRuntimeConfirmedFuncCount=0;

    // v7.1 counters (F32-F34 retrospective rules)
    private int ctorMultiFieldInitCount=0;
    private int lifecycleLazyInitCount=0;
    private int bitbltbufT4hhUploaderCount=0;
    private int drawingChainCount=0;       // funcs with chain_depth >= 0

    // v8 counters
    private int ctorCriticalCount=0, ctorHighCount=0, ctorMediumCount=0;
    private int ctorAssignedGlobalCount=0, ctorInstallsVtableCount=0;
    private int ctorDualCallModeCount=0;
    private int virtualDispatchSiteCount=0;       // total sites across all funcs
    private int virtualDispatchFuncCount=0;       // funcs with at least one site
    private int padButtonMaskConsumerCount=0;
    private int gifNloopDoubleCountRiskCount=0;
    private int filePathSprintfCount=0;
    private int frameClockDriverCount=0;
    private int sceVu0HelperCount=0;
    private int assetUploadTraceFuncCount=0;
    private int overrideClassifiedCount=0;
    private int overrideRetireCount=0;
    private int dispfbWriterViaSdkCallerCount=0;
    private int dmaKickViaSdkCallerCount=0;
    private int returnWrittenToGlobalCount=0;
    private int autoExtendedDc2GlobalsCount=0;
    // Auto-extended DC2 gp globals discovered via return-to-global tracking.
    // Address -> guessed-name (class name where available, else "g_unk_<addr>").
    private Map<Long,String> autoExtendedDc2Globals = new LinkedHashMap<>();

    // v9 counters
    private int gifTagInlineBuilderCount = 0;
    private int bitbltbufMacroSeqCount   = 0;
    private int dmaChcrStartKickCount    = 0;
    private int dmaSourceChainBuilderCount = 0;
    private int compositeMmioRecoveryCount = 0;
    private int syscallTrampolineCount    = 0;
    private int backwardSyncWaitCount     = 0;
    private int infiniteSpinLoopCount     = 0;
    private int infiniteFailLoopCount     = 0;
    private int irxLoaderCount            = 0;
    private int iopRebootHandlerCount     = 0;
    private int renderFrameEntryCount     = 0;
    private int structInitializerCount    = 0;
    private int dispatchTableTargetCount  = 0;
    private int tableDispatchCallCount    = 0;
    private int dc2HostWaitCandidateCount = 0;
    private int dc2KnownAddressMatched    = 0;
    private int discoveredRpcSidCount     = 0;
    // Top-level discoveries
    private Map<Long, List<long[]>> functionPointerTables = new LinkedHashMap<>();
    private Map<Integer, Set<Long>> moduleClusters       = new LinkedHashMap<>();
    private Map<String, List<Long>> namePrefixModules    = new LinkedHashMap<>();
    // address -> set of caller addresses (for discovered_iop_sids)
    private Map<Long, Set<Long>> discoveredSidToCallers  = new LinkedHashMap<>();
    private Map<Long, Set<Long>> discoveredFidToCallers  = new LinkedHashMap<>();
    // Rule 93 class registry: class name -> aggregated info.
    private Map<String, ClassEntry> classRegistry = new LinkedHashMap<>();
    // Rule 103 asset upload traces: tag -> list of (funcAddr, funcName) + callers.
    private Map<String, List<long[]>> assetUploadTraces = new LinkedHashMap<>();
    // Rule 109 diff-mode: address -> prior `disposition|category` string.
    private Map<Long,String> priorTriageMapCats = null;

    /** Rule 93: aggregated per-class info for the JSON `classes` section. */
    static class ClassEntry {
        String  className;
        Set<Long> ctorAddresses = new LinkedHashSet<>();
        Long    dtorAddress = null;
        Set<String> methodNames = new LinkedHashSet<>();
        Map<String,Long> methodAddrs = new LinkedHashMap<>();
        boolean hasVirtualDraw = false;
        Long    vtableAddr = null;
        Set<Long> instantiationSites = new LinkedHashSet<>(); // jal call PCs
        Set<String> globalHolders = new LinkedHashSet<>();
        String  riskTier = "LOW";
    }

    // v4: BFS roots. main_loop_addr stays optional; entry/_start used for init chain.
    private Long mainLoopAddrOpt = null;
    private Long entryAddrOpt    = null;

    // =========================================================
    // ENTRY POINT
    // =========================================================
    @Override
    public void run() throws Exception {
        funcManager = currentProgram.getFunctionManager();
        refManager = currentProgram.getReferenceManager();
        memory = currentProgram.getMemory();

        println("=========================================================");
        println("PS2Recomp TRIAGE ENRICHER v3 - DC2-aware (Rules 18-24)");
        println("=========================================================\n");

        File csvFile = askFile("Select functions.csv from Step 1","Open");
        if (csvFile==null||!csvFile.exists()){printerr("No CSV. Aborting.");return;}

        File configToml = askFile("Select config.toml from Step 1","Open");
        if (configToml==null||!configToml.exists()){printerr("No config.toml. Aborting.");return;}

        File outputDir = csvFile.getParentFile();
        File unifiedToml = new File(outputDir,"config_auto_recomp.toml");
        File triageJson  = new File(outputDir,"triage_map.json");

        // Rule 9: Parse step 1 config
        parseStep1Config(configToml);
        println(String.format("[STEP1] %d stub addrs + %d stub names, %d skip addrs + %d skip names.",
            step1StubAddresses.size(),step1StubNames.size(),
            step1SkipAddresses.size(),step1SkipNames.size()));

        // Rule 18 (v3 NEW): Parse game override file
        try {
            File overrideFile = askFile(
                "Select dc2_game_override.cpp (or similar) - Cancel to skip","Open");
            if (overrideFile!=null && overrideFile.exists()) {
                parseGameOverrideFile(overrideFile);
                println(String.format("[OVERRIDE] Imported %d pre-bound addresses from %s.",
                    gameOverrideImportedCount, overrideFile.getName()));
            } else {
                println("[OVERRIDE] Skipped - no game override file selected.");
            }
        } catch (Exception ignored) {
            println("[OVERRIDE] Skipped (dialog cancelled).");
        }

        // v7 (NEW): GS-dump runtime evidence folder. Optional.
        try {
            File gsDir = askDirectory(
                "Select folder of *.gs.summary.json files (Cancel to skip)","Open");
            if (gsDir!=null && gsDir.isDirectory()) {
                loadGsSummaryFolder(gsDir);
                int n = gsEvidence.checkpoints.size();
                if (n > 0) {
                    println(String.format("[GS-EVIDENCE] Loaded %d checkpoints from %s.",
                        n, gsDir.getName()));
                    println(String.format("[GS-EVIDENCE] anyP1=%s anyP2=%s anyP3=%s any4HH=%s anyPrimGarb=%s imrAllMasked=%s",
                        gsEvidence.anyPath1, gsEvidence.anyPath2, gsEvidence.anyPath3,
                        gsEvidence.anyPsmt4hh, gsEvidence.anyPrimGarbage,
                        gsEvidence.imrAllMaskedGsIrqs));
                } else {
                    println("[GS-EVIDENCE] Folder selected but no .summary.json found.");
                }
            } else {
                println("[GS-EVIDENCE] Skipped - no folder selected.");
            }
        } catch (Exception ex) {
            println("[GS-EVIDENCE] Skipped: "+ex.getMessage());
        }

        // Rule 11: MainLoop shield
        Address mainLoopAddr = null;
        try {
            mainLoopAddr = askAddress("MainLoop Address",
                "Enter MainLoop address (Cancel = auto-detect or skip)");
        } catch (Exception ignored) {}
        if (mainLoopAddr==null) {
            for (Function f : funcManager.getFunctions(true)) {
                String n = f.getName().toLowerCase();
                if (n.equals("mainloop__fv")||n.equals("mainloop")||n.equals("main_loop")) {
                    mainLoopAddr = f.getEntryPoint();
                    println("[MAINLOOP] Auto-detected: "+f.getName()+" @ "+mainLoopAddr);
                    break;
                }
            }
        }
        if (mainLoopAddr!=null) {
            buildMainLoopShield(mainLoopAddr);
            mainLoopAddrOpt = mainLoopAddr.getOffset() & 0xFFFFFFFFL;
            println("[MAINLOOP] Shield: "+mainLoopShield.size()+" functions protected.\n");
        } else {
            println("[MAINLOOP] No MainLoop found. Shield disabled.\n");
        }

        // v4: locate entry/_start for init-chain depth BFS (Rule 40).
        for (String n : new String[]{"entry","_start"}) {
            SymbolIterator si = currentProgram.getSymbolTable().getSymbols(n);
            if (si.hasNext()) {
                entryAddrOpt = si.next().getAddress().getOffset() & 0xFFFFFFFFL;
                println("[ENTRY] BFS root for init chain: "+n+" @ 0x"+Long.toHexString(entryAddrOpt));
                break;
            }
        }

        detectTextSection();
        long gpValue = detectGlobalPointer();

        // v9.1: pre-scan KNOWN_DC2_FUNCTION_ADDRESSES. Counts both address +
        // name hits across the ELF — independent of Step1/override gate that
        // would otherwise skip pre-classified entries (so the static map is
        // still populated even for funcs the main scan loop continues past).
        {
            int addrHits = 0, nameHits = 0;
            ghidra.program.model.address.AddressFactory af = currentProgram.getAddressFactory();
            for(Object[] row : KNOWN_DC2_FUNCTION_ADDRESSES) {
                long want = ((Number)row[0]).longValue() & 0xFFFFFFFFL;
                String wantName = (String)row[1];
                Function f = funcManager.getFunctionAt(af.getDefaultAddressSpace().getAddress(want));
                if(f != null) addrHits++;
                else {
                    SymbolIterator si = currentProgram.getSymbolTable().getSymbols(wantName);
                    if(si.hasNext()) nameHits++;
                }
            }
            dc2KnownAddressMatched = addrHits + nameHits;
            println(String.format("[DC2-KNOWN] address_hits=%d name_hits=%d of %d entries.",
                addrHits, nameHits, KNOWN_DC2_FUNCTION_ADDRESSES.length));
        }
        String elfHash = computeElfHash();

        println("[SCAN] Analyzing...");

        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);
        BasicBlockModel blockModel = new BasicBlockModel(currentProgram);

        PrintWriter asmWriter   = new PrintWriter(new FileWriter(new File(outputDir,"assembly.txt")));
        PrintWriter decompWriter = new PrintWriter(new FileWriter(new File(outputDir,"decompiled.txt")));
        PrintWriter flowWriter  = new PrintWriter(new FileWriter(new File(outputDir,"flowchart.txt")));

        long scanStart = System.currentTimeMillis();
        try {
            FunctionIterator allFuncs = funcManager.getFunctions(true);
            int totalFuncs=0, uncategorized=0;
            List<FuncResult> results = new ArrayList<>();
            List<String> newStubs = new ArrayList<>();
            List<String> newSkips = new ArrayList<>();

            while (allFuncs.hasNext() && !monitor.isCancelled()) {
                Function func = allFuncs.next();
                totalFuncs++;
                if (totalFuncs%500==0) monitor.setMessage("Scanning function "+totalFuncs+"...");

                Address addr = func.getEntryPoint();
                long offset = addr.getOffset();
                String funcName = func.getName();

                // Export text files
                String header = "\n\n========================================\n"+
                    "FUNCTION: "+funcName+"\n"+"ADDRESS: "+addr+"\n"+
                    "========================================\n";
                asmWriter.println(header);
                InstructionIterator instructions = currentProgram.getListing().getInstructions(func.getBody(),true);
                while (instructions.hasNext()) {
                    Instruction instr = instructions.next();
                    asmWriter.println(instr.getAddress()+" "+instr);
                }
                decompWriter.println(header);
                DecompileResults decompResult = decomp.decompileFunction(func,30,monitor);
                if (decompResult!=null&&decompResult.decompileCompleted())
                    decompWriter.println(decompResult.getDecompiledFunction().getC());
                else
                    decompWriter.println("[decompile failed]");
                flowWriter.println(header);
                try {
                    CodeBlockIterator blocks = blockModel.getCodeBlocksContaining(func.getBody(),monitor);
                    while (blocks.hasNext()) {
                        CodeBlock block = blocks.next();
                        flowWriter.println("  BLOCK: "+block.getFirstStartAddress());
                        CodeBlockReferenceIterator dests = block.getDestinations(monitor);
                        while (dests.hasNext()) {
                            CodeBlockReference ref = dests.next();
                            flowWriter.println("    --> "+ref.getDestinationAddress()+" ["+ref.getFlowType().getName()+"]");
                        }
                    }
                } catch (Exception e) {
                    flowWriter.println("  [flowchart failed: "+e.getMessage()+"]");
                }

                // Rule 9: skip already-classified from step 1
                if (step1StubAddresses.contains(offset)||step1SkipAddresses.contains(offset)
                        ||step1StubNames.contains(funcName)||step1SkipNames.contains(funcName))
                    continue;

                // Rule 18 (v3): skip already bound in game override
                if (gameOverrideAddresses.contains(offset)) continue;

                uncategorized++;

                FuncTraits traits = getTraits(func);

                // Rule 10: Whitelist check
                boolean isWhitelisted = false;
                for (String wl : WHITELIST_NAMES) {
                    if (funcName.equals(wl)){isWhitelisted=true;break;}
                }
                if (!isWhitelisted) {
                    if (funcName.contains("__ct__")||
                        (funcName.contains("__dt__")&&!funcName.contains("std"))||
                        funcName.contains("__as__")||
                        funcName.startsWith("__sinit_")||
                        funcName.toLowerCase().contains("callback")||
                        funcName.toLowerCase().contains("handler"))
                        isWhitelisted = true;
                }
                if (mainLoopShield.contains(offset)) isWhitelisted=true;

                // Rule 20 (v3 NEW): Large init functions must be RECOMPILE, never nop-stubbed
                // v4: extend to vtable-setter ctors, A0/A1 passthrough returners,
                // libgcc intrinsics, and process terminators. All four were
                // historically auto-stubbed and caused multi-phase debugging trips.
                // v7.1: add F33-derived firewalls — multi-field ctors and
                // lifecycle lazy-init guards. drawing_chain_depth firewall is
                // applied in a post-pass after BFS runs.
                boolean forceRecompile = traits.isLargeInitFunc
                                       || traits.ctorWritesVTablePointer
                                       || traits.returnsA0 || traits.returnsA1
                                       || traits.isLibgccIntrinsic
                                       || traits.isProcessTerminator
                                       || traits.isCtorMultiFieldInit
                                       || traits.isLifecycleLazyInit
                                       || traits.isBitbltbufT4hhUploader;

                // --- Disposition decision ---
                String disposition = "RECOMPILE";
                if (!isWhitelisted && !forceRecompile) {
                    if (isRadarFirewalled(func)) {
                        disposition="STUB";
                        newStubs.add(funcName+"@"+hex(offset));
                        radarNewStubs++;
                    } else if (traits.refsIopModuleString) {
                        disposition="STUB";
                        newStubs.add(funcName+"@"+hex(offset));
                        radarNewStubs++;
                    } else if (traits.hasSyscall||traits.hasCOP0) {
                        disposition="SKIP";
                        newSkips.add(funcName+"@"+hex(offset));
                        radarNewSkips++;
                    } else if (traits.hasVcallms) {
                        disposition="STUB";
                        newStubs.add(funcName+"@"+hex(offset));
                        radarNewStubs++;
                    }
                }

                // --- Tags ---
                List<String> tags = new ArrayList<>();
                String category = assignCategory(traits);

                // SAFE_LEAF: no callees, no call ops, not a thunk, and not VU0 microcode
                // (vcallms implicitly "calls" VU0 - not safe for auto-translation)
                if (traits.calleeCount==0&&traits.callOps==0&&!traits.isThunk&&
                    traits.byteSize>0&&!traits.hasVcallms)
                    {tags.add("SAFE_LEAF");safeLeafCount++;}
                // [FIX] VU0_MICROCODE tagged before ACC_PRECISION_HAZARD so that
                // classify_phases() in triage_analyzer.py routes consistently:
                // a function with both tags lands in phase7, not phase5.
                if (traits.hasVcallms)
                    {tags.add("VU0_MICROCODE");vcallmsCount++;}
                if (traits.accOps>=3)
                    {tags.add("ACC_PRECISION_HAZARD");accHazardCount++;}
                if (traits.writesToText)
                    {tags.add("SMC_HAZARD");smcHazardCount++;}
                if (traits.usesSPR&&traits.hasSyncInstr)
                    {tags.add("SPR_SYNC_HAZARD");sprSyncCount++;}
                if (traits.hasBusyWait)
                    {tags.add("BUSY_WAIT_HAZARD");busyWaitCount++;}
                if (traits.hasJumpTable)
                    {tags.add("COMPLEX_CONTROL_FLOW");jumpTableCount++;}
                if (traits.accessesMMIO)
                    {tags.add("ACCESSES_MMIO");mmioCount++;}
                if (traits.usesCop2) tags.add("VU0_VECTORS");
                if (traits.usesCop1) tags.add("FPU_HEAVY");
                if (traits.usesSPR)  tags.add("USES_SPR");
                if (traits.writesToGlobal) tags.add("WRITES_GLOBAL");
                if (traits.returnPaths>=3) tags.add("MULTI_RETURN");
                if (!refManager.hasReferencesTo(addr)&&!isWhitelisted)
                    {tags.add("ORPHAN_CODE");orphanCount++;}

                // v3 new tags:
                // Rule 19
                if (traits.writesToA1Buffer)
                    {tags.add("CONVENTION_VIOLATION");conventionViolationCount++;}
                // Rule 20
                if (traits.isLargeInitFunc)
                    {tags.add("INIT_LARGE_FUNC");initLargeFuncCount++;}
                // Rule 21
                if (traits.callsDmaSend&&traits.accessesVif1MMIO)
                    {tags.add("DMA_CHAIN_TTE_RISK");dmaTteRiskCount++;}
                // Rule 22
                if (traits.callsSifRpc)
                    {tags.add("IOP_RPC_DISPATCH");iopRpcCount++;}
                // Rule 23
                if (traits.refsArchiveStrings)
                    {tags.add("ARCHIVE_IO");archiveIoCount++;}
                // Rule 25
                if (traits.isThreadSyncPoint)
                    {tags.add("THREAD_SYNC_POINT");threadSyncCount++;}
                // Rule 24
                if (traits.callsPadPollCallee&&traits.hasBusyWait)
                    {tags.add("PAD_POLL_LOOP");padPollLoopCount++;}

                // ===== v4 tags =====
                // Rule 26/27
                if (traits.ctorWritesA0Slot)
                    {tags.add("CTOR_FIELD_WRITER");ctorFieldWriterCount++;}
                if (traits.ctorWritesVTablePointer)
                    {tags.add("VTABLE_SETTER");vtableSetterCount++;}
                // Rule 29
                if (traits.returnsA0||traits.returnsA1)
                    {tags.add("A0_PASSTHROUGH_RETURNER");a0PassthroughCount++;}
                // Rule 30
                if (traits.isProcessTerminator)
                    {tags.add("PROCESS_TERMINATOR");procTerminatorCount++;}
                // Rule 31
                if (traits.isLibgccIntrinsic)
                    {tags.add("LIBGCC_INTRINSIC");libgccIntrinsicCount++;}
                // Rule 32 - GIF Path3 hazard: CTRL/CHCR touch OR write to PRIM offset
                if (traits.touchesGifCtrl||traits.writesGsPrimReg)
                    {tags.add("GIF_PATH3_HAZARD");gifPath3HazardCount++;}
                // Rule 33 - Z-buffer alias risk
                if (traits.writesZbufReg && (traits.hasShift24Pattern||traits.hasDsll32OrDsrl32))
                    {tags.add("Z_BUFFER_ALIAS_RISK");zBufferAliasCount++;}
                // Rule 34
                if (traits.callsMpegFamily)
                    {tags.add("MPEG_DECODER_TRAP");mpegTrapCount++;}
                // Rule 35
                if (traits.writesDispfbReg)
                    {tags.add("DISPFB_WRITER");dispfbWriterCount++;}
                // v7 Rule 75: SDK-routed DISPFB writer
                if (traits.writesDispfbViaSdk) {
                    if(!tags.contains("DISPFB_SDK_WRITER")) tags.add("DISPFB_SDK_WRITER");
                    if(!tags.contains("DISPFB_WRITER")) {
                        tags.add("DISPFB_WRITER");
                        dispfbWriterCount++;
                    }
                    dispfbSdkWriterCount++;
                }
                // v7 Rule 76: SDK-routed Path3 kicker
                if (traits.path3KickViaDmaApi) {
                    if(!tags.contains("PATH3_KICK_VIA_DMA_API")) tags.add("PATH3_KICK_VIA_DMA_API");
                    if(!tags.contains("PATH3_INITIATOR")) {
                        tags.add("PATH3_INITIATOR");
                        path3InitiatorCount++;
                    }
                    path3KickViaApiCount++;
                }
                // v7 Rule 79 name-match counter (the safe-stub TAG is added in
                // the post-pass once runtime IMR is known).
                if (traits.isGsIrqHandlerName) gsIrqHandlerCount++;
                // Rule 36 - VIF1 tag-high builder
                if (traits.accessesVif1MMIO && traits.hasDsll32OrDsrl32)
                    {tags.add("VIF1_TAGHI_BUILDER");vif1TagHiBuilderCount++;}
                // Rule 37
                if (traits.tailCallIndirect)
                    {tags.add("TAIL_CALL_INDIRECT");tailCallIndirectCount++;}
                // Rule 38
                if (traits.indirectCallT9Count>0) {
                    tags.add("INDIRECT_CALL_T9");
                    indirectCallT9Funcs++;
                }

                // ===== v5 tags =====
                // Rule 43
                if (traits.isSceGifPkRefLoadImage)
                    {tags.add("IS_SCE_GIF_PK_REF_LOAD_IMAGE");isSceGifPkRefLoadImageCount++;}
                // Rule 44
                if (traits.path3Initiator)
                    {tags.add("PATH3_INITIATOR");path3InitiatorCount++;}
                // Rule 45
                if (traits.isSceGifPkFamily)
                    {tags.add("SCE_GIF_PK_FAMILY");sceGifPkFamilyCount++;}
                // Rule 46
                if (traits.writesTex0Reg)
                    {tags.add("TEX0_REG_WRITER");tex0WriterCount++;}
                // Rule 47
                if (traits.readsPrimReg)
                    {tags.add("PRIM_REG_READER");primReaderCount++;}
                // Rule 48
                if (traits.writesRgbaqReg)
                    {tags.add("RGBAQ_WRITER");rgbaqWriterCount++;}
                // Rule 49
                if (!traits.dmaKickChannels.isEmpty())
                    {tags.add("DMA_KICK_PATTERN");dmaKickCount++;}
                // Rule 50
                if (!traits.dmaQwcTadrChannels.isEmpty())
                    {tags.add("DMA_QWC_TADR_WRITER");dmaQwcTadrCount++;}
                // Rule 51
                if (traits.isMicrocodeUploader)
                    {tags.add("MICROCODE_UPLOADER");microcodeUploaderCount++;}
                // Rule 52
                if (traits.isAudioRpcHandler)
                    {tags.add("AUDIO_RPC_HANDLER");audioRpcCount++;}
                // Rule 53
                if (traits.refsMeswinStrings)
                    {tags.add("MESWIN_LOADER");meswinLoaderCount++;}
                // Rule 54
                if (traits.isMcTransitionGate)
                    {tags.add("MC_TRANSITION_GATE");mcGateCount++;}
                // ===== v6 tags =====
                if (traits.accessesIpuMmio) {tags.add("ACCESSES_IPU_MMIO");ipuMmioCount++;}
                if (traits.writesIpuCmd)    {tags.add("WRITES_IPU_CMD");writesIpuCmdCount++;}
                if (traits.touchesGifP3Reg) {tags.add("GIF_PATH3_REG_TOUCHER");gifP3RegCount++;}
                if (traits.writesGifFifo)   {tags.add("GIF_FIFO_DIRECT_WRITER");gifFifoWriteCount++;}
                if (traits.writesVif1Fifo)  {tags.add("VIF1_FIFO_DIRECT_WRITER");vif1FifoWriteCount++;}
                if (traits.writesVif0Fifo)  {tags.add("VIF0_FIFO_DIRECT_WRITER");vif0FifoWriteCount++;}
                if (traits.accessesVuMicromem) {tags.add("ACCESSES_VU_MICROMEM");vuMicromemCount++;}
                if (traits.accessesVuDatamem)  {tags.add("ACCESSES_VU_DATAMEM");vuDatamemCount++;}
                if (traits.touchesSbus)     {tags.add("SBUS_IOP_COMM_TOUCHER");sbusCount++;}
                if (traits.loadsPsm4hhConstant) {tags.add("PSMT4HH_REFERENCE");psm4hhCount++;}
                // v7.1 Rule 82
                if (traits.isCtorMultiFieldInit) {
                    tags.add("CTOR_MULTI_FIELD_INITIALIZER");
                    ctorMultiFieldInitCount++;
                }
                // v7.1 Rule 84
                if (traits.isLifecycleLazyInit) {
                    tags.add("LIFECYCLE_LAZY_INIT_GUARD");
                    lifecycleLazyInitCount++;
                }
                // v7.1 Rule 85
                if (traits.isBitbltbufT4hhUploader) {
                    tags.add("BITBLTBUF_T4HH_UPLOADER");
                    bitbltbufT4hhUploaderCount++;
                }
                if (!traits.vifOpcodesBuilt.isEmpty()) {
                    tags.add("VIF_OPCODE_BUILDER");vifOpcodeBuilderCount++;
                    if (traits.vifOpcodesBuilt.contains("MPG"))
                        {tags.add("VIF_MPG_OPCODE_BUILDER");vifMpgBuilderCount++;}
                    if (traits.vifOpcodesBuilt.contains("MSCAL") ||
                        traits.vifOpcodesBuilt.contains("MSCALF") ||
                        traits.vifOpcodesBuilt.contains("MSCNT"))
                        {tags.add("VIF_MSCAL_OPCODE_BUILDER");vifMscalBuilderCount++;}
                    if (traits.vifOpcodesBuilt.contains("DIRECT") ||
                        traits.vifOpcodesBuilt.contains("DIRECTHL"))
                        {tags.add("VIF_DIRECT_OPCODE_BUILDER");vifDirectBuilderCount++;}
                    if (traits.vifOpcodesBuilt.contains("UNPACK"))
                        {tags.add("VIF_UNPACK_OPCODE_BUILDER");vifUnpackBuilderCount++;}
                }
                if (!traits.dmaTagIdsBuilt.isEmpty())
                    {tags.add("DMA_TAG_BUILDER");dmaTagBuilderCount++;}

                // ===== v9 tags =====
                if (traits.gifTagInlineBuilder) {
                    tags.add("GIF_TAG_INLINE_BUILDER"); gifTagInlineBuilderCount++;
                }
                if (traits.bitbltbufMacroSequence) {
                    if(!tags.contains("BITBLTBUF_MACRO_SEQUENCE"))
                        tags.add("BITBLTBUF_MACRO_SEQUENCE");
                    bitbltbufMacroSeqCount++;
                }
                if (traits.dmaChcrStartKick) {
                    tags.add("DMA_CHCR_START_KICK"); dmaChcrStartKickCount++;
                }
                if (traits.dmaSourceChainTagBuilder) {
                    tags.add("DMA_SOURCE_CHAIN_TAG_BUILDER"); dmaSourceChainBuilderCount++;
                }
                if (!traits.storedVifOpcodes.isEmpty()) {
                    tags.add("VIF_TAG_STORED_IMMEDIATE");
                    if (traits.storedVifOpcodes.contains("MPG") &&
                        !tags.contains("VIF_MPG_OPCODE_BUILDER"))
                        tags.add("VIF_MPG_OPCODE_BUILDER");
                    if ((traits.storedVifOpcodes.contains("MSCAL") ||
                         traits.storedVifOpcodes.contains("MSCALF") ||
                         traits.storedVifOpcodes.contains("MSCNT")) &&
                        !tags.contains("VIF_MSCAL_OPCODE_BUILDER"))
                        tags.add("VIF_MSCAL_OPCODE_BUILDER");
                }
                if (!traits.storedDmaTagIds.isEmpty())
                    tags.add("DMA_TAG_STORED_IMMEDIATE");
                if (!traits.compositeMmioRangesHit.isEmpty()) {
                    tags.add("COMPOSITE_MMIO_RECOVERED");
                    compositeMmioRecoveryCount++;
                }
                if (traits.inferredSyscallImm > 0) {
                    tags.add("SYSCALL_TRAMPOLINE"); syscallTrampolineCount++;
                }
                if (traits.isSyncWaitLoop) {
                    tags.add("BACKWARD_BRANCH_SYNC_WAIT"); backwardSyncWaitCount++;
                    // F24/F27 host-wait class marker for the report tool.
                    if (mainLoopShield.contains(offset)) {
                        tags.add("DC2_HOST_WAIT_CANDIDATE");
                        traits.dc2HostWaitCandidate = true;
                        dc2HostWaitCandidateCount++;
                    }
                }
                if (traits.isInfiniteSpinLoop) {
                    tags.add("INFINITE_SPIN_LOOP"); infiniteSpinLoopCount++;
                }
                if (traits.containsInfiniteFailLoop) {
                    tags.add("INFINITE_FAIL_LOOP"); infiniteFailLoopCount++;
                }
                if (traits.isIrxLoader) {
                    tags.add("IRX_LOADER"); irxLoaderCount++;
                }
                if (traits.isIopRebootHandler) {
                    tags.add("IOP_REBOOT_HANDLER"); iopRebootHandlerCount++;
                }
                if (traits.isRenderFrameEntry) {
                    tags.add("RENDER_FRAME_ENTRY"); renderFrameEntryCount++;
                }
                if (traits.isStructInitializer) {
                    tags.add("STRUCT_INITIALIZER"); structInitializerCount++;
                }
                if (traits.dc2KnownRole != null) {
                    tags.add("DC2_KNOWN_ROLE_" + traits.dc2KnownRole.toUpperCase());
                    if ("BLOCKER".equals(traits.dc2KnownCriticality))
                        tags.add("DC2_BLOCKER_REF");
                }
                if (!traits.discoveredRpcSids.isEmpty()) {
                    tags.add("DISCOVERED_IOP_SID"); discoveredRpcSidCount++;
                }

                // Rule 56 (v5, extended by v6, v9): derived top-priority bullseye.
                if (traits.isSceGifPkRefLoadImage || traits.path3Initiator ||
                    traits.path3KickViaDmaApi || traits.writesDispfbViaSdk ||
                    traits.isBitbltbufT4hhUploader ||
                    (traits.writesZbufReg && (traits.hasShift24Pattern||traits.hasDsll32OrDsrl32)) ||
                    traits.writesGsPrimReg || traits.touchesGifCtrl ||
                    traits.callsMpegFamily || traits.writesIpuCmd ||
                    traits.touchesGifP3Reg || traits.loadsPsm4hhConstant ||
                    traits.vifOpcodesBuilt.contains("MPG") ||
                    traits.bitbltbufMacroSequence || traits.dmaChcrStartKick ||
                    traits.dmaSourceChainTagBuilder || traits.isRenderFrameEntry ||
                    "BLOCKER".equals(traits.dc2KnownCriticality)) {
                    traits.isTopPriorityFix = true;
                    if(!tags.contains("TOP_PRIORITY_FIX")) {
                        tags.add("TOP_PRIORITY_FIX");
                        topPriorityFixCount++;
                    }
                }

                FuncResult r = new FuncResult();
                r.address=offset; r.name=funcName; r.category=category;
                r.disposition=disposition; r.traits=traits; r.tags=tags;
                results.add(r);
            }

            long scanSec = (System.currentTimeMillis()-scanStart)/1000;
            println(String.format("[SCAN] %d functions in %dm%02ds.",totalFuncs,scanSec/60,scanSec%60));
            println(String.format("  New stubs: %d | New skips: %d",radarNewStubs,radarNewSkips));
            println(String.format("  v2 tags: SAFE=%d MMIO=%d ACC=%d SMC=%d SPR=%d VCALLMS=%d JTABLE=%d ORPHAN=%d",
                safeLeafCount,mmioCount,accHazardCount,smcHazardCount,
                sprSyncCount,vcallmsCount,jumpTableCount,orphanCount));
            println(String.format("  v3 tags: CONV_VIOLATION=%d INIT_LARGE=%d DMA_TTE=%d IOP_RPC=%d ARCHIVE_IO=%d PAD_POLL=%d THREAD_SYNC=%d",
                conventionViolationCount,initLargeFuncCount,dmaTteRiskCount,
                iopRpcCount,archiveIoCount,padPollLoopCount,threadSyncCount));
            println(String.format("  v4 tags: CTOR_FW=%d VTABLE_SET=%d A0_PASS=%d PROC_TERM=%d LIBGCC=%d GIF_P3=%d ZBUF_ALIAS=%d MPEG=%d DISPFB=%d VIF1_TAGHI=%d TAIL_INDIR=%d JALR_T9=%d",
                ctorFieldWriterCount,vtableSetterCount,a0PassthroughCount,
                procTerminatorCount,libgccIntrinsicCount,gifPath3HazardCount,
                zBufferAliasCount,mpegTrapCount,dispfbWriterCount,
                vif1TagHiBuilderCount,tailCallIndirectCount,indirectCallT9Funcs));
            println(String.format("  v5 tags: PK_REF_LD_IMG=%d PATH3_INIT=%d GIFPK_FAM=%d TEX0_W=%d PRIM_R=%d RGBAQ_W=%d DMA_KICK=%d DMA_QWC_TADR=%d MICROCODE_UP=%d AUDIO_RPC=%d MESWIN=%d MC_GATE=%d TOP_PRIORITY=%d",
                isSceGifPkRefLoadImageCount,path3InitiatorCount,sceGifPkFamilyCount,
                tex0WriterCount,primReaderCount,rgbaqWriterCount,
                dmaKickCount,dmaQwcTadrCount,microcodeUploaderCount,
                audioRpcCount,meswinLoaderCount,mcGateCount,topPriorityFixCount));
            println(String.format("  v6 tags: IPU_MMIO=%d IPU_CMD=%d GIF_P3=%d GIF_FIFO=%d VIF1_FIFO=%d VIF0_FIFO=%d VU_MICRO=%d VU_DATA=%d SBUS=%d PSMT4HH=%d VIFOP=%d MPG=%d MSCAL=%d DIRECT=%d UNPACK=%d DMATAG=%d",
                ipuMmioCount,writesIpuCmdCount,gifP3RegCount,gifFifoWriteCount,
                vif1FifoWriteCount,vif0FifoWriteCount,vuMicromemCount,vuDatamemCount,
                sbusCount,psm4hhCount,vifOpcodeBuilderCount,vifMpgBuilderCount,
                vifMscalBuilderCount,vifDirectBuilderCount,vifUnpackBuilderCount,
                dmaTagBuilderCount));
            println(String.format("  v7.1 tags: CTOR_MULTI=%d LAZY_INIT=%d BITBLTBUF_T4HH=%d",
                ctorMultiFieldInitCount, lifecycleLazyInitCount, bitbltbufT4hhUploaderCount));
            println(String.format("  v8 tags: CTOR_CRIT=%d CTOR_HIGH=%d CTOR_MED=%d CTOR_ASSIGN_GLOBAL=%d CTOR_VTABLE=%d CTOR_DUAL=%d VDISP_SITES=%d VDISP_FUNCS=%d PAD_MASK=%d NLOOP_RISK=%d FILE_SPRINTF=%d FRAME_CLK=%d VU0_HELPER=%d ASSET_UPLD=%d OVR_CLASS=%d OVR_RETIRE=%d DISPFB_VIA_SDK=%d DMA_KICK_VIA_SDK=%d RET2GLOBAL=%d AUTO_EXT_GLOBALS=%d CLASSES=%d",
                ctorCriticalCount, ctorHighCount, ctorMediumCount, ctorAssignedGlobalCount,
                ctorInstallsVtableCount, ctorDualCallModeCount, virtualDispatchSiteCount,
                virtualDispatchFuncCount, padButtonMaskConsumerCount, gifNloopDoubleCountRiskCount,
                filePathSprintfCount, frameClockDriverCount, sceVu0HelperCount,
                assetUploadTraceFuncCount, overrideClassifiedCount, overrideRetireCount,
                dispfbWriterViaSdkCallerCount, dmaKickViaSdkCallerCount,
                returnWrittenToGlobalCount, autoExtendedDc2GlobalsCount, classRegistry.size()));

            // F21-prep: build reverse call-graph. After all FuncResults are
            // built and each carries its outgoing jalSites, fill every callee's
            // traits.callers with (callerAddr, callSitePc) pairs. Caller name
            // resolution happens at JSON-emit time via the address index.
            Map<Long, FuncResult> resultsByAddr = new HashMap<>();
            for (FuncResult fr : results) resultsByAddr.put(fr.address & 0xFFFFFFFFL, fr);
            for (FuncResult caller : results) {
                if (caller.traits == null) continue;
                for (long[] site : caller.traits.jalSites) {
                    long target = site[1] & 0xFFFFFFFFL;
                    FuncResult callee = resultsByAddr.get(target);
                    if (callee != null && callee.traits != null) {
                        callee.traits.callers.add(new long[]{caller.address & 0xFFFFFFFFL, site[0]});
                    }
                }
            }

            // v4 Rule 39/40: BFS depth from MainLoop and entry/_start.
            // Build forward adjacency once from jalSites, then two BFS passes.
            // F28 wanted exactly this: "what functions live in the MainLoop subtree"
            // — derived by hand last time.
            Map<Long, List<Long>> fwd = new HashMap<>();
            for (FuncResult caller : results) {
                if (caller.traits == null) continue;
                long ca = caller.address & 0xFFFFFFFFL;
                List<Long> lst = fwd.computeIfAbsent(ca, k -> new ArrayList<>());
                for (long[] site : caller.traits.jalSites) {
                    long tgt = site[1] & 0xFFFFFFFFL;
                    if (tgt == 0xFFFFFFFFL) continue;
                    lst.add(tgt);
                }
            }
            if (mainLoopAddrOpt != null)
                bfsAssignDepth(fwd, resultsByAddr, mainLoopAddrOpt, true);
            if (entryAddrOpt != null)
                bfsAssignDepth(fwd, resultsByAddr, entryAddrOpt, false);
            // v7.1 Rule 83: BFS from GS-bullseye render roots; populates
            // traits.drawingChainDepth.
            bfsAssignDrawingChainDepth(fwd, resultsByAddr, results);
            // v7.1: drawing_chain_depth <= 6 firewall against STUB. Promote any
            // such already-classified STUB back to RECOMPILE and drop it from
            // newStubs so writeUnifiedConfig emits the corrected disposition.
            int promotedFromStub = 0;
            for(FuncResult r : results) {
                if(r.traits == null) continue;
                int d = r.traits.drawingChainDepth;
                if(d < 0 || d > 6) continue;
                if("STUB".equals(r.disposition)) {
                    r.disposition = "RECOMPILE";
                    newStubs.remove(r.name + "@" + hex(r.address));
                    promotedFromStub++;
                }
                if(!r.tags.contains("DRAWING_CHAIN_NEAR_ROOT"))
                    r.tags.add("DRAWING_CHAIN_NEAR_ROOT");
            }
            println(String.format("  v7.1 post: drawing_chain_funcs=%d (promoted_from_stub=%d)",
                drawingChainCount, promotedFromStub));

            // v4 Rule 28: POLL_RETURN_CONSUMER — a tiny returner is likely a
            // poll target if any caller contains a backward branch. We can't
            // grep the caller's body cheaply here; use the proxy: caller has
            // hasBackwardBranch AND the callee has byteSize<60, returnPaths>=1,
            // callOps==0. Tag the *callee*.
            for (FuncResult callee : results) {
                if (callee.traits == null) continue;
                FuncTraits t = callee.traits;
                if (t.byteSize>=60 || t.callOps>0 || t.returnPaths<1) continue;
                for (long[] cinfo : t.callers) {
                    FuncResult caller = resultsByAddr.get(cinfo[0] & 0xFFFFFFFFL);
                    if (caller != null && caller.traits != null && caller.traits.hasBackwardBranch) {
                        t.isLikelyPollTarget = true;
                        if (!callee.tags.contains("POLL_RETURN_CONSUMER")) {
                            callee.tags.add("POLL_RETURN_CONSUMER");
                            pollTargetCount++;
                        }
                        break;
                    }
                }
            }
            println(String.format("  v4 post: MAINLOOP_DEPTH set | INIT_DEPTH set | POLL_TARGET=%d",
                pollTargetCount));

            // v8 post-pass: build class registry, return-to-global tracking,
            // ctor risk grading, asset upload traces, override classification,
            // pad mask / vdispatch counters, SDK-caller depth-1 propagation.
            runV8PostPasses(results, resultsByAddr, fwd, newStubs);

            // v7 Rule 80: runtime corroboration pass. Walks every function,
            // compares static bullseye predictions against merged GS evidence,
            // attaches RUNTIME_CONFIRMED / RUNTIME_DORMANT_GLOBAL /
            // RUNTIME_MENU_ONLY decorations. No-op when no GS dumps loaded.
            if (!gsEvidence.empty()) {
                runtimeCorroborationPass(results);
                println(String.format("  v7 post: RUNTIME_CONFIRMED=%d RUNTIME_DORMANT_GLOBAL=%d RUNTIME_MENU_ONLY=%d TBP_CONFIRMED_FUNCS=%d GS_IRQ_SAFE_STUB=%d",
                    runtimeConfirmedCount, runtimeDormantCount, runtimeMenuOnlyCount,
                    tbpRuntimeConfirmedFuncCount, gsIrqSafeStubCount));
            } else {
                println("  v7 post: GS evidence empty — corroboration skipped.");
            }

            // ===== v9 post-passes =====
            // Rule 128 function pointer tables (must run BEFORE module clusters
            // so any discovered vtables seed the inferredClassName).
            scanFunctionPointerTables(results, resultsByAddr);
            // Rule 129 module clustering on jal edges
            assignModuleIds(results);
            // Rule 130 name-prefix module index
            buildNamePrefixModules(results);
            // Rule 134 tag DC2 call chain participants
            tagDc2CallChains(results);
            println(String.format("  v9 post: GIF_INLINE=%d BITBLTBUF_MACRO=%d CHCR_KICK=%d DMA_SRC_CHAIN=%d MMIO_RECOVERED=%d SYSCALL_TR=%d SYNC_WAIT=%d INF_SPIN=%d INF_FAIL=%d IRX=%d REBOOT=%d RENDER_ENTRY=%d STRUCT_INIT=%d DISPATCH_TGT=%d TABLE_CALL=%d HOST_WAIT=%d DC2_KNOWN=%d DISC_SIDS=%d FPT_TABLES=%d MODULES=%d PREFIXES=%d",
                gifTagInlineBuilderCount, bitbltbufMacroSeqCount, dmaChcrStartKickCount,
                dmaSourceChainBuilderCount, compositeMmioRecoveryCount, syscallTrampolineCount,
                backwardSyncWaitCount, infiniteSpinLoopCount, infiniteFailLoopCount,
                irxLoaderCount, iopRebootHandlerCount, renderFrameEntryCount,
                structInitializerCount, dispatchTableTargetCount, tableDispatchCallCount,
                dc2HostWaitCandidateCount, dc2KnownAddressMatched, discoveredRpcSidCount,
                functionPointerTables.size(), moduleClusters.size(), namePrefixModules.size()));

            writeUnifiedConfig(unifiedToml,configToml,newStubs,newSkips,results,resultsByAddr);
            // v8 Rule 109: diff against prior triage_map.json if present.
            // Renames the old file to triage_map.prev.json before overwriting.
            File priorJson = new File(outputDir, "triage_map.json");
            Map<Long,String> priorCats = null;
            if (priorJson.exists()) {
                try {
                    priorCats = loadPriorTriageMapCats(priorJson);
                    File backup = new File(outputDir, "triage_map.prev.json");
                    if (backup.exists()) backup.delete();
                    priorJson.renameTo(backup);
                    println(String.format("[DIFF] Backed up prior triage_map.json (%d funcs).",
                        priorCats != null ? priorCats.size() : 0));
                } catch (Exception ex) {
                    println("[DIFF] Failed to load prior map: "+ex.getMessage());
                    priorCats = null;
                }
            }
            this.priorTriageMapCats = priorCats;
            writeTriageJson(triageJson,results,elfHash,gpValue,totalFuncs,uncategorized);

            println("\n[SUCCESS] Unified TOML : "+unifiedToml.getAbsolutePath());
            println("[SUCCESS] Triage JSON  : "+triageJson.getAbsolutePath());
            println("[SUCCESS] Text logs    : assembly.txt, decompiled.txt, flowchart.txt");
            println("All 5 files saved to: "+outputDir.getAbsolutePath());

        } finally {
            asmWriter.close();
            decompWriter.close();
            flowWriter.close();
            decomp.dispose();
        }
    }

    // =========================================================
    // v7: GS-DUMP SUMMARY LOADER + RUNTIME CORROBORATION PASS
    // =========================================================
    /**
     * Walk {@code dir}, parse every *.gs.summary.json with the minimal hand-
     * rolled reader, populate {@link #gsEvidence}. No-op if folder empty.
     */
    private void loadGsSummaryFolder(File dir) {
        File[] files = dir.listFiles();
        if (files == null) return;
        // Stable order: sort by name so output is deterministic.
        List<File> jsonFiles = new ArrayList<>();
        for (File f : files) {
            String nm = f.getName().toLowerCase();
            if (f.isFile() && nm.endsWith(".summary.json")) jsonFiles.add(f);
        }
        jsonFiles.sort(Comparator.comparing(File::getName));
        for (File f : jsonFiles) {
            try {
                GsCheckpoint cp = parseGsSummary(f);
                if (cp != null) {
                    gsEvidence.checkpoints.add(cp);
                    println(String.format("[GS-EVIDENCE]   + %s (P3=%d giftags=%d psm_tex0=%s 4HH=%s)",
                        cp.name, cp.path3Count, cp.gifTagCount, cp.psmTex0,
                        cp.psmt4hhUsed));
                }
            } catch (Exception ex) {
                println("[GS-EVIDENCE]   ! failed "+f.getName()+": "+ex.getMessage());
            }
        }
        mergeGsEvidence();
    }

    /**
     * Minimal JSON reader keyed on the fixed schema emitted by
     * gs_dump_to_summary.py. Only fields under {@code summary_for_enricher},
     * {@code gif}, {@code transfers}, and the top-level metadata are extracted.
     * Tolerates whitespace + ordering changes; not a full JSON parser.
     */
    private GsCheckpoint parseGsSummary(File f) throws IOException {
        String s = readFileFully(f);
        GsCheckpoint cp = new GsCheckpoint();
        // Checkpoint name: strip ".gs.summary.json" suffix; if file embeds an
        // ELF-name prefix like "Dark Cloud 2_SCUS-..._20260524..." keep the
        // leading non-date portion.
        String nm = f.getName();
        int dot = nm.toLowerCase().indexOf(".gs.summary.json");
        if (dot > 0) nm = nm.substring(0, dot);
        cp.name = nm;
        cp.sourceFile = f.getAbsolutePath();

        cp.serial         = jsonStringField(s, "serial");
        cp.crc            = jsonStringField(s, "crc");
        cp.stateVersion   = (int) jsonNumberField(s, "state_version", 0);
        cp.stateSizeBytes =      jsonNumberField(s, "state_size_bytes", 0);
        cp.vsyncs         = (int) jsonNumberField(s, "vsyncs", 0);

        // transfers.{PATH1,PATH2,PATH3}.{count,total_bytes}
        cp.path1Count = (int) jsonScopedNumber(s, "PATH1", "count", 0);
        cp.path2Count = (int) jsonScopedNumber(s, "PATH2", "count", 0);
        cp.path3Count = (int) jsonScopedNumber(s, "PATH3", "count", 0);
        cp.path1Bytes =       jsonScopedNumber(s, "PATH1", "total_bytes", 0);
        cp.path2Bytes =       jsonScopedNumber(s, "PATH2", "total_bytes", 0);
        cp.path3Bytes =       jsonScopedNumber(s, "PATH3", "total_bytes", 0);
        cp.path1Active = cp.path1Count > 0;
        cp.path2Active = cp.path2Count > 0;
        cp.path3Active = cp.path3Count > 0;

        cp.gifTagCount    = (int) jsonNumberField(s, "giftag_count", 0);
        cp.malformedTags  = (int) jsonNumberField(s, "malformed_tags", 0);
        cp.packedCount    = (int) jsonScopedNumber(s, "gif_flg_counts", "PACKED", 0);
        cp.reglistCount   = (int) jsonScopedNumber(s, "gif_flg_counts", "REGLIST", 0);
        cp.imageCount     = (int) jsonScopedNumber(s, "gif_flg_counts", "IMAGE", 0);
        cp.image2Count    = (int) jsonScopedNumber(s, "gif_flg_counts", "IMAGE2", 0);
        cp.reglistUsed = cp.reglistCount > 0;
        cp.image2Used  = cp.image2Count  > 0;

        cp.readfifo2Active = jsonNumberField(s, "readfifo2_calls", 0) > 0;

        // summary_for_enricher block
        cp.psmt4hhUsed   = jsonBooleanField(s, "psmt4hh_used", false);
        cp.psmt4hlUsed   = jsonBooleanField(s, "psmt4hl_used", false);
        cp.psmt8hUsed    = jsonBooleanField(s, "psmt8h_used",  false);
        // F32 retro upload-side witnesses (only present in summaries produced by
        // the upgraded gs_dump_to_summary.py; older summaries default false).
        cp.psmt4hhUpload = jsonBooleanField(s, "psmt4hh_upload", false);
        cp.psmt4hlUpload = jsonBooleanField(s, "psmt4hl_upload", false);
        cp.psmt8hUpload  = jsonBooleanField(s, "psmt8h_upload",  false);
        for (long v : jsonIntArrayField(s, "bitbltbuf_dpsms_used"))
            cp.bitbltbufDpsms.add((int) v);
        cp.primGarbage   = jsonBooleanField(s, "prim_garbage_detected", false);

        for (long v : jsonIntArrayField(s, "psm_seen_tex0"))  cp.psmTex0.add((int)v);
        for (long v : jsonIntArrayField(s, "psm_seen_frame")) cp.psmFrame.add((int)v);
        for (long v : jsonIntArrayField(s, "psm_seen_zbuf"))  cp.psmZbuf.add((int)v);
        for (long v : jsonIntArrayField(s, "tex0_tbps_used")) cp.tex0Tbps.add(v);
        for (long v : jsonIntArrayField(s, "vram_upload_tbps")) cp.vramTbps.add(v);
        for (String name : jsonStringArrayField(s, "a_d_regs_written_named"))
            cp.adRegs.add(name);
        for (String hx : jsonStringArrayField(s, "prim_distinct_values")) {
            try { cp.primValues.add(Long.parseLong(hx.replace("0x","").replace("0X",""), 16)); }
            catch (NumberFormatException ignored) {}
        }
        if (cp.adRegs.contains("SIGNAL") || cp.adRegs.contains("FINISH") || cp.adRegs.contains("LABEL"))
            cp.signalFinishLabelSeen = true;

        // priv regs (PMODE/IMR/CSR) — string hex form
        String imrStr   = jsonStringField(s, "IMR");
        String pmodeStr = jsonStringField(s, "PMODE");
        if (imrStr   != null) cp.imr   = parseHexULong(imrStr);
        if (pmodeStr != null) cp.pmode = parseHexULong(pmodeStr);

        // frame_final / zbuf_final / dispfb1/2 sub-objects
        cp.frameFbp   = (int) jsonScopedNumber(s, "frame_final", "fbp", -1);
        cp.frameFbw   = (int) jsonScopedNumber(s, "frame_final", "fbw", -1);
        cp.framePsm   = (int) jsonScopedNumber(s, "frame_final", "psm", -1);
        cp.zbufZbp    = (int) jsonScopedNumber(s, "zbuf_final",  "zbp", -1);
        cp.zbufPsm    = (int) jsonScopedNumber(s, "zbuf_final",  "psm", -1);
        cp.zbufZmsk   = (int) jsonScopedNumber(s, "zbuf_final",  "zmsk", -1);
        cp.dispfb1Fbp = (int) jsonScopedNumber(s, "dispfb1",     "fbp", -1);
        cp.dispfb2Fbp = (int) jsonScopedNumber(s, "dispfb2",     "fbp", -1);
        return cp;
    }

    /** Compute union flags and intersections across {@link #gsEvidence}. */
    private void mergeGsEvidence() {
        GsRuntimeEvidence ev = gsEvidence;
        long imrAnd = ~0L;
        boolean haveImr = false;
        boolean allMasked = true;
        for (GsCheckpoint c : ev.checkpoints) {
            if (c.path1Active) ev.anyPath1 = true;
            if (c.path2Active) ev.anyPath2 = true;
            if (c.path3Active) ev.anyPath3 = true;
            if (c.psmt4hhUsed) ev.anyPsmt4hh = true;
            if (c.psmt4hlUsed) ev.anyPsmt4hl = true;
            if (c.psmt8hUsed)  ev.anyPsmt8h  = true;
            if (c.psmt4hhUpload) ev.anyPsmt4hhUpload = true;
            if (c.psmt4hlUpload) ev.anyPsmt4hlUpload = true;
            if (c.psmt8hUpload)  ev.anyPsmt8hUpload  = true;
            ev.bitbltbufDpsmsUnion.addAll(c.bitbltbufDpsms);
            if (c.primGarbage) ev.anyPrimGarbage = true;
            if (c.readfifo2Active) ev.anyReadfifo2 = true;
            if (c.reglistUsed) ev.anyReglist = true;
            if (c.image2Used)  ev.anyImage2  = true;
            if (c.signalFinishLabelSeen) ev.anySignalFinishLabel = true;
            ev.psmTex0Union.addAll(c.psmTex0);
            ev.psmFrameUnion.addAll(c.psmFrame);
            ev.psmZbufUnion.addAll(c.psmZbuf);
            ev.adRegsUnion.addAll(c.adRegs);
            ev.tex0TbpsUnion.addAll(c.tex0Tbps);
            ev.vramTbpsUnion.addAll(c.vramTbps);
            ev.primUnion.addAll(c.primValues);
            ev.totalPath3Count += c.path3Count;
            ev.totalPath3Bytes += c.path3Bytes;
            for (Integer p : c.psmTex0)
                ev.psmTex0Witnesses.computeIfAbsent(p, k -> new LinkedHashSet<>()).add(c.name);
            if (c.imr >= 0) {
                imrAnd &= c.imr;
                haveImr = true;
                if ((c.imr & 0x7F00L) != 0x7F00L) allMasked = false;
            }
        }
        ev.imrIntersection = haveImr ? imrAnd : -1L;
        ev.imrAllMaskedGsIrqs = haveImr && allMasked;
    }

    /**
     * Rule 80: per-function corroboration. Decoration only — no disposition
     * flip. Predictions checked:
     *  • PSMT4HH_REFERENCE         <-> any checkpoint witness PSMT4HH (44)
     *  • MICROCODE_UPLOADER / VIF_*_BUILDER <-> any path1/path2 witness
     *  • PATH3_INITIATOR / GIF_PATH3_HAZARD <-> any path3 witness +
     *                                          (prim_garbage in any cp for hazard)
     *  • MPEG_DECODER_TRAP / IPU   <-> readfifo2 OR ipuActive
     *  • TEX0_REG_WRITER + tbp constants <-> tex0_tbps_union / vram_tbps_union
     *  • SIGNAL/FINISH/LABEL handler names <-> imrAllMaskedGsIrqs → safe-stub
     * Status precedence:
     *  CONFIRMED > MENU_ONLY > DORMANT > INDETERMINATE
     */
    private void runtimeCorroborationPass(List<FuncResult> results) {
        GsRuntimeEvidence ev = gsEvidence;
        for (FuncResult r : results) {
            FuncTraits t = r.traits;
            if (t == null) continue;

            // Build prediction list + witness map
            if (t.loadsPsm4hhConstant) {
                t.runtimeBullseyePredictions.add("PSMT4HH_REFERENCE");
                // Witnessed if either sampler-side or upload-side observed it.
                t.runtimeWitness.put("PSMT4HH_REFERENCE",
                    ev.anyPsmt4hh || ev.anyPsmt4hhUpload ||
                    ev.anyPsmt4hl || ev.anyPsmt4hlUpload ||
                    ev.anyPsmt8h  || ev.anyPsmt8hUpload);
            }
            if (t.isBitbltbufT4hhUploader) {
                t.runtimeBullseyePredictions.add("BITBLTBUF_T4HH_UPLOADER");
                t.runtimeWitness.put("BITBLTBUF_T4HH_UPLOADER",
                    ev.anyPsmt4hhUpload || ev.anyPsmt4hlUpload || ev.anyPsmt8hUpload);
            }
            if (t.isMicrocodeUploader || t.vifOpcodesBuilt.contains("MPG")) {
                t.runtimeBullseyePredictions.add("MICROCODE_UPLOADER");
                t.runtimeWitness.put("MICROCODE_UPLOADER", ev.anyPath1 || ev.anyPath2);
            }
            if (t.vifOpcodesBuilt.contains("MSCAL") || t.vifOpcodesBuilt.contains("MSCALF")
                || t.vifOpcodesBuilt.contains("MSCNT")) {
                t.runtimeBullseyePredictions.add("VIF_MSCAL");
                t.runtimeWitness.put("VIF_MSCAL", ev.anyPath1);
            }
            if (t.path3Initiator || t.path3KickViaDmaApi || t.touchesGifP3Reg) {
                t.runtimeBullseyePredictions.add("PATH3_KICK");
                t.runtimeWitness.put("PATH3_KICK", ev.anyPath3);
            }
            if (t.touchesGifCtrl) {
                t.runtimeBullseyePredictions.add("GIF_PATH3_HAZARD");
                t.runtimeWitness.put("GIF_PATH3_HAZARD", ev.anyPath3 && ev.anyPrimGarbage);
            }
            if (t.callsMpegFamily || t.writesIpuCmd || t.accessesIpuMmio) {
                t.runtimeBullseyePredictions.add("MPEG_DECODER_TRAP");
                t.runtimeWitness.put("MPEG_DECODER_TRAP", ev.anyReadfifo2);
            }
            if (t.writesTex0Reg) {
                t.runtimeBullseyePredictions.add("TEX0_REG_WRITER");
                // TEX0 writers are confirmed if game uploaded *any* tex data —
                // every PATH3-active capture qualifies.
                t.runtimeWitness.put("TEX0_REG_WRITER", ev.anyPath3);
            }
            if (t.writesRgbaqReg) {
                t.runtimeBullseyePredictions.add("RGBAQ_WRITER");
                t.runtimeWitness.put("RGBAQ_WRITER", ev.adRegsUnion.contains("RGBAQ"));
            }
            if (t.writesZbufReg) {
                t.runtimeBullseyePredictions.add("ZBUF_REG_WRITER");
                t.runtimeWitness.put("ZBUF_REG_WRITER", ev.adRegsUnion.contains("ZBUF_1")
                    || ev.adRegsUnion.contains("ZBUF_2"));
            }
            if (t.writesDispfbReg || t.writesDispfbViaSdk) {
                t.runtimeBullseyePredictions.add("DISPFB_WRITER");
                // Every checkpoint where PMODE/DISPFB sampled differs = witness.
                boolean dispfbWitness = false;
                for (GsCheckpoint c : ev.checkpoints) {
                    if (c.dispfb1Fbp != null && c.dispfb1Fbp >= 0) { dispfbWitness = true; break; }
                }
                t.runtimeWitness.put("DISPFB_WRITER", dispfbWitness);
            }

            // Rule 78: TBP constant matches against runtime upload heatmap.
            for (Long c : t.tbpConstantsLoaded) {
                if (ev.vramTbpsUnion.contains(c) || ev.tex0TbpsUnion.contains(c))
                    t.tbpRuntimeConfirmed.add(c);
            }
            if (!t.tbpRuntimeConfirmed.isEmpty()) {
                tbpRuntimeConfirmedFuncCount++;
                if (!r.tags.contains("VRAM_TBP_OVERLAY")) r.tags.add("VRAM_TBP_OVERLAY");
            }

            // A+D register intersection (informational)
            for (String s : t.gsRegHits) if (ev.adRegsUnion.contains(s)) t.runtimeAdRegMatch.add(s);

            // Rule 79: GS IRQ handler safe-stub candidate.
            if (t.isGsIrqHandlerName && ev.imrAllMaskedGsIrqs) {
                t.gsIrqSafeStubCandidate = true;
                if (!r.tags.contains("GS_IRQ_SAFE_STUB")) {
                    r.tags.add("GS_IRQ_SAFE_STUB");
                    gsIrqSafeStubCount++;
                }
            }

            // Status calculation
            boolean anyConfirmed = false, anyDormant = false;
            for (Boolean w : t.runtimeWitness.values()) {
                if (Boolean.TRUE.equals(w)) anyConfirmed = true; else anyDormant = true;
            }
            // RUNTIME_MENU_ONLY: PSMT4HH predicted AND only UI/menu checkpoints
            // witnessed it (no 3D-scene checkpoint witness).
            // v7.1 refinement: F32 showed BITBLTBUF.dpsm=0x2C uploads are NOT
            // menu-only — they also occur during 3D scene loads. Same for any
            // function close to the render roots (drawing_chain_depth <= 3) or
            // explicitly tagged BITBLTBUF_T4HH_UPLOADER. Skipping the MENU_ONLY
            // tag in those cases prevents deprioritizing F32-critical uploaders.
            if (t.runtimeBullseyePredictions.contains("PSMT4HH_REFERENCE") && ev.anyPsmt4hh) {
                Set<String> witnesses = ev.psmTex0Witnesses.getOrDefault(PSM_PSMT4HH,
                                                              Collections.<String>emptySet());
                boolean menuOnly = !witnesses.isEmpty();
                for (String wname : witnesses) {
                    if (!isMenuCheckpointName(wname)) { menuOnly = false; break; }
                }
                boolean exempt = t.isBitbltbufT4hhUploader ||
                                 (t.drawingChainDepth >= 0 && t.drawingChainDepth <= 3);
                if (menuOnly && !exempt) {
                    t.runtimeMenuOnly = true;
                    if (!r.tags.contains("RUNTIME_MENU_ONLY")) {
                        r.tags.add("RUNTIME_MENU_ONLY");
                        runtimeMenuOnlyCount++;
                    }
                }
            }
            if (anyConfirmed) {
                t.runtimeConfirmed = true;
                t.runtimeStatus = t.runtimeMenuOnly ? "CONFIRMED_MENU_ONLY" : "CONFIRMED";
                if (!r.tags.contains("RUNTIME_CONFIRMED")) {
                    r.tags.add("RUNTIME_CONFIRMED");
                    runtimeConfirmedCount++;
                }
            } else if (anyDormant) {
                t.runtimeDormantGlobal = true;
                t.runtimeStatus = "DORMANT";
                if (!r.tags.contains("RUNTIME_DORMANT_GLOBAL")) {
                    r.tags.add("RUNTIME_DORMANT_GLOBAL");
                    runtimeDormantCount++;
                }
            }
        }
    }

    private static boolean isMenuCheckpointName(String nm) {
        String low = nm.toLowerCase();
        for (String frag : MENU_CHECKPOINT_FRAGMENTS) if (low.contains(frag)) return true;
        return false;
    }

    // ---------- minimal JSON readers ----------

    private static String readFileFully(File f) throws IOException {
        StringBuilder sb = new StringBuilder((int)Math.min(f.length()+16, 1<<20));
        BufferedReader br = new BufferedReader(new InputStreamReader(
            new FileInputStream(f), "UTF-8"));
        try {
            char[] buf = new char[8192];
            int n;
            while ((n = br.read(buf)) > 0) sb.append(buf, 0, n);
        } finally { br.close(); }
        return sb.toString();
    }

    /** Find {@code "key": <value>} after position {@code from} in {@code s}. Returns -1 if absent. */
    private static int findKey(String s, String key, int from) {
        String needle = "\"" + key + "\"";
        int i = s.indexOf(needle, from);
        if (i < 0) return -1;
        // Skip optional whitespace and colon
        int j = i + needle.length();
        while (j < s.length() && Character.isWhitespace(s.charAt(j))) j++;
        if (j >= s.length() || s.charAt(j) != ':') return -1;
        j++;
        while (j < s.length() && Character.isWhitespace(s.charAt(j))) j++;
        return j;
    }

    private static String jsonStringField(String s, String key) {
        int v = findKey(s, key, 0);
        if (v < 0 || s.charAt(v) != '"') return null;
        int end = v + 1;
        StringBuilder out = new StringBuilder();
        while (end < s.length()) {
            char c = s.charAt(end);
            if (c == '\\' && end+1 < s.length()) { out.append(s.charAt(end+1)); end += 2; continue; }
            if (c == '"') break;
            out.append(c); end++;
        }
        return out.toString();
    }

    private static long jsonNumberField(String s, String key, long deflt) {
        int v = findKey(s, key, 0);
        if (v < 0) return deflt;
        return parseScalarAt(s, v, deflt);
    }

    private static boolean jsonBooleanField(String s, String key, boolean deflt) {
        int v = findKey(s, key, 0);
        if (v < 0) return deflt;
        if (s.startsWith("true",  v)) return true;
        if (s.startsWith("false", v)) return false;
        return deflt;
    }

    private static long parseScalarAt(String s, int v, long deflt) {
        int end = v;
        // hex like "0x..." inside quotes? Strip quotes first.
        boolean quoted = (v < s.length() && s.charAt(v) == '"');
        if (quoted) {
            int e = s.indexOf('"', v+1);
            if (e < 0) return deflt;
            return parseHexULong(s.substring(v+1, e));
        }
        while (end < s.length()) {
            char c = s.charAt(end);
            if ((c>='0'&&c<='9') || c=='-' || c=='+' || c=='.' ||
                c=='x' || c=='X' || (c>='a'&&c<='f') || (c>='A'&&c<='F')) end++;
            else break;
        }
        if (end == v) return deflt;
        String tok = s.substring(v, end);
        try {
            if (tok.startsWith("0x") || tok.startsWith("0X"))
                return Long.parseLong(tok.substring(2), 16);
            return Long.parseLong(tok);
        } catch (NumberFormatException ex) { return deflt; }
    }

    private static long parseHexULong(String tok) {
        try {
            String t = tok.trim();
            if (t.startsWith("0x") || t.startsWith("0X")) t = t.substring(2);
            // 64-bit unsigned: use BigInteger to dodge sign issues
            return new java.math.BigInteger(t, 16).longValue();
        } catch (Exception ex) { return -1L; }
    }

    /**
     * Find {@code "scope": { ... "key": <v> ... }}. The scope opens at the
     * nearest '{' after the colon; we read up to the matching '}'.
     */
    private static long jsonScopedNumber(String s, String scope, String key, long deflt) {
        int o = findKey(s, scope, 0);
        if (o < 0 || s.charAt(o) != '{') return deflt;
        int end = matchBrace(s, o);
        if (end < 0) return deflt;
        int v = findKey(s.substring(o, end), key, 0);
        if (v < 0) return deflt;
        return parseScalarAt(s.substring(o, end), v, deflt);
    }

    private static int matchBrace(String s, int openIdx) {
        int depth = 0;
        boolean inStr = false; boolean esc = false;
        for (int i = openIdx; i < s.length(); i++) {
            char c = s.charAt(i);
            if (inStr) {
                if (esc) esc = false;
                else if (c == '\\') esc = true;
                else if (c == '"') inStr = false;
            } else {
                if (c == '"') inStr = true;
                else if (c == '{') depth++;
                else if (c == '}') { depth--; if (depth == 0) return i+1; }
            }
        }
        return -1;
    }

    private static long[] jsonIntArrayField(String s, String key) {
        int v = findKey(s, key, 0);
        if (v < 0 || s.charAt(v) != '[') return new long[0];
        int end = v;
        // Walk to matching ']'
        int depth = 0; boolean inStr = false; boolean esc = false;
        for (int i = v; i < s.length(); i++) {
            char c = s.charAt(i);
            if (inStr) { if (esc) esc=false; else if (c=='\\') esc=true; else if (c=='"') inStr=false; }
            else if (c == '"') inStr = true;
            else if (c == '[') depth++;
            else if (c == ']') { depth--; if (depth == 0) { end = i+1; break; } }
        }
        String body = s.substring(v+1, Math.max(v+1, end-1));
        List<Long> out = new ArrayList<>();
        for (String tok : body.split(",")) {
            String t = tok.trim();
            if (t.isEmpty()) continue;
            try { out.add(Long.parseLong(t)); }
            catch (NumberFormatException ex) {
                if (t.startsWith("0x") || t.startsWith("0X"))
                    try { out.add(Long.parseLong(t.substring(2), 16)); }
                    catch (NumberFormatException ignored) {}
            }
        }
        long[] arr = new long[out.size()];
        for (int i = 0; i < out.size(); i++) arr[i] = out.get(i);
        return arr;
    }

    private static List<String> jsonStringArrayField(String s, String key) {
        List<String> out = new ArrayList<>();
        int v = findKey(s, key, 0);
        if (v < 0 || s.charAt(v) != '[') return out;
        int depth = 0; int end = v;
        for (int i = v; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '[') depth++;
            else if (c == ']') { depth--; if (depth == 0) { end = i+1; break; } }
        }
        String body = s.substring(v+1, Math.max(v+1, end-1));
        int i = 0;
        while (i < body.length()) {
            while (i < body.length() && body.charAt(i) != '"') i++;
            if (i >= body.length()) break;
            int j = i+1;
            StringBuilder sb = new StringBuilder();
            while (j < body.length()) {
                char c = body.charAt(j);
                if (c == '\\' && j+1 < body.length()) { sb.append(body.charAt(j+1)); j += 2; continue; }
                if (c == '"') break;
                sb.append(c); j++;
            }
            out.add(sb.toString());
            i = j+1;
        }
        return out;
    }

    // =========================================================
    // RULE 18 (v3 NEW): GAME OVERRIDE FILE PARSER
    // Reads dc2_game_override.cpp and extracts every address that
    // has already been manually bound. These are skipped entirely
    // so the triage report doesn't re-classify them as candidates.
    //
    // Handles both patterns:
    //   bindAddressHandler(runtime, 0x00104288u, "memclr");
    //   runtime.registerFunction(0x0015C160u, nop_stub);
    // =========================================================
    // Override binding -> classification (v8 Rule 98). Set when handler-name
    // matches certain patterns OR when the helper body (best-effort) looks
    // like a probe / nop / state machine / constant return.
    private Map<Long, String> overrideKindByAddr = new HashMap<>();
    // Override binding -> handler function name (3rd arg of bindAddressHandler).
    private Map<Long, String> overrideHandlerNames = new HashMap<>();

    private void parseGameOverrideFile(File f) throws IOException {
        BufferedReader reader = new BufferedReader(new FileReader(f));
        // First pass: scan all lines into a list so we can inspect helper bodies.
        List<String> allLines = new ArrayList<>();
        String line;
        while((line = reader.readLine()) != null) allLines.add(line);
        reader.close();

        // Pass 1: collect bindings.
        for(int i = 0; i < allLines.size(); i++) {
            String t = allLines.get(i).trim();
            if(!t.contains("bindAddressHandler") && !t.contains("registerFunction")) continue;
            long addr = extractFirstHexLiteral(t);
            if(addr <= 0) continue;
            String name = extractQuotedString(t);
            gameOverrideAddresses.add(addr);
            if(name != null && !name.isEmpty()) gameOverrideNames.put(addr, name);
            gameOverrideImportedCount++;
            // Extract handler symbol (the C++ identifier after the last comma).
            String handler = extractHandlerSymbol(t);
            if(handler != null) overrideHandlerNames.put(addr, handler);
        }

        // Pass 2: best-effort classification of helper bodies.
        // For each unique handler name, find its function body and inspect.
        for(Map.Entry<Long,String> e : overrideHandlerNames.entrySet()) {
            String hn = e.getValue();
            String kind = classifyHandlerBody(hn, allLines);
            overrideKindByAddr.put(e.getKey(), kind);
            overrideClassifiedCount++;
            if("nop_stub".equals(kind) || "probe".equals(kind))
                overrideRetireCount++;
        }
    }

    private String extractHandlerSymbol(String line) {
        // bindAddressHandler(0xADDR, "name", &handler) — return identifier after &.
        int amp = line.indexOf('&');
        if(amp < 0) return null;
        int end = amp + 1;
        while(end < line.length()) {
            char c = line.charAt(end);
            if(Character.isLetterOrDigit(c) || c == '_' || c == ':' || c == '<' || c == '>') end++;
            else break;
        }
        if(end <= amp + 1) return null;
        return line.substring(amp + 1, end);
    }

    private String classifyHandlerBody(String handlerName, List<String> lines) {
        if(handlerName == null) return "real_shim";
        // Heuristic name-based hints first.
        String lower = handlerName.toLowerCase();
        if(lower.contains("nop_stub") || lower.endsWith("_nop")) return "nop_stub";
        if(lower.contains("probe")) return "probe";
        if(lower.contains("state_machine") || lower.contains("state_step")) return "state_machine";
        if(lower.contains("const_return") || lower.endsWith("_zero")) return "constant_return";
        // Body-scan: find a line `<retT> <handlerName>(...)` and look at next ~30 lines.
        int start = -1;
        for(int i = 0; i < lines.size(); i++) {
            String t = lines.get(i);
            int hnIdx = t.indexOf(handlerName);
            if(hnIdx < 0) continue;
            int parenIdx = t.indexOf('(', hnIdx);
            if(parenIdx < 0 || parenIdx == hnIdx + handlerName.length()) {
                if(t.contains("{") || (i + 1 < lines.size() && lines.get(i+1).contains("{"))) {
                    start = i; break;
                }
            }
        }
        if(start < 0) return "real_shim";
        int bodyLines = 0, returnsConst = 0, callOps = 0, traceLogs = 0, conditionals = 0;
        for(int i = start; i < Math.min(start + 60, lines.size()); i++) {
            String t = lines.get(i);
            if(t.contains("}") && bodyLines > 4) break;
            bodyLines++;
            if(t.matches(".*return\\s+\\d+.*")) returnsConst++;
            if(t.contains("(*ctx") || t.contains("ctx->")) callOps++;
            if(t.contains("[F4") || t.contains("[F49") || t.contains("LOG") || t.contains("trace") ||
               t.contains("println") || t.contains("getenv("))
                traceLogs++;
            if(t.contains("if(") || t.contains("if (") || t.contains("switch(") || t.contains("switch ("))
                conditionals++;
        }
        if(traceLogs > 0 && callOps == 0) return "probe";
        if(bodyLines <= 5 && returnsConst > 0 && callOps == 0) return "constant_return";
        if(bodyLines <= 5 && callOps == 0 && returnsConst == 0) return "nop_stub";
        if(conditionals > 1 && callOps == 0) return "state_machine";
        return "real_shim";
    }

    private long extractFirstHexLiteral(String line) {
        int idx = line.indexOf("0x");
        if (idx<0) idx = line.indexOf("0X");
        if (idx<0) return -1L;
        StringBuilder sb = new StringBuilder();
        int i = idx+2;
        while (i<line.length()) {
            char c = line.charAt(i);
            if ((c>='0'&&c<='9')||(c>='a'&&c<='f')||(c>='A'&&c<='F')) {
                sb.append(c); i++;
            } else break;
        }
        if (sb.length()==0) return -1L;
        try { return Long.parseLong(sb.toString(),16)&0xFFFFFFFFL; }
        catch (NumberFormatException ignored) { return -1L; }
    }

    private String extractQuotedString(String line) {
        int q1 = line.indexOf('"');
        if (q1<0) return null;
        int q2 = line.indexOf('"',q1+1);
        if (q2<=q1) return null;
        // If there's a second quoted string (the name in bindAddressHandler), return it
        int q3 = line.indexOf('"',q2+1);
        if (q3>=0) {
            int q4 = line.indexOf('"',q3+1);
            if (q4>q3) return line.substring(q3+1,q4);
        }
        return line.substring(q1+1,q2);
    }

    // =========================================================
    // RULE 9: PARSE STEP 1 CONFIG
    // =========================================================
    private void parseStep1Config(File configFile) throws IOException {
        BufferedReader reader = new BufferedReader(new FileReader(configFile));
        String line; boolean inStubs=false,inSkip=false;
        while ((line=reader.readLine())!=null) {
            String t=line.trim();
            if (t.startsWith("stubs")){inStubs=true;inSkip=false;continue;}
            if (t.startsWith("skip")&&!t.startsWith("skip_count")){inSkip=true;inStubs=false;continue;}
            if (t.equals("]")){inStubs=false;inSkip=false;continue;}
            if (!inStubs&&!inSkip) continue;
            int q1=t.indexOf('"'),q2=t.lastIndexOf('"');
            if (q1<0||q2<=q1) continue;
            String entry=t.substring(q1+1,q2);
            String name; long addr=-1;
            int atIdx=entry.lastIndexOf("@0x");
            if (atIdx<0) atIdx=entry.lastIndexOf("@0X");
            if (atIdx>=0) {
                name=entry.substring(0,atIdx);
                String hexStr=entry.substring(atIdx+3).replaceAll("[^0-9a-fA-F]","");
                if(!hexStr.isEmpty()) try{addr=Long.parseLong(hexStr,16);}catch(NumberFormatException ignored){}
            } else {name=entry;}
            if (inStubs){if(!name.isEmpty())step1StubNames.add(name);if(addr>=0)step1StubAddresses.add(addr);}
            else if (inSkip){if(!name.isEmpty())step1SkipNames.add(name);if(addr>=0)step1SkipAddresses.add(addr);}
        }
        reader.close();
    }

    // =========================================================
    // RULE 11: MAINLOOP SHIELD
    // =========================================================
    private void buildMainLoopShield(Address mlAddr) {
        mainLoopShield.add(mlAddr.getOffset());
        Function mlFunc = funcManager.getFunctionAt(mlAddr);
        if (mlFunc==null) return;
        for (Function callee : mlFunc.getCalledFunctions(monitor))
            mainLoopShield.add(callee.getEntryPoint().getOffset());
    }

    // =========================================================
    // v4 Rule 39/40: BFS depth from a root, writing into traits.mainLoopDepth
    // (mainloop=true) or traits.initChainDepth (mainloop=false). Unreached
    // functions stay at -1.
    // =========================================================
    private void bfsAssignDepth(Map<Long,List<Long>> fwd, Map<Long,FuncResult> byAddr,
                                long root, boolean isMainLoop) {
        Map<Long,Integer> depth = new HashMap<>();
        depth.put(root, 0);
        Deque<Long> q = new ArrayDeque<>();
        q.add(root);
        while(!q.isEmpty()) {
            long cur = q.poll();
            int dc = depth.get(cur);
            List<Long> outs = fwd.get(cur);
            if(outs==null) continue;
            for(long n : outs) {
                if(depth.containsKey(n)) continue;
                depth.put(n, dc+1);
                q.add(n);
            }
        }
        for(Map.Entry<Long,Integer> e : depth.entrySet()) {
            FuncResult r = byAddr.get(e.getKey());
            if(r==null || r.traits==null) continue;
            if(isMainLoop) r.traits.mainLoopDepth = e.getValue();
            else           r.traits.initChainDepth = e.getValue();
        }
    }

    // v7.1 Rule 83: multi-root BFS for drawing_chain_depth. Roots = all
    // FuncResults whose traits flag them as a GS-bullseye render entrypoint:
    //  - isSceGifPkRefLoadImage / isSceGifPkFamily / path3Initiator /
    //    path3KickViaDmaApi / writesDispfbViaSdk / writesGsPrimReg
    //  - name starts with mgEndFrame / Begin__11mgCDrawPrim
    // Records min depth across all roots into traits.drawingChainDepth.
    private void bfsAssignDrawingChainDepth(Map<Long,List<Long>> fwd,
                                            Map<Long,FuncResult> byAddr,
                                            List<FuncResult> results) {
        Set<Long> roots = new HashSet<>();
        for(FuncResult r : results) {
            if(r.traits == null) continue;
            FuncTraits t = r.traits;
            boolean isRoot = t.isSceGifPkRefLoadImage || t.isSceGifPkFamily ||
                             t.path3Initiator || t.path3KickViaDmaApi ||
                             t.writesDispfbViaSdk || t.writesGsPrimReg ||
                             t.isBitbltbufT4hhUploader;
            if(!isRoot && r.name != null) {
                String n = r.name;
                if(n.startsWith("mgEndFrame") || n.startsWith("Begin__11mgCDrawPrim") ||
                   n.startsWith("Begin__11mgCDrawEnv") || n.startsWith("mgFlipDrawEnv"))
                    isRoot = true;
            }
            if(isRoot) roots.add(r.address & 0xFFFFFFFFL);
        }
        if(roots.isEmpty()) return;
        Map<Long,Integer> depth = new HashMap<>();
        Deque<Long> q = new ArrayDeque<>();
        for(Long r : roots) { depth.put(r, 0); q.add(r); }
        while(!q.isEmpty()) {
            long cur = q.poll();
            int dc = depth.get(cur);
            List<Long> outs = fwd.get(cur);
            if(outs == null) continue;
            for(long n : outs) {
                if(depth.containsKey(n)) continue;
                depth.put(n, dc + 1);
                q.add(n);
            }
        }
        for(Map.Entry<Long,Integer> e : depth.entrySet()) {
            FuncResult r = byAddr.get(e.getKey());
            if(r == null || r.traits == null) continue;
            r.traits.drawingChainDepth = e.getValue();
            drawingChainCount++;
        }
    }

    // =========================================================
    // v8 POST-PASSES: ctor risk, class registry, return-to-global,
    //                 asset upload traces, override classification,
    //                 SDK-caller depth-1 propagation, frame clock drivers.
    // =========================================================
    private void runV8PostPasses(List<FuncResult> results,
                                  Map<Long,FuncResult> byAddr,
                                  Map<Long,List<Long>> fwd,
                                  List<String> newStubs) {
        // -------- Pass A: ctor call mode + return-to-global --------
        // For every direct jal site, look at the caller's instructions just
        // after the jal for `sw $v0, +imm($gp)`. If found, record on callee.
        for(FuncResult caller : results) {
            if(caller.traits == null) continue;
            Function cf = funcManager.getFunctionAt(
                currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(caller.address & 0xFFFFFFFFL));
            if(cf == null) continue;
            for(long[] site : caller.traits.jalSites) {
                long callPc = site[0];
                long target = site[1] & 0xFFFFFFFFL;
                if(target == 0xFFFFFFFFL) continue;
                FuncResult callee = byAddr.get(target);
                if(callee == null || callee.traits == null) continue;
                // Mark direct-jal observation on callee.
                callee.traits.calledViaDirectJal = true;
                // Examine 1-4 instructions immediately after the jal for sw $v0, +imm($gp).
                try {
                    Instruction jalInst = currentProgram.getListing().getInstructionAt(
                        currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(callPc));
                    if(jalInst == null) continue;
                    Instruction probe = jalInst.getNext();
                    int look = 0;
                    while(probe != null && look < 4) {
                        String mn = probe.getMnemonicString();
                        if(mn != null) {
                            String ml = mn.toLowerCase();
                            if(ml.equals("sw") || ml.equals("sd")) {
                                Object[] dop = probe.getOpObjects(0);
                                Object[] aop = probe.getOpObjects(1);
                                String src = (dop!=null && dop.length>0 && dop[0] instanceof ghidra.program.model.lang.Register)
                                    ? ((ghidra.program.model.lang.Register)dop[0]).getName() : null;
                                boolean baseIsGp = false;
                                long off = -1;
                                if(aop != null) {
                                    for(Object o : aop) {
                                        if(o instanceof ghidra.program.model.lang.Register &&
                                           ((ghidra.program.model.lang.Register)o).getName().equalsIgnoreCase("gp"))
                                            baseIsGp = true;
                                        else if(o instanceof ghidra.program.model.scalar.Scalar)
                                            off = ((ghidra.program.model.scalar.Scalar)o).getSignedValue();
                                    }
                                }
                                if(src != null && src.equalsIgnoreCase("v0") && baseIsGp && off != -1) {
                                    long norm = off & 0xFFFFFFFFL;
                                    callee.traits.returnWrittenToGlobals.add(norm);
                                    callee.traits.ctorAssignedToGlobal = true;
                                    // Auto-extend known_dc2_globals if unknown.
                                    if(!KNOWN_DC2_GP_OFFSETS.containsKey(norm) &&
                                       !autoExtendedDc2Globals.containsKey(norm)) {
                                        String guess = callee.traits.ctorClassName != null
                                            ? callee.traits.ctorClassName + "_global"
                                            : "g_unk_" + String.format("%08X", norm);
                                        autoExtendedDc2Globals.put(norm, guess);
                                        autoExtendedDc2GlobalsCount++;
                                    }
                                    break;
                                }
                            }
                        }
                        probe = probe.getNext();
                        look++;
                    }
                } catch(Exception ignore) {}
            }
        }
        // -------- Pass B: ctor risk grading --------
        // Caller mode classification — was a ctor reached only via direct jal,
        // only via jalr $t9, or both?
        for(FuncResult r : results) {
            if(r.traits == null || !r.traits.isCtor) continue;
            FuncTraits t = r.traits;
            // Determine if any caller calls via jalr $t9 (indirect).
            for(long[] c : t.callers) {
                FuncResult caller = byAddr.get(c[0] & 0xFFFFFFFFL);
                if(caller == null || caller.traits == null) continue;
                // If caller has indirectCallT9Count>0 we *may* dispatch this
                // ctor via $t9; not a strict proof but a useful proxy.
                if(caller.traits.indirectCallT9Count > 0) t.calledViaJrT9 = true;
            }
            // Mode
            if(t.calledViaDirectJal && t.calledViaJrT9) t.ctorCallMode = "dual";
            else if(t.calledViaDirectJal)               t.ctorCallMode = "direct_only";
            else if(t.calledViaJrT9)                    t.ctorCallMode = "indirect_only";
            else                                        t.ctorCallMode = "unobserved";
            // Risk tier
            boolean autoStubLikely = !t.ctorInstallsVtable && !t.isCtorMultiFieldInit
                                  && !t.ctorWritesA0Slot && t.byteSize < 60;
            if(t.ctorAssignedToGlobal && ("dual".equals(t.ctorCallMode) || "direct_only".equals(t.ctorCallMode))
                                       && autoStubLikely) {
                t.ctorRiskTier = "CRITICAL"; ctorCriticalCount++;
            } else if(t.ctorInstallsVtable && "dual".equals(t.ctorCallMode)) {
                t.ctorRiskTier = "HIGH"; ctorHighCount++;
            } else if(t.isCtorMultiFieldInit || t.ctorInstallsVtable || t.ctorAssignedToGlobal) {
                t.ctorRiskTier = "MEDIUM"; ctorMediumCount++;
            } else {
                t.ctorRiskTier = "LOW";
            }
            if(t.ctorAssignedToGlobal) ctorAssignedGlobalCount++;
            if(t.ctorInstallsVtable)   ctorInstallsVtableCount++;
            if("dual".equals(t.ctorCallMode)) ctorDualCallModeCount++;
            // Promote CRITICAL/HIGH ctors out of STUB.
            if(("CRITICAL".equals(t.ctorRiskTier) || "HIGH".equals(t.ctorRiskTier)) &&
               "STUB".equals(r.disposition)) {
                r.disposition = "RECOMPILE";
                newStubs.remove(r.name + "@" + hex(r.address));
            }
            if(!r.tags.contains("CTOR_RISK_" + t.ctorRiskTier))
                r.tags.add("CTOR_RISK_" + t.ctorRiskTier);
        }
        // -------- Pass C: class registry build --------
        for(FuncResult r : results) {
            if(r.traits == null) continue;
            FuncTraits t = r.traits;
            String cls = null;
            if(t.isCtor) cls = t.ctorClassName;
            else if(t.isDtor) cls = t.methodClassName;
            else if(t.methodClassName != null) cls = t.methodClassName;
            if(cls == null) continue;
            ClassEntry ce = classRegistry.computeIfAbsent(cls, k -> { ClassEntry x = new ClassEntry(); x.className = k; return x; });
            if(t.isCtor) {
                ce.ctorAddresses.add(r.address & 0xFFFFFFFFL);
                if(t.ctorInstallsVtable && t.ctorVtableAddr != 0)
                    ce.vtableAddr = t.ctorVtableAddr;
                for(Long g : t.returnWrittenToGlobals) {
                    String label = KNOWN_DC2_GP_OFFSETS.get(g);
                    if(label == null) label = autoExtendedDc2Globals.get(g);
                    if(label == null) label = String.format("0x%08X", g);
                    ce.globalHolders.add(label);
                }
                // Track instantiation sites (caller PCs).
                for(long[] c : t.callers) ce.instantiationSites.add(c[1] & 0xFFFFFFFFL);
                // Class risk = highest ctor risk
                if(rankRisk(t.ctorRiskTier) > rankRisk(ce.riskTier))
                    ce.riskTier = t.ctorRiskTier;
            } else if(t.isDtor) {
                ce.dtorAddress = r.address & 0xFFFFFFFFL;
            } else if(t.methodName != null) {
                ce.methodNames.add(t.methodName);
                ce.methodAddrs.put(t.methodName, r.address & 0xFFFFFFFFL);
                if(t.isVirtualDrawMethod) ce.hasVirtualDraw = true;
            }
        }
        // Bump ctor risk to CRITICAL when class has virtual draw method.
        for(FuncResult r : results) {
            if(r.traits == null || !r.traits.isCtor) continue;
            String cls = r.traits.ctorClassName;
            if(cls == null) continue;
            ClassEntry ce = classRegistry.get(cls);
            if(ce != null && ce.hasVirtualDraw &&
               (rankRisk(r.traits.ctorRiskTier) < rankRisk("HIGH"))) {
                r.traits.ctorRiskTier = "HIGH";
                if(!r.tags.contains("CTOR_RISK_HIGH")) r.tags.add("CTOR_RISK_HIGH");
            }
        }
        // -------- Pass D: virtual dispatch site counters + tags --------
        for(FuncResult r : results) {
            if(r.traits == null) continue;
            if(!r.traits.virtualDispatchSites.isEmpty()) {
                virtualDispatchSiteCount += r.traits.virtualDispatchSites.size();
                virtualDispatchFuncCount++;
                if(!r.tags.contains("VIRTUAL_DISPATCH_SITE"))
                    r.tags.add("VIRTUAL_DISPATCH_SITE");
            }
            if(r.traits.isPadButtonMaskConsumer) {
                padButtonMaskConsumerCount++;
                if(!r.tags.contains("PAD_BUTTON_MASK_CONSUMER"))
                    r.tags.add("PAD_BUTTON_MASK_CONSUMER");
            }
            if(r.traits.gifNloopDoubleCountRisk) {
                gifNloopDoubleCountRiskCount++;
                if(!r.tags.contains("GIF_NLOOP_DOUBLE_COUNT_RISK"))
                    r.tags.add("GIF_NLOOP_DOUBLE_COUNT_RISK");
            }
            if(!r.traits.filePathSprintfFormats.isEmpty()) {
                filePathSprintfCount++;
                if(!r.tags.contains("FILE_PATH_SPRINTF_SOURCE"))
                    r.tags.add("FILE_PATH_SPRINTF_SOURCE");
            }
            if(r.traits.isFrameClockDriver) {
                frameClockDriverCount++;
                if(!r.tags.contains("FRAME_CLOCK_DRIVER"))
                    r.tags.add("FRAME_CLOCK_DRIVER");
            }
            if(r.traits.isSceVu0Helper) {
                sceVu0HelperCount++;
                if(!r.tags.contains("SCEVU0_HELPER_MUSTIMPL"))
                    r.tags.add("SCEVU0_HELPER_MUSTIMPL");
                // Promote out of STUB
                if("STUB".equals(r.disposition)) {
                    r.disposition = "RECOMPILE";
                    newStubs.remove(r.name + "@" + hex(r.address));
                }
            }
            if(!r.traits.returnWrittenToGlobals.isEmpty()) returnWrittenToGlobalCount++;
        }
        // -------- Pass E: asset upload traces (Rule 103) --------
        for(FuncResult r : results) {
            if(r.traits == null) continue;
            if(!r.traits.writesBitbltbufReg && r.traits.assetUploadTagsHit.isEmpty()) continue;
            for(String tag : r.traits.assetUploadTagsHit) {
                List<long[]> bucket = assetUploadTraces.computeIfAbsent(tag, k -> new ArrayList<>());
                bucket.add(new long[]{ r.address & 0xFFFFFFFFL, 0L });
            }
            if(!r.traits.assetUploadTagsHit.isEmpty()) {
                assetUploadTraceFuncCount++;
                if(!r.tags.contains("ASSET_UPLOAD_BULLSEYE"))
                    r.tags.add("ASSET_UPLOAD_BULLSEYE");
            }
        }
        // Uploader caller depth-1 / depth-2 markers.
        Set<Long> uploaderSet = new HashSet<>();
        for(FuncResult r : results)
            if(r.traits != null && r.traits.isBitbltbufT4hhUploader)
                uploaderSet.add(r.address & 0xFFFFFFFFL);
        for(FuncResult r : results) {
            if(r.traits == null) continue;
            for(long[] site : r.traits.jalSites) {
                long tgt = site[1] & 0xFFFFFFFFL;
                if(uploaderSet.contains(tgt)) {
                    r.traits.uploaderCallerDepth1 = true;
                    if(!r.tags.contains("UPLOADER_CALLER_D1"))
                        r.tags.add("UPLOADER_CALLER_D1");
                    break;
                }
            }
        }
        // -------- Pass F0: stamp override classification on per-func traits --------
        for(FuncResult r : results) {
            if(r.traits == null) continue;
            long addr = r.address & 0xFFFFFFFFL;
            if(overrideKindByAddr.containsKey(addr)) {
                r.traits.overrideKind = overrideKindByAddr.get(addr);
                String k = r.traits.overrideKind;
                r.traits.overrideRetireCandidate = "nop_stub".equals(k) || "probe".equals(k);
                if(!r.tags.contains("OVERRIDE_" + (k == null ? "REAL_SHIM" : k.toUpperCase())))
                    r.tags.add("OVERRIDE_" + (k == null ? "REAL_SHIM" : k.toUpperCase()));
            }
        }
        // -------- Pass F: SDK-caller depth-1 propagation (Rule 111) --------
        Set<Long> dispfbWriters = new HashSet<>();
        Set<Long> dmaKickers    = new HashSet<>();
        for(FuncResult r : results) {
            if(r.traits == null) continue;
            if(r.traits.writesDispfbReg || r.traits.writesDispfbViaSdk)
                dispfbWriters.add(r.address & 0xFFFFFFFFL);
            if(!r.traits.dmaKickChannels.isEmpty() || r.traits.path3KickViaDmaApi)
                dmaKickers.add(r.address & 0xFFFFFFFFL);
        }
        for(FuncResult r : results) {
            if(r.traits == null) continue;
            for(long[] site : r.traits.jalSites) {
                long tgt = site[1] & 0xFFFFFFFFL;
                if(dispfbWriters.contains(tgt) && !r.traits.dispfbWriterViaSdkCallerDepth1) {
                    r.traits.dispfbWriterViaSdkCallerDepth1 = true;
                    dispfbWriterViaSdkCallerCount++;
                }
                if(dmaKickers.contains(tgt) && !r.traits.dmaKickViaSdkCallerDepth1) {
                    r.traits.dmaKickViaSdkCallerDepth1 = true;
                    dmaKickViaSdkCallerCount++;
                }
            }
        }
    }

    // Risk-tier comparator helper.
    private static int rankRisk(String tier) {
        if(tier == null) return 0;
        switch(tier) {
            case "CRITICAL": return 3;
            case "HIGH":     return 2;
            case "MEDIUM":   return 1;
            default:         return 0;
        }
    }

    // =========================================================
    // TEXT SECTION DETECTION
    // =========================================================
    private void detectTextSection() {
        for (MemoryBlock block : memory.getBlocks()) {
            String bname = block.getName().toLowerCase();
            if (bname.equals(".text")||bname.equals("text")) {
                textStart=block.getStart().getOffset(); textEnd=block.getEnd().getOffset();
                println(String.format("[SECTIONS] .text: 0x%08X-0x%08X",textStart,textEnd));
                return;
            }
        }
        long first=Long.MAX_VALUE,last=0;
        FunctionIterator fit=funcManager.getFunctions(true);
        while(fit.hasNext()) {
            Function f=fit.next();
            long s=f.getEntryPoint().getOffset(),e=f.getBody().getMaxAddress().getOffset();
            if(s<first)first=s; if(e>last)last=e;
        }
        if(first<Long.MAX_VALUE){textStart=first;textEnd=last;
            println(String.format("[SECTIONS] Code: 0x%08X-0x%08X",textStart,textEnd));}
        else{println("[SECTIONS] WARNING: No code range.");}
    }

    // =========================================================
    // GLOBAL POINTER DETECTION
    // =========================================================
    private long detectGlobalPointer() {
        SymbolIterator syms=currentProgram.getSymbolTable().getSymbols("_gp");
        while(syms.hasNext()){long v=syms.next().getAddress().getOffset();
            println(String.format("[GP] _gp: 0x%08X",v));return v;}
        syms=currentProgram.getSymbolTable().getSymbols("_gp_disp");
        while(syms.hasNext()){long v=syms.next().getAddress().getOffset();
            println(String.format("[GP] _gp_disp: 0x%08X",v));return v;}
        println("[GP] No symbol. Scanning entry...");
        Function entryFunc=null;
        for(String n:new String[]{"entry","_start"}){
            SymbolIterator si=currentProgram.getSymbolTable().getSymbols(n);
            while(si.hasNext()){Function f=funcManager.getFunctionAt(si.next().getAddress());
                if(f!=null){entryFunc=f;break;}}
            if(entryFunc!=null) break;
        }
        if(entryFunc==null){FunctionIterator fi=funcManager.getFunctions(true);if(fi.hasNext())entryFunc=fi.next();}
        if(entryFunc!=null){
            long gpUpper=0; int checked=0;
            InstructionIterator it=currentProgram.getListing().getInstructions(entryFunc.getBody(),true);
            while(it.hasNext()&&checked<20){
                Instruction inst=it.next();checked++;
                String mnem=inst.getMnemonicString();if(mnem==null)continue;
                if(mnem.equalsIgnoreCase("lui")){
                    boolean isGp=false;
                    for(Object op:inst.getResultObjects())
                        if(op instanceof ghidra.program.model.lang.Register&&
                           ((ghidra.program.model.lang.Register)op).getName().equalsIgnoreCase("gp"))
                            isGp=true;
                    if(isGp) for(Object op:inst.getInputObjects())
                        if(op instanceof ghidra.program.model.scalar.Scalar)
                            gpUpper=((ghidra.program.model.scalar.Scalar)op).getUnsignedValue()<<16;
                }
                if(gpUpper!=0&&(mnem.equalsIgnoreCase("addiu")||mnem.equalsIgnoreCase("ori"))){
                    boolean wGp=false,rGp=false;
                    for(Object op:inst.getResultObjects())
                        if(op instanceof ghidra.program.model.lang.Register&&
                           ((ghidra.program.model.lang.Register)op).getName().equalsIgnoreCase("gp"))
                            wGp=true;
                    for(Object op:inst.getInputObjects())
                        if(op instanceof ghidra.program.model.lang.Register&&
                           ((ghidra.program.model.lang.Register)op).getName().equalsIgnoreCase("gp"))
                            rGp=true;
                    if(wGp&&rGp) for(Object op:inst.getInputObjects())
                        if(op instanceof ghidra.program.model.scalar.Scalar){
                            long lower=((ghidra.program.model.scalar.Scalar)op).getValue();
                            long gpVal=gpUpper+lower;
                            println(String.format("[GP] crt0: 0x%08X",gpVal));return gpVal;
                        }
                }
            }
        }
        println("[GP] WARNING: $gp not found."); return 0;
    }

    // =========================================================
    // ELF HASH
    // =========================================================
    private String computeElfHash() {
        try {
            MessageDigest md=MessageDigest.getInstance("MD5");int h=0;
            for(MemoryBlock b:memory.getBlocks()){
                if(!b.isInitialized()||h>=65536)break;
                int r=(int)Math.min(b.getSize(),65536-h);byte[]d=new byte[r];
                b.getBytes(b.getStart(),d);md.update(d);h+=r;
            }
            StringBuilder sb=new StringBuilder();
            for(byte b:md.digest())sb.append(String.format("%02x",b));
            return sb.toString();
        } catch(Exception e){return "UNKNOWN";}
    }

    // =========================================================
    // RULE 6: KSEG1 NORMALIZATION
    // =========================================================
    private static long normalizeAddress(long eeAddress) {
        return eeAddress & 0x1FFFFFFFL;
    }

    // =========================================================
    // DNA TRAIT SCANNER - v3 extended
    // =========================================================
    private FuncTraits getTraits(Function func) {
        Address key=func.getEntryPoint();
        if(cache.containsKey(key)) return cache.get(key);
        FuncTraits traits=new FuncTraits();
        traits.byteSize=func.getBody().getNumAddresses();
        String fname=func.getName();

        Set<Function> callees=func.getCalledFunctions(monitor);
        traits.calleeCount=callees.size();
        for(Function callee:callees) {
            String cn=callee.getName();
            traits.calleeNames.add(cn);
            // Rule 21: DMA send detection - all sceDmaSend* / sceDmaChain* variants
            if(cn.startsWith("sceDmaSend")||cn.startsWith("sceDmaChain")||
               cn.equals("sceDmaRecv")||cn.equals("sceDmaRecvN"))
                traits.callsDmaSend=true;
            // Rule 22: SIF RPC detection
            if(cn.equals("sceSifCallRpc")||cn.equals("sceSifBindRpc"))
                traits.callsSifRpc=true;
            // Rule 24: Pad poll callee detection
            if(PAD_POLL_CALLEES.contains(cn))
                traits.callsPadPollCallee=true;
            // v7 Rule 75: SDK-routed DISPFB writer
            for(String s : DISPFB_SDK_CALLEES) if(cn.equals(s)) { traits.writesDispfbViaSdk=true; break; }
            // v7 Rule 76: SDK-routed Path3 kicker
            for(String s : PATH3_KICK_API_CALLEES) if(cn.equals(s)) { traits.path3KickViaDmaApi=true; break; }
            // v8 Rule 96: GIF NLOOP double-count hazard helpers
            if(GIF_PACKET_NLOOP_HELPERS.contains(cn)) traits.callsGifPacketOpen=true;
            if(GIF_PACKET_CLOSE_HELPERS.contains(cn)) traits.callsGifPacketClose=true;
            // v8 Rule 99: file open callee
            if(FILE_OPEN_CALLEES.contains(cn)) traits.callsFileOpen=true;
            // v8 Rule 100: frame-clock driver detection
            if(FRAME_CLOCK_CALLEES.contains(cn)) traits.isFrameClockDriver=true;
        }
        // v8 Rule 96: NLOOP double-count risk = open AND close in same function.
        if(traits.callsGifPacketOpen && traits.callsGifPacketClose)
            traits.gifNloopDoubleCountRisk = true;

        // v8 Rule 102: sceVu0 helper whitelist.
        for(String p : SCEVU0_HELPER_PREFIXES) {
            if(fname.startsWith(p)) {
                traits.isSceVu0Helper = true;
                traits.mustBeImplemented = true;
                if(fname.contains("Matrix")) traits.vu0HelperFamily = "matrix";
                else if(fname.contains("Vector")) traits.vu0HelperFamily = "vector";
                else if(fname.contains("Trans")||fname.contains("Camera")||
                        fname.contains("Light")||fname.contains("Clip"))
                    traits.vu0HelperFamily = "transform";
                else traits.vu0HelperFamily = "generic";
                break;
            }
        }

        // v8 Rule 108: C++ demangler for class/method extraction.
        demangleAndPopulate(fname, traits);
        // v7 Rule 79: GS IRQ handler name shape (decided here so it's available
        // for the corroboration pass even on functions with empty callee sets).
        for(String frag : GS_IRQ_HANDLER_NAME_FRAGMENTS)
            if(fname.contains(frag)) { traits.isGsIrqHandlerName=true; break; }

        int xrefCount=0;
        for(Reference ref:refManager.getReferencesTo(func.getEntryPoint()))
            if(ref.getReferenceType().isCall()||ref.getReferenceType().isFlow()) xrefCount++;
        traits.xrefToCount=xrefCount;
        traits.isThunk=func.isThunk()||(traits.byteSize<=8&&traits.calleeCount>0);
        if(traits.isThunk){cache.put(key,traits);return traits;}

        // Rule 20 (v3): Large init function detection
        boolean isInitNamed = fname.toLowerCase().contains("init")||
                              fname.contains("__ct__")||fname.startsWith("__sinit_");
        if(isInitNamed&&(traits.calleeCount>10||traits.byteSize>2000))
            traits.isLargeInitFunc=true;

        // v4 Rule 30: process terminator by name. Pure name-based check.
        if(PROCESS_TERMINATOR_NAMES.contains(fname)) traits.isProcessTerminator=true;

        // v4 Rule 31: libgcc 64-bit/FP intrinsic by name. Pattern:
        //   __[u]div/mod/mul/neg/abs/cmp(di|si|hi)[23]
        //   __(fix|float)(df|sf|si|di)(df|sf|si|di)
        // Forced RECOMPILE downstream — auto-stub halts the runner on first call (F23a).
        if(fname.startsWith("__")) {
            String n=fname;
            if(n.matches("__(u?div|u?mod|mul|neg|abs|cmp)(di|si|hi|qi)[23]") ||
               n.matches("__(fix|float)(df|sf|si|di)(df|sf|si|di)"))
                traits.isLibgccIntrinsic=true;
        }
        // v8 Rule 88: also accept hardcoded exact-name list.
        if(LIBGCC_EXACT_NAMES.contains(fname)) traits.isLibgccIntrinsic = true;

        // v4 Rule 34: MPEG / IPU / DVD callee scan (decoder trap)
        for(String cn : traits.calleeNames) {
            for(String p : MPEG_CALLEE_PREFIXES)
                if(cn.startsWith(p)) { traits.callsMpegFamily=true; break; }
            if(traits.callsMpegFamily) break;
        }

        // v5 Rule 43 (v9.1 broadened): bullseye for the Path3 4HH guard. Match
        // bare name, Ghidra-mangled `sceGifPkRefLoadImage_0xADDR`, OR the
        // GCC2-mangled `sceGifPkRefLoadImage__FP12sceGifPacket...` suffix.
        if(fname.equals(SCE_GIF_PK_REF_LOAD_IMAGE) ||
           fname.startsWith(SCE_GIF_PK_REF_LOAD_IMAGE+"_0x") ||
           fname.startsWith(SCE_GIF_PK_REF_LOAD_IMAGE+"__"))
            traits.isSceGifPkRefLoadImage = true;

        // v5 Rule 45: sceGifPk*/sceVif1Pk* family roster
        for(String p : SCE_GIF_PK_PREFIXES) {
            if(fname.startsWith(p)) { traits.isSceGifPkFamily = true; break; }
        }

        // v5 Rule 52: audio callees (sceSd / sceSpu2 / sceLibSd / sceMSIn)
        for(String cn : traits.calleeNames) {
            for(String p : AUDIO_CALLEE_PREFIXES)
                if(cn.startsWith(p)) { traits.isAudioRpcHandler = true; break; }
            if(traits.isAudioRpcHandler) break;
        }

        // v5 Rule 54: MC transition gate by name + small size
        for(String frag : MC_GATE_NAME_FRAGMENTS) {
            if(fname.contains(frag) && traits.byteSize < 200) {
                traits.isMcTransitionGate = true; break;
            }
        }

        // Rule 25: Thread sync point detection.
        // Pattern: contains a syscall instruction, has a backward branch (spin loop),
        // is small (< 300 bytes), and is NOT an IOP module loader (those are stubs).
        // Phase F blocker: EE thread at pc=0x100008 was stuck in one of these.
        // Detection deferred to post-scan (needs containsSyscall result).
        // Computed after instruction scan below - see traits.isThreadSyncPoint assignment.

        InstructionIterator asmIter=currentProgram.getListing().getInstructions(func.getBody(),true);
        int instrIdx=0,mmioReadCount=0,totalInstrs=0;
        long firstInstrOffset = func.getEntryPoint().getOffset();

        while(asmIter.hasNext()) {
            Instruction inst=asmIter.next();
            String mnem=inst.getMnemonicString();
            if(mnem==null){instrIdx++;totalInstrs++;continue;}
            String ml=mnem.toLowerCase();totalInstrs++;

            // Stack frame
            if(instrIdx<8&&(ml.equals("addiu")||ml.equals("daddiu")))
                for(Object op:inst.getInputObjects())
                    if(op instanceof ghidra.program.model.lang.Register&&
                       ((ghidra.program.model.lang.Register)op).getName().equals("sp"))
                        traits.hasStackFrame=true;

            // COP1/COP2
            if(ml.contains("c1")||ml.endsWith(".s")||ml.endsWith(".d")) traits.usesCop1=true;
            if(ml.startsWith("vadd")||ml.startsWith("vmul")||ml.startsWith("vsub")||
               ml.startsWith("vscl")||ml.startsWith("vdiv")||ml.startsWith("vmfir")||
               ml.startsWith("vmtir")||ml.contains("c2")) traits.usesCop2=true;
            if(ml.equals("lqc2")||ml.equals("sqc2")){traits.usesCop2=true;traits.quadwordVU++;}

            // ACC ops: all instructions that read or write the VU0 accumulator register.
            // vmadda/vmsuba/vmula/vadda: write ACC. vmadd/vmsub/vopmsub: read ACC.
            // [FIX] v3 was missing vmadda, vmsuba, vmula, vadda, vopmsub - the exact
            // instructions listed in the phase5 table. Phase5 functions were mis-classified.
            if(ml.startsWith("vmadda")||ml.startsWith("vmsuba")||ml.startsWith("vmula")||
               ml.startsWith("vadda") ||ml.equals("vopmsub")||
               ml.startsWith("madda") ||ml.startsWith("vmadd")||ml.startsWith("vmsub")||
               ml.startsWith("madd"))
                traits.accOps++;
            if(ml.equals("sync.l")||ml.equals("sync.p")||ml.equals("sync")) traits.hasSyncInstr=true;
            if(ml.equals("vcallms")||ml.equals("vcallmsr")) traits.hasVcallms=true;

            // [FIX v4] Folded from containsSyscall/containsCOP0:
            if(ml.equalsIgnoreCase("syscall")) traits.hasSyscall=true;
            if(ml.equals("di")||ml.equals("ei")||ml.equals("mfc0")||ml.equals("mtc0")||
               ml.equals("eret")||ml.startsWith("c0")) traits.hasCOP0=true;

            // [FIX v4] Folded from referencesIopModule: detect IOP module strings inline.
            // Only check if not already found and function is small enough (-800 bytes).
            if(!traits.refsIopModuleString && traits.byteSize<=800) {
                for(Reference ref:inst.getReferencesFrom()) {
                    Data data=getDataAt(ref.getToAddress());
                    if(data!=null&&data.hasStringValue()) {
                        String str=data.getDefaultValueRepresentation();
                        for(String s:IOP_MODULE_STRINGS)
                            if(str.contains(s)){traits.refsIopModuleString=true;break;}
                    }
                    if(traits.refsIopModuleString) break;
                }
            }

            // Rule 17: jr + jump table
            // [FIX v4] Use Ghidra's flow type analysis to distinguish:
            //   - jr $ra (return)        -> isTerminal, count returnPaths
            //   - jr $t9 (indirect call) -> isCall, ignore (PIC convention)
            //   - jr $reg (switch table) -> isComputed + isJump, set hasJumpTable
            // The old code tagged ANY jr with non-ra input as a jump table,
            // causing 80%+ false-positive rate.
            if(ml.equals("jr")) {
                ghidra.program.model.symbol.FlowType ft = inst.getFlowType();
                if(ft.isTerminal()) {
                    traits.returnPaths++;
                } else if(ft.isComputed()&&ft.isJump()&&!ft.isCall()) {
                    traits.hasJumpTable=true;
                } else if(ft.isCall()||ft.isComputed()) {
                    // v4 Rule 37: terminal jr $reg used as a tail-call (e.g. jr $t9
                    // virtual dispatch at MenuCamInit F22). The recompiler may not
                    // restore RA correctly, leaking the return into a non-entry PC.
                    boolean toRa = false;
                    for(Object op : inst.getInputObjects())
                        if(op instanceof ghidra.program.model.lang.Register &&
                           ((ghidra.program.model.lang.Register)op).getName().equalsIgnoreCase("ra"))
                            toRa = true;
                    if(!toRa) traits.tailCallIndirect = true;
                }
            }

            // v4 Rule 38: jalr $t9 — PIC / vtable indirect call.
            // v8 Rule 89: accept ANY jalr regardless of flow type; both $t9 PIC
            // and any other register are counted as indirect dispatch.
            if(ml.equals("jalr")) {
                for(Object op : inst.getInputObjects())
                    if(op instanceof ghidra.program.model.lang.Register) {
                        String rn = ((ghidra.program.model.lang.Register)op).getName().toLowerCase();
                        if(rn.equals("t9")) traits.indirectCallT9Count++;
                    }
                // v8 Rule 94: virtual dispatch site capture — jalr $rX where the
                // previous instruction (or one within 3) was `lw $rX, K($rY)`
                // (K = vtable slot offset). Best-effort backward scan.
                try {
                    Object[] iop = inst.getOpObjects(0);
                    String tgtReg = null;
                    if(iop != null && iop.length>0 && iop[0] instanceof ghidra.program.model.lang.Register)
                        tgtReg = ((ghidra.program.model.lang.Register)iop[0]).getName();
                    if(tgtReg != null && !tgtReg.equalsIgnoreCase("ra")) {
                        Instruction prev = inst.getPrevious();
                        int back = 0;
                        while(prev != null && back < 4) {
                            String pmn = prev.getMnemonicString();
                            if(pmn != null && pmn.equalsIgnoreCase("lw")) {
                                Object[] dop = prev.getOpObjects(0);
                                Object[] aop = prev.getOpObjects(1);
                                String dr = null, br = null;
                                long off = -1;
                                if(dop!=null && dop.length>0 && dop[0] instanceof ghidra.program.model.lang.Register)
                                    dr = ((ghidra.program.model.lang.Register)dop[0]).getName();
                                if(aop != null) {
                                    for(Object o : aop) {
                                        if(o instanceof ghidra.program.model.lang.Register)
                                            br = ((ghidra.program.model.lang.Register)o).getName();
                                        else if(o instanceof ghidra.program.model.scalar.Scalar)
                                            off = ((ghidra.program.model.scalar.Scalar)o).getSignedValue();
                                    }
                                }
                                if(dr != null && dr.equalsIgnoreCase(tgtReg)) {
                                    traits.virtualDispatchSites.add(new String[]{
                                        String.format("0x%08X", inst.getAddress().getOffset()),
                                        off>=0 ? String.format("0x%X", off) : "?",
                                        br != null ? br : "?"
                                    });
                                    break;
                                }
                            }
                            prev = prev.getPrevious();
                            back++;
                        }
                    }
                } catch(Exception ignore) {}
            }

            // v8 Rule 97: pad button mask consumer — andi/and immediate matches
            // a PS2 DUALSHOCK bit. Captures friendly name per immediate.
            if(ml.equals("andi") || ml.equals("and")) {
                for(Object op : inst.getInputObjects()) {
                    if(!(op instanceof ghidra.program.model.scalar.Scalar)) continue;
                    long imm = ((ghidra.program.model.scalar.Scalar)op).getUnsignedValue() & 0xFFFFL;
                    String nm = PAD_BUTTON_MASKS.get(imm);
                    if(nm != null) {
                        traits.padMasksTested.add(nm + "=0x" + String.format("%04X", imm));
                        traits.isPadButtonMaskConsumer = true;
                    }
                }
            }

            // v4 Rule 33/36: 64-bit shift markers. dsll32/dsrl32 are MIPS III
            // shift-by-(32+imm) ops used to pack tag-high (Rule 36 VIF1) or to
            // alias upper bits of a 64-bit slot (Rule 33 ZBUF). sll/srl by 24
            // are the 8-bit-channel manipulation signature.
            if(ml.equals("dsll32")||ml.equals("dsrl32")||ml.equals("dsra32"))
                traits.hasDsll32OrDsrl32 = true;
            if((ml.equals("sll")||ml.equals("srl")||ml.equals("sra"))) {
                for(Object op : inst.getInputObjects())
                    if(op instanceof ghidra.program.model.scalar.Scalar &&
                       ((ghidra.program.model.scalar.Scalar)op).getUnsignedValue()==24L)
                        traits.hasShift24Pattern = true;
            }

            // Backward branch detection (improved BUSY_WAIT v3)
            // [FIX v4] Use inst.getFlows() for branch target resolution.
            // Ghidra's MIPS model does NOT reliably expose branch targets as
            // Address objects in getInputObjects(); getFlows() is the correct API.
            if((ml.startsWith("b")&&!ml.equals("break"))||ml.equals("beqz")||ml.equals("bnez")) {
                traits.branchOps++;
                for(ghidra.program.model.address.Address target:inst.getFlows()) {
                    if(target.getOffset()<inst.getAddress().getOffset())
                        traits.hasBackwardBranch=true;
                }
            }

            // Store: global write + SMC
            if(ml.equals("sw")||ml.equals("swc1")||ml.equals("sqc2")||ml.equals("sh")||ml.equals("sb")) {
                traits.hasMutatingInstructions=true;
                for(Reference ref:inst.getReferencesFrom()) {
                    if(!ref.getReferenceType().isWrite()) continue;
                    long tOff=ref.getToAddress().getOffset();
                    long norm=normalizeAddress(tOff);
                    if(ref.getToAddress().getAddressSpace().isMemorySpace()&&norm>=GLOBAL_ADDR_MIN)
                        traits.writesToGlobal=true;
                    if(textStart>0&&norm>=textStart&&norm<=textEnd) {
                        Instruction ti=currentProgram.getListing().getInstructionAt(ref.getToAddress());
                        if(ti!=null) traits.writesToText=true;
                    }
                }
                // Rule 19 (v3): Detect STORE to $a1-addressed buffer near function entry.
                // [FIX] Only scalar stores (sw/sh/sb/swc1) - NOT sqc2 (VU0 register dump).
                // sqc2 stores 128-bit VU0 regs, not output buffers.
                if(instrIdx<30 && (ml.equals("sw")||ml.equals("sh")||
                                   ml.equals("sb")||ml.equals("swc1"))) {
                    for(Object op:inst.getInputObjects())
                        if(op instanceof ghidra.program.model.lang.Register) {
                            String rn=((ghidra.program.model.lang.Register)op).getName().toLowerCase();
                            if(rn.equals("a1")) { traits.writesToA1Buffer=true; }
                        }
                }

                // v4 Rule 26/27: Constructor field-writer detection.
                // Pattern: `sw $rN, +K($a0)` near function entry where K is a small
                // positive offset (< 0x200). For VTABLE_SETTER we additionally
                // require that the stored register was written by a `lui+addiu`
                // constant earlier in the same function (best-effort static check).
                // Phase F22 mgCCamera ctor was nop_stubbed → null vtable → pc-zero.
                if(instrIdx<40 && (ml.equals("sw")||ml.equals("sd"))) {
                    boolean baseIsA0 = false;
                    long offset = -1;
                    Object[] aop = inst.getOpObjects(1);
                    if(aop!=null) {
                        for(Object o : aop) {
                            if(o instanceof ghidra.program.model.lang.Register &&
                               ((ghidra.program.model.lang.Register)o).getName().equalsIgnoreCase("a0"))
                                baseIsA0 = true;
                            else if(o instanceof ghidra.program.model.scalar.Scalar)
                                offset = ((ghidra.program.model.scalar.Scalar)o).getSignedValue();
                        }
                    }
                    if(baseIsA0 && offset>=0 && offset<0x200) {
                        // ctor name OR very small leaf-like writer is suspicious;
                        // restrict the tag to ctor-named ones to keep precision.
                        if(fname.contains("__ct__")||fname.startsWith("__sinit_")||
                           fname.toLowerCase().contains("init"))
                            traits.ctorWritesA0Slot = true;
                        // v7.1 Rule 82: distinct slot tracking for the multi-field
                        // ctor / initializer test. F33: __ct__11mgCDrawPrimFv writes
                        // 7+ slots (manager / draw env / texture / PRIM / flag / Q / C-Z).
                        traits.ctorSlotsWritten.add(offset);
                    }
                }
            }

            if(ml.equals("jal")||ml.equals("jalr")){
                traits.hasMutatingInstructions=true;traits.callOps++;
                // F21-prep: capture call-site PC + target address for reverse call-graph.
                // getFlows() returns the resolved call target for direct JAL; for JALR
                // it may be empty (indirect via register), in which case we record only
                // a sentinel target = 0xFFFFFFFF so the count of call sites still lines up.
                // v4 Rule 42: dedup (callSitePc,target) pairs. Ghidra sometimes returns
                // duplicate flows for jalr through a switch / delay-slot quirk — that
                // is the root cause of the "GetMainStack=3, called from one site" F28
                // anomaly. Use linear scan (jalSites stay short per function).
                long callSitePc = inst.getAddress().getOffset();
                ghidra.program.model.address.Address[] flows = inst.getFlows();
                if(flows.length>0) {
                    for(ghidra.program.model.address.Address tgt : flows) {
                        long target = tgt.getOffset();
                        boolean dup = false;
                        for(long[] e : traits.jalSites)
                            if(e[0]==callSitePc && e[1]==target){dup=true;break;}
                        if(!dup) traits.jalSites.add(new long[]{callSitePc, target});
                    }
                } else {
                    boolean dup = false;
                    for(long[] e : traits.jalSites)
                        if(e[0]==callSitePc && e[1]==0xFFFFFFFFL){dup=true;break;}
                    if(!dup) traits.jalSites.add(new long[]{callSitePc, 0xFFFFFFFFL});
                }
            }

            // F21-prep: literal-offset memory-access index.
            // Captures (pc, mnem, base, offset, dest) for every load/store that uses
            // a constant displacement. Operand layout for MIPS load/store is consistent:
            //   opObjects(0) = dest/source register
            //   opObjects(1) = [Scalar offset, Register base]
            if(ml.equals("lw")||ml.equals("sw")||ml.equals("lb")||ml.equals("sb")||
               ml.equals("lh")||ml.equals("sh")||ml.equals("lwc1")||ml.equals("swc1")||
               ml.equals("ld")||ml.equals("sd")||ml.equals("lbu")||ml.equals("lhu")||
               ml.equals("lq")||ml.equals("sq")) {
                try {
                    Object[] dop = inst.getOpObjects(0);
                    Object[] aop = inst.getOpObjects(1);
                    String destReg = "?";
                    String baseReg = "?";
                    String offsetHex = null;
                    if(dop.length>=1 && dop[0] instanceof ghidra.program.model.lang.Register)
                        destReg = ((ghidra.program.model.lang.Register)dop[0]).getName();
                    if(aop!=null) {
                        for(Object o : aop) {
                            if(o instanceof ghidra.program.model.scalar.Scalar)
                                offsetHex = String.format("0x%X", ((ghidra.program.model.scalar.Scalar)o).getSignedValue());
                            else if(o instanceof ghidra.program.model.lang.Register)
                                baseReg = ((ghidra.program.model.lang.Register)o).getName();
                        }
                    }
                    if(offsetHex!=null) {
                        traits.literalRefs.add(new String[]{
                            String.format("0x%08X", inst.getAddress().getOffset()),
                            ml, baseReg, offsetHex, destReg
                        });
                        // v5 Rule 55: gp-relative load/store -> map to DC2 named global
                        if("gp".equalsIgnoreCase(baseReg)) {
                            try {
                                long off = Long.parseLong(offsetHex.replace("0x","").replace("-",""), 16);
                                if(offsetHex.startsWith("-")) off = (-off) & 0xFFFFFFFFL;
                                String lbl = KNOWN_DC2_GP_OFFSETS.get(off);
                                if(lbl != null) traits.dc2GlobalsTouched.add(lbl);
                            } catch(NumberFormatException ignored) {}
                        }
                    }
                } catch(Exception ignore) {}
            }

            // SPR + MMIO (Rule 4+5+21, v4 32/35)
            for(Reference ref:inst.getReferencesFrom()) {
                long norm=normalizeAddress(ref.getToAddress().getOffset());
                if(norm>=SPR_START&&norm<=SPR_END) traits.usesSPR=true;
                if(!ref.getReferenceType().isCall()&&!ref.getReferenceType().isFlow()) {
                    if((norm>=MMIO_START&&norm<=MMIO_END)||(norm>=MMIO_GS_START&&norm<=MMIO_GS_END))
                        traits.accessesMMIO=true;
                    // Rule 21: VIF1 channel MMIO specifically
                    if(norm>=VIF1_CHANNEL_BASE&&norm<=VIF1_CHANNEL_END)
                        traits.accessesVif1MMIO=true;
                    // v4 Rule 32: GIF CTRL / CHCR MMIO
                    if((norm>=GIF_CTRL_BASE&&norm<=GIF_CTRL_END)||
                       (norm>=GIF_CHCR_BASE&&norm<=GIF_CHCR_END))
                        traits.touchesGifCtrl=true;
                    // v4 Rule 32/33/35 + v5 Rule 46/47/48: GS privileged register.
                    if(norm>=MMIO_GS_START&&norm<=MMIO_GS_END) {
                        long reg = (norm - MMIO_GS_START) & 0xFFFFL;
                        String name = KNOWN_GS_REGS.get(reg);
                        if(name!=null) traits.gsRegHits.add(name);
                        if(ref.getReferenceType().isWrite()) {
                            if(reg==GS_PRIM_REG)   traits.writesGsPrimReg = true;
                            if(reg==GS_ZBUF_1||reg==GS_ZBUF_2) traits.writesZbufReg = true;
                            if(reg==GS_DISPFB1||reg==GS_DISPFB2) traits.writesDispfbReg = true;
                            // v5
                            if(reg==GS_TEX0_1||reg==0x07L) traits.writesTex0Reg = true;
                            if(reg==GS_RGBAQ_REG)  traits.writesRgbaqReg = true;
                        }
                        if(ref.getReferenceType().isRead() && reg==GS_PRIM_REG)
                            traits.readsPrimReg = true;
                    }
                    // v5 Rule 49/50: any DMA channel CHCR (+0x00) / QWC (+0x20) / TADR (+0x30)
                    for(int chIdx=0; chIdx<DMA_CHANNEL_BASES.length; chIdx++) {
                        long base = DMA_CHANNEL_BASES[chIdx];
                        if(norm < base || norm > base + 0x3F) continue;
                        long slot = norm - base;
                        if(slot == 0x00 && ref.getReferenceType().isWrite())
                            traits.dmaKickChannels.add(DMA_CHANNEL_NAMES[chIdx]);
                        else if((slot == 0x20 || slot == 0x30) && ref.getReferenceType().isWrite())
                            traits.dmaQwcTadrChannels.add(DMA_CHANNEL_NAMES[chIdx]);
                        break;
                    }
                    // v5 Rule 44: PATH3 initiator — any write to GIF CHCR range
                    if(norm >= GIF_CHCR_BASE && norm <= GIF_CHCR_END &&
                       ref.getReferenceType().isWrite())
                        traits.path3Initiator = true;

                    // ===== v6 ranges =====
                    // Rule 58: REAL GS privileged MMIO (PMODE, DISPFB1, ...)
                    if(norm >= GS_PRIV_START && norm <= GS_PRIV_END) {
                        long off = norm - GS_PRIV_START;
                        String nm = KNOWN_GS_PRIV_REGS.get(off);
                        if(nm != null) {
                            traits.gsPrivRegHits.add(nm);
                            if(ref.getReferenceType().isWrite() &&
                               (off == 0x70L || off == 0x90L))
                                traits.writesDispfbReg = true;  // re-confirm via correct addrs
                        }
                    }
                    // Rule 59/60: IPU MMIO + IPU_CMD specifically
                    if(norm >= IPU_MMIO_START && norm < IPU_MMIO_END) {
                        traits.accessesIpuMmio = true;
                        if(norm == IPU_CMD && ref.getReferenceType().isWrite())
                            traits.writesIpuCmd = true;
                    }
                    // Rule 61: GIF Path3 control regs
                    if(norm == GIF_P3CNT || norm == GIF_P3TAG)
                        traits.touchesGifP3Reg = true;
                    // Rule 62/63/64: FIFO direct writers
                    if(norm >= GIF_FIFO_START && norm <= GIF_FIFO_END &&
                       ref.getReferenceType().isWrite())
                        traits.writesGifFifo = true;
                    if(norm >= VIF1_FIFO_START && norm <= VIF1_FIFO_END &&
                       ref.getReferenceType().isWrite())
                        traits.writesVif1Fifo = true;
                    if(norm >= VIF0_FIFO_START && norm <= VIF0_FIFO_END &&
                       ref.getReferenceType().isWrite())
                        traits.writesVif0Fifo = true;
                    if(norm >= IPU_FIFO_START && norm <= IPU_FIFO_END &&
                       ref.getReferenceType().isWrite())
                        traits.writesIpuFifo = true;
                    // Rule 65/66: VU memory ranges
                    if((norm >= VU0_MICRO_START && norm <= VU0_MICRO_END) ||
                       (norm >= VU1_MICRO_START && norm <= VU1_MICRO_END))
                        traits.accessesVuMicromem = true;
                    if((norm >= VU0_DATA_START && norm <= VU0_DATA_END) ||
                       (norm >= VU1_DATA_START && norm <= VU1_DATA_END))
                        traits.accessesVuDatamem = true;
                    // Rule 74: SBUS comm regs
                    if(norm == SBUS_MSCOM || norm == SBUS_SMCOM)
                        traits.touchesSbus = true;
                }

                // ===== v6 Rule 67-73: lui-constant scan for VIF opcodes /
                // DMAtag IDs / PSMT4HH PSM constant. Run only on `lui` and
                // `ori` so cost stays bounded.
                if(ml.equals("lui") || ml.equals("ori")) {
                    for(Object op : inst.getInputObjects()) {
                        if(!(op instanceof ghidra.program.model.scalar.Scalar)) continue;
                        long c = ((ghidra.program.model.scalar.Scalar)op).getUnsignedValue();
                        // v7 Rule 78: capture small positive immediates that fit
                        // in TEX0.TBP / BITBLTBUF.DBP shape (14-bit, 1..0x3FFF).
                        // Runtime intersection filters noise later.
                        if(ml.equals("ori") && c > 0 && c <= 0x3FFFL)
                            traits.tbpConstantsLoaded.add(c);
                        // For lui, the immediate is the upper 16 bits of a 32-bit
                        // word — the high byte is what we test against VIF opcodes.
                        long highByte;
                        if(ml.equals("lui")) {
                            // c is a 16-bit immediate; the high byte of the full
                            // 32-bit word is c>>8.
                            highByte = (c >> 8) & 0xFFL;
                        } else {
                            // ori — full 16-bit immediate could BE the VIF opcode
                            // if it's an ori-then-shift pattern. Test both halves.
                            highByte = (c >> 8) & 0xFFL;
                            // Also check the immediate directly for PSMT4HH etc.
                            if(c == PSMT4HH || c == PSMT4HL || c == PSMT8H)
                                traits.loadsPsm4hhConstant = true;
                            // v8 Rule 87: PSMT8 (0x13) — current F43 T8 blocker.
                            if(c == 0x13L) traits.loadsPsm4hhConstant = true;
                            // v8 Rule 103: expected dbp constants
                            if(EXPECTED_DBP_SET.contains(c)) {
                                for(Object[] row : EXPECTED_UPLOADS) {
                                    if(((Number)row[2]).longValue() == c)
                                        traits.assetUploadTagsHit.add((String)row[0]);
                                }
                            }
                        }
                        // VIF opcode named hits
                        String vifName = VIF_OPCODES.get(highByte);
                        if(vifName != null) traits.vifOpcodesBuilt.add(vifName);
                        // UNPACK family 0x60-0x7F (excluding 0x67 reserved)
                        if(highByte >= 0x60L && highByte <= 0x7FL)
                            traits.vifOpcodesBuilt.add("UNPACK");
                        // DMAtag ID — bits[30:28] of upper 32-bit word.
                        // For lui imm=0xIIII, the upper bits of the 32-bit word
                        // are at bit 16+. So highByte covers bits 24-31; the ID
                        // is bits 28-30 of the original word == bits 4-6 of
                        // highByte. We match the canonical encodings as in
                        // DMA_TAG_IDS.
                        long tagPrefix = highByte & 0xF0L;
                        String dmaName = DMA_TAG_IDS.get(tagPrefix);
                        if(dmaName != null && ml.equals("lui"))
                            traits.dmaTagIdsBuilt.add(dmaName);
                        // Direct PSM constant via lui imm = 0x002C... pattern is
                        // unusual; the more common case is `addiu $rN, $zero, 0x2C`
                        // or `ori $rN, $zero, 0x2C` — covered by ori branch above.
                    }
                }
                // Also catch `addiu $rN, $zero, 0x2C` for PSMT4HH (zero-base
                // constant load).
                if(ml.equals("addiu") || ml.equals("daddiu") || ml.equals("li")) {
                    boolean srcZero = false;
                    long imm = -1;
                    for(Object op : inst.getInputObjects()) {
                        if(op instanceof ghidra.program.model.lang.Register &&
                           ((ghidra.program.model.lang.Register)op).getName().equalsIgnoreCase("zero"))
                            srcZero = true;
                        else if(op instanceof ghidra.program.model.scalar.Scalar)
                            imm = ((ghidra.program.model.scalar.Scalar)op).getUnsignedValue();
                    }
                    if((srcZero || ml.equals("li")) && imm >= 0) {
                        if(imm == PSMT4HH || imm == PSMT4HL || imm == PSMT8H)
                            traits.loadsPsm4hhConstant = true;
                        // v8 Rule 87: also match additional PSM codes used in DC2.
                        // 0x13 = PSMT8 (T8 textures, current F43 blocker target).
                        // 0x14 = PSMT4. 0x02 = PSMCT16. 0x00 = PSMCT32.
                        if(imm == 0x13L) traits.loadsPsm4hhConstant = true;
                        // v7 Rule 78: TBP-shape constant via addiu/li (14-bit positive).
                        if(imm > 0 && imm <= 0x3FFFL)
                            traits.tbpConstantsLoaded.add(imm);
                        // v8 Rule 103: expected dbp constants (T8 dbp=0x2720 etc).
                        if(EXPECTED_DBP_SET.contains(imm)) {
                            for(Object[] row : EXPECTED_UPLOADS) {
                                if(((Number)row[2]).longValue() == imm) {
                                    traits.assetUploadTagsHit.add((String)row[0]);
                                }
                            }
                        }
                    }
                }
                // Rule 22: SID literal scan near sceSifBindRpc calls
                // Look for lui+addiu pattern yielding a value matching a known SID
                if(traits.callsSifRpc&&ref.getReferenceType().isData()) {
                    long candidate=ref.getToAddress().getOffset()&0xFFFFFFFFL;
                    if(KNOWN_IOP_SIDS.containsKey(candidate))
                        traits.detectedRpcSid=candidate;
                }
            }

            // Rule 23 (v3): Archive I/O string reference detection
            // v5 Rule 52/53: same scan picks up audio module strings + meswin
            if(!traits.refsArchiveStrings || !traits.refsMeswinStrings || !traits.isAudioRpcHandler) {
                for(Reference ref:inst.getReferencesFrom()) {
                    Data data=getDataAt(ref.getToAddress());
                    if(data!=null&&data.hasStringValue()) {
                        String str=data.getDefaultValueRepresentation();
                        if(!traits.refsArchiveStrings)
                            for(String s:ARCHIVE_IO_STRINGS)
                                if(str.contains(s)){traits.refsArchiveStrings=true;break;}
                        if(!traits.refsMeswinStrings)
                            for(String s:MESWIN_STRINGS)
                                if(str.contains(s)){traits.refsMeswinStrings=true;break;}
                        if(!traits.isAudioRpcHandler)
                            for(String s:AUDIO_MODULE_STRINGS)
                                if(str.contains(s)){traits.isAudioRpcHandler=true;break;}
                    }
                }
            }

            // Counters
            if(ml.startsWith("l")&&!ml.equals("lui")&&!ml.equals("lq")&&!ml.equals("lqc2")) {
                traits.loadOps++;
                for(Reference ref:inst.getReferencesFrom()) {
                    long norm=normalizeAddress(ref.getToAddress().getOffset());
                    if(norm>=MMIO_START&&norm<=MMIO_END) mmioReadCount++;
                }
            } else if(ml.startsWith("add")||ml.startsWith("dadd")||ml.startsWith("sub")||
                      ml.startsWith("mul")||ml.startsWith("div")) traits.mathOps++;
            if(ml.endsWith(".s")||ml.endsWith(".d")||ml.startsWith("cvt.")||ml.startsWith("c."))
                traits.floatOps++;
            instrIdx++;
        }

        // BUSY_WAIT detection - v3 improved:
        // Original: small func + MMIO reads + branches
        boolean originalBusyWait = (totalInstrs>0&&totalInstrs<=15&&mmioReadCount>0&&traits.branchOps>=1);
        // v3 addition: backward branch + call to pad/vsync polling callee (Phase F3.5 pattern)
        boolean padVsyncBusyWait = traits.hasBackwardBranch&&traits.callsPadPollCallee&&traits.byteSize<400;
        traits.hasBusyWait = originalBusyWait||padVsyncBusyWait;

        // Rule 25: Thread sync point - set after full instruction scan.
        // syscall present + backward branch (spinning) + small + not IOP module loader.
        if(traits.hasSyscall && traits.hasBackwardBranch &&
           traits.byteSize < 300 && !traits.refsIopModuleString)
            traits.isThreadSyncPoint = true;

        // v4 Rule 29: A0/A1 passthrough returner.
        // Scan the last ~6 instructions for `move $v0, $a0` or `or $v0, $a0, $zero`
        // (canonical MIPS `move`) or `or $v0, $zero, $a0`. Same for $a1.
        // Auto-stub returning 0 silently breaks chained-call ABIs (F5 GetFullPath).
        try {
            ghidra.program.model.address.Address ep = func.getEntryPoint();
            ghidra.program.model.address.Address last = func.getBody().getMaxAddress();
            InstructionIterator tail = currentProgram.getListing()
                .getInstructions(last,false);
            int count=0;
            while(tail.hasNext() && count<8) {
                Instruction ti = tail.next();
                if(ti.getAddress().getOffset() < ep.getOffset()) break;
                count++;
                String mn = ti.getMnemonicString();
                if(mn==null) continue;
                String mll = mn.toLowerCase();
                if(!(mll.equals("or")||mll.equals("move")||mll.equals("addu")||
                     mll.equals("daddu"))) continue;
                boolean destV0 = false;
                for(Object o : ti.getResultObjects())
                    if(o instanceof ghidra.program.model.lang.Register &&
                       ((ghidra.program.model.lang.Register)o).getName().equalsIgnoreCase("v0"))
                        destV0 = true;
                if(!destV0) continue;
                boolean srcA0 = false, srcA1 = false;
                for(Object o : ti.getInputObjects()) {
                    if(o instanceof ghidra.program.model.lang.Register) {
                        String rn = ((ghidra.program.model.lang.Register)o).getName().toLowerCase();
                        if(rn.equals("a0")) srcA0 = true;
                        else if(rn.equals("a1")) srcA1 = true;
                    }
                }
                if(srcA0) traits.returnsA0 = true;
                if(srcA1) traits.returnsA1 = true;
            }
        } catch(Exception ignore) {}

        // v5 Rule 51: microcode uploader heuristic. VIF1 MMIO touched AND we
        // observed loads of constant inline addresses (literalRefs base=gp/at/v0
        // resolving via the lui+addiu pattern doesn't reach here, so use a
        // simpler proxy: any load whose base register is among the standard
        // pic-pointer regs ($at, $v0) likely sources MPG payload from .data).
        if(traits.accessesVif1MMIO) {
            int picLoadCount = 0;
            for(String[] lr : traits.literalRefs) {
                String mn = lr[1]; String br = lr[2];
                if(("lq".equals(mn)||"lqc2".equals(mn)||"ld".equals(mn)) &&
                   (br!=null && (br.equalsIgnoreCase("at")||br.equalsIgnoreCase("v0")||
                                 br.equalsIgnoreCase("v1")||br.equalsIgnoreCase("t0"))))
                    picLoadCount++;
            }
            if(picLoadCount >= 4) traits.isMicrocodeUploader = true;
        }

        // v4 Rule 27 follow-up: VTABLE_SETTER vs CTOR_FIELD_WRITER.
        // If we observed an A0-slot write AND a hi/lo-constant load (lui present
        // in this function), treat as VTABLE_SETTER (high-confidence).
        // Without const-load evidence the ctor still writes a field but the
        // stored value may be a runtime pointer (less risky to auto-stub).
        if(traits.ctorWritesA0Slot) {
            // hasShift24Pattern doesn't help here; check if the function had any
            // lui ops — quick proxy via instruction iterator second pass would
            // be expensive. Use the byteSize heuristic: ctor with body>40 bytes
            // almost always assigns a vtable.
            if(traits.byteSize >= 40) traits.ctorWritesVTablePointer = true;
        }

        // v7.1 Rule 82: CTOR_MULTI_FIELD_INITIALIZER. F33 root cause: a ctor that
        // initializes 5+ distinct slots (manager / embedded objects / packet
        // pointers / defaults). Auto-stubbing such a ctor leaves the entire
        // object in undefined state and breaks the call chain downstream.
        boolean ctorLike = fname.contains("__ct__") || fname.startsWith("__sinit_")
                        || fname.toLowerCase().contains("init");
        if(ctorLike && traits.ctorSlotsWritten.size() >= 5)
            traits.isCtorMultiFieldInit = true;

        // v7.1 Rule 84: LIFECYCLE_LAZY_INIT_GUARD. F33: Initialize__11mgCDrawPrim
        // tested this+0x00 for null and only installed manager when zero. If
        // auto-stubbed, manager never installed across all subsequent draws.
        // Pattern: name matches lifecycle verb AND function body opens with
        // `lw $rN, 0($a0)` followed within a few instructions by `beq $rN, $zero`
        // / `bne $rN, $zero` / `beqz` / `bnez`. We pre-scanned the first ~8
        // instructions in detectLifecycleLazyInit() below.
        if(isLifecycleVerbName(fname) && traits.byteSize > 50)
            traits.isLifecycleLazyInit = detectLifecycleLazyInit(func);

        // v7.1 Rule 85: BITBLTBUF_T4HH_UPLOADER. F32 bug: BITBLTBUF.dpsm=0x2C
        // (PSMT4HH destination) upload paths. writesBitbltbufReg is gathered
        // alongside the existing gsRegHits set; here we collapse the two
        // signals: BITBLTBUF reg writer that also loads a 4HH/4HL/8H constant.
        if(traits.gsRegHits.contains("BITBLTBUF")) traits.writesBitbltbufReg = true;
        if(traits.writesBitbltbufReg && traits.loadsPsm4hhConstant)
            traits.isBitbltbufT4hhUploader = true;

        // v8 Rule 92: vtable install pattern at start of ctor.
        // `lui $rN, hi; addiu $rN, $rN, lo; sw $rN, 0($a0)` within first ~10 instrs.
        if(traits.isCtor) {
            detectCtorVtableInstall(func, traits);
            // Sibling ctor calls — any jal target that is itself a __ct__.
            for(String cn : traits.calleeNames) {
                if(cn != null && cn.contains("__ct__")) {
                    // Address resolved through jalSites pairs.
                    for(long[] s : traits.jalSites) {
                        long tgt = s[1] & 0xFFFFFFFFL;
                        if(tgt != 0xFFFFFFFFL) traits.ctorSiblingCtorCalls.add(tgt);
                    }
                }
            }
        }

        // v8 Rule 101: SIF RPC fid scan. If function calls sceSifCallRpc, scan
        // the body for an `ori $a1, $zero, imm` / `addiu $a1, $zero, imm` /
        // `li $a1, imm` literal in the 8 instructions preceding any jal site.
        if(traits.callsSifRpc) {
            detectSifRpcFids(func, traits);
        }

        // v8 Rule 99: file-open caller sprintf-source scan. Look for `%s` in any
        // referenced string, AND a preceding sprintf-style callee.
        if(traits.callsFileOpen) {
            detectFilePathSprintfFormats(func, traits);
        }

        // ===== v9 detector pipeline =====
        // Rule 113 GIFtag inline builder + R117/R118 stored opcode capture
        detectGifTagInlineBuilder(func, traits);
        // Rule 114 BITBLTBUF macro sequence — sharper than raw GS reg writes
        detectBitbltbufSequence(func, traits);
        // Rule 115 DMA CHCR start kick — Path3 starter
        detectDmaChcrStartKick(func, traits);
        // Rule 116 DMA source-chain tag builder
        detectDmaSourceChainTagBuilder(func, traits);
        // Rule 119 composite MMIO recovery — catches hidden lui+ori MMIO writes
        detectCompositeMmioConsts(func, traits);
        // v9.1 Rule A: sharpen A+D reg writer detection via const-tracked sd/sw.
        detectAdRegImmediateStores(func, traits);
        // v9.1: aggressive PSM constant scan covering reg-bag-shape composites.
        if(!traits.loadsPsm4hhConstant) detectPsmConstantsAggressive(func, traits);
        // Rule 120 syscall trampoline — names anonymous syscall stubs
        if(traits.hasSyscall && traits.byteSize <= 64)
            detectSyscallTrampoline(func, traits);
        // Rule 121 sync-wait loop class
        detectSyncWaitLoop(func, traits);
        // Rule 122/123 infinite spin / fail loop
        if(traits.byteSize <= 600)
            detectInfiniteLoops(func, traits);
        // Rule 124/125 IRX loader + IOP reboot handler
        detectIrxLoaderShape(func, traits);
        // Rule 126 render frame entry name match
        detectRenderFrameEntry(fname, traits);
        // Rule 127 non-ctor struct initializer
        detectStructInitializer(func, traits);
        // Rule 131 stamp DC2 hardcoded role
        stampDc2KnownRole(func.getEntryPoint().getOffset() & 0xFFFFFFFFL, traits);
        // Rule 139 discovered SIDs / FIDs
        if(traits.callsSifRpc) detectDiscoveredSidsFids(func, traits);

        // Update BITBLTBUF_T4HH_UPLOADER after v9 BITBLTBUF macro detection.
        if(traits.bitbltbufMacroSequence && traits.loadsPsm4hhConstant)
            traits.isBitbltbufT4hhUploader = true;

        cache.put(key,traits);
        return traits;
    }

    // v8 Rule 92: vtable install detector — looks for lui+addiu+sw $rN, 0($a0).
    private void detectCtorVtableInstall(Function func, FuncTraits traits) {
        InstructionIterator it = currentProgram.getListing().getInstructions(func.getBody(), true);
        long hi = 0; String hiReg = null;
        long val = 0; String valReg = null;
        int scanned = 0;
        while(it.hasNext() && scanned < 16) {
            Instruction inst = it.next();
            scanned++;
            String mn = inst.getMnemonicString();
            if(mn == null) continue;
            String mll = mn.toLowerCase();
            if(mll.equals("lui")) {
                Object[] dop = inst.getOpObjects(0);
                if(dop!=null && dop.length>0 && dop[0] instanceof ghidra.program.model.lang.Register) {
                    String dr = ((ghidra.program.model.lang.Register)dop[0]).getName();
                    for(Object o : inst.getInputObjects()) {
                        if(o instanceof ghidra.program.model.scalar.Scalar) {
                            hi = (((ghidra.program.model.scalar.Scalar)o).getUnsignedValue() & 0xFFFFL) << 16;
                            hiReg = dr;
                        }
                    }
                }
            } else if(mll.equals("addiu") || mll.equals("ori")) {
                Object[] dop = inst.getOpObjects(0);
                String dr = (dop!=null && dop.length>0 && dop[0] instanceof ghidra.program.model.lang.Register)
                    ? ((ghidra.program.model.lang.Register)dop[0]).getName() : null;
                boolean readsHiReg = false;
                long imm = 0;
                for(Object o : inst.getInputObjects()) {
                    if(o instanceof ghidra.program.model.lang.Register) {
                        String rn = ((ghidra.program.model.lang.Register)o).getName();
                        if(hiReg != null && rn.equalsIgnoreCase(hiReg)) readsHiReg = true;
                    } else if(o instanceof ghidra.program.model.scalar.Scalar) {
                        imm = ((ghidra.program.model.scalar.Scalar)o).getSignedValue();
                    }
                }
                if(readsHiReg && dr != null) {
                    val = (hi + imm) & 0xFFFFFFFFL;
                    valReg = dr;
                }
            } else if(mll.equals("sw") || mll.equals("sd")) {
                Object[] dop = inst.getOpObjects(0);
                Object[] aop = inst.getOpObjects(1);
                String srcReg = (dop!=null && dop.length>0 && dop[0] instanceof ghidra.program.model.lang.Register)
                    ? ((ghidra.program.model.lang.Register)dop[0]).getName() : null;
                boolean baseIsA0 = false;
                long off = -1;
                if(aop != null) {
                    for(Object o : aop) {
                        if(o instanceof ghidra.program.model.lang.Register &&
                           ((ghidra.program.model.lang.Register)o).getName().equalsIgnoreCase("a0"))
                            baseIsA0 = true;
                        else if(o instanceof ghidra.program.model.scalar.Scalar)
                            off = ((ghidra.program.model.scalar.Scalar)o).getSignedValue();
                    }
                }
                if(baseIsA0 && off == 0 && srcReg != null && srcReg.equalsIgnoreCase(valReg) && val != 0) {
                    traits.ctorInstallsVtable = true;
                    traits.ctorVtableAddr = val;
                    break;
                }
            }
        }
    }

    // v8 Rule 101: scan for $a1 immediate set just before sceSifCallRpc.
    private void detectSifRpcFids(Function func, FuncTraits traits) {
        InstructionIterator it = currentProgram.getListing().getInstructions(func.getBody(), true);
        long lastA1 = -1;
        while(it.hasNext()) {
            Instruction inst = it.next();
            String mn = inst.getMnemonicString();
            if(mn == null) continue;
            String mll = mn.toLowerCase();
            if(mll.equals("addiu") || mll.equals("ori") || mll.equals("li")) {
                Object[] dop = inst.getOpObjects(0);
                String dr = (dop!=null && dop.length>0 && dop[0] instanceof ghidra.program.model.lang.Register)
                    ? ((ghidra.program.model.lang.Register)dop[0]).getName() : null;
                long imm = -1;
                for(Object o : inst.getInputObjects()) {
                    if(o instanceof ghidra.program.model.scalar.Scalar)
                        imm = ((ghidra.program.model.scalar.Scalar)o).getUnsignedValue();
                }
                if(dr != null && dr.equalsIgnoreCase("a1") && imm >= 0) lastA1 = imm;
            } else if(mll.equals("jal") || mll.equals("jalr")) {
                for(ghidra.program.model.address.Address tgt : inst.getFlows()) {
                    Function t = funcManager.getFunctionAt(tgt);
                    if(t != null && t.getName().equals("sceSifCallRpc") && lastA1 >= 0)
                        traits.detectedRpcFids.add(lastA1);
                }
            }
        }
    }

    // v8 Rule 99: collect %s-bearing format strings referenced near a sprintf call
    // chained into a file open call.
    private void detectFilePathSprintfFormats(Function func, FuncTraits traits) {
        InstructionIterator it = currentProgram.getListing().getInstructions(func.getBody(), true);
        while(it.hasNext()) {
            Instruction inst = it.next();
            for(Reference ref : inst.getReferencesFrom()) {
                Data data = getDataAt(ref.getToAddress());
                if(data != null && data.hasStringValue()) {
                    String s = data.getDefaultValueRepresentation();
                    if(s == null) continue;
                    // Look for %s placeholder + path-like prefix.
                    if(s.contains("%s") && (s.contains("/") || s.contains(".dat") ||
                       s.contains(".hd2") || s.contains(".bin") || s.contains(".tex"))) {
                        traits.filePathSprintfFormats.add(s);
                        traits.filePathHasPercentS = true;
                    }
                }
            }
        }
    }

    // v8 Rule 108: hand-rolled GCC2-style C++ symbol demangler.
    //   __ct__<N><className>F<args>          -> ctor
    //   __dt__<N><className>F<args>          -> dtor
    //   <method>__<N><className>F<args>      -> method
    //   __sinit_<file>.cpp                   -> static init (left as-is)
    // Populates traits.ctorClassName / traits.methodClassName / traits.methodName.
    private void demangleAndPopulate(String fname, FuncTraits traits) {
        if(fname == null) return;
        // ctor
        if(fname.startsWith("__ct__")) {
            traits.isCtor = true;
            traits.ctorClassName = extractClassNameFromMangled(fname.substring(6));
            return;
        }
        if(fname.startsWith("__dt__")) {
            traits.isDtor = true;
            traits.methodClassName = extractClassNameFromMangled(fname.substring(6));
            return;
        }
        // method__<N><class>F<args>
        int idx = fname.indexOf("__");
        if(idx > 0 && idx + 2 < fname.length()) {
            char c = fname.charAt(idx + 2);
            if(Character.isDigit(c)) {
                String method = fname.substring(0, idx);
                String rest = fname.substring(idx + 2);
                String cls = extractClassNameFromMangled(rest);
                if(cls != null) {
                    traits.methodClassName = cls;
                    traits.methodName = method;
                    String mlower = method.toLowerCase();
                    if(mlower.equals("draw") || mlower.equals("step") ||
                       mlower.equals("update") || mlower.equals("render") ||
                       mlower.equals("paint") || mlower.startsWith("draw") ||
                       mlower.startsWith("step"))
                        traits.isVirtualDrawMethod = true;
                }
            }
        }
    }

    // Parses "<N><name>F<args>" or "<N><name>Fv" — returns the class name
    // (the <name> portion). Tolerates trailing template marker missing.
    private static String extractClassNameFromMangled(String s) {
        if(s == null || s.isEmpty()) return null;
        int i = 0;
        while(i < s.length() && Character.isDigit(s.charAt(i))) i++;
        if(i == 0) return null;
        int n;
        try { n = Integer.parseInt(s.substring(0, i)); }
        catch(NumberFormatException ex) { return null; }
        if(i + n > s.length()) return null;
        return s.substring(i, i + n);
    }

    // v7.1 Rule 84: lifecycle-verb name match. Includes the F33 culprit
    // Initialize__11mgCDrawPrim variants plus the broader category.
    private static boolean isLifecycleVerbName(String name) {
        if(name == null) return false;
        if(name.startsWith("Initialize")) return true;
        if(name.startsWith("Begin__"))    return true;
        if(name.startsWith("Open"))       return true;
        if(name.startsWith("Acquire"))    return true;
        if(name.startsWith("Setup"))      return true;
        if(name.startsWith("Reset"))      return true;
        return false;
    }

    // v7.1 Rule 84: scan first ~8 instructions for `lw $rN, 0($a0)` followed by
    // a branch-on-zero / branch-not-zero of the same register. This is the F33
    // "if (this->manager == null) install manager" guard. False positive risk
    // is low because the verb-name match restricts the search.
    private boolean detectLifecycleLazyInit(Function func) {
        InstructionIterator it = currentProgram.getListing().getInstructions(func.getBody(), true);
        String loadDestReg = null;
        int scanned = 0;
        while(it.hasNext() && scanned < 8) {
            Instruction inst = it.next();
            scanned++;
            String ml = inst.getMnemonicString();
            if(ml == null) continue;
            ml = ml.toLowerCase();
            if(loadDestReg == null && (ml.equals("lw") || ml.equals("ld") || ml.equals("lwu"))) {
                // dest is opObjects(0); base+offset in opObjects(1).
                Object[] dop = inst.getOpObjects(0);
                Object[] aop = inst.getOpObjects(1);
                String destName = null;
                boolean baseIsA0 = false;
                long off = -1;
                if(dop != null && dop.length > 0 &&
                   dop[0] instanceof ghidra.program.model.lang.Register)
                    destName = ((ghidra.program.model.lang.Register)dop[0]).getName();
                if(aop != null) {
                    for(Object o : aop) {
                        if(o instanceof ghidra.program.model.lang.Register &&
                           ((ghidra.program.model.lang.Register)o).getName().equalsIgnoreCase("a0"))
                            baseIsA0 = true;
                        else if(o instanceof ghidra.program.model.scalar.Scalar)
                            off = ((ghidra.program.model.scalar.Scalar)o).getSignedValue();
                    }
                }
                if(destName != null && baseIsA0 && off == 0) loadDestReg = destName;
                continue;
            }
            if(loadDestReg != null && (ml.equals("beq") || ml.equals("bne") ||
                                       ml.equals("beqz") || ml.equals("bnez"))) {
                for(Object o : inst.getInputObjects()) {
                    if(o instanceof ghidra.program.model.lang.Register &&
                       ((ghidra.program.model.lang.Register)o).getName().equalsIgnoreCase(loadDestReg))
                        return true;
                }
            }
        }
        return false;
    }

    // =========================================================
    // v9 DETECTORS (ported from General v11/v12)
    // =========================================================

    // v9 Rule 113: GIFtag inline builder. 4-stride store cluster (0/8/0x10/0x18)
    // to same base + per-reg lui+ori composite tracking for embedded GIFtag
    // REGS/FLG/NLOOP encoding. Also feeds Rule 117/118 stored-immediate captures.
    private void detectGifTagInlineBuilder(Function func, FuncTraits traits) {
        InstructionIterator it = currentProgram.getListing().getInstructions(func.getBody(), true);
        Map<String, Set<Long>> baseOffsets = new HashMap<>();
        Map<String, Long> regConsts = new HashMap<>();
        while(it.hasNext()) {
            Instruction inst = it.next();
            String mn = inst.getMnemonicString(); if(mn == null) continue;
            String mll = mn.toLowerCase();
            if(mll.equals("lui")) {
                Object[] dops = inst.getOpObjects(0);
                String dr = (dops!=null && dops.length>0 && dops[0] instanceof ghidra.program.model.lang.Register)
                    ? ((ghidra.program.model.lang.Register)dops[0]).getName() : null;
                long imm = -1;
                for(Object o : inst.getInputObjects())
                    if(o instanceof ghidra.program.model.scalar.Scalar)
                        imm = ((ghidra.program.model.scalar.Scalar)o).getUnsignedValue();
                if(dr != null && imm >= 0) regConsts.put(dr, (imm & 0xFFFFL) << 16);
            } else if(mll.equals("ori") || mll.equals("addiu") || mll.equals("daddiu")) {
                Object[] dops = inst.getOpObjects(0);
                String dr = (dops!=null && dops.length>0 && dops[0] instanceof ghidra.program.model.lang.Register)
                    ? ((ghidra.program.model.lang.Register)dops[0]).getName() : null;
                String src = null; long imm = 0;
                for(Object o : inst.getInputObjects()) {
                    if(o instanceof ghidra.program.model.lang.Register) {
                        String rn = ((ghidra.program.model.lang.Register)o).getName();
                        if(!rn.equalsIgnoreCase(dr)) src = rn;
                    } else if(o instanceof ghidra.program.model.scalar.Scalar) {
                        imm = ((ghidra.program.model.scalar.Scalar)o).getSignedValue();
                    }
                }
                if(dr != null && src != null && regConsts.containsKey(src))
                    regConsts.put(dr, (regConsts.get(src) + imm) & 0xFFFFFFFFL);
            } else if(mll.equals("li")) {
                Object[] dops = inst.getOpObjects(0);
                String dr = (dops!=null && dops.length>0 && dops[0] instanceof ghidra.program.model.lang.Register)
                    ? ((ghidra.program.model.lang.Register)dops[0]).getName() : null;
                long imm = -1;
                for(Object o : inst.getInputObjects())
                    if(o instanceof ghidra.program.model.scalar.Scalar)
                        imm = ((ghidra.program.model.scalar.Scalar)o).getUnsignedValue();
                if(dr != null && imm >= 0) regConsts.put(dr, imm);
            } else if(mll.equals("sw") || mll.equals("sd") || mll.equals("sq")) {
                Object[] dop = inst.getOpObjects(0);
                Object[] aop = inst.getOpObjects(1);
                String src = (dop!=null && dop.length>0 && dop[0] instanceof ghidra.program.model.lang.Register)
                    ? ((ghidra.program.model.lang.Register)dop[0]).getName() : null;
                String base = null; long off = -1;
                if(aop != null) for(Object o : aop) {
                    if(o instanceof ghidra.program.model.lang.Register)
                        base = ((ghidra.program.model.lang.Register)o).getName();
                    else if(o instanceof ghidra.program.model.scalar.Scalar)
                        off = ((ghidra.program.model.scalar.Scalar)o).getSignedValue();
                }
                // R117/R118 stored VIF/DMA tag immediates.
                if(src != null && regConsts.containsKey(src) && off >= 0 && (off % 4) == 0) {
                    long sval = regConsts.get(src) & 0xFFFFFFFFL;
                    long hb = (sval >> 24) & 0xFFL;
                    String vn = VIF_OPCODES.get(hb);
                    if(vn != null) traits.storedVifOpcodes.add(vn);
                    if(hb >= 0x60L && hb <= 0x7FL) traits.storedVifOpcodes.add("UNPACK");
                    if(hb >= 0x10L) {
                        long tp = hb & 0xF0L;
                        String dn = DMA_TAG_IDS.get(tp);
                        if(dn != null) traits.storedDmaTagIds.add(dn);
                    }
                    // Const-load capture for table-dispatch resolution.
                    if(traits.constLoads.size() < 24)
                        traits.constLoads.add(new long[]{ inst.getAddress().getOffset() & 0xFFFFFFFFL, sval });
                }
                if(base == null || off < 0 || off > 0x40) continue;
                Set<Long> offsets = baseOffsets.computeIfAbsent(base, k -> new LinkedHashSet<>());
                offsets.add(off);
                if(src != null && regConsts.containsKey(src)) {
                    long val = regConsts.get(src);
                    long highByte = (val >> 24) & 0xFFL;
                    long nloop = val & 0x7FFFL;
                    if((highByte & 0x0FL) == 0x0EL || (val & 0xFFFFL) == 0x000EL) {
                        traits.gifTagRegsFields.add(0x0EL);
                        if(nloop > 0) traits.gifTagNloops.add(nloop);
                    }
                    long flg = (val >> 26) & 0x3L;
                    if(flg == 0 && (val & 0xFFFF0000L) != 0) traits.gifTagFlags.add("PACKED");
                    if(flg == 1) traits.gifTagFlags.add("REGLIST");
                    if(flg == 2) traits.gifTagFlags.add("IMAGE");
                }
            }
        }
        for(Set<Long> offsets : baseOffsets.values()) {
            boolean h0=false, h8=false, h10=false, h18=false;
            for(Long o : offsets) {
                if(o == 0L)    h0=true;
                if(o == 8L)    h8=true;
                if(o == 0x10L) h10=true;
                if(o == 0x18L) h18=true;
            }
            int cnt = (h0?1:0)+(h8?1:0)+(h10?1:0)+(h18?1:0);
            if(cnt >= 3) { traits.gifTagInlineBuilder = true; break; }
        }
    }

    // v9 Rule 114: BITBLTBUF macro sequence. Const-tracked store of 0x50/0x51/
    // 0x52/0x53 (BITBLTBUF/TRXPOS/TRXREG/TRXDIR A+D ids) in same function.
    private void detectBitbltbufSequence(Function func, FuncTraits traits) {
        InstructionIterator it = currentProgram.getListing().getInstructions(func.getBody(), true);
        boolean s50=false,s51=false,s52=false,s53=false;
        Map<String,Long> regConsts = new HashMap<>();
        while(it.hasNext()) {
            Instruction inst = it.next();
            String mn = inst.getMnemonicString(); if(mn == null) continue;
            String mll = mn.toLowerCase();
            if(mll.equals("addiu") || mll.equals("li") || mll.equals("ori") || mll.equals("daddiu")) {
                Object[] dops = inst.getOpObjects(0);
                String dr = (dops!=null && dops.length>0 && dops[0] instanceof ghidra.program.model.lang.Register)
                    ? ((ghidra.program.model.lang.Register)dops[0]).getName() : null;
                long imm = -1;
                for(Object o : inst.getInputObjects())
                    if(o instanceof ghidra.program.model.scalar.Scalar)
                        imm = ((ghidra.program.model.scalar.Scalar)o).getUnsignedValue();
                if(dr != null && imm >= 0) regConsts.put(dr, imm);
            } else if(mll.equals("sw") || mll.equals("sd") || mll.equals("sq")) {
                Object[] dop = inst.getOpObjects(0);
                String src = (dop!=null && dop.length>0 && dop[0] instanceof ghidra.program.model.lang.Register)
                    ? ((ghidra.program.model.lang.Register)dop[0]).getName() : null;
                if(src != null && regConsts.containsKey(src)) {
                    long v = regConsts.get(src);
                    if(v == 0x50L) s50 = true;
                    if(v == 0x51L) s51 = true;
                    if(v == 0x52L) s52 = true;
                    if(v == 0x53L) s53 = true;
                }
            }
        }
        // v9.1: strict (all 4) OR loose (3 of 4 including 0x50 BITBLTBUF).
        int cnt = (s50?1:0)+(s51?1:0)+(s52?1:0)+(s53?1:0);
        if(s50 && cnt >= 3) {
            traits.bitbltbufMacroSequence = true;
            traits.writesBitbltbufReg = true;
        }
    }

    // v9 Rule 115: DMA_CHCR_START_KICK. Loads const 0x101 (STR | TIE) AND
    // touches a known DMA channel CHCR address.
    private void detectDmaChcrStartKick(Function func, FuncTraits traits) {
        boolean loaded101 = false;
        InstructionIterator it = currentProgram.getListing().getInstructions(func.getBody(), true);
        Map<String,Long> regConsts = new HashMap<>();
        while(it.hasNext()) {
            Instruction inst = it.next();
            String mn = inst.getMnemonicString(); if(mn == null) continue;
            String mll = mn.toLowerCase();
            if(mll.equals("addiu") || mll.equals("li") || mll.equals("ori")) {
                Object[] dops = inst.getOpObjects(0);
                String dr = (dops!=null && dops.length>0 && dops[0] instanceof ghidra.program.model.lang.Register)
                    ? ((ghidra.program.model.lang.Register)dops[0]).getName() : null;
                long imm = -1;
                for(Object o : inst.getInputObjects())
                    if(o instanceof ghidra.program.model.scalar.Scalar)
                        imm = ((ghidra.program.model.scalar.Scalar)o).getUnsignedValue();
                if(dr != null && imm == DMA_CHCR_START_CONST) {
                    regConsts.put(dr, imm); loaded101 = true;
                }
            }
        }
        traits.loadsChcrStartConst = loaded101;
        // v9.1: dmaKickChannels often empty because raw-MMIO scan misses
        // composite addrs. Fall back to dmaTagIdsBuilt OR storedDmaTagIds
        // OR touchesGifCtrl as kick-context indicator.
        if(loaded101 && (!traits.dmaKickChannels.isEmpty()
                       || !traits.dmaTagIdsBuilt.isEmpty()
                       || !traits.storedDmaTagIds.isEmpty()
                       || traits.touchesGifCtrl
                       || traits.path3Initiator))
            traits.dmaChcrStartKick = true;
    }

    // v9 Rule 116: DMA source-chain tag builder. Stores const with high nibble
    // matching CNT/REF/REFS/CALL/RET/END at offset 0 of any base.
    private void detectDmaSourceChainTagBuilder(Function func, FuncTraits traits) {
        InstructionIterator it = currentProgram.getListing().getInstructions(func.getBody(), true);
        Map<String,Long> regConsts = new HashMap<>();
        while(it.hasNext()) {
            Instruction inst = it.next();
            String mn = inst.getMnemonicString(); if(mn == null) continue;
            String mll = mn.toLowerCase();
            if(mll.equals("lui")) {
                Object[] dops = inst.getOpObjects(0);
                String dr = (dops!=null && dops.length>0 && dops[0] instanceof ghidra.program.model.lang.Register)
                    ? ((ghidra.program.model.lang.Register)dops[0]).getName() : null;
                long imm = -1;
                for(Object o : inst.getInputObjects())
                    if(o instanceof ghidra.program.model.scalar.Scalar)
                        imm = ((ghidra.program.model.scalar.Scalar)o).getUnsignedValue();
                if(dr != null && imm >= 0) regConsts.put(dr, (imm & 0xFFFFL) << 16);
            } else if(mll.equals("ori") || mll.equals("addiu") || mll.equals("daddiu")) {
                Object[] dops = inst.getOpObjects(0);
                String dr = (dops!=null && dops.length>0 && dops[0] instanceof ghidra.program.model.lang.Register)
                    ? ((ghidra.program.model.lang.Register)dops[0]).getName() : null;
                String src = null; long imm = 0;
                for(Object o : inst.getInputObjects()) {
                    if(o instanceof ghidra.program.model.lang.Register) {
                        String rn = ((ghidra.program.model.lang.Register)o).getName();
                        if(!rn.equalsIgnoreCase(dr)) src = rn;
                    } else if(o instanceof ghidra.program.model.scalar.Scalar) {
                        imm = ((ghidra.program.model.scalar.Scalar)o).getSignedValue();
                    }
                }
                if(dr != null && src != null && regConsts.containsKey(src))
                    regConsts.put(dr, (regConsts.get(src) + imm) & 0xFFFFFFFFL);
            } else if(mll.equals("li")) {
                Object[] dops = inst.getOpObjects(0);
                String dr = (dops!=null && dops.length>0 && dops[0] instanceof ghidra.program.model.lang.Register)
                    ? ((ghidra.program.model.lang.Register)dops[0]).getName() : null;
                long imm = -1;
                for(Object o : inst.getInputObjects())
                    if(o instanceof ghidra.program.model.scalar.Scalar)
                        imm = ((ghidra.program.model.scalar.Scalar)o).getUnsignedValue();
                if(dr != null && imm >= 0) regConsts.put(dr, imm);
            } else if(mll.equals("sw") || mll.equals("sd")) {
                Object[] dop = inst.getOpObjects(0);
                Object[] aop = inst.getOpObjects(1);
                String src = (dop!=null && dop.length>0 && dop[0] instanceof ghidra.program.model.lang.Register)
                    ? ((ghidra.program.model.lang.Register)dop[0]).getName() : null;
                long off = -1;
                if(aop != null) for(Object o : aop)
                    if(o instanceof ghidra.program.model.scalar.Scalar)
                        off = ((ghidra.program.model.scalar.Scalar)o).getSignedValue();
                if(src != null && regConsts.containsKey(src) && off >= 0 && off <= 0x10) {
                    long v = regConsts.get(src) & 0xFFFFFFFFL;
                    long highByte = (v >> 24) & 0xFFL;
                    String name = null;
                    if(highByte == 0x70L)      name = "END";
                    else if(highByte == 0x10L) name = "CNT";
                    else if(highByte == 0x30L) name = "REF";
                    else if(highByte == 0x40L) name = "REFS";
                    else if(highByte == 0x50L) name = "CALL";
                    else if(highByte == 0x60L) name = "RET";
                    else if(highByte == 0x20L) name = "NEXT";
                    if(name != null) {
                        traits.dmaSourceChainTagBuilder = true;
                        traits.dmaSourceChainTagIds.add(name);
                    }
                }
            }
        }
    }

    // v9 Rule 119: composite MMIO recovery. lui+ori|addiu|or per reg tracking,
    // matched against every documented EE peripheral range. Sets the corresponding
    // FuncTraits flag so existing tag/counter logic fires.
    private void detectCompositeMmioConsts(Function func, FuncTraits traits) {
        InstructionIterator it = currentProgram.getListing().getInstructions(func.getBody(), true);
        Map<String,Long> regConsts = new HashMap<>();
        while(it.hasNext()) {
            Instruction inst = it.next();
            String mn = inst.getMnemonicString(); if(mn == null) continue;
            String mll = mn.toLowerCase();
            if(mll.equals("lui")) {
                Object[] dops = inst.getOpObjects(0);
                String dr = (dops!=null && dops.length>0 && dops[0] instanceof ghidra.program.model.lang.Register)
                    ? ((ghidra.program.model.lang.Register)dops[0]).getName() : null;
                long imm = -1;
                for(Object o : inst.getInputObjects())
                    if(o instanceof ghidra.program.model.scalar.Scalar)
                        imm = ((ghidra.program.model.scalar.Scalar)o).getUnsignedValue();
                if(dr != null && imm >= 0) regConsts.put(dr, (imm & 0xFFFFL) << 16);
            } else if(mll.equals("ori") || mll.equals("addiu") || mll.equals("daddiu")) {
                Object[] dops = inst.getOpObjects(0);
                String dr = (dops!=null && dops.length>0 && dops[0] instanceof ghidra.program.model.lang.Register)
                    ? ((ghidra.program.model.lang.Register)dops[0]).getName() : null;
                String src = null; long imm = 0;
                for(Object o : inst.getInputObjects()) {
                    if(o instanceof ghidra.program.model.lang.Register) {
                        String rn = ((ghidra.program.model.lang.Register)o).getName();
                        if(!rn.equalsIgnoreCase(dr)) src = rn;
                    } else if(o instanceof ghidra.program.model.scalar.Scalar) {
                        imm = ((ghidra.program.model.scalar.Scalar)o).getSignedValue();
                    }
                }
                if(dr != null && src != null && regConsts.containsKey(src))
                    regConsts.put(dr, (regConsts.get(src) + imm) & 0xFFFFFFFFL);
            } else if(mll.equals("li")) {
                Object[] dops = inst.getOpObjects(0);
                String dr = (dops!=null && dops.length>0 && dops[0] instanceof ghidra.program.model.lang.Register)
                    ? ((ghidra.program.model.lang.Register)dops[0]).getName() : null;
                long imm = -1;
                for(Object o : inst.getInputObjects())
                    if(o instanceof ghidra.program.model.scalar.Scalar)
                        imm = ((ghidra.program.model.scalar.Scalar)o).getUnsignedValue();
                if(dr != null && imm >= 0) regConsts.put(dr, imm);
            }
            for(Long vB : regConsts.values()) {
                long v = vB & 0xFFFFFFFFL;
                if(v == 0) continue;
                matchMmioRange(v, traits);
            }
        }
    }

    /** Classify 32-bit composite address into a peripheral range and stamp the
     *  matching FuncTraits flag. Idempotent via compositeMmioRangesHit. */
    private void matchMmioRange(long addr, FuncTraits traits) {
        long norm = addr & 0x1FFFFFFFL;
        if((norm >= VU0_MICRO_START && norm <= VU0_MICRO_END) ||
           (norm >= VU1_MICRO_START && norm <= VU1_MICRO_END)) {
            if(traits.compositeMmioRangesHit.add("VU_MICROMEM"))
                traits.accessesVuMicromem = true;
        }
        if((norm >= VU0_DATA_START && norm <= VU0_DATA_END) ||
           (norm >= VU1_DATA_START && norm <= VU1_DATA_END)) {
            if(traits.compositeMmioRangesHit.add("VU_DATAMEM"))
                traits.accessesVuDatamem = true;
        }
        if(norm >= IPU_MMIO_START && norm < IPU_MMIO_END) {
            traits.compositeMmioRangesHit.add("IPU_MMIO");
            traits.accessesIpuMmio = true;
            if(norm == IPU_CMD) traits.writesIpuCmd = true;
        }
        if(norm == GIF_P3CNT || norm == GIF_P3TAG) {
            traits.compositeMmioRangesHit.add("GIF_P3_CTRL");
            traits.touchesGifP3Reg = true;
        }
        if((norm >= GIF_CTRL_BASE && norm <= GIF_CTRL_END) ||
           (norm >= GIF_CHCR_BASE && norm <= GIF_CHCR_END)) {
            traits.compositeMmioRangesHit.add("GIF_CTRL");
            traits.touchesGifCtrl = true;
        }
        if(norm >= GIF_FIFO_START && norm <= GIF_FIFO_END) {
            traits.compositeMmioRangesHit.add("GIF_FIFO");
            traits.writesGifFifo = true;
        }
        if(norm >= VIF1_FIFO_START && norm <= VIF1_FIFO_END) {
            traits.compositeMmioRangesHit.add("VIF1_FIFO");
            traits.writesVif1Fifo = true;
        }
        if(norm >= VIF0_FIFO_START && norm <= VIF0_FIFO_END) {
            traits.compositeMmioRangesHit.add("VIF0_FIFO");
            traits.writesVif0Fifo = true;
        }
        if(norm >= IPU_FIFO_START && norm <= IPU_FIFO_END) {
            traits.compositeMmioRangesHit.add("IPU_FIFO");
        }
        if(norm >= VIF1_CHANNEL_BASE && norm <= VIF1_CHANNEL_END) {
            traits.compositeMmioRangesHit.add("VIF1_CHANNEL");
            traits.accessesVif1MMIO = true;
        }
        for(int chIdx=0; chIdx<DMA_CHANNEL_BASES.length; chIdx++) {
            long base = DMA_CHANNEL_BASES[chIdx];
            if(norm < base || norm > base + 0x3F) continue;
            long slot = norm - base;
            if(slot == 0x00)
                traits.dmaKickChannels.add(DMA_CHANNEL_NAMES[chIdx]);
            else if(slot == 0x20 || slot == 0x30)
                traits.dmaQwcTadrChannels.add(DMA_CHANNEL_NAMES[chIdx]);
            if(norm >= GIF_CHCR_BASE && norm <= GIF_CHCR_END)
                traits.path3Initiator = true;
            traits.compositeMmioRangesHit.add("DMA_CHAN_" + DMA_CHANNEL_NAMES[chIdx]);
            break;
        }
        if(norm >= GS_PRIV_START && norm <= GS_PRIV_END) {
            long off = norm - GS_PRIV_START;
            String nm = KNOWN_GS_PRIV_REGS.get(off);
            if(nm != null) {
                traits.gsPrivRegHits.add(nm);
                traits.compositeMmioRangesHit.add("GS_PRIV_" + nm);
                if(off == 0x70L || off == 0x90L) traits.writesDispfbReg = true;
            }
        }
        if(norm == SBUS_MSCOM || norm == SBUS_SMCOM) {
            traits.compositeMmioRangesHit.add("SBUS_COM");
            traits.touchesSbus = true;
        }
        if(norm == SBUS_MSFLG || norm == SBUS_SMFLG) {
            traits.compositeMmioRangesHit.add("SBUS_FLAG");
            traits.touchesSbusFlags = true;
        }
        if(norm >= RCNT_RANGE_START && norm <= RCNT_RANGE_END) {
            traits.compositeMmioRangesHit.add("RCNT");
            traits.accessesRcnt = true;
        }
        if((norm >= VIF0_CTRL_START && norm <= VIF0_CTRL_END) ||
           (norm >= VIF1_CTRL_START && norm <= VIF1_CTRL_END)) {
            traits.compositeMmioRangesHit.add("VIF_CTRL");
            traits.accessesVifCtrl = true;
        }
        if(norm >= DMAC_GLOBAL_START && norm <= DMAC_GLOBAL_END) {
            traits.compositeMmioRangesHit.add("DMAC_GLOBAL");
            traits.accessesDmacGlobal = true;
        }
        if(norm == INTC_MASK_ADDR) {
            traits.compositeMmioRangesHit.add("INTC_MASK");
            traits.writesIntcMask = true;
        }
        if(norm == INTC_STAT_ADDR) {
            traits.compositeMmioRangesHit.add("INTC_STAT");
            traits.readsIntcStat = true;
        }
        if(norm >= SIO_RANGE_START && norm <= SIO_RANGE_END) {
            traits.compositeMmioRangesHit.add("SIO");
            traits.accessesSio = true;
        }
        if(norm >= DMAC_EXT_START && norm <= DMAC_EXT_END) {
            traits.compositeMmioRangesHit.add("DMAC_EXT");
            traits.writesDmacEnable = true;
        }
        if((norm >= MMIO_START && norm <= MMIO_END) ||
           (norm >= MMIO_GS_START && norm <= MMIO_GS_END))
            traits.accessesMMIO = true;
        if(norm >= SPR_START && norm <= SPR_END)
            traits.usesSPR = true;
    }

    // v9 Rule 120: syscall trampoline shape (addiu $v1,$zero,N; syscall; jr ra).
    private void detectSyscallTrampoline(Function func, FuncTraits traits) {
        InstructionIterator it = currentProgram.getListing().getInstructions(func.getBody(), true);
        long syscallImm = -1L;
        Map<String,Long> regConsts = new HashMap<>();
        int count = 0;
        while(it.hasNext() && count < 6) {
            Instruction inst = it.next(); count++;
            String mn = inst.getMnemonicString(); if(mn == null) continue;
            String mll = mn.toLowerCase();
            if(mll.equals("addiu") || mll.equals("li") || mll.equals("ori") || mll.equals("daddiu")) {
                Object[] dops = inst.getOpObjects(0);
                String dr = (dops!=null && dops.length>0 && dops[0] instanceof ghidra.program.model.lang.Register)
                    ? ((ghidra.program.model.lang.Register)dops[0]).getName() : null;
                long imm = -1;
                for(Object o : inst.getInputObjects())
                    if(o instanceof ghidra.program.model.scalar.Scalar)
                        imm = ((ghidra.program.model.scalar.Scalar)o).getUnsignedValue();
                if(dr != null && imm >= 0) regConsts.put(dr.toLowerCase(), imm);
            } else if(mll.equals("syscall")) {
                Long v1 = regConsts.get("v1");
                if(v1 != null) syscallImm = v1 & 0xFFL;
                for(Object o : inst.getInputObjects())
                    if(o instanceof ghidra.program.model.scalar.Scalar) {
                        long s = ((ghidra.program.model.scalar.Scalar)o).getUnsignedValue();
                        if(s > 0 && s <= 0xFFL) syscallImm = s;
                    }
                break;
            }
        }
        if(syscallImm > 0) {
            String nm = EE_SYSCALL_NAMES.get(syscallImm);
            traits.inferredSyscallImm = syscallImm;
            if(nm != null) traits.inferredName = nm;
        }
    }

    // v9 Rule 122/123 (v9.1 loosened): infinite spin = small body, has backward
    // branch, no `jr ra` return. F27 evidence: entry_0x100008 inlines MainLoop
    // and never returns — original 1-2-BB + self-branch shape missed it.
    // Also: backward branch into break/syscall/nop-only block (fail loop).
    private void detectInfiniteLoops(Function func, FuncTraits traits) {
        InstructionIterator it = currentProgram.getListing().getInstructions(func.getBody(), true);
        long entryPc = func.getEntryPoint().getOffset();
        int branchCount = 0;
        boolean selfBranchSeen = false;
        boolean failBranchSeen = false;
        boolean backwardBranchSeen = false;
        boolean returnSeen = false;
        while(it.hasNext()) {
            Instruction inst = it.next();
            String mn = inst.getMnemonicString(); if(mn == null) continue;
            String mll = mn.toLowerCase();
            // jr ra terminator detection (function returns somewhere).
            if(mll.equals("jr")) {
                for(Object o : inst.getInputObjects())
                    if(o instanceof ghidra.program.model.lang.Register &&
                       ((ghidra.program.model.lang.Register)o).getName().equalsIgnoreCase("ra"))
                        returnSeen = true;
            }
            if(!(mll.startsWith("b") || mll.equals("j") || mll.equals("jal"))) continue;
            if(mll.startsWith("bal")) continue;
            ghidra.program.model.address.Address[] flows = inst.getFlows();
            if(flows == null || flows.length == 0) continue;
            branchCount++;
            for(ghidra.program.model.address.Address fa : flows) {
                long ft = fa.getOffset();
                if(ft == entryPc || ft == inst.getAddress().getOffset()) selfBranchSeen = true;
                if(ft < inst.getAddress().getOffset() && (ft >= entryPc) &&
                   func.getBody().contains(fa)) {
                    backwardBranchSeen = true;
                    if(traits.patchCandidatePcs.size() < 32)
                        traits.patchCandidatePcs.add(inst.getAddress().getOffset() & 0xFFFFFFFFL);
                    try {
                        Instruction probe = currentProgram.getListing().getInstructionAt(fa);
                        int look = 0;
                        boolean onlyTrivial = true;
                        while(probe != null && look < 4) {
                            String pm = probe.getMnemonicString();
                            if(pm == null) break;
                            String pml = pm.toLowerCase();
                            if(!(pml.equals("nop") || pml.equals("break") || pml.equals("syscall") ||
                                 pml.startsWith("b") || pml.equals("j"))) {
                                onlyTrivial = false; break;
                            }
                            probe = probe.getNext(); look++;
                        }
                        if(onlyTrivial) failBranchSeen = true;
                    } catch(Exception ignore) {}
                }
            }
        }
        // v9.1: strict shape (≤2 branches + self-target) OR loose shape (backward
        // branch + no jr ra reachable). Loose form catches F27 inlined-MainLoop class.
        if((branchCount <= 2 && selfBranchSeen) ||
           (backwardBranchSeen && !returnSeen && traits.byteSize > 0))
            traits.isInfiniteSpinLoop = true;
        if(failBranchSeen) traits.containsInfiniteFailLoop = true;
    }

    // v9 Rule 121: backward-branch sync-wait. Small body, has backward branch,
    // load or syscall in body — F24 / F27 / F28 host-wait blocker class.
    private void detectSyncWaitLoop(Function func, FuncTraits traits) {
        if(traits.byteSize > 400) return;
        if(!traits.hasBackwardBranch) return;
        if(!(traits.loadOps > 0 || traits.hasSyscall || traits.callsPadPollCallee
             || traits.callsSifRpc)) return;
        traits.isSyncWaitLoop = true;
    }

    // v9 Rule 124 / 125: IRX loader + IOP reboot handler from callee names.
    private void detectIrxLoaderShape(Function func, FuncTraits traits) {
        int loadCount = 0;
        for(Function c : func.getCalledFunctions(monitor)) {
            String cn = c.getName();
            if(cn == null) continue;
            if(IRX_LOAD_CALLEES.contains(cn)) loadCount++;
            if(IOP_REBOOT_CALLEES.contains(cn)) traits.isIopRebootHandler = true;
        }
        traits.sifLoadModuleCallCount = loadCount;
        if(loadCount >= 2) traits.isIrxLoader = true;
        // Single call + IRX path string ref: tag too.
        if(loadCount == 1 && refsAnyIrxString(func)) traits.isIrxLoader = true;
    }

    private boolean refsAnyIrxString(Function func) {
        for(Reference ref : refManager.getReferencesFrom(func.getEntryPoint())) {
            if(!ref.getReferenceType().isData()) continue;
            try {
                Data d = currentProgram.getListing().getDataAt(ref.getToAddress());
                if(d == null) continue;
                String s = d.getDefaultValueRepresentation();
                if(s == null) continue;
                String low = s.toLowerCase();
                if(low.contains(".irx") || low.contains("rom0:")) return true;
            } catch(Exception ignore) {}
        }
        return false;
    }

    // v9 Rule 126: render frame entry name fragment match.
    private void detectRenderFrameEntry(String fname, FuncTraits traits) {
        if(fname == null) return;
        for(String frag : RENDER_FRAME_ENTRY_FRAGMENTS) {
            if(fname.contains(frag)) { traits.isRenderFrameEntry = true; return; }
        }
    }

    // v9 Rule 127: non-ctor function writing >= 4 distinct +K($a0) slots.
    private void detectStructInitializer(Function func, FuncTraits traits) {
        if(traits.isCtor) return;
        if(traits.byteSize > 800) return;
        Set<Long> slots = new HashSet<>();
        InstructionIterator it = currentProgram.getListing().getInstructions(func.getBody(), true);
        int n = 0;
        while(it.hasNext() && n < 60) {
            Instruction inst = it.next(); n++;
            String mn = inst.getMnemonicString(); if(mn == null) continue;
            String mll = mn.toLowerCase();
            if(!(mll.equals("sw") || mll.equals("sd") || mll.equals("sq") || mll.equals("sh") || mll.equals("sb"))) continue;
            Object[] aop = inst.getOpObjects(1);
            boolean baseA0 = false; long off = -1;
            if(aop != null) for(Object o : aop) {
                if(o instanceof ghidra.program.model.lang.Register &&
                   ((ghidra.program.model.lang.Register)o).getName().equalsIgnoreCase("a0"))
                    baseA0 = true;
                else if(o instanceof ghidra.program.model.scalar.Scalar)
                    off = ((ghidra.program.model.scalar.Scalar)o).getSignedValue();
            }
            if(baseA0 && off >= 0 && off < 0x400) slots.add(off);
        }
        if(slots.size() >= 4) traits.isStructInitializer = true;
    }

    // v9.1: detectAdRegImmediateStores (General Rule A port). Sharpens
    // PRIM/RGBAQ/TEX0/ZBUF/DISPFB/BITBLTBUF writer detection via const-tracked
    // sd/sw of an A+D reg id. Distinct from raw MMIO scan (which catches
    // GS priv reg writes at 0x12000000+, not GIF A+D payloads).
    private void detectAdRegImmediateStores(Function func, FuncTraits traits) {
        InstructionIterator it = currentProgram.getListing().getInstructions(func.getBody(), true);
        Map<String,Long> regConsts = new HashMap<>();
        while(it.hasNext()) {
            Instruction inst = it.next();
            String mn = inst.getMnemonicString(); if(mn == null) continue;
            String mll = mn.toLowerCase();
            if(mll.equals("addiu") || mll.equals("li") || mll.equals("ori") || mll.equals("daddiu")) {
                Object[] dops = inst.getOpObjects(0);
                String dr = (dops!=null && dops.length>0 && dops[0] instanceof ghidra.program.model.lang.Register)
                    ? ((ghidra.program.model.lang.Register)dops[0]).getName() : null;
                long imm = -1;
                for(Object o : inst.getInputObjects())
                    if(o instanceof ghidra.program.model.scalar.Scalar)
                        imm = ((ghidra.program.model.scalar.Scalar)o).getUnsignedValue();
                if(dr != null && imm >= 0) regConsts.put(dr, imm);
            } else if(mll.equals("sd") || mll.equals("sw") || mll.equals("sq")) {
                Object[] dop = inst.getOpObjects(0);
                String src = (dop!=null && dop.length>0 && dop[0] instanceof ghidra.program.model.lang.Register)
                    ? ((ghidra.program.model.lang.Register)dop[0]).getName() : null;
                if(src != null && regConsts.containsKey(src)) {
                    long v = regConsts.get(src);
                    if(v <= 0x6CL) {
                        if(v == 0x00L) traits.writesGsPrimReg = true;
                        else if(v == 0x01L) traits.writesRgbaqReg = true;
                        else if(v == 0x06L || v == 0x07L) traits.writesTex0Reg = true;
                        else if(v == 0x4EL || v == 0x4FL) traits.writesZbufReg = true;
                        else if(v == 0x59L || v == 0x5BL) traits.writesDispfbReg = true;
                        else if(v == 0x50L) traits.writesBitbltbufReg = true;
                        // Track named hit for JSON gsRegHits set.
                        String nm = KNOWN_GS_REGS.get(v);
                        if(nm != null) traits.gsRegHits.add(nm);
                    }
                }
            }
        }
    }

    // v9.1: aggressive PSMT-constant scan. Walks every const-load and matches
    // PSMT4HH (0x2C), PSMT4HL (0x24), PSMT8H (0x1B), PSMT8 (0x13), PSMT4 (0x14).
    // Looser than the existing Rule 73/87 path — accepts the constant in any
    // reg, any context.
    private void detectPsmConstantsAggressive(Function func, FuncTraits traits) {
        InstructionIterator it = currentProgram.getListing().getInstructions(func.getBody(), true);
        Map<String,Long> regConsts = new HashMap<>();
        while(it.hasNext()) {
            Instruction inst = it.next();
            String mn = inst.getMnemonicString(); if(mn == null) continue;
            String mll = mn.toLowerCase();
            long imm = -1;
            String dr = null;
            if(mll.equals("addiu") || mll.equals("li") || mll.equals("ori") ||
               mll.equals("daddiu") || mll.equals("lui")) {
                Object[] dops = inst.getOpObjects(0);
                dr = (dops!=null && dops.length>0 && dops[0] instanceof ghidra.program.model.lang.Register)
                    ? ((ghidra.program.model.lang.Register)dops[0]).getName() : null;
                for(Object o : inst.getInputObjects())
                    if(o instanceof ghidra.program.model.scalar.Scalar)
                        imm = ((ghidra.program.model.scalar.Scalar)o).getUnsignedValue();
                if(dr != null && imm >= 0) regConsts.put(dr, imm);
            }
            for(Long cBoxed : regConsts.values()) {
                long c = cBoxed & 0xFFFFFFFFL;
                if(c == 0x2CL || c == 0x24L || c == 0x1BL)
                    traits.loadsPsm4hhConstant = true;
                if(c == 0x13L) traits.loadsPsm4hhConstant = true;
                if(c > 0 && c <= 0x3FFFL) traits.tbpConstantsLoaded.add(c);
                if(EXPECTED_DBP_SET.contains(c)) {
                    for(Object[] row : EXPECTED_UPLOADS) {
                        if(((Number)row[2]).longValue() == c)
                            traits.assetUploadTagsHit.add((String)row[0]);
                    }
                }
            }
        }
    }

    // v9 Rule 131 (v9.1): stamp DC2 hardcoded role from KNOWN_DC2_FUNCTION_ADDRESSES
    // when address matches. Counter incremented separately in pre-scan so totals
    // are address-uniqueness based, not per-getTraits-call.
    private void stampDc2KnownRole(long addr, FuncTraits traits) {
        for(Object[] row : KNOWN_DC2_FUNCTION_ADDRESSES) {
            if(((Number)row[0]).longValue() != addr) continue;
            traits.dc2KnownPhase       = (String)row[2];
            traits.dc2KnownRole        = (String)row[3];
            traits.dc2KnownCriticality = (String)row[4];
            return;
        }
    }

    // v9 Rule 139: SID/FID composite recovery via $a1 lui+ori before sceSifCallRpc.
    private void detectDiscoveredSidsFids(Function func, FuncTraits traits) {
        InstructionIterator it = currentProgram.getListing().getInstructions(func.getBody(), true);
        Map<String,Long> regConsts = new HashMap<>();
        long lastA1Const = -1;
        while(it.hasNext()) {
            Instruction inst = it.next();
            String mn = inst.getMnemonicString(); if(mn == null) continue;
            String mll = mn.toLowerCase();
            if(mll.equals("lui")) {
                Object[] dops = inst.getOpObjects(0);
                String dr = (dops!=null && dops.length>0 && dops[0] instanceof ghidra.program.model.lang.Register)
                    ? ((ghidra.program.model.lang.Register)dops[0]).getName() : null;
                long imm = -1;
                for(Object o : inst.getInputObjects())
                    if(o instanceof ghidra.program.model.scalar.Scalar)
                        imm = ((ghidra.program.model.scalar.Scalar)o).getUnsignedValue();
                if(dr != null && imm >= 0) regConsts.put(dr, (imm & 0xFFFFL) << 16);
            } else if(mll.equals("ori") || mll.equals("addiu")) {
                Object[] dops = inst.getOpObjects(0);
                String dr = (dops!=null && dops.length>0 && dops[0] instanceof ghidra.program.model.lang.Register)
                    ? ((ghidra.program.model.lang.Register)dops[0]).getName() : null;
                String src = null; long imm = 0;
                for(Object o : inst.getInputObjects()) {
                    if(o instanceof ghidra.program.model.lang.Register) {
                        String rn = ((ghidra.program.model.lang.Register)o).getName();
                        if(!rn.equalsIgnoreCase(dr)) src = rn;
                    } else if(o instanceof ghidra.program.model.scalar.Scalar) {
                        imm = ((ghidra.program.model.scalar.Scalar)o).getSignedValue();
                    }
                }
                if(dr != null && src != null && regConsts.containsKey(src))
                    regConsts.put(dr, (regConsts.get(src) + imm) & 0xFFFFFFFFL);
                else if(dr != null && imm != 0)
                    regConsts.put(dr, imm & 0xFFFFFFFFL);
                if("a1".equalsIgnoreCase(dr) && regConsts.containsKey(dr))
                    lastA1Const = regConsts.get(dr);
                if("a0".equalsIgnoreCase(dr) && regConsts.containsKey(dr) && lastA1Const < 0)
                    lastA1Const = regConsts.get(dr);
            } else if(mll.equals("li")) {
                Object[] dops = inst.getOpObjects(0);
                String dr = (dops!=null && dops.length>0 && dops[0] instanceof ghidra.program.model.lang.Register)
                    ? ((ghidra.program.model.lang.Register)dops[0]).getName() : null;
                long imm = -1;
                for(Object o : inst.getInputObjects())
                    if(o instanceof ghidra.program.model.scalar.Scalar)
                        imm = ((ghidra.program.model.scalar.Scalar)o).getUnsignedValue();
                if(dr != null && imm >= 0) regConsts.put(dr, imm);
                if("a1".equalsIgnoreCase(dr)) lastA1Const = imm;
                if("a0".equalsIgnoreCase(dr) && lastA1Const < 0) lastA1Const = imm;
            } else if(mll.equals("jal") || mll.equals("jalr")) {
                Object[] tops = inst.getOpObjects(0);
                String tname = null;
                if(tops != null && tops.length > 0) {
                    if(tops[0] instanceof ghidra.program.model.address.Address) {
                        try {
                            Function c = funcManager.getFunctionAt((ghidra.program.model.address.Address)tops[0]);
                            if(c != null) tname = c.getName();
                        } catch(Exception ignore) {}
                    }
                }
                if(tname != null && (tname.equals("sceSifCallRpc") || tname.equals("sceSifBindRpc"))) {
                    Long a0 = regConsts.get("a0");
                    if(a0 != null) {
                        traits.discoveredRpcSids.add(a0 & 0xFFFFFFFFL);
                        long fa = func.getEntryPoint().getOffset() & 0xFFFFFFFFL;
                        discoveredSidToCallers.computeIfAbsent(a0 & 0xFFFFFFFFL, k -> new LinkedHashSet<>()).add(fa);
                    }
                    Long a1 = regConsts.get("a1");
                    if(a1 != null && tname.equals("sceSifCallRpc")) {
                        traits.discoveredRpcFids2.add(a1 & 0xFFFFFFFFL);
                        long fa = func.getEntryPoint().getOffset() & 0xFFFFFFFFL;
                        discoveredFidToCallers.computeIfAbsent(a1 & 0xFFFFFFFFL, k -> new LinkedHashSet<>()).add(fa);
                    }
                }
                lastA1Const = -1;
            }
        }
    }

    // v9 Rule 128: scan non-.text blocks for runs of function-entry pointers.
    private void scanFunctionPointerTables(List<FuncResult> results,
                                            Map<Long,FuncResult> byAddr) {
        Set<Long> entryAddrs = new HashSet<>();
        for(FuncResult r : results) entryAddrs.add(r.address & 0xFFFFFFFFL);
        Map<Long, Long> aliasMap = new HashMap<>();
        for(Long e : entryAddrs) aliasMap.put(e, e);
        for(Long e : entryAddrs)
            for(int tag = 1; tag <= 0xF; tag++) aliasMap.putIfAbsent(e | (long)tag, e);
        for(MemoryBlock blk : memory.getBlocks()) {
            if(!blk.isInitialized()) continue;
            String bn = blk.getName().toLowerCase();
            if(bn.equals(".text") || bn.equals("text")) continue;
            long start = blk.getStart().getOffset();
            long end   = blk.getEnd().getOffset();
            long size  = end - start + 1;
            if(size < 16) continue;
            try {
                byte[] data = new byte[(int)Math.min(size, 1 << 22)];
                blk.getBytes(blk.getStart(), data);
                long runStart = -1;
                List<long[]> runEntries = new ArrayList<>();
                for(int i = 0; i + 4 <= data.length; i += 4) {
                    long v = ((long)(data[i] & 0xFF))
                           | ((long)(data[i+1] & 0xFF) << 8)
                           | ((long)(data[i+2] & 0xFF) << 16)
                           | ((long)(data[i+3] & 0xFF) << 24);
                    Long resolved = aliasMap.get(v);
                    if(resolved == null && (v & 0xFL) != 0) {
                        Long maskTry = aliasMap.get(v & ~0xFL);
                        if(maskTry != null) resolved = maskTry;
                    }
                    if(resolved != null) {
                        if(runStart < 0) runStart = start + i;
                        runEntries.add(new long[]{ resolved & 0xFFFFFFFFL, 0L });
                    } else {
                        if(runEntries.size() >= 3 && v == 0L) continue;
                        if(runEntries.size() >= 3)
                            functionPointerTables.put(runStart, new ArrayList<>(runEntries));
                        runStart = -1;
                        runEntries.clear();
                    }
                }
                if(runEntries.size() >= 3)
                    functionPointerTables.put(runStart, new ArrayList<>(runEntries));
            } catch(Exception ignore) {}
        }
        // Synthesise class names for stripped binaries.
        for(Map.Entry<Long,List<long[]>> e : functionPointerTables.entrySet()) {
            long tableAddr = e.getKey() & 0xFFFFFFFFL;
            String className = String.format("Class_0x%08X", tableAddr);
            int slot = 0;
            for(long[] row : e.getValue()) {
                long fnAddr = row[0] & 0xFFFFFFFFL;
                FuncResult fr = byAddr.get(fnAddr);
                if(fr != null && fr.traits != null) {
                    boolean stripped = fr.name == null || fr.name.startsWith("FUN_") || fr.name.startsWith("sub_");
                    if(stripped && fr.traits.inferredClassName == null) {
                        fr.traits.inferredClassName = className;
                        fr.traits.inferredVtableSlot = slot;
                    }
                }
                slot++;
            }
        }
        // DISPATCH_TABLE_TARGET / TABLE_DISPATCH_CALL tags.
        Set<Long> dispatchTargets = new HashSet<>();
        for(List<long[]> entries : functionPointerTables.values())
            for(long[] row : entries) dispatchTargets.add(row[0] & 0xFFFFFFFFL);
        for(FuncResult r : results) {
            if(dispatchTargets.contains(r.address & 0xFFFFFFFFL)) {
                if(!r.tags.contains("DISPATCH_TABLE_TARGET")) {
                    r.tags.add("DISPATCH_TABLE_TARGET");
                    dispatchTableTargetCount++;
                }
            }
            if(r.traits == null) continue;
            if(r.traits.indirectCallT9Count == 0 && r.traits.virtualDispatchSites.isEmpty())
                continue;
            for(long[] cl : r.traits.constLoads) {
                long v = cl[1] & 0xFFFFFFFFL;
                if(functionPointerTables.containsKey(v)) {
                    r.traits.tableDispatchSites.add(String.format("0x%08X", v));
                    if(!r.tags.contains("TABLE_DISPATCH_CALL")) {
                        r.tags.add("TABLE_DISPATCH_CALL");
                        tableDispatchCallCount++;
                    }
                }
            }
        }
    }

    // v9 Rule 129: greedy module clustering. Bidirectional jal edges.
    private void assignModuleIds(List<FuncResult> results) {
        Map<Long, Set<Long>> adj = new HashMap<>();
        for(FuncResult r : results) {
            if(r.traits == null) continue;
            long a = r.address & 0xFFFFFFFFL;
            Set<Long> nbrs = adj.computeIfAbsent(a, k -> new HashSet<>());
            for(long[] site : r.traits.jalSites) {
                long t = site[1] & 0xFFFFFFFFL;
                if(t == 0xFFFFFFFFL) continue;
                nbrs.add(t);
                adj.computeIfAbsent(t, k -> new HashSet<>()).add(a);
            }
        }
        Map<Long, Long> compId = new HashMap<>();
        for(FuncResult r : results) {
            long a = r.address & 0xFFFFFFFFL;
            if(compId.containsKey(a)) continue;
            Deque<Long> q = new ArrayDeque<>();
            Set<Long> seen = new HashSet<>();
            q.add(a); seen.add(a);
            long minAddr = a;
            while(!q.isEmpty()) {
                long cur = q.poll();
                if(cur < minAddr) minAddr = cur;
                Set<Long> ns = adj.get(cur);
                if(ns == null) continue;
                for(long n : ns) if(seen.add(n)) q.add(n);
            }
            for(long n : seen) compId.put(n, minAddr);
        }
        Map<Long, Integer> idMap = new HashMap<>();
        int idCounter = 0;
        for(FuncResult r : results) {
            long a = r.address & 0xFFFFFFFFL;
            Long cid = compId.get(a);
            if(cid == null) continue;
            Integer mid = idMap.get(cid);
            if(mid == null) { mid = idCounter++; idMap.put(cid, mid); }
            if(r.traits != null) r.traits.moduleId = mid;
            moduleClusters.computeIfAbsent(mid, k -> new LinkedHashSet<>()).add(a);
        }
    }

    // v9 Rule 130: name-prefix module index. Length 2-6, occur >= 5 times.
    private void buildNamePrefixModules(List<FuncResult> results) {
        Map<String, List<Long>> byPrefix = new HashMap<>();
        for(FuncResult r : results) {
            if(r.name == null || r.name.isEmpty()) continue;
            String n = r.name;
            if(n.startsWith("sub_") || n.startsWith("FUN_")) continue;
            int maxLen = Math.min(6, n.length());
            for(int len = 2; len <= maxLen; len++) {
                String prefix = n.substring(0, len);
                char last = prefix.charAt(len-1);
                if(!Character.isLetter(last) && last != '_') continue;
                byPrefix.computeIfAbsent(prefix, k -> new ArrayList<>()).add(r.address & 0xFFFFFFFFL);
            }
        }
        List<Map.Entry<String,List<Long>>> kept = new ArrayList<>();
        for(Map.Entry<String,List<Long>> e : byPrefix.entrySet())
            if(e.getValue().size() >= 5) kept.add(e);
        kept.sort((a,b) -> Integer.compare(b.getKey().length(), a.getKey().length()));
        Set<Long> assigned = new HashSet<>();
        for(Map.Entry<String,List<Long>> e : kept) {
            List<Long> taken = new ArrayList<>();
            for(Long a : e.getValue()) if(assigned.add(a)) taken.add(a);
            if(taken.size() >= 5) {
                Collections.sort(taken);
                namePrefixModules.put(e.getKey(), taken);
            }
        }
    }

    // v9 Rule 134: tag every function that participates in a DC2 call chain.
    private void tagDc2CallChains(List<FuncResult> results) {
        for(Object[] row : DC2_CALL_CHAINS) {
            String chainTag = (String)row[0];
            String[] stations = (String[])row[1];
            for(FuncResult r : results) {
                if(r.name == null) continue;
                for(String s : stations) {
                    if(r.name.contains(s)) {
                        if(r.traits != null) r.traits.dc2CallChainsTagged.add(chainTag);
                        if(!r.tags.contains("DC2_CHAIN_" + chainTag.toUpperCase()))
                            r.tags.add("DC2_CHAIN_" + chainTag.toUpperCase());
                        break;
                    }
                }
            }
        }
    }

    // v9 Rule 137: prioritise function tags for TOML comment generation.
    private String prioritizeTagsForComment(List<String> tags, int max) {
        if(tags == null || tags.isEmpty()) return "";
        List<String> sorted = new ArrayList<>(tags);
        sorted.sort((a,b) -> Integer.compare(
            TAG_PRIORITY.getOrDefault(b, 0),
            TAG_PRIORITY.getOrDefault(a, 0)));
        StringBuilder sb = new StringBuilder();
        for(int i = 0; i < sorted.size() && i < max; i++) {
            if(i > 0) sb.append(",");
            sb.append(sorted.get(i));
        }
        return sb.toString();
    }

    // v9 Rule 136: synthetic focus score for fallback when no bullseyes fire.
    private long scoreFocus(FuncTraits t) {
        if(t == null) return 0;
        long score = 0;
        if(t.isCtor)                       score += 30;
        if("CRITICAL".equals(t.ctorRiskTier)) score += 50;
        if("HIGH".equals(t.ctorRiskTier))     score += 30;
        if(t.isRenderFrameEntry)           score += 80;
        if(t.isFrameClockDriver)           score += 50;
        if(t.isInfiniteSpinLoop)           score += 40;
        if(t.isSyncWaitLoop)               score += 40;
        if(t.bitbltbufMacroSequence)       score += 70;
        if(t.gifTagInlineBuilder)          score += 60;
        if(t.dmaSourceChainTagBuilder)     score += 50;
        if(t.dmaChcrStartKick)             score += 70;
        if(t.isIrxLoader)                  score += 35;
        if(t.isBitbltbufT4hhUploader)      score += 90;
        if(t.isCtorMultiFieldInit)         score += 40;
        if(t.isLifecycleLazyInit)          score += 40;
        if(t.drawingChainDepth >= 0 && t.drawingChainDepth <= 6) score += 50;
        if("BLOCKER".equals(t.dc2KnownCriticality)) score += 100;
        if("HIGH".equals(t.dc2KnownCriticality))    score += 60;
        if("MEDIUM".equals(t.dc2KnownCriticality))  score += 30;
        if(t.dc2HostWaitCandidate)         score += 80;
        score += Math.min(t.calleeNames.size(), 20);
        score += Math.min(t.callers.size(), 10);
        return score;
    }

    // =========================================================
    // CATEGORY HEURISTICS
    // =========================================================
    private String assignCategory(FuncTraits t) {
        boolean calls=(t.calleeCount>0||t.callOps>0);
        if(!calls&&t.byteSize<100&&!t.writesToGlobal) return "GETTER_OR_STUB";
        if(t.usesCop2||t.floatOps>=6||(t.mathOps>10&&!calls)) return "MATH_VECTORS";
        if(t.branchOps>=4||t.returnPaths>=2) return "STATE_MACHINES";
        if(t.writesToGlobal&&t.loadOps>0&&calls) return "GAME_LOGIC";
        if(calls&&t.byteSize<200&&t.branchOps<=2) return "WRAPPER";
        return "UNCATEGORIZED";
    }

    // =========================================================
    // FIREWALLS
    // =========================================================
    private boolean isRadarFirewalled(Function func) {
        Address key=func.getEntryPoint();
        Boolean c=staticFwCache.get(key);if(c!=null)return c;
        String name=func.getName();
        if(name.startsWith("sceVu0")){staticFwCache.put(key,false);return false;}
        for(String p:RADAR_FIREWALL_PREFIXES) if(name.startsWith(p)){staticFwCache.put(key,true);return true;}
        for(String p:BIOS_FIREWALL_PREFIXES) if(name.startsWith(p)){staticFwCache.put(key,true);return true;}
        staticFwCache.put(key,false);return false;
    }

    // [FIX v4] containsSyscall and containsCOP0 removed - folded into getTraits() main loop.
    // Their logic now populates traits.hasSyscall and traits.hasCOP0 fields.
    // isKernelInternal replaced with inline traits.hasSyscall||traits.hasCOP0.
    // referencesIopModule replaced with traits.refsIopModuleString.

    // =========================================================
    // UNIFIED CONFIG OUTPUT
    // =========================================================
    private void writeUnifiedConfig(File outFile,File step1Config,
                                    List<String> newStubs,List<String> newSkips,
                                    List<FuncResult> results,
                                    Map<Long,FuncResult> byAddr) throws IOException {
        // v9 Rule 138: build address -> FuncResult lookup by name@addr token,
        // so each spliced stub/skip line can carry a top-tag comment.
        Map<String,FuncResult> byToken = new HashMap<>();
        for(FuncResult r : results) {
            byToken.put(r.name + "@" + hex(r.address), r);
        }
        List<String> lines=new ArrayList<>();
        BufferedReader reader=new BufferedReader(new FileReader(step1Config));
        String line;while((line=reader.readLine())!=null)lines.add(line);
        reader.close();
        int stubsClose=-1,skipClose=-1;
        boolean inStubs=false,inSkip=false;
        for(int i=0;i<lines.size();i++) {
            String t=lines.get(i).trim();
            if(t.startsWith("stubs"))inStubs=true;
            if(t.startsWith("skip")&&!t.startsWith("skip_count"))inSkip=true;
            if(t.equals("]")){if(inStubs){stubsClose=i;inStubs=false;}else if(inSkip){skipClose=i;inSkip=false;}}
        }
        List<String> stubLines=new ArrayList<>();
        if(!newStubs.isEmpty()){
            stubLines.add("  # --- Triage Enricher v9 additions ---");
            for(String s:newStubs){
                FuncResult r = byToken.get(s);
                String comment = (r != null) ? prioritizeTagsForComment(r.tags, 4) : "";
                if(!comment.isEmpty())
                    stubLines.add("  \""+s+"\",  # "+comment);
                else
                    stubLines.add("  \""+s+"\",");
            }
        }
        List<String> skipLines=new ArrayList<>();
        if(!newSkips.isEmpty()){
            skipLines.add("  # --- Triage Enricher v9 additions ---");
            for(String s:newSkips){
                FuncResult r = byToken.get(s);
                String comment = (r != null) ? prioritizeTagsForComment(r.tags, 4) : "";
                if(!comment.isEmpty())
                    skipLines.add("  \""+s+"\",  # "+comment);
                else
                    skipLines.add("  \""+s+"\",");
            }
        }
        if(skipClose>=0&&!skipLines.isEmpty()){
            lines.addAll(skipClose,skipLines);
            if(stubsClose>=skipClose)stubsClose+=skipLines.size();
        }
        if(stubsClose>=0&&!stubLines.isEmpty())lines.addAll(stubsClose,stubLines);
        lines.add(0,"# Unified config: "+step1Config.getName()+" + "+newStubs.size()+" stubs + "+newSkips.size()+" skips (Enricher v9)");
        for(int i=0;i<lines.size();i++){
            String l=lines.get(i);
            if(l.startsWith("stub_count =")){
                int old=Integer.parseInt(l.split("=")[1].trim());
                lines.set(i,"stub_count = "+(old+newStubs.size()));
            } else if(l.startsWith("skip_count =")){
                int old=Integer.parseInt(l.split("=")[1].trim());
                lines.set(i,"skip_count = "+(old+newSkips.size()));
            } else if(l.startsWith("input =") || l.startsWith("output_file =") || l.startsWith("output =") || l.startsWith("ghidra_output =")) {
                // Sanitize hardcoded absolute paths to relative paths
                int q1 = l.indexOf('"');
                int q2 = l.lastIndexOf('"');
                if (q1 >= 0 && q2 > q1) {
                    String path = l.substring(q1 + 1, q2);
                    String file = new File(path).getName();
                    lines.set(i, l.substring(0, q1 + 1) + "./" + file + "\"");
                }
            }
        }
        // v9 Rule 137: append [triage_advisory] block. ps2recomp.exe will ignore
        // unknown sections, so this serves as machine-readable hints for the
        // report tool and human triage.
        List<String> advisory = buildTriageAdvisoryBlock(results);
        PrintWriter w=new PrintWriter(new FileWriter(outFile));
        for(String l:lines)w.println(l);
        for(String l:advisory)w.println(l);
        w.close();
    }

    // v9 Rule 137: build [triage_advisory] appendix lines.
    private List<String> buildTriageAdvisoryBlock(List<FuncResult> results) {
        List<String> out = new ArrayList<>();
        List<String> nopList = new ArrayList<>();
        List<String> patchList = new ArrayList<>();
        List<String> forceRecompileList = new ArrayList<>();
        List<String> mustImplementList = new ArrayList<>();
        List<String> dc2BlockersList = new ArrayList<>();
        List<String> dc2HostWaitList = new ArrayList<>();
        List<String> bullseyeUploadList = new ArrayList<>();
        List<String> patchCandidateLines = new ArrayList<>();
        for(FuncResult r : results) {
            if(r.traits == null) continue;
            FuncTraits t = r.traits;
            String token = r.name + "@" + hex(r.address);
            String tagCmt = prioritizeTagsForComment(r.tags, 4);
            String suffix = tagCmt.isEmpty() ? "" : "  # " + tagCmt;
            // nop = libgcc/process-terminator that's currently STUB and provably side-effect-free
            if(t.isLibgccIntrinsic && "STUB".equals(r.disposition))
                nopList.add("  \""+token+"\","+suffix);
            // patch = small functions with $a1 buffer convention violation
            if(t.writesToA1Buffer && t.byteSize < 80)
                patchList.add("  \""+token+"\","+suffix);
            // force_recompile = bullseyes / critical ctors / lifecycle guards / DC2 BLOCKERs
            boolean fr = t.isBitbltbufT4hhUploader || t.isCtorMultiFieldInit ||
                         t.isLifecycleLazyInit || t.ctorWritesVTablePointer ||
                         t.isRenderFrameEntry || t.bitbltbufMacroSequence ||
                         t.isSceGifPkRefLoadImage || t.isTopPriorityFix ||
                         "BLOCKER".equals(t.dc2KnownCriticality);
            if(fr) forceRecompileList.add("  \""+token+"\","+suffix);
            // must_implement = sceVu0 helpers + DC2 HIGH criticality
            if(t.isSceVu0Helper ||
               "HIGH".equals(t.dc2KnownCriticality) || "BLOCKER".equals(t.dc2KnownCriticality))
                mustImplementList.add("  \""+token+"\","+suffix);
            // dc2_blockers
            if("BLOCKER".equals(t.dc2KnownCriticality))
                dc2BlockersList.add("  \""+token+"\","+suffix);
            // dc2_host_wait
            if(t.dc2HostWaitCandidate)
                dc2HostWaitList.add("  \""+token+"\","+suffix);
            // bullseye_upload — functions matching expected_uploads dpsm + dbp
            if(!t.assetUploadTagsHit.isEmpty())
                bullseyeUploadList.add("  \""+token+"\","+suffix);
            // patch instruction candidates for backward branches
            for(Long pc : t.patchCandidatePcs) {
                if(patchCandidateLines.size() >= 256) break;
                String reason = t.isSyncWaitLoop ? "BACKWARD_BRANCH_SYNC_WAIT" :
                                t.containsInfiniteFailLoop ? "INFINITE_FAIL_LOOP" :
                                t.isInfiniteSpinLoop ? "INFINITE_SPIN_LOOP" :
                                "BACKWARD_BRANCH";
                patchCandidateLines.add(String.format(
                    "  {address = \"0x%08X\", value = \"0x00000000\"},  # %s in %s",
                    pc & 0xFFFFFFFFL, reason, token));
            }
        }
        out.add("");
        out.add("# ============================================================");
        out.add("# [triage_advisory] - Enricher v9 (DC2). Hints only.");
        out.add("# ps2recomp.exe ignores this section. Consumed by report tool.");
        out.add("# Each line: \"name@0xADDR\",  # TOP_TAG,NEXT_TAG,...");
        out.add("# ============================================================");
        out.add("[triage_advisory]");
        emitTomlList(out, "nop",                  nopList);
        emitTomlList(out, "patch",                patchList);
        emitTomlList(out, "force_recompile",      forceRecompileList);
        emitTomlList(out, "must_implement",       mustImplementList);
        emitTomlList(out, "dc2_blockers",         dc2BlockersList);
        emitTomlList(out, "dc2_host_wait",        dc2HostWaitList);
        emitTomlList(out, "bullseye_upload",      bullseyeUploadList);
        // Commented patches block — humans uncomment manually after verifying.
        out.add("");
        out.add("# [patches]");
        out.add("# instructions = [");
        for(String l : patchCandidateLines) out.add("#" + l);
        out.add("# ]");
        return out;
    }

    private void emitTomlList(List<String> out, String name, List<String> entries) {
        out.add("");
        out.add(name + " = [");
        for(String e : entries) out.add(e);
        out.add("]");
    }

    // v8 Rule 109: cheap line-scanning reader. Extracts {address: "disposition|category"}
    // pairs from a prior triage_map.json without bringing in a JSON dependency.
    private Map<Long,String> loadPriorTriageMapCats(File f) throws IOException {
        Map<Long,String> out = new HashMap<>();
        BufferedReader r = new BufferedReader(new FileReader(f));
        String line;
        while((line = r.readLine()) != null) {
            int aIdx = line.indexOf("\"address\":");
            int cIdx = line.indexOf("\"category\":");
            int dIdx = line.indexOf("\"disposition\":");
            if(aIdx < 0 || (cIdx < 0 && dIdx < 0)) continue;
            int q1 = line.indexOf('"', aIdx + 10);
            int q2 = line.indexOf('"', q1 + 1);
            if(q1 < 0 || q2 <= q1) continue;
            long addr;
            try { addr = Long.parseLong(line.substring(q1+1, q2).replace("0x",""), 16); }
            catch(NumberFormatException ex) { continue; }
            String cat = "?", disp = "?";
            if(cIdx >= 0) {
                int c1 = line.indexOf('"', cIdx + 11); int c2 = line.indexOf('"', c1 + 1);
                if(c1 >= 0 && c2 > c1) cat = line.substring(c1+1, c2);
            }
            if(dIdx >= 0) {
                int d1 = line.indexOf('"', dIdx + 14); int d2 = line.indexOf('"', d1 + 1);
                if(d1 >= 0 && d2 > d1) disp = line.substring(d1+1, d2);
            }
            out.put(addr & 0xFFFFFFFFL, disp + "|" + cat);
        }
        r.close();
        return out;
    }

    // =========================================================
    // JSON OUTPUT - v3 extended with new fields
    // =========================================================
    private void writeTriageJson(File outFile,List<FuncResult> results,
                                 String elfHash,long gpValue,
                                 int totalFuncs,int uncategorized) throws IOException {
        PrintWriter w=new PrintWriter(new FileWriter(outFile));
        w.println("{");
        w.println("  \"schema_version\": 9.0,");
        w.println("  \"elf_hash\": \""+elfHash+"\",");
        if(gpValue!=0)w.println("  \"global_pointer\": \""+hex(gpValue)+"\",");
        w.println("  \"text_range\": { \"start\": \""+hex(textStart)+"\", \"end\": \""+hex(textEnd)+"\" },");
        w.println("  \"mainloop_shield_size\": "+mainLoopShield.size()+",");
        w.println("  \"game_override_imported\": "+gameOverrideImportedCount+",");
        w.println("  \"statistics\": {");
        w.println("    \"total_functions\": "+totalFuncs+",");
        w.println("    \"uncategorized_from_step1\": "+uncategorized+",");
        w.println("    \"enriched_count\": "+results.size()+",");
        w.println("    \"safe_leaf\": "+safeLeafCount+",");
        w.println("    \"acc_hazard\": "+accHazardCount+",");
        w.println("    \"mmio_access\": "+mmioCount+",");
        w.println("    \"smc_hazard\": "+smcHazardCount+",");
        w.println("    \"spr_sync\": "+sprSyncCount+",");
        w.println("    \"busy_wait\": "+busyWaitCount+",");
        w.println("    \"vcallms\": "+vcallmsCount+",");
        w.println("    \"jump_tables\": "+jumpTableCount+",");
        w.println("    \"orphan_code\": "+orphanCount+",");
        w.println("    \"convention_violation\": "+conventionViolationCount+",");
        w.println("    \"init_large_func\": "+initLargeFuncCount+",");
        w.println("    \"dma_tte_risk\": "+dmaTteRiskCount+",");
        w.println("    \"iop_rpc_dispatch\": "+iopRpcCount+",");
        w.println("    \"archive_io\": "+archiveIoCount+",");
        w.println("    \"pad_poll_loop\": "+padPollLoopCount+",");
        w.println("    \"thread_sync_point\": "+threadSyncCount+",");
        w.println("    \"ctor_field_writer\": "+ctorFieldWriterCount+",");
        w.println("    \"vtable_setter\": "+vtableSetterCount+",");
        w.println("    \"a0_passthrough_returner\": "+a0PassthroughCount+",");
        w.println("    \"process_terminator\": "+procTerminatorCount+",");
        w.println("    \"libgcc_intrinsic\": "+libgccIntrinsicCount+",");
        w.println("    \"gif_path3_hazard\": "+gifPath3HazardCount+",");
        w.println("    \"z_buffer_alias_risk\": "+zBufferAliasCount+",");
        w.println("    \"mpeg_decoder_trap\": "+mpegTrapCount+",");
        w.println("    \"dispfb_writer\": "+dispfbWriterCount+",");
        w.println("    \"vif1_taghi_builder\": "+vif1TagHiBuilderCount+",");
        w.println("    \"tail_call_indirect\": "+tailCallIndirectCount+",");
        w.println("    \"indirect_call_t9_funcs\": "+indirectCallT9Funcs+",");
        w.println("    \"poll_return_consumer\": "+pollTargetCount+",");
        w.println("    \"is_sce_gif_pk_ref_load_image\": "+isSceGifPkRefLoadImageCount+",");
        w.println("    \"path3_initiator\": "+path3InitiatorCount+",");
        w.println("    \"sce_gif_pk_family\": "+sceGifPkFamilyCount+",");
        w.println("    \"tex0_reg_writer\": "+tex0WriterCount+",");
        w.println("    \"prim_reg_reader\": "+primReaderCount+",");
        w.println("    \"rgbaq_writer\": "+rgbaqWriterCount+",");
        w.println("    \"dma_kick_pattern\": "+dmaKickCount+",");
        w.println("    \"dma_qwc_tadr_writer\": "+dmaQwcTadrCount+",");
        w.println("    \"microcode_uploader\": "+microcodeUploaderCount+",");
        w.println("    \"audio_rpc_handler\": "+audioRpcCount+",");
        w.println("    \"meswin_loader\": "+meswinLoaderCount+",");
        w.println("    \"mc_transition_gate\": "+mcGateCount+",");
        w.println("    \"top_priority_fix\": "+topPriorityFixCount+",");
        w.println("    \"ipu_mmio\": "+ipuMmioCount+",");
        w.println("    \"writes_ipu_cmd\": "+writesIpuCmdCount+",");
        w.println("    \"gif_path3_reg\": "+gifP3RegCount+",");
        w.println("    \"gif_fifo_writer\": "+gifFifoWriteCount+",");
        w.println("    \"vif1_fifo_writer\": "+vif1FifoWriteCount+",");
        w.println("    \"vif0_fifo_writer\": "+vif0FifoWriteCount+",");
        w.println("    \"vu_micromem\": "+vuMicromemCount+",");
        w.println("    \"vu_datamem\": "+vuDatamemCount+",");
        w.println("    \"sbus_iop_comm\": "+sbusCount+",");
        w.println("    \"psmt4hh_reference\": "+psm4hhCount+",");
        w.println("    \"vif_opcode_builder\": "+vifOpcodeBuilderCount+",");
        w.println("    \"vif_mpg_builder\": "+vifMpgBuilderCount+",");
        w.println("    \"vif_mscal_builder\": "+vifMscalBuilderCount+",");
        w.println("    \"vif_direct_builder\": "+vifDirectBuilderCount+",");
        w.println("    \"vif_unpack_builder\": "+vifUnpackBuilderCount+",");
        w.println("    \"dma_tag_builder\": "+dmaTagBuilderCount+",");
        // v7 stats
        w.println("    \"dispfb_sdk_writer\": "+dispfbSdkWriterCount+",");
        w.println("    \"path3_kick_via_dma_api\": "+path3KickViaApiCount+",");
        w.println("    \"gs_irq_handler_name_funcs\": "+gsIrqHandlerCount+",");
        w.println("    \"gs_irq_safe_stub_funcs\": "+gsIrqSafeStubCount+",");
        w.println("    \"runtime_confirmed\": "+runtimeConfirmedCount+",");
        w.println("    \"runtime_dormant_global\": "+runtimeDormantCount+",");
        w.println("    \"runtime_menu_only\": "+runtimeMenuOnlyCount+",");
        w.println("    \"tbp_runtime_confirmed_funcs\": "+tbpRuntimeConfirmedFuncCount+",");
        w.println("    \"gs_evidence_checkpoints\": "+gsEvidence.checkpoints.size()+",");
        // v7.1 stats
        w.println("    \"ctor_multi_field_initializer\": "+ctorMultiFieldInitCount+",");
        w.println("    \"lifecycle_lazy_init_guard\": "+lifecycleLazyInitCount+",");
        w.println("    \"bitbltbuf_t4hh_uploader\": "+bitbltbufT4hhUploaderCount+",");
        w.println("    \"drawing_chain_funcs\": "+drawingChainCount+",");
        // v8 stats
        w.println("    \"ctor_risk_critical\": "+ctorCriticalCount+",");
        w.println("    \"ctor_risk_high\": "+ctorHighCount+",");
        w.println("    \"ctor_risk_medium\": "+ctorMediumCount+",");
        w.println("    \"ctor_assigned_to_global\": "+ctorAssignedGlobalCount+",");
        w.println("    \"ctor_installs_vtable\": "+ctorInstallsVtableCount+",");
        w.println("    \"ctor_dual_call_mode\": "+ctorDualCallModeCount+",");
        w.println("    \"virtual_dispatch_sites\": "+virtualDispatchSiteCount+",");
        w.println("    \"virtual_dispatch_funcs\": "+virtualDispatchFuncCount+",");
        w.println("    \"pad_button_mask_consumer\": "+padButtonMaskConsumerCount+",");
        w.println("    \"gif_nloop_double_count_risk\": "+gifNloopDoubleCountRiskCount+",");
        w.println("    \"file_path_sprintf_source\": "+filePathSprintfCount+",");
        w.println("    \"frame_clock_driver\": "+frameClockDriverCount+",");
        w.println("    \"sce_vu0_helper_mustimpl\": "+sceVu0HelperCount+",");
        w.println("    \"asset_upload_trace_funcs\": "+assetUploadTraceFuncCount+",");
        w.println("    \"override_classified\": "+overrideClassifiedCount+",");
        w.println("    \"override_retire_candidate\": "+overrideRetireCount+",");
        w.println("    \"dispfb_writer_via_sdk_caller\": "+dispfbWriterViaSdkCallerCount+",");
        w.println("    \"dma_kick_via_sdk_caller\": "+dmaKickViaSdkCallerCount+",");
        w.println("    \"return_written_to_global_funcs\": "+returnWrittenToGlobalCount+",");
        w.println("    \"auto_extended_dc2_globals\": "+autoExtendedDc2GlobalsCount+",");
        w.println("    \"class_registry_count\": "+classRegistry.size()+",");
        // v9 stats
        w.println("    \"gif_tag_inline_builder\": "+gifTagInlineBuilderCount+",");
        w.println("    \"bitbltbuf_macro_sequence\": "+bitbltbufMacroSeqCount+",");
        w.println("    \"dma_chcr_start_kick\": "+dmaChcrStartKickCount+",");
        w.println("    \"dma_source_chain_tag_builder\": "+dmaSourceChainBuilderCount+",");
        w.println("    \"composite_mmio_recovered\": "+compositeMmioRecoveryCount+",");
        w.println("    \"syscall_trampoline\": "+syscallTrampolineCount+",");
        w.println("    \"backward_branch_sync_wait\": "+backwardSyncWaitCount+",");
        w.println("    \"infinite_spin_loop\": "+infiniteSpinLoopCount+",");
        w.println("    \"infinite_fail_loop\": "+infiniteFailLoopCount+",");
        w.println("    \"irx_loader\": "+irxLoaderCount+",");
        w.println("    \"iop_reboot_handler\": "+iopRebootHandlerCount+",");
        w.println("    \"render_frame_entry\": "+renderFrameEntryCount+",");
        w.println("    \"struct_initializer\": "+structInitializerCount+",");
        w.println("    \"dispatch_table_target\": "+dispatchTableTargetCount+",");
        w.println("    \"table_dispatch_call\": "+tableDispatchCallCount+",");
        w.println("    \"dc2_host_wait_candidate\": "+dc2HostWaitCandidateCount+",");
        w.println("    \"dc2_known_address_matched\": "+dc2KnownAddressMatched+",");
        w.println("    \"discovered_iop_sid_funcs\": "+discoveredRpcSidCount+",");
        w.println("    \"function_pointer_tables\": "+functionPointerTables.size()+",");
        w.println("    \"module_clusters\": "+moduleClusters.size()+",");
        w.println("    \"name_prefix_modules\": "+namePrefixModules.size());
        w.println("  },");

        // v5 Rule 55: known DC2 gp-relative globals (labels for literal_refs decode).
        w.println("  \"known_dc2_globals\": {");
        {
            boolean firstG=true;
            for(Map.Entry<Long,String> e : KNOWN_DC2_GP_OFFSETS.entrySet()) {
                if(!firstG) w.println(","); firstG=false;
                w.print("    \"0x"+String.format("%08X", e.getKey()&0xFFFFFFFFL)+"\": \""+e.getValue()+"\"");
            }
        }
        w.println("\n  },");

        // v8 Rule 95: auto-extended DC2 globals discovered via return-to-global tracking.
        w.println("  \"auto_extended_dc2_globals\": {");
        {
            boolean f=true;
            for(Map.Entry<Long,String> e : autoExtendedDc2Globals.entrySet()) {
                if(!f) w.println(","); f=false;
                w.print("    \"0x"+String.format("%08X", e.getKey()&0xFFFFFFFFL)+"\": "+jsonString(e.getValue()));
            }
        }
        w.println("\n  },");

        // v8 Rule 107: phase trace env-var flag inventory.
        w.println("  \"phase_trace_flags\": [");
        for(int i=0; i<PHASE_TRACE_FLAGS.length; i++) {
            w.print("    "+jsonString(PHASE_TRACE_FLAGS[i]));
            w.println(i<PHASE_TRACE_FLAGS.length-1 ? "," : "");
        }
        w.println("  ],");

        // v8 Rule 106: build invariants.
        w.println("  \"build_invariants\": {");
        w.println("    \"build_cmd\": "+jsonString(BUILD_CMD)+",");
        w.println("    \"do_not_modify\": [");
        for(int i=0; i<BUILD_DO_NOT_MODIFY.length; i++) {
            w.print("      "+jsonString(BUILD_DO_NOT_MODIFY[i]));
            w.println(i<BUILD_DO_NOT_MODIFY.length-1 ? "," : "");
        }
        w.println("    ]");
        w.println("  },");

        // v8 Rule 104: expected uploads per phase. Consumers may compare
        // against gs_runtime_evidence.bitbltbuf_dpsms_union to spot gaps.
        w.println("  \"current_phase_inputs\": {");
        w.println("    \"expected_uploads\": [");
        for(int i=0; i<EXPECTED_UPLOADS.length; i++) {
            Object[] row = EXPECTED_UPLOADS[i];
            w.print("      {\"tag\": "+jsonString((String)row[0])+
                    ", \"dpsm\": \""+String.format("0x%02X", ((Number)row[1]).intValue())+"\""+
                    ", \"dbp\": \""+String.format("0x%08X", ((Number)row[2]).longValue())+"\""+
                    ", \"phase\": "+jsonString((String)row[3])+
                    ", \"hint\": "+jsonString((String)row[4])+"}");
            w.println(i<EXPECTED_UPLOADS.length-1 ? "," : "");
        }
        w.println("    ]");
        w.println("  },");

        // v6 Rule 58: REAL GS privileged MMIO map (PCSX2-grounded). Replaces
        // the v4 misnamed KNOWN_GS_REGS for 0x12000000+ accesses. The v4 map
        // is still emitted below as known_gs_registers but should be treated
        // as the GIF A+D reg labels (payload encoding, not MMIO offsets).
        w.println("  \"known_gs_priv_regs\": {");
        {
            boolean f=true;
            for(Map.Entry<Long,String> e : KNOWN_GS_PRIV_REGS.entrySet()) {
                if(!f) w.println(","); f=false;
                w.print("    \"0x"+String.format("%04X", e.getKey())+"\": \""+e.getValue()+"\"");
            }
        }
        w.println("\n  },");

        // v6: VIF opcode table (high byte of VIFcode word)
        w.println("  \"vif_opcode_constants\": {");
        {
            boolean f=true;
            for(Map.Entry<Long,String> e : VIF_OPCODES.entrySet()) {
                if(!f) w.println(","); f=false;
                w.print("    \"0x"+String.format("%02X", e.getKey())+"\": \""+e.getValue()+"\"");
            }
            w.println(",");
            w.print("    \"0x60..0x7F\": \"UNPACK\"");
        }
        w.println("\n  },");

        // v6: DMAtag IDs (bits 28-30 of upper word, exposed as upper-byte mask)
        w.println("  \"dma_tag_ids\": {");
        {
            boolean f=true;
            for(Map.Entry<Long,String> e : DMA_TAG_IDS.entrySet()) {
                if(!f) w.println(","); f=false;
                w.print("    \"0x"+String.format("%02X", e.getKey())+"\": \""+e.getValue()+"\"");
            }
        }
        w.println("\n  },");

        // v6: PCSX2 baseline metadata. v7 auto-populates checkpoint slots from
        // loaded gs_dump_to_summary.py outputs (filename → checkpoint name).
        // Slots without a matching GS dump remain null.
        w.println("  \"pcsx2_baseline\": {");
        w.println("    \"_note\": \"v7: checkpoint slots auto-populated from gs_runtime_evidence.checkpoints[]\",");
        {
            String[] standardSlots = {"sce_logo","title_screen","menu_main","3d_scene","cutscene","inventory","pause_menu","character_select"};
            for (int si = 0; si < standardSlots.length; si++) {
                String slot = standardSlots[si];
                GsCheckpoint match = findCheckpointForSlot(slot);
                w.print("    \""+slot+"\": ");
                if (match == null) w.print("null");
                else {
                    w.print("{\"source\": "+jsonString(match.name)+
                            ", \"path3_count\": "+match.path3Count+
                            ", \"giftags\": "+match.gifTagCount+
                            ", \"psmt4hh\": "+match.psmt4hhUsed+
                            ", \"psm_tex0\": "+intSetToJsonArray(match.psmTex0)+"}");
                }
                w.println(si == standardSlots.length-1 ? "" : ",");
            }
        }
        w.println("  },");

        // v7: GS runtime evidence block — per-checkpoint facts + merged union.
        emitGsRuntimeEvidence(w);

        // v4: GS register name map (consumers can label MMIO_GS hits).
        w.println("  \"known_gs_registers\": {");
        {
            boolean firstGs=true;
            for(Map.Entry<Long,String> e:KNOWN_GS_REGS.entrySet()){
                if(!firstGs)w.println(","); firstGs=false;
                w.print("    \"0x"+String.format("%02X",e.getKey())+"\": \""+e.getValue()+"\"");
            }
        }
        w.println("\n  },");
        
        w.println("  \"known_iop_sids\": {");
        boolean firstSid=true;
        for(Map.Entry<Long,String> e:KNOWN_IOP_SIDS.entrySet()){
            if(!firstSid)w.println(","); firstSid=false;
            w.print("    \""+hex(e.getKey())+"\": \""+e.getValue()+"\"");
        }
        w.println("\n  },");
        
        w.println("  \"game_override_addresses\": [");
        List<Long> oaList=new ArrayList<>(gameOverrideAddresses);
        Collections.sort(oaList);
        for(int i=0;i<oaList.size();i++){
            long oa=oaList.get(i);
            String oaName=gameOverrideNames.getOrDefault(oa,"");
            w.print("    {\"address\": \""+hex(oa)+"\", \"bound_name\": "+jsonString(oaName)+"}");
            if(i<oaList.size()-1)w.println(","); else w.println();
        }
        w.println("  ],");

        // v8 Rule 98 + 110: override classification + retire candidates.
        w.println("  \"override_classification\": {");
        {
            boolean first = true;
            for(Long a : oaList) {
                String kind = overrideKindByAddr.getOrDefault(a, "real_shim");
                String handler = overrideHandlerNames.getOrDefault(a, "");
                String bound   = gameOverrideNames.getOrDefault(a, "");
                boolean retire = "nop_stub".equals(kind) || "probe".equals(kind);
                if(!first) w.println(","); first = false;
                w.print("    \""+hex(a)+"\": {\"kind\": "+jsonString(kind)+
                        ", \"handler\": "+jsonString(handler)+
                        ", \"bound_name\": "+jsonString(bound)+
                        ", \"retire_candidate\": "+retire+"}");
            }
        }
        w.println("\n  },");

        // v8 Rule 93: classes section.
        w.println("  \"classes\": {");
        {
            boolean first = true;
            for(Map.Entry<String,ClassEntry> e : classRegistry.entrySet()) {
                ClassEntry ce = e.getValue();
                if(!first) w.println(","); first = false;
                w.print("    "+jsonString(e.getKey())+": {");
                w.print("\"ctors\": [");
                {
                    boolean f = true;
                    for(Long a : ce.ctorAddresses) {
                        if(!f) w.print(", "); f = false;
                        w.print("\""+hex(a)+"\"");
                    }
                }
                w.print("], ");
                w.print("\"dtor\": "+(ce.dtorAddress != null ? "\""+hex(ce.dtorAddress)+"\"" : "null")+", ");
                w.print("\"vtable_addr\": "+(ce.vtableAddr != null ? "\""+hex(ce.vtableAddr)+"\"" : "null")+", ");
                w.print("\"has_virtual_draw\": "+ce.hasVirtualDraw+", ");
                w.print("\"risk_tier\": "+jsonString(ce.riskTier)+", ");
                w.print("\"methods\": [");
                {
                    boolean f = true;
                    for(String m : ce.methodNames) {
                        if(!f) w.print(", "); f = false;
                        w.print(jsonString(m));
                    }
                }
                w.print("], ");
                w.print("\"method_addrs\": {");
                {
                    boolean f = true;
                    for(Map.Entry<String,Long> me : ce.methodAddrs.entrySet()) {
                        if(!f) w.print(", "); f = false;
                        w.print(jsonString(me.getKey())+": \""+hex(me.getValue())+"\"");
                    }
                }
                w.print("}, ");
                w.print("\"instantiation_sites\": [");
                {
                    boolean f = true;
                    for(Long pc : ce.instantiationSites) {
                        if(!f) w.print(", "); f = false;
                        w.print("\""+hex(pc)+"\"");
                    }
                }
                w.print("], ");
                w.print("\"global_holders\": [");
                {
                    boolean f = true;
                    for(String gh : ce.globalHolders) {
                        if(!f) w.print(", "); f = false;
                        w.print(jsonString(gh));
                    }
                }
                w.print("]}");
            }
        }
        w.println("\n  },");

        // v8 Rule 103: asset upload traces (T8/T4HH back-solve).
        w.println("  \"asset_upload_traces\": {");
        {
            boolean first = true;
            for(Map.Entry<String,List<long[]>> e : assetUploadTraces.entrySet()) {
                if(!first) w.println(","); first = false;
                w.print("    "+jsonString(e.getKey())+": {\"matches\": [");
                List<long[]> bucket = e.getValue();
                for(int j=0; j<bucket.size(); j++) {
                    if(j>0) w.print(", ");
                    w.print("\""+hex(bucket.get(j)[0])+"\"");
                }
                w.print("]}");
            }
        }
        w.println("\n  },");

        // v8: frame clock driver shortlist (Rule 100).
        w.println("  \"frame_clock_drivers\": [");
        {
            boolean first = true;
            for(FuncResult r : results) {
                if(r.traits != null && r.traits.isFrameClockDriver) {
                    if(!first) w.println(","); first = false;
                    w.print("    {\"address\": \""+hex(r.address)+
                            "\", \"name\": "+jsonString(r.name)+"}");
                }
            }
        }
        w.println("\n  ],");

        // v8 Rule 109: delta against prior triage_map.json. Empty when no prior.
        w.println("  \"delta\": {");
        if(priorTriageMapCats == null || priorTriageMapCats.isEmpty()) {
            w.println("    \"available\": false");
        } else {
            Set<Long> nowAddrs = new HashSet<>();
            for(FuncResult r : results) nowAddrs.add(r.address & 0xFFFFFFFFL);
            int added=0, removed=0, changed=0;
            List<String> changedList = new ArrayList<>();
            for(FuncResult r : results) {
                long a = r.address & 0xFFFFFFFFL;
                String now = r.disposition + "|" + r.category;
                String prev = priorTriageMapCats.get(a);
                if(prev == null) { added++; }
                else if(!prev.equals(now)) {
                    changed++;
                    if(changedList.size() < 200)
                        changedList.add(hex(a)+":"+prev+"->"+now);
                }
            }
            for(Long a : priorTriageMapCats.keySet())
                if(!nowAddrs.contains(a)) removed++;
            w.println("    \"available\": true,");
            w.println("    \"added\": "+added+",");
            w.println("    \"removed\": "+removed+",");
            w.println("    \"changed\": "+changed+",");
            w.println("    \"changed_sample\": [");
            for(int i=0; i<changedList.size(); i++) {
                w.print("      "+jsonString(changedList.get(i)));
                w.println(i<changedList.size()-1 ? "," : "");
            }
            w.println("    ]");
        }
        w.println("  },");

        // F21-prep: address -> name map for resolving caller names in the
        // reverse call-graph emit below.
        Map<Long,String> nameByAddr = new HashMap<>();
        for(FuncResult fr : results) nameByAddr.put(fr.address & 0xFFFFFFFFL, fr.name);

        w.println("  \"functions\": [");
        for(int i=0;i<results.size();i++) {
            if(monitor.isCancelled())break;
            FuncResult r=results.get(i);FuncTraits t=r.traits;
            w.print("    {");
            w.print("\"address\": \""+hex(r.address)+"\", ");
            w.print("\"name\": "+jsonString(r.name)+", ");
            w.print("\"category\": \""+r.category+"\", ");
            w.print("\"disposition\": \""+r.disposition+"\", ");
            w.print("\"size\": "+t.byteSize+", ");
            w.print("\"metrics\": {");
            w.print("\"fpu_ops\": "+t.floatOps+", ");
            w.print("\"math_ops\": "+t.mathOps+", ");
            w.print("\"branch_ops\": "+t.branchOps+", ");
            w.print("\"load_ops\": "+t.loadOps+", ");
            w.print("\"acc_ops\": "+t.accOps+", ");
            w.print("\"call_ops\": "+t.callOps+", ");
            w.print("\"callee_count\": "+t.calleeCount+", ");
            w.print("\"xref_to_count\": "+t.xrefToCount+", ");
            w.print("\"return_paths\": "+t.returnPaths);
            w.print("}, ");
            w.print("\"hardware\": {");
            w.print("\"uses_cop1\": "+t.usesCop1+", ");
            w.print("\"uses_cop2\": "+t.usesCop2+", ");
            w.print("\"uses_spr\": "+t.usesSPR+", ");
            w.print("\"writes_global\": "+t.writesToGlobal+", ");
            w.print("\"has_stack_frame\": "+t.hasStackFrame+", ");
            w.print("\"has_mutation\": "+t.hasMutatingInstructions+", ");
            w.print("\"has_vcallms\": "+t.hasVcallms+", ");
            w.print("\"has_jump_table\": "+t.hasJumpTable+", ");
            w.print("\"accesses_vif1_mmio\": "+t.accessesVif1MMIO+", ");
            w.print("\"calls_dma_send\": "+t.callsDmaSend+", ");
            w.print("\"calls_sif_rpc\": "+t.callsSifRpc+", ");
            w.print("\"detected_rpc_sid\": "+(t.detectedRpcSid!=0?("\""+hex(t.detectedRpcSid)+"\""):"null")+", ");
            w.print("\"refs_archive_strings\": "+t.refsArchiveStrings+", ");
            w.print("\"calls_pad_poll_callee\": "+t.callsPadPollCallee+", ");
            w.print("\"has_backward_branch\": "+t.hasBackwardBranch+", ");
            w.print("\"writes_to_a1_buffer\": "+t.writesToA1Buffer+", ");
            w.print("\"is_large_init_func\": "+t.isLargeInitFunc+", ");
            w.print("\"is_thread_sync_point\": "+t.isThreadSyncPoint+", ");
            // v4 hardware-shape fields
            w.print("\"ctor_writes_a0_slot\": "+t.ctorWritesA0Slot+", ");
            w.print("\"ctor_writes_vtable_pointer\": "+t.ctorWritesVTablePointer+", ");
            w.print("\"returns_a0\": "+t.returnsA0+", ");
            w.print("\"returns_a1\": "+t.returnsA1+", ");
            w.print("\"is_process_terminator\": "+t.isProcessTerminator+", ");
            w.print("\"is_libgcc_intrinsic\": "+t.isLibgccIntrinsic+", ");
            w.print("\"touches_gif_ctrl\": "+t.touchesGifCtrl+", ");
            w.print("\"writes_gs_prim_reg\": "+t.writesGsPrimReg+", ");
            w.print("\"writes_zbuf_reg\": "+t.writesZbufReg+", ");
            w.print("\"writes_dispfb_reg\": "+t.writesDispfbReg+", ");
            w.print("\"has_shift24_pattern\": "+t.hasShift24Pattern+", ");
            w.print("\"has_dsll32_or_dsrl32\": "+t.hasDsll32OrDsrl32+", ");
            w.print("\"calls_mpeg_family\": "+t.callsMpegFamily+", ");
            w.print("\"tail_call_indirect\": "+t.tailCallIndirect+", ");
            w.print("\"indirect_call_t9_count\": "+t.indirectCallT9Count+", ");
            w.print("\"is_likely_poll_target\": "+t.isLikelyPollTarget+", ");
            w.print("\"gs_register_hits\": [");
            {
                boolean firstHit=true;
                for(String s:t.gsRegHits){
                    if(!firstHit) w.print(", ");
                    firstHit=false;
                    w.print(jsonString(s));
                }
            }
            w.print("], ");
            // v5 fields
            w.print("\"is_sce_gif_pk_ref_load_image\": "+t.isSceGifPkRefLoadImage+", ");
            w.print("\"path3_initiator\": "+t.path3Initiator+", ");
            w.print("\"is_sce_gif_pk_family\": "+t.isSceGifPkFamily+", ");
            w.print("\"writes_tex0_reg\": "+t.writesTex0Reg+", ");
            w.print("\"reads_prim_reg\": "+t.readsPrimReg+", ");
            w.print("\"writes_rgbaq_reg\": "+t.writesRgbaqReg+", ");
            w.print("\"is_microcode_uploader\": "+t.isMicrocodeUploader+", ");
            w.print("\"is_audio_rpc_handler\": "+t.isAudioRpcHandler+", ");
            w.print("\"refs_meswin_strings\": "+t.refsMeswinStrings+", ");
            w.print("\"is_mc_transition_gate\": "+t.isMcTransitionGate+", ");
            w.print("\"is_top_priority_fix\": "+t.isTopPriorityFix+", ");
            w.print("\"dma_kick_channels\": [");
            {
                boolean firstK=true;
                for(String s:t.dmaKickChannels){
                    if(!firstK) w.print(", ");
                    firstK=false;
                    w.print(jsonString(s));
                }
            }
            w.print("], ");
            w.print("\"dma_qwc_tadr_channels\": [");
            {
                boolean firstQ=true;
                for(String s:t.dmaQwcTadrChannels){
                    if(!firstQ) w.print(", ");
                    firstQ=false;
                    w.print(jsonString(s));
                }
            }
            w.print("], ");
            w.print("\"dc2_globals_touched\": [");
            {
                boolean firstD=true;
                for(String s:t.dc2GlobalsTouched){
                    if(!firstD) w.print(", ");
                    firstD=false;
                    w.print(jsonString(s));
                }
            }
            w.print("], ");
            // v6 fields
            w.print("\"accesses_ipu_mmio\": "+t.accessesIpuMmio+", ");
            w.print("\"writes_ipu_cmd\": "+t.writesIpuCmd+", ");
            w.print("\"touches_gif_p3_reg\": "+t.touchesGifP3Reg+", ");
            w.print("\"writes_gif_fifo\": "+t.writesGifFifo+", ");
            w.print("\"writes_vif1_fifo\": "+t.writesVif1Fifo+", ");
            w.print("\"writes_vif0_fifo\": "+t.writesVif0Fifo+", ");
            w.print("\"writes_ipu_fifo\": "+t.writesIpuFifo+", ");
            w.print("\"accesses_vu_micromem\": "+t.accessesVuMicromem+", ");
            w.print("\"accesses_vu_datamem\": "+t.accessesVuDatamem+", ");
            w.print("\"touches_sbus\": "+t.touchesSbus+", ");
            w.print("\"loads_psm4hh_constant\": "+t.loadsPsm4hhConstant+", ");
            w.print("\"gs_priv_reg_hits\": [");
            {
                boolean f=true;
                for(String s:t.gsPrivRegHits){
                    if(!f) w.print(", "); f=false;
                    w.print(jsonString(s));
                }
            }
            w.print("], ");
            w.print("\"vif_opcodes_built\": [");
            {
                boolean f=true;
                for(String s:t.vifOpcodesBuilt){
                    if(!f) w.print(", "); f=false;
                    w.print(jsonString(s));
                }
            }
            w.print("], ");
            w.print("\"dma_tag_ids_built\": [");
            {
                boolean f=true;
                for(String s:t.dmaTagIdsBuilt){
                    if(!f) w.print(", "); f=false;
                    w.print(jsonString(s));
                }
            }
            w.print("], ");
            // v7 hardware-shape fields
            w.print("\"writes_dispfb_via_sdk\": "+t.writesDispfbViaSdk+", ");
            w.print("\"path3_kick_via_dma_api\": "+t.path3KickViaDmaApi+", ");
            w.print("\"is_gs_irq_handler_name\": "+t.isGsIrqHandlerName+", ");
            // v7.1 hardware-shape fields
            w.print("\"writes_bitbltbuf_reg\": "+t.writesBitbltbufReg+", ");
            w.print("\"is_bitbltbuf_t4hh_uploader\": "+t.isBitbltbufT4hhUploader+", ");
            w.print("\"is_ctor_multi_field_init\": "+t.isCtorMultiFieldInit+", ");
            w.print("\"ctor_slots_written_count\": "+t.ctorSlotsWritten.size()+", ");
            w.print("\"is_lifecycle_lazy_init\": "+t.isLifecycleLazyInit+", ");
            // v8 hardware-shape fields
            w.print("\"is_ctor\": "+t.isCtor+", ");
            w.print("\"is_dtor\": "+t.isDtor+", ");
            w.print("\"ctor_class_name\": "+jsonString(t.ctorClassName)+", ");
            w.print("\"method_class_name\": "+jsonString(t.methodClassName)+", ");
            w.print("\"method_name\": "+jsonString(t.methodName)+", ");
            w.print("\"is_virtual_draw_method\": "+t.isVirtualDrawMethod+", ");
            w.print("\"ctor_installs_vtable\": "+t.ctorInstallsVtable+", ");
            w.print("\"ctor_vtable_addr\": "+(t.ctorVtableAddr!=0?"\""+hex(t.ctorVtableAddr)+"\"":"null")+", ");
            w.print("\"ctor_assigned_to_global\": "+t.ctorAssignedToGlobal+", ");
            w.print("\"ctor_call_mode\": "+jsonString(t.ctorCallMode)+", ");
            w.print("\"ctor_risk_tier\": "+jsonString(t.ctorRiskTier)+", ");
            w.print("\"called_via_direct_jal\": "+t.calledViaDirectJal+", ");
            w.print("\"called_via_jr_t9\": "+t.calledViaJrT9+", ");
            w.print("\"is_pad_button_mask_consumer\": "+t.isPadButtonMaskConsumer+", ");
            w.print("\"calls_gif_packet_open\": "+t.callsGifPacketOpen+", ");
            w.print("\"calls_gif_packet_close\": "+t.callsGifPacketClose+", ");
            w.print("\"gif_nloop_double_count_risk\": "+t.gifNloopDoubleCountRisk+", ");
            w.print("\"calls_file_open\": "+t.callsFileOpen+", ");
            w.print("\"file_path_has_percent_s\": "+t.filePathHasPercentS+", ");
            w.print("\"is_frame_clock_driver\": "+t.isFrameClockDriver+", ");
            w.print("\"is_sce_vu0_helper\": "+t.isSceVu0Helper+", ");
            w.print("\"vu0_helper_family\": "+jsonString(t.vu0HelperFamily)+", ");
            w.print("\"must_be_implemented\": "+t.mustBeImplemented+", ");
            w.print("\"uploader_caller_depth1\": "+t.uploaderCallerDepth1+", ");
            w.print("\"dispfb_writer_via_sdk_caller_depth1\": "+t.dispfbWriterViaSdkCallerDepth1+", ");
            w.print("\"dma_kick_via_sdk_caller_depth1\": "+t.dmaKickViaSdkCallerDepth1+", ");
            w.print("\"override_kind\": "+jsonString(t.overrideKind)+", ");
            w.print("\"override_retire_candidate\": "+t.overrideRetireCandidate+", ");
            w.print("\"pad_masks_tested\": [");
            {
                boolean f=true;
                for(String s:t.padMasksTested){ if(!f) w.print(", "); f=false; w.print(jsonString(s)); }
            }
            w.print("], ");
            w.print("\"detected_rpc_fids\": [");
            {
                boolean f=true;
                for(Long v:t.detectedRpcFids){ if(!f) w.print(", "); f=false; w.print("\""+hex(v)+"\""); }
            }
            w.print("], ");
            w.print("\"ctor_sibling_ctor_calls\": [");
            {
                boolean f=true;
                for(Long v:t.ctorSiblingCtorCalls){ if(!f) w.print(", "); f=false; w.print("\""+hex(v)+"\""); }
            }
            w.print("], ");
            w.print("\"return_written_to_globals\": [");
            {
                boolean f=true;
                for(Long v:t.returnWrittenToGlobals){ if(!f) w.print(", "); f=false; w.print("\""+hex(v)+"\""); }
            }
            w.print("], ");
            w.print("\"asset_upload_tags_hit\": [");
            {
                boolean f=true;
                for(String s:t.assetUploadTagsHit){ if(!f) w.print(", "); f=false; w.print(jsonString(s)); }
            }
            w.print("], ");
            w.print("\"file_path_sprintf_formats\": [");
            {
                boolean f=true;
                for(String s:t.filePathSprintfFormats){ if(!f) w.print(", "); f=false; w.print(jsonString(s)); }
            }
            w.print("], ");
            w.print("\"virtual_dispatch_sites\": [");
            {
                boolean f=true;
                for(String[] vd:t.virtualDispatchSites){
                    if(!f) w.print(", "); f=false;
                    w.print("{\"pc\": \""+vd[0]+"\", \"vtable_slot\": \""+vd[1]+"\", \"object_reg\": "+jsonString(vd[2])+"}");
                }
            }
            w.print("]");
            w.print("}, ");
            // v4 graph-derived fields, hoisted above tags so consumers can sort.
            w.print("\"mainloop_depth\": "+t.mainLoopDepth+", ");
            w.print("\"init_chain_depth\": "+t.initChainDepth+", ");
            w.print("\"drawing_chain_depth\": "+t.drawingChainDepth+", ");
            w.print("\"tags\": [");
            for(int j=0;j<r.tags.size();j++){if(j>0)w.print(", ");w.print("\""+r.tags.get(j)+"\"");}
            w.print("], ");
            w.print("\"callees\": [");
            for(int j=0;j<t.calleeNames.size();j++){if(j>0)w.print(", ");w.print(jsonString(t.calleeNames.get(j)));}
            w.print("], ");
            // F21-prep: reverse call-graph entries.
            w.print("\"callers\": [");
            for(int j=0;j<t.callers.size();j++){
                if(j>0)w.print(", ");
                long[] c = t.callers.get(j);
                String cn = nameByAddr.getOrDefault(c[0]&0xFFFFFFFFL, "");
                w.print("{\"address\": \""+hex(c[0])+"\", \"name\": "+jsonString(cn)+
                        ", \"call_site_pc\": \""+hex(c[1])+"\"}");
            }
            w.print("], ");
            // F21-prep: literal-offset memory-access index.
            w.print("\"literal_refs\": [");
            for(int j=0;j<t.literalRefs.size();j++){
                if(j>0)w.print(", ");
                String[] lr = t.literalRefs.get(j);
                w.print("{\"pc\": \""+lr[0]+"\", \"mnem\": "+jsonString(lr[1])+
                        ", \"base_reg\": "+jsonString(lr[2])+
                        ", \"offset\": "+jsonString(lr[3])+
                        ", \"dest_reg\": "+jsonString(lr[4])+"}");
            }
            w.print("]");
            // v4 Rule 41: archive_io_callers — emit per ARCHIVE_IO function for
            // convenience (the same info exists in `callers`, but consumers
            // generating phase docs want it at the per-function level without
            // re-running the reverse lookup).
            if(t.refsArchiveStrings) {
                w.print(", \"archive_io_callers\": [");
                for(int j=0;j<t.callers.size();j++){
                    if(j>0)w.print(", ");
                    long[] c = t.callers.get(j);
                    String cn = nameByAddr.getOrDefault(c[0]&0xFFFFFFFFL, "");
                    w.print("{\"address\": \""+hex(c[0])+"\", \"name\": "+jsonString(cn)+
                            ", \"call_site_pc\": \""+hex(c[1])+"\"}");
                }
                w.print("]");
            }
            // v7: runtime_corroboration block. Emitted only when there is
            // either a prediction or a TBP-constant match; omitted otherwise
            // to keep JSON size bounded for leaf/utility functions.
            if (!t.runtimeBullseyePredictions.isEmpty() || !t.tbpConstantsLoaded.isEmpty()
                || t.gsIrqSafeStubCandidate) {
                w.print(", \"runtime_corroboration\": {");
                w.print("\"status\": "+jsonString(t.runtimeStatus)+", ");
                w.print("\"confirmed\": "+t.runtimeConfirmed+", ");
                w.print("\"dormant_global\": "+t.runtimeDormantGlobal+", ");
                w.print("\"menu_only\": "+t.runtimeMenuOnly+", ");
                w.print("\"gs_irq_safe_stub_candidate\": "+t.gsIrqSafeStubCandidate+", ");
                w.print("\"predicted_bullseye\": [");
                {
                    boolean f=true;
                    for(String s:t.runtimeBullseyePredictions){
                        if(!f) w.print(", "); f=false;
                        w.print(jsonString(s));
                    }
                }
                w.print("], ");
                w.print("\"witness\": {");
                {
                    boolean f=true;
                    for(Map.Entry<String,Boolean> e:t.runtimeWitness.entrySet()){
                        if(!f) w.print(", "); f=false;
                        w.print(jsonString(e.getKey())+": "+e.getValue());
                    }
                }
                w.print("}, ");
                w.print("\"a_d_reg_runtime_match\": [");
                {
                    boolean f=true;
                    for(String s:t.runtimeAdRegMatch){
                        if(!f) w.print(", "); f=false;
                        w.print(jsonString(s));
                    }
                }
                w.print("], ");
                w.print("\"tbp_constants_loaded\": [");
                {
                    boolean f=true;
                    for(Long c:t.tbpConstantsLoaded){
                        if(!f) w.print(", "); f=false;
                        w.print(c);
                    }
                }
                w.print("], ");
                w.print("\"tbp_runtime_confirmed\": [");
                {
                    boolean f=true;
                    for(Long c:t.tbpRuntimeConfirmed){
                        if(!f) w.print(", "); f=false;
                        w.print(c);
                    }
                }
                w.print("]");
                w.print("}");
            }
            w.print("}");
            if(i<results.size()-1)w.println(",");else w.println();
        }
        w.println("  ],");

        // v5 Rule 57: focus_set — top-priority bullseye. The community lessons
        // say "you only need to rewrite the 5 exact functions"; this array is
        // exactly that shortlist (plus PATH3_INITIATOR / TEX0 writers / etc.).
        // Pre-sorted by tag class for the report tool.
        w.println("  \"focus_set\": [");
        {
            List<FuncResult> focus = new ArrayList<>();
            for(FuncResult r : results)
                if(r.traits != null && r.traits.isTopPriorityFix) focus.add(r);
            // v9 Rule 136: synth fallback when no bullseyes fire — top-32 by score.
            boolean synthetic = focus.isEmpty();
            if(synthetic) {
                List<FuncResult> scored = new ArrayList<>(results);
                scored.sort((a,b) -> Long.compare(
                    scoreFocus(b.traits == null ? null : b.traits),
                    scoreFocus(a.traits == null ? null : a.traits)));
                int cap = Math.min(32, scored.size());
                for(int i = 0; i < cap; i++) {
                    FuncResult r = scored.get(i);
                    if(r.traits == null) continue;
                    if(!r.tags.contains("FOCUS_SYNTHETIC")) r.tags.add("FOCUS_SYNTHETIC");
                    focus.add(r);
                }
            }
            // v7 Rule 81: re-rank — CONFIRMED first, INDETERMINATE next,
            // MENU_ONLY then DORMANT. Stable within a bucket by address.
            focus.sort((a,b) -> {
                int ra = focusRank(a.traits);
                int rb = focusRank(b.traits);
                if (ra != rb) return Integer.compare(ra, rb);
                return Long.compare(a.address & 0xFFFFFFFFL, b.address & 0xFFFFFFFFL);
            });
            for(int i=0;i<focus.size();i++) {
                FuncResult r = focus.get(i);
                FuncTraits t = r.traits;
                w.print("    {\"address\": \""+hex(r.address)+
                        "\", \"name\": "+jsonString(r.name)+
                        ", \"tags\": [");
                for(int j=0;j<r.tags.size();j++){
                    if(j>0) w.print(", ");
                    w.print(jsonString(r.tags.get(j)));
                }
                w.print("], \"mainloop_depth\": "+t.mainLoopDepth+
                        ", \"drawing_chain_depth\": "+t.drawingChainDepth+
                        ", \"caller_count\": "+t.callers.size()+
                        ", \"runtime_status\": "+jsonString(t.runtimeStatus)+
                        ", \"dc2_role\": "+jsonString(t.dc2KnownRole == null ? "" : t.dc2KnownRole)+
                        ", \"dc2_phase\": "+jsonString(t.dc2KnownPhase == null ? "" : t.dc2KnownPhase)+
                        ", \"dc2_criticality\": "+jsonString(t.dc2KnownCriticality == null ? "" : t.dc2KnownCriticality)+
                        ", \"module_id\": "+t.moduleId+
                        ", \"synthetic\": "+(synthetic ? "true" : "false")+"}");
                if(i<focus.size()-1) w.println(","); else w.println();
            }
        }
        w.println("  ],");

        // v9 Rule 131: DC2 known function addresses (hardcoded from PROJECT_STATE.md)
        w.println("  \"dc2_known_function_addresses\": [");
        for(int i=0; i<KNOWN_DC2_FUNCTION_ADDRESSES.length; i++) {
            Object[] row = KNOWN_DC2_FUNCTION_ADDRESSES[i];
            w.print("    {\"address\": \""+hex(((Number)row[0]).longValue())+
                    "\", \"name\": "+jsonString((String)row[1])+
                    ", \"phase\": "+jsonString((String)row[2])+
                    ", \"role\": "+jsonString((String)row[3])+
                    ", \"criticality\": "+jsonString((String)row[4])+"}");
            w.println(i<KNOWN_DC2_FUNCTION_ADDRESSES.length-1 ? "," : "");
        }
        w.println("  ],");

        // v9 Rule 132: DC2 VRAM TBP labels
        w.println("  \"dc2_known_tbp_labels\": {");
        {
            boolean f = true;
            for(Map.Entry<Long,String> e : KNOWN_DC2_TBP_LABELS.entrySet()) {
                if(!f) w.println(","); f = false;
                w.print("    \"0x"+String.format("%04X", e.getKey() & 0xFFFFL)+
                        "\": "+jsonString(e.getValue()));
            }
        }
        w.println("\n  },");

        // v9 Rule 133: DC2 runtime invariants confirmed across all 9 GS dumps
        w.println("  \"dc2_runtime_invariants\": [");
        for(int i=0; i<DC2_RUNTIME_INVARIANTS.length; i++) {
            String[] row = DC2_RUNTIME_INVARIANTS[i];
            w.print("    {\"name\": "+jsonString(row[0])+
                    ", \"description\": "+jsonString(row[1])+"}");
            w.println(i<DC2_RUNTIME_INVARIANTS.length-1 ? "," : "");
        }
        w.println("  ],");

        // v9 Rule 134: DC2 pre-computed call chains
        w.println("  \"dc2_call_chains\": {");
        for(int i=0; i<DC2_CALL_CHAINS.length; i++) {
            Object[] row = DC2_CALL_CHAINS[i];
            String tag = (String)row[0];
            String[] stations = (String[])row[1];
            w.print("    "+jsonString(tag)+": [");
            for(int j=0; j<stations.length; j++) {
                if(j>0) w.print(", ");
                w.print(jsonString(stations[j]));
            }
            w.print("]");
            w.println(i<DC2_CALL_CHAINS.length-1 ? "," : "");
        }
        w.println("  },");

        // v9 Rule 135: working DC2_PAD_INPUT scripts from fix logs
        w.println("  \"dc2_pad_input_scripts\": [");
        for(int i=0; i<DC2_PAD_INPUT_SCRIPTS.length; i++) {
            String[] row = DC2_PAD_INPUT_SCRIPTS[i];
            w.print("    {\"tag\": "+jsonString(row[0])+
                    ", \"script\": "+jsonString(row[1])+
                    ", \"frame_anchor\": "+jsonString(row[2])+
                    ", \"observed_effect\": "+jsonString(row[3])+"}");
            w.println(i<DC2_PAD_INPUT_SCRIPTS.length-1 ? "," : "");
        }
        w.println("  ],");

        // v9 Rule 128: function pointer tables
        w.println("  \"function_pointer_tables\": [");
        {
            int n = functionPointerTables.size(); int i = 0;
            for(Map.Entry<Long,List<long[]>> e : functionPointerTables.entrySet()) {
                w.print("    {\"address\": \""+hex(e.getKey())+
                        "\", \"entries\": [");
                List<long[]> entries = e.getValue();
                for(int j = 0; j < entries.size(); j++) {
                    if(j>0) w.print(", ");
                    w.print("\""+hex(entries.get(j)[0])+"\"");
                }
                w.print("], \"size\": "+entries.size()+"}");
                w.println((++i < n) ? "," : "");
            }
        }
        w.println("  ],");

        // v9 Rule 129: module clusters
        w.println("  \"module_clusters\": {");
        {
            int n = moduleClusters.size(); int i = 0;
            for(Map.Entry<Integer,Set<Long>> e : moduleClusters.entrySet()) {
                w.print("    \"mod_"+e.getKey()+"\": [");
                int j = 0;
                for(Long a : e.getValue()) {
                    if(j>0) w.print(", "); j++;
                    w.print("\""+hex(a)+"\"");
                }
                w.print("]");
                w.println((++i < n) ? "," : "");
            }
        }
        w.println("  },");

        // v9 Rule 130: name-prefix modules
        w.println("  \"name_prefix_modules\": {");
        {
            int n = namePrefixModules.size(); int i = 0;
            for(Map.Entry<String,List<Long>> e : namePrefixModules.entrySet()) {
                w.print("    "+jsonString(e.getKey())+": [");
                List<Long> lst = e.getValue();
                for(int j = 0; j < lst.size(); j++) {
                    if(j>0) w.print(", ");
                    w.print("\""+hex(lst.get(j))+"\"");
                }
                w.print("]");
                w.println((++i < n) ? "," : "");
            }
        }
        w.println("  },");

        // v9 Rule 139: discovered IOP SIDs with caller list
        w.println("  \"discovered_iop_sids\": [");
        {
            List<Long> sids = new ArrayList<>(discoveredSidToCallers.keySet());
            Collections.sort(sids);
            for(int i = 0; i < sids.size(); i++) {
                long sid = sids.get(i);
                Set<Long> callers = discoveredSidToCallers.get(sid);
                w.print("    {\"sid\": \""+hex(sid)+"\", \"callers\": [");
                int j = 0;
                for(Long c : callers) {
                    if(j>0) w.print(", "); j++;
                    w.print("\""+hex(c)+"\"");
                }
                w.print("]}");
                w.println(i < sids.size()-1 ? "," : "");
            }
        }
        w.println("  ],");

        // v9: discovered FIDs (function-ids for sceSifCallRpc)
        w.println("  \"discovered_iop_fids\": [");
        {
            List<Long> fids = new ArrayList<>(discoveredFidToCallers.keySet());
            Collections.sort(fids);
            for(int i = 0; i < fids.size(); i++) {
                long fid = fids.get(i);
                Set<Long> callers = discoveredFidToCallers.get(fid);
                w.print("    {\"fid\": \""+hex(fid)+"\", \"callers\": [");
                int j = 0;
                for(Long c : callers) {
                    if(j>0) w.print(", "); j++;
                    w.print("\""+hex(c)+"\"");
                }
                w.print("]}");
                w.println(i < fids.size()-1 ? "," : "");
            }
        }
        w.println("  ]");
        w.println("}");
        w.close();
    }

    class FuncResult{long address;String name,category,disposition;FuncTraits traits;List<String>tags;}
    private static String hex(long v){return String.format("0x%08X",v&0xFFFFFFFFL);}
    private static String jsonString(String v){
        if(v==null)return "\"\"";
        return "\""+v.replace("\\","\\\\").replace("\"","\\\"").replace("\n","\\n").replace("\r","\\r").replace("\t","\\t")+"\"";
    }

    // v7: bucket sort for focus_set rerank.
    //  0 = CONFIRMED (true bullseye, witnessed at runtime)
    //  1 = INDETERMINATE (no runtime evidence loaded OR mixed)
    //  2 = MENU_ONLY (UI pipeline; non-3D-critical)
    //  3 = DORMANT (predicted bullseye, never witnessed anywhere)
    private static int focusRank(FuncTraits t) {
        if (t == null) return 1;
        if (t.runtimeConfirmed && !t.runtimeMenuOnly) return 0;
        if (t.runtimeConfirmed && t.runtimeMenuOnly)  return 2;
        if (t.runtimeMenuOnly) return 2;
        if (t.runtimeDormantGlobal) return 3;
        return 1;
    }

    /**
     * Heuristic match between a fixed checkpoint slot name and any loaded
     * {@link GsCheckpoint}. Loose substring matching on lower-case names.
     * Returns the first match, or null.
     */
    private GsCheckpoint findCheckpointForSlot(String slot) {
        String low = slot.toLowerCase();
        // Synonyms: collapse common variations the user files might use.
        String[] aliases;
        if (low.equals("sce_logo"))         aliases = new String[]{"sce_logo","scelogo"};
        else if (low.equals("title_screen"))aliases = new String[]{"title","main_title"};
        else if (low.equals("menu_main"))   aliases = new String[]{"menu","main_menu"};
        else if (low.equals("3d_scene"))    aliases = new String[]{"3d_scene","3dscene","gameplay","field"};
        else if (low.equals("cutscene"))    aliases = new String[]{"cutscene","movie","fmv"};
        else if (low.equals("inventory"))   aliases = new String[]{"inventory"};
        else if (low.equals("pause_menu"))  aliases = new String[]{"pause"};
        else if (low.equals("character_select")) aliases = new String[]{"character","select"};
        else                                aliases = new String[]{low};
        for (GsCheckpoint c : gsEvidence.checkpoints) {
            String cn = c.name.toLowerCase();
            for (String a : aliases) if (cn.contains(a)) return c;
        }
        return null;
    }

    private static String intSetToJsonArray(Set<Integer> s) {
        StringBuilder sb = new StringBuilder("[");
        boolean f = true;
        for (Integer v : s) { if(!f) sb.append(", "); f=false; sb.append(v); }
        sb.append("]");
        return sb.toString();
    }

    private static String longSetToJsonArray(Set<Long> s) {
        StringBuilder sb = new StringBuilder("[");
        boolean f = true;
        for (Long v : s) { if(!f) sb.append(", "); f=false; sb.append(v); }
        sb.append("]");
        return sb.toString();
    }

    private static String stringSetToJsonArray(Set<String> s) {
        StringBuilder sb = new StringBuilder("[");
        boolean f = true;
        for (String v : s) { if(!f) sb.append(", "); f=false; sb.append(jsonString(v)); }
        sb.append("]");
        return sb.toString();
    }

    /** v7: emit the gs_runtime_evidence top-level block. */
    private void emitGsRuntimeEvidence(PrintWriter w) {
        GsRuntimeEvidence ev = gsEvidence;
        w.println("  \"gs_runtime_evidence\": {");
        w.println("    \"checkpoint_count\": "+ev.checkpoints.size()+",");
        w.println("    \"merged\": {");
        w.println("      \"any_path1\": "+ev.anyPath1+",");
        w.println("      \"any_path2\": "+ev.anyPath2+",");
        w.println("      \"any_path3\": "+ev.anyPath3+",");
        w.println("      \"any_psmt4hh\": "+ev.anyPsmt4hh+",");
        w.println("      \"any_psmt4hl\": "+ev.anyPsmt4hl+",");
        w.println("      \"any_psmt8h\": "+ev.anyPsmt8h+",");
        w.println("      \"any_psmt4hh_upload\": "+ev.anyPsmt4hhUpload+",");
        w.println("      \"any_psmt4hl_upload\": "+ev.anyPsmt4hlUpload+",");
        w.println("      \"any_psmt8h_upload\": "+ev.anyPsmt8hUpload+",");
        w.println("      \"bitbltbuf_dpsms_union\": "+intSetToJsonArray(ev.bitbltbufDpsmsUnion)+",");
        w.println("      \"any_prim_garbage\": "+ev.anyPrimGarbage+",");
        w.println("      \"any_readfifo2\": "+ev.anyReadfifo2+",");
        w.println("      \"any_reglist\": "+ev.anyReglist+",");
        w.println("      \"any_image2\": "+ev.anyImage2+",");
        w.println("      \"any_signal_finish_label\": "+ev.anySignalFinishLabel+",");
        w.println("      \"imr_intersection\": "+(ev.imrIntersection<0 ? "null"
                                                  : "\"0x"+String.format("%016X", ev.imrIntersection)+"\"")+",");
        w.println("      \"imr_all_masked_gs_irqs\": "+ev.imrAllMaskedGsIrqs+",");
        w.println("      \"total_path3_count\": "+ev.totalPath3Count+",");
        w.println("      \"total_path3_bytes\": "+ev.totalPath3Bytes+",");
        w.println("      \"psm_tex0_union\": "+intSetToJsonArray(ev.psmTex0Union)+",");
        w.println("      \"psm_frame_union\": "+intSetToJsonArray(ev.psmFrameUnion)+",");
        w.println("      \"psm_zbuf_union\": "+intSetToJsonArray(ev.psmZbufUnion)+",");
        w.println("      \"a_d_regs_union\": "+stringSetToJsonArray(ev.adRegsUnion)+",");
        w.println("      \"tex0_tbps_union\": "+longSetToJsonArray(ev.tex0TbpsUnion)+",");
        w.println("      \"vram_upload_tbps_union\": "+longSetToJsonArray(ev.vramTbpsUnion)+",");
        w.println("      \"prim_distinct_union\": "+longSetToJsonArray(ev.primUnion));
        w.println("    },");
        w.println("    \"psm_tex0_witnesses\": {");
        {
            boolean f = true;
            for (Map.Entry<Integer,Set<String>> e : ev.psmTex0Witnesses.entrySet()) {
                if (!f) w.println(","); f = false;
                w.print("      \""+e.getKey()+"\": "+stringSetToJsonArray(e.getValue()));
            }
        }
        w.println("\n    },");
        w.println("    \"checkpoints\": [");
        for (int ci = 0; ci < ev.checkpoints.size(); ci++) {
            GsCheckpoint c = ev.checkpoints.get(ci);
            w.print("      {");
            w.print("\"name\": "+jsonString(c.name)+", ");
            w.print("\"serial\": "+jsonString(c.serial)+", ");
            w.print("\"crc\": "+jsonString(c.crc)+", ");
            w.print("\"source_file\": "+jsonString(c.sourceFile)+", ");
            w.print("\"vsyncs\": "+c.vsyncs+", ");
            w.print("\"path1_count\": "+c.path1Count+", ");
            w.print("\"path2_count\": "+c.path2Count+", ");
            w.print("\"path3_count\": "+c.path3Count+", ");
            w.print("\"path3_bytes\": "+c.path3Bytes+", ");
            w.print("\"giftag_count\": "+c.gifTagCount+", ");
            w.print("\"malformed_tags\": "+c.malformedTags+", ");
            w.print("\"packed\": "+c.packedCount+", ");
            w.print("\"reglist\": "+c.reglistCount+", ");
            w.print("\"image\": "+c.imageCount+", ");
            w.print("\"image2\": "+c.image2Count+", ");
            w.print("\"readfifo2_active\": "+c.readfifo2Active+", ");
            w.print("\"psmt4hh\": "+c.psmt4hhUsed+", ");
            w.print("\"psmt4hl\": "+c.psmt4hlUsed+", ");
            w.print("\"psmt8h\": "+c.psmt8hUsed+", ");
            w.print("\"psmt4hh_upload\": "+c.psmt4hhUpload+", ");
            w.print("\"psmt4hl_upload\": "+c.psmt4hlUpload+", ");
            w.print("\"psmt8h_upload\": "+c.psmt8hUpload+", ");
            w.print("\"bitbltbuf_dpsms\": "+intSetToJsonArray(c.bitbltbufDpsms)+", ");
            w.print("\"prim_garbage\": "+c.primGarbage+", ");
            w.print("\"psm_tex0\": "+intSetToJsonArray(c.psmTex0)+", ");
            w.print("\"psm_frame\": "+intSetToJsonArray(c.psmFrame)+", ");
            w.print("\"psm_zbuf\": "+intSetToJsonArray(c.psmZbuf)+", ");
            w.print("\"a_d_regs\": "+stringSetToJsonArray(c.adRegs)+", ");
            w.print("\"tex0_tbps\": "+longSetToJsonArray(c.tex0Tbps)+", ");
            w.print("\"vram_upload_tbps\": "+longSetToJsonArray(c.vramTbps)+", ");
            w.print("\"prim_distinct\": "+longSetToJsonArray(c.primValues)+", ");
            w.print("\"imr\": "+(c.imr<0 ? "null" : "\"0x"+String.format("%016X", c.imr)+"\"")+", ");
            w.print("\"pmode\": "+(c.pmode<0 ? "null" : "\"0x"+String.format("%016X", c.pmode)+"\"")+", ");
            w.print("\"frame_final\": {\"fbp\": "+c.frameFbp+", \"fbw\": "+c.frameFbw+", \"psm\": "+c.framePsm+"}, ");
            w.print("\"zbuf_final\": {\"zbp\": "+c.zbufZbp+", \"psm\": "+c.zbufPsm+", \"zmsk\": "+c.zbufZmsk+"}, ");
            w.print("\"dispfb1_fbp\": "+c.dispfb1Fbp+", \"dispfb2_fbp\": "+c.dispfb2Fbp);
            w.print("}");
            if (ci < ev.checkpoints.size()-1) w.println(","); else w.println();
        }
        w.println("    ]");
        w.println("  },");
    }
}

