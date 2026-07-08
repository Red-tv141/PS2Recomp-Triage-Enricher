// PS2Recomp Triage Enricher v17.1 (DC2 Edition) - Ghidra Script (Step 2 of Pipeline)
// ==================================================================
// Run AFTER ExportPS2Functions.java on the same Ghidra project.
//
// RULES (1-233) - organized numerically for AI readability
// ================================================================
//
// Rule 1  No DANGEROUS_KEYWORDS (removed - was killing game logic)
// Rule 2  IOP_MODULE_STRINGS: only .IRX/.irx + specific module names (no .BIN/.DAT)
// Rule 3  referencesIopModule: size cap 800 bytes (larger = game logic)
// Rule 4  accessesHardware: DATA references only (not CALL/FLOW)
// Rule 5  accessesHardware - ACCESSES_MMIO tag only (not disposition)
// Rule 6  KSEG1 masking in all address checks (addr & 0x1FFFFFFF)
// Rule 7  isKernelInternal replaces isRadarBehaviorallyDangerous (syscall+COP0 only)
// Rule 8  IOP refs - STUB, kernel internals - SKIP
// Rule 9  TOML parser: handles name-only AND name@address entries
// Rule 10 Whitelist: entry/_start exempt from all firewalls; BUSY_WAIT_HAZARD with backward branch + jal to syscall stub
// Rule 11 MainLoop shield: ML + depth-1 callees exempt (manual or auto-detect)
// Rule 12 $gp fallback: lui+addiu scan in entry point for stripped binaries
// Rule 13 SMC detection: function boundaries + instruction-at-target check
// Rule 14 No lui scanner for VIF (didn't work, removed)
// Rule 15 No VIF_DMA_UPLOAD tag (ACCESSES_MMIO covers it)
// Rule 16 vcallms - VU0_MICROCODE - forced STUB
// Rule 17 jr $reg (reg!=ra) - COMPLEX_CONTROL_FLOW tag; ORPHAN_CODE tag for zero-xref functions; Unified config output
//
// Rule 18 DC2_GAME_OVERRIDE_PARSER: Reads dc2_game_override.cpp (or any *_game_override.cpp)
//        and imports every bindAddressHandler / registerFunction address as already-classified.
//        Prevents re-stubbing functions that the runtime has already manually bound.
//
// Rule 19 CONVENTION_VIOLATION tag: Detects functions where Ghidra's decompiler reports a0/a1
//        arg aliasing or where the function writes to $a1 as if it were a return buffer
//        (pattern from GetFullPath__FPcPc bug in Phase F5).
//
// Rule 20 INIT_LARGE_FUNC guard: Functions named *init* / *Init* / *__ct__* / *__sinit_*
//        that have calleeCount > 10 OR byteSize > 2000 are tagged INIT_LARGE_FUNC and
//        forced to RECOMPILE (not nop-stubbed). Prevents the Phase F4 bug where init__Fv
//        (large, spawns threads) was silently nop'd.
//
// Rule 21 DMA_CHAIN_TTE_RISK tag: Functions that call both a DMA Send variant AND touch
//        VIF1-range MMIO (0x10009000) are tagged DMA_CHAIN_TTE_RISK. Flags potential
//        TTE=0 + embedded VIFcodes patterns (Phase F7 root cause).
//
// Rule 22 IOP_RPC_DISPATCH tag: Detects the sceSifCallRpc / sceSifBindRpc pattern + sid
//        constant scan. Extracts the SID literal if found, emits it into JSON for
//        cross-referencing with ps2_iop.cpp known SIDs.
//
// Rule 23 ARCHIVE_IO tag: Detects DATA.DAT / DATA.HD2 string references inside I/O wrapper
//        functions (from Phase F6). Tags for human review; these are game-specific archive
//        stubs that need real implementations, not nop returns.
//
// Rule 24 PAD_POLL_LOOP tag: Detects the busy-wait pattern: small function, calls
//        scePadGetState (or has a loop branch + jal), byteSize < 200. Phase F3.5 lesson:
//        always flag pad-state polling loops early.
//
// Rule 25 (reserved/skipped)
//
// Rule 26 CTOR_FIELD_WRITER: __ct__ that writes *(this+K); never nop-stub
// Rule 27 VTABLE_SETTER: CTOR + lui+addiu constant -> *(this+K) (vtable)
// Rule 28 POLL_RETURN_CONSUMER: Tiny returner polled by a backward-branching caller
// Rule 29 A0_PASSTHROUGH_RETURNER: move $v0,$a0/$a1 — auto-stub returning 0 breaks chains
// Rule 30 PROCESS_TERMINATOR: _Exit/abort/TerminateLibrary — never nop_stub
// Rule 31 LIBGCC_INTRINSIC: __[u]div/mod/mul/fix/floatXXdiYY libgcc helpers
// Rule 32 GIF_PATH3_HAZARD: Touches GIF CTRL/CHCR or GS PRIM offset (0x00)
// Rule 33 Z_BUFFER_ALIAS_RISK: ZBUF reg + dsll32/dsrl32 shift-24 pattern (4HH font)
// Rule 34 MPEG_DECODER_TRAP: Calls sceIpu*/sceMpeg*/sceDvd* or refs mpeg.irx
// Rule 35 DISPFB_WRITER: Writes GS reg 0x59/0x5B (DISPFB1/DISPFB2)
// Rule 36 VIF1_TAGHI_BUILDER: VIF1 channel MMIO + dsll32/dsrl32 (DMAtag tag-high)
// Rule 37 TAIL_CALL_INDIRECT: Terminal jr $reg (reg!=ra) as a call/computed flow
// Rule 38 INDIRECT_CALL_T9: jalr $t9 count > 0 (vtable / PIC dispatch)
// Rule 39 mainloop_depth: BFS depth from MainLoop (-1 if unreachable)
// Rule 40 init_chain_depth: BFS depth from entry/_start
// Rule 41 archive_io_callers: Per ARCHIVE_IO function, named caller list
// Rule 42 jalSites dedup: Set semantics on (callSitePc,target) — fixes 3-count anomaly
// Rule 43 IS_SCE_GIF_PK_REF_LOAD_IMAGE: Bullseye for the 4HH/Path3 guard
// Rule 44 PATH3_INITIATOR: Writes to GIF CHCR (0x1000A000) — Path3 starters
// Rule 45 SCE_GIF_PK_FAMILY: sceGifPk*/sceVif1Pk* roster
// Rule 46 TEX0_REG_WRITER: GS reg 0x06/0x07 writers (TEX state corruption hunt)
// Rule 47 PRIM_REG_READER: Reads GS reg 0x00 (PRIM corruption witnesses)
// Rule 48 RGBAQ_WRITER: Writes GS reg 0x01 (vertex color setters)
// Rule 49 DMA_KICK_PATTERN: Writes any DMA channel CHCR base (+0x00)
// Rule 50 DMA_QWC_TADR_WRITER: Writes any DMA channel +0x20 (QWC) / +0x30 (TADR)
// Rule 51 MICROCODE_UPLOADER: VIF1 MMIO + load from .text/.data (MPG payload)
// Rule 52 AUDIO_RPC_HANDLER: sceSd*/sceSpu2*/libsd.irx audio path
// Rule 53 MESWIN_LOADER: Refs string "meswin" — dialogue rendering pipeline
// Rule 54 MC_TRANSITION_GATE: *ForMC/*McCheck*/*McError* small gates (FinishForMC pattern)
// Rule 55 known_dc2_globals: JSON map of known DC2 gp-relative offsets
// Rule 56 is_top_priority_fix: Derived: any community-bullseye tag is set
// Rule 57 focus_set: Top-level array of every top-priority function
// Rule 58 CORRECTED GS privileged MMIO map (0x12000070=DISPFB1, 0x12000090=DISPFB2, ...)
// Rule 59 ACCESSES_IPU_MMIO: 0x10002000-0x10003000 — MPEG decoder hardware
// Rule 60 WRITES_IPU_CMD: 0x10002000 — the MPEG kick (sub-MPEG_DECODER_TRAP)
// Rule 61 GIF_PATH3_REG_TOUCHER: GIF_P3CNT (0x10003090) or GIF_P3TAG (0x100030A0)
// Rule 62 GIF_FIFO_DIRECT_WRITER: 0x10006000 — bypass-DMA GIF write
// Rule 63 VIF1_FIFO_DIRECT_WRITER: 0x10005000 — bypass-DMA VIF1 write
// Rule 64 VIF0_FIFO_DIRECT_WRITER: 0x10004000
// Rule 65 ACCESSES_VU_MICROMEM: VU0/VU1 micro-mem ranges (0x11000000/0x11008000)
// Rule 66 ACCESSES_VU_DATAMEM: VU0/VU1 data-mem ranges
// Rule 67 VIF_OPCODE_BUILDER: lui constant matches MPG/MSCAL/DIRECT/UNPACK opcode
// Rule 68 VIF_MPG_OPCODE_BUILDER: lui 0x4A__ pattern (microcode upload)
// Rule 69 VIF_MSCAL_OPCODE_BUILDER: lui 0x14__/0x15__ (kick)
// Rule 70 VIF_DIRECT_OPCODE_BUILDER: lui 0x50__/0x51__ (GIF inline)
// Rule 71 VIF_UNPACK_OPCODE_BUILDER: lui 0x60__-0x7F__ (vertex upload)
// Rule 72 DMA_TAG_BUILDER: lui constant matches CNT/REF/REFS/CALL/RET/END/REFE
// Rule 73 PSMT4HH_REFERENCE: lui/ori constant == 0x2C (font Z-buffer alias PSM)
// Rule 74 SBUS_IOP_COMM_TOUCHER: 0x1000F200 (MSCOM) / 0x1000F210 (SMCOM)
//
// Rule 75 DISPFB_SDK_WRITER: Callee in {sceGsPutDispEnv, sceGsSetDispEnv, sceGsSetCRTC,
//        mgSetDispEnv, sceGsResetGraph} — picks up SDK-routed DISPFB writers that
//        the raw-MMIO Rule 35/58 misses. Includes GS-dump runtime corroboration input:
//        optional folder of `*.gs.summary.json` from gs_dump_to_summary.py.
//
// Rule 76 PATH3_KICK_VIA_DMA_API: Caller of sceDmaSend*/sceGifSendChain*/
//        sceGsSwapDBuff/sceGsExecStoreImage — the SDK-routed Path3 starters
//        (raw-CHCR Rule 44 misses them).
//
// Rule 77 (reserved/skipped)
//
// Rule 78 VRAM_TBP_OVERLAY: Constants (lui/ori/addiu/li) matching runtime-witnessed
//        tex0_tbps or vram_upload_tbps; emitted as `tbp_constants_loaded` + intersection
//        with merged runtime as `tbp_runtime_confirmed`. TBP list gated on GS-side evidence
//        (trampolines reported "TBP constants").
//
// Rule 79 GS_IRQ_HANDLER_SAFE_STUB: Name matches Signal/Finish/Label/Intc/sceGsSyncH/V
//        handler shape AND all loaded GS-dump captures show IMR fully masking GS IRQs →
//        tag as safe-stub candidate (decoration; no auto disposition flip).
//
// Rule 80 runtime_corroboration: Per-function block cross-checking static bullseye
//        predictions against the merged runtime evidence. Adds tags:
//        RUNTIME_CONFIRMED — at least one bullseye prediction has a witness.
//        RUNTIME_DORMANT_GLOBAL — bullseye predictions but zero runtime witness.
//        RUNTIME_MENU_ONLY — PSMT4HH_REFERENCE only witnessed in UI checkpoints
//        (Inventory/Pause/Character/UI scenes), not in 3D-scene captures.
//        gs_runtime_evidence top-level JSON block with per-checkpoint facts + merged unions.
//
// Rule 81 focus_set re-rank: Confirmed entries first, dormant last.
//
// Rule 82 CTOR_MULTI_FIELD_INITIALIZER: Ctor / Initialize that writes >= 5 distinct
//        this+K slots in first 40 instructions. F33 caught __ct__11mgCDrawPrimFv nop-stubbed
//        → manager/PRIM/Q/Z slots all garbage → entire Begin/Texture/Color chain dead.
//        Firewalled against STUB classification (forceRecompile).
//
// Rule 83 DRAWING_CHAIN_DEPTH: BFS from GS-bullseye roots (sceGifPk family, PATH3_INITIATOR,
//        mgEndFrame, Begin__11mgCDrawPrim). Functions with chain_depth <= 6 firewalled
//        against STUB. Locks in F33's TitleModeDraw -> PrimQuad -> SetSpriteEnv -> Begin chain.
//
// Rule 84 LIFECYCLE_LAZY_INIT_GUARD: Initialize* / Begin__ / Open* / Acquire* whose first
//        instructions read this+0x00 and branch on zero, with byteSize > 50. The
//        "if (manager==null) { install manager; }" pattern that F33 had to manually override.
//        Firewalled.
//
// Rule 85 BITBLTBUF_T4HH_UPLOADER: Function writes BITBLTBUF (GIF reg 0x50) AND loads
//        PSMT4HH/4HL/8H constant. The F32 BITBLTBUF.dpsm=0x2C upload bullseye. Tagged
//        separately from generic PSMT4HH_REFERENCE (which is sampler-side TEX0.psm) so
//        runtime menu_only does not deprioritize these. RUNTIME_MENU_ONLY refinement:
//        skip the tag when the function is a BITBLTBUF_T4HH_UPLOADER or drawing_chain_depth <= 3.
//
// Rule 86 VIF_BUILDER counter wiring: counters now incremented; per-func vif_opcodes_built[] retained.
// Rule 87 PSMT constant — expand match: Now also matches addiu/li-zero, ori-zero, single-imm li
//        for 0x2C/0x24/0x1B/0x13/0x2D (T4HH/T4HL/T8H/PSMCT16/T4).
// Rule 88 LIBGCC_INTRINSIC exact-name: Hardcoded list (__divdi3 etc.) wired alongside regex;
//        PS2 64-bit single-reg ABI tag.
// Rule 89 JALR_T9 accept-any-flow: Counter no longer gated on flow type; tail_call_indirect splits direct vs $t9.
// Rule 90 SPR_SYNC split fields: uses_spr / has_sync_instr / spr_sync_combined emitted separately.
// Rule 91 BITBLTBUF_T4HH depth-2: Caller of an uploader also tagged via asset_upload_traces
//        post-pass; runtime menu_only no longer suppresses.
//
// Rule 92 CTOR class+global+vtable: Demangled __ct__ class name, vtable install offset,
//        vtable target addr, caller mode (direct_only / indirect_only / dual / unobserved),
//        assigned-to-global flag, sibling ctor calls, ctor_risk_tier (CRITICAL / HIGH / MEDIUM / LOW).
//
// Rule 93 CLASS_REGISTRY top-level: classes section grouping ctors / dtor / methods /
//        vtable_addr / has_virtual_draw / instantiation_sites.
//
// Rule 94 VIRTUAL_DISPATCH_SITES: Per-func list of `lw $rX,K($a0); lw $rY,K2($rX); jalr $rY`
//        dispatch sites; slot offset captured.
//
// Rule 95 GLOBAL_RETURN_TRACKING: For every jal site, look ahead for `sw $v0, +imm($gp)`
//        to discover ctor->global bindings. Catches F46.5 TitleCamera null-deref class of bugs.
//        Auto-extends known_dc2_globals.
//
// Rule 96 GIF_NLOOP_DOUBLE_COUNT_RISK: Function that calls both makeGiftagAplusD/
//        MakeGiftagAplusD and closePacketGifTag (Rule 86 F37).
//
// Rule 97 PAD_BUTTON_MASK_CONSUMER: andi/and against a known PS2 pad mask constant.
//        Emits pad_masks_tested[] with friendly names.
//
// Rule 98 OVERRIDE_CLASSIFICATION: Parses dc2_game_override.cpp helper bodies; tags
//        each binding as nop_stub / constant_return / state_machine / probe / real_shim;
//        flags retire_candidate.
//
// Rule 99 FILE_PATH_SPRINTF_SOURCE: Caller of LoadFile2/sceCdRead/sceOpen whose $a0
//        argument was set by sprintf with %s format; emits the format string when resolvable.
//
// Rule 100 FRAME_CLOCK_DRIVER: Function calls sceGsSyncV / WaitVSync / mgEndFrame;
//        emit per-func + collect frame_clock_drivers[].
//
// Rule 101 SIF_CALL_RPC_FID: Capture the constant passed in $a1 to sceSifCallRpc
//        (function-id) alongside SID.
//
// Rule 102 SCEVU0_HELPER_MUSTIMPL: Whitelist sceVu0* matrix/vector helpers; never
//        auto-stubbed; emitted with vu0_helper_family.
//
// Rule 103 ASSET_UPLOAD_TRACES: Cross-references gs_runtime_evidence vram_upload_tbps_union
//        and bitbltbuf_dpsms_union against per-func ori/li constants + writes_bitbltbuf_reg.
//        Back-solves which ELF func should emit the missing T8 dbp=0x2720 dpsm=0x13 upload.
//
// Rule 104 CURRENT_PHASE_INPUTS: Expected upload manifest (dpsm/dbp pairs per phase)
//        consumed by asset_upload_traces.
//
// Rule 105 CALL_CHAINS: save_to_map_load / title_to_menu / texture_upload — pre-computed
//        forward callgraphs to bullseye sinks.
//
// Rule 106 BUILD_INVARIANTS: Build cmd + do-not-modify list emitted for downstream tools.
// Rule 107 PHASE_TRACE_FLAGS: Inventory of DC2_TRACE_* env flags.
//
// Rule 108 C++ DEMANGLER: Itanium-style __ct__<digits><name>F<args>, __dt__, __vt__,
//        method-mangled names. Adds class_name+method_name to per-func record.
//
// Rule 109 DIFF MODE: If prior triage_map.json sits next to output, emit `delta` section
//        listing new/changed/removed funcs.
//
// Rule 110 OVERRIDE_COVERAGE_REPORT: For every game_override binding, flag retire_candidate
//        based on current static signals.
//
// Rule 111 SDK_CALLER_DEDUP_COUNT: Companion *_via_sdk_caller depth-1 metric for every
//        count-zero raw-MMIO detector.
//
// Rule 112 SCHEMA_VERSION: 12.0 (v12 adds Rules 165-177).
//
// Rule 113 GIF_TAG_INLINE_BUILDER: 4-stride store cluster (0/8/0x10/0x18) to a common base,
//        with stored constants whose upper byte encodes a GIFtag REGS/FLG field. Catches
//        mgEndFrame / drawing-prim packet builders that the v8 raw-MMIO detectors miss.
//
// Rule 114 BITBLTBUF_MACRO_SEQUENCE: Function stores const 0x50/0x51/0x52/0x53
//        (BITBLTBUF / TRXPOS / TRXREG / TRXDIR) — a complete upload macro regardless of dpsm.
//        Auto-sets writesBitbltbufReg.
//
// Rule 115 DMA_CHCR_START_KICK: Loads const 0x101 (STR | TIE) AND writes to a known DMA
//        channel CHCR (Path3 starter detection).
//
// Rule 116 DMA_SOURCE_CHAIN_TAG_BUILDER: Stores composite const with high nibble
//        0x10/0x30/0x40/0x50/0x60/0x70 at offset 0 of any base — CNT/REF/REFS/CALL/RET/END
//        source-chain DMA tags.
//
// Rule 117 VIF_TAG_STORED_IMMEDIATE: Any store of const-tracked reg whose upper byte
//        matches VIF_OPCODES — captures MPG/MSCAL/UNPACK built ahead of DMA kick
//        (Rule 67 detected lui only).
//
// Rule 118 DMA_TAG_STORED_IMMEDIATE: Same for high-nibble DMA tag ids.
//
// Rule 119 COMPOSITE_MMIO_RECOVERY: Tracks lui+ori|addiu|or composite values per reg and
//        matches against every EE peripheral range. Fixes MMIO miss when Ghidra doesn't
//        ref-flag the synthesised addr (the F26 vu_micromem=0 / F31 vif1 chunk class
//        of false negatives).
//
// Rule 120 SYSCALL_TRAMPOLINE: addiu $v1,$zero,N; syscall; jr ra stub — names the function
//        from EE_SYSCALL_NAMES (db-syscalls.md).
//
// Rule 121 BACKWARD_BRANCH_SYNC_WAIT: Small body, backward branch, polls a load/syscall
//        in body — F24 / F27 / F28 host-wait blocker class. Tagged DC2_HOST_WAIT_CANDIDATE
//        when also in mainLoopShield.
//
// Rule 122 INFINITE_SPIN_LOOP: 1-2 BB function whose only branch targets its entry. Same
//        family as F24's never-returning dispatch path; quietly retired by the F23c libgcc
//        unblock. INFINITE_SPIN_LOOP requires storeOps==0 (copy loops stored every iteration
//        -> NOP-patch would corrupt data).
//
// Rule 123 INFINITE_FAIL_LOOP: Backward branch into a `break`/`syscall` / `nop`-only block
//        — assertion / panic loops.
//
// Rule 124 IRX_LOADER: >=2 calls to sceSifLoadModule, or 1 call + IRX path string ref.
//        IOP-side init function.
//
// Rule 125 IOP_REBOOT_HANDLER: Calls sceSifRebootIop.
//
// Rule 126 RENDER_FRAME_ENTRY: Name match against the DC2 render frame entry list
//        (mgEndFrame*, mgEndDraw*, mgBeginFrame*, BeginDrawing*, EndDrawing*).
//
// Rule 127 STRUCT_INITIALIZER: Non-ctor func that writes >=4 distinct +K($a0) slots.
//        Catches mgInit-style initializers the ctor demangler misses.
//
// Rule 128 FUNCTION_POINTER_TABLES: Scans non-.text initialized blocks for runs of >=3
//        valid function entry pointers (tag-tolerant for boxed pointers). Discovers
//        vtables Ghidra didn't auto-create. Tags entries DISPATCH_TABLE_TARGET and
//        table-reading funcs TABLE_DISPATCH_CALL. Anonymous classes named Class_0xADDR / slot N.
//
// Rule 129 MODULE_CLUSTERS: Connected components on jal edges. Each function gets module_id;
//        module addr lists emitted at top level. Useful for grouping mg*/mgC*/CScene/CMap/CMenu code.
//
// Rule 130 NAME_PREFIX_MODULES: Prefixes of length 2-6 occurring >=5 times — surfaces
//        engineer-visible subsystems independent of callgraph.
//
// Rule 131 DC2_KNOWN_FUNCTION_ADDRESSES: Hardcoded address -> {name,phase,role,criticality}
//        map from PROJECT_STATE.md so the report tool can lay out priority lists without
//        re-deriving them. (+v11.3 block): VU1 model render+kick chain, character draw chain,
//        CRunScript event VM, front-end, treemap/pad path, UI-text repros.
//
// Rule 132 DC2_KNOWN_TBP_LABELS: VRAM heatmap labels per memory invariants doc
//        (T8_map=0x2720, font_4HH=0x10E0, CLUT_T4HH=0x3FDC, mgDBuff_fbp=0x68,
//        HUD_font_cache=16284..16316). (+G-era atlas/CLUT pages 0x2aa0 title,
//        0x2920/0x2c20 fukusel/cursor, 0x3fd4/0x3fd8 CLUTs).
//
// Rule 133 DC2_RUNTIME_INVARIANTS: Top-level section listing every invariant confirmed
//        across all 9 GS dumps (Path1/2 dead, REGLIST/IMAGE2 never used, IMR=0x7F00,
//        PMODE=0x7F23, FRAME PSM=0, ZBUF PSM=1, HUD pages 16324..16348). Lets the
//        report tool gray-out functions whose only output is into a confirmed-dead pipe.
//        (+G-era): EE_SCRATCHPAD_DMA_CH8_9_REQUIRED, SUBWORD_DMA_STR_KICK,
//        VU1_XGKICK_LIVE_FOR_CHARACTER_MODELS, STALE_PTR_CACHE_CTOR, UNFUNDED_GUEST_HEAP_OOM,
//        EVENT_VM_AUDIO_GATED_STALL, LIVE_PAD_IS_read_pad_stub, DC2_KEY_GLOBALS roster.
//
// Rule 134 DC2_CALL_CHAINS: Pre-computed forward callgraphs for the 5 critical chains:
//        save_to_map_load / title_to_menu / texture_upload / frame_loop / render_chain.
//        (+character_model_vu1 / event_script_vm / costume_select).
//
// Rule 135 DC2_PAD_INPUT_SCRIPTS: Working DC2_PAD_INPUT scripts from F40/F42/F46 fix logs
//        — embedded so the runtime side can re-use them as headless input templates.
//        (+F64 dungeon/opening, +G9 costume).
//
// Rule 136 SCORE_FOCUS_SYNTH: Fallback for focus_set when zero bullseyes fire —
//        picks top-32 by static score.
//
// Rule 137 TRIAGE_ADVISORY_TOML: New TOML appendix [triage_advisory] with nop / patch /
//        force_recompile categorised lists, each line carrying a 4-tag prioritised comment.
//
// Rule 138 STUB_TOML_TAG_COMMENTS: Every spliced stub/skip entry gets ` # TAG1,TAG2,TAG3`
//        so ps2recomp.exe operators can triage at a glance.
//
// Rule 139 DISCOVERED_IOP_SIDS_SECTION: Aggregated map of every detected SID with its caller
//        list — captures ezMIDI / save data / loader RPCs the hardcoded KNOWN_IOP_SIDS table misses.
//
// Rule 140 COP2_DESTMASK_VERIFY: VU0-macro COP2 ops with a PARTIAL dest field (.xy / .z / .xyz ...).
//        F51.8 ROOT CAUSE: the recompiler emitted the COP2 dest-component blend mask in REVERSED
//        lane order, so every partial-dest op wrote X/Y/Z into the wrong SIMD lane → ALL
//        VU0-macro 3D perspective transforms degenerate (off-screen) → dungeon black for 50+ phases.
//        Emits per-func partial/full counts + dest_fields and a top-level `cop2_partial_dest_risk`
//        list (Vertex__11mgCDrawPrim, mgInversMatrix, mgClipBox*, mgDistVector*). Firewalled against STUB.
//
// Rule 141 STATIC_INIT_MANIFEST: For every `__sinit_*` (no jal caller — runs only via the
//        global-ctors table) emit the globals/vtables it installs + UNCALLED_STATIC_INIT. F50.4/F50.7:
//        un-run __sinit leaves a global object's vtable pointer null → its virtual init dispatch
//        silently no-ops (MainScene+0x10548=__vt__6CScene; CRandomCircle / CGeoStone).
//        Top-level `static_init_manifest` is replayable.
//
// Rule 142 MEMORY_ALLOCATOR_NEVER_STUB: Allocator / pool-init / placement-new / array-ctor
//        (memoryInit, Alloc__9mgCMemory, __nw__, construct_new_array, stAlloc, SetHeapMem).
//        F50.1/F50.2: auto-stubbing one returns 0 → null pool → construct-on-null = garbage
//        vtable PC (masquerades as a bad ctor). Forced RECOMPILE; top-level `memory_allocators` list.
//
// Rule 143 GUEST_LOCK_HOG_CANDIDATE: Thread yield/spin function that may hold the single
//        guest-execution mutex without releasing it (GamePadStep → RotateThreadReadyQueue syscall 0x2B).
//        F49.5/F50 menu→dungeon deadlock.
//
// Rule 144 EABI_ARG_T0: Function reads $t0 ($a4) before defining it — consuming the MIPS-EABI
//        5th integer arg. F50.1/F50.2: DC2 passes arg5 in $t0, not on the stack; a CRT/runtime
//        override must match.
//
// Rule 145 MAP_CLUT_PSMCT16_UPLOADER: BITBLTBUF writer that loads a PSMCT16 (dpsm=0x2)
//        constant. F50.8-F50.11: the dungeon map texture subsystem (tbp=0x2580 / CLUT cbp=0x2980
//        PSMCT16) is separate from mgCTextureManager and its CLUT is NEVER transferred → empty CLUT → black.
//
// Rule 146 COMPUTED_JUMP_TARGETS: Back-solves computed `jr $reg` switch tables: harvests
//        Ghidra's resolved jump-table destinations per site and emits them (top-level
//        `computed_jump_targets`) so the recompiler can pre-populate its indirect-jump dispatch
//        instead of panicking on an unknown target. Sites with no resolved target →
//        COMPUTED_JUMP_UNRESOLVED (the real risk set). (jalr $t9 vtable slots remain
//        in virtual_dispatch_sites.)
//
// Rule 147 COP2_SPECIAL_OPS_REVIEW: EE COP2 macro ops beyond the Rule 140 dest-mask blends
//        — vdiv/vsqrt/vrsqrt (EFU Q latency), vclipw (CLIP flag), vrnext/vrget/vrxor (R register),
//        vmr32, vwaitq/p, vopmsub/vopmula, xgkick. The F51.8 fix log explicitly says to spot-check
//        these; they share the COP2 codegen path that reversed the dest mask. Firewalled against STUB.
//
// Rule 148 FPU_NONIEEE_SENSITIVE: EE FPU is non-IEEE (no denormals/NaN, truncation, soft div/sqrt).
//        Flags funcs that write FPU control (ctc1/cfc1) or use div.s/sqrt.s/rsqrt.s while FPU-heavy
//        — naive host float diverges (collision/physics drift).
//
// Rule 149 SDK_COVERAGE_AUDIT: Cross-references every SDK-shaped callee (sce*) against the known
//        rosters + game_override bindings; emits `sdk_coverage_audit` partitioned into must_implement /
//        must_stub / coverage_gap (called but neither bound nor recognized → needs a stub/implement
//        decision before the recomp build).
//
// Rule 150 OVERLAY_LOADER: Detects EE code-overlay exec/load callees (LoadExecPS2/ExecPS2/
//        LoadModuleBuffer ...). Static recompilers assume a flat address space; an overlay game needs
//        per-bank TOMLs. Empty for a single-binary game (DC2) — absence is itself the finding.
//
// Rule 151 STEP1_NAME_MISMATCH: name@addr disagrees with ELF symbol → stale/wrong-region DAC.toml;
//        forced RECOMPILE + review. Also: TRUNCATED NAMES (v9-era input truncated mangled C++ labels).
//        step1 tokens bind by ADDRESS so these are NOT wrong-region drift - they were inflating
//        name_mismatches. Now detected (isTruncatedNameOf), counted as step1_truncated_names, tagged
//        STEP1_TRUNCATED_NAME, and passed through the NORMAL keep gate (decided on real traits)
//        instead of force-rescued with a misleading "wrong-region?" reason.
//
// Rule 152 dual-binding hygiene: entry in BOTH stubs and skip -> keep stub.
//
// Rule 153 RUNTIME-HANDLER ROSTER: scrapes ps2xRuntime (tries D:\ps2r\PS2Recomp\ps2xRuntime first,
//        then asks) for implemented handler names; bound stubs without a handler get
//        NO_RUNTIME_HANDLER -> native_impl_needed + review; per-func has_runtime_handler in JSON.
//        Roster-backed keeps beat promote passes (handler existence = intent + tested implementation).
//
// Rule 154 ELF IDENTITY GUARD: DAC.toml `elf_hash` vs this ELF's md5. output [general] now carries
//        `elf_hash = "<md5>"` of THIS ELF, so the next re-entrant run gets the Rule 154 identity
//        guard automatically.
//
// Rule 155 (reserved - veto override)
//
// Rule 156 MAINLOOP SHIELD DEPTH-3: capped 768; was direct callees only.
//
// Rule 157 SUGGESTED TRIAGE RETURNS: per bound stub: reta0 / ret0_or_ret1_ab_test / ret0 / ret0_then_verify.
//
// Rule 158 OVERLAY GUARD: overlay-block bindings vetoed; out-of-text bindings tagged OUT_OF_TEXT_BINDING
//        -> review. The keep gate is BYPASSED for LOCKED entries and no promote pass (drawing-chain /
//        ctor-risk / sceVu0 / v13 binding firewall / Rule 161b) ever rescues the binding. Only the
//        Rule 158 overlay veto beats a lock.
//
// Rule 159 SYSCALL_TRAMPOLINE POLICY: trampoline shape decided FIRST: STUB only when the runtime
//        implements the handler by name; SKIP only when xref count is 0; otherwise RECOMPILE
//        (recompiler turns `syscall` into runtime->handleSyscall(), always correct).
//
// Rule 160 STRIPPED TRAMPOLINE NAME RECOVERY: decoded $v1 immediate -> EE_SYSCALL_NAMES -> roster
//        -> bind "Handler@0xADDR".
//
// Rule 161 DYNAMIC_CODE_LOADER: FlushCache + file/archive evidence (same body or layered across
//        the call graph). PRECISION: dynamic_code_loaders over-fired on DC2 (34 false: asset loaders
//        that stream DATA.DAT/HD2 + FlushCache per DMA). Real code loader must EXECUTE loaded bytes
//        - now requires an overlay/exec callee (LoadExecPS2/ExecPS2/LoadModuleBuffer) in the same body,
//        and the layered Rule 161b post-pass only runs when the ELF has >=1 overlay-exec callee
//        anywhere (overlay_loaders>0). DC2 (flat ELF, overlay_loaders=0) -> 0. DC2 is a single flat
//        ELF: statistic should be 0; non-zero is a project red flag.
//
// Rule 162 SPR_DMA_STAGER / SUBWORD_DMA_STR_KICK: The G26 root-cause class, generalised. Flags funcs
//        that program a fromSPR(ch8 0x1000D000)/toSPR(ch9 0x1000D400) DMA channel, and funcs that kick
//        a DMA via a sub-word (sb/sh) store into a CHCR word (the STR bit). DC2 stages each VU1 model
//        VIF packet in EE scratchpad then copies it into mgVif1Packet via a fromSPR DMA started by a
//        `sb` to CHCR+1; a runtime whose writeIORegister only dispatches GIF/VIF1 word writes drops it
//        -> empty model slot -> no XGKICK. Detected in BOTH the Ghidra-ref and the composite-MMIO-recovery
//        scan paths; per-func + top-level `spr_dma_stagers` list (with override_hookable for the fix strategy).
//
// Rule 163 VU1_DOUBLE_BUFFER_FRAMER: Builds BASE+OFFSET VIFcodes = the TOPS double-buffer framing
//        the model needs (the context G23/G24 hunted). Derived from vifOpcodesBuilt (BASE 0x03 +
//        OFFSET 0x02 both present).
//
// Rule 164 STALE_PTR_CACHE_CTOR: A ctor that caches a derived global pointer (a Get*Ptr/Man/Data/Mgr
//        callee result) into this+K. If it runs before the source is funded it caches 0/stale and the
//        downstream Draw silently skips (G12 cursor / G13 names / F50.4). Repair idempotently in a
//        per-frame wrapper, never in the ctor. Per-func emit: derived `override_hookable` (= called
//        only via indirect jalr/jr $t9, never via direct jal). registerFunction overrides are consulted
//        ONLY for indirect dispatch; a direct-jal-only function is NOT hookable that way and must be
//        fixed by wrapping the jal target or codegen.
//
// ================================================================
// v12 RULES (165-177) - DC2 G27-G52 retrospective + general PS2 RTT/present hazards
// ================================================================
//
// Rule 165 VRAM_OVERLAP_MAP (top-level `vram_overlap_pairs`): cross-function VRAM page-aliasing
//        hunt. Every G-phase from G33-G50 chased one bug class - a FRAME/ZBUF target whose VRAM
//        page ALIASES a texture/CLUT page (the model RTT fbp=0x139 == tex page 0x2720; the costume
//        Z block 0x1a00 == menu-text VRAM, G45). This pass intersects each function's loaded
//        VRAM-page constants (tbpConstantsLoaded ∩ KNOWN_DC2_TBP_LABELS) with the GS reg KIND it
//        writes (FRAME / ZBUF / TEX0 / BITBLTBUF / DISPFB) and emits pairs of functions that
//        target the SAME labelled page with DIFFERING kinds → RTT_ALIAS / Z_ALIAS / TIMESHARE.
//        One static signal that would have front-loaded ~20 phases of blind page hunting.
//
// Rule 166 RTT_TARGET (per-func): writesFrameReg AND loads a const that hits a known texture/CLUT
//        page (or fbp 0x139) → tag RTT_TARGET + rtt_aliased_pages[]. Firewalled against STUB
//        (G37/G44 had to hand-protect the in-place RTT writers).
//
// Rule 167 ZBUF_VRAM_ALIAS_RISK (per-func): writesZbufReg AND a loaded const hits a FRAME/texture
//        page → the G45 root (synthetic Z block aliases live VRAM). Generalises the narrow v4
//        Rule 33 (which only caught the 4HH dsll32 font shape).
//
// Rule 168 SKINNED_DRAW_CHAIN refresh: DC2_KNOWN_FUNCTION_ADDRESSES extended with the G26-G52
//        skinned-model chain (DrawDirect__12CActionChara/CCharacter2, COutLineDraw, DrawDivSprite4,
//        DeformMesh, MotionProc2, GetLWMatrix, mgInversMatrix, mgGetDrawRect). Marks skin_chain_role.
//
// Rule 169 VF0_DEPENDENT_INVERSE (per-func): a matrix-inverse helper (name ~Invers / mgInvers*)
//        that uses COP2 + an EFU_Q-latency op (vdiv/vrsqrt → Q) feeding a vmulq. The G40 50-phase
//        collapse: Q = vf0.w/det, and vf0.w must be the HW-hardwired 1. Emits a note that the
//        runtime must pin vu0_vf[0]=(0,0,0,1). Firewalled against STUB.
//
// Rule 170 AUDIO_COMPLETION_GATE (per-func): backward-branch wait that polls an audio/stream
//        completion signal (sceSifCheckStatRpc / StreamOpenState / sceSd* / voice-done flag).
//        F63/F64 event stall class AND the #3 active foundation blocker (audio). Tagged
//        DC2_AUDIO_GATED_STALL when also a sync-wait loop.
//
// Rule 171 MEMCARD_IO (per-func): calls the sceMc*/libmc save-data family (card detect / dir /
//        file / format). #4 active blocker (save/load) - not yet implemented, so a roster of the
//        subsystem entry points is pure forward-help. Top-level `memcard_io_roster`.
//
// Rule 172 EVENT_SCRIPT_VM: CRunScript VM materialised in DC2_KNOWN + DC2_RUNTIME_INVARIANTS
//        (exe/resume/run @0x1873c0/0x1871e0/0x187210; layout +0x38 vmcode / +0x3c done / +0x40
//        skip / +0x08 ext table; opcodes 3 push / 0x13 call / 0x15 ext / 0xf|0x1b end / 0x17 yield).
//
// Rule 173 PRESENTATION_FIELD_STATE (per-func): writes a GS privileged field/interlace reg
//        (SMODE1 / SMODE2 / PMODE / CSR / SYNCV) beyond plain DISPFB. #5 blocker (interlace jitter).
//        Top-level `presentation_field_writers`. General PS2: the deinterlace/field-timing surface.
//
// Rule 174 DISPLAY_BUFFER_FLIP (per-func): a DISPFB writer that is also a frame-clock driver or
//        loads >=2 distinct fbp-shape constants → the double-buffer/present boundary signal G49
//        needed (clear private Z once per flip). General PS2 double-buffer detection.
//
// Rule 175 CLUT_CACHE_INVALIDATOR (per-func): issues TEXFLUSH (GS reg 0x3F) or writes TEX0 while
//        loading a known CLUT-page const. PROJECT_STATE flags CLUT upload / cache-invalidation as a
//        top corruption suspect after allocator fixes; no prior detector. Top-level `clut_cache_ops`.
//
// Rule 176 PERF_HOT_FRAME_PATH (per-func, derived): mainloop_depth in [0,3] AND has a backward
//        branch (inner loop) AND calleeCount high → frame-hot optimisation candidate. #7 blocker
//        (few FPS). Static cannot measure frequency; ranks the suspects. Top-level `perf_hot_candidates`.
//
// Rule 177 GS_LOCAL_MEM_BUDGET (top-level `gs_local_mem_budget`): sum of distinct labelled VRAM
//        pages referenced statically; flags >4MB (PS2 GS local memory) → bank-switched VRAM the
//        recompiler's flat model would break. Pairs with Rule 150 overlay logic on the GS side.
//
// ================================================================
// v13 RULES (178-189) - DC2 G53-G82 title-3D retrospective + general PS2 hazards
// ================================================================
//
// Rule 178 CONDITIONAL_INIT_ON_GLOBAL (per-func): instruction-scan for the shape
//        `lw $rX, <global>; beq/beqz $rX,$zero,skip; <stores that configure an object>`.
//        G58/G81 KILLER (cost ~6 phases): TitleModeInit's camera-setup block runs only
//        `if (TitleCamera != 0)`; headless TitleCamera@0x377E38 was still 0 (its producer
//        had not run) → the block was skipped → the camera kept its ctor defaults
//        (mgCCameraFollow distance=40/height=30/look-at-origin) → the rock cavern was out of
//        frame. Same shape as the empty scene-camera slots (CScene::Initialize ordering).
//        Generalises Rule 84 (LIFECYCLE_LAZY_INIT_GUARD, which only saw `this+0`) to a
//        GLOBAL-guarded configuration block. Captures guard_globals + configured_slots.
//        Firewalled against STUB. Feeds Rule 186.
//
// Rule 179 RENDER_MODE_SELECTOR (per-func): a function that picks a per-mesh render mode
//        (copy/passthrough vs transform/VU-packer) and writes the selector into a render-info
//        struct. G75-G80 (cost ~6 phases): every title map-part mesh was flagged TRANSFORM
//        (`mgRENDER_INFO+0xfc4`!=0 → VU packers 0x1c50/0x1ff0/0x1dc0 whose +2048/ADC gate culls
//        100%) instead of COPY (passthrough packer 0x1b68 that carries tbp + per-vertex ADC) →
//        flat-blue background. The discriminator is `mgClipInBoxW@0x12f380` ret stored as the mode
//        flag. Detected as: callee in the clip-test/render-mode roster OR name in the render-mode
//        roster, with a store of the result. Top-level `render_mode_selectors`. Firewalled.
//
// Rule 180 VERTEX_LIGHTING_NORMAL_TERM (per-func): per-vertex directional-light path. G82:
//        the title rock per-vertex SHADE had RED ≈ half HW (runner R≈36 vs HW R≈66) → MODULATEd
//        brown texture went green everywhere; prime suspect = the title map-part directional-light
//        N·L sign / normal-transform applied with the wrong sign (HW brightens R, runner darkens it).
//        Detected as: callee in {GetLightInfo, mgSetLight, mgSetAmbient, mgSetFogParam, *Light*} OR
//        (COP2 OUTER_PRODUCT/dot feeding an RGBAQ writer), with a draw-chain anchor. Top-level
//        `vertex_lighting_terms`. Firewalled. Static cannot prove the sign — it ranks suspects.
//
// Rule 181 VTABLE_TAILCALL_THUNK (per-func): a terminal `jr $rX` (rX∉{ra,t9}) where $rX was
//        loaded from `*(objptr + K)` (a vtable slot) — the inherited-virtual tail-call. G59:
//        Draw__8mgCFrame@0x1387f0 (`a1=0; jr *(vtable+0x44)`) was mistranslated by the recompiler
//        into a return-to-dispatcher ("Function at address 0xN not found") instead of completing
//        the inherited call → mgDraw exited early → process fell through to _Exit. Distinct from
//        Rule 37 (generic indirect tail) and Rule 38 (jalr $t9). Emits tailcall_vtable_slots[].
//        Firewalled (recompiler-dispatch risk). General PS2: every C++ game with virtual inheritance.
//
// Rule 182 RTT_NO_RESTORE (per-func): an RTT_TARGET (Rule 166) FRAME writer that targets an RTT/
//        texture page but does NOT also write a display-buffer FRAME (0x0/0x68) back in the same
//        body → GS render-target / scissor left pointing at the RTT page. G79: after Title→New
//        Game→costume→back, the costume RTT (fbp=0x139) was never restored → title 3D bg flat-blue.
//        Top-level `rtt_no_restore`. General PS2: RTT scope leaks.
//
// Rule 183 TITLE_CHAIN_ROSTER refresh: KNOWN_DC2_FUNCTION_ADDRESSES + KNOWN_DC2_TBP_LABELS +
//        DC2_RUNTIME_INVARIANTS + DC2_CALL_CHAINS extended with the G53-G82 title-3D facts
//        (TitleLoop/TitleModeInit/TitleMapDraw, the clip-test render-mode discriminator, the
//        copy vs transform packer addresses, mgRENDER_INFO lightInfo layout, TitleCamera globals,
//        the per-vertex-RED-deficit invariant). Pure data — stops the report re-deriving them.
//
// Rule 184 VU_FLAG_PIPELINE_UPLOADER (per-func, advisory): an EE function that uploads VU
//        microcode (Rule 51/68 MICROCODE_UPLOADER, or mgSendVuProg). The EE script cannot scan VU
//        μcode, but G71 found the VU1 interpreter never maintained MAC/STATUS flags, so any
//        FMEQ/FMAND/FMOR/FCAND→IBxx in an uploaded program evaluated against constant 0. Top-level
//        `vu_flag_pipeline_uploaders` flags the upload sites whose programs need flag upkeep verified.
//
// Rule 185 LOOP_STATE_MODEL (top-level `loop_state_model`): the front-end/dungeon LoopNo legend +
//        the mutually-exclusive front-end sub-states. G79: `LoopNo=3 && titleMode=2 && menuId=0x17`
//        is an illegal-concurrent state (TitleLoop New-Game menu + MenuCostumeSel both live) that
//        leaked GS state. Materialised so the report can flag draws reachable in contradictory states.
//
// Rule 186 INIT_ORDER_DEPENDENCY (top-level `init_order_hazards`, general PS2): cross-function
//        producer→consumer ordering for globals. Builds global→writers (ctor/return-to-global/
//        __sinit installs) and global→guarded-readers (Rule 178). Emits INIT_ORDER_HAZARD when a
//        global is read-and-branched-on by a reader whose only writer is a __sinit / uncalled
//        static-init (headless-init-ordering gap, the most reusable G58/G81 signal).
//
// Rule 187 PACKED_RGBAQ_BUILDER (per-func, advisory, general PS2): a GIF_TAG_INLINE_BUILDER
//        (Rule 113) that also writes RGBAQ. G82: GIF PACKED RGBAQ is a SPREAD layout (R=byte0,
//        G=byte4, B=byte8, A=byte12) — a contiguous parser gets (R,0,0,0). Flags the builders whose
//        emitted PACKED vertex colour the runtime GS decode must read as spread. Top-level
//        `packed_rgbaq_builders`.
//
// Rule 188 FRAME_RESUME_RISK (per-func, advisory, general PS2): a large draw/frame function that
//        can be preempted/resumed mid-body (re-entered at an interior label) — G58/G59 resumed
//        TitleMapDraw at an interior label with the wrong $sp ($0x830 too low) → garbage saved-$ra
//        → bad-PC. Approximated as: byteSize large AND (render-frame-entry OR drawing_chain_depth in
//        [0,6]) AND terminal indirect flow. Top-level `frame_resume_risk`.
//
// Rule 189 SCHEMA_VERSION: 13.0 (v13 adds Rules 178-189).
//
// ================================================================
// v15 RULES (190-198) - DC2 G83-G115 retrospective + general PS2 ADC/packer,
//                       allocator-coherence, frame-pacing, camera hazards
// ================================================================
//
// Rule 190 GIFTAG_PRIM_CLASS_SELECTOR (per-func + top-level `prim_class_selectors`):
//        an EE function that builds the VIF UNPACK selector qword (DC2 `qword38`) a VU
//        dispatcher reads to PICK the PRIM-class packer (indep-tri / tristrip / trifan /
//        copy). G77-G115 (cost ~30 phases) hand-decoded this every phase. DC2 anchor =
//        CreateRenderInfoPacket__12mgCVisualMDT@0x1404d0; the selector bit formula is
//        materialised as static metadata (bit0=fc0||fc4, bit1=fc4, bit2=desc+0x2c, ...).
//        Detected as: name in PRIM_SELECTOR_NAMES, OR (builds a VIF UNPACK opcode AND is a
//        render-mode selector). Firewalled against STUB. General PS2: every mg/libgraph-style
//        VU engine routes primitives through a selector qword.
//
// Rule 191 ADC_KICK_VERTEX_SOURCE (per-func + top-level `adc_kick_sources`): the 50-phase
//        title hole (G65-G115). The VU `+2048`/0x800 add that sets the per-vertex ADC
//        ("Add Drawing Kick" suppression = tristrip strip-restart) is UNCONDITIONAL in the
//        packer, so HW's selective ~60% pattern is driven by the per-vertex INPUT (the vertex
//        `.w` / a per-vertex ADC flag in the EE-built geometry stream). The runner zeroes /
//        uniformly-sets it (blue void or over-draw). Flags EE-side per-vertex geometry builders
//        and classifies adc_source = input_driven_xyz3 (writes both XYZ2+XYZ3 = restart control
//        present) / uniform_xyz2 / constant_kick (only the 0x800 add). Firewalled. THE signal
//        that would have front-loaded the active blocker. General PS2: any VU1 tristrip game.
//
// Rule 192 XYZ2_VS_XYZ3_KICK_WRITER (per-func + top-level `kick_mode_writers`): GS reg 0x05
//        XYZ2 (draw-kick) vs 0x0D XYZ3 (no-kick / strip-restart) writer. Both already in
//        KNOWN_GS_REGS but had no detector. Alternating them is per-vertex drawing-kick control;
//        in PACKED mode the ADC bit is bit 111 of the XYZ qword (a SPREAD field, cf. Rule 187
//        RGBAQ). Detected via the const-tracked A+D reg store (0x05/0x0D). General PS2.
//
// Rule 193 TEXTURE_RELOAD_INTERLEAVE_HAZARD (per-func + top-level `texture_reload_interleave`):
//        G90-G97 (cost ~8 phases). A "per-block reload" function binds MANY TEX0 up front then
//        draws MANY batches in a loop, so each batch samples whatever was last-bound (HW binds
//        one TEX0 per strip). Detected as: writes TEX0 AND a per-batch loop (backward branch)
//        AND draw-kick evidence (gifTagInlineBuilder / path3 / indirect dispatch), or a
//        texture-manager name. Advisory. General PS2: any block-batched texture pipeline.
//
// Rule 194 ALLOCATOR_FAMILY_COHERENCE (top-level `allocator_family` + `allocator_family_split`):
//        the PROJECT_STATE regen caveat #1. malloc/_malloc_r, free/_free_r, realloc, calloc,
//        memalign/_memalign_r, operator new/delete MUST all land on the SAME side (all runtime
//        or all recompiled); a split heap frees through a different allocator → silent
//        alignment / CLUT / menu corruption. Audits the whole family's dispositions and raises
//        ALLOCATOR_FAMILY_SPLIT. A build-correctness invariant the map now enforces. General PS2.
//
// Rule 195 VSYNC_COUPLED_GAME_STEP (per-func + top-level `frame_pacing_drivers`): the #2
//        foundation blocker (perf). The title game-loop steps logic only when render completes
//        (~0.3-1.5x/s vs 30; G103/F52 half-rate). Flags functions that BOTH advance game state
//        (writes globals, fan-out) AND wait on vsync/frame completion (FRAME_CLOCK_DRIVER /
//        sceGsSyncV / mgEndFrame) in one body, shallow from the main loop. Static cannot measure
//        FPS - it names the coupling site so the perf phase starts at the right function.
//        Complements Rule 176 PERF_HOT_FRAME_PATH. General PS2.
//
// Rule 196 VIEW_PROJECTION_MATRIX_WRITER (per-func + top-level `view_projection_writers`):
//        G98/G99. The SHARED camera/view-projection matrix (DC2 mgRENDER_INFO@0x380ec0 +0x10
//        view / +0x110 proj / +0x150) was wrong while the per-part WORLD matrices were
//        byte-perfect. Separates view/projection writers from world-matrix writers so an
//        "off-screen geometry" bug routes to the camera source, not the (correct) world
//        transform. Detected via camera/projection callee+name roster + a write to a renderinfo
//        global. Firewalled. General PS2: every 3D engine with a shared view matrix.
//
// Rule 197 OBJECT_ARRAY_CTOR (per-func + top-level `object_array_ctors`): the G92 deferred
//        georama null-vtable. An array of polymorphic objects (CEditMap+0x1054[i]) each needs
//        its vtable; an auto-stubbed element ctor leaves vtable+K null → the indexed virtual
//        dispatch (`*(base+i*stride + K)` jalr) faults (DrawSub__8CEditMapFi pc-zero). Extends
//        Rule 142 construct_new_array with the construct-loop + the indexed-dispatch consumer.
//        Firewalled against STUB. General PS2: any C++ game with arrays of virtual objects.
//
// Rule 184+ VU_EXEC_HAZARD_MANIFEST (top-level `vu_exec_hazard_manifest`): consolidation of the
//        four worst VU/COP2 interpreter divergences this project burned phases on - Q-register
//        latency (G87), MAC/STATUS/CLIP flag pipeline (G71), vf0=(0,0,0,1) (G40), COP2 dest-mask
//        lane order (F51.8), plus EE-FPU/denormal clamp - emitted per relevant function as a
//        checklist so a future regen/route cannot silently miss one. Derived from existing
//        traits (no new scan). General PS2.
//
// Rule 198 SCHEMA_VERSION: 14.0 (v15 adds Rules 190-198; refreshes Rule 184).
//
// ================================================================
// v15.1 RULES (199-202) - PCSX2 source cross-check (D:\ps2r\pcsx2-master).
// All EE constants verified against PCSX2 (GS A+D reg ids GSRegs.h; PACKED ADC =
// U32[3]&0x8000 = bit 111; DMA tag ids REFE=0..END=7 Dmac.h; VIF cmd map
// Vif_Codes.cpp). These add the few HW behaviours PCSX2 models that no rule flagged.
// ================================================================
//
// Rule 199 VIF_UNPACK_DECOMPRESS_STATE (per-func + top-level `vif_unpack_decompress_state`):
//        PCSX2 Vif_Unpack.cpp/Vif_Codes.cpp. The VIF1 UNPACK path decompresses with STMOD
//        (mode 1 = dest+MaskRow, mode 2 = difference-accumulate), STMASK (per-component 2-bit:
//        0 data / 1 MaskRow / 2 MaskCol / 3 SKIP the VU-mem write), STCYCL (cl/wl fill-skip),
//        STROW/STCOL (the row/col regs), plus ITOP/BASE/OFFSET (double-buffer framing). A
//        runtime VIF that ignores mode/mask/row/col/cycle silently corrupts the unpacked
//        vertex/colour stream. DC2 stages every VU1 model packet through UNPACK (G26 delivery).
//        Detected from const-tracked VIF command bytes, GATED on independent VIF evidence
//        (vifOpcodesBuilt / VIF1 MMIO / microcode upload / double-buffer framer). General PS2.
//
// Rule 200 GS_XYOFFSET_GUARD_BAND (per-func + top-level `xyoffset_guard_writers`): writes GS
//        XYOFFSET (A+D 0x18/0x19) — the 12.4 guard-band centre (typ. 2048<<4). G88: the title
//        rock's `+2048` integer bias places verts into the ±2047 guard band; an XYOFFSET /
//        bias mismatch fans geometry off-screen. Pairs with Rule 191's kick_const_add (0x800).
//        General PS2: every VU1 geometry game biases into the guard band.
//
// Rule 201 GS_TEX1_FILTER_WRITER (per-func + top-level `tex1_filter_writers`): writes GS TEX1
//        (A+D 0x14/0x15) — MMAG/MMIN texture filter (+ MXL/LCM mip). G8: DC2 UI/HUD fonts are
//        point-sampled (TEX1=0x201, MMAG/MMIN=0); "fix the blur" by changing filter mode is
//        wrong. Flags the filter-mode setters so a sampling bug routes to TEX1, not the sampler.
//        General PS2.
//
// Rule 184++ VU_EXEC_HAZARD_MANIFEST adds P_LATENCY: PCSX2 VUops.cpp confirms the VU EFU
//        P-register pipeline (ESADD/ERSADD/ELENG/ERLENG/EATAN/ESUM/ESQRT/ERSQRT/ESIN/EEXP +
//        WAITP) - reading P before WAITP gives the stale pipelined value (the exact G87 Q-latency
//        class, separate register). Every microcode uploader's program is flagged to verify P
//        (and Q) latency + MAC/STATUS/CLIP flags. EE script cannot scan VU microcode; it marks
//        the upload sites. General PS2.
//
// Rule 202 SCHEMA_VERSION: 14.1 (v15.1 adds Rules 199-202; refreshes Rule 184 with P_LATENCY).
//
// ================================================================
// v15.2 RULES (203-206) - skill cross-check (D:\ps2r\dc2\skill). The agent skill the
// porter reads names FOUR silent-wrong recompiler codegen classes (SKILL.md L13;
// 10-agent-guardrails L27/L64 "audit the WHOLE class"): VU0/COP2 partial-dest masks
// (Rule 140), MMI, control-reg maps, branch thunks (Rule 181). It also lists CFC2/CTC2
// in the 15-vu1-gs-debugging §2 VU checklist and a "sampled page with no upload" decisive
// probe in §4.1. These add the rosters that let the AI sweep those whole classes.
// ================================================================
//
// Rule 203 MMI_SIMD_OP (per-func + top-level `mmi_codegen_risk`): the EE R5900 Multimedia
//        Instructions (128-bit SIMD integer: PADDW/PEXTLW/PMADDW/PCPYLD/PMFHL/PPACW/QFSRV...
//        + the pipeline-1 ops MULT1/DIV1/MADD1/MFHI1/MFLO1). The recompiler can emit wrong
//        C++ for these (lane/pack/HI1-LO1 errors) SILENTLY, exactly like the partial-dest
//        class. No prior rule flagged them. Emits the roster so the AI can "audit the whole
//        class" (guardrails L64) instead of one op at a time. General PS2.
//
// Rule 204 COP2_CONTROL_REG_ACCESS (per-func + top-level `cop2_control_reg_access`; adds
//        CONTROL_REG_MAP to the Rule 184 manifest): CFC2/CTC2 read/write a VU0 control
//        register by ARCHITECTURAL macro index (15-vu1-gs-debugging §2.1: STATUS=16, MAC=17,
//        CLIP=18, R=20, I=21, Q=22, P=23, TPC=26, CMSAR0=27, FBRST=28, VPU_STAT=29,
//        CMSAR1=31). The F51.8 audit found a control-reg map defect; the recompiler can map
//        the numeric field to the wrong reg. Completes the §2 VU checklist coverage. Captures
//        the index when resolvable. General PS2.
//
// Rule 205 UNFUNDED_TEXTURE_PAGE (top-level `unfunded_texture_pages`, advisory): the
//        15-vu1-gs-debugging §4.1 DECISIVE probe materialised statically - a labelled VRAM
//        page that is SAMPLED (a TEX0 writer loads its const) but has NO BITBLTBUF uploader
//        in the static set → the "game binds a tbp/cbp the texture manager never uploads to"
//        black-texture class. Static can miss composite/computed uploads (false positives),
//        so it is flagged "confirm with a runtime BITBLTBUF-dbp counter", not asserted.
//        Derived from the Rule 165 vramPageWriters map. General PS2.
//
// Rule 206 SCHEMA_VERSION: 14.2 (v15.2 adds Rules 203-206; surfaces the v15 hazard counts in
//        functions_index statistics{}; fixes the per-func/index schema_version stamp).
//
// ================================================================
// v16 RULES (207-216) - DC2 G116-G137 retrospective (the ~22-phase title-cavern
//                       copy/transform packer + near-plane-clip + SPI-dispatch saga)
//                       + general PS2 GS-clip / packed-field / data-driven-VM hazards.
// Grounded in plans/phase-G{116..137}-fix-log.md + PS2_PROJECT_STATE.md + ROADMAP.md.
// ================================================================
//
// Rule 207 VERTEX_KICK_FORMAT_ADC_CAPABILITY (per-func + top-level `adc_capable_packers`):
//        the G131-G137 root (cost ~7 phases). A vertex-emitting VU/EE packer's per-vertex
//        DRAW-control (ADC = strip-restart / "no draw kick") is only possible if its emitted
//        GS vertex FORMAT carries the ADC bit. G132 decoded DC2's copy packer 0x1b68: it emits
//        XYZF2 where word3 is the FOG byte (VF26.w = clamp(VF29.x + VF29.w*VF16.w, 0, 255), a
//        fog-clamp whose ceiling 255 << 2048) so ADC = bit15(FTOI4(.w)) is STRUCTURALLY ALWAYS
//        0 BY DESIGN -- it physically cannot carry HW's selective ~45%-at-pos2+ restart pattern.
//        The transform packer 0x1ff0 emits XYZ2 (ADC-capable via the +2048 guard add) but is
//        100% nodraw by correct microcode (G117/G119). Classifies each packer's adc_capability =
//        xyzf2_fog_no_adc (restart impossible) / xyz2_adc_capable (+2048 guard) / xyz3_norestart.
//        Detection: const-tracked FTOI4 -> SQI/store of a position vector whose .w source is a
//        fog-clamp (mul+add then clamp to a <=255 ceiling) => xyzf2_fog_no_adc; whose .w is a
//        +0x800/+2048 guard bias (cf. Rule 191/200) => xyz2_adc_capable. Refines Rule 192
//        (which only saw the A+D 0x05/0x0D store, not the emitted-format ADC capability).
//        Firewalled. THE signal that would have ended the streak hunt in one phase.
//        General PS2: any VU1 packer -- "can this packer even restart a strip?" is a format fact.
//
// Rule 208 PERSPECTIVE_DIVIDE_NEAR_PLANE_SOURCE (per-func + top-level `near_plane_sites`):
//        G125-G129 (cost ~5 phases). PS2 GS performs NO triangle/near-plane clipping (Rule 213),
//        and FTOI4 packs screen XY as 12.4 fixed point (int32 then masked to 16 bits) -- so a
//        BEHIND-camera vertex (q = 1/W <= 0) has an already-SATURATED/WRAPPED screen XY before the
//        GS sees it. Reconstructing clip-space (clip = screen * W) from that saturated XY yields
//        GARBAGE -> screen-spanning wedges (G128). The near plane MUST be handled on the float
//        position + q BEFORE FTOI4 (where the true 1/W sign lives), or the straddling triangle
//        rejected. Flags EE/VU sites that compute 1/W (DIV/RSQRT feeding a position multiply) and
//        then FTOI4 the result; emits pre_ftoi4_w_available + near_plane_strategy = clip_homog /
//        reject_q_le_0 so the runtime rasterizer routes near-plane handling to the unsaturated
//        source, not the reconstructed 12.4. DC2 anchors: copy/transform packer pipelines, the
//        title-rock g104 clip path. General PS2: every perspective-divide-then-FTOI4 geometry path.
//
// Rule 209 SPI_CONFIG_COMMAND_DISPATCH (top-level `spi_config_commands`): G129/G130 (cost ~2
//        phases) hunting why `cfgWATER_VERTEX@0x1648F0` never dispatches during the title map
//        load (and then learning HW never dispatches it either -- the trifans are cavern MODEL
//        geometry, not water). DC2's map-config is a STRING/ID-keyed command table: handlers in
//        the `cfgXXX` family, args pulled via `spiGetStackInt@0x1463E0` / `spiGetStackVector`,
//        created objects stored into CMap slots (e.g. CWaterFrame -> CMap+0xcf0). Rosters the
//        command-name -> handler bindings + whether each handler is reached, so a "missing map
//        feature" routes to the dispatch table, not a blind render hunt. Anchor cfgWATER_VERTEX,
//        CreateWaterFrame@0x185D40. Feeds Rule 210. DC2-specific roster; general shape in Rule 210.
//
// Rule 210 DATA_DRIVEN_COMMAND_INTERPRETER (per-func + top-level `command_interpreters`, general
//        PS2): generalises Rule 209 + the CRunScript event VM (Rule 172). Detects a function that
//        reads an opcode/command-id from a stream/struct (`lw $op, K($stream)`) then dispatches
//        through a `base + id*4` function-pointer table (Rule 128 / computed-jump / jalr). These
//        interpreters STALL SILENTLY when one handler is unimplemented/stubbed (DC2 burned this on
//        the CRunScript audio-gated ext wait F63/F64 and the SPI config dispatch G129/G130). Emits
//        the table base + resolved handler set + any unresolved/uncalled id. General PS2: every
//        game ships script / cutscene / map-config / AI VMs on this shape.
//
// Rule 211 PASSTHROUGH_PACKER_RENDER_PATH (per-func + top-level `packer_families`): G130 root.
//        DC2's VU1 dispatcher (routes 0x730/0x760/0x7b0) selects among THREE packer families with
//        very different render contracts: COPY/passthrough `0x1b68` (EE-pre-projected screen-space,
//        no VU transform, XYZF2 fog -> Rule 207), TRANSFORM `0x1ff0`(tristrip)/`0x1dc0`(tri)
//        (VU-projected, XYZ2 +2048 ADC gate), and TRIFAN `0x1c50`. HW draws the visible cavern via
//        the copy/trifan route; the runner had no working copy-route render so G100 FORCE-routes
//        everything through the nodraw transform packer (load-bearing band-aid) -> holes + over-floor
//        + zero trifans. Tags each packer family + flags geometry force-routed away from a
//        non-functional passthrough path. General PS2: mg/libgraph VU engines all multiplex packers.
//
// Rule 212 PRIVATE_DEPTH_SCOPE (per-func, advisory): G125. A scene/RTT draw that depth-orders its
//        own geometry but shares (or lacks) a Z buffer overdraws back-over-front. The title cavern
//        needed a PRIVATE per-frame-cleared Z buffer (the back cavern wall was overdrawing the front
//        mural with no depth test). Flags RTT_TARGET (Rule 166) / scene draws that write FRAME to an
//        RTT page and emit many overlapping triangles but write no ZBUF in the same scope. Pairs
//        with Rule 174 (display-buffer flip = when to clear the private Z). General PS2.
//
// Rule 213 GS_NO_HW_CLIP_MANIFEST (top-level invariant, general PS2): materialises the hardware
//        fact that burned G125-G129 -- the PS2 GS does NO triangle, near-plane, or guard-band
//        CLIPPING; it only SCISSORS, and out-of-guard-band coords WRAP (12.4). All clipping is the
//        VU's responsibility (per-strip ADC restart / vertex drop), done on float clip-space BEFORE
//        FTOI4. Consolidates Rule 200 (guard band), Rule 207 (ADC format), Rule 208 (near-plane
//        source) into a single checklist so a future regen/route cannot silently re-introduce the
//        "reconstruct clip from saturated 12.4" wedge bug. General PS2.
//
// Rule 214 PACKED_FIELD_ALIAS_FOG_ADC (per-func, advisory, general PS2): the GS PACKED-mode
//        field-alias hazard generalised from the G132 root. Word3 of the XYZ qword is the FOG byte
//        (XYZF2, when PRIM.FGE=1) OR carries the ADC bit at bit 111 (XYZ2/XYZ3) -- the SAME bytes
//        mean different things by format. A runtime GS decoder that reads word3 as ADC when the
//        packer wrote fog (or vice-versa) corrupts per-vertex draw control. Extends Rule 187
//        (RGBAQ spread) + Rule 192 (XYZ2/XYZ3) with the explicit fog<->ADC overlap. Flags A+D /
//        PACKED vertex emitters and the format selector they depend on (PRIM.FGE / XYZF2 vs XYZ2).
//
// Rule 215 G-CHAIN ROSTER refresh (data): extends DC2_KNOWN_FUNCTION_ADDRESSES + DC2_RUNTIME_INVARIANTS
//        + DC2_CALL_CHAINS with the G116-G137 title-cavern facts so the report stops re-deriving them:
//        packer addresses (copy 0x1b68 / trifan 0x1c50 / tri 0x1dc0 / tristrip 0x1ff0), VU dispatcher
//        route decisions (0x730/0x760/0x7b0) and the qword38 selector, the copy fog-clamp constant
//        VF29=(-191.25,255,0,535500) (ceiling 255 => ADC always 0), CreateRenderInfoPacket@0x1404d0
//        (selector builder) + @0x28a660 (motion-MDT), the SPI dispatch anchors (cfgWATER_VERTEX
//        @0x1648F0, CreateWaterFrame@0x185D40, spiGetStackInt@0x1463E0), and the invariants
//        TITLE_HAS_NO_WATER_ON_HW (CMap+0xcec/cf0 empty on HW too), GS_NO_HW_TRIANGLE_CLIP,
//        COPY_PACKER_WORD3_IS_FOG_NOT_ADC, FORCED_0x1ff0_DRAW_IS_LOAD_BEARING. Pure data.
//
// Rule 216 SCHEMA_VERSION: 15.0 (v16 adds Rules 207-216).
//
// ================================================================
// v17 RULES (217-225) - DC2 G138-G140 retrospective (the VU1-interpreter
//                       root-cause arc: FMEQ/FMAND opcode-table swap, 4-deep
//                       MAC-flag pipeline, same-pair upper->lower VF hazard,
//                       stale G64 band-aid inverting the VU clipper) + the
//                       static VU-microcode analysis layer that would have
//                       front-loaded all four roots (G87/G138/G139/G140,
//                       ~70 phases) + G141 performance-phase support.
// Grounded in plans/phase-G{138,139,140}-fix-log.md + ROADMAP.md +
// PS2_PROJECT_STATE.md "Learned Patterns" + PCSX2 VUops.cpp dispatch tables.
// ================================================================
//
// Rule 217 VU_MICROCODE_EXTRACTOR (top-level `vu_microcode_programs`, general PS2):
//        VU microcode is STATIC DATA inside the ELF (uploaded via VIF MPG), yet no prior
//        rule ever disassembled it - G138/G139/G140 all rooted in semantics the ELF bytes
//        already encode. Scans initialized data blocks for VIF MPG headers (cmd byte 0x4A:
//        num 64-bit pairs, imm = VU dest addr/8), validates the following payload by
//        decode plausibility (>=80% valid pairs, >=6 distinct upper opcodes), and groups
//        consecutive chunks (next imm == prev imm+num, adjacent payload) into whole
//        programs. Emits per program: elf_addr, vu_dest, size_pairs, chunk list, and a
//        best-effort uploader function link (const-load match against Rule 51/68 uploaders).
//
// Rule 218 VU_MICROCODE_HAZARD_SCAN (per program, general PS2): static disassembly of every
//        extracted program with the CANONICAL PCSX2 tables (VUops.cpp _vuTablesMess). Emits:
//        - opcode census (which lower/upper ops the game actually uses - the interpreter
//          conformance checklist; DC2 uses FMAND, which the runner had parked on FMEQ for
//          70 phases, G138 root #1);
//        - flag producer->consumer DISTANCES: for every FMxx/FSxx (MAC/STATUS) and FCxx
//          (CLIP) consumer, distance in pairs to the nearest preceding producer. DC2's
//          gates are hand-scheduled at EXACTLY 4 pairs = the real FMAC flag latency
//          (G138 root #2: MACPIPE depth 4; depths 3/5 kill the gate). Consumers at
//          distance <4 mean the immediate and pipelined models DIVERGE -> hazard list;
//        - SAME-PAIR upper->lower VF hazards: a lower op (SQ/SQI/SQD/DIV/MTIR/MOVE/...)
//          that reads/stores a VF its OWN pair's upper writes. On real VU1 the lower sees
//          the OLD value (G139 root: `SUB VF24.xyz,VF17,VF16 | SQ VF24` @0x1fa8 stored raw
//          edge-vector bits as the middle vertex -> beam shards). Statically enumerable;
//        - Q/P latency events: DIV/SQRT/RSQRT->q-consumer and EFU->MFP distances, WAITQ/
//          WAITP presence (the G87 class);
//        - XGKICK sites, CLIPw/FCGET clusters (Sutherland-Hodgman clipper shape - the G140
//          clipper at 0x2740..0x2f48 would appear on day one).
//
// Rule 219 VU_PROGRAM_COVERAGE (per program): branch-target map (B/BAL/IBxx decode),
//        BAL subroutine entries, dispatcher-region branches (pc < 0x800 - the 0x5e0
//        pre-dispatcher + 0x708 dispatcher shape), JR/JALR indirect sites, and BFS
//        reachability from entry 0 + all branch targets -> unreached-region spans.
//        G140 lesson: the [G39:code] runtime dump was capped at 0x1c90 and the clipper
//        past 0x2180 was NEVER disassembled -> "trifan route" misattributed for 20+
//        phases. Static full-program coverage kills that class permanently.
//
// Rule 220 VU_OPCODE_CANON + RUNTIME CONFORMANCE DIFF (top-level `vu_lower_opcode_canon`
//        + `vu_opcode_map_check` + `vu_opcode_coverage_gap`, general PS2): embeds the
//        AUTHORITATIVE lower-opcode index->name map (PCSX2 _LOWER_OPCODE: 0x18=FMEQ,
//        0x1A=FMAND, 0x1B=FMOR, 0x1C=FCGET ...) as data - NOT derived from the runner
//        (shared-bug hazard: pre-G138 g117_vudis.py printed FMAND as "FMEQ" because it
//        copied the runner's table). Best-effort diff: scrapes ps2_vu1.cpp `case 0xNN:`
//        bodies for opcode-name tokens and flags disagreements with canon (would have
//        printed "0x1A: runner says FMEQ, canon says FMAND, game uses it" at map time).
//        Also: census opcodes (len>=3) absent from the runner source -> coverage gap.
//
// Rule 221 RUNTIME_LEVER_REGISTRY (top-level `runtime_lever_registry` +
//        `runtime_bandaid_status`): scrapes the ps2xRuntime checkout (Rule 153 walk) for
//        getenv("...") behaviour levers; classifies diagnostic / kill_switch_of_default_on
//        (_NO_) / reenable_of_retired (FORCE) / semantic_lever; captures VU-pc-shaped hex
//        literals near the getenv (the G64 shape: IAND patch at pc 0x30d8/0x30f8/0x3168).
//        A default-ON pc-scoped semantic patch = STALE_BANDAID_SUSPECT. G140 root: the
//        June G64 "enable fix" inverted the VU clipper's inside/outside test (VI1 = FCGET
//        clip flags, set=OUTSIDE) and force-broke the water pool for 70 phases after its
//        credited effect was superseded by the G138/G139 root fixes. The retired-band-aid
//        roster (G89/G100/G104/G125-clip/G128/G64 + kill-switches) ships as data.
//
// Rule 222 PERF_STATIC_COST (per-func `perf_static_cost` + top-level `perf_cost_ranking`
//        + `memcpy_shaped_loops` + `idle_spin_yield_sites`, general PS2): G141 (ACTIVE)
//        is performance (~2.4 f/s title). Static cost model: instruction count, inner
//        loops, COP2 density, callee fan-out, weighted by mainloop depth -> ranked
//        suspects so the "measure first" phase starts at named functions. Two fast-path
//        sub-detectors: MEMCPY_SHAPED_LOOP (tight lq/sq copy loop, no callees -> host
//        memcpy substitution candidate) and IDLE_SPIN_YIELD_SITE (store-free poll spin
//        -> host-yield patch candidate; refines Rules 121/122/143).
//
// Rule 223 G138-G140 ROSTER/INVARIANT refresh (data): DC2_RUNTIME_INVARIANTS +=
//        VU1_LOWER_OPCODE_TABLE_CANON, VU1_MAC_FLAG_PIPELINE_DEPTH_4,
//        VU1_SAME_PAIR_UPPER_LOWER_HAZARD, TITLE_VU1_CLIPPER_MAP (pre-dispatcher 0x5e0
//        bit1=fc4 -> clip packers 0x21b0/0x23e8, clipper 0x2740..0x2f48, edge sub 0x3088,
//        fan template VU qw39->780, XGKICK 0x2d88/0x2f38 - the "trifans" are CLIPPED WALL
//        GEOMETRY, not an object route), TITLE_TRANSFORM_GATE_FMAND_CASCADE (corrects the
//        G117 "structurally never takeable" claim: VI3=0xD0|qw30 under real FMAND),
//        STALE_PC_SCOPED_BANDAID_SWEEP, GS_DUMP_RECORD_ALIGNMENT_TRICK. PHASE_TRACE_FLAGS
//        += G138/G140 probes. Golden title smoke = 211646 (frame_001500 PixelNonZero).
//        Rule 153 default runtime path corrected to D:\ps2r\dc2\PS2Recomp\ps2xRuntime.
//
// Rule 224 GIFTAG_TEMPLATE_SCAN (top-level `giftag_templates`, general PS2): scans
//        initialized data for GIFtag-shaped 16-byte records (structural zeros in word0
//        bits16-31 + word1 bits0-13, nreg>=1, no reserved REGS nibble 0xB), grouped by
//        value with counts + example addresses + full decode (nloop/eop/pre/prim/
//        prim_class/flg/nreg/regs). nloop==0 = TEMPLATE (VIF-delivered, VU-patched -
//        G140: the trifan giftag 302ec000 existed at exactly TWO RAM addresses, both
//        nloop=0 templates for VU qw39; a standing scan answers "where do these giftags
//        come from" for any prim class in one pass).
//
// Rule 225 SCHEMA_VERSION: 16.0 (v17 adds Rules 217-225).
//
// ================================================================
// v17.1 RULES (226-233) - PCSX2 source cross-check round 2
// (D:\ps2r\pcsx2-master\pcsx2: Dmac.h/Dmac.cpp, Vif_Codes.cpp, Gif.h/Gif_Unit.h,
// GS.cpp/Hw.h, Vif.h, FiFo.cpp, Counters.h/cpp, COP0.cpp). These cover the EE
// hardware CONTRACTS PCSX2 models that no prior rule flagged: DMA MFIFO rings,
// DMA stall control, VIF path arbitration, GS downloads, PRMODE attribute
// source, TEXA/CLAMP sampling contracts, and the EE time sources (perf/G141).
// ================================================================
//
// Rule 226 DMA_MFIFO_RING_CONFIG (per-func + top-level `dma_mfifo_users`, general PS2):
//        PCSX2 Dmac.h tDMAC_CTRL.MFD (Memory-FIFO Drain: VIF1 or GIF) + DMAC_RBOR
//        (0x1000E050 ring base) / DMAC_RBSR (0x1000E040 ring size). A game that drives
//        GIF/VIF1 through an MFIFO ring feeds the drain channel from a circular buffer
//        the SPR channel fills; a runtime that treats CHCR/MADR as a flat transfer
//        (no ring wrap, no drain-on-fill) silently drops geometry or hangs on the
//        stalled drain. Detected: composite const hits on RBOR/RBSR/CTRL (exact reg
//        split of the old blanket DMAC_GLOBAL range hit). DC2 expectation: unused
//        (statistic 0 is the finding, like Rule 150); many PS2 engines (Jak, GT) live on it.
//
// Rule 227 DMA_STALL_CONTROL_SYNC (per-func + top-level `dma_stall_control_sync`, general
//        PS2): PCSX2 Dmac.h STS/STD (stall source/drain) + DMAC_STADR (0x1000E060) + the
//        REFS source-chain tag (id 4, stall-controlled REF). The producer channel updates
//        STADR as it writes; the consumer channel STALLS until STADR passes its MADR -
//        the EE's hardware read-after-write interlock for streamed data. A runtime that
//        ignores stall control runs the consumer ahead of the producer -> reads garbage
//        (streaming geometry/texture corruption with no other witness). Detected:
//        STADR const hit, or REFS in dmaTagIdsBuilt/storedDmaTagIds.
//
// Rule 228 VIF_PATH_ARBITRATION (per-func + top-level `vif_path_arbitration`, general PS2):
//        PCSX2 Vif_Codes.cpp MSKPATH3 (VIF cmd 0x06) / FLUSH 0x11 / FLUSHA 0x13 / FLUSHE
//        0x10 / MARK 0x07 + Gif_Unit GIF MODE (0x10003010) M3R/IMT (Path3 mask +
//        intermittent mode). These are the GIF PATH1/2/3 arbitration controls: MSKPATH3
//        masks texture Path3 while VU1 XGKICK geometry owns the GIF; FLUSHA waits for
//        Path3 idle; FLUSHE waits for the VU program end. A runtime that executes VIF
//        streams but ignores arbitration interleaves Path3 texture qwords INTO Path1
//        geometry packets (corruption) or waits forever (FLUSHA deadlock). The VIF codes
//        were already decoded (VIF_OPCODES) but NO rule consumed them. DC2 relevance:
//        Path3 is the primary pipe AND VU1 XGKICK is live for models/title - the mask
//        windows matter exactly there.
//
// Rule 229 GS_DOWNLOAD_READBACK_PATH (per-func + top-level `gs_readback_sites`, general
//        PS2): the GS->EE download path PCSX2 models in GS.cpp GS_BUSDIR + Vif.h
//        VIF1_STAT.FDR (bit 23, VIF1 FIFO reversed) + FiFo.cpp ReadFIFO_VIF1 + TRXDIR=1
//        (local->host). Games use it for RTT readback, save-file screenshots, picking/
//        collision-from-render tricks. A runtime with no readback returns zeros ->
//        wrong-but-silent data (or a hang polling FDR). Detected: BUSDIR priv-reg hit,
//        VIF1_STAT const with bit23 shape near VIF CTRL access, or a TRXDIR (0x53) A+D
//        store whose const-tracked value is 1. DC2: READFIFO2_DEAD invariant says unused
//        in the 9 dumps - the roster proves ABSENCE for DC2 and coverage for other games.
//
// Rule 230 GS_PRMODE_ATTRIBUTE_SOURCE (per-func + top-level `prmode_attr_writers`,
//        general PS2): GS PRMODECONT (A+D 0x1A) selects whether primitive attributes
//        (IIP/TME/FGE/ABE/AA1/FST/CTXT/FIX) come from PRIM or from PRMODE (A+D 0x1B).
//        A runtime GS decoder that always reads PRIM mis-attributes every prim drawn
//        under PRMODECONT.AC=0 (wrong context -> wrong TEX0/FRAME pair, fog/blend flips).
//        Both regs sat in KNOWN_GS_REGS with NO detector. Detected via the Rule A
//        const-tracked A+D store path (0x1A/0x1B).
//
// Rule 231 GS_TEXA_CLAMP_CONTRACT (per-func + top-level `texa_clamp_writers`, general
//        PS2): two sampling contracts a software rasterizer must honour:
//        (a) TEXA (A+D 0x3B) - the 16/24-bit texel alpha expansion (AEM/TA0/TA1). DC2
//        samples PSMCT16 CLUTs; wrong TEXA turns "black = transparent" into opaque
//        black boxes (or everything invisible).
//        (b) CLAMP_1/2 (A+D 0x08/0x09) with WMS/WMT >= 2 - REGION_CLAMP/REGION_REPEAT,
//        the atlas sub-rectangle wrap modes (UMIN/UMAX/VMIN/VMAX). An atlas-heavy UI
//        (DC2 menus: fukusel/cursor sheets) draws sub-sprites via region clamp; a
//        rasterizer that wraps on the full texture bleeds neighbouring atlas cells.
//        Detected via the Rule A const-tracked A+D store path (0x3B/0x08/0x09).
//
// Rule 232 EE_TIME_SOURCE_ROSTER (per-func + top-level `ee_time_sources`, general PS2 +
//        G141 perf): WHERE the game reads time. Three hardware sources: EE timers
//        T0-T3 COUNT/MODE (0x10000000/0x10000800/0x10001000/0x10001800 +0x10, PCSX2
//        Counters.cpp - MODE gate bits tie a timer to h/v-blank), COP0 Count (mfc0 reg
//        9, the cycle counter PCSX2 models in COP0.cpp UpdateCP0Count), and vsync waits
//        (already Rule 100/195). A recompiled runtime whose timers/cycle-counter advance
//        at the wrong RATE makes the game step slow/fast/never - exactly the G141
//        "title steps ~2.4 f/s" class: if game logic paces on a timer the runtime
//        never advances, no amount of render optimisation fixes pacing. The roster
//        names every function that consumes a time source so the perf phase checks
//        the runtime's clock model FIRST. Detected: exact RCNT COUNT/MODE/TARGET reg
//        split of the old blanket RCNT range hit + an mfc0-Count operand scan.
//
// Rule 233 SCHEMA_VERSION: 16.1 (v17.1 adds Rules 226-233).
//
// ================================================================
// v18 RULES (234-242) - DC2 G142-G172 PERFORMANCE-ARC retrospective + general PS2.
// The whole prior rule set stops at G141 (Rule 222 marks it ACTIVE); everything the
// recomp project learned across G142-G172 (the perf arc) is added here. Grounded in
// plans/phase-G{142..172}-fix-log.md + ROADMAP.md + PS2_PROJECT_STATE.md.
// ================================================================
//
// Rule 234 GS_PRIM_SPRITE_EMITTER + PRIMITIVE_CLASS_COST_PROFILE (per-func +
//        top-level `prim_class_emitters`): THE G171 miss (cost ~16 phases, G144-G171).
//        Inline SPRITE raster (GS_PRIM_SPRITE prim=6, abe=1, fbp=0x0, reached via the
//        A+D packed-descriptor 0x0E write path to XYZF2/XYZ2) was ~76-79ms/frame - the
//        DOMINANT title cost - yet INVISIBLE to G144's triangle-only tile-bin defer and
//        every triangle-only perf probe, misattributed as GIF-parse cost for G155/G156.
//        Detects sprite-draw name roster (drawSprite/DrawDivSprite4/PrimQuad/SetSpriteEnv/
//        mgC3DSprite/DrawMesWin...) + a const-tracked PRIM-value census on real draw
//        builders (PRIM class = bits[0:2]; require an attribute bit 0x78 = IIP/TME/ABE so
//        bare A+D reg-ids 0x03..0x07 aren't mistaken for a PRIM value). Emits per-func
//        prim_classes_emitted[] (triangle/tristrip/trifan/sprite). General PS2: sprite/HUD
//        raster is the classic hidden cost; any deferred-raster lever must enumerate ALL
//        prim classes, not just triangles. Advisory.
//
// Rule 235 SPRITE_GROUP_ORDER_DEPENDENCY (per-func + top-level `sprite_compound_widgets`):
//        G172. Naively widening G144's defer to sprites regressed the costume prompt box to
//        EMPTY - it is several sub-sprites (bg/border/text glyphs) that MUST draw as an
//        unbroken GROUP (implicit ordering/atomicity; HW binds one TEX0 per strip). Flags a
//        sprite emitter whose name is a compound-widget shape (Window/Box/Prompt/MesWin/
//        Cursor/Menu/Dialog/...) that emits several sub-sprites in one body (backward loop or
//        multiple XYZ2 kicks) -> reorder-unsafe for tile-bin defer / band-parallel replay.
//        DC2_G172_SPRITE_DEFER must NOT be enabled. General PS2: layered 2D UI compositors.
//        Advisory.
//
// Rule 236 RECOMPILE_TARGET_COVERAGE_GAP (per-func tag + top-level `recompile_coverage_gaps`):
//        DC2 blocker #2 (some levels won't load: "Warning: Function at address 0xe3dc70 not
//        found" stalls the load). Every direct-call (jal) / computed-jump (Rule 146) target
//        that lands in the code range but has NO defined function makes the recompiler panic
//        that way at runtime. Cross-checks the union of discovered target addresses against
//        the defined-function set (funcManager) within the [minFn,maxFn] code-range proxy;
//        emits in-range-but-undefined targets + their referencing site. Firewalled - never
//        stub these away. General PS2: the #1 recompiler coverage failure (overlay/late-bound/
//        jump-table code the exporter missed).
//
// Rule 237 TEXTURE_STREAM_CHURN (top-level `streamed_texture_pages`, advisory): G148/G149
//        refutation. A de-swizzle/decode texture cache was BIT-EXACT but a MEASURED NET LOSS
//        because streamed title textures are re-uploaded (BITBLT) frequently AND sparsely
//        sampled per frame - whole-texture decode > the sparse sampler it replaces, and coarse
//        VRAM-generation bumps (~82/frame) kill reuse. Distinct BITBLTBUF uploaders per
//        labelled page (Rule 165 vramPageWriters) proxies churn: >=2 = STREAMED (poor cache
//        candidate); ==1 = static (cacheable). General PS2.
//
// Rule 238 PRESENTATION_REGISTER_FIFO_BYPASS (per-func + top-level `presentation_fifo_bypass`,
//        general PS2 - the most reusable MTGS lesson): the 6 presentation regs (PMODE/SMODE2/
//        DISPFB1/DISPFB2/DISPLAY1/DISPLAY2) are written on the EE thread via the direct IO
//        path (writeIORegister -> gs_regs), synchronously, no mutex, BYPASSING the GS draw
//        FIFO. This broke MTGS v1 (worker latched present regs the EE had raced past ->
//        alternating wrong-field frames); G157 fixed it by fencing the register WRITE. Any
//        multithreaded/pipelined GS runtime must fence/latch these separately from the draw
//        stream. Derived from DISPFB_WRITER / DISPFB_SDK_WRITER / PRESENTATION_FIELD_STATE.
//
// Rule 239 INTERLACED_FIELD_HEIGHT_VARIANCE (invariant): G157/G170. GS DISPLAY1/2's DH field
//        legitimately alternates between two valid interlaced field heights (h=415/416) per
//        NTSC field parity; under a pipeline's ~1-frame present lag a fixed-tick golden-height
//        check flags a FALSE regression. Materialised as a DC2_RUNTIME_INVARIANT + noted on
//        presentation writers: any golden-height check on an interlaced route must accept BOTH
//        field heights, never a constant. General PS2: any interlaced NTSC/PAL route.
//
// Rule 240 GPU_RASTER_ELIGIBILITY_CENSUS (per-func + top-level `gpu_raster_eligibility`,
//        general PS2): G161 closed the whole GPU-raster arc (G158-G167) with one census - the
//        signed-off gate (abe==0 no-blend, PSM in {CT32,CT24,CT16,CT16S}, alpha-test off)
//        matched 0/216000 real title triangles (every one has BOTH blend AND alpha-test, most
//        paletted T8). Classifies each draw builder by whether it SETS blend (ALPHA 0x42) /
//        alpha-test (TEST 0x47/0x48) / paletted PSM constants -> blend_atest_paletted_ineligible
//        vs opaque_eligible, so "is any prim GPU-raster eligible?" is answerable BEFORE writing
//        shader/thread code. Advisory.
//
// Rule 241 G142-G172 ROSTER/INVARIANT refresh (data): DC2_RUNTIME_INVARIANTS +=
//        TITLE_INLINE_SPRITE_IS_DOMINANT_COST, SPRITE_DEFER_HAS_GROUP_ORDER_HAZARD,
//        PRESENTATION_REGS_BYPASS_GS_FIFO, INTERLACED_DH_TWO_VALID_HEIGHTS,
//        STREAMED_TEXTURE_CACHE_REFUTED, GPU_RASTER_GATE_ZERO_ELIGIBLE_ON_TITLE,
//        PERF_PROMOTION_NEEDS_VISUAL_NOT_JUST_NONZERO (multi-frame visual review > nonzero
//        count; windowed-avg fps not dump-count; verify the full distribution/tail; best stack
//        = G150+G144+G157 ~9.2fps opt-in, safe default = MTGS+G144 tilebin ~5.5fps). Pure data.
//
// Rule 242 SCHEMA_VERSION: 17.0 (v18 adds Rules 234-242).
//
// ================================================================
// v19 RULES (243-251) - PCSX2 source cross-check round 3 (D:\ps2r\pcsx2-master\pcsx2:
// Hw.h, Dmac.h, Vif.h, Sif.h, Counters.cpp, Cache.cpp, COP0.cpp). These cover the EE
// hardware CONTRACTS PCSX2 models that no prior rule flagged: the EE interrupt-dispatch
// path (INTC/DMAC), DMAtag-IRQ completion, VIFcode i-bit, SIF RPC transport handshake,
// CDVD read-completion gating, EE cache coherency, GS CSR signal handshake, TLB mapping.
// Maps directly onto DC2's remaining blockers (audio/memcard/cd via SIF; the 2nd level-
// load failure mode via CDVD; the half-rate title loop via the vblank interrupt).
// ================================================================
//
// Rule 243 EE_INTERRUPT_HANDLER_REGISTRATION (per-func + top-level `interrupt_handlers`,
//        general PS2): the biggest EE contract no rule flagged. PCSX2 Hw.h INTC_STAT
//        (0x1000F000)/INTC_MASK(0x1000F010) + Counters.cpp vblank cause bits. The EE
//        dispatches guest handlers registered via the libkernel SDK (AddIntcHandler/
//        EnableIntc/AddDmacHandler/EnableDmac); each ACKs by writing 1 to its INTC/DMAC_STAT
//        bit. A static recompiler that never RAISES these leaves the game's vblank + DMAC-
//        completion callbacks DEAD - DC2's half-rate title loop (F52) + g_vsync_flag_mutex
//        path (G7) depend on the vblank IRQ firing. Detects the handler SDK roster OR INTC/
//        DMAC STAT/MASK/PCR/ENABLE MMIO; captures the INTC cause bit when the id is a const.
//
// Rule 244 DMA_TAG_IRQ_COMPLETION (per-func + top-level `dma_tag_irq_sites`, general PS2):
//        PCSX2 Dmac.h DMAtag IRQ:1 (qword bit31) + CHCR TIE:1 (bit7). A source-chain tag
//        with IRQ set + TIE raises the channel DMAC interrupt on tag completion. A runtime
//        ignoring tag-IRQ/TIE never signals chain-done -> the DMA-complete semaphore/handler
//        never fires (silent transfer-done deadlock). Detected: a chain-DMA builder (Rule
//        115/116) whose const-tracked CHCR value has STR|TIE (0x180). Distinct from Rule
//        21/115 (which see the kick, not the completion interrupt).
//
// Rule 245 VIF_INTERRUPT_IBIT (per-func + top-level `vif_interrupt_sites`, general PS2):
//        PCSX2 Vif.h STAT.INT (bit11), the VIFcode i-bit (bit31), MARK/FBRST/MII. A VIFcode
//        with the i-bit raises VIF1 STAT.INT and stalls until acked. A runtime that runs VIF
//        streams but ignores the i-bit never fires VIF-INT -> a game syncing on it (progress
//        callback / DBUF swap) hangs. Extends Rule 117 (saw the VIFcode, not the i-bit). DC2
//        stages every VU1 model packet through VIF1 UNPACK. Detected: a VIF builder with a
//        const-tracked value carrying bit31.
//
// Rule 246 SIF_RPC_TRANSPORT (per-func + top-level `sif_transport_sites`, general PS2):
//        extends Rule 74 (MSCOM/SMCOM only) with the SBUS MSFLG/SMFLG (0x1000F220/F230)
//        handshake flags + EE SIF DMA ch5(SIF0 0x1000C000 IOP->EE)/ch6(SIF1 0x1000C400
//        EE->IOP) + the Sif.h sifData EE/IOP dual-tag junk-fill hazard. With no IOP the EE
//        deadlocks polling SMFLG for a bit the IOP never sets - the DC2 audio(#3)/memcard(#4)/
//        cd-RPC wait class. Flags the poll sites so an IOP-dead stall routes to the transport,
//        not game logic (marks POLL_WAIT when also a sync-wait loop).
//
// Rule 247 CDVD_READ_COMPLETION_GATE (per-func + top-level `cdvd_completion_gates`, DC2
//        blocker #2 + general): a backward-branch wait polling a sceCd* completion signal
//        (sceCdSync/sceCdDiskReady/sceCdGetError/sceCdStatus/sceCdRead/sceCdSeek). DC2 level
//        load streams DATA.DAT via sceCdRead + SearchFile@0x148850 (F55); a level that
//        "cannot be loaded" can stall on a CD-completion wait that never signals if the
//        runtime's CDVD model returns busy/never-ready. The 2nd static level-load failure
//        mode beside the Rule 236 coverage gap. Analog to Rule 170 (audio gate).
//
// Rule 248 EE_CACHE_COHERENCY_OP (per-func + top-level `cache_ops`, general PS2): PCSX2
//        Cache.cpp models the EE D-cache + cache/sync.l/sync.p. A flat coherent runtime can
//        ignore most - EXCEPT when the game DMAs code/data into RAM then relies on a cache/
//        sync before reading/executing it (stale read otherwise). Flags raw cache/sync ops,
//        especially near a DMA kick / SPR / dynamic-code loader. Distinct from Rule 161
//        (FlushCache + exec loader). DC2 G26 scratchpad staging touches this shape.
//
// Rule 249 GS_CSR_SIGNAL_HANDSHAKE (per-func + top-level `gs_csr_sites`, general PS2,
//        extends Rule 79): GS CSR (priv 0x12001000) SIGNAL/FINISH/HSINT/VSINT latch + IMR
//        mask. GIF A+D SIGNAL(0x60)/FINISH(0x61)/LABEL(0x62) writes latch CSR and raise GS
//        INT unless IMR masks; the handler acks via CSR. DC2's IMR=0x7F00 masks all (so Rule
//        79 stubs its handlers) - but a game leaving GS IRQs unmasked and syncing on FINISH
//        needs the handshake. Flags SIGNAL/FINISH/LABEL writers + CSR access.
//
// Rule 250 EE_TLB_MAPPING (per-func + top-level `tlb_writers`, general PS2, "absence is a
//        finding"): PCSX2 COP0.cpp TLB (tlbwi/tlbwr/tlbr/tlbp + EntryHi/Lo/PageMask). A game
//        installing custom TLB entries (memory remap / scratchpad-as-RAM) breaks a flat-
//        address recompiler. DC2 statistic 0 confirms it is flat (like Rule 150/226/229);
//        non-zero is a red flag. Detected from the raw TLB instructions.
//
// Rule 251 ROSTER/INVARIANT refresh + SCHEMA_VERSION: 18.0 (v19 adds Rules 243-251).
//        DC2_RUNTIME_INVARIANTS += EE_INTC_VBLANK_HANDLER_MUST_FIRE, DMA_TAG_IRQ_TIE_COMPLETION,
//        VIF_IBIT_RAISES_STAT_INT, IOP_RPC_SMFLG_POLL_DEADLOCK_CLASS,
//        CDVD_LEVEL_LOAD_IS_sceCdRead_STREAM, DC2_IS_FLAT_NO_TLB_UCAB. Pure data.
//
// PIPELINE (v11.3): the script now asks "FIRST run for this ELF?" up front:
//   - YES -> full pipeline. Delegates the Step-1 export to ExportPS2Functions via runScript,
//            then enriches; emits csv + assembly + decompiled + flowchart + unified TOML + triage_map.json.
//   - NO -> INCREMENTAL. Re-emits triage_map.json and MODIFIES the live config IN PLACE, but only
//           when the executable content actually changed. Preserves # LOCKED + manual edits via the
//           re-entrant+LOCK machinery. Pick NO whenever the ELF is unchanged.
//
// POST-REGEN COP2 (v11.3): emitCop2FixScript writes fix_cop2_destmask.py (RECOMP path pre-filled) +
//   post_regen_steps.md beside the output, derived from this run's cop2_partial_dest_risk model.
//   The F51.8 fix CANNOT run inside this Ghidra pass, so it ships with the map and is listed as
//   a mandatory post-regen step.
//
// RE-ENTRANT INPUT: The step1 input may now be a PREVIOUS enricher output (evolving config_auto_recomp.toml
//   workflow) instead of the frozen DAC.toml. writeUnifiedConfig sanitizes its own artifacts on read
//   (header comment block, advisory pointer comment, any old [triage_advisory] section), so headers/advisory
//   never stack across runs. COUNT RECOMPUTE: stub_count / skip_count recomputed from ACTUAL array contents.
//   PROVENANCE SPLIT: entries under a "# --- Triage Enricher" marker parse as step1_source = "enricher_prev"
//   (vs "exporter") in the JSON. LOCK: `"name@0xADDR",  # LOCKED` trailing comment or a `locked = ["..."]`
//   array in [general]: the keep gate is BYPASSED and no promote pass ever rescues the binding. Use for
//   deliberate F-phase stubs that carry no host-boundary evidence. Locked entries: STEP1_LOCKED tag,
//   "step1_locked": true, statistic step1_locked_kept.
//
// OUTPUT-SURFACE POLICY (v11): unified TOML = executable safe subset + pointer comment; full advisory
//   content (incl. all DC2 categories) moved to triage_map.json "triage_advisory" as {entry, tags} objects.
//   UTF-8 everywhere (utf8Writer/utf8Reader); jsonString full RFC 8259 control-char escaping.
//   EE_SYSCALL_NAMES rebuilt against pcsx2 R5900OpcodeImpl.cpp + ps2xRuntime Dispatcher.cpp.
//   detectSyscallTrampoline $v1 always wins over spurious scalars; single-line TOML arrays parsed + rewritten correctly.
//   STEP1 VETTING: DAC.toml stub/skip entries are no longer trusted blindly and skipped. Every function is analyzed
//   and included in the JSON with provenance (origin = auto/step1/override); inherited bindings survive only through
//   a high-confidence keep gate (host-boundary evidence). RADAR REWRITE: Exact-name set + word-boundary prefix
//   families replace bare startsWith(). v13 BINDING FIREWALL: post-pass rescues stub/skip entries that are
//   address-taken callbacks / dispatch-table targets / init-chain members / render-critical. v13 DETECTOR GATES:
//   PSMT4HH_REFERENCE requires GS-side context; VIF_OPCODE_BUILDER requires independent VIF/DMA/GIF evidence;
//   A+D writer flags need >=2 distinct GS reg ids. v14: SIF_PACKET_BUILDER demotion; native_impl_needed + review
//   advisory lists. SKIP no longer fires on hasSyscall||hasCOP0 (game ISRs use di/ei/mfc0); only bare syscall-trampoline
//   shapes skip.
//
// OUTPUTS:
//   1. config_auto_recomp.toml - UNIFIED config ready for ps2recomp.exe
//   2. triage_map.json - full DNA map with tags for the report tool
//
// @author Puggsy + Claude (v11: DC2 comprehensive rule reorganization)
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
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

public class PS2Recomp_TriageEnricher extends GhidraScript {

    // =========================================================
    // v11 (ported from General v15.2): OUTPUT-SURFACE POLICY
    // The unified TOML is the EXECUTABLE SAFE SUBSET: [general], active
    // stubs, active skip, [patches]. All advisory material (force_recompile,
    // native_impl_needed, review, nop, patch-instruction candidates, rescue
    // reasons/evidence) lives in triage_map.json - the detailed source of
    // truth. Set this to true only for debugging to also emit the legacy
    // [triage_advisory] block into the TOML.
    // =========================================================
    private static final boolean EMIT_VERBOSE_TOML_ADVISORY = false;

    // v11 (General v15.5 Bugfix S): all text outputs are written as UTF-8
    // regardless of platform default charset. JSON MUST be UTF-8 (RFC 8259);
    // the old FileWriter default produced mojibake / U+FFFD bytes on Windows
    // (cp125x) hosts.
    private static PrintWriter utf8Writer(File f) throws IOException {
        // Self-heal the output tree: every file write funnels through here, so creating the
        // parent dir on demand guarantees index/ and functions/ exist regardless of which
        // output location the run picked (the one-time mkdirs at setup can be a no-op when the
        // chosen outputDir has no pre-existing index/ subdir -> FileNotFoundException).
        File p = f.getParentFile();
        if (p != null && !p.isDirectory() && !p.mkdirs() && !p.isDirectory())
            throw new IOException("Cannot create output directory: " + p.getAbsolutePath());
        return new PrintWriter(new BufferedWriter(new OutputStreamWriter(
            new FileOutputStream(f), StandardCharsets.UTF_8)));
    }
    private static BufferedReader utf8Reader(File f) throws IOException {
        return new BufferedReader(new InputStreamReader(
            new FileInputStream(f), StandardCharsets.UTF_8));
    }

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
    // v11 (ported from General v15, FF1-benchmark corrections): the old
    // RADAR_FIREWALL_PREFIXES list used bare startsWith() with short tokens.
    // On FF1 this stubbed `exponent` (matched prefix "exp" - a 224-byte
    // newlib float formatter), and on any game it would match `tangent`,
    // `logo_*`, `power_*`, `freeCamera`, `sinit`, etc. Two structural fixes:
    //  1. EXACT names vs PREFIX FAMILIES are now separate lists; families are
    //     matched with a word-boundary check (next char after the family root
    //     must not be a lowercase letter, so "sceCd"+"Read" matches but
    //     "sceCd"+"romdata" or "Scene*" never can).
    //  2. Pure-computation names were REMOVED from stub candidacy entirely.
    //     Stubbing routes calls to a named runtime handler; for pure EE
    //     computation (mem*/str*/sprintf/math/libgcc/operator new/static
    //     inits/__cxa_*) recompilation is always correct and a stub is only
    //     correct if a handler exists - so the safe default is RECOMPILE:
    //       - malloc/free/calloc/realloc/__builtin_new: Rule 142 already says
    //         never auto-stub allocators; the old list contradicted it.
    //       - "_Z" stubbed EVERY Itanium-mangled C++ function - fatal on a
    //         C++ game like DC2 (mg*/Sg*/CScene class methods).
    //       - "__sti"/"__std"/"_GLOBAL_" stubbed static initializers - the
    //         exact functions Rule 141 (__sinit manifest, F50.4/F50.7) exists
    //         to protect.
    //       - sin/cos/tan/sqrt/mem*/str*/sprintf: FPU/integer math the
    //         recompiler translates exactly; a host handler is an optional
    //         optimization, never a triage decision.
    // Matching additionally requires host-boundary trait evidence - see
    // hasHostBoundaryEvidence(). A name match alone never stubs.
    private static final Set<String> RADAR_EXACT_STUB_NAMES = new HashSet<>(Arrays.asList(
        // DC2 Group D confirmed-safe oddballs (exact spellings from
        // dc2_game_override.cpp)
        "InitTLB","_InitTLB","SetTLBEntry","GetTLBEntry",
        "InitAlarm","ReleaseAlarm",
        "mcHearAlarm","mcDelayThread",
        "printfloat","_system_header","dmaRefImage",
        "EnableCache","DisableCache",
        "isceSifSetDma","isceSifSetDChain","_sceCallCode",
        // SDK names with lowercase continuation that defeat the
        // family-boundary rule (General v15.4 FF1 benchmark set).
        "sceGszbufaddr","sceSetBrokenLink","sceSetPtm","sceVpu0Reset",
        "scePrintf","sceFsInit","sceFsReset","sceResetttyinit"
    ));
    private static final String[] RADAR_STUB_PREFIX_FAMILIES = {
        // Sony SDK host-boundary families (CD/MC/PAD/SIF RPC, GS privileged,
        // IPU/MPEG, VIF low-level control, filesystem, debug console).
        "sceCd","sceMc","scePad","sceSif","sceDma",
        // sceVif split: low-level HW control stubs are safe; sceVif1Pk* must RECOMPILE.
        "sceVif0","sceVif1Cmd","sceVif1Stop","sceVif1Mark","sceVif1Flush",
        "sceVif1Wait","sceVif1Reset","sceVifCode",
        "sceIpu","sceMpeg","sceGs","sceVu1",
        "sceOpen","sceClose","sceRead","sceWrite","sceLseek","sceIoctl",
        "sceDevFont","sceDevCons","sceDevVif","sceDevVu","sceDeci",
        "sceMSIn",
        "sceDopen","sceDclose","sceDread","sceGetstat","sceChstat",
        "sceRename","sceChdir","sceSync","sceMount","sceUmount",
        "sceSymlink","sceReadlink","sceRemove","sceMkdir","sceRmdir",
        "sceFormat","sceAddDrv","sceDelDrv","sceDevctl",
        "scePowerOffHandler",
        // SPU2 audio + TTY debug output families (host boundaries).
        "sceSd","sceTty",
        "_sceCd_","_sceFsIob","_sceFsWait","_sceFs_",
        "sceGsfx","sceLgfx"
    };

    /** v11 (General v15): word-boundary family match. A family root that ends
     *  in '_' (or any non-letter) matches as a plain prefix; otherwise the
     *  char following the root must NOT be a lowercase letter. This keeps
     *  "sceCd"->"sceCdRead" and "_sceCd_"->"_sceCd_cd_callback" while
     *  rejecting "exp"->"exponent" class bugs (and DC2's Scene/mg game code
     *  can never collide with the "sce" SDK families). */
    private static boolean matchesFamilyPrefix(String name, String family) {
        if (!name.startsWith(family)) return false;
        if (name.length() == family.length()) return true;
        char last = family.charAt(family.length() - 1);
        if (!Character.isLetter(last)) return true;
        char next = name.charAt(family.length());
        return !Character.isLowerCase(next);
    }

    /** v11 (General v15): name-only part of the stub gate (no trait evidence). */
    private boolean matchesHostBoundaryName(String name) {
        if (name.startsWith("sceVu0")) return false; // VU0 macro math: always RECOMPILE
        if (RADAR_EXACT_STUB_NAMES.contains(name)) return true;
        for (String f : RADAR_STUB_PREFIX_FAMILIES)
            if (matchesFamilyPrefix(name, f)) return true;
        for (String b : BIOS_FIREWALL_PREFIXES)
            if (matchesFamilyPrefix(name, b)) return true;
        return false;
    }

    /** v11 (General v15): trait corroboration required before any name-based
     *  stub binding. "Host boundary" = the function provably leaves the EE
     *  program: kernel syscall, SIF RPC to the IOP, IRX module loading,
     *  IPU/MPEG hardware, or a tiny leaf thunk (classic SDK wrapper shape).
     *  COP1/COP2 usage and plain MMIO stores are deliberately NOT evidence -
     *  the recompiler translates those (patch_cop0 / runtime MMIO routing). */
    private static boolean hasHostBoundaryEvidence(FuncTraits t) {
        if (t == null) return false;
        if (t.hasSyscall) return true;
        if (t.callsSifRpc || t.detectedRpcSid != 0 || !t.discoveredRpcSids.isEmpty()
            || !t.detectedRpcFids.isEmpty()) return true;
        if (t.refsIopModuleString || t.isIrxLoader || t.sifLoadModuleCallCount >= 1) return true;
        if (t.isAudioRpcHandler || t.isIopRebootHandler) return true;
        if (t.callsMpegFamily || t.accessesIpuMmio || t.writesIpuCmd) return true;
        // General v15.4 (FF1 rerun fix): SIF transport itself. sceSifCallRpc/
        // SetDma/SendCmd build SIF packets and kick the SIF0/SIF1 DMA channels
        // or touch SBUS registers - they ARE the EE<->IOP boundary, but carry
        // no syscall and don't call themselves.
        if (t.touchesSbus || t.touchesSbusFlags) return true;
        if (t.dmaKickChannels.contains("SIF0") || t.dmaKickChannels.contains("SIF1")
            || t.dmaKickChannels.contains("SIF2")) return true;
        return false;
    }

    /** v11 (General v15): weak evidence - tiny leaf MMIO thunk (<=64 bytes,
     *  no calls). The classic SDK register-poker/poller shape. Only acceptable
     *  as stub corroboration when the name ALSO matches a known SDK family: a
     *  game-code DMA-kick leaf has the same shape and must recompile -
     *  runtime MMIO routing executes it correctly. */
    private static boolean hasWeakSdkThunkEvidence(FuncTraits t) {
        return t != null && t.byteSize <= 64 && t.callOps == 0 && t.accessesMMIO;
    }

    private static final String[] BIOS_FIREWALL_PREFIXES = {
        "CreateThread","StartThread","ExitThread","SleepThread",
        "WakeupThread","iWakeupThread","RotateThreadReadyQueue",
        "CreateSema","WaitSema","SignalSema","DeleteSema",
        "iWaitSema","iSignalSema","PollSema","iPollSema",
        "AddIntcHandler","RemoveIntcHandler","EnableIntc","DisableIntc",
        "AddDmacHandler","RemoveDmacHandler","EnableDmac","DisableDmac",
        "SetVSyncFlag","SetSyscall","SetVBlankHandler","SetHBlankHandler",
        "FlushCache","AllocSysMemory","FreeSysMemory",
        // v11 (General v15.4): EE kernel syscall wrappers missing from the
        // original list - found in the runtime roster but unmatched here.
        "SetGsCrt","GsGetIMR","GsPutIMR","Deci2Call",
        "SetAlarm","iSetAlarm","DeleteThread","iReleaseWaitThread",
        "CancelWakeupThread","iCancelWakeupThread","SuspendThread","ResumeThread",
        "EndOfHeap","iReferSemaStatus","ReferSemaStatus","ReferThreadStatus",
        "SetOsdConfigParam","GetOsdConfigParam","iFlushCache","GetMemorySize",
        "InitThread","ChangeThreadPriority","iChangeThreadPriority",
        "EnableIntcHandler","DisableIntcHandler","EnableDmacHandler","DisableDmacHandler",
        // v11 (General v15.5): EE kernel syscall wrappers seen unmatched on
        // the Jak ELFs (word-boundary matched, so e.g. "GetThreadId" never
        // hits game code spelled getThreadIdle - next char must not be
        // lowercase).
        "GetThreadId","TerminateThread","iTerminateThread","ExitDeleteThread",
        "SetVTLBRefillHandler","SetVCommonHandler","SetVInterruptHandler",
        "AddSbusIntcHandler","RemoveSbusIntcHandler","DelayThread",
        "ReleaseWaitThread","ReferEventFlagStatus","GetOsdConfigParam2",
        "SetOsdConfigParam2"
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
        // ===== v11.3: F52-G26 gp-relative globals (gp=0x0037E4F0) =====
        // Absolute = gp + signed_offset. Dungeon/free-roam + costume + VU1-stage.
        KNOWN_DC2_GP_OFFSETS.put(-0x70FCL & 0xFFFFFFFFL, "DngTreeMode");          // F64 half @0x003773F4; 0=display map
        KNOWN_DC2_GP_OFFSETS.put(-0x7228L & 0xFFFFFFFFL, "MainChara_ptr");        // F66 @0x003772C8; pos +0xe0, vtable 0x3756f0
        KNOWN_DC2_GP_OFFSETS.put(-0x7268L & 0xFFFFFFFFL, "DebugPause");           // F66 @0x00377288; gates DngMainKey movement
        KNOWN_DC2_GP_OFFSETS.put(-0x7538L & 0xFFFFFFFFL, "DebugFlag");            // F50.6/debug-menu enable @0x00376FB8
        KNOWN_DC2_GP_OFFSETS.put(-0x63D0L & 0xFFFFFFFFL, "MenuCosPtr");           // G12/G13 @0x00378120; +0x2d0 char-data cache, +0x2d8 cursor texObj
        KNOWN_DC2_GP_OFFSETS.put(-0x63DCL & 0xFFFFFFFFL, "MenuCosutumeLoadPhase");// G10 @0x00378114; phase 4 = interactive costume list
        KNOWN_DC2_GP_OFFSETS.put(-0x7530L & 0xFFFFFFFFL, "LanguageCode");         // G13 @0x00376FC0; indexes static name tables
        KNOWN_DC2_GP_OFFSETS.put(-0x78ACL & 0xFFFFFFFFL, "GetScrPad_dbuf_slot");  // G26 @0x00376C44; EE scratchpad double-buffer toggle (0x70000000/0x70002000)
        KNOWN_DC2_GP_OFFSETS.put(-0x7890L & 0xFFFFFFFFL, "SendDMA_sprchcr_cache");// G26 @0x00376C60; cached =0x1000D000 (fromSPR CHCR) used by SendDMA@0x13e3d0
        KNOWN_DC2_GP_OFFSETS.put(-0x7FE0L & 0xFFFFFFFFL, "mgVuProg_resident_id"); // G21/G22 @0x003764D0; resident VU1 microprogram cache id (mpg skip gate)
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
        // v16 (G116-G137 title-cavern): the motion-MDT selector builder + SPI dispatch anchors.
        // (0x1404d0 CreateRenderInfoPacket is ALREADY in this table below as vu1_model_packet_builder
        // and already fires isPrimClassSelector via the hardcoded addr check; not duplicated here.)
        // The four VU packer addresses (copy 0x1b68 / trifan 0x1c50 / tri 0x1dc0 / tristrip 0x1ff0)
        // are VU1 micro-mem PCs, not EE function entries, so they live in the invariants text.
        { 0x0028A660L, "CreateRenderInfoPacket_motionMDT_0x28a660",          "G120",       "prim_class_selector",     "HIGH"    },
        { 0x001648F0L, "cfgWATER_VERTEX__Fv",                                "G129/G130",  "spi_config_command",      "MEDIUM"  },
        { 0x00185D40L, "CreateWaterFrame__Fv",                               "G129/G130",  "spi_config_command",      "MEDIUM"  },
        { 0x001463E0L, "spiGetStackInt__Fv",                                 "G130",       "spi_stack_arg_getter",    "LOW"     },
        { 0x0015E800L, "DrawWater__4CMapFv",                                 "G129/G130",  "title_water_gate",        "LOW"     },
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
        // ===== v10: F47-F52 dungeon path (PROJECT_STATE.md + F50/F51 fix logs) =====
        { 0x001CC040L, "InitDungeonMain__Fv",                                "F50",        "dungeon_init_root",        "BLOCKER" },
        { 0x001CEA00L, "LoopDungeonMain__Fv",                                "F50.3",      "dungeon_frame_loop",       "BLOCKER" },
        { 0x001CE9F0L, "FinishDungeonMain__Fv",                              "F50",        "dungeon_exit",             "MEDIUM"  },
        { 0x001D06C0L, "DngStep__Fv",                                        "F50.4",      "dungeon_update",           "HIGH"    },
        { 0x001CF090L, "DngMainDraw__Fv",                                    "F50.11",     "dungeon_draw_root",        "HIGH"    },
        { 0x001CBD70L, "memoryInit__Fv",                                     "F50.1",      "mgCMemory_pool_init",      "BLOCKER" },
        { 0x00139D20L, "Alloc__9mgCMemoryFi",                                "F50.1",      "pool_alloc_returns_ptr",   "BLOCKER" },
        { 0x001398E0L, "__nw__FUiP1",                                        "F50.1",      "placement_new_eabi",       "HIGH"    },
        { 0x001002F0L, "ps2___construct_new_array",                          "F50.2",      "array_ctor_eabi_t0_count", "BLOCKER" },
        { 0x00134B70L, "Vertex__11mgCDrawPrimFPf",                           "F51.8",      "cop2_transform_vertex_writer","BLOCKER"},
        { 0x00107008L, "sceVu0InversMatrix",                                 "F50.7",      "vu0_helper_implemented",   "HIGH"    },
        { 0x0010FF90L, "RotateThreadReadyQueue",                             "F50.3",      "thread_yield_lock_hog",    "HIGH"    },
        { 0x0014B770L, "GamePadStep__Fv",                                    "F49.5/F50",  "guest_lock_hog",           "HIGH"    },
        { 0x0010FF30L, "TerminateThread",                                    "F50.3",      "thread_terminate_wait",    "MEDIUM"  },
        { 0x00373580L, "__sinit_mainloop",                                   "F50.4",      "static_init_scene_vtable", "BLOCKER" },
        { 0x00191970L, "MenuInit__Fv",                                       "F50.6",      "debug_menu_init",          "MEDIUM"  },
        { 0x00191C30L, "MenuLoop__Fv",                                       "F50.6",      "debug_menu_loop",          "MEDIUM"  },
        { 0x0012E970L, "ReloadTexture_raw_0x12e970",                         "F51",        "t8_ct32_alias_upload",     "HIGH"    },
        { 0x00142560L, "mgEndDrawReloadTexture__Fv",                         "F51",        "texture_reload_frame_end", "MEDIUM"  },
        { 0x001E8F30L, "SetupMainUnit",                                      "F50.5",      "equipment_model_loader",   "MEDIUM"  },
        { 0x00149320L, "LoadFile__FPcPvPi",                                  "F50.5",      "fatal_loadfile_aborts",    "HIGH"    },
        // ===== v11.3: F52-G26 character/deform 3D-MODEL VU1 chain (active blocker, Known Issue #2) =====
        // The model is a per-draw VU1 MSCAL packet STAGED in EE scratchpad and copied into mgVif1Packet
        // via a fromSPR (ch8) DMA. See DC2_RUNTIME_INVARIANTS EE_SCRATCHPAD_DMA_CH8_9_REQUIRED.
        { 0x0013E3B0L, "GetScrPad__Fv",                                      "G26",        "ee_scratchpad_allocator",  "BLOCKER" },
        { 0x0013E3D0L, "SendDMA__FUiUiUi",                                   "G26",        "spr_ch8_dma_stager_subword_str_kick","BLOCKER" },
        { 0x001404D0L, "CreateRenderInfoPacket__12mgCVisualMDT",             "G25/G26",    "vu1_model_packet_builder", "BLOCKER" },
        { 0x00142FD0L, "mgDrawDirect__Fv",                                   "G24/G26",    "vu1_packet_emit_root",     "BLOCKER" },
        { 0x00142EA0L, "mgSendPacket__Fv",                                   "G24",        "mgvif1packet_dma_send_ch1","HIGH"    },
        { 0x00143A20L, "mgFlushRenderInfo__Fv",                              "G25",        "vu1_packet_trailer",       "HIGH"    },
        { 0x00137E10L, "Draw__8mgCFrame",                                    "G18/G19",    "mesh_frame_emit",          "HIGH"    },
        { 0x0013F4E0L, "Draw__12mgCVisualMDT",                              "G15/G16",    "mesh_visual_emit",         "HIGH"    },
        { 0x00145E80L, "mgSendVuProg__Fv",                                   "G21",        "vu1_microprog_upload_mpg", "HIGH"    },
        { 0x00145E20L, "mgGetVuProgPacket__Fv",                              "G21",        "vu1_microprog_packet",     "MEDIUM"  },
        { 0x00145DC0L, "CheckVuProgID__Fv",                                  "G21",        "vu1_resident_prog_cache",  "MEDIUM"  },
        { 0x0012F2E0L, "mgClipBoxW__Fv",                                     "G15",        "mesh_clip_test_not_culled","LOW"     },
        { 0x001731F0L, "DrawDirect__11CCharacter2",                          "G13/G24",    "character_model_draw",     "BLOCKER" },
        { 0x0016B940L, "DrawDirect__12CActionChara",                         "G14",        "actor_model_draw",         "HIGH"    },
        { 0x002BD640L, "Draw__15CMenuCostumeSel",                            "G13",        "costume_select_draw",      "HIGH"    },
        { 0x002BC500L, "__ct__15CMenuCostumeSel",                            "G13",        "stale_ptr_cache_ctor",     "HIGH"    },
        { 0x00223A50L, "MenuCursorDraw__Fv",                                 "G12",        "menu_cursor_uv_consumer",  "MEDIUM"  },
        { 0x00197700L, "GetName__13CGameDataUsedFi",                         "G13",        "name_from_static_eltable", "MEDIUM"  },
        { 0x00374310L, "__sinit_menudraw",                                   "G12",        "uncalled_static_init_uv",  "HIGH"    },
        // ===== v11.3: F63-G7 event VM / front-end / pad / UI-text =====
        { 0x001D1360L, "RunMainEvent__Fv",                                   "F64",        "event_run_sets_dngstatus0","HIGH"    },
        { 0x002555E0L, "EventLoop__Fv",                                      "F63/F64",    "event_loop_wait_selector", "HIGH"    },
        { 0x001873C0L, "exe__10CRunScriptFP8vmcode_t",                       "F63/F64",    "event_script_vm_stackmachine","HIGH" },
        { 0x001871E0L, "resume__10CRunScript",                               "F63",        "event_script_resume",      "MEDIUM"  },
        { 0x00187210L, "run__10CRunScript",                                  "F63",        "event_script_restart",     "MEDIUM"  },
        { 0x0029FFA0L, "TitleLoop__Fv",                                      "F64/G9",     "frontend_loopno3_root",    "HIGH"    },
        { 0x00233FF0L, "MenuMainKey__Fv",                                    "G12/G13",    "frontend_perframe_wrapper_idempotent_restore","HIGH" },
        { 0x00232DF0L, "MenuMainInit__Fv",                                   "G9",         "menu_main_init_selector",  "MEDIUM"  },
        { 0x00234290L, "MenuMainDraw__Fv",                                   "F64",        "menu_draw_replaces_3d",    "MEDIUM"  },
        { 0x001909A0L, "GetNowLoopNo__Fv",                                   "F64",        "top_level_loopno_getter",  "MEDIUM"  },
        { 0x0014A930L, "UpDate__8CGamePad",                                  "F66",        "cgamepad_update_read_pad",  "HIGH"   },
        { 0x0023E320L, "CheckPushButton__Fv",                               "F66",        "treemap_button_decoder",   "MEDIUM"  },
        { 0x0023E1B0L, "MenuCheckPushButton_treemap_0x23e1b0",               "F66",        "treemap_abstract_pad_code","MEDIUM"  },
        { 0x001EFF40L, "Step__12CMenuTreeMapFv",                             "F66",        "floorselect_treemap_step", "MEDIUM"  },
        { 0x00186380L, "__putc__11dbgCJISFont",                              "G5",         "debug_psmt4hh_font_putc",  "MEDIUM"  },
        { 0x001D4260L, "DebugMainDraw__Fv",                                  "G5",         "debug_menu_draw_root",     "MEDIUM"  },
        // ===== v12 Rule 168: G27-G52 skinned-model draw chain (ROADMAP "Durable 3D-model chain") =====
        { 0x0014D390L, "DeformMesh__Fv",                                     "G40",        "skin_matrix_build_root",   "HIGH"    },
        { 0x0014CB60L, "MotionProc2__Fv",                                    "G40",        "skin_motion_proc",         "HIGH"    },
        { 0x00137030L, "GetLWMatrix__Fv",                                    "G40",        "joint_lw_matrix_getter",   "HIGH"    },
        { 0x001302D0L, "mgInversMatrix__Fv",                                 "G40",        "vf0_dependent_inverse",    "BLOCKER" },
        { 0x0017C2D0L, "Draw__12COutLineDraw",                               "G47/G48",    "model_rtt_outline_draw",   "BLOCKER" },
        { 0x0017CB20L, "DrawDivSprite4__Fv",                                 "G36",        "rtt_to_display_composite", "HIGH"    },
        { 0x00143160L, "mgGetDrawRect__Fv",                                  "G37",        "vu0_bbox_screen_projection","HIGH"   },
        { 0x001381C0L, "GetDrawRect__8mgCFrame",                             "G37",        "vu0_aabb_drawrect",        "HIGH"    },
        // ===== v13 Rule 183: G53-G82 main-title 3D-background chain =====
        { 0x002A1020L, "TitleModeInit__Fv",                                  "G81",        "title_camera_init_on_global","BLOCKER"},
        { 0x0012F380L, "mgClipInBoxW__Fv",                                   "G78",        "render_mode_copy_discriminator","BLOCKER"},
        { 0x001387F0L, "Draw__8mgCFrameFv_thunk",                            "G59",        "vtable_tailcall_thunk",    "BLOCKER" },
        { 0x00142F90L, "mgDraw__Fv",                                         "G59",        "frame_draw_tailcall_parent","HIGH"    },
        { 0x00168FD0L, "GetTextureBlockNo__11CMdsListSetFi",                 "G58/G59",    "title_mds_block_walk",     "HIGH"    },
        { 0x002BE040L, "MenuCostumeDraw__Fv",                                "G79",        "costume_rtt_state_leak",   "HIGH"    },
        { 0x002838C0L, "GetCamera__6CScene",                                 "G58",        "scene_camera_slot_getter", "HIGH"    },
        { 0x00282EA0L, "Initialize__6CScene",                                "G58",        "scene_init_sets_cam_count","HIGH"    },
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
        KNOWN_DC2_TBP_LABELS.put(0x2720L,  "Mgr_T8_texture");        // F51: manager T8, uploaded via CT32 alias (dpsm=0, dbw=2)
        KNOWN_DC2_TBP_LABELS.put(0x3FDCL,  "CLUT_T4HH");             // F37 companion to font 4HH
        KNOWN_DC2_TBP_LABELS.put(0x280L,   "Misc_PSMCT32_upload");
        KNOWN_DC2_TBP_LABELS.put(0x3FD4L,  "Pre_CLUT_PSMCT32");
        // v10: F50.8-F51.8 dungeon map texture subsystem (separate from mgCTextureManager)
        KNOWN_DC2_TBP_LABELS.put(0x2580L,  "Map_PSMT4_pixels_NEVER_UPLOADED"); // F50.10/F50.11 dominant black geom
        KNOWN_DC2_TBP_LABELS.put(0x2980L,  "Map_CLUT_PSMCT16_NEVER_UPLOADED"); // F50.8 empty CLUT => black (dpsm=0x2 never transferred)
        KNOWN_DC2_TBP_LABELS.put(0x3220L,  "Map_T8_dungeon");        // F51.4/F51.8 dungeon map T8 (psm=0x13, CLUT 0x3fb8)
        KNOWN_DC2_TBP_LABELS.put(0x1A00L,  "Title_4HH_leftover");    // F50.10/F51.4 stale title 4HH, dead CLUT 0x3fe0 in-dungeon
        KNOWN_DC2_TBP_LABELS.put(0x3FB8L,  "Dungeon_CLUT_base");     // F51.4 uploaded dungeon CLUT
        KNOWN_DC2_TBP_LABELS.put(0x3FBCL,  "Dungeon_CLUT_alt");      // F50.12/F51.2 manager CLUT base
        KNOWN_DC2_TBP_LABELS.put(0x3FE0L,  "Title_CLUT_stale");      // F51.4 title CLUT, empty in-dungeon
        // Framebuffer pages (fbp units): display + in-place RTT
        KNOWN_DC2_TBP_LABELS.put(0x139L,   "RTT_fbp_in_place");      // F51.2 game-set in-place render-to-texture (= tbp 0x2720/32)
        // v11.3: G9-G13 front-end / costume-select texture pages (mgCTextureManager slots).
        KNOWN_DC2_TBP_LABELS.put(0x2AA0L,  "Title_atlas_slot64");    // G10/G11/G12 men0.pac common-menu frame; correctly bound on HW too (NOT the costume bug)
        KNOWN_DC2_TBP_LABELS.put(0x2920L,  "Fukusel_atlas_slot84_b");// G12 costume sheet page 2 (slot[84])
        KNOWN_DC2_TBP_LABELS.put(0x2C20L,  "Fukusel_cursor_tex");    // G12 cursor texObj tbp (CLUT 0x3fd4); menu_long_hand UV consumer
        KNOWN_DC2_TBP_LABELS.put(0x3FD8L,  "Title_CLUT_slot64");     // G11 title-atlas CLUT companion to 0x2aa0
        // v13 G80-G82: main-title rock-cavern T8 textures (s19_01..s19_11a),
        // VRAM 0x2720..0x3960, MODULATE tfx=0 tcc=1, sampled by the COPY-mode
        // map-part meshes (per-vertex RED-deficit / green tint, G82).
        KNOWN_DC2_TBP_LABELS.put(0x2760L, "Title_rock_s19_b");
        KNOWN_DC2_TBP_LABELS.put(0x28A0L, "Title_rock_s19_c");
        KNOWN_DC2_TBP_LABELS.put(0x2B20L, "Title_rock_wall_s19_02");
        KNOWN_DC2_TBP_LABELS.put(0x2F20L, "Title_rock_wall_s19_04");
        KNOWN_DC2_TBP_LABELS.put(0x3320L, "Title_rock_wall_s19_06");
        KNOWN_DC2_TBP_LABELS.put(0x3720L, "Title_rock_s19_d");
        KNOWN_DC2_TBP_LABELS.put(0x3820L, "Title_rock_upper_s19_e");
        KNOWN_DC2_TBP_LABELS.put(0x3920L, "Title_rock_upper_s19_f");
        KNOWN_DC2_TBP_LABELS.put(0x3960L, "Title_rock_block_s19_05");
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
        // ===== v10: F47-F52 retrospective facts (runner-side, not GS-dump) =====
        { "COP2_DESTMASK_LANE_REVERSAL","F51.8: the recompiler emitted the VU0-macro COP2 dest-component blend mask in REVERSED lane order. Every PARTIAL-dest op (vftoi.xy / vadd.xyz) wrote to the wrong SIMD lane; full .xyzw symmetric and unaffected. ALL 3D perspective transforms were degenerate for 50+ phases. Verify dest-mask lane order in any COP2_DESTMASK_VERIFY function." },
        { "DUNGEON_MAP_PATH2_DIRECT","F51.7: the dungeon map (tbp=0x3220) is drawn via Path2 VIF1 DIRECT as EE-built 224-byte 4-vert GIF packets — NOT VU1. Over the whole dungeon route VIF1 mscal=0/mscnt=0 and VU1 execute/resume/XGKICK fire 0x. The transform is inline COP2 (VU0 macro mode) in the mg* math lib + mgCDrawPrim, not the throwing sceVu0RotTransPers* stubs." },
        { "MAP_CLUT_PSMCT16_NEVER_UPLOADED","F50.8-F50.11: the dungeon map texture subsystem (tbp=0x2580 pixels / cbp=0x2980 PSMCT16 CLUT) is separate from mgCTextureManager and is NEVER transferred to VRAM (0x BITBLTBUF dpsm=0x2 anywhere). Empty CLUT => idx resolves color=0 => black. A missing loader, not a swizzle/aliasing bug." },
        { "FRAME_TEX0_VRAM_ALIAS","F51.1/F51.2: the manager draws into fbp=0x139 and samples tbp=0x2720 — both map to VRAM byte 0x272000 (fbp*8192 == tbp*256). This is a deliberate in-place render-to-texture (game-set FRAME), faithful to real HW; not a stale FRAME bug." },
        { "MGDBUFFID_TOGGLED_BY_GUEST","F52: mgDBuffID (gp+0xFFFF8818) is toggled by the guest's own mgEndFrame@0x1425b0, NOT by sceGsSwapDBuff's return. Live PCSX2 A/B confirms 0->1->0 across 3 swaps, identical to the runner; gp=0x37e4f0 matches. Double-buffer sync was never the dungeon-black cause." },
        { "RUNTIME_LOG_DEAD_IN_RELEASE","F51.7: RUNTIME_LOG is compiled out in Release. VU/VIF/GS diagnostics must use env-gated fprintf(stderr,...); a silent RUNTIME_LOG probe is NOT evidence of absence." },
        { "GUEST_EXEC_SINGLE_MUTEX","F49.5/F50: all recompiled guest threads serialize on one m_guestExecutionMutex. A thread spinning without releasing it (GamePadStep -> RotateThreadReadyQueue syscall 0x2B) starves every other guest thread. Yield/sleep syscalls must wrap their wait in GuestExecutionReleaseScope." },
        { "UNRUN_SINIT_NULL_VTABLE","F50.4/F50.7: __sinit_* static initializers have no jal caller and run only via the global-ctors table. Headless static-init coverage is incomplete, so a global object's vtable pointer can stay null and its virtual init dispatch silently no-ops. Replay STATIC_INIT_VTABLE_INSTALLER manifests to repair." },
        // ===== v11.3: F52-G26 retrospective facts (runner-side). Several SCOPE or CORRECT older invariants. =====
        { "VU1_XGKICK_LIVE_FOR_CHARACTER_MODELS","G21-G26 SCOPES/CORRECTS PATH1_DEAD: that invariant held only for the 9 original non-character GS dumps (title/menu/dungeon-map). Character/deform 3D models ARE rendered by a RESIDENT VU1 microprogram (uploaded mpg=7 to VU1 code 0x320) executed per-draw via MSCAL, emitting per-strip screen-space tristrip giftags (prim=0x5c) = canonical VU1 XGKICK output (Select_costume.gs count_prims_path={3:4876}=Path1New). Do NOT treat PATH1/VU1 as dead when a character or deform mesh is on screen. The dungeon MAP geometry is still Path2 DIRECT (DUNGEON_MAP_PATH2_DIRECT); only character/deform meshes use VU1." },
        { "EE_SCRATCHPAD_DMA_CH8_9_REQUIRED","G26 ROOT CAUSE of the 13-phase model chase: DC2's mg library builds each model VIF packet in the EE SCRATCHPAD (GetScrPad@0x13e3b0 -> 0x70000000/0x70002000, double-buffered via gp-0x78AC) then copies it into its RAM slot in the mgVif1Packet DMA chain with a fromSPR DMA on DMAC channel 8 (SendDMA@0x13e3d0). A runtime whose writeIORegister only dispatches GIF(0x1000A000)+VIF1(0x10009000) silently drops ch8(0x1000D000 fromSPR)+ch9(0x1000D400 toSPR) -> the staged packet never reaches VIF1 -> empty model slot -> no XGKICK. Runtime MUST implement SPR_FROM/SPR_TO normal-mode copies (SADR+0x80 / MADR+0x10 / QWC+0x20)." },
        { "SUBWORD_DMA_STR_KICK","G26: SendDMA starts the SPR ch8 transfer with a single BYTE store (sb) to CHCR+1 (the STR bit), NOT a word store to CHCR+0. A runtime IO dispatcher that only matches word-aligned CHCR writes will miss the kick; write8/write16 to an MMIO/DMA register must be reconstructed into the full-word register write. Statically: a delivery-critical packet stager is a func that programs a fromSPR/toSPR channel (uses_spr + dma channel) and kicks via sb/sh." },
        { "STALE_PTR_CACHE_CTOR","G12/G13/F50.4 recurring FIX class: a ctor caches a DERIVED global pointer ONCE at construction (e.g. __ct__15CMenuCostumeSel@0x2bc500 caches MenuCosPtr+0x2d0 = GetCharaDataPtr(GetUserDataMan(),0)); if it runs before the source (ActiveSaveData / a __sinit / disc data) is funded, it caches 0/stale -> the downstream Draw silently skips (names/cursor/model absent). Repair idempotently in a per-frame wrapper (MenuMainKey@0x233ff0), never by editing the ctor. Same class as G12 menu_long_hand UV (un-run __sinit_menudraw@0x374310)." },
        { "UNFUNDED_GUEST_HEAP_OOM","F57/F58: malloc/_malloc_r are runtime stubs -> PS2Runtime::guestMalloc over [base,limit] set by SetupHeap (syscall 0x3D) from the guest's $a0/$a1, clamped to [0,kGuestHeapHardLimit]. DC2's _end=0x1F64E00 fills RAM and it asks for [_end, top]; kGuestHeapHardLimit MUST exceed _end or the clamp collapses the window to base==limit (empty) -> every alloc fails -> operator new throws bad_alloc -> uncaught -> abort (silent exit). A guest that 'mostly works' via static pools can still have a dead malloc; only checked operator new exposes it." },
        { "EVENT_VM_AUDIO_GATED_STALL","F63/F64: the CRunScript event VM (object @0x01ece3d0; exe@0x1873c0 stack machine, vmcode_t=[op,arg1,arg2]) can park forever on an ext command (op 0x15) or a wait sub-fn that loops until a director asserts the skip flag (+0x40). Headless, with no audio subsystem, scene-sound/stream waits (op 3 push_str names like snd2/sp/sp_030.snd; EventLoop selector DAT_01ece504=3 StreamOpenState) never signal done -> DngStatus stuck at 2. For event-progress bugs, check a sound/stream wait BEFORE assuming game-logic. RunMainEvent@0x1d1360 sets DngStatus=0 when EventLoop returns 1 (needs CRunScript+0x3c done != 0)." },
        { "LIVE_PAD_IS_read_pad_stub","F66/G7: the live pad read is read_pad_stub (registered @0x0014A490, overrides read_pad__FP10PAD_STATUS) -> dc2_write_pad_status, writing the button mask to PAD_STATUS+0 and four analog ints (+4 LY,+8 LX,+0xc RY,+0x10 RX). scePadRead is DEAD (the game never calls it) -> editing it is inert. In-dungeon free-roam MOVEMENT is the LEFT ANALOG STICK (RunScript__CActionChara->Analog__CPadControl), not the D-pad; a digital-only injector navigates menus but never moves the player. Face buttons are not read on the floor-select treemap (Step__CMenuTreeMap reads abstract codes from padtbl; confirm = DOWN x2)." },
        { "ALLOCATOR_FAMILY_COHERENT_G1","G1 GATE PASS: the C/C++ public allocator family (malloc/free/_malloc_r/_free_r/_calloc_r/operator new/delete) is uniformly runtime-backed (PS2Runtime::guest{Malloc,Free,Calloc,Realloc}); newlib internals (sbrk/_sbrk_r/malloc_extend_top) are DEAD; game mgCMemory pools self-manage BSS. Title + dungeon-0 floor-load each do 3 mallocs/1 free, 0 sbrk. => texture/CLUT/menu corruption is a GS/texture-layer bug, NOT heap. After any regen/TOML edit the WHOLE family must stay runtime-backed (no half-runtime/half-recompiled split) or silent alignment/CLUT corruption returns." },
        { "DC2_KEY_GLOBALS","v11.3 absolute-address roster (not gp-relative): DngStatus@0x01E9F6E0 (0 free-roam/1,4 menu/2 event/3 event-edit/5 exit), MenuActionChara@0x01F0CAA0 ([0]=0xebf9c0 costume actor, model ptr +0x124), MenuCommonInfo ptr@0x003779E8 (+0x50 sel=0x14 costume), DAT_01ecd618@0x01ECD618 (costume selector=0x14), DAT_01ecd62c@0x01ECD62C (new-game trigger: 0xc=New Game), CRunScript event obj@0x01ECE3D0 (+0x38 vmcode/+0x3c done/+0x40 skip/+0x48 strbase), prog_adr@0x00334260 (VU1 microprogram packet table), CGamePad singleton@0x003D76E0 (raw scePad bit layout, +0x4 PAD_STATUS), header_buff@0x00382680 (DATA.HD3 archive table, header_num=6693)." },
        // ===== v12: G27-G52 skinned-model render invariants (Rule 165/166/167/169) =====
        { "VF0_HARDWIRED_FOR_INVERSE","G40 (THE 50-phase skinned-collapse): VU0/VU1 vf0 is HW-hardwired (0,0,0,1); recompiled COP2 macro ops read ctx->vu0_vf[0] as that constant. The runtime memsets the context to zero and nothing writes vf0 -> mgInversMatrix@0x1302d0 computes Q=vf0.w/det=0 then vmulq -> zero bone palette -> ALL skinned characters collapse. Plain mgMulMatrix and the VIF1-DIRECT map path don't read vf0 so they masked it. FIX: pin vu0_vf[0]=(0,0,0,1) after the context memset and re-assert after any context reset. Statically flagged VF0_DEPENDENT_INVERSE." },
        { "RTT_FRAME_TEXTURE_ALIAS_GENERAL","G33-G50: DC2 renders the skinned model in-place to FRAME fbp=0x139 (= block 0x2720) and samples that page as a texture - a deliberate render-to-texture, faithful to HW. ANY FRAME writer whose page aliases a TEX0/BITBLTBUF upload page is an RTT; never stub it (G37/G44 had to hand-protect them). The model is drawn in ~8 interleaved 0x139 segments per frame, each bracketed by a draw to the display buffer (0x68/0x0). Statically: RTT_TARGET / vram_overlap_pairs(RTT_ALIAS)." },
        { "COSTUME_Z_PRIVATE_BUFFER","G45/G47/G49: the costume model Z must NOT live in flat VRAM - its synthetic block 0x1a00 ALIASES menu-text/sprite VRAM, so per-frame text sprites stomp the model Z (GEQUAL rejects model tris -> shred) and vice-versa. Use a PRIVATE off-screen Z (aliases nothing). Clear it ONCE PER RENDERED FRAME on the display-buffer FLIP (not per 0x139 entry, which wipes Z between head sub-meshes -> cap/hair draws dark over the face). Statically: ZBUF_VRAM_ALIAS_RISK / DISPLAY_BUFFER_FLIP." },
        { "RGBAQ_ZERO_HOLD_COSTUME","G52: the costume model packet emits an explicit fully-zero RGBAQ (lo=0 hi=0) for ~8.6% of skinned skin verts; HW never does (every model vertex alpha=0x80, color>=0x50). A fully-zero RGBAQ in the costume context (fbp=0x139 tristrip) must HOLD the last valid color, not clobber it. The all-zero write originates in the VU1/XGKICK path (deeper root not chased). RGBAQ writers feeding an RTT tristrip are vertex-color critical." },
        // ===== v13: G53-G82 main-title 3D-background invariants (Rules 178-182) =====
        { "TITLE_CAMERA_INIT_ON_GLOBAL","G81 (cost ~6 phases): TitleModeInit@0x2a1020's camera-setup block runs only `if (TitleCamera@0x00377E38 != 0)`. Headless the producer had not run so TitleCamera==0 -> the block was skipped -> mgCCameraFollow kept its CTOR defaults (distance=40,height=30,look-at origin) -> the rock cavern (look-at (-70,281,-493), dist ~1296) was OUT OF FRAME. Same shape as the empty CScene camera slots (AssignCamera returns -1 before CScene::Initialize@0x282ea0 sets count=8). FIX g81_fix_title_camera re-applies the init when the camera holds the ctor defaults. THE general lesson: an `if(global!=0){configure}` block silently no-ops headless when the global's producer runs later/never. Statically: CONDITIONAL_INIT_ON_GLOBAL / init_order_hazards." },
        { "TITLE_RENDER_MODE_COPY_VS_TRANSFORM","G75-G80 (cost ~6 phases): each title map-part mesh selects a render mode in mgRENDER_INFO+0xfc4 - COPY (passthrough VU packer 0x1b68, carries tbp + per-vertex ADC) vs TRANSFORM (VU packers 0x1c50/0x1ff0/0x1dc0 whose +2048/ADC gate culls 100% on the runner AND on PCSX2). Every title mesh was flagged TRANSFORM -> all culled -> flat-blue bg. The discriminator is mgClipInBoxW@0x12f380 ret in Draw__8mgCFrame@0x137e10 (ret!=0 -> fc4=0 copy). The VU cull is CORRECT (PCSX2 _vuFMEQ identical); the bug is purely the wrong mode flag. Statically: RENDER_MODE_SELECTOR." },
        { "TITLE_ROCK_VERTEX_RED_DEFICIT","G82: the framed title rock is GREEN where HW is brown. NOT fog (HW FGE=0), NOT texture (samples correct brown texel), NOT lighting globals (ambient/light/dir byte-identical to HW), NOT over-draw (uniform across regions). ROOT: per-vertex SHADE has RED ~half HW (runner R≈36 vs HW R≈66) -> MODULATEd brown goes green. HW directional light col0 (-0.894,0,0) modifies RED only and ends R ABOVE ambient; the runner ends R BELOW ambient -> prime suspect = the title map-part directional-light N·L sign / normal-transform (DrawSub__4CMap/Draw__9CMapParts; costume lighting matches HW so it is title-map-part-specific). Statically: VERTEX_LIGHTING_NORMAL_TERM. NOTE: GIF PACKED RGBAQ is a SPREAD layout (R=byte0,G=byte4,B=byte8,A=byte12); a contiguous decode gets (R,0,0,0)." },
        { "MGFRAME_VTABLE_TAILCALL","G59: Draw__8mgCFrame@0x1387f0 is `a1=0; jr *(vtable+0x44)` - an inherited-virtual TAIL CALL. The recompiler mistranslated it into a return-to-dispatcher (`Function at address 0xN not found`) instead of completing the inherited call -> mgDraw@0x142f90 exited early with its frame still active -> the process fell through the startup _Exit path. FIX g59_frame_draw_tailcall_fix sets a1=0, calls the virtual slot synchronously, returns to mgDraw continuation 0x142fac. General PS2: a terminal `jr` through a loaded vtable slot (not ra/t9) needs explicit tail-call handling. Statically: VTABLE_TAILCALL_THUNK." },
        { "TITLE_RESUME_STACK_FRAME","G58/G59: TitleMapDraw@0x2a2280 is preempted/resumed mid-body; the runner resumed interior labels 0x2a2548/0x2a2644 with sp one 0x830 frame too low -> the epilogue `ld $ra,0xA0($sp)` loaded garbage -> bad-PC 0x9f84a0. NOT a saved-$ra overwrite (refuted) and NOT a mistranslated store. FIX = title-scoped resume wrappers restoring sp=0x1fff760. General PS2: a large draw/frame function re-entered at an interior label must restore a consistent frame. Statically: FRAME_RESUME_RISK." },
        { "COSTUME_RTT_STATE_LEAK_ON_ROUNDTRIP","G79: after Title->New Game->costume->back, the front-end runs TitleLoop (titleMode=2) and MenuCostumeDraw@0x2be040 (menuId 0x17) CONCURRENTLY - costume never tore down. The costume RTT GS-state (FRAME=fbp=0x139 / scissor) is left set, so TitleMapDraw's rock copy geom reaches the GS but is invisible (drawn into the RTT target, not the display buffer). FIX = restore the display FRAME / tear down the costume before the title draw. General PS2: an RTT writer that never restores the display-buffer FRAME leaks render-target scope. Statically: RTT_NO_RESTORE / LoopNo+menuId contradiction (loop_state_model)." },
        // ===== v16: G116-G137 main-title 3D-background copy/transform/clip invariants (Rules 207-215) =====
        { "COPY_PACKER_WORD3_IS_FOG_NOT_ADC","G132 (cost ~7 phases, G131-G137): the title COPY packer 0x1b68 emits XYZF2 where word3 is the FOG byte (VF26.w = clamp(VF29.x + VF29.w*VF16.w, 0, 255), VF29=(-191.25,255,0,535500)). Packed by FTOI4 into word3 bits [4:11]; the ADC bit15 needs VF26.w>=2048 but the clamp ceiling is 255 << 2048, so the copy packer's per-vertex ADC is STRUCTURALLY ALWAYS 0 BY DESIGN - it CANNOT carry HW's selective ~45%-at-pos2+ tristrip restart pattern. The G131 `ILWR VI7,(VI12)&0x8000` per-vertex flag is REFUTED (that runs once pre-loop and writes the GIFtag word). A packer's per-vertex strip-restart capability is a FORMAT fact (XYZF2 fog vs XYZ2 ADC), not a lost flag. Statically: VERTEX_KICK_FORMAT_ADC_CAPABILITY / PACKED_FIELD_ALIAS_FOG_ADC." },
        { "GS_NO_HW_TRIANGLE_CLIP","G125-G129 (cost ~5 phases): the PS2 GS performs NO triangle / near-plane / guard-band CLIPPING - it only SCISSORS, and out-of-guard-band 12.4 coords WRAP. FTOI4 packs screen XY as 12.4 fixed point (int32 then masked to 16 bits), so a BEHIND-camera vertex (q=1/W<=0) has an already-SATURATED/WRAPPED screen XY before the GS. Reconstructing clip-space (clip = screen*W) from that saturated XY yields GARBAGE -> screen-spanning wedges (G128). The near plane MUST be handled on the float position + q BEFORE FTOI4 (homogeneous clip where the true 1/W sign lives) or the straddling triangle REJECTED (q<=0). Tristrips can't be per-vertex clipped (shared vertex -> swimming connectors, G102) so reject. Statically: PERSPECTIVE_DIVIDE_NEAR_PLANE_SOURCE / GS_XYOFFSET_GUARD_BAND." },
        { "TITLE_HAS_NO_WATER_ON_HW","G130 (corrects G129): the title CMap (0x8fc880) water arrays (+0xcec/+0xcf0/+0xcf4/+0xcf8) are EMPTY, cfgWater=0, WaterIndex=0 - BYTE-IDENTICAL between the runner and LIVE HW. HW never creates a CWaterFrame for the title map and its DrawWater@0x15e800 ALSO gates SKIP. The SPI map-config command cfgWATER_VERTEX@0x1648F0 (->CreateWaterFrame@0x185D40) NEVER fires during title load on EITHER side. The reference's ~1012 trifans are cavern MODEL geometry (100% draw under wall pages 0x2b20/0x2720/0x2760/0x2f20), NOT a water pool. Implementing the WATER_VERTEX SPI dispatch is the WRONG target. The string/id-keyed SPI config dispatcher (spiGetStackInt@0x1463E0) is the place to verify a 'missing map feature'. Statically: SPI_CONFIG_COMMAND_DISPATCH." },
        { "TITLE_PACKER_DISPATCH_MAP","G117/G130/G137: the title VU1 dispatcher routes (decode pcs 0x730/0x760/0x7b0) the qword38 selector to one of FOUR packers: COPY/passthrough 0x1b68 (EE-pre-projected screen-space, no VU transform, XYZF2 fog), TRANSFORM tristrip 0x1ff0 (100% nodraw by correct microcode - the +2048/ADC gate is structurally never-taken, ==PCSX2 _vuFMEQ), TRANSFORM tri 0x1dc0, TRIFAN 0x1c50. selector built in CreateRenderInfoPacket@0x1404d0 (motion-MDT direct call @0x28a660): bit2=desc+0x2c, bit0=fc0||fc4. HW draws the visible cavern via the copy/tri/trifan route; routing (desc+0x2c) is BYTE-IDENTICAL runner-vs-HW (G121), so the defect is the copy RENDER contract, not routing. G100 FORCE-routes everything through the nodraw 0x1ff0 (LOAD-BEARING band-aid). Statically: PASSTHROUGH_PACKER_RENDER_PATH." },
        { "TITLE_NEEDS_PRIVATE_Z","G125: the title cavern needs a PRIVATE per-frame-cleared Z buffer - without a depth test the back cavern wall overdrew the front carved mural. The full title transform-matrix chain (mgRENDER_INFO@0x380ec0 +0x10/+0x110/+0x150/+0x1a0/+0x260) is BYTE-IDENTICAL to LIVE HW (refutes any 'X-scale'/projection bug, G124/G125); the residual was the near-plane clip + depth ordering, fixed by a homogeneous clip (clip=screen*W, q preserved) + a private title Z. Statically: PRIVATE_DEPTH_SCOPE / RTT_TARGET." },
        // ===== v17: G138-G140 VU1-interpreter root-cause invariants (Rules 217-223) =====
        { "VU1_LOWER_OPCODE_TABLE_CANON","G138 ROOT #1 (ended the whole G70-G137 title blue-void line): the real VU lower-opcode dispatch (PCSX2 _LOWER_OPCODE, index=code>>25) is 0x18=FMEQ, 0x1A=FMAND, 0x1B=FMOR, 0x1C=FCGET. The runner had FMEQ/FMAND SWAPPED (+FMOR parked on 0x1C) - DC2's draw gates are FMAND mask cascades and could never equal the mask under FMEQ 0/1 semantics ('gate structurally never takeable' was true only under the swapped table). SHARED-BUG HAZARD: the g117_vudis.py disassembler copied the runner's table, so every 'FMEQ' in the G70-G137 analyses was really FMAND - verify opcode maps against PCSX2's dispatch tables, never against the runner's own case labels. Kill-switch DC2_VU1_NO_FMSWAPFIX=1. Statically: Rules 218/220." },
        { "VU1_MAC_FLAG_PIPELINE_DEPTH_4","G138 ROOT #2: real VU1 MAC/STATUS flags become visible ~4 instruction pairs after the producing FMAC, and DC2's gate chains are hand-scheduled at EXACTLY that distance (each FMAND reads the guard SUB 4 pairs earlier). The runner read flags un-pipelined -> FMANDs consumed the interleaved fog/pos ops' flags. Fix = 4-deep flag shift register (DC2_VU1_MACPIPE_DEPTH=4 validated; 3 kills the gate entirely, 5 mostly kills it). Same defect class as the G87 Q-register latency. Kill DC2_VU1_NO_MACPIPE=1. Statically: Rule 218 flag-consumer distances (all ==4 -> pipeline REQUIRED; <4 -> program needs exact latency)." },
        { "VU1_SAME_PAIR_UPPER_LOWER_HAZARD","G139 ROOT (beam shards): a lower op can NEVER see its same-pair upper's result on real VU1 (FMAC latency). Tri packer pair 0x1fa8 `SUB VF24.xyz,VF17,VF16 | SQ VF24` is a store-then-clobber idiom - the SQ must store the OLD VF24 (=FTOI4(VF17) from exactly 4 pairs back); the runner's immediate upper commit made it store the just-computed edge vector's raw float bits as the middle vertex XYZ (.w survived via the .xyz dest mask - why ADC/fog stats matched HW while positions exploded). SIGNATURE: 'positions garbage but ADC/fog fine' = look for a dest-masked upper clobbering a lower-read VF in one pair. Fix default-ON (kill DC2_VU1_NO_PAIRHAZ=1). Statically: Rule 218 same_pair_hazards." },
        { "TITLE_VU1_CLIPPER_MAP","G140 (corrects the G132/G139 'trifan wall route 0x1c50' framing TWICE): HW never routes the cavern through 0x1c50 (live selector sweep: no title object has bit2=0&&bit0=1). The title VU program has a PRE-dispatcher at 0x5e0 - selector bit1 (=fc4, mgClipInBoxW 'frame straddles clip box') routes batches to CLIP-transform packers 0x21b0(tri)/0x23e8(tstrip); only bit1=0 batches reach the known 0x708 bit2/bit0 dispatcher. The Sutherland-Hodgman polygon clipper at 0x2740..0x2f48 (per-edge sub 0x3088: CLIPw->FCGET->IAND inside/outside; intersection sub 0x3210 with DIV Q+WAITQ+MR32) emits clipped polys as TRIFANS from the template at VU qw39->780 (nloop|=0x8000), XGKICKed at 0x2d88/0x2f38 - the alternating `00008000/0000800N 302ec000` records in the HW .gs. The HW's ~1012 'trifan' verts = CLIPPED WALL GEOMETRY at the frame edge (incl. the water pool / bottom strip), NOT a water object and NOT an object route." },
        { "TITLE_TRANSFORM_GATE_FMAND_CASCADE","G138 (corrects TITLE_PACKER_DISPATCH_MAP's '0x1ff0 is 100% nodraw by correct microcode' and retires FORCED_0x1ff0_DRAW_IS_LOAD_BEARING): under the REAL opcode table the transform gates are takeable and bit-exact vs HW. Gate formula: draw when the FMAND mask cascade equals VI3 = 0xD0|qw30, where 0xD0 = MAC S-flags x,y,w ('guard SUB negative in all three tested lanes' = inside guard planes), 0x20 = OPMSUB winding cross S.z (backface), and qw30 = the winding-flip bit written by the setup determinant code at VU 0x01c0..0x0210 (FMAND VI9,0x80 on the view determinant's S.x). 5-vert tstrip loop 0x2070..0x2180 (IBEQ @0x2128), 3-vert loop 0x1ec8..0x1fd0 (IBEQ @0x1f68), tri packer 0x1d08..0x1da0 (IBEQ @0x1d48). G100 forced-draw RETIRED (re-enable DC2_G100_FORCE_DRAW=1); with faithful gates it OVER-draws." },
        { "STALE_PC_SCOPED_BANDAID_SWEEP","G140 DURABLE LESSON: a stale default-ON band-aid can BE the 'missing feature'. The June G64 'enable fix' (ps2_vu1.cpp IAND patch scoped to pc 0x30d8/0x30f8/0x3168) ORed the tested mask into VI1 - but VI1 there is the clipper's FCGET CLIP FLAGS (set = OUTSIDE), so every vertex read outside, all 6 Sutherland-Hodgman passes emptied, and the water pool never rendered. G64's credited effect was really the then-unfixed G138/G139 roots. When retiring a root fix's band-aids, sweep OLD pc-scoped interpreter patches too (G64 predated G138 by 70 phases). Retired default-OFF: G100 forced-draw, G89 guard cull, G104/G125 near-plane tri clip, G128 behind-drop, G64 enable-fix (DC2_*_FORCE_* re-enables); G125 title Z stays default-ON. Golden title smoke: frame_001500 PixelNonZero=211646. Statically: Rule 221 runtime_lever_registry." },
        { "GS_DUMP_RECORD_ALIGNMENT_TRICK","G139 reusable tooling lesson: runner GS dumps write one strip per record with order preserved, so a contiguous runner record window aligns to the HW dump by (prim,tbp,nverts) SIGNATURE matching - no camera-pose matching needed. This record-order alignment found the per-vertex slot-1 corruption (G139) that centroid-join missed. Harness: DC2_G138_GSDUMP (runner .gs container with per-XGKICK packer-PC NOP markers) + tools/g138_hw_slice.py (per-TBP/per-strip census: ALLDRAW/PRIMED/MIXED/ALLNODRAW) + tools/g138_join.py (geometry join + per-vertex outlier A/B). ALSO: split-IMAGE continuation records misparse as giant fake PACKED groups (the 'MIXED >=2048px:842' artifact) - dedupe/validate before trusting extent stats." },
        // ===== v18: G142-G172 performance-arc invariants (Rules 234-241) =====
        { "TITLE_INLINE_SPRITE_IS_DOMINANT_COST","G171 (ROOT of the whole G155/G156 '~28ms parserOther' mystery): the dominant title per-frame cost is INLINE SPRITE rasterization - ~76-79ms/frame at ~62,000ns/call for A+D descriptor 0x0E writes to XYZF2/XYZ2 (0x04/0x05) with prim=6 GS_PRIM_SPRITE, abe=1, fbp=0x0 (vs 25-90ns/call for every other register type, a 700-1000x gap). G144's tile-bin defer + parallel band-replay ONLY ever covered GS_PRIM_TRIANGLE/TRISTRIP, so sprites ALWAYS rasterized synchronously inline, invisible to every triangle-only perf probe for ~16 phases (G144-G171). It was never GIF parse time. LESSON: perf instrumentation and deferred-raster levers must enumerate ALL primitive classes, not just triangles. Statically: GS_PRIM_SPRITE_EMITTER / prim_class_emitters." },
        { "SPRITE_DEFER_HAS_GROUP_ORDER_HAZARD","G172: naively widening G144's tile-bin defer to GS_PRIM_SPRITE regressed the costume 'Select Max's costume' prompt box to EMPTY (missing bg/border/text glyphs). The box is several sub-sprites that MUST draw as an unbroken GROUP (HW draws one TEX0 per strip; ordering/atomicity is implicit). A differential 'textured-only sprites' test made it WORSE, ruling out untextured-sprites as the cause. A reordering/band-parallel rasterizer must preserve compound-widget sprite groups. DC2_G172_SPRITE_DEFER must NOT be enabled. Statically: SPRITE_GROUP_ORDER_DEPENDENCY." },
        { "PRESENTATION_REGS_BYPASS_GS_FIFO","G150/G157 (general PS2 MTGS lesson): the 6 presentation registers (PMODE/SMODE2/DISPFB1/DISPFB2/DISPLAY1/DISPLAY2) are mutated via PS2Memory::writeIORegister writing gs_regs DIRECTLY, synchronously, on the EE thread, with NO mutex and NO ordering vs the GS worker's draws - they BYPASS the GifArbiter/worker FIFO entirely. This is the exact mechanism that broke MTGS v1 (worker latched present regs the EE had already raced past -> alternating wrong-field frames). Fix = gate the register WRITE behind a fence (G157 g150_pipeline_wait_register_slot) so the worker's unmodified latchHostPresentationFrame is correct by construction. Any multithreaded/pipelined GS runtime MUST fence/latch these separately from the draw stream. Statically: PRESENTATION_REGISTER_FIFO_BYPASS." },
        { "INTERLACED_DH_TWO_VALID_HEIGHTS","G157/G170: GS DISPLAY1/2's DH field genuinely alternates between two valid interlaced field heights (h=415 and h=416) every field (real NTSC field-parity behavior). A synchronous default samples a fixed field parity at a fixed tick; G157's inherent ~1-frame present lag shifts a fixed-tick sample onto the OTHER valid field most of the time. Verified BENIGN (identical legible content, zero corruption) - NOT a regression. LESSON: any automated golden-height check on an INTERLACED 2D route must ACCEPT BOTH field heights, never assume a constant like the (progressive) title route's 211646. Statically: presentation_fifo_bypass + this invariant." },
        { "STREAMED_TEXTURE_CACHE_REFUTED","G148/G149: a shared de-swizzle/decode texture cache (decode a bound texture ONCE into linear CLUT-pre-applied RGBA, read lock-free by all tilebin lanes) was BIT-EXACT but a MEASURED NET LOSS (~226ms vs ~213ms baseline, -6% fps) despite a ~99% intra-frame hit. Root: the streamed title textures are SPARSELY sampled per frame (perspective/minified taps change nearly every pixel), so whole-texture decodes (many 512x512 T8 = ~1.6M swizzle+CLUT reads/f) EXCEED the ~1.18M-leaf sampler they replace; coarse global VRAM-generation bumps (~82x/frame) also kill cross-frame reuse. Do NOT invest in texture-decode caching for high-BITBLT-churn pages. Statically: TEXTURE_STREAM_CHURN / streamed_texture_pages (distinct uploaders >=2 = poor cache candidate)." },
        { "GPU_RASTER_GATE_ZERO_ELIGIBLE_ON_TITLE","G158-G167 (the whole GPU-raster arc, closed by ONE census in G161): the signed-off eligibility gate (abe==0 no-blend, PSM in {CT32,CT24,CT16,CT16S}, alpha-test disabled, wrap in {REPEAT,CLAMP}) matched eligible=0/216000 (0.0%) real deferred title triangles - EVERY one has BOTH blend AND alpha-test enabled, and most are paletted T8 (badPsm=201484, the cavern is PSMT8). The abe==0 clause alone excludes the entire workload. Building the queue/shader/diff on this gate would have been dead code. A static census of which draw builders SET blend/alpha-test/paletted-PSM constants answers 'is any prim GPU-raster eligible?' before writing shader/thread code. Statically: GPU_RASTER_ELIGIBILITY_CENSUS. Also G167: cross-thread GPU contention (decoder thread vs main present thread on one physical GPU, glFinish/glReadPixels) confirmed as the real ceiling; user STOPPED the arc." },
        { "PERF_PROMOTION_NEEDS_VISUAL_NOT_JUST_NONZERO","G168/G157/G150 durable perf-method lessons: (1) golden PixelNonZero count alone (211646+/-4) is INSUFFICIENT for a promotion - the G168 full stack passed the nonzero gate but visibly dropped bottom-left title geometry; use MULTI-FRAME VISUAL review / contact sheets. (2) raw captures/frame_*.ppm dump COUNT over a fixed wall-clock window is BOOT-TIME-CONFOUNDED (the same config dumped 15/19/21 frames across runs) - use the windowed average ([G154:perf]), not dump counts, as the fps proxy. (3) verify the full-frame DISTRIBUTION/tail, not a single median sample (the G150-v1 single-sample false 'golden'). (4) a new unverified lever must never ride in on an already-default-on mechanism. Best verified title stack today = G150(MTGS)+G144(tilebin)+G157(pipeline) ~9.2fps OPT-IN; safe default = MTGS+G144 tilebin ~5.5fps." },
        // ===== v19: PCSX2 cross-check round 3 - EE interrupt/DMA/SIF/CDVD contracts (Rules 243-250) =====
        { "EE_INTC_VBLANK_HANDLER_MUST_FIRE","PCSX2 Hw.h INTC_STAT(0x1000F000)/INTC_MASK(0x1000F010) + Counters.cpp vblank cause bits (2=VBLANK_ON,3=VBLANK_OFF). The EE dispatches guest interrupt handlers registered via libkernel (AddIntcHandler/EnableIntc/AddDmacHandler/EnableDmac); the handler ACKs by writing 1 to its INTC/DMAC_STAT bit. A static recompiler that never RAISES these interrupts leaves the game's vblank + DMAC-completion callbacks dead - the DC2 half-rate title loop (F52) and the g_vsync_flag_mutex path (G7) depend on the vblank IRQ firing at the right cadence. Verify the runtime raises INTC(2/3) each field and INTC(5)=VIF1/INTC(9-12)=timers on the modelled event. Statically: EE_INTERRUPT_HANDLER_REGISTRATION." },
        { "DMA_TAG_IRQ_TIE_COMPLETION","PCSX2 Dmac.h: a source-chain DMAtag with the IRQ bit (qword bit31) set, combined with CHCR.TIE (bit7), raises that channel's DMAC interrupt on the tag's completion. A runtime that ignores tag-IRQ+TIE never signals chain completion -> the game's DMA-done handler/semaphore never fires (a silent transfer-complete deadlock, distinct from a missing kick). Statically: DMA_TAG_IRQ_COMPLETION (CHCR const with STR|TIE = 0x180 in a chain-DMA builder)." },
        { "VIF_IBIT_RAISES_STAT_INT","PCSX2 Vif.h: a VIFcode with the i-bit (bit31) set raises VIF1 STAT.INT (bit11) and stalls until acked (STC clears it); MARK writes VIF_MARK, FBRST FBK/STP/STC control the stall, MII masks the STAT INT. A runtime that executes VIF streams but ignores the i-bit never fires the VIF interrupt -> a game syncing on VIF-INT (progress callback / double-buffer swap) hangs. DC2 stages every VU1 model packet through VIF1 UNPACK. Statically: VIF_INTERRUPT_IBIT." },
        { "IOP_RPC_SMFLG_POLL_DEADLOCK_CLASS","PCSX2 Hw.h SBUS MSCOM(0x1000F200)/SMCOM(0x1000F210)/MSFLG(0x1000F220)/SMFLG(0x1000F230) + EE SIF DMA ch5(SIF0 0x1000C000 IOP->EE)/ch6(SIF1 0x1000C400 EE->IOP); Sif.h sifData EE/IOP dual-tag + sub-QW junk-fill (an IOP transfer <1QW reuses the prior QW / EE tag). MSFLG/SMFLG are the EE<->IOP handshake flags. With NO IOP CPU (DC2 blocker #1) the EE can deadlock polling SMFLG for a bit the IOP never sets - the audio(#3)/memcard(#4)/cd-RPC wait class (masked today by DC2_DISABLE_EVENT_SKIP). Statically: SIF_RPC_TRANSPORT (flags the poll sites so an IOP-dead stall routes to the transport, not game logic)." },
        { "CDVD_LEVEL_LOAD_IS_sceCdRead_STREAM","DC2 blocker #2 (some levels won't load) has TWO static failure modes: (a) a missing recompiled function at an in-range call/jump target -> 'Warning: Function at address 0xN not found' (0xe3dc70; Rule 236 RECOMPILE_TARGET_COVERAGE_GAP); (b) a CDVD read-completion WAIT that never signals if the runtime's CDVD model returns busy/never-ready. DC2 streams DATA.DAT via sceCdRead + SearchFile@0x148850 (F55) and polls sceCdSync/sceCdDiskReady/sceCdGetError. Analog to the F63/F64 audio-gated stall (Rule 170). Statically: CDVD_READ_COMPLETION_GATE." },
        { "DC2_IS_FLAT_NO_TLB_UCAB","PCSX2 models the EE TLB (tlbwi/tlbwr + COP0 EntryHi/Lo/PageMask) and the uncached-accelerated segment. DC2 is expected to be a FLAT single ELF that installs no custom TLB entries (tlb_writers statistic 0 confirms the flat-address recompiler assumption is safe - like overlay_loaders=0 for Rule 150). A non-zero tlb_writers count is a red flag that the runtime's flat memory model would break a remapped region. Statically: EE_TLB_MAPPING. Also: GS CSR SIGNAL/FINISH handshake is stubbable for DC2 (IMR=0x7F00 masks all GS IRQs, Rule 79/GS_CSR_SIGNAL_HANDSHAKE) but a game leaving GS IRQs unmasked needs it." },
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
        // v10: F50-F52 dungeon entry + render chains.
        { "dungeon_init", new String[]{
            "InitDungeonMain","memoryInit","GetMainStack","stAlloc","SetHeapMem",
            "ps2___construct_new_array","__nw__","Alloc__9mgCMemory","CActiveMonster",
            "__sinit_mainloop","Initialize__6CScene","SetupMainUnit","LoadFile"
        }},
        { "dungeon_render", new String[]{
            "LoopDungeonMain","DngStep","DngMainDraw","CScene","CMapParts",
            "mgCDrawPrim","Vertex__11mgCDrawPrim","sceVu0InversMatrix","mgInversMatrix",
            "mgEndFrame","ReloadTexture","mgLoadImage"
        }},
        { "thread_yield_lock", new String[]{
            "GamePadStep","SwitchGamePadThread","RotateThreadReadyQueue",
            "TerminateThread","WaitForNextVSyncTick","sceGsSyncV","cooperativeGuestYield"
        }},
        // v11.3: G21-G26 character/deform 3D-model render chain (active blocker, Known Issue #2).
        // Builds a VU1 MSCAL packet, stages it in scratchpad, DMAs via fromSPR ch8 to mgVif1Packet.
        { "character_model_vu1", new String[]{
            "Draw__15CMenuCostumeSel","DrawDirect__12CActionChara","DrawDirect__11CCharacter2",
            "SetDeformMesh","mgDrawDirect","Draw__8mgCFrame","Draw__12mgCVisualMDT",
            "CreateRenderInfoPacket","mgClipBoxW","GetScrPad","SendDMA",
            "mgFlushRenderInfo","mgSendVuProg","mgSendPacket","sceDmaSend"
        }},
        // v11.3: F63/F64 event-script VM (cutscene/door waits; stalls headless on audio).
        { "event_script_vm", new String[]{
            "RunMainEvent","EventLoop","resume__10CRunScript","exe__10CRunScript",
            "run__10CRunScript","StreamOpenState","sceSifCheckStatRpc","_SND_LOAD_SOUND"
        }},
        // v11.3: G9-G13 front-end New-Game -> Select-Costume route (names/cursor/model).
        { "costume_select", new String[]{
            "TitleLoop","TitleModeKey","MenuMainInit","MenuMainKey","MenuMainDraw",
            "__ct__15CMenuCostumeSel","MenuItemCharaDataLoad","GetCharaDataPtr","GetUserDataMan",
            "Draw__15CMenuCostumeSel","GetName__13CGameDataUsed","MenuCursorDraw"
        }},
        // v13 Rule 183: G53-G82 main-title 3D-background render chain.
        { "title_3d_background", new String[]{
            "TitleLoop","TitleModeInit","TitleMapDraw","GetCamera__6CScene","Initialize__6CScene",
            "mgCCameraFollow","GetLightInfo__4CMap","mgSetLight","mgSetAmbient",
            "DrawSub__4CMap","Draw__9CMapParts","Draw__12mgCVisualMDT","CreateRenderInfoPacket",
            "Draw__8mgCFrame","mgClipInBoxW","mgDraw","mgEndFrame"
        }},
    };

    // v13 Rule 185: LOOP_STATE_MODEL. The front-end/dungeon program-state legend +
    // the mutually-exclusive front-end sub-states (G79 illegal-concurrent leak).
    // Format: {state, where, legend}.
    private static final String[][] LOOP_STATE_MODEL = {
        { "LoopNo", "*(gp-0x7524)=0x00376fcc via GetNowLoopNo@0x1909a0",
          "0=boot, 2=dungeon/in-game loop (LoopDungeonMain), 3=front-end (title/menu/costume - all one loop, TitleLoop@0x29ffa0)" },
        { "TitleInfo", "*TitleInfo (sub-state of LoopNo=3; probe DC2_TRACE_LOOP_TIMING)",
          "0=intro movie, 1=press-START (TitleModeKey@0x2a1220), 2/7=New Game/Load menu (MenuMainKey@0x233ff0), 3=MC-check, 4=copyright. Boot auto-advances 3->1->2." },
        { "DngStatus", "0x01E9F6E0 (lui at,0x1ea; lw -0x920(at))",
          "0=free-roam, 1/4=menu (MenuMainDraw@0x234290 replaces 3D), 2=event, 3=event-edit, 5=exit. DngMainDraw@0x1cf090 runs for {0,2,3}." },
        { "NewGameTrigger", "DAT_01ecd62c@0x01ECD62C (set by MenuMainKey on confirm)",
          "0xc=New Game -> TitleLoop case 2 -> NextLoop(2); 0x10=Load Save; 0x13=HDD; else=load." },
        { "ILLEGAL_CONCURRENT", "LoopNo=3 && titleMode=2 && menuId=0x17",
          "G79 contradictory state: TitleLoop New-Game menu + MenuCostumeSel (Draw__15CMenuCostumeSel) both live; costume never tore down -> leaked RTT GS-state -> flat-blue title 3D bg. A draw reachable in this state is suspect." },
    };

    // v9 Rule 135: working DC2_PAD_INPUT scripts from F40/F42/F46 fix logs.
    // Format: {tag, script, frame_anchor, observed_effect}.
    private static final String[][] DC2_PAD_INPUT_SCRIPTS = {
        { "F40_baseline_smoke",       "1:Start",                                                   "mgEndFrame=1",   "single inject at boot frame; baseline only" },
        { "F41_R1_title_confirm",     "30..39:R1",                                                 "mgEndFrame=30",  "R1 -> MenuCheckPushButton ret=0x10 -> TitlePhase 0->1; 3x PPM brightness" },
        { "F42_menu_progression",     "200:R1;320:R1;440:R1;560:R1;680:R1;800:R1",                 "mgEndFrame=200", "drives TitleModeKey->MenuMain->MenuNewGame; [F39:lf2] count=41; map/map1.cfg + def.sky hits" },
        { "F46_canonical_sweep",      "30..39:R1;120..129/160..169/190..199/220..229/260..269:Cross", "mgEndFrame=30","canonical menu sequence; [F40:inject]=10 frames 30-39 only" },
        { "F46_calibration_probe",    "1..120:R1",                                                 "mgEndFrame=1",   "verifies injector fires; only frame 1 reachable in 30s window" },
        // v10: F48.4 costume-confirm route to NextLoop(2) (menu->dungeon transition).
        { "F48.4_costume_confirm",    "30..39:R1;216..223:Cross;238..245:Cross;260..267:Cross;282..289:Cross;304..311:Down;326..333:Square;348..355:Down", "d62c=0xc@351; next=2@442", "row cursor 0->3, Down opens Yes/No, Square->Yes, Down confirms; TitleLoop NextLoop(2)" },
        // v10: F50.6+ built-in debug-menu dungeon-0 route (needs DC2_DEBUG_MENU=1).
        { "F50.6_debug_dungeon0",     "90..99:DebugDown;130..139:DebugDown;170..179:DebugConfirm", "InitDungeonMain enter", "with DC2_DEBUG_MENU=1: navigates MenuLoop@0x191C30 to 'dungeon 0' (map/d/d01/f01) and enters InitDungeonMain@0x1CC040" },
        // v11.3: F64 debug-menu dungeon-entrance cutscene (validated 2026-06-14). Runner reads RAW CGamePad bits: Circle==DebugConfirm(0x20), Down==DebugDown(0x4000).
        { "F64_dungeon_event",        "90..97:DebugConfirm;130..297:DebugDown;330..337:DebugConfirm;370..657:DebugDown;690..697:DebugConfirm", "DngStatus 0->2 @~700", "DC2_DEBUG_MENU=1: Select+Start->Circle->Down x5->Circle->Down x8->Circle; DngMainMap=0x103c2f0 mapIdx=0; parks the F63 stuck entrance event (vmcode=0x9261d4)" },
        { "F64_opening_event",        "90..97:DebugConfirm;130..297:DebugDown;330..337:DebugConfirm;370..617:DebugDown;650..657:DebugConfirm", "DngStatus 0->2 (opening)", "same as F64_dungeon_event but Down x7 (not x8); parks a DIFFERENT script point (vmcode=0x8ec430, op=0x10 cond-jump wait, d504=0)" },
        // v11.3: G9 Select-Costume headless entry (needs DC2_G9_COSTUME forcing TitleModeKey ret=5; Cross pulses dismiss the 'Select Max costume' prompt at phase 4).
        { "G9_costume_select",        "30..39:R1;120..200:Cross", "MenuCommonInfo+0x50=0x14", "DC2_G9_COSTUME: forced New-Game path -> MenuMainInit case 0x14; pulse Cross at MenuCosutumeLoadPhase==4 to populate the costume list" },
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
        // v11 REBUILD (General v15.5 Bugfix W): the old map had wrong
        // assignments (0x66/0x67 are CpuConfig/iGetCop0, NOT GsGetIMR/
        // GsPutIMR; 0x68 is iFlushCache, NOT SetVSyncFlag; SetVSyncFlag is
        // 0x73 and SetSyscall is 0x74) - and Rule 160 now BINDS runtime
        // handlers from these names, so every entry is cross-checked against
        // two authorities:
        //   - pcsx2/R5900OpcodeImpl.cpp syscall name table (numbering), and
        //   - ps2xRuntime Kernel/Syscalls/Dispatcher.cpp numeric dispatch
        //     (handler spelling - names here use the RUNTIME's spelling so
        //     hasRuntimeHandler() lookups succeed, e.g. GsSetCrt, EnableIntc,
        //     CancelAlarm, SetupThread/SetupHeap).
        // Numbers whose meaning is contested across BIOS revisions (0x5A/
        // 0x5B: iReferEventFlagStatus vs QueryBootMode/GetThreadTLS) are
        // deliberately OMITTED: an unmapped trampoline recompiles and the
        // runtime's numeric dispatcher resolves it at run time, which is
        // always correct.
        EE_SYSCALL_NAMES.put(0x01L, "ResetEE");
        EE_SYSCALL_NAMES.put(0x02L, "GsSetCrt");
        EE_SYSCALL_NAMES.put(0x06L, "LoadExecPS2");
        EE_SYSCALL_NAMES.put(0x07L, "ExecPS2");
        EE_SYSCALL_NAMES.put(0x0AL, "AddSbusIntcHandler");
        EE_SYSCALL_NAMES.put(0x0BL, "RemoveSbusIntcHandler");
        EE_SYSCALL_NAMES.put(0x0CL, "Interrupt2Iop");
        EE_SYSCALL_NAMES.put(0x0DL, "SetVTLBRefillHandler");
        EE_SYSCALL_NAMES.put(0x0EL, "SetVCommonHandler");
        EE_SYSCALL_NAMES.put(0x0FL, "SetVInterruptHandler");
        EE_SYSCALL_NAMES.put(0x10L, "AddIntcHandler");
        EE_SYSCALL_NAMES.put(0x11L, "RemoveIntcHandler");
        EE_SYSCALL_NAMES.put(0x12L, "AddDmacHandler");
        EE_SYSCALL_NAMES.put(0x13L, "RemoveDmacHandler");
        EE_SYSCALL_NAMES.put(0x14L, "EnableIntc");
        EE_SYSCALL_NAMES.put(0x15L, "DisableIntc");
        EE_SYSCALL_NAMES.put(0x16L, "EnableDmac");
        EE_SYSCALL_NAMES.put(0x17L, "DisableDmac");
        EE_SYSCALL_NAMES.put(0x18L, "SetAlarm");
        EE_SYSCALL_NAMES.put(0x19L, "CancelAlarm");
        EE_SYSCALL_NAMES.put(0x20L, "CreateThread");
        EE_SYSCALL_NAMES.put(0x21L, "DeleteThread");
        EE_SYSCALL_NAMES.put(0x22L, "StartThread");
        EE_SYSCALL_NAMES.put(0x23L, "ExitThread");
        EE_SYSCALL_NAMES.put(0x24L, "ExitDeleteThread");
        EE_SYSCALL_NAMES.put(0x25L, "TerminateThread");
        EE_SYSCALL_NAMES.put(0x26L, "iTerminateThread");
        EE_SYSCALL_NAMES.put(0x29L, "ChangeThreadPriority");
        EE_SYSCALL_NAMES.put(0x2BL, "RotateThreadReadyQueue");
        EE_SYSCALL_NAMES.put(0x2DL, "ReleaseWaitThread");
        EE_SYSCALL_NAMES.put(0x2FL, "GetThreadId");
        EE_SYSCALL_NAMES.put(0x30L, "ReferThreadStatus");
        EE_SYSCALL_NAMES.put(0x32L, "SleepThread");
        EE_SYSCALL_NAMES.put(0x33L, "WakeupThread");
        EE_SYSCALL_NAMES.put(0x35L, "CancelWakeupThread");
        EE_SYSCALL_NAMES.put(0x37L, "SuspendThread");
        EE_SYSCALL_NAMES.put(0x39L, "ResumeThread");
        EE_SYSCALL_NAMES.put(0x3BL, "JoinThread");
        EE_SYSCALL_NAMES.put(0x3CL, "SetupThread");
        EE_SYSCALL_NAMES.put(0x3DL, "SetupHeap");
        EE_SYSCALL_NAMES.put(0x3EL, "EndOfHeap");
        EE_SYSCALL_NAMES.put(0x40L, "CreateSema");
        EE_SYSCALL_NAMES.put(0x41L, "DeleteSema");
        EE_SYSCALL_NAMES.put(0x42L, "SignalSema");
        EE_SYSCALL_NAMES.put(0x44L, "WaitSema");
        EE_SYSCALL_NAMES.put(0x45L, "PollSema");
        EE_SYSCALL_NAMES.put(0x47L, "ReferSemaStatus");
        EE_SYSCALL_NAMES.put(0x48L, "iReferSemaStatus");
        EE_SYSCALL_NAMES.put(0x4AL, "SetOsdConfigParam");
        EE_SYSCALL_NAMES.put(0x4BL, "GetOsdConfigParam");
        EE_SYSCALL_NAMES.put(0x4CL, "GetGsHParam");
        EE_SYSCALL_NAMES.put(0x4DL, "GetGsVParam");
        EE_SYSCALL_NAMES.put(0x4EL, "SetGsHParam");
        EE_SYSCALL_NAMES.put(0x4FL, "SetGsVParam");
        EE_SYSCALL_NAMES.put(0x50L, "CreateEventFlag");
        EE_SYSCALL_NAMES.put(0x51L, "DeleteEventFlag");
        EE_SYSCALL_NAMES.put(0x52L, "SetEventFlag");
        EE_SYSCALL_NAMES.put(0x53L, "iSetEventFlag");
        EE_SYSCALL_NAMES.put(0x54L, "ClearEventFlag");
        EE_SYSCALL_NAMES.put(0x55L, "iClearEventFlag");
        EE_SYSCALL_NAMES.put(0x56L, "WaitEventFlag");
        EE_SYSCALL_NAMES.put(0x57L, "PollEventFlag");
        EE_SYSCALL_NAMES.put(0x58L, "iPollEventFlag");
        EE_SYSCALL_NAMES.put(0x59L, "ReferEventFlagStatus");
        EE_SYSCALL_NAMES.put(0x5CL, "EnableIntcHandler");
        EE_SYSCALL_NAMES.put(0x5DL, "DisableIntcHandler");
        EE_SYSCALL_NAMES.put(0x5EL, "EnableDmacHandler");
        EE_SYSCALL_NAMES.put(0x5FL, "DisableDmacHandler");
        EE_SYSCALL_NAMES.put(0x61L, "EnableCache");
        EE_SYSCALL_NAMES.put(0x62L, "DisableCache");
        EE_SYSCALL_NAMES.put(0x64L, "FlushCache");
        EE_SYSCALL_NAMES.put(0x68L, "iFlushCache");
        EE_SYSCALL_NAMES.put(0x70L, "GsGetIMR");
        EE_SYSCALL_NAMES.put(0x71L, "GsPutIMR");
        EE_SYSCALL_NAMES.put(0x72L, "SetPgifHandler");
        EE_SYSCALL_NAMES.put(0x73L, "SetVSyncFlag");
        EE_SYSCALL_NAMES.put(0x74L, "SetSyscall");
        EE_SYSCALL_NAMES.put(0x76L, "sceSifDmaStat");
        EE_SYSCALL_NAMES.put(0x77L, "sceSifSetDma");
        EE_SYSCALL_NAMES.put(0x78L, "sceSifSetDChain");
        EE_SYSCALL_NAMES.put(0x79L, "sceSifSetReg");
        EE_SYSCALL_NAMES.put(0x7AL, "sceSifGetReg");
        EE_SYSCALL_NAMES.put(0x7BL, "ExecOSD");
        EE_SYSCALL_NAMES.put(0x7CL, "Deci2Call");
        EE_SYSCALL_NAMES.put(0x7EL, "MachineType");
        EE_SYSCALL_NAMES.put(0x7FL, "GetMemorySize");
        EE_SYSCALL_NAMES.put(0x83L, "FindAddress");
        EE_SYSCALL_NAMES.put(0x85L, "SetMemoryMode");
        // i-variant kernel calls encode as NEGATIVE $v1 ((0x100 - N) after
        // the detector's &0xFF mask). Runtime dispatcher implements these.
        EE_SYSCALL_NAMES.put(0xE6L, "iEnableIntc");          // -0x1A
        EE_SYSCALL_NAMES.put(0xE5L, "iDisableIntc");         // -0x1B
        EE_SYSCALL_NAMES.put(0xE4L, "iEnableDmac");          // -0x1C
        EE_SYSCALL_NAMES.put(0xE3L, "iDisableDmac");         // -0x1D
        EE_SYSCALL_NAMES.put(0xE2L, "iSetAlarm");            // -0x1E
        EE_SYSCALL_NAMES.put(0xE1L, "iCancelAlarm");         // -0x1F
        EE_SYSCALL_NAMES.put(0xD6L, "iChangeThreadPriority");// -0x2A
        EE_SYSCALL_NAMES.put(0xD4L, "iRotateThreadReadyQueue");// -0x2C
        EE_SYSCALL_NAMES.put(0xD2L, "iReleaseWaitThread");   // -0x2E
        EE_SYSCALL_NAMES.put(0xD1L, "GetThreadId");          // -0x2F
        EE_SYSCALL_NAMES.put(0xCFL, "iReferThreadStatus");   // -0x31
        EE_SYSCALL_NAMES.put(0xCCL, "iWakeupThread");        // -0x34
        EE_SYSCALL_NAMES.put(0xCAL, "iCancelWakeupThread");  // -0x36
        EE_SYSCALL_NAMES.put(0xC8L, "iSuspendThread");       // -0x38
        EE_SYSCALL_NAMES.put(0xC6L, "iResumeThread");        // -0x3A
        EE_SYSCALL_NAMES.put(0xBDL, "iSignalSema");          // -0x43
        EE_SYSCALL_NAMES.put(0xBAL, "iPollSema");            // -0x46
        EE_SYSCALL_NAMES.put(0xB8L, "iReferSemaStatus");     // -0x48
        EE_SYSCALL_NAMES.put(0xB7L, "iDeleteSema");          // -0x49
        EE_SYSCALL_NAMES.put(0xADL, "iSetEventFlag");        // -0x53
        EE_SYSCALL_NAMES.put(0xABL, "iClearEventFlag");      // -0x55
        EE_SYSCALL_NAMES.put(0xA8L, "iPollEventFlag");       // -0x58
        EE_SYSCALL_NAMES.put(0xA6L, "iReferEventFlagStatus");// -0x5A
        EE_SYSCALL_NAMES.put(0xA4L, "iEnableIntcHandler");   // -0x5C
        EE_SYSCALL_NAMES.put(0xA3L, "iDisableIntcHandler");  // -0x5D
        EE_SYSCALL_NAMES.put(0xA2L, "iEnableDmacHandler");   // -0x5E
        EE_SYSCALL_NAMES.put(0xA1L, "iDisableDmacHandler");  // -0x5F
        EE_SYSCALL_NAMES.put(0x90L, "iGsGetIMR");            // -0x70
        EE_SYSCALL_NAMES.put(0x8FL, "iGsPutIMR");            // -0x71
    }

    // v9 Rule 137: tag priority for TOML comment generation (higher = printed first).
    private static final Map<String,Integer> TAG_PRIORITY = new HashMap<>();
    static {
        // Tier-0 blocker tags
        TAG_PRIORITY.put("TOP_PRIORITY_FIX", 1000);
        // v11 (General v15.3): input-hygiene + handler-roster tags rank just
        // below the render bullseyes - they mark wrong bindings, not wrong code.
        TAG_PRIORITY.put("NO_RUNTIME_HANDLER", 985);
        TAG_PRIORITY.put("STEP1_NAME_MISMATCH", 980);
        TAG_PRIORITY.put("STEP1_TRUNCATED_NAME", 360);
        TAG_PRIORITY.put("OVERLAY_REGION", 975);
        TAG_PRIORITY.put("OUT_OF_TEXT_BINDING", 970);
        // v11 (General v15.5 Rule 161): runtime code linker/loader.
        TAG_PRIORITY.put("DYNAMIC_CODE_LOADER", 965);
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
        // v13 Rules 178-188 (render/init-critical tier).
        TAG_PRIORITY.put("CONDITIONAL_INIT_ON_GLOBAL", 938);
        TAG_PRIORITY.put("RENDER_MODE_SELECTOR", 936);
        TAG_PRIORITY.put("VERTEX_LIGHTING_NORMAL_TERM", 934);
        TAG_PRIORITY.put("VTABLE_TAILCALL_THUNK", 932);
        TAG_PRIORITY.put("RTT_NO_RESTORE", 930);
        // v16 (G116-G137 title-cavern): render-path classes, ranked just under the v13 render rules.
        TAG_PRIORITY.put("VERTEX_KICK_FORMAT_ADC_CAPABILITY", 928);
        TAG_PRIORITY.put("PERSPECTIVE_DIVIDE_NEAR_PLANE_SOURCE", 926);
        TAG_PRIORITY.put("PASSTHROUGH_PACKER_RENDER_PATH", 924);
        TAG_PRIORITY.put("PACKED_FIELD_ALIAS_FOG_ADC", 922);
        TAG_PRIORITY.put("SPI_CONFIG_COMMAND_DISPATCH", 520);
        TAG_PRIORITY.put("DATA_DRIVEN_COMMAND_INTERPRETER", 510);
        TAG_PRIORITY.put("PRIVATE_DEPTH_SCOPE", 700);
        TAG_PRIORITY.put("FRAME_RESUME_RISK", 760);
        TAG_PRIORITY.put("VU_FLAG_PIPELINE_UPLOADER", 705);
        TAG_PRIORITY.put("PACKED_RGBAQ_BUILDER", 655);
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
        // v11: step1-provenance + trampoline tags (informational tier).
        TAG_PRIORITY.put("STEP1_LOCKED", 335);
        TAG_PRIORITY.put("BINDING_FIREWALL_RESCUED", 330);
        TAG_PRIORITY.put("STEP1_RESCUED", 325);
        TAG_PRIORITY.put("ADDRESS_TAKEN_CALLBACK", 320);
        TAG_PRIORITY.put("STEP1_BOUND_HOST_BOUNDARY", 315);
        TAG_PRIORITY.put("STEP1_BOUND_ROSTER_HANDLER", 310);
        TAG_PRIORITY.put("SYSCALL_TRAMPOLINE", 305);
        TAG_PRIORITY.put("SIF_PACKET_BUILDER", 300);
        // v12 Rules 165-177 (render/present/io hazard tier).
        TAG_PRIORITY.put("RTT_TARGET", 945);
        TAG_PRIORITY.put("VF0_DEPENDENT_INVERSE", 935);
        TAG_PRIORITY.put("ZBUF_VRAM_ALIAS_RISK", 745);
        TAG_PRIORITY.put("DC2_AUDIO_GATED_STALL", 835);
        TAG_PRIORITY.put("AUDIO_COMPLETION_GATE", 525);
        TAG_PRIORITY.put("CLUT_CACHE_INVALIDATOR", 515);
        TAG_PRIORITY.put("PRESENTATION_FIELD_STATE", 510);
        TAG_PRIORITY.put("DISPLAY_BUFFER_FLIP", 505);
        TAG_PRIORITY.put("MEMCARD_IO", 470);
        TAG_PRIORITY.put("PERF_HOT_FRAME_PATH", 295);
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

    // v10.1 Rule 150: EE code-overlay exec/load callees. NOTE: sceSifLoadModule
    // (IOP modules) is deliberately excluded — that is IRX loading (Rule 124),
    // not an EE-address-space overlay. sceCdRead is excluded as too common.
    private static final Set<String> OVERLAY_LOADER_CALLEES = new HashSet<>(Arrays.asList(
        "LoadExecPS2","ExecPS2","sceExecPS2","LoadModuleBuffer",
        "sceSifLoadModuleBuffer","sceSifLoadElf","ExecModule","sceSifLoadElfPart"
    ));

    // Rule 102: VU0 helper whitelist (must be implemented, never auto-stub).
    private static final String[] SCEVU0_HELPER_PREFIXES = {
        "sceVu0","_sceVu0"
    };

    // v10: sceVu0* helpers still TODO_NAMED (throwing) in Kernel/Stubs/VU.cpp as
    // of F50.7. Implement from ref/assembly.txt when a 3D route hits one. Already
    // implemented: sceVu0InversMatrix (F50.7), sceVu0MulMatrix (F46.6),
    // sceVu0CameraMatrix (F46.5). The RotTransPers* / ViewScreenMatrix throwers
    // are NOT on the dungeon route (it uses inline COP2 instead, per F51.7).
    private static final String[] SCEVU0_UNIMPLEMENTED = {
        "sceVu0ecossin","sceVu0InterVector","sceVu0InterVectorf",
        "sceVu0LightColorMatrix","sceVu0MulVector",
        "sceVu0RotTransPers","sceVu0RotTransPersN","sceVu0ViewScreenMatrix"
    };

    // Rule 107: phase-trace env flags inventory (emitted into JSON for tools).
    private static final String[] PHASE_TRACE_FLAGS = {
        "DC2_PHASE_TRACE","DC2_TRACE_TITLE_PATH","DC2_TRACE_T8_UPLOAD",
        "DC2_HUD","DC2_FRAME_DUMP","DC2_PAD_INPUT","DC2_TRACE_PAD",
        "DC2_TRACE_VTABLE","DC2_TRACE_CTOR","DC2_TRACE_MAP_LOAD",
        "DC2_TRACE_SAVE","DC2_TRACE_DRAW","DC2_TRACE_BITBLTBUF",
        // v10: F49.5-F51.8 env-gated probes (all quiet by default).
        "DC2_TRACE_VU1","DC2_TRACE_RENDER_QUALITY","DC2_TRACE_HANG",
        "DC2_TRACE_FRAME_REGS","DC2_DEBUG_MENU","DC2_TRACE_MAP_ENTRY",
        "DC2_TRACE_MENU_STATE","DC2_TRACE_F50_10","DC2_TRACE_F50_11",
        "DC2_TRACE_F50_12","DC2_T8_ALIAS_TBW",
        // v17: G138-G140 packet-level A/B + VU1 clipper probes (env-gated, quiet by default).
        "DC2_G138_GSDUMP","DC2_G138_GSDUMP_MAX","DC2_G140_CLIP","DC2_G63_GATE",
        "DC2_VU1_MACPIPE_DEPTH","DC2_G22_VU1_CYCLES"
    };

    // v17 Rule 221/223: the retired/kill-switch band-aid roster from the G138-G140
    // root-cause arc. Emitted as `runtime_bandaid_status` so a future phase never
    // re-tunes a retired lever or misses a stale pc-scoped patch (the G64 class).
    // Format: {env, phase, default_state, note}.
    private static final String[][] DC2_RETIRED_BANDAIDS = {
        { "DC2_G100_FORCE_DRAW",        "G138", "retired_off", "title forced-draw band-aid; with faithful FMAND gates it OVER-draws (and never covered the 3-vert loop gate 0x1f68)" },
        { "DC2_VU1_NO_FMSWAPFIX",       "G138", "fix_on",      "kill-switch for the FMEQ/FMAND lower-opcode-table root fix (0x18=FMEQ,0x1A=FMAND,0x1B=FMOR,0x1C=FCGET)" },
        { "DC2_VU1_NO_MACPIPE",         "G138", "fix_on",      "kill-switch for the 4-deep MAC/STATUS flag pipeline (DC2_VU1_MACPIPE_DEPTH=4; 3/5 kill the gate)" },
        { "DC2_VU1_NO_PAIRHAZ",         "G139", "fix_on",      "kill-switch for the same-pair upper->lower VF hazard fix (lower reads pre-upper value; upper's masked lanes overlaid after)" },
        { "DC2_G89_FORCE_GUARD_CULL",   "G139", "retired_off", "rasterizer guard-cull band-aid retired; natural gates+positions are HW-faithful" },
        { "DC2_G104_FORCE_TRI_CLIP",    "G139", "retired_off", "near-plane homogeneous tri-clip band-aid retired (G104/G125)" },
        { "DC2_G128_FORCE_BEHIND_DROP", "G139", "retired_off", "behind-drop reject band-aid retired" },
        { "DC2_G125_NO_TITLE_Z",        "G125", "still_on",    "title private-Z substitute STILL default-ON - load-bearing for depth order (foreground rocks); re-A/B before deleting" },
        { "DC2_G64_FORCE_ENABLE_FIX",   "G140", "retired_off", "G64 IAND VI1-forcing retired: VI1 at pc 0x30d8/0x30f8/0x3168 is the clipper's FCGET clip flags (set=OUTSIDE); forcing bits inverted the inside/outside test and emptied all 6 clip passes (no water pool)" },
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
        // v10: F50.8-F51.8 dungeon map texture subsystem (separate from manager).
        { "MAP_PSMT4_PIX",  0x14, 0x2580L, "F50.11_MAP",   "dungeon map PSMT4 pixels - NEVER uploaded (missing loader)" },
        { "MAP_CLUT_PSMCT16",0x02,0x2980L, "F50.8_MAPCLUT","dungeon map PSMCT16 CLUT - NEVER transferred => empty CLUT => black" },
        { "MAP_T8_DUNGEON", 0x13, 0x3220L, "F51.8_MAPT8",  "dungeon map T8 (CLUT 0x3fb8) - uploaded GOOD; geom was degenerate via COP2 bug" },
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
        // v11 (General v13): store-instruction count. Used to separate true
        // idle/poll spins (no stores) from counted copy/clear loops
        // (memcpy/memset shapes), which the old INFINITE_SPIN_LOOP rule
        // falsely flagged for NOP patching.
        int storeOps=0;
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
        // ===== v11.3 detectors (DC2 F52-G26 retrospective) =====
        // Rule 162 SPR_DMA_STAGER: writes a fromSPR(ch8 0x1000D000)/toSPR(ch9
        // 0x1000D400) DMA channel reg. DC2 stages each VU1 model VIF packet in
        // EE scratchpad then copies it into mgVif1Packet via a fromSPR DMA
        // (SendDMA@0x13e3d0). A runtime whose IO dispatch only handles GIF/VIF1
        // drops ch8/ch9 -> empty model slot -> no XGKICK (G26 root cause).
        boolean programsSprDma=false;
        Set<String> sprDmaChannels=new LinkedHashSet<>();   // "fromSPR" / "toSPR"
        // Rule 162 SUBWORD_DMA_STR_KICK: sb/sh landing in a DMA CHCR word
        // (slot 0..3). The STR bit is set via a sub-word store (G26: SendDMA
        // kicks ch8 with `sb` to CHCR+1). A word-only writeIORegister misses it.
        boolean subwordDmaStrKick=false;
        Set<String> subwordKickChannels=new LinkedHashSet<>();
        // Rule 163 VU1_DOUBLE_BUFFER_FRAMER: builds BASE+OFFSET VIFcodes (the
        // TOPS double-buffer framing G23/G24 could not find). Derived from
        // vifOpcodesBuilt at categorise time.
        boolean isVu1DoubleBufferFramer=false;
        // Rule 164 STALE_PTR_CACHE_CTOR: a ctor that caches a getter result into
        // this+K (G12/G13/F50.4). If it runs before the source is funded it
        // caches 0/stale and the downstream Draw silently skips. Derived.
        boolean isStalePtrCacheCtor=false;
        String  stalePtrCacheGetter=null;
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
        // v11 (General v15.5 Rule 161): dynamic-code loader (reads payload
        // from disc, then flushes the instruction cache before executing it).
        boolean isDynamicCodeLoader = false;
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
        // v11 (General v14): 16-byte-stride store pattern matched but the only
        // context is SIF RPC packet building (no GIF/VIF/DMA evidence).
        // Demoted from gifTagInlineBuilder so render heuristics ignore it.
        boolean sifPacketBuilder = false;
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

        // ===== v10 fields (DC2 F47-F52 retrospective) =====
        // Rule 140: VU0-macro COP2 partial-destination write ops. F51.8 root
        // cause: the recompiler emitted the COP2 dest-component blend mask in
        // REVERSED lane order, so every PARTIAL-dest op (vftoi4.xy / vadd.xyz /
        // vftoi0.z ...) wrote X/Y/Z into the wrong SIMD lane → all VU0-macro 3D
        // perspective transforms produced degenerate (off-screen) vertices.
        // Full `.xyzw` ops are symmetric → unaffected → the bug hid for 50+
        // phases behind working 2D/UI. Any func with cop2PartialDestOps>0 must
        // have its generated COP2 dest-mask lane order verified.
        int cop2PartialDestOps = 0;
        int cop2FullDestOps    = 0;
        Set<String> cop2DestFields = new LinkedHashSet<>();   // e.g. "xy","z","xyz"
        boolean cop2DestMaskVerify = false;                   // partial-dest present
        // Rule 141: static-initializer (__sinit_*) install manifest. These funcs
        // have NO `jal` caller — they run ONLY via the global-ctors table. When
        // that table is not driven (headless port), the global object's vtable
        // pointer / field stays null and the next virtual dispatch silently
        // no-ops (F50.4 MainScene+0x10548=__vt__6CScene, F50.7 CRandomCircle /
        // CGeoStone). Each entry = [storePc, installedValue(target), storeOff].
        List<long[]> staticInitInstalls = new ArrayList<>();
        boolean isStaticInitializer = false;     // name starts with __sinit_
        boolean staticInitInstallsVtable = false;// installs a __vt__* pointer
        boolean isUncalledStaticInit = false;    // __sinit AND zero call/flow xrefs
        // Rule 142: memory allocator / pool / placement-new. F50.1/F50.2: when
        // auto-stubbed to `setReturnS32(0)` the pool is never created, Alloc
        // returns 0, and constructing on null yields a garbage vtable PC deep in
        // an init chain (masquerades as a bad-ctor crash). Never auto-stub.
        boolean isMemoryAllocator = false;
        String  allocatorKind = null;            // pool_init | alloc | placement_new | array_ctor | stack
        // Rule 143: guest-execution-lock hog. F49.5/F50: a guest thread spinning
        // without yielding the single m_guestExecutionMutex (e.g. GamePadStep ->
        // SwitchGamePadThread / RotateThreadReadyQueue syscall 0x2B) starves all
        // other guest threads → menu→dungeon deadlock. Yield syscalls MUST wrap
        // their wait in GuestExecutionReleaseScope.
        boolean isGuestLockHogCandidate = false;
        // Rule 144: MIPS EABI 5th-arg detection. F50.1/F50.2: DC2 passes the 5th
        // integer arg in $t0 ($a4), not on the stack (construct_new_array:
        // a0=array,a1=ctor,a2=dtor,a3=elemSize,a4=$t0=count). A runtime/CRT
        // helper override must derive its ABI from the real call site. True when
        // the body reads $t0 as a source before defining it in the prologue.
        boolean readsEabiArgT0 = false;
        // Rule 145: PSMCT16 map-CLUT uploader. F50.8-F50.11: the dungeon map
        // texture subsystem (tbp=0x2580 / CLUT cbp=0x2980 PSMCT16) is separate
        // from mgCTextureManager and its PSMCT16 CLUT (dpsm=0x2) is NEVER
        // transferred → empty CLUT → black. Flags BITBLTBUF writers that load a
        // PSMCT16 dpsm constant.
        boolean loadsPsmct16Const = false;
        boolean isPsmct16ClutUploader = false;

        // ===== v10.1 fields (PCSX2- + skill-grounded) =====
        // Rule 146: computed `jr $reg` switch-table sites + Ghidra-resolved
        // destinations. Static recompilers panic on unresolved indirect jumps;
        // emitting the resolved target list lets the recompiler pre-populate its
        // jump dispatch. Each target entry = [sitePc, targetAddr]. switchPcs holds
        // every computed-jr site (so a site with no targets = UNRESOLVED).
        List<long[]> computedJumpTargets = new ArrayList<>();
        Set<Long> computedJumpSwitchPcs = new LinkedHashSet<>();
        // Rule 147: COP2 special-op / latency hazards beyond the dest-mask blends
        // (F51.8 fix log: "watch vmr32 / vclip / vopmsub"). Families: EFU_Q_LATENCY
        // (vdiv/vsqrt/vrsqrt write Q with latency), CLIP_FLAG (vclipw), R_REGISTER
        // (vrnext/vrget/vrxor), VMR32, WAIT (vwaitq/p), OUTER_PRODUCT (vopmsub/
        // vopmula), XGKICK.
        Set<String> cop2SpecialOps = new LinkedHashSet<>();
        // Rule 148: EE FPU is non-IEEE (no denormals/NaN, truncation, soft div/
        // sqrt). Naive host float diverges. writesFpuControl = ctc1/cfc1 (rounding
        // mode); usesFpuDivSqrt = div.s/sqrt.s/rsqrt.s.
        boolean writesFpuControl = false;
        boolean usesFpuDivSqrt = false;
        // Rule 150: calls an EE code-overlay loader (LoadExecPS2/ExecPS2/
        // LoadModuleBuffer ...). Static recompilers assume a flat address space;
        // overlay games reuse a region for multiple code banks.
        boolean isOverlayLoader = false;

        // ===== v12 fields (DC2 G27-G52 retrospective + general RTT/present hazards) =====
        // Rule 166: writes the GS FRAME reg (A+D id 0x4C/0x4D) — the render-target setter.
        boolean writesFrameReg = false;
        // Rule 165/166/167: labelled VRAM pages this func loads as constants
        // (tbpConstantsLoaded ∩ KNOWN_DC2_TBP_LABELS), captured before the
        // Rule 78 noise gate clears tbpConstantsLoaded.
        Set<Long> vramKnownPagesHit = new LinkedHashSet<>();
        // Rule 166: writesFrameReg + a known texture/CLUT page const → in-place RTT.
        boolean isRttTarget = false;
        // Rule 167: writesZbufReg + a known FRAME/texture page const → Z aliases live VRAM (G45).
        boolean zbufVramAliasRisk = false;
        // Rule 169: matrix-inverse helper that depends on the vf0.w==1 HW constant (G40).
        boolean isVf0DependentInverse = false;
        // Rule 170: backward-branch wait on an audio/stream completion signal (F63/F64).
        boolean isAudioCompletionGate = false;
        Set<String> audioGateSignals = new LinkedHashSet<>();
        // Rule 171: sceMc*/libmc save-data callee.
        boolean isMemcardIo = false;
        Set<String> memcardCallees = new LinkedHashSet<>();
        // Rule 173: writes an interlace/field GS privileged reg (SMODE/PMODE/CSR/SYNCV).
        boolean writesPresentationFieldState = false;
        Set<String> presentationRegs = new LinkedHashSet<>();
        // Rule 174: DISPFB writer that signals the double-buffer/present flip.
        boolean isDisplayBufferFlip = false;
        // Rule 175: TEXFLUSH / CLUT-page cache op.
        boolean isClutCacheInvalidator = false;
        // Rule 176: derived frame-hot optimisation candidate.
        boolean isPerfHotFramePath = false;

        // ===== v13 fields (DC2 G53-G82 title-3D retrospective + general PS2 hazards) =====
        // Rule 178: `lw $rX,<global>; beqz $rX; <stores>` guarded-config block (G58/G81).
        boolean isConditionalInitOnGlobal = false;
        Set<String> guardGlobals = new LinkedHashSet<>();   // gp-rel label or abs-hex of the guard
        int conditionalInitSlots = 0;                        // stores inside the guarded block
        // Rule 179: render-mode (copy vs transform) selector writer (G75-G80).
        boolean isRenderModeSelector = false;
        // Rule 180: per-vertex directional-light / N·L term (G82).
        boolean isVertexLightingTerm = false;
        Set<String> lightingSources = new LinkedHashSet<>();
        // Rule 181: terminal `jr $rX` through a loaded vtable slot (G59 recompiler tail-call bug).
        boolean isVtableTailcallThunk = false;
        Set<Long> tailcallVtableSlots = new LinkedHashSet<>();
        // Rule 182: RTT_TARGET that never writes a display-buffer FRAME back (G79 GS-state leak).
        boolean isRttNoRestore = false;
        // Rule 184: uploads VU microcode whose flag pipeline needs verifying (G71).
        boolean isVuFlagPipelineUploader = false;
        // Rule 187: GIF_TAG_INLINE_BUILDER that writes RGBAQ (PACKED spread-layout, G82).
        boolean isPackedRgbaqBuilder = false;
        // Rule 188: large draw/frame func re-enterable at an interior label (G58/G59 resume risk).
        boolean isFrameResumeRisk = false;

        // ===== v15 fields (DC2 G83-G115 retrospective + general PS2 ADC/packer/pacing) =====
        // Rule 190: builds the VIF UNPACK selector qword a VU dispatcher reads to pick the
        // PRIM-class packer (DC2 qword38 in CreateRenderInfoPacket@0x1404d0). G77-G115.
        boolean isPrimClassSelector = false;
        // Rule 192: const-tracked A+D store of GS reg 0x05 (XYZ2 draw-kick) / 0x0D (XYZ3 no-kick).
        boolean writesXyz2Reg = false;     // 0x05 draw-kick vertex
        boolean writesXyz3Reg = false;     // 0x0D no-kick / strip-restart vertex
        boolean isKickModeWriter = false;
        // Rule 191: the VU/EE per-vertex ADC strip-restart "+2048"/0x800 kick add (G65-G115).
        int kickConstAddCount = 0;         // imm 0x800 in an add-family op
        boolean isAdcKickVertexSource = false;
        String  adcSource = null;          // input_driven_xyz3 | uniform_xyz2 | constant_kick
        // Rule 193: per-block texture reload that de-interleaves TEX0 from geometry (G90-G97).
        boolean isTextureReloadInterleave = false;
        // Rule 195: game-step coupled to vsync/frame completion (G103 perf blocker).
        boolean isVsyncCoupledGameStep = false;
        // Rule 196: writes the shared view/projection (camera) matrix, not a world matrix (G98/G99).
        boolean isViewProjectionMatrixWriter = false;
        // Rule 197: ctor that constructs an array of objects whose elements need per-element vtables (G92).
        boolean isObjectArrayCtor = false;
        // Rule 184+: VU/COP2 interpreter-divergence hazards this func touches (manifest).
        Set<String> vuExecHazards = new LinkedHashSet<>();

        // ===== v15.1 fields (PCSX2-grounded cross-check, Rules 199-202) =====
        // Rule 199: VIF unpack decompression-state commands this func programs
        // (STMOD/STMASK/STROW/STCOL/STCYCL/ITOP/BASE/OFFSET). PCSX2 Vif_Unpack.cpp:
        // mode 1 adds MaskRow, mode 2 difference-accumulates, mask nibble 3 skips the
        // VU-mem write. A runtime VIF that ignores mode/mask/row/col/cycle decompresses
        // the vertex/colour stream wrong.
        Set<String> vifUnpackStateCmds = new LinkedHashSet<>();
        boolean isVifUnpackDecompressState = false;
        // Rule 200: writes GS XYOFFSET (A+D 0x18/0x19) — the ±2048 guard-band centre (G88).
        boolean writesXyoffsetReg = false;
        boolean isXyoffsetGuardWriter = false;
        // Rule 201: writes GS TEX1 (A+D 0x14/0x15) — MMAG/MMIN texture filter mode (G8).
        boolean writesTex1Reg = false;
        boolean isTex1FilterWriter = false;

        // ===== v15.2 fields (skill cross-check, Rules 203-206) =====
        // Rule 203: EE MMI (128-bit SIMD integer) ops — a silent-wrong recompiler codegen class.
        boolean usesMmi = false;
        int mmiOpCount = 0;
        Set<String> mmiFamilies = new LinkedHashSet<>();    // e.g. PEXT, PCPY, PMADD, PMFHL, PIPE1
        // Rule 204: CFC2/CTC2 VU0 control-register access (control-reg map codegen class).
        boolean usesCop2ControlReg = false;
        Set<String> cop2ControlRegs = new LinkedHashSet<>();  // resolved index names (STATUS/MAC/CLIP/Q/...)

        // ===== v16 fields (DC2 G116-G137 retrospective + general PS2) =====
        // Rule 207: vertex-emit packer's ADC capability by emitted GS format. G132.
        boolean usesFtoi4 = false;          // has an FTOI4 (COP2) pack op
        boolean hasFogClampShape = false;   // mul+add then clamp to a <=255 ceiling (XYZF2 fog .w)
        boolean isAdcCapablePacker = false;
        String  adcCapability = null;       // xyzf2_fog_no_adc | xyz2_adc_capable | xyz3_norestart | unknown_packer
        // Rule 208: perspective-divide -> FTOI4 site; near-plane must be handled pre-FTOI4. G125-G129.
        boolean computesPerspectiveDivide = false; // DIV/RSQRT feeding a position multiply
        boolean isNearPlaneSite = false;
        String  nearPlaneStrategy = null;   // clip_homog | reject_q_le_0
        // Rule 209/210: data-driven command/config interpreter (SPI cfgXXX, CRunScript VM). G129/G130/F63.
        boolean isSpiConfigCommand = false;
        boolean isCommandInterpreter = false;
        String  interpreterDetail = null;
        // Rule 211: which VU packer family this func feeds / is. G130.
        boolean isPackerFamily = false;
        String  packerFamily = null;        // copy_passthrough | transform | trifan | dispatcher
        // Rule 212: scene/RTT draw needing a private per-frame Z buffer. G125.
        boolean isPrivateDepthScope = false;
        // Rule 214: PACKED word3 fog<->ADC field-alias hazard. G132.
        boolean isPackedFieldAlias = false;

        // ===== v17 fields (G138-G140 retrospective + G141 perf support) =====
        // Rule 222: static frame-cost estimate (instr count + loops + COP2 density
        // + fan-out, weighted by mainloop depth). Ranks the G141 perf suspects.
        long perfStaticCost = 0;
        // Rule 222: tight lq/sq copy loop, no callees -> host memcpy/memset
        // substitution candidate (guest exec is the perf blocker).
        boolean isMemcpyShapedLoop = false;
        // Rule 222: store-free poll spin -> host-yield patch candidate
        // (refines Rules 121/122/143 into an actionable perf roster).
        boolean isIdleSpinYieldSite = false;

        // ===== v17.1 fields (PCSX2 cross-check round 2, Rules 226-232) =====
        // Rule 226/227: exact DMAC-global reg names hit (CTRL/STAT/PCR/SQWC/
        // RBSR/RBOR/STADR) - splits the blanket DMAC_GLOBAL range stamp.
        Set<String> dmacGlobalRegsHit = new LinkedHashSet<>();
        boolean isDmaMfifoUser = false;         // Rule 226
        boolean isDmaStallControlSync = false;  // Rule 227
        // Rule 228: path-arbitration VIF codes this func builds/stores.
        Set<String> vifPathArbCodes = new LinkedHashSet<>();
        boolean isVifPathArbiter = false;
        // Rule 229: GS->EE download signals (BUSDIR / TRXDIR=1 / VIF1 FDR).
        Set<String> gsReadbackSignals = new LinkedHashSet<>();
        boolean isGsReadbackSite = false;
        boolean storesTrxdirLocalToHost = false; // TRXDIR store, const value == 1
        // Rule 230: PRMODECONT (0x1A) / PRMODE (0x1B) A+D writers.
        boolean writesPrmodecontReg = false;
        boolean writesPrmodeReg = false;
        // Rule 231: TEXA (0x3B) / CLAMP_1/2 (0x08/0x09) A+D writers.
        boolean writesTexaReg = false;
        boolean writesClampReg = false;
        // Rule 232: EE time sources - exact timer regs hit + COP0 Count reads.
        Set<String> rcntRegsHit = new LinkedHashSet<>();  // e.g. T0_COUNT, T2_MODE
        boolean readsCop0Count = false;
        boolean isEeTimeSource = false;
        // ===== v18 (Rules 234-240): G142-G172 performance-arc retrospective =====
        // Rule 234: draw-relevant GIF PRIM classes this builder emits (triangle/
        // tristrip/trifan/sprite), from const-tracked PRIM values (attribute-bit gated).
        Set<String> primClassesEmitted = new LinkedHashSet<>();
        boolean isSpriteEmitter = false;             // Rule 234 (emits GS_PRIM_SPRITE)
        boolean spriteGroupOrderDependency = false;  // Rule 235 (compound 2D widget)
        boolean writesAlphaBlendReg = false;         // Rule 240 (A+D ALPHA 0x42)
        boolean writesTestReg = false;               // Rule 240 (A+D TEST_1/2 0x47/0x48)
        boolean presentationFifoBypass = false;      // Rule 238 (present regs bypass GS FIFO)
        String  gpuRasterEligibility = null;         // Rule 240 (opaque_eligible / blend_atest_ineligible)
        // ===== v19 (Rules 243-251): PCSX2 cross-check round 3 (EE interrupt/DMA/SIF/CDVD/cache) =====
        boolean isInterruptHandlerReg = false;       // Rule 243 (INTC/DMAC handler install)
        boolean dmaChcrTie = false;                  // Rule 244 (CHCR STR|TIE = completion IRQ enable)
        boolean vifCodeIBit = false;                 // Rule 245 (VIFcode i-bit bit31)
        boolean isSifTransport = false;              // Rule 246 (SBUS flags + SIF0/1 DMA)
        boolean isCdvdCompletionGate = false;        // Rule 247 (sceCd* completion poll)
        boolean hasCacheOp = false;                  // Rule 248 (cache instruction)
        boolean hasSyncOp = false;                   // Rule 248 (sync.l/sync.p)
        boolean writesTlb = false;                   // Rule 250 (tlbwi/tlbwr/tlbr/tlbp)
        boolean isGsCsrSignalSite = false;           // Rule 249 (GS SIGNAL/FINISH/LABEL + CSR)
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
    // v11 (General v15): step1 entries rescued to RECOMPILE (keyed by address
    // and by name, because step1 entries may carry either). writeUnifiedConfig
    // drops these from the copied stubs/skip arrays; reasons live in the JSON.
    private Map<Long,String> step1RescueByAddr = new LinkedHashMap<>();
    private Map<String,String> step1RescueByName = new LinkedHashMap<>();
    // v11 Rule 151: expected name per step1 address - detects stale /
    // wrong-region input tomls (US vs EU/JP ELF address drift).
    private Map<Long,String> step1NameByAddr = new HashMap<>();
    private int step1NameMismatchCount = 0;
    // v11.2: step1 tokens whose label is a TRUNCATED form of the real ELF
    // symbol (v9-era mangled-name truncation, e.g. `__ct@0xADDR`). Counted
    // separately so they never inflate step1_name_mismatches (which must
    // mean genuine wrong-region/revision drift). The binding is valid (binds
    // by address); the entry proceeds through the normal keep gate.
    private int step1TruncatedNameCount = 0;
    // v11.1 LOCK: entries marked `# LOCKED` (trailing comment) or listed in a
    // `locked = [...]` array. Phase-era hand decisions: keep gate is BYPASSED
    // (a deliberate F-phase stub rarely carries host-boundary evidence - the
    // gate would strip it and silently regress the build). Locked bindings
    // are never rescued by any promote pass.
    private Set<Long> step1LockedAddresses = new HashSet<>();
    private Set<String> step1LockedNames = new HashSet<>();
    private int step1LockedKeptCount = 0;
    // v11.1 RE-ENTRANT: entries that sit under a "# --- Triage Enricher"
    // marker in the input toml were added by a PREVIOUS enricher run, not by
    // the step1 exporter. Same vetting, distinct provenance in the JSON
    // (step1_source = "enricher_prev" vs "exporter").
    private Set<Long> step1EnricherPrevAddresses = new HashSet<>();
    private Set<String> step1EnricherPrevNames = new HashSet<>();
    // v11.1: this ELF's hash, stashed by run() so writeUnifiedConfig can
    // embed `elf_hash = "<md5>"` into [general] - future re-entrant runs
    // then get the Rule 154 identity guard for free.
    private String elfHashForEmit = null;
    // v11 Rule 153: runtime-handler roster. The script first tries the known
    // DC2 layout (D:\ps2r\PS2Recomp\ps2xRuntime), then asks. A STUB binding
    // routes to a runtime handler BY NAME, so a stub whose name is absent
    // from the roster is a silent dead call: flag NO_RUNTIME_HANDLER ->
    // native_impl_needed + review.
    private Set<String> runtimeHandlerNames = new HashSet<>();
    private boolean runtimeRosterLoaded = false;
    private int noHandlerStubCount = 0;
    // v11 Rule 154: elf identity guard. Exporters may embed the hash of the
    // ELF they were generated from: `elf_hash = "<md5>"` in [general].
    private String step1ElfHash = null;
    private String step1ElfHashStatus = "absent";   // absent | match | mismatch
    // v11 Rule 158: overlay / out-of-text binding guards.
    private int overlayVetoCount = 0, outOfTextBindingCount = 0;

    // v11 (General v15.2): advisory lists handed from buildTriageAdvisoryBlock
    // to writeTriageJson so the JSON carries the full [triage_advisory]
    // content as structured {entry, tags} objects (TOML stays
    // executable-only). Keyed by advisory category name; entries are raw
    // "name@0xADDR" optionally followed by " # TAG,TAG".
    private Map<String,List<String>> advisoryJsonLists = new LinkedHashMap<>();
    // patch-instruction candidates: {pcHex, reason, funcToken}.
    private List<String[]> advisoryPatchInstr = new ArrayList<>();

    /** v11 (General v15.5): remove an auto stub/skip binding from a pending
     *  TOML list. Covers both spellings: the ELF symbol and (Rule 160) the
     *  inferred syscall handler name the entry may have been bound under. */
    private void removeAutoBindingEntries(List<String> list, FuncResult r) {
        list.remove(r.name + "@" + hex(r.address));
        if (r.traits != null && r.traits.inferredName != null)
            list.remove(r.traits.inferredName + "@" + hex(r.address));
    }

    /** v11 (General v15): record a step1 stub/skip entry rescued to RECOMPILE. */
    private void noteStep1Rescue(String name, long addr, String reason) {
        step1RescueByAddr.putIfAbsent(addr & 0xFFFFFFFFL, reason);
        if (name != null && !name.isEmpty()) step1RescueByName.putIfAbsent(name, reason);
    }

    /** Post-pass variant: records only when the result is step1-bound, and
     *  mirrors the rescue into the result's provenance fields. */
    private void noteStep1Rescue(FuncResult r, String reason, String pass) {
        if (r == null || !"step1".equals(r.origin)) return;
        if (r.rescueReason == null) r.rescueReason = reason;
        if (r.rescuedBy == null) r.rescuedBy = pass;
        if (!r.tags.contains("STEP1_RESCUED")) r.tags.add("STEP1_RESCUED");
        r.tags.remove("STEP1_BOUND_HOST_BOUNDARY");
        noteStep1Rescue(r.name, r.address, reason);
    }

    /** v11 (General v15): step1 binding kept on HARD host-boundary evidence -
     *  a deliberate boundary later promote passes must not unwind. v15.4:
     *  roster-backed keeps (runtime implements the handler by name) are
     *  equally hard. */
    private boolean isHardBoundStep1(FuncResult r) {
        if (!"step1".equals(r.origin)) return false;
        // v11.1: explicit user lock beats every promote pass.
        if (r.tags.contains("STEP1_LOCKED")) return true;
        if (!r.tags.contains("STEP1_BOUND_HOST_BOUNDARY")) return false;
        if (hasHostBoundaryEvidence(r.traits)) return true;
        return r.tags.contains("STEP1_BOUND_ROSTER_HANDLER");
    }

    /** v11 (General v15) high-confidence keep gate for inherited (step1 /
     *  DAC.toml) stub/skip bindings. Returns null when the binding may stand;
     *  otherwise the rescue reason. Philosophy: RECOMPILE is the safe default
     *  for anything that is pure EE code - recompiled code is always
     *  semantically correct, while a stub is only correct if the runtime
     *  actually services it. A binding therefore survives only with
     *  host-boundary evidence (syscall / SIF RPC / IRX / IPU-MPEG / SDK-named
     *  MMIO poller), and never against the existing trait firewalls. */
    private String step1KeepGateFailure(String name, FuncTraits t, boolean isSkip,
                                        boolean isWhitelisted, boolean forceRecompile) {
        // Rule 159 (order matters, BEFORE the trait firewall): bare syscall
        // trampolines. A <=32-byte, 0-call body with a syscall is just
        // `li $v1,N; syscall; jr $ra` - the trait firewalls that can set
        // forceRecompile on it (PROCESS_TERMINATOR / allocator / ctor names)
        // are name-derived false positives on a 2-instruction body and used
        // to rescue _exit/_Exit with a misleading reason.
        //  - STUB binding + runtime handler by name -> keep (real impl).
        //  - STUB binding + roster loaded but NO handler -> rescue: the stub
        //    would compile to a ps2_stubs::TODO_NAMED placeholder returning
        //    -1, silently losing the kernel call; RECOMPILE is strictly
        //    better because the recompiler turns `syscall` into
        //    runtime->handleSyscall() ($v1/numeric dispatch).
        //  - roster not loaded -> keep legacy behavior (can't judge).
        //  - SKIP bindings fall through to the existing isSkip branch
        //    (explicit user choice, trampoline shape already allowed).
        boolean trampolineShape = t != null && t.hasSyscall
                && t.byteSize <= 32 && t.callOps == 0;
        if (!isSkip && trampolineShape && runtimeRosterLoaded && !hasRuntimeHandler(name))
            return "Rule 159: syscall trampoline with no runtime handler (stub would be a "
                 + "TODO_NAMED placeholder returning -1); RECOMPILE dispatches correctly "
                 + "via runtime handleSyscall()";
        if (!isSkip && trampolineShape)
            return null;
        if (forceRecompile)
            return "trait firewall (vtable-ctor/allocator/large-init/multi-field-ctor/terminator/COP2)";
        // General v15.4: roster-backed keep. The runtime author already
        // implemented a handler with this exact name AND the name is a known
        // SDK boundary family - that is the strongest possible keep signal
        // (handler existence = intent + tested implementation). Checked
        // before the sceVu0 deny: runtimes ship SIMD-native sceVu0 math, and
        // a verified handler beats recompiled COP2-macro translation. The
        // sceGifPk/sceVif1Pk packet families stay excluded - they build
        // EE-RAM packets and the SF3/DC2 benchmarks proved they must
        // recompile even when the runtime carries lookalike impls.
        boolean pkFamily = name.startsWith("sceGifPk") || name.startsWith("sceVif1Pk");
        if (runtimeRosterLoaded && hasRuntimeHandler(name) && !pkFamily && !isSkip
            && (matchesHostBoundaryName(name) || name.startsWith("sceVu0")))
            return null;
        if (name.startsWith("sceVu0"))
            return "sceVu0 VU0-macro math must be recompiled (pure computation)";
        boolean syscallWrapperShape = t != null && t.hasSyscall
                && t.byteSize <= 32 && t.callOps == 0;
        if (isSkip) {
            // SKIP generates an error-returning placeholder: legal only for
            // bare kernel trampolines and unreachable bootstrap code. Pure
            // computation whose loss silently corrupts math and static init
            // (libgcc/__do_global_ctors class) must recompile.
            if (syscallWrapperShape) return null;
            if (t != null && t.hasSyscall && t.xrefToCount == 0) return null; // unreferenced kernel bootstrap
            return "SKIP only for bare syscall trampolines / unreachable bootstrap; "
                 + "pure code must RECOMPILE";
        }
        // Rule 156 (order matters): HARD host-boundary evidence (syscall /
        // SIF RPC / IRX / IPU-MPEG) keeps the stub even when the name looks
        // like a callback/handler or sits inside the (now depth-3) mainloop
        // shield - per-frame SDK wrappers like sceGsSyncV are still
        // deliberate boundaries. Whitelist shapes only rescue functions
        // WITHOUT hard evidence.
        if (hasHostBoundaryEvidence(t)) return null;
        if (isWhitelisted)
            return "whitelisted shape (ctor/dtor/callback/handler name or mainloop shield), "
                 + "no hard host-boundary evidence";
        // Weak tiny-MMIO thunk shape additionally requires an SDK-family name
        // (game-code DMA kick leaves share the shape and must recompile).
        if (matchesHostBoundaryName(name) && hasWeakSdkThunkEvidence(t)) return null;
        return "no host-boundary evidence (no syscall/SIF-RPC/IRX/IPU; pure EE code)";
    }

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
    // v11.3 detector counters (Rules 162-164).
    private int sprDmaStagerCount=0, subwordDmaStrKickCount=0;
    private int vu1DoubleBufferFramerCount=0, stalePtrCacheCtorCount=0;
    // v12 Rules 165-177 counters + top-level collectors
    private int rttTargetCount=0, zbufVramAliasCount=0, vf0DependentInverseCount=0;
    private int audioCompletionGateCount=0, memcardIoCount=0;
    private int presentationFieldStateCount=0, displayBufferFlipCount=0;
    private int clutCacheInvalidatorCount=0, perfHotFramePathCount=0;
    private int frameRegWriterCount=0;
    // Rule 165: VRAM page -> {kind -> list of func names} for overlap pairing.
    private final Map<Long,Map<String,List<String>>> vramPageWriters = new LinkedHashMap<>();
    // Rule 165 output: [pageHex, label, kindA, funcA, kindB, funcB, classification]
    private final List<String[]> vramOverlapPairs = new ArrayList<>();
    // Rule 177: distinct labelled VRAM pages referenced statically.
    private final Set<Long> gsLocalMemPagesReferenced = new LinkedHashSet<>();
    // ===== v13 counters + top-level lists (Rules 178-189) =====
    private int conditionalInitOnGlobalCount=0, renderModeSelectorCount=0;
    private int vertexLightingTermCount=0, vtableTailcallThunkCount=0;
    private int rttNoRestoreCount=0, packedRgbaqBuilderCount=0, frameResumeRiskCount=0;
    private int vuFlagPipelineUploaderCount=0;
    // Rule 179/180/182/184/187/188 top-level rosters: [name, addrHex, detail].
    private final List<String[]> renderModeSelectors = new ArrayList<>();
    private final List<String[]> vertexLightingTerms = new ArrayList<>();
    private final List<String[]> vtableTailcallThunks = new ArrayList<>();
    private final List<String[]> rttNoRestoreFuncs = new ArrayList<>();
    private final List<String[]> packedRgbaqBuilders = new ArrayList<>();
    private final List<String[]> frameResumeRiskFuncs = new ArrayList<>();
    private final List<String[]> vuFlagPipelineUploaders = new ArrayList<>();
    // Rule 186 INIT_ORDER_DEPENDENCY: global token -> writer/reader func-name lists.
    private final Map<String,List<String>> initGlobalWriters = new LinkedHashMap<>();
    private final Map<String,List<String>> initGlobalSinitWriters = new LinkedHashMap<>();
    private final Map<String,List<String>> initGlobalReaders = new LinkedHashMap<>();
    // Rule 186 output: [globalToken, readerFunc, writerFunc, writerKind].
    private final List<String[]> initOrderHazards = new ArrayList<>();
    // ===== v15 counters + top-level rosters (Rules 190-198) =====
    private int primClassSelectorCount=0, adcKickVertexSourceCount=0, kickModeWriterCount=0;
    private int textureReloadInterleaveCount=0, vsyncCoupledGameStepCount=0;
    private int viewProjectionWriterCount=0, objectArrayCtorCount=0;
    // [name, addrHex, detail] triads (reuse emitV13Roster).
    private final List<String[]> primClassSelectors      = new ArrayList<>();
    private final List<String[]> adcKickSources          = new ArrayList<>();
    private final List<String[]> kickModeWriters         = new ArrayList<>();
    private final List<String[]> textureReloadInterleave = new ArrayList<>();
    private final List<String[]> framePacingDrivers      = new ArrayList<>();
    private final List<String[]> viewProjectionWriters   = new ArrayList<>();
    private final List<String[]> objectArrayCtors        = new ArrayList<>();
    // Rule 194 ALLOCATOR_FAMILY_COHERENCE: [name, addrHex, disposition].
    private final List<String[]> allocatorFamily = new ArrayList<>();
    private boolean allocatorFamilySplit = false;
    // Rule 184+ VU_EXEC_HAZARD_MANIFEST: [name, addrHex, hazard1|hazard2|...].
    private final List<String[]> vuExecHazardManifest = new ArrayList<>();
    // ===== v15.1 counters + rosters (PCSX2-grounded, Rules 199-202) =====
    private int vifUnpackDecompressCount=0, xyoffsetGuardWriterCount=0, tex1FilterWriterCount=0;
    private final List<String[]> vifUnpackDecompressState = new ArrayList<>();
    private final List<String[]> xyoffsetGuardWriters     = new ArrayList<>();
    private final List<String[]> tex1FilterWriters        = new ArrayList<>();
    // ===== v15.2 counters + rosters (skill cross-check, Rules 203-205) =====
    private int mmiCodegenRiskCount=0, cop2ControlRegCount=0;
    private final List<String[]> mmiCodegenRisk      = new ArrayList<>();
    private final List<String[]> cop2ControlRegAccess = new ArrayList<>();
    // Rule 205 UNFUNDED_TEXTURE_PAGE: [pageHex, label, samplerFunc].
    private final List<String[]> unfundedTexturePages = new ArrayList<>();
    // ===== v16 counters + rosters (Rules 207-216, G116-G137 retrospective) =====
    private int adcCapablePackerCount=0, nearPlaneSiteCount=0, spiConfigCommandCount=0;
    private int commandInterpreterCount=0, packerFamilyCount=0, privateDepthScopeCount=0;
    private int packedFieldAliasCount=0;
    // [name, addrHex, detail] triads (reuse emitV13Roster).
    private final List<String[]> adcCapablePackers   = new ArrayList<>(); // Rule 207
    private final List<String[]> nearPlaneSites       = new ArrayList<>(); // Rule 208
    private final List<String[]> spiConfigCommands    = new ArrayList<>(); // Rule 209
    private final List<String[]> commandInterpreters  = new ArrayList<>(); // Rule 210
    private final List<String[]> packerFamilies       = new ArrayList<>(); // Rule 211
    private final List<String[]> privateDepthScopes   = new ArrayList<>(); // Rule 212
    private final List<String[]> packedFieldAliases   = new ArrayList<>(); // Rule 214
    // ===== v17 counters + rosters (Rules 217-225, G138-G140 retrospective) =====
    private int memcpyShapedLoopCount=0, idleSpinYieldCount=0;
    private final List<String[]> memcpyShapedLoops  = new ArrayList<>(); // Rule 222
    private final List<String[]> idleSpinYieldSites = new ArrayList<>(); // Rule 222
    // Rule 217-219: extracted + analyzed VU microcode programs.
    private final List<VuProgram> vuMicrocodePrograms = new ArrayList<>();
    // Rule 220: runner-vs-canon lower-opcode map check [idxHex, canon, runnerToken, status].
    private final List<String[]> vuOpcodeMapCheck = new ArrayList<>();
    private int vuOpcodeMapMismatchCount = 0;
    // Rule 220: census opcode names (len>=3) absent from the runner VU source.
    private final List<String> vuOpcodeCoverageGap = new ArrayList<>();
    // Rule 221: [env, file, line, classification, pcLiterals, staleSuspect]
    private final List<String[]> runtimeLeverRegistry = new ArrayList<>();
    private int staleBandaidSuspectCount = 0;
    // Rule 224: GIFtag-shaped data records grouped by value.
    private final List<GiftagTemplate> giftagTemplates = new ArrayList<>();
    // ===== v17.1 counters + rosters (Rules 226-232, PCSX2 cross-check 2) =====
    private int dmaMfifoUserCount=0, dmaStallControlCount=0, vifPathArbCount=0;
    private int gsReadbackSiteCount=0, prmodeAttrWriterCount=0, texaClampWriterCount=0;
    private int eeTimeSourceCount=0;
    private final List<String[]> dmaMfifoUsers        = new ArrayList<>(); // Rule 226
    private final List<String[]> dmaStallControlSync  = new ArrayList<>(); // Rule 227
    private final List<String[]> vifPathArbitration   = new ArrayList<>(); // Rule 228
    private final List<String[]> gsReadbackSites      = new ArrayList<>(); // Rule 229
    private final List<String[]> prmodeAttrWriters    = new ArrayList<>(); // Rule 230
    private final List<String[]> texaClampWriters     = new ArrayList<>(); // Rule 231
    private final List<String[]> eeTimeSources        = new ArrayList<>(); // Rule 232
    // ===== v18 counters + rosters (Rules 234-240, G142-G172 perf-arc retrospective) =====
    private int spriteEmitterCount=0, spriteGroupOrderCount=0, presentationFifoBypassCount=0;
    private int gpuRasterEligibleCount=0, gpuRasterIneligibleCount=0;
    private final List<String[]> primClassEmitters      = new ArrayList<>(); // Rule 234
    private final List<String[]> spriteCompoundWidgets   = new ArrayList<>(); // Rule 235
    private final List<String[]> recompileCoverageGaps   = new ArrayList<>(); // Rule 236
    private final List<String[]> streamedTexturePages    = new ArrayList<>(); // Rule 237
    private final List<String[]> presentationFifoBypass  = new ArrayList<>(); // Rule 238
    private final List<String[]> gpuRasterEligibility    = new ArrayList<>(); // Rule 240
    // Rule 234/235 name rosters (sprite draw path + compound-widget shapes).
    private static final String[] SPRITE_EMITTER_NAMES = {
        "drawSprite","DrawSprite","DrawDivSprite","DrawDivSprite4","PrimQuad","SetSpriteEnv",
        "PutSprite","mgC3DSprite","3DSprite","Sprite2D","DrawFont","PutFont","DrawMesWin","meswin" };
    private static final String[] COMPOUND_WIDGET_NAMES = {
        "Window","Wnd","Box","Prompt","MesWin","Message","Dialog","Panel","Cursor","Frame",
        "Menu","Balloon","Caption","Icon","Gauge" };
    // ===== v19 counters + rosters (Rules 243-250, PCSX2 cross-check round 3) =====
    private int interruptHandlerCount=0, dmaTagIrqCount=0, vifInterruptCount=0;
    private int sifTransportCount=0, cdvdGateCount=0, cacheOpCount=0, tlbWriterCount=0, gsCsrCount=0;
    private final List<String[]> interruptHandlers   = new ArrayList<>(); // Rule 243
    private final List<String[]> dmaTagIrqSites       = new ArrayList<>(); // Rule 244
    private final List<String[]> vifInterruptSites    = new ArrayList<>(); // Rule 245
    private final List<String[]> sifTransportSites    = new ArrayList<>(); // Rule 246
    private final List<String[]> cdvdCompletionGates  = new ArrayList<>(); // Rule 247
    private final List<String[]> cacheOps             = new ArrayList<>(); // Rule 248
    private final List<String[]> tlbWriters           = new ArrayList<>(); // Rule 250
    private final List<String[]> gsCsrSites           = new ArrayList<>(); // Rule 249
    // Rule 243: EE interrupt-handler-registration SDK (libkernel INTC/DMAC handler install).
    private static final String[] INTC_DMAC_HANDLER_NAMES = {
        "AddIntcHandler","_AddIntcHandler","EnableIntc","DisableIntc","iEnableIntc","iDisableIntc",
        "AddDmacHandler","_AddDmacHandler","EnableDmac","DisableDmac","iEnableDmac","iDisableDmac",
        "RemoveIntcHandler","RemoveDmacHandler","_intc_","IntcHandler","DmacHandler" };
    // Rule 247: sceCd* read/seek completion family (level-load stream gate, analog to Rule 170).
    private static final String[] CDVD_COMPLETION_NAMES = {
        "sceCdSync","sceCdDiskReady","sceCdGetError","sceCdStatus","sceCdRead","sceCdSeek",
        "sceCdGetToc","sceCdReadClock","sceCdSearchFile","sceCdComplete" };
    // Rule 153/220/221: runtime checkout root actually used for the roster scrape.
    private File runtimeRootDir = null;

    /** Rule 217-219: one extracted VU microcode program + its static hazard scan. */
    static class VuProgram {
        long elfAddr;              // payload start of first chunk
        int  vuDestQw;             // first chunk's MPG imm (64-bit units)
        int  sizePairs;            // total instruction pairs across chunks
        int  chunkCount;
        String uploaderFunc = "";  // best-effort Rule 51/68 const-load link
        Map<String,Integer> census = new LinkedHashMap<>();
        // flag consumers: MAC/STATUS + CLIP producer->consumer distances.
        int flagConsumers=0, flagConsumersUnder4=0, flagConsumersExactly4=0;
        Map<Integer,Integer> flagDistHistogram = new LinkedHashMap<>(); // dist(cap 9+)->count
        List<String[]> flagUnder4Examples = new ArrayList<>();  // [pcHex, op, dist]
        // same-pair upper->lower VF hazards (the G139 class).
        List<String[]> samePairHazards = new ArrayList<>();     // [pcHex, upper, lower, vf]
        int samePairHazardCount=0;
        // Q/P latency events (the G87 class).
        int qProducers=0, qConsumers=0, qMinGap=Integer.MAX_VALUE, waitqCount=0;
        int pProducers=0, pConsumers=0, pMinGap=Integer.MAX_VALUE, waitpCount=0;
        // Rule 219: dispatch/coverage.
        List<Long> xgkickPcs = new ArrayList<>();
        List<Long> balSubroutines = new ArrayList<>();          // BAL targets (byte pcs)
        List<Long> dispatcherBranchPcs = new ArrayList<>();     // branches with pc < 0x800
        int branchTargetCount=0, jrIndirectCount=0, clipwCount=0, fcgetCount=0;
        int reachablePairs=0;
        List<long[]> unreachedSpans = new ArrayList<>();        // [startPc, endPc] byte pcs
    }

    /** Rule 224: one distinct GIFtag-shaped 16-byte record found in data. */
    static class GiftagTemplate {
        long w0, w1, w2, w3;
        int count=0;
        List<Long> exampleAddrs = new ArrayList<>();
        int nloop, eop, pre, prim, flg, nreg;
        String primClass;
    }
    // v11.3: run mode. false => FIRST run (full pipeline: generate functions.csv
    // + base config + assembly/decompiled/flowchart + unified TOML + JSON).
    // true => INCREMENTAL (emit the new JSON, and MODIFY the existing live
    // config_auto_recomp.toml in place only when the content actually changes;
    // preserves # LOCKED and manual edits via the re-entrant + LOCK machinery).
    private boolean incrementalMode=false;
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
    // v11 (General v15.5 Rule 161) counter
    private int dynamicCodeLoaderCount    = 0;
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
    // v11 (DC2 Rule 151 extension): known addresses whose real ELF symbol
    // disagrees with the curated US-ELF name map (wrong-region detector).
    private int dc2KnownNameMismatches    = 0;
    private int discoveredRpcSidCount     = 0;
    // v10 counters (DC2 F47-F52 retrospective)
    private int cop2PartialDestFuncCount  = 0;   // Rule 140
    private int staticInitializerFuncCount= 0;   // Rule 141
    private int uncalledStaticInitCount   = 0;   // Rule 141
    private int memoryAllocatorCount      = 0;   // Rule 142
    private int guestLockHogCount         = 0;   // Rule 143
    private int eabiArgT0Count            = 0;   // Rule 144
    private int psmct16ClutUploaderCount  = 0;   // Rule 145
    // v10.1 counters
    private int computedJumpSiteCount     = 0;   // Rule 146 (distinct switch pcs)
    private int computedJumpUnresolvedCount = 0; // Rule 146 (sites with 0 targets)
    private int cop2SpecialOpFuncCount    = 0;   // Rule 147
    private int fpuNonIeeeCount           = 0;   // Rule 148
    private int overlayLoaderCount        = 0;   // Rule 150
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

        // v11.3: run mode. FIRST run = full pipeline (generate functions.csv +
        // base config via ExportPS2Functions, then enrich). INCREMENTAL = re-emit
        // the JSON and MODIFY the existing live config in place, only on delta.
        // If the ELF is unchanged since the last run, choose NO; the Rule 154
        // elf_hash guard double-checks and warns on a real mismatch.
        boolean firstRun = askYesNo("DC2 TriageEnricher - run mode",
            "Is this the FIRST run for this ELF?\n\n"
          + "YES = full pipeline: generate functions.csv + base config (via "
          + "ExportPS2Functions) + assembly/decompiled/flowchart + unified TOML + JSON.\n\n"
          + "NO = incremental: emit the new triage_map.json and MODIFY the existing "
          + "config_auto_recomp.toml IN PLACE, only where needed (preserves # LOCKED "
          + "and manual edits).");
        incrementalMode = !firstRun;

        File csvFile, configToml, outputDir;
        if (firstRun) {
            // Step-1 export is delegated to ExportPS2Functions so the recompiler's
            // ghidra_output CSV + executable-label records stay authoritative (no
            // duplicated classifier). Falls back to manual select if the script is
            // not on Ghidra's script path.
            println("[RUN-MODE] FIRST run - generating functions.csv + base config via ExportPS2Functions.");
            try { runScript("ExportPS2Functions.java"); }
            catch (Exception ex) {
                printerr("[RUN-MODE] ExportPS2Functions not run automatically ("
                    + ex.getMessage() + "); run it yourself, then select its outputs.");
            }
            csvFile = askFile("Select the functions.csv (from ExportPS2Functions)","Open");
            if (csvFile==null||!csvFile.exists()){printerr("No CSV. Aborting.");return;}
            configToml = askFile("Select the base config.toml (from ExportPS2Functions)","Open");
            if (configToml==null||!configToml.exists()){printerr("No config.toml. Aborting.");return;}
            outputDir = csvFile.getParentFile();
        } else {
            // Incremental: point at the LIVE project config to modify in place.
            configToml = askFile("Select the LIVE config_auto_recomp.toml to modify in place","Open");
            if (configToml==null||!configToml.exists()){printerr("No config. Aborting.");return;}
            outputDir = configToml.getParentFile();
            csvFile = new File(outputDir, "functions.csv"); // directory anchor only; never parsed
            println("[RUN-MODE] INCREMENTAL - "+configToml.getName()
                +" will be modified in place only if the content changes.");
        }
        File unifiedToml = incrementalMode ? configToml
                                           : new File(outputDir,"config_auto_recomp.toml");
        // v14: the monolithic triage_map.json is replaced by index/functions_index.json
        // (full machine-readable map) + per-function Markdown docs in functions/.
        File indexDir    = new File(outputDir,"index");
        File functionsDir = new File(outputDir,"functions");
        indexDir.mkdirs(); functionsDir.mkdirs();
        if(!indexDir.isDirectory() || !functionsDir.isDirectory())
            println("[WARN] could not pre-create index/ or functions/ under "
                + outputDir.getAbsolutePath() + " - utf8Writer will retry per file.");
        File triageJson  = new File(indexDir,"functions_index.json");

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

        // v11 Rule 153 (DC2-tuned): ps2xRuntime handler roster. Try the
        // known DC2 working-tree location first so the common case needs no
        // dialog; fall back to askDirectory (Cancel to skip).
        try {
            // v17 Rule 223: the runtime lives at D:\ps2r\dc2\PS2Recomp\ps2xRuntime
            // in the current working layout; the old D:\ps2r\PS2Recomp path kept
            // as a fallback for older checkouts.
            File dc2Runtime = new File("D:\\ps2r\\dc2\\PS2Recomp\\ps2xRuntime");
            if (!dc2Runtime.isDirectory())
                dc2Runtime = new File("D:\\ps2r\\PS2Recomp\\ps2xRuntime");
            if (dc2Runtime.isDirectory()) {
                println("[RUNTIME-ROSTER] Using known DC2 runtime checkout: "
                        + dc2Runtime.getAbsolutePath());
                loadRuntimeHandlerRoster(dc2Runtime);
            } else {
                File rtDir = askDirectory(
                    "Select ps2xRuntime root for handler-roster check (Cancel to skip)","Open");
                if (rtDir!=null && rtDir.isDirectory()) {
                    loadRuntimeHandlerRoster(rtDir);
                } else {
                    println("[RUNTIME-ROSTER] Skipped - no runtime folder selected. "+
                            "Stub-vs-handler check disabled.");
                }
            }
        } catch (Exception ex) {
            println("[RUNTIME-ROSTER] Skipped: "+ex.getMessage());
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
            int addrHits = 0, nameHits = 0, nameMismatches = 0;
            ghidra.program.model.address.AddressFactory af = currentProgram.getAddressFactory();
            for(Object[] row : KNOWN_DC2_FUNCTION_ADDRESSES) {
                long want = ((Number)row[0]).longValue() & 0xFFFFFFFFL;
                String wantName = (String)row[1];
                Function f = funcManager.getFunctionAt(af.getDefaultAddressSpace().getAddress(want));
                if(f != null) {
                    addrHits++;
                    // v11 (DC2-specific Rule 151 extension): the curated
                    // address map is ground truth for the US (SCUS-97316)
                    // ELF. A real symbol at a known address that does NOT
                    // match the expected name means this Ghidra project was
                    // built from a different revision/region ELF - the same
                    // failure mode Rule 154 catches via elf_hash, detectable
                    // here even when DAC.toml carries no hash.
                    String got = f.getName();
                    if(!got.startsWith("FUN_") && !got.startsWith("sub_")
                       && !got.startsWith("LAB_") && !got.startsWith("thunk_")
                       && !got.equals(wantName)
                       && !got.startsWith(wantName)) {
                        nameMismatches++;
                        if(nameMismatches <= 8)
                            println("[DC2-KNOWN] !! 0x"+Long.toHexString(want)
                                +" expected '"+wantName+"' but ELF symbol is '"+got+"'");
                    }
                } else {
                    SymbolIterator si = currentProgram.getSymbolTable().getSymbols(wantName);
                    if(si.hasNext()) nameHits++;
                }
            }
            dc2KnownAddressMatched = addrHits + nameHits;
            dc2KnownNameMismatches = nameMismatches;
            println(String.format("[DC2-KNOWN] address_hits=%d name_hits=%d of %d entries.",
                addrHits, nameHits, KNOWN_DC2_FUNCTION_ADDRESSES.length));
            if(nameMismatches > 0)
                println("[!!] DC2-KNOWN: "+nameMismatches+" known addresses carry a DIFFERENT real "
                    +"symbol - this project may be a wrong-region/revision ELF (expect US SCUS-97316).");
        }
        String elfHash = computeElfHash();
        // v11.1: stash for writeUnifiedConfig so the output [general] carries
        // elf_hash for the next (re-entrant) run's Rule 154 check.
        elfHashForEmit = elfHash;

        // v11 Rule 154: ELF identity guard. If the step1 toml (DAC.toml)
        // recorded the hash of the ELF it was generated from, compare it with
        // this program's hash. A mismatch means every address-based binding
        // in the input may point at the wrong function (different revision /
        // region ELF) - Rule 151 then catches the per-entry damage, but the
        // global warning surfaces the root cause.
        if (step1ElfHash != null && elfHash != null && !elfHash.isEmpty()) {
            step1ElfHashStatus = step1ElfHash.equalsIgnoreCase(elfHash) ? "match" : "mismatch";
            if ("mismatch".equals(step1ElfHashStatus)) {
                println("[!!] Rule 154: step1 toml elf_hash="+step1ElfHash
                    +" but this ELF hashes to "+elfHash
                    +" - input toml was built for a DIFFERENT ELF. All address bindings suspect.");
            } else {
                println("[STEP1] Rule 154: elf_hash matches this ELF ("+elfHash+").");
            }
        }

        println("[SCAN] Analyzing...");

        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);
        BasicBlockModel blockModel = new BasicBlockModel(currentProgram);

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

                // v14: capture listing text per function for the per-function
                // Markdown docs (functions/<addr>_<name>.md), no longer streamed
                // to monolithic assembly.txt / decompiled.txt / flowchart.txt.
                StringBuilder sbAsm = new StringBuilder();
                InstructionIterator instructions = currentProgram.getListing().getInstructions(func.getBody(),true);
                while (instructions.hasNext()) {
                    Instruction instr = instructions.next();
                    sbAsm.append(instr.getAddress()).append("  ").append(instr).append('\n');
                }
                String decompText;
                DecompileResults decompResult = decomp.decompileFunction(func,30,monitor);
                if (decompResult!=null&&decompResult.decompileCompleted())
                    decompText = decompResult.getDecompiledFunction().getC();
                else
                    decompText = "[decompile failed]";
                StringBuilder sbFlow = new StringBuilder();
                try {
                    CodeBlockIterator blocks = blockModel.getCodeBlocksContaining(func.getBody(),monitor);
                    while (blocks.hasNext()) {
                        CodeBlock block = blocks.next();
                        sbFlow.append("BLOCK: ").append(block.getFirstStartAddress()).append('\n');
                        CodeBlockReferenceIterator dests = block.getDestinations(monitor);
                        while (dests.hasNext()) {
                            CodeBlockReference ref = dests.next();
                            sbFlow.append("  --> ").append(ref.getDestinationAddress())
                                  .append(" [").append(ref.getFlowType().getName()).append("]\n");
                        }
                    }
                } catch (Exception e) {
                    sbFlow.append("[flowchart failed: ").append(e.getMessage()).append("]\n");
                }
                String capturedAsm = sbAsm.toString();
                String capturedFlow = sbFlow.toString();
                String capturedDecomp = decompText;

                // Rule 9 (v11 REWRITE, ported from General v15): step1
                // (DAC.toml) classified functions are no longer trusted
                // blindly and skipped. FF1 benchmark: a name-policy exporter
                // had stubbed memcpy/strcpy/sprintf, whole game-code
                // subsystems (Scene* name-collided with the "sce" SDK
                // prefix), sceVu0 VU0 math, and SKIPPED libm/libgcc/newlib
                // internals. The old `continue` meant such functions were
                // never analyzed, never appeared in the triage JSON, and were
                // re-emitted verbatim into the unified TOML. Now: analyze
                // every function; inherit the step1 disposition only if it
                // survives the high-confidence keep gate
                // (step1KeepGateFailure); otherwise rescue to RECOMPILE and
                // drop the entry from the unified TOML with the reason in
                // triage_map.json.
                boolean step1Stub = step1StubAddresses.contains(offset)
                        || step1StubNames.contains(funcName);
                boolean step1Skip = !step1Stub && (step1SkipAddresses.contains(offset)
                        || step1SkipNames.contains(funcName));

                // Rule 18 (v11): override-bound functions are also analyzed
                // and included in the JSON (origin="override") so the triage
                // map is complete; they never enter stub/skip/advisory lists.
                boolean overrideBound = gameOverrideAddresses.contains(offset);

                // v11 Rule 158: overlay / out-of-text guards. Overlay blocks
                // reuse the same address range for different code blobs - any
                // address-keyed binding there is unsafe by construction.
                // (DC2 US is a single flat ELF, so this should stay 0 - a
                // non-zero count is itself a red flag about the project.)
                boolean inOverlayBlock = false;
                try {
                    MemoryBlock mb = currentProgram.getMemory().getBlock(addr);
                    inOverlayBlock = mb != null && mb.isOverlay();
                } catch (Exception ignored) {}
                boolean outOfTextBinding = !inOverlayBlock && textEnd > 0
                        && (offset < textStart || offset > textEnd)
                        && (step1Stub || step1Skip);

                if (!step1Stub && !step1Skip && !overrideBound) uncategorized++;

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
                                       || traits.isBitbltbufT4hhUploader
                                       // v10: never auto-stub allocators (F50.1/F50.2),
                                       // static-init vtable installers (F50.4/F50.7), or
                                       // COP2 partial-dest transforms (F51.8 codegen risk).
                                       || traits.isMemoryAllocator
                                       || traits.staticInitInstallsVtable
                                       || traits.cop2DestMaskVerify
                                       // v10.1: COP2 special-op funcs share the COP2
                                       // codegen path — keep real bodies for review.
                                       || !traits.cop2SpecialOps.isEmpty()
                                       // v11 Rule 161: runtime code linker/loader.
                                       || traits.isDynamicCodeLoader
                                       // v13 Rule 178: a global-guarded init block must keep its
                                       // real body (stubbing skips the configuration, G58/G81).
                                       || traits.isConditionalInitOnGlobal
                                       // v13 Rule 181: vtable tail-call thunk - stubbing breaks
                                       // the recompiler's inherited-virtual dispatch (G59).
                                       || traits.isVtableTailcallThunk
                                       // v15 Rules 190/191/196/197: the PRIM-class selector,
                                       // the per-vertex ADC/strip-restart geometry builder, the
                                       // shared view/projection matrix writer, and the object-
                                       // array ctor all carry render/init-critical state that a
                                       // nop-stub silently destroys (G92/G98/G115).
                                       || traits.isPrimClassSelector
                                       || traits.isAdcKickVertexSource
                                       || traits.isViewProjectionMatrixWriter
                                       || traits.isObjectArrayCtor
                                       // v16 Rules 207/208/211: vertex-emit packers (ADC
                                       // capability), perspective-divide near-plane sites, and
                                       // the copy/transform/trifan packer family are all render
                                       // path - a nop-stub kills the title cavern (G116-G137).
                                       || traits.isAdcCapablePacker
                                       || traits.isNearPlaneSite
                                       || traits.isPackerFamily;

                // --- Disposition decision ---
                // v11 (ported from General v13 SF3-benchmark corrections - all
                // three legacy rules here produced false safe-stubs on real
                // game code):
                //  - refsIopModuleString alone stubbed whole system-init
                //    functions (IOP module loads + pad init + DMA-interrupt-
                //    handler install in one body). Only "pure loader" shapes
                //    (small, few callees, no MMIO/handler side effects) are
                //    still stub candidates; mixed init functions stay
                //    RECOMPILE.
                //  - hasSyscall||hasCOP0 skipped game interrupt handlers and
                //    critical sections: di/ei/sync/mfc0 appear all over EE
                //    game code. COP0 presence is not kernel-internal
                //    evidence; the recompiler patches COP0 ops anyway
                //    (patch_cop0). SKIP now requires the bare
                //    syscall-trampoline shape only.
                //  - hasVcallms stubbed VU0-microcode dispatchers - exactly
                //    the functions that must run real logic. Now routed to
                //    must-implement instead.
                boolean pureIrxLoaderShape = traits.refsIopModuleString &&
                        traits.byteSize <= 200 && traits.calleeCount <= 4 &&
                        !traits.accessesMMIO && !traits.writesIntcMask &&
                        traits.dmaKickChannels.isEmpty();
                boolean syscallWrapperShape = traits.hasSyscall &&
                        traits.byteSize <= 32 && traits.callOps == 0;
                String disposition = "RECOMPILE";
                String origin = "auto";
                String step1Disposition = null;
                String rescueReason = null;
                boolean step1KeptHostBoundary = false;
                boolean step1NameMismatchFlag = false;
                boolean step1TruncatedFlag = false;
                boolean step1LockedFlag = false;
                if (overrideBound) {
                    // Already hand-bound in dc2_game_override.cpp - record for
                    // the JSON map, make no triage decision.
                    origin = "override";
                    disposition = "OVERRIDE";
                } else if (step1Stub || step1Skip) {
                    origin = "step1";
                    step1Disposition = step1Stub ? "STUB" : "SKIP";
                    // v11.1 LOCK: phase-era hand decision - keep gate
                    // BYPASSED. A deliberate F-phase stub rarely carries
                    // host-boundary evidence; the gate would strip it and
                    // silently regress the working build. Locked beats
                    // everything except the overlay veto (address reuse is
                    // unsafe no matter what the user wrote).
                    boolean step1Locked = step1LockedAddresses.contains(offset)
                            || step1LockedNames.contains(funcName);
                    if (step1Locked && !inOverlayBlock) {
                        disposition = step1Disposition;
                        step1LockedKeptCount++;
                        step1LockedFlag = true;
                        // Rule 151 mismatch still surfaces for review (a
                        // locked binding on a wrong-region address is worth
                        // a human look), but does not unbind. v11.2: a
                        // truncated mangled label is not drift - skip it.
                        String expectedL = step1NameByAddr.get(offset);
                        if (expectedL != null && !expectedL.isEmpty()
                                && !funcName.equals(expectedL)
                                && !funcName.startsWith("FUN_") && !funcName.startsWith("sub_")
                                && !funcName.startsWith("LAB_") && !funcName.startsWith("thunk_")) {
                            if (isTruncatedNameOf(expectedL, funcName)) { step1TruncatedNameCount++; step1TruncatedFlag = true; }
                            else { step1NameMismatchCount++; step1NameMismatchFlag = true; }
                        }
                        if (outOfTextBinding) outOfTextBindingCount++;
                    } else {
                    // v11 Rule 151: name/address mismatch veto. If the step1
                    // entry recorded a different name for this address than
                    // the ELF symbol, the input toml is stale or built for a
                    // different region's ELF (US vs EU/JP address drift) -
                    // binding a handler to the wrong function is the worst
                    // failure mode, so force RECOMPILE + review. Only fires
                    // when the Ghidra name is real (not FUN_/sub_ defaults).
                    String expected = step1NameByAddr.get(offset);
                    boolean nameDiffers = expected != null && !expected.isEmpty()
                            && !funcName.equals(expected)
                            && !funcName.startsWith("FUN_") && !funcName.startsWith("sub_")
                            && !funcName.startsWith("LAB_") && !funcName.startsWith("thunk_");
                    // v11.2: a truncated mangled label (`__ct`, `SetStatus`)
                    // is NOT region drift - the address binds correctly. Such
                    // entries skip the Rule 151 veto and proceed through the
                    // normal keep gate, decided on real trait evidence (ctors
                    // hit the ctor firewall, etc.). Only a genuinely different
                    // symbol is a mismatch.
                    boolean truncatedName = nameDiffers && isTruncatedNameOf(expected, funcName);
                    boolean nameMismatch = nameDiffers && !truncatedName;
                    String gateFail;
                    if (inOverlayBlock) {
                        // v11 Rule 158: hard veto - overlay address reuse.
                        gateFail = "Rule 158: address sits in an overlay memory block - "
                                 + "address-keyed bindings are unsafe (overlays reuse addresses)";
                        overlayVetoCount++;
                    } else if (nameMismatch) {
                        gateFail = "Rule 151: step1 entry expects '"+expected
                                 +"' at this address but ELF symbol is '"+funcName
                                 +"' (stale or wrong-region input toml?)";
                    } else {
                        gateFail = step1KeepGateFailure(funcName, traits, step1Skip,
                                                        isWhitelisted, forceRecompile);
                    }
                    if (nameMismatch) { step1NameMismatchCount++; step1NameMismatchFlag = true; }
                    if (truncatedName) { step1TruncatedNameCount++; step1TruncatedFlag = true; }
                    if (outOfTextBinding) outOfTextBindingCount++;
                    if (gateFail == null) {
                        disposition = step1Disposition;   // binding survives the gate
                        step1KeptHostBoundary = true;
                    } else {
                        disposition = "RECOMPILE";        // rescued
                        rescueReason = gateFail;
                        noteStep1Rescue(funcName, offset, gateFail);
                    }
                    // (rescuedBy recorded on the FuncResult below)
                    }   // end v11.1 locked/vetted split
                } else if (syscallWrapperShape && !inOverlayBlock) {
                    // v11 Rule 159: bare syscall trampolines, decided BEFORE
                    // the whitelist/trait-firewall guard. The old order let
                    // the name-substring whitelist ("handler"/"callback") and
                    // the PROCESS_TERMINATOR firewall block classification of
                    // AddIntcHandler/_Exit-style kernel trampolines, and the
                    // old action (auto-SKIP) compiled into a TODO_NAMED
                    // placeholder returning -1, silently losing live kernel
                    // calls. New policy:
                    //  - runtime implements the handler by name AND the name
                    //    is a known boundary family -> STUB (real impl wins);
                    //  - completely unreferenced -> SKIP (dead bootstrap);
                    //  - otherwise leave RECOMPILE: the recompiler translates
                    //    `syscall` into runtime->handleSyscall() which
                    //    dispatches by $v1/immediate, so recompiled
                    //    trampolines are always semantically correct.
                    String trampolineBindName = null;
                    if (runtimeRosterLoaded && hasRuntimeHandler(funcName)
                            && matchesHostBoundaryName(funcName)) {
                        trampolineBindName = funcName;
                    } else if (runtimeRosterLoaded && traits.inferredName != null
                            && hasRuntimeHandler(traits.inferredName)) {
                        // v11 Rule 160: stripped-name recovery. The syscall
                        // immediate decoded from the body (`li $v1,N;
                        // syscall`) is ground truth; when EE_SYSCALL_NAMES[N]
                        // resolves to a handler the runtime implements, bind
                        // the ADDRESS to that handler via the recompiler's
                        // documented "Handler@0xADDR" stub selector - works
                        // even when the ELF symbol is FUN_xxxxxxxx or a
                        // wrapper alias.
                        trampolineBindName = traits.inferredName;
                    }
                    if (trampolineBindName != null) {
                        disposition="STUB";
                        newStubs.add(trampolineBindName+"@"+hex(offset));
                        radarNewStubs++;
                    } else if (traits.xrefToCount == 0) {
                        disposition="SKIP";
                        newSkips.add(funcName+"@"+hex(offset));
                        radarNewSkips++;
                    }
                    // else: RECOMPILE (default) - SYSCALL_TRAMPOLINE tag below.
                } else if (!isWhitelisted && !forceRecompile && !inOverlayBlock) {
                    // v11 Rule 158: never auto-stub/skip inside overlay blocks.
                    if (isRadarFirewalled(func, traits)) {
                        disposition="STUB";
                        newStubs.add(funcName+"@"+hex(offset));
                        radarNewStubs++;
                    } else if (pureIrxLoaderShape) {
                        disposition="STUB";
                        newStubs.add(funcName+"@"+hex(offset));
                        radarNewStubs++;
                    } else if (traits.hasVcallms) {
                        // VU0 microcode kick - never a stub candidate.
                        traits.mustBeImplemented = true;
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
                // ===== v10 tags (DC2 F47-F52) =====
                // Rule 140: COP2 partial-dest transform — verify generated
                // dest-mask lane order (F51.8 recompiler codegen bug).
                if (traits.cop2DestMaskVerify) {
                    tags.add("COP2_DESTMASK_VERIFY");
                    cop2PartialDestFuncCount++;
                }
                // Rule 141: static-init install manifest.
                if (traits.isStaticInitializer) {
                    staticInitializerFuncCount++;
                    if (traits.staticInitInstallsVtable) tags.add("STATIC_INIT_VTABLE_INSTALLER");
                    if (traits.isUncalledStaticInit) {
                        tags.add("UNCALLED_STATIC_INIT");
                        uncalledStaticInitCount++;
                    }
                }
                // Rule 142: memory allocator — never auto-stub.
                if (traits.isMemoryAllocator) {
                    tags.add("MEMORY_ALLOCATOR_NEVER_STUB");
                    memoryAllocatorCount++;
                }
                // Rule 143: guest-execution-lock hog candidate.
                if (traits.isGuestLockHogCandidate) {
                    tags.add("GUEST_LOCK_HOG_CANDIDATE");
                    guestLockHogCount++;
                }
                // Rule 144: reads EABI 5th arg ($t0).
                if (traits.readsEabiArgT0) {
                    tags.add("EABI_ARG_T0");
                    eabiArgT0Count++;
                }
                // Rule 145: PSMCT16 map-CLUT uploader.
                if (traits.isPsmct16ClutUploader) {
                    tags.add("MAP_CLUT_PSMCT16_UPLOADER");
                    psmct16ClutUploaderCount++;
                }
                // ===== v10.1 tags (PCSX2- + skill-grounded) =====
                // Rule 146: computed-jump sites; flag the ones with no resolved target.
                if (!traits.computedJumpSwitchPcs.isEmpty()) {
                    computedJumpSiteCount += traits.computedJumpSwitchPcs.size();
                    Set<Long> resolvedPcs = new HashSet<>();
                    for (long[] e : traits.computedJumpTargets) resolvedPcs.add(e[0]);
                    int unresolved = 0;
                    for (Long pc : traits.computedJumpSwitchPcs)
                        if (!resolvedPcs.contains(pc)) unresolved++;
                    if (unresolved > 0) {
                        tags.add("COMPUTED_JUMP_UNRESOLVED");
                        computedJumpUnresolvedCount += unresolved;
                    }
                }
                // Rule 147: COP2 special-op / latency review.
                if (!traits.cop2SpecialOps.isEmpty()) {
                    tags.add("COP2_SPECIAL_OPS_REVIEW");
                    cop2SpecialOpFuncCount++;
                }
                // Rule 148: EE FPU non-IEEE sensitivity.
                if (traits.usesCop1 && (traits.usesFpuDivSqrt || traits.writesFpuControl)) {
                    tags.add("FPU_NONIEEE_SENSITIVE");
                    fpuNonIeeeCount++;
                }
                // Rule 150: EE code-overlay loader.
                if (traits.isOverlayLoader) {
                    tags.add("OVERLAY_LOADER");
                    overlayLoaderCount++;
                }
                if (traits.usesCop1) tags.add("FPU_HEAVY");
                if (traits.usesSPR)  tags.add("USES_SPR");
                // ===== v11.3 Rules 162-164 (DC2 F52-G26 retrospective) =====
                // Rule 162 SPR_DMA_STAGER / SUBWORD_DMA_STR_KICK — the G26
                // delivery-bug class (scratchpad-staged VU1 model packet copied
                // via fromSPR ch8, kicked by a sub-word CHCR store).
                if (traits.programsSprDma)
                    {tags.add("SPR_DMA_STAGER");sprDmaStagerCount++;}
                if (traits.subwordDmaStrKick)
                    {tags.add("SUBWORD_DMA_STR_KICK");subwordDmaStrKickCount++;}
                // Rule 163 VU1_DOUBLE_BUFFER_FRAMER — builds BASE+OFFSET VIFcodes
                // (TOPS double-buffer framing; the missing context in G23/G24).
                if (traits.vifOpcodesBuilt.contains("BASE") &&
                    traits.vifOpcodesBuilt.contains("OFFSET")) {
                    traits.isVu1DoubleBufferFramer = true;
                    tags.add("VU1_DOUBLE_BUFFER_FRAMER");vu1DoubleBufferFramerCount++;
                }
                // Rule 164 STALE_PTR_CACHE_CTOR — a ctor that caches a derived
                // global pointer (Get*Ptr/Man/Data/Mgr) into this+K (G12/G13/
                // F50.4). Caches 0/stale if it runs before the source is funded.
                if (traits.isCtor && traits.ctorWritesA0Slot &&
                    traits.stalePtrCacheGetter == null) {
                    for (String cn : traits.calleeNames) {
                        if (cn == null) continue;
                        if (cn.startsWith("Get") && (cn.contains("Ptr") ||
                            cn.contains("Man") || cn.contains("Data") || cn.contains("Mgr"))) {
                            traits.isStalePtrCacheCtor = true;
                            traits.stalePtrCacheGetter = cn;
                            break;
                        }
                    }
                }
                if (traits.isStalePtrCacheCtor)
                    {tags.add("STALE_PTR_CACHE_CTOR");stalePtrCacheCtorCount++;}
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
                // v11 (General v14): SIF RPC packet headers are built with the
                // same 16-byte-stride qword stores as a GIF tag (SF3:
                // sceOpen/sceSync landed in force_recompile this way, then
                // corroborated PSMT4HH false positives). If the function talks
                // to SIF RPC and shows zero GIF/VIF/DMA evidence, demote the
                // trait to sifPacketBuilder so every downstream render
                // heuristic (PSMT4HH gate, Rule 56 scoring, classification)
                // ignores it. Must run BEFORE the PSMT4HH gate below.
                if (traits.gifTagInlineBuilder && traits.callsSifRpc &&
                    !traits.writesGifFifo && !traits.writesVif1Fifo &&
                    !traits.writesVif0Fifo && !traits.accessesMMIO &&
                    traits.dmaKickChannels.isEmpty() && !traits.dmaChcrStartKick &&
                    !traits.dmaSourceChainTagBuilder && !traits.bitbltbufMacroSequence &&
                    !traits.path3Initiator && traits.gifTagRegsFields.isEmpty()) {
                    traits.gifTagInlineBuilder = false;
                    traits.sifPacketBuilder = true;
                }
                // v11 (General v13): PSM constants (0x2C/0x24/0x1B) are tiny
                // integers that appear constantly as struct sizes / loop
                // counts / error codes. Bare matches tagged ~90% of SF3's
                // force list. Require GS-side corroboration before tagging.
                boolean psm4hhInGsContext = traits.loadsPsm4hhConstant &&
                    (traits.writesTex0Reg || traits.writesBitbltbufReg ||
                     traits.bitbltbufMacroSequence || traits.gifTagInlineBuilder ||
                     traits.isBitbltbufT4hhUploader);
                if (psm4hhInGsContext) {tags.add("PSMT4HH_REFERENCE");psm4hhCount++;}
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
                // v11 (General v13): lui-derived VIF opcode matches collide
                // with ordinary global-address materialization (lui 0x60-0x7F
                // == UNPACK is any global above 0x00600000). Require
                // independent VIF/DMA/GIF evidence in the same function
                // before believing the opcode match.
                boolean vifBuilderCorroborated = !traits.vifOpcodesBuilt.isEmpty() &&
                    (traits.accessesVif1MMIO || traits.writesVif1Fifo ||
                     traits.writesVif0Fifo || traits.writesGifFifo ||
                     !traits.dmaKickChannels.isEmpty() || traits.dmaChcrStartKick ||
                     !traits.storedVifOpcodes.isEmpty() || !traits.storedDmaTagIds.isEmpty() ||
                     traits.dmaSourceChainTagBuilder || traits.gifTagInlineBuilder ||
                     traits.accessesVifCtrl || traits.accessesMMIO);
                if (vifBuilderCorroborated) {
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
                // v11 (General v14): informational tag for the demoted case.
                if (traits.sifPacketBuilder) {
                    tags.add("SIF_PACKET_BUILDER");
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
                // v11 Rule 159: tag any bare-trampoline shape (not just the
                // ones whose immediate decoded). RECOMPILE-d trampolines route
                // through runtime handleSyscall(); the tag lets the report
                // tool group the kernel-boundary surface.
                if (syscallWrapperShape || traits.inferredSyscallImm > 0) {
                    tags.add("SYSCALL_TRAMPOLINE"); syscallTrampolineCount++;
                }
                // v11 Rule 161: dynamic-code loader. For DC2 (single flat ELF,
                // no overlays) this should stay 0 - a non-zero count means the
                // recompiled ELF alone does NOT cover the game.
                if (traits.isDynamicCodeLoader) {
                    tags.add("DYNAMIC_CODE_LOADER");
                    dynamicCodeLoaderCount++;
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
                    // v11 (General v13): use the corroborated forms so SIF
                    // packet builders / loop-count constants don't inflate
                    // the bullseye set.
                    traits.touchesGifP3Reg || psm4hhInGsContext ||
                    (vifBuilderCorroborated && traits.vifOpcodesBuilt.contains("MPG")) ||
                    traits.bitbltbufMacroSequence || traits.dmaChcrStartKick ||
                    traits.dmaSourceChainTagBuilder || traits.isRenderFrameEntry ||
                    "BLOCKER".equals(traits.dc2KnownCriticality)) {
                    traits.isTopPriorityFix = true;
                    if(!tags.contains("TOP_PRIORITY_FIX")) {
                        tags.add("TOP_PRIORITY_FIX");
                        topPriorityFixCount++;
                    }
                }

                // v11 (General v15): step1/override provenance tags.
                if ("step1".equals(origin)) {
                    if (step1LockedFlag) {
                        // v11.1: explicit user lock - never rescued by any
                        // later promote pass (isHardBoundStep1 honors this).
                        tags.add("STEP1_LOCKED");
                    } else if (rescueReason != null) tags.add("STEP1_RESCUED");
                    else if (step1KeptHostBoundary) {
                        tags.add("STEP1_BOUND_HOST_BOUNDARY");
                        // roster-backed keep is hard-bound too.
                        if (runtimeRosterLoaded && hasRuntimeHandler(funcName))
                            tags.add("STEP1_BOUND_ROSTER_HANDLER");
                    }
                    if (step1NameMismatchFlag) tags.add("STEP1_NAME_MISMATCH");
                    if (step1TruncatedFlag) tags.add("STEP1_TRUNCATED_NAME");
                    if (outOfTextBinding) tags.add("OUT_OF_TEXT_BINDING");
                }
                if (inOverlayBlock) tags.add("OVERLAY_REGION");
                if ("override".equals(origin)) tags.add("OVERRIDE_BOUND");

                FuncResult r = new FuncResult();
                r.address=offset; r.name=funcName; r.category=category;
                r.disposition=disposition; r.traits=traits; r.tags=tags;
                r.origin=origin; r.step1Disposition=step1Disposition;
                r.rescueReason=rescueReason;
                r.asmText=capturedAsm; r.decompText=capturedDecomp; r.flowText=capturedFlow;
                if(rescueReason!=null) r.rescuedBy="step1_keep_gate";
                // v11.1: provenance detail - did this binding come from the
                // step1 exporter or from a previous enricher run's additions?
                if ("step1".equals(origin)) {
                    boolean prev = step1EnricherPrevAddresses.contains(offset)
                            || step1EnricherPrevNames.contains(funcName);
                    r.step1Source = prev ? "enricher_prev" : "exporter";
                }
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

            println(String.format("  v10 tags: COP2_PARTIAL_DEST=%d STATIC_INIT=%d UNCALLED_SINIT=%d ALLOCATOR=%d LOCK_HOG=%d EABI_T0=%d PSMCT16_CLUT=%d",
                cop2PartialDestFuncCount, staticInitializerFuncCount, uncalledStaticInitCount,
                memoryAllocatorCount, guestLockHogCount, eabiArgT0Count, psmct16ClutUploaderCount));

            println(String.format("  v10.1 tags: COMPUTED_JUMP=%d UNRESOLVED=%d COP2_SPECIAL=%d FPU_NONIEE=%d OVERLAY=%d",
                computedJumpSiteCount, computedJumpUnresolvedCount, cop2SpecialOpFuncCount,
                fpuNonIeeeCount, overlayLoaderCount));

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

            // v11 Rule 161b (General v15.5): LAYERED dynamic-code loader
            // detection. Real engines split the idiom across functions
            // (load -> FileLoad [file evidence] + link_and_exec ->
            // CacheFlush -> FlushCache [icache flush]), so the same-body
            // Rule 161 never fires. Post-pass over the call graph:
            //   flushReach = functions named FlushCache/iFlushCache, or with
            //     a direct callee prefix-matching FlushCache/iFlushCache/
            //     CacheFlush (catches mangled C++ wrappers), propagated UP
            //     the caller chain <= 3 hops;
            //   evidence   = callsFileOpen/refsArchiveStrings on the function
            //     itself, a direct callee, or a direct caller.
            // Intersection = suspected runtime code loader: tagged, counted,
            // and promoted out of STUB (never out of a hard step1 binding).
            // For DC2 this should find nothing - a hit is a project-level
            // red flag.
            // v11.2 PRECISION GATE: only run the layered search when the ELF
            // actually contains at least one overlay/exec callee anywhere
            // (overlayLoaderCount>0). If nothing in the binary can execute
            // loaded bytes (DC2: overlay_loaders=0), runtime code loading is
            // impossible and the flush+file intersection is pure asset-loader
            // noise (DC2 streams from DATA.DAT/HD2 and flushes per DMA).
            if (overlayLoaderCount > 0) {
                Set<Long> flushReach = new HashSet<>();
                for (FuncResult r : results) {
                    if (r.traits == null) continue;
                    boolean hit = r.name.startsWith("FlushCache")
                               || r.name.startsWith("iFlushCache");
                    if (!hit) for (String cn : r.traits.calleeNames) {
                        if (cn.startsWith("FlushCache") || cn.startsWith("iFlushCache")
                            || cn.startsWith("CacheFlush")) { hit = true; break; }
                    }
                    if (hit) flushReach.add(r.address & 0xFFFFFFFFL);
                }
                Set<Long> frontier = new HashSet<>(flushReach);
                for (int hop = 0; hop < 3 && !frontier.isEmpty(); hop++) {
                    Set<Long> next = new HashSet<>();
                    for (Long a : frontier) {
                        FuncResult r = resultsByAddr.get(a);
                        if (r == null || r.traits == null) continue;
                        for (long[] c : r.traits.callers) {
                            long ca = c[0] & 0xFFFFFFFFL;
                            if (flushReach.add(ca)) next.add(ca);
                        }
                    }
                    frontier = next;
                }
                for (FuncResult r : results) {
                    FuncTraits t = r.traits;
                    if (t == null || t.isDynamicCodeLoader) continue;
                    if (!flushReach.contains(r.address & 0xFFFFFFFFL)) continue;
                    boolean evidence = t.callsFileOpen || t.refsArchiveStrings;
                    if (!evidence) for (long[] site : t.jalSites) {
                        FuncResult cal = resultsByAddr.get(site[1] & 0xFFFFFFFFL);
                        if (cal != null && cal.traits != null &&
                            (cal.traits.callsFileOpen || cal.traits.refsArchiveStrings)) {
                            evidence = true; break;
                        }
                    }
                    if (!evidence) for (long[] c : t.callers) {
                        FuncResult cr = resultsByAddr.get(c[0] & 0xFFFFFFFFL);
                        if (cr != null && cr.traits != null &&
                            (cr.traits.callsFileOpen || cr.traits.refsArchiveStrings)) {
                            evidence = true; break;
                        }
                    }
                    if (!evidence) continue;
                    t.isDynamicCodeLoader = true;
                    if (!r.tags.contains("DYNAMIC_CODE_LOADER")) {
                        r.tags.add("DYNAMIC_CODE_LOADER");
                        dynamicCodeLoaderCount++;
                    }
                    if ("STUB".equals(r.disposition) && !isHardBoundStep1(r)) {
                        r.disposition = "RECOMPILE";
                        removeAutoBindingEntries(newStubs, r);
                        noteStep1Rescue(r, "dynamic-code loader (Rule 161b) must never be stubbed",
                                        "dynamic_code_loader_firewall");
                    }
                }
                if (dynamicCodeLoaderCount > 0)
                    println("  v11 Rule 161b: " + dynamicCodeLoaderCount
                        + " suspected dynamic-code loader(s) - this ELF likely loads EE code at runtime.");
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
                // v11 (General v15): step1 bindings kept on HARD host-boundary
                // evidence (syscall/SIF-RPC/IRX/IPU) are deliberate boundaries
                // - render-chain proximity alone must not unwind them.
                if("STUB".equals(r.disposition) && !isHardBoundStep1(r)) {
                    r.disposition = "RECOMPILE";
                    removeAutoBindingEntries(newStubs, r);
                    noteStep1Rescue(r, "drawing_chain_depth<=6 render firewall",
                                    "drawing_chain_firewall");
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
            // v12 Rules 165-177: RTT/Z VRAM-alias, audio/memcard/present hazards,
            // perf-hot ranking. Runs after BFS depths + DC2-known tagging are final
            // and BEFORE the Rule 78 noise gate clears tbpConstantsLoaded.
            applyV12Rules(results);
            // v13 Rules 178-188: render-mode/lighting/tailcall/RTT-leak + init-order.
            applyV13Rules(results);
            // v15 Rules 190-198: ADC/PRIM-class packer, allocator-family coherence,
            // frame-pacing, view-matrix, object-array ctor, VU-exec hazard manifest.
            applyV15Rules(results);
            // v16 Rules 207-216: packer ADC-capability, near-plane source, SPI/command
            // dispatch, packer families, private depth scope, packed fog/ADC alias.
            applyV16Rules(results);
            // v17 Rules 217-225 (G138-G140 retrospective + G141 perf support):
            // static VU-microcode extraction + hazard scan (the analysis layer that
            // would have front-loaded G87/G138/G139/G140), GIFtag template scan,
            // runtime lever registry, canon-vs-runner VU opcode diff, perf ranking.
            applyV17Rules(results);
            // v18 Rules 234-242 (G142-G172 perf-arc retrospective): sprite-emitter prim-class
            // census, sprite-group order dependency, recompile target coverage gap (the
            // level-load "function not found" class), streamed-texture cache suitability,
            // presentation-register FIFO bypass, GPU-raster eligibility census.
            applyV18Rules(results);
            // v19 Rules 243-251 (PCSX2 cross-check round 3): EE interrupt-handler dispatch,
            // DMAtag-IRQ+TIE completion, VIFcode i-bit, SIF RPC transport, CDVD read-completion
            // gate (2nd level-load failure mode), EE cache-coherency ops, GS CSR handshake, TLB.
            applyV19Rules(results);
            scanVuMicrocodePrograms(results);
            scanGiftagTemplates();
            scanRuntimeLeverRegistry();
            checkVuOpcodeConformance();
            println(String.format("  v9 post: GIF_INLINE=%d BITBLTBUF_MACRO=%d CHCR_KICK=%d DMA_SRC_CHAIN=%d MMIO_RECOVERED=%d SYSCALL_TR=%d SYNC_WAIT=%d INF_SPIN=%d INF_FAIL=%d IRX=%d REBOOT=%d RENDER_ENTRY=%d STRUCT_INIT=%d DISPATCH_TGT=%d TABLE_CALL=%d HOST_WAIT=%d DC2_KNOWN=%d DISC_SIDS=%d FPT_TABLES=%d MODULES=%d PREFIXES=%d",
                gifTagInlineBuilderCount, bitbltbufMacroSeqCount, dmaChcrStartKickCount,
                dmaSourceChainBuilderCount, compositeMmioRecoveryCount, syscallTrampolineCount,
                backwardSyncWaitCount, infiniteSpinLoopCount, infiniteFailLoopCount,
                irxLoaderCount, iopRebootHandlerCount, renderFrameEntryCount,
                structInitializerCount, dispatchTableTargetCount, tableDispatchCallCount,
                dc2HostWaitCandidateCount, dc2KnownAddressMatched, discoveredRpcSidCount,
                functionPointerTables.size(), moduleClusters.size(), namePrefixModules.size()));

            // ===== v11 binding-consistency firewall (General v13) =====
            // Runs after ALL tag/trait post-passes so it sees the final
            // evidence. A function the enricher itself flags as render-
            // critical / must-implement / init-chain / callback-target must
            // never stay in the BINDING stubs/skip arrays - those are consumed
            // by the recompiler, while force_recompile is only advisory.
            // SF3 benchmark failures this pass prevents:
            //  - system-init stubbed (init_chain_depth already computed and
            //    ignored) -> game cannot boot;
            //  - DMA-interrupt / vsync callbacks skipped while their
            //    addresses are taken as callback arguments -> no rendering;
            //  - same function simultaneously in stubs AND force_recompile.
            {
                int rescued = 0;
                for(FuncResult r : results) {
                    if(r.traits == null) continue;
                    if(!"STUB".equals(r.disposition) && !"SKIP".equals(r.disposition)) continue;
                    FuncTraits t = r.traits;
                    // Address-taken probe: any non-call/non-jump reference to
                    // the entry point (function-pointer table slot, lui/addiu
                    // materialization as a handler argument) means something
                    // installs this function as a callback.
                    boolean addressTaken = false;
                    try {
                        ghidra.program.model.symbol.ReferenceIterator ri =
                            currentProgram.getReferenceManager()
                                .getReferencesTo(toAddr(r.address & 0xFFFFFFFFL));
                        while(ri.hasNext()) {
                            ghidra.program.model.symbol.Reference ref = ri.next();
                            ghidra.program.model.symbol.RefType rt = ref.getReferenceType();
                            if(!rt.isCall() && !rt.isJump()) { addressTaken = true; break; }
                        }
                    } catch(Exception e) { /* probe is best-effort */ }
                    boolean pureIrxLoaderShape = t.refsIopModuleString &&
                            t.byteSize <= 200 && t.calleeCount <= 4 &&
                            !t.accessesMMIO && !t.writesIntcMask &&
                            t.dmaKickChannels.isEmpty();
                    // v14: bare syscall trampolines (<=32 bytes, no calls) sit
                    // on every init chain by construction - the kernel handles
                    // them, so init-chain membership alone must not rescue
                    // them. Address-taken / dispatch / render evidence still
                    // rescues.
                    boolean syscallWrapperShape = t.hasSyscall &&
                            t.byteSize <= 32 && t.callOps == 0;
                    // v15: SIF RPC gateways sit on init chains by construction
                    // (every subsystem binds its RPC channels during boot) -
                    // same logic as the syscall-trampoline exclusion.
                    boolean rpcGatewayShape = t.callsSifRpc ||
                            t.detectedRpcSid != 0 || !t.discoveredRpcSids.isEmpty();
                    boolean onInitChain = t.initChainDepth >= 0 && t.initChainDepth <= 6;
                    boolean renderOrMustImpl = t.isTopPriorityFix || t.mustBeImplemented ||
                            t.isRenderFrameEntry || t.isSceVu0Helper ||
                            t.isBitbltbufT4hhUploader || t.isCtorMultiFieldInit ||
                            t.isSceGifPkFamily || t.path3Initiator ||
                            t.writesGifFifo || t.writesVif1Fifo || t.hasVcallms ||
                            // v12 Rule 166/169: in-place RTT writers and vf0-
                            // dependent matrix inverses are render-critical
                            // (G37/G44/G40); never leave them stubbed.
                            t.isRttTarget || t.isVf0DependentInverse ||
                            // v13 Rules 179/180/182: render-mode selectors, per-vertex
                            // lighting terms, and RTT-no-restore writers are all
                            // render-critical (G75-G82) - never leave them stubbed.
                            t.isRenderModeSelector || t.isVertexLightingTerm ||
                            t.isRttNoRestore || t.isConditionalInitOnGlobal ||
                            t.isVtableTailcallThunk ||
                            // v11 Rule 155: GS-dump corroboration - this
                            // function's TBP/PSM signature was observed in an
                            // actual PCSX2 capture; stubbing it provably
                            // kills uploads that happen on real hardware.
                            r.tags.contains("RUNTIME_CONFIRMED");
                    boolean dispatchTarget = r.tags.contains("DISPATCH_TABLE_TARGET");
                    // v15.4: step1 bindings kept on hard host-boundary
                    // evidence are deliberate; address-taken no longer unwinds
                    // them either - PS2Recomp dispatch is address-keyed, so an
                    // indirect call through a taken pointer still lands on the
                    // bound runtime handler (16-byte kernel wrappers take
                    // their addresses legitimately, SetSyscall-style).
                    // Surface the conflict for review, keep the binding.
                    if(isHardBoundStep1(r)) {
                        if(addressTaken && !r.tags.contains("ADDRESS_TAKEN_CALLBACK"))
                            r.tags.add("ADDRESS_TAKEN_CALLBACK");
                        continue;
                    }
                    if(addressTaken || dispatchTarget || renderOrMustImpl ||
                       (onInitChain && !pureIrxLoaderShape && !syscallWrapperShape
                                    && !rpcGatewayShape)) {
                        removeAutoBindingEntries(newStubs, r);
                        removeAutoBindingEntries(newSkips, r);
                        r.disposition = "RECOMPILE";
                        if(!r.tags.contains("BINDING_FIREWALL_RESCUED"))
                            r.tags.add("BINDING_FIREWALL_RESCUED");
                        if(addressTaken && !r.tags.contains("ADDRESS_TAKEN_CALLBACK"))
                            r.tags.add("ADDRESS_TAKEN_CALLBACK");
                        noteStep1Rescue(r, "v13 binding firewall (" +
                            (addressTaken ? "address-taken callback" :
                             dispatchTarget ? "dispatch-table target" :
                             renderOrMustImpl ? "render-critical/must-implement" :
                             "init-chain member") + ")", "v13_binding_firewall");
                        rescued++;
                    }
                }
                println("  v11 binding firewall: "+rescued+" stub/skip entries rescued to RECOMPILE "+
                        "(address-taken / dispatch-target / init-chain / render-critical).");
            }

            // v11: step1 vetting summary.
            {
                int s1kept=0, s1rescued=0, ovr=0;
                for(FuncResult r : results) {
                    if("step1".equals(r.origin)) {
                        if(r.rescueReason!=null) s1rescued++; else s1kept++;
                    } else if("override".equals(r.origin)) ovr++;
                }
                println("  v11 step1 vetting: "+s1kept+" inherited bindings kept (host-boundary evidence), "
                        +s1rescued+" rescued to RECOMPILE, "+ovr
                        +" override-bound - all now analyzed and included in the JSON.");
                if(step1LockedKeptCount>0)
                    println("  v11.1 lock: "+step1LockedKeptCount
                            +" locked entries kept verbatim (keep gate bypassed).");
                if(step1NameMismatchCount>0)
                    println("  v11 Rule 151: "+step1NameMismatchCount
                            +" step1 name/address mismatches (stale or wrong-region input?) - forced RECOMPILE + review.");
                if(step1TruncatedNameCount>0)
                    println("  v11.2 Rule 151: "+step1TruncatedNameCount
                            +" truncated mangled labels (e.g. __ct@addr) - NOT drift, address binds correctly, sent through normal gate.");
            }

            // v11 Rule 153: handler-roster cross-check. Runs after every
            // promote pass so it sees FINAL stub dispositions. A stub routes
            // to a runtime handler BY NAME - no handler in the roster means
            // the call dies silently at runtime. We do not unbind (the stub
            // may be a planned implementation); we surface it loudly:
            // NO_RUNTIME_HANDLER tag -> native_impl_needed + review.
            if (runtimeRosterLoaded) {
                for (FuncResult r : results) {
                    if (!"STUB".equals(r.disposition)) continue;
                    if (hasRuntimeHandler(r.name)) continue;
                    // Rule 160: trampolines bound by inferred syscall name
                    // route to that handler, not the ELF symbol.
                    if (r.traits != null && r.traits.inferredName != null
                        && hasRuntimeHandler(r.traits.inferredName)) continue;
                    if (!r.tags.contains("NO_RUNTIME_HANDLER")) {
                        r.tags.add("NO_RUNTIME_HANDLER");
                        noHandlerStubCount++;
                    }
                }
                println("  v11 Rule 153: roster="+runtimeHandlerNames.size()
                        +" handlers; "+noHandlerStubCount
                        +" bound stubs have NO matching runtime handler (-> native_impl_needed + review).");
            }
            if (overlayVetoCount>0 || outOfTextBindingCount>0)
                println("  v11 Rule 158: overlay vetoes="+overlayVetoCount
                        +", out-of-text bindings flagged="+outOfTextBindingCount+".");

            if (incrementalMode) {
                // Modify the live config IN PLACE, only if the executable content
                // (selectors/sections, ignoring comments + # TAG annotations)
                // actually changed. Preserves the file untouched when there is no
                // need; backs up the prior on a real delta.
                File tmp = new File(outputDir, "config_auto_recomp.toml.new");
                writeUnifiedConfig(tmp,configToml,newStubs,newSkips,results,resultsByAddr);
                if (unifiedToml.exists() && configBodyEquals(tmp, unifiedToml)) {
                    tmp.delete();
                    println("[INCREMENTAL] "+unifiedToml.getName()
                        +" unchanged - left in place (no modification needed).");
                } else {
                    File bak = new File(outputDir, "config_auto_recomp.prev.toml");
                    if (bak.exists()) bak.delete();
                    if (unifiedToml.exists()) unifiedToml.renameTo(bak);
                    if (!tmp.renameTo(unifiedToml)) {
                        java.nio.file.Files.copy(tmp.toPath(), unifiedToml.toPath(),
                            java.nio.file.StandardCopyOption.REPLACE_EXISTING);
                        tmp.delete();
                    }
                    println("[INCREMENTAL] "+unifiedToml.getName()
                        +" MODIFIED (delta applied); prior saved as config_auto_recomp.prev.toml.");
                }
            } else {
                writeUnifiedConfig(unifiedToml,configToml,newStubs,newSkips,results,resultsByAddr);
            }
            // v8 Rule 109: diff against prior index/functions_index.json if present.
            // Renames the old file to functions_index.prev.json before overwriting.
            File priorJson = new File(indexDir, "functions_index.json");
            Map<Long,String> priorCats = null;
            if (priorJson.exists()) {
                try {
                    priorCats = loadPriorTriageMapCats(priorJson);
                    File backup = new File(indexDir, "functions_index.prev.json");
                    if (backup.exists()) backup.delete();
                    priorJson.renameTo(backup);
                    println(String.format("[DIFF] Backed up prior functions_index.json (%d funcs).",
                        priorCats != null ? priorCats.size() : 0));
                } catch (Exception ex) {
                    println("[DIFF] Failed to load prior map: "+ex.getMessage());
                    priorCats = null;
                }
            }
            this.priorTriageMapCats = priorCats;
            writeTriageJson(triageJson,results,elfHash,gpValue,totalFuncs,uncategorized);
            // v14: per-function Markdown docs + the focused lookup indexes.
            writeFunctionDocs(functionsDir, results, elfHash, gpValue);
            writeLookupIndexes(indexDir, results, elfHash, gpValue);

            // v11.3: auto-generate the post-regen COP2 dest-mask patch from this
            // run's COP2 model. CANNOT run inside this Ghidra pass (it rewrites
            // recomp/*.cpp that only exist AFTER ps2_recomp.exe regenerates), so
            // it ships next to the triage output with RECOMP pre-filled and is
            // listed in post_regen_steps.md - so the F51.8 fix can't be forgotten.
            emitCop2FixScript(outputDir, results);

            println("\n[SUCCESS] Unified TOML : "+unifiedToml.getAbsolutePath());
            println("[SUCCESS] Function docs: functions/<addr>_<name>.md ("+results.size()+" files)");
            println("[SUCCESS] Indexes      : index/{functions_index,calls_index,xrefs_index,tags_index,globals_index}.json");
            println("[SUCCESS] Post-regen   : fix_cop2_destmask.py + post_regen_steps.md");
            println("All files saved to: "+outputDir.getAbsolutePath());

        } finally {
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
        BufferedReader reader = utf8Reader(f);
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
    // =========================================================
    // v11 Rule 153 (General v15.3): RUNTIME-HANDLER ROSTER SCRAPE
    // Walks a ps2xRuntime checkout and collects every handler name the
    // runtime actually implements. Sources of names:
    //   (a) `void Name(R5900Context& ...)`            - classic handler def
    //   (b) `void Name(uint8_t* rdram, R5900Context*` - raw wrapper def
    //   (c) bindAddressHandler(..., "Name")            - name-routed binding
    //   (d) ps2_stubs::Name                            - stub-namespace refs
    // NEVER descends into runner/ or build dirs (30k generated files).
    // =========================================================
    private void loadRuntimeHandlerRoster(File root) {
        // v17 Rules 220/221 reuse the same checkout for the VU-opcode
        // conformance diff and the env-lever registry scrape.
        runtimeRootDir = root;
        // Prefer src/ when present - handlers live in src/lib per the
        // PS2Recomp layout; fall back to the given dir.
        File start = new File(root, "src");
        if (!start.isDirectory()) start = root;
        java.util.regex.Pattern pCtxRef  = java.util.regex.Pattern.compile(
            "void\\s+([A-Za-z_]\\w*)\\s*\\(\\s*R5900Context\\s*[&*]");
        java.util.regex.Pattern pRawWrap = java.util.regex.Pattern.compile(
            "void\\s+([A-Za-z_]\\w*)\\s*\\(\\s*uint8_t\\s*\\*\\s*\\w+\\s*,\\s*R5900Context");
        java.util.regex.Pattern pBindStr = java.util.regex.Pattern.compile(
            "bindAddressHandler\\s*\\([^;]*?\"([A-Za-z_]\\w*)\"");
        java.util.regex.Pattern pStubsNs = java.util.regex.Pattern.compile(
            "ps2_stubs::([A-Za-z_]\\w*)");
        Deque<File> stack = new ArrayDeque<>();
        stack.push(start);
        int filesScanned = 0;
        while (!stack.isEmpty() && filesScanned < 800) {
            File f = stack.pop();
            String nameLower = f.getName().toLowerCase();
            if (f.isDirectory()) {
                // runner/ = 30k+ generated out_*.cpp (context bomb, and its
                // names are recompiled funcs, not runtime handlers).
                if (nameLower.equals("runner") || nameLower.startsWith("build")
                    || nameLower.equals(".git") || nameLower.equals("out")) continue;
                File[] kids = f.listFiles();
                if (kids != null) for (File k : kids) stack.push(k);
                continue;
            }
            if (!(nameLower.endsWith(".cpp") || nameLower.endsWith(".h")
                  || nameLower.endsWith(".hpp") || nameLower.endsWith(".cc"))) continue;
            if (nameLower.startsWith("out_")) continue;   // stray generated file
            filesScanned++;
            try {
                String src = readFileFully(f);
                for (java.util.regex.Pattern p :
                        new java.util.regex.Pattern[]{pCtxRef, pRawWrap, pBindStr, pStubsNs}) {
                    java.util.regex.Matcher m = p.matcher(src);
                    while (m.find()) runtimeHandlerNames.add(m.group(1));
                }
            } catch (Exception ignored) {}
        }
        runtimeRosterLoaded = !runtimeHandlerNames.isEmpty();
        println(String.format("[RUNTIME-ROSTER] %d handler names from %d files under %s.",
            runtimeHandlerNames.size(), filesScanned, start.getAbsolutePath()));
    }

    /** Rule 153 membership check - tolerates Ghidra's `Name_0xADDR` suffix
     *  variants on either side. */
    private boolean hasRuntimeHandler(String name) {
        if (runtimeHandlerNames.contains(name)) return true;
        int us = name.lastIndexOf("_0x");
        return us > 0 && runtimeHandlerNames.contains(name.substring(0, us));
    }

    private void parseStep1Config(File configFile) throws IOException {
        BufferedReader reader = utf8Reader(configFile);
        String line; boolean inStubs=false,inSkip=false;
        // v11.1: `locked = [...]` array state + "previous enricher additions"
        // marker zone (re-entrant input = our own earlier output).
        boolean inLocked=false;
        boolean enricherZone=false;
        // v11.1: ignore everything inside an old [triage_advisory] section
        // (pre-v11 runs emitted it into the TOML; advisory arrays must never
        // be mistaken for binding arrays).
        boolean inAdvisorySection=false;
        while ((line=reader.readLine())!=null) {
            String t=line.trim();
            if (t.startsWith("[")) {
                inAdvisorySection = t.startsWith("[triage_advisory]");
                inStubs=false; inSkip=false; inLocked=false; enricherZone=false;
                continue;
            }
            if (inAdvisorySection) continue;
            // v11 Rule 154: exporter-embedded ELF identity.
            if (t.startsWith("elf_hash")) {
                int q1=t.indexOf('"'),q2=t.lastIndexOf('"');
                if (q1>=0 && q2>q1) step1ElfHash=t.substring(q1+1,q2).trim().toLowerCase();
                continue;
            }
            // v11.1: previous-run additions marker. Entries below it (until
            // the array closes) carry step1_source = "enricher_prev".
            if (t.startsWith("# --- Triage Enricher")) { enricherZone=true; continue; }
            // v11 (General v15.5 Bugfix T): single-line arrays
            // (`stubs = ["a@0x1", "b@0x2"]` or `stubs = []`) are valid TOML
            // and appear in hand-edited and third-party exporter configs; the
            // old line-based parser silently dropped every entry on such
            // lines (and mis-tracked the open-array state). Inline entries
            // are consumed here. v11.1 adds the `locked` array.
            boolean isLockedKey = t.startsWith("locked");
            if (t.startsWith("stubs")||isLockedKey||
                (t.startsWith("skip")&&!t.startsWith("skip_count"))) {
                boolean stubsArr = t.startsWith("stubs");
                if (t.contains("[") && t.contains("]")) {
                    // fully inline array
                    String body = t.substring(t.indexOf('[')+1, t.lastIndexOf(']'));
                    java.util.regex.Matcher m =
                        java.util.regex.Pattern.compile("\"((?:[^\"\\\\]|\\\\.)*)\"").matcher(body);
                    while (m.find()) {
                        if (isLockedKey) addLockedEntry(m.group(1));
                        else addStep1Entry(m.group(1), stubsArr, false);
                    }
                    inStubs=false; inSkip=false; inLocked=false;
                } else {
                    inLocked=isLockedKey;
                    inStubs=!isLockedKey&&stubsArr;
                    inSkip=!isLockedKey&&!stubsArr;
                }
                enricherZone=false;
                continue;
            }
            if (t.equals("]")||t.startsWith("]")){inStubs=false;inSkip=false;inLocked=false;enricherZone=false;continue;}
            if (!inStubs&&!inSkip&&!inLocked) continue;
            int q1=t.indexOf('"'),q2=t.lastIndexOf('"');
            if (q1<0||q2<=q1) continue;
            String entry=t.substring(q1+1,q2);
            if (inLocked) { addLockedEntry(entry); continue; }
            addStep1Entry(entry, inStubs, enricherZone);
            // v11.1 LOCK: trailing `# LOCKED` comment on a stub/skip line.
            if (t.substring(q2+1).toUpperCase().contains("# LOCKED")
                || t.substring(q2+1).toUpperCase().contains("#LOCKED"))
                addLockedEntry(entry);
        }
        reader.close();
        // v11 Rule 152: dual-binding hygiene - an address (or name) listed
        // in BOTH stubs and skip is an input bug. Keep the stub (named
        // handler routing beats an error placeholder), drop the skip.
        {
            Set<Long> dualA = new HashSet<>(step1StubAddresses);
            dualA.retainAll(step1SkipAddresses);
            Set<String> dualN = new HashSet<>(step1StubNames);
            dualN.retainAll(step1SkipNames);
            if (!dualA.isEmpty() || !dualN.isEmpty()) {
                step1SkipAddresses.removeAll(dualA);
                step1SkipNames.removeAll(dualN);
                println("[STEP1] Rule 152: "+(dualA.size()+dualN.size())
                    +" entries were in BOTH stubs and skip - kept as stubs, dropped from skip.");
            }
        }
    }

    /** v11: shared step1 entry recorder ("name" or "name@0xADDR").
     *  v11.1: enricherPrev marks entries a PREVIOUS enricher run added. */
    private void addStep1Entry(String entry, boolean isStubArray, boolean enricherPrev) {
        if (entry == null || entry.isEmpty()) return;
        String name; long addr = -1;
        int atIdx = entry.lastIndexOf("@0x");
        if (atIdx < 0) atIdx = entry.lastIndexOf("@0X");
        if (atIdx >= 0) {
            name = entry.substring(0, atIdx);
            String hexStr = entry.substring(atIdx+3).replaceAll("[^0-9a-fA-F]","");
            if (!hexStr.isEmpty())
                try { addr = Long.parseLong(hexStr,16); } catch (NumberFormatException ignored) {}
        } else { name = entry; }
        if (isStubArray) {
            if (!name.isEmpty()) step1StubNames.add(name);
            if (addr >= 0) step1StubAddresses.add(addr);
        } else {
            if (!name.isEmpty()) step1SkipNames.add(name);
            if (addr >= 0) step1SkipAddresses.add(addr);
        }
        if (enricherPrev) {
            if (!name.isEmpty()) step1EnricherPrevNames.add(name);
            if (addr >= 0) step1EnricherPrevAddresses.add(addr);
        }
        // v11 Rule 151: remember the expected name per address.
        if (addr >= 0 && !name.isEmpty()) step1NameByAddr.putIfAbsent(addr, name);
    }

    /** v11.2: is `expected` a TRUNCATED form of the real ELF symbol rather
     *  than a different function? step1 tokens bind by ADDRESS; the name is
     *  only a label, and v9-era exporters truncated mangled C++ names
     *  (`__ct@0xADDR` for `__ct__15mgCTexAnimeDataFv`, `SetStatus@0xADDR` for
     *  `SetStatus__6CSceneFiii`). Such a token is NOT a wrong-region
     *  mismatch - the address is correct. Detected when the real symbol
     *  starts with the expected label and continues with the Itanium mangle
     *  marker `__`. Genuine drift (different function) fails this and stays a
     *  real Rule 151 mismatch. */
    private static boolean isTruncatedNameOf(String expected, String actual) {
        if (expected == null || actual == null) return false;
        if (!actual.startsWith(expected)) return false;
        if (actual.length() <= expected.length()) return false;
        return actual.substring(expected.length()).startsWith("__");
    }

    /** v11.1: record a locked binding ("name" or "name@0xADDR"). Locked
     *  entries bypass the keep gate and every rescue/promote pass. */
    private void addLockedEntry(String entry) {
        if (entry == null || entry.isEmpty()) return;
        String name = entry; long addr = -1;
        int atIdx = entry.lastIndexOf("@0x");
        if (atIdx < 0) atIdx = entry.lastIndexOf("@0X");
        if (atIdx >= 0) {
            name = entry.substring(0, atIdx);
            String hexStr = entry.substring(atIdx+3).replaceAll("[^0-9a-fA-F]","");
            if (!hexStr.isEmpty())
                try { addr = Long.parseLong(hexStr,16); } catch (NumberFormatException ignored) {}
        }
        if (!name.isEmpty()) step1LockedNames.add(name);
        if (addr >= 0) step1LockedAddresses.add(addr & 0xFFFFFFFFL);
    }

    // =========================================================
    // RULE 11: MAINLOOP SHIELD
    // v11 Rule 156 (General v15.3): extended from depth-1 (direct callees
    // only) to a depth-3 BFS, capped. Per-frame wrappers two hops below the
    // loop (MainLoop -> SceneStep -> SceneDraw class chains) were
    // stub-eligible before. The shield only suppresses ENRICHER stub/skip
    // decisions and feeds the step1 whitelist rescue; SDK boundaries with
    // HARD evidence (syscall / SIF RPC / IRX / IPU) keep their stubs
    // regardless - the step1 keep gate checks hard evidence BEFORE the
    // whitelist (see step1KeepGateFailure).
    // =========================================================
    private static final int MAINLOOP_SHIELD_DEPTH = 3;
    private static final int MAINLOOP_SHIELD_CAP   = 768;
    private void buildMainLoopShield(Address mlAddr) {
        Function mlFunc = funcManager.getFunctionAt(mlAddr);
        mainLoopShield.add(mlAddr.getOffset());
        if (mlFunc==null) return;
        Map<Long,Integer> depth = new HashMap<>();
        Deque<Function> q = new ArrayDeque<>();
        depth.put(mlAddr.getOffset(), 0);
        q.add(mlFunc);
        while (!q.isEmpty() && mainLoopShield.size() < MAINLOOP_SHIELD_CAP) {
            Function cur = q.poll();
            int d = depth.get(cur.getEntryPoint().getOffset());
            if (d >= MAINLOOP_SHIELD_DEPTH) continue;
            for (Function callee : cur.getCalledFunctions(monitor)) {
                long off = callee.getEntryPoint().getOffset();
                if (depth.containsKey(off)) continue;
                depth.put(off, d+1);
                mainLoopShield.add(off);
                q.add(callee);
                if (mainLoopShield.size() >= MAINLOOP_SHIELD_CAP) break;
            }
        }
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
        // v11.3: generalize the jr-$t9 caller proxy to ALL functions so the
        // emitted `override_hookable` is meaningful for non-ctors too.
        // registerFunction overrides are consulted ONLY for indirect jalr/jr $t9;
        // a function with any direct-jal caller is not fully hookable that way
        // (the G11 ReloadTexture / F51.8 COP2 gotcha). Same proxy Pass B uses.
        for(FuncResult r : results) {
            if(r.traits == null || r.traits.calledViaJrT9) continue;
            for(long[] c : r.traits.callers) {
                FuncResult caller = byAddr.get(c[0] & 0xFFFFFFFFL);
                if(caller == null || caller.traits == null) continue;
                if(caller.traits.indirectCallT9Count > 0) { r.traits.calledViaJrT9 = true; break; }
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
            // v11 (General v15.4): hard-bound step1 keeps are deliberate
            // boundaries; surface conflicts via review, don't unwind.
            if(("CRITICAL".equals(t.ctorRiskTier) || "HIGH".equals(t.ctorRiskTier)) &&
               "STUB".equals(r.disposition) && !isHardBoundStep1(r)) {
                r.disposition = "RECOMPILE";
                removeAutoBindingEntries(newStubs, r);
                noteStep1Rescue(r, "ctor risk " + t.ctorRiskTier + " (vtable/global-assigned ctor)",
                                "v8_ctor_risk");
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
                // Promote out of STUB - unless the runtime ships a verified
                // handler for it (v15.4 roster-backed keep, e.g. SIMD-native
                // sceVu0ApplyMatrix).
                if("STUB".equals(r.disposition) && !isHardBoundStep1(r)) {
                    r.disposition = "RECOMPILE";
                    removeAutoBindingEntries(newStubs, r);
                    noteStep1Rescue(r, "sceVu0 helper must be implemented (VU0 macro math)",
                                    "v8_scevu0_helper");
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

            // v10 Rule 140: VU0-macro COP2 PARTIAL-DESTINATION write detection.
            // F51.8: the recompiler emitted the dest-component blend mask in
            // reversed lane order; only PARTIAL-dest ops (.xy/.z/.xyz/...) were
            // corrupted — full `.xyzw` masks are symmetric and were spared.
            // Ghidra renders EE VU0-macro ops with the dest field as a `.<field>`
            // suffix (e.g. "vftoi4.xy", "vadd.xyz", "vmul.xyzw"). We count any
            // maskable arithmetic/convert op whose dest field is a strict subset
            // of {x,y,z,w}. (Broadcast-source variants like "vmulx"/"vaddw" still
            // start with the base family and carry the dest field in the suffix.)
            {
                boolean cop2Maskable =
                    ml.startsWith("vadd")||ml.startsWith("vsub")||ml.startsWith("vmul")||
                    ml.startsWith("vmax")||ml.startsWith("vmini")||ml.startsWith("vmin")||
                    ml.startsWith("vmadd")||ml.startsWith("vmsub")||ml.startsWith("vabs")||
                    ml.startsWith("vftoi")||ml.startsWith("vitof")||ml.startsWith("vmove")||
                    ml.startsWith("vmr32")||ml.startsWith("vopmsub")||ml.startsWith("vmula")||
                    ml.startsWith("vadda")||ml.startsWith("vsuba")||ml.startsWith("vmadda")||
                    ml.startsWith("vmsuba")||ml.startsWith("vscl");
                int dot = ml.indexOf('.');
                if(cop2Maskable && dot >= 0) {
                    String field = ml.substring(dot+1);
                    boolean allXYZW = field.length() > 0 && field.length() <= 4;
                    if(allXYZW)
                        for(int ci=0; ci<field.length(); ci++)
                            if("xyzw".indexOf(field.charAt(ci)) < 0){allXYZW=false;break;}
                    if(allXYZW) {
                        traits.usesCop2 = true;
                        if(field.equals("xyzw")) {
                            traits.cop2FullDestOps++;
                        } else {
                            traits.cop2PartialDestOps++;
                            traits.cop2DestFields.add(field);
                        }
                    }
                }
            }

            // v10.1 Rule 147: COP2 special-op / latency hazards beyond the Rule
            // 140 dest-mask blends — the recompiler can mis-codegen these the same
            // way it reversed the dest mask (F51.8 follow-up). All are EE COP2
            // macro-mode mnemonics Ghidra disassembles.
            if(ml.startsWith("vdiv")||ml.startsWith("vsqrt")||ml.startsWith("vrsqrt"))
                {traits.cop2SpecialOps.add("EFU_Q_LATENCY");traits.usesCop2=true;}
            if(ml.startsWith("vclip"))
                {traits.cop2SpecialOps.add("CLIP_FLAG");traits.usesCop2=true;}
            if(ml.startsWith("vrnext")||ml.startsWith("vrget")||ml.startsWith("vrxor")||ml.startsWith("vrinit"))
                {traits.cop2SpecialOps.add("R_REGISTER");traits.usesCop2=true;}
            if(ml.startsWith("vmr32"))
                {traits.cop2SpecialOps.add("VMR32");traits.usesCop2=true;}
            if(ml.startsWith("vwaitq")||ml.startsWith("vwaitp"))
                {traits.cop2SpecialOps.add("WAIT");traits.usesCop2=true;}
            if(ml.startsWith("vopmsub")||ml.startsWith("vopmula"))
                {traits.cop2SpecialOps.add("OUTER_PRODUCT");traits.usesCop2=true;}
            if(ml.startsWith("xgkick")||ml.equals("vxgkick"))
                {traits.cop2SpecialOps.add("XGKICK");traits.usesCop2=true;}

            // v10.1 Rule 148: EE FPU non-IEEE semantics. ctc1/cfc1 set the FPU
            // control/rounding; div.s/sqrt.s/rsqrt.s are soft on the EE FPU and
            // diverge from host IEEE for denormals/NaN/rounding.
            if(ml.equals("ctc1")||ml.equals("cfc1")) traits.writesFpuControl=true;
            if(ml.equals("div.s")||ml.equals("sqrt.s")||ml.equals("rsqrt.s")) traits.usesFpuDivSqrt=true;

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
            // v17.1 Rule 232: mfc0 of COP0 reg 9 (Count) - the EE cycle counter as a
            // game time source (PCSX2 COP0.cpp UpdateCP0Count). Operand-name match
            // covers both "Count" symbolic and raw-index disassembly variants.
            if(ml.equals("mfc0") && !traits.readsCop0Count) {
                try {
                    String rep = inst.getDefaultOperandRepresentation(1);
                    if(rep != null && (rep.toLowerCase().contains("count") || rep.trim().equals("9")))
                        traits.readsCop0Count = true;
                } catch(Exception ignore) {}
            }

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
                    // v10.1 Rule 146: harvest Ghidra-resolved jump-table targets so
                    // the recompiler can pre-populate its computed-jump dispatch.
                    // A switch site with zero resolved targets is the real risk set
                    // (tagged COMPUTED_JUMP_UNRESOLVED downstream).
                    long sitePc = inst.getAddress().getOffset() & 0xFFFFFFFFL;
                    traits.computedJumpSwitchPcs.add(sitePc);
                    for(Reference jr : inst.getReferencesFrom()) {
                        if(traits.computedJumpTargets.size() >= 512) break;
                        if(jr.getReferenceType().isJump()) {
                            long tgt = jr.getToAddress().getOffset() & 0xFFFFFFFFL;
                            if(tgt != sitePc)
                                traits.computedJumpTargets.add(new long[]{sitePc, tgt});
                        }
                    }
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

            // v11 (General v13): count all store forms (incl. sd/sq) for
            // spin-loop gating.
            if(ml.equals("sw")||ml.equals("swc1")||ml.equals("sqc2")||ml.equals("sh")||
               ml.equals("sb")||ml.equals("sd")||ml.equals("sq")||ml.equals("sdc1"))
                traits.storeOps++;
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
                            // v12 Rule 166: GS FRAME reg (render-target setter)
                            if(reg==0x4CL||reg==0x4DL) traits.writesFrameReg = true;
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
                        // v11.3 Rule 162: sub-word STR kick — sb/sh into the CHCR
                        // word (slot 0..3). A word-only IO dispatcher drops it
                        // (G26: SendDMA kicks ch8 via `sb` to CHCR+1).
                        if(slot <= 0x03 && ref.getReferenceType().isWrite() &&
                           (ml.equals("sb")||ml.equals("sh"))) {
                            traits.subwordDmaStrKick = true;
                            traits.subwordKickChannels.add(DMA_CHANNEL_NAMES[chIdx]);
                        }
                        // v11.3 Rule 162: fromSPR(8)/toSPR(9) scratchpad DMA
                        // channel — the staged-packet copy path (G26).
                        if((chIdx==8||chIdx==9) && ref.getReferenceType().isWrite()) {
                            traits.programsSprDma = true;
                            traits.sprDmaChannels.add(DMA_CHANNEL_NAMES[chIdx]);
                        }
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
        // v11.2 Rule 161 (DC2-tuned precision): dynamic-code loader. The
        // canonical idiom is "read code from disc, FlushCache the I-cache,
        // then EXECUTE the loaded bytes". The General-script trigger
        // (cache-flush + file/archive evidence) over-fired on DC2: the game
        // streams every asset from DATA.DAT / DATA.HD2 and flushes the cache
        // after each DMA, so 34 pure ASSET loaders were flagged as code
        // loaders (DC2 is a single flat ELF with no runtime code loading -
        // confirmed across 9 GS dumps; overlay_loaders=0). The fix: require
        // EXECUTION evidence - an overlay/exec callee (LoadExecPS2 / ExecPS2
        // / LoadModuleBuffer ...) in the SAME body. Asset loaders never call
        // those, so DC2 -> 0; real overlay games (General use) still fire.
        {
            boolean callsCacheFlush = false, execsOverlay = false;
            for(String cn : traits.calleeNames) {
                if(cn.equals("FlushCache") || cn.equals("iFlushCache")
                   || cn.equals("CacheFlush")
                   || cn.startsWith("FlushCache_0x") || cn.startsWith("iFlushCache_0x")
                   || cn.startsWith("CacheFlush_0x")) {
                    callsCacheFlush = true;
                }
                if(OVERLAY_LOADER_CALLEES.contains(cn)) execsOverlay = true;
            }
            // file/archive input still required - a flush+exec with no load is
            // an in-place patcher, not a loader.
            if(callsCacheFlush && execsOverlay &&
               (traits.callsFileOpen || traits.refsArchiveStrings))
                traits.isDynamicCodeLoader = true;
        }
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

        // ===== v10 detector pipeline (DC2 F47-F52) =====
        // Rule 140: any partial-dest COP2 op flags the func for dest-mask review.
        if(traits.cop2PartialDestOps > 0) traits.cop2DestMaskVerify = true;
        // Rule 141: static-initializer install manifest (vtable/global writes).
        if(fname.startsWith("__sinit_")) {
            traits.isStaticInitializer = true;
            collectStaticInitManifest(func, traits);
            // Uncalled == no call/flow xref (runs only via the global-ctors table).
            if(traits.xrefToCount == 0) traits.isUncalledStaticInit = true;
        }
        // Rule 142: memory allocator / pool / placement-new — never auto-stub.
        detectMemoryAllocator(fname, traits);
        // Rule 143: guest-execution-lock hog (thread yield-spin starver).
        detectGuestLockHog(fname, traits);
        // Rule 144: MIPS EABI 5th-arg-in-$t0 read in the prologue.
        detectEabiArgT0(func, traits);
        // Rule 145: PSMCT16 map-CLUT uploader (only meaningful for BITBLTBUF funcs).
        if(traits.writesBitbltbufReg) detectPsmct16ClutUploader(func, traits);
        // Rule 150: EE code-overlay loader (flat-address-space assumption risk).
        for(String cn : traits.calleeNames)
            if(OVERLAY_LOADER_CALLEES.contains(cn)) { traits.isOverlayLoader = true; break; }

        // ===== v13 detector pipeline (DC2 G53-G82) =====
        // Rule 178: global-guarded configuration block (init-ordering gap).
        detectConditionalInitOnGlobal(func, traits);
        // Rule 181: terminal jr through a vtable slot (recompiler tail-call bug).
        detectVtableTailcallThunk(func, traits);

        // ===== v15 detector pipeline (DC2 G83-G115) =====
        // Sets the firewalled scan-time booleans (190/191/196/197) that forceRecompile
        // consults; the non-firewalled rosters/tags (192/193/195/194/184+) are derived
        // later in applyV15Rules from these traits.
        detectV15Signals(func, fname, traits);
        // v15.1 Rule 199: VIF unpack decompression-state command bytes (PCSX2-grounded).
        detectVifUnpackState(func, traits);
        // v15.2 Rules 203/204: MMI SIMD ops + CFC2/CTC2 control-reg access (skill codegen classes).
        detectCodegenClasses(func, traits);
        // v16 Rules 207/208: FTOI4 + fog-clamp shape (ADC capability) + perspective-divide near-plane.
        detectV16Signals(func, fname, traits);
        // v19 Rules 244/245/248/250: CHCR TIE bit, VIFcode i-bit, cache/sync/tlb instructions.
        detectV19Signals(func, traits);

        cache.put(key,traits);
        return traits;
    }

    // v15.2 macro control-reg indices (15-vu1-gs-debugging §2.1, confirmed vs PCSX2 VU.h).
    private static final Map<Long,String> COP2_CONTROL_REGS = new HashMap<>();
    static {
        COP2_CONTROL_REGS.put(16L,"STATUS"); COP2_CONTROL_REGS.put(17L,"MAC");
        COP2_CONTROL_REGS.put(18L,"CLIP");   COP2_CONTROL_REGS.put(20L,"R");
        COP2_CONTROL_REGS.put(21L,"I");      COP2_CONTROL_REGS.put(22L,"Q");
        COP2_CONTROL_REGS.put(23L,"P");      COP2_CONTROL_REGS.put(26L,"TPC");
        COP2_CONTROL_REGS.put(27L,"CMSAR0"); COP2_CONTROL_REGS.put(28L,"FBRST");
        COP2_CONTROL_REGS.put(29L,"VPU_STAT"); COP2_CONTROL_REGS.put(31L,"CMSAR1");
    }

    // v15.2 Rule 203/204: flag the two recompiler codegen classes the skill names but no
    // rule covered - EE MMI (128-bit SIMD integer) ops and CFC2/CTC2 VU0 control-reg access.
    // Both are emitted as wrong C++ for some operand shapes SILENTLY; the map flags the
    // functions so the AI can audit the whole class (10-agent-guardrails §2 L64).
    private void detectCodegenClasses(Function func, FuncTraits traits) {
        InstructionIterator it = currentProgram.getListing().getInstructions(func.getBody(), true);
        int scanned = 0;
        Map<String,Long> regConsts = new HashMap<>();
        while(it.hasNext() && scanned < 6000) {
            Instruction inst = it.next(); scanned++;
            String mn = inst.getMnemonicString(); if(mn == null) continue;
            String m = mn.toLowerCase();
            // track small immediates so a ctc2 sourcing a const reg can name the index
            if(m.equals("addiu")||m.equals("li")||m.equals("ori")||m.equals("daddiu")) {
                String dr = regOf(inst.getOpObjects(0));
                long imm = -1;
                for(Object o : inst.getInputObjects())
                    if(o instanceof ghidra.program.model.scalar.Scalar)
                        imm = ((ghidra.program.model.scalar.Scalar)o).getUnsignedValue();
                if(dr != null && imm >= 0) regConsts.put(dr, imm);
            }
            // --- Rule 203 MMI ---
            String fam = mmiFamily(m);
            if(fam != null) { traits.usesMmi = true; traits.mmiOpCount++; traits.mmiFamilies.add(fam); }
            // --- Rule 204 CFC2/CTC2 ---
            // Only indices 16-31 are the SPECIAL control regs (STATUS/MAC/CLIP/Q/...) the F51.8
            // control-reg-map codegen class is about. Indices 0-15 are plain VI00-VI15 integer
            // register copies (routine, not a codegen hazard) — they over-fired the rule, so
            // skip them. An unresolved index stays flagged (could be a special reg).
            if(m.equals("cfc2") || m.equals("ctc2")) {
                long idx = -1;
                for(Object o : inst.getInputObjects())
                    if(o instanceof ghidra.program.model.scalar.Scalar) {
                        long v = ((ghidra.program.model.scalar.Scalar)o).getUnsignedValue();
                        if(v <= 31) idx = v;
                    }
                if(idx < 0) {  // ctc2 source may be a tracked const reg
                    for(Object o : inst.getInputObjects())
                        if(o instanceof ghidra.program.model.lang.Register) {
                            Long c = regConsts.get(((ghidra.program.model.lang.Register)o).getName());
                            if(c != null && c <= 31) idx = c;
                        }
                }
                if(idx >= 16) {
                    traits.usesCop2ControlReg = true;
                    traits.cop2ControlRegs.add(COP2_CONTROL_REGS.getOrDefault(idx, "idx"+idx));
                } else if(idx < 0) {
                    traits.usesCop2ControlReg = true;
                    traits.cop2ControlRegs.add("unresolved");
                }
                // idx 0-15 (VI00-VI15 read) is routine — not recorded.
            }
        }
    }

    // v15.2 Rule 203: classify an EE R5900 MMI mnemonic into a family (null if not MMI).
    // The MMI opcode space is the p-prefixed 128-bit SIMD integer ops plus the pipeline-1
    // HI1/LO1 ops. `pref` is the one p-prefixed NON-MMI op (cache prefetch) - excluded.
    private static String mmiFamily(String m) {
        if(m.equals("pref")) return null;
        if(m.equals("mult1")||m.equals("multu1")||m.equals("div1")||m.equals("divu1")
           ||m.equals("madd1")||m.equals("maddu1")||m.equals("mfhi1")||m.equals("mflo1")
           ||m.equals("mthi1")||m.equals("mtlo1")) return "PIPE1";
        if(!m.startsWith("p") && !m.equals("qfsrv")) return null;
        if(m.equals("qfsrv")) return "QFSRV";
        if(m.startsWith("pext")||m.startsWith("pexc")||m.startsWith("pexe")) return "PEXT";
        if(m.startsWith("pcpy")) return "PCPY";
        if(m.startsWith("ppac")||m.startsWith("ppacb")) return "PPAC";
        if(m.startsWith("pmfhl")||m.startsWith("pmthl")) return "PMFHL";
        if(m.startsWith("pmadd")||m.startsWith("pmsub")||m.startsWith("phmadh")||m.startsWith("phmsbh"))
            return "PMADD";
        if(m.startsWith("pmult")||m.startsWith("pmulth")||m.startsWith("pdiv")||m.startsWith("pdivbw"))
            return "PMULT";
        if(m.startsWith("padd")||m.startsWith("psub")||m.startsWith("padsbh")) return "PADD";
        if(m.startsWith("pmax")||m.startsWith("pmin")) return "PMINMAX";
        if(m.startsWith("psll")||m.startsWith("psrl")||m.startsWith("psra")) return "PSHIFT";
        if(m.startsWith("pand")||m.startsWith("por")||m.startsWith("pxor")||m.startsWith("pnor"))
            return "PLOGIC";
        if(m.startsWith("pcgt")||m.startsWith("pceq")) return "PCMP";
        if(m.startsWith("pmfh")||m.startsWith("pmth")||m.startsWith("pmfl")||m.startsWith("pmtl"))
            return "PHILO";
        if(m.startsWith("pabs")||m.startsWith("plzcw")||m.startsWith("prot3w")||m.startsWith("pinteh")
           ||m.startsWith("prev")||m.startsWith("pmulth")) return "PMISC";
        // any remaining p-prefixed op is still an MMI op (catch-all, excl. pref above)
        return "PMISC";
    }

    // v15.1 Rule 199: VIF unpack decompression-state command builder. Const-scan for
    // VIFcode command bytes (bits 24-31) that program the UNPACK decompression: STMOD
    // (add-row / difference), STMASK (per-component write-mask incl. SKIP), STROW/STCOL
    // (the row/col regs), STCYCL (fill-skip), and the ITOP/BASE/OFFSET double-buffer
    // framing. Verified against pcsx2/Vif_Codes.cpp (vifCmdHandler) + Vif_Unpack.cpp
    // (writeXYZW mode/mask). Recorded here; gated on independent VIF evidence + tagged
    // in applyV15Rules (the v13 detector-gate philosophy avoids false positives on a
    // bare 0x05000000-shaped constant).
    private void detectVifUnpackState(Function func, FuncTraits traits) {
        InstructionIterator it = currentProgram.getListing().getInstructions(func.getBody(), true);
        int scanned = 0;
        while(it.hasNext() && scanned < 4000) {
            Instruction inst = it.next(); scanned++;
            String mn = inst.getMnemonicString(); if(mn == null) continue;
            String m = mn.toLowerCase();
            long v = -1;
            if(m.equals("lui")) {
                for(Object o : inst.getInputObjects())
                    if(o instanceof ghidra.program.model.scalar.Scalar)
                        v = (((ghidra.program.model.scalar.Scalar)o).getUnsignedValue() & 0xFFFFL) << 16;
            } else if(m.equals("ori") || m.equals("addiu") || m.equals("li") || m.equals("daddiu")) {
                for(Object o : inst.getInputObjects())
                    if(o instanceof ghidra.program.model.scalar.Scalar)
                        v = ((ghidra.program.model.scalar.Scalar)o).getUnsignedValue() & 0xFFFFFFFFL;
            }
            if(v < 0x01000000L) continue;
            long cmd = (v >> 24) & 0xFFL;
            String nm = null;
            if(cmd == 0x01L) nm = "STCYCL";
            else if(cmd == 0x02L) nm = "OFFSET";
            else if(cmd == 0x03L) nm = "BASE";
            else if(cmd == 0x04L) nm = "ITOP";
            else if(cmd == 0x05L) nm = "STMOD";
            else if(cmd == 0x06L) nm = "MSKPATH3";
            else if(cmd == 0x20L) nm = "STMASK";
            else if(cmd == 0x30L) nm = "STROW";
            else if(cmd == 0x31L) nm = "STCOL";
            if(nm != null) traits.vifUnpackStateCmds.add(nm);
        }
    }

    // v15 name rosters for the structural detectors (Rules 190/196).
    // Builder-specific tokens (NOT the bare class name "mgCVisualMDT", which also matched
    // getters like Iam/GetMaterialNum/GetpMaterial — FP). These name the funcs that emit the
    // selector packet: CreateRenderInfoPacket, the MDT builder, the visual-MDT Draw.
    private static final String[] PRIM_SELECTOR_NAMES = {
        "CreateRenderInfoPacket", "RenderInfoPacket", "MDTBuilder", "Draw__12mgCVisualMDT" };
    private static final String[] VIEW_PROJ_NAMES = {
        "Perspective", "LookAt", "SetView", "ViewMatrix", "ProjMatrix",
        "Projection", "SetCamera", "CreateRenderInfoPacket" };
    private static final java.util.Set<String> VIEW_PROJ_CALLEES = new java.util.HashSet<>(
        java.util.Arrays.asList("mgPerspective", "mgLookAt", "mgSetView", "mgProjection",
            "mgSetCamera", "sceVu0CameraMatrix", "mgSetProjection", "mgFrustum"));

    // v16 name rosters (G116-G137).
    // Rule 209: SPI map-config command handlers + the stack-arg getters that mark a handler.
    private static final String[] SPI_CONFIG_NAMES = {
        "cfgWATER", "cfgMAP", "cfgOBJ", "cfgLIGHT", "cfgCAMERA", "cfg_", "spiSet", "spiCfg" };
    private static final java.util.Set<String> SPI_STACK_GETTERS = new java.util.HashSet<>(
        java.util.Arrays.asList("spiGetStackInt", "spiGetStackVector", "spiGetStackFloat",
            "spiGetStackStr", "spiGetStackPtr"));
    // Rule 210: data-driven interpreter anchors (CRunScript event VM, Rule 172).
    private static final String[] CMD_INTERP_NAMES = {
        "exe__10CRunScript", "resume__10CRunScript", "run__10CRunScript",
        "Interpret", "ExecScript", "RunScript", "VmExec", "DispatchCmd", "ParseCmd" };
    // Rule 211: VU packer family anchors (passthrough/copy vs transform vs trifan vs dispatcher).
    private static final String[] PACKER_FAMILY_NAMES = {
        "CreateRenderInfoPacket", "RenderInfoPacket", "PacketBuilder", "AddPacket",
        "DrawDirect", "mgDrawDirect", "VuPacker" };

    // v15 Rule 190/191/196/197: per-function structural signals decoded over the
    // course of G83-G115. One light instruction pass for the per-vertex kick add
    // (0x800), the rest derived from already-collected traits + name rosters. Only
    // the firewalled booleans are set here (so forceRecompile honours them); the
    // tag/roster/counter work is done in applyV15Rules.
    private void detectV15Signals(Function func, String fname, FuncTraits traits) {
        long addr = func.getEntryPoint().getOffset() & 0xFFFFFFFFL;

        // --- the per-vertex ADC strip-restart "+2048"/0x800 kick add (Rule 191) ---
        InstructionIterator it = currentProgram.getListing().getInstructions(func.getBody(), true);
        int scanned = 0;
        while(it.hasNext() && scanned < 4000) {
            Instruction inst = it.next(); scanned++;
            String mn = inst.getMnemonicString(); if(mn == null) continue;
            String m = mn.toLowerCase();
            if(m.equals("addiu")||m.equals("addi")||m.equals("daddiu")||m.equals("ori")||
               m.equals("addu")||m.equals("daddu")||m.equals("li")) {
                for(Object o : inst.getInputObjects())
                    if(o instanceof ghidra.program.model.scalar.Scalar &&
                       (((ghidra.program.model.scalar.Scalar)o).getUnsignedValue() & 0xFFFFL) == 0x800L)
                        traits.kickConstAddCount++;
            }
        }

        // --- Rule 190 GIFTAG_PRIM_CLASS_SELECTOR ---
        boolean primName = false;
        for(String f : PRIM_SELECTOR_NAMES) if(fname.contains(f)) { primName = true; break; }
        boolean buildsSelectorPacket = traits.gifTagInlineBuilder &&
            (!traits.vifOpcodesBuilt.isEmpty() || !traits.storedVifOpcodes.isEmpty());
        if(addr == 0x1404d0L || primName || (buildsSelectorPacket && traits.usesCop2))
            traits.isPrimClassSelector = true;

        // --- Rule 191 ADC_KICK_VERTEX_SOURCE ---
        // An EE-side per-vertex geometry builder that controls the ADC/strip-restart bit.
        // PRECISION: the bare 0x800/kick-const add is far too common (framebuffer width, page
        // size) and over-fired on framebuffer/sound-init setters (sceGsSetDefDBuff, Init__6CSound,
        // viBufReset). A real per-vertex ADC source either writes the XYZ2/XYZ3 register itself,
        // OR emits a quadword vertex stream in a loop while building a GIF/PRIM packet. The
        // kick-const add is kept only as the discriminator for the constant_kick sub-class.
        boolean realVertexReg  = traits.writesXyz2Reg || traits.writesXyz3Reg;
        boolean vertexEmitLoop = traits.hasBackwardBranch && traits.quadwordVU > 0
            && traits.gifTagInlineBuilder && (traits.writesGsPrimReg || traits.writesRgbaqReg);
        if(realVertexReg || vertexEmitLoop) {
            traits.isAdcKickVertexSource = true;
            if(traits.writesXyz2Reg && traits.writesXyz3Reg) traits.adcSource = "input_driven_xyz3";
            else if(traits.writesXyz2Reg)                    traits.adcSource = "uniform_xyz2";
            else if(traits.writesXyz3Reg)                    traits.adcSource = "no_kick_xyz3";
            else                                              traits.adcSource =
                traits.kickConstAddCount > 0 ? "constant_kick" : "vertex_emit_loop";
        }

        // --- Rule 196 VIEW_PROJECTION_MATRIX_WRITER ---
        boolean vpName = false;
        for(String f : VIEW_PROJ_NAMES) if(fname.contains(f)) { vpName = true; break; }
        boolean vpCallee = false;
        for(String cn : traits.calleeNames)
            if(VIEW_PROJ_CALLEES.contains(cn) || cn.contains("MulMatrix")) { vpCallee = true; break; }
        // A camera/view-matrix builder OFTEN calls matrix helpers (mgMulMatrix) rather than
        // doing inline COP2 — requiring usesCop2 made this dead-fire (0 hits). G98/G99's
        // CreateRenderInfoPacket builds the combined matrix via mgMulMatrix, no inline VU0.
        if((vpName || vpCallee) &&
           (traits.writesToGlobal || traits.isStructInitializer || traits.gifTagInlineBuilder || traits.usesCop2))
            traits.isViewProjectionMatrixWriter = true;

        // --- Rule 197 OBJECT_ARRAY_CTOR ---
        boolean arrayCtorName = fname.contains("construct_new_array")
            || (traits.allocatorKind != null && traits.allocatorKind.equals("array_ctor"));
        boolean ctorLoopShape = (fname.contains("__ct__") || traits.isCtor || traits.isCtorMultiFieldInit)
            && traits.hasBackwardBranch && (traits.readsEabiArgT0 || traits.callOps > 0);
        if(arrayCtorName || ctorLoopShape)
            traits.isObjectArrayCtor = true;
    }

    // v16 Rule 207/208: one instruction pass for the FTOI4 pack op, the EFU divide
    // (DIV/RSQRT = perspective 1/W), and the fog-clamp shape (MUL/ADD feeding a MIN/MAX
    // pair). These structural facts decide a packer's ADC capability (G132) and whether
    // a near-plane site has the unsaturated float available pre-FTOI4 (G125-G129). Only
    // the scan-time facts are set here; tags/rosters are derived in applyV16Rules.
    private void detectV16Signals(Function func, String fname, FuncTraits traits) {
        InstructionIterator it = currentProgram.getListing().getInstructions(func.getBody(), true);
        int scanned = 0;
        boolean sawMul = false, sawAdd = false, sawMinMax = false, sawDiv = false;
        while(it.hasNext() && scanned < 4000) {
            Instruction inst = it.next(); scanned++;
            String mn = inst.getMnemonicString(); if(mn == null) continue;
            String m = mn.toLowerCase();
            // VU/COP2 macro ops Ghidra renders as vftoi4 / vdiv / vrsqrt / vmul / vadd / vmini/vmax,
            // and the EE FPU forms cvt.w.s / div.s / mul.s / add.s. Match both.
            if(m.contains("ftoi4") || m.equals("cvt.w.s") || m.contains("vftoi"))
                traits.usesFtoi4 = true;
            if(m.contains("vdiv") || m.contains("vrsqrt") || m.equals("div.s")
               || m.equals("rsqrt.s") || m.contains("vsqrt"))
                { sawDiv = true; }
            if(m.contains("vmul") || m.equals("mul.s") || m.contains("vmadd")) sawMul = true;
            if(m.contains("vadd") || m.equals("add.s") || m.contains("vmadd"))  sawAdd = true;
            if(m.contains("vmini")|| m.contains("vmax") || m.contains("vclip")
               || m.equals("min.s")|| m.equals("max.s")) sawMinMax = true;
        }
        // Fog-clamp shape (XYZF2 .w = clamp(a + b*w, lo, hi)): a multiply+add feeding a min/max
        // clamp pair. The fog byte ceiling is <=255 so the ADC bit15 (>=2048) is never set (G132).
        traits.hasFogClampShape = sawMul && sawAdd && sawMinMax;
        // Perspective divide -> position: an EFU divide present alongside a multiply (1/W * pos).
        traits.computesPerspectiveDivide = sawDiv && sawMul;

        long a = func.getEntryPoint().getOffset() & 0xFFFFFFFFL;
        // --- Rule 207 ADC capability (scan-time so the STUB firewall can honour it) ---
        // writesXyz2Reg/writesXyz3Reg are set by the GS-reg scan that runs before this; the
        // v15 detector above also consumes them, so they are reliable here.
        boolean emitsVertex = traits.writesXyz2Reg || traits.writesXyz3Reg
            || (traits.usesFtoi4 && (traits.gifTagInlineBuilder || traits.isAdcKickVertexSource));
        if(emitsVertex) {
            if(traits.hasFogClampShape && !traits.writesXyz3Reg) {
                traits.adcCapability = "xyzf2_fog_no_adc";   traits.isAdcCapablePacker = false;
            } else if(traits.writesXyz3Reg) {
                traits.adcCapability = "xyz3_norestart";      traits.isAdcCapablePacker = false;
            } else if(traits.writesXyz2Reg || traits.kickConstAddCount > 0) {
                traits.adcCapability = "xyz2_adc_capable";    traits.isAdcCapablePacker = true;
            } else {
                traits.adcCapability = "unknown_packer";      traits.isAdcCapablePacker = false;
            }
        }
        // --- Rule 208 near-plane source (scan-time) ---
        if(traits.computesPerspectiveDivide && traits.usesFtoi4) {
            traits.isNearPlaneSite = true;
            traits.nearPlaneStrategy = (traits.writesXyz3Reg || "xyzf2_fog_no_adc".equals(traits.adcCapability))
                ? "reject_q_le_0" : "clip_homog";
        }
        // --- Rule 211 packer family (scan-time; address + the prim-class selector flag) ---
        if(a == 0x1b68L)        { traits.isPackerFamily = true; traits.packerFamily = "copy_passthrough"; }
        else if(a == 0x1c50L)   { traits.isPackerFamily = true; traits.packerFamily = "trifan"; }
        else if(a == 0x1dc0L || a == 0x1ff0L) { traits.isPackerFamily = true; traits.packerFamily = "transform"; }
        else if(traits.isPrimClassSelector)   { traits.isPackerFamily = true; traits.packerFamily = "dispatcher"; }
        else if(fname.contains("DrawDirect") || fname.contains("mgDrawDirect"))
            { traits.isPackerFamily = true; traits.packerFamily = "copy_passthrough"; }
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

    // v13 helpers: small operand extractors mirroring the existing detectors.
    private static String regOf(Object[] ops) {
        if(ops != null && ops.length > 0 && ops[0] instanceof ghidra.program.model.lang.Register)
            return ((ghidra.program.model.lang.Register)ops[0]).getName();
        return null;
    }
    private static String baseRegOf(Object[] memOps) {
        if(memOps == null) return null;
        for(Object o : memOps)
            if(o instanceof ghidra.program.model.lang.Register)
                return ((ghidra.program.model.lang.Register)o).getName();
        return null;
    }
    private static long scalarOf(Object[] memOps) {
        if(memOps == null) return 0;
        for(Object o : memOps)
            if(o instanceof ghidra.program.model.scalar.Scalar)
                return ((ghidra.program.model.scalar.Scalar)o).getSignedValue();
        return 0;
    }
    // gp-relative offset -> label (if a known DC2 global) else "gp"+hex token.
    private String gpRelLabel(long signedOff) {
        String lbl = KNOWN_DC2_GP_OFFSETS.get(signedOff & 0xFFFFFFFFL);
        return lbl != null ? lbl : ("gp" + (signedOff < 0 ? "-" : "+") + Long.toHexString(Math.abs(signedOff)));
    }

    // v13 Rule 178: CONDITIONAL_INIT_ON_GLOBAL. Detect the G58/G81 shape
    // `lw $rX, <global>; beq/beqz $rX,$zero,skip; <stores that configure an object>`.
    // A global is loaded, branched-on-zero, and a block of >=2 config stores follows.
    private void detectConditionalInitOnGlobal(Function func, FuncTraits traits) {
        String fn = func.getName();
        boolean nameGate = isLifecycleVerbName(fn)
            || fn.contains("Init") || fn.contains("init") || fn.contains("Setup")
            || fn.contains("Begin") || fn.contains("Assign") || fn.contains("Open")
            || fn.contains("Create") || fn.contains("Reset");
        if(!nameGate) return;
        // regName -> guard token (set on a global load; cleared on overwrite).
        Map<String,String> globalLoadReg = new HashMap<>();
        Map<String,Long> luiHi = new HashMap<>();
        String pendingGuard = null; int storeWindow = 0, slots = 0;
        InstructionIterator it = currentProgram.getListing().getInstructions(func.getBody(), true);
        int scanned = 0;
        while(it.hasNext() && scanned < 600) {
            Instruction inst = it.next(); scanned++;
            String mn = inst.getMnemonicString(); if(mn == null) continue;
            String m = mn.toLowerCase();
            String d0 = regOf(inst.getOpObjects(0));
            if(m.equals("lui")) {
                if(d0 != null) { luiHi.put(d0, (scalarOf(inst.getOpObjects(1)) & 0xFFFFL) << 16); globalLoadReg.remove(d0); }
            } else if(m.equals("lw") || m.equals("lwu") || m.equals("ld")) {
                Object[] mem = inst.getOpObjects(1);
                String base = baseRegOf(mem); long off = scalarOf(mem);
                if(d0 != null && base != null) {
                    if(base.equalsIgnoreCase("gp")) globalLoadReg.put(d0, gpRelLabel(off));
                    else if(luiHi.containsKey(base)) globalLoadReg.put(d0, "0x" + Long.toHexString((luiHi.get(base) + off) & 0xFFFFFFFFL));
                    else globalLoadReg.remove(d0);
                }
            } else if(m.startsWith("beq") || m.startsWith("bne") || m.equals("beqz") || m.equals("bnez")) {
                String token = null;
                for(int oi=0; oi<2; oi++) { String r = regOf(inst.getOpObjects(oi)); if(r != null && globalLoadReg.containsKey(r)) token = globalLoadReg.get(r); }
                if(token != null) { pendingGuard = token; storeWindow = 24; slots = 0; }
            } else if(m.startsWith("sw") || m.startsWith("sd") || m.startsWith("sh") || m.startsWith("sb")) {
                if(pendingGuard != null && storeWindow > 0) {
                    String base = baseRegOf(inst.getOpObjects(1));
                    if(base != null && !base.equalsIgnoreCase("sp")) slots++;
                }
            }
            if(pendingGuard != null) {
                if(--storeWindow <= 0) {
                    if(slots >= 2) { traits.isConditionalInitOnGlobal = true; traits.guardGlobals.add(pendingGuard); traits.conditionalInitSlots += slots; }
                    pendingGuard = null;
                }
            }
            if(d0 != null && !m.equals("lui") && !m.equals("lw") && !m.equals("lwu") && !m.equals("ld"))
                globalLoadReg.remove(d0); // reg redefined by a non-load
        }
        if(pendingGuard != null && slots >= 2) {
            traits.isConditionalInitOnGlobal = true; traits.guardGlobals.add(pendingGuard); traits.conditionalInitSlots += slots;
        }
    }

    // v13 Rule 181: VTABLE_TAILCALL_THUNK. Terminal `jr $rX` (rX != ra/t9) where $rX
    // was loaded from `*(objptr + K)` (a vtable slot). G59 recompiler tail-call bug.
    private void detectVtableTailcallThunk(Function func, FuncTraits traits) {
        Map<String,Long> slotReg = new HashMap<>();   // reg -> small vtable slot offset
        InstructionIterator it = currentProgram.getListing().getInstructions(func.getBody(), true);
        int scanned = 0;
        while(it.hasNext() && scanned < 4000) {
            Instruction inst = it.next(); scanned++;
            String mn = inst.getMnemonicString(); if(mn == null) continue;
            String m = mn.toLowerCase();
            String d0 = regOf(inst.getOpObjects(0));
            if(m.equals("lw") || m.equals("lwu") || m.equals("ld")) {
                Object[] mem = inst.getOpObjects(1);
                String base = baseRegOf(mem); long off = scalarOf(mem);
                if(d0 != null && base != null && !base.equalsIgnoreCase("sp")
                   && !base.equalsIgnoreCase("gp") && off >= 0 && off < 0x400)
                    slotReg.put(d0, off);
                else if(d0 != null) slotReg.remove(d0);
            } else if(m.equals("jr")) {
                String r = d0;
                if(r != null && !r.equalsIgnoreCase("ra") && !r.equalsIgnoreCase("t9")
                   && slotReg.containsKey(r)) {
                    traits.isVtableTailcallThunk = true;
                    traits.tailcallVtableSlots.add(slotReg.get(r));
                }
            } else if(d0 != null) {
                slotReg.remove(d0); // reg redefined
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

    // =========================================================
    // v10 DETECTORS (DC2 F47-F52 retrospective)
    // =========================================================

    // v10 Rule 141: static-initializer (__sinit_*) install manifest. Tracks
    // lui/addiu/ori/li composite constants per register and records every store
    // of a pointer-looking constant (a mapped .text/.data address — typically a
    // vtable or global object pointer) to a slot. This is exactly what a
    // __sinit_* runs, and these writes are LOST when the headless port does not
    // drive the global-ctors table (F50.4 MainScene+0x10548=__vt__6CScene;
    // F50.7 CRandomCircle/CGeoStone) → the global's vtable pointer stays null
    // and the next virtual dispatch silently no-ops. The runtime side can replay
    // this manifest (idempotent dc2_write_u32) to repair un-run static init.
    private void collectStaticInitManifest(Function func, FuncTraits traits) {
        InstructionIterator it = currentProgram.getListing().getInstructions(func.getBody(), true);
        Map<String,Long> regConsts = new HashMap<>();
        ghidra.program.model.symbol.SymbolTable symtab = currentProgram.getSymbolTable();
        while(it.hasNext()) {
            if(traits.staticInitInstalls.size() >= 32) break;
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
                String src = (dop!=null && dop.length>0 && dop[0] instanceof ghidra.program.model.lang.Register)
                    ? ((ghidra.program.model.lang.Register)dop[0]).getName() : null;
                long off = 0;
                Object[] aop = inst.getOpObjects(1);
                if(aop != null) for(Object o : aop)
                    if(o instanceof ghidra.program.model.scalar.Scalar)
                        off = ((ghidra.program.model.scalar.Scalar)o).getSignedValue();
                if(src != null && regConsts.containsKey(src)) {
                    long val = regConsts.get(src) & 0xFFFFFFFFL;
                    if(val >= 0x00100000L) {   // EE load base; below this is not a pointer
                        Address va = toAddr(val);
                        boolean mapped;
                        try { mapped = memory.contains(va); } catch(Exception e) { mapped = false; }
                        if(mapped) {
                            traits.staticInitInstalls.add(new long[]{
                                inst.getAddress().getOffset() & 0xFFFFFFFFL, val, off & 0xFFFFFFFFL });
                            ghidra.program.model.symbol.Symbol s = symtab.getPrimarySymbol(va);
                            if(s != null && s.getName().startsWith("__vt__"))
                                traits.staticInitInstallsVtable = true;
                        }
                    }
                }
            }
        }
    }

    // v10 Rule 142: memory allocator / pool initializer / placement-new. F50.1/
    // F50.2: auto-stubbing one of these to `setReturnS32(0)` leaves the pool
    // uncreated, Alloc returns 0, and constructing on the null pointer produces a
    // garbage vtable PC deep in an init chain (looks like a bad-ctor crash, isn't
    // one). These must never be auto-stubbed.
    private void detectMemoryAllocator(String fname, FuncTraits traits) {
        String low = fname.toLowerCase();
        if(fname.contains("memoryInit"))            { traits.isMemoryAllocator=true; traits.allocatorKind="pool_init";     return; }
        if(fname.contains("construct_new_array"))   { traits.isMemoryAllocator=true; traits.allocatorKind="array_ctor";    return; }
        if(fname.startsWith("__nw__")||fname.startsWith("__nwa__"))
                                                    { traits.isMemoryAllocator=true; traits.allocatorKind="placement_new"; return; }
        if(fname.contains("stAlloc")||fname.contains("GetMainStack")||fname.contains("stSetBuffer"))
                                                    { traits.isMemoryAllocator=true; traits.allocatorKind="stack";          return; }
        if(fname.contains("SetHeapMem")||fname.contains("SetTableBuffer"))
                                                    { traits.isMemoryAllocator=true; traits.allocatorKind="pool_init";     return; }
        // Generic Alloc verb. DC2 demangled form: `Alloc__9mgCMemoryFi`.
        if(low.startsWith("alloc")||low.contains("alloc__")||fname.contains("__9mgCMemory"))
                                                    { traits.isMemoryAllocator=true; traits.allocatorKind="alloc"; }
    }

    // v10 Rule 143: guest-execution-lock hog. F49.5/F50: a guest thread that
    // spins without yielding the single m_guestExecutionMutex starves every other
    // guest thread (the GamePadStep -> SwitchGamePadThread / RotateThreadReadyQueue
    // syscall-0x2B loop caused the menu→dungeon deadlock). Such yield/spin
    // functions MUST release the lock (GuestExecutionReleaseScope).
    private void detectGuestLockHog(String fname, FuncTraits traits) {
        boolean spinShape = traits.isInfiniteSpinLoop || traits.isSyncWaitLoop
                         || (traits.hasBackwardBranch && traits.byteSize < 400);
        boolean threadName = fname.contains("GamePad") || fname.contains("RotateThread")
                          || fname.contains("SwitchGamePad") || fname.contains("ThreadReadyQueue")
                          || fname.contains("cooperativeYield") || fname.contains("ReadyQueue");
        if(spinShape && threadName) traits.isGuestLockHogCandidate = true;
    }

    // v10 Rule 144: MIPS EABI 5th-argument detection. F50.1/F50.2: DC2 passes the
    // 5th integer arg in $t0 ($a4), not on the stack. A function that READS $t0
    // before defining it in its prologue is consuming an incoming EABI arg — a
    // signal that any runtime/CRT override must read $t0, not a stack slot.
    private void detectEabiArgT0(Function func, FuncTraits traits) {
        InstructionIterator it = currentProgram.getListing().getInstructions(func.getBody(), true);
        int scanned = 0; boolean t0Defined = false;
        while(it.hasNext() && scanned < 24) {
            Instruction inst = it.next(); scanned++;
            for(Object o : inst.getInputObjects()) {
                if(o instanceof ghidra.program.model.lang.Register &&
                   ((ghidra.program.model.lang.Register)o).getName().equalsIgnoreCase("t0")) {
                    if(!t0Defined) traits.readsEabiArgT0 = true;
                }
            }
            if(traits.readsEabiArgT0) break;
            Object[] dop = inst.getOpObjects(0);
            String dr = (dop!=null && dop.length>0 && dop[0] instanceof ghidra.program.model.lang.Register)
                ? ((ghidra.program.model.lang.Register)dop[0]).getName() : null;
            if("t0".equalsIgnoreCase(dr)) t0Defined = true;
        }
    }

    // v10 Rule 145: PSMCT16 map-CLUT uploader. F50.8-F50.11: the dungeon map
    // texture subsystem (tbp=0x2580 / CLUT cbp=0x2980 PSMCT16) is separate from
    // mgCTextureManager and its PSMCT16 CLUT (dpsm=0x2) is NEVER transferred to
    // VRAM → empty CLUT → black. Only invoked for BITBLTBUF-writing functions
    // (0x02 is otherwise too common to be a useful signal on its own).
    private void detectPsmct16ClutUploader(Function func, FuncTraits traits) {
        InstructionIterator it = currentProgram.getListing().getInstructions(func.getBody(), true);
        while(it.hasNext()) {
            Instruction inst = it.next();
            String mn = inst.getMnemonicString(); if(mn == null) continue;
            String mll = mn.toLowerCase();
            if(mll.equals("ori")||mll.equals("addiu")||mll.equals("daddiu")||mll.equals("li")) {
                boolean srcZeroOrLi = mll.equals("li");
                long imm = -1;
                for(Object o : inst.getInputObjects()) {
                    if(o instanceof ghidra.program.model.lang.Register &&
                       ((ghidra.program.model.lang.Register)o).getName().equalsIgnoreCase("zero"))
                        srcZeroOrLi = true;
                    else if(o instanceof ghidra.program.model.scalar.Scalar)
                        imm = ((ghidra.program.model.scalar.Scalar)o).getUnsignedValue();
                }
                if(srcZeroOrLi && imm == 0x02L) { traits.loadsPsmct16Const = true; break; }
            }
        }
        if(traits.loadsPsmct16Const) traits.isPsmct16ClutUploader = true;
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

    // v19 Rules 244/245/248/250 scan-time facts (PCSX2 cross-check round 3):
    //  - Rule 244: a CHCR const with STR|TIE (bits 8|7 = 0x180) enables the
    //    tag-completion DMAC interrupt (PCSX2 Dmac.h TIE:1 + DMAtag IRQ:1).
    //  - Rule 245: a VIFcode with the i-bit (bit31) raises VIF STAT.INT (PCSX2
    //    Vif.h INT:1) - detected as a tracked const whose top byte has bit7 set.
    //  - Rule 248: EE cache-coherency ops (cache / sync.l / sync.p) - the DMA-to-
    //    RAM-then-execute / SMC hazard PCSX2 models in Cache.cpp.
    //  - Rule 250: TLB writers (tlbwi/tlbwr/tlbr/tlbp) - custom memory mapping a
    //    flat-address recompiler would break (statistic 0 = flat, the finding).
    private void detectV19Signals(Function func, FuncTraits traits) {
        InstructionIterator it = currentProgram.getListing().getInstructions(func.getBody(), true);
        Map<String,Long> regConsts = new HashMap<>();
        while(it.hasNext()) {
            Instruction inst = it.next();
            String mn = inst.getMnemonicString(); if(mn == null) continue;
            String mll = mn.toLowerCase();
            if(mll.equals("cache")) traits.hasCacheOp = true;
            else if(mll.equals("sync") || mll.equals("sync.l") || mll.equals("sync.p")) traits.hasSyncOp = true;
            else if(mll.equals("tlbwi") || mll.equals("tlbwr") || mll.equals("tlbr") || mll.equals("tlbp"))
                traits.writesTlb = true;
            // composite const tracking (lui high half + ori/addiu low half), same as
            // detectDmaSourceChainTagBuilder, so full 32-bit CHCR/VIFcode values recover.
            if(mll.equals("lui")) {
                Object[] dops = inst.getOpObjects(0);
                String dr = (dops!=null && dops.length>0 && dops[0] instanceof ghidra.program.model.lang.Register)
                    ? ((ghidra.program.model.lang.Register)dops[0]).getName() : null;
                long imm = -1;
                for(Object o : inst.getInputObjects())
                    if(o instanceof ghidra.program.model.scalar.Scalar)
                        imm = ((ghidra.program.model.scalar.Scalar)o).getUnsignedValue();
                if(dr != null && imm >= 0) regConsts.put(dr, (imm & 0xFFFFL) << 16);
            } else if(mll.equals("ori") || mll.equals("addiu") || mll.equals("li") || mll.equals("daddiu")) {
                Object[] dops = inst.getOpObjects(0);
                String dr = (dops!=null && dops.length>0 && dops[0] instanceof ghidra.program.model.lang.Register)
                    ? ((ghidra.program.model.lang.Register)dops[0]).getName() : null;
                String src = null; long imm = 0;
                for(Object o : inst.getInputObjects()) {
                    if(o instanceof ghidra.program.model.lang.Register) {
                        String rn = ((ghidra.program.model.lang.Register)o).getName();
                        if(!rn.equalsIgnoreCase(dr)) src = rn;
                    } else if(o instanceof ghidra.program.model.scalar.Scalar)
                        imm = ((ghidra.program.model.scalar.Scalar)o).getUnsignedValue();
                }
                if(dr != null) {
                    long base = (src != null && regConsts.containsKey(src)) ? regConsts.get(src)
                              : (regConsts.containsKey(dr) ? regConsts.get(dr) : 0L);
                    regConsts.put(dr, base | (imm & 0xFFFFL));
                }
            }
        }
        for(Long cb : regConsts.values()) {
            long v = cb & 0xFFFFFFFFL;
            // Rule 244: STR|TIE (0x180). Require both so a plain STR kick (0x100/0x101) is excluded.
            if((v & 0x180L) == 0x180L) traits.dmaChcrTie = true;
            // Rule 245: VIFcode i-bit = bit31 set with a plausible VIF cmd in the top byte.
            if((v & 0x80000000L) != 0L) traits.vifCodeIBit = true;
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
            // v11.3 Rule 162: fromSPR(8)/toSPR(9) DMA channel built via a tracked
            // lui/ori constant (e.g. SendDMA@0x13e3d0 stores gp-cached 0x1000D000).
            if(chIdx==8||chIdx==9) {
                traits.programsSprDma = true;
                traits.sprDmaChannels.add(DMA_CHANNEL_NAMES[chIdx]);
            }
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
            // v17.1 Rule 232: exact timer reg split (PCSX2 Hw.h RCNTn_COUNT/MODE/
            // TARGET/HOLD at +0x00/+0x10/+0x20/+0x30 per 0x800-stride timer).
            long tOff = norm & 0x7FFL;
            int timer = (int)((norm - RCNT_RANGE_START) >>> 11);
            if(timer >= 0 && timer <= 3){
                String rn = (tOff == 0x00) ? "COUNT" : (tOff == 0x10) ? "MODE"
                          : (tOff == 0x20) ? "TARGET" : (tOff == 0x30) ? "HOLD" : null;
                if(rn != null) traits.rcntRegsHit.add("T"+timer+"_"+rn);
            }
        }
        if((norm >= VIF0_CTRL_START && norm <= VIF0_CTRL_END) ||
           (norm >= VIF1_CTRL_START && norm <= VIF1_CTRL_END)) {
            traits.compositeMmioRangesHit.add("VIF_CTRL");
            traits.accessesVifCtrl = true;
        }
        if(norm >= DMAC_GLOBAL_START && norm <= DMAC_GLOBAL_END) {
            traits.compositeMmioRangesHit.add("DMAC_GLOBAL");
            traits.accessesDmacGlobal = true;
            // v17.1 Rules 226/227: exact DMAC-global reg split (PCSX2 Hw.h:
            // CTRL 0x1000E000, STAT E010, PCR E020, SQWC E030, RBSR E040
            // (MFIFO ring size), RBOR E050 (MFIFO ring base), STADR E060
            // (stall-control address)).
            switch((int)(norm & 0xF0L)){
                case 0x00: traits.dmacGlobalRegsHit.add("CTRL");  break;
                case 0x10: traits.dmacGlobalRegsHit.add("STAT");  break;
                case 0x20: traits.dmacGlobalRegsHit.add("PCR");   break;
                case 0x30: traits.dmacGlobalRegsHit.add("SQWC");  break;
                case 0x40: traits.dmacGlobalRegsHit.add("RBSR");  break;
                case 0x50: traits.dmacGlobalRegsHit.add("RBOR");  break;
                case 0x60: traits.dmacGlobalRegsHit.add("STADR"); break;
            }
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
                // v11 fix (General v15.5 Bugfix V): the $v1 constant is the
                // architectural dispatch number on the EE and MUST win. The
                // old code let any scalar in the syscall instruction's input
                // objects overwrite it - Ghidra reports a spurious constant
                // there, which mapped EVERY trampoline to imm 0x02 on the Jak
                // ELFs (li v1,0x74 / 0x5a / 0x5b all reported 0x02). The
                // encoded code field is only a fallback when $v1 is unknown.
                Long v1 = regConsts.get("v1");
                if(v1 != null && v1 > 0) {
                    syscallImm = v1 & 0xFFL;
                } else {
                    for(Object o : inst.getInputObjects())
                        if(o instanceof ghidra.program.model.scalar.Scalar) {
                            long s = ((ghidra.program.model.scalar.Scalar)o).getUnsignedValue();
                            if(s > 0 && s <= 0xFFL) syscallImm = s;
                        }
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
        // v11 (General v13): also require ZERO stores. A true idle/poll spin
        // writes nothing; counted copy/clear loops (memcpy/memset/strcpy
        // shapes) store every iteration. SF3 benchmark: the old rule emitted
        // NOP-patch candidates for the backward branch of u16-copy and
        // word-clear loops, which would corrupt data if an engineer enabled
        // them.
        if(traits.storeOps == 0 &&
           ((branchCount <= 2 && selfBranchSeen) ||
            (backwardBranchSeen && !returnSeen && traits.byteSize > 0)))
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
        Set<Long> adRegIdsStored = new LinkedHashSet<>(); // v11: distinct GS reg-id store evidence
        Set<Long> allConsts = new LinkedHashSet<>();       // v18 Rule 234: every tracked immediate
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
                if(dr != null && imm >= 0) { regConsts.put(dr, imm); allConsts.add(imm); }
            } else if(mll.equals("sd") || mll.equals("sw") || mll.equals("sq")) {
                Object[] dop = inst.getOpObjects(0);
                String src = (dop!=null && dop.length>0 && dop[0] instanceof ghidra.program.model.lang.Register)
                    ? ((ghidra.program.model.lang.Register)dop[0]).getName() : null;
                if(src != null && regConsts.containsKey(src)) {
                    long v = regConsts.get(src);
                    if(v <= 0x6CL) adRegIdsStored.add(v);
                }
            }
        }
        // v11 (General v13): storing a register that happens to hold 0 or 1
        // is among the most common operations in compiled code (`flag = 1`,
        // `ptr = NULL`), so a single hit is meaningless - SF3 benchmark
        // tagged 464 functions (incl. sceMcInit) as RGBAQ writers. A real
        // A+D packet builder stores several distinct GS register ids
        // (PRIM+RGBAQ+XYZ2, BITBLTBUF+TRXPOS+TRXREG+TRXDIR). Require >=2
        // distinct ids, or independent GIF-tag evidence in the same function,
        // before stamping the writer flags.
        if(adRegIdsStored.size() >= 2 || traits.gifTagInlineBuilder ||
           traits.bitbltbufMacroSequence) {
            if(adRegIdsStored.contains(0x00L)) traits.writesGsPrimReg = true;
            if(adRegIdsStored.contains(0x01L)) traits.writesRgbaqReg = true;
            if(adRegIdsStored.contains(0x06L) || adRegIdsStored.contains(0x07L)) traits.writesTex0Reg = true;
            if(adRegIdsStored.contains(0x4EL) || adRegIdsStored.contains(0x4FL)) traits.writesZbufReg = true;
            if(adRegIdsStored.contains(0x59L) || adRegIdsStored.contains(0x5BL)) traits.writesDispfbReg = true;
            if(adRegIdsStored.contains(0x50L)) traits.writesBitbltbufReg = true;
            // v12 Rule 166: FRAME A+D reg ids
            if(adRegIdsStored.contains(0x4CL) || adRegIdsStored.contains(0x4DL)) traits.writesFrameReg = true;
            // v15 Rule 192: XYZ2 (0x05 draw-kick) / XYZ3 (0x0D no-kick / strip-restart).
            if(adRegIdsStored.contains(0x05L)) traits.writesXyz2Reg = true;
            if(adRegIdsStored.contains(0x0DL)) traits.writesXyz3Reg = true;
            // v15.1 Rule 201: TEX1_1/TEX1_2 (0x14/0x15) texture filter (G8 point-sampling).
            if(adRegIdsStored.contains(0x14L) || adRegIdsStored.contains(0x15L)) traits.writesTex1Reg = true;
            // v15.1 Rule 200: XYOFFSET_1/2 (0x18/0x19) guard-band centre (G88).
            if(adRegIdsStored.contains(0x18L) || adRegIdsStored.contains(0x19L)) traits.writesXyoffsetReg = true;
            // v17.1 Rule 230: PRMODECONT (0x1A) / PRMODE (0x1B) - attribute-source select.
            if(adRegIdsStored.contains(0x1AL)) traits.writesPrmodecontReg = true;
            if(adRegIdsStored.contains(0x1BL)) traits.writesPrmodeReg = true;
            // v17.1 Rule 231: TEXA (0x3B) alpha expansion / CLAMP_1/2 (0x08/0x09) region wrap.
            if(adRegIdsStored.contains(0x3BL)) traits.writesTexaReg = true;
            if(adRegIdsStored.contains(0x08L) || adRegIdsStored.contains(0x09L)) traits.writesClampReg = true;
            // v17.1 Rule 229: TRXDIR (0x53) writer - direction value (0 up / 1 down)
            // is not statically proven here; the readback post-pass requires an
            // additional BUSDIR / VIF-CTRL signal before flagging.
            if(adRegIdsStored.contains(0x53L)) traits.storesTrxdirLocalToHost = true;
            // v18 Rule 240: ALPHA (0x42) blend + TEST_1/2 (0x47/0x48) alpha-test writers —
            // the GPU-raster eligibility axes (G161: title tris all had blend AND atest).
            if(adRegIdsStored.contains(0x42L)) traits.writesAlphaBlendReg = true;
            if(adRegIdsStored.contains(0x47L) || adRegIdsStored.contains(0x48L)) traits.writesTestReg = true;
            for(Long v : adRegIdsStored) {
                String nm = KNOWN_GS_REGS.get(v);
                if(nm != null) traits.gsRegHits.add(nm);
            }
        }
        // v18 Rule 234: per-emitter GIF PRIM-class census (the G171 miss — inline SPRITE
        // raster was the dominant title cost, invisible to triangle-only instrumentation).
        // Gate on being a real draw builder, then read PRIM-shaped constants. A PRIM value
        // is 11 bits; prim class = bits[0:2]. Require an attribute bit (IIP/TME/ABE/FGE =
        // bits 3/4/6, mask 0x78) set so bare A+D reg-ids (0x03..0x07) are NOT mistaken for
        // a PRIM value (e.g. reg-id 0x06 TEX0 vs PRIM class 6 sprite).
        if(traits.gifTagInlineBuilder || traits.writesGsPrimReg) {
            for(Long cb : allConsts) {
                long v = cb & 0xFFFFFFFFL;
                if(v == 0 || v > 0x7FFL) continue;
                if((v & 0x78L) == 0) continue;            // no attribute bit -> likely a reg-id
                long cls = v & 7L;
                if(cls < 3 || cls > 6) continue;          // triangle/tristrip/trifan/sprite only
                traits.primClassesEmitted.add(GIF_PRIM_CLASS[(int)cls]);
                if(cls == 6L) traits.isSpriteEmitter = true;
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

    // =========================================================
    // v12 Rules 165-177: RTT/Z VRAM-alias map, audio/memcard/present
    // hazards, CLUT cache ops, perf-hot ranking. Derived from already-
    // collected traits + BFS depths; appends tags, bumps counters, and
    // builds the cross-function VRAM overlap pairs.
    // =========================================================
    private void applyV12Rules(List<FuncResult> results) {
        // Pass 1: per-function derivations + collect VRAM page writers by kind.
        for(FuncResult r : results) {
            FuncTraits t = r.traits;
            if(t == null) continue;
            String nm = r.name == null ? "" : r.name;

            // VRAM pages this func references (labelled subset only).
            for(Long c : t.tbpConstantsLoaded) {
                if(KNOWN_DC2_TBP_LABELS.containsKey(c)) {
                    t.vramKnownPagesHit.add(c);
                    gsLocalMemPagesReferenced.add(c);
                }
            }
            // Writer kinds for the overlap map.
            List<String> kinds = new ArrayList<>();
            if(t.writesFrameReg)     { kinds.add("FRAME"); frameRegWriterCount++; }
            if(t.writesZbufReg)        kinds.add("ZBUF");
            if(t.writesTex0Reg)        kinds.add("TEX0");
            if(t.writesBitbltbufReg)   kinds.add("BITBLTBUF");
            if(t.writesDispfbReg)      kinds.add("DISPFB");
            for(Long page : t.vramKnownPagesHit) {
                Map<String,List<String>> byKind =
                    vramPageWriters.computeIfAbsent(page, k -> new LinkedHashMap<>());
                for(String kind : kinds)
                    byKind.computeIfAbsent(kind, k -> new ArrayList<>()).add(nm);
            }

            // Rule 166 RTT_TARGET: FRAME writer that references a labelled tex/CLUT/RTT page.
            if(t.writesFrameReg && !t.vramKnownPagesHit.isEmpty()) {
                t.isRttTarget = true;
                if(!r.tags.contains("RTT_TARGET")) { r.tags.add("RTT_TARGET"); rttTargetCount++; }
            }
            // Rule 167 ZBUF_VRAM_ALIAS_RISK: ZBUF writer referencing a labelled live VRAM page.
            if(t.writesZbufReg && !t.vramKnownPagesHit.isEmpty()) {
                t.zbufVramAliasRisk = true;
                if(!r.tags.contains("ZBUF_VRAM_ALIAS_RISK")) {
                    r.tags.add("ZBUF_VRAM_ALIAS_RISK"); zbufVramAliasCount++;
                }
            }
            // Rule 169 VF0_DEPENDENT_INVERSE: matrix-inverse helper using COP2 + EFU Q latency.
            boolean efuQ = t.cop2SpecialOps.contains("EFU_Q_LATENCY") || t.usesFpuDivSqrt;
            if(nm.contains("Invers") && t.usesCop2 && efuQ) {
                t.isVf0DependentInverse = true;
                if(!r.tags.contains("VF0_DEPENDENT_INVERSE")) {
                    r.tags.add("VF0_DEPENDENT_INVERSE"); vf0DependentInverseCount++;
                }
            }
            // Rule 170 AUDIO_COMPLETION_GATE: wait loop polling an audio/stream completion signal.
            for(String cn : t.calleeNames) {
                String lc = cn.toLowerCase();
                if(cn.contains("sceSifCheckStatRpc") || lc.contains("streamopenstate")
                   || lc.contains("voice") || lc.contains("streamstat")
                   || cn.startsWith("sceSd") || cn.startsWith("sceSpu2"))
                    t.audioGateSignals.add(cn);
            }
            if(t.isAudioRpcHandler) t.audioGateSignals.add("audio_rpc_handler");
            boolean waitShape = t.isSyncWaitLoop || t.dc2HostWaitCandidate
                    || (t.hasBackwardBranch && t.byteSize < 400);
            if(!t.audioGateSignals.isEmpty() && waitShape) {
                t.isAudioCompletionGate = true;
                if(!r.tags.contains("AUDIO_COMPLETION_GATE")) {
                    r.tags.add("AUDIO_COMPLETION_GATE"); audioCompletionGateCount++;
                }
                if(t.dc2HostWaitCandidate && !r.tags.contains("DC2_AUDIO_GATED_STALL"))
                    r.tags.add("DC2_AUDIO_GATED_STALL");
            }
            // Rule 171 MEMCARD_IO: sceMc*/libmc save-data callee.
            for(String cn : t.calleeNames) {
                String lc = cn.toLowerCase();
                if(cn.startsWith("sceMc") || lc.contains("libmc")
                   || lc.startsWith("mclib") || lc.contains("memcard")
                   || lc.contains("mccard") || lc.contains("savedata"))
                    t.memcardCallees.add(cn);
            }
            if(!t.memcardCallees.isEmpty()) {
                t.isMemcardIo = true;
                if(!r.tags.contains("MEMCARD_IO")) { r.tags.add("MEMCARD_IO"); memcardIoCount++; }
            }
            // Rule 173 PRESENTATION_FIELD_STATE: interlace/field GS privileged reg.
            for(String pr : t.gsPrivRegHits) {
                if(pr.equals("PMODE") || pr.equals("SMODE1") || pr.equals("SMODE2")
                   || pr.equals("CSR") || pr.equals("SYNCV"))
                    t.presentationRegs.add(pr);
            }
            if(!t.presentationRegs.isEmpty()) {
                t.writesPresentationFieldState = true;
                if(!r.tags.contains("PRESENTATION_FIELD_STATE")) {
                    r.tags.add("PRESENTATION_FIELD_STATE"); presentationFieldStateCount++;
                }
            }
            // Rule 174 DISPLAY_BUFFER_FLIP: DISPFB writer that drives the present boundary.
            if(t.writesDispfbReg && (t.isFrameClockDriver || t.isRenderFrameEntry)) {
                t.isDisplayBufferFlip = true;
                if(!r.tags.contains("DISPLAY_BUFFER_FLIP")) {
                    r.tags.add("DISPLAY_BUFFER_FLIP"); displayBufferFlipCount++;
                }
            }
            // Rule 175 CLUT_CACHE_INVALIDATOR: TEXFLUSH or TEX0 write touching a CLUT page.
            boolean clutPage = false;
            for(Long page : t.vramKnownPagesHit) {
                String lbl = KNOWN_DC2_TBP_LABELS.get(page);
                if(lbl != null && lbl.toUpperCase().contains("CLUT")) { clutPage = true; break; }
            }
            if(t.gsRegHits.contains("TEXFLUSH") || (t.writesTex0Reg && clutPage)) {
                t.isClutCacheInvalidator = true;
                if(!r.tags.contains("CLUT_CACHE_INVALIDATOR")) {
                    r.tags.add("CLUT_CACHE_INVALIDATOR"); clutCacheInvalidatorCount++;
                }
            }
            // Rule 176 PERF_HOT_FRAME_PATH: shallow mainloop reach + inner loop + fan-out.
            if(t.mainLoopDepth >= 0 && t.mainLoopDepth <= 3
               && t.hasBackwardBranch && t.calleeCount >= 8) {
                t.isPerfHotFramePath = true;
                if(!r.tags.contains("PERF_HOT_FRAME_PATH")) {
                    r.tags.add("PERF_HOT_FRAME_PATH"); perfHotFramePathCount++;
                }
            }
        }

        // Pass 2: Rule 165 VRAM_OVERLAP_MAP — pages targeted by >=2 differing kinds.
        for(Map.Entry<Long,Map<String,List<String>>> e : vramPageWriters.entrySet()) {
            long page = e.getKey();
            Map<String,List<String>> byKind = e.getValue();
            if(byKind.size() < 2) continue;
            String label = KNOWN_DC2_TBP_LABELS.getOrDefault(page, "");
            List<String> kindList = new ArrayList<>(byKind.keySet());
            for(int i=0;i<kindList.size();i++) {
                for(int j=i+1;j<kindList.size();j++) {
                    String ka = kindList.get(i), kb = kindList.get(j);
                    String cls;
                    boolean aTarget = ka.equals("FRAME")||ka.equals("ZBUF")||ka.equals("DISPFB");
                    boolean bUpload = kb.equals("TEX0")||kb.equals("BITBLTBUF");
                    boolean bTarget = kb.equals("FRAME")||kb.equals("ZBUF")||kb.equals("DISPFB");
                    boolean aUpload = ka.equals("TEX0")||ka.equals("BITBLTBUF");
                    if(ka.equals("ZBUF")||kb.equals("ZBUF")) cls = "Z_ALIAS";
                    else if((aTarget&&bUpload)||(bTarget&&aUpload)) cls = "RTT_ALIAS";
                    else cls = "TIMESHARE";
                    String fa = byKind.get(ka).get(0);
                    String fb = byKind.get(kb).get(0);
                    vramOverlapPairs.add(new String[]{
                        hex(page), label, ka, fa, kb, fb, cls });
                }
            }
        }
        println(String.format(
            "  v12: RTT_TARGET=%d ZBUF_ALIAS=%d VRAM_OVERLAP=%d VF0_INV=%d AUDIO_GATE=%d "
          + "MEMCARD=%d PRESENT_FIELD=%d DBUF_FLIP=%d CLUT_CACHE=%d PERF_HOT=%d FRAME_W=%d GSMEM_PAGES=%d",
            rttTargetCount, zbufVramAliasCount, vramOverlapPairs.size(), vf0DependentInverseCount,
            audioCompletionGateCount, memcardIoCount, presentationFieldStateCount,
            displayBufferFlipCount, clutCacheInvalidatorCount, perfHotFramePathCount,
            frameRegWriterCount, gsLocalMemPagesReferenced.size()));
    }

    // =========================================================
    // v13 Rules 178-188: DC2 G53-G82 title-3D retrospective.
    // Render-mode selectors, per-vertex lighting terms, vtable
    // tail-call thunks, RTT-no-restore leaks, VU-flag uploaders,
    // PACKED-RGBAQ builders, frame-resume risk, and the
    // cross-function init-order hazard graph. Derived from traits
    // already collected (Rules 178/181 are filled in the scan).
    // =========================================================
    private void applyV13Rules(List<FuncResult> results) {
        // Name fragments anchoring the G75-G82 render-mode + lighting paths.
        final String[] CLIP_CALLEES   = { "ClipInBox", "ClipBox", "mgClip" };
        final String[] RMODE_NAMES    = { "CreateRenderInfoPacket", "mgFlushRenderInfo",
            "Draw__12mgCVisualMDT", "Draw__8mgCFrame", "Draw__9CMapParts", "DrawSub__4CMap", "Draw__4CMap" };
        final String[] LIGHT_CALLEES  = { "GetLightInfo", "mgSetLight", "mgSetAmbient",
            "mgSetFogParam", "SetFogParam", "LightColorMatrix", "SetLight", "SetAmbient" };
        final String[] LIGHT_NAMES    = { "DrawSub__4CMap", "Draw__9CMapParts", "Draw__4CMap" };

        for(FuncResult r : results) {
            FuncTraits t = r.traits; if(t == null) continue;
            String nm = r.name == null ? "" : r.name;

            // Rule 178 (set in scan): tag + counter + feed init-order readers.
            if(t.isConditionalInitOnGlobal) {
                if(!r.tags.contains("CONDITIONAL_INIT_ON_GLOBAL")) {
                    r.tags.add("CONDITIONAL_INIT_ON_GLOBAL"); conditionalInitOnGlobalCount++;
                }
                for(String g : t.guardGlobals)
                    initGlobalReaders.computeIfAbsent(g, k -> new ArrayList<>()).add(nm);
            }
            // Rule 181 (set in scan): tag + counter + roster.
            if(t.isVtableTailcallThunk) {
                if(!r.tags.contains("VTABLE_TAILCALL_THUNK")) {
                    r.tags.add("VTABLE_TAILCALL_THUNK"); vtableTailcallThunkCount++;
                }
                StringBuilder sl = new StringBuilder();
                for(Long s : t.tailcallVtableSlots) { if(sl.length()>0) sl.append("|"); sl.append(hex(s)); }
                vtableTailcallThunks.add(new String[]{ nm, hex(r.address), sl.toString() });
            }
            // Rule 179 RENDER_MODE_SELECTOR: calls a clip-test discriminator (and stores),
            // or is one of the known render-mode submit functions.
            boolean callsClip = false;
            for(String cn : t.calleeNames) for(String f : CLIP_CALLEES) if(cn.contains(f)) callsClip = true;
            boolean rmodeName = false; for(String f : RMODE_NAMES) if(nm.contains(f)) rmodeName = true;
            if((callsClip && (t.writesToGlobal || t.isStructInitializer || t.gifTagInlineBuilder)) || rmodeName) {
                t.isRenderModeSelector = true;
                if(!r.tags.contains("RENDER_MODE_SELECTOR")) {
                    r.tags.add("RENDER_MODE_SELECTOR"); renderModeSelectorCount++;
                }
                renderModeSelectors.add(new String[]{ nm, hex(r.address), callsClip ? "clip_test" : "submit" });
            }
            // Rule 180 VERTEX_LIGHTING_NORMAL_TERM: lighting-setup callee, or a COP2
            // outer-product/dot feeding a vertex-colour writer, in a draw context.
            boolean callsLight = false;
            for(String cn : t.calleeNames) for(String f : LIGHT_CALLEES) if(cn.contains(f)) { callsLight = true; t.lightingSources.add(cn); }
            boolean cop2Dot = t.usesCop2 && (t.cop2SpecialOps.contains("OUTER_PRODUCT") || t.writesRgbaqReg);
            boolean lightName = false; for(String f : LIGHT_NAMES) if(nm.contains(f)) lightName = true;
            if(callsLight || (cop2Dot && (t.writesRgbaqReg || lightName)) || (lightName && t.usesCop2)) {
                t.isVertexLightingTerm = true;
                if(!r.tags.contains("VERTEX_LIGHTING_NORMAL_TERM")) {
                    r.tags.add("VERTEX_LIGHTING_NORMAL_TERM"); vertexLightingTermCount++;
                }
                String src = t.lightingSources.isEmpty() ? (cop2Dot ? "cop2_dot" : "draw_chain")
                                                          : String.join("|", t.lightingSources);
                vertexLightingTerms.add(new String[]{ nm, hex(r.address), src });
            }
            // Rule 182 RTT_NO_RESTORE: an RTT writer that targets an RTT/texture page but
            // never writes a display-buffer FRAME (0x0/0x68) back in the same body.
            if(t.isRttTarget) {
                boolean writesDisplayPage = false;
                for(Long p : t.vramKnownPagesHit) {
                    String lbl = KNOWN_DC2_TBP_LABELS.get(p);
                    if(p == 0x68L || p == 0x0L || (lbl != null && lbl.contains("DBuff"))) writesDisplayPage = true;
                }
                if(!writesDisplayPage) {
                    t.isRttNoRestore = true;
                    if(!r.tags.contains("RTT_NO_RESTORE")) {
                        r.tags.add("RTT_NO_RESTORE"); rttNoRestoreCount++;
                    }
                    rttNoRestoreFuncs.add(new String[]{ nm, hex(r.address), "rtt_target_no_display_fbp" });
                }
            }
            // Rule 184 VU_FLAG_PIPELINE_UPLOADER: VU microcode upload site (advisory).
            if(t.isMicrocodeUploader || nm.contains("SendVuProg") || nm.contains("VuProg")
               || t.vifOpcodesBuilt.contains("MPG")) {
                t.isVuFlagPipelineUploader = true;
                if(!r.tags.contains("VU_FLAG_PIPELINE_UPLOADER")) {
                    r.tags.add("VU_FLAG_PIPELINE_UPLOADER"); vuFlagPipelineUploaderCount++;
                }
                vuFlagPipelineUploaders.add(new String[]{ nm, hex(r.address),
                    t.isMicrocodeUploader ? "microcode_uploader" : "vuprog_name" });
            }
            // Rule 187 PACKED_RGBAQ_BUILDER: inline GIFtag builder that writes RGBAQ.
            if(t.gifTagInlineBuilder && t.writesRgbaqReg) {
                t.isPackedRgbaqBuilder = true;
                if(!r.tags.contains("PACKED_RGBAQ_BUILDER")) {
                    r.tags.add("PACKED_RGBAQ_BUILDER"); packedRgbaqBuilderCount++;
                }
                packedRgbaqBuilders.add(new String[]{ nm, hex(r.address), "verify_spread_layout" });
            }
            // Rule 188 FRAME_RESUME_RISK: large draw/frame func with terminal indirect flow.
            if(t.byteSize > 1500 && (t.isRenderFrameEntry
                    || (t.drawingChainDepth >= 0 && t.drawingChainDepth <= 6))
                    && (t.tailCallIndirect || t.isVtableTailcallThunk)) {
                t.isFrameResumeRisk = true;
                if(!r.tags.contains("FRAME_RESUME_RISK")) {
                    r.tags.add("FRAME_RESUME_RISK"); frameResumeRiskCount++;
                }
                frameResumeRiskFuncs.add(new String[]{ nm, hex(r.address), "large_resumable_draw" });
            }

            // Rule 186: collect init-order writers (normal vs __sinit) by global token.
            boolean isSinit = t.isStaticInitializer || t.isUncalledStaticInit;
            Set<String> writeTokens = new LinkedHashSet<>();
            for(Long a : t.returnWrittenToGlobals) writeTokens.add("0x" + Long.toHexString(a & 0xFFFFFFFFL));
            for(Long a : t.ctorGlobalAddresses)    writeTokens.add("0x" + Long.toHexString(a & 0xFFFFFFFFL));
            for(long[] inst : t.staticInitInstalls) writeTokens.add("0x" + Long.toHexString(inst[1] & 0xFFFFFFFFL));
            if(t.isStructInitializer || t.isCtor || isSinit)
                for(String lbl : t.dc2GlobalsTouched) writeTokens.add(lbl);
            for(String tok : writeTokens)
                (isSinit ? initGlobalSinitWriters : initGlobalWriters)
                    .computeIfAbsent(tok, k -> new ArrayList<>()).add(nm);
        }

        // Rule 186 pass 2: a guard-read global whose only writer is a __sinit (or which has
        // no normal writer at all) is an init-ordering hazard (G58/G81 headless gap).
        for(Map.Entry<String,List<String>> e : initGlobalReaders.entrySet()) {
            String tok = e.getKey();
            List<String> normal = initGlobalWriters.get(tok);
            List<String> sinit  = initGlobalSinitWriters.get(tok);
            boolean hasNormal = normal != null && !normal.isEmpty();
            if(sinit != null && !sinit.isEmpty()) {
                for(String reader : e.getValue())
                    initOrderHazards.add(new String[]{ tok, reader, sinit.get(0), "__sinit" });
            } else if(!hasNormal) {
                for(String reader : e.getValue())
                    initOrderHazards.add(new String[]{ tok, reader, "(none-found)", "no_static_writer" });
            }
        }

        println(String.format(
            "  v13: COND_INIT=%d RENDER_MODE=%d VTX_LIGHT=%d VTABLE_TAILCALL=%d RTT_NO_RESTORE=%d "
          + "VU_FLAG_UP=%d PACKED_RGBAQ=%d FRAME_RESUME=%d INIT_ORDER_HAZARD=%d",
            conditionalInitOnGlobalCount, renderModeSelectorCount, vertexLightingTermCount,
            vtableTailcallThunkCount, rttNoRestoreCount, vuFlagPipelineUploaderCount,
            packedRgbaqBuilderCount, frameResumeRiskCount, initOrderHazards.size()));
    }

    // =========================================================
    // v15 Rules 190-198: DC2 G83-G115 retrospective + general PS2
    // ADC/PRIM-class packer, allocator-family coherence, frame-pacing,
    // view-matrix, object-array ctor, VU-exec hazard manifest. The
    // firewalled per-func booleans (190/191/196/197) were set in the
    // scan (detectV15Signals); this pass adds tags/counters/rosters and
    // derives the non-firewalled rules (192/193/195/194/184+).
    // =========================================================
    private void applyV15Rules(List<FuncResult> results) {
        // Texture-manager name fragments anchoring the G90-G97 reload-interleave path.
        final String[] TEXMGR_NAMES = { "TextureManager", "TexCache", "Reload", "BindTex",
            "SetTexture", "mgCTexture", "LoadTexture", "TexReload" };
        // Allocator-family member names (Rule 194). Match by exact-equals on the symbol.
        final java.util.Set<String> ALLOC_FAMILY = new java.util.HashSet<>(java.util.Arrays.asList(
            "malloc", "_malloc_r", "_malloc", "free", "_free_r", "_free",
            "realloc", "_realloc_r", "_realloc", "reallocf", "calloc", "_calloc_r", "_calloc",
            "memalign", "_memalign_r", "valloc", "_valloc_r",
            "__nw__FUi", "__nwa__FUi", "__dl__FPv", "__dla__FPv", "__nw__", "__dl__"));

        for(FuncResult r : results) {
            FuncTraits t = r.traits; if(t == null) continue;
            String nm = r.name == null ? "" : r.name;

            // Rule 190 GIFTAG_PRIM_CLASS_SELECTOR (set in scan): tag + roster.
            if(t.isPrimClassSelector) {
                if(!r.tags.contains("GIFTAG_PRIM_CLASS_SELECTOR")) {
                    r.tags.add("GIFTAG_PRIM_CLASS_SELECTOR"); primClassSelectorCount++;
                }
                // DC2 anchor carries the decoded bit formula; others carry the VU selector addr.
                String detail = ((r.address & 0xFFFFFFFFL) == 0x1404d0L)
                    ? "qword38: bit0=fc0||fc4,bit1=fc4,bit2=desc+0x2c,bit3=desc+0x40&1,bit4=fc8"
                    : "vu_selector_qword";
                primClassSelectors.add(new String[]{ nm, hex(r.address), detail });
            }
            // Rule 191 ADC_KICK_VERTEX_SOURCE (set in scan): tag + roster.
            if(t.isAdcKickVertexSource) {
                adcKickVertexSourceCount++;
                if(!r.tags.contains("ADC_KICK_VERTEX_SOURCE")) r.tags.add("ADC_KICK_VERTEX_SOURCE");
                adcKickSources.add(new String[]{ nm, hex(r.address),
                    t.adcSource == null ? "constant_kick" : t.adcSource });
            }
            // Rule 192 XYZ2_VS_XYZ3_KICK_WRITER: a per-vertex draw-kick / no-kick writer.
            if(t.writesXyz3Reg || (t.writesXyz2Reg && (t.gifTagInlineBuilder || t.writesXyz3Reg))) {
                t.isKickModeWriter = true;
                if(!r.tags.contains("XYZ2_VS_XYZ3_KICK_WRITER")) {
                    r.tags.add("XYZ2_VS_XYZ3_KICK_WRITER"); kickModeWriterCount++;
                }
                String mode = (t.writesXyz2Reg && t.writesXyz3Reg) ? "xyz2+xyz3(restart_control)"
                            : t.writesXyz3Reg ? "xyz3(no_kick)" : "xyz2(draw_kick)";
                kickModeWriters.add(new String[]{ nm, hex(r.address), mode });
            }
            // Rule 193 TEXTURE_RELOAD_INTERLEAVE_HAZARD: bind-many-then-draw-many shape.
            boolean texmgrName = false;
            for(String f : TEXMGR_NAMES) if(nm.contains(f)) { texmgrName = true; break; }
            boolean drawKickEvidence = t.gifTagInlineBuilder || t.path3Initiator
                || t.path3KickViaDmaApi || t.indirectCallT9Count > 0 || !t.dmaKickChannels.isEmpty();
            if(t.writesTex0Reg && t.hasBackwardBranch && (drawKickEvidence || texmgrName)) {
                t.isTextureReloadInterleave = true;
                if(!r.tags.contains("TEXTURE_RELOAD_INTERLEAVE_HAZARD")) {
                    r.tags.add("TEXTURE_RELOAD_INTERLEAVE_HAZARD"); textureReloadInterleaveCount++;
                }
                textureReloadInterleave.add(new String[]{ nm, hex(r.address),
                    texmgrName ? "texmgr_per_block_reload" : "tex0_loop_with_draws" });
            }
            // Rule 195 VSYNC_COUPLED_GAME_STEP: game-state advance + frame-completion wait.
            boolean waitsFrame = t.isFrameClockDriver || t.isRenderFrameEntry;
            if(!waitsFrame) for(String cn : t.calleeNames) {
                if(cn.contains("sceGsSyncV") || cn.contains("WaitVSync") || cn.contains("mgEndFrame")
                   || cn.contains("FlipDrawEnv") || cn.contains("SwapDBuff")) { waitsFrame = true; break; }
            }
            boolean advancesState = t.writesToGlobal && (t.calleeCount >= 4 || t.hasBackwardBranch);
            if(waitsFrame && advancesState && t.mainLoopDepth >= 0 && t.mainLoopDepth <= 4) {
                t.isVsyncCoupledGameStep = true;
                if(!r.tags.contains("VSYNC_COUPLED_GAME_STEP")) {
                    r.tags.add("VSYNC_COUPLED_GAME_STEP"); vsyncCoupledGameStepCount++;
                }
                framePacingDrivers.add(new String[]{ nm, hex(r.address),
                    "depth=" + t.mainLoopDepth + " callees=" + t.calleeCount });
            }
            // Rule 196 VIEW_PROJECTION_MATRIX_WRITER (set in scan): tag + roster.
            if(t.isViewProjectionMatrixWriter) {
                if(!r.tags.contains("VIEW_PROJECTION_MATRIX_WRITER")) {
                    r.tags.add("VIEW_PROJECTION_MATRIX_WRITER"); viewProjectionWriterCount++;
                }
                viewProjectionWriters.add(new String[]{ nm, hex(r.address),
                    "shared_view_proj(not_world)" });
            }
            // Rule 197 OBJECT_ARRAY_CTOR (set in scan): tag + roster.
            if(t.isObjectArrayCtor) {
                if(!r.tags.contains("OBJECT_ARRAY_CTOR")) {
                    r.tags.add("OBJECT_ARRAY_CTOR"); objectArrayCtorCount++;
                }
                objectArrayCtors.add(new String[]{ nm, hex(r.address),
                    t.readsEabiArgT0 ? "array_ctor_count_in_t0" : "ctor_loop" });
            }
            // Rule 184+ VU_EXEC_HAZARD_MANIFEST: per-func interpreter-divergence checklist.
            if(t.cop2SpecialOps.contains("EFU_Q_LATENCY")) t.vuExecHazards.add("Q_LATENCY");
            if(t.isVuFlagPipelineUploader) {
                t.vuExecHazards.add("MAC_STATUS_FLAGS");
                // v15.1: an uploaded VU program the EE script cannot scan may use either
                // EFU pipeline. PCSX2 VUops.cpp: Q (div/sqrt/rsqrt) and P (ESADD/ELENG/
                // ESIN/EEXP/ERSQRT...) both latch late; reading before WAITQ/WAITP gives a
                // stale value (the G87 class). Flag both for verification.
                t.vuExecHazards.add("Q_LATENCY");
                t.vuExecHazards.add("P_LATENCY");
            }
            if(t.isVf0DependentInverse)                    t.vuExecHazards.add("VF0_W_ONE");
            if(t.cop2DestMaskVerify)                       t.vuExecHazards.add("DESTMASK_LANE_ORDER");
            if(t.usesFpuDivSqrt || !t.cop2SpecialOps.isEmpty()) t.vuExecHazards.add("FLOAT_CLAMP");
            // v15.2 Rule 204: CFC2/CTC2 control-reg map is the F51.8 silent-wrong class.
            if(t.usesCop2ControlReg)                       t.vuExecHazards.add("CONTROL_REG_MAP");
            if(!t.vuExecHazards.isEmpty())
                vuExecHazardManifest.add(new String[]{ nm, hex(r.address),
                    String.join("|", t.vuExecHazards) });

            // Rule 199 VIF_UNPACK_DECOMPRESS_STATE (PCSX2 Vif_Unpack.cpp): gated on
            // independent VIF evidence, the decompression-critical commands (STMOD/STMASK/
            // STROW/STCOL) mean the runtime VIF must honour mode+mask+row+col or the
            // unpacked vertex/colour stream is corrupt.
            boolean vifEvidence = !t.vifOpcodesBuilt.isEmpty() || !t.storedVifOpcodes.isEmpty()
                || t.accessesVif1MMIO || t.isMicrocodeUploader || t.isVu1DoubleBufferFramer;
            boolean decompressCritical = t.vifUnpackStateCmds.contains("STMOD")
                || t.vifUnpackStateCmds.contains("STMASK")
                || t.vifUnpackStateCmds.contains("STROW")
                || t.vifUnpackStateCmds.contains("STCOL");
            if(vifEvidence && decompressCritical) {
                t.isVifUnpackDecompressState = true;
                if(!r.tags.contains("VIF_UNPACK_DECOMPRESS_STATE")) {
                    r.tags.add("VIF_UNPACK_DECOMPRESS_STATE"); vifUnpackDecompressCount++;
                }
                vifUnpackDecompressState.add(new String[]{ nm, hex(r.address),
                    String.join("|", t.vifUnpackStateCmds) });
            }
            // Rule 200 GS_XYOFFSET_GUARD_BAND (PCSX2 GSRegs.h XYOFFSET): guard-band centre (G88).
            if(t.writesXyoffsetReg) {
                t.isXyoffsetGuardWriter = true;
                if(!r.tags.contains("GS_XYOFFSET_GUARD_BAND")) {
                    r.tags.add("GS_XYOFFSET_GUARD_BAND"); xyoffsetGuardWriterCount++;
                }
                xyoffsetGuardWriters.add(new String[]{ nm, hex(r.address),
                    t.kickConstAddCount > 0 ? "with_kick_const_add" : "guard_band_offset" });
            }
            // Rule 201 GS_TEX1_FILTER_WRITER (PCSX2 GSRegs.h TEX1): MMAG/MMIN filter (G8).
            if(t.writesTex1Reg) {
                t.isTex1FilterWriter = true;
                if(!r.tags.contains("GS_TEX1_FILTER_WRITER")) {
                    r.tags.add("GS_TEX1_FILTER_WRITER"); tex1FilterWriterCount++;
                }
                tex1FilterWriters.add(new String[]{ nm, hex(r.address), "mmag_mmin_filter_mode" });
            }
            // Rule 203 MMI_SIMD_OP (skill silent-wrong codegen class): roster for whole-class audit.
            if(t.usesMmi) {
                if(!r.tags.contains("MMI_SIMD_OP")) { r.tags.add("MMI_SIMD_OP"); mmiCodegenRiskCount++; }
                mmiCodegenRisk.add(new String[]{ nm, hex(r.address),
                    t.mmiOpCount + " ops: " + String.join("|", t.mmiFamilies) });
            }
            // Rule 204 COP2_CONTROL_REG_ACCESS (CFC2/CTC2): tag + roster (the manifest already
            // carries CONTROL_REG_MAP from the block above).
            if(t.usesCop2ControlReg) {
                if(!r.tags.contains("COP2_CONTROL_REG_ACCESS")) {
                    r.tags.add("COP2_CONTROL_REG_ACCESS"); cop2ControlRegCount++;
                }
                cop2ControlRegAccess.add(new String[]{ nm, hex(r.address),
                    String.join("|", t.cop2ControlRegs) });
            }

            // Rule 194: collect allocator-family members + their dispositions.
            if(ALLOC_FAMILY.contains(nm) || isAllocFamilyName(nm)) {
                String disp = r.disposition == null ? "RECOMPILE" : r.disposition;
                allocatorFamily.add(new String[]{ nm, hex(r.address), disp });
            }
        }

        // Rule 194: a SPLIT family (some recompiled, some stubbed/skipped) = the
        // PROJECT_STATE regen-caveat corruption hazard. Raise the flag.
        java.util.Set<String> dispKinds = new java.util.LinkedHashSet<>();
        for(String[] e : allocatorFamily) {
            String d = e[2];
            boolean nativeSide = d.equals("STUB") || d.equals("SKIP") || d.equals("OVERRIDE");
            dispKinds.add(nativeSide ? "native" : "recompiled");
        }
        allocatorFamilySplit = dispKinds.size() > 1;

        // Rule 205 UNFUNDED_TEXTURE_PAGE (advisory): a labelled VRAM page SAMPLED (TEX0 writer)
        // but with NO BITBLTBUF uploader in the static set. The 15-vu1-gs-debugging §4.1
        // decisive black-texture probe (upload-dest vs draw-ref divergence). vramPageWriters
        // was built in applyV12Rules. Static can miss composite/computed uploads → advisory.
        for(Map.Entry<Long,Map<String,List<String>>> e : vramPageWriters.entrySet()) {
            Map<String,List<String>> byKind = e.getValue();
            boolean sampled  = byKind.containsKey("TEX0");
            boolean uploaded = byKind.containsKey("BITBLTBUF");
            if(sampled && !uploaded) {
                long page = e.getKey();
                String sampler = byKind.get("TEX0").get(0);
                unfundedTexturePages.add(new String[]{
                    hex(page), KNOWN_DC2_TBP_LABELS.getOrDefault(page,""), sampler });
            }
        }

        println(String.format(
            "  v15: PRIM_SELECTOR=%d ADC_KICK=%d KICK_MODE=%d TEX_INTERLEAVE=%d VSYNC_STEP=%d "
          + "VIEW_PROJ=%d OBJ_ARRAY_CTOR=%d ALLOC_FAMILY=%d(split=%b) VU_HAZARD=%d",
            primClassSelectorCount, adcKickVertexSourceCount, kickModeWriterCount,
            textureReloadInterleaveCount, vsyncCoupledGameStepCount, viewProjectionWriterCount,
            objectArrayCtorCount, allocatorFamily.size(), allocatorFamilySplit,
            vuExecHazardManifest.size()));
        println(String.format(
            "  v15.1 (PCSX2): VIF_UNPACK_DECOMPRESS=%d XYOFFSET_GUARD=%d TEX1_FILTER=%d",
            vifUnpackDecompressCount, xyoffsetGuardWriterCount, tex1FilterWriterCount));
        println(String.format(
            "  v15.2 (skill): MMI_CODEGEN=%d COP2_CONTROL_REG=%d UNFUNDED_TEX_PAGE=%d",
            mmiCodegenRiskCount, cop2ControlRegCount, unfundedTexturePages.size()));
    }

    // =========================================================
    // v16: G116-G137 title-cavern retrospective + general PS2.
    // Tags/counters/rosters only. The firewalled booleans (207/208/211) and the
    // classification strings (adcCapability / nearPlaneStrategy / packerFamily)
    // are set earlier in detectV16Signals (scan time), so forceRecompile honours
    // them at disposition; this post-pass just surfaces them + derives the
    // non-firewalled rules (209/210/212/214) from the collected traits.
    // =========================================================
    private void applyV16Rules(List<FuncResult> results) {
        for(FuncResult r : results) {
            FuncTraits t = r.traits; if(t == null) continue;
            String nm = r.name == null ? "" : r.name;
            long a = r.address & 0xFFFFFFFFL;

            // --- Rule 207 VERTEX_KICK_FORMAT_ADC_CAPABILITY (classified in detectV16Signals) ---
            if(t.adcCapability != null) {
                if(!r.tags.contains("VERTEX_KICK_FORMAT_ADC_CAPABILITY")) {
                    r.tags.add("VERTEX_KICK_FORMAT_ADC_CAPABILITY"); adcCapablePackerCount++;
                }
                adcCapablePackers.add(new String[]{ nm, hex(r.address), t.adcCapability });
                // Rule 214 PACKED_FIELD_ALIAS_FOG_ADC: a fog-clamp packer's word3 IS the fog byte,
                // not the ADC bit — flag the alias for the runtime GS decoder.
                if(t.hasFogClampShape) {
                    t.isPackedFieldAlias = true;
                    if(!r.tags.contains("PACKED_FIELD_ALIAS_FOG_ADC")) {
                        r.tags.add("PACKED_FIELD_ALIAS_FOG_ADC"); packedFieldAliasCount++;
                    }
                    packedFieldAliases.add(new String[]{ nm, hex(r.address),
                        "word3=fog(XYZF2,FGE)_not_adc_bit111" });
                }
            }

            // --- Rule 208 PERSPECTIVE_DIVIDE_NEAR_PLANE_SOURCE (classified in detectV16Signals) ---
            if(t.isNearPlaneSite) {
                if(!r.tags.contains("PERSPECTIVE_DIVIDE_NEAR_PLANE_SOURCE")) {
                    r.tags.add("PERSPECTIVE_DIVIDE_NEAR_PLANE_SOURCE"); nearPlaneSiteCount++;
                }
                nearPlaneSites.add(new String[]{ nm, hex(r.address),
                    "pre_ftoi4_w_available;" + t.nearPlaneStrategy });
            }

            // --- Rule 209 SPI_CONFIG_COMMAND_DISPATCH ---
            boolean spiName = false;
            for(String f : SPI_CONFIG_NAMES) if(nm.contains(f)) { spiName = true; break; }
            boolean spiArgGetter = false;
            for(String cn : t.calleeNames) if(SPI_STACK_GETTERS.contains(cn)) { spiArgGetter = true; break; }
            if(a == 0x1648f0L /*cfgWATER_VERTEX*/ || a == 0x185d40L /*CreateWaterFrame*/
               || spiName || spiArgGetter) {
                t.isSpiConfigCommand = true;
                if(!r.tags.contains("SPI_CONFIG_COMMAND_DISPATCH")) {
                    r.tags.add("SPI_CONFIG_COMMAND_DISPATCH"); spiConfigCommandCount++;
                }
                spiConfigCommands.add(new String[]{ nm, hex(r.address),
                    spiArgGetter ? "reads_spi_stack_args" : "cfg_handler" });
            }

            // --- Rule 210 DATA_DRIVEN_COMMAND_INTERPRETER (general PS2) ---
            boolean interpName = false;
            for(String f : CMD_INTERP_NAMES) if(nm.contains(f)) { interpName = true; break; }
            // Structural: reads an id then dispatches through an ID-KEYED TABLE — a computed-jump
            // switch table (Rule 146) or a discovered function-pointer table (Rule 128). Deliberately
            // EXCLUDES generic vtable jalr $t9 (polymorphic dispatch is not command interpretation;
            // including it made nearly every loop-with-virtual-call a false "interpreter").
            boolean tableDispatch = !t.tableDispatchSites.isEmpty()
                || !t.computedJumpTargets.isEmpty();
            boolean interpShape = t.hasBackwardBranch && tableDispatch && t.loadOps > 0;
            if(interpName || t.isSpiConfigCommand || interpShape) {
                t.isCommandInterpreter = true;
                t.interpreterDetail = interpName ? "named_vm"
                    : t.isSpiConfigCommand ? "spi_config" : "id_keyed_table_dispatch";
                if(!r.tags.contains("DATA_DRIVEN_COMMAND_INTERPRETER")) {
                    r.tags.add("DATA_DRIVEN_COMMAND_INTERPRETER"); commandInterpreterCount++;
                }
                commandInterpreters.add(new String[]{ nm, hex(r.address), t.interpreterDetail });
            }

            // --- Rule 211 PASSTHROUGH_PACKER_RENDER_PATH (classified in detectV16Signals) ---
            if(t.isPackerFamily) {
                if(!r.tags.contains("PASSTHROUGH_PACKER_RENDER_PATH")) {
                    r.tags.add("PASSTHROUGH_PACKER_RENDER_PATH"); packerFamilyCount++;
                }
                packerFamilies.add(new String[]{ nm, hex(r.address), t.packerFamily });
            }

            // --- Rule 212 PRIVATE_DEPTH_SCOPE ---
            // An RTT/scene draw emitting many overlapping triangles but no ZBUF write in scope
            // needs a private per-frame Z (G125 title cavern back-over-front overdraw).
            boolean drawsMany = t.gifTagInlineBuilder || t.isAdcKickVertexSource
                || (t.drawingChainDepth >= 0 && t.drawingChainDepth <= 6);
            if(t.isRttTarget && drawsMany && !t.writesZbufReg) {
                t.isPrivateDepthScope = true;
                if(!r.tags.contains("PRIVATE_DEPTH_SCOPE")) {
                    r.tags.add("PRIVATE_DEPTH_SCOPE"); privateDepthScopeCount++;
                }
                privateDepthScopes.add(new String[]{ nm, hex(r.address),
                    "rtt_draw_no_zbuf_in_scope" });
            }
        }

        println(String.format(
            "  v16 (G116-G137): ADC_CAPABLE_PACKER=%d NEAR_PLANE_SITE=%d SPI_CFG_CMD=%d "
          + "CMD_INTERP=%d PACKER_FAMILY=%d PRIVATE_Z=%d PACKED_ALIAS=%d",
            adcCapablePackerCount, nearPlaneSiteCount, spiConfigCommandCount,
            commandInterpreterCount, packerFamilyCount, privateDepthScopeCount,
            packedFieldAliasCount));
    }

    // =========================================================
    // v17 Rules 217-220: canonical VU instruction tables + decoder.
    // Source of truth: PCSX2 VUops.cpp _vuTablesMess (read directly from
    // D:\ps2r\pcsx2-master\pcsx2\VUops.cpp, 2026-07-06). NEVER derive these
    // from the runner - the G138 shared-bug hazard (g117_vudis.py copied the
    // runner's swapped table and printed FMAND as "FMEQ" for 70 phases).
    // Encoding: 64-bit pair = lower word at +0, upper word at +4.
    //   upper: op = code&0x3F; 0x3C-0x3F -> FD tables[(code>>6)&0x1F].
    //   lower: idx = code>>>25 into the 128-table; idx 0x40 -> special
    //          op = code&0x3F; 0x3C-0x3F -> T3 tables[(code>>6)&0x1F].
    //   upper bit31 = I (lower word is a 32-bit float immediate),
    //   bit30 = E (end after next pair).
    // =========================================================
    private static final String[]   VU_LOWER_MAIN    = new String[128];
    private static final String[]   VU_LOWER_SPECIAL = new String[64];
    private static final String[][] VU_LOWER_T3      = new String[4][32];
    private static final String[]   VU_UPPER_MAIN    = new String[64];
    private static final String[][] VU_UPPER_FD      = new String[4][32];
    // Rule 220: the disputed main-table region emitted as `vu_lower_opcode_canon`.
    private static final Map<Integer,String> VU_LOWER_CANON_MAP = new LinkedHashMap<>();
    private static final Set<String> VU_EFU_OPS = new HashSet<>(Arrays.asList(
        "ESADD","ERSADD","ELENG","ERLENG","EATANxy","EATANxz","EATAN","ESUM",
        "ERCPR","ESQRT","ERSQRT","ESIN","EEXP"));
    private static final Set<String> VU_BRANCH_OPS = new HashSet<>(Arrays.asList(
        "B","BAL","IBEQ","IBNE","IBLTZ","IBGTZ","IBLEZ","IBGEZ"));
    private static final String[] GIF_PRIM_CLASS = {
        "point","line","linestrip","triangle","tristrip","trifan","sprite","reserved"};
    static {
        String[] lm = VU_LOWER_MAIN;
        lm[0x00]="LQ"; lm[0x01]="SQ"; lm[0x04]="ILW"; lm[0x05]="ISW";
        lm[0x08]="IADDIU"; lm[0x09]="ISUBIU";
        lm[0x10]="FCEQ"; lm[0x11]="FCSET"; lm[0x12]="FCAND"; lm[0x13]="FCOR";
        lm[0x14]="FSEQ"; lm[0x15]="FSSET"; lm[0x16]="FSAND"; lm[0x17]="FSOR";
        lm[0x18]="FMEQ"; lm[0x1A]="FMAND"; lm[0x1B]="FMOR"; lm[0x1C]="FCGET";
        lm[0x20]="B"; lm[0x21]="BAL"; lm[0x24]="JR"; lm[0x25]="JALR";
        lm[0x28]="IBEQ"; lm[0x29]="IBNE";
        lm[0x2C]="IBLTZ"; lm[0x2D]="IBGTZ"; lm[0x2E]="IBLEZ"; lm[0x2F]="IBGEZ";
        String[] ls = VU_LOWER_SPECIAL;
        ls[0x30]="IADD"; ls[0x31]="ISUB"; ls[0x32]="IADDI";
        ls[0x34]="IAND"; ls[0x35]="IOR";
        String[][] t3 = VU_LOWER_T3;
        t3[0][0x0C]="MOVE";  t3[0][0x0D]="LQI";  t3[0][0x0E]="DIV";   t3[0][0x0F]="MTIR";
        t3[0][0x10]="RNEXT"; t3[0][0x19]="MFP";  t3[0][0x1A]="XTOP";  t3[0][0x1B]="XGKICK";
        t3[0][0x1C]="ESADD"; t3[0][0x1D]="EATANxy"; t3[0][0x1E]="ESQRT"; t3[0][0x1F]="ESIN";
        t3[1][0x0C]="MR32";  t3[1][0x0D]="SQI";  t3[1][0x0E]="SQRT";  t3[1][0x0F]="MFIR";
        t3[1][0x10]="RGET";  t3[1][0x1A]="XITOP";
        t3[1][0x1C]="ERSADD"; t3[1][0x1D]="EATANxz"; t3[1][0x1E]="ERSQRT"; t3[1][0x1F]="EATAN";
        t3[2][0x0D]="LQD";   t3[2][0x0E]="RSQRT"; t3[2][0x0F]="ILWR"; t3[2][0x10]="RINIT";
        t3[2][0x1C]="ELENG"; t3[2][0x1D]="ESUM";  t3[2][0x1E]="ERCPR"; t3[2][0x1F]="EEXP";
        t3[3][0x0D]="SQD";   t3[3][0x0E]="WAITQ"; t3[3][0x0F]="ISWR"; t3[3][0x10]="RXOR";
        t3[3][0x1C]="ERLENG"; t3[3][0x1E]="WAITP";
        String[] um = VU_UPPER_MAIN;
        String[] lanes = {"x","y","z","w"};
        String[] fams  = {"ADD","SUB","MADD","MSUB","MAX","MINI","MUL"};
        for(int fi=0; fi<7; fi++) for(int li=0; li<4; li++) um[fi*4+li] = fams[fi]+lanes[li];
        um[0x1C]="MULq"; um[0x1D]="MAXi"; um[0x1E]="MULi"; um[0x1F]="MINIi";
        um[0x20]="ADDq"; um[0x21]="MADDq"; um[0x22]="ADDi"; um[0x23]="MADDi";
        um[0x24]="SUBq"; um[0x25]="MSUBq"; um[0x26]="SUBi"; um[0x27]="MSUBi";
        um[0x28]="ADD";  um[0x29]="MADD";  um[0x2A]="MUL";  um[0x2B]="MAX";
        um[0x2C]="SUB";  um[0x2D]="MSUB";  um[0x2E]="OPMSUB"; um[0x2F]="MINI";
        String[][] fd = VU_UPPER_FD;
        for(int t=0; t<4; t++){
            fd[t][0]="ADDA"+lanes[t];  fd[t][1]="SUBA"+lanes[t];
            fd[t][2]="MADDA"+lanes[t]; fd[t][3]="MSUBA"+lanes[t];
            fd[t][6]="MULA"+lanes[t];
        }
        fd[0][4]="ITOF0";  fd[0][5]="FTOI0";  fd[0][7]="MULAq"; fd[0][8]="ADDAq";  fd[0][9]="SUBAq";  fd[0][10]="ADDA";  fd[0][11]="SUBA";
        fd[1][4]="ITOF4";  fd[1][5]="FTOI4";  fd[1][7]="ABS";   fd[1][8]="MADDAq"; fd[1][9]="MSUBAq"; fd[1][10]="MADDA"; fd[1][11]="MSUBA";
        fd[2][4]="ITOF12"; fd[2][5]="FTOI12"; fd[2][7]="MULAi"; fd[2][8]="ADDAi";  fd[2][9]="SUBAi";  fd[2][10]="MULA";  fd[2][11]="OPMULA";
        fd[3][4]="ITOF15"; fd[3][5]="FTOI15"; fd[3][7]="CLIP";  fd[3][8]="MADDAi"; fd[3][9]="MSUBAi"; fd[3][11]="NOP";
        for(int i=0; i<0x30; i++) if(lm[i] != null) VU_LOWER_CANON_MAP.put(i, lm[i]);
    }

    private static String vuDecodeUpper(int code){
        int op = code & 0x3F;
        if(op >= 0x3C) return VU_UPPER_FD[op-0x3C][(code>>>6)&0x1F];
        return VU_UPPER_MAIN[op];
    }
    private static String vuDecodeLower(int code){
        int top = code >>> 25;
        if(top == 0x40){
            int op = code & 0x3F;
            if(op >= 0x3C) return VU_LOWER_T3[op-0x3C][(code>>>6)&0x1F];
            return VU_LOWER_SPECIAL[op];
        }
        return top < 128 ? VU_LOWER_MAIN[top] : null;
    }
    /** VF register the upper op writes (fd for ALU, ft for ITOF/FTOI/ABS), or -1 for
     *  ACC/CLIP/NOP writers. VF00 (hardwired) treated as no hazard by callers. */
    private static int vuUpperDestVf(int code, String name){
        if(name == null || name.equals("NOP") || name.equals("CLIP")) return -1;
        if(name.startsWith("ITOF") || name.startsWith("FTOI") || name.equals("ABS"))
            return (code>>>16)&0x1F;
        if(name.matches("(ADD|SUB|MADD|MSUB|MUL|OPMUL)A.*")) return -1; // ACC writers
        return (code>>>6)&0x1F;
    }
    /** Primary VF a lower op READS (the G139 hazard side): fs for stores/DIV/MTIR/
     *  MOVE/MR32/EFU, ft for SQRT. -1 when the op reads no VF. */
    private static int vuLowerReadVfPrimary(int code, String name){
        if(name == null) return -1;
        switch(name){
            case "SQ": case "SQI": case "SQD": case "MTIR": case "MOVE": case "MR32":
            case "DIV": case "RSQRT":
                return (code>>>11)&0x1F;
            case "SQRT":
                return (code>>>16)&0x1F;
            default:
                return VU_EFU_OPS.contains(name) ? (code>>>11)&0x1F : -1;
        }
    }
    private static int vuLowerReadVfSecondary(int code, String name){
        if("DIV".equals(name) || "RSQRT".equals(name)) return (code>>>16)&0x1F;
        return -1;
    }
    /** Branch displacement: signed 11-bit pair offset relative to the NEXT pair. */
    private static int vuBranchTargetPair(int idx, int code){
        int imm = code & 0x7FF;
        if(imm >= 0x400) imm -= 0x800;
        return idx + 1 + imm;
    }
    private static int leWord(byte[] d, int off){
        return (d[off]&0xFF) | ((d[off+1]&0xFF)<<8) | ((d[off+2]&0xFF)<<16) | ((d[off+3]&0xFF)<<24);
    }

    /** Rule 217 payload gate: >=80% decodable pairs, >=50% non-zero, >=6 distinct
     *  upper opcodes (kills zero-fill and repetitive-data false positives - every
     *  32-bit value lands in SOME table slot, so emptiness alone is not enough). */
    private static boolean vuPayloadPlausible(byte[] d, int off, int pairs){
        int valid=0, nonZero=0;
        Set<String> distinctUpper = new HashSet<>();
        for(int i=0; i<pairs; i++){
            int lo = leWord(d, off+i*8), hi = leWord(d, off+i*8+4);
            if(lo!=0 || hi!=0) nonZero++;
            String un = vuDecodeUpper(hi);
            if(un == null) continue;
            distinctUpper.add(un);
            if((hi & 0x80000000)!=0) { valid++; continue; }  // I bit: lower = float imm
            if(vuDecodeLower(lo) != null) valid++;
        }
        return valid >= pairs*4/5 && nonZero >= pairs/2 && distinctUpper.size() >= 6;
    }

    // =========================================================
    // v17 Rules 217-219: VU microcode extraction + static hazard scan.
    // The analysis layer that would have front-loaded G87 (Q latency),
    // G138 (opcode table + MAC pipeline), G139 (same-pair VF hazard) and
    // G140 (clipper never disassembled) - ~70 phases of runtime archaeology
    // over facts the ELF data bytes already encode.
    // =========================================================
    private void scanVuMicrocodePrograms(List<FuncResult> results) {
        try {
            // [payloadAddr, imm, pairs, headerAddr]
            List<long[]> candidates = new ArrayList<>();
            for(MemoryBlock block : memory.getBlocks()){
                if(!block.isInitialized() || block.isExecute()) continue;
                long bsize = block.getSize();
                if(bsize < 64 || bsize > 64L*1024*1024) continue;
                byte[] data = new byte[(int)bsize];
                try { block.getBytes(block.getStart(), data); } catch(Exception e){ continue; }
                long base = block.getStart().getOffset();
                for(int off=0; off+8<=data.length && candidates.size()<256; off+=4){
                    int w = leWord(data, off);
                    if(((w>>>24)&0x7F) != 0x4A) continue;         // VIF MPG (irq bit masked)
                    int num = (w>>>16)&0xFF;
                    int pairs = (num==0) ? 256 : num;
                    if(pairs < 16) continue;                      // noise gate
                    int imm = w & 0xFFFF;
                    int p = off+4;
                    // MPG data is 64-bit aligned in the VIF stream; a single NOP pad allowed.
                    if(((base+p)&7) != 0){
                        if(p+4 > data.length || leWord(data,p) != 0) continue;
                        p += 4;
                    }
                    if(p + pairs*8 > data.length) continue;
                    if(!vuPayloadPlausible(data, p, pairs)) continue;
                    candidates.add(new long[]{ base+p, imm, pairs, base+off });
                }
            }
            candidates.sort((a,b)->Long.compare(a[0],b[0]));
            // Rule 217: group consecutive chunks (adjacent payload + continuing imm)
            // into whole programs - DC2's 16KB title program uploads as num=0 (256-pair)
            // chunks with increasing imm.
            int ci=0;
            while(ci < candidates.size() && vuMicrocodePrograms.size() < 32){
                long[] first = candidates.get(ci);
                List<long[]> chunks = new ArrayList<>(); chunks.add(first);
                long expectAddr = first[0] + first[2]*8;
                long expectImm  = first[1] + first[2];
                int cj = ci+1;
                while(cj < candidates.size()){
                    long[] nx = candidates.get(cj);
                    if(nx[3] >= expectAddr && nx[3] <= expectAddr+16 && nx[1] == expectImm){
                        chunks.add(nx);
                        expectAddr = nx[0] + nx[2]*8;
                        expectImm  = nx[1] + nx[2];
                        cj++;
                    } else break;
                }
                ci = cj;
                int total=0; for(long[] c : chunks) total += (int)c[2];
                int[] loArr = new int[total], hiArr = new int[total];
                int k=0; boolean ok=true;
                for(long[] c : chunks){
                    try {
                        byte[] buf = new byte[(int)c[2]*8];
                        memory.getBytes(toAddr(c[0]), buf);
                        for(int i=0; i<(int)c[2]; i++){
                            loArr[k]=leWord(buf,i*8); hiArr[k]=leWord(buf,i*8+4); k++;
                        }
                    } catch(Exception e){ ok=false; break; }
                }
                if(!ok) continue;
                VuProgram p = analyzeVuProgram(chunks.get(0)[0], (int)chunks.get(0)[1],
                                               loArr, hiArr, chunks.size());
                // Best-effort uploader link: a Rule 51/68 uploader (or mgSendVuProg)
                // whose captured const loads hit the header/payload address.
                long hdr = chunks.get(0)[3], pay = chunks.get(0)[0];
                outer:
                for(FuncResult r : results){
                    FuncTraits t = r.traits; if(t==null) continue;
                    boolean uploaderShape = t.isMicrocodeUploader
                        || t.vifOpcodesBuilt.contains("MPG")
                        || (r.name != null && r.name.contains("SendVuProg"));
                    if(!uploaderShape) continue;
                    for(long[] cl : t.constLoads){
                        long v = cl[1] & 0xFFFFFFFFL;
                        if(Math.abs(v-hdr) <= 64 || Math.abs(v-pay) <= 64){
                            p.uploaderFunc = r.name; break outer;
                        }
                    }
                }
                vuMicrocodePrograms.add(p);
            }
            int spTot=0, u4Tot=0;
            for(VuProgram p : vuMicrocodePrograms){ spTot+=p.samePairHazardCount; u4Tot+=p.flagConsumersUnder4; }
            println(String.format(
                "  v17 Rules 217-219: %d MPG candidates -> %d VU programs; "
              + "same-pair hazards=%d, flag consumers <4 pairs=%d.",
                candidates.size(), vuMicrocodePrograms.size(), spTot, u4Tot));
        } catch(Exception ex) {
            println("  v17 Rules 217-219: VU microcode scan skipped: " + ex.getMessage());
        }
    }

    /** Rules 218/219: full static pass over one extracted program. */
    private VuProgram analyzeVuProgram(long elfAddr, int vuDestQw,
                                       int[] loArr, int[] hiArr, int chunkCount){
        VuProgram p = new VuProgram();
        p.elfAddr = elfAddr; p.vuDestQw = vuDestQw;
        p.sizePairs = loArr.length; p.chunkCount = chunkCount;
        int n = loArr.length;
        int lastMacProducer = -1000, lastClipProducer = -1000;
        int lastQProducer = -1000, lastPProducer = -1000;
        for(int i=0; i<n; i++){
            int hi = hiArr[i], lo = loArr[i];
            String un = vuDecodeUpper(hi);
            boolean iBit = (hi & 0x80000000) != 0;
            String ln = iBit ? null : vuDecodeLower(lo);
            long pc = i*8L;
            if(un != null) p.census.merge(un, 1, Integer::sum);
            if(ln != null) p.census.merge(ln, 1, Integer::sum);
            // ---- lower side first: flag consumers see producers from EARLIER pairs only ----
            if(ln != null){
                boolean macCons = ln.equals("FMEQ")||ln.equals("FMAND")||ln.equals("FMOR")
                               || ln.equals("FSEQ")||ln.equals("FSAND")||ln.equals("FSOR");
                boolean clipCons = ln.equals("FCEQ")||ln.equals("FCAND")||ln.equals("FCOR")
                               || ln.equals("FCGET");
                if(macCons || clipCons){
                    int dist = i - (macCons ? lastMacProducer : lastClipProducer);
                    if(dist < 0 || dist > 900) dist = 9;
                    p.flagConsumers++;
                    p.flagDistHistogram.merge(Math.min(dist,9), 1, Integer::sum);
                    if(dist == 4) p.flagConsumersExactly4++;
                    if(dist < 4){
                        p.flagConsumersUnder4++;
                        if(p.flagUnder4Examples.size() < 40)
                            p.flagUnder4Examples.add(new String[]{
                                "0x"+Long.toHexString(pc), ln, String.valueOf(dist)});
                    }
                }
                if(ln.equals("FCGET")) p.fcgetCount++;
                if(ln.equals("XGKICK") && p.xgkickPcs.size() < 64) p.xgkickPcs.add(pc);
                if(ln.equals("WAITQ")){ p.waitqCount++; lastQProducer = -1000; }
                if(ln.equals("WAITP")){ p.waitpCount++; lastPProducer = -1000; }
                if(ln.equals("DIV")||ln.equals("SQRT")||ln.equals("RSQRT")){
                    p.qProducers++; lastQProducer = i;
                }
                if(VU_EFU_OPS.contains(ln)){ p.pProducers++; lastPProducer = i; }
                if(ln.equals("MFP")){
                    p.pConsumers++;
                    int g = i - lastPProducer;
                    if(g > 0 && g < p.pMinGap) p.pMinGap = g;
                }
                if(ln.equals("JR")||ln.equals("JALR")) p.jrIndirectCount++;
                if(ln.equals("BAL")){
                    int t = vuBranchTargetPair(i, lo);
                    long tpc = t*8L;
                    if(t>=0 && t<n && p.balSubroutines.size()<32 && !p.balSubroutines.contains(tpc))
                        p.balSubroutines.add(tpc);
                }
                if(VU_BRANCH_OPS.contains(ln)){
                    p.branchTargetCount++;
                    if(pc < 0x800 && p.dispatcherBranchPcs.size() < 48)
                        p.dispatcherBranchPcs.add(pc);
                }
            }
            // ---- upper side: same-pair hazard, Q consumers, then producer updates ----
            if(un != null){
                if(un.endsWith("q")){
                    p.qConsumers++;
                    int g = i - lastQProducer;
                    if(g > 0 && g < p.qMinGap) p.qMinGap = g;
                }
                int destVf = vuUpperDestVf(hi, un);
                if(destVf > 0 && ln != null){
                    int r1 = vuLowerReadVfPrimary(lo, ln);
                    int r2 = vuLowerReadVfSecondary(lo, ln);
                    if(r1 == destVf || r2 == destVf){
                        p.samePairHazardCount++;
                        if(p.samePairHazards.size() < 40)
                            p.samePairHazards.add(new String[]{
                                "0x"+Long.toHexString(pc), un, ln,
                                "VF"+String.format("%02d", destVf)});
                    }
                }
                if(un.equals("CLIP")){ p.clipwCount++; lastClipProducer = i; }
                else if(!un.equals("NOP") && !un.startsWith("MAX") && !un.startsWith("MINI"))
                    lastMacProducer = i;   // MAX/MINI do not update MAC flags on real VU
            }
        }
        // ---- Rule 219: reachability from entry 0 + every static branch target ----
        boolean[] reached = new boolean[n];
        Deque<Integer> pending = new ArrayDeque<>();
        pending.add(0);
        for(int i=0; i<n; i++){
            if((hiArr[i] & 0x80000000) != 0) continue;
            String ln = vuDecodeLower(loArr[i]);
            if(ln != null && VU_BRANCH_OPS.contains(ln)){
                int t = vuBranchTargetPair(i, loArr[i]);
                if(t>=0 && t<n) pending.add(t);
            }
        }
        while(!pending.isEmpty()){
            int i = pending.poll();
            while(i >= 0 && i < n && !reached[i]){
                reached[i] = true;
                int hi = hiArr[i];
                boolean iBit = (hi & 0x80000000) != 0;
                String ln = iBit ? null : vuDecodeLower(loArr[i]);
                if(ln != null && (ln.equals("B") || ln.equals("JR"))){
                    if(i+1 < n) reached[i+1] = true;   // delay slot
                    break;
                }
                if((hi & 0x40000000) != 0){            // E bit: end after next pair
                    if(i+1 < n) reached[i+1] = true;
                    break;
                }
                i++;
            }
        }
        int rp=0; for(boolean b : reached) if(b) rp++;
        p.reachablePairs = rp;
        int i2=0;
        while(i2 < n && p.unreachedSpans.size() < 8){
            if(!reached[i2]){
                int s=i2;
                while(i2 < n && !reached[i2]) i2++;
                if(i2-s >= 4) p.unreachedSpans.add(new long[]{ s*8L, (i2-1)*8L+8 });
            } else i2++;
        }
        return p;
    }

    // =========================================================
    // v17 Rule 224: GIFtag-shaped records in initialized data.
    // Structural filter: GIFtag word0 bits16-31 and word1 bits0-13 are
    // architecturally ZERO; nreg>=1; PACKED REGS nibbles never 0xB (reserved).
    // nloop==0 = TEMPLATE (VIF-delivered, VU-patched - the G140 trifan
    // template shape: exactly two 302ec000 nloop=0 hits in 32MB of RAM).
    // =========================================================
    private void scanGiftagTemplates() {
        try {
            Map<String,GiftagTemplate> byValue = new LinkedHashMap<>();
            for(MemoryBlock block : memory.getBlocks()){
                if(!block.isInitialized() || block.isExecute()) continue;
                long bsize = block.getSize();
                if(bsize < 32 || bsize > 64L*1024*1024) continue;
                byte[] data = new byte[(int)bsize];
                try { block.getBytes(block.getStart(), data); } catch(Exception e){ continue; }
                long base = block.getStart().getOffset();
                for(int off=0; off+16<=data.length; off+=4){
                    int w0 = leWord(data,off), w1 = leWord(data,off+4);
                    if((w0>>>16) != 0) continue;
                    if(w0 == 0 && w1 == 0) continue;
                    if((w1 & 0x3FFF) != 0) continue;
                    int nreg = (w1>>>28)&0xF; if(nreg == 0) continue;
                    int flg = (w1>>>26)&3; if(flg == 3) continue;   // disabled/IMAGE2
                    int nloop = w0 & 0x7FFF; if(nloop > 0x2000) continue;
                    int w2 = leWord(data,off+8), w3 = leWord(data,off+12);
                    if(flg == 0){
                        long regs = ((long)w3 << 32) | (w2 & 0xFFFFFFFFL);
                        boolean bad = false;
                        for(int ri=0; ri<nreg; ri++)
                            if(((regs >>> (ri*4)) & 0xF) == 0xB){ bad=true; break; }
                        if(bad) continue;
                        if(w2 == 0 && w3 == 0 && nreg > 1) continue; // all-PRIM run = noise
                    }
                    String key = String.format("%08x%08x%08x%08x", w3, w2, w1, w0);
                    GiftagTemplate g = byValue.get(key);
                    if(g == null){
                        if(byValue.size() >= 512) continue;
                        g = new GiftagTemplate();
                        g.w0=w0&0xFFFFFFFFL; g.w1=w1&0xFFFFFFFFL;
                        g.w2=w2&0xFFFFFFFFL; g.w3=w3&0xFFFFFFFFL;
                        g.nloop=nloop; g.eop=(w0>>>15)&1; g.pre=(w1>>>14)&1;
                        g.prim=(w1>>>15)&0x7FF; g.flg=flg; g.nreg=nreg;
                        g.primClass = GIF_PRIM_CLASS[g.prim & 7];
                        byValue.put(key, g);
                    }
                    g.count++;
                    if(g.exampleAddrs.size() < 4) g.exampleAddrs.add(base+off);
                }
            }
            List<GiftagTemplate> kept = new ArrayList<>();
            for(GiftagTemplate g : byValue.values())
                if(g.nloop == 0 || g.count >= 2) kept.add(g);
            kept.sort((a,b)->Integer.compare(b.count, a.count));
            if(kept.size() > 128) kept = new ArrayList<>(kept.subList(0,128));
            giftagTemplates.addAll(kept);
            int templates=0; for(GiftagTemplate g : kept) if(g.nloop==0) templates++;
            println(String.format(
                "  v17 Rule 224: %d distinct GIFtag-shaped patterns kept (%d nloop=0 templates).",
                kept.size(), templates));
        } catch(Exception ex) {
            println("  v17 Rule 224: giftag template scan skipped: " + ex.getMessage());
        }
    }

    // =========================================================
    // v17 Rule 221: runtime env-lever registry + stale-band-aid suspects.
    // The G64 class: a default-ON pc-scoped interpreter patch outliving the
    // root fix that superseded it (it force-broke the VU clipper for 70
    // phases). Every getenv lever is inventoried; VU-pc-shaped hex literals
    // near a semantic lever in a VU/GS source = STALE_BANDAID_SUSPECT.
    // =========================================================
    private void scanRuntimeLeverRegistry() {
        if(runtimeRootDir == null){
            println("  v17 Rule 221: no runtime checkout - lever registry skipped.");
            return;
        }
        File start = new File(runtimeRootDir, "src");
        if(!start.isDirectory()) start = runtimeRootDir;
        java.util.regex.Pattern pEnv = java.util.regex.Pattern.compile(
            "getenv\\s*\\(\\s*\"([A-Za-z0-9_]+)\"");
        java.util.regex.Pattern pPc = java.util.regex.Pattern.compile(
            "0x[0-9a-fA-F]{3,4}\\b");
        Set<String> emitted = new HashSet<>();
        Deque<File> stack = new ArrayDeque<>();
        stack.push(start);
        int filesScanned = 0;
        while(!stack.isEmpty() && filesScanned < 800 && runtimeLeverRegistry.size() < 400){
            File f = stack.pop();
            String nl = f.getName().toLowerCase();
            if(f.isDirectory()){
                if(nl.equals("runner") || nl.startsWith("build")
                   || nl.equals(".git") || nl.equals("out")) continue;
                File[] kids = f.listFiles();
                if(kids != null) for(File kf : kids) stack.push(kf);
                continue;
            }
            if(!(nl.endsWith(".cpp")||nl.endsWith(".h")||nl.endsWith(".hpp")||nl.endsWith(".cc"))) continue;
            filesScanned++;
            try {
                List<String> lines = new ArrayList<>();
                BufferedReader br = utf8Reader(f);
                String ln;
                while((ln = br.readLine()) != null) lines.add(ln);
                br.close();
                boolean vuOrGsFile = nl.contains("vu") || nl.contains("rasterizer")
                                  || nl.contains("gs") || nl.contains("gif");
                for(int i=0; i<lines.size() && runtimeLeverRegistry.size() < 400; i++){
                    java.util.regex.Matcher m = pEnv.matcher(lines.get(i));
                    while(m.find()){
                        String env = m.group(1);
                        if(!emitted.add(env + "|" + f.getName())) continue;
                        String up = env.toUpperCase();
                        String cls;
                        if(up.contains("TRACE")||up.contains("DUMP")||up.contains("LOG")
                           ||up.contains("CENSUS")||up.contains("PROBE"))
                            cls = "diagnostic";
                        else if(up.contains("_NO_"))  cls = "kill_switch_of_default_on_fix";
                        else if(up.contains("FORCE")) cls = "reenable_of_retired_bandaid";
                        else                          cls = "semantic_lever";
                        StringBuilder pcs = new StringBuilder();
                        if(vuOrGsFile){
                            int lo = Math.max(0, i-3), hi2 = Math.min(lines.size()-1, i+15);
                            Set<String> found = new LinkedHashSet<>();
                            for(int j=lo; j<=hi2 && found.size()<6; j++){
                                java.util.regex.Matcher pm = pPc.matcher(lines.get(j));
                                while(pm.find() && found.size()<6) found.add(pm.group());
                            }
                            pcs.append(String.join("|", found));
                        }
                        boolean stale = cls.equals("semantic_lever") && pcs.length() > 0;
                        if(stale) staleBandaidSuspectCount++;
                        runtimeLeverRegistry.add(new String[]{
                            env, f.getName(), String.valueOf(i+1), cls,
                            pcs.toString(), stale ? "true" : "false"});
                    }
                }
            } catch(Exception ignored) {}
        }
        println(String.format(
            "  v17 Rule 221: %d env levers from %d files; %d stale-band-aid suspects.",
            runtimeLeverRegistry.size(), filesScanned, staleBandaidSuspectCount));
    }

    // =========================================================
    // v17 Rule 220: canon-vs-runner lower-opcode conformance (best-effort).
    // Would have printed "0x1a: runner token FMEQ, canon FMAND" at map time
    // (the G138 root). Advisory: case labels are matched textually, so an
    // unrelated switch can produce a false pairing - MISMATCH? entries are
    // leads to verify against PCSX2 _LOWER_OPCODE, not verdicts.
    // =========================================================
    private void checkVuOpcodeConformance() {
        File vuSrc = null;
        if(runtimeRootDir != null){
            File direct = new File(runtimeRootDir, "src" + File.separator + "lib"
                + File.separator + "ps2_vu1.cpp");
            if(direct.isFile()) vuSrc = direct;
            else {
                Deque<File> stack = new ArrayDeque<>();
                stack.push(runtimeRootDir);
                int seen = 0;
                while(!stack.isEmpty() && seen < 2000 && vuSrc == null){
                    File f = stack.pop(); seen++;
                    String nl = f.getName().toLowerCase();
                    if(f.isDirectory()){
                        if(nl.equals("runner")||nl.startsWith("build")||nl.equals(".git")||nl.equals("out")) continue;
                        File[] kids = f.listFiles();
                        if(kids != null) for(File kf : kids) stack.push(kf);
                    } else if(nl.equals("ps2_vu1.cpp")) vuSrc = f;
                }
            }
        }
        if(vuSrc == null){
            println("  v17 Rule 220: ps2_vu1.cpp not found - conformance diff skipped.");
            return;
        }
        try {
            String src = readFileFully(vuSrc);
            java.util.regex.Pattern pCase = java.util.regex.Pattern.compile(
                "case\\s+0x([0-9a-fA-F]{1,2})\\s*:");
            java.util.regex.Pattern pTok = java.util.regex.Pattern.compile(
                "\\b(FMEQ|FMAND|FMOR|FCGET|FCEQ|FCSET|FCAND|FCOR|FSEQ|FSSET|FSAND|FSOR|"
              + "IADDIU|ISUBIU|IBLTZ|IBGTZ|IBLEZ|IBGEZ|IBEQ|IBNE|JALR|BAL|ILW|ISW)\\b",
                java.util.regex.Pattern.CASE_INSENSITIVE);
            java.util.regex.Matcher cm = pCase.matcher(src);
            Set<String> seenPair = new HashSet<>();
            while(cm.find() && vuOpcodeMapCheck.size() < 64){
                int idx;
                try { idx = Integer.parseInt(cm.group(1), 16); } catch(Exception e){ continue; }
                String canon = VU_LOWER_CANON_MAP.get(idx);
                if(canon == null) continue;
                int end = Math.min(src.length(), cm.end()+400);
                java.util.regex.Matcher tm = pTok.matcher(src.substring(cm.end(), end));
                if(!tm.find()) continue;
                String tok = tm.group(1).toUpperCase();
                if(!seenPair.add(idx + "|" + tok)) continue;
                String status = tok.equals(canon) ? "match" : "MISMATCH?";
                if(!tok.equals(canon)) vuOpcodeMapMismatchCount++;
                vuOpcodeMapCheck.add(new String[]{
                    String.format("0x%02x", idx), canon, tok, status});
            }
            // Coverage gap: census opcodes (len>=3, avoids trivial B/LQ/SQ hits)
            // with no textual presence anywhere in the runner's VU source.
            Set<String> used = new TreeSet<>();
            for(VuProgram p : vuMicrocodePrograms) used.addAll(p.census.keySet());
            for(String name : used){
                if(name.length() < 3) continue;
                if(vuOpcodeCoverageGap.size() >= 32) break;
                java.util.regex.Pattern pw = java.util.regex.Pattern.compile(
                    "\\b" + java.util.regex.Pattern.quote(name) + "\\b",
                    java.util.regex.Pattern.CASE_INSENSITIVE);
                if(!pw.matcher(src).find()) vuOpcodeCoverageGap.add(name);
            }
            println(String.format(
                "  v17 Rule 220: %d case-label pairings checked, %d mismatch leads, "
              + "%d census opcodes absent from %s.",
                vuOpcodeMapCheck.size(), vuOpcodeMapMismatchCount,
                vuOpcodeCoverageGap.size(), vuSrc.getName()));
        } catch(Exception ex) {
            println("  v17 Rule 220: conformance diff skipped: " + ex.getMessage());
        }
    }

    // =========================================================
    // v17 Rule 222: perf static cost + fast-path sub-detectors (G141 support).
    // Static cannot measure FPS; it ranks WHERE the measure-first phase
    // starts (skill 17-performance-optimization doctrine).
    // =========================================================
    private void applyV17Rules(List<FuncResult> results) {
        for(FuncResult r : results){
            FuncTraits t = r.traits; if(t == null) continue;
            String nm = r.name == null ? "" : r.name;
            // perf cost model: instruction count, inner loops, COP2 density,
            // IO-dispatch overhead, fan-out; weighted by mainloop depth.
            long instr = Math.max(1, t.byteSize/4);
            long cost = instr;
            if(t.hasBackwardBranch) cost += instr;
            if(t.usesCop2)          cost += instr/2;
            if(t.accessesMMIO)      cost += 64;
            cost += (long)t.calleeCount * 8;
            int d = t.mainLoopDepth;
            if(d >= 0 && d <= 2)      cost *= 4;
            else if(d >= 3 && d <= 4) cost *= 2;
            else if(d < 0)            cost /= 2;
            t.perfStaticCost = cost;
            // MEMCPY_SHAPED_LOOP: tight wide-copy loop -> host memcpy candidate.
            int wideMemOps = 0;
            for(String[] lr : t.literalRefs){
                String mn = lr[1];
                if("lq".equals(mn)||"sq".equals(mn)||"ld".equals(mn)||"sd".equals(mn)) wideMemOps++;
            }
            boolean copyName = nm.contains("memcpy")||nm.contains("memset")
                || nm.contains("memmove")||nm.contains("bcopy")||nm.contains("bzero");
            if(copyName || (t.hasBackwardBranch && t.calleeCount == 0 && t.byteSize <= 200
                            && wideMemOps >= 2 && t.loadOps > 0 && t.storeOps > 0
                            && !t.accessesMMIO)){
                t.isMemcpyShapedLoop = true;
                if(!r.tags.contains("MEMCPY_SHAPED_LOOP")){
                    r.tags.add("MEMCPY_SHAPED_LOOP"); memcpyShapedLoopCount++;
                }
                memcpyShapedLoops.add(new String[]{ nm, hex(r.address),
                    (copyName ? "named_copy" : "tight_wide_copy_loop") + ";wide_ops=" + wideMemOps });
            }
            // IDLE_SPIN_YIELD_SITE: store-free poll spin -> host-yield candidate.
            if((t.isInfiniteSpinLoop || t.isSyncWaitLoop || (t.hasBusyWait && t.hasBackwardBranch))
               && t.storeOps == 0 && t.calleeCount <= 1 && !t.isMemcpyShapedLoop){
                t.isIdleSpinYieldSite = true;
                if(!r.tags.contains("IDLE_SPIN_YIELD_SITE")){
                    r.tags.add("IDLE_SPIN_YIELD_SITE"); idleSpinYieldCount++;
                }
                idleSpinYieldSites.add(new String[]{ nm, hex(r.address),
                    "mainloop_depth=" + t.mainLoopDepth + ";kind="
                    + (t.isInfiniteSpinLoop ? "infinite_spin"
                       : t.isSyncWaitLoop ? "sync_wait" : "busy_wait") });
            }
            // ===== v17.1 Rules 226-232 (PCSX2 cross-check round 2) =====
            // Rule 226 DMA_MFIFO_RING_CONFIG: MFIFO ring base/size writers.
            if(t.dmacGlobalRegsHit.contains("RBOR") || t.dmacGlobalRegsHit.contains("RBSR")){
                t.isDmaMfifoUser = true;
                if(!r.tags.contains("DMA_MFIFO_RING_CONFIG")){
                    r.tags.add("DMA_MFIFO_RING_CONFIG"); dmaMfifoUserCount++;
                }
                dmaMfifoUsers.add(new String[]{ nm, hex(r.address),
                    String.join("|", t.dmacGlobalRegsHit) });
            }
            // Rule 227 DMA_STALL_CONTROL_SYNC: STADR writer or REFS tag builder.
            boolean refsTag = t.dmaTagIdsBuilt.contains("REFS") || t.storedDmaTagIds.contains("REFS");
            if(t.dmacGlobalRegsHit.contains("STADR") || refsTag){
                t.isDmaStallControlSync = true;
                if(!r.tags.contains("DMA_STALL_CONTROL_SYNC")){
                    r.tags.add("DMA_STALL_CONTROL_SYNC"); dmaStallControlCount++;
                }
                dmaStallControlSync.add(new String[]{ nm, hex(r.address),
                    t.dmacGlobalRegsHit.contains("STADR")
                        ? "stadr_writer" + (refsTag ? "+refs_tag" : "") : "refs_tag_builder" });
            }
            // Rule 228 VIF_PATH_ARBITRATION: MSKPATH3/FLUSH*/MARK codes or GIF MODE toucher.
            for(String code : new String[]{"MSKPATH3","FLUSH","FLUSHA","FLUSHE","MARK"})
                if(t.vifOpcodesBuilt.contains(code) || t.storedVifOpcodes.contains(code))
                    t.vifPathArbCodes.add(code);
            boolean gifModeTouch = t.compositeMmioRangesHit.contains("GIF_P3_CTRL")
                                || t.touchesGifP3Reg;
            if(!t.vifPathArbCodes.isEmpty() || (gifModeTouch && !t.vifOpcodesBuilt.isEmpty())){
                t.isVifPathArbiter = true;
                if(!r.tags.contains("VIF_PATH_ARBITRATION")){
                    r.tags.add("VIF_PATH_ARBITRATION"); vifPathArbCount++;
                }
                vifPathArbitration.add(new String[]{ nm, hex(r.address),
                    t.vifPathArbCodes.isEmpty() ? "gif_mode_m3r_imt"
                        : String.join("|", t.vifPathArbCodes) });
            }
            // Rule 229 GS_DOWNLOAD_READBACK_PATH: BUSDIR, or TRXDIR writer + VIF-reverse context.
            if(t.compositeMmioRangesHit.contains("GS_PRIV_BUSDIR"))
                t.gsReadbackSignals.add("BUSDIR");
            if(t.storesTrxdirLocalToHost && (t.accessesVifCtrl || t.writesVif1Fifo))
                t.gsReadbackSignals.add("TRXDIR+VIF1_REVERSE_CONTEXT");
            if(!t.gsReadbackSignals.isEmpty()){
                t.isGsReadbackSite = true;
                if(!r.tags.contains("GS_DOWNLOAD_READBACK_PATH")){
                    r.tags.add("GS_DOWNLOAD_READBACK_PATH"); gsReadbackSiteCount++;
                }
                gsReadbackSites.add(new String[]{ nm, hex(r.address),
                    String.join("|", t.gsReadbackSignals) });
            }
            // Rule 230 GS_PRMODE_ATTRIBUTE_SOURCE.
            if(t.writesPrmodecontReg || t.writesPrmodeReg){
                if(!r.tags.contains("GS_PRMODE_ATTRIBUTE_SOURCE")){
                    r.tags.add("GS_PRMODE_ATTRIBUTE_SOURCE"); prmodeAttrWriterCount++;
                }
                prmodeAttrWriters.add(new String[]{ nm, hex(r.address),
                    (t.writesPrmodecontReg ? "PRMODECONT" : "")
                    + (t.writesPrmodecontReg && t.writesPrmodeReg ? "+" : "")
                    + (t.writesPrmodeReg ? "PRMODE" : "") });
            }
            // Rule 231 GS_TEXA_CLAMP_CONTRACT.
            if(t.writesTexaReg || t.writesClampReg){
                if(!r.tags.contains("GS_TEXA_CLAMP_CONTRACT")){
                    r.tags.add("GS_TEXA_CLAMP_CONTRACT"); texaClampWriterCount++;
                }
                texaClampWriters.add(new String[]{ nm, hex(r.address),
                    (t.writesTexaReg ? "TEXA_alpha_expansion" : "")
                    + (t.writesTexaReg && t.writesClampReg ? "+" : "")
                    + (t.writesClampReg ? "CLAMP_region_wrap" : "") });
            }
            // Rule 232 EE_TIME_SOURCE_ROSTER: timer COUNT/MODE consumers + COP0 Count readers.
            boolean timerHit = false;
            for(String rn : t.rcntRegsHit)
                if(rn.endsWith("_COUNT") || rn.endsWith("_MODE")) { timerHit = true; break; }
            if(timerHit || t.readsCop0Count){
                t.isEeTimeSource = true;
                if(!r.tags.contains("EE_TIME_SOURCE")){
                    r.tags.add("EE_TIME_SOURCE"); eeTimeSourceCount++;
                }
                StringBuilder det = new StringBuilder();
                if(!t.rcntRegsHit.isEmpty()) det.append(String.join("|", t.rcntRegsHit));
                if(t.readsCop0Count){
                    if(det.length() > 0) det.append("|");
                    det.append("COP0_COUNT");
                }
                det.append(";mainloop_depth=").append(t.mainLoopDepth);
                eeTimeSources.add(new String[]{ nm, hex(r.address), det.toString() });
            }
        }
        println(String.format(
            "  v17 Rule 222: MEMCPY_LOOP=%d IDLE_SPIN_YIELD=%d (perf ranking in perf_cost_ranking).",
            memcpyShapedLoopCount, idleSpinYieldCount));
        println(String.format(
            "  v17.1 (PCSX2 x2): MFIFO=%d STALL_CTRL=%d PATH_ARB=%d READBACK=%d "
          + "PRMODE=%d TEXA_CLAMP=%d TIME_SOURCE=%d",
            dmaMfifoUserCount, dmaStallControlCount, vifPathArbCount, gsReadbackSiteCount,
            prmodeAttrWriterCount, texaClampWriterCount, eeTimeSourceCount));
    }

    // =========================================================
    // v18 Rules 234-242: G142-G172 performance-arc retrospective + general PS2.
    // The whole prior rule set stops at G141 (Rule 222 = ACTIVE); everything learned
    // across the G142-G172 perf arc (inline sprite raster, MTGS present-reg bypass,
    // streamed-texture cache refutation, GPU-raster zero-eligibility, the level-load
    // "function not found" coverage gap, interlaced field-height variance) is added here.
    // Tags/counters/rosters; the scan-time facts (primClassesEmitted, isSpriteEmitter,
    // writesAlphaBlendReg/writesTestReg) were set in detectAdRegImmediateStores.
    // =========================================================
    private void applyV18Rules(List<FuncResult> results) {
        // --- collect the defined-function address set + a code-range proxy (Rule 236) ---
        Set<Long> definedAddrs = new HashSet<>();
        long minFn = Long.MAX_VALUE, maxFn = Long.MIN_VALUE;
        FunctionIterator dfi = funcManager.getFunctions(true);
        while(dfi.hasNext()) {
            Function f = dfi.next();
            long a = f.getEntryPoint().getOffset() & 0xFFFFFFFFL;
            definedAddrs.add(a);
            if(a < minFn) minFn = a;
            if(a > maxFn) maxFn = a;
        }

        for(FuncResult r : results) {
            FuncTraits t = r.traits; if(t == null) continue;
            String nm = r.name == null ? "" : r.name;

            // --- Rule 234 GS_PRIM_SPRITE_EMITTER + primitive-class cost profile ---
            boolean spriteName = false;
            for(String s : SPRITE_EMITTER_NAMES) if(nm.contains(s)) { spriteName = true; break; }
            if(spriteName) { t.isSpriteEmitter = true; t.primClassesEmitted.add("sprite"); }
            if(t.isSpriteEmitter || !t.primClassesEmitted.isEmpty()) {
                if(t.isSpriteEmitter && !r.tags.contains("GS_PRIM_SPRITE_EMITTER")) {
                    r.tags.add("GS_PRIM_SPRITE_EMITTER"); spriteEmitterCount++;
                }
                primClassEmitters.add(new String[]{ nm, hex(r.address),
                    String.join("|", t.primClassesEmitted) });
            }

            // --- Rule 235 SPRITE_GROUP_ORDER_DEPENDENCY ---
            // A compound 2D widget: a sprite emitter whose name is a widget shape and
            // that emits several sub-sprites in one body (backward loop, or >=2 XYZ2
            // kicks). Reorder-unsafe for tile-bin defer / band-parallel replay (G172).
            if(t.isSpriteEmitter) {
                boolean widgetName = false;
                for(String s : COMPOUND_WIDGET_NAMES) if(nm.contains(s)) { widgetName = true; break; }
                boolean multiKick = t.hasBackwardBranch || t.writesXyz2Reg;
                if(widgetName && multiKick) {
                    t.spriteGroupOrderDependency = true;
                    if(!r.tags.contains("SPRITE_GROUP_ORDER_DEPENDENCY")) {
                        r.tags.add("SPRITE_GROUP_ORDER_DEPENDENCY"); spriteGroupOrderCount++;
                    }
                    spriteCompoundWidgets.add(new String[]{ nm, hex(r.address),
                        "compound_widget;" + (t.hasBackwardBranch ? "loop_of_subsprites"
                                              : "multi_xyz2_kick") + ";defer_unsafe" });
                }
            }

            // --- Rule 236 RECOMPILE_TARGET_COVERAGE_GAP ---
            // Every direct-call / computed-jump target that lands in the code range but has
            // no defined function makes the recompiler panic "Function at address 0xN not
            // found" at runtime (DC2 blocker #2: 0xe3dc70 stalls level load).
            Set<Long> tgts = new LinkedHashSet<>();
            for(long[] s : t.jalSites)            if(s[1] != 0xFFFFFFFFL) tgts.add(s[1] & 0xFFFFFFFFL);
            for(long[] e : t.computedJumpTargets) tgts.add(e[1] & 0xFFFFFFFFL);
            for(Long tg : tgts) {
                if(tg == 0 || tg == 0xFFFFFFFFL) continue;
                if(tg < minFn || tg > maxFn) continue;          // outside code range = not this class
                if(definedAddrs.contains(tg)) continue;         // resolves to a real function
                if(!r.tags.contains("RECOMPILE_TARGET_COVERAGE_GAP")) {
                    r.tags.add("RECOMPILE_TARGET_COVERAGE_GAP");
                }
                recompileCoverageGaps.add(new String[]{ hex(tg),
                    "referenced_by=" + nm + "@" + hex(r.address),
                    "in_code_range_no_function;recompiler_will_panic_not_found" });
            }

            // --- Rule 238 PRESENTATION_REGISTER_FIFO_BYPASS (general PS2, the MTGS lesson) ---
            // The 6 presentation regs (PMODE/SMODE2/DISPFB1/DISPFB2/DISPLAY1/DISPLAY2) are
            // written on the EE thread through the direct IO path, BYPASSING the GS draw FIFO.
            // A multithreaded/pipelined GS must fence/latch them separately (G150/G157).
            boolean present = r.tags.contains("DISPFB_WRITER") || r.tags.contains("DISPFB_SDK_WRITER")
                || r.tags.contains("PRESENTATION_FIELD_STATE");
            if(present) {
                t.presentationFifoBypass = true;
                if(!r.tags.contains("PRESENTATION_REGISTER_FIFO_BYPASS")) {
                    r.tags.add("PRESENTATION_REGISTER_FIFO_BYPASS"); presentationFifoBypassCount++;
                }
                presentationFifoBypass.add(new String[]{ nm, hex(r.address),
                    "present_regs_bypass_gs_fifo;fence_or_latch_under_MTGS" });
            }

            // --- Rule 240 GPU_RASTER_ELIGIBILITY_CENSUS (general PS2) ---
            // G161 closed the whole GPU-raster arc: every deferred title triangle had BOTH
            // blend AND alpha-test, most paletted T8 -> the opaque-only gate matched 0/216000.
            // Classify each draw builder so "which prims are GPU-raster eligible" is static.
            boolean drawBuilder = t.gifTagInlineBuilder || t.writesGsPrimReg || t.writesXyz2Reg
                || t.isPackerFamily;
            if(drawBuilder && (t.writesAlphaBlendReg || t.writesTestReg || t.loadsPsm4hhConstant)) {
                boolean ineligible = t.writesAlphaBlendReg || t.writesTestReg || t.loadsPsm4hhConstant;
                t.gpuRasterEligibility = ineligible ? "blend_atest_paletted_ineligible" : "opaque_eligible";
                if(ineligible) gpuRasterIneligibleCount++; else gpuRasterEligibleCount++;
                gpuRasterEligibility.add(new String[]{ nm, hex(r.address),
                    t.gpuRasterEligibility
                    + (t.writesAlphaBlendReg ? ";blend" : "")
                    + (t.writesTestReg ? ";atest" : "")
                    + (t.loadsPsm4hhConstant ? ";paletted_psm" : "") });
            }
        }

        // --- Rule 237 TEXTURE_STREAM_CHURN (advisory) ---
        // G148/G149 refutation: a de-swizzle/decode texture cache is a NET LOSS for STREAMED
        // pages (re-uploaded every frame) that are sparsely sampled. Distinct BITBLTBUF
        // uploaders per labelled page proxies upload churn: >=2 = streamed (poor cache
        // candidate); ==1 = static (cacheable). Derived from the Rule 165 vramPageWriters map.
        for(Map.Entry<Long,Map<String,List<String>>> e : vramPageWriters.entrySet()) {
            Map<String,List<String>> byKind = e.getValue();
            List<String> uploaders = byKind.get("BITBLTBUF");
            if(uploaders == null || uploaders.isEmpty()) continue;
            long page = e.getKey();
            int distinct = new LinkedHashSet<>(uploaders).size();
            String label = KNOWN_DC2_TBP_LABELS.getOrDefault(page, "");
            streamedTexturePages.add(new String[]{ hex(page),
                (label.isEmpty() ? "" : label + ";") + (distinct >= 2 ? "STREAMED" : "static"),
                "distinct_uploaders=" + distinct
                + (distinct >= 2 ? ";poor_cache_candidate(sparse+churn)" : ";cacheable") });
        }

        println(String.format(
            "  v18 (G142-G172): SPRITE_EMIT=%d SPRITE_GROUP=%d COVERAGE_GAP=%d "
          + "STREAMED_TEX=%d PRESENT_BYPASS=%d GPU_RASTER(elig=%d/inelig=%d)",
            spriteEmitterCount, spriteGroupOrderCount, recompileCoverageGaps.size(),
            streamedTexturePages.size(), presentationFifoBypassCount,
            gpuRasterEligibleCount, gpuRasterIneligibleCount));
    }

    // =========================================================
    // v19 Rules 243-251: PCSX2 cross-check round 3 (D:\ps2r\pcsx2-master).
    // EE hardware CONTRACTS PCSX2 models that no prior rule flagged: interrupt-handler
    // dispatch (INTC/DMAC STAT/MASK + libkernel SDK), DMAtag-IRQ+TIE completion, VIFcode
    // i-bit, SIF RPC transport (SBUS flags + SIF0/1 DMA), CDVD read-completion gates, EE
    // cache-coherency ops, GS CSR SIGNAL/FINISH handshake, TLB mapping. Grounded in
    // Hw.h:304-330, Dmac.h:78/117, Vif.h:96, Sif.h. Scan-time facts (dmaChcrTie, vifCodeIBit,
    // hasCacheOp/hasSyncOp, writesTlb) set in detectV19Signals; the rest derive from existing
    // MMIO-recovery traits (writesIntcMask/readsIntcStat/dmacGlobalRegsHit/touchesSbusFlags/...).
    // =========================================================
    private void applyV19Rules(List<FuncResult> results) {
        for(FuncResult r : results) {
            FuncTraits t = r.traits; if(t == null) continue;
            String nm = r.name == null ? "" : r.name;

            // --- Rule 243 EE_INTERRUPT_HANDLER_REGISTRATION (general PS2) ---
            // The EE dispatches guest handlers registered via the libkernel SDK; the handler
            // ACKs by writing 1 to its INTC_STAT/DMAC_STAT bit. A recompiler that never fires
            // these leaves vsync/DMAC-completion callbacks dead (DC2 half-rate title loop F52).
            boolean handlerName = false;
            for(String cn : t.calleeNames) { for(String s : INTC_DMAC_HANDLER_NAMES) if(cn.contains(s)) { handlerName = true; break; } if(handlerName) break; }
            if(!handlerName) for(String s : INTC_DMAC_HANDLER_NAMES) if(nm.contains(s)) { handlerName = true; break; }
            boolean intcDmacMmio = t.writesIntcMask || t.readsIntcStat || t.writesDmacEnable
                || t.dmacGlobalRegsHit.contains("STAT") || t.dmacGlobalRegsHit.contains("PCR");
            if(handlerName || intcDmacMmio) {
                t.isInterruptHandlerReg = true;
                if(!r.tags.contains("EE_INTERRUPT_HANDLER_REGISTRATION")) {
                    r.tags.add("EE_INTERRUPT_HANDLER_REGISTRATION"); interruptHandlerCount++;
                }
                interruptHandlers.add(new String[]{ nm, hex(r.address),
                    (handlerName ? "handler_sdk" : "")
                    + (handlerName && intcDmacMmio ? "+" : "")
                    + (t.writesIntcMask ? "INTC_MASK" : "") + (t.readsIntcStat ? ";INTC_STAT" : "")
                    + (t.dmacGlobalRegsHit.contains("STAT") ? ";DMAC_STAT" : "")
                    + (t.dmacGlobalRegsHit.contains("PCR") ? ";DMAC_PCR" : "")
                    + (t.writesDmacEnable ? ";DMAC_ENABLE" : "") });
            }

            // --- Rule 244 DMA_TAG_IRQ_COMPLETION (general PS2) ---
            // A source-chain DMAtag with IRQ (bit31) + CHCR.TIE raises the channel DMAC IRQ on
            // tag completion (Dmac.h). Ignoring it -> the DMA-done handler/semaphore never fires.
            boolean chainKick = t.dmaSourceChainTagBuilder || t.dmaChcrStartKick
                || !t.dmaKickChannels.isEmpty() || !t.storedDmaTagIds.isEmpty();
            if(t.dmaChcrTie && chainKick) {
                if(!r.tags.contains("DMA_TAG_IRQ_COMPLETION")) {
                    r.tags.add("DMA_TAG_IRQ_COMPLETION"); dmaTagIrqCount++;
                }
                dmaTagIrqSites.add(new String[]{ nm, hex(r.address),
                    "CHCR_STR_TIE;chain_dma;verify_tag_IRQ_completion_interrupt_fires" });
            }

            // --- Rule 245 VIF_INTERRUPT_IBIT (general PS2, DC2 VU1 packets) ---
            // A VIFcode i-bit (bit31) raises VIF1 STAT.INT (Vif.h). A runtime that ignores it
            // never fires the VIF interrupt -> a game syncing on VIF-INT hangs.
            boolean vifBuilder = !t.vifOpcodesBuilt.isEmpty() || !t.storedVifOpcodes.isEmpty()
                || t.accessesVifCtrl || t.isMicrocodeUploader;
            if(t.vifCodeIBit && vifBuilder) {
                if(!r.tags.contains("VIF_INTERRUPT_IBIT")) {
                    r.tags.add("VIF_INTERRUPT_IBIT"); vifInterruptCount++;
                }
                vifInterruptSites.add(new String[]{ nm, hex(r.address),
                    "vifcode_i_bit;raises_VIF_STAT_INT;verify_interrupt_and_stall_handling" });
            }

            // --- Rule 246 SIF_RPC_TRANSPORT (general PS2, all DC2 IOP blockers) ---
            // SBUS MSFLG/SMFLG handshake + SIF0(ch5)/SIF1(ch6) DMA. With no IOP the EE deadlocks
            // polling SMFLG for a bit that never arrives (DC2 audio/memcard/cd RPC-wait class).
            boolean sifDma = t.compositeMmioRangesHit.contains("DMA_CHAN_SIF0")
                || t.compositeMmioRangesHit.contains("DMA_CHAN_SIF1");
            if(t.touchesSbusFlags || t.touchesSbus || sifDma) {
                t.isSifTransport = true;
                if(!r.tags.contains("SIF_RPC_TRANSPORT")) {
                    r.tags.add("SIF_RPC_TRANSPORT"); sifTransportCount++;
                }
                sifTransportSites.add(new String[]{ nm, hex(r.address),
                    (t.touchesSbusFlags ? "SBUS_MSFLG/SMFLG" : "")
                    + (t.touchesSbus ? ";SBUS_MSCOM/SMCOM" : "")
                    + (sifDma ? ";SIF0/1_DMA" : "")
                    + (t.isSyncWaitLoop ? ";POLL_WAIT(iop_dead_deadlock_risk)" : "") });
            }

            // --- Rule 247 CDVD_READ_COMPLETION_GATE (DC2 blocker #2, general) ---
            // A backward-branch wait polling a sceCd* completion signal. DC2 level load streams
            // DATA.DAT via sceCdRead (F55); a level that "cannot be loaded" can stall here.
            boolean cdName = false;
            for(String cn : t.calleeNames) { for(String s : CDVD_COMPLETION_NAMES) if(cn.contains(s)) { cdName = true; break; } if(cdName) break; }
            if(!cdName) for(String s : CDVD_COMPLETION_NAMES) if(nm.contains(s)) { cdName = true; break; }
            if(cdName && (t.isSyncWaitLoop || t.hasBackwardBranch)) {
                t.isCdvdCompletionGate = true;
                if(!r.tags.contains("CDVD_READ_COMPLETION_GATE")) {
                    r.tags.add("CDVD_READ_COMPLETION_GATE"); cdvdGateCount++;
                }
                cdvdCompletionGates.add(new String[]{ nm, hex(r.address),
                    "sceCd_completion_poll;level_load_stream_gate;mainloop_depth=" + t.mainLoopDepth });
            }

            // --- Rule 248 EE_CACHE_COHERENCY_OP (general PS2, DC2 scratchpad) ---
            // cache/sync ops matter when the game DMAs code/data into RAM then reads/executes it
            // before a coherency op (stale read otherwise). Flag them, esp. near a DMA kick.
            if(t.hasCacheOp || t.hasSyncOp) {
                boolean nearDma = chainKick || t.usesSPR || t.isDynamicCodeLoader;
                if(!r.tags.contains("EE_CACHE_COHERENCY_OP")) {
                    r.tags.add("EE_CACHE_COHERENCY_OP"); cacheOpCount++;
                }
                cacheOps.add(new String[]{ nm, hex(r.address),
                    (t.hasCacheOp ? "cache" : "") + (t.hasCacheOp && t.hasSyncOp ? "+" : "")
                    + (t.hasSyncOp ? "sync" : "") + (nearDma ? ";near_dma_or_loader" : "") });
            }

            // --- Rule 249 GS_CSR_SIGNAL_HANDSHAKE (general PS2, extends Rule 79) ---
            // GIF A+D SIGNAL/FINISH/LABEL writes latch GS CSR + raise GS INT unless IMR masks;
            // the handler acks via CSR. DC2 IMR=0x7F00 masks all (Rule 79 stubs its handlers).
            boolean signalWrite = t.gsRegHits.contains("SIGNAL") || t.gsRegHits.contains("FINISH")
                || t.gsRegHits.contains("LABEL");
            boolean csrAccess = t.gsPrivRegHits.contains("CSR");
            if(signalWrite || csrAccess) {
                t.isGsCsrSignalSite = true;
                if(!r.tags.contains("GS_CSR_SIGNAL_HANDSHAKE")) {
                    r.tags.add("GS_CSR_SIGNAL_HANDSHAKE"); gsCsrCount++;
                }
                gsCsrSites.add(new String[]{ nm, hex(r.address),
                    (t.gsRegHits.contains("SIGNAL") ? "SIGNAL" : "")
                    + (t.gsRegHits.contains("FINISH") ? ";FINISH" : "")
                    + (t.gsRegHits.contains("LABEL") ? ";LABEL" : "")
                    + (csrAccess ? ";CSR_ack" : "")
                    + ";DC2_IMR_masks_all(Rule79_stubbable)" });
            }

            // --- Rule 250 EE_TLB_MAPPING (general PS2, "absence is a finding") ---
            if(t.writesTlb) {
                if(!r.tags.contains("EE_TLB_MAPPING")) {
                    r.tags.add("EE_TLB_MAPPING"); tlbWriterCount++;
                }
                tlbWriters.add(new String[]{ nm, hex(r.address),
                    "tlb_write;custom_memory_mapping;flat_recompiler_hazard" });
            }
        }

        println(String.format(
            "  v19 (PCSX2 x3): INTC_DMAC_HANDLER=%d DMA_TAG_IRQ=%d VIF_IBIT=%d SIF_TRANSPORT=%d "
          + "CDVD_GATE=%d CACHE_OP=%d TLB=%d GS_CSR=%d",
            interruptHandlerCount, dmaTagIrqCount, vifInterruptCount, sifTransportCount,
            cdvdGateCount, cacheOpCount, tlbWriterCount, gsCsrCount));
    }

    // v15 Rule 194: fuzzy allocator-family membership for demangled/underscore variants
    // (operator new/delete, _r reentrant forms) not in the exact-name set.
    private static boolean isAllocFamilyName(String nm) {
        if(nm == null) return false;
        String n = nm;
        if(n.equals("malloc") || n.equals("free") || n.equals("calloc") || n.equals("realloc")
            || n.equals("memalign") || n.equals("valloc")
            || n.matches("_(malloc|free|calloc|realloc|memalign|valloc)_r"))
            return true;
        // operator delete (incl. array) always frees the heap.
        if(n.startsWith("__dl__") || n.startsWith("__dla__")) return true;
        // operator new (incl. array): HEAP new only. PLACEMENT new — operator new(size, void*)
        // mangled `__nw__FUiPv` / `__nw__FUiP1` — constructs in place, does NOT allocate, and is
        // legitimately bound separately (OVERRIDE). Excluding it stops a spurious family "split".
        if(n.startsWith("__nw__") || n.startsWith("__nwa__"))
            return !n.matches("__nwa?__FU.*P.*");
        return false;
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
    // v11 (General v15): a radar stub now needs BOTH a host-boundary name
    // match (exact or word-boundary family) AND trait corroboration.
    // Name-only matching is what stubbed `exponent` on FF1 (prefix "exp")
    // and would stub real game code on any title that reuses SDK-ish
    // spellings.
    private boolean isRadarFirewalled(Function func, FuncTraits traits) {
        Address key=func.getEntryPoint();
        Boolean c=staticFwCache.get(key);if(c!=null)return c;
        boolean hit = matchesHostBoundaryName(func.getName())
                && (hasHostBoundaryEvidence(traits) || hasWeakSdkThunkEvidence(traits));
        staticFwCache.put(key,hit);return hit;
    }

    // [FIX v4] containsSyscall and containsCOP0 removed - folded into getTraits() main loop.
    // Their logic now populates traits.hasSyscall and traits.hasCOP0 fields.
    // isKernelInternal replaced with inline traits.hasSyscall||traits.hasCOP0.
    // referencesIopModule replaced with traits.refsIopModuleString.

    // =========================================================
    // v11.3: POST-REGEN COP2 PATCH GENERATION
    // The COP2 dest-mask fix (F51.8) patches recomp/*.cpp, which only exist
    // AFTER ps2_recomp.exe runs - so it cannot run inside this Ghidra pass.
    // Instead we EMIT it (RECOMP path pre-filled) next to the triage output and
    // list it in post_regen_steps.md, derived from this run's COP2 model, so it
    // ships with the map and can't be forgotten or drift.
    // =========================================================
    private void emitCop2FixScript(File outputDir, List<FuncResult> results) {
        int riskFns = 0;
        for (FuncResult r : results)
            if (r.traits != null && r.traits.cop2DestMaskVerify) riskFns++;
        String recompDir = "D:/ps2r/dc2/recomp";
        try (PrintWriter w = utf8Writer(new File(outputDir, "fix_cop2_destmask.py"))) {
            w.println("#!/usr/bin/env python3");
            w.println("# AUTO-GENERATED by the DC2 TriageEnricher (v11.3). Do not hand-edit; regenerate.");
            w.println("# F51.8: reverse the recompiler COP2 dest-component-mask lane order in generated");
            w.println("# recomp files. The generator emits `__m128i mask = _mm_set_epi32(X,Y,Z,W)` mapping");
            w.println("# VU dest X->lane3 .. W->lane0, but lqc2/sqc2/broadcast use X=lane0 .. W=lane3, so the");
            w.println("# 4 args are reversed. Full-dest masks (-1,-1,-1,-1) are symmetric -> no-op.");
            w.println("# >>> RUN THIS AFTER ps2_recomp.exe regenerates recomp/*.cpp (post-regen stage). <<<");
            w.println("# This run flagged " + riskFns + " COP2 partial-dest-risk fn(s) (triage_map.json cop2_partial_dest_risk).");
            w.println("import re, sys, glob, os");
            w.println("");
            w.println("RECOMP = r\"" + recompDir + "\"");
            w.println("pat = re.compile(r\"(__m128i mask = _mm_set_epi32\\()\\s*(-?\\d+)\\s*,\\s*(-?\\d+)\\s*,\\s*(-?\\d+)\\s*,\\s*(-?\\d+)\\s*(\\))\")");
            w.println("");
            w.println("def fix_text(text):");
            w.println("    n = [0]");
            w.println("    def repl(m):");
            w.println("        a, b, c, d = m.group(2), m.group(3), m.group(4), m.group(5)");
            w.println("        if a == d and b == c:");
            w.println("            return m.group(0)  # symmetric -> unchanged");
            w.println("        n[0] += 1");
            w.println("        return f\"{m.group(1)}{d}, {c}, {b}, {a}{m.group(6)}\"");
            w.println("    out = pat.sub(repl, text)");
            w.println("    return out, n[0]");
            w.println("");
            w.println("def main():");
            w.println("    files = sys.argv[1:]");
            w.println("    if not files:");
            w.println("        files = []");
            w.println("        for f in glob.glob(os.path.join(RECOMP, \"*.cpp\")):");
            w.println("            with open(f, \"r\", encoding=\"utf-8\", errors=\"replace\") as fh:");
            w.println("                t = fh.read()");
            w.println("            if \"_mm_blendv_ps(ctx->vu0_vf\" in t or \"PS2_VBLEND(ctx->vu0_vf\" in t:");
            w.println("                files.append(f)");
            w.println("    total_files = 0");
            w.println("    total_swaps = 0");
            w.println("    for f in files:");
            w.println("        with open(f, \"r\", encoding=\"utf-8\", errors=\"replace\") as fh:");
            w.println("            t = fh.read()");
            w.println("        nt, n = fix_text(t)");
            w.println("        if n > 0:");
            w.println("            with open(f, \"w\", encoding=\"utf-8\", newline=\"\") as fh:");
            w.println("                fh.write(nt)");
            w.println("            total_files += 1");
            w.println("            total_swaps += n");
            w.println("            print(f\"  {os.path.basename(f)}: {n} partial-mask(s) reversed\")");
            w.println("    print(f\"DONE: {total_files} files changed, {total_swaps} partial dest-masks reversed\")");
            w.println("");
            w.println("if __name__ == \"__main__\":");
            w.println("    main()");
        } catch (Exception e) {
            printerr("[COP2] Failed to emit fix_cop2_destmask.py: " + e.getMessage());
        }
        try (PrintWriter w = utf8Writer(new File(outputDir, "post_regen_steps.md"))) {
            w.println("# Post-regen steps (auto-generated by the DC2 TriageEnricher v11.3)");
            w.println("");
            w.println("Run these AFTER `ps2_recomp.exe` regenerates `recomp/*.cpp`, in order:");
            w.println("");
            w.println("1. **COP2 dest-mask reversal (F51.8) - MANDATORY.** `python fix_cop2_destmask.py`");
            w.println("   (emitted beside this file, RECOMP path pre-filled). " + riskFns + " partial-dest-risk");
            w.println("   function(s) flagged this run. Skipping it regresses ALL VU0-macro 3D transforms.");
            w.println("2. **VU0 helper collision audit.** Any `sceVu0*` rescued to RECOMPILE that the runtime");
            w.println("   also implements (Kernel/Stubs/VU.cpp) collides under /FORCE:MULTIPLE - verify the");
            w.println("   winner per function, or lock the runtime-backed ones in the config.");
            w.println("3. **Allocator-family coherence.** malloc/free/_malloc_r/memalign/operator new must all");
            w.println("   route to the runtime (G1) - no half-runtime/half-recompiled split.");
            w.println("4. **Smoke test.** `tools/run_30s_diagnose.ps1` - title must stay golden before promoting.");
        } catch (Exception e) {
            printerr("[COP2] Failed to emit post_regen_steps.md: " + e.getMessage());
        }
        println("[COP2] Emitted fix_cop2_destmask.py + post_regen_steps.md (" + riskFns + " risk fns).");
    }

    // v11.3: compare two configs by EXECUTABLE content only - each line is cut at
    // its first '#' (drops the header block, the advisory pointer, and inline
    // # TAG annotations) then trimmed; blank results are dropped. Lets the
    // incremental mode leave the live config untouched when only comments/tags
    // would have churned, and rewrite only on a real selector/section delta.
    private boolean configBodyEquals(File a, File b) {
        try { return semanticConfigLines(a).equals(semanticConfigLines(b)); }
        catch (Exception e) { return false; }
    }
    private List<String> semanticConfigLines(File f) throws IOException {
        List<String> out = new ArrayList<>();
        try (BufferedReader r = utf8Reader(f)) {
            String ln;
            while ((ln = r.readLine()) != null) {
                int h = ln.indexOf('#');
                if (h >= 0) ln = ln.substring(0, h);
                ln = ln.trim();
                if (!ln.isEmpty()) out.add(ln);
            }
        }
        return out;
    }

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
        BufferedReader reader=utf8Reader(step1Config);
        String line;while((line=reader.readLine())!=null)lines.add(line);
        reader.close();
        // v11.1 RE-ENTRANT SANITIZE: when the input is a previous enricher
        // output (evolving config_auto_recomp.toml workflow), strip
        // everything THIS script generates before regenerating it - header
        // comment block, advisory pointer comment, and any old
        // [triage_advisory] section (incl. its banner comments and the
        // trailing commented-out "# [patches]" candidate block). Without
        // this, headers stack and stale advisory data survives forever.
        // Step1-exporter inputs (DAC.toml) contain none of these lines, so
        // the pass is a no-op for them.
        {
            // 1. Drop the old [triage_advisory] section: from its banner
            //    comments through to the next REAL section header or EOF.
            int advIdx=-1;
            for(int i=0;i<lines.size();i++)
                if(lines.get(i).trim().equals("[triage_advisory]")){advIdx=i;break;}
            if(advIdx>=0){
                int start=advIdx;
                // back up over the banner comment lines directly above it.
                while(start>0){
                    String p=lines.get(start-1).trim();
                    if(p.startsWith("#")||p.isEmpty()) start--;
                    else break;
                }
                int end=advIdx+1;
                while(end<lines.size()){
                    String p=lines.get(end).trim();
                    if(p.startsWith("[")&&!p.startsWith("[triage_advisory")) break;
                    end++;
                }
                lines.subList(start,end).clear();
            }
            // 2. Drop our own one-line artifacts wherever they sit.
            lines.removeIf(l -> {
                String t=l.trim();
                if(!t.startsWith("#")) return false;
                return t.startsWith("# Unified config:")
                    || (t.contains("inherited stub +") && t.contains("inherited skip"))
                    || t.startsWith("# removed (now RECOMPILE)")
                    || t.startsWith("# !! Rule 154:")
                    || t.contains("EMIT_VERBOSE_TOML_ADVISORY")
                    || t.contains("\"triage_advisory\". Set")
                    || (t.startsWith("# v11:") && t.contains("advisory entries"))
                    || t.contains("locked entries kept verbatim")
                    || t.startsWith("# native_impl_needed / review / nop")
                    || t.startsWith("# candidates) live in triage_map.json");
            });
        }
        // v11 (General v15.5 Bugfix T): normalize single-line stub/skip
        // arrays (`stubs = [..]`, `skip = []`) into multi-line form so the
        // rescue-removal and insertion passes below see one entry per line.
        // The old scanner never found the closing `]` of an inline array:
        // enricher additions were silently dropped and the in-array state
        // leaked into the following lines.
        for(int i=0;i<lines.size();i++){
            String t=lines.get(i).trim();
            boolean isStubsLine = t.startsWith("stubs");
            boolean isSkipLine  = t.startsWith("skip") && !t.startsWith("skip_count");
            if(!(isStubsLine||isSkipLine)) continue;
            int ob=t.indexOf('['); int cb=t.lastIndexOf(']');
            if(ob<0||cb<=ob) continue;            // already multi-line
            String body=t.substring(ob+1,cb);
            List<String> expanded=new ArrayList<>();
            expanded.add((isStubsLine?"stubs":"skip")+" = [");
            java.util.regex.Matcher m=java.util.regex.Pattern
                .compile("\"((?:[^\"\\\\]|\\\\.)*)\"").matcher(body);
            while(m.find()) expanded.add("  \""+m.group(1)+"\",");
            expanded.add("]");
            lines.remove(i);
            lines.addAll(i, expanded);
            i += expanded.size()-1;
        }
        // v11: guarantee both arrays exist when we have additions to place.
        {
            boolean hasStubsArr=false, hasSkipArr=false;
            int generalIdx=-1;
            for(int i=0;i<lines.size();i++){
                String t=lines.get(i).trim();
                if(t.equals("[general]")) generalIdx=i;
                if(t.startsWith("stubs")) hasStubsArr=true;
                if(t.startsWith("skip")&&!t.startsWith("skip_count")) hasSkipArr=true;
            }
            int insertAt = generalIdx>=0 ? generalIdx+1 : lines.size();
            if(!hasSkipArr && !newSkips.isEmpty()){
                lines.add(insertAt,"]");
                lines.add(insertAt,"skip = [");
            }
            if(!hasStubsArr && !newStubs.isEmpty()){
                lines.add(insertAt,"]");
                lines.add(insertAt,"stubs = [");
            }
        }
        // v11 (General v15.1): DROP inherited stub/skip entries the keep gate
        // (or a later promote pass) rescued to RECOMPILE. The TOML stays the
        // executable safe subset; per-entry reasons/evidence live in
        // triage_map.json under "rescued_from_step1".
        int rescuedStubLines=0, rescuedSkipLines=0;
        {
            boolean inS=false,inK=false;
            for(int i=0;i<lines.size();i++){
                String t=lines.get(i).trim();
                if(t.startsWith("stubs")){inS=true;inK=false;continue;}
                if(t.startsWith("skip")&&!t.startsWith("skip_count")){inK=true;inS=false;continue;}
                if(t.equals("]")){inS=false;inK=false;continue;}
                if(!(inS||inK)||!t.startsWith("\""))continue;
                int q2=t.indexOf('"',1);
                if(q2<0)continue;
                String tok=t.substring(1,q2);
                String nm=tok;long ad=-1;
                int at=tok.lastIndexOf('@');
                if(at>=0){
                    nm=tok.substring(0,at);
                    ad=parseHexULong(tok.substring(at+1));
                    if(ad>=0)ad&=0xFFFFFFFFL;
                }
                String reason = ad>=0 ? step1RescueByAddr.get(ad) : null;
                if(reason==null && !nm.isEmpty()) reason=step1RescueByName.get(nm);
                if(reason==null)continue;
                lines.remove(i); i--;
                if(inS)rescuedStubLines++;else rescuedSkipLines++;
            }
        }
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
        lines.add(0,"# Unified config: "+step1Config.getName()+" + "+newStubs.size()+" stubs + "
            +newSkips.size()+" skips (DC2 Enricher v11)");
        lines.add(1,"# "+rescuedStubLines+" inherited stub + "+rescuedSkipLines
            +" inherited skip entries failed the high-confidence safety gate and were");
        lines.add(2,"# removed (now RECOMPILE). Per-entry reason/evidence: triage_map.json "
            +"\"rescued_from_step1\".");
        if(step1LockedKeptCount>0)
            lines.add(3,"# v11.1: "+step1LockedKeptCount+" locked entries kept verbatim "
                +"(# LOCKED / locked = [...] - keep gate bypassed).");
        // v11 Rule 154: surface ELF identity mismatch at the top of the config.
        if("mismatch".equals(step1ElfHashStatus))
            lines.add(3,"# !! Rule 154: input toml elf_hash does NOT match this ELF - "
                +"every surviving address binding is suspect. Regenerate the input toml.");
        // v11.1: recompute stub_count/skip_count from ACTUAL array contents.
        // The old `old + new - rescued` delta math compounded across
        // re-entrant runs (each run re-adjusted an already-adjusted count).
        int actualStubCount=0, actualSkipCount=0;
        {
            boolean inS=false,inK=false;
            for(String l0 : lines){
                String t=l0.trim();
                if(t.startsWith("stubs")){inS=true;inK=false;continue;}
                if(t.startsWith("skip")&&!t.startsWith("skip_count")){inK=true;inS=false;continue;}
                if(t.equals("]")||t.startsWith("]")){inS=false;inK=false;continue;}
                if(!(inS||inK)||!t.startsWith("\"")) continue;
                if(inS)actualStubCount++;else actualSkipCount++;
            }
        }
        // v11.1: embed this ELF's hash into [general] so the NEXT run gets
        // the Rule 154 identity guard even on re-entrant input. Update an
        // existing elf_hash line in place; otherwise insert after [general].
        if(elfHashForEmit!=null && !elfHashForEmit.isEmpty()){
            boolean hashSet=false;
            for(int i=0;i<lines.size();i++){
                if(lines.get(i).trim().startsWith("elf_hash")){
                    lines.set(i,"elf_hash = \""+elfHashForEmit+"\"");
                    hashSet=true;break;
                }
            }
            if(!hashSet){
                for(int i=0;i<lines.size();i++){
                    if(lines.get(i).trim().equals("[general]")){
                        lines.add(i+1,"elf_hash = \""+elfHashForEmit+"\"");
                        break;
                    }
                }
            }
        }
        for(int i=0;i<lines.size();i++){
            String l=lines.get(i);
            if(l.startsWith("stub_count =")){
                lines.set(i,"stub_count = "+actualStubCount);
            } else if(l.startsWith("skip_count =")){
                lines.set(i,"skip_count = "+actualSkipCount);
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
        // v9 Rule 137 / v11 (General v15.2): the advisory block is built
        // unconditionally (it also populates advisoryJsonLists for the JSON
        // "triage_advisory" object - the detailed source of truth), but it is
        // appended to the TOML only when EMIT_VERBOSE_TOML_ADVISORY is set.
        // By default the TOML stays the executable safe subset: [general] /
        // stubs / skip / [patches] + a short pointer comment.
        List<String> advisory = buildTriageAdvisoryBlock(results);
        PrintWriter w=utf8Writer(outFile);
        for(String l:lines)w.println(l);
        if(EMIT_VERBOSE_TOML_ADVISORY) {
            for(String l:advisory)w.println(l);
        } else {
            int advisoryTotal = 0;
            for(List<String> v : advisoryJsonLists.values()) advisoryTotal += v.size();
            advisoryTotal += advisoryPatchInstr.size();
            if(advisoryTotal > 0) {
                w.println("");
                w.println("# v11: "+advisoryTotal+" advisory entries (force_recompile / must_implement /");
                w.println("# native_impl_needed / review / nop / patch / DC2 lists / patch-instruction");
                w.println("# candidates) live in triage_map.json \"triage_advisory\". Set");
                w.println("# EMIT_VERBOSE_TOML_ADVISORY=true to also emit them here.");
            }
        }
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
        // v10 advisory lists
        List<String> cop2DestmaskList = new ArrayList<>();
        List<String> memoryAllocatorList = new ArrayList<>();
        List<String> staticInitRepairList = new ArrayList<>();
        List<String> guestLockHogList = new ArrayList<>();
        // v10.1 advisory lists
        List<String> cop2SpecialList = new ArrayList<>();
        List<String> computedJumpUnresolvedList = new ArrayList<>();
        // v11 (General v14) advisory lists
        List<String> nativeImplList = new ArrayList<>();
        List<String> reviewList = new ArrayList<>();
        advisoryJsonLists.clear();
        advisoryPatchInstr.clear();
        for(FuncResult r : results) {
            if(r.traits == null) continue;
            // v11 (General v15): override-bound functions already have a
            // hand-written handler - never emit them into advisory arrays.
            if("OVERRIDE".equals(r.disposition)) continue;
            FuncTraits t = r.traits;
            String token = r.name + "@" + hex(r.address);
            String tagCmt = prioritizeTagsForComment(r.tags, 4);
            String suffix = tagCmt.isEmpty() ? "" : "  # " + tagCmt;
            // v11 (General v13): never emit a function into the advisory
            // force_recompile list while it sits in the binding stubs/skip
            // arrays. The binding firewall already rescued everything with
            // hard evidence; what remains stubbed (e.g. pure IRX-loader
            // shapes) must not be contradicted one section lower in the same
            // TOML.
            boolean boundToStubOrSkip = "STUB".equals(r.disposition) || "SKIP".equals(r.disposition);
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
            if(fr && !boundToStubOrSkip) forceRecompileList.add("  \""+token+"\","+suffix);
            // v11 (General v14): native_impl_needed collection. Two ways in:
            //  (a) bound stub/skip whose traits show it fronted an IOP-side
            //      subsystem (IRX loader string, SIF RPC, audio RPC) - the
            //      stub is intentional but the subsystem now needs a host
            //      implementation;
            //  (b) recompiled RPC binder/IRX loader - the EE side will run,
            //      but only works if the runtime services its RPC SIDs /
            //      module loads natively.
            boolean rpcGateway = t.callsSifRpc ||
                    t.detectedRpcSid != 0 || !t.discoveredRpcSids.isEmpty();
            boolean iopSubsystemFront = t.refsIopModuleString ||
                    t.isIrxLoader || t.sifLoadModuleCallCount >= 1 ||
                    t.isAudioRpcHandler || t.isIopRebootHandler;
            boolean noHandlerStub = r.tags.contains("NO_RUNTIME_HANDLER");
            if((boundToStubOrSkip && (iopSubsystemFront || rpcGateway || noHandlerStub)) ||
               (!boundToStubOrSkip && (t.isIrxLoader ||
                    t.detectedRpcSid != 0 || !t.discoveredRpcSids.isEmpty()))) {
                nativeImplList.add("  \""+token+"\","+suffix);
            }
            // v11 (General v14/v15): review collection - firewall rescues,
            // mixed IRX-init shapes, step1 rescues, handler-less stubs,
            // out-of-text bindings, kept-but-address-taken bindings.
            boolean pureLoaderShape = t.refsIopModuleString &&
                    t.byteSize <= 200 && t.calleeCount <= 4 &&
                    !t.accessesMMIO && !t.writesIntcMask &&
                    t.dmaKickChannels.isEmpty();
            boolean mixedIrxInit = t.refsIopModuleString && !pureLoaderShape;
            if(r.tags.contains("BINDING_FIREWALL_RESCUED") || mixedIrxInit ||
               r.tags.contains("STEP1_RESCUED") ||
               r.tags.contains("NO_RUNTIME_HANDLER") ||
               r.tags.contains("OUT_OF_TEXT_BINDING") ||
               r.tags.contains("ADDRESS_TAKEN_CALLBACK")) {
                reviewList.add("  \""+token+"\","+suffix);
            }
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
            // v10 advisory categories
            if(t.cop2DestMaskVerify)
                cop2DestmaskList.add("  \""+token+"\","+suffix);
            if(t.isMemoryAllocator)
                memoryAllocatorList.add("  \""+token+"\","+suffix);
            if(t.isStaticInitializer && t.staticInitInstallsVtable)
                staticInitRepairList.add("  \""+token+"\","+suffix);
            if(t.isGuestLockHogCandidate)
                guestLockHogList.add("  \""+token+"\","+suffix);
            // v10.1
            if(!t.cop2SpecialOps.isEmpty())
                cop2SpecialList.add("  \""+token+"\","+suffix);
            if(!t.computedJumpSwitchPcs.isEmpty()){
                java.util.Set<Long> resolved = new java.util.HashSet<>();
                for(long[] e : t.computedJumpTargets) resolved.add(e[0]);
                boolean anyUnres=false;
                for(Long pc : t.computedJumpSwitchPcs) if(!resolved.contains(pc)){anyUnres=true;break;}
                if(anyUnres) computedJumpUnresolvedList.add("  \""+token+"\","+suffix);
            }
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
                // v11: structured copy for the JSON triage_advisory object.
                advisoryPatchInstr.add(new String[]{
                    String.format("0x%08X", pc & 0xFFFFFFFFL), reason, token});
            }
        }
        // v11: stash raw copies of every advisory list for the JSON
        // "triage_advisory" object (TOML stays executable-only by default).
        advisoryJsonLists.put("nop",                       rawAdvisoryEntries(nopList));
        advisoryJsonLists.put("patch",                     rawAdvisoryEntries(patchList));
        advisoryJsonLists.put("force_recompile",           rawAdvisoryEntries(forceRecompileList));
        advisoryJsonLists.put("must_implement",            rawAdvisoryEntries(mustImplementList));
        advisoryJsonLists.put("native_impl_needed",        rawAdvisoryEntries(nativeImplList));
        advisoryJsonLists.put("review",                    rawAdvisoryEntries(reviewList));
        advisoryJsonLists.put("dc2_blockers",              rawAdvisoryEntries(dc2BlockersList));
        advisoryJsonLists.put("dc2_host_wait",             rawAdvisoryEntries(dc2HostWaitList));
        advisoryJsonLists.put("bullseye_upload",           rawAdvisoryEntries(bullseyeUploadList));
        advisoryJsonLists.put("cop2_destmask_verify",      rawAdvisoryEntries(cop2DestmaskList));
        advisoryJsonLists.put("memory_allocator_never_stub", rawAdvisoryEntries(memoryAllocatorList));
        advisoryJsonLists.put("static_init_vtable_repair", rawAdvisoryEntries(staticInitRepairList));
        advisoryJsonLists.put("guest_lock_hog_candidate",  rawAdvisoryEntries(guestLockHogList));
        advisoryJsonLists.put("cop2_special_ops_review",   rawAdvisoryEntries(cop2SpecialList));
        advisoryJsonLists.put("computed_jump_unresolved",  rawAdvisoryEntries(computedJumpUnresolvedList));
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
        // v11 (General v14)
        emitTomlList(out, "native_impl_needed",   nativeImplList);
        emitTomlList(out, "review",               reviewList);
        emitTomlList(out, "dc2_blockers",         dc2BlockersList);
        emitTomlList(out, "dc2_host_wait",        dc2HostWaitList);
        emitTomlList(out, "bullseye_upload",      bullseyeUploadList);
        // v10: F47-F52 advisory categories.
        emitTomlList(out, "cop2_destmask_verify", cop2DestmaskList);
        emitTomlList(out, "memory_allocator_never_stub", memoryAllocatorList);
        emitTomlList(out, "static_init_vtable_repair", staticInitRepairList);
        emitTomlList(out, "guest_lock_hog_candidate", guestLockHogList);
        // v10.1: PCSX2-/skill-grounded advisory categories.
        emitTomlList(out, "cop2_special_ops_review", cop2SpecialList);
        emitTomlList(out, "computed_jump_unresolved", computedJumpUnresolvedList);
        // Commented patches block — humans uncomment manually after verifying.
        out.add("");
        out.add("# [patches]");
        out.add("# instructions = [");
        for(String l : patchCandidateLines) out.add("#" + l);
        out.add("# ]");
        return out;
    }

    // v10.1: emit a JSON `"name": [ <pre-rendered entries> ]` member inside an
    // object. Entries already carry their own indentation.
    private void emitJsonObjArray(PrintWriter w, String name, List<String> entries, boolean trailingComma) {
        w.println("    \""+name+"\": [");
        for(int i=0;i<entries.size();i++)
            w.println(entries.get(i) + (i<entries.size()-1 ? "," : ""));
        w.println("    ]" + (trailingComma ? "," : ""));
    }

    private void emitTomlList(List<String> out, String name, List<String> entries) {
        out.add("");
        out.add(name + " = [");
        for(String e : entries) out.add(e);
        out.add("]");
    }

    /** v11: convert pre-rendered TOML advisory lines (`  "name@0xADDR",  # T1,T2`)
     *  back to raw `name@0xADDR # T1,T2` entries for the JSON writer. */
    private static List<String> rawAdvisoryEntries(List<String> tomlLines) {
        List<String> out = new ArrayList<>();
        for(String l : tomlLines) {
            String t = l.trim();
            if(!t.startsWith("\"")) continue;
            int q2 = t.indexOf('"', 1);
            if(q2 < 0) continue;
            String entry = t.substring(1, q2);
            int hash = t.indexOf('#', q2);
            String tags = hash >= 0 ? t.substring(hash+1).trim() : "";
            out.add(tags.isEmpty() ? entry : entry + " # " + tags);
        }
        return out;
    }

    // v8 Rule 109: cheap line-scanning reader. Extracts {address: "disposition|category"}
    // pairs from a prior triage_map.json without bringing in a JSON dependency.
    private Map<Long,String> loadPriorTriageMapCats(File f) throws IOException {
        Map<Long,String> out = new HashMap<>();
        BufferedReader r = utf8Reader(f);
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
    /** v11 (General v15.5 Bugfix U): GS-side static evidence gate for the
     *  Rule 78 TBP constant list. */
    private static boolean hasGsSideEvidence(FuncTraits t) {
        return t.writesTex0Reg || t.writesBitbltbufReg || t.writesRgbaqReg
            || t.writesZbufReg || t.writesDispfbReg || t.writesDispfbViaSdk
            || t.writesGsPrimReg || t.gifTagInlineBuilder
            || t.bitbltbufMacroSequence || t.isMicrocodeUploader
            || t.path3Initiator || t.path3KickViaDmaApi || t.touchesGifCtrl
            || t.touchesGifP3Reg || t.writesGifFifo || t.writesVif1Fifo
            || t.writesVif0Fifo || t.accessesVuMicromem || t.accessesVuDatamem
            || t.loadsPsm4hhConstant || !t.dmaKickChannels.isEmpty()
            || t.dmaChcrStartKick;
    }

    // v14: filename-safe slug for a function name.
    private static String slug(String s) {
        if(s == null || s.isEmpty()) return "anon";
        StringBuilder b = new StringBuilder(s.length());
        for(int i=0;i<s.length() && b.length()<80;i++){
            char c = s.charAt(i);
            b.append((Character.isLetterOrDigit(c)||c=='.'||c=='_'||c=='-') ? c : '_');
        }
        return b.length()==0 ? "anon" : b.toString();
    }
    // v14.1: stable grep token - keep symbol chars, collapse the rest to '_'.
    private static String tok(String s) {
        if(s == null || s.isEmpty()) return "anon";
        StringBuilder b = new StringBuilder(s.length());
        for(int i=0;i<s.length();i++){
            char c = s.charAt(i);
            b.append((Character.isLetterOrDigit(c)||c=='_'||c=='.'||c=='$') ? c : '_');
        }
        return b.toString();
    }
    // v14.1: derived per-function Markdown filename (matches writeFunctionDocs).
    private static String mdNameFor(long addr, String name) {
        String f = (name==null||name.isEmpty()) ? ("sub_"+hex(addr)) : name;
        return hex(addr)+"_"+slug(f)+".md";
    }
    // v14: append "- LABEL\n" for each true boolean signal (compact, readable).
    private static void sig(StringBuilder b, boolean on, String label) {
        if(on) b.append("- ").append(label).append('\n');
    }
    private static void sigList(StringBuilder b, Collection<String> c, String label) {
        if(c != null && !c.isEmpty()) b.append("- ").append(label).append(": `")
            .append(String.join("`, `", c)).append("`\n");
    }

    // v14: per-function Markdown docs. One functions/<addr>_<name>.md per ELF
    // function, with the full triage signal set + assembly + decompiled C +
    // control-flow, for an AI working on the recompilation.
    private void writeFunctionDocs(File functionsDir, List<FuncResult> results,
                                   String elfHash, long gpValue) throws IOException {
        Map<Long,String> nameByAddr = new HashMap<>();
        Map<String,Long> nameToAddr = new HashMap<>();
        for(FuncResult r : results) {
            nameByAddr.put(r.address & 0xFFFFFFFFL, r.name);
            if(r.name != null && !r.name.isEmpty()) nameToAddr.putIfAbsent(r.name, r.address & 0xFFFFFFFFL);
        }
        String exportTs  = new java.text.SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss").format(new java.util.Date());
        String exportVer = "DC2 enricher v19 (schema 18.0)";
        int n = 0;
        for(FuncResult r : results) {
            if(monitor.isCancelled()) break;
            FuncTraits t = r.traits;
            AiRec rec = buildFunctionRecommendation(r);
            String fname = (r.name==null||r.name.isEmpty()) ? ("sub_"+hex(r.address)) : r.name;
            File md = new File(functionsDir, hex(r.address)+"_"+slug(fname)+".md");
            try (PrintWriter w = utf8Writer(md)) {
                w.println("# "+fname);
                w.println();
                w.println("`"+hex(r.address)+"` · **"+r.category+"** · disposition **"+r.disposition
                    +"** · origin `"+r.origin+"`");
                w.println();
                // --- Export metadata (stale-export protection) ---
                w.println("> schema_version `18.0` · elf_hash `"+elfHash+"` · global_pointer `"+hex(gpValue)
                    +"` · exported `"+exportTs+"` · enricher `"+exportVer+"`");
                w.println(">");
                w.println("> _If elf_hash / global_pointer differ from the current ELF, this doc is stale — re-run the enricher._");
                w.println();
                // --- Summary table ---
                w.println("## Summary");
                w.println();
                w.println("| field | value |");
                w.println("|---|---|");
                w.println("| address | `"+hex(r.address)+"` |");
                w.println("| name | `"+fname+"` |");
                w.println("| category | "+r.category+" |");
                w.println("| disposition | "+r.disposition+(r.rescueReason!=null?(" (rescued: "+r.rescueReason+")"):"")+" |");
                w.println("| origin | "+r.origin+(r.step1Disposition!=null?(" / step1="+r.step1Disposition):"")+" |");
                if(t != null) {
                    w.println("| size (bytes) | "+t.byteSize+" |");
                    w.println("| mainloop_depth | "+t.mainLoopDepth+" |");
                    w.println("| init_chain_depth | "+t.initChainDepth+" |");
                    w.println("| drawing_chain_depth | "+t.drawingChainDepth+" |");
                    w.println("| module_id | "+t.moduleId+" |");
                    if(t.dc2KnownRole!=null)
                        w.println("| dc2_known_role | "+t.dc2KnownRole+" ("+t.dc2KnownPhase+", "+t.dc2KnownCriticality+") |");
                }
                w.println("| subsystem (AI) | "+rec.subsystem+" |");
                w.println("| role (AI) | "+rec.role+" |");
                w.println();
                // --- AI recommendation ---
                w.println("## Recommendation (AI)");
                w.println();
                w.println("- **action**: "+rec.action+"  (confidence "+rec.confidence+", risk "+rec.risk+")");
                if(rec.reason!=null && !rec.reason.isEmpty())          w.println("- **reason**: "+rec.reason);
                if(rec.suggestedNextStep!=null && !rec.suggestedNextStep.isEmpty()) w.println("- **next step**: "+rec.suggestedNextStep);
                if(rec.riskIfStubbed!=null && !rec.riskIfStubbed.isEmpty())     w.println("- **risk if stubbed**: "+rec.riskIfStubbed);
                if(rec.riskIfRecompiled!=null && !rec.riskIfRecompiled.isEmpty()) w.println("- **risk if recompiled**: "+rec.riskIfRecompiled);
                if(rec.gateway) w.println("- **gateway function** (subsystem entry point)");
                w.println();
                // --- Tags ---
                w.println("## Tags");
                w.println();
                if(r.tags.isEmpty()) w.println("_(none)_");
                else { StringBuilder tb=new StringBuilder(); for(String tg:r.tags) tb.append("`").append(tg).append("` "); w.println(tb.toString().trim()); }
                w.println();
                // --- Signals (every true trait / non-empty list) ---
                if(t != null) {
                    StringBuilder s = new StringBuilder();
                    sig(s,t.usesCop1,"uses COP1 (FPU)"); sig(s,t.usesCop2,"uses COP2 / VU0 macro");
                    sig(s,t.usesSPR,"uses scratchpad (SPR)"); sig(s,t.writesToGlobal,"writes a global");
                    sig(s,t.hasVcallms,"VU0 microcode (vcallms)"); sig(s,t.hasJumpTable,"jump table");
                    sig(s,t.accessesMMIO,"accesses MMIO"); sig(s,t.accessesVif1MMIO,"VIF1 MMIO");
                    sig(s,t.callsDmaSend,"calls DMA send"); sig(s,t.callsSifRpc,"SIF RPC");
                    sig(s,t.hasBackwardBranch,"backward branch (loop)"); sig(s,t.hasSyscall,"syscall");
                    sig(s,t.isLargeInitFunc,"large init func"); sig(s,t.isMemoryAllocator,"memory allocator ("+t.allocatorKind+")");
                    sig(s,t.isCtor,"C++ ctor ("+t.ctorClassName+")"); sig(s,t.isDtor,"C++ dtor");
                    sig(s,t.ctorInstallsVtable,"installs vtable @"+hex(t.ctorVtableAddr));
                    sig(s,t.isStaticInitializer,"__sinit static initializer"); sig(s,t.isUncalledStaticInit,"UNCALLED __sinit (init-order risk)");
                    sig(s,t.staticInitInstallsVtable,"sinit installs vtable");
                    sig(s,t.isProcessTerminator,"process terminator"); sig(s,t.isLibgccIntrinsic,"libgcc intrinsic");
                    sig(s,t.readsEabiArgT0,"reads EABI 5th arg in $t0");
                    sig(s,t.writesFrameReg,"writes GS FRAME"); sig(s,t.writesZbufReg,"writes GS ZBUF");
                    sig(s,t.writesTex0Reg,"writes GS TEX0"); sig(s,t.writesBitbltbufReg,"writes BITBLTBUF");
                    sig(s,t.writesDispfbReg,"writes DISPFB"); sig(s,t.writesRgbaqReg,"writes RGBAQ");
                    sig(s,t.isRttTarget,"RTT_TARGET (renders to a texture page)");
                    sig(s,t.zbufVramAliasRisk,"ZBUF aliases live VRAM"); sig(s,t.isVf0DependentInverse,"vf0-dependent matrix inverse");
                    sig(s,t.cop2DestMaskVerify,"COP2 partial-dest (verify lane order, F51.8)");
                    sig(s,t.isAudioCompletionGate,"audio/stream completion gate"); sig(s,t.isMemcardIo,"memcard I/O");
                    sig(s,t.writesPresentationFieldState,"interlace/field GS reg"); sig(s,t.isDisplayBufferFlip,"display-buffer flip");
                    sig(s,t.isClutCacheInvalidator,"CLUT cache invalidator / TEXFLUSH"); sig(s,t.isPerfHotFramePath,"perf-hot frame path");
                    sig(s,t.programsSprDma,"programs fromSPR/toSPR DMA"); sig(s,t.subwordDmaStrKick,"sub-word DMA STR kick");
                    // v13
                    sig(s,t.isConditionalInitOnGlobal,"CONDITIONAL_INIT_ON_GLOBAL (init-order gap, G58/G81)");
                    sig(s,t.isRenderModeSelector,"RENDER_MODE_SELECTOR (copy vs transform, G75-G80)");
                    sig(s,t.isVertexLightingTerm,"VERTEX_LIGHTING_NORMAL_TERM (N·L / shade, G82)");
                    sig(s,t.isVtableTailcallThunk,"VTABLE_TAILCALL_THUNK (G59 recompiler dispatch)");
                    sig(s,t.isRttNoRestore,"RTT_NO_RESTORE (GS-state leak, G79)");
                    sig(s,t.isVuFlagPipelineUploader,"VU_FLAG_PIPELINE_UPLOADER (G71)");
                    sig(s,t.isPackedRgbaqBuilder,"PACKED_RGBAQ_BUILDER (spread layout, G82)");
                    sig(s,t.isFrameResumeRisk,"FRAME_RESUME_RISK (mid-body resume, G58/G59)");
                    // v15
                    sig(s,t.isPrimClassSelector,"GIFTAG_PRIM_CLASS_SELECTOR (qword38 PRIM route, G77-G115)");
                    sig(s,t.isAdcKickVertexSource,"ADC_KICK_VERTEX_SOURCE ("+(t.adcSource==null?"":t.adcSource)+", G65-G115)");
                    sig(s,t.isKickModeWriter,"XYZ2_VS_XYZ3_KICK_WRITER (per-vertex draw-kick)");
                    sig(s,t.isTextureReloadInterleave,"TEXTURE_RELOAD_INTERLEAVE_HAZARD (G90-G97)");
                    sig(s,t.isVsyncCoupledGameStep,"VSYNC_COUPLED_GAME_STEP (perf, G103)");
                    sig(s,t.isViewProjectionMatrixWriter,"VIEW_PROJECTION_MATRIX_WRITER (shared camera, G98/G99)");
                    sig(s,t.isObjectArrayCtor,"OBJECT_ARRAY_CTOR (per-element vtables, G92)");
                    sigList(s,new ArrayList<>(t.vuExecHazards),"VU exec hazards (manifest)");
                    // v15.1 (PCSX2-grounded)
                    sig(s,t.isVifUnpackDecompressState,"VIF_UNPACK_DECOMPRESS_STATE (STMOD/STMASK/STROW/STCOL)");
                    sig(s,t.isXyoffsetGuardWriter,"GS_XYOFFSET_GUARD_BAND (guard-band centre, G88)");
                    sig(s,t.isTex1FilterWriter,"GS_TEX1_FILTER_WRITER (MMAG/MMIN, G8)");
                    sigList(s,new ArrayList<>(t.vifUnpackStateCmds),"VIF unpack state cmds");
                    // v15.2 (skill codegen classes)
                    sig(s,t.usesMmi,"MMI_SIMD_OP ("+t.mmiOpCount+" ops — verify recompiler lane/pack codegen)");
                    sig(s,t.usesCop2ControlReg,"COP2_CONTROL_REG_ACCESS (CFC2/CTC2 — verify control-reg map)");
                    // v16 (G116-G137 title-cavern retrospective)
                    sig(s,t.isAdcCapablePacker||t.adcCapability!=null,"VERTEX_KICK_FORMAT_ADC_CAPABILITY ("+(t.adcCapability==null?"":t.adcCapability)+", G132)");
                    sig(s,t.isNearPlaneSite,"PERSPECTIVE_DIVIDE_NEAR_PLANE_SOURCE ("+(t.nearPlaneStrategy==null?"":t.nearPlaneStrategy)+", G125-G129)");
                    sig(s,t.isSpiConfigCommand,"SPI_CONFIG_COMMAND_DISPATCH (cfgXXX map-config, G129/G130)");
                    sig(s,t.isCommandInterpreter,"DATA_DRIVEN_COMMAND_INTERPRETER ("+(t.interpreterDetail==null?"":t.interpreterDetail)+")");
                    sig(s,t.isPackerFamily,"PASSTHROUGH_PACKER_RENDER_PATH ("+(t.packerFamily==null?"":t.packerFamily)+", G130)");
                    sig(s,t.isPrivateDepthScope,"PRIVATE_DEPTH_SCOPE (needs private per-frame Z, G125)");
                    sig(s,t.isPackedFieldAlias,"PACKED_FIELD_ALIAS_FOG_ADC (word3 fog vs ADC bit111, G132)");
                    sigList(s,new ArrayList<>(t.mmiFamilies),"MMI families");
                    sigList(s,new ArrayList<>(t.cop2ControlRegs),"COP2 control regs");
                    sigList(s,t.guardGlobals,"guard globals");
                    sigList(s,t.lightingSources,"lighting sources");
                    sigList(s,t.cop2SpecialOps,"COP2 special ops");
                    sigList(s,t.dc2GlobalsTouched,"DC2 globals touched");
                    sigList(s,new ArrayList<>(t.audioGateSignals),"audio gate signals");
                    sigList(s,new ArrayList<>(t.presentationRegs),"presentation regs");
                    sigList(s,new ArrayList<>(t.vifOpcodesBuilt),"VIF opcodes built");
                    if(!t.vramKnownPagesHit.isEmpty()){
                        StringBuilder pg=new StringBuilder();
                        for(Long p:t.vramKnownPagesHit){ if(pg.length()>0)pg.append(", ");
                            pg.append(hex(p)).append("=").append(KNOWN_DC2_TBP_LABELS.getOrDefault(p,"")); }
                        s.append("- VRAM pages: ").append(pg).append('\n');
                    }
                    if(!t.tailcallVtableSlots.isEmpty()){
                        StringBuilder sl=new StringBuilder(); for(Long x:t.tailcallVtableSlots){ if(sl.length()>0)sl.append(", "); sl.append(hex(x)); }
                        s.append("- vtable tail-call slots: ").append(sl).append('\n');
                    }
                    if(s.length()>0){ w.println("## Signals"); w.println(); w.print(s.toString()); w.println(); }
                }
                // --- Memory / Globals (gp-relative refs recovered from assembly) ---
                w.println("## Memory / Globals");
                w.println();
                if(t != null && !t.literalRefs.isEmpty()) {
                    // signed gp offset -> [readBit, writeBit]; preserve first-seen order.
                    Map<Long,boolean[]> gpModes = new LinkedHashMap<>();
                    for(String[] lr : t.literalRefs) {
                        if(lr.length < 4 || !"gp".equalsIgnoreCase(lr[2])) continue;
                        String oh = lr[3]; boolean neg = oh.startsWith("-");
                        String hp = oh.replace("-","").replace("0x","").replace("0X","");
                        long mag; try { mag = Long.parseLong(hp, 16); } catch(Exception e){ continue; }
                        long signed = neg ? -mag : mag;
                        boolean[] m = gpModes.computeIfAbsent(signed, k -> new boolean[2]);
                        if(lr[1]!=null && lr[1].toLowerCase().startsWith("s")) m[1]=true; else m[0]=true;
                    }
                    if(gpModes.isEmpty()) w.println("_(no gp-relative references)_");
                    else for(Map.Entry<Long,boolean[]> e : gpModes.entrySet()) {
                        long signed = e.getKey();
                        long absAddr = (gpValue + signed) & 0xFFFFFFFFL;
                        boolean[] m = e.getValue();
                        String mode = m[0] && m[1] ? "read/write" : (m[1] ? "write" : "read");
                        String gpTok = "gp" + (signed<0?"-":"+") + "0x" + Long.toHexString(Math.abs(signed));
                        String sym = KNOWN_DC2_GP_OFFSETS.get(signed & 0xFFFFFFFFL);
                        w.println("- `"+gpTok+"` = `"+hex(absAddr)+"` — "+mode
                            + (sym!=null ? (" — `"+sym+"`") : ""));
                    }
                } else {
                    w.println("_(no gp-relative references)_");
                }
                w.println();
                // --- Calls ---
                w.println("## Calls");
                w.println();
                if(t != null) {
                    w.println("**Callees ("+t.calleeNames.size()+"):** "
                        + (t.calleeNames.isEmpty() ? "_(none)_" : "`"+String.join("`, `", t.calleeNames)+"`"));
                    w.println();
                    StringBuilder cb = new StringBuilder();
                    for(long[] c : t.callers){
                        String cn = nameByAddr.getOrDefault(c[0]&0xFFFFFFFFL, "");
                        if(cb.length()>0) cb.append(", ");
                        cb.append(cn).append("(").append(hex(c[0])).append("@").append(hex(c[1])).append(")");
                    }
                    w.println("**Callers ("+t.callers.size()+"):** "+(t.callers.isEmpty()?"_(none)_":cb.toString()));
                    w.println();
                }
                // --- Related Function Files (direct edges only, with derived filenames) ---
                w.println("## Related Function Files");
                w.println();
                if(t != null) {
                    w.println("### Callees");
                    boolean anyCallee=false;
                    java.util.LinkedHashSet<String> seenCallee = new java.util.LinkedHashSet<>();
                    for(String cn : t.calleeNames){
                        if(cn==null || !seenCallee.add(cn)) continue;
                        Long ca = nameToAddr.get(cn);
                        if(ca != null) { w.println("- `"+hex(ca)+"` — `"+cn+"` — `"+mdNameFor(ca,cn)+"`"); anyCallee=true; }
                        else           { w.println("- `"+cn+"` — _(address not resolved; external/SDK or stripped)_"); anyCallee=true; }
                    }
                    if(!anyCallee) w.println("_(none)_");
                    w.println();
                    w.println("### Callers");
                    if(t.callers.isEmpty()) w.println("_(none)_");
                    else for(long[] c : t.callers){
                        long ca = c[0]&0xFFFFFFFFL; String cn = nameByAddr.getOrDefault(ca, "");
                        w.println("- `"+hex(ca)+"` — `"+(cn.isEmpty()?("sub_"+hex(ca)):cn)+"` @ `"+hex(c[1])
                            +"` — `"+mdNameFor(ca,cn)+"`");
                    }
                    w.println();
                }
                // --- Search Anchors (grep-friendly tokens) ---
                w.println("## Search Anchors");
                w.println();
                {
                    StringBuilder a = new StringBuilder();
                    a.append("`FUNC_").append(hex(r.address)).append("`\n");
                    a.append("`NAME_").append(tok(fname)).append("`\n");
                    a.append("`CATEGORY_").append(tok(r.category)).append("`\n");
                    a.append("`DISPOSITION_").append(tok(r.disposition)).append("`\n");
                    for(String tg : r.tags) a.append("`TAG_").append(tok(tg)).append("`\n");
                    if(t != null){
                        java.util.LinkedHashSet<String> cs = new java.util.LinkedHashSet<>();
                        for(String cn : t.calleeNames){ if(cn!=null && cs.add(cn)) a.append("`CALLS_").append(tok(cn)).append("`\n"); }
                        java.util.LinkedHashSet<String> cb2 = new java.util.LinkedHashSet<>();
                        for(long[] c : t.callers){ String cn=nameByAddr.getOrDefault(c[0]&0xFFFFFFFFL,""); if(!cn.isEmpty() && cb2.add(cn)) a.append("`CALLED_BY_").append(tok(cn)).append("`\n"); }
                    }
                    w.print(a.toString());
                }
                w.println();
                // --- Code ---
                w.println("## Assembly");
                w.println();
                w.println("```asm");
                w.println(r.asmText==null?"":r.asmText.trim());
                w.println("```");
                w.println();
                w.println("## Decompiled");
                w.println();
                w.println("```c");
                w.println(r.decompText==null?"":r.decompText.trim());
                w.println("```");
                w.println();
                w.println("## Control flow");
                w.println();
                w.println("```");
                w.println(r.flowText==null?"":r.flowText.trim());
                w.println("```");
                w.println();
                w.println("---");
                w.println("_Full machine-readable record: `index/functions_index.json` (address `"+hex(r.address)+"`)._");
            }
            n++;
            if(n%500==0) monitor.setMessage("Writing function doc "+n+"...");
        }
        println("[DOCS] Wrote "+n+" function Markdown files to functions/");
    }

    // v14: the four focused lookup indexes (functions_index.json is written by
    // writeTriageJson). Small, queryable, cross-cutting views for the AI.
    private void writeLookupIndexes(File indexDir, List<FuncResult> results,
                                    String elfHash, long gpValue) throws IOException {
        Map<Long,String> nameByAddr = new HashMap<>();
        for(FuncResult r : results) nameByAddr.put(r.address & 0xFFFFFFFFL, r.name);
        // Stale-export metadata stamped into every index header.
        final String idxMeta = "  \"elf_hash\": \""+elfHash+"\",\n"
            + "  \"global_pointer\": \""+hex(gpValue)+"\",\n"
            + "  \"export_timestamp\": \""
            + new java.text.SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss").format(new java.util.Date())+"\",";

        // --- calls_index.json ---
        try (PrintWriter w = utf8Writer(new File(indexDir,"calls_index.json"))) {
            w.println("{");
            w.println("  \"schema_version\": \"1.0\",");
            w.println(idxMeta);
            w.println("  \"purpose\": \"forward + reverse call graph (jal edges) per function\",");
            w.println("  \"functions\": [");
            for(int i=0;i<results.size();i++){
                FuncResult r = results.get(i); FuncTraits t = r.traits;
                w.print("    {\"address\": \""+hex(r.address)+"\", \"name\": "+jsonString(r.name)
                    +", \"callees\": "+(t==null?"[]":jsonStrArray(t.calleeNames))
                    +", \"callers\": [");
                if(t != null) for(int j=0;j<t.callers.size();j++){
                    if(j>0) w.print(", ");
                    long[] c = t.callers.get(j);
                    w.print("{\"address\": \""+hex(c[0])+"\", \"name\": "
                        +jsonString(nameByAddr.getOrDefault(c[0]&0xFFFFFFFFL,""))
                        +", \"call_site\": \""+hex(c[1])+"\"}");
                }
                w.print("]}");
                w.println(i<results.size()-1?",":"");
            }
            w.println("  ]");
            w.println("}");
        }

        // --- xrefs_index.json ---
        try (PrintWriter w = utf8Writer(new File(indexDir,"xrefs_index.json"))) {
            w.println("{");
            w.println("  \"schema_version\": \"1.0\",");
            w.println(idxMeta);
            w.println("  \"purpose\": \"xref counts + incoming references + referenced globals per function\",");
            w.println("  \"functions\": [");
            for(int i=0;i<results.size();i++){
                FuncResult r = results.get(i); FuncTraits t = r.traits;
                w.print("    {\"address\": \""+hex(r.address)+"\", \"name\": "+jsonString(r.name)
                    +", \"xref_to_count\": "+(t==null?0:t.xrefToCount)
                    +", \"caller_count\": "+(t==null?0:t.callers.size())
                    +", \"referenced_globals\": "+(t==null?"[]":jsonStrArray(new ArrayList<>(t.dc2GlobalsTouched)))
                    +", \"literal_refs\": [");
                if(t != null) for(int j=0;j<t.literalRefs.size();j++){
                    if(j>0) w.print(", ");
                    String[] lr = t.literalRefs.get(j);
                    w.print("{\"pc\": "+jsonString(lr[0])+", \"mnem\": "+jsonString(lr[1])
                        +", \"base_reg\": "+jsonString(lr[2])+", \"offset\": "+jsonString(lr[3])
                        +", \"dest_reg\": "+jsonString(lr[4])+"}");
                }
                w.print("]}");
                w.println(i<results.size()-1?",":"");
            }
            w.println("  ]");
            w.println("}");
        }

        // --- tags_index.json ---
        try (PrintWriter w = utf8Writer(new File(indexDir,"tags_index.json"))) {
            Map<String,List<FuncResult>> byTag = new TreeMap<>();
            for(FuncResult r : results) for(String tg : r.tags)
                byTag.computeIfAbsent(tg, k -> new ArrayList<>()).add(r);
            w.println("{");
            w.println("  \"schema_version\": \"1.0\",");
            w.println(idxMeta);
            w.println("  \"purpose\": \"tag -> functions carrying it (priority-ranked triage buckets)\",");
            w.println("  \"tags\": {");
            int ti=0;
            for(Map.Entry<String,List<FuncResult>> e : byTag.entrySet()){
                w.print("    "+jsonString(e.getKey())+": {\"count\": "+e.getValue().size()
                    +", \"priority\": "+TAG_PRIORITY.getOrDefault(e.getKey(),0)+", \"functions\": [");
                List<FuncResult> fs = e.getValue();
                for(int j=0;j<fs.size();j++){
                    if(j>0) w.print(", ");
                    w.print("{\"address\": \""+hex(fs.get(j).address)+"\", \"name\": "+jsonString(fs.get(j).name)+"}");
                }
                w.print("]}");
                w.println(++ti<byTag.size()?",":"");
            }
            w.println("  }");
            w.println("}");
        }

        // --- globals_index.json ---
        try (PrintWriter w = utf8Writer(new File(indexDir,"globals_index.json"))) {
            // token -> readers / writers / sinit-writers / touchers.
            Map<String,Set<String>> readers = new TreeMap<>();
            Map<String,Set<String>> writers = new TreeMap<>();
            Map<String,Set<String>> sinitWriters = new TreeMap<>();
            Map<String,Set<String>> touchers = new TreeMap<>();
            for(FuncResult r : results){
                FuncTraits t = r.traits; if(t==null) continue;
                String nm = r.name==null?"":r.name;
                boolean isSinit = t.isStaticInitializer || t.isUncalledStaticInit;
                for(String g : t.guardGlobals) readers.computeIfAbsent(g,k->new LinkedHashSet<>()).add(nm);
                for(String lbl : t.dc2GlobalsTouched) touchers.computeIfAbsent(lbl,k->new LinkedHashSet<>()).add(nm);
                Set<String> wts = new LinkedHashSet<>();
                for(Long a : t.returnWrittenToGlobals) wts.add("0x"+Long.toHexString(a & 0xFFFFFFFFL));
                for(Long a : t.ctorGlobalAddresses)    wts.add("0x"+Long.toHexString(a & 0xFFFFFFFFL));
                for(long[] inst : t.staticInitInstalls) wts.add("0x"+Long.toHexString(inst[1] & 0xFFFFFFFFL));
                for(String tok : wts)
                    (isSinit?sinitWriters:writers).computeIfAbsent(tok,k->new LinkedHashSet<>()).add(nm);
            }
            Set<String> all = new TreeSet<>();
            all.addAll(readers.keySet()); all.addAll(writers.keySet());
            all.addAll(sinitWriters.keySet()); all.addAll(touchers.keySet());
            w.println("{");
            w.println("  \"schema_version\": \"1.0\",");
            w.println(idxMeta);
            w.println("  \"purpose\": \"global token -> readers / writers / __sinit-writers / touchers; init-order hazard support (Rule 186)\",");
            w.println("  \"globals\": {");
            int gi=0;
            for(String tok : all){
                Set<String> rd=readers.getOrDefault(tok,Collections.emptySet());
                Set<String> wr=writers.getOrDefault(tok,Collections.emptySet());
                Set<String> si=sinitWriters.getOrDefault(tok,Collections.emptySet());
                Set<String> tc=touchers.getOrDefault(tok,Collections.emptySet());
                boolean hazard = !rd.isEmpty() && wr.isEmpty();
                w.print("    "+jsonString(tok)+": {\"readers\": "+jsonStrArray(new ArrayList<>(rd))
                    +", \"writers\": "+jsonStrArray(new ArrayList<>(wr))
                    +", \"sinit_writers\": "+jsonStrArray(new ArrayList<>(si))
                    +", \"touchers\": "+jsonStrArray(new ArrayList<>(tc))
                    +", \"init_order_hazard\": "+hazard+"}");
                w.println(++gi<all.size()?",":"");
            }
            w.println("  }");
            w.println("}");
        }
        println("[INDEX] Wrote calls_index, xrefs_index, tags_index, globals_index to index/");
    }

    private void writeTriageJson(File outFile,List<FuncResult> results,
                                 String elfHash,long gpValue,
                                 int totalFuncs,int uncategorized) throws IOException {
        // v11 (General v15.5 Bugfix U) Rule 78 noise gate: tbp_constants_loaded
        // used to collect EVERY immediate in (0,0x3FFF] from every function -
        // 16-byte syscall trampolines were reporting "TBP constants". A
        // function with no GS-side evidence and no runtime-confirmed TBP match
        // carries no meaningful TBP signal; drop the list before emission.
        for(FuncResult r:results){
            FuncTraits t=r.traits;
            if(t==null) continue;
            if(t.tbpRuntimeConfirmed.isEmpty() && !hasGsSideEvidence(t))
                t.tbpConstantsLoaded.clear();
        }
        PrintWriter w=utf8Writer(outFile);
        w.println("{");
        w.println("  \"schema_version\": 18.0,");
        w.println("  \"enricher_version\": \"DC2 enricher v19 (schema 18.0)\",");
        w.println("  \"export_timestamp\": \""
            +new java.text.SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss").format(new java.util.Date())+"\",");
        w.println("  \"elf_hash\": \""+elfHash+"\",");
        if(gpValue!=0)w.println("  \"global_pointer\": \""+hex(gpValue)+"\",");
        w.println("  \"text_range\": { \"start\": \""+hex(textStart)+"\", \"end\": \""+hex(textEnd)+"\" },");
        w.println("  \"mainloop_shield_size\": "+mainLoopShield.size()+",");
        w.println("  \"game_override_imported\": "+gameOverrideImportedCount+",");
        w.println("  \"statistics\": {");
        w.println("    \"total_functions\": "+totalFuncs+",");
        w.println("    \"uncategorized_from_step1\": "+uncategorized+",");
        w.println("    \"enriched_count\": "+results.size()+",");
        // v11 (General v15): step1 vetting summary.
        {
            int s1kept=0, s1rescued=0, ovr=0;
            for(FuncResult r : results) {
                if("step1".equals(r.origin)) {
                    if(r.rescueReason!=null) s1rescued++; else s1kept++;
                } else if("override".equals(r.origin)) ovr++;
            }
            w.println("    \"step1_inherited_kept\": "+s1kept+",");
            w.println("    \"step1_rescued_to_recompile\": "+s1rescued+",");
            w.println("    \"step1_locked_kept\": "+step1LockedKeptCount+",");
            w.println("    \"step1_name_mismatches\": "+step1NameMismatchCount+",");
            w.println("    \"step1_truncated_names\": "+step1TruncatedNameCount+",");
            w.println("    \"step1_elf_hash\": \""+step1ElfHashStatus+"\",");
            w.println("    \"runtime_handler_roster_size\": "
                +(runtimeRosterLoaded ? runtimeHandlerNames.size() : 0)+",");
            w.println("    \"no_runtime_handler_stubs\": "+noHandlerStubCount+",");
            w.println("    \"overlay_binding_vetoes\": "+overlayVetoCount+",");
            w.println("    \"out_of_text_bindings\": "+outOfTextBindingCount+",");
            w.println("    \"override_bound\": "+ovr+",");
        }
        // v11 Rule 161: >0 means this ELF loads EE code at runtime (overlay /
        // DGO-style); recompiling the ELF alone does not cover the game.
        // DC2 expectation: 0.
        w.println("    \"dynamic_code_loaders\": "+dynamicCodeLoaderCount+",");
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
        // v11.3 Rules 162-164
        w.println("    \"spr_dma_stager\": "+sprDmaStagerCount+",");
        w.println("    \"subword_dma_str_kick\": "+subwordDmaStrKickCount+",");
        w.println("    \"vu1_double_buffer_framer\": "+vu1DoubleBufferFramerCount+",");
        w.println("    \"stale_ptr_cache_ctor\": "+stalePtrCacheCtorCount+",");
        // v12 Rules 165-177
        w.println("    \"frame_reg_writer\": "+frameRegWriterCount+",");
        w.println("    \"rtt_target\": "+rttTargetCount+",");
        w.println("    \"zbuf_vram_alias_risk\": "+zbufVramAliasCount+",");
        w.println("    \"vram_overlap_pairs\": "+vramOverlapPairs.size()+",");
        w.println("    \"vf0_dependent_inverse\": "+vf0DependentInverseCount+",");
        w.println("    \"audio_completion_gate\": "+audioCompletionGateCount+",");
        w.println("    \"memcard_io\": "+memcardIoCount+",");
        w.println("    \"presentation_field_state\": "+presentationFieldStateCount+",");
        w.println("    \"display_buffer_flip\": "+displayBufferFlipCount+",");
        w.println("    \"clut_cache_invalidator\": "+clutCacheInvalidatorCount+",");
        w.println("    \"perf_hot_frame_path\": "+perfHotFramePathCount+",");
        w.println("    \"gs_local_mem_pages_referenced\": "+gsLocalMemPagesReferenced.size()+",");
        // v13 Rules 178-188
        w.println("    \"conditional_init_on_global\": "+conditionalInitOnGlobalCount+",");
        w.println("    \"render_mode_selector\": "+renderModeSelectorCount+",");
        w.println("    \"vertex_lighting_normal_term\": "+vertexLightingTermCount+",");
        w.println("    \"vtable_tailcall_thunk\": "+vtableTailcallThunkCount+",");
        w.println("    \"rtt_no_restore\": "+rttNoRestoreCount+",");
        w.println("    \"vu_flag_pipeline_uploader\": "+vuFlagPipelineUploaderCount+",");
        w.println("    \"packed_rgbaq_builder\": "+packedRgbaqBuilderCount+",");
        w.println("    \"frame_resume_risk\": "+frameResumeRiskCount+",");
        w.println("    \"init_order_hazards\": "+initOrderHazards.size()+",");
        // v15 Rules 190-198 (G83-G115 ADC/packer/pacing) — surfaced for the boot dashboard.
        w.println("    \"prim_class_selector\": "+primClassSelectorCount+",");
        w.println("    \"adc_kick_vertex_source\": "+adcKickVertexSourceCount+",");
        w.println("    \"kick_mode_writer\": "+kickModeWriterCount+",");
        w.println("    \"texture_reload_interleave\": "+textureReloadInterleaveCount+",");
        w.println("    \"vsync_coupled_game_step\": "+vsyncCoupledGameStepCount+",");
        w.println("    \"view_projection_writer\": "+viewProjectionWriterCount+",");
        w.println("    \"object_array_ctor\": "+objectArrayCtorCount+",");
        w.println("    \"allocator_family_split\": "+allocatorFamilySplit+",");
        w.println("    \"vu_exec_hazard_manifest\": "+vuExecHazardManifest.size()+",");
        // v15.1 Rules 199-202 (PCSX2 cross-check)
        w.println("    \"vif_unpack_decompress_state\": "+vifUnpackDecompressCount+",");
        w.println("    \"xyoffset_guard_writer\": "+xyoffsetGuardWriterCount+",");
        w.println("    \"tex1_filter_writer\": "+tex1FilterWriterCount+",");
        // v15.2 Rules 203-206 (skill cross-check)
        w.println("    \"mmi_codegen_risk\": "+mmiCodegenRiskCount+",");
        w.println("    \"cop2_control_reg_access\": "+cop2ControlRegCount+",");
        w.println("    \"unfunded_texture_pages\": "+unfundedTexturePages.size()+",");
        // v16 Rules 207-214 (G116-G137 title-cavern retrospective)
        w.println("    \"adc_capable_packer\": "+adcCapablePackerCount+",");
        w.println("    \"near_plane_site\": "+nearPlaneSiteCount+",");
        w.println("    \"spi_config_command\": "+spiConfigCommandCount+",");
        w.println("    \"command_interpreter\": "+commandInterpreterCount+",");
        w.println("    \"packer_family\": "+packerFamilyCount+",");
        w.println("    \"private_depth_scope\": "+privateDepthScopeCount+",");
        w.println("    \"packed_field_alias\": "+packedFieldAliasCount+",");
        // v17 Rules 217-225 (G138-G140 VU1-interpreter retrospective + G141 perf)
        w.println("    \"vu_microcode_programs\": "+vuMicrocodePrograms.size()+",");
        {
            int spTot=0, u4Tot=0, x4Tot=0;
            for(VuProgram vp : vuMicrocodePrograms){
                spTot += vp.samePairHazardCount;
                u4Tot += vp.flagConsumersUnder4;
                x4Tot += vp.flagConsumersExactly4;
            }
            w.println("    \"vu_same_pair_hazards\": "+spTot+",");
            w.println("    \"vu_flag_consumers_under4\": "+u4Tot+",");
            w.println("    \"vu_flag_consumers_exactly4\": "+x4Tot+",");
        }
        w.println("    \"vu_opcode_map_mismatch_leads\": "+vuOpcodeMapMismatchCount+",");
        w.println("    \"vu_opcode_coverage_gap\": "+vuOpcodeCoverageGap.size()+",");
        w.println("    \"giftag_template_patterns\": "+giftagTemplates.size()+",");
        w.println("    \"runtime_levers\": "+runtimeLeverRegistry.size()+",");
        w.println("    \"stale_bandaid_suspects\": "+staleBandaidSuspectCount+",");
        w.println("    \"memcpy_shaped_loop\": "+memcpyShapedLoopCount+",");
        w.println("    \"idle_spin_yield_site\": "+idleSpinYieldCount+",");
        // v17.1 Rules 226-232 (PCSX2 cross-check round 2). dma_mfifo_users==0 and
        // gs_readback_sites==0 are FINDINGS for DC2 (flat DMA, READFIFO2 dead).
        w.println("    \"dma_mfifo_users\": "+dmaMfifoUserCount+",");
        w.println("    \"dma_stall_control_sync\": "+dmaStallControlCount+",");
        w.println("    \"vif_path_arbitration\": "+vifPathArbCount+",");
        w.println("    \"gs_readback_sites\": "+gsReadbackSiteCount+",");
        w.println("    \"prmode_attr_writers\": "+prmodeAttrWriterCount+",");
        w.println("    \"texa_clamp_writers\": "+texaClampWriterCount+",");
        w.println("    \"ee_time_sources\": "+eeTimeSourceCount+",");
        // v18 Rules 234-240 (G142-G172 perf-arc retrospective). recompile_coverage_gaps>0
        // is the level-load "function not found" red flag; streamed_texture_pages flags
        // poor texture-cache candidates.
        w.println("    \"sprite_emitters\": "+spriteEmitterCount+",");
        w.println("    \"sprite_group_order_deps\": "+spriteGroupOrderCount+",");
        w.println("    \"recompile_coverage_gaps\": "+recompileCoverageGaps.size()+",");
        w.println("    \"streamed_texture_pages\": "+streamedTexturePages.size()+",");
        w.println("    \"presentation_fifo_bypass\": "+presentationFifoBypassCount+",");
        w.println("    \"gpu_raster_eligible\": "+gpuRasterEligibleCount+",");
        w.println("    \"gpu_raster_ineligible\": "+gpuRasterIneligibleCount+",");
        // v19 Rules 243-250 (PCSX2 cross-check round 3). tlb_writers==0 confirms DC2 is flat;
        // interrupt_handlers/sif_transport/cdvd_gates are the EE contracts a runtime must model.
        w.println("    \"interrupt_handlers\": "+interruptHandlerCount+",");
        w.println("    \"dma_tag_irq_sites\": "+dmaTagIrqCount+",");
        w.println("    \"vif_interrupt_sites\": "+vifInterruptCount+",");
        w.println("    \"sif_transport_sites\": "+sifTransportCount+",");
        w.println("    \"cdvd_completion_gates\": "+cdvdGateCount+",");
        w.println("    \"cache_ops\": "+cacheOpCount+",");
        w.println("    \"tlb_writers\": "+tlbWriterCount+",");
        w.println("    \"gs_csr_sites\": "+gsCsrCount+",");
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
        w.println("    \"dc2_known_name_mismatches\": "+dc2KnownNameMismatches+",");
        w.println("    \"discovered_iop_sid_funcs\": "+discoveredRpcSidCount+",");
        w.println("    \"function_pointer_tables\": "+functionPointerTables.size()+",");
        w.println("    \"module_clusters\": "+moduleClusters.size()+",");
        w.println("    \"name_prefix_modules\": "+namePrefixModules.size()+",");
        // v10 stats (DC2 F47-F52)
        w.println("    \"cop2_partial_dest_funcs\": "+cop2PartialDestFuncCount+",");
        w.println("    \"static_initializer_funcs\": "+staticInitializerFuncCount+",");
        w.println("    \"uncalled_static_init\": "+uncalledStaticInitCount+",");
        w.println("    \"memory_allocators\": "+memoryAllocatorCount+",");
        w.println("    \"guest_lock_hog_candidates\": "+guestLockHogCount+",");
        w.println("    \"eabi_arg_t0_funcs\": "+eabiArgT0Count+",");
        w.println("    \"psmct16_clut_uploaders\": "+psmct16ClutUploaderCount+",");
        // v10.1 stats
        w.println("    \"computed_jump_sites\": "+computedJumpSiteCount+",");
        w.println("    \"computed_jump_unresolved\": "+computedJumpUnresolvedCount+",");
        w.println("    \"cop2_special_op_funcs\": "+cop2SpecialOpFuncCount+",");
        w.println("    \"fpu_noniee_sensitive\": "+fpuNonIeeeCount+",");
        w.println("    \"overlay_loaders\": "+overlayLoaderCount);
        w.println("  },");

        // v11 (General v15.1): structured rescue ledger - the detailed
        // explanation surface for every inherited (step1/DAC.toml) stub/skip
        // binding that failed the high-confidence safety gate. The unified
        // TOML only carries the executable safe subset plus a one-line
        // pointer here.
        w.println("  \"rescued_from_step1\": [");
        {
            boolean first=true;
            for(FuncResult r : results) {
                if(!"step1".equals(r.origin) || r.rescueReason==null) continue;
                FuncTraits t=r.traits;
                if(!first) w.println(",");
                first=false;
                w.print("    {");
                w.print("\"entry\": "+jsonString(r.name+"@"+hex(r.address))+", ");
                w.print("\"from_section\": \""+("STUB".equals(r.step1Disposition)?"stubs":"skip")+"\", ");
                // All rescues recompile; ones the enricher flags for human
                // confirmation surface as "review" (they also sit in the
                // triage_advisory review array).
                boolean review = r.tags.contains("BINDING_FIREWALL_RESCUED")
                              || r.tags.contains("ADDRESS_TAKEN_CALLBACK");
                w.print("\"new_decision\": \""+(review?"review":"recompile")+"\", ");
                w.print("\"reason\": "+jsonString(r.rescueReason)+", ");
                // Evidence: the determinative trait facts the gate looked at.
                List<String> ev=new ArrayList<>();
                if(t!=null) {
                    ev.add(t.hasSyscall?"has_syscall":"no_syscall");
                    ev.add((t.callsSifRpc||t.detectedRpcSid!=0||!t.discoveredRpcSids.isEmpty())
                           ?"sif_rpc":"no_sif_rpc");
                    ev.add((t.refsIopModuleString||t.isIrxLoader||t.sifLoadModuleCallCount>=1)
                           ?"irx_evidence":"no_irx_evidence");
                    ev.add((t.callsMpegFamily||t.accessesIpuMmio||t.writesIpuCmd)
                           ?"ipu_mpeg":"no_ipu_mpeg");
                    if(t.accessesMMIO) ev.add("accesses_mmio");
                    ev.add("size="+t.byteSize);
                    ev.add("call_ops="+t.callOps);
                    if(t.drawingChainDepth>=0) ev.add("drawing_chain_depth="+t.drawingChainDepth);
                    if(t.initChainDepth>=0) ev.add("init_chain_depth="+t.initChainDepth);
                }
                w.print("\"evidence\": "+jsonStrArray(ev)+", ");
                // derived_from: the rescuing pass + most actionable tags.
                List<String> der=new ArrayList<>();
                der.add(r.rescuedBy!=null?r.rescuedBy:"step1_keep_gate");
                String topTags = prioritizeTagsForComment(r.tags, 4);
                if(!topTags.isEmpty())
                    for(String tag : topTags.split(","))
                        if(!der.contains(tag.trim())) der.add(tag.trim());
                w.print("\"derived_from\": "+jsonStrArray(der));
                w.print("}");
            }
        }
        w.println("\n  ],");

        // v11 (General v15.2): full advisory content - mirrored here from the
        // TOML [triage_advisory] block (TOML = executable safe subset, JSON =
        // detailed source of truth). Entry strings are "name@0xADDR"; tags
        // are the priority-sorted hint tags previously emitted as TOML
        // trailing comments.
        w.println("  \"triage_advisory\": {");
        w.println("    \"_note\": \"Advisory only - not consumed by ps2recomp.exe. "
            +"nop: confirmed no-op stub candidates; patch: single-instr convention fixes; "
            +"force_recompile: must run real game logic; must_implement: VU0/DC2-critical math; "
            +"native_impl_needed: IOP-side subsystems needing host implementations; "
            +"review: enricher overrode/refused a binding decision; DC2 lists: blockers / "
            +"host-wait / upload bullseyes / F47-F52 categories; patch_instruction_candidates: "
            +"spin/wait backward-branch NOP patches (opt-in).\",");
        for(Map.Entry<String,List<String>> e : advisoryJsonLists.entrySet())
            emitAdvisoryJsonArray(w, e.getKey(), e.getValue(), true);
        w.println("    \"patch_instruction_candidates\": [");
        for(int pi=0; pi<advisoryPatchInstr.size(); pi++) {
            String[] c = advisoryPatchInstr.get(pi);
            w.print("      {\"address\": \""+c[0]+"\", \"value\": \"0x00000000\", "
                +"\"reason\": "+jsonString(c[1])+", \"function\": "+jsonString(c[2])+"}");
            w.println(pi==advisoryPatchInstr.size()-1 ? "" : ",");
        }
        w.println("    ]");
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

        // ===== v10 top-level sections (DC2 F47-F52) =====
        // sceVu0 helpers still unimplemented (throwing) in Kernel/Stubs/VU.cpp (F50.7).
        w.println("  \"sce_vu0_unimplemented\": [");
        for(int i=0;i<SCEVU0_UNIMPLEMENTED.length;i++){
            w.print("    "+jsonString(SCEVU0_UNIMPLEMENTED[i]));
            w.println(i<SCEVU0_UNIMPLEMENTED.length-1?",":"");
        }
        w.println("  ],");

        // ===== v12 Rules 165-177 top-level sections =====
        // Rule 165 VRAM_OVERLAP_MAP: functions targeting the SAME labelled VRAM
        // page with DIFFERING GS reg kinds → RTT_ALIAS / Z_ALIAS / TIMESHARE.
        // The G33-G50 / G45 page-alias bug class, surfaced statically.
        w.println("  \"vram_overlap_pairs\": [");
        for(int i=0;i<vramOverlapPairs.size();i++){
            String[] p = vramOverlapPairs.get(i);
            w.print("    {\"page\": \""+p[0]+"\", \"label\": "+jsonString(p[1])
                +", \"kind_a\": \""+p[2]+"\", \"func_a\": "+jsonString(p[3])
                +", \"kind_b\": \""+p[4]+"\", \"func_b\": "+jsonString(p[5])
                +", \"classification\": \""+p[6]+"\"}");
            w.println(i<vramOverlapPairs.size()-1?",":"");
        }
        w.println("  ],");

        // Rule 171 MEMCARD_IO roster (#4 active blocker: save/load).
        w.println("  \"memcard_io_roster\": [");
        {
            List<FuncResult> mc = new ArrayList<>();
            for(FuncResult r : results) if(r.traits != null && r.traits.isMemcardIo) mc.add(r);
            for(int i=0;i<mc.size();i++){
                FuncResult r = mc.get(i);
                w.print("    {\"address\": \""+hex(r.address)+"\", \"name\": "+jsonString(r.name)
                    +", \"memcard_callees\": "+jsonStrArray(new ArrayList<>(r.traits.memcardCallees))+"}");
                w.println(i<mc.size()-1?",":"");
            }
        }
        w.println("  ],");

        // Rule 170 AUDIO_COMPLETION_GATE (#3 active blocker: audio/event signals).
        w.println("  \"audio_completion_gates\": [");
        {
            List<FuncResult> ag = new ArrayList<>();
            for(FuncResult r : results) if(r.traits != null && r.traits.isAudioCompletionGate) ag.add(r);
            for(int i=0;i<ag.size();i++){
                FuncResult r = ag.get(i);
                w.print("    {\"address\": \""+hex(r.address)+"\", \"name\": "+jsonString(r.name)
                    +", \"signals\": "+jsonStrArray(new ArrayList<>(r.traits.audioGateSignals))
                    +", \"dc2_audio_gated_stall\": "+r.tags.contains("DC2_AUDIO_GATED_STALL")+"}");
                w.println(i<ag.size()-1?",":"");
            }
        }
        w.println("  ],");

        // Rule 173 PRESENTATION_FIELD_STATE (#5 active blocker: interlace jitter).
        w.println("  \"presentation_field_writers\": [");
        {
            List<FuncResult> pf = new ArrayList<>();
            for(FuncResult r : results) if(r.traits != null && r.traits.writesPresentationFieldState) pf.add(r);
            for(int i=0;i<pf.size();i++){
                FuncResult r = pf.get(i);
                w.print("    {\"address\": \""+hex(r.address)+"\", \"name\": "+jsonString(r.name)
                    +", \"regs\": "+jsonStrArray(new ArrayList<>(r.traits.presentationRegs))
                    +", \"display_buffer_flip\": "+r.traits.isDisplayBufferFlip+"}");
                w.println(i<pf.size()-1?",":"");
            }
        }
        w.println("  ],");

        // Rule 175 CLUT_CACHE_INVALIDATOR (TEXFLUSH / CLUT-page cache ops).
        w.println("  \"clut_cache_ops\": [");
        {
            List<FuncResult> cc = new ArrayList<>();
            for(FuncResult r : results) if(r.traits != null && r.traits.isClutCacheInvalidator) cc.add(r);
            for(int i=0;i<cc.size();i++){
                FuncResult r = cc.get(i);
                w.print("    {\"address\": \""+hex(r.address)+"\", \"name\": "+jsonString(r.name)+"}");
                w.println(i<cc.size()-1?",":"");
            }
        }
        w.println("  ],");

        // Rule 176 PERF_HOT_FRAME_PATH (#7 active blocker: frame pacing). Ranked
        // by callee fan-out (shallow mainloop reach + inner loop = hot suspect).
        w.println("  \"perf_hot_candidates\": [");
        {
            List<FuncResult> ph = new ArrayList<>();
            for(FuncResult r : results) if(r.traits != null && r.traits.isPerfHotFramePath) ph.add(r);
            ph.sort((a,b)->Integer.compare(b.traits.calleeCount, a.traits.calleeCount));
            for(int i=0;i<ph.size();i++){
                FuncResult r = ph.get(i);
                w.print("    {\"address\": \""+hex(r.address)+"\", \"name\": "+jsonString(r.name)
                    +", \"mainloop_depth\": "+r.traits.mainLoopDepth
                    +", \"callee_count\": "+r.traits.calleeCount+"}");
                w.println(i<ph.size()-1?",":"");
            }
        }
        w.println("  ],");

        // Rule 177 GS_LOCAL_MEM_BUDGET: distinct labelled VRAM pages seen
        // statically. >4MB worth → bank-switched VRAM the flat recomp model breaks.
        w.println("  \"gs_local_mem_budget\": {");
        w.println("    \"distinct_labelled_pages\": "+gsLocalMemPagesReferenced.size()+",");
        w.print("    \"pages\": [");
        {
            boolean f=true;
            for(Long p : gsLocalMemPagesReferenced){ if(!f)w.print(", "); f=false;
                w.print("{\"page\": \""+hex(p)+"\", \"label\": "
                    +jsonString(KNOWN_DC2_TBP_LABELS.getOrDefault(p,""))+"}"); }
        }
        w.println("]");
        w.println("  },");

        // ===== v13 Rules 178-188 top-level rosters (DC2 G53-G82) =====
        // Rule 179 RENDER_MODE_SELECTOR (G75-G80 copy-vs-transform routing).
        emitV13Roster(w, "render_mode_selectors", renderModeSelectors, "kind");
        // Rule 180 VERTEX_LIGHTING_NORMAL_TERM (G82 per-vertex N·L / shade-RED deficit).
        emitV13Roster(w, "vertex_lighting_terms", vertexLightingTerms, "source");
        // Rule 181 VTABLE_TAILCALL_THUNK (G59 recompiler inherited-virtual tail-call bug).
        emitV13Roster(w, "vtable_tailcall_thunks", vtableTailcallThunks, "slots");
        // Rule 182 RTT_NO_RESTORE (G79 GS render-target / scissor leak across scenes).
        emitV13Roster(w, "rtt_no_restore", rttNoRestoreFuncs, "reason");
        // Rule 184 VU_FLAG_PIPELINE_UPLOADER (G71 VU MAC/STATUS flag pipeline advisory).
        emitV13Roster(w, "vu_flag_pipeline_uploaders", vuFlagPipelineUploaders, "kind");
        // Rule 187 PACKED_RGBAQ_BUILDER (G82 GIF PACKED RGBAQ spread-layout advisory).
        emitV13Roster(w, "packed_rgbaq_builders", packedRgbaqBuilders, "note");
        // Rule 188 FRAME_RESUME_RISK (G58/G59 mid-body preempt/resume risk).
        emitV13Roster(w, "frame_resume_risk", frameResumeRiskFuncs, "reason");
        // Rule 186 INIT_ORDER_DEPENDENCY: globals read-guarded but only __sinit-written (G58/G81).
        w.println("  \"init_order_hazards\": [");
        for(int i=0;i<initOrderHazards.size();i++){
            String[] h = initOrderHazards.get(i);
            w.print("    {\"global\": "+jsonString(h[0])+", \"reader\": "+jsonString(h[1])
                +", \"writer\": "+jsonString(h[2])+", \"writer_kind\": "+jsonString(h[3])+"}");
            w.println(i<initOrderHazards.size()-1?",":"");
        }
        w.println("  ],");

        // ===== v15 Rules 190-198 top-level rosters (DC2 G83-G115) =====
        // Rule 190 GIFTAG_PRIM_CLASS_SELECTOR (the qword38 PRIM-class route decode, G77-G115).
        emitV13Roster(w, "prim_class_selectors", primClassSelectors, "selector");
        // Rule 191 ADC_KICK_VERTEX_SOURCE (the per-vertex strip-restart ADC source, G65-G115).
        emitV13Roster(w, "adc_kick_sources", adcKickSources, "adc_source");
        // Rule 192 XYZ2_VS_XYZ3_KICK_WRITER (per-vertex draw-kick vs no-kick writers).
        emitV13Roster(w, "kick_mode_writers", kickModeWriters, "mode");
        // Rule 193 TEXTURE_RELOAD_INTERLEAVE_HAZARD (per-block TEX0 de-interleave, G90-G97).
        emitV13Roster(w, "texture_reload_interleave", textureReloadInterleave, "reason");
        // Rule 195 VSYNC_COUPLED_GAME_STEP (game-step coupled to render, G103 perf blocker).
        emitV13Roster(w, "frame_pacing_drivers", framePacingDrivers, "detail");
        // Rule 196 VIEW_PROJECTION_MATRIX_WRITER (shared camera/view matrix, G98/G99).
        emitV13Roster(w, "view_projection_writers", viewProjectionWriters, "kind");
        // Rule 197 OBJECT_ARRAY_CTOR (array-of-objects ctor needing per-element vtables, G92).
        emitV13Roster(w, "object_array_ctors", objectArrayCtors, "shape");
        // Rule 184+ VU_EXEC_HAZARD_MANIFEST (consolidated VU/COP2 interpreter divergences).
        emitV13Roster(w, "vu_exec_hazard_manifest", vuExecHazardManifest, "hazards");
        // ===== v15.1 PCSX2-grounded rosters (Rules 199-201) =====
        // Rule 199 VIF_UNPACK_DECOMPRESS_STATE (STMOD/STMASK/STROW/STCOL decompression).
        emitV13Roster(w, "vif_unpack_decompress_state", vifUnpackDecompressState, "commands");
        // Rule 200 GS_XYOFFSET_GUARD_BAND (guard-band centre, G88).
        emitV13Roster(w, "xyoffset_guard_writers", xyoffsetGuardWriters, "detail");
        // Rule 201 GS_TEX1_FILTER_WRITER (MMAG/MMIN texture filter, G8).
        emitV13Roster(w, "tex1_filter_writers", tex1FilterWriters, "detail");
        // ===== v15.2 skill-grounded rosters (Rules 203-205) =====
        // Rule 203 MMI_SIMD_OP (EE MMI codegen class - audit the whole class).
        emitV13Roster(w, "mmi_codegen_risk", mmiCodegenRisk, "detail");
        // Rule 204 COP2_CONTROL_REG_ACCESS (CFC2/CTC2 control-reg map codegen class).
        emitV13Roster(w, "cop2_control_reg_access", cop2ControlRegAccess, "regs");
        // Rule 205 UNFUNDED_TEXTURE_PAGE (sampled page with no static BITBLTBUF upload, advisory).
        w.println("  \"unfunded_texture_pages\": [");
        for(int i=0;i<unfundedTexturePages.size();i++){
            String[] e = unfundedTexturePages.get(i);
            w.print("    {\"page\": "+jsonString(e[0])+", \"label\": "+jsonString(e[1])
                +", \"sampler\": "+jsonString(e[2])+", \"note\": \"confirm with runtime BITBLTBUF-dbp counter\"}");
            w.println(i<unfundedTexturePages.size()-1?",":"");
        }
        w.println("  ],");
        // Rule 194 ALLOCATOR_FAMILY_COHERENCE: the family + the split flag (regen-caveat #1).
        w.println("  \"allocator_family_split\": "+allocatorFamilySplit+",");
        w.println("  \"allocator_family\": [");
        for(int i=0;i<allocatorFamily.size();i++){
            String[] e = allocatorFamily.get(i);
            w.print("    {\"name\": "+jsonString(e[0])+", \"address\": "+jsonString(e[1])
                +", \"disposition\": "+jsonString(e[2])+"}");
            w.println(i<allocatorFamily.size()-1?",":"");
        }
        w.println("  ],");

        // ===== v16 rosters (Rules 207-214, G116-G137 title-cavern retrospective) =====
        // Rule 207 VERTEX_KICK_FORMAT_ADC_CAPABILITY (xyzf2_fog_no_adc vs xyz2_adc_capable, G132).
        emitV13Roster(w, "adc_capable_packers", adcCapablePackers, "adc_capability");
        // Rule 208 PERSPECTIVE_DIVIDE_NEAR_PLANE_SOURCE (pre-FTOI4 1/W available, G125-G129).
        emitV13Roster(w, "near_plane_sites", nearPlaneSites, "strategy");
        // Rule 209 SPI_CONFIG_COMMAND_DISPATCH (cfgXXX map-config command handlers, G129/G130).
        emitV13Roster(w, "spi_config_commands", spiConfigCommands, "role");
        // Rule 210 DATA_DRIVEN_COMMAND_INTERPRETER (script/config VMs, general PS2).
        emitV13Roster(w, "command_interpreters", commandInterpreters, "kind");
        // Rule 211 PASSTHROUGH_PACKER_RENDER_PATH (copy/transform/trifan/dispatcher, G130).
        emitV13Roster(w, "packer_families", packerFamilies, "family");
        // Rule 212 PRIVATE_DEPTH_SCOPE (RTT draw needing a private per-frame Z, G125).
        emitV13Roster(w, "private_depth_scopes", privateDepthScopes, "detail");
        // Rule 214 PACKED_FIELD_ALIAS_FOG_ADC (word3 fog vs ADC bit111, G132).
        emitV13Roster(w, "packed_field_aliases", packedFieldAliases, "detail");

        // ===== v17 sections (Rules 217-225, G138-G140 retrospective + G141 perf) =====
        // Rule 222 fast-path rosters + static perf ranking (G141 ACTIVE blocker).
        emitV13Roster(w, "memcpy_shaped_loops", memcpyShapedLoops, "detail");
        emitV13Roster(w, "idle_spin_yield_sites", idleSpinYieldSites, "detail");
        // ===== v17.1 rosters (Rules 226-232, PCSX2 cross-check round 2) =====
        // Rule 226 DMA_MFIFO_RING_CONFIG (RBOR/RBSR MFIFO ring; 0 = flat-DMA finding).
        emitV13Roster(w, "dma_mfifo_users", dmaMfifoUsers, "regs");
        // Rule 227 DMA_STALL_CONTROL_SYNC (STADR / REFS read-after-write interlock).
        emitV13Roster(w, "dma_stall_control_sync", dmaStallControlSync, "kind");
        // Rule 228 VIF_PATH_ARBITRATION (MSKPATH3 / FLUSH family / GIF MODE M3R+IMT).
        emitV13Roster(w, "vif_path_arbitration", vifPathArbitration, "codes");
        // Rule 229 GS_DOWNLOAD_READBACK_PATH (BUSDIR / TRXDIR=down / VIF1 FDR; 0 = finding for DC2).
        emitV13Roster(w, "gs_readback_sites", gsReadbackSites, "signals");
        // Rule 230 GS_PRMODE_ATTRIBUTE_SOURCE (PRIM-vs-PRMODE attribute select).
        emitV13Roster(w, "prmode_attr_writers", prmodeAttrWriters, "regs");
        // Rule 231 GS_TEXA_CLAMP_CONTRACT (16/24-bit alpha expansion + atlas region wrap).
        emitV13Roster(w, "texa_clamp_writers", texaClampWriters, "contract");
        // Rule 232 EE_TIME_SOURCE_ROSTER (timer COUNT/MODE + COP0 Count readers - the
        // G141 pacing checklist: verify the runtime's clock model at these functions first).
        emitV13Roster(w, "ee_time_sources", eeTimeSources, "detail");
        // ===== v18 rosters (Rules 234-240, G142-G172 perf-arc retrospective) =====
        // Rule 234 GS_PRIM_SPRITE_EMITTER + prim-class census (G171: inline sprite raster was
        // the dominant title cost, invisible to triangle-only defer/instrumentation).
        emitV13Roster(w, "prim_class_emitters", primClassEmitters, "prim_classes");
        // Rule 235 SPRITE_GROUP_ORDER_DEPENDENCY (compound 2D widgets, reorder-unsafe, G172).
        emitV13Roster(w, "sprite_compound_widgets", spriteCompoundWidgets, "detail");
        // Rule 236 RECOMPILE_TARGET_COVERAGE_GAP (in-code-range call/jump target with no
        // function -> "Function at address 0xN not found"; DC2 blocker #2 = 0xe3dc70).
        emitV13Roster(w, "recompile_coverage_gaps", recompileCoverageGaps, "note");
        // Rule 237 TEXTURE_STREAM_CHURN (streamed vs static pages; poor cache candidates, G148/G149).
        emitV13Roster(w, "streamed_texture_pages", streamedTexturePages, "detail");
        // Rule 238 PRESENTATION_REGISTER_FIFO_BYPASS (present regs bypass the GS FIFO; MTGS/pipeline
        // must fence/latch them, G150/G157 - general PS2).
        emitV13Roster(w, "presentation_fifo_bypass", presentationFifoBypass, "detail");
        // Rule 240 GPU_RASTER_ELIGIBILITY_CENSUS (blend/atest/paletted vs opaque; G161 - general PS2).
        emitV13Roster(w, "gpu_raster_eligibility", gpuRasterEligibility, "eligibility");
        // ===== v19 rosters (Rules 243-250, PCSX2 cross-check round 3) =====
        // Rule 243 EE_INTERRUPT_HANDLER_REGISTRATION (INTC/DMAC handler dispatch - vsync/DMA callbacks).
        emitV13Roster(w, "interrupt_handlers", interruptHandlers, "detail");
        // Rule 244 DMA_TAG_IRQ_COMPLETION (DMAtag IRQ + CHCR.TIE tag-completion interrupt).
        emitV13Roster(w, "dma_tag_irq_sites", dmaTagIrqSites, "detail");
        // Rule 245 VIF_INTERRUPT_IBIT (VIFcode i-bit -> VIF STAT.INT).
        emitV13Roster(w, "vif_interrupt_sites", vifInterruptSites, "detail");
        // Rule 246 SIF_RPC_TRANSPORT (SBUS MSFLG/SMFLG + SIF0/1 DMA; IOP-dead poll deadlock class).
        emitV13Roster(w, "sif_transport_sites", sifTransportSites, "detail");
        // Rule 247 CDVD_READ_COMPLETION_GATE (sceCd* completion poll; DC2 level-load stream gate).
        emitV13Roster(w, "cdvd_completion_gates", cdvdCompletionGates, "detail");
        // Rule 248 EE_CACHE_COHERENCY_OP (cache/sync near DMA-to-RAM-then-execute).
        emitV13Roster(w, "cache_ops", cacheOps, "detail");
        // Rule 249 GS_CSR_SIGNAL_HANDSHAKE (SIGNAL/FINISH/LABEL + CSR ack; DC2 IMR masks all).
        emitV13Roster(w, "gs_csr_sites", gsCsrSites, "detail");
        // Rule 250 EE_TLB_MAPPING (custom TLB mapping; 0 = flat, the finding for DC2).
        emitV13Roster(w, "tlb_writers", tlbWriters, "detail");
        w.println("  \"perf_cost_ranking\": [");
        {
            List<FuncResult> pr = new ArrayList<>();
            for(FuncResult r : results)
                if(r.traits != null && r.traits.perfStaticCost > 0) pr.add(r);
            pr.sort((a,b)->Long.compare(b.traits.perfStaticCost, a.traits.perfStaticCost));
            int cap = Math.min(100, pr.size());
            for(int i=0; i<cap; i++){
                FuncResult r = pr.get(i);
                w.print("    {\"address\": \""+hex(r.address)+"\", \"name\": "+jsonString(r.name)
                    +", \"perf_static_cost\": "+r.traits.perfStaticCost
                    +", \"mainloop_depth\": "+r.traits.mainLoopDepth
                    +", \"callee_count\": "+r.traits.calleeCount
                    +", \"has_inner_loop\": "+r.traits.hasBackwardBranch
                    +", \"uses_cop2\": "+r.traits.usesCop2+"}");
                w.println(i<cap-1?",":"");
            }
        }
        w.println("  ],");

        // Rules 217-219: extracted VU microcode programs + static hazard scan.
        // needs_flag_pipeline: gates hand-scheduled at exactly 4 pairs (the G138
        // MACPIPE depth). immediate_model_diverges: consumers closer than 4 pairs.
        // same_pair_hazards: the G139 store-then-clobber class, per exact VU pc.
        // coverage.unreached_spans: regions no branch targets and no fallthrough
        // reaches (the G140 "clipper never disassembled" class).
        w.println("  \"vu_microcode_programs\": [");
        for(int i=0; i<vuMicrocodePrograms.size(); i++){
            VuProgram p = vuMicrocodePrograms.get(i);
            w.print("    {\"elf_addr\": \""+hex(p.elfAddr)+"\", \"vu_dest_qw\": "+p.vuDestQw
                +", \"vu_dest_bytes\": \"0x"+Long.toHexString((long)p.vuDestQw*8L)+"\""
                +", \"size_pairs\": "+p.sizePairs+", \"chunks\": "+p.chunkCount
                +", \"uploader\": "+jsonString(p.uploaderFunc)+", ");
            w.print("\"opcode_census\": {");
            boolean f = true;
            for(Map.Entry<String,Integer> e : p.census.entrySet()){
                if(!f) w.print(", "); f=false;
                w.print(jsonString(e.getKey())+": "+e.getValue());
            }
            w.print("}, ");
            w.print("\"flag_consumers\": {\"total\": "+p.flagConsumers
                +", \"exactly_4_pairs\": "+p.flagConsumersExactly4
                +", \"under_4_pairs\": "+p.flagConsumersUnder4
                +", \"needs_flag_pipeline\": "+(p.flagConsumersExactly4 > 0)
                +", \"immediate_model_diverges\": "+(p.flagConsumersUnder4 > 0)
                +", \"distance_histogram\": {");
            f = true;
            for(Map.Entry<Integer,Integer> e : new TreeMap<>(p.flagDistHistogram).entrySet()){
                if(!f) w.print(", "); f=false;
                w.print("\""+(e.getKey()>=9 ? "9+" : String.valueOf(e.getKey()))+"\": "+e.getValue());
            }
            w.print("}, \"under4_examples\": [");
            f = true;
            for(String[] ex : p.flagUnder4Examples){
                if(!f) w.print(", "); f=false;
                w.print("{\"pc\": \""+ex[0]+"\", \"op\": \""+ex[1]+"\", \"dist\": "+ex[2]+"}");
            }
            w.print("]}, ");
            w.print("\"same_pair_hazards\": {\"count\": "+p.samePairHazardCount+", \"sites\": [");
            f = true;
            for(String[] ex : p.samePairHazards){
                if(!f) w.print(", "); f=false;
                w.print("{\"pc\": \""+ex[0]+"\", \"upper\": \""+ex[1]
                    +"\", \"lower\": \""+ex[2]+"\", \"vf\": \""+ex[3]+"\"}");
            }
            w.print("]}, ");
            w.print("\"q_pipeline\": {\"producers\": "+p.qProducers+", \"consumers\": "+p.qConsumers
                +", \"min_gap_pairs\": "+(p.qMinGap==Integer.MAX_VALUE ? -1 : p.qMinGap)
                +", \"waitq\": "+p.waitqCount+"}, ");
            w.print("\"p_pipeline\": {\"producers\": "+p.pProducers+", \"consumers\": "+p.pConsumers
                +", \"min_gap_pairs\": "+(p.pMinGap==Integer.MAX_VALUE ? -1 : p.pMinGap)
                +", \"waitp\": "+p.waitpCount+"}, ");
            w.print("\"clipper_shape\": {\"clipw\": "+p.clipwCount+", \"fcget\": "+p.fcgetCount
                +", \"looks_like_polygon_clipper\": "+(p.clipwCount >= 3 && p.fcgetCount >= 1)+"}, ");
            w.print("\"xgkick_pcs\": [");
            f = true;
            for(Long pc : p.xgkickPcs){ if(!f) w.print(", "); f=false; w.print("\"0x"+Long.toHexString(pc)+"\""); }
            w.print("], \"bal_subroutines\": [");
            f = true;
            for(Long pc : p.balSubroutines){ if(!f) w.print(", "); f=false; w.print("\"0x"+Long.toHexString(pc)+"\""); }
            w.print("], \"dispatcher_branch_pcs\": [");
            f = true;
            for(Long pc : p.dispatcherBranchPcs){ if(!f) w.print(", "); f=false; w.print("\"0x"+Long.toHexString(pc)+"\""); }
            w.print("], \"branches\": "+p.branchTargetCount+", \"jr_indirect\": "+p.jrIndirectCount);
            w.print(", \"coverage\": {\"reachable_pairs\": "+p.reachablePairs
                +", \"total_pairs\": "+p.sizePairs+", \"unreached_spans\": [");
            f = true;
            for(long[] sp : p.unreachedSpans){
                if(!f) w.print(", "); f=false;
                w.print("{\"start\": \"0x"+Long.toHexString(sp[0])+"\", \"end\": \"0x"+Long.toHexString(sp[1])+"\"}");
            }
            w.print("]}}");
            w.println(i<vuMicrocodePrograms.size()-1?",":"");
        }
        w.println("  ],");

        // Rule 220: the authoritative lower-opcode map (PCSX2 _LOWER_OPCODE) +
        // the best-effort runner conformance diff. MISMATCH? entries are leads,
        // not verdicts (textual case-label pairing can cross switches).
        w.println("  \"vu_lower_opcode_canon\": {");
        {
            boolean f = true;
            for(Map.Entry<Integer,String> e : VU_LOWER_CANON_MAP.entrySet()){
                if(!f) w.println(","); f = false;
                w.print("    \""+String.format("0x%02x", e.getKey())+"\": "+jsonString(e.getValue()));
            }
        }
        w.println("\n  },");
        w.println("  \"vu_opcode_map_check\": [");
        for(int i=0; i<vuOpcodeMapCheck.size(); i++){
            String[] e = vuOpcodeMapCheck.get(i);
            w.print("    {\"index\": \""+e[0]+"\", \"canonical\": "+jsonString(e[1])
                +", \"runner_token\": "+jsonString(e[2])+", \"status\": "+jsonString(e[3])+"}");
            w.println(i<vuOpcodeMapCheck.size()-1?",":"");
        }
        w.println("  ],");
        w.println("  \"vu_opcode_coverage_gap\": "+jsonStrArray(vuOpcodeCoverageGap)+",");

        // Rule 221: env-lever registry + the G138-G140 retired-band-aid roster.
        w.println("  \"runtime_lever_registry\": [");
        for(int i=0; i<runtimeLeverRegistry.size(); i++){
            String[] e = runtimeLeverRegistry.get(i);
            w.print("    {\"env\": "+jsonString(e[0])+", \"file\": "+jsonString(e[1])
                +", \"line\": "+e[2]+", \"classification\": "+jsonString(e[3])
                +", \"pc_literals\": "+jsonString(e[4])
                +", \"stale_bandaid_suspect\": "+e[5]+"}");
            w.println(i<runtimeLeverRegistry.size()-1?",":"");
        }
        w.println("  ],");
        w.println("  \"runtime_bandaid_status\": [");
        for(int i=0; i<DC2_RETIRED_BANDAIDS.length; i++){
            String[] b = DC2_RETIRED_BANDAIDS[i];
            w.print("    {\"env\": "+jsonString(b[0])+", \"phase\": "+jsonString(b[1])
                +", \"default_state\": "+jsonString(b[2])+", \"note\": "+jsonString(b[3])+"}");
            w.println(i<DC2_RETIRED_BANDAIDS.length-1?",":"");
        }
        w.println("  ],");

        // Rule 224: GIFtag-shaped data records (nloop==0 = VIF-delivered template).
        w.println("  \"giftag_templates\": [");
        for(int i=0; i<giftagTemplates.size(); i++){
            GiftagTemplate g = giftagTemplates.get(i);
            w.print("    {\"w1_w0\": \""+String.format("%08x_%08x", g.w1, g.w0)
                +"\", \"regs_w3_w2\": \""+String.format("%08x_%08x", g.w3, g.w2)
                +"\", \"count\": "+g.count
                +", \"nloop\": "+g.nloop+", \"eop\": "+g.eop+", \"pre\": "+g.pre
                +", \"prim\": \"0x"+Long.toHexString(g.prim)+"\", \"prim_class\": \""+g.primClass
                +"\", \"flg\": "+g.flg+", \"nreg\": "+g.nreg
                +", \"is_template\": "+(g.nloop==0)+", \"example_addrs\": [");
            boolean f = true;
            for(Long a : g.exampleAddrs){ if(!f) w.print(", "); f=false; w.print("\""+hex(a)+"\""); }
            w.print("]}");
            w.println(i<giftagTemplates.size()-1?",":"");
        }
        w.println("  ],");

        // Rule 185 LOOP_STATE_MODEL: program-state legend + illegal-concurrent states (G79).
        w.println("  \"loop_state_model\": [");
        for(int i=0;i<LOOP_STATE_MODEL.length;i++){
            String[] s = LOOP_STATE_MODEL[i];
            w.print("    {\"state\": "+jsonString(s[0])+", \"where\": "+jsonString(s[1])
                +", \"legend\": "+jsonString(s[2])+"}");
            w.println(i<LOOP_STATE_MODEL.length-1?",":"");
        }
        w.println("  ],");

        // Rule 140: COP2 partial-dest transform risk set (F51.8). Every function
        // here uses VU0-macro ops with a PARTIAL dest field; its generated COP2
        // dest-mask lane order must be verified against READ128/WRITE128 (X=lane0).
        // The F51.8 fix reversed the mask in code_generator.cpp; a clean regen of
        // these functions is the canonical fix.
        w.println("  \"cop2_partial_dest_risk\": [");
        {
            List<FuncResult> risk = new ArrayList<>();
            for(FuncResult r : results)
                if(r.traits != null && r.traits.cop2DestMaskVerify) risk.add(r);
            risk.sort((a,b)->Integer.compare(
                b.traits.cop2PartialDestOps, a.traits.cop2PartialDestOps));
            for(int i=0;i<risk.size();i++){
                FuncResult r = risk.get(i);
                w.print("    {\"address\": \""+hex(r.address)+"\", \"name\": "+jsonString(r.name)+
                        ", \"partial_dest_ops\": "+r.traits.cop2PartialDestOps+
                        ", \"full_dest_ops\": "+r.traits.cop2FullDestOps+
                        ", \"dest_fields\": [");
                boolean f=true;
                for(String s:r.traits.cop2DestFields){ if(!f) w.print(", "); f=false; w.print(jsonString(s)); }
                w.print("]}");
                w.println(i<risk.size()-1?",":"");
            }
        }
        w.println("  ],");

        // v11.3 Rule 162: SPR/scratchpad DMA stagers — the G26 delivery-bug
        // class. Each func programs a fromSPR/toSPR (ch8/9) DMA and/or kicks a
        // transfer via a sub-word CHCR store. A runtime whose writeIORegister
        // only handles GIF/VIF1 word writes drops these, so a scratchpad-staged
        // VU1 model packet never reaches VIF1 (no XGKICK). override_hookable
        // tells the fix strategy (registerFunction vs wrap-the-jal/runtime IO).
        w.println("  \"spr_dma_stagers\": [");
        {
            List<FuncResult> sp = new ArrayList<>();
            for(FuncResult r : results)
                if(r.traits != null && (r.traits.programsSprDma || r.traits.subwordDmaStrKick))
                    sp.add(r);
            for(int i=0;i<sp.size();i++){
                FuncResult r = sp.get(i);
                FuncTraits t = r.traits;
                w.print("    {\"address\": \""+hex(r.address)+"\", \"name\": "+jsonString(r.name)+
                        ", \"programs_spr_dma\": "+t.programsSprDma+
                        ", \"subword_dma_str_kick\": "+t.subwordDmaStrKick+
                        ", \"override_hookable\": "+(t.calledViaJrT9 && !t.calledViaDirectJal)+
                        ", \"spr_channels\": [");
                boolean f=true;
                for(String s:t.sprDmaChannels){ if(!f) w.print(", "); f=false; w.print(jsonString(s)); }
                w.print("], \"subword_kick_channels\": [");
                f=true;
                for(String s:t.subwordKickChannels){ if(!f) w.print(", "); f=false; w.print(jsonString(s)); }
                w.print("]}");
                w.println(i<sp.size()-1?",":"");
            }
        }
        w.println("  ],");

        // Rule 141: static-init manifest — the globals/vtables each __sinit_*
        // installs. Replay these (idempotent dc2_write_u32) to repair un-run
        // static init when the global-ctors table is not driven (F50.4/F50.7).
        w.println("  \"static_init_manifest\": [");
        {
            List<FuncResult> si = new ArrayList<>();
            for(FuncResult r : results)
                if(r.traits != null && r.traits.isStaticInitializer && !r.traits.staticInitInstalls.isEmpty())
                    si.add(r);
            for(int i=0;i<si.size();i++){
                FuncResult r = si.get(i);
                FuncTraits t = r.traits;
                w.print("    {\"address\": \""+hex(r.address)+"\", \"name\": "+jsonString(r.name)+
                        ", \"uncalled\": "+t.isUncalledStaticInit+
                        ", \"installs_vtable\": "+t.staticInitInstallsVtable+
                        ", \"installs\": [");
                boolean f=true;
                for(long[] e : t.staticInitInstalls){
                    if(!f) w.print(", "); f=false;
                    w.print("{\"pc\": \""+hex(e[0])+"\", \"value\": \""+hex(e[1])+"\", \"offset\": \""+hex(e[2])+"\"}");
                }
                w.print("]}");
                w.println(i<si.size()-1?",":"");
            }
        }
        w.println("  ],");

        // Rule 142: memory allocators — never auto-stub (F50.1/F50.2 pool/null-vtable trap).
        w.println("  \"memory_allocators\": [");
        {
            List<FuncResult> al = new ArrayList<>();
            for(FuncResult r : results)
                if(r.traits != null && r.traits.isMemoryAllocator) al.add(r);
            for(int i=0;i<al.size();i++){
                FuncResult r = al.get(i);
                w.print("    {\"address\": \""+hex(r.address)+"\", \"name\": "+jsonString(r.name)+
                        ", \"kind\": "+jsonString(r.traits.allocatorKind)+
                        ", \"reads_eabi_arg_t0\": "+r.traits.readsEabiArgT0+"}");
                w.println(i<al.size()-1?",":"");
            }
        }
        w.println("  ],");

        // ===== v10.1 top-level sections (PCSX2- + skill-grounded) =====
        // Rule 146: computed-jump resolution — per-func switch sites + Ghidra-
        // resolved targets. The recompiler pre-populates its indirect-jump
        // dispatch from this; sites with "unresolved": true are the real risk set.
        w.println("  \"computed_jump_targets\": [");
        {
            List<FuncResult> cj = new ArrayList<>();
            for(FuncResult r : results)
                if(r.traits != null && !r.traits.computedJumpSwitchPcs.isEmpty()) cj.add(r);
            for(int i=0;i<cj.size();i++){
                FuncResult r = cj.get(i); FuncTraits t = r.traits;
                Map<Long,List<Long>> byPc = new LinkedHashMap<>();
                for(Long pc : t.computedJumpSwitchPcs) byPc.put(pc, new ArrayList<>());
                for(long[] e : t.computedJumpTargets){
                    List<Long> l=byPc.get(e[0]); if(l==null){l=new ArrayList<>();byPc.put(e[0],l);} l.add(e[1]);
                }
                w.print("    {\"address\": \""+hex(r.address)+"\", \"name\": "+jsonString(r.name)+", \"sites\": [");
                boolean f=true;
                for(Map.Entry<Long,List<Long>> e : byPc.entrySet()){
                    if(!f) w.print(", "); f=false;
                    w.print("{\"pc\": \""+hex(e.getKey())+"\", \"unresolved\": "+e.getValue().isEmpty()+", \"targets\": [");
                    boolean g=true;
                    for(Long tg : e.getValue()){ if(!g) w.print(", "); g=false; w.print("\""+hex(tg)+"\""); }
                    w.print("]}");
                }
                w.print("]}");
                w.println(i<cj.size()-1?",":"");
            }
        }
        w.println("  ],");

        // Rule 149: SDK / syscall coverage audit. Every SDK-shaped callee (sce*)
        // partitioned vs the known rosters + game_override bindings. coverage_gap =
        // called but neither bound nor recognized → needs a stub/implement decision.
        w.println("  \"sdk_coverage_audit\": {");
        {
            java.util.Map<String,Integer> calleeCounts = new java.util.TreeMap<>();
            for(FuncResult r : results) if(r.traits != null)
                for(String cn : r.traits.calleeNames)
                    if(cn != null) calleeCounts.merge(cn, 1, Integer::sum);
            Set<String> bound = new HashSet<>(gameOverrideNames.values());
            Set<String> iopNames = new HashSet<>(KNOWN_IOP_SIDS.values());
            Set<String> unimpl = new HashSet<>(Arrays.asList(SCEVU0_UNIMPLEMENTED));
            List<String> mustStub = new ArrayList<>(), mustImpl = new ArrayList<>(), gap = new ArrayList<>();
            for(Map.Entry<String,Integer> e : calleeCounts.entrySet()){
                String n = e.getKey();
                if(!(n.startsWith("sce")||n.startsWith("_sce"))) continue;
                String entry = "    {\"name\": "+jsonString(n)+", \"calls\": "+e.getValue()+"}";
                if(n.startsWith("sceVu0")||n.startsWith("_sceVu0")||unimpl.contains(n)) { mustImpl.add(entry); continue; }
                if(bound.contains(n)) continue;  // handled by game_override
                boolean recognized = iopNames.contains(n) || FILE_OPEN_CALLEES.contains(n) || FRAME_CLOCK_CALLEES.contains(n);
                if(!recognized) for(String p : SCE_GIF_PK_PREFIXES)    if(n.startsWith(p)){recognized=true;break;}
                if(!recognized) for(String p : AUDIO_CALLEE_PREFIXES)  if(n.startsWith(p)){recognized=true;break;}
                if(recognized) mustStub.add(entry); else gap.add(entry);
            }
            emitJsonObjArray(w, "must_implement", mustImpl, true);
            emitJsonObjArray(w, "must_stub",      mustStub, true);
            emitJsonObjArray(w, "coverage_gap",   gap,      false);
        }
        w.println("  },");

        // Rule 150: EE code-overlay loaders. Empty for a single-binary game
        // (DC2) — absence confirms the flat-address-space assumption holds.
        w.println("  \"overlay_load_sites\": [");
        {
            List<FuncResult> ol = new ArrayList<>();
            for(FuncResult r : results) if(r.traits != null && r.traits.isOverlayLoader) ol.add(r);
            for(int i=0;i<ol.size();i++){
                FuncResult r = ol.get(i);
                w.print("    {\"address\": \""+hex(r.address)+"\", \"name\": "+jsonString(r.name)+"}");
                w.println(i<ol.size()-1?",":"");
            }
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

        // ===== v11 AI-facing abstraction layer (additive; derived from existing signals) =====
        // Build per-function recommendation + subsystem/role/gateway metadata ONCE,
        // then reuse it for both the top-level summary blocks and the per-function
        // layer below. This keeps the whole layer to a constant number of O(N) /
        // O(N+E) passes — no per-function full-graph BFS, no new graph engine.
        Map<Long,AiRec> aiRecs = new LinkedHashMap<>();
        for(FuncResult r : results) aiRecs.put(r.address & 0xFFFFFFFFL, buildFunctionRecommendation(r));
        Map<Long,String> aiPrefixByAddr = new HashMap<>();
        for(Map.Entry<String,List<Long>> e : namePrefixModules.entrySet())
            for(Long ad : e.getValue()) aiPrefixByAddr.putIfAbsent(ad & 0xFFFFFFFFL, e.getKey());
        Set<Long> aiImportantAddrs = new HashSet<>();
        Set<String> aiImportantNames = new HashSet<>();
        collectImportant(results, aiImportantAddrs, aiImportantNames);
        Map<String,List<FuncResult>> aiSubMembers = new LinkedHashMap<>();
        for(String k : SUBSYSTEM_KEYS) aiSubMembers.put(k, new ArrayList<>());
        for(FuncResult r : results){
            AiRec rec = aiRecs.get(r.address & 0xFFFFFFFFL);
            if(rec != null) aiSubMembers.get(rec.subsystem).add(r);
        }
        buildDecisionConstraints(w);
        buildAiDecisionSupport(w, results, aiRecs, aiSubMembers);
        buildAiRelationshipView(w, results, aiRecs, aiSubMembers,
                aiImportantAddrs, aiImportantNames, aiPrefixByAddr);

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
            // v11 (General v15): provenance - "auto" (enricher), "step1"
            // (inherited from DAC.toml and vetted), "override" (hand-bound in
            // dc2_game_override.cpp).
            w.print("\"origin\": \""+r.origin+"\", ");
            if(r.step1Disposition != null) {
                w.print("\"step1_disposition\": \""+r.step1Disposition+"\", ");
                w.print("\"step1_rescue_reason\": "
                    +(r.rescueReason==null?"null":jsonString(r.rescueReason))+", ");
                // v11.1: exporter vs previous-enricher-run provenance +
                // explicit user lock.
                if(r.step1Source != null)
                    w.print("\"step1_source\": \""+r.step1Source+"\", ");
                if(r.tags.contains("STEP1_LOCKED"))
                    w.print("\"step1_locked\": true, ");
            }
            // v11 Rule 157: triage-return suggestion for bound stubs, per the
            // runtime triage-stub strategy (ret0/ret1/reta0 bindings). Poll
            // targets (callers spin on v0) need an A/B test: wrong constant =
            // infinite wait loop.
            if("STUB".equals(r.disposition)) {
                String sug;
                if(t.returnsA0 || t.returnsA1) sug = "reta0";
                else if(t.isLikelyPollTarget)  sug = "ret0_or_ret1_ab_test";
                else if(t.byteSize < 60 && !t.writesToGlobal && t.callOps == 0) sug = "ret0";
                else sug = "ret0_then_verify";
                w.print("\"suggested_triage_return\": \""+sug+"\", ");
                w.print("\"has_runtime_handler\": "
                    +(runtimeRosterLoaded ? String.valueOf(hasRuntimeHandler(r.name)
                        || (t.inferredName != null && hasRuntimeHandler(t.inferredName))) : "null")+", ");
            }
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
            // v11.3: registerFunction overrides are consulted ONLY for indirect jalr/jr $t9.
            // A function reached via direct jal at any site is NOT fully hookable that way -
            // fix it by wrapping the jal TARGET or in codegen (the G11 ReloadTexture / F51.8
            // COP2 gotcha). hookable=true => every observed caller is indirect (safe to override);
            // partial => mixed (some direct jal sites bypass the override).
            w.print("\"override_hookable\": "+(t.calledViaJrT9 && !t.calledViaDirectJal)+", ");
            w.print("\"override_hookable_partial\": "+(t.calledViaJrT9 && t.calledViaDirectJal)+", ");
            // v11.3 Rules 162-164
            w.print("\"programs_spr_dma\": "+t.programsSprDma+", ");
            w.print("\"subword_dma_str_kick\": "+t.subwordDmaStrKick+", ");
            w.print("\"is_vu1_double_buffer_framer\": "+t.isVu1DoubleBufferFramer+", ");
            w.print("\"is_stale_ptr_cache_ctor\": "+t.isStalePtrCacheCtor+", ");
            if(t.stalePtrCacheGetter!=null)
                w.print("\"stale_ptr_cache_getter\": "+jsonString(t.stalePtrCacheGetter)+", ");
            w.print("\"is_pad_button_mask_consumer\": "+t.isPadButtonMaskConsumer+", ");
            w.print("\"calls_gif_packet_open\": "+t.callsGifPacketOpen+", ");
            w.print("\"calls_gif_packet_close\": "+t.callsGifPacketClose+", ");
            w.print("\"gif_nloop_double_count_risk\": "+t.gifNloopDoubleCountRisk+", ");
            w.print("\"calls_file_open\": "+t.callsFileOpen+", ");
            w.print("\"is_dynamic_code_loader\": "+t.isDynamicCodeLoader+", ");
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
            // ===== v10 hardware-shape fields (DC2 F47-F52) =====
            w.print(", \"cop2_partial_dest_ops\": "+t.cop2PartialDestOps+", ");
            w.print("\"cop2_full_dest_ops\": "+t.cop2FullDestOps+", ");
            w.print("\"cop2_dest_mask_verify\": "+t.cop2DestMaskVerify+", ");
            w.print("\"cop2_dest_fields\": [");
            {
                boolean f=true;
                for(String s:t.cop2DestFields){ if(!f) w.print(", "); f=false; w.print(jsonString(s)); }
            }
            w.print("], ");
            w.print("\"is_static_initializer\": "+t.isStaticInitializer+", ");
            w.print("\"static_init_installs_vtable\": "+t.staticInitInstallsVtable+", ");
            w.print("\"is_uncalled_static_init\": "+t.isUncalledStaticInit+", ");
            w.print("\"static_init_installs\": [");
            {
                boolean f=true;
                for(long[] e:t.staticInitInstalls){
                    if(!f) w.print(", "); f=false;
                    w.print("{\"pc\": \""+hex(e[0])+"\", \"value\": \""+hex(e[1])+
                            "\", \"offset\": \""+hex(e[2])+"\"}");
                }
            }
            w.print("], ");
            w.print("\"is_memory_allocator\": "+t.isMemoryAllocator+", ");
            w.print("\"allocator_kind\": "+jsonString(t.allocatorKind)+", ");
            w.print("\"is_guest_lock_hog_candidate\": "+t.isGuestLockHogCandidate+", ");
            w.print("\"reads_eabi_arg_t0\": "+t.readsEabiArgT0+", ");
            w.print("\"loads_psmct16_const\": "+t.loadsPsmct16Const+", ");
            w.print("\"is_psmct16_clut_uploader\": "+t.isPsmct16ClutUploader+", ");
            // ===== v10.1 hardware-shape fields =====
            w.print("\"cop2_special_ops\": [");
            {
                boolean f=true;
                for(String s:t.cop2SpecialOps){ if(!f) w.print(", "); f=false; w.print(jsonString(s)); }
            }
            w.print("], ");
            w.print("\"writes_fpu_control\": "+t.writesFpuControl+", ");
            w.print("\"uses_fpu_div_sqrt\": "+t.usesFpuDivSqrt+", ");
            w.print("\"is_overlay_loader\": "+t.isOverlayLoader+", ");
            // ===== v12 fields (Rules 165-177) =====
            w.print("\"writes_frame_reg\": "+t.writesFrameReg+", ");
            w.print("\"is_rtt_target\": "+t.isRttTarget+", ");
            w.print("\"zbuf_vram_alias_risk\": "+t.zbufVramAliasRisk+", ");
            w.print("\"vram_known_pages_hit\": [");
            { boolean f=true; for(Long p : t.vramKnownPagesHit){ if(!f)w.print(", "); f=false;
                w.print("{\"page\": \""+hex(p)+"\", \"label\": "
                    +jsonString(KNOWN_DC2_TBP_LABELS.getOrDefault(p,""))+"}"); } }
            w.print("], ");
            w.print("\"is_vf0_dependent_inverse\": "+t.isVf0DependentInverse+", ");
            w.print("\"is_audio_completion_gate\": "+t.isAudioCompletionGate+", ");
            w.print("\"audio_gate_signals\": "+jsonStrArray(new ArrayList<>(t.audioGateSignals))+", ");
            w.print("\"is_memcard_io\": "+t.isMemcardIo+", ");
            w.print("\"memcard_callees\": "+jsonStrArray(new ArrayList<>(t.memcardCallees))+", ");
            w.print("\"writes_presentation_field_state\": "+t.writesPresentationFieldState+", ");
            w.print("\"presentation_regs\": "+jsonStrArray(new ArrayList<>(t.presentationRegs))+", ");
            w.print("\"is_display_buffer_flip\": "+t.isDisplayBufferFlip+", ");
            w.print("\"is_clut_cache_invalidator\": "+t.isClutCacheInvalidator+", ");
            w.print("\"is_perf_hot_frame_path\": "+t.isPerfHotFramePath+", ");
            // ===== v13 fields (Rules 178-188) =====
            w.print("\"is_conditional_init_on_global\": "+t.isConditionalInitOnGlobal+", ");
            w.print("\"guard_globals\": "+jsonStrArray(new ArrayList<>(t.guardGlobals))+", ");
            w.print("\"is_render_mode_selector\": "+t.isRenderModeSelector+", ");
            w.print("\"is_vertex_lighting_term\": "+t.isVertexLightingTerm+", ");
            w.print("\"lighting_sources\": "+jsonStrArray(new ArrayList<>(t.lightingSources))+", ");
            w.print("\"is_vtable_tailcall_thunk\": "+t.isVtableTailcallThunk+", ");
            w.print("\"tailcall_vtable_slots\": [");
            { boolean f=true; for(Long s : t.tailcallVtableSlots){ if(!f)w.print(", "); f=false; w.print("\""+hex(s)+"\""); } }
            w.print("], ");
            w.print("\"is_rtt_no_restore\": "+t.isRttNoRestore+", ");
            w.print("\"is_vu_flag_pipeline_uploader\": "+t.isVuFlagPipelineUploader+", ");
            w.print("\"is_packed_rgbaq_builder\": "+t.isPackedRgbaqBuilder+", ");
            w.print("\"is_frame_resume_risk\": "+t.isFrameResumeRisk+", ");
            // ===== v15 fields (Rules 190-198) =====
            w.print("\"is_prim_class_selector\": "+t.isPrimClassSelector+", ");
            w.print("\"is_adc_kick_vertex_source\": "+t.isAdcKickVertexSource+", ");
            w.print("\"adc_source\": "+jsonString(t.adcSource==null?"":t.adcSource)+", ");
            w.print("\"writes_xyz2_reg\": "+t.writesXyz2Reg+", ");
            w.print("\"writes_xyz3_reg\": "+t.writesXyz3Reg+", ");
            w.print("\"is_kick_mode_writer\": "+t.isKickModeWriter+", ");
            w.print("\"kick_const_add_count\": "+t.kickConstAddCount+", ");
            w.print("\"is_texture_reload_interleave\": "+t.isTextureReloadInterleave+", ");
            w.print("\"is_vsync_coupled_game_step\": "+t.isVsyncCoupledGameStep+", ");
            w.print("\"is_view_projection_matrix_writer\": "+t.isViewProjectionMatrixWriter+", ");
            w.print("\"is_object_array_ctor\": "+t.isObjectArrayCtor+", ");
            w.print("\"vu_exec_hazards\": "+jsonStrArray(new ArrayList<>(t.vuExecHazards))+", ");
            // ===== v15.1 fields (PCSX2-grounded, Rules 199-201) =====
            w.print("\"is_vif_unpack_decompress_state\": "+t.isVifUnpackDecompressState+", ");
            w.print("\"vif_unpack_state_cmds\": "+jsonStrArray(new ArrayList<>(t.vifUnpackStateCmds))+", ");
            w.print("\"writes_xyoffset_reg\": "+t.writesXyoffsetReg+", ");
            w.print("\"writes_tex1_reg\": "+t.writesTex1Reg+", ");
            // ===== v15.2 fields (skill codegen classes, Rules 203-204) =====
            w.print("\"uses_mmi\": "+t.usesMmi+", ");
            w.print("\"mmi_op_count\": "+t.mmiOpCount+", ");
            w.print("\"mmi_families\": "+jsonStrArray(new ArrayList<>(t.mmiFamilies))+", ");
            w.print("\"uses_cop2_control_reg\": "+t.usesCop2ControlReg+", ");
            w.print("\"cop2_control_regs\": "+jsonStrArray(new ArrayList<>(t.cop2ControlRegs))+", ");
            // ===== v16 fields (Rules 207-214, G116-G137) =====
            w.print("\"is_adc_capable_packer\": "+t.isAdcCapablePacker+", ");
            w.print("\"adc_capability\": "+jsonString(t.adcCapability==null?"":t.adcCapability)+", ");
            w.print("\"is_near_plane_site\": "+t.isNearPlaneSite+", ");
            w.print("\"near_plane_strategy\": "+jsonString(t.nearPlaneStrategy==null?"":t.nearPlaneStrategy)+", ");
            w.print("\"is_spi_config_command\": "+t.isSpiConfigCommand+", ");
            w.print("\"is_command_interpreter\": "+t.isCommandInterpreter+", ");
            w.print("\"is_packer_family\": "+t.isPackerFamily+", ");
            w.print("\"packer_family\": "+jsonString(t.packerFamily==null?"":t.packerFamily)+", ");
            w.print("\"is_private_depth_scope\": "+t.isPrivateDepthScope+", ");
            w.print("\"is_packed_field_alias\": "+t.isPackedFieldAlias+", ");
            // v17 Rule 222 (G141 perf support)
            w.print("\"perf_static_cost\": "+t.perfStaticCost+", ");
            w.print("\"is_memcpy_shaped_loop\": "+t.isMemcpyShapedLoop+", ");
            w.print("\"is_idle_spin_yield_site\": "+t.isIdleSpinYieldSite+", ");
            // v18 Rules 234-240 (G142-G172 perf-arc retrospective)
            w.print("\"is_sprite_emitter\": "+t.isSpriteEmitter+", ");
            if(!t.primClassesEmitted.isEmpty())
                w.print("\"prim_classes_emitted\": "+jsonStrArray(new ArrayList<>(t.primClassesEmitted))+", ");
            w.print("\"sprite_group_order_dependency\": "+t.spriteGroupOrderDependency+", ");
            w.print("\"presentation_fifo_bypass\": "+t.presentationFifoBypass+", ");
            if(t.gpuRasterEligibility != null)
                w.print("\"gpu_raster_eligibility\": "+jsonString(t.gpuRasterEligibility)+", ");
            // v19 Rules 243-250 (PCSX2 cross-check round 3)
            w.print("\"is_interrupt_handler_reg\": "+t.isInterruptHandlerReg+", ");
            w.print("\"dma_chcr_tie\": "+t.dmaChcrTie+", ");
            w.print("\"vif_code_ibit\": "+t.vifCodeIBit+", ");
            w.print("\"is_sif_transport\": "+t.isSifTransport+", ");
            w.print("\"is_cdvd_completion_gate\": "+t.isCdvdCompletionGate+", ");
            if(t.hasCacheOp || t.hasSyncOp)
                w.print("\"cache_coherency_op\": true, ");
            if(t.writesTlb) w.print("\"writes_tlb\": true, ");
            w.print("\"is_gs_csr_signal_site\": "+t.isGsCsrSignalSite+", ");
            // v17.1 Rules 226-232 (PCSX2 cross-check round 2)
            w.print("\"is_dma_mfifo_user\": "+t.isDmaMfifoUser+", ");
            w.print("\"is_dma_stall_control_sync\": "+t.isDmaStallControlSync+", ");
            w.print("\"is_vif_path_arbiter\": "+t.isVifPathArbiter+", ");
            w.print("\"is_gs_readback_site\": "+t.isGsReadbackSite+", ");
            w.print("\"is_ee_time_source\": "+t.isEeTimeSource+", ");
            if(!t.rcntRegsHit.isEmpty())
                w.print("\"rcnt_regs_hit\": "+jsonStrArray(new ArrayList<>(t.rcntRegsHit))+", ");
            if(!t.dmacGlobalRegsHit.isEmpty())
                w.print("\"dmac_global_regs_hit\": "+jsonStrArray(new ArrayList<>(t.dmacGlobalRegsHit))+", ");
            w.print("\"computed_jump_sites\": [");
            {
                Map<Long,List<Long>> byPc = new LinkedHashMap<>();
                for(Long pc : t.computedJumpSwitchPcs) byPc.put(pc, new ArrayList<>());
                for(long[] e : t.computedJumpTargets) {
                    List<Long> lst = byPc.get(e[0]);
                    if(lst == null) { lst = new ArrayList<>(); byPc.put(e[0], lst); }
                    lst.add(e[1]);
                }
                boolean f=true;
                for(Map.Entry<Long,List<Long>> e : byPc.entrySet()){
                    if(!f) w.print(", "); f=false;
                    w.print("{\"pc\": \""+hex(e.getKey())+"\", \"unresolved\": "+e.getValue().isEmpty()+
                            ", \"targets\": [");
                    boolean g=true;
                    for(Long tg : e.getValue()){ if(!g) w.print(", "); g=false; w.print("\""+hex(tg)+"\""); }
                    w.print("]}");
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
            // ===== v11 AI-facing per-function layer (additive) =====
            // recommendation + relationship_summary, reusing the precomputed AiRec.
            {
                AiRec __rec = aiRecs.get(r.address & 0xFFFFFFFFL);
                if(__rec == null) __rec = new AiRec();
                w.print(", ");
                emitFunctionRecommendation(w, __rec);
                w.print(", ");
                emitFunctionRelationshipSummary(w, r, t, __rec, nameByAddr,
                        aiPrefixByAddr, aiImportantAddrs, aiImportantNames);
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

    // =========================================================================
    // v11 AI-FACING ABSTRACTION LAYER (additive)
    // -------------------------------------------------------------------------
    // Purpose: expose the intelligence already collected by Rules 1-150 in a
    // shape another AI can reason about — per-function recommendations, a
    // subsystem/relationship view, decision guardrails, and next-rule hints.
    // This is NOT a second triage engine: every field is DERIVED from existing
    // traits, tags, depths, module clusters, call chains, class registry,
    // runtime corroboration, asset-upload traces and override coverage.
    // Cost: a constant number of O(N) / O(N+E) passes; no per-function BFS.
    // =========================================================================

    private static final String[] SUBSYSTEM_KEYS = {
        "render","texture_upload","archive_io","input","audio","memory_card",
        "iop_rpc","main_loop","init","class_ctor_vtable","unknown"
    };

    // Dangerous-tag guardrail sets (mirror the project's "never auto-stub" rules).
    private static final String[] NEVER_AUTO_STUB_TAGS = {
        "RENDER_FRAME_ENTRY","CTOR_FIELD_WRITER","CTOR_MULTI_FIELD_INITIALIZER",
        "STRUCT_INITIALIZER","VTABLE_SETTER","DRAWING_CHAIN_NEAR_ROOT","PATH3_INITIATOR",
        "PATH3_KICK_VIA_DMA_API","DMA_CHAIN_TTE_RISK","ARCHIVE_IO","MPEG_DECODER_TRAP",
        "IRX_LOADER","IOP_RPC_DISPATCH","IOP_REBOOT_HANDLER","SCEVU0_HELPER_MUSTIMPL",
        "MEMORY_ALLOCATOR_NEVER_STUB","BITBLTBUF_T4HH_UPLOADER","BITBLTBUF_MACRO_SEQUENCE",
        "GIF_TAG_INLINE_BUILDER","DMA_CHCR_START_KICK","DMA_SOURCE_CHAIN_TAG_BUILDER",
        "MICROCODE_UPLOADER","TEX0_REG_WRITER","DISPFB_WRITER","DISPFB_SDK_WRITER",
        "COP2_DESTMASK_VERIFY","STATIC_INIT_VTABLE_INSTALLER","MAP_CLUT_PSMCT16_UPLOADER",
        "FRAME_CLOCK_DRIVER","LIBGCC_INTRINSIC",
        // v11 Rule 161: runtime code linker/loader - stubbing it kills the
        // game's entire runtime-loaded code path.
        "DYNAMIC_CODE_LOADER"
    };
    private static final String[] NEVER_AUTO_PATCH_TAGS = {
        "INDIRECT_CALL_T9","TAIL_CALL_INDIRECT","COMPLEX_CONTROL_FLOW",
        "COMPUTED_JUMP_UNRESOLVED","VIRTUAL_DISPATCH_SITE","TABLE_DISPATCH_CALL",
        "DISPATCH_TABLE_TARGET"
    };
    private static final String[] REQUIRE_REVIEW_TAGS = {
        "INDIRECT_CALL_T9","TAIL_CALL_INDIRECT","COMPLEX_CONTROL_FLOW","VIRTUAL_DISPATCH_SITE",
        "TABLE_DISPATCH_CALL","DISPATCH_TABLE_TARGET","COMPUTED_JUMP_UNRESOLVED",
        "GIF_NLOOP_DOUBLE_COUNT_RISK","Z_BUFFER_ALIAS_RISK","COP2_DESTMASK_VERIFY",
        "COP2_SPECIAL_OPS_REVIEW","FPU_NONIEEE_SENSITIVE","EABI_ARG_T0",
        "GUEST_LOCK_HOG_CANDIDATE","OVERLAY_LOADER","DC2_HOST_WAIT_CANDIDATE"
    };
    private static final String[] SAFE_STUB_REQUIRES = {
        "override system already classified kind in {nop_stub, constant_return, probe}",
        "GS_IRQ_SAFE_STUB: IMR=0x7F00 masks all GS IRQs across every loaded GS checkpoint",
        "disposition==SKIP from kernel syscall/COP0 firewall (HLE provides behavior)",
        "radar/BIOS firewall prefix match OR IOP-module string reference (existing Rule 1/2)",
        "no never_auto_stub tag present on the function"
    };

    /** Per-function AI recommendation + relationship metadata, computed once. */
    private static class AiRec {
        String action = "review";
        double confidence = 0.30;
        String risk = "medium";
        String riskIfStubbed = "";
        String riskIfRecompiled = "";
        String reason = "";
        String suggestedNextStep = "";
        boolean humanReview = true;
        List<String> evidence = new ArrayList<>();
        LinkedHashSet<String> derivedFrom = new LinkedHashSet<>();
        String subsystem = "unknown";
        String role = "unknown";
        boolean gateway = false;
    }

    private static int riskRank(String r){
        if("critical".equals(r)) return 3;
        if("high".equals(r))     return 2;
        if("medium".equals(r))   return 1;
        return 0;
    }
    private static String fmtConf(double c){ return String.format(Locale.US, "%.2f", c); }
    /** v11 (General v15.2): emit one advisory array as
     *  [{"entry": "...", "tags": [...]}]. Input strings are "name@0xADDR"
     *  optionally followed by " # TAG,TAG". */
    private static void emitAdvisoryJsonArray(PrintWriter w, String key,
                                              List<String> list, boolean trailingComma) {
        w.println("    \""+key+"\": [");
        for(int i=0;i<list.size();i++){
            String e = list.get(i);
            int hash = e.indexOf(" # ");
            String entry = hash<0 ? e : e.substring(0, hash);
            List<String> tags = new ArrayList<>();
            if(hash>=0) for(String t : e.substring(hash+3).split(",")) {
                String tt = t.trim();
                if(!tt.isEmpty()) tags.add(tt);
            }
            w.print("      {\"entry\": "+jsonString(entry)+", \"tags\": "+jsonStrArray(tags)+"}");
            w.println(i==list.size()-1 ? "" : ",");
        }
        w.println("    ]"+(trailingComma?",":""));
    }
    private static String jsonStrArray(Collection<String> c){
        StringBuilder sb = new StringBuilder("["); boolean f = true;
        for(String s : c){ if(!f) sb.append(", "); f = false; sb.append(jsonString(s)); }
        return sb.append("]").toString();
    }
    private static String jsonStrArrayCapped(List<String> c, int cap){
        StringBuilder sb = new StringBuilder("["); int n = 0; boolean f = true;
        for(String s : c){ if(n >= cap) break; if(!f) sb.append(", "); f = false; sb.append(jsonString(s)); n++; }
        if(c.size() > cap){ if(!f) sb.append(", "); sb.append(jsonString("+" + (c.size()-cap) + " more")); }
        return sb.append("]").toString();
    }
    // v13: emit a [name, addrHex, detail] roster as a JSON array of objects.
    private static void emitV13Roster(java.io.PrintWriter w, String key,
                                      List<String[]> rows, String detailKey){
        w.println("  \""+key+"\": [");
        for(int i=0;i<rows.size();i++){
            String[] e = rows.get(i);
            w.print("    {\"name\": "+jsonString(e[0])+", \"address\": "+jsonString(e[1])
                +", \""+detailKey+"\": "+jsonString(e[2])+"}");
            w.println(i<rows.size()-1?",":"");
        }
        w.println("  ],");
    }
    private static boolean hasAnyTag(FuncResult r, String[] tags){
        if(r.tags == null) return false;
        for(String t : tags) if(r.tags.contains(t)) return true;
        return false;
    }

    /** Functions worth pointing at as nodes/edges in the relationship view. */
    private void collectImportant(List<FuncResult> results, Set<Long> addrs, Set<String> names){
        for(FuncResult r : results){
            FuncTraits t = r.traits; if(t == null) continue;
            boolean imp = t.isTopPriorityFix || r.tags.contains("TOP_PRIORITY_FIX")
                || t.isRenderFrameEntry || t.path3Initiator || t.isBitbltbufT4hhUploader
                || t.dc2KnownRole != null || t.isFrameClockDriver || t.isMemoryAllocator
                || t.mustBeImplemented || t.ctorInstallsVtable || t.isStaticInitializer
                || !t.dc2CallChainsTagged.isEmpty() || t.isIrxLoader || t.callsSifRpc
                || t.mainLoopDepth == 0;
            if(imp){ addrs.add(r.address & 0xFFFFFFFFL); if(r.name != null) names.add(r.name); }
        }
    }

    // -------------------------------------------------------------------------
    // Subsystem / role / gateway inference (reuses existing traits + tags only)
    // -------------------------------------------------------------------------
    private String inferSubsystemGuess(FuncResult r, FuncTraits t, boolean isMainLoop){
        if(t == null) return "unknown";
        if(t.mainLoopDepth == 0) return "main_loop";
        boolean uploader = t.isBitbltbufT4hhUploader || t.writesBitbltbufReg || t.bitbltbufMacroSequence
            || t.isPsmct16ClutUploader || t.loadsPsm4hhConstant || t.isSceGifPkRefLoadImage
            || !t.assetUploadTagsHit.isEmpty() || r.tags.contains("UPLOADER_CALLER_D1");
        if(uploader) return "texture_upload";
        boolean render = t.path3Initiator || t.isRenderFrameEntry || t.drawingChainDepth >= 0
            || t.gifTagInlineBuilder || t.dmaChcrStartKick || t.dmaSourceChainTagBuilder
            || t.writesTex0Reg || t.writesRgbaqReg || t.readsPrimReg || t.writesDispfbReg
            || t.writesZbufReg || t.touchesGifP3Reg || t.writesGifFifo || t.writesVif1Fifo
            || t.writesVif0Fifo || t.accessesVuMicromem || t.accessesVuDatamem || t.isMicrocodeUploader
            || r.tags.contains("GIF_PATH3_HAZARD") || r.tags.contains("DISPFB_WRITER")
            || (t.methodClassName != null && t.methodClassName.startsWith("mg"))
            || (t.ctorClassName  != null && t.ctorClassName.startsWith("mg"));
        if(render) return "render";
        boolean iop = t.callsSifRpc || t.isIrxLoader || t.isIopRebootHandler
            || r.tags.contains("IOP_RPC_DISPATCH") || r.tags.contains("IRX_LOADER")
            || t.detectedRpcSid != 0 || !t.discoveredRpcSids.isEmpty() || t.touchesSbus;
        if(iop) return "iop_rpc";
        if(t.isAudioRpcHandler || r.tags.contains("AUDIO_RPC_HANDLER")) return "audio";
        boolean archive = t.refsArchiveStrings || t.callsFileOpen || !t.filePathSprintfFormats.isEmpty()
            || r.tags.contains("ARCHIVE_IO");
        if(archive) return "archive_io";
        boolean input = t.callsPadPollCallee || t.isPadButtonMaskConsumer
            || r.tags.contains("PAD_POLL_LOOP") || r.tags.contains("PAD_BUTTON_MASK_CONSUMER");
        if(input) return "input";
        if(t.isMcTransitionGate || r.tags.contains("MC_TRANSITION_GATE")) return "memory_card";
        if(isMainLoop || t.isFrameClockDriver) return "main_loop";
        boolean cls = t.isCtor || t.isDtor || t.ctorInstallsVtable || t.ctorWritesVTablePointer
            || t.isStructInitializer || t.isCtorMultiFieldInit || t.isStaticInitializer
            || t.methodClassName != null || !t.virtualDispatchSites.isEmpty()
            || r.tags.contains("VTABLE_SETTER") || r.tags.contains("CTOR_FIELD_WRITER");
        if(cls) return "class_ctor_vtable";
        if(t.isLargeInitFunc || t.initChainDepth >= 0) return "init";
        return "unknown";
    }

    private String inferRoleGuess(FuncResult r, FuncTraits t, boolean isMainLoop){
        if(t == null) return "unknown";
        if(t.mainLoopDepth == 0) return "main_loop_entry";
        if(t.isRenderFrameEntry) return "render_frame_entry";
        if(t.isFrameClockDriver) return "frame_clock_driver";
        if(t.isBitbltbufT4hhUploader || t.isPsmct16ClutUploader) return "texture_uploader";
        if(t.writesBitbltbufReg || t.bitbltbufMacroSequence) return "bitbltbuf_writer";
        if(t.path3Initiator) return "path3_initiator";
        if(t.gifTagInlineBuilder || t.dmaSourceChainTagBuilder || t.dmaChcrStartKick) return "dma_gif_packet_builder";
        if(t.isMicrocodeUploader) return "vu_microcode_uploader";
        if(t.ctorInstallsVtable || r.tags.contains("VTABLE_SETTER")) return "vtable_installer";
        if(t.isStaticInitializer) return "static_initializer";
        if(t.isCtorMultiFieldInit || t.ctorWritesA0Slot || r.tags.contains("CTOR_FIELD_WRITER")) return "field_initializing_ctor";
        if(t.isCtor) return "constructor";
        if(t.isDtor) return "destructor";
        if(t.isMemoryAllocator) return "memory_allocator";
        if(t.isIrxLoader) return "irx_loader";
        if(t.isIopRebootHandler) return "iop_reboot_handler";
        if(t.callsSifRpc || r.tags.contains("IOP_RPC_DISPATCH")) return "iop_rpc_dispatch";
        if(t.callsFileOpen || r.tags.contains("ARCHIVE_IO")) return "archive_loader";
        if(t.isPadButtonMaskConsumer) return "pad_button_consumer";
        if(t.callsPadPollCallee || r.tags.contains("PAD_POLL_LOOP")) return "pad_poll_loop";
        if(t.isMcTransitionGate) return "memory_card_gate";
        if(t.isAudioRpcHandler) return "audio_rpc_handler";
        if(t.mustBeImplemented || t.isSceVu0Helper) return "vu0_math_helper";
        if(t.dc2HostWaitCandidate || r.tags.contains("BACKWARD_BRANCH_SYNC_WAIT")) return "sync_wait_loop";
        if(r.tags.contains("INFINITE_FAIL_LOOP")) return "infinite_fail_loop";
        if(!t.virtualDispatchSites.isEmpty()) return "virtual_dispatcher";
        if(!t.computedJumpSwitchPcs.isEmpty() || t.hasJumpTable) return "jump_table_dispatcher";
        if(t.methodClassName != null) return "class_method";
        if(t.isLargeInitFunc || t.initChainDepth >= 0) return "initializer";
        if(r.tags.contains("SAFE_LEAF")) return "leaf_utility";
        return "unknown";
    }

    private boolean inferGateway(FuncResult r, FuncTraits t, boolean isMainLoop){
        if(t == null) return false;
        return t.mainLoopDepth == 0 || t.isRenderFrameEntry || t.isFrameClockDriver
            || t.path3Initiator || t.isIrxLoader || t.isOverlayLoader
            || t.isStaticInitializer || t.ctorInstallsVtable
            || (t.callsFileOpen && t.refsArchiveStrings)
            || t.callsSifRpc || t.isMemoryAllocator
            || t.callers.size() >= 8 || !t.dc2CallChainsTagged.isEmpty();
    }

    private List<String> mainLoopHints(FuncTraits t){
        List<String> h = new ArrayList<>();
        if(t.mainLoopDepth == 0) h.add("is the main-loop entry (depth 0)");
        else if(t.mainLoopDepth > 0) h.add("depth " + t.mainLoopDepth + " from main loop");
        if(t.isFrameClockDriver) h.add("calls frame-clock / vsync");
        if(t.isRenderFrameEntry) h.add("render frame entry");
        return h;
    }
    private List<String> initHints(FuncTraits t){
        List<String> h = new ArrayList<>();
        if(t.initChainDepth == 0) h.add("init chain root (depth 0)");
        else if(t.initChainDepth > 0) h.add("depth " + t.initChainDepth + " from init chain");
        if(t.isStaticInitializer) h.add("runs via global-ctors table (no jal caller)");
        if(t.isLargeInitFunc) h.add("large initializer");
        return h;
    }
    private List<String> hardwareHints(FuncResult r, FuncTraits t){
        List<String> h = new ArrayList<>();
        if(t.path3Initiator) h.add("PATH3_INITIATOR (writes GIF CHCR)");
        if(t.drawingChainDepth >= 0) h.add("depth " + t.drawingChainDepth + " from render root");
        if(t.writesBitbltbufReg || t.isBitbltbufT4hhUploader) h.add("writes BITBLTBUF (VRAM upload)");
        if(t.callsDmaSend) h.add("calls DMA send");
        if(t.usesCop2) h.add("uses COP2/VU0 vectors");
        if(t.cop2DestMaskVerify) h.add("COP2 partial-dest (verify lane order)");
        if(h.size() > 5) return new ArrayList<>(h.subList(0, 5));
        return h;
    }

    // -------------------------------------------------------------------------
    // Per-function recommendation (Part 2). Pure derivation from existing data.
    // -------------------------------------------------------------------------
    private AiRec buildFunctionRecommendation(FuncResult r){
        AiRec rec = new AiRec();
        FuncTraits t = r.traits;
        if(t == null){
            rec.action = "review"; rec.confidence = 0.10; rec.risk = "medium";
            rec.reason = "no traits available"; rec.suggestedNextStep = "review";
            rec.derivedFrom.add("RULE_DISPOSITION_BASELINE");
            return rec;
        }
        long a = r.address & 0xFFFFFFFFL;
        boolean isMainLoop = (t.mainLoopDepth == 0) || mainLoopShield.contains(a);
        rec.subsystem = inferSubsystemGuess(r, t, isMainLoop);
        rec.role      = inferRoleGuess(r, t, isMainLoop);
        rec.gateway   = inferGateway(r, t, isMainLoop);

        List<String> ev = rec.evidence;
        LinkedHashSet<String> df = rec.derivedFrom;

        // ---- evidence + derived_from collection (independent of the chosen action) ----
        if(t.isTopPriorityFix || r.tags.contains("TOP_PRIORITY_FIX")){ ev.add("focus_set bullseye"); df.add("RULE_57_FOCUS_SET"); }
        if(r.tags.contains("FOCUS_SYNTHETIC")){ ev.add("focus_set synthetic top-score"); df.add("RULE_136_FOCUS_SYNTHETIC"); }
        if(!"INDETERMINATE".equals(t.runtimeStatus)){ ev.add("runtime_status=" + t.runtimeStatus); df.add("RULE_80_RUNTIME_CORROBORATION"); }
        if(!t.runtimeBullseyePredictions.isEmpty()){ df.add("RULE_80_RUNTIME_CORROBORATION"); }
        if(t.drawingChainDepth >= 0){ ev.add("drawing_chain_depth=" + t.drawingChainDepth); df.add("RULE_83_DRAWING_CHAIN_DEPTH"); }
        if(t.mainLoopDepth >= 0){ ev.add("mainloop_depth=" + t.mainLoopDepth); df.add("RULE_39_MAINLOOP_DEPTH"); }
        if(t.initChainDepth >= 0){ ev.add("init_chain_depth=" + t.initChainDepth); df.add("RULE_40_INIT_CHAIN_DEPTH"); }
        if(t.moduleId >= 0){ df.add("RULE_129_MODULE_CLUSTERS"); }
        if(!t.dc2CallChainsTagged.isEmpty()){ ev.add("dc2_chains=" + t.dc2CallChainsTagged); df.add("RULE_134_DC2_CALL_CHAINS"); }
        if(t.dc2KnownRole != null){ ev.add("dc2_known=" + t.dc2KnownRole + "/" + t.dc2KnownCriticality); df.add("RULE_131_DC2_KNOWN_ADDRESSES"); }
        if(t.isCtor || t.methodClassName != null || t.ctorClassName != null){ df.add("RULE_93_CLASS_REGISTRY"); }
        if(!t.assetUploadTagsHit.isEmpty() || r.tags.contains("UPLOADER_CALLER_D1") || r.tags.contains("ASSET_UPLOAD_BULLSEYE")){ ev.add("asset_upload trace"); df.add("RULE_103_ASSET_UPLOAD_TRACES"); }
        if(t.overrideKind != null){ ev.add("override_kind=" + t.overrideKind); df.add("RULE_98_OVERRIDE_COVERAGE"); }
        if(t.runtimeDormantGlobal){ ev.add("runtime: predicted but never witnessed (dormant)"); }
        if(t.runtimeMenuOnly){ ev.add("runtime: menu/UI pipeline only"); }

        // ---- decision tree (precedence: must-keep-real → patch → review → safe-stub → skip) ----
        boolean uploader = t.isBitbltbufT4hhUploader || t.writesBitbltbufReg || t.bitbltbufMacroSequence
            || t.isPsmct16ClutUploader || t.loadsPsm4hhConstant || t.isSceGifPkRefLoadImage
            || !t.assetUploadTagsHit.isEmpty();
        boolean renderHw = t.path3Initiator || t.isRenderFrameEntry || t.gifTagInlineBuilder
            || t.dmaChcrStartKick || t.dmaSourceChainTagBuilder || t.writesTex0Reg || t.writesRgbaqReg
            || t.readsPrimReg || t.writesDispfbReg || t.writesZbufReg || t.touchesGifP3Reg
            || t.writesGifFifo || t.writesVif1Fifo || t.writesVif0Fifo || t.accessesVuMicromem
            || t.accessesVuDatamem || t.isMicrocodeUploader || r.tags.contains("GIF_PATH3_HAZARD")
            || r.tags.contains("DISPFB_WRITER") || r.tags.contains("DMA_KICK_PATTERN")
            || r.tags.contains("DMA_QWC_TADR_WRITER") || (t.drawingChainDepth >= 0 && t.drawingChainDepth <= 6);
        boolean lifecycle = t.isCtor || t.ctorWritesA0Slot || t.ctorWritesVTablePointer
            || t.isCtorMultiFieldInit || t.isStructInitializer || t.isLifecycleLazyInit
            || t.ctorInstallsVtable || r.tags.contains("VTABLE_SETTER") || r.tags.contains("CTOR_FIELD_WRITER");
        boolean staticInit = t.isStaticInitializer || r.tags.contains("STATIC_INIT_VTABLE_INSTALLER")
            || r.tags.contains("UNCALLED_STATIC_INIT");
        boolean cop2Codegen = t.cop2DestMaskVerify || !t.cop2SpecialOps.isEmpty();
        boolean indirect = r.tags.contains("INDIRECT_CALL_T9") || r.tags.contains("TAIL_CALL_INDIRECT")
            || r.tags.contains("COMPLEX_CONTROL_FLOW") || r.tags.contains("VIRTUAL_DISPATCH_SITE")
            || r.tags.contains("TABLE_DISPATCH_CALL") || r.tags.contains("DISPATCH_TABLE_TARGET")
            || r.tags.contains("COMPUTED_JUMP_UNRESOLVED") || !t.computedJumpSwitchPcs.isEmpty()
            || t.tailCallIndirect || t.indirectCallT9Count > 0 || t.hasJumpTable;
        boolean patchable = r.tags.contains("BACKWARD_BRANCH_SYNC_WAIT") || r.tags.contains("INFINITE_FAIL_LOOP")
            || t.dc2HostWaitCandidate || !t.patchCandidatePcs.isEmpty();
        boolean archive = t.refsArchiveStrings || t.callsFileOpen || !t.filePathSprintfFormats.isEmpty()
            || r.tags.contains("ARCHIVE_IO") || r.tags.contains("FILE_PATH_SPRINTF_SOURCE");
        boolean iop = t.callsSifRpc || t.isIrxLoader || t.isIopRebootHandler || r.tags.contains("IOP_RPC_DISPATCH")
            || r.tags.contains("IRX_LOADER") || t.detectedRpcSid != 0 || !t.discoveredRpcSids.isEmpty();
        boolean input = t.callsPadPollCallee || t.isPadButtonMaskConsumer
            || r.tags.contains("PAD_POLL_LOOP") || r.tags.contains("PAD_BUTTON_MASK_CONSUMER");
        boolean mcGate = t.isMcTransitionGate || r.tags.contains("MC_TRANSITION_GATE");
        boolean overrideSafe = t.overrideKind != null &&
            (t.overrideKind.equals("nop_stub") || t.overrideKind.equals("constant_return") || t.overrideKind.equals("probe"));
        boolean gsIrqSafe = t.gsIrqSafeStubCandidate || r.tags.contains("GS_IRQ_SAFE_STUB");
        boolean kernelSkip = "SKIP".equals(r.disposition) || t.hasSyscall || t.hasCOP0;
        boolean firewalledStub = "STUB".equals(r.disposition) && t.refsIopModuleString;
        boolean mustImpl = t.mustBeImplemented || t.isSceVu0Helper || r.tags.contains("SCEVU0_HELPER_MUSTIMPL");
        boolean allocator = t.isMemoryAllocator || r.tags.contains("MEMORY_ALLOCATOR_NEVER_STUB");
        boolean safeLeaf = r.tags.contains("SAFE_LEAF") && t.byteSize > 0 && t.calleeCount == 0
            && !t.writesToGlobal && !t.usesCop2 && !t.usesCop1;

        if(isMainLoop){
            rec.action = "force_recompile"; rec.confidence = 0.97; rec.risk = "critical"; rec.humanReview = false;
            rec.reason = "main loop / frame pump — the recompiler entry; stubbing halts the game";
            rec.riskIfStubbed = "game never advances a frame (hard hang)";
            rec.riskIfRecompiled = "none — this must run the real body";
            rec.suggestedNextStep = "force_recompile; never stub. Confirm it is the recompiler entry.";
            df.add("RULE_11_MAINLOOP_SHIELD");
        } else if(mustImpl){
            rec.action = "native_impl_needed"; rec.confidence = 0.90; rec.risk = "high"; rec.humanReview = true;
            rec.reason = "sceVu0 / must-implement math helper — a throwing or zero stub corrupts transforms";
            rec.riskIfStubbed = "degenerate/off-screen vertices, null transforms";
            rec.riskIfRecompiled = "n/a — needs a real native implementation, not raw recompile";
            rec.suggestedNextStep = "implement from ref/assembly.txt; cross-check sce_vu0_unimplemented[]";
            df.add("RULE_102_SCEVU0_MUSTIMPL");
        } else if(allocator){
            rec.action = "force_recompile"; rec.confidence = 0.92; rec.risk = "critical"; rec.humanReview = true;
            rec.reason = "memory allocator / pool — a 0-returning stub yields construct-on-null and a garbage vtable PC (F50.1/F50.2)";
            rec.riskIfStubbed = "Alloc returns 0 → null-vtable crash deep in an init chain";
            rec.riskIfRecompiled = "low — recompile the real body or supply a real allocator shim";
            rec.suggestedNextStep = "never auto-stub; recompile real body. See memory_allocators[].";
            df.add("RULE_142_MEMORY_ALLOCATOR");
        } else if(cop2Codegen){
            rec.action = "force_recompile"; rec.confidence = 0.85; rec.risk = "high"; rec.humanReview = true;
            rec.reason = "COP2 partial-dest / special-op — verify generated dest-mask lane order (F51.8 codegen bug)";
            rec.riskIfStubbed = "3D transforms break";
            rec.riskIfRecompiled = "lane-order codegen bug if the mask is reversed — verify against READ128/WRITE128";
            rec.suggestedNextStep = "force_recompile then verify COP2 dest-mask lane order. See cop2_partial_dest_risk[].";
            df.add("RULE_140_COP2_DESTMASK"); if(!t.cop2SpecialOps.isEmpty()) df.add("RULE_147_COP2_SPECIAL_OPS");
        } else if(uploader){
            rec.action = "force_recompile"; rec.confidence = 0.85; rec.risk = "high"; rec.humanReview = true;
            rec.reason = "texture/CLUT uploader (BITBLTBUF) — drives VRAM; a stub leaves textures black";
            rec.riskIfStubbed = "missing / black textures";
            rec.riskIfRecompiled = "low — recompile the real upload body";
            rec.suggestedNextStep = "force_recompile; cross-check tbp vs dc2_known_tbp_labels and gs_runtime_evidence.";
            df.add("RULE_85_BITBLTBUF_T4HH"); df.add("RULE_103_ASSET_UPLOAD_TRACES");
            if(t.isPsmct16ClutUploader) df.add("RULE_145_PSMCT16_CLUT");
        } else if(lifecycle){
            rec.action = "force_recompile"; rec.confidence = 0.85; rec.risk = "high"; rec.humanReview = true;
            rec.reason = "constructor / vtable / struct initializer — writes object fields or the vtable pointer";
            rec.riskIfStubbed = "uninitialized fields / null vtable → silent no-op or crash on next virtual call";
            rec.riskIfRecompiled = "low — recompile real body";
            rec.suggestedNextStep = "force_recompile; never stub. See classes[] for this class.";
            df.add("RULE_82_CTOR_MULTI_FIELD"); df.add("RULE_93_CLASS_REGISTRY");
            if(t.ctorInstallsVtable || r.tags.contains("VTABLE_SETTER")) df.add("RULE_27_VTABLE_SETTER");
        } else if(staticInit){
            rec.action = "force_recompile"; rec.confidence = 0.80; rec.risk = "high"; rec.humanReview = true;
            rec.reason = "static initializer (__sinit) — installs a global vtable/fields via the global-ctors table";
            rec.riskIfStubbed = "global object vtable stays null → next virtual dispatch no-ops (F50.4)";
            rec.riskIfRecompiled = "low — but ensure the global-ctors table actually runs";
            rec.suggestedNextStep = "ensure global-ctors run, or replay static_init_manifest[].";
            df.add("RULE_141_STATIC_INIT");
        } else if(renderHw){
            rec.action = "force_recompile"; rec.confidence = 0.80; rec.risk = "high"; rec.humanReview = true;
            rec.reason = "render / GS / GIF / VIF / DMA packet path — must emit real hardware packets";
            rec.riskIfStubbed = "frame not drawn / GS desync";
            rec.riskIfRecompiled = "low — recompile real body; verify against gs_runtime_evidence path counts";
            rec.suggestedNextStep = "force_recompile; review against gs_runtime_evidence.";
            df.add("RULE_44_PATH3"); df.add("RULE_61_GIF_PATH3");
            if(t.drawingChainDepth >= 0) df.add("RULE_83_DRAWING_CHAIN_DEPTH");
        } else if(archive && t.callsFileOpen){
            rec.action = "native_impl_needed"; rec.confidence = 0.75; rec.risk = "high"; rec.humanReview = true;
            rec.reason = "archive / file loader (DATA.DAT / .HD2) — needs real host file I/O";
            rec.riskIfStubbed = "no asset data loaded → empty world / immediate failure";
            rec.riskIfRecompiled = "medium — file-open callees need host shims regardless";
            rec.suggestedNextStep = "provide native file-I/O shim; see file_path_sprintf_formats.";
            df.add("RULE_23_ARCHIVE_IO"); df.add("RULE_99_FILE_PATH_SPRINTF");
        } else if(archive){
            rec.action = "review"; rec.confidence = 0.50; rec.risk = "medium"; rec.humanReview = true;
            rec.reason = "references archive strings but no file-open callee — classify before any action";
            rec.suggestedNextStep = "review whether this is a loader or a path/string builder.";
            df.add("RULE_23_ARCHIVE_IO");
        } else if(iop){
            rec.action = "review"; rec.confidence = 0.55; rec.risk = "high"; rec.humanReview = true;
            rec.reason = "IOP RPC / IRX loader / SIF bridge — host IOP services must be wired before stubbing";
            rec.riskIfStubbed = "missing IOP service (audio / MC / cdvd) — subsystem dead";
            rec.riskIfRecompiled = "medium — RPC targets resolve on the IOP side";
            rec.suggestedNextStep = "review against discovered_iop_sids / known_iop_sids; wire host service.";
            df.add("RULE_22_IOP_RPC"); if(t.isIrxLoader) df.add("RULE_124_IRX_LOADER");
            if(!t.discoveredRpcSids.isEmpty()) df.add("RULE_139_DISCOVERED_SIDS");
        } else if(patchable){
            rec.action = "patch_candidate"; rec.confidence = 0.60; rec.risk = "high"; rec.humanReview = true;
            rec.reason = "sync-wait / infinite-fail loop — needs a host-wait patch, not a stub";
            rec.riskIfStubbed = "deadlock or busy spin";
            rec.riskIfRecompiled = "high — naive recompile re-creates the guest spin/deadlock";
            rec.suggestedNextStep = "apply BACKWARD_BRANCH_SYNC_WAIT / DC2_HOST_WAIT patch at the patch-candidate PCs.";
            df.add("RULE_121_SYNC_WAIT"); df.add("RULE_123_INFINITE_FAIL_LOOP");
        } else if(mcGate){
            if(overrideSafe){
                rec.action = "stub_candidate"; rec.confidence = 0.70; rec.risk = "medium"; rec.humanReview = true;
                rec.reason = "memory-card transition gate; override system already classifies a safe " + t.overrideKind;
                rec.suggestedNextStep = "apply the existing override " + t.overrideKind + ".";
                df.add("RULE_98_OVERRIDE_COVERAGE");
            } else {
                rec.action = "review"; rec.confidence = 0.50; rec.risk = "medium"; rec.humanReview = true;
                rec.reason = "memory-card transition gate — review the save/load state machine before any action";
                rec.suggestedNextStep = "review; only stub if a DC2 rule already marks this pattern safe.";
            }
            df.add("RULE_54_MC_GATE");
        } else if(input){
            if(overrideSafe){
                rec.action = "stub_candidate"; rec.confidence = 0.70; rec.risk = "low"; rec.humanReview = false;
                rec.reason = "pad / input function; override system confirms a safe shim/stub (" + t.overrideKind + ")";
                rec.suggestedNextStep = "apply the existing override shim.";
                df.add("RULE_98_OVERRIDE_COVERAGE");
            } else {
                rec.action = "review"; rec.confidence = 0.50; rec.risk = "medium"; rec.humanReview = true;
                rec.reason = "pad polling / button-mask consumer — wire host input before stubbing";
                rec.suggestedNextStep = "review; corroborate with dc2_pad_input_scripts.";
            }
            df.add("RULE_24_PAD_POLL"); if(t.isPadButtonMaskConsumer) df.add("RULE_97_PAD_MASK");
        } else if(indirect){
            rec.action = "review"; rec.confidence = 0.45; rec.risk = "high"; rec.humanReview = true;
            rec.reason = "indirect / computed control flow — resolve dispatch targets before any patch";
            rec.riskIfStubbed = "recompiler may panic on an unresolved indirect jump";
            rec.riskIfRecompiled = "medium — unresolved targets must be pre-populated";
            rec.suggestedNextStep = "review computed_jump_targets / virtual_dispatch_sites; never auto-patch.";
            if(t.indirectCallT9Count > 0) df.add("RULE_38_INDIRECT_CALL_T9");
            if(!t.virtualDispatchSites.isEmpty()) df.add("RULE_94_VIRTUAL_DISPATCH");
            if(r.tags.contains("TABLE_DISPATCH_CALL") || r.tags.contains("DISPATCH_TABLE_TARGET")) df.add("RULE_128_TABLE_DISPATCH");
            if(!t.computedJumpSwitchPcs.isEmpty()) df.add("RULE_146_COMPUTED_JUMP");
        } else if(gsIrqSafe){
            rec.action = "stub_candidate"; rec.confidence = 0.85; rec.risk = "low"; rec.humanReview = false;
            rec.reason = "GS IRQ handler — IMR=0x7F00 masks all GS IRQs across every loaded checkpoint → can never fire";
            rec.riskIfStubbed = "none — handler is unreachable at runtime";
            rec.riskIfRecompiled = "none";
            rec.suggestedNextStep = "safe to stub per runtime evidence (gs_runtime_evidence.imr_all_masked_gs_irqs).";
            df.add("RULE_79_GS_IRQ_HANDLER"); df.add("RULE_80_RUNTIME_CORROBORATION");
        } else if(overrideSafe){
            rec.action = "stub_candidate"; rec.confidence = 0.80; rec.risk = "low"; rec.humanReview = false;
            rec.reason = "override system already classified a safe " + t.overrideKind;
            rec.riskIfStubbed = "low — existing override already validated";
            rec.suggestedNextStep = "apply the existing override " + t.overrideKind + ".";
            df.add("RULE_98_OVERRIDE_COVERAGE");
        } else if(kernelSkip){
            rec.action = "skip_candidate"; rec.confidence = 0.85; rec.risk = "low"; rec.humanReview = false;
            rec.reason = "kernel-internal (syscall / COP0) — provided by HLE; the existing firewall already skips it";
            rec.riskIfStubbed = "n/a — skipped, HLE provides behavior";
            rec.suggestedNextStep = "leave as SKIP.";
            df.add("RULE_3_SYSCALL_FIREWALL");
        } else if(r.tags.contains("LIBGCC_INTRINSIC")){
            rec.action = "force_recompile"; rec.confidence = 0.70; rec.risk = "medium"; rec.humanReview = false;
            rec.reason = "libgcc / FP intrinsic — needs the real arithmetic body (auto-stub corrupts math)";
            rec.riskIfStubbed = "wrong arithmetic results (div/mod/float)";
            rec.riskIfRecompiled = "low";
            rec.suggestedNextStep = "force_recompile (existing triage already promotes these from STUB).";
            df.add("RULE_31_LIBGCC");
        } else if(firewalledStub){
            rec.action = "stub_candidate"; rec.confidence = 0.70; rec.risk = "low"; rec.humanReview = false;
            rec.reason = "IOP-module / firewalled wrapper — the existing radar/IOP firewall already stubs it";
            rec.riskIfStubbed = "low — firewall-confirmed";
            rec.suggestedNextStep = "apply the existing firewall stub.";
            df.add("RULE_2_RADAR_FIREWALL");
        } else if(safeLeaf){
            rec.action = "force_recompile"; rec.confidence = 0.60; rec.risk = "low"; rec.humanReview = false;
            rec.reason = "safe leaf — small, no callees, no MMIO; recompiling the real body is low-risk";
            rec.riskIfStubbed = "medium — even leaves may carry meaningful return values";
            rec.riskIfRecompiled = "low";
            rec.suggestedNextStep = "force_recompile (low risk).";
            df.add("RULE_1_SAFE_LEAF");
        } else {
            // Fallback: map from the existing disposition. Recompiling the real body
            // is the non-destructive default; only stub/skip/patch are "aggressive",
            // so we never pick those here on weak evidence.
            if("RECOMPILE".equals(r.disposition)){
                rec.action = "force_recompile"; rec.confidence = 0.55;
                rec.risk = (t.writesToGlobal || t.usesCop1 || t.usesCop2 || t.accessesMMIO) ? "medium" : "low";
                rec.humanReview = false;
                rec.reason = "default: translate the real body (no hazard or safe-stub signal fired)";
                rec.suggestedNextStep = "force_recompile.";
            } else if("STUB".equals(r.disposition)){
                rec.action = "review"; rec.confidence = 0.40; rec.risk = "medium"; rec.humanReview = true;
                rec.reason = "existing triage stubbed it but no confirming safe-stub rule fired — review before trusting the stub";
                rec.suggestedNextStep = "review whether the stub is safe.";
            } else {
                rec.action = "review"; rec.confidence = 0.40; rec.risk = "medium"; rec.humanReview = true;
                rec.reason = "no specific signal — review";
                rec.suggestedNextStep = "review.";
            }
            df.add("RULE_DISPOSITION_BASELINE");
        }

        // Down-weight confidence when runtime evidence says this never fires.
        if((t.runtimeDormantGlobal || t.runtimeMenuOnly) && rec.confidence > 0.40)
            rec.confidence = Math.max(0.40, rec.confidence - 0.10);

        // finalize defaults
        if(rec.reason.isEmpty()) rec.reason = "no specific hazard or safe-stub signal; defaulting conservatively";
        if(rec.suggestedNextStep.isEmpty()) rec.suggestedNextStep = "review";
        if(rec.riskIfStubbed.isEmpty()) rec.riskIfStubbed = "unknown — verify before stubbing";
        if(rec.riskIfRecompiled.isEmpty()) rec.riskIfRecompiled = "low (recompiling the real body is non-destructive)";
        if(df.isEmpty()) df.add("RULE_DISPOSITION_BASELINE");
        return rec;
    }

    // -------------------------------------------------------------------------
    // Emit helpers
    // -------------------------------------------------------------------------
    private void emitFunctionRecommendation(PrintWriter w, AiRec rec){
        w.print("\"recommendation\": {");
        w.print("\"action\": " + jsonString(rec.action) + ", ");
        w.print("\"confidence\": " + fmtConf(rec.confidence) + ", ");
        w.print("\"risk_level\": " + jsonString(rec.risk) + ", ");
        w.print("\"risk_if_stubbed\": " + jsonString(rec.riskIfStubbed) + ", ");
        w.print("\"risk_if_recompiled\": " + jsonString(rec.riskIfRecompiled) + ", ");
        w.print("\"reason\": " + jsonString(rec.reason) + ", ");
        w.print("\"evidence_summary\": " + jsonStrArrayCapped(rec.evidence, 8) + ", ");
        w.print("\"derived_from\": " + jsonStrArray(rec.derivedFrom) + ", ");
        w.print("\"suggested_next_step\": " + jsonString(rec.suggestedNextStep) + ", ");
        w.print("\"human_review_needed\": " + rec.humanReview);
        w.print("}");
    }

    private void emitImportantEntry(PrintWriter w, FuncResult r, AiRec rec){
        w.print("{\"address\": \"" + hex(r.address) + "\", \"name\": " + jsonString(r.name) +
            ", \"recommended_action\": " + jsonString(rec.action) +
            ", \"confidence\": " + fmtConf(rec.confidence) +
            ", \"risk_level\": " + jsonString(rec.risk) +
            ", \"reason\": " + jsonString(rec.reason) +
            ", \"evidence_summary\": " + jsonStrArrayCapped(rec.evidence, 6) +
            ", \"derived_from\": " + jsonStrArray(rec.derivedFrom) +
            ", \"suggested_next_step\": " + jsonString(rec.suggestedNextStep) + "}");
    }

    private void emitImportantList(PrintWriter w, String key, List<FuncResult> list,
            Map<Long,AiRec> recs, int cap, boolean trailingComma){
        w.println("    \"" + key + "\": [");
        int n = Math.min(list.size(), cap);
        for(int i = 0; i < n; i++){
            FuncResult r = list.get(i);
            AiRec rec = recs.get(r.address & 0xFFFFFFFFL);
            if(rec == null) rec = new AiRec();
            w.print("      "); emitImportantEntry(w, r, rec);
            boolean more = (i < n-1) || (list.size() > cap);
            w.println(more ? "," : "");
        }
        if(list.size() > cap)
            w.println("      {\"truncated\": true, \"omitted\": " + (list.size()-cap) + "}");
        w.println(trailingComma ? "    ]," : "    ]");
    }

    private void emitTomlSuggestList(PrintWriter w, String key, List<FuncResult> list,
            Map<Long,AiRec> recs, int cap, boolean trailingComma){
        w.println("      \"" + key + "\": [");
        int n = Math.min(list.size(), cap);
        for(int i = 0; i < n; i++){
            FuncResult r = list.get(i);
            AiRec rec = recs.get(r.address & 0xFFFFFFFFL);
            if(rec == null) rec = new AiRec();
            String td = "stub_candidate".equals(rec.action) ? "STUB"
                      : "skip_candidate".equals(rec.action) ? "SKIP" : r.disposition;
            w.print("        {\"address\": \"" + hex(r.address) + "\", \"name\": " + jsonString(r.name) +
                ", \"toml_disposition\": " + jsonString(td) +
                ", \"recommended_action\": " + jsonString(rec.action) +
                ", \"reason\": " + jsonString(rec.reason) + "}");
            boolean more = (i < n-1) || (list.size() > cap);
            w.println(more ? "," : "");
        }
        if(list.size() > cap)
            w.println("        {\"truncated\": true, \"omitted\": " + (list.size()-cap) + "}");
        w.println(trailingComma ? "      ]," : "      ]");
    }

    private void emitFunctionRelationshipSummary(PrintWriter w, FuncResult r, FuncTraits t, AiRec rec,
            Map<Long,String> nameByAddr, Map<Long,String> prefixByAddr,
            Set<Long> importantAddrs, Set<String> importantNames){
        w.print("\"relationship_summary\": {");
        w.print("\"subsystem_guess\": " + jsonString(rec.subsystem) + ", ");
        w.print("\"role_guess\": " + jsonString(rec.role) + ", ");
        // called_by (resolved names, cap 12)
        w.print("\"called_by\": [");
        { int n = 0; boolean f = true;
          for(long[] c : t.callers){ if(n >= 12) break; String cn = nameByAddr.getOrDefault(c[0] & 0xFFFFFFFFL, "");
            if(!f) w.print(", "); f = false; w.print(jsonString(cn)); n++; } }
        w.print("], ");
        // calls (callee names, cap 12)
        w.print("\"calls\": [");
        { int n = 0; boolean f = true;
          for(String cn : t.calleeNames){ if(n >= 12) break; if(!f) w.print(", "); f = false; w.print(jsonString(cn)); n++; } }
        w.print("], ");
        // nearby important functions (callers ∩ important, callees ∩ important-names)
        w.print("\"nearby_important_functions\": [");
        { LinkedHashSet<String> near = new LinkedHashSet<>();
          for(long[] c : t.callers){ long ca = c[0] & 0xFFFFFFFFL;
            if(importantAddrs.contains(ca)){ String cn = nameByAddr.get(ca); if(cn != null && !cn.isEmpty()) near.add(cn); } }
          for(String cn : t.calleeNames){ if(importantNames.contains(cn)) near.add(cn); }
          int n = 0; boolean f = true;
          for(String s : near){ if(n >= 8) break; if(!f) w.print(", "); f = false; w.print(jsonString(s)); n++; } }
        w.print("], ");
        w.print("\"known_chain_membership\": " + jsonStrArray(t.dc2CallChainsTagged) + ", ");
        w.print("\"module_cluster_id\": " + (t.moduleId >= 0 ? Integer.toString(t.moduleId) : "null") + ", ");
        String pfx = prefixByAddr.get(r.address & 0xFFFFFFFFL);
        w.print("\"name_prefix_module\": " + (pfx == null ? "null" : jsonString(pfx)) + ", ");
        w.print("\"chain_to_main_loop_hint\": " + jsonStrArray(mainLoopHints(t)) + ", ");
        w.print("\"chain_to_init_hint\": " + jsonStrArray(initHints(t)) + ", ");
        w.print("\"chain_to_hardware_hint\": " + jsonStrArray(hardwareHints(r, t)) + ", ");
        w.print("\"is_gateway_function\": " + rec.gateway + ", ");
        LinkedHashSet<String> df = new LinkedHashSet<>();
        if(t.moduleId >= 0) df.add("RULE_129_MODULE_CLUSTERS");
        if(pfx != null) df.add("RULE_130_NAME_PREFIX_MODULES");
        if(!t.dc2CallChainsTagged.isEmpty()) df.add("RULE_134_DC2_CALL_CHAINS");
        if(t.mainLoopDepth >= 0) df.add("RULE_39_MAINLOOP_DEPTH");
        if(t.initChainDepth >= 0) df.add("RULE_40_INIT_CHAIN_DEPTH");
        if(t.drawingChainDepth >= 0) df.add("RULE_83_DRAWING_CHAIN_DEPTH");
        df.add("RULE_21_REVERSE_CALLGRAPH");
        w.print("\"derived_from\": " + jsonStrArray(df));
        w.print("}");
    }

    // -------------------------------------------------------------------------
    // Top-level blocks (Parts 1, 3, 5, 6)
    // -------------------------------------------------------------------------
    private void buildDecisionConstraints(PrintWriter w){
        w.println("  \"decision_constraints\": {");
        w.println("    \"schema_version\": \"1.0\",");
        w.println("    \"purpose\": \"Hard guardrails so a downstream AI never makes a destructive recommendation; derived from existing DC2 dangerous-tag rules.\",");
        w.println("    \"never_auto_stub_if_tags\": " + jsonStrArray(Arrays.asList(NEVER_AUTO_STUB_TAGS)) + ",");
        w.println("    \"never_auto_patch_if_tags\": " + jsonStrArray(Arrays.asList(NEVER_AUTO_PATCH_TAGS)) + ",");
        w.println("    \"requires_human_review_if_tags\": " + jsonStrArray(Arrays.asList(REQUIRE_REVIEW_TAGS)) + ",");
        w.println("    \"safe_stub_requires\": " + jsonStrArray(Arrays.asList(SAFE_STUB_REQUIRES)));
        w.println("  },");
    }

    private void buildAiDecisionSupport(PrintWriter w, List<FuncResult> results,
            Map<Long,AiRec> aiRecs, Map<String,List<FuncResult>> subMembers){
        final Map<Long,AiRec> recs = aiRecs;
        int nForce=0,nReview=0,nStub=0,nSkip=0,nNative=0,nPatch=0,nCritical=0,nHigh=0,nHumanReview=0;
        for(FuncResult r : results){
            AiRec rec = recs.get(r.address & 0xFFFFFFFFL); if(rec == null) continue;
            if("force_recompile".equals(rec.action)) nForce++;
            else if("stub_candidate".equals(rec.action)) nStub++;
            else if("skip_candidate".equals(rec.action)) nSkip++;
            else if("native_impl_needed".equals(rec.action)) nNative++;
            else if("patch_candidate".equals(rec.action)) nPatch++;
            else nReview++;
            if("critical".equals(rec.risk)) nCritical++; else if("high".equals(rec.risk)) nHigh++;
            if(rec.humanReview) nHumanReview++;
        }
        Comparator<FuncResult> byRisk = (x,y) -> {
            AiRec rx = recs.get(x.address & 0xFFFFFFFFL), ry = recs.get(y.address & 0xFFFFFFFFL);
            int rr = Integer.compare(riskRank(ry.risk), riskRank(rx.risk)); if(rr != 0) return rr;
            int cc = Double.compare(ry.confidence, rx.confidence); if(cc != 0) return cc;
            return Long.compare(x.address & 0xFFFFFFFFL, y.address & 0xFFFFFFFFL);
        };
        Comparator<FuncResult> byConf = (x,y) -> {
            AiRec rx = recs.get(x.address & 0xFFFFFFFFL), ry = recs.get(y.address & 0xFFFFFFFFL);
            int cc = Double.compare(ry.confidence, rx.confidence); if(cc != 0) return cc;
            int rr = Integer.compare(riskRank(ry.risk), riskRank(rx.risk)); if(rr != 0) return rr;
            return Long.compare(x.address & 0xFFFFFFFFL, y.address & 0xFFFFFFFFL);
        };
        Comparator<FuncResult> byAddrCmp = (x,y) -> Long.compare(x.address & 0xFFFFFFFFL, y.address & 0xFFFFFFFFL);

        List<FuncResult> topRisks=new ArrayList<>(), highConf=new ArrayList<>(), needsReview=new ArrayList<>(),
            safeIgnore=new ArrayList<>(), tomlSafe=new ArrayList<>(), tomlNeeds=new ArrayList<>(), tomlNo=new ArrayList<>();
        for(FuncResult r : results){
            AiRec rec = recs.get(r.address & 0xFFFFFFFFL); if(rec == null) continue;
            FuncTraits t = r.traits;
            boolean noAuto = hasAnyTag(r, NEVER_AUTO_STUB_TAGS) || hasAnyTag(r, NEVER_AUTO_PATCH_TAGS);
            if(riskRank(rec.risk) >= 2) topRisks.add(r);
            if(rec.confidence >= 0.80 && !"review".equals(rec.action)) highConf.add(r);
            if(rec.humanReview && !noAuto) needsReview.add(r);
            if(noAuto) tomlNo.add(r);
            boolean runtimeDead = (t != null && (t.runtimeDormantGlobal || t.runtimeMenuOnly));
            boolean lowSafe = ("skip_candidate".equals(rec.action) || "stub_candidate".equals(rec.action))
                              && "low".equals(rec.risk) && !rec.humanReview;
            if(runtimeDead || lowSafe) safeIgnore.add(r);
            if(("stub_candidate".equals(rec.action) || "skip_candidate".equals(rec.action)) && !rec.humanReview && !noAuto)
                tomlSafe.add(r);
            else if(rec.humanReview && !noAuto && !"review".equals(rec.action))
                tomlNeeds.add(r);
        }
        topRisks.sort(byRisk); highConf.sort(byConf); needsReview.sort(byRisk);
        safeIgnore.sort(byAddrCmp); tomlSafe.sort(byRisk); tomlNeeds.sort(byRisk); tomlNo.sort(byRisk);

        w.println("  \"ai_decision_support\": {");
        w.println("    \"schema_version\": \"1.0\",");
        w.println("    \"purpose\": \"AI-facing summary layer derived from existing triage signals (focus_set, runtime_corroboration, module clusters, DC2 chains, class registry, override coverage). Pointers + rationale, not a copy of the raw JSON.\",");
        w.println("    \"run_summary\": {");
        w.println("      \"total_functions\": " + results.size() + ",");
        w.println("      \"action_force_recompile\": " + nForce + ",");
        w.println("      \"action_review\": " + nReview + ",");
        w.println("      \"action_stub_candidate\": " + nStub + ",");
        w.println("      \"action_skip_candidate\": " + nSkip + ",");
        w.println("      \"action_native_impl_needed\": " + nNative + ",");
        w.println("      \"action_patch_candidate\": " + nPatch + ",");
        w.println("      \"risk_critical\": " + nCritical + ",");
        w.println("      \"risk_high\": " + nHigh + ",");
        w.println("      \"human_review_needed\": " + nHumanReview + ",");
        w.println("      \"runtime_evidence_loaded\": " + (gsEvidence.checkpoints.size() > 0) + ",");
        w.println("      \"focus_set_seed_count\": " + topPriorityFixCount + ",");
        w.println("      \"delta_available\": " + (priorTriageMapCats != null && !priorTriageMapCats.isEmpty()));
        w.println("    },");
        emitImportantList(w, "top_risks", topRisks, recs, 30, true);
        emitImportantList(w, "high_confidence_recommendations", highConf, recs, 30, true);
        emitImportantList(w, "needs_human_review", needsReview, recs, 30, true);
        w.println("    \"safe_to_ignore_for_now\": [");
        { int cap = 30; int n = Math.min(safeIgnore.size(), cap);
          for(int i = 0; i < n; i++){
            FuncResult r = safeIgnore.get(i); AiRec rec = recs.get(r.address & 0xFFFFFFFFL);
            if(rec == null) rec = new AiRec();
            w.print("      {\"address\": \"" + hex(r.address) + "\", \"name\": " + jsonString(r.name) +
                ", \"reason\": " + jsonString(rec.reason) +
                ", \"derived_from\": " + jsonStrArray(rec.derivedFrom) + "}");
            boolean more = (i < n-1) || (safeIgnore.size() > cap); w.println(more ? "," : ""); }
          if(safeIgnore.size() > cap)
            w.println("      {\"truncated\": true, \"omitted\": " + (safeIgnore.size()-cap) + "}"); }
        w.println("    ],");
        w.println("    \"toml_suggestions\": {");
        emitTomlSuggestList(w, "safe_to_apply", tomlSafe, recs, 30, true);
        emitTomlSuggestList(w, "needs_review", tomlNeeds, recs, 30, true);
        emitTomlSuggestList(w, "do_not_apply_automatically", tomlNo, recs, 30, false);
        w.println("    },");
        w.println("    \"next_rule_candidates\": [");
        { List<String> cands = buildNextRuleCandidates(results, recs);
          for(int i = 0; i < cands.size(); i++){ w.print("      " + cands.get(i)); w.println(i < cands.size()-1 ? "," : ""); } }
        w.println("    ]");
        w.println("  },");
    }

    private String ruleCandidate(String pattern, String why, List<String> evidence,
            String name, String confidence, List<Long> examples, List<String> derived){
        StringBuilder sb = new StringBuilder();
        sb.append("{\"pattern\": ").append(jsonString(pattern));
        sb.append(", \"why\": ").append(jsonString(why));
        sb.append(", \"evidence\": ").append(jsonStrArray(evidence));
        sb.append(", \"suggested_rule_name\": ").append(jsonString(name));
        sb.append(", \"confidence\": ").append(jsonString(confidence));
        sb.append(", \"example_functions\": [");
        for(int i = 0; i < examples.size(); i++){ if(i > 0) sb.append(", "); sb.append("\"").append(hex(examples.get(i))).append("\""); }
        sb.append("], \"derived_from\": ").append(jsonStrArray(derived)).append("}");
        return sb.toString();
    }

    /** Next-rule hints — only emitted when there is repeated evidence THIS run. */
    private List<String> buildNextRuleCandidates(List<FuncResult> results, Map<Long,AiRec> aiRecs){
        List<String> out = new ArrayList<>();
        Map<Long,FuncResult> byAddr = new HashMap<>();
        for(FuncResult r : results) byAddr.put(r.address & 0xFFFFFFFFL, r);

        // 1) module clusters dominated by unclassified UNCATEGORIZED functions
        for(Map.Entry<Integer,Set<Long>> e : moduleClusters.entrySet()){
            int unknown = 0; List<Long> ex = new ArrayList<>();
            for(Long ad : e.getValue()){
                FuncResult r = byAddr.get(ad & 0xFFFFFFFFL); if(r == null || r.traits == null) continue;
                AiRec rec = aiRecs.get(ad & 0xFFFFFFFFL);
                boolean unk = (rec == null || "unknown".equals(rec.subsystem)) && "UNCATEGORIZED".equals(r.category);
                if(unk){ unknown++; if(ex.size() < 5) ex.add(r.address & 0xFFFFFFFFL); }
            }
            if(unknown >= 5)
                out.add(ruleCandidate(
                    "module cluster mod_" + e.getKey() + " has " + unknown + " unclassified UNCATEGORIZED functions",
                    "A tight call-graph cluster with many unknown functions usually shares one subsystem; a cluster-scoped rule could classify them together.",
                    Arrays.asList(unknown + " unknown UNCATEGORIZED in mod_" + e.getKey(), "cluster size " + e.getValue().size()),
                    "DC2_MODULE_CLUSTER_" + e.getKey() + "_CLASSIFIER", "medium", ex,
                    Arrays.asList("RULE_129_MODULE_CLUSTERS")));
        }
        // 2) UNCATEGORIZED functions sitting on a known DC2 chain
        { int c = 0; List<Long> ex = new ArrayList<>();
          for(FuncResult r : results){ FuncTraits t = r.traits; if(t == null) continue;
            if(!t.dc2CallChainsTagged.isEmpty() && "UNCATEGORIZED".equals(r.category)){ c++; if(ex.size() < 5) ex.add(r.address & 0xFFFFFFFFL); } }
          if(c >= 3) out.add(ruleCandidate(
            c + " UNCATEGORIZED functions are tagged into a known DC2 call chain",
            "Functions on a known chain but still UNCATEGORIZED are prime candidates for a chain-station-specific rule.",
            Arrays.asList(c + " chain-tagged UNCATEGORIZED"),
            "DC2_CHAIN_STATION_CLASSIFIER", "medium", ex,
            Arrays.asList("RULE_134_DC2_CALL_CHAINS"))); }
        // 3) archive-string references with no recognized loader
        { int c = 0; List<Long> ex = new ArrayList<>();
          for(FuncResult r : results){ FuncTraits t = r.traits; if(t == null) continue;
            if(t.refsArchiveStrings && !t.callsFileOpen && "UNCATEGORIZED".equals(r.category)){ c++; if(ex.size() < 5) ex.add(r.address & 0xFFFFFFFFL); } }
          if(c >= 3) out.add(ruleCandidate(
            c + " functions reference archive strings but call no known file-open API",
            "Repeated archive-string references without a recognized loader suggest a custom/inlined archive reader worth its own rule.",
            Arrays.asList(c + " archive-string refs w/o file-open"),
            "DC2_INLINE_ARCHIVE_READER", "medium", ex,
            Arrays.asList("RULE_23_ARCHIVE_IO", "RULE_99_FILE_PATH_SPRINTF"))); }
        // 4) BITBLTBUF writers not covered by an existing uploader rule
        { int c = 0; List<Long> ex = new ArrayList<>();
          for(FuncResult r : results){ FuncTraits t = r.traits; if(t == null) continue;
            if(t.writesBitbltbufReg && !t.isBitbltbufT4hhUploader && !t.bitbltbufMacroSequence && !t.isPsmct16ClutUploader){ c++; if(ex.size() < 5) ex.add(r.address & 0xFFFFFFFFL); } }
          if(c >= 3) out.add(ruleCandidate(
            c + " BITBLTBUF writers are matched by no specific uploader rule",
            "Uncovered BITBLTBUF writers may be a new texture/CLUT upload shape (cf. F50.8-F50.11 PSMCT16 gap).",
            Arrays.asList(c + " uncovered BITBLTBUF writers"),
            "DC2_UNCOVERED_BITBLTBUF_UPLOADER", "high", ex,
            Arrays.asList("RULE_85_BITBLTBUF_T4HH", "RULE_145_PSMCT16_CLUT"))); }
        // 5) virtual-dispatch sites with no resolved class
        { int c = 0; List<Long> ex = new ArrayList<>();
          for(FuncResult r : results){ FuncTraits t = r.traits; if(t == null) continue;
            if(!t.virtualDispatchSites.isEmpty() && t.methodClassName == null && t.ctorClassName == null){ c++; if(ex.size() < 5) ex.add(r.address & 0xFFFFFFFFL); } }
          if(c >= 3) out.add(ruleCandidate(
            c + " functions have virtual-dispatch sites but no resolved class",
            "Indirect dispatch targets not yet assigned to a class are unresolved vtable risk; a class-resolution rule would help.",
            Arrays.asList(c + " virtual-dispatch funcs w/o class"),
            "DC2_UNRESOLVED_VTABLE_CLASS", "medium", ex,
            Arrays.asList("RULE_94_VIRTUAL_DISPATCH", "RULE_128_TABLE_DISPATCH"))); }
        // 6) complex control flow that landed in subsystem=unknown
        { int c = 0; List<Long> ex = new ArrayList<>();
          for(FuncResult r : results){ AiRec rec = aiRecs.get(r.address & 0xFFFFFFFFL);
            if(rec != null && "unknown".equals(rec.subsystem) && r.tags.contains("COMPLEX_CONTROL_FLOW")){ c++; if(ex.size() < 5) ex.add(r.address & 0xFFFFFFFFL); } }
          if(c >= 4) out.add(ruleCandidate(
            c + " COMPLEX_CONTROL_FLOW functions remain in subsystem=unknown",
            "Many unclassified jump-table / complex functions share a pattern no current subsystem rule captures.",
            Arrays.asList(c + " unknown COMPLEX_CONTROL_FLOW"),
            "DC2_COMPLEX_FLOW_SUBSYSTEM_HINT", "low", ex,
            Arrays.asList("RULE_146_COMPUTED_JUMP"))); }
        return out;
    }

    private List<String> subsystemEvidence(String key, List<FuncResult> mem){
        List<String> e = new ArrayList<>();
        e.add(mem.size() + " functions");
        int conf = 0, dormant = 0;
        for(FuncResult r : mem){ FuncTraits t = r.traits; if(t == null) continue;
            if(t.runtimeConfirmed) conf++; if(t.runtimeDormantGlobal) dormant++; }
        if(conf > 0) e.add(conf + " runtime-confirmed");
        if(dormant > 0) e.add(dormant + " runtime-dormant");
        return e;
    }

    private List<String> subsystemDerivedFrom(String key){
        switch(key){
            case "render":           return Arrays.asList("RULE_44_PATH3","RULE_83_DRAWING_CHAIN_DEPTH","RULE_61_GIF_PATH3","RULE_134_DC2_CALL_CHAINS");
            case "texture_upload":   return Arrays.asList("RULE_85_BITBLTBUF_T4HH","RULE_103_ASSET_UPLOAD_TRACES","RULE_145_PSMCT16_CLUT","RULE_132_DC2_TBP_LABELS");
            case "archive_io":       return Arrays.asList("RULE_23_ARCHIVE_IO","RULE_99_FILE_PATH_SPRINTF");
            case "input":            return Arrays.asList("RULE_24_PAD_POLL","RULE_97_PAD_MASK","RULE_135_DC2_PAD_INPUT");
            case "audio":            return Arrays.asList("RULE_52_AUDIO_RPC","RULE_22_IOP_RPC");
            case "memory_card":      return Arrays.asList("RULE_54_MC_GATE");
            case "iop_rpc":          return Arrays.asList("RULE_22_IOP_RPC","RULE_124_IRX_LOADER","RULE_139_DISCOVERED_SIDS");
            case "main_loop":        return Arrays.asList("RULE_11_MAINLOOP_SHIELD","RULE_39_MAINLOOP_DEPTH","RULE_100_FRAME_CLOCK_DRIVER");
            case "init":             return Arrays.asList("RULE_40_INIT_CHAIN_DEPTH","RULE_141_STATIC_INIT");
            case "class_ctor_vtable":return Arrays.asList("RULE_93_CLASS_REGISTRY","RULE_94_VIRTUAL_DISPATCH","RULE_82_CTOR_MULTI_FIELD");
            default:                 return Arrays.asList("RULE_129_MODULE_CLUSTERS","RULE_130_NAME_PREFIX_MODULES");
        }
    }

    private void buildAiRelationshipView(PrintWriter w, List<FuncResult> results,
            Map<Long,AiRec> aiRecs, Map<String,List<FuncResult>> subMembers,
            Set<Long> importantAddrs, Set<String> importantNames, Map<Long,String> prefixByAddr){
        final Map<Long,AiRec> recs = aiRecs;
        Map<Long,String> nameByAddr = new HashMap<>();
        for(FuncResult r : results) nameByAddr.put(r.address & 0xFFFFFFFFL, r.name);

        w.println("  \"ai_relationship_view\": {");
        w.println("    \"schema_version\": \"1.0\",");
        w.println("    \"purpose\": \"AI-facing abstraction over existing callgraph, module, chain, class, and runtime evidence. Not a second source of truth.\",");
        w.println("    \"subsystems\": {");
        for(int si = 0; si < SUBSYSTEM_KEYS.length; si++){
            String key = SUBSYSTEM_KEYS[si];
            List<FuncResult> mem = subMembers.get(key);
            mem.sort((x,y) -> {
                AiRec rx = recs.get(x.address & 0xFFFFFFFFL), ry = recs.get(y.address & 0xFFFFFFFFL);
                int rr = Integer.compare(riskRank(ry.risk), riskRank(rx.risk)); if(rr != 0) return rr;
                long sc = scoreFocus(y.traits) - scoreFocus(x.traits); if(sc != 0) return sc > 0 ? 1 : -1;
                return Long.compare(x.address & 0xFFFFFFFFL, y.address & 0xFFFFFFFFL);
            });
            int maxRisk = 0, gw = 0;
            for(FuncResult r : mem){ AiRec rec = recs.get(r.address & 0xFFFFFFFFL);
                maxRisk = Math.max(maxRisk, riskRank(rec.risk)); if(rec.gateway) gw++; }
            String riskLevel = maxRisk == 3 ? "critical" : maxRisk == 2 ? "high" : maxRisk == 1 ? "medium" : "low";
            w.print("      " + jsonString(key) + ": {");
            w.print("\"key_functions\": [");
            { int n = Math.min(mem.size(), 12);
              for(int i = 0; i < n; i++){ FuncResult r = mem.get(i); AiRec rec = recs.get(r.address & 0xFFFFFFFFL);
                if(i > 0) w.print(", ");
                w.print("{\"address\": \"" + hex(r.address) + "\", \"name\": " + jsonString(r.name) +
                    ", \"role\": " + jsonString(rec.role) + ", \"risk_level\": " + jsonString(rec.risk) + "}"); } }
            w.print("], ");
            w.print("\"gateway_functions\": [");
            { int n = 0; boolean f = true;
              for(FuncResult r : mem){ AiRec rec = recs.get(r.address & 0xFFFFFFFFL); if(!rec.gateway) continue;
                if(n >= 12) break; if(!f) w.print(", "); f = false;
                w.print("{\"address\": \"" + hex(r.address) + "\", \"name\": " + jsonString(r.name) + "}"); n++; } }
            w.print("], ");
            w.print("\"risk_level\": " + jsonString(riskLevel) + ", ");
            w.print("\"member_count\": " + mem.size() + ", ");
            w.print("\"gateway_count\": " + gw + ", ");
            w.print("\"evidence_summary\": " + jsonStrArray(subsystemEvidence(key, mem)) + ", ");
            w.print("\"derived_from\": " + jsonStrArray(subsystemDerivedFrom(key)));
            w.print("}");
            w.println(si < SUBSYSTEM_KEYS.length-1 ? "," : "");
        }
        w.println("    },");

        // important_edges: caller->callee among the "important" node set (bounded).
        w.println("    \"important_edges\": [");
        { List<String> edges = new ArrayList<>();
          for(FuncResult r : results){ long ra = r.address & 0xFFFFFFFFL; if(!importantAddrs.contains(ra)) continue;
            FuncTraits t = r.traits; if(t == null) continue;
            for(long[] c : t.callers){ long ca = c[0] & 0xFFFFFFFFL;
              if(importantAddrs.contains(ca))
                edges.add("{\"from\": \"" + hex(ca) + "\", \"from_name\": " + jsonString(nameByAddr.getOrDefault(ca, "")) +
                    ", \"to\": \"" + hex(ra) + "\", \"to_name\": " + jsonString(r.name) + "}"); } }
          int cap = 80; int n = Math.min(edges.size(), cap);
          for(int i = 0; i < n; i++){ w.print("      " + edges.get(i));
            boolean more = (i < n-1) || (edges.size() > cap); w.println(more ? "," : ""); }
          if(edges.size() > cap) w.println("      {\"truncated\": true, \"omitted\": " + (edges.size()-cap) + "}"); }
        w.println("    ],");

        // hardware_paths: render + texture members ordered by distance from render root.
        w.println("    \"hardware_paths\": [");
        { List<FuncResult> hw = new ArrayList<>();
          hw.addAll(subMembers.get("render")); hw.addAll(subMembers.get("texture_upload"));
          hw.sort((x,y) -> {
            int dx = (x.traits != null && x.traits.drawingChainDepth >= 0) ? x.traits.drawingChainDepth : Integer.MAX_VALUE;
            int dy = (y.traits != null && y.traits.drawingChainDepth >= 0) ? y.traits.drawingChainDepth : Integer.MAX_VALUE;
            if(dx != dy) return Integer.compare(dx, dy);
            return Long.compare(x.address & 0xFFFFFFFFL, y.address & 0xFFFFFFFFL); });
          int cap = 40; int n = Math.min(hw.size(), cap);
          for(int i = 0; i < n; i++){ FuncResult r = hw.get(i); AiRec rec = recs.get(r.address & 0xFFFFFFFFL);
            int d = (r.traits != null) ? r.traits.drawingChainDepth : -1;
            w.print("      {\"address\": \"" + hex(r.address) + "\", \"name\": " + jsonString(r.name) +
                ", \"drawing_chain_depth\": " + d + ", \"role\": " + jsonString(rec.role) + "}");
            boolean more = (i < n-1) || (hw.size() > cap); w.println(more ? "," : ""); }
          if(hw.size() > cap) w.println("      {\"truncated\": true, \"omitted\": " + (hw.size()-cap) + "}"); }
        w.println("    ],");

        // main_loop_paths: anything with a known main-loop depth, nearest first.
        w.println("    \"main_loop_paths\": [");
        { List<FuncResult> ml = new ArrayList<>();
          for(FuncResult r : results) if(r.traits != null && r.traits.mainLoopDepth >= 0) ml.add(r);
          ml.sort((x,y) -> { int c = Integer.compare(x.traits.mainLoopDepth, y.traits.mainLoopDepth);
            return c != 0 ? c : Long.compare(x.address & 0xFFFFFFFFL, y.address & 0xFFFFFFFFL); });
          int cap = 40; int n = Math.min(ml.size(), cap);
          for(int i = 0; i < n; i++){ FuncResult r = ml.get(i); AiRec rec = recs.get(r.address & 0xFFFFFFFFL);
            w.print("      {\"address\": \"" + hex(r.address) + "\", \"name\": " + jsonString(r.name) +
                ", \"mainloop_depth\": " + r.traits.mainLoopDepth + ", \"role\": " + jsonString(rec.role) + "}");
            boolean more = (i < n-1) || (ml.size() > cap); w.println(more ? "," : ""); }
          if(ml.size() > cap) w.println("      {\"truncated\": true, \"omitted\": " + (ml.size()-cap) + "}"); }
        w.println("    ],");

        // init_paths: anything with a known init-chain depth, nearest first.
        w.println("    \"init_paths\": [");
        { List<FuncResult> ip = new ArrayList<>();
          for(FuncResult r : results) if(r.traits != null && r.traits.initChainDepth >= 0) ip.add(r);
          ip.sort((x,y) -> { int c = Integer.compare(x.traits.initChainDepth, y.traits.initChainDepth);
            return c != 0 ? c : Long.compare(x.address & 0xFFFFFFFFL, y.address & 0xFFFFFFFFL); });
          int cap = 40; int n = Math.min(ip.size(), cap);
          for(int i = 0; i < n; i++){ FuncResult r = ip.get(i); AiRec rec = recs.get(r.address & 0xFFFFFFFFL);
            w.print("      {\"address\": \"" + hex(r.address) + "\", \"name\": " + jsonString(r.name) +
                ", \"init_chain_depth\": " + r.traits.initChainDepth + ", \"role\": " + jsonString(rec.role) + "}");
            boolean more = (i < n-1) || (ip.size() > cap); w.println(more ? "," : ""); }
          if(ip.size() > cap) w.println("      {\"truncated\": true, \"omitted\": " + (ip.size()-cap) + "}"); }
        w.println("    ],");

        // known_dc2_chains: reuse the pre-computed DC2_CALL_CHAINS + tagged members.
        w.println("    \"known_dc2_chains\": [");
        for(int ci = 0; ci < DC2_CALL_CHAINS.length; ci++){
            Object[] row = DC2_CALL_CHAINS[ci];
            String tag = (String)row[0]; String[] stations = (String[])row[1];
            String chainTag = "DC2_CHAIN_" + tag.toUpperCase();
            List<Long> tagged = new ArrayList<>();
            for(FuncResult r : results){ if(r.tags.contains(chainTag) && tagged.size() < 20) tagged.add(r.address & 0xFFFFFFFFL); }
            w.print("      {\"tag\": " + jsonString(tag) + ", \"stations\": [");
            for(int j = 0; j < stations.length; j++){ if(j > 0) w.print(", "); w.print(jsonString(stations[j])); }
            w.print("], \"tagged_functions\": [");
            for(int j = 0; j < tagged.size(); j++){ if(j > 0) w.print(", "); w.print("\"" + hex(tagged.get(j)) + "\""); }
            w.print("]}");
            w.println(ci < DC2_CALL_CHAINS.length-1 ? "," : "");
        }
        w.println("    ]");
        w.println("  },");
    }

    class FuncResult{long address;String name,category,disposition;FuncTraits traits;List<String>tags;
        // v11 (General v15): provenance. origin: "auto" (enricher decision),
        // "step1" (inherited from DAC.toml, vetted), "override" (bound in
        // dc2_game_override.cpp). step1Disposition/rescueReason only for step1.
        String origin="auto";String step1Disposition=null;String rescueReason=null;
        // which pass rescued the step1 binding (step1_keep_gate /
        // drawing_chain_firewall / v8_ctor_risk / v8_scevu0_helper /
        // v13_binding_firewall / dynamic_code_loader_firewall).
        String rescuedBy=null;
        // v11.1: for origin="step1", whether the entry came from the step1
        // exporter ("exporter") or a previous enricher run ("enricher_prev").
        String step1Source=null;
        // v14: captured listing text for the per-function Markdown docs
        // (functions/<addr>_<name>.md). Streamed once during the scan.
        String asmText=null, decompText=null, flowText=null;}
    private static String hex(long v){return String.format("0x%08X",v&0xFFFFFFFFL);}
    private static String jsonString(String v){
        if(v==null)return "\"\"";
        // v11 (General v15.5 Bugfix S): full RFC 8259 escaping. Symbol names
        // scraped from arbitrary ELFs can carry control bytes; bare emission
        // produced invalid JSON.
        StringBuilder sb = new StringBuilder(v.length()+8);
        sb.append('"');
        for(int i=0;i<v.length();i++){
            char c = v.charAt(i);
            switch(c){
                case '\\': sb.append("\\\\"); break;
                case '"':  sb.append("\\\""); break;
                case '\n': sb.append("\\n");  break;
                case '\r': sb.append("\\r");  break;
                case '\t': sb.append("\\t");  break;
                default:
                    if(c < 0x20) sb.append(String.format("\\u%04x",(int)c));
                    else sb.append(c);
            }
        }
        return sb.append('"').toString();
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

