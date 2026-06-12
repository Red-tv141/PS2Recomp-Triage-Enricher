// PS2Recomp Triage Enricher v15.5 - Ghidra Script (Step 2 of Pipeline)
//
// WHAT'S NEW IN v15.5 (Jak 1/2/3 tri-game benchmark retrospective):
//   Bugfix R  class_registry trailing comma     On stripped binaries (empty
//             registry, Jak3) the unconditional comma after "_note" made the
//             whole triage_map.json INVALID JSON. Comma now prefixes entries.
//   Bugfix S  UTF-8 everywhere                  All readers/writers were
//             platform-default charset; on Windows (cp125x) every em dash in
//             an emitted string became mojibake/U+FFFD inside the JSON.
//             utf8Writer()/utf8Reader() + the source itself is pure ASCII +
//             jsonString() now escapes all control chars per RFC 8259.
//             schema_version bumped to 12.3.
//   Rule 159  SYSCALL_TRAMPOLINE policy         A <=32-byte 0-call body with
//             a syscall is the kernel boundary itself:
//              - the old auto-SKIP compiled to a TODO_NAMED placeholder that
//                returns -1, silently losing live kernel calls (Jak3
//                GetThreadId, Jak1/2 alarm helpers setup/Copy/GetEntryAddress);
//              - the old whitelist ("handler"/"callback" substring) and the
//                PROCESS_TERMINATOR/allocator trait firewalls blocked or
//                mis-rescued trampolines (_exit "trait firewall" reason; Jak3
//                AddIntcHandler left unbound).
//             New order: trampoline shape decided FIRST. STUB when the
//             runtime roster implements the handler by name AND the name is
//             a known boundary family; SKIP only when xref count is 0 (dead
//             bootstrap); otherwise RECOMPILE - the recompiler translates
//             `syscall` to runtime->handleSyscall() ($v1/numeric dispatch),
//             which is always semantically correct. Same ordering applied in
//             the step1 keep gate with an accurate rescue reason. New tag
//             SYSCALL_TRAMPOLINE + "syscall_trampolines" statistic.
//   Bugfix T  Single-line TOML arrays           `stubs = ["a@0x1"]` /
//             `skip = []` inline arrays were silently dropped by both the
//             step1 parser and the unified-config rewriter (entries lost,
//             array state leaked onto following lines). Both now expand or
//             consume inline arrays; missing arrays are created under
//             [general] when the enricher has additions to place.
//   Bugfix U  Rule 78 TBP noise gate            tbp_constants_loaded had
//             collected EVERY immediate in (0,0x3FFF] from every function
//             (16-byte trampolines "loaded TBP constants"). The list is now
//             emitted only for functions with GS-side static evidence or a
//             runtime-confirmed TBP match.
//   Rule 160  STRIPPED TRAMPOLINE NAME RECOVERY  The syscall immediate
//             decoded from a trampoline body is ground truth; when
//             EE_SYSCALL_NAMES[N] names a handler the runtime roster
//             implements, the ADDRESS is bound via the recompiler's
//             documented "Handler@0xADDR" stub selector - recovers correct
//             stubs on stripped ELFs (FUN_*/RFU* symbols).
//   Bugfix V  detectSyscallTrampoline $v1 override  A spurious scalar in the
//             syscall instruction's input objects overwrote the $v1 constant:
//             on Jak1, li v1,0x74/0x5a/0x5b ALL reported imm 0x02/"SetGsCrt".
//             $v1 now always wins; the encoded code field is only a fallback.
//   Bugfix W  EE_SYSCALL_NAMES rebuilt against pcsx2 R5900OpcodeImpl.cpp +
//             ps2xRuntime Dispatcher.cpp. Old map had 0x66/0x67 as
//             GsGetIMR/GsPutIMR (really CpuConfig/iGetCop0), 0x68 as
//             SetVSyncFlag (really iFlushCache; SetVSyncFlag=0x73), 0x73 as
//             SetSyscall (really 0x74). Names now use the runtime's spelling
//             so Rule 160 roster lookups succeed; contested numbers
//             (0x5A/0x5B) omitted; negative-encoded i-variants added.
//   Rule 161  DYNAMIC_CODE_LOADER               Calls FlushCache/iFlushCache/
//             CacheFlush AND reads files/archives in the same body - the
//             "read code from disc, flush I-cache, execute" overlay/linker
//             idiom (Jak klink). Never stubbed (firewalled); statistic
//             "dynamic_code_loaders" > 0 warns that the ELF loads EE code at
//             runtime, so recompiling the ELF alone cannot cover the game.
//   Plus      BIOS_FIREWALL_PREFIXES extended with kernel wrappers observed
//             unmatched on the Jak ELFs (GetThreadId, TerminateThread,
//             ExitDeleteThread, SetVTLBRefillHandler, SetVCommonHandler,
//             SetVInterruptHandler, AddSbusIntcHandler, DelayThread, ...).
//
// Pre-v15.5 history retained below for archival reference.
// ==================================================================
// PS2Recomp Triage Enricher v11 - Ghidra Script (Step 2 of Pipeline)
//
// WHAT'S NEW IN v11 (FF1 Himuro retrospective + cross-game bug sweep):
//   Bugfix A  Broken A+D reg detection            Removed MMIO-offset==RegID
//             match (was misreading PMODE@0x12000000 as PRIM A+D reg 0x00).
//             Replaced with detectAdRegImmediateStores() which scans qword
//             A+D-mode payload-imm pairs and sets writesGsPrimReg/Tex0/Rgbaq/
//             Zbuf/DispfbReg/BitbltbufReg via real payload evidence.
//   Bugfix B  VIF_OPCODE_BUILDER NOP flood        Guard highByte=0 (matches VIF
//             NOP). On FF1 dropped 2361 false positives to a small precise set.
//   Bugfix C  MainLoop autodetect missed bare main + low-callee mainloops.
//             Added "main" to mlNames. Relaxed behavioral fallback: callees>=6
//             OR (callees>=4 AND isFrameClockDriver). Frame-clock bonus *=4.
//   Rule  D  RPC SID/FID extraction extended to lui+ori composite into $a1
//             before sceSifBindRpc (SID) and sceSifCallRpc (FID). Captures
//             raw immediates independent of KNOWN_IOP_SIDS whitelist.
//   Rule  E  Peripheral reg ranges expanded per PCSX2 EEMemoryMap: RCNT0-3
//             (timers), VIF0/VIF1 CONTROL block (distinct from VIF DMA chan),
//             DMAC global block (CTRL/STAT/PCR/...), INTC_STAT/MASK, SIO,
//             DMAC ext (D_ENABLEW/R), SBUS_MSFLG/SMFLG. New tags:
//             RCNT_ACCESS, VIF_CONTROL_REG, DMAC_GLOBAL_REG, WRITES_INTC_MASK,
//             READS_INTC_STAT, SIO_ACCESS, WRITES_DMAC_ENABLE,
//             SBUS_FLAG_TOUCHER.
//   Rule  F  DMA_SOURCE_CHAIN_TAG_BUILDER         2-store qword pattern with
//             tag-id high nibble (REF/CNT/CALL/RET/END/REFS/NEXT) at +0.
//             Catches the canonical `size | 0x30000000` PS2 idiom.
//   Rule  G  Cross-instruction const tracker hoisted into a dedicated helper
//             (used by F and the existing R1/R4 GIF builders).
//   Rule  H  FORMAT_MAGIC_PARSER                  Catches TIM2/CLT2/ELF/PSS/
//             SW01/imp2 magics in const_loads.
//   Rule  I  IRX_LOADER (>=2 sceSifLoadModule calls) + IOP_REBOOT_HANDLER
//             (sceSifRebootIop callee). Captures inline IRX paths.
//   Rule  J  BACKWARD_BRANCH_SYNC_WAIT            backward branch + Sync/Stat
//             callee. INFINITE_FAIL_LOOP for the `while(1){}` after
//             sceSif*Bind/Reboot/Sync/Load error idiom.
//   Rule  K  name_prefix_modules                  Secondary subsystem index
//             - prefixes occurring >=5 times across the binary (Scene*, Mc*,
//             scePad*, Tim2*, Movie*, Sg*, sce*). Complements call-graph
//             clustering on symbol-rich (non-stripped) builds.
//   Rule  L  Function-pointer-table edges feed BFS forward adjacency before
//             mainloop/init-chain depth computation. Recovers depth on
//             switch-dispatched callees that direct-jal BFS missed.
//   Polish M  runtime_corroboration block omitted when no GS dumps loaded.
//   Polish N  Trailing tag comments preserved on nop/patch/force_recompile
//             TOML emit so engineers see WHY without cross-checking JSON.
//   Polish P  literal_refs JSON array capped at 32 + truncated flag.
//   Polish Q  Header doc rewritten (was stuck on "v9 Rules 1-17").
//
// Pre-v11 history retained below for archival reference.
// ==================================================================
// PS2Recomp Triage Enricher v9 - Ghidra Script (Step 2 of Pipeline)
// ==================================================================
// Run AFTER ExportPS2Functions.java on the same Ghidra project.
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
//   Rule 29 A0_PASSTHROUGH_RETURNER move $v0,$a0/$a1 - auto-stub returning 0 breaks chains
//   Rule 30 PROCESS_TERMINATOR      _Exit/abort/TerminateLibrary - never nop_stub
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
//   Rule 42 jalSites dedup          Set semantics on (callSitePc,target) - fixes 3-count anomaly
//   Plus:   known_gs_registers map + extended IOP module string list
//
// WHAT'S NEW IN v5 (community gap closure + DC2 next-step bullseye):
//   Rule 43 IS_SCE_GIF_PK_REF_LOAD_IMAGE  Bullseye for the 4HH/Path3 guard
//   Rule 44 PATH3_INITIATOR        Writes to GIF CHCR (0x1000A000) - Path3 starters
//   Rule 45 SCE_GIF_PK_FAMILY      sceGifPk*/sceVif1Pk* roster
//   Rule 46 TEX0_REG_WRITER        GS reg 0x06/0x07 writers (TEX state corruption hunt)
//   Rule 47 PRIM_REG_READER        Reads GS reg 0x00 (PRIM corruption witnesses)
//   Rule 48 RGBAQ_WRITER           Writes GS reg 0x01 (vertex color setters)
//   Rule 49 DMA_KICK_PATTERN       Writes any DMA channel CHCR base (+0x00)
//   Rule 50 DMA_QWC_TADR_WRITER    Writes any DMA channel +0x20 (QWC) / +0x30 (TADR)
//   Rule 51 MICROCODE_UPLOADER     VIF1 MMIO + load from .text/.data (MPG payload)
//   Rule 52 AUDIO_RPC_HANDLER      sceSd*/sceSpu2*/libsd.irx audio path
//   Rule 53 MESWIN_LOADER          Refs string "meswin" - dialogue rendering pipeline
//   Rule 54 MC_TRANSITION_GATE     *ForMC/*McCheck*/*McError* small gates (FinishForMC pattern)
//   Rule 55 known_dc2_globals      JSON map of known DC2 gp-relative offsets
//   Rule 56 is_top_priority_fix    Derived: any community-bullseye tag is set
//   Rule 57 focus_set              Top-level array of every top-priority function
//
// WHAT'S NEW IN v6 (PCSX2 source-grounded):
//   Rule 58 CORRECTED GS privileged MMIO map (0x12000070=DISPFB1, 0x12000090=DISPFB2, ...)
//   Rule 59 ACCESSES_IPU_MMIO      0x10002000-0x10003000 - MPEG decoder hardware
//   Rule 60 WRITES_IPU_CMD         0x10002000 - the MPEG kick (sub-MPEG_DECODER_TRAP)
//   Rule 61 GIF_PATH3_REG_TOUCHER  GIF_P3CNT (0x10003090) or GIF_P3TAG (0x100030A0)
//   Rule 62 GIF_FIFO_DIRECT_WRITER 0x10006000 - bypass-DMA GIF write
//   Rule 63 VIF1_FIFO_DIRECT_WRITER 0x10005000 - bypass-DMA VIF1 write
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
//                                   - picks up SDK-routed DISPFB writers that
//                                   the raw-MMIO Rule 35/58 misses.
//   Rule 76 PATH3_KICK_VIA_DMA_API  Caller of sceDmaSend*/sceGifSendChain*/
//                                   sceGsSwapDBuff/sceGsExecStoreImage - the
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
//                                   masking GS IRQs -> tag as safe-stub
//                                   candidate (decoration; no auto disposition flip).
//   Rule 80 runtime_corroboration   Per-function block cross-checking
//                                   static bullseye predictions against the
//                                   merged runtime evidence. Adds tags:
//                                   RUNTIME_CONFIRMED         - at least one
//                                       bullseye prediction has a witness.
//                                   RUNTIME_DORMANT_GLOBAL    - bullseye
//                                       predictions but zero runtime witness
//                                       across loaded checkpoints.
//                                   RUNTIME_MENU_ONLY         - PSMT4HH_REFERENCE
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
//          __ct__11mgCDrawPrimFv nop-stubbed -> manager/PRIM/Q/Z slots all
//          garbage -> entire Begin/Texture/Color chain dead. Firewalled
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
//   Plus: RUNTIME_MENU_ONLY refinement - skip the tag when the function is
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
//  ===== v15 (FF1 / Himuro-benchmark corrections) =====
//  Benchmarked against Fatal Frame 1 (SLUS_203.88) with the Himuro decomp
//  project as ground truth. The input toml (name-policy exporter) had:
//    - stubbed memcpy/strcpy/sprintf/atoi/rand (pure libc compute),
//    - stubbed the whole mc* memory-card UI + Scene*/Pad*/Dma*/str* game
//      code ("Scene" had name-collided with the "sce" SDK prefix),
//    - stubbed sceVu0*/sceRotMatrixXYZ VU0-macro math (broken camera/anim),
//    - SKIPPED __ieee754_*/__kernel_*/libgcc int64+softfloat/newlib stdio
//      internals and __do_global_ctors (broken math, dead static init).
//  The old Rule 9 inherited all 651 entries blindly and excluded them from
//  the JSON. v15 changes (all game-agnostic):
//    1. Step1 stub/skip entries are fully analyzed, included in the JSON
//       (origin="step1"), and must pass a high-confidence keep gate
//       (step1KeepGateFailure): a STUB survives only with host-boundary
//       evidence (syscall / SIF RPC / IRX load / IPU-MPEG / SDK-named tiny
//       MMIO thunk); a SKIP only as a bare syscall trampoline or
//       unreachable bootstrap. Everything else is rescued to RECOMPILE:
//       the entry is REMOVED from the unified TOML (which stays the
//       executable safe subset) and documented in the triage JSON's
//       "rescued_from_step1" ledger (entry / from_section / new_decision /
//       reason / evidence / derived_from) - v15.1 split: TOML executes,
//       JSON explains.
//    2. RADAR name matching rebuilt: exact-name set + word-boundary prefix
//       families (matchesFamilyPrefix). The old bare startsWith() stubbed
//       `exponent` via prefix "exp" and would hit tangent/logo_*/power_*.
//       Pure-computation names (mem*/str*/math/malloc/_Z mangled C++/
//       static-init sections/__cxa_*) removed from stub candidacy: for pure
//       EE code, RECOMPILE is always correct; a stub is only correct if the
//       runtime services it.
//    3. A radar stub now requires name match AND trait corroboration
//       (hasHostBoundaryEvidence / hasWeakSdkThunkEvidence).
//    4. v13 firewall: SIF-RPC gateways excluded from init-chain-only rescue
//       (they sit on init chains by construction, like syscall wrappers);
//       step1 bindings kept on HARD evidence are only unwound by
//       address-taken / dispatch-table conflicts (sent to review).
//    5. Override-bound functions included in JSON (origin="override",
//       disposition=OVERRIDE), never emitted into advisory arrays.
//    6. JSON schema 12.2: per-function origin / step1_disposition /
//       step1_rescue_reason; statistics step1_inherited_kept /
//       step1_rescued_to_recompile / override_bound.
//
//  ===== v15.2 (output-surface split + input hygiene) =====
//    7. EMIT_VERBOSE_TOML_ADVISORY (default false): the TOML now carries
//       ONLY [general] / active stubs / active skip / [patches] plus a
//       short pointer comment. The full advisory content (nop, patch,
//       force_recompile, native_impl_needed, review, patch-instruction
//       candidates) is emitted into triage_map.json "triage_advisory" as
//       structured {entry, tags} objects. TOML executes, JSON explains.
//    8. Rule 151 STEP1_NAME_MISMATCH: a step1 "name@addr" entry whose name
//       differs from the real ELF symbol at that address (and the symbol is
//       not a FUN_/sub_ default) marks a stale or wrong-region input toml
//       (US vs EU/JP address drift). Binding a handler to the wrong
//       function is the worst failure mode -> forced RECOMPILE + review.
//    9. Rule 152 dual-binding hygiene: an entry listed in BOTH stubs and
//       skip is an input bug - kept as stub, dropped from skip, warned.
//
//  ===== v15.3 (Rules 153-158) =====
//   10. Rule 153 RUNTIME-HANDLER ROSTER (optional): user may select a
//       ps2xRuntime checkout; handler names are scraped from src/ (handler
//       defs taking R5900Context, raw rdram wrappers, bindAddressHandler
//       string bindings, ps2_stubs:: refs; runner/ and build dirs never
//       walked). Final bound stubs whose name is missing from the roster
//       get NO_RUNTIME_HANDLER -> native_impl_needed + review, and a
//       per-function has_runtime_handler field in the JSON.
//   11. Rule 154 ELF IDENTITY GUARD: if the step1 toml embeds
//       `elf_hash = "<md5>"`, it is compared with this program's hash.
//       Mismatch = the input was built for a different ELF (revision or
//       region) -> loud console + TOML-header warning + JSON statistic.
//   12. Rule 155 RUNTIME_CONFIRMED VETO: GS-dump-corroborated functions
//       (observed TBP/PSM signature in real captures) added to the v13
//       firewall's render-critical rescue set - never left stubbed.
//   13. Rule 156 MAINLOOP SHIELD DEPTH-3: shield BFS extended from direct
//       callees to depth 3 (capped 768). Gate ordering updated: HARD
//       host-boundary evidence now beats the whitelist, so per-frame SDK
//       wrappers (sceGsSyncV) keep their stubs while per-frame game
//       wrappers two hops below the loop are protected from stubbing.
//   14. Rule 157 SUGGESTED TRIAGE RETURNS: every bound stub gets a JSON
//       suggested_triage_return (reta0 / ret0_or_ret1_ab_test / ret0 /
//       ret0_then_verify) derived from A0-passthrough + poll-target traits.
//   15. Rule 158 OVERLAY GUARD: step1 bindings inside Ghidra overlay
//       memory blocks are vetoed (overlays reuse addresses); enricher
//       never auto-stubs/skips overlay code; non-overlay bindings outside
//       [textStart,textEnd] get OUT_OF_TEXT_BINDING -> review.
//
//  ===== v15.4 (FF1 rerun corrections - over-rescue fixes) =====
//  First full rerun kept only 9 of 651 inherited bindings; root causes and
//  fixes (verified against Himuro ground truth + the real ps2xRuntime):
//   16. SIF transport evidence: sceSifCallRpc/SetDma/SendCmd carry no
//       syscall and don't call themselves - they kick SIF0/SIF1 DMA and
//       touch SBUS. touchesSbus/touchesSbusFlags/SIF dma channels added to
//       hasHostBoundaryEvidence (the whole RPC layer was being recompiled).
//   17. ROSTER-BACKED KEEP: handler implemented in the runtime by exact
//       name + SDK-family name match -> keep the stub (handler existence =
//       intent + tested implementation). Beats whitelist/mainloop-shield
//       rescue; also covers sceVu0* (runtimes ship SIMD-native math).
//       sceGifPk*/sceVif1Pk* stay excluded (must recompile per SF3/DC2).
//   18. v13 address-taken no longer unwinds hard-bound step1 stubs:
//       PS2Recomp dispatch is address-keyed, so indirect calls through a
//       taken pointer still reach the bound handler. FF1 showed addressTaken
//       firing on EVERY 16-byte kernel wrapper (SetSyscall-style vector
//       installs). Conflict still surfaced via ADDRESS_TAKEN_CALLBACK ->
//       review. v8 ctor/sceVu0 promotes also respect hard-bound keeps.
//   19. BIOS_FIREWALL_PREFIXES completed (SetGsCrt/GsPutIMR/Deci2Call/
//       SetAlarm/Suspend-ResumeThread/EndOfHeap/OsdConfigParam/...);
//       families += sceSd (SPU2), sceTty; exacts += sceGszbufaddr/
//       sceSetBrokenLink/sceSetPtm/sceVpu0Reset/scePrintf/sceFs* (SDK names
//       with lowercase continuation that defeat the boundary rule).
//       Ground-truth re-check: 338 name matches on Himuro, zero game code.
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
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

public class General_PS2Recomp_TriageEnricher extends GhidraScript {

    // =========================================================
    // v15.2: OUTPUT-SURFACE POLICY
    // The unified TOML is the EXECUTABLE SAFE SUBSET: [general], active
    // stubs, active skip, [patches]. All advisory material (force_recompile,
    // native_impl_needed, review, nop, patch-instruction candidates, rescue
    // reasons/evidence) lives in triage_map.json - the detailed source of
    // truth. Set this to true only for debugging to also emit the legacy
    // [triage_advisory] block into the TOML.
    // =========================================================
    private static final boolean EMIT_VERBOSE_TOML_ADVISORY = false;

    // v15.5: all text outputs are written as UTF-8 regardless of platform
    // default charset. JSON MUST be UTF-8 (RFC 8259); the old FileWriter
    // default produced mojibake / U+FFFD bytes on Windows (cp125x) hosts.
    private static PrintWriter utf8Writer(File f) throws IOException {
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

    // v4 Rule 32: GIF MMIO (CTRL + CHCR) - Path3 hazard hunt
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
    // Known GS register name map (emitted to JSON for the report tool to label hits).
    // Complete GIF A+D register table from pcsx2/GS/GSRegs.h (GIF_A_D_REG_*).
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
    // v15 (FF1-benchmark corrections): the old RADAR_FIREWALL_PREFIXES list
    // used bare startsWith() with short tokens. On FF1 this stubbed
    // `exponent` (matched prefix "exp" - a 224-byte newlib float formatter),
    // and on any game it would match `tangent`, `logo_*`, `power_*`,
    // `freeCamera`, `sinit`, etc. Two structural fixes:
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
    //       - "_Z" stubbed EVERY Itanium-mangled C++ function - fatal on any
    //         C++ game.
    //       - "__sti"/"__std"/"_GLOBAL_" stubbed static initializers - the
    //         exact functions Rule 141 (STATIC_INIT_VTABLE_INSTALLER) exists
    //         to protect.
    //       - sin/cos/tan/sqrt/mem*/str*/sprintf: FPU/integer math the
    //         recompiler translates exactly; a host handler is an optional
    //         optimization, never a triage decision.
    // Matching additionally requires host-boundary trait evidence - see
    // hasHostBoundaryEvidence(). A name match alone never stubs.
    private static final Set<String> RADAR_EXACT_STUB_NAMES = new HashSet<>(Arrays.asList(
        // DC2 Group D confirmed-safe oddballs (exact spellings)
        "InitTLB","_InitTLB","SetTLBEntry","GetTLBEntry",
        "InitAlarm","ReleaseAlarm",
        "mcHearAlarm","mcDelayThread",
        "printfloat","_system_header","dmaRefImage",
        "EnableCache","DisableCache",
        "isceSifSetDma","isceSifSetDChain","_sceCallCode",
        // v15.4: SDK names with lowercase continuation that defeat the
        // family-boundary rule, plus TTY/FS init wrappers (FF1 benchmark).
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
        // v15.4: SPU2 audio + TTY debug output families (host boundaries).
        "sceSd","sceTty",
        "_sceCd_","_sceFsIob","_sceFsWait","_sceFs_",
        // v9: CRI ADX middleware (SF3 / many Capcom & Sega ports). All audio /
        // streaming runtime - STUB candidates.
        "adx_","cri_","sj_","sjx_","sjr_","dvci","htci","svm_",
        "lsc_","dtr_","dtx_","rna_","mwadx","acrmw",
        // v9: PS2 SDK extras
        "sceGsfx","sceLgfx"
    };

    /** v15: word-boundary family match. A family root that ends in '_' (or any
     *  non-letter) matches as a plain prefix; otherwise the char following the
     *  root must NOT be a lowercase letter. This keeps "sceCd"->"sceCdRead"
     *  and "adx_"->"adx_open" while rejecting "exp"->"exponent" class bugs. */
    private static boolean matchesFamilyPrefix(String name, String family) {
        if (!name.startsWith(family)) return false;
        if (name.length() == family.length()) return true;
        char last = family.charAt(family.length() - 1);
        if (!Character.isLetter(last)) return true;
        char next = name.charAt(family.length());
        return !Character.isLowerCase(next);
    }

    /** v15: name-only part of the stub gate (no trait evidence). */
    private boolean matchesHostBoundaryName(String name) {
        if (name.startsWith("sceVu0")) return false; // VU0 macro math: always RECOMPILE
        if (RADAR_EXACT_STUB_NAMES.contains(name)) return true;
        for (String f : RADAR_STUB_PREFIX_FAMILIES)
            if (matchesFamilyPrefix(name, f)) return true;
        for (String b : BIOS_FIREWALL_PREFIXES)
            if (matchesFamilyPrefix(name, b)) return true;
        return false;
    }

    /** v15: trait corroboration required before any name-based stub binding.
     *  "Host boundary" = the function provably leaves the EE program: kernel
     *  syscall, SIF RPC to the IOP, IRX module loading, IPU/MPEG hardware, or
     *  a tiny leaf thunk (classic SDK wrapper shape). COP1/COP2 usage and
     *  plain MMIO stores are deliberately NOT evidence - the recompiler
     *  translates those (patch_cop0 / runtime MMIO routing). */
    private static boolean hasHostBoundaryEvidence(FuncTraits t) {
        if (t == null) return false;
        if (t.hasSyscall) return true;
        if (t.callsSifRpc || t.detectedRpcSid != 0 || !t.detectedRpcSids.isEmpty()
            || !t.allDetectedSids.isEmpty()) return true;
        if (t.refsIopModuleString || t.isIrxLoader || t.sifLoadModuleCallCount >= 1) return true;
        if (t.isAudioRpcHandler || t.isIopRebootHandler) return true;
        if (t.callsMpegFamily || t.accessesIpuMmio || t.writesIpuCmd) return true;
        // v15.4 (FF1 rerun fix): SIF transport itself. sceSifCallRpc/SetDma/
        // SendCmd build SIF packets and kick the SIF0/SIF1 DMA channels or
        // touch SBUS registers - they ARE the EE<->IOP boundary, but carry no
        // syscall and don't call themselves, so the first benchmark rescued
        // them and recompiled the whole RPC layer.
        if (t.touchesSbus || t.touchesSbusFlags) return true;
        if (t.dmaKickChannels.contains("SIF0") || t.dmaKickChannels.contains("SIF1")
            || t.dmaKickChannels.contains("SIF2")) return true;
        return false;
    }

    /** v15: weak evidence - tiny leaf MMIO thunk (<=64 bytes, no calls). The
     *  classic SDK register-poker/poller shape. Only acceptable as stub
     *  corroboration when the name ALSO matches a known SDK family: a
     *  game-code DMA-kick leaf (FF1: scePP1_Kick, DmaTransReq) has the same
     *  shape and must recompile - runtime MMIO routing executes it correctly. */
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
        // v15.4: EE kernel syscall wrappers missing from the original list -
        // FF1 benchmark found these in the runtime roster but unmatched here.
        "SetGsCrt","GsGetIMR","GsPutIMR","Deci2Call",
        "SetAlarm","iSetAlarm","DeleteThread","iReleaseWaitThread",
        "CancelWakeupThread","iCancelWakeupThread","SuspendThread","ResumeThread",
        "EndOfHeap","iReferSemaStatus","ReferSemaStatus","ReferThreadStatus",
        "SetOsdConfigParam","GetOsdConfigParam","iFlushCache","GetMemorySize",
        "InitThread","ChangeThreadPriority","iChangeThreadPriority",
        "EnableIntcHandler","DisableIntcHandler","EnableDmacHandler","DisableDmacHandler",
        // v15.5: EE kernel syscall wrappers seen unmatched on the Jak ELFs
        // (word-boundary matched, so e.g. "GetThreadId" never hits game code
        // spelled getThreadIdle - next char must not be lowercase).
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
        // v4 additions - IOP video / audio streaming modules. Relevant for
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
    // v12 (F1): added 989snd (`snd_`) - used by Jak/Ratchet/Sly/many SCE titles.
    // Also CRI ADX (`cri_adx_`, `acrmw`), generic `Audio_`/`sceMSnd`/`sceSnd`.
    private static final String[] AUDIO_CALLEE_PREFIXES = {
        "sceSd","sceSpu2","sceLibSd","sceAudio","sceMSIn","sceLibsd",
        "sceSnd","sceMSnd",
        "snd_","Snd_",                     // 989snd library
        "cri_adx_","cri_aix_","cri_sj_",   // CRI middleware
        "acrmw","Audio_","audio_"
    };
    private static final String[] AUDIO_MODULE_STRINGS = {
        "audsrv.irx","libsd.irx","libsd","sdrdrv.irx","sdrdrv","modmidi.irx",
        "989snd.irx","989snd","SsAudio","SsUtil"
    };

    // Rule 53: dialogue/menu text source path.
    private static final String[] MESWIN_STRINGS = {
        "meswin","FontTex","sysmes","fonttbl","font2"
    };

    // v9 R7: archive / asset file extensions referenced inline.
    // v12 (E3): added Jak (.DGO/.STR/.CGO/.MUS/.AYB/.GO),
    // generic SCE/ports (.LMP/.WAD/.LEV/.HDR/.VPK), and host0:/cdfs0: prefixes.
    private static final String[] ARCHIVE_EXTS = {
        ".AFS",".afs",".HD2",".hd2",".DAT",".dat",".BIN",".bin",
        ".TIM2",".tim2",".TM2",".tm2",".AVB",".avb",".PSS",".pss",
        ".SS2",".ss2",".IPU",".ipu",".ADX",".adx",".VAG",".vag",
        ".AHX",".ahx",".ASS",".ass",".AFP",".afp",
        // v12 (E3): Jak / Naughty Dog
        ".DGO",".dgo",".CGO",".cgo",".STR",".str",".GO",".AYB",".ayb",
        ".MUS",".mus",
        // v12 (E3): common port/asset extensions
        ".LMP",".lmp",".WAD",".wad",".LEV",".lev",".HDR",".hdr",
        ".VPK",".vpk",".SBK",".sbk",".VPP",".vpp",".CHM",".chm",
        ".TXM",".txm",".MDL",".mdl",".MOV",".mov",".PSF",".psf",
        // path prefixes
        "/CD/","/MC0/","/MC1/","cdrom0:","mc0:","mc1:","host0:","cdfs0:","rom0:"
    };
    // v12 (E1): behavioral asset-name regex - uppercase basename + extension.
    // Captures TWEAKVAL.MUS / VAGDIR.AYB / *.DGO without per-game ext list.
    private static final java.util.regex.Pattern ASSET_NAME_REGEX =
        java.util.regex.Pattern.compile("^[A-Z0-9_]{1,16}\\.[A-Z0-9]{2,5}$");

    // Rule 54: memory-card transition gates that historically had to be no-op'd
    // (F21 FinishForMC, F-future McError). Small + name match.
    // v12 (F2): generalized beyond DC2 - added MemCard/save_data/savefile shapes.
    private static final String[] MC_GATE_NAME_FRAGMENTS = {
        "ForMC","McCheck","McError","FinishForMC","McUd","mcDelay","mcHear",
        "MemCard","memcard","Memcard",
        "mc_save","mc_load","saveGame","loadGame","savegame","loadgame",
        "save_data","save_file","savefile","SaveData","LoadData",
        "save_state","load_state"
    };
    // v12 (F2): behavioral MC gate - any function calling MC SDK functions.
    private static final Set<String> MC_SDK_CALLEES = new HashSet<>(Arrays.asList(
        "sceMcOpen","sceMcRead","sceMcWrite","sceMcClose","sceMcSeek",
        "sceMcMkdir","sceMcDelete","sceMcGetDir","sceMcGetInfo",
        "sceMcFormat","sceMcUnformat","sceMcSync","sceMcFlush",
        "sceMcChdir","sceMcRename","sceMcSetFileInfo"
    ));

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
    private static final long SBUS_MSFLG          = 0x1000F220L;
    private static final long SBUS_SMFLG          = 0x1000F230L;
    // DMA CHCR STR|TIE start pattern (Rule 115 DMA_CHCR_START_KICK).
    private static final long DMA_CHCR_START_CONST = 0x101L;

    // v11 (E): EE peripheral register ranges per pcsx2/Hw.h. Distinguishes
    // categories the v9 ACCESSES_MMIO bucket lumped together.
    // Timer channels: 0x10000000-0x10001FFF (RCNT0-3).
    private static final long RCNT_RANGE_START    = 0x10000000L;
    private static final long RCNT_RANGE_END      = 0x10001FFFL;
    // VIF unit CONTROL regs (STAT/FBRST/ERR/MARK/CYCLE/MODE/CODE/...) -
    // distinct from VIF DMA channel block at 0x10008000 / 0x10009000.
    private static final long VIF0_CTRL_START     = 0x10003800L;
    private static final long VIF0_CTRL_END       = 0x10003BFFL;
    private static final long VIF1_CTRL_START     = 0x10003C00L;
    private static final long VIF1_CTRL_END       = 0x10003FFFL;
    // DMAC global control block (CTRL/STAT/PCR/SQWC/RBSR/RBOR/STADR).
    private static final long DMAC_GLOBAL_START   = 0x1000E000L;
    private static final long DMAC_GLOBAL_END     = 0x1000E0FFL;
    // INTC (interrupt controller).
    private static final long INTC_STAT_ADDR      = 0x1000F000L;
    private static final long INTC_MASK_ADDR      = 0x1000F010L;
    // SIO (deci2 / debug printf).
    private static final long SIO_RANGE_START     = 0x1000F100L;
    private static final long SIO_RANGE_END       = 0x1000F1FFL;
    // DMAC ext (D_ENABLER / D_ENABLEW) - the master DMA gate.
    private static final long DMAC_EXT_START      = 0x1000F500L;
    private static final long DMAC_EXT_END        = 0x1000F5FFL;
    private static final long D_ENABLER           = 0x1000F520L;
    private static final long D_ENABLEW           = 0x1000F590L;

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
        VIF_OPCODES.put(0x4AL, "MPG");        // Microcode upload - Path1 bullseye
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
    // Also PSMT4HL=36 (0x24), PSMT8H=27 (0x1B) - other Z-buffer aliases.
    private static final long PSMT4HH = 0x2CL;
    private static final long PSMT4HL = 0x24L;
    private static final long PSMT8H  = 0x1BL;



    // Rule 22: Known IOP SIDs from ps2_iop.h (for cross-referencing)
    // v12 (D): added Jak SIDs from jak-project (game/common/*_rpc_types.h).
    // Useful even when the binary is stripped - engineer can grep for usage.
    private static final Map<Long, String> KNOWN_IOP_SIDS = new HashMap<>();
    static {
        KNOWN_IOP_SIDS.put(0x00000000L, "IOP_SID_SNDDRV_COMMAND");
        KNOWN_IOP_SIDS.put(0x00000001L, "IOP_SID_SNDDRV_STATE");
        KNOWN_IOP_SIDS.put(0x80000701L, "IOP_SID_LIBSD");
        // Jak1 RPC IDs (jak-project game/common/*_rpc_types.h)
        KNOWN_IOP_SIDS.put(0x0000DEB1L, "JAK1_PLAYER_RPC");
        KNOWN_IOP_SIDS.put(0x0000DEB2L, "JAK1_LOADER_RPC");
        KNOWN_IOP_SIDS.put(0x0000DEB3L, "JAK1_RAMDISK_RPC");
        KNOWN_IOP_SIDS.put(0x0000DEB4L, "JAK1_DGO_RPC");
        KNOWN_IOP_SIDS.put(0x0000DEB5L, "JAK1_STR_RPC");
        KNOWN_IOP_SIDS.put(0x0000DEB6L, "JAK1_PLAY_RPC");
        // Jak2/3/X RPC IDs (same table)
        KNOWN_IOP_SIDS.put(0x0000FAB0L, "JAK23X_PLAYER_RPC");
        KNOWN_IOP_SIDS.put(0x0000FAB1L, "JAK23X_LOADER_RPC");
        KNOWN_IOP_SIDS.put(0x0000FAB2L, "JAK23X_RAMDISK_RPC");
        KNOWN_IOP_SIDS.put(0x0000FAB3L, "JAK23X_DGO_RPC");
        KNOWN_IOP_SIDS.put(0x0000FAB4L, "JAK23X_STR_RPC");
        KNOWN_IOP_SIDS.put(0x0000FAB5L, "JAK23X_PLAY_RPC");
    }

    // v12 (A1): EE syscall imm -> canonical name. Sourced from
    // skill/resources/db-syscalls.md (ps2tek sec.BIOS EE Syscalls). Covers the
    // common bootstrap+thread+sema+intc+dmac surface that PS2 binaries wrap
    // as tiny `syscall N; jr ra; nop` 12-byte trampolines.
    private static final Map<Long, String> EE_SYSCALL_NAMES = new HashMap<>();
    static {
        // v15.5 REBUILD: the old map had wrong assignments (0x66/0x67 are
        // CpuConfig/iGetCop0, NOT GsGetIMR/GsPutIMR; 0x68 is iFlushCache,
        // NOT SetVSyncFlag; SetVSyncFlag is 0x73 and SetSyscall is 0x74) -
        // and Rule 160 now BINDS runtime handlers from these names, so every
        // entry is cross-checked against two authorities:
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

    // Rule 10: Absolute whitelist - immune to ALL firewalls
    private static final String[] WHITELIST_NAMES = {
        "entry","_start","crt0","topThread","cmd_sem_init"
    };

    // Rule 24: Known pad-polling syscall names (for PAD_POLL_LOOP detection)
    // v12 (F4): added generic names so stripped-symbol games still hit.
    private static final Set<String> PAD_POLL_CALLEES = new HashSet<>(Arrays.asList(
        "scePadGetState","scePadGetReqState","scePadRead","scePadGetData",
        "sceGsSyncV","sceGsSyncVCallback","WaitVSync",
        "padGetData","padGetState","padRead","pad_get_state","pad_read",
        "_pad_read_","_pad_get_state_","read_pad_state","read_pad_data"
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
    // (all GS IRQs masked) these handlers can never fire - safe-stub label.
    private static final String[] GS_IRQ_HANDLER_NAME_FRAGMENTS = {
        "GsSignal","GsFinish","GsLabel","SignalHandler","FinishHandler",
        "LabelHandler","sceGsSyncH","sceGsSyncV"
    };

    // Rule 88: libgcc intrinsic exact names (union of General + DC2 sets).
    private static final Set<String> LIBGCC_EXACT_NAMES = new HashSet<>(Arrays.asList(
        // 64-bit integer helpers
        "__divdi3", "__udivdi3", "__moddi3", "__umoddi3",
        "__muldi3", "__negdi2", "__lshrdi3", "__ashldi3", "__ashrdi3",
        "__cmpdi2", "__ucmpdi2", "__ffsdi2", "__clzdi2", "__ctzdi2",
        "__popcountdi2", "__paritydi2", "__bswapdi2",
        // 32-bit integer helpers (DC2 set)
        "__divsi3", "__udivsi3", "__modsi3", "__umodsi3",
        // float<->int conversion
        "__fixdfdi", "__fixunsdfdi", "__floatdidf", "__floatundidf",
        "__fixsfdi", "__fixunssfdi", "__floatdisf", "__floatundisf",
        "__floatsisf", "__floatsidf",
        // double helpers
        "__adddf3", "__subdf3", "__muldf3", "__divdf3",
        "__cmpdf2",
        // float helpers
        "__addsf3", "__subsf3", "__mulsf3", "__divsf3",
        "__cmpsf2",
        // misc conversion
        "__extendsfdf2", "__truncdfsf2", "__negdf2", "__negsf2",
        // low-level FP pack/unpack (DC2 set - found in stripped PS2 SDK rt libs)
        "__pack_d", "__unpack_d", "__pack_f", "__unpack_f",
        "__fpcmp_parts_d", "__fpcmp_parts_f",
        "__make_dp", "__make_fp"
    ));

    // Rule 96: GIF NLOOP hazard helpers (DC2: added MakeGiftagAplusD/makeGifTagAplusD/openGifTag)
    private static final Set<String> GIF_PACKET_NLOOP_HELPERS = new HashSet<>(Arrays.asList(
        "sceGifPkOpenGifTag", "sceVif1PkOpenGifTag", "sceGifPkAddGsAD",
        "makeGiftagAplusD", "MakeGiftagAplusD", "makeGifTagAplusD", "openGifTag"
    ));
    // DC2: added ClosePacketGifTag/closeGifTag
    private static final Set<String> GIF_PACKET_CLOSE_HELPERS = new HashSet<>(Arrays.asList(
        "sceGifPkCloseGifTag", "sceVif1PkCloseGifTag", "closePacketGifTag",
        "ClosePacketGifTag", "closeGifTag"
    ));

    // Rule 97: Pad button masks
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

    // Rule 99: File open callees (DC2: added LoadFileEx, sceCdStRead)
    private static final Set<String> FILE_OPEN_CALLEES = new HashSet<>(Arrays.asList(
        "sceCdRead", "sceCdSearchFile", "sceOpen", "sceLseek", "sceRead",
        "LoadFile", "LoadFile2", "LoadFileEx", "fopen", "fread", "fseek",
        "sceCdStRead"
    ));

    // Rule 100: Frame clock driver callees
    // v12 (F3): generic frame-pacing names + engine-specific common variants.
    private static final Set<String> FRAME_CLOCK_CALLEES = new HashSet<>(Arrays.asList(
        "sceGsSyncV", "sceGsSyncH", "WaitVSync", "SetVSyncFlag",
        "sceGsSyncVCallback",
        "wait_vsync","WaitFrameSync","wait_for_vsync","WaitForVBlank",
        "WaitForVSync","wait_for_vblank","WaitForVblank",
        "mgEndFrame","EndFrame","end_frame","present_frame","PresentFrame",
        "vsync_handler","vsync-handler","vif1-vsync-handler"
    ));

    // Rule 124/125: IRX loader and IOP reboot callee name sets.
    private static final Set<String> IRX_LOAD_CALLEES = new HashSet<>(Arrays.asList(
        "sceSifLoadModule", "sceSifLoadStartModule", "sceSifLoadFileEx",
        "SifLoadModule", "SifLoadStartModule"
    ));
    private static final Set<String> IOP_REBOOT_CALLEES = new HashSet<>(Arrays.asList(
        "sceSifRebootIop", "SifRebootIop", "sceSifInitIopHeap"
    ));

    // Rule 150: EE code-overlay exec/load callees. sceSifLoadModule (IOP modules)
    // excluded - that is IRX loading (Rule 124), not an EE address-space overlay.
    private static final Set<String> OVERLAY_LOADER_CALLEES = new HashSet<>(Arrays.asList(
        "LoadExecPS2", "ExecPS2", "sceExecPS2", "LoadModuleBuffer",
        "sceSifLoadModuleBuffer", "sceSifLoadElf", "ExecModule", "sceSifLoadElfPart"
    ));

    // Rule 102: sceVu0 helper prefixes
    private static final String[] SCEVU0_HELPER_PREFIXES = {
        "sceVu0", "_sceVu0"
    };

    // PSM code constants (PCSX2 GSRegs.h) for VRAM/Z-alias decoding.
    private static final int PSM_PSMT4HH = 44;   // 0x2C - UI/font Z-buffer alias
    private static final int PSM_PSMT4HL = 36;   // 0x24
    private static final int PSM_PSMT8H  = 27;   // 0x1B

    // v11 (H): well-known PS2 file-format magic constants. Detection scans
    // const_loads (lui+ori/li composites already gathered) for any 16/32-bit
    // immediate matching this table. Entry: {label, 32-bit magic}.
    // 16-bit shorts are tested against (mask & 0xFFFF).
    private static final Map<Long,String> FORMAT_MAGIC_CONSTS = new LinkedHashMap<>();
    static {
        FORMAT_MAGIC_CONSTS.put(0x324D4954L, "TIM2");      // 'TIM2'
        FORMAT_MAGIC_CONSTS.put(0x3254434CL, "CLT2");      // 'CLT2'
        FORMAT_MAGIC_CONSTS.put(0x464C457FL, "ELF");       // 0x7F ELF
        FORMAT_MAGIC_CONSTS.put(0x46524550L, "PERF");      // 'PERF'
        FORMAT_MAGIC_CONSTS.put(0x53573031L, "SW01");      // ".SS2"-class
        FORMAT_MAGIC_CONSTS.put(0xBA010000L, "PSS_PACK");  // PSS pack hdr
        FORMAT_MAGIC_CONSTS.put(0x43475053L, "PSGC");      // 'SPGC'/'PSGC'
        FORMAT_MAGIC_CONSTS.put(0x32706D69L, "imp2");      // 'imp2'
    }
    // 16-bit halves of common 32-bit magics (caught as standalone shorts).
    private static final Map<Long,String> FORMAT_MAGIC_SHORTS = new LinkedHashMap<>();
    static {
        FORMAT_MAGIC_SHORTS.put(0x4954L, "TIM2_lo");
        FORMAT_MAGIC_SHORTS.put(0x324DL, "TIM2_hi");
        FORMAT_MAGIC_SHORTS.put(0x4C43L, "CLT2_lo");
        FORMAT_MAGIC_SHORTS.put(0x3254L, "CLT2_hi");
    }

    // Checkpoint name fragments treated as "menu/UI" for RUNTIME_MENU_ONLY
    // classification. Lowercase comparison.
    private static final String[] MENU_CHECKPOINT_FRAGMENTS = {
        "menu","inventory","pause","character","title","select","ui","hud"
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
        // True if no captures loaded - disables corroboration tags.
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
        // v13: store-instruction count. Used to separate true idle/poll spins
        // (no stores) from counted copy/clear loops (memcpy/memset shapes),
        // which the old INFINITE_SPIN_LOOP rule falsely flagged for NOP patching.
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
        // F21-prep: outgoing JAL records - pairs of (callSitePc, calleeTargetAddr).
        // Collected during the instruction scan; consumed in a post-pass to
        // build the reverse call-graph that lands in JSON as "callers".
        List<long[]> jalSites = new ArrayList<>();
        // F21-prep: incoming-call records populated by buildReverseCallGraph()
        // after all functions are scanned. Each entry is [callerAddr, callSitePc].
        List<long[]> callers = new ArrayList<>();
        // F21-prep: memory-access literal references. Each entry is
        // [pcHex, mnem, baseReg, offsetHex, destReg] - captured for load/store
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
        // Rule 29: function whose tail does `move $v0, $a0` (or $a1) - passthrough.
        // Auto-stub returning 0 would break chained calls like `f(g(x))` where
        // g forwards x. Detected via last-10 instructions scan.
        boolean returnsA0=false;
        boolean returnsA1=false;
        // Rule 30: name-based - process terminator
        boolean isProcessTerminator=false;
        // Rule 31: libgcc 64-bit / FP intrinsic
        boolean isLibgccIntrinsic=false;
        // Rule 32: GIF Path3 hazard - CTRL/CHCR/PRIM-offset signals
        boolean touchesGifCtrl=false;
        boolean writesGsPrimReg=false;
        // Rule 33: Z-buffer alias risk - ZBUF reg + 24-bit shift
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
        // Rule 94: virtual dispatch sites - entries [pcHex, slotOffsetHex, objReg].
        List<String[]> virtualDispatchSites = new ArrayList<>();
        // Rule 95: any return value of a `jal <this>` site that was subsequently
        // stored to a $gp-rooted global. Populated post-scan.
        Set<Long> returnWrittenToGlobals = new LinkedHashSet<>();
        // Rule 97: andi/and immediates that look like PS2 pad button masks.
        Set<String> padMasksTested = new LinkedHashSet<>();
        boolean isPadButtonMaskConsumer = false;
        // Rule 96: GIF NLOOP double-count hazard - function calls both open+close
        // helpers; flag for human review.
        boolean callsGifPacketOpen = false;
        boolean callsGifPacketClose = false;
        boolean gifNloopDoubleCountRisk = false;
        // Rule 99: file-open callee + format-string source for $a0 path argument.
        boolean callsFileOpen = false;
        // v15.5 Rule 161: dynamic-code loader (reads payload from disc, then
        // flushes the instruction cache before executing it).
        boolean isDynamicCodeLoader = false;
        Set<String> filePathSprintfFormats = new LinkedHashSet<>();
        boolean filePathHasPercentS = false;
        // Rule 100: frame-clock driver - calls vsync / mgEndFrame
        boolean isFrameClockDriver = false;
        // Rule 101: SIF RPC fid (function id) literal - captured alongside SID.
        Set<Long> detectedRpcFids = new LinkedHashSet<>();
        // Rule 102: sceVu0 family - must-implement whitelist.
        boolean isSceVu0Helper = false;
        String  vu0HelperFamily = null;         // matrix / vector / transform
        boolean mustBeImplemented = false;
        // Rule 91: caller of an uploader (depth 1 or 2). Filled post-scan.
        boolean uploaderCallerDepth1 = false;
        boolean uploaderCallerDepth2 = false;
        // Rule 111: companion SDK-caller depth-1 flags (used for *_via_sdk_caller
        // statistics so SDK-wrapped accesses still show in counts).
        boolean dispfbWriterViaSdkCallerDepth1 = false;
        boolean dmaKickViaSdkCallerDepth1 = false;
        
        // Rule 98: override classification
        String overrideKind = null;
        boolean overrideRetireCandidate = false;
        
        // Rule 103: asset upload traces
        Set<String> assetUploadTagsHit = new LinkedHashSet<>();

        // ===== v9 fields =====
        // R11: every lui/ori/addiu/li constant in function body.
        // entries = {pc, immediateValue, destReg.hashCode()}.
        List<long[]> constLoads = new ArrayList<>();
        Set<String> constLoadDestRegs = new LinkedHashSet<>();
        // R2: function loads 0x101 (DMA CHCR start bit).
        boolean loadsChcrStartConst = false;
        // R2: function pairs CHCR-start const with channel-base load.
        boolean dmaChcrStartKick = false;
        // R1: GIF tag inline builder (>=4 16-byte-stride stores to same base
        // with GIF NLOOP/FLG/REGS bit shape).
        boolean gifTagInlineBuilder = false;
        // v14: 16-byte-stride store pattern matched but the only context is
        // SIF RPC packet building (no GIF/VIF/DMA evidence). Demoted from
        // gifTagInlineBuilder so render heuristics ignore it.
        boolean sifPacketBuilder = false;
        Set<String> gifTagFlags = new LinkedHashSet<>();   // PACKED/REGLIST/IMAGE
        Set<Long> gifTagNloops = new LinkedHashSet<>();
        Set<Long> gifTagRegsFields = new LinkedHashSet<>();
        // R4: writes BITBLTBUF then TRXPOS then TRXREG then TRXDIR adjacent.
        boolean bitbltbufMacroSequence = false;
        // R6: render frame entry (frame-clock + MMIO writer reachable from mainloop).
        boolean isRenderFrameEntry = false;
        // R7: archive-IO string evidence.
        Set<String> archiveStringExts = new LinkedHashSet<>();
        boolean refsArchiveStrings = false;
        // R8: every string referenced by this function (sampled, max ~16 per
        // function to keep JSON bounded).
        List<String> stringRefs = new ArrayList<>();
        // R10: jalr through known function-pointer table - table base + slot.
        Set<String> tableDispatchSites = new LinkedHashSet<>();
        // R16: VU0 macro helper - instruction-mix derived.
        int vu0MacroOps = 0;
        boolean isVu0MacroHelper = false;
        // R17: struct initializer (C-style ctor, no name match required).
        boolean isStructInitializer = false;
        // R18: module-cluster id assigned post-pass.
        int moduleId = -1;
        // R20: idle / spin-loop detection (refined).
        boolean isInfiniteSpinLoop = false;
        // Float compare cluster (R19).
        int floatCmpOps = 0;

        // ===== v10 generic fields =====
        // G1: stored-immediate VIF/DMA tag detection. Tracks 32-bit values
        // stored to qword-aligned offsets whose high byte matches an opcode.
        Set<String> storedVifOpcodes = new LinkedHashSet<>();
        Set<String> storedDmaTagIds  = new LinkedHashSet<>();
        // G2: memory section / block name containing function entry.
        String sectionName = null;
        // G3: HI/LO register reads (integer mul/div result consumers).
        int hiLoOps = 0;
        // G3: per-opcode counter sample (mnem -> count). Capped emit.
        Map<String, Integer> opcodeHistogram = new HashMap<>();
        // 64-bit GIF tag composition fingerprint: lui+ori then dsll32 then ori
        // resolved within ~6 instructions. Captures SCE_GIF_SET_TAG macro.
        boolean buildsGifTag64 = false;
        // Texture upload chunk-size constant (VIF1 LoadImage uses 0x70000).
        boolean loads70000Chunk = false;
        // Cyclomatic proxy = branchOps + jal callsites - returnPaths + 1.
        // Computed at end. Stored here for emit.
        int cyclomaticProxy = 0;
        // dsll32-followed-by-ori-within-3 marker (64-bit composition).
        boolean hasDsll32OrSequence = false;

        // ===== v11 (E): peripheral register categories =====
        boolean accessesRcnt = false;            // 0x10000000-0x10001FFF
        boolean accessesVifCtrl = false;         // 0x10003800-0x10003FFF
        boolean accessesDmacGlobal = false;      // 0x1000E000-0x1000E0FF
        boolean writesIntcMask = false;          // 0x1000F010 write
        boolean readsIntcStat = false;           // 0x1000F000 read
        boolean accessesSio = false;             // 0x1000F100-0x1000F1FF
        boolean writesDmacEnable = false;        // 0x1000F590 write (D_ENABLEW)
        boolean touchesSbusFlags = false;        // 0x1000F220 / 0x1000F230
        // ===== v11 (D): raw SID/FID list =====
        Set<Long> detectedRpcSids = new LinkedHashSet<>();
        // ===== v11 (F): source-chain DMA tag builder =====
        boolean dmaSourceChainTagBuilder = false;
        Set<String> dmaSourceChainTagIds = new LinkedHashSet<>();
        // ===== v11 (H): file-format magic numbers =====
        Set<String> formatMagicHits = new LinkedHashSet<>();
        // ===== v11 (I): IRX loader + IOP reboot =====
        int sifLoadModuleCallCount = 0;
        boolean isIrxLoader = false;
        boolean isIopRebootHandler = false;
        Set<String> irxModulePaths = new LinkedHashSet<>();
        // ===== v11 (J): tight-loop sync waits =====
        boolean isSyncWaitLoop = false;
        boolean containsInfiniteFailLoop = false;
        // ===== v12 fields =====
        // F2: behavioral MC gate (function calls sceMcOpen/Read/Write/...).
        boolean callsMcSdk = false;
        // B1: composite-const MMIO ranges recovered post-scan from lui+ori
        // pairs, not just resolved Ghidra refs. Each populates the matching
        // legacy boolean flag in addition (so downstream stats/tags fire).
        Set<String> compositeMmioRangesHit = new LinkedHashSet<>();
        // A2: name inferred from syscall imm when ELF was stripped.
        String inferredName = null;
        long  inferredSyscallImm = -1L;
        // E1: behavioral asset-string discovery (regex over string refs).
        Set<String> discoveredAssetPaths = new LinkedHashSet<>();
        // D2: full SID + FID lists (multi-RPC functions).
        Set<Long> allDetectedSids = new LinkedHashSet<>();
        Set<Long> allDetectedFids = new LinkedHashSet<>();
        // G1: candidate patch instructions (PC of backward branches in spin/wait).
        Set<Long> patchCandidatePcs = new LinkedHashSet<>();
        // H2: synthesized vtable-class name (stripped binaries).
        String inferredClassName = null;
        int    inferredVtableSlot = -1;

        // ===== Rules 140-150 fields =====
        // Rule 140: COP2_DESTMASK_VERIFY - partial dest-field VU0-macro ops.
        int cop2PartialDestOps = 0;
        int cop2FullDestOps = 0;
        Set<String> cop2DestFields = new LinkedHashSet<>();
        boolean cop2DestMaskVerify = false;
        // Rule 141: STATIC_INIT_MANIFEST - __sinit_* vtable/global installers.
        List<String> staticInitInstalls = new ArrayList<>();
        boolean isStaticInitializer = false;
        boolean staticInitInstallsVtable = false;
        boolean isUncalledStaticInit = false;
        // Rule 142: MEMORY_ALLOCATOR_NEVER_STUB - pool/alloc/placement-new/array-ctor.
        boolean isMemoryAllocator = false;
        String  allocatorKind = null;
        // Rule 143: GUEST_LOCK_HOG_CANDIDATE - yield-without-mutex-release pattern.
        boolean isGuestLockHogCandidate = false;
        // Rule 144: EABI_ARG_T0 - reads $t0 as 5th integer argument before defining it.
        boolean readsEabiArgT0 = false;
        // Rule 145: MAP_CLUT_PSMCT16_UPLOADER - BITBLTBUF writer loading PSMCT16 (dpsm=0x2).
        boolean loadsPsmct16Const = false;
        boolean isPsmct16ClutUploader = false;
        // Rule 146: COMPUTED_JUMP_TARGETS - Ghidra-resolved jr $reg switch tables.
        Map<Long,List<Long>> computedJumpTargets = new LinkedHashMap<>();
        Set<Long> computedJumpSwitchPcs = new LinkedHashSet<>();
        // Rule 147: COP2_SPECIAL_OPS_REVIEW - vdiv/vsqrt/vrsqrt/vclipw/xgkick etc.
        Set<String> cop2SpecialOps = new LinkedHashSet<>();
        // Rule 148: FPU_NONIEEE_SENSITIVE - ctc1/cfc1 or div.s/sqrt.s with usesCop1.
        boolean writesFpuControl = false;
        boolean usesFpuDivSqrt = false;
        // Rule 150: OVERLAY_LOADER - EE code-overlay exec/load callee detected.
        boolean isOverlayLoader = false;
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
    // v15: step1 entries rescued to RECOMPILE (keyed by address and by name,
    // because step1 entries may carry either). writeUnifiedConfig drops
    // these from the copied stubs/skip arrays; reasons live in the JSON.
    private Map<Long,String> step1RescueByAddr = new LinkedHashMap<>();
    private Map<String,String> step1RescueByName = new LinkedHashMap<>();
    // v15.2 Rule 151: expected name per step1 address - detects stale /
    // wrong-region input tomls (US vs EU/JP ELF address drift).
    private Map<Long,String> step1NameByAddr = new HashMap<>();
    private int step1NameMismatchCount = 0;
    // v15.3 Rule 153: runtime-handler roster. Optional - user may point the
    // script at a ps2xRuntime checkout; we scrape the handler names actually
    // implemented there. A STUB binding routes to a runtime handler BY NAME,
    // so a stub whose name is absent from the roster is a silent dead call:
    // flag NO_RUNTIME_HANDLER -> native_impl_needed + review.
    private Set<String> runtimeHandlerNames = new HashSet<>();
    private boolean runtimeRosterLoaded = false;
    private int noHandlerStubCount = 0;
    // v15.3 Rule 154: elf identity guard. Exporters may embed the hash of the
    // ELF they were generated from: `elf_hash = "<md5>"` in [general].
    private String step1ElfHash = null;
    private String step1ElfHashStatus = "absent";   // absent | match | mismatch
    // v15.3 Rule 158: overlay / out-of-text binding guards.
    private int overlayVetoCount = 0, outOfTextBindingCount = 0;

    // v15.2: advisory lists handed from run() to writeTriageJson so the JSON
    // carries the full [triage_advisory] content (TOML stays executable-only).
    private List<String> advisoryNop = new ArrayList<>();
    private List<String> advisoryPatch = new ArrayList<>();
    private List<String> advisoryForceRecomp = new ArrayList<>();
    private List<String> advisoryNativeImpl = new ArrayList<>();
    private List<String> advisoryReview = new ArrayList<>();
    private List<long[]> advisoryPatchInstr = new ArrayList<>();

    /** v15: record a step1 stub/skip entry rescued to RECOMPILE. Called both
     *  from the main-loop keep gate and from every later promote-out-of-STUB
     *  post-pass (drawing chain, ctor risk, sceVu0 helper, v13 firewall). */
    /** v15.5: remove an auto stub/skip binding from a pending TOML list.
     *  Covers both spellings: the ELF symbol and (Rule 160) the inferred
     *  syscall handler name the entry may have been bound under. */
    private void removeAutoBindingEntries(List<String> list, FuncResult r) {
        list.remove(r.name + "@" + hex(r.address));
        if (r.traits != null && r.traits.inferredName != null)
            list.remove(r.traits.inferredName + "@" + hex(r.address));
    }

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

    /** v15: step1 binding kept on HARD host-boundary evidence - a deliberate
     *  boundary later promote passes must not unwind. v15.4: roster-backed
     *  keeps (runtime implements the handler by name) are equally hard. */
    private boolean isHardBoundStep1(FuncResult r) {
        if (!"step1".equals(r.origin)) return false;
        if (!r.tags.contains("STEP1_BOUND_HOST_BOUNDARY")) return false;
        if (hasHostBoundaryEvidence(r.traits)) return true;
        return r.tags.contains("STEP1_BOUND_ROSTER_HANDLER");
    }

    /** v15 high-confidence keep gate for inherited (step1) stub/skip bindings.
     *  Returns null when the binding may stand; otherwise the rescue reason.
     *  Philosophy: RECOMPILE is the safe default for anything that is pure EE
     *  code - recompiled code is always semantically correct, while a stub is
     *  only correct if the runtime actually services it. A binding therefore
     *  survives only with host-boundary evidence (syscall / SIF RPC / IRX /
     *  IPU-MPEG / SDK-named MMIO poller), and never against the existing
     *  trait firewalls. */
    private String step1KeepGateFailure(String name, FuncTraits t, boolean isSkip,
                                        boolean isWhitelisted, boolean forceRecompile) {
        // v15.5 Rule 159 (order matters, BEFORE the trait firewall): bare
        // syscall trampolines. A <=32-byte, 0-call body with a syscall is
        // just `li $v1,N; syscall; jr $ra` - the trait firewalls that can
        // set forceRecompile on it (PROCESS_TERMINATOR / allocator / ctor
        // names) are name-derived false positives on a 2-instruction body
        // and used to rescue _exit/_Exit with a misleading reason.
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
        // v15.4: roster-backed keep. The runtime author already implemented a
        // handler with this exact name AND the name is a known SDK boundary
        // family - that is the strongest possible keep signal (handler
        // existence = intent + tested implementation). Checked before the
        // sceVu0 deny: runtimes ship SIMD-native sceVu0 math (skill sec.6), and
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
        boolean syscallWrapperShape = t.hasSyscall && t.byteSize <= 32 && t.callOps == 0;
        if (isSkip) {
            // SKIP generates an error-returning placeholder: legal only for
            // bare kernel trampolines and unreachable bootstrap code. The FF1
            // input toml had SKIPPED __ieee754_sqrtf/__muldi3/__do_global_ctors
            // - pure computation whose loss silently corrupts math and static
            // init. Those must recompile.
            if (syscallWrapperShape) return null;
            if (t.hasSyscall && t.xrefToCount == 0) return null; // unreferenced kernel bootstrap
            return "SKIP only for bare syscall trampolines / unreachable bootstrap; "
                 + "pure code must RECOMPILE";
        }
        // v15.3 Rule 156 (order matters): HARD host-boundary evidence
        // (syscall / SIF RPC / IRX / IPU-MPEG) keeps the stub even when the
        // name looks like a callback/handler or sits inside the (now depth-3)
        // mainloop shield - per-frame SDK wrappers like sceGsSyncV are still
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
    // Rule 98: handler body classification (addr -> kind string).
    private Map<Long, String> overrideKindByAddr = new HashMap<>();
    private Map<Long, String> overrideHandlerNames = new HashMap<>();
    private int overrideClassifiedCount = 0;
    private int overrideRetireCount = 0;

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
    private int padPollLoopCount=0;
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
    private int dispfbWriterViaSdkCallerCount=0;
    private int dmaKickViaSdkCallerCount=0;
    private int returnWrittenToGlobalCount=0;

    // v9 counters
    private int archiveIoCount=0;
    private int gifTagBuilderCount=0;
    private int bitbltbufMacroCount=0;
    private int vu0MacroHelperCount=0;
    private int structInitCount=0;
    private int spinLoopCount=0;
    private int dmaChcrStartKickCount=0;
    private int renderFrameEntryCount=0;
    private int tableDispatchCallCount=0;
    // v10 generic counters
    private int storedVifTagCount=0;
    private int storedDmaTagCount=0;
    private int gifTag64Count=0;
    private int chunk70000Count=0;
    private int hiLoConsumerCount=0;

    // v11 counters (E/F/H/I/J)
    private int rcntAccessCount=0;
    private int vifCtrlAccessCount=0;
    private int dmacGlobalAccessCount=0;
    private int intcMaskWriterCount=0;
    private int intcStatReaderCount=0;
    private int sioAccessCount=0;
    private int dmacEnableWriterCount=0;
    private int sbusFlagAccessCount=0;
    private int dmaSourceChainTagCount=0;
    private int formatMagicHitCount=0;
    private int irxLoaderCount=0;
    private int iopRebootHandlerCount=0;
    private int syncWaitLoopCount=0;
    private int infiniteFailLoopCount=0;
    // v15.5 Rule 159/161 counters
    private int syscallTrampolineCount=0;
    private int dynamicCodeLoaderCount=0;

    // Rules 140-150 counters
    private int cop2PartialDestFuncCount=0;
    private int staticInitializerFuncCount=0;
    private int uncalledStaticInitCount=0;
    private int memoryAllocatorCount=0;
    private int guestLockHogCount=0;
    private int eabiArgT0Count=0;
    private int psmct16ClutUploaderCount=0;
    private int computedJumpSiteCount=0;
    private int computedJumpUnresolvedCount=0;
    private int cop2SpecialOpFuncCount=0;
    private int fpuNonIeeeCount=0;
    private int overlayLoaderCount=0;
    private int discoveredSidCount=0;

    // Rule 139: discovered IOP SID tracking (cross-function aggregation).
    private Map<Long,List<Long>> discoveredSidToCallers = new LinkedHashMap<>();
    private Map<Long,List<Long>> discoveredFidToCallers = new LinkedHashMap<>();

    // Rule 93 class registry: class name -> aggregated info.
    private Map<String, ClassEntry> classRegistry = new LinkedHashMap<>();
    // Rule 109 diff-mode: address -> prior `disposition|category` string.
    private Map<Long,String> priorTriageMapCats = null;

    // v9 R9: discovered function-pointer tables. {tableAddr -> list of entries}.
    private Map<Long, List<Long>> functionPointerTables = new LinkedHashMap<>();
    // v9 R18: module cluster registry. id -> set of function addrs.
    private Map<Integer, Set<Long>> moduleClusters = new LinkedHashMap<>();
    // v11 (K): name-prefix module index. prefix -> sorted addresses.
    private Map<String, List<Long>> namePrefixModules = new LinkedHashMap<>();

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
        println("PS2Recomp TRIAGE ENRICHER v11 - FF1+DC2 cross-game rules");
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

        // v15.3 Rule 153: optional ps2xRuntime checkout - handler roster.
        try {
            File rtDir = askDirectory(
                "Select ps2xRuntime root for handler-roster check (Cancel to skip)","Open");
            if (rtDir!=null && rtDir.isDirectory()) {
                loadRuntimeHandlerRoster(rtDir);
            } else {
                println("[RUNTIME-ROSTER] Skipped - no runtime folder selected. "+
                        "Stub-vs-handler check disabled.");
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
            // v9: widened name list (SF3 uses AcrMain; nj/SEGA SDK use njUserMain;
            // common bare-C names: app_main / game_main; libc-style __libc_start_main).
            // v12 (C2): expanded list. Demangled C++ ctor name still encoded
            // as `Name__Fv`; behavioral fallback below covers stripped builds.
            String[] mlNames = {
                "mainloop__fv","mainloop","main_loop","MainLoop","Main_Loop",
                "AcrMain","acrmain","app_main","game_main","gameMain",
                "njUserMain","__libc_start_main","mainLoop","GameMain",
                // v12 (C2): Jak / Naughty Dog kernel dispatch + generic shapes.
                "KernelCheckAndDispatch","KernelCheckAndDispatch__Fv",
                "kdispatch","kernel_main","start_kernel","MasterLoop",
                "RunGame","RunGame__Fv","RunLoop","run_loop","RunMain",
                "RunFrame","run_frame","tick","Tick","Tick__Fv",
                "DispatchLoop","Dispatch__Fv","kernel_dispatcher",
                // v11 (C): bare `main` - common in C-based PS2 titles
                // (FF1 Himuro, many mid-2000s ports). Listed last so a more
                // specific GameMain/mainLoop label wins when both exist.
                "main"
            };
            // v12 (C2): name match accepts contains/suffix for engine-mangled
            // forms (e.g. `_KernelCheckAndDispatch__Fv_0x00100130`).
            outer:
            for (Function f : funcManager.getFunctions(true)) {
                String nLow = f.getName().toLowerCase();
                for (String cand : mlNames) {
                    String c = cand.toLowerCase();
                    if (nLow.equals(c) || nLow.startsWith(c+"_0x") ||
                        (c.length() >= 8 && nLow.contains(c))) {
                        mainLoopAddr = f.getEntryPoint();
                        println("[MAINLOOP] Auto-detected by name: "+f.getName()+" @ "+mainLoopAddr);
                        break outer;
                    }
                }
            }
        }
        // v9 behavioral fallback: if no name match, attempt graph-shape detection.
        // Run AFTER scan in run() - defer detection until traits/jalSites built.
        // (Hook below in main scan loop; see resolveMainLoopBehavioral().)
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
        String elfHash = computeElfHash();

        // v15.3 Rule 154: ELF identity guard. If the step1 toml recorded the
        // hash of the ELF it was generated from, compare it with this
        // program's hash. A mismatch means every address-based binding in the
        // input may point at the wrong function (different revision / region
        // ELF) - Rule 151 then catches the per-entry damage, but the global
        // warning surfaces the root cause.
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

        PrintWriter asmWriter   = utf8Writer(new File(outputDir,"assembly.txt"));
        PrintWriter decompWriter = utf8Writer(new File(outputDir,"decompiled.txt"));
        PrintWriter flowWriter  = utf8Writer(new File(outputDir,"flowchart.txt"));

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

                // Rule 9 (v15 REWRITE): step1-classified functions are no
                // longer trusted blindly and skipped. FF1 benchmark: the input
                // toml (made by a name-policy exporter) had stubbed memcpy/
                // strcpy/sprintf, the whole mc* memory-card UI, ScenePrerender
                // /SceneDraw (game render core, name-collided with the "sce"
                // SDK prefix), sceVu0/sceRotMatrix VU0 math, and SKIPPED libm/
                // libgcc/newlib internals (__ieee754_sqrtf, __muldi3,
                // __do_global_ctors). The old `continue` meant these 651
                // functions were never analyzed, never appeared in the triage
                // JSON, and were re-emitted verbatim into the unified TOML.
                // Now: analyze every function; inherit the step1 disposition
                // only if it survives the high-confidence keep gate
                // (step1KeepGateFailure); otherwise rescue to RECOMPILE and
                // comment the entry out of the unified TOML with the reason.
                boolean step1Stub = step1StubAddresses.contains(offset)
                        || step1StubNames.contains(funcName);
                boolean step1Skip = !step1Stub && (step1SkipAddresses.contains(offset)
                        || step1SkipNames.contains(funcName));

                // Rule 18 (v15): override-bound functions are also analyzed
                // and included in the JSON (origin="override") so the triage
                // map is complete; they never enter stub/skip/advisory lists.
                boolean overrideBound = gameOverrideAddresses.contains(offset);

                // v15.3 Rule 158: overlay / out-of-text guards. Overlay blocks
                // reuse the same address range for different code blobs - any
                // address-keyed binding there is unsafe by construction.
                // Out-of-primary-text (non-overlay) bindings are merely
                // suspicious: tagged + reviewed, not vetoed.
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
                // v7.1: add F33-derived firewalls - multi-field ctors and
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
                                       // Rules 140-147: new safety firewalls
                                       || traits.isDynamicCodeLoader            // Rule 161: runtime code linker/loader
                                       || traits.isMemoryAllocator              // Rule 142: never auto-stub allocators
                                       || traits.staticInitInstallsVtable       // Rule 141: uncalled static init vtable installers
                                       || traits.cop2DestMaskVerify             // Rule 140: COP2 partial-dest transforms
                                       || !traits.cop2SpecialOps.isEmpty();     // Rule 147: COP2 special-op review

                // --- Disposition decision ---
                // v13 (SF3-benchmark corrections - all three legacy rules here
                // produced false safe-stubs on real game code):
                //  - refsIopModuleString alone stubbed whole system-init
                //    functions (SF3: system_hard_init = IOP module loads + pad
                //    init + DMA-interrupt-handler install + channel caching).
                //    Only "pure loader" shapes (small, few callees, no MMIO/
                //    handler side effects) are still stub candidates; mixed
                //    init functions stay RECOMPILE.
                //  - hasSyscall||hasCOP0 skipped game interrupt handlers and
                //    critical sections: di/ei/sync/mfc0 appear all over EE game
                //    code (SF3: flPS2DmaInterrupt, flPS2VSyncCallback were
                //    skipped - no rendering, no frame flip). COP0 presence is
                //    not kernel-internal evidence; the recompiler patches COP0
                //    ops anyway (patch_cop0). SKIP now requires the bare
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
                if (overrideBound) {
                    // Already hand-bound in game_override.cpp - record for the
                    // JSON map, make no triage decision.
                    origin = "override";
                    disposition = "OVERRIDE";
                } else if (step1Stub || step1Skip) {
                    origin = "step1";
                    step1Disposition = step1Stub ? "STUB" : "SKIP";
                    // v15.2 Rule 151: name/address mismatch veto. If the step1
                    // entry recorded a different name for this address than
                    // the ELF symbol, the input toml is stale or built for a
                    // different region's ELF (US vs EU/JP address drift) -
                    // binding a handler to the wrong function is the worst
                    // failure mode, so force RECOMPILE + review. Only fires
                    // when the Ghidra name is real (not FUN_/sub_ defaults).
                    String expected = step1NameByAddr.get(offset);
                    boolean nameMismatch = expected != null && !expected.isEmpty()
                            && !funcName.equals(expected)
                            && !funcName.startsWith("FUN_") && !funcName.startsWith("sub_")
                            && !funcName.startsWith("LAB_") && !funcName.startsWith("thunk_");
                    String gateFail;
                    if (inOverlayBlock) {
                        // v15.3 Rule 158: hard veto - overlay address reuse.
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
                } else if (syscallWrapperShape && !inOverlayBlock) {
                    // v15.5 Rule 159: bare syscall trampolines, decided BEFORE
                    // the whitelist/trait-firewall guard. The old order let the
                    // name-substring whitelist ("handler"/"callback") and the
                    // PROCESS_TERMINATOR firewall block classification of
                    // AddIntcHandler/_Exit-style kernel trampolines, and the
                    // old action (auto-SKIP) compiled into a TODO_NAMED
                    // placeholder returning -1, silently losing live kernel
                    // calls (Jak3: GetThreadId). New policy:
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
                        // v15.5 Rule 160: stripped-name recovery. The syscall
                        // immediate decoded from the body (`li $v1,N; syscall`)
                        // is ground truth; when EE_SYSCALL_NAMES[N] resolves to
                        // a handler the runtime implements, bind the ADDRESS to
                        // that handler via the recompiler's documented
                        // "Handler@0xADDR" stub selector - works even when the
                        // ELF symbol is FUN_xxxxxxxx or a wrapper alias
                        // (RFU116_SetSyscall).
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
                    // v15.3 Rule 158: never auto-stub/skip inside overlay blocks.
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
                // v15.5 Rule 159: bare syscall trampoline marker. RECOMPILE-d
                // trampolines route through runtime handleSyscall(); the tag
                // lets the report tool group the kernel-boundary surface.
                if (syscallWrapperShape)
                    {tags.add("SYSCALL_TRAMPOLINE");syscallTrampolineCount++;}
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
                // v9 R7: archive-IO string evidence.
                if (traits.refsArchiveStrings) {
                    tags.add("ARCHIVE_IO");
                    archiveIoCount++;
                }
                // v15.5 Rule 161: dynamic-code loader.
                if (traits.isDynamicCodeLoader) {
                    tags.add("DYNAMIC_CODE_LOADER");
                    dynamicCodeLoaderCount++;
                }
                // v14: SIF RPC packet headers are built with the same
                // 16-byte-stride qword stores as a GIF tag (SF3 benchmark:
                // sceOpen/sceSync landed in force_recompile this way, then
                // corroborated PSMT4HH false positives). If the function
                // talks to SIF RPC and shows zero GIF/VIF/DMA evidence,
                // demote the trait to sifPacketBuilder so every downstream
                // render heuristic (Rule 56, PSM gating, scoring,
                // classification) ignores it.
                if (traits.gifTagInlineBuilder && traits.callsSifRpc &&
                    !traits.writesGifFifo && !traits.writesVif1Fifo &&
                    !traits.writesVif0Fifo && !traits.accessesMMIO &&
                    traits.dmaKickChannels.isEmpty() && !traits.dmaChcrStartKick &&
                    !traits.dmaSourceChainTagBuilder && !traits.bitbltbufMacroSequence &&
                    !traits.path3Initiator && traits.gifTagRegsFields.isEmpty()) {
                    traits.gifTagInlineBuilder = false;
                    traits.sifPacketBuilder = true;
                }
                // v9 R1: GIF tag inline builder.
                if (traits.gifTagInlineBuilder) {
                    tags.add("GIF_TAG_INLINE_BUILDER");
                    gifTagBuilderCount++;
                }
                // v14: informational tag for the demoted case.
                if (traits.sifPacketBuilder) {
                    tags.add("SIF_PACKET_BUILDER");
                }
                // v9 R4: BITBLTBUF macro sequence.
                if (traits.bitbltbufMacroSequence) {
                    if(!tags.contains("BITBLTBUF_MACRO_SEQUENCE"))
                        tags.add("BITBLTBUF_MACRO_SEQUENCE");
                    bitbltbufMacroCount++;
                }
                // v9 R16: VU0 macro helper.
                if (traits.isVu0MacroHelper) {
                    tags.add("VU0_MACRO_HELPER");
                    vu0MacroHelperCount++;
                }
                // v9 R17: C-style struct initializer.
                if (traits.isStructInitializer) {
                    tags.add("STRUCT_INITIALIZER");
                    structInitCount++;
                }
                // v9 R20: infinite spin loop.
                if (traits.isInfiniteSpinLoop) {
                    tags.add("INFINITE_SPIN_LOOP");
                    spinLoopCount++;
                }
                // v10 G1: stored-immediate VIF/DMA tag
                if(!traits.storedVifOpcodes.isEmpty()) {
                    if(!tags.contains("VIF_TAG_STORED_IMMEDIATE"))
                        tags.add("VIF_TAG_STORED_IMMEDIATE");
                    storedVifTagCount++;
                }
                if(!traits.storedDmaTagIds.isEmpty()) {
                    if(!tags.contains("DMA_TAG_STORED_IMMEDIATE"))
                        tags.add("DMA_TAG_STORED_IMMEDIATE");
                    storedDmaTagCount++;
                }
                // v10 bonus: SCE_GIF_SET_TAG composition
                if(traits.buildsGifTag64) {
                    if(!tags.contains("BUILDS_GIF_TAG_64"))
                        tags.add("BUILDS_GIF_TAG_64");
                    gifTag64Count++;
                }
                // v10 bonus: texture upload chunk const
                if(traits.loads70000Chunk) {
                    if(!tags.contains("LOADS_VIF1_CHUNK_70000"))
                        tags.add("LOADS_VIF1_CHUNK_70000");
                    chunk70000Count++;
                }
                // v10 G3: HI/LO consumer
                if(traits.hiLoOps > 0) {
                    if(!tags.contains("HI_LO_CONSUMER"))
                        tags.add("HI_LO_CONSUMER");
                    hiLoConsumerCount++;
                }
                // ===== v11 tags =====
                // E: peripheral categories
                if(traits.accessesRcnt) {
                    tags.add("RCNT_ACCESS"); rcntAccessCount++;
                }
                if(traits.accessesVifCtrl) {
                    tags.add("VIF_CONTROL_REG"); vifCtrlAccessCount++;
                }
                if(traits.accessesDmacGlobal) {
                    tags.add("DMAC_GLOBAL_REG"); dmacGlobalAccessCount++;
                }
                if(traits.writesIntcMask) {
                    tags.add("WRITES_INTC_MASK"); intcMaskWriterCount++;
                }
                if(traits.readsIntcStat) {
                    tags.add("READS_INTC_STAT"); intcStatReaderCount++;
                }
                if(traits.accessesSio) {
                    tags.add("SIO_ACCESS"); sioAccessCount++;
                }
                if(traits.writesDmacEnable) {
                    tags.add("WRITES_DMAC_ENABLE"); dmacEnableWriterCount++;
                }
                if(traits.touchesSbusFlags) {
                    tags.add("SBUS_FLAG_TOUCHER"); sbusFlagAccessCount++;
                }
                // F: source-chain DMA tag builder
                if(traits.dmaSourceChainTagBuilder) {
                    tags.add("DMA_SOURCE_CHAIN_TAG_BUILDER");
                    dmaSourceChainTagCount++;
                }
                // H: format magic
                if(!traits.formatMagicHits.isEmpty()) {
                    tags.add("FORMAT_MAGIC_PARSER");
                    formatMagicHitCount++;
                }
                // I: IRX loader / IOP reboot
                if(traits.isIrxLoader) {
                    tags.add("IRX_LOADER"); irxLoaderCount++;
                }
                if(traits.isIopRebootHandler) {
                    tags.add("IOP_REBOOT_HANDLER"); iopRebootHandlerCount++;
                }
                // J: sync waits
                if(traits.isSyncWaitLoop) {
                    tags.add("BACKWARD_BRANCH_SYNC_WAIT"); syncWaitLoopCount++;
                }
                if(traits.containsInfiniteFailLoop) {
                    tags.add("INFINITE_FAIL_LOOP"); infiniteFailLoopCount++;
                }
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
                // Rule 139: discovered IOP SID via lui+ori composite (beyond whitelist).
                if (!traits.allDetectedSids.isEmpty())
                    {tags.add("DISCOVERED_IOP_SID"); discoveredSidCount++;}

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
                // v13: PSM constants (0x2C/0x24/0x1B/0x13) are tiny integers that
                // appear constantly as struct sizes / loop counts / error codes.
                // Bare matches tagged ~90% of SF3's force list, incl. sceOpen and
                // sceMcRename. Require GS-side corroboration before tagging.
                boolean psm4hhInGsContext = traits.loadsPsm4hhConstant &&
                    (traits.writesTex0Reg || traits.writesBitbltbufReg ||
                     traits.bitbltbufMacroSequence || traits.gifTagInlineBuilder ||
                     traits.buildsGifTag64);
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
                // Rules 140-150: new tags
                if (traits.cop2DestMaskVerify)
                    {tags.add("COP2_DESTMASK_VERIFY"); cop2PartialDestFuncCount++;}
                if (traits.staticInitInstallsVtable)
                    {tags.add("STATIC_INIT_VTABLE_INSTALLER"); staticInitializerFuncCount++;}
                if (traits.isUncalledStaticInit)
                    {tags.add("UNCALLED_STATIC_INIT"); uncalledStaticInitCount++;}
                if (traits.isMemoryAllocator)
                    {tags.add("MEMORY_ALLOCATOR_NEVER_STUB"); memoryAllocatorCount++;}
                if (traits.isGuestLockHogCandidate)
                    {tags.add("GUEST_LOCK_HOG_CANDIDATE"); guestLockHogCount++;}
                if (traits.readsEabiArgT0)
                    {tags.add("EABI_ARG_T0"); eabiArgT0Count++;}
                if (traits.isPsmct16ClutUploader)
                    {tags.add("MAP_CLUT_PSMCT16_UPLOADER"); psmct16ClutUploaderCount++;}
                if (!traits.computedJumpSwitchPcs.isEmpty()) {
                    computedJumpSiteCount += traits.computedJumpSwitchPcs.size();
                    boolean anyUnresolved = false;
                    for(Map.Entry<Long,List<Long>> e : traits.computedJumpTargets.entrySet())
                        if(e.getValue().isEmpty()) { anyUnresolved = true; break; }
                    if(anyUnresolved)
                        {tags.add("COMPUTED_JUMP_UNRESOLVED"); computedJumpUnresolvedCount++;}
                }
                if (!traits.cop2SpecialOps.isEmpty())
                    {tags.add("COP2_SPECIAL_OPS_REVIEW"); cop2SpecialOpFuncCount++;}
                if (traits.usesCop1 && (traits.usesFpuDivSqrt || traits.writesFpuControl))
                    {tags.add("FPU_NONIEEE_SENSITIVE"); fpuNonIeeeCount++;}
                if (traits.isOverlayLoader)
                    {tags.add("OVERLAY_LOADER"); overlayLoaderCount++;}
                // HOST_WAIT_CANDIDATE: sync-wait loop reachable from mainloop.
                if (traits.isSyncWaitLoop && mainLoopShield.contains(offset))
                    tags.add("HOST_WAIT_CANDIDATE");

                // v13: lui-derived VIF opcode matches collide with ordinary
                // global-address materialization (lui 0x60-0x7F == UNPACK is
                // any global above 0x00600000 - SF3 tagged sceMcInit as a VIF
                // builder this way). Require independent VIF/DMA/GIF evidence
                // in the same function before believing the opcode match.
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

                // Rule 56 (v5, extended by v6): derived top-priority bullseye.
                // v6 adds: WRITES_IPU_CMD, GIF_PATH3_REG_TOUCHER, PSMT4HH_REFERENCE,
                // VIF_MPG_OPCODE_BUILDER (microcode upload bullseye).
                if (traits.isSceGifPkRefLoadImage || traits.path3Initiator ||
                    traits.path3KickViaDmaApi || traits.writesDispfbViaSdk ||
                    traits.isBitbltbufT4hhUploader ||
                    (traits.writesZbufReg && (traits.hasShift24Pattern||traits.hasDsll32OrDsrl32)) ||
                    traits.writesGsPrimReg || traits.touchesGifCtrl ||
                    traits.callsMpegFamily || traits.writesIpuCmd ||
                    traits.touchesGifP3Reg || psm4hhInGsContext ||
                    (vifBuilderCorroborated && traits.vifOpcodesBuilt.contains("MPG")) ||
                    traits.bitbltbufMacroSequence || traits.dmaChcrStartKick ||
                    traits.dmaSourceChainTagBuilder || traits.isRenderFrameEntry) {
                    traits.isTopPriorityFix = true;
                    if(!tags.contains("TOP_PRIORITY_FIX")) {
                        tags.add("TOP_PRIORITY_FIX");
                        topPriorityFixCount++;
                    }
                }

                // v15: step1/override provenance tags.
                if ("step1".equals(origin)) {
                    if (rescueReason != null) tags.add("STEP1_RESCUED");
                    else if (step1KeptHostBoundary) {
                        tags.add("STEP1_BOUND_HOST_BOUNDARY");
                        // v15.4: roster-backed keep is hard-bound too.
                        if (runtimeRosterLoaded && hasRuntimeHandler(funcName))
                            tags.add("STEP1_BOUND_ROSTER_HANDLER");
                    }
                    if (step1NameMismatchFlag) tags.add("STEP1_NAME_MISMATCH");
                    if (outOfTextBinding) tags.add("OUT_OF_TEXT_BINDING");
                }
                if (inOverlayBlock) tags.add("OVERLAY_REGION");
                if ("override".equals(origin)) tags.add("OVERRIDE_BOUND");

                FuncResult r = new FuncResult();
                r.address=offset; r.name=funcName; r.category=category;
                r.disposition=disposition; r.traits=traits; r.tags=tags;
                r.origin=origin; r.step1Disposition=step1Disposition;
                r.rescueReason=rescueReason;
                if(rescueReason!=null) r.rescuedBy="step1_keep_gate";
                results.add(r);
            }

            long scanSec = (System.currentTimeMillis()-scanStart)/1000;
            println(String.format("[SCAN] %d functions in %dm%02ds.",totalFuncs,scanSec/60,scanSec%60));
            println(String.format("  New stubs: %d | New skips: %d",radarNewStubs,radarNewSkips));
            println(String.format("  v2 tags: SAFE=%d MMIO=%d ACC=%d SMC=%d SPR=%d VCALLMS=%d JTABLE=%d ORPHAN=%d",
                safeLeafCount,mmioCount,accHazardCount,smcHazardCount,
                sprSyncCount,vcallmsCount,jumpTableCount,orphanCount));
            println(String.format("  v3 tags: CONV_VIOLATION=%d INIT_LARGE=%d DMA_TTE=%d IOP_RPC=%d PAD_POLL=%d THREAD_SYNC=%d",
                conventionViolationCount,initLargeFuncCount,dmaTteRiskCount,
                iopRpcCount,padPollLoopCount,threadSyncCount));
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
            println(String.format("  Rules 140-150: COP2_DESTMASK=%d SINIT=%d UNCALLED_SINIT=%d ALLOC=%d LOCK_HOG=%d EABI_T0=%d PSMCT16_CLUT=%d JUMP_UNRES=%d COP2_SPECOPS=%d FPU_NONIEEE=%d OVERLAY=%d",
                cop2PartialDestFuncCount, staticInitializerFuncCount, uncalledStaticInitCount,
                memoryAllocatorCount, guestLockHogCount, eabiArgT0Count, psmct16ClutUploaderCount,
                computedJumpUnresolvedCount, cop2SpecialOpFuncCount, fpuNonIeeeCount, overlayLoaderCount));

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

            // v15.5 Rule 161b: LAYERED dynamic-code loader detection. Real
            // engines split the idiom across functions (Jak: load_and_link ->
            // FileLoad [file evidence] + link_and_exec -> finish ->
            // CacheFlush__FPvi -> FlushCache [icache flush]), so the
            // same-body Rule 161 never fires. Post-pass over the call graph:
            //   flushReach = functions named FlushCache/iFlushCache, or with
            //     a direct callee prefix-matching FlushCache/iFlushCache/
            //     CacheFlush (catches mangled C++ wrappers), propagated UP
            //     the caller chain <= 3 hops;
            //   evidence   = callsFileOpen/refsArchiveStrings on the function
            //     itself, a direct callee, or a direct caller.
            // Intersection = suspected runtime code loader: tagged, counted,
            // and promoted out of STUB (never out of a hard step1 binding).
            {
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
                    println("  v15.5 Rule 161b: " + dynamicCodeLoaderCount
                        + " suspected dynamic-code loader(s) - this ELF likely loads EE code at runtime.");
            }

            // v4 Rule 39/40: BFS depth from MainLoop and entry/_start.
            // Build forward adjacency once from jalSites, then two BFS passes.
            // F28 wanted exactly this: "what functions live in the MainLoop subtree"
            // - derived by hand last time.
            // v11 (L): pre-scan function-pointer tables so their entries can
            // augment fwd. Without it, BFS misses every function reached only
            // via switch/dispatch table (FF1: ModeSlctInit, TitleCtrl chain,
            // etc. all came up mainloop_depth=-1).
            scanFunctionPointerTables(results, resultsByAddr);
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
                // v11 (L): augment with function-pointer-table entries when
                // caller has TABLE_DISPATCH_CALL OR holds a table-base const.
                if (caller.traits.tableDispatchSites != null && !caller.traits.tableDispatchSites.isEmpty()) {
                    for (String hexBase : caller.traits.tableDispatchSites) {
                        try {
                            long base = Long.parseLong(hexBase.replace("0x","").replace("0X",""), 16);
                            List<Long> entries = functionPointerTables.get(base);
                            if (entries == null) continue;
                            for (Long e : entries) lst.add(e & 0xFFFFFFFFL);
                        } catch (NumberFormatException ignore) {}
                    }
                }
            }
            if (mainLoopAddrOpt != null)
                bfsAssignDepth(fwd, resultsByAddr, mainLoopAddrOpt, true);
            if (entryAddrOpt != null)
                bfsAssignDepth(fwd, resultsByAddr, entryAddrOpt, false);
            // v9 behavioral MainLoop fallback. After init-chain BFS, pick best
            // candidate: reachable depth 1-4 from entry, backward branch,
            // callee_count >= 8, byteSize >= 1500. Score by (callees * size).
            // v12 (C1): run ALWAYS. If a name-matched ml exists, compute its
            // score and only switch when behavioral scores >=2x higher. Avoids
            // the Jak1 case where `main` matched but `KernelCheckAndDispatch`
            // is the real frame-driver loop.
            if (entryAddrOpt != null) {
                FuncResult bestML = null; long bestScore = 0;
                long nameScore = 0;
                for (FuncResult r : results) {
                    if (r.traits == null) continue;
                    FuncTraits t = r.traits;
                    if (t.initChainDepth < 1 || t.initChainDepth > 4) continue;
                    if (!t.hasBackwardBranch) continue;
                    // v11 (C): relaxed thresholds. FF1 main is 148 bytes / 14
                    // callees; old gate (size>=1500, callees>=8) missed it.
                    // New: callees>=6 OR (callees>=4 AND a frame-clock callee).
                    if (t.calleeCount < 6 && !(t.calleeCount >= 4 && t.isFrameClockDriver))
                        continue;
                    long sizeScore = Math.max(t.byteSize, 64);
                    long score = (long)t.calleeCount * sizeScore;
                    if (t.isFrameClockDriver) score *= 4;
                    // v12 (C3): kernel-shape bonus. A small driver loop that
                    // calls another driver (depth-1 dispatcher) is strong.
                    if (t.calleeCount >= 4 && t.hasBackwardBranch &&
                        t.byteSize < 600 && t.callOps >= 2)
                        score = (long)(score * 1.5);
                    if (mainLoopAddrOpt != null &&
                        (r.address & 0xFFFFFFFFL) == mainLoopAddrOpt) {
                        nameScore = score;
                        continue;
                    }
                    if (score > bestScore) { bestScore = score; bestML = r; }
                }
                boolean prefer = false;
                if (mainLoopAddrOpt == null && bestML != null) prefer = true;
                else if (bestML != null && bestScore >= nameScore * 2) prefer = true;
                if (prefer && bestML != null) {
                    long oldAddr = mainLoopAddrOpt == null ? -1 : mainLoopAddrOpt;
                    mainLoopAddrOpt = bestML.address & 0xFFFFFFFFL;
                    println(String.format("[MAINLOOP] Behavioral %s: %s @ 0x%08X (callees=%d size=%d depth=%d score=%d, name_score=%d, prev=0x%08X)",
                        (oldAddr<0 ? "autodetect" : "OVERRIDE"),
                        bestML.name, mainLoopAddrOpt, bestML.traits.calleeCount,
                        bestML.traits.byteSize, bestML.traits.initChainDepth,
                        bestScore, nameScore, oldAddr));
                    bfsAssignDepth(fwd, resultsByAddr, mainLoopAddrOpt, true);
                    Function mlFunc = funcManager.getFunctionAt(
                        currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(mainLoopAddrOpt));
                    if (mlFunc != null) {
                        // v15.3 Rule 156: same depth-3 BFS as the up-front shield.
                        buildMainLoopShield(mlFunc.getEntryPoint());
                    }
                }
            }
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
                // v15: step1 bindings kept on HARD host-boundary evidence
                // (syscall/SIF-RPC/IRX/IPU) are deliberate boundaries - render
                // -chain proximity alone must not unwind them.
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

            // v4 Rule 28: POLL_RETURN_CONSUMER - a tiny returner is likely a
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
                println("  v7 post: GS evidence empty - corroboration skipped.");
            }

            // v12 (A3): rewire callee-name flags using inferred names. For
            // stripped binaries where Ghidra names a function FUN_xxxx but
            // detectSyscallTrampoline recovered the kernel name, propagate
            // that into every caller's flag set (PAD/FRAME/MC/etc.). Without
            // this the firewall lists are inert on stripped builds.
            int aliasMapSize = 0;
            int reflagged = 0;
            {
                Map<Long,String> addr2inferred = new HashMap<>();
                for(FuncResult r : results) {
                    if(r.traits == null) continue;
                    if(r.traits.inferredName != null) {
                        addr2inferred.put(r.address & 0xFFFFFFFFL, r.traits.inferredName);
                        aliasMapSize++;
                    }
                }
                if(!addr2inferred.isEmpty()) {
                    for(FuncResult r : results) {
                        if(r.traits == null) continue;
                        boolean changed = false;
                        for(long[] site : r.traits.jalSites) {
                            String cn = addr2inferred.get(site[1] & 0xFFFFFFFFL);
                            if(cn == null) continue;
                            if(!r.traits.calleeNames.contains(cn)) {
                                r.traits.calleeNames.add(cn);
                                changed = true;
                            }
                            if(PAD_POLL_CALLEES.contains(cn))    r.traits.callsPadPollCallee = true;
                            if(FRAME_CLOCK_CALLEES.contains(cn)) r.traits.isFrameClockDriver = true;
                            if(MC_SDK_CALLEES.contains(cn))     {r.traits.callsMcSdk = true; r.traits.isMcTransitionGate = true;}
                            for(String s : DISPFB_SDK_CALLEES) if(cn.equals(s)) r.traits.writesDispfbViaSdk = true;
                            for(String s : PATH3_KICK_API_CALLEES) if(cn.equals(s)) r.traits.path3KickViaDmaApi = true;
                            if(cn.equals("sceSifCallRpc") || cn.equals("sceSifBindRpc"))
                                r.traits.callsSifRpc = true;
                            if(cn.startsWith("sceDmaSend") || cn.startsWith("sceDmaChain"))
                                r.traits.callsDmaSend = true;
                            if(cn.equals("sceSifLoadModule") || cn.equals("sceSifLoadStartModule"))
                                r.traits.sifLoadModuleCallCount++;
                            if(cn.equals("sceSifRebootIop"))
                                r.traits.isIopRebootHandler = true;
                            for(String p : AUDIO_CALLEE_PREFIXES)
                                if(cn.startsWith(p)) { r.traits.isAudioRpcHandler = true; break; }
                        }
                        if(r.traits.sifLoadModuleCallCount >= 2) r.traits.isIrxLoader = true;
                        if(changed) reflagged++;
                    }
                }
            }
            println(String.format("  v12 A3: inferred_syscall_names=%d, callers_reflagged=%d",
                aliasMapSize, reflagged));

            // v8 Rule 92/94/96/97/99/100/102/111 etc. post-passes.
            runV8PostPasses(results, resultsByAddr, newStubs);

            // ===== v13 binding-consistency firewall =====
            // Runs after ALL tag/trait post-passes so it sees the final
            // evidence. A function the enricher itself flags as render-
            // critical / must-implement / init-chain / callback-target must
            // never stay in the BINDING stubs/skip arrays - those are consumed
            // by the recompiler, while force_recompile is only advisory.
            // SF3 benchmark failures this pass prevents:
            //  - system_hard_init stubbed (init_chain_depth=4 was already
            //    computed and ignored) -> game cannot boot;
            //  - flPS2DmaInterrupt / flPS2VSyncCallback skipped while their
            //    addresses are taken as callback arguments -> no rendering,
            //    no frame flip;
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
                    // them (SF3: 13 SDK wrappers like ChangeThreadPriority
                    // were needlessly recompiled). Address-taken / dispatch /
                    // render evidence still rescues.
                    boolean syscallWrapperShape = t.hasSyscall &&
                            t.byteSize <= 32 && t.callOps == 0;
                    // v15: SIF RPC gateways sit on init chains by construction
                    // (every subsystem binds its RPC channels during boot) -
                    // same logic as the v14 syscall-trampoline exclusion.
                    // Init-chain membership alone must not rescue them;
                    // address-taken / dispatch / render evidence still does.
                    boolean rpcGatewayShape = t.callsSifRpc ||
                            t.detectedRpcSid != 0 || !t.detectedRpcSids.isEmpty();
                    boolean onInitChain = t.initChainDepth >= 0 && t.initChainDepth <= 6;
                    boolean renderOrMustImpl = t.isTopPriorityFix || t.mustBeImplemented ||
                            t.isRenderFrameEntry || t.isVu0MacroHelper ||
                            t.isBitbltbufT4hhUploader || t.isCtorMultiFieldInit ||
                            t.isSceGifPkFamily || t.path3Initiator ||
                            t.writesGifFifo || t.writesVif1Fifo || t.hasVcallms ||
                            // v15.3 Rule 155: GS-dump corroboration - this
                            // function's TBP/PSM signature was observed in an
                            // actual runtime capture; stubbing it provably
                            // kills uploads that happen on real hardware.
                            r.tags.contains("RUNTIME_CONFIRMED");
                    boolean dispatchTarget = r.tags.contains("DISPATCH_TABLE_TARGET");
                    // v15: step1 bindings kept on hard host-boundary evidence
                    // are deliberate. v15.4: address-taken no longer unwinds
                    // them either - PS2Recomp dispatch is address-keyed, so an
                    // indirect call through a taken pointer still lands on the
                    // bound runtime handler (the FF1 rerun showed addressTaken
                    // firing on EVERY 16-byte kernel wrapper: SetSyscall-style
                    // vector installs take their addresses legitimately).
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
                println("  v13 firewall: "+rescued+" stub/skip entries rescued to RECOMPILE "+
                        "(address-taken / dispatch-target / init-chain / render-critical).");
            }

            // v15: step1 vetting summary.
            {
                int s1kept=0, s1rescued=0, ovr=0;
                for(FuncResult r : results) {
                    if("step1".equals(r.origin)) {
                        if(r.rescueReason!=null) s1rescued++; else s1kept++;
                    } else if("override".equals(r.origin)) ovr++;
                }
                println("  v15 step1 vetting: "+s1kept+" inherited bindings kept (host-boundary evidence), "
                        +s1rescued+" rescued to RECOMPILE, "+ovr
                        +" override-bound - all now analyzed and included in the JSON.");
                if(step1NameMismatchCount>0)
                    println("  v15.2 Rule 151: "+step1NameMismatchCount
                            +" step1 name/address mismatches (stale or wrong-region input?) - forced RECOMPILE + review.");
            }

            // v15.3 Rule 153: handler-roster cross-check. Runs after every
            // promote pass so it sees FINAL stub dispositions. A stub routes
            // to a runtime handler BY NAME - no handler in the roster means
            // the call dies silently at runtime. We do not unbind (the stub
            // may be a planned implementation); we surface it loudly:
            // NO_RUNTIME_HANDLER tag -> native_impl_needed + review.
            if (runtimeRosterLoaded) {
                for (FuncResult r : results) {
                    if (!"STUB".equals(r.disposition)) continue;
                    if (hasRuntimeHandler(r.name)) continue;
                    // v15.5 Rule 160: trampolines bound by inferred syscall
                    // name route to that handler, not the ELF symbol.
                    if (r.traits != null && r.traits.inferredName != null
                        && hasRuntimeHandler(r.traits.inferredName)) continue;
                    if (!r.tags.contains("NO_RUNTIME_HANDLER")) {
                        r.tags.add("NO_RUNTIME_HANDLER");
                        noHandlerStubCount++;
                    }
                }
                println("  v15.3 Rule 153: roster="+runtimeHandlerNames.size()
                        +" handlers; "+noHandlerStubCount
                        +" bound stubs have NO matching runtime handler (-> native_impl_needed + review).");
            }
            if (overlayVetoCount>0 || outOfTextBindingCount>0)
                println("  v15.3 Rule 158: overlay vetoes="+overlayVetoCount
                        +", out-of-text bindings flagged="+outOfTextBindingCount+".");

            // v9: collect nop, patch, force_recompile from final result set.
            // v12 (G1): patchInstrCandidates carries (pc, funcAddr, reasonMask)
            // entries for backward-branch nop patches.
            List<String> nopList = new ArrayList<>();
            List<String> patchList = new ArrayList<>();
            List<String> forceRecompList = new ArrayList<>();
            // v14: native_impl_needed - stubbing/skipping these leaves a
            // subsystem hole (IOP module load, SIF RPC service, audio/pad/mc
            // gateway) that the recomp runtime must fill with a native
            // implementation. Advisory only; surfaces what a stub silences.
            List<String> nativeImplList = new ArrayList<>();
            // v14: review - firewall-rescued entries and mixed IRX-init
            // functions; the cases where the enricher overrode or refused a
            // binding decision and a human should confirm.
            List<String> reviewList = new ArrayList<>();
            List<long[]> patchInstrCandidates = new ArrayList<>();
            for(FuncResult r : results) {
                if(r.traits == null) continue;
                // v15: override-bound functions already have a hand-written
                // handler - never emit them into advisory arrays.
                if("OVERRIDE".equals(r.disposition)) continue;
                String entry = r.name + "@" + hex(r.address);
                // v12 (K): priority-sorted tag preview. Most actionable tags
                // surface first (TOP_PRIORITY_FIX, BITBLTBUF_T4HH_UPLOADER,
                // render bullseyes), so the 4-tag truncation never drops the
                // most-important hint.
                String tagComment = r.tags.isEmpty() ? "" :
                    " # " + String.join(",", prioritizeTagsForComment(r.tags, 4));
                // libgcc intrinsics are nop-stub candidates only if NOT inside
                // call chain (auto: emit as nop here, runtime can override).
                // We keep them in stubs by default; nop list reserved for true
                // no-ops like __ct__ chained-stub returners.
                if(r.traits.isLibgccIntrinsic && "STUB".equals(r.disposition)) {
                    nopList.add(entry + tagComment);
                }
                // Patch candidates: convention-violation single-instruction fixes.
                if(r.traits.writesToA1Buffer && r.traits.byteSize < 50) {
                    patchList.add(entry + tagComment);
                }
                // force_recompile: must_be_implemented OR top-priority bullseye OR
                // BITBLTBUF uploader / CTOR_MULTI_FIELD_INIT.
                // v12 (K): also promote ARCHIVE_IO wrappers + render-path bullseyes.
                boolean renderBullseye = r.traits.isSceGifPkFamily ||
                                         r.traits.path3Initiator ||
                                         r.traits.writesGifFifo ||
                                         r.traits.writesVif1Fifo ||
                                         (r.traits.accessesVuMicromem && r.traits.hasMutatingInstructions);
                boolean archiveIo = r.traits.refsArchiveStrings && r.traits.calleeCount >= 2;
                // v13: never emit a function into the advisory force_recompile
                // list while it sits in the binding stubs/skip arrays. The v13
                // firewall already rescued everything with hard evidence; what
                // remains stubbed (e.g. pure IRX-loader shapes) must not be
                // contradicted one section lower in the same TOML.
                boolean boundToStubOrSkip = "STUB".equals(r.disposition) || "SKIP".equals(r.disposition);
                if(!boundToStubOrSkip &&
                   (r.traits.mustBeImplemented || r.traits.isTopPriorityFix ||
                    r.traits.isBitbltbufT4hhUploader || r.traits.isCtorMultiFieldInit ||
                    r.traits.isVu0MacroHelper || r.traits.isRenderFrameEntry ||
                    renderBullseye || archiveIo)) {
                    forceRecompList.add(entry + tagComment);
                }
                // v14: native_impl_needed collection. Two ways in:
                //  (a) bound stub/skip whose traits show it fronted an IOP-side
                //      subsystem (IRX loader string, SIF RPC, audio RPC) - the
                //      stub is intentional but the subsystem now needs a host
                //      implementation;
                //  (b) recompiled RPC binder/IRX loader - the EE side will run,
                //      but only works if the runtime services its RPC SIDs /
                //      module loads natively.
                boolean rpcGateway = r.traits.callsSifRpc ||
                        r.traits.detectedRpcSid != 0 ||
                        !r.traits.detectedRpcSids.isEmpty();
                boolean iopSubsystemFront = r.traits.refsIopModuleString ||
                        r.traits.isIrxLoader || r.traits.sifLoadModuleCallCount >= 1 ||
                        r.traits.isAudioRpcHandler || r.traits.isIopRebootHandler;
                // v15.3 Rule 153: stub with no matching runtime handler.
                boolean noHandlerStub = r.tags.contains("NO_RUNTIME_HANDLER");
                if((boundToStubOrSkip && (iopSubsystemFront || rpcGateway || noHandlerStub)) ||
                   (!boundToStubOrSkip && (r.traits.isIrxLoader ||
                        r.traits.detectedRpcSid != 0 || !r.traits.detectedRpcSids.isEmpty()))) {
                    nativeImplList.add(entry + tagComment);
                }
                // v14: review collection - firewall rescues + mixed IRX-init
                // shapes (IRX string present but too much other work to stub).
                boolean pureLoaderShape = r.traits.refsIopModuleString &&
                        r.traits.byteSize <= 200 && r.traits.calleeCount <= 4 &&
                        !r.traits.accessesMMIO && !r.traits.writesIntcMask &&
                        r.traits.dmaKickChannels.isEmpty();
                boolean mixedIrxInit = r.traits.refsIopModuleString && !pureLoaderShape;
                // v15: step1 rescues also go to review - the enricher overrode
                // the input toml's binding and a human should confirm.
                // v15.3: + Rule 153 handler-less stubs and Rule 158
                // out-of-text bindings.
                if(r.tags.contains("BINDING_FIREWALL_RESCUED") || mixedIrxInit ||
                   r.tags.contains("STEP1_RESCUED") ||
                   r.tags.contains("NO_RUNTIME_HANDLER") ||
                   r.tags.contains("OUT_OF_TEXT_BINDING") ||
                   // v15.4: kept-but-address-taken bindings - verify the
                   // pointer use is a SetSyscall-style install, not a vtable.
                   r.tags.contains("ADDRESS_TAKEN_CALLBACK")) {
                    reviewList.add(entry + tagComment);
                }
                // v12 (G1): collect candidate patch instructions from hazard
                // tags. Reason mask: 1=IFL, 2=ISL, 4=BBSW, 8=BWH.
                long reason = 0;
                if(r.traits.containsInfiniteFailLoop) reason |= 0x1;
                if(r.traits.isInfiniteSpinLoop)       reason |= 0x2;
                if(r.traits.isSyncWaitLoop)           reason |= 0x4;
                if(r.traits.hasBusyWait)              reason |= 0x8;
                if(reason != 0) {
                    for(Long pc : r.traits.patchCandidatePcs) {
                        patchInstrCandidates.add(new long[]{pc, r.address & 0xFFFFFFFFL, reason});
                    }
                }
            }
            // v9 T3 inline tags: append per-stub tag comment.
            List<String> annotatedStubs = new ArrayList<>(newStubs);
            List<String> annotatedSkips = new ArrayList<>(newSkips);
            // v15.2: hand the advisory lists to the JSON writer - the JSON is
            // the detailed source of truth; the TOML stays executable-only
            // (unless EMIT_VERBOSE_TOML_ADVISORY).
            advisoryNop = nopList;
            advisoryPatch = patchList;
            advisoryForceRecomp = forceRecompList;
            advisoryNativeImpl = nativeImplList;
            advisoryReview = reviewList;
            advisoryPatchInstr = patchInstrCandidates;
            // (keep raw lists for back-compat; comments handled inside writer)
            writeUnifiedConfig(unifiedToml,configToml,annotatedStubs,annotatedSkips,
                               nopList,patchList,forceRecompList,
                               nativeImplList,reviewList,patchInstrCandidates);
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

        // priv regs (PMODE/IMR/CSR) - string hex form
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
     * Rule 80: per-function corroboration. Decoration only - no disposition
     * flip. Predictions checked:
     *  * PSMT4HH_REFERENCE         <-> any checkpoint witness PSMT4HH (44)
     *  * MICROCODE_UPLOADER / VIF_*_BUILDER <-> any path1/path2 witness
     *  * PATH3_INITIATOR / GIF_PATH3_HAZARD <-> any path3 witness +
     *                                          (prim_garbage in any cp for hazard)
     *  * MPEG_DECODER_TRAP / IPU   <-> readfifo2 OR ipuActive
     *  * TEX0_REG_WRITER + tbp constants <-> tex0_tbps_union / vram_tbps_union
     *  * SIGNAL/FINISH/LABEL handler names <-> imrAllMaskedGsIrqs -> safe-stub
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
                // TEX0 writers are confirmed if game uploaded *any* tex data -
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
            // menu-only - they also occur during 3D scene loads. Same for any
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
    // Rule 98: enhanced 2-pass override parser. Pass 1 collects bindings.
    // Pass 2 classifies handler bodies (nop_stub/constant_return/state_machine/probe/real_shim).
    private void parseGameOverrideFile(File f) throws IOException {
        BufferedReader reader = utf8Reader(f);
        List<String> allLines = new ArrayList<>();
        String line;
        while((line = reader.readLine()) != null) allLines.add(line);
        reader.close();

        for(int i = 0; i < allLines.size(); i++) {
            String t = allLines.get(i).trim();
            if(!t.contains("bindAddressHandler") && !t.contains("registerFunction")) continue;
            long addr = extractFirstHexLiteral(t);
            if(addr <= 0) continue;
            String name = extractQuotedString(t);
            gameOverrideAddresses.add(addr);
            if(name != null && !name.isEmpty()) gameOverrideNames.put(addr, name);
            gameOverrideImportedCount++;
            String handler = extractHandlerSymbol(t);
            if(handler != null) overrideHandlerNames.put(addr, handler);
        }

        for(Map.Entry<Long,String> e : overrideHandlerNames.entrySet()) {
            String kind = classifyHandlerBody(e.getValue(), allLines);
            overrideKindByAddr.put(e.getKey(), kind);
            overrideClassifiedCount++;
            if("nop_stub".equals(kind) || "probe".equals(kind)) overrideRetireCount++;
        }
    }

    private String extractHandlerSymbol(String line) {
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
        String lower = handlerName.toLowerCase();
        if(lower.contains("nop_stub") || lower.endsWith("_nop")) return "nop_stub";
        if(lower.contains("probe")) return "probe";
        if(lower.contains("state_machine") || lower.contains("state_step")) return "state_machine";
        if(lower.contains("const_return") || lower.endsWith("_zero")) return "constant_return";
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
        int bodyLines=0, returnsConst=0, callOps=0, traceLogs=0, conditionals=0;
        for(int i = start; i < Math.min(start+60, lines.size()); i++) {
            String t = lines.get(i);
            if(t.contains("}") && bodyLines > 4) break;
            bodyLines++;
            if(t.matches(".*return\\s+\\d+.*")) returnsConst++;
            if(t.contains("(*ctx") || t.contains("ctx->")) callOps++;
            if(t.contains("LOG")||t.contains("trace")||t.contains("println")||t.contains("getenv(")) traceLogs++;
            if(t.contains("if(")||t.contains("if (")||t.contains("switch(")||t.contains("switch (")) conditionals++;
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
    // v15.3 Rule 153: RUNTIME-HANDLER ROSTER SCRAPE
    // Walks a ps2xRuntime checkout and collects every handler name the
    // runtime actually implements. Sources of names:
    //   (a) `void Name(R5900Context& ...)`            - classic handler def
    //   (b) `void Name(uint8_t* rdram, R5900Context*` - raw wrapper def
    //   (c) bindAddressHandler(..., "Name")            - name-routed binding
    //   (d) ps2_stubs::Name                            - stub-namespace refs
    // NEVER descends into runner/ or build dirs (30k generated files).
    // =========================================================
    private void loadRuntimeHandlerRoster(File root) {
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
        while ((line=reader.readLine())!=null) {
            String t=line.trim();
            // v15.3 Rule 154: exporter-embedded ELF identity.
            if (t.startsWith("elf_hash")) {
                int q1=t.indexOf('"'),q2=t.lastIndexOf('"');
                if (q1>=0 && q2>q1) step1ElfHash=t.substring(q1+1,q2).trim().toLowerCase();
                continue;
            }
            // v15.5: single-line arrays (`stubs = ["a@0x1", "b@0x2"]` or
            // `stubs = []`) are valid TOML and appear in hand-edited and
            // third-party exporter configs; the old line-based parser
            // silently dropped every entry on such lines (and mis-tracked
            // the open-array state). Inline entries are consumed here.
            if (t.startsWith("stubs")||
                (t.startsWith("skip")&&!t.startsWith("skip_count"))) {
                boolean stubsArr = t.startsWith("stubs");
                if (t.contains("[") && t.contains("]")) {
                    // fully inline array
                    String body = t.substring(t.indexOf('[')+1, t.lastIndexOf(']'));
                    java.util.regex.Matcher m =
                        java.util.regex.Pattern.compile("\"((?:[^\"\\\\]|\\\\.)*)\"").matcher(body);
                    while (m.find()) addStep1Entry(m.group(1), stubsArr);
                    inStubs=false; inSkip=false;
                } else {
                    inStubs=stubsArr; inSkip=!stubsArr;
                }
                continue;
            }
            if (t.equals("]")||t.startsWith("]")){inStubs=false;inSkip=false;continue;}
            if (!inStubs&&!inSkip) continue;
            int q1=t.indexOf('"'),q2=t.lastIndexOf('"');
            if (q1<0||q2<=q1) continue;
            addStep1Entry(t.substring(q1+1,q2), inStubs);
        }
        reader.close();
        // v15.2 Rule 152: dual-binding hygiene - an address (or name) listed
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

    /** v15.5: shared step1 entry recorder ("name" or "name@0xADDR"). */
    private void addStep1Entry(String entry, boolean isStubArray) {
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
        // v15.2 Rule 151: remember the expected name per address.
        if (addr >= 0 && !name.isEmpty()) step1NameByAddr.putIfAbsent(addr, name);
    }

    // =========================================================
    // RULE 11: MAINLOOP SHIELD
    // v15.3 Rule 156: extended from depth-1 (direct callees only) to a
    // depth-3 BFS, capped. Per-frame wrappers two hops below the loop (FF1:
    // GameMain -> ModeIngame -> SceneDraw) were stub-eligible before. The
    // shield only suppresses ENRICHER stub/skip decisions and feeds the
    // step1 whitelist rescue; SDK boundaries with HARD evidence (syscall /
    // SIF RPC / IRX / IPU) keep their stubs regardless - the step1 keep gate
    // checks hard evidence BEFORE the whitelist (see step1KeepGateFailure).
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
            // v11 (I): IRX module loader / IOP reboot detection.
            if(IRX_LOAD_CALLEES.contains(cn) || cn.equals("_sceSifLoadModule"))
                traits.sifLoadModuleCallCount++;
            if(IOP_REBOOT_CALLEES.contains(cn))
                traits.isIopRebootHandler = true;
            // v12 (F2): behavioral MC gate - any call to a memory-card SDK fn.
            if(MC_SDK_CALLEES.contains(cn))
                traits.callsMcSdk = true;
        }
        // v11 (I): >=2 sceSifLoadModule calls = IRX loader bootstrap.
        if(traits.sifLoadModuleCallCount >= 2) traits.isIrxLoader = true;
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
        // Forced RECOMPILE downstream - auto-stub halts the runner on first call (F23a).
        if(fname.startsWith("__")) {
            String n=fname;
            if(n.matches("__(u?div|u?mod|mul|neg|abs|cmp)(di|si|hi|qi)[23]") ||
               n.matches("__(fix|float)(df|sf|si|di)(df|sf|si|di)"))
                traits.isLibgccIntrinsic=true;
        }

        // v4 Rule 34: MPEG / IPU / DVD callee scan (decoder trap)
        for(String cn : traits.calleeNames) {
            for(String p : MPEG_CALLEE_PREFIXES)
                if(cn.startsWith(p)) { traits.callsMpegFamily=true; break; }
            if(traits.callsMpegFamily) break;
        }

        // v5 Rule 43: bullseye for the Path3 4HH guard. Match bare name or
        // Ghidra-mangled `sceGifPkRefLoadImage_0xADDR`.
        if(fname.equals(SCE_GIF_PK_REF_LOAD_IMAGE) ||
           fname.startsWith(SCE_GIF_PK_REF_LOAD_IMAGE+"_0x"))
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
        // v12 (F2): behavioral MC gate - any function calling MC SDK.
        if(traits.callsMcSdk) traits.isMcTransitionGate = true;

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
            // R16: VU0 macro instruction mix counter.
            if(ml.startsWith("v")||ml.equals("qmtc2")||ml.equals("qmfc2")||
               ml.equals("lqc2")||ml.equals("sqc2")||ml.equals("cfc2")||ml.equals("ctc2"))
                traits.vu0MacroOps++;
            // R19: float-compare cluster counter.
            if(ml.startsWith("c.")) traits.floatCmpOps++;
            // G3 v10: HI/LO consumer count.
            if(ml.equals("mflo")||ml.equals("mfhi")||ml.equals("mthi")||ml.equals("mtlo")||
               ml.equals("mflo1")||ml.equals("mfhi1"))
                traits.hiLoOps++;
            // G3 v10: opcode histogram - capped to top-N at emit.
            traits.opcodeHistogram.merge(ml, 1, Integer::sum);
            // v10 bonus: 64-bit GIF tag composition. `dsll32` followed within
            // 3 instructions by an `ori` against the same register marks the
            // bit-shift+merge half of SCE_GIF_SET_TAG.
            if(ml.equals("dsll32") || ml.equals("dsrl32")) {
                Instruction nx = inst.getNext();
                int look = 0;
                while(nx != null && look < 3) {
                    String nmn = nx.getMnemonicString();
                    if(nmn != null && nmn.equalsIgnoreCase("ori")) {
                        traits.hasDsll32OrSequence = true;
                        traits.buildsGifTag64 = true;
                        break;
                    }
                    nx = nx.getNext();
                    look++;
                }
            }
            // v10 bonus: texture-upload chunk-size const (VIF1 LoadImage = 0x70000).
            if(ml.equals("lui") || ml.equals("ori") || ml.equals("addiu") || ml.equals("li")) {
                for(Object op : inst.getInputObjects()) {
                    if(!(op instanceof ghidra.program.model.scalar.Scalar)) continue;
                    long v = ((ghidra.program.model.scalar.Scalar)op).getUnsignedValue();
                    if(v == 0x70000L || (ml.equals("lui") && v == 0x0007L)) {
                        traits.loads70000Chunk = true;
                        break;
                    }
                }
            }

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

            // Rule 140: VU0-macro COP2 partial-destination write detection (F51.8
            // root cause: recompiler emitted dest-component blend mask reversed).
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
            // Rule 147: COP2 special-op / latency hazards (vdiv/vsqrt/vrsqrt/
            // vclipw/vrnext/vmr32/vwaitq/vopmsub/xgkick).
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
            // Rule 148: EE FPU non-IEEE semantics. ctc1/cfc1 write FPU control;
            // div.s/sqrt.s/rsqrt.s diverge from host IEEE for denormals/NaN/rounding.
            if(ml.equals("ctc1")||ml.equals("cfc1")) traits.writesFpuControl=true;
            if(ml.equals("div.s")||ml.equals("sqrt.s")||ml.equals("rsqrt.s")) traits.usesFpuDivSqrt=true;

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
                    // Rule 146: harvest Ghidra-resolved jump-table targets so the
                    // recompiler can pre-populate computed-jump dispatch.
                    long sitePc = inst.getAddress().getOffset() & 0xFFFFFFFFL;
                    traits.computedJumpSwitchPcs.add(sitePc);
                    List<Long> tgts = new ArrayList<>();
                    for(Reference jr : inst.getReferencesFrom()) {
                        if(traits.computedJumpSwitchPcs.size() > 512) break;
                        if(jr.getReferenceType().isJump()) {
                            long t = jr.getToAddress().getOffset() & 0xFFFFFFFFL;
                            if(t != sitePc) tgts.add(t);
                        }
                    }
                    traits.computedJumpTargets.put(sitePc, tgts);
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

            // v4 Rule 38: jalr $t9 - PIC / vtable indirect call.
            // v8 Rule 89: accept ANY jalr regardless of flow type; both $t9 PIC
            // and any other register are counted as indirect dispatch.
            if(ml.equals("jalr")) {
                for(Object op : inst.getInputObjects())
                    if(op instanceof ghidra.program.model.lang.Register) {
                        String rn = ((ghidra.program.model.lang.Register)op).getName().toLowerCase();
                        if(rn.equals("t9")) traits.indirectCallT9Count++;
                    }
                // v8 Rule 94: virtual dispatch site capture - jalr $rX where the
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

            // v8 Rule 97: pad button mask consumer - andi/and immediate matches
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
                    if(target.getOffset()<inst.getAddress().getOffset()) {
                        traits.hasBackwardBranch=true;
                        // v12 (G1): record the backward branch PC so the patches
                        // emit pass can synthesise a candidate `[patches.instructions]`
                        // entry to NOP the spin / wait loop.
                        if(traits.patchCandidatePcs.size() < 4)
                            traits.patchCandidatePcs.add(inst.getAddress().getOffset() & 0xFFFFFFFFL);
                    }
                }
            }

            // v13: count all store forms (incl. sd/sq) for spin-loop gating.
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
                // Phase F22 mgCCamera ctor was nop_stubbed -> null vtable -> pc-zero.
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
                // duplicate flows for jalr through a switch / delay-slot quirk - that
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
                    // v11 fix (A): old code treated (norm - 0x12000000) as a
                    // GIF A+D reg id. WRONG - those ids are payload encodings,
                    // not MMIO offsets. 0x12000000 is PMODE (priv reg), not PRIM.
                    // gsRegHits retained for backward compat reports but the
                    // PRIM/TEX0/RGBAQ/ZBUF flag-setting moved to detectAdRegPayloadWriters
                    // (post-scan) which inspects qword AD-mode store-imm pairs.
                    if(norm>=MMIO_GS_START&&norm<=MMIO_GS_END) {
                        long reg = (norm - MMIO_GS_START) & 0xFFFFL;
                        String name = KNOWN_GS_REGS.get(reg);
                        if(name!=null) traits.gsRegHits.add(name);
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
                    // v5 Rule 44: PATH3 initiator - any write to GIF CHCR range
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
                    // v11 (E): MSFLG/SMFLG too - same EE<->IOP comm block.
                    if(norm == SBUS_MSFLG || norm == SBUS_SMFLG)
                        traits.touchesSbusFlags = true;
                    // v11 (E): peripheral category tagging.
                    if(norm >= RCNT_RANGE_START && norm <= RCNT_RANGE_END)
                        traits.accessesRcnt = true;
                    if((norm >= VIF0_CTRL_START && norm <= VIF0_CTRL_END) ||
                       (norm >= VIF1_CTRL_START && norm <= VIF1_CTRL_END))
                        traits.accessesVifCtrl = true;
                    if(norm >= DMAC_GLOBAL_START && norm <= DMAC_GLOBAL_END)
                        traits.accessesDmacGlobal = true;
                    if(norm == INTC_MASK_ADDR && ref.getReferenceType().isWrite())
                        traits.writesIntcMask = true;
                    if(norm == INTC_STAT_ADDR && ref.getReferenceType().isRead())
                        traits.readsIntcStat = true;
                    if(norm >= SIO_RANGE_START && norm <= SIO_RANGE_END)
                        traits.accessesSio = true;
                    if(norm >= DMAC_EXT_START && norm <= DMAC_EXT_END &&
                       ref.getReferenceType().isWrite())
                        traits.writesDmacEnable = true;
                }

                // Rule 22: SID literal scan near sceSifBindRpc calls
                // Look for lui+addiu pattern yielding a value matching a known SID
                if(traits.callsSifRpc&&ref.getReferenceType().isData()) {
                    long candidate=ref.getToAddress().getOffset()&0xFFFFFFFFL;
                    if(KNOWN_IOP_SIDS.containsKey(candidate))
                        traits.detectedRpcSid=candidate;
                }
            }

            // ===== v6 Rule 67-73 (FIXED v9): lui/ori/addiu/li constant scan.
            // Was previously nested inside the per-Reference loop - fired only
            // when Ghidra resolved the immediate to a memory ref. Pure constants
            // (VIF opcodes, DMA tag IDs, PSM codes) have NO ref, so the scan was
            // dead. Now top-level per-instruction.
            //
            // v9 fixes:
            //  - REFE (DMA_TAG_IDS key 0x00) only matched when highByte >= 0x10,
            //    avoiding false positive on every lui $rN, 0x00XX (very common).
            //  - Const-load list (R11) captured per (pc, value, dest_reg).
            if(ml.equals("lui") || ml.equals("ori") ||
               ml.equals("addiu") || ml.equals("daddiu") || ml.equals("li")) {
                long constImm = -1;
                String destReg = null;
                boolean srcZero = false;
                Object[] dops = inst.getOpObjects(0);
                if(dops!=null && dops.length>0 && dops[0] instanceof ghidra.program.model.lang.Register)
                    destReg = ((ghidra.program.model.lang.Register)dops[0]).getName();
                for(Object op : inst.getInputObjects()) {
                    if(op instanceof ghidra.program.model.scalar.Scalar)
                        constImm = ((ghidra.program.model.scalar.Scalar)op).getUnsignedValue();
                    else if(op instanceof ghidra.program.model.lang.Register &&
                            ((ghidra.program.model.lang.Register)op).getName().equalsIgnoreCase("zero"))
                        srcZero = true;
                }
                if(constImm >= 0) {
                    // R11: emit raw const for downstream tooling.
                    traits.constLoads.add(new long[]{
                        inst.getAddress().getOffset(), constImm,
                        destReg != null ? destReg.hashCode() : 0
                    });
                    if(destReg != null)
                        traits.constLoadDestRegs.add(destReg);

                    // R15: SPR const detect (0x7000 high-half via lui).
                    if(ml.equals("lui") && constImm == 0x7000L)
                        traits.usesSPR = true;

                    if(ml.equals("lui") || ml.equals("ori")) {
                        if(ml.equals("ori") && constImm > 0 && constImm <= 0x3FFFL)
                            traits.tbpConstantsLoaded.add(constImm);
                        long highByte;
                        if(ml.equals("lui")) {
                            highByte = (constImm >> 8) & 0xFFL;
                        } else {
                            highByte = (constImm >> 8) & 0xFFL;
                            if(constImm == PSMT4HH || constImm == PSMT4HL ||
                               constImm == PSMT8H || constImm == 0x13L)
                                traits.loadsPsm4hhConstant = true;
                        }
                        // v11 fix (B): highByte=0 matches VIF NOP, which is
                        // every `lui $r,0x0000` - 2,361 false positives on FF1.
                        // Skip NOP; require highByte >= 0x01. Also require lui+ori
                        // composite (constLoadDestRegs hit twice) OR a non-NOP
                        // opcode value to confirm it's a real builder.
                        if(highByte >= 0x01L) {
                            String vifName = VIF_OPCODES.get(highByte);
                            if(vifName != null) traits.vifOpcodesBuilt.add(vifName);
                            if(highByte >= 0x60L && highByte <= 0x7FL)
                                traits.vifOpcodesBuilt.add("UNPACK");
                        }
                        // v9 REFE-guard: require highByte >= 0x10 to suppress
                        // the lui-of-0x00XX false-positive flood.
                        if(ml.equals("lui") && highByte >= 0x10L) {
                            long tagPrefix = highByte & 0xF0L;
                            String dmaName = DMA_TAG_IDS.get(tagPrefix);
                            if(dmaName != null) traits.dmaTagIdsBuilt.add(dmaName);
                        }
                        // R2 DMA_CHCR_START_KICK fingerprint: 0x101 (CHCR start
                        // bit). Combined with mmio/data-ref base later.
                        if(constImm == 0x101L) traits.loadsChcrStartConst = true;
                    }
                    if(ml.equals("addiu") || ml.equals("daddiu") || ml.equals("li")) {
                        if((srcZero || ml.equals("li"))) {
                            if(constImm == PSMT4HH || constImm == PSMT4HL ||
                               constImm == PSMT8H || constImm == 0x13L)
                                traits.loadsPsm4hhConstant = true;
                            if(constImm > 0 && constImm <= 0x3FFFL)
                                traits.tbpConstantsLoaded.add(constImm);
                            if(constImm == 0x101L) traits.loadsChcrStartConst = true;
                        }
                    }
                }
            }

            // v5 Rule 52/53 + v9 R7/R8: scan all string refs.
            //  - meswin / audio / archive-ext detection
            //  - per-function string sample list (cap 16, len 80)
            for(Reference ref:inst.getReferencesFrom()) {
                Data data=getDataAt(ref.getToAddress());
                if(data==null || !data.hasStringValue()) continue;
                String str = data.getDefaultValueRepresentation();
                if(str == null) continue;
                if(!traits.refsMeswinStrings)
                    for(String s:MESWIN_STRINGS)
                        if(str.contains(s)){traits.refsMeswinStrings=true;break;}
                if(!traits.isAudioRpcHandler)
                    for(String s:AUDIO_MODULE_STRINGS)
                        if(str.contains(s)){traits.isAudioRpcHandler=true;break;}
                // R7: archive-extension fingerprint
                for(String ext:ARCHIVE_EXTS) {
                    if(str.contains(ext)) {
                        traits.archiveStringExts.add(ext);
                        traits.refsArchiveStrings=true;
                    }
                }
                // v12 (E1): behavioral asset-name detector. Token-split on
                // path separators / spaces / quotes; check each token against
                // the uppercase basename + extension regex. Captures any
                // SHORTNAME.EXT regardless of curated ext list.
                String[] toks = str.split("[\\s/\\\\:\";]+");
                for(String tok : toks) {
                    if(tok.isEmpty() || tok.length() > 24) continue;
                    if(ASSET_NAME_REGEX.matcher(tok).matches()) {
                        traits.discoveredAssetPaths.add(tok);
                        traits.refsArchiveStrings = true;
                        if(traits.discoveredAssetPaths.size() >= 16) break;
                    }
                }
                // v11 (I): capture IRX module paths inline.
                String upper = str.toUpperCase();
                if(upper.contains(".IRX") || upper.contains(".IMG")) {
                    if(traits.irxModulePaths.size() < 16)
                        traits.irxModulePaths.add(str);
                }
                // R8: sample up to 16 strings for engineer recovery
                if(traits.stringRefs.size() < 16) {
                    String trimmed = str.length() > 80 ? str.substring(0, 80) : str;
                    if(!traits.stringRefs.contains(trimmed))
                        traits.stringRefs.add(trimmed);
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
            // lui ops - quick proxy via instruction iterator second pass would
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

        // v8 Rule 88: libgcc intrinsic exact-name match.
        if(LIBGCC_EXACT_NAMES.contains(fname))
            traits.isLibgccIntrinsic = true;

        // v8 Rule 108: GCC2 C++ demangler and population.
        demangleAndPopulate(fname, traits);

        // v8 Rule 92: ctor vtable install pattern check.
        if(traits.isCtor) detectCtorVtableInstall(func, traits);

        // v8 Rule 101: RPC fid capture.
        if(traits.callsSifRpc) {
            detectSifRpcFids(func, traits);
            // Rule 139: aggressive lui+ori composite SID/FID tracking across all RPC sites.
            detectDiscoveredSidsFids(func, traits);
        }

        // v8 Rule 99: filepath sprintf format capture.
        if(traits.callsFileOpen) detectFilePathSprintfFormats(func, traits);

        // v9 R1: GIF tag inline builder detection.
        detectGifTagInlineBuilder(func, traits);
        // v9 R4: BITBLTBUF macro sequence (4-store cluster with GS AD reg ids
        // 0x50/0x51/0x52/0x53 in second 64-bit half).
        detectBitbltbufSequence(func, traits);
        // v11 (A): generic A+D-payload writers - PRIM/RGBAQ/TEX0/ZBUF/DISPFB.
        // Replaces broken MMIO-offset-as-reg-id detection.
        detectAdRegImmediateStores(func, traits);
        // v11 (F+G): source-chain DMA tag builder. Cross-instruction const
        // tracker reconstructs lui+ori/li/or composites then flags tag-id
        // high nibble stores. Catches sgdma.c `size | 0x30000000` REF idiom.
        detectDmaSourceChainTagBuilder(func, traits);
        // v12 (B1): composite-const MMIO range pass. Fold lui+ori|addiu pairs
        // on same dest reg into 32-bit values and match against peripheral
        // ranges. Recovers vu_micromem/vu_datamem/intc_*/sbus/dmac_global/sio
        // accesses that Ghidra refs miss because the computed address never
        // shows up as a memory Reference.
        detectCompositeMmioConsts(func, traits);
        // v12 (A1+A2): infer syscall trampoline name from `syscall N; jr ra; nop`
        // shape. Recovers SDK function names on stripped binaries (Jak3).
        // v15.5: widened 24 -> 32 bytes to match syscallWrapperShape (Rule 159/160).
        if(traits.byteSize <= 32 && traits.hasSyscall)
            detectSyscallTrampoline(func, traits);
        // v15.5 Rule 161: dynamic-code loader (post-scan: needs both callee
        // names and refsArchiveStrings). Calls a cache-flush family callee
        // AND shows file/archive input in the same body - the canonical
        // "read code from disc, FlushCache, execute" overlay / runtime-
        // linker idiom (Jak klink: CacheFlush(code_start, code_size) after
        // relocating a DGO; generic PS2 overlay loaders look identical).
        // Any hit means the ELF loads EE code at runtime, so a static
        // recompile of this ELF alone does NOT cover the whole game.
        {
            boolean callsCacheFlush = false;
            for(String cn : traits.calleeNames) {
                if(cn.equals("FlushCache") || cn.equals("iFlushCache")
                   || cn.equals("CacheFlush")
                   || cn.startsWith("FlushCache_0x") || cn.startsWith("iFlushCache_0x")
                   || cn.startsWith("CacheFlush_0x")) {
                    callsCacheFlush = true; break;
                }
            }
            if(callsCacheFlush &&
               (traits.callsFileOpen || traits.refsArchiveStrings))
                traits.isDynamicCodeLoader = true;
        }
        // v11 (H): file-format magic. Scan const_loads (already gathered) for
        // any 32-bit constant matching FORMAT_MAGIC_CONSTS or its 16-bit halves.
        for(long[] cl : traits.constLoads) {
            long v = cl[1] & 0xFFFFFFFFL;
            String hit = FORMAT_MAGIC_CONSTS.get(v);
            if(hit != null) traits.formatMagicHits.add(hit);
            String s = FORMAT_MAGIC_SHORTS.get(v & 0xFFFFL);
            if(s != null) traits.formatMagicHits.add(s);
        }
        // v9 R16: VU0 macro helper - instruction mix.
        if(traits.byteSize > 0) {
            double frac = (double)traits.vu0MacroOps / Math.max(1, traits.byteSize / 4);
            if(frac >= 0.30 && traits.vu0MacroOps >= 6) {
                traits.isVu0MacroHelper = true;
                traits.mustBeImplemented = true;
            }
        }
        // v9 R17: C-style struct initializer. No name gate - purely behavioral.
        if(!traits.isCtor && traits.ctorSlotsWritten.size() >= 5 &&
           traits.calleeCount == 0 && traits.byteSize >= 50 && traits.byteSize <= 600 &&
           traits.returnPaths >= 1)
            traits.isStructInitializer = true;
        // v9 R20: infinite spin-loop refine. Single backward branch to entry
        // region + no callees + small size + no MMIO.
        // v13: also require ZERO stores. A true idle/poll spin writes nothing;
        // counted copy/clear loops (memcpy/memset/strcpy shapes) store every
        // iteration. SF3 benchmark: the old rule emitted NOP-patch candidates
        // for the backward branch of u16-copy and word-clear loops, which
        // would corrupt data if an engineer enabled them.
        if(traits.calleeCount == 0 && traits.byteSize <= 60 &&
           traits.hasBackwardBranch && !traits.accessesMMIO && !traits.hasSyscall &&
           traits.storeOps == 0)
            traits.isInfiniteSpinLoop = true;
        // v11 (J): backward-branch sync wait - function with a callee whose
        // name matches a sync/bind/stat-poll pattern AND a backward branch
        // AND small body. Catches the `while(sceXxxSync()){}` / `while(...<0){}`
        // idiom that hasSyscall-based Rule 25 misses.
        if(traits.hasBackwardBranch && traits.callOps >= 1 && traits.byteSize < 400) {
            for(String cn : traits.calleeNames) {
                if(cn == null) continue;
                if(cn.endsWith("Sync") || cn.endsWith("SyncS") || cn.endsWith("Stat") ||
                   cn.endsWith("CheckStat") || cn.endsWith("CheckStatRpc") ||
                   cn.equals("sceSifBindRpc") || cn.equals("sceSifCallRpc") ||
                   cn.equals("sceCdDiskReady") || cn.equals("sceDmaSync")) {
                    traits.isSyncWaitLoop = true;
                    break;
                }
            }
        }
        // v11 (J): infinite-fail loop - function contains a `while(1){}` after
        // an SDK call that returned an error. Detect via SDK callee + >=2
        // backward branches + tight body (<200 bytes). Coarse signal but
        // enough to mark candidates for human review.
        if(traits.hasBackwardBranch && traits.branchOps >= 4 && traits.byteSize < 200) {
            for(String cn : traits.calleeNames) {
                if(cn == null) continue;
                if(cn.equals("sceSifBindRpc") || cn.equals("sceSifSyncIop") ||
                   IOP_REBOOT_CALLEES.contains(cn) || IRX_LOAD_CALLEES.contains(cn)) {
                    traits.containsInfiniteFailLoop = true;
                    break;
                }
            }
        }

        // v10 G2: section / memory-block name containing function entry.
        MemoryBlock blk = memory.getBlock(func.getEntryPoint());
        if(blk != null) traits.sectionName = blk.getName();
        // v10 cyclomatic proxy.
        traits.cyclomaticProxy = traits.branchOps + traits.callOps - traits.returnPaths + 1;

        // Rule 140: any partial-dest COP2 op flags function for dest-mask review.
        if(traits.cop2PartialDestOps > 0) traits.cop2DestMaskVerify = true;
        // Rule 141: static-initializer install manifest (vtable/global writes).
        if(fname.startsWith("__sinit_")) {
            traits.isStaticInitializer = true;
            collectStaticInitManifest(func, traits);
            if(traits.xrefToCount == 0) traits.isUncalledStaticInit = true;
        }
        // Rule 142: memory allocator / pool / placement-new - never auto-stub.
        detectMemoryAllocator(fname, traits);
        // Rule 143: guest-execution-lock hog (thread yield-spin starver).
        detectGuestLockHog(fname, traits);
        // Rule 144: MIPS EABI 5th-arg-in-$t0 read in prologue.
        detectEabiArgT0(func, traits);
        // Rule 145: PSMCT16 CLUT uploader (only meaningful for BITBLTBUF writers).
        if(traits.writesBitbltbufReg) detectPsmct16ClutUploader(func, traits);
        // Rule 150: EE code-overlay loader.
        for(String cn : traits.calleeNames)
            if(cn != null && OVERLAY_LOADER_CALLEES.contains(cn))
                { traits.isOverlayLoader = true; break; }

        cache.put(key,traits);
        return traits;
    }

    // v9 R1: GIF tag inline builder. Sliding window over body instructions
    // looking for >=4 stores at +0/+8/+0x10/+0x18 to same base register where
    // one of the stored 32-bit constant words has the GIF tag REGS-field
    // shape 0x__0E____ (REGS=0x0E = A+D mode, most common). Also captures
    // immediate values that match PACKED(0)/REGLIST(1)/IMAGE(2) in FLG slot.
    private void detectGifTagInlineBuilder(Function func, FuncTraits traits) {
        InstructionIterator it = currentProgram.getListing().getInstructions(func.getBody(), true);
        // base reg -> last seen offset; tracks store cluster shapes.
        Map<String, Set<Long>> baseOffsets = new HashMap<>();
        // last 32-bit const seen per reg.
        Map<String, Long> regConsts = new HashMap<>();
        while(it.hasNext()) {
            Instruction inst = it.next();
            String mn = inst.getMnemonicString();
            if(mn == null) continue;
            String mll = mn.toLowerCase();
            // Track lui/ori composite to recover full 32-bit const per dest reg.
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
            } else if(mll.equals("sw") || mll.equals("sd") || mll.equals("sq")) {
                // store: src reg in opObjects(0), {scalar offset, base reg} in opObjects(1).
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
                // G1 v10: stored-immediate VIF/DMA tag detection. Check ANY
                // store of a const-tracked register against opcode tables,
                // regardless of offset alignment.
                if(src != null && regConsts.containsKey(src) &&
                   off >= 0 && (off % 4) == 0) {
                    long sval = regConsts.get(src) & 0xFFFFFFFFL;
                    long hb   = (sval >> 24) & 0xFFL;
                    String vn = VIF_OPCODES.get(hb);
                    if(vn != null) traits.storedVifOpcodes.add(vn);
                    if(hb >= 0x60L && hb <= 0x7FL)
                        traits.storedVifOpcodes.add("UNPACK");
                    if(hb >= 0x10L) {
                        long tp = hb & 0xF0L;
                        String dn = DMA_TAG_IDS.get(tp);
                        if(dn != null) traits.storedDmaTagIds.add(dn);
                    }
                }
                if(base == null || off < 0 || off > 0x40) continue;
                Set<Long> offsets = baseOffsets.computeIfAbsent(base, k -> new LinkedHashSet<>());
                offsets.add(off);
                // Inspect stored const for GIFtag fingerprint.
                if(src != null && regConsts.containsKey(src)) {
                    long val = regConsts.get(src);
                    // REGS field nibble at bits 28-30 of upper 32-bit half:
                    // pattern val high byte 0x_E or value contains 0x0E____ shape.
                    long highByte = (val >> 24) & 0xFFL;
                    long nloop = val & 0x7FFFL;       // lower 15 bits
                    if((highByte & 0x0FL) == 0x0EL || (val & 0xFFFFL) == 0x000EL) {
                        traits.gifTagRegsFields.add(0x0EL);
                        if(nloop > 0) traits.gifTagNloops.add(nloop);
                    }
                    // FLG bits 58:58 of qword (PACKED=0, REGLIST=1, IMAGE=2, IMAGE2=3).
                    // For 32-bit halves, FLG is bits 26-27 of upper-half-of-qword-0.
                    long flg = (val >> 26) & 0x3L;
                    if(flg == 0 && (val & 0xFFFF0000L) != 0) traits.gifTagFlags.add("PACKED");
                    if(flg == 1) traits.gifTagFlags.add("REGLIST");
                    if(flg == 2) traits.gifTagFlags.add("IMAGE");
                }
            }
        }
        // Verdict: >=4 16-byte-stride store offsets to same base.
        for(Set<Long> offsets : baseOffsets.values()) {
            boolean has0=false, has8=false, has10=false, has18=false;
            for(Long o : offsets) {
                if(o == 0)    has0 = true;
                if(o == 8)    has8 = true;
                if(o == 0x10) has10 = true;
                if(o == 0x18) has18 = true;
            }
            int cnt = (has0?1:0) + (has8?1:0) + (has10?1:0) + (has18?1:0);
            if(cnt >= 3) {
                traits.gifTagInlineBuilder = true;
                break;
            }
        }
    }

    // v9 R4: BITBLTBUF macro sequence - 4 stores to qword buffer with second
    // 64-bit half == GS A+D reg id 0x50/0x51/0x52/0x53 in immediate const.
    private void detectBitbltbufSequence(Function func, FuncTraits traits) {
        InstructionIterator it = currentProgram.getListing().getInstructions(func.getBody(), true);
        boolean seenBitblt=false, seenTrxpos=false, seenTrxreg=false, seenTrxdir=false;
        Map<String, Long> regConsts = new HashMap<>();
        while(it.hasNext()) {
            Instruction inst = it.next();
            String mn = inst.getMnemonicString();
            if(mn == null) continue;
            String mll = mn.toLowerCase();
            if(mll.equals("addiu") || mll.equals("li") || mll.equals("ori")) {
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
                    if(v == 0x50) seenBitblt = true;
                    if(v == 0x51) seenTrxpos = true;
                    if(v == 0x52) seenTrxreg = true;
                    if(v == 0x53) seenTrxdir = true;
                }
            }
        }
        if(seenBitblt && seenTrxpos && seenTrxreg && seenTrxdir) {
            traits.bitbltbufMacroSequence = true;
            traits.writesBitbltbufReg = true;
        }
    }

    // v11 (F+G): source-chain DMA tag builder. PS2 source-chain tags occupy
    // the upper 64 bits of a qword with shape (size | (id<<28)) - REF=0x3,
    // CNT=0x1, CALL=0x5, RET=0x6, END=0x7, REFS=0x4, REFE=0x0, NEXT=0x2.
    // Encoded high nibble of 32-bit word: 0x10/0x30/0x50/etc. Pattern:
    //   sw  $r1, +0($base)        ; tag-high word (size|id<<28)
    //   sw  $r2, +4($base)        ; addr ptr (DMA addr; KSEG1 masked)
    //   sw  zero,+8($base)        ; pad
    //   sw  zero,+0xC($base)      ; pad
    // Or via sd writing both halves in one quad-aligned pair. Tracks per-reg
    // composite const from lui/ori/addiu; flags when a const matching tag-id
    // high nibble is stored at offset 0 of any base.
    private void detectDmaSourceChainTagBuilder(Function func, FuncTraits traits) {
        InstructionIterator it = currentProgram.getListing().getInstructions(func.getBody(), true);
        Map<String, Long> regConsts = new HashMap<>();
        while(it.hasNext()) {
            Instruction inst = it.next();
            String mn = inst.getMnemonicString();
            if(mn == null) continue;
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
            } else if(mll.equals("or")) {
                // Common idiom: or $rN, $rA, $rB where one src is the size and
                // other carries the tag-id high nibble. Combine if both tracked.
                Object[] dops = inst.getOpObjects(0);
                String dr = (dops!=null && dops.length>0 && dops[0] instanceof ghidra.program.model.lang.Register)
                    ? ((ghidra.program.model.lang.Register)dops[0]).getName() : null;
                long combined = 0; int seenSrc = 0;
                for(Object o : inst.getInputObjects()) {
                    if(o instanceof ghidra.program.model.lang.Register) {
                        String rn = ((ghidra.program.model.lang.Register)o).getName();
                        if(dr != null && rn.equalsIgnoreCase(dr)) continue;
                        if(regConsts.containsKey(rn)) {
                            combined |= regConsts.get(rn); seenSrc++;
                        }
                    }
                }
                if(dr != null && seenSrc >= 1)
                    regConsts.put(dr, combined & 0xFFFFFFFFL);
            } else if(mll.equals("sw") || mll.equals("sd")) {
                Object[] dop = inst.getOpObjects(0);
                Object[] aop = inst.getOpObjects(1);
                String src = (dop!=null && dop.length>0 && dop[0] instanceof ghidra.program.model.lang.Register)
                    ? ((ghidra.program.model.lang.Register)dop[0]).getName() : null;
                long off = -1;
                if(aop != null) for(Object o : aop)
                    if(o instanceof ghidra.program.model.scalar.Scalar)
                        off = ((ghidra.program.model.scalar.Scalar)o).getSignedValue();
                // First-word slot: offset 0 or 8 (qword pair).
                if(src != null && regConsts.containsKey(src) && off >= 0 && off <= 0x10) {
                    long v = regConsts.get(src) & 0xFFFFFFFFL;
                    long highByte = (v >> 24) & 0xFFL;
                    // Source-chain id encoded in bits 30:28 of upper word, so
                    // high byte is 0x_X where X = id<<4. Map 0x00/10/20/30/40/50/60/70.
                    long idNib = highByte & 0xF0L;
                    String name = null;
                    if(highByte == 0x70L) name = "END";
                    else if(highByte == 0x10L) name = "CNT";
                    else if(highByte == 0x30L) name = "REF";
                    else if(highByte == 0x40L) name = "REFS";
                    else if(highByte == 0x50L) name = "CALL";
                    else if(highByte == 0x60L) name = "RET";
                    else if(highByte == 0x20L) name = "NEXT";
                    // REFE (0x00) too ambiguous to flag without paired size.
                    if(name == null && idNib != 0) name = DMA_TAG_IDS.get(idNib);
                    if(name != null) {
                        traits.dmaSourceChainTagBuilder = true;
                        traits.dmaSourceChainTagIds.add(name);
                    }
                }
            }
        }
    }

    // v12 (A1+A2): Detect tiny syscall trampoline `addiu $v1,$zero,N; syscall;
    // jr $ra; nop` (or variants without the immediate-load when N is already
    // in $v1). Recovers the canonical kernel name on stripped builds. Sets
    // traits.inferredName + traits.inferredSyscallImm for downstream re-mapping.
    private void detectSyscallTrampoline(Function func, FuncTraits traits) {
        InstructionIterator it = currentProgram.getListing().getInstructions(func.getBody(), true);
        long syscallImm = -1L;
        Map<String,Long> regConsts = new HashMap<>();
        int count = 0;
        while(it.hasNext() && count < 6) {
            Instruction inst = it.next();
            count++;
            String mn = inst.getMnemonicString();
            if(mn == null) continue;
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
                // v15.5 fix: the $v1 constant is the architectural dispatch
                // number on the EE and MUST win. The old code let any scalar
                // in the syscall instruction's input objects overwrite it -
                // Ghidra reports a spurious constant there, which mapped
                // EVERY trampoline to imm 0x02/"SetGsCrt" on the Jak ELFs
                // (li v1,0x74 / 0x5a / 0x5b all reported 0x02). The encoded
                // code field is only a fallback when $v1 is unknown.
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
            if(nm != null) {
                traits.inferredName = nm;
                traits.inferredSyscallImm = syscallImm;
            } else {
                traits.inferredSyscallImm = syscallImm;
            }
        }
    }

    // v12 (B1): composite-const MMIO range pass. Walk instructions, track full
    // 32-bit constant per dest reg across lui+ori|addiu|or sequences. Each
    // tracked value is matched against every documented peripheral range:
    // IPU/GIF/VIF/DMAC FIFO + VU micro+data + SBUS + INTC + RCNT + SIO +
    // DMAC global/ext + GS priv + DMA channel CHCR. Sets the matching trait
    // flag so existing tag/counter logic fires. Crucial for engines where the
    // synthesised address never resolves to a Ghidra memory Reference (which
    // was the root cause of vu_micromem/sbus/intc/dmac_global=0 across Jak1-3).
    private void detectCompositeMmioConsts(Function func, FuncTraits traits) {
        InstructionIterator it = currentProgram.getListing().getInstructions(func.getBody(), true);
        Map<String, Long> regConsts = new HashMap<>();
        while(it.hasNext()) {
            Instruction inst = it.next();
            String mn = inst.getMnemonicString();
            if(mn == null) continue;
            String mll = mn.toLowerCase();
            if(mll.equals("lui")) {
                Object[] dops = inst.getOpObjects(0);
                String dr = (dops!=null && dops.length>0 && dops[0] instanceof ghidra.program.model.lang.Register)
                    ? ((ghidra.program.model.lang.Register)dops[0]).getName() : null;
                long imm = -1;
                for(Object o : inst.getInputObjects())
                    if(o instanceof ghidra.program.model.scalar.Scalar)
                        imm = ((ghidra.program.model.scalar.Scalar)o).getUnsignedValue();
                if(dr != null && imm >= 0)
                    regConsts.put(dr, (imm & 0xFFFFL) << 16);
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
            // Match every tracked composite against MMIO ranges. Cheap - set
            // dedup ensures we only flag each range once per function.
            for(Long vBoxed : regConsts.values()) {
                long v = vBoxed & 0xFFFFFFFFL;
                if(v == 0) continue;
                matchMmioRange(v, traits);
            }
        }
    }

    /** Helper: classify a 32-bit address into a peripheral range and stamp
     *  the matching FuncTraits flag (plus add a label to compositeMmioRangesHit
     *  for the JSON emit). Idempotent. */
    private void matchMmioRange(long addr, FuncTraits traits) {
        long norm = addr & 0x1FFFFFFFL;
        // VU micro/data
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
        // IPU
        if(norm >= IPU_MMIO_START && norm < IPU_MMIO_END) {
            if(traits.compositeMmioRangesHit.add("IPU_MMIO"))
                traits.accessesIpuMmio = true;
            if(norm == IPU_CMD)
                traits.writesIpuCmd = true;
        }
        // GIF Path3 ctrl
        if(norm == GIF_P3CNT || norm == GIF_P3TAG) {
            traits.compositeMmioRangesHit.add("GIF_P3_CTRL");
            traits.touchesGifP3Reg = true;
        }
        if((norm >= GIF_CTRL_BASE && norm <= GIF_CTRL_END) ||
           (norm >= GIF_CHCR_BASE && norm <= GIF_CHCR_END)) {
            traits.compositeMmioRangesHit.add("GIF_CTRL");
            traits.touchesGifCtrl = true;
        }
        // FIFOs
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
            traits.writesIpuFifo = true;
        }
        // VIF1 channel
        if(norm >= VIF1_CHANNEL_BASE && norm <= VIF1_CHANNEL_END) {
            traits.compositeMmioRangesHit.add("VIF1_CHANNEL");
            traits.accessesVif1MMIO = true;
        }
        // DMA channels (CHCR base/QWC/TADR).
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
        // GS privileged registers
        if(norm >= GS_PRIV_START && norm <= GS_PRIV_END) {
            long off = norm - GS_PRIV_START;
            String nm = KNOWN_GS_PRIV_REGS.get(off);
            if(nm != null) {
                traits.gsPrivRegHits.add(nm);
                traits.compositeMmioRangesHit.add("GS_PRIV_" + nm);
                if(off == 0x70L || off == 0x90L) traits.writesDispfbReg = true;
            }
        }
        // SBUS
        if(norm == SBUS_MSCOM || norm == SBUS_SMCOM) {
            traits.compositeMmioRangesHit.add("SBUS_COM");
            traits.touchesSbus = true;
        }
        if(norm == SBUS_MSFLG || norm == SBUS_SMFLG) {
            traits.compositeMmioRangesHit.add("SBUS_FLAG");
            traits.touchesSbusFlags = true;
        }
        // INTC / RCNT / SIO / DMAC global+ext / VIF ctrl
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
        // Generic MMIO bucket
        if((norm >= MMIO_START && norm <= MMIO_END) ||
           (norm >= MMIO_GS_START && norm <= MMIO_GS_END))
            traits.accessesMMIO = true;
        // Scratchpad
        if(norm >= SPR_START && norm <= SPR_END)
            traits.usesSPR = true;
    }

    // v11 (A): generic A+D-payload reg writer scanner. PRIM/RGBAQ/TEX0/ZBUF/etc.
    // are A+D reg IDs written by storing a value tagged with the id in the upper
    // qword half. Pattern matches detectBitbltbufSequence but covers the full
    // A+D reg id space. Sets writesGsPrimReg / writesRgbaqReg / writesTex0Reg /
    // writesZbufReg / writesDispfbReg via real payload evidence (not the bogus
    // MMIO-offset reg id match the old code used).
    private void detectAdRegImmediateStores(Function func, FuncTraits traits) {
        InstructionIterator it = currentProgram.getListing().getInstructions(func.getBody(), true);
        Map<String, Long> regConsts = new HashMap<>();
        Set<Long> adRegIdsStored = new LinkedHashSet<>(); // v13: distinct GS reg-id store evidence
        while(it.hasNext()) {
            Instruction inst = it.next();
            String mn = inst.getMnemonicString();
            if(mn == null) continue;
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
                    if(v <= 0x6CL) adRegIdsStored.add(v);
                }
            }
        }
        // v13: storing a register that happens to hold 0 or 1 is among the most
        // common operations in compiled code (`flag = 1`, `ptr = NULL`), so a
        // single hit is meaningless - SF3 benchmark tagged 464 functions
        // (incl. sceMcInit) as RGBAQ writers. A real A+D packet builder stores
        // several distinct GS register ids (PRIM+RGBAQ+XYZ2, BITBLTBUF+TRXPOS+
        // TRXREG+TRXDIR). Require >=2 distinct ids, or independent GIF-tag
        // evidence in the same function, before stamping the writer flags.
        if(adRegIdsStored.size() >= 2 || traits.gifTagInlineBuilder ||
           traits.buildsGifTag64 || traits.bitbltbufMacroSequence) {
            if(adRegIdsStored.contains(0x00L)) traits.writesGsPrimReg = true;
            if(adRegIdsStored.contains(0x01L)) traits.writesRgbaqReg = true;
            if(adRegIdsStored.contains(0x06L) || adRegIdsStored.contains(0x07L)) traits.writesTex0Reg = true;
            if(adRegIdsStored.contains(0x4EL) || adRegIdsStored.contains(0x4FL)) traits.writesZbufReg = true;
            if(adRegIdsStored.contains(0x59L) || adRegIdsStored.contains(0x5BL)) traits.writesDispfbReg = true;
            if(adRegIdsStored.contains(0x50L)) traits.writesBitbltbufReg = true;
        }
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

    // Parses "<N><name>F<args>" or "<N><name>Fv" - returns the class name
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

    // v8 Rule 92: vtable install detector - looks for lui+addiu+sw $rN, 0($a0).
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

    // v8 Rule 101 / v11 (D): scan for $a1 immediate set just before
    // sceSifCallRpc (FID) OR sceSifBindRpc (SID). Reconstructs lui+ori
    // composite 32-bit immediate so SIDs like FF1's 0x19740512 (audio RPC)
    // and 0x12358 (file loader RPC) are captured raw - independent of
    // KNOWN_IOP_SIDS whitelist.
    private void detectSifRpcFids(Function func, FuncTraits traits) {
        InstructionIterator it = currentProgram.getListing().getInstructions(func.getBody(), true);
        long lastA1 = -1;
        long luiHiA1 = -1;  // upper 16 bits assembled from `lui $a1, hi`
        while(it.hasNext()) {
            Instruction inst = it.next();
            String mn = inst.getMnemonicString();
            if(mn == null) continue;
            String mll = mn.toLowerCase();
            if(mll.equals("lui")) {
                Object[] dop = inst.getOpObjects(0);
                String dr = (dop!=null && dop.length>0 && dop[0] instanceof ghidra.program.model.lang.Register)
                    ? ((ghidra.program.model.lang.Register)dop[0]).getName() : null;
                long imm = -1;
                for(Object o : inst.getInputObjects())
                    if(o instanceof ghidra.program.model.scalar.Scalar)
                        imm = ((ghidra.program.model.scalar.Scalar)o).getUnsignedValue();
                if(dr != null && dr.equalsIgnoreCase("a1") && imm >= 0) {
                    luiHiA1 = (imm & 0xFFFFL) << 16;
                    lastA1 = luiHiA1;
                }
            } else if(mll.equals("addiu") || mll.equals("ori") || mll.equals("li") || mll.equals("daddiu")) {
                Object[] dop = inst.getOpObjects(0);
                String dr = (dop!=null && dop.length>0 && dop[0] instanceof ghidra.program.model.lang.Register)
                    ? ((ghidra.program.model.lang.Register)dop[0]).getName() : null;
                boolean readsA1 = false;
                long imm = -1;
                for(Object o : inst.getInputObjects()) {
                    if(o instanceof ghidra.program.model.lang.Register) {
                        if(((ghidra.program.model.lang.Register)o).getName().equalsIgnoreCase("a1"))
                            readsA1 = true;
                    } else if(o instanceof ghidra.program.model.scalar.Scalar) {
                        imm = ((ghidra.program.model.scalar.Scalar)o).getUnsignedValue();
                    }
                }
                if(dr != null && dr.equalsIgnoreCase("a1") && imm >= 0) {
                    if(readsA1 && luiHiA1 >= 0)
                        lastA1 = (luiHiA1 + imm) & 0xFFFFFFFFL;
                    else
                        lastA1 = imm;
                }
            } else if(mll.equals("jal") || mll.equals("jalr")) {
                for(ghidra.program.model.address.Address tgt : inst.getFlows()) {
                    Function t = funcManager.getFunctionAt(tgt);
                    if(t == null || lastA1 < 0) continue;
                    String tn = t.getName();
                    if(tn.equals("sceSifCallRpc")) {
                        traits.detectedRpcFids.add(lastA1);
                    } else if(tn.equals("sceSifBindRpc")) {
                        // Capture raw SID regardless of whitelist.
                        traits.detectedRpcSid = lastA1;
                        traits.detectedRpcSids.add(lastA1);
                    }
                }
                // Reset between calls so cross-call register state doesn't leak.
                lastA1 = -1; luiHiA1 = -1;
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

    // Rule 141: __sinit_* static-initializer manifest. Scans body for stores of
    // pointer-shaped constants (>=0x00100000) and records what each install does.
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
                    if(val >= 0x00100000L) {
                        Address va = toAddr(val);
                        boolean mapped;
                        try { mapped = memory.contains(va); } catch(Exception e) { mapped = false; }
                        if(mapped) {
                            traits.staticInitInstalls.add(String.format("0x%08X->0x%08X@+0x%X",
                                inst.getAddress().getOffset() & 0xFFFFFFFFL, val, off & 0xFFFFFFFFL));
                            ghidra.program.model.symbol.Symbol s = symtab.getPrimarySymbol(va);
                            if(s != null && s.getName().startsWith("__vt__"))
                                traits.staticInitInstallsVtable = true;
                        }
                    }
                }
            }
        }
    }

    // Rule 142: memory allocator / pool / placement-new - never auto-stub.
    private void detectMemoryAllocator(String fname, FuncTraits traits) {
        String low = fname.toLowerCase();
        if(fname.contains("memoryInit"))          { traits.isMemoryAllocator=true; traits.allocatorKind="pool_init";     return; }
        if(fname.contains("construct_new_array")) { traits.isMemoryAllocator=true; traits.allocatorKind="array_ctor";    return; }
        if(fname.startsWith("__nw__")||fname.startsWith("__nwa__"))
                                                  { traits.isMemoryAllocator=true; traits.allocatorKind="placement_new"; return; }
        if(fname.contains("stAlloc")||fname.contains("GetMainStack")||fname.contains("stSetBuffer"))
                                                  { traits.isMemoryAllocator=true; traits.allocatorKind="stack";         return; }
        if(fname.contains("SetHeapMem")||fname.contains("SetTableBuffer"))
                                                  { traits.isMemoryAllocator=true; traits.allocatorKind="pool_init";     return; }
        if(low.startsWith("alloc")||low.contains("alloc__"))
                                                  { traits.isMemoryAllocator=true; traits.allocatorKind="alloc"; }
    }

    // Rule 143: guest-execution-lock hog - thread yield/spin without releasing mutex.
    private void detectGuestLockHog(String fname, FuncTraits traits) {
        boolean spinShape = traits.isInfiniteSpinLoop || traits.isSyncWaitLoop
                         || (traits.hasBackwardBranch && traits.byteSize < 400);
        boolean threadName = fname.contains("GamePad") || fname.contains("RotateThread")
                          || fname.contains("SwitchGamePad") || fname.contains("ThreadReadyQueue")
                          || fname.contains("cooperativeYield") || fname.contains("ReadyQueue");
        if(spinShape && threadName) traits.isGuestLockHogCandidate = true;
    }

    // Rule 144: MIPS EABI 5th-arg ($t0) read before define in prologue.
    private void detectEabiArgT0(Function func, FuncTraits traits) {
        InstructionIterator it = currentProgram.getListing().getInstructions(func.getBody(), true);
        int scanned = 0; boolean t0Defined = false;
        while(it.hasNext() && scanned < 24) {
            Instruction inst = it.next(); scanned++;
            for(Object o : inst.getInputObjects()) {
                if(o instanceof ghidra.program.model.lang.Register &&
                   ((ghidra.program.model.lang.Register)o).getName().equalsIgnoreCase("t0")) {
                    if(!t0Defined) { traits.readsEabiArgT0 = true; return; }
                }
            }
            Object[] dop = inst.getOpObjects(0);
            String dr = (dop!=null && dop.length>0 && dop[0] instanceof ghidra.program.model.lang.Register)
                ? ((ghidra.program.model.lang.Register)dop[0]).getName() : null;
            if("t0".equalsIgnoreCase(dr)) t0Defined = true;
        }
    }

    // Rule 145: PSMCT16 CLUT uploader - BITBLTBUF writer that loads dpsm=0x2.
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

    // Rule 139: aggressive lui+ori composite SID/FID tracking across all sceSifCallRpc/BindRpc sites.
    private void detectDiscoveredSidsFids(Function func, FuncTraits traits) {
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
            } else if(mll.equals("li")) {
                Object[] dops = inst.getOpObjects(0);
                String dr = (dops!=null && dops.length>0 && dops[0] instanceof ghidra.program.model.lang.Register)
                    ? ((ghidra.program.model.lang.Register)dops[0]).getName() : null;
                long imm = -1;
                for(Object o : inst.getInputObjects())
                    if(o instanceof ghidra.program.model.scalar.Scalar)
                        imm = ((ghidra.program.model.scalar.Scalar)o).getUnsignedValue();
                if(dr != null && imm >= 0) regConsts.put(dr, imm);
            } else if(mll.equals("jal") || mll.equals("jalr")) {
                Object[] tops = inst.getOpObjects(0);
                String tname = null;
                if(tops != null && tops.length > 0 && tops[0] instanceof ghidra.program.model.address.Address) {
                    try {
                        Function c = funcManager.getFunctionAt((ghidra.program.model.address.Address)tops[0]);
                        if(c != null) tname = c.getName();
                    } catch(Exception ignore) {}
                }
                if(tname != null && (tname.equals("sceSifCallRpc") || tname.equals("sceSifBindRpc"))) {
                    Long a0 = regConsts.get("a0");
                    if(a0 != null) {
                        long sid = a0 & 0xFFFFFFFFL;
                        traits.allDetectedSids.add(sid);
                        long fa = func.getEntryPoint().getOffset() & 0xFFFFFFFFL;
                        discoveredSidToCallers.computeIfAbsent(sid, k -> new ArrayList<>()).add(fa);
                    }
                    Long a1 = regConsts.get("a1");
                    if(a1 != null && tname.equals("sceSifCallRpc")) {
                        long fid = a1 & 0xFFFFFFFFL;
                        traits.allDetectedFids.add(fid);
                        long fa = func.getEntryPoint().getOffset() & 0xFFFFFFFFL;
                        discoveredFidToCallers.computeIfAbsent(fid, k -> new ArrayList<>()).add(fa);
                    }
                }
            }
        }
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
    // v15: a radar stub now needs BOTH a host-boundary name match (exact or
    // word-boundary family) AND trait corroboration. Name-only matching is
    // what stubbed `exponent` on FF1 (prefix "exp") and would stub real game
    // code on any title that reuses SDK-ish spellings.
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
    // v9 R9: scan all initialized memory blocks (typically .data / .rodata)
    // for runs of >=4 consecutive 4-byte words where each value lands in
    // [textStart, textEnd] AND each matches a known function entry. Emits a
    // map of table base -> entry list. Pairs with R10 in JSON emit.
    private void scanFunctionPointerTables(List<FuncResult> results,
                                            Map<Long,FuncResult> byAddr) {
        Set<Long> entryAddrs = new HashSet<>();
        for(FuncResult r : results) entryAddrs.add(r.address & 0xFFFFFFFFL);
        // v12 (H1): tag-tolerant alias map. GOAL-compiled binaries store boxed
        // pointers with low-bit type tags (or +constant offsets); strip the
        // low 4 bits before lookup, but always resolve back to the precise
        // function entry. Also accept values that ARE textStart-relative
        // (small ints whose addition to textStart hits an entry).
        Map<Long, Long> aliasMap = new HashMap<>();
        for(Long e : entryAddrs) aliasMap.put(e, e);
        for(Long e : entryAddrs) {
            for(int tag = 1; tag <= 0xF; tag++)
                aliasMap.putIfAbsent(e | (long)tag, e);
        }
        for(MemoryBlock blk : memory.getBlocks()) {
            if(!blk.isInitialized()) continue;
            String bn = blk.getName().toLowerCase();
            // Skip the code segment itself.
            if(bn.equals(".text") || bn.equals("text")) continue;
            long start = blk.getStart().getOffset();
            long end   = blk.getEnd().getOffset();
            long size  = end - start + 1;
            if(size < 16) continue;
            try {
                byte[] data = new byte[(int)Math.min(size, 1 << 22)]; // cap 4MB
                blk.getBytes(blk.getStart(), data);
                long runStart = -1;
                List<Long> runEntries = new ArrayList<>();
                for(int i = 0; i + 4 <= data.length; i += 4) {
                    // Little-endian 32-bit read.
                    long v = ((long)(data[i] & 0xFF))
                           | ((long)(data[i+1] & 0xFF) << 8)
                           | ((long)(data[i+2] & 0xFF) << 16)
                           | ((long)(data[i+3] & 0xFF) << 24);
                    // v12 (H1): tag-tolerant entry resolution. Direct hit first,
                    // then masked-low-nibble for boxed pointers.
                    Long resolved = aliasMap.get(v);
                    if(resolved == null && (v & 0xFL) != 0) {
                        Long maskTry = aliasMap.get(v & ~0xFL);
                        if(maskTry != null) resolved = maskTry;
                    }
                    boolean isEntry = resolved != null;
                    if(isEntry) {
                        if(runStart < 0) runStart = start + i;
                        runEntries.add(resolved);
                    } else {
                        // v12 (H1): allow up to 1 null/zero entry mid-run
                        // (vtables often pad with 0 for missing slots).
                        if(runEntries.size() >= 3 && v == 0L) continue;
                        if(runEntries.size() >= 3) {
                            functionPointerTables.put(runStart, new ArrayList<>(runEntries));
                        }
                        runStart = -1;
                        runEntries.clear();
                    }
                }
                if(runEntries.size() >= 3)
                    functionPointerTables.put(runStart, new ArrayList<>(runEntries));
            } catch(Exception ignore) {}
        }
        // v12 (H2): synthesise class names for stripped binaries. For each
        // discovered table whose members have generic Ghidra names (FUN_/sub_),
        // assign them ClassXXXXXXXX / slot N labels via FuncTraits.
        for(Map.Entry<Long,List<Long>> e : functionPointerTables.entrySet()) {
            long tableAddr = e.getKey() & 0xFFFFFFFFL;
            String className = String.format("Class_0x%08X", tableAddr);
            int slot = 0;
            for(Long fnAddr : e.getValue()) {
                FuncResult fr = byAddr.get(fnAddr & 0xFFFFFFFFL);
                if(fr != null && fr.traits != null) {
                    boolean stripped = fr.name == null || fr.name.startsWith("FUN_") ||
                                       fr.name.startsWith("sub_");
                    if(stripped && fr.traits.inferredClassName == null) {
                        fr.traits.inferredClassName = className;
                        fr.traits.inferredVtableSlot = slot;
                    }
                }
                slot++;
            }
        }
        // R10 tag: every function whose entry appears in a discovered table
        // gets DISPATCH_TABLE_TARGET. Function CONTAINING jalr with target
        // resolved via lw from table base gets TABLE_DISPATCH_CALL.
        Set<Long> dispatchTargets = new HashSet<>();
        for(List<Long> entries : functionPointerTables.values())
            dispatchTargets.addAll(entries);
        for(FuncResult r : results) {
            if(dispatchTargets.contains(r.address & 0xFFFFFFFFL)) {
                if(!r.tags.contains("DISPATCH_TABLE_TARGET"))
                    r.tags.add("DISPATCH_TABLE_TARGET");
            }
            if(r.traits == null) continue;
            // R10 site detection: function loads a constant matching a table
            // base AND has jalr indirect call.
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

    // v11 (K): name-prefix module index. Discover prefixes of length 2-6 that
    // occur >=5 times across the function set; emit {prefix -> [addrs]}.
    // Complements call-graph clustering (which gives 696 small components on
    // FF1) by surfacing engineer-visible subsystems (Scene*, Mc*, Pad*, ...).
    private void buildNamePrefixModules(List<FuncResult> results) {
        Map<String, List<Long>> byPrefix = new HashMap<>();
        for(FuncResult r : results) {
            if(r.name == null || r.name.isEmpty()) continue;
            String n = r.name;
            // Skip sub_XXXXXX (Ghidra default) - no semantic prefix.
            if(n.startsWith("sub_") || n.startsWith("FUN_")) continue;
            int maxLen = Math.min(6, n.length());
            for(int len = 2; len <= maxLen; len++) {
                String prefix = n.substring(0, len);
                // Trim trailing digit/separator - keeps "Scene" over "Scene1".
                char last = prefix.charAt(len-1);
                if(!Character.isLetter(last) && last != '_') continue;
                byPrefix.computeIfAbsent(prefix, k -> new ArrayList<>()).add(r.address & 0xFFFFFFFFL);
            }
        }
        // Filter: >=5 occurrences, prefer longest qualifying prefix per address
        // so a function isn't listed under both "Sc" and "Scene".
        List<Map.Entry<String,List<Long>>> kept = new ArrayList<>();
        for(Map.Entry<String,List<Long>> e : byPrefix.entrySet())
            if(e.getValue().size() >= 5) kept.add(e);
        kept.sort((a,b) -> Integer.compare(b.getKey().length(), a.getKey().length()));
        Set<Long> assigned = new HashSet<>();
        for(Map.Entry<String,List<Long>> e : kept) {
            List<Long> taken = new ArrayList<>();
            for(Long a : e.getValue())
                if(assigned.add(a)) taken.add(a);
            if(taken.size() >= 5) {
                Collections.sort(taken);
                namePrefixModules.put(e.getKey(), taken);
            }
        }
    }

    // v9 R18: greedy module clustering. Connected components on bidirectional
    // jal call edges. Cluster id encoded as smallest function address in the
    // cluster. Functions never called and never calling stay id=-1.
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
        int idCounter = 0;
        for(FuncResult r : results) {
            long a = r.address & 0xFFFFFFFFL;
            if(compId.containsKey(a)) continue;
            // BFS flood.
            Deque<Long> q = new ArrayDeque<>();
            Set<Long> seen = new HashSet<>();
            q.add(a); seen.add(a);
            long minAddr = a;
            while(!q.isEmpty()) {
                long cur = q.poll();
                if(cur < minAddr) minAddr = cur;
                Set<Long> ns = adj.get(cur);
                if(ns == null) continue;
                for(long n : ns) {
                    if(seen.add(n)) q.add(n);
                }
            }
            for(long n : seen) compId.put(n, minAddr);
        }
        // Renumber to compact integer ids.
        Map<Long, Integer> idMap = new HashMap<>();
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

    private void runV8PostPasses(List<FuncResult> results,
                                  Map<Long,FuncResult> byAddr,
                                  List<String> newStubs) {
        // -------- Pass A: ctor call mode + return-to-global --------
        // For every direct jal site, look at the caller's instructions just
        // after the jal for `sw $v0, +imm($gp)`. If found, record on callee.
        for(FuncResult caller : results) {
            if(caller.traits == null) continue;
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
        // Caller mode classification - was a ctor reached only via direct jal,
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
                    ce.globalHolders.add(String.format("0x%08X", g));
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
        // -------- Pass E: Uploader caller depth-1 / depth-2 markers --------
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
        // ===== v9 post-passes =====
        // Pass V9-A: R2 DMA_CHCR_START_KICK - pair 0x101 const with channel
        // base load. Channel base may live in .data; we approximate by:
        // loadsChcrStartConst AND any literalRef whose base register was loaded
        // via a const matching a DMA channel CHCR address.
        for(FuncResult r : results) {
            if(r.traits == null) continue;
            FuncTraits t = r.traits;
            if(!t.loadsChcrStartConst) continue;
            boolean hasChannelLoad = false;
            for(long[] cl : t.constLoads) {
                long v = cl[1] & 0xFFFFFFFFL;
                for(long base : DMA_CHANNEL_BASES) {
                    if(v == base || v == (base >> 16) || v == (base & 0xFFFFL)) {
                        hasChannelLoad = true; break;
                    }
                }
                if(hasChannelLoad) break;
            }
            // Also count VIF1 channel range, MMIO indirect via ref capture.
            if(t.accessesMMIO || t.accessesVif1MMIO) hasChannelLoad = true;
            if(hasChannelLoad) {
                t.dmaChcrStartKick = true;
                if(!r.tags.contains("DMA_CHCR_START_KICK")) {
                    r.tags.add("DMA_CHCR_START_KICK");
                    dmaChcrStartKickCount++;
                }
            }
        }

        // Pass V9-B: R9 function_pointer_tables - moved to pre-BFS in run()
        // so table-edge augmentation can feed mainloop/init-chain depth BFS.
        // (Was: scanFunctionPointerTables(results, byAddr);)

        // Pass V9-C: R5/R6 frame driver + render frame entry.
        for(FuncResult r : results) {
            if(r.traits == null) continue;
            FuncTraits t = r.traits;
            // R6: writes GIF/VIF MMIO + mainloop_depth 1-2 + frame-clock callee.
            boolean writesGifVif = t.accessesVif1MMIO || t.writesGifFifo ||
                                   t.writesVif1Fifo || t.touchesGifCtrl ||
                                   !t.dmaKickChannels.isEmpty();
            if(writesGifVif && t.isFrameClockDriver &&
               t.mainLoopDepth >= 0 && t.mainLoopDepth <= 2) {
                t.isRenderFrameEntry = true;
                if(!r.tags.contains("RENDER_FRAME_ENTRY")) {
                    r.tags.add("RENDER_FRAME_ENTRY");
                    renderFrameEntryCount++;
                }
            }
        }

        // Pass V9-D: R18 module clustering via mutual-call density. Greedy
        // connected components on bidirectional jal edges. O(F * avgCallees).
        assignModuleIds(results);
        // v11 (K): secondary name-prefix module index.
        buildNamePrefixModules(results);

        // -------- Pass F0: stamp Rule 98 override classification on per-func traits --------
        for(FuncResult r : results) {
            if(r.traits == null) continue;
            long addr = r.address & 0xFFFFFFFFL;
            if(overrideKindByAddr.containsKey(addr)) {
                r.traits.overrideKind = overrideKindByAddr.get(addr);
                String k = r.traits.overrideKind;
                r.traits.overrideRetireCandidate = "nop_stub".equals(k) || "probe".equals(k);
                String tag = "OVERRIDE_" + (k == null ? "REAL_SHIM" : k.toUpperCase());
                if(!r.tags.contains(tag)) r.tags.add(tag);
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
    // UNIFIED CONFIG OUTPUT
    // =========================================================
    private void writeUnifiedConfig(File outFile,File step1Config,
                                    List<String> newStubs,List<String> newSkips,
                                    List<String> nopList,List<String> patchList,
                                    List<String> forceRecompList,
                                    List<String> nativeImplList,
                                    List<String> reviewList,
                                    List<long[]> patchInstrCandidates) throws IOException {
        List<String> lines=new ArrayList<>();
        BufferedReader reader=utf8Reader(step1Config);
        String line;while((line=reader.readLine())!=null)lines.add(line);
        reader.close();
        // v15.5: normalize single-line stub/skip arrays (`stubs = [..]`,
        // `skip = []`) into multi-line form so the rescue-removal and
        // insertion passes below see one entry per line. The old scanner
        // never found the closing `]` of an inline array: enricher
        // additions were silently dropped and the in-array state leaked
        // into the following lines.
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
        // v15.5: guarantee both arrays exist when we have additions to place.
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
        // v15.1: DROP inherited stub/skip entries the keep gate (or a later
        // promote pass) rescued to RECOMPILE. The TOML stays the executable
        // safe subset; per-entry reasons/evidence live in triage_map.json
        // under "rescued_from_step1" (the detailed source of truth).
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
            stubLines.add("  # --- Triage Enricher v3 additions ---");
            for(String s:newStubs)stubLines.add("  \""+s+"\",");
        }
        List<String> skipLines=new ArrayList<>();
        if(!newSkips.isEmpty()){
            skipLines.add("  # --- Triage Enricher v3 additions ---");
            for(String s:newSkips)skipLines.add("  \""+s+"\",");
        }
        if(skipClose>=0&&!skipLines.isEmpty()){
            lines.addAll(skipClose,skipLines);
            if(stubsClose>=skipClose)stubsClose+=skipLines.size();
        }
        if(stubsClose>=0&&!stubLines.isEmpty())lines.addAll(stubsClose,stubLines);
        lines.add(0,"# Unified config: "+step1Config.getName()+" + "+newStubs.size()+" stubs + "
            +newSkips.size()+" skips (Enricher v15.5)");
        lines.add(1,"# "+rescuedStubLines+" inherited stub + "+rescuedSkipLines
            +" inherited skip entries failed the high-confidence safety gate and were");
        lines.add(2,"# removed (now RECOMPILE). Per-entry reason/evidence: triage_map.json "
            +"\"rescued_from_step1\".");
        // v15.3 Rule 154: surface ELF identity mismatch at the top of the config.
        if("mismatch".equals(step1ElfHashStatus))
            lines.add(3,"# !! Rule 154: input toml elf_hash does NOT match this ELF - "
                +"every surviving address binding is suspect. Regenerate the input toml.");
        for(int i=0;i<lines.size();i++){
            String l=lines.get(i);
            if(l.startsWith("stub_count =")){
                int old=Integer.parseInt(l.split("=")[1].trim());
                lines.set(i,"stub_count = "+(old+newStubs.size()-rescuedStubLines));
            } else if(l.startsWith("skip_count =")){
                int old=Integer.parseInt(l.split("=")[1].trim());
                lines.set(i,"skip_count = "+(old+newSkips.size()-rescuedSkipLines));
            } else if(l.startsWith("input =") || l.startsWith("output_file =") || l.startsWith("output =") || l.startsWith("ghidra_output =")) {
                // [FIX v4] Sanitize hardcoded absolute paths to relative paths
                int q1 = l.indexOf('"');
                int q2 = l.lastIndexOf('"');
                if (q1 >= 0 && q2 > q1) {
                    String path = l.substring(q1 + 1, q2);
                    String file = new File(path).getName();
                    lines.set(i, l.substring(0, q1 + 1) + "./" + file + "\"");
                }
            }
        }
        PrintWriter w=utf8Writer(outFile);
        for(String l:lines)w.println(l);
        // v9 T1/T2: append nop / patch / force_recompile arrays.
        // v11 (N): preserve trailing tag comments on each emitted entry so
        // engineers can see WHY a function is in nop/patch/force_recompile
        // without cross-referencing the JSON.
        // v12 (G2): advisory arrays moved under [triage_advisory] so they no
        // longer collide with the recompiler's documented schema (which only
        // recognises stubs/skip/[patches]). Engineers consume these via the
        // companion report tool; recompiler ignores unknown sections.
        // v15.2: advisory block is OFF by default - the TOML is the executable
        // safe subset; the full advisory content (with reasons/evidence) is
        // emitted into triage_map.json "triage_advisory" instead. Flip
        // EMIT_VERBOSE_TOML_ADVISORY for the legacy debug behaviour.
        if(!EMIT_VERBOSE_TOML_ADVISORY) {
            int advisoryTotal = nopList.size()+patchList.size()+forceRecompList.size()
                +nativeImplList.size()+reviewList.size()+patchInstrCandidates.size();
            if(advisoryTotal > 0) {
                w.println("");
                w.println("# v15.2: "+advisoryTotal+" advisory entries (force_recompile / native_impl_needed /");
                w.println("# review / nop / patch-instruction candidates) live in triage_map.json");
                w.println("# \"triage_advisory\". Set EMIT_VERBOSE_TOML_ADVISORY=true to also emit them here.");
            }
            w.close();
            return;
        }
        boolean anyAdvisory = !nopList.isEmpty() || !patchList.isEmpty() ||
            !forceRecompList.isEmpty() || !nativeImplList.isEmpty() || !reviewList.isEmpty();
        if(anyAdvisory) {
            w.println("");
            w.println("# v12 Enricher advisory block. Not consumed by ps2recomp.exe.");
            w.println("# Engineer review surface for stub/patch/force-recompile candidates.");
            w.println("[triage_advisory]");
        }
        if(!nopList.isEmpty()) {
            w.println("# nop candidates - runtime can emit NO-OP body if confirmed.");
            w.println("nop = [");
            for(String e : nopList) {
                int hash = e.indexOf(" # ");
                String entry = hash<0 ? e : e.substring(0, hash);
                String tail  = hash<0 ? ""  : e.substring(hash);
                w.println("  \"" + entry + "\"," + tail);
            }
            w.println("]");
        }
        if(!patchList.isEmpty()) {
            w.println("");
            w.println("# patch candidates - single-instr convention fix needed.");
            w.println("patch = [");
            for(String e : patchList) {
                int hash = e.indexOf(" # ");
                String entry = hash<0 ? e : e.substring(0, hash);
                String tail  = hash<0 ? ""  : e.substring(hash);
                w.println("  \"" + entry + "\"," + tail);
            }
            w.println("]");
        }
        if(!forceRecompList.isEmpty()) {
            w.println("");
            w.println("# force_recompile - these MUST run real game logic.");
            w.println("# (must_be_implemented / top_priority / VU0 / render driver / etc.)");
            w.println("force_recompile = [");
            for(String e : forceRecompList) {
                int hash = e.indexOf(" # ");
                String entry = hash<0 ? e : e.substring(0, hash);
                String tail  = hash<0 ? ""  : e.substring(hash);
                w.println("  \"" + entry + "\"," + tail);
            }
            w.println("]");
        }
        // v14: native_impl_needed - runtime must provide host-side behaviour.
        if(!nativeImplList.isEmpty()) {
            w.println("");
            w.println("# native_impl_needed - IOP-side subsystems behind these functions");
            w.println("# (IRX module loads, SIF RPC services, audio/pad/mc gateways) need a");
            w.println("# native runtime implementation. A stub here boots but the subsystem");
            w.println("# stays dead until the runtime services it.");
            w.println("native_impl_needed = [");
            for(String e : nativeImplList) {
                int hash = e.indexOf(" # ");
                String entry = hash<0 ? e : e.substring(0, hash);
                String tail  = hash<0 ? ""  : e.substring(hash);
                w.println("  \"" + entry + "\"," + tail);
            }
            w.println("]");
        }
        // v14: review - enricher overrode/refused a binding decision.
        if(!reviewList.isEmpty()) {
            w.println("");
            w.println("# review - firewall-rescued stub/skip entries and mixed IRX-init");
            w.println("# functions. Human should confirm the enricher's override was right.");
            w.println("review = [");
            for(String e : reviewList) {
                int hash = e.indexOf(" # ");
                String entry = hash<0 ? e : e.substring(0, hash);
                String tail  = hash<0 ? ""  : e.substring(hash);
                w.println("  \"" + entry + "\"," + tail);
            }
            w.println("]");
        }
        // v12 (G1): candidate [patches.instructions] entries derived from
        // INFINITE_FAIL_LOOP / INFINITE_SPIN_LOOP / BACKWARD_BRANCH_SYNC_WAIT
        // backward-branch PCs. Emitted COMMENTED-OUT so engineers must opt in
        // before nopping a backward branch. patchInstrCandidates entries are
        // [pc, funcAddr, reasonTagBitmask]; we only know pc+func here.
        if(!patchInstrCandidates.isEmpty()) {
            w.println("");
            w.println("# v12 Enricher: candidate patches.instructions entries for spin/wait loops.");
            w.println("# Each entry NOPs the backward branch PC of a detected hazard. UNCOMMENT TO ENABLE.");
            w.println("# [patches]");
            w.println("# instructions = [");
            int emitted = 0;
            for(long[] c : patchInstrCandidates) {
                long pc = c[0] & 0xFFFFFFFFL;
                long funcAddr = c[1] & 0xFFFFFFFFL;
                String reason = c.length>=3 ? humanizeReasonMask(c[2]) : "spin/wait";
                w.println(String.format("#   { address = \"0x%08X\", value = \"0x00000000\" }, # %s in func@0x%08X",
                    pc, reason, funcAddr));
                if(++emitted >= 256) {
                    w.println("#   # ... ("+(patchInstrCandidates.size()-emitted)+" more truncated)");
                    break;
                }
            }
            w.println("# ]");
        }
        w.close();
    }

    // v12 (K): TOML tag-comment priority ranking. Higher rank = more actionable.
    private static final Map<String,Integer> TAG_PRIORITY = new HashMap<>();
    static {
        int[] r = {0};
        String[] order = {
            "TOP_PRIORITY_FIX","RUNTIME_CONFIRMED",
            // v15.3: input-hygiene + handler-roster tags rank just below the
            // render bullseyes - they mark wrong bindings, not wrong code.
            "NO_RUNTIME_HANDLER","STEP1_NAME_MISMATCH","OVERLAY_REGION",
            "OUT_OF_TEXT_BINDING",
            "BITBLTBUF_T4HH_UPLOADER",
            "MUST_BE_IMPLEMENTED","SCEVU0_HELPER_MUSTIMPL","VU0_MACRO_HELPER",
            // Rules 140-150: high-confidence firewall tags
            "COP2_DESTMASK_VERIFY","MEMORY_ALLOCATOR_NEVER_STUB",
            "STATIC_INIT_VTABLE_INSTALLER","UNCALLED_STATIC_INIT",
            "COP2_SPECIAL_OPS_REVIEW","MAP_CLUT_PSMCT16_UPLOADER",
            "COMPUTED_JUMP_UNRESOLVED","FPU_NONIEEE_SENSITIVE",
            "GUEST_LOCK_HOG_CANDIDATE","EABI_ARG_T0","OVERLAY_LOADER",
            "HOST_WAIT_CANDIDATE",
            "RENDER_FRAME_ENTRY","PATH3_INITIATOR","PATH3_KICK_VIA_DMA_API",
            "DISPFB_WRITER","DISPFB_SDK_WRITER","CTOR_MULTI_FIELD_INITIALIZER",
            "CTOR_RISK_CRITICAL","CTOR_RISK_HIGH","INIT_LARGE_FUNC",
            "DMA_CHCR_START_KICK","GIF_TAG_INLINE_BUILDER","BITBLTBUF_MACRO_SEQUENCE",
            "VIF_MPG_OPCODE_BUILDER","VIF_MSCAL_OPCODE_BUILDER","VIF_DIRECT_OPCODE_BUILDER",
            "VIF_OPCODE_BUILDER","DMA_TAG_BUILDER","DMA_SOURCE_CHAIN_TAG_BUILDER",
            "VIF_TAG_STORED_IMMEDIATE","DMA_TAG_STORED_IMMEDIATE","BUILDS_GIF_TAG_64",
            "DYNAMIC_CODE_LOADER","SYSCALL_TRAMPOLINE",
            "DISCOVERED_IOP_SID","ARCHIVE_IO","IRX_LOADER","IOP_RPC_DISPATCH",
            "FRAME_CLOCK_DRIVER","DRAWING_CHAIN_NEAR_ROOT","WRITES_BITBLTBUF_REG",
            "ACCESSES_VU_MICROMEM","ACCESSES_VU_DATAMEM",
            "ACCESSES_MMIO","COMPLEX_CONTROL_FLOW","INFINITE_FAIL_LOOP",
            "INFINITE_SPIN_LOOP","BACKWARD_BRANCH_SYNC_WAIT","BUSY_WAIT_HAZARD",
            "VU0_MICROCODE","WRITES_GLOBAL","SAFE_LEAF","ORPHAN_CODE"
        };
        for(String s : order) TAG_PRIORITY.put(s, 1000 - r[0]++);
    }
    private static List<String> prioritizeTagsForComment(List<String> tags, int limit) {
        List<String> sorted = new ArrayList<>(tags);
        sorted.sort((a, b) -> {
            int pa = TAG_PRIORITY.getOrDefault(a, 0);
            int pb = TAG_PRIORITY.getOrDefault(b, 0);
            return Integer.compare(pb, pa);
        });
        return sorted.subList(0, Math.min(limit, sorted.size()));
    }

    /** Helper: map low-bit-set flags to a comma-joined reason label. */
    private String humanizeReasonMask(long mask) {
        StringBuilder sb = new StringBuilder();
        if((mask & 0x1L) != 0) sb.append("INFINITE_FAIL_LOOP,");
        if((mask & 0x2L) != 0) sb.append("INFINITE_SPIN_LOOP,");
        if((mask & 0x4L) != 0) sb.append("BACKWARD_BRANCH_SYNC_WAIT,");
        if((mask & 0x8L) != 0) sb.append("BUSY_WAIT_HAZARD,");
        if(sb.length() == 0) return "spin/wait";
        sb.setLength(sb.length()-1);
        return sb.toString();
    }

    // =========================================================
    // JSON OUTPUT - v3 extended with new fields
    // =========================================================
    /** v15.5: GS-side static evidence gate for Rule 78 TBP constants. */
    private static boolean hasGsSideEvidence(FuncTraits t) {
        return t.writesTex0Reg || t.writesBitbltbufReg || t.writesRgbaqReg
            || t.writesZbufReg || t.writesDispfbReg || t.writesDispfbViaSdk
            || t.writesGsPrimReg || t.gifTagInlineBuilder || t.buildsGifTag64
            || t.bitbltbufMacroSequence || t.isMicrocodeUploader
            || t.path3Initiator || t.path3KickViaDmaApi || t.touchesGifCtrl
            || t.touchesGifP3Reg || t.writesGifFifo || t.writesVif1Fifo
            || t.writesVif0Fifo || t.accessesVuMicromem || t.accessesVuDatamem
            || t.loadsPsm4hhConstant || !t.dmaKickChannels.isEmpty()
            || t.dmaChcrStartKick;
    }

    private void writeTriageJson(File outFile,List<FuncResult> results,
                                 String elfHash,long gpValue,
                                 int totalFuncs,int uncategorized) throws IOException {
        // v15.5 Rule 78 noise gate: tbp_constants_loaded used to collect
        // EVERY immediate in (0,0x3FFF] from every function - 16-byte syscall
        // trampolines were reporting "TBP constants". A function with no
        // GS-side evidence and no runtime-confirmed TBP match carries no
        // meaningful TBP signal; drop the list before emission.
        for(FuncResult r:results){
            FuncTraits t=r.traits;
            if(t==null) continue;
            if(t.tbpRuntimeConfirmed.isEmpty() && !hasGsSideEvidence(t))
                t.tbpConstantsLoaded.clear();
        }
        PrintWriter w=utf8Writer(outFile);
        w.println("{");
        w.println("  \"schema_version\": 12.3,");
        w.println("  \"elf_hash\": \""+elfHash+"\",");
        if(gpValue!=0)w.println("  \"global_pointer\": \""+hex(gpValue)+"\",");
        w.println("  \"text_range\": { \"start\": \""+hex(textStart)+"\", \"end\": \""+hex(textEnd)+"\" },");
        w.println("  \"mainloop_shield_size\": "+mainLoopShield.size()+",");
        w.println("  \"game_override_imported\": "+gameOverrideImportedCount+",");
        w.println("  \"statistics\": {");
        w.println("    \"total_functions\": "+totalFuncs+",");
        w.println("    \"uncategorized_from_step1\": "+uncategorized+",");
        w.println("    \"enriched_count\": "+results.size()+",");
        // v15: step1 vetting summary.
        {
            int s1kept=0, s1rescued=0, ovr=0;
            for(FuncResult r : results) {
                if("step1".equals(r.origin)) {
                    if(r.rescueReason!=null) s1rescued++; else s1kept++;
                } else if("override".equals(r.origin)) ovr++;
            }
            w.println("    \"step1_inherited_kept\": "+s1kept+",");
            w.println("    \"step1_rescued_to_recompile\": "+s1rescued+",");
            w.println("    \"step1_name_mismatches\": "+step1NameMismatchCount+",");
            w.println("    \"step1_elf_hash\": \""+step1ElfHashStatus+"\",");
            w.println("    \"runtime_handler_roster_size\": "
                +(runtimeRosterLoaded ? runtimeHandlerNames.size() : 0)+",");
            w.println("    \"no_runtime_handler_stubs\": "+noHandlerStubCount+",");
            w.println("    \"overlay_binding_vetoes\": "+overlayVetoCount+",");
            w.println("    \"out_of_text_bindings\": "+outOfTextBindingCount+",");
            w.println("    \"override_bound\": "+ovr+",");
        }
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
        w.println("    \"archive_io\": "+archiveIoCount+","); // v13: was hardcoded 0
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
        // v9 stats
        w.println("    \"archive_io_v9\": "+archiveIoCount+",");
        w.println("    \"gif_tag_inline_builder\": "+gifTagBuilderCount+",");
        w.println("    \"bitbltbuf_macro_sequence\": "+bitbltbufMacroCount+",");
        w.println("    \"vu0_macro_helper\": "+vu0MacroHelperCount+",");
        w.println("    \"struct_initializer\": "+structInitCount+",");
        w.println("    \"infinite_spin_loop\": "+spinLoopCount+",");
        w.println("    \"dma_chcr_start_kick\": "+dmaChcrStartKickCount+",");
        w.println("    \"render_frame_entry\": "+renderFrameEntryCount+",");
        w.println("    \"table_dispatch_call\": "+tableDispatchCallCount+",");
        w.println("    \"function_pointer_tables_count\": "+functionPointerTables.size()+",");
        w.println("    \"module_clusters_count\": "+moduleClusters.size()+",");
        // v10 generic stats
        w.println("    \"vif_tag_stored_immediate\": "+storedVifTagCount+",");
        w.println("    \"dma_tag_stored_immediate\": "+storedDmaTagCount+",");
        w.println("    \"builds_gif_tag_64\": "+gifTag64Count+",");
        w.println("    \"loads_vif1_chunk_70000\": "+chunk70000Count+",");
        w.println("    \"hi_lo_consumer\": "+hiLoConsumerCount+",");
        // v11 stats (E/F/H/I/J)
        w.println("    \"rcnt_access\": "+rcntAccessCount+",");
        w.println("    \"vif_control_reg\": "+vifCtrlAccessCount+",");
        w.println("    \"dmac_global_reg\": "+dmacGlobalAccessCount+",");
        w.println("    \"writes_intc_mask\": "+intcMaskWriterCount+",");
        w.println("    \"reads_intc_stat\": "+intcStatReaderCount+",");
        w.println("    \"sio_access\": "+sioAccessCount+",");
        w.println("    \"writes_dmac_enable\": "+dmacEnableWriterCount+",");
        w.println("    \"sbus_flag_toucher\": "+sbusFlagAccessCount+",");
        w.println("    \"dma_source_chain_tag_builder\": "+dmaSourceChainTagCount+",");
        w.println("    \"format_magic_parser\": "+formatMagicHitCount+",");
        w.println("    \"irx_loader\": "+irxLoaderCount+",");
        w.println("    \"iop_reboot_handler\": "+iopRebootHandlerCount+",");
        w.println("    \"backward_branch_sync_wait\": "+syncWaitLoopCount+",");
        w.println("    \"infinite_fail_loop\": "+infiniteFailLoopCount+",");
        // v12 (D3 + others) - counters for new fields.
        {
            int sidCount = 0, assetCount = 0, inferredNames = 0, mcGate = 0;
            Set<Long> distinctSids = new HashSet<>();
            for(FuncResult r : results) {
                if(r.traits == null) continue;
                distinctSids.addAll(r.traits.detectedRpcSids);
                if(r.traits.detectedRpcSid != 0) distinctSids.add(r.traits.detectedRpcSid);
                assetCount += r.traits.discoveredAssetPaths.size();
                if(r.traits.inferredName != null) inferredNames++;
                if(r.traits.callsMcSdk) mcGate++;
                sidCount += r.traits.detectedRpcSids.size();
            }
            w.println("    \"discovered_iop_sids_count\": "+distinctSids.size()+",");
            w.println("    \"detected_rpc_sids_total\": "+sidCount+",");
            w.println("    \"discovered_asset_paths_total\": "+assetCount+",");
            w.println("    \"inferred_syscall_name_count\": "+inferredNames+",");
            w.println("    \"syscall_trampolines\": "+syscallTrampolineCount+",");
            // Rule 161: >0 means this ELF loads EE code at runtime (overlay /
            // DGO-style); recompiling the ELF alone does not cover the game.
            w.println("    \"dynamic_code_loaders\": "+dynamicCodeLoaderCount+",");
            w.println("    \"behavioral_mc_gate_count\": "+mcGate+",");
        }
        // O5: derived disposition totals.
        {
            int stubN=0, skipN=0, recN=0, mustN=0;
            for(FuncResult r : results) {
                if("STUB".equals(r.disposition)) stubN++;
                else if("SKIP".equals(r.disposition)) skipN++;
                else recN++;
                if(r.traits != null && r.traits.mustBeImplemented) mustN++;
            }
            w.println("    \"stub_candidates\": "+stubN+",");
            w.println("    \"skip_candidates\": "+skipN+",");
            w.println("    \"recompile_candidates\": "+recN+",");
            w.println("    \"must_implement_count\": "+mustN);
        }
        w.println("  },");

        // v15.1: structured rescue ledger - the detailed explanation surface
        // for every inherited (step1) stub/skip binding that failed the
        // high-confidence safety gate. The unified TOML only carries the
        // executable safe subset plus a one-line pointer here.
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
                // TOML [triage_advisory].review array).
                boolean review = r.tags.contains("BINDING_FIREWALL_RESCUED")
                              || r.tags.contains("ADDRESS_TAKEN_CALLBACK");
                w.print("\"new_decision\": \""+(review?"review":"recompile")+"\", ");
                w.print("\"reason\": "+jsonString(r.rescueReason)+", ");
                // Evidence: the determinative trait facts the gate looked at.
                List<String> ev=new ArrayList<>();
                if(t!=null) {
                    ev.add(t.hasSyscall?"has_syscall":"no_syscall");
                    ev.add((t.callsSifRpc||t.detectedRpcSid!=0||!t.detectedRpcSids.isEmpty())
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
                for(String tag : prioritizeTagsForComment(r.tags,4))
                    if(!der.contains(tag)) der.add(tag);
                w.print("\"derived_from\": "+jsonStrArray(der));
                w.print("}");
            }
        }
        w.println("\n  ],");

        // v15.2: full advisory content - moved here from the TOML
        // [triage_advisory] block (TOML = executable safe subset, JSON =
        // detailed source of truth). Entry strings are "name@0xADDR"; tags
        // are the priority-sorted hint tags previously emitted as TOML
        // trailing comments.
        w.println("  \"triage_advisory\": {");
        w.println("    \"_note\": \"Advisory only - not consumed by ps2recomp.exe. "
            +"nop: confirmed no-op stub candidates; patch: single-instr convention fixes; "
            +"force_recompile: must run real game logic; native_impl_needed: IOP-side "
            +"subsystems needing host implementations; review: enricher overrode/refused "
            +"a binding decision; patch_instruction_candidates: spin/wait backward-branch "
            +"NOP patches (opt-in).\",");
        emitAdvisoryJsonArray(w, "nop", advisoryNop, true);
        emitAdvisoryJsonArray(w, "patch", advisoryPatch, true);
        emitAdvisoryJsonArray(w, "force_recompile", advisoryForceRecomp, true);
        emitAdvisoryJsonArray(w, "native_impl_needed", advisoryNativeImpl, true);
        emitAdvisoryJsonArray(w, "review", advisoryReview, true);
        w.println("    \"patch_instruction_candidates\": [");
        for(int pi=0; pi<advisoryPatchInstr.size(); pi++) {
            long[] c = advisoryPatchInstr.get(pi);
            long pc = c[0] & 0xFFFFFFFFL;
            long fa = c[1] & 0xFFFFFFFFL;
            String reason = c.length>=3 ? humanizeReasonMask(c[2]) : "spin/wait";
            w.print("      {\"address\": \""+hex(pc)+"\", \"value\": \"0x00000000\", "
                +"\"reason\": "+jsonString(reason)+", \"function\": \""+hex(fa)+"\"}");
            w.println(pi==advisoryPatchInstr.size()-1 ? "" : ",");
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
        // loaded gs_dump_to_summary.py outputs (filename -> checkpoint name).
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

        // v7: GS runtime evidence block - per-checkpoint facts + merged union.
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

        // v12 (D1): discovered IOP SIDs across the whole binary. Aggregates
        // every SID literal that any function passed to sceSifBindRpc. Output:
        // { "0xfab3": { "label": "JAK23X_DGO_RPC" | "UNKNOWN",
        //               "callers": [ {"addr","name"}, ... ] } }
        // Lets engineers map the EE<->IOP comm surface at a glance even when
        // labels are stripped.
        {
            Map<Long, List<long[]>> sidToCallers = new TreeMap<>();
            for(FuncResult r : results) {
                if(r.traits == null) continue;
                Set<Long> sids = new LinkedHashSet<>(r.traits.detectedRpcSids);
                if(r.traits.detectedRpcSid != 0) sids.add(r.traits.detectedRpcSid);
                for(Long sid : sids) {
                    sidToCallers.computeIfAbsent(sid, k -> new ArrayList<>())
                                .add(new long[]{r.address & 0xFFFFFFFFL, 0});
                }
            }
            // Merge in cross-function discovered SIDs from detectDiscoveredSidsFids().
            for(Map.Entry<Long,List<Long>> e : discoveredSidToCallers.entrySet()) {
                long sid = e.getKey() & 0xFFFFFFFFL;
                List<long[]> existing = sidToCallers.get(sid);
                if(existing == null) { existing = new ArrayList<>(); sidToCallers.put(sid, existing); }
                for(Long fa : e.getValue()) existing.add(new long[]{fa & 0xFFFFFFFFL, 0});
            }
            w.println("  \"discovered_iop_sids\": {");
            boolean firstDS = true;
            for(Map.Entry<Long, List<long[]>> e : sidToCallers.entrySet()) {
                if(!firstDS) w.println(","); firstDS = false;
                String label = KNOWN_IOP_SIDS.getOrDefault(e.getKey(), "UNKNOWN");
                w.print("    \""+hex(e.getKey())+"\": { \"label\": \""+label+"\", \"callers\": [");
                boolean firstC = true;
                for(long[] c : e.getValue()) {
                    if(!firstC) w.print(", "); firstC = false;
                    String nm = "";
                    for(FuncResult fr : results)
                        if((fr.address & 0xFFFFFFFFL) == c[0]) { nm = fr.name; break; }
                    w.print("{\"addr\":\""+hex(c[0])+"\",\"name\":"+jsonString(nm)+"}");
                }
                w.print("] }");
            }
            w.println("\n  },");
        }

        // Rule 140: COP2 partial-dest transform risk set.
        {
            List<FuncResult> cop2Risk = new ArrayList<>();
            for(FuncResult r : results)
                if(r.traits != null && r.traits.cop2DestMaskVerify) cop2Risk.add(r);
            cop2Risk.sort((a,b) -> Integer.compare(b.traits.cop2PartialDestOps, a.traits.cop2PartialDestOps));
            w.println("  \"cop2_partial_dest_risk\": [");
            for(int ci=0; ci<cop2Risk.size(); ci++) {
                FuncResult r = cop2Risk.get(ci); FuncTraits t2 = r.traits;
                w.print("    {\"addr\":\""+hex(r.address)+"\",\"name\":"+jsonString(r.name));
                w.print(",\"partial_dest_ops\":"+t2.cop2PartialDestOps);
                w.print(",\"full_dest_ops\":"+t2.cop2FullDestOps);
                w.print(",\"dest_fields\":[");
                boolean fdf=true; for(String df:t2.cop2DestFields){if(!fdf)w.print(",");fdf=false;w.print("\""+df+"\"");}
                w.print("]}");
                if(ci<cop2Risk.size()-1) w.println(","); else w.println();
            }
            w.println("  ],");
        }

        // Rule 141: static-init manifest.
        {
            List<FuncResult> sinits = new ArrayList<>();
            for(FuncResult r : results)
                if(r.traits != null && r.traits.isStaticInitializer) sinits.add(r);
            w.println("  \"static_init_manifest\": [");
            for(int ci=0; ci<sinits.size(); ci++) {
                FuncResult r = sinits.get(ci); FuncTraits t2 = r.traits;
                w.print("    {\"addr\":\""+hex(r.address)+"\",\"name\":"+jsonString(r.name));
                w.print(",\"uncalled\":"+t2.isUncalledStaticInit);
                w.print(",\"installs_vtable\":"+t2.staticInitInstallsVtable);
                w.print(",\"installs\":[");
                boolean fi=true; for(String s:t2.staticInitInstalls){if(!fi)w.print(",");fi=false;w.print(jsonString(s));}
                w.print("]}");
                if(ci<sinits.size()-1) w.println(","); else w.println();
            }
            w.println("  ],");
        }

        // Rule 142: memory allocators.
        {
            List<FuncResult> allocs = new ArrayList<>();
            for(FuncResult r : results)
                if(r.traits != null && r.traits.isMemoryAllocator) allocs.add(r);
            w.println("  \"memory_allocators\": [");
            for(int ci=0; ci<allocs.size(); ci++) {
                FuncResult r = allocs.get(ci); FuncTraits t2 = r.traits;
                w.print("    {\"addr\":\""+hex(r.address)+"\",\"name\":"+jsonString(r.name));
                w.print(",\"kind\":"+jsonString(t2.allocatorKind)+"}");
                if(ci<allocs.size()-1) w.println(","); else w.println();
            }
            w.println("  ],");
        }

        // Rule 146: computed-jump resolution - per-func switch sites + Ghidra targets.
        {
            List<FuncResult> jumpFuncs = new ArrayList<>();
            for(FuncResult r : results)
                if(r.traits != null && !r.traits.computedJumpSwitchPcs.isEmpty()) jumpFuncs.add(r);
            w.println("  \"computed_jump_targets\": [");
            for(int ci=0; ci<jumpFuncs.size(); ci++) {
                FuncResult r = jumpFuncs.get(ci); FuncTraits t2 = r.traits;
                w.print("    {\"addr\":\""+hex(r.address)+"\",\"name\":"+jsonString(r.name));
                w.print(",\"switch_sites\":[");
                boolean fs=true;
                for(Map.Entry<Long,List<Long>> e : t2.computedJumpTargets.entrySet()) {
                    if(!fs) w.print(","); fs=false;
                    w.print("{\"pc\":\""+hex(e.getKey())+"\",\"targets\":[");
                    boolean ft=true;
                    for(Long tg : e.getValue()){if(!ft)w.print(",");ft=false;w.print("\""+hex(tg)+"\"");}
                    w.print("]}");
                }
                w.print("]}");
                if(ci<jumpFuncs.size()-1) w.println(","); else w.println();
            }
            w.println("  ],");
        }

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
        
        // ===== v11 AI-facing abstraction layer (additive; derived from existing signals) =====
        // Build per-function recommendation + subsystem/role/gateway metadata ONCE,
        // then reuse it for both the top-level summary blocks and the per-function
        // layer below. This keeps the whole layer to a constant number of O(N) /
        // O(N+E) passes - no per-function full-graph BFS, no new graph engine.
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
            // v15: provenance - "auto" (enricher), "step1" (inherited from the
            // input toml and vetted), "override" (hand-bound in game_override).
            w.print("\"origin\": \""+r.origin+"\", ");
            if(r.step1Disposition != null) {
                w.print("\"step1_disposition\": \""+r.step1Disposition+"\", ");
                w.print("\"step1_rescue_reason\": "
                    +(r.rescueReason==null?"null":jsonString(r.rescueReason))+", ");
            }
            // v15.3 Rule 157: triage-return suggestion for bound stubs, per
            // the runtime triage-stub strategy (ret0/ret1/reta0 bindings).
            // Poll targets (callers spin on v0) need an A/B test: wrong
            // constant = infinite wait loop.
            if("STUB".equals(r.disposition)) {
                String sug;
                if(t.returnsA0 || t.returnsA1) sug = "reta0";
                else if(t.isLikelyPollTarget)  sug = "ret0_or_ret1_ab_test";
                else if(t.byteSize < 60 && !t.writesToGlobal && t.callOps == 0) sug = "ret0";
                else sug = "ret0_then_verify";
                w.print("\"suggested_triage_return\": \""+sug+"\", ");
                w.print("\"has_runtime_handler\": "
                    +(runtimeRosterLoaded ? String.valueOf(hasRuntimeHandler(r.name)) : "null")+", ");
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
            w.print("], ");
            // v9 fields
            w.print("\"loads_chcr_start_const\": "+t.loadsChcrStartConst+", ");
            w.print("\"dma_chcr_start_kick\": "+t.dmaChcrStartKick+", ");
            w.print("\"gif_tag_inline_builder\": "+t.gifTagInlineBuilder+", ");
            w.print("\"sif_packet_builder\": "+t.sifPacketBuilder+", ");
            w.print("\"bitbltbuf_macro_sequence\": "+t.bitbltbufMacroSequence+", ");
            w.print("\"is_render_frame_entry\": "+t.isRenderFrameEntry+", ");
            w.print("\"refs_archive_strings_v9\": "+t.refsArchiveStrings+", ");
            w.print("\"is_vu0_macro_helper\": "+t.isVu0MacroHelper+", ");
            w.print("\"vu0_macro_op_count\": "+t.vu0MacroOps+", ");
            w.print("\"is_struct_initializer\": "+t.isStructInitializer+", ");
            w.print("\"is_infinite_spin_loop\": "+t.isInfiniteSpinLoop+", ");
            w.print("\"float_cmp_ops\": "+t.floatCmpOps+", ");
            w.print("\"module_id\": "+t.moduleId+", ");
            w.print("\"archive_string_exts\": [");
            {
                boolean f=true;
                for(String s:t.archiveStringExts){ if(!f) w.print(", "); f=false; w.print(jsonString(s)); }
            }
            w.print("], ");
            w.print("\"gif_tag_flags\": [");
            {
                boolean f=true;
                for(String s:t.gifTagFlags){ if(!f) w.print(", "); f=false; w.print(jsonString(s)); }
            }
            w.print("], ");
            w.print("\"table_dispatch_sites\": [");
            {
                boolean f=true;
                for(String s:t.tableDispatchSites){ if(!f) w.print(", "); f=false; w.print(jsonString(s)); }
            }
            w.print("], ");
            w.print("\"string_refs\": [");
            {
                boolean f=true;
                for(String s:t.stringRefs){ if(!f) w.print(", "); f=false; w.print(jsonString(s)); }
            }
            w.print("], ");
            w.print("\"const_loads\": [");
            {
                boolean f=true;
                int emitted = 0;
                for(long[] cl : t.constLoads) {
                    if(emitted >= 24) break;  // cap per function to bound JSON size
                    if(!f) w.print(", "); f=false;
                    w.print("{\"pc\": \""+String.format("0x%08X", cl[0])+"\", \"value\": \""+
                            String.format("0x%X", cl[1])+"\"}");
                    emitted++;
                }
            }
            w.print("], ");
            // v10 generic emit
            w.print("\"section_name\": "+jsonString(t.sectionName)+", ");
            w.print("\"hi_lo_ops\": "+t.hiLoOps+", ");
            w.print("\"cyclomatic_proxy\": "+t.cyclomaticProxy+", ");
            w.print("\"builds_gif_tag_64\": "+t.buildsGifTag64+", ");
            w.print("\"loads_vif1_chunk_70000\": "+t.loads70000Chunk+", ");
            w.print("\"stored_vif_opcodes\": [");
            {
                boolean f=true;
                for(String s:t.storedVifOpcodes){ if(!f) w.print(", "); f=false; w.print(jsonString(s)); }
            }
            w.print("], ");
            w.print("\"stored_dma_tag_ids\": [");
            {
                boolean f=true;
                for(String s:t.storedDmaTagIds){ if(!f) w.print(", "); f=false; w.print(jsonString(s)); }
            }
            w.print("], ");
            w.print("\"opcode_top5\": {");
            {
                List<Map.Entry<String,Integer>> sorted = new ArrayList<>(t.opcodeHistogram.entrySet());
                sorted.sort((a,b) -> Integer.compare(b.getValue(), a.getValue()));
                int cap = Math.min(5, sorted.size());
                for(int k=0; k<cap; k++) {
                    if(k>0) w.print(", ");
                    Map.Entry<String,Integer> e = sorted.get(k);
                    w.print(jsonString(e.getKey())+": "+e.getValue());
                }
            }
            w.print("}, ");
            // v11 per-function fields
            w.print("\"accesses_rcnt\": "+t.accessesRcnt+", ");
            w.print("\"accesses_vif_ctrl\": "+t.accessesVifCtrl+", ");
            w.print("\"accesses_dmac_global\": "+t.accessesDmacGlobal+", ");
            w.print("\"writes_intc_mask\": "+t.writesIntcMask+", ");
            w.print("\"reads_intc_stat\": "+t.readsIntcStat+", ");
            w.print("\"accesses_sio\": "+t.accessesSio+", ");
            w.print("\"writes_dmac_enable\": "+t.writesDmacEnable+", ");
            w.print("\"touches_sbus_flags\": "+t.touchesSbusFlags+", ");
            w.print("\"dma_source_chain_tag_builder\": "+t.dmaSourceChainTagBuilder+", ");
            w.print("\"dma_source_chain_tag_ids\": [");
            {
                boolean f=true;
                for(String s:t.dmaSourceChainTagIds){ if(!f) w.print(", "); f=false; w.print(jsonString(s)); }
            }
            w.print("], ");
            w.print("\"format_magic_hits\": [");
            {
                boolean f=true;
                for(String s:t.formatMagicHits){ if(!f) w.print(", "); f=false; w.print(jsonString(s)); }
            }
            w.print("], ");
            w.print("\"sif_load_module_call_count\": "+t.sifLoadModuleCallCount+", ");
            w.print("\"is_irx_loader\": "+t.isIrxLoader+", ");
            w.print("\"is_iop_reboot_handler\": "+t.isIopRebootHandler+", ");
            w.print("\"irx_module_paths\": [");
            {
                boolean f=true;
                for(String s:t.irxModulePaths){ if(!f) w.print(", "); f=false; w.print(jsonString(s)); }
            }
            w.print("], ");
            w.print("\"is_sync_wait_loop\": "+t.isSyncWaitLoop+", ");
            w.print("\"contains_infinite_fail_loop\": "+t.containsInfiniteFailLoop+", ");
            w.print("\"detected_rpc_sids\": [");
            {
                boolean f=true;
                for(Long v:t.detectedRpcSids){ if(!f) w.print(", "); f=false; w.print("\""+hex(v)+"\""); }
            }
            w.print("], ");
            // v12 fields.
            w.print("\"inferred_name\": "+(t.inferredName==null?"null":jsonString(t.inferredName))+", ");
            w.print("\"inferred_syscall_imm\": "+(t.inferredSyscallImm<0?"null":("\"0x"+String.format("%02X",t.inferredSyscallImm)+"\""))+", ");
            w.print("\"calls_mc_sdk\": "+t.callsMcSdk+", ");
            w.print("\"composite_mmio_ranges\": [");
            {
                boolean f=true;
                for(String s : t.compositeMmioRangesHit){ if(!f) w.print(", "); f=false; w.print(jsonString(s)); }
            }
            w.print("], ");
            w.print("\"discovered_asset_paths\": [");
            {
                boolean f=true;
                for(String s : t.discoveredAssetPaths){ if(!f) w.print(", "); f=false; w.print(jsonString(s)); }
            }
            w.print("], ");
            w.print("\"patch_candidate_pcs\": [");
            {
                boolean f=true;
                for(Long pc : t.patchCandidatePcs){ if(!f) w.print(", "); f=false; w.print("\""+hex(pc)+"\""); }
            }
            w.print("], ");
            w.print("\"inferred_class_name\": "+(t.inferredClassName==null?"null":jsonString(t.inferredClassName))+", ");
            w.print("\"inferred_vtable_slot\": "+(t.inferredVtableSlot<0?"null":Integer.toString(t.inferredVtableSlot))+", ");
            // Rules 140-150 per-function fields
            w.print("\"cop2_partial_dest_ops\": "+t.cop2PartialDestOps+", ");
            w.print("\"cop2_full_dest_ops\": "+t.cop2FullDestOps+", ");
            w.print("\"cop2_dest_mask_verify\": "+t.cop2DestMaskVerify+", ");
            w.print("\"cop2_dest_fields\": [");
            { boolean f=true; for(String s:t.cop2DestFields){if(!f)w.print(", ");f=false;w.print("\""+s+"\"");} }
            w.print("], ");
            w.print("\"cop2_special_ops\": [");
            { boolean f=true; for(String s:t.cop2SpecialOps){if(!f)w.print(", ");f=false;w.print("\""+s+"\"");} }
            w.print("], ");
            w.print("\"writes_fpu_control\": "+t.writesFpuControl+", ");
            w.print("\"uses_fpu_div_sqrt\": "+t.usesFpuDivSqrt+", ");
            w.print("\"is_static_initializer\": "+t.isStaticInitializer+", ");
            w.print("\"static_init_installs_vtable\": "+t.staticInitInstallsVtable+", ");
            w.print("\"is_uncalled_static_init\": "+t.isUncalledStaticInit+", ");
            w.print("\"is_memory_allocator\": "+t.isMemoryAllocator+", ");
            w.print("\"allocator_kind\": "+jsonString(t.allocatorKind)+", ");
            w.print("\"is_guest_lock_hog_candidate\": "+t.isGuestLockHogCandidate+", ");
            w.print("\"reads_eabi_arg_t0\": "+t.readsEabiArgT0+", ");
            w.print("\"loads_psmct16_const\": "+t.loadsPsmct16Const+", ");
            w.print("\"is_psmct16_clut_uploader\": "+t.isPsmct16ClutUploader+", ");
            w.print("\"is_overlay_loader\": "+t.isOverlayLoader+", ");
            w.print("\"computed_jump_switch_pcs\": [");
            { boolean f=true; for(Long pc:t.computedJumpSwitchPcs){if(!f)w.print(", ");f=false;w.print("\""+hex(pc)+"\"");} }
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
            // v11 (P) revert: cap removed - user found 669 FF1 functions
            // truncating at 32 dropped substantial literal_refs data. Uncapped
            // emit restored. Use jq filtering downstream if size matters.
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

            // v7: runtime_corroboration block. Emitted whenever there is a
            // bullseye prediction OR TBP constant load OR safe-stub candidate.
            // v11 (M) revert: original gate kept - TBP constants are static
            // facts useful even without GS dump corroboration. Witness fields
            // stay false/empty when no GS evidence loaded, which is correct.
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

        // v8 class registry
        // v15.5 fix: the _note line used to carry an unconditional trailing
        // comma; on stripped binaries (empty classRegistry) that produced
        // invalid JSON ({"_note": "...",}). The comma is now emitted as a
        // prefix of each entry instead.
        w.println("  \"class_registry\": {");
        w.print("    \"_note\": \"v8: populated during runV8PostPasses()\"");
        {
            for(Map.Entry<String,ClassEntry> e : classRegistry.entrySet()) {
                ClassEntry ce = e.getValue();
                w.println(",");
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

        // v5 Rule 57: focus_set - top-priority bullseye. The community lessons
        // say "you only need to rewrite the 5 exact functions"; this array is
        // exactly that shortlist (plus PATH3_INITIATOR / TEX0 writers / etc.).
        // Pre-sorted by tag class for the report tool.
        w.println("  \"focus_set\": [");
        {
            List<FuncResult> focus = new ArrayList<>();
            for(FuncResult r : results)
                if(r.traits != null && r.traits.isTopPriorityFix) focus.add(r);
            // O4: when no GS bullseyes hit (typical of stripped binaries),
            // synthesize top-32 by composite criticality score.
            if(focus.isEmpty()) {
                List<FuncResult> candidates = new ArrayList<>();
                for(FuncResult r : results) {
                    if(r.traits == null) continue;
                    FuncTraits t = r.traits;
                    int score = 0;
                    if(t.callOps > 5) score += 2;
                    if(t.accessesMMIO) score += 3;
                    if(t.mainLoopDepth >= 0 && t.mainLoopDepth <= 4) score += 3;
                    if(t.writesToGlobal) score += 1;
                    if(t.indirectCallT9Count > 0) score += 2;
                    if(t.hasJumpTable) score += 1;
                    if(t.refsArchiveStrings) score += 2;
                    if(t.isVu0MacroHelper) score += 3;
                    if(t.gifTagInlineBuilder) score += 4;
                    if(t.dmaChcrStartKick) score += 4;
                    if(t.bitbltbufMacroSequence) score += 4;
                    if(t.isRenderFrameEntry) score += 4;
                    if(score >= 4) candidates.add(r);
                }
                candidates.sort((a,b) -> {
                    int sa = scoreFocus(a.traits);
                    int sb = scoreFocus(b.traits);
                    if (sa != sb) return Integer.compare(sb, sa);  // desc
                    return Long.compare(a.address & 0xFFFFFFFFL, b.address & 0xFFFFFFFFL);
                });
                int cap = Math.min(32, candidates.size());
                focus = candidates.subList(0, cap);
            }
            // v7 Rule 81: re-rank - CONFIRMED first, INDETERMINATE next,
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
                        ", \"runtime_status\": "+jsonString(t.runtimeStatus)+"}");
                if(i<focus.size()-1) w.println(","); else w.println();
            }
        }
        w.println("  ],");

        // v9: top-level indexes.
        w.println("  \"function_pointer_tables\": [");
        {
            boolean first = true;
            for(Map.Entry<Long,List<Long>> e : functionPointerTables.entrySet()) {
                if(!first) w.println(","); first = false;
                w.print("    {\"address\": \""+hex(e.getKey())+"\", \"entries\": [");
                List<Long> entries = e.getValue();
                for(int i=0;i<entries.size();i++) {
                    if(i>0) w.print(", ");
                    w.print("\""+hex(entries.get(i))+"\"");
                }
                w.print("]}");
            }
        }
        w.println("\n  ],");

        w.println("  \"module_clusters\": {");
        {
            boolean first = true;
            for(Map.Entry<Integer,Set<Long>> e : moduleClusters.entrySet()) {
                if(e.getValue().size() < 2) continue;  // skip singletons
                if(!first) w.println(","); first = false;
                w.print("    \"m"+e.getKey()+"\": {\"size\": "+e.getValue().size()+
                        ", \"min_address\": \""+hex(Collections.min(e.getValue()))+"\"}");
            }
        }
        w.println("\n  },");
        // v11 (K): name-prefix subsystem index.
        w.println("  \"name_prefix_modules\": {");
        {
            boolean first = true;
            for(Map.Entry<String,List<Long>> e : namePrefixModules.entrySet()) {
                if(!first) w.println(","); first = false;
                w.print("    "+jsonString(e.getKey())+": {\"size\": "+e.getValue().size()+
                        ", \"min_address\": \""+hex(Collections.min(e.getValue()))+"\"}");
            }
        }
        w.println("\n  }");
        w.println("}");
        w.close();
    }

    class FuncResult{long address;String name,category,disposition;FuncTraits traits;List<String>tags;
        // v15: provenance. origin: "auto" (enricher decision), "step1"
        // (inherited from the input toml, vetted), "override" (bound in
        // game_override.cpp). step1Disposition/rescueReason only for step1.
        String origin="auto";String step1Disposition=null;String rescueReason=null;
        // v15.1: which pass rescued the step1 binding (step1_keep_gate /
        // drawing_chain_firewall / v8_ctor_risk / v8_scevu0_helper /
        // v13_binding_firewall).
        String rescuedBy=null;}
    private static String hex(long v){return String.format("0x%08X",v&0xFFFFFFFFL);}
    private static String jsonString(String v){
        if(v==null)return "\"\"";
        // v15.5: full RFC 8259 escaping. Symbol names scraped from arbitrary
        // ELFs can carry control bytes; bare emission produced invalid JSON.
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

    // v9 O4 helper - composite score for stripped-binary focus fallback.
    // Rule 136: composite focus score - fallback when no bullseyes fire.
    private static int scoreFocus(FuncTraits t) {
        if(t == null) return 0;
        int score = 0;
        // Legacy signals
        if(t.callOps > 5) score += 2;
        if(t.accessesMMIO) score += 3;
        if(t.mainLoopDepth >= 0 && t.mainLoopDepth <= 4) score += 3;
        if(t.writesToGlobal) score += 1;
        if(t.indirectCallT9Count > 0) score += 2;
        if(t.hasJumpTable) score += 1;
        if(t.refsArchiveStrings) score += 2;
        if(t.isVu0MacroHelper) score += 3;
        // v9+ high-value signals (DC2 Rule 136)
        if(t.isCtor)                                            score += 8;
        if("CRITICAL".equals(t.ctorRiskTier))                  score += 14;
        if("HIGH".equals(t.ctorRiskTier))                      score += 8;
        if(t.isRenderFrameEntry)                               score += 20;
        if(t.isFrameClockDriver)                               score += 12;
        if(t.isInfiniteSpinLoop)                               score += 10;
        if(t.isSyncWaitLoop)                                   score += 10;
        if(t.isBitbltbufT4hhUploader)                         score += 22;
        if(t.isCtorMultiFieldInit)                             score += 10;
        if(t.isLifecycleLazyInit)                              score += 10;
        if(t.gifTagInlineBuilder)                              score += 16;
        if(t.dmaChcrStartKick)                                 score += 18;
        if(t.bitbltbufMacroSequence)                           score += 18;
        if(t.dmaSourceChainTagBuilder)                         score += 12;
        if(t.isIrxLoader)                                      score += 8;
        if(t.drawingChainDepth >= 0 && t.drawingChainDepth <= 6) score += 12;
        score += Math.min(t.calleeNames.size(), 5);
        score += Math.min(t.callers.size(), 3);
        return score;
    }

    // =========================================================================
    // v11 AI-FACING ABSTRACTION LAYER (additive)
    // -------------------------------------------------------------------------
    // Purpose: expose the intelligence already collected by Rules 1-150 in a
    // shape another AI can reason about - per-function recommendations, a
    // subsystem/relationship view, decision guardrails, and next-rule hints.
    // This is NOT a second triage engine: every field is DERIVED from existing
    // traits, tags, depths, module clusters, class registry, runtime
    // corroboration, asset-upload traces and override coverage.
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
        // v15.5 Rule 161: runtime code linker/loader - stubbing it kills the
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
        "GUEST_LOCK_HOG_CANDIDATE","OVERLAY_LOADER","HOST_WAIT_CANDIDATE"
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
    /** v15.2: emit one advisory array as [{"entry": "...", "tags": [...]}].
     *  Input strings are "name@0xADDR" optionally followed by " # TAG,TAG". */
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
                || t.isFrameClockDriver || t.isMemoryAllocator
                || t.mustBeImplemented || t.ctorInstallsVtable || t.isStaticInitializer
                || t.isIrxLoader || t.callsSifRpc
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
            || r.tags.contains("GIF_PATH3_HAZARD") || r.tags.contains("DISPFB_WRITER");
        if(render) return "render";
        boolean iop = t.callsSifRpc || t.isIrxLoader || t.isIopRebootHandler
            || r.tags.contains("IOP_RPC_DISPATCH") || r.tags.contains("IRX_LOADER")
            || t.detectedRpcSid != 0 || !t.allDetectedSids.isEmpty() || t.touchesSbus;
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
        if(r.tags.contains("HOST_WAIT_CANDIDATE") || r.tags.contains("BACKWARD_BRANCH_SYNC_WAIT")) return "sync_wait_loop";
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
            || t.callers.size() >= 8;
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
    // Per-function recommendation. Pure derivation from existing data.
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
        if(t.isCtor || t.methodClassName != null || t.ctorClassName != null){ df.add("RULE_93_CLASS_REGISTRY"); }
        if(!t.assetUploadTagsHit.isEmpty() || r.tags.contains("UPLOADER_CALLER_D1") || r.tags.contains("ASSET_UPLOAD_BULLSEYE")){ ev.add("asset_upload trace"); df.add("RULE_103_ASSET_UPLOAD_TRACES"); }
        if(t.overrideKind != null){ ev.add("override_kind=" + t.overrideKind); df.add("RULE_98_OVERRIDE_COVERAGE"); }
        if(t.runtimeDormantGlobal){ ev.add("runtime: predicted but never witnessed (dormant)"); }
        if(t.runtimeMenuOnly){ ev.add("runtime: menu/UI pipeline only"); }

        // ---- decision tree (precedence: must-keep-real -> patch -> review -> safe-stub -> skip) ----
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
            || r.tags.contains("HOST_WAIT_CANDIDATE") || !t.patchCandidatePcs.isEmpty();
        boolean archive = t.refsArchiveStrings || t.callsFileOpen || !t.filePathSprintfFormats.isEmpty()
            || r.tags.contains("ARCHIVE_IO") || r.tags.contains("FILE_PATH_SPRINTF_SOURCE");
        boolean iop = t.callsSifRpc || t.isIrxLoader || t.isIopRebootHandler || r.tags.contains("IOP_RPC_DISPATCH")
            || r.tags.contains("IRX_LOADER") || t.detectedRpcSid != 0 || !t.allDetectedSids.isEmpty();
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
            rec.reason = "main loop / frame pump - the recompiler entry; stubbing halts the game";
            rec.riskIfStubbed = "game never advances a frame (hard hang)";
            rec.riskIfRecompiled = "none - this must run the real body";
            rec.suggestedNextStep = "force_recompile; never stub. Confirm it is the recompiler entry.";
            df.add("RULE_11_MAINLOOP_SHIELD");
        } else if(mustImpl){
            rec.action = "native_impl_needed"; rec.confidence = 0.90; rec.risk = "high"; rec.humanReview = true;
            rec.reason = "sceVu0 / must-implement math helper - a throwing or zero stub corrupts transforms";
            rec.riskIfStubbed = "degenerate/off-screen vertices, null transforms";
            rec.riskIfRecompiled = "n/a - needs a real native implementation, not raw recompile";
            rec.suggestedNextStep = "implement from ref/assembly.txt; cross-check sce_vu0_unimplemented[]";
            df.add("RULE_102_SCEVU0_MUSTIMPL");
        } else if(allocator){
            rec.action = "force_recompile"; rec.confidence = 0.92; rec.risk = "critical"; rec.humanReview = true;
            rec.reason = "memory allocator / pool - a 0-returning stub yields construct-on-null and a garbage vtable PC";
            rec.riskIfStubbed = "Alloc returns 0 -> null-vtable crash deep in an init chain";
            rec.riskIfRecompiled = "low - recompile the real body or supply a real allocator shim";
            rec.suggestedNextStep = "never auto-stub; recompile real body. See memory_allocators[].";
            df.add("RULE_142_MEMORY_ALLOCATOR");
        } else if(cop2Codegen){
            rec.action = "force_recompile"; rec.confidence = 0.85; rec.risk = "high"; rec.humanReview = true;
            rec.reason = "COP2 partial-dest / special-op - verify generated dest-mask lane order";
            rec.riskIfStubbed = "3D transforms break";
            rec.riskIfRecompiled = "lane-order codegen bug if the mask is reversed - verify against READ128/WRITE128";
            rec.suggestedNextStep = "force_recompile then verify COP2 dest-mask lane order. See cop2_partial_dest_risk[].";
            df.add("RULE_140_COP2_DESTMASK"); if(!t.cop2SpecialOps.isEmpty()) df.add("RULE_147_COP2_SPECIAL_OPS");
        } else if(uploader){
            rec.action = "force_recompile"; rec.confidence = 0.85; rec.risk = "high"; rec.humanReview = true;
            rec.reason = "texture/CLUT uploader (BITBLTBUF) - drives VRAM; a stub leaves textures black";
            rec.riskIfStubbed = "missing / black textures";
            rec.riskIfRecompiled = "low - recompile the real upload body";
            rec.suggestedNextStep = "force_recompile; cross-check tbp vs gs_runtime_evidence.";
            df.add("RULE_85_BITBLTBUF_T4HH"); df.add("RULE_103_ASSET_UPLOAD_TRACES");
            if(t.isPsmct16ClutUploader) df.add("RULE_145_PSMCT16_CLUT");
        } else if(lifecycle){
            rec.action = "force_recompile"; rec.confidence = 0.85; rec.risk = "high"; rec.humanReview = true;
            rec.reason = "constructor / vtable / struct initializer - writes object fields or the vtable pointer";
            rec.riskIfStubbed = "uninitialized fields / null vtable -> silent no-op or crash on next virtual call";
            rec.riskIfRecompiled = "low - recompile real body";
            rec.suggestedNextStep = "force_recompile; never stub. See classes[] for this class.";
            df.add("RULE_82_CTOR_MULTI_FIELD"); df.add("RULE_93_CLASS_REGISTRY");
            if(t.ctorInstallsVtable || r.tags.contains("VTABLE_SETTER")) df.add("RULE_27_VTABLE_SETTER");
        } else if(staticInit){
            rec.action = "force_recompile"; rec.confidence = 0.80; rec.risk = "high"; rec.humanReview = true;
            rec.reason = "static initializer (__sinit) - installs a global vtable/fields via the global-ctors table";
            rec.riskIfStubbed = "global object vtable stays null -> next virtual dispatch no-ops";
            rec.riskIfRecompiled = "low - but ensure the global-ctors table actually runs";
            rec.suggestedNextStep = "ensure global-ctors run, or replay static_init_manifest[].";
            df.add("RULE_141_STATIC_INIT");
        } else if(renderHw){
            rec.action = "force_recompile"; rec.confidence = 0.80; rec.risk = "high"; rec.humanReview = true;
            rec.reason = "render / GS / GIF / VIF / DMA packet path - must emit real hardware packets";
            rec.riskIfStubbed = "frame not drawn / GS desync";
            rec.riskIfRecompiled = "low - recompile real body; verify against gs_runtime_evidence path counts";
            rec.suggestedNextStep = "force_recompile; review against gs_runtime_evidence.";
            df.add("RULE_44_PATH3"); df.add("RULE_61_GIF_PATH3");
            if(t.drawingChainDepth >= 0) df.add("RULE_83_DRAWING_CHAIN_DEPTH");
        } else if(archive && t.callsFileOpen){
            rec.action = "native_impl_needed"; rec.confidence = 0.75; rec.risk = "high"; rec.humanReview = true;
            rec.reason = "archive / file loader - needs real host file I/O";
            rec.riskIfStubbed = "no asset data loaded -> empty world / immediate failure";
            rec.riskIfRecompiled = "medium - file-open callees need host shims regardless";
            rec.suggestedNextStep = "provide native file-I/O shim; see file_path_sprintf_formats.";
            df.add("RULE_23_ARCHIVE_IO"); df.add("RULE_99_FILE_PATH_SPRINTF");
        } else if(archive){
            rec.action = "review"; rec.confidence = 0.50; rec.risk = "medium"; rec.humanReview = true;
            rec.reason = "references archive strings but no file-open callee - classify before any action";
            rec.suggestedNextStep = "review whether this is a loader or a path/string builder.";
            df.add("RULE_23_ARCHIVE_IO");
        } else if(iop){
            rec.action = "review"; rec.confidence = 0.55; rec.risk = "high"; rec.humanReview = true;
            rec.reason = "IOP RPC / IRX loader / SIF bridge - host IOP services must be wired before stubbing";
            rec.riskIfStubbed = "missing IOP service (audio / MC / cdvd) - subsystem dead";
            rec.riskIfRecompiled = "medium - RPC targets resolve on the IOP side";
            rec.suggestedNextStep = "review against discovered_iop_sids / known_iop_sids; wire host service.";
            df.add("RULE_22_IOP_RPC"); if(t.isIrxLoader) df.add("RULE_124_IRX_LOADER");
            if(!t.allDetectedSids.isEmpty()) df.add("RULE_139_DISCOVERED_SIDS");
        } else if(patchable){
            rec.action = "patch_candidate"; rec.confidence = 0.60; rec.risk = "high"; rec.humanReview = true;
            rec.reason = "sync-wait / infinite-fail loop - needs a host-wait patch, not a stub";
            rec.riskIfStubbed = "deadlock or busy spin";
            rec.riskIfRecompiled = "high - naive recompile re-creates the guest spin/deadlock";
            rec.suggestedNextStep = "apply BACKWARD_BRANCH_SYNC_WAIT / HOST_WAIT patch at the patch-candidate PCs.";
            df.add("RULE_121_SYNC_WAIT"); df.add("RULE_123_INFINITE_FAIL_LOOP");
        } else if(mcGate){
            if(overrideSafe){
                rec.action = "stub_candidate"; rec.confidence = 0.70; rec.risk = "medium"; rec.humanReview = true;
                rec.reason = "memory-card transition gate; override system already classifies a safe " + t.overrideKind;
                rec.suggestedNextStep = "apply the existing override " + t.overrideKind + ".";
                df.add("RULE_98_OVERRIDE_COVERAGE");
            } else {
                rec.action = "review"; rec.confidence = 0.50; rec.risk = "medium"; rec.humanReview = true;
                rec.reason = "memory-card transition gate - review the save/load state machine before any action";
                rec.suggestedNextStep = "review; only stub if a rule already marks this pattern safe.";
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
                rec.reason = "pad polling / button-mask consumer - wire host input before stubbing";
                rec.suggestedNextStep = "review; corroborate with pad input scripts.";
            }
            df.add("RULE_24_PAD_POLL"); if(t.isPadButtonMaskConsumer) df.add("RULE_97_PAD_MASK");
        } else if(indirect){
            rec.action = "review"; rec.confidence = 0.45; rec.risk = "high"; rec.humanReview = true;
            rec.reason = "indirect / computed control flow - resolve dispatch targets before any patch";
            rec.riskIfStubbed = "recompiler may panic on an unresolved indirect jump";
            rec.riskIfRecompiled = "medium - unresolved targets must be pre-populated";
            rec.suggestedNextStep = "review computed_jump_targets / virtual_dispatch_sites; never auto-patch.";
            if(t.indirectCallT9Count > 0) df.add("RULE_38_INDIRECT_CALL_T9");
            if(!t.virtualDispatchSites.isEmpty()) df.add("RULE_94_VIRTUAL_DISPATCH");
            if(r.tags.contains("TABLE_DISPATCH_CALL") || r.tags.contains("DISPATCH_TABLE_TARGET")) df.add("RULE_128_TABLE_DISPATCH");
            if(!t.computedJumpSwitchPcs.isEmpty()) df.add("RULE_146_COMPUTED_JUMP");
        } else if(gsIrqSafe){
            rec.action = "stub_candidate"; rec.confidence = 0.85; rec.risk = "low"; rec.humanReview = false;
            rec.reason = "GS IRQ handler - IMR=0x7F00 masks all GS IRQs across every loaded checkpoint -> can never fire";
            rec.riskIfStubbed = "none - handler is unreachable at runtime";
            rec.riskIfRecompiled = "none";
            rec.suggestedNextStep = "safe to stub per runtime evidence (gs_runtime_evidence.imr_all_masked_gs_irqs).";
            df.add("RULE_79_GS_IRQ_HANDLER"); df.add("RULE_80_RUNTIME_CORROBORATION");
        } else if(overrideSafe){
            rec.action = "stub_candidate"; rec.confidence = 0.80; rec.risk = "low"; rec.humanReview = false;
            rec.reason = "override system already classified a safe " + t.overrideKind;
            rec.riskIfStubbed = "low - existing override already validated";
            rec.suggestedNextStep = "apply the existing override " + t.overrideKind + ".";
            df.add("RULE_98_OVERRIDE_COVERAGE");
        } else if(kernelSkip){
            rec.action = "skip_candidate"; rec.confidence = 0.85; rec.risk = "low"; rec.humanReview = false;
            rec.reason = "kernel-internal (syscall / COP0) - provided by HLE; the existing firewall already skips it";
            rec.riskIfStubbed = "n/a - skipped, HLE provides behavior";
            rec.suggestedNextStep = "leave as SKIP.";
            df.add("RULE_3_SYSCALL_FIREWALL");
        } else if(r.tags.contains("LIBGCC_INTRINSIC")){
            rec.action = "force_recompile"; rec.confidence = 0.70; rec.risk = "medium"; rec.humanReview = false;
            rec.reason = "libgcc / FP intrinsic - needs the real arithmetic body (auto-stub corrupts math)";
            rec.riskIfStubbed = "wrong arithmetic results (div/mod/float)";
            rec.riskIfRecompiled = "low";
            rec.suggestedNextStep = "force_recompile (existing triage already promotes these from STUB).";
            df.add("RULE_31_LIBGCC");
        } else if(firewalledStub){
            rec.action = "stub_candidate"; rec.confidence = 0.70; rec.risk = "low"; rec.humanReview = false;
            rec.reason = "IOP-module / firewalled wrapper - the existing radar/IOP firewall already stubs it";
            rec.riskIfStubbed = "low - firewall-confirmed";
            rec.suggestedNextStep = "apply the existing firewall stub.";
            df.add("RULE_2_RADAR_FIREWALL");
        } else if(safeLeaf){
            rec.action = "force_recompile"; rec.confidence = 0.60; rec.risk = "low"; rec.humanReview = false;
            rec.reason = "safe leaf - small, no callees, no MMIO; recompiling the real body is low-risk";
            rec.riskIfStubbed = "medium - even leaves may carry meaningful return values";
            rec.riskIfRecompiled = "low";
            rec.suggestedNextStep = "force_recompile (low risk).";
            df.add("RULE_1_SAFE_LEAF");
        } else {
            // Fallback: map from the existing disposition.
            if("RECOMPILE".equals(r.disposition)){
                rec.action = "force_recompile"; rec.confidence = 0.55;
                rec.risk = (t.writesToGlobal || t.usesCop1 || t.usesCop2 || t.accessesMMIO) ? "medium" : "low";
                rec.humanReview = false;
                rec.reason = "default: translate the real body (no hazard or safe-stub signal fired)";
                rec.suggestedNextStep = "force_recompile.";
            } else if("STUB".equals(r.disposition)){
                rec.action = "review"; rec.confidence = 0.40; rec.risk = "medium"; rec.humanReview = true;
                rec.reason = "existing triage stubbed it but no confirming safe-stub rule fired - review before trusting the stub";
                rec.suggestedNextStep = "review whether the stub is safe.";
            } else {
                rec.action = "review"; rec.confidence = 0.40; rec.risk = "medium"; rec.humanReview = true;
                rec.reason = "no specific signal - review";
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
        if(rec.riskIfStubbed.isEmpty()) rec.riskIfStubbed = "unknown - verify before stubbing";
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
        // nearby important functions (callers intersect important, callees intersect important-names)
        w.print("\"nearby_important_functions\": [");
        { LinkedHashSet<String> near = new LinkedHashSet<>();
          for(long[] c : t.callers){ long ca = c[0] & 0xFFFFFFFFL;
            if(importantAddrs.contains(ca)){ String cn = nameByAddr.get(ca); if(cn != null && !cn.isEmpty()) near.add(cn); } }
          for(String cn : t.calleeNames){ if(importantNames.contains(cn)) near.add(cn); }
          int n = 0; boolean f = true;
          for(String s : near){ if(n >= 8) break; if(!f) w.print(", "); f = false; w.print(jsonString(s)); n++; } }
        w.print("], ");
        w.print("\"known_chain_membership\": [], ");
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
        if(t.mainLoopDepth >= 0) df.add("RULE_39_MAINLOOP_DEPTH");
        if(t.initChainDepth >= 0) df.add("RULE_40_INIT_CHAIN_DEPTH");
        if(t.drawingChainDepth >= 0) df.add("RULE_83_DRAWING_CHAIN_DEPTH");
        df.add("RULE_21_REVERSE_CALLGRAPH");
        w.print("\"derived_from\": " + jsonStrArray(df));
        w.print("}");
    }

    // -------------------------------------------------------------------------
    // Top-level blocks
    // -------------------------------------------------------------------------
    private void buildDecisionConstraints(PrintWriter w){
        w.println("  \"decision_constraints\": {");
        w.println("    \"schema_version\": \"1.0\",");
        w.println("    \"purpose\": \"Hard guardrails so a downstream AI never makes a destructive recommendation; derived from existing dangerous-tag rules.\",");
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
        w.println("    \"purpose\": \"AI-facing summary layer derived from existing triage signals (focus_set, runtime_corroboration, module clusters, class registry, override coverage). Pointers + rationale, not a copy of the raw JSON.\",");
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

    /** Next-rule hints - only emitted when there is repeated evidence THIS run. */
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
                    "MODULE_CLUSTER_" + e.getKey() + "_CLASSIFIER", "medium", ex,
                    Arrays.asList("RULE_129_MODULE_CLUSTERS")));
        }
        // 2) archive-string references with no recognized loader
        { int c = 0; List<Long> ex = new ArrayList<>();
          for(FuncResult r : results){ FuncTraits t = r.traits; if(t == null) continue;
            if(t.refsArchiveStrings && !t.callsFileOpen && "UNCATEGORIZED".equals(r.category)){ c++; if(ex.size() < 5) ex.add(r.address & 0xFFFFFFFFL); } }
          if(c >= 3) out.add(ruleCandidate(
            c + " functions reference archive strings but call no known file-open API",
            "Repeated archive-string references without a recognized loader suggest a custom/inlined archive reader worth its own rule.",
            Arrays.asList(c + " archive-string refs w/o file-open"),
            "INLINE_ARCHIVE_READER", "medium", ex,
            Arrays.asList("RULE_23_ARCHIVE_IO", "RULE_99_FILE_PATH_SPRINTF"))); }
        // 3) BITBLTBUF writers not covered by an existing uploader rule
        { int c = 0; List<Long> ex = new ArrayList<>();
          for(FuncResult r : results){ FuncTraits t = r.traits; if(t == null) continue;
            if(t.writesBitbltbufReg && !t.isBitbltbufT4hhUploader && !t.bitbltbufMacroSequence && !t.isPsmct16ClutUploader){ c++; if(ex.size() < 5) ex.add(r.address & 0xFFFFFFFFL); } }
          if(c >= 3) out.add(ruleCandidate(
            c + " BITBLTBUF writers are matched by no specific uploader rule",
            "Uncovered BITBLTBUF writers may be a new texture/CLUT upload shape.",
            Arrays.asList(c + " uncovered BITBLTBUF writers"),
            "UNCOVERED_BITBLTBUF_UPLOADER", "high", ex,
            Arrays.asList("RULE_85_BITBLTBUF_T4HH", "RULE_145_PSMCT16_CLUT"))); }
        // 4) virtual-dispatch sites with no resolved class
        { int c = 0; List<Long> ex = new ArrayList<>();
          for(FuncResult r : results){ FuncTraits t = r.traits; if(t == null) continue;
            if(!t.virtualDispatchSites.isEmpty() && t.methodClassName == null && t.ctorClassName == null){ c++; if(ex.size() < 5) ex.add(r.address & 0xFFFFFFFFL); } }
          if(c >= 3) out.add(ruleCandidate(
            c + " functions have virtual-dispatch sites but no resolved class",
            "Indirect dispatch targets not yet assigned to a class are unresolved vtable risk; a class-resolution rule would help.",
            Arrays.asList(c + " virtual-dispatch funcs w/o class"),
            "UNRESOLVED_VTABLE_CLASS", "medium", ex,
            Arrays.asList("RULE_94_VIRTUAL_DISPATCH", "RULE_128_TABLE_DISPATCH"))); }
        // 5) complex control flow that landed in subsystem=unknown
        { int c = 0; List<Long> ex = new ArrayList<>();
          for(FuncResult r : results){ AiRec rec = aiRecs.get(r.address & 0xFFFFFFFFL);
            if(rec != null && "unknown".equals(rec.subsystem) && r.tags.contains("COMPLEX_CONTROL_FLOW")){ c++; if(ex.size() < 5) ex.add(r.address & 0xFFFFFFFFL); } }
          if(c >= 4) out.add(ruleCandidate(
            c + " COMPLEX_CONTROL_FLOW functions remain in subsystem=unknown",
            "Many unclassified jump-table / complex functions share a pattern no current subsystem rule captures.",
            Arrays.asList(c + " unknown COMPLEX_CONTROL_FLOW"),
            "COMPLEX_FLOW_SUBSYSTEM_HINT", "low", ex,
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
            case "render":           return Arrays.asList("RULE_44_PATH3","RULE_83_DRAWING_CHAIN_DEPTH","RULE_61_GIF_PATH3");
            case "texture_upload":   return Arrays.asList("RULE_85_BITBLTBUF_T4HH","RULE_103_ASSET_UPLOAD_TRACES","RULE_145_PSMCT16_CLUT");
            case "archive_io":       return Arrays.asList("RULE_23_ARCHIVE_IO","RULE_99_FILE_PATH_SPRINTF");
            case "input":            return Arrays.asList("RULE_24_PAD_POLL","RULE_97_PAD_MASK");
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
        w.println("    \"purpose\": \"AI-facing abstraction over existing callgraph, module, class, and runtime evidence. Not a second source of truth.\",");
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
        w.println("    ]");
        w.println("  },");
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
