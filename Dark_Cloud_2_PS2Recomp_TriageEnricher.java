// PS2Recomp Triage Enricher v7 - Ghidra Script (Step 2 of Pipeline)
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
    // Known GS register name map (emitted to JSON for the report tool to label hits).
    private static final Map<Long,String> KNOWN_GS_REGS = new LinkedHashMap<>();
    static {
        KNOWN_GS_REGS.put(0x00L, "PRIM");
        KNOWN_GS_REGS.put(0x01L, "RGBAQ");
        KNOWN_GS_REGS.put(0x05L, "XYZ2");
        KNOWN_GS_REGS.put(0x06L, "TEX0_1");
        KNOWN_GS_REGS.put(0x07L, "TEX0_2");
        KNOWN_GS_REGS.put(0x4CL, "FRAME_1");
        KNOWN_GS_REGS.put(0x4DL, "FRAME_2");
        KNOWN_GS_REGS.put(0x4EL, "ZBUF_1");
        KNOWN_GS_REGS.put(0x4FL, "ZBUF_2");
        KNOWN_GS_REGS.put(0x50L, "BITBLTBUF");
        KNOWN_GS_REGS.put(0x51L, "TRXPOS");
        KNOWN_GS_REGS.put(0x52L, "TRXREG");
        KNOWN_GS_REGS.put(0x53L, "TRXDIR");
        KNOWN_GS_REGS.put(0x59L, "DISPFB1");
        KNOWN_GS_REGS.put(0x5BL, "DISPFB2");
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
        // Same offsets in signed-16 form (Ghidra sometimes emits negative scalar)
        KNOWN_DC2_GP_OFFSETS.put(-0x77E8L & 0xFFFFFFFFL, "mgDBuffID");
        KNOWN_DC2_GP_OFFSETS.put(-0x788CL & 0xFFFFFFFFL, "mgVif1Packet");
        KNOWN_DC2_GP_OFFSETS.put(-0x6684L & 0xFFFFFFFFL, "TitleInfo");
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

                // Rule 56 (v5, extended by v6): derived top-priority bullseye.
                // v6 adds: WRITES_IPU_CMD, GIF_PATH3_REG_TOUCHER, PSMT4HH_REFERENCE,
                // VIF_MPG_OPCODE_BUILDER (microcode upload bullseye).
                if (traits.isSceGifPkRefLoadImage || traits.path3Initiator ||
                    traits.path3KickViaDmaApi || traits.writesDispfbViaSdk ||
                    traits.isBitbltbufT4hhUploader ||
                    (traits.writesZbufReg && (traits.hasShift24Pattern||traits.hasDsll32OrDsrl32)) ||
                    traits.writesGsPrimReg || traits.touchesGifCtrl ||
                    traits.callsMpegFamily || traits.writesIpuCmd ||
                    traits.touchesGifP3Reg || traits.loadsPsm4hhConstant ||
                    traits.vifOpcodesBuilt.contains("MPG")) {
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

            writeUnifiedConfig(unifiedToml,configToml,newStubs,newSkips);
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
    private void parseGameOverrideFile(File f) throws IOException {
        BufferedReader reader = new BufferedReader(new FileReader(f));
        String line;
        // Regex-free: look for 0x literal after '(' on lines containing
        // bindAddressHandler or registerFunction.
        while ((line=reader.readLine())!=null) {
            String t = line.trim();
            if (!t.contains("bindAddressHandler")&&!t.contains("registerFunction")) continue;
            // Extract hex address: first 0x... token
            long addr = extractFirstHexLiteral(t);
            if (addr<=0) continue;
            // Extract optional name (second string arg in bindAddressHandler)
            String name = extractQuotedString(t);
            gameOverrideAddresses.add(addr);
            if (name!=null&&!name.isEmpty()) gameOverrideNames.put(addr,name);
            gameOverrideImportedCount++;
        }
        reader.close();
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
        // Forced RECOMPILE downstream — auto-stub halts the runner on first call (F23a).
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

            // v4 Rule 38: jalr $t9 — PIC / vtable indirect call
            if(ml.equals("jalr")) {
                for(Object op : inst.getInputObjects())
                    if(op instanceof ghidra.program.model.lang.Register &&
                       ((ghidra.program.model.lang.Register)op).getName().equalsIgnoreCase("t9"))
                        traits.indirectCallT9Count++;
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
                        // v7 Rule 78: TBP-shape constant via addiu/li (14-bit positive).
                        if(imm > 0 && imm <= 0x3FFFL)
                            traits.tbpConstantsLoaded.add(imm);
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

        cache.put(key,traits);
        return traits;
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
                                    List<String> newStubs,List<String> newSkips) throws IOException {
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
        lines.add(0,"# Unified config: "+step1Config.getName()+" + "+newStubs.size()+" stubs + "+newSkips.size()+" skips (Enricher v3)");
        for(int i=0;i<lines.size();i++){
            String l=lines.get(i);
            if(l.startsWith("stub_count =")){
                int old=Integer.parseInt(l.split("=")[1].trim());
                lines.set(i,"stub_count = "+(old+newStubs.size()));
            } else if(l.startsWith("skip_count =")){
                int old=Integer.parseInt(l.split("=")[1].trim());
                lines.set(i,"skip_count = "+(old+newSkips.size()));
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
        PrintWriter w=new PrintWriter(new FileWriter(outFile));
        for(String l:lines)w.println(l);
        w.close();
    }

    // =========================================================
    // JSON OUTPUT - v3 extended with new fields
    // =========================================================
    private void writeTriageJson(File outFile,List<FuncResult> results,
                                 String elfHash,long gpValue,
                                 int totalFuncs,int uncategorized) throws IOException {
        PrintWriter w=new PrintWriter(new FileWriter(outFile));
        w.println("{");
        w.println("  \"schema_version\": 7.1,");
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
        w.println("    \"drawing_chain_funcs\": "+drawingChainCount);
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
            w.print("\"is_lifecycle_lazy_init\": "+t.isLifecycleLazyInit);
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
                        ", \"runtime_status\": "+jsonString(t.runtimeStatus)+"}");
                if(i<focus.size()-1) w.println(","); else w.println();
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

