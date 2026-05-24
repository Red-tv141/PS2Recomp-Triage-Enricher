// PS2Recomp Triage Enricher v3 — Ghidra Script (Step 2 of Pipeline)
// ==================================================================
// Run AFTER ExportPS2Functions.java on the same Ghidra project.
//
// WHAT'S NEW IN v3 (learned from DC2 Phase F3–F12 triage):
//
//  Rule 18 — DC2 GAME OVERRIDE PARSER
//      Reads a dc2_game_override.cpp (or any *_game_override.cpp) and
//      imports every bindAddressHandler / registerFunction address as
//      already-classified. Prevents re-stubbing functions that the
//      runtime has already manually bound.
//
//  Rule 19 — CONVENTION_VIOLATION tag
//      Detects functions where Ghidra's decompiler reports a0/a1 arg
//      aliasing or where the function writes to $a1 as if it were a
//      return buffer (pattern from GetFullPath__FPcPc bug in Phase F5).
//
//  Rule 20 — INIT_LARGE_FUNC guard
//      Functions named *init* / *Init* / *__ct__* / *__sinit_* that
//      have calleeCount > 10 OR byteSize > 2000 are tagged
//      INIT_LARGE_FUNC and forced to RECOMPILE (not nop-stubbed).
//      Prevents the Phase F4 bug where init__Fv (large, spawns threads)
//      was silently nop'd.
//
//  Rule 21 — DMA_CHAIN_TTE_RISK tag
//      Functions that call both a DMA Send variant AND touch VIF1-range
//      MMIO (0x10009000) are tagged DMA_CHAIN_TTE_RISK. Flags potential
//      TTE=0 + embedded VIFcodes patterns (Phase F7 root cause).
//
//  Rule 22 — IOP_RPC_DISPATCH tag
//      Detects the sceSifCallRpc / sceSifBindRpc pattern + sid constant
//      scan. Extracts the SID literal if found, emits it into JSON for
//      cross-referencing with ps2_iop.cpp known SIDs.
//
//  Rule 23 — ARCHIVE_IO tag
//      Detects DATA.DAT / DATA.HD2 string references inside I/O
//      wrapper functions (from Phase F6). Tags for human review;
//      these are game-specific archive stubs that need real
//      implementations, not nop returns.
//
//  Rule 24 — PAD_POLL_LOOP tag
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
//      config_auto_recomp.toml  — unified config for ps2recomp.exe
//      triage_map.json          — full DNA map with new tags
//      assembly.txt / decompiled.txt / flowchart.txt  (unchanged)
//
// @author Puggsy + Claude (v3: DC2 Phase F3–F12 knowledge integration)
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

    // =========================================================
    // FIREWALL LISTS
    // Rule 1:  No DANGEROUS_KEYWORDS (removed in v2, kept removed)
    // Rule 2:  IOP_MODULE_STRINGS — .IRX/.irx + specific module names
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
        "sceDevFont","sceDevCons",         // debug console — nop safe
        "sceMSIn",                         // MIDI input — nop safe
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
    private static final String[] IOP_MODULE_STRINGS = {
        "loadcore","iopmac","iopheap","threadman","sysclib","sifman","sifcmd",
        "cdvdman","cdvdfsv","mcman","xmcman","mcserv","atad","hdd","pfs",
        "sio2man","padman","xpadman","mtapman","libsd","sdrdrv","audsrv","modmidi",
        "usbd","dev9","smap","ps2smap","ps2ip",".IRX",".irx"
    };

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

    // Rule 10: Absolute whitelist — immune to ALL firewalls
    private static final String[] WHITELIST_NAMES = {
        "entry","_start","crt0","topThread","cmd_sem_init"
    };

    // Rule 24: Known pad-polling syscall names (for PAD_POLL_LOOP detection)
    private static final Set<String> PAD_POLL_CALLEES = new HashSet<>(Arrays.asList(
        "scePadGetState","scePadGetReqState","scePadRead",
        "sceGsSyncV","sceGsSyncVCallback","WaitVSync"
    ));

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
        // Rule 25: Thread sync point — syscall + backward branch + small size, NOT IOP module.
        // Phase F blocker: EE thread parked at pc=0x100008 waiting on IOP response.
        // These functions spin on a syscall (WaitSema/SleepThread/etc.) until IOP replies.
        // They must NOT be nop-stubbed — the thread scheduler depends on them.
        boolean isThreadSyncPoint=false;
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

    // =========================================================
    // ENTRY POINT
    // =========================================================
    @Override
    public void run() throws Exception {
        funcManager = currentProgram.getFunctionManager();
        refManager = currentProgram.getReferenceManager();
        memory = currentProgram.getMemory();

        println("=========================================================");
        println("PS2Recomp TRIAGE ENRICHER v3 — DC2-aware (Rules 18-24)");
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
                "Select dc2_game_override.cpp (or similar) — Cancel to skip","Open");
            if (overrideFile!=null && overrideFile.exists()) {
                parseGameOverrideFile(overrideFile);
                println(String.format("[OVERRIDE] Imported %d pre-bound addresses from %s.",
                    gameOverrideImportedCount, overrideFile.getName()));
            } else {
                println("[OVERRIDE] Skipped — no game override file selected.");
            }
        } catch (Exception ignored) {
            println("[OVERRIDE] Skipped (dialog cancelled).");
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
            println("[MAINLOOP] Shield: "+mainLoopShield.size()+" functions protected.\n");
        } else {
            println("[MAINLOOP] No MainLoop found. Shield disabled.\n");
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
                boolean forceRecompile = traits.isLargeInitFunc;

                // --- Disposition decision ---
                String disposition = "RECOMPILE";
                if (!isWhitelisted && !forceRecompile) {
                    if (isRadarFirewalled(func)) {
                        disposition="STUB";
                        newStubs.add(funcName+"@"+hex(offset));
                        radarNewStubs++;
                    } else if (referencesIopModule(func,traits)) {
                        disposition="STUB";
                        newStubs.add(funcName+"@"+hex(offset));
                        radarNewStubs++;
                    } else if (isKernelInternal(func)) {
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
                // (vcallms implicitly "calls" VU0 — not safe for auto-translation)
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
    // DNA TRAIT SCANNER — v3 extended
    // =========================================================
    private FuncTraits getTraits(Function func) {
        Address key=func.getEntryPoint();
        if(cache.containsKey(key)) return cache.get(key);
        FuncTraits traits=new FuncTraits();
        traits.byteSize=func.getBody().getNumAddresses();

        Set<Function> callees=func.getCalledFunctions(monitor);
        traits.calleeCount=callees.size();
        for(Function callee:callees) {
            String cn=callee.getName();
            traits.calleeNames.add(cn);
            // Rule 21: DMA send detection — all sceDmaSend* / sceDmaChain* variants
            if(cn.startsWith("sceDmaSend")||cn.startsWith("sceDmaChain")||
               cn.equals("sceDmaRecv")||cn.equals("sceDmaRecvN"))
                traits.callsDmaSend=true;
            // Rule 22: SIF RPC detection
            if(cn.equals("sceSifCallRpc")||cn.equals("sceSifBindRpc"))
                traits.callsSifRpc=true;
            // Rule 24: Pad poll callee detection
            if(PAD_POLL_CALLEES.contains(cn))
                traits.callsPadPollCallee=true;
        }

        int xrefCount=0;
        for(Reference ref:refManager.getReferencesTo(func.getEntryPoint()))
            if(ref.getReferenceType().isCall()||ref.getReferenceType().isFlow()) xrefCount++;
        traits.xrefToCount=xrefCount;
        traits.isThunk=func.isThunk()||(traits.byteSize<=8&&traits.calleeCount>0);
        if(traits.isThunk){cache.put(key,traits);return traits;}

        // Rule 20 (v3): Large init function detection
        String fname=func.getName();
        boolean isInitNamed = fname.toLowerCase().contains("init")||
                              fname.contains("__ct__")||fname.startsWith("__sinit_");
        if(isInitNamed&&(traits.calleeCount>10||traits.byteSize>2000))
            traits.isLargeInitFunc=true;

        // Rule 25: Thread sync point detection.
        // Pattern: contains a syscall instruction, has a backward branch (spin loop),
        // is small (< 300 bytes), and is NOT an IOP module loader (those are stubs).
        // Phase F blocker: EE thread at pc=0x100008 was stuck in one of these.
        // Detection deferred to post-scan (needs containsSyscall result).
        // Computed after instruction scan below — see traits.isThreadSyncPoint assignment.

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
            // [FIX] v3 was missing vmadda, vmsuba, vmula, vadda, vopmsub — the exact
            // instructions listed in the phase5 table. Phase5 functions were mis-classified.
            if(ml.startsWith("vmadda")||ml.startsWith("vmsuba")||ml.startsWith("vmula")||
               ml.startsWith("vadda") ||ml.equals("vopmsub")||
               ml.startsWith("madda") ||ml.startsWith("vmadd")||ml.startsWith("vmsub")||
               ml.startsWith("madd"))
                traits.accOps++;
            if(ml.equals("sync.l")||ml.equals("sync.p")||ml.equals("sync")) traits.hasSyncInstr=true;
            if(ml.equals("vcallms")||ml.equals("vcallmsr")) traits.hasVcallms=true;

            // Rule 17: jr + jump table
            if(ml.equals("jr")) {
                boolean isRa=false;
                for(Object op:inst.getInputObjects())
                    if(op instanceof ghidra.program.model.lang.Register) {
                        String rn=((ghidra.program.model.lang.Register)op).getName().toLowerCase();
                        if(rn.equals("ra")) isRa=true; else traits.hasJumpTable=true;
                    }
                if(isRa) traits.returnPaths++;
            }

            // Backward branch detection (improved BUSY_WAIT v3)
            if((ml.startsWith("b")&&!ml.equals("break"))||ml.equals("beqz")||ml.equals("bnez")) {
                traits.branchOps++;
                for(Object op:inst.getInputObjects())
                    if(op instanceof ghidra.program.model.address.Address) {
                        long target=((ghidra.program.model.address.Address)op).getOffset();
                        if(target<inst.getAddress().getOffset())
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
                // [FIX] Only scalar stores (sw/sh/sb/swc1) — NOT sqc2 (VU0 register dump).
                // sqc2 stores 128-bit VU0 regs, not output buffers.
                if(instrIdx<30 && (ml.equals("sw")||ml.equals("sh")||
                                   ml.equals("sb")||ml.equals("swc1"))) {
                    for(Object op:inst.getInputObjects())
                        if(op instanceof ghidra.program.model.lang.Register) {
                            String rn=((ghidra.program.model.lang.Register)op).getName().toLowerCase();
                            if(rn.equals("a1")) { traits.writesToA1Buffer=true; }
                        }
                }
            }

            if(ml.equals("jal")||ml.equals("jalr")){traits.hasMutatingInstructions=true;traits.callOps++;}

            // SPR + MMIO (Rule 4+5+21)
            for(Reference ref:inst.getReferencesFrom()) {
                long norm=normalizeAddress(ref.getToAddress().getOffset());
                if(norm>=SPR_START&&norm<=SPR_END) traits.usesSPR=true;
                if(!ref.getReferenceType().isCall()&&!ref.getReferenceType().isFlow()) {
                    if((norm>=MMIO_START&&norm<=MMIO_END)||(norm>=MMIO_GS_START&&norm<=MMIO_GS_END))
                        traits.accessesMMIO=true;
                    // Rule 21: VIF1 channel MMIO specifically
                    if(norm>=VIF1_CHANNEL_BASE&&norm<=VIF1_CHANNEL_END)
                        traits.accessesVif1MMIO=true;
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
            if(!traits.refsArchiveStrings) {
                for(Reference ref:inst.getReferencesFrom()) {
                    Data data=getDataAt(ref.getToAddress());
                    if(data!=null&&data.hasStringValue()) {
                        String str=data.getDefaultValueRepresentation();
                        for(String archStr:ARCHIVE_IO_STRINGS)
                            if(str.contains(archStr)){traits.refsArchiveStrings=true;break;}
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

        // BUSY_WAIT detection — v3 improved:
        // Original: small func + MMIO reads + branches
        boolean originalBusyWait = (totalInstrs>0&&totalInstrs<=15&&mmioReadCount>0&&traits.branchOps>=1);
        // v3 addition: backward branch + call to pad/vsync polling callee (Phase F3.5 pattern)
        boolean padVsyncBusyWait = traits.hasBackwardBranch&&traits.callsPadPollCallee&&traits.byteSize<400;
        traits.hasBusyWait = originalBusyWait||padVsyncBusyWait;

        // Rule 25: Thread sync point — set after full instruction scan.
        // syscall present + backward branch (spinning) + small + not IOP module loader.
        if(containsSyscall(func) && traits.hasBackwardBranch &&
           traits.byteSize < 300 && !referencesIopModule(func, traits))
            traits.isThreadSyncPoint = true;

        cache.put(key,traits);
        return traits;
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

    private boolean isKernelInternal(Function func) {
        Address key=func.getEntryPoint();
        Boolean c=behavFwCache.get(key);if(c!=null)return c;
        boolean k=containsSyscall(func)||containsCOP0(func);
        behavFwCache.put(key,k);return k;
    }

    private boolean referencesIopModule(Function func,FuncTraits traits) {
        if(traits.byteSize>800) return false;
        Address key=func.getEntryPoint();
        Boolean c=iopFwCache.get(key);if(c!=null)return c;
        InstructionIterator it=currentProgram.getListing().getInstructions(func.getBody(),true);
        while(it.hasNext()) {
            for(Reference ref:it.next().getReferencesFrom()) {
                Data data=getDataAt(ref.getToAddress());
                if(data!=null&&data.hasStringValue()) {
                    String str=data.getDefaultValueRepresentation();
                    for(String s:IOP_MODULE_STRINGS)if(str.contains(s)){iopFwCache.put(key,true);return true;}
                }
            }
        }
        iopFwCache.put(key,false);return false;
    }

    private boolean containsSyscall(Function func) {
        InstructionIterator it=currentProgram.getListing().getInstructions(func.getBody(),true);
        while(it.hasNext()){String m=it.next().getMnemonicString();if(m!=null&&m.equalsIgnoreCase("syscall"))return true;}
        return false;
    }

    private boolean containsCOP0(Function func) {
        InstructionIterator it=currentProgram.getListing().getInstructions(func.getBody(),true);
        while(it.hasNext()) {
            String m=it.next().getMnemonicString();if(m==null)continue;m=m.toLowerCase();
            if(m.equals("di")||m.equals("ei")||m.equals("mfc0")||m.equals("mtc0")||
               m.equals("eret")||m.startsWith("c0")) return true;
        }
        return false;
    }

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
            }
        }
        PrintWriter w=new PrintWriter(new FileWriter(outFile));
        for(String l:lines)w.println(l);
        w.close();
    }

    // =========================================================
    // JSON OUTPUT — v3 extended with new fields
    // =========================================================
    private void writeTriageJson(File outFile,List<FuncResult> results,
                                 String elfHash,long gpValue,
                                 int totalFuncs,int uncategorized) throws IOException {
        PrintWriter w=new PrintWriter(new FileWriter(outFile));
        w.println("{");
        w.println("  \"schema_version\": 3,");
        w.println("  \"elf_hash\": \""+elfHash+"\",");
        if(gpValue!=0)w.println("  \"global_pointer\": \""+hex(gpValue)+"\",");
        w.println("  \"text_range\": { \"start\": \""+hex(textStart)+"\", \"end\": \""+hex(textEnd)+"\" },");
        w.println("  \"mainloop_shield_size\": "+mainLoopShield.size()+",");
        w.println("  \"game_override_imported\": "+gameOverrideImportedCount+",");
        w.println("  \"statistics\": {");
        w.println("    \"total_functions\": "+totalFuncs+",");
        w.println("    \"uncategorized_from_step1\": "+uncategorized+",");
        w.println("    \"enriched_count\": "+results.size()+",");
        // v2 counters
        w.println("    \"safe_leaf\": "+safeLeafCount+",");
        w.println("    \"acc_hazard\": "+accHazardCount+",");
        w.println("    \"mmio_access\": "+mmioCount+",");
        w.println("    \"smc_hazard\": "+smcHazardCount+",");
        w.println("    \"spr_sync\": "+sprSyncCount+",");
        w.println("    \"busy_wait\": "+busyWaitCount+",");
        w.println("    \"vcallms\": "+vcallmsCount+",");
        w.println("    \"jump_tables\": "+jumpTableCount+",");
        w.println("    \"orphan_code\": "+orphanCount+",");
        // v3 counters
        w.println("    \"convention_violation\": "+conventionViolationCount+",");
        w.println("    \"init_large_func\": "+initLargeFuncCount+",");
        w.println("    \"dma_tte_risk\": "+dmaTteRiskCount+",");
        w.println("    \"iop_rpc_dispatch\": "+iopRpcCount+",");
        w.println("    \"archive_io\": "+archiveIoCount+",");
        w.println("    \"pad_poll_loop\": "+padPollLoopCount+",");
        w.println("    \"thread_sync_point\": "+threadSyncCount);
        w.println("  },");
        // Known IOP SIDs for cross-reference
        w.println("  \"known_iop_sids\": {");
        boolean firstSid=true;
        for(Map.Entry<Long,String> e:KNOWN_IOP_SIDS.entrySet()){
            if(!firstSid)w.println(","); firstSid=false;
            w.print("    \""+hex(e.getKey())+"\": \""+e.getValue()+"\"");
        }
        w.println("\n  },");
        // Game override address map
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
            // v3 fields
            w.print("\"accesses_vif1_mmio\": "+t.accessesVif1MMIO+", ");
            w.print("\"calls_dma_send\": "+t.callsDmaSend+", ");
            w.print("\"calls_sif_rpc\": "+t.callsSifRpc+", ");
            w.print("\"detected_rpc_sid\": "+(t.detectedRpcSid!=0?("\""+hex(t.detectedRpcSid)+"\""):"null")+", ");
            w.print("\"refs_archive_strings\": "+t.refsArchiveStrings+", ");
            w.print("\"calls_pad_poll_callee\": "+t.callsPadPollCallee+", ");
            w.print("\"has_backward_branch\": "+t.hasBackwardBranch+", ");
            w.print("\"writes_to_a1_buffer\": "+t.writesToA1Buffer+", ");
            w.print("\"is_large_init_func\": "+t.isLargeInitFunc+", ");
            w.print("\"is_thread_sync_point\": "+t.isThreadSyncPoint);
            w.print("}, ");
            w.print("\"tags\": [");
            for(int j=0;j<r.tags.size();j++){if(j>0)w.print(", ");w.print("\""+r.tags.get(j)+"\"");}
            w.print("], ");
            w.print("\"callees\": [");
            for(int j=0;j<t.calleeNames.size();j++){if(j>0)w.print(", ");w.print(jsonString(t.calleeNames.get(j)));}
            w.print("]}");
            if(i<results.size()-1)w.println(",");else w.println();
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
}
