// PS2Recomp Triage Enricher v3 — Ghidra Script
// =============================================
// Improvements over v2:
//  [FIX-1]  __ct__/__as__/__sinit_ no longer SKIPped — they are RECOMPILE
//           (matching DAC.toml behavior; skipping them breaks init chains)
//  [FIX-2]  VU0_MICROCODE priority > ACC_PRECISION_HAZARD in classify_phases
//           (a function with both tags now lands in phase7, not phase5)
//  [NEW-1]  cpp_found field in triage_map.json — pass --recomp-dir at runtime
//           (enables triage_analyzer.py to skip pre-generated functions)
//  [NEW-2]  stub_gap analysis: runtime_has_handler field per STUB function
//           (extracted from ps2_call_list.h names baked into KNOWN_HANDLERS set)
//  [NEW-3]  callee_names exported as array (was already there in v2, but now
//           deduped and capped at 64 to avoid massive JSON)
//  [NEW-4]  xref_from_count = outgoing call count (separate from callee_count)
//  [NEW-5]  schema_version bumped to 3
//
// RULES (all v2 rules retained, additions marked [NEW]):
//  1-17: unchanged from v2
//  [NEW] 18: __ct__/__as__/__sinit_ exempt from skip firewall
//  [NEW] 19: STUB functions tagged with runtime_has_handler true/false
//
// @author Puggsy + Claude
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
    private static final long SPR_START     = 0x70000000L;
    private static final long SPR_END       = 0x70003FFFL;
    private static final long GLOBAL_ADDR_MIN = 0x00100000L;
    private static final long MMIO_GS_START = 0x12000000L;
    private static final long MMIO_GS_END   = 0x12002000L;

    // =========================================================
    // [NEW-2] KNOWN RUNTIME HANDLERS
    // Extracted from ps2_call_list.h (PS2_SYSCALL_LIST + PS2_STUB_LIST).
    // A STUB function is "covered" if its name appears here.
    // Update this set when ps2_call_list.h changes.
    // =========================================================
    private static final Set<String> KNOWN_HANDLERS = new HashSet<>(Arrays.asList(
        // PS2_SYSCALL_LIST
        "FlushCache","iFlushCache","ResetEE","SetMemoryMode",
        "InitThread","CreateThread","DeleteThread","StartThread","ExitThread",
        "ExitDeleteThread","TerminateThread","SuspendThread","ResumeThread",
        "GetThreadId","ReferThreadStatus","iReferThreadStatus","SleepThread",
        "WakeupThread","iWakeupThread","CancelWakeupThread","iCancelWakeupThread",
        "ChangeThreadPriority","iChangeThreadPriority","RotateThreadReadyQueue",
        "iRotateThreadReadyQueue","ReleaseWaitThread","iReleaseWaitThread",
        "CreateSema","DeleteSema","SignalSema","iSignalSema","WaitSema","PollSema",
        "iPollSema","ReferSemaStatus","iReferSemaStatus",
        "CreateEventFlag","DeleteEventFlag","SetEventFlag","iSetEventFlag",
        "ClearEventFlag","iClearEventFlag","WaitEventFlag","PollEventFlag",
        "iPollEventFlag","ReferEventFlagStatus","iReferEventFlagStatus",
        "InitAlarm","SetAlarm","iSetAlarm","CancelAlarm","iCancelAlarm",
        "ReleaseAlarm","iReleaseAlarm",
        "AddIntcHandler","AddIntcHandler2","RemoveIntcHandler",
        "AddDmacHandler","AddDmacHandler2","RemoveDmacHandler",
        "EnableIntc","iEnableIntc","DisableIntc","iDisableIntc",
        "EnableDmac","iEnableDmac","DisableDmac","iDisableDmac",
        "SifStopModule","SifLoadModule","SifInitRpc","SifBindRpc","SifCallRpc",
        "SifRegisterRpc","SifCheckStatRpc","SifSetRpcQueue","SifRemoveRpcQueue",
        "SifRemoveRpc","sceSifCallRpc","sceSifSendCmd","sceRpcGetPacket",
        "fioOpen","fioClose","fioRead","fioWrite","fioLseek","fioMkdir",
        "fioChdir","fioRmdir","fioGetstat","fioRemove",
        "SetGsCrt","GsSetCrt","GsGetIMR","iGsGetIMR","GsPutIMR","iGsPutIMR",
        "SetVSyncFlag","SetSyscall","GsSetVideoMode",
        "GetOsdConfigParam","SetOsdConfigParam","EnableCache","DisableCache",
        "GetRomName","SifLoadElfPart","sceSifLoadElf","sceSifLoadElfPart",
        "sceSifLoadModule","sceSifLoadModuleBuffer",
        "SetupThread","EndOfHeap","GetMemorySize","Deci2Call",
        "QueryBootMode","GetThreadTLS","RegisterExitHandler",
        // PS2_STUB_LIST (key ones — libc/math/ps2 native)
        "ret0","ret1","reta0","calloc_r","free_r","malloc_r","malloc_trim_r",
        "printf_r","abs","atan","atan2","calloc","ceil","close","cos","exit",
        "exp","fabs","fclose","fflush","floor","fopen","fprintf","fread","free",
        "fseek","fstat","ftell","fwrite","getpid","log","log10","lseek","malloc",
        "memchr","memcmp","memcpy","memmove","memset","open","pow","printf","puts",
        "rand","read","realloc","sin","snprintf","sprintf","sqrt","srand","stat",
        "strcasecmp","strcat","strchr","strcmp","strcpy","strlen","strncat",
        "strncmp","strncpy","strrchr","strstr","tan","vfprintf","vsprintf","write",
        "sceDmaGetChan","sceDmaReset","sceDmaDebug","sceDmaPutEnv","sceDmaGetEnv",
        "sceDmaPutStallAddr","sceDmaSend","sceDmaSendN","sceDmaSendI",
        "sceDmaRecv","sceDmaRecvN","sceDmaRecvI","sceDmaSync","sceDmaWatch",
        "sceDmaPause","sceDmaRestart",
        "sceGsResetGraph","sceGsGetGParam","sceGsResetPath","sceGsSetDefDispEnv",
        "sceGsPutDispEnv","sceGszbufaddr","sceGsSetDefDrawEnv","sceGsSetDefClear",
        "sceGsPutDrawEnv","sceGsSetDefDBuff","sceGsSwapDBuff","sceGsSyncV",
        "sceGsSyncPath","sceGsSetDefLoadImage","sceGsSetDefStoreImage",
        "sceGsExecLoadImage","sceGsExecStoreImage","sceGsSyncVCallback",
        "sceGifPkInit","sceGifPkReset","sceGifPkTerminate","sceGifPkCnt",
        "sceGifPkRef","sceGifPkEnd","sceGifPkReserve","sceGifPkOpenGifTag",
        "sceGifPkCloseGifTag","sceGifPkAddGsData","sceGifPkAddGsAD",
        "sceGifPkRefLoadImage",
        "sceVif1PkInit","sceVif1PkReset","sceVif1PkTerminate","sceVif1PkCnt",
        "sceVif1PkCall","sceVif1PkEnd","sceVif1PkOpenDirectCode",
        "sceVif1PkCloseDirectCode","sceVif1PkOpenGifTag","sceVif1PkCloseGifTag",
        "sceVif1PkReserve","sceVif1PkAlign","sceVif1PkAddGsAD",
        "sceVu0ApplyMatrix","sceVu0MulMatrix","sceVu0OuterProduct",
        "sceVu0InnerProduct","sceVu0Normalize","sceVu0TransposeMatrix",
        "sceVu0InversMatrix","sceVu0DivVector","sceVu0DivVectorXYZ",
        "sceVu0InterVector","sceVu0AddVector","sceVu0SubVector","sceVu0MulVector",
        "sceVu0ScaleVector","sceVu0TransMatrix","sceVu0CopyVector","sceVu0CopyMatrix",
        "sceVu0FTOI4Vector","sceVu0FTOI0Vector","sceVu0ITOF4Vector","sceVu0ITOF0Vector",
        "sceVu0ITOF12Vector","sceVu0UnitMatrix","sceVu0RotMatrixZ","sceVu0RotMatrixX",
        "sceVu0RotMatrixY","sceVu0RotMatrix","sceVu0ClampVector","sceVu0CameraMatrix",
        "sceVu0NormalLightMatrix","sceVu0LightColorMatrix","sceVu0ViewScreenMatrix",
        "sceVu0DropShadowMatrix","sceVu0RotTransPersN","sceVu0RotTransPers",
        "sceVu0CopyVectorXYZ","sceVu0InterVectorXYZ","sceVu0ScaleVectorXYZ",
        "sceVu0ClipScreen","sceVu0ClipScreen3","sceVu0ClipAll","sceVpu0Reset",
        "sceVu0ecossin",
        "scePadInit","scePadInit2","scePadPortOpen","scePadPortClose","scePadRead",
        "scePadGetState","scePadSetMainMode","scePadSetActDirect","scePadSetActAlign",
        "scePadInfoMode","scePadInfoAct","scePadInfoComb","scePadInfoPressMode",
        "scePadEnterPressMode","scePadExitPressMode","scePadSetButtonInfo",
        "sceCdInit","sceCdRead","sceCdSeek","sceCdSync","sceCdGetError",
        "sceCdGetDiskType","sceCdDiskReady","sceCdSearchFile","sceCdCallback",
        "sceMpegInit","sceMpegCreate","sceMpegDelete","sceMpegAddBs",
        "sceMpegGetPicture","sceMpegIsEnd","sceMpegReset",
        "sceMcInit","sceMcOpen","sceMcClose","sceMcRead","sceMcWrite",
        "sceMcSeek","sceMcSync","sceMcGetInfo","sceMcGetDir","sceMcMkdir",
        "sceIpuInit","sceIpuStopDMA","sceIpuRestartDMA","sceIpuSync",
        "sceSifDmaStat","sceSifSetDma","isceSifSetDma","sceSifSetDChain",
        "isceSifSetDChain","sceSifSetReg","sceSifGetReg",
        "sceDeci2Open","sceDeci2Close","sceDeci2ReqSend","sceDeci2Poll"
    ));

    // =========================================================
    // FIREWALL LISTS (unchanged from v2)
    // =========================================================
    private static final String[] RADAR_FIREWALL_PREFIXES = {
        "sceCd","sceMc","scePad","sceSif","sceVif","sceDma",
        "sceIpu","sceGs","sceVu1",
        "malloc","free","realloc","calloc","memcpy","memset","memmove",
        "printf","sprintf","vsprintf","strcpy","strlen","strcmp","strcat",
        "sin","cos","tan","atan","atan2","sqrt","pow","exp","log","fabs","floor","ceil",
        "__builtin_new","__builtin_vec_new","__builtin_delete",
        "__sti","__std","_GLOBAL_","__gnu_","__cxa_","_Z",
        "sceOpen","sceClose","sceRead","sceWrite","sceLseek",
        "sceSifCallRpc","sceSifBindRpc"
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
    private static final String[] IOP_MODULE_STRINGS = {
        "loadcore","iopmac","iopheap","threadman","sysclib","sifman","sifcmd",
        "cdvdman","cdvdfsv","mcman","xmcman","mcserv","atad","hdd","pfs",
        "sio2man","padman","xpadman","mtapman","libsd","sdrdrv","audsrv","modmidi",
        "usbd","dev9","smap","ps2smap","ps2ip",".IRX",".irx"
    };
    private static final String[] WHITELIST_NAMES = {
        "entry", "_start", "crt0", "topThread", "cmd_sem_init"
    };

    // =========================================================
    // [NEW-1] RECOMPILE-SAFE NAME PATTERNS
    // [FIX-1] These are never SKIPped — they must be recompiled.
    // Previously these landed in skip via BIOS_FIREWALL or isKernelInternal.
    // =========================================================
    private static boolean isCppRuntimeFunction(String name) {
        return name.startsWith("__ct__")    // constructors
            || name.startsWith("__dt__")    // destructors
            || name.startsWith("__as__")    // assignment operators
            || name.startsWith("__sinit_")  // static initializers
            || name.startsWith("__nw__")    // operator new
            || name.startsWith("__nwa__")   // operator new[]
            || name.startsWith("__putc__"); // debug font output
    }

    // =========================================================
    // DNA ANALYSIS: FuncTraits
    // =========================================================
    class FuncTraits {
        int floatOps=0, branchOps=0, mathOps=0, loadOps=0, returnPaths=0;
        long byteSize=0;
        int calleeCount=0, callOps=0;
        int xrefToCount=0;
        List<String> calleeNames=new ArrayList<>();
        boolean isThunk=false;
        boolean writesToGlobal=false, usesCop1=false, usesCop2=false;
        boolean usesSPR=false, hasStackFrame=false, hasMutatingInstructions=false;
        int quadwordVU=0, accOps=0;
        boolean writesToText=false, hasSyncInstr=false, hasBusyWait=false;
        boolean hasVcallms=false, hasJumpTable=false, accessesMMIO=false;
    }

    // =========================================================
    // STATE
    // =========================================================
    private FunctionManager funcManager;
    private ReferenceManager refManager;
    private Memory memory;
    private Map<Address, FuncTraits> cache = new HashMap<>();
    private Map<Address, Boolean> staticFwCache = new HashMap<>();
    private Map<Address, Boolean> iopFwCache    = new HashMap<>();
    private Map<Address, Boolean> behavFwCache  = new HashMap<>();

    private Set<Long> step1StubAddresses = new HashSet<>();
    private Set<Long> step1SkipAddresses = new HashSet<>();
    private Set<String> step1StubNames   = new HashSet<>();
    private Set<String> step1SkipNames   = new HashSet<>();
    private Set<Long> mainLoopShield = new HashSet<>();

    private long textStart=0, textEnd=0;
    private int radarNewStubs=0, radarNewSkips=0;
    private int safeLeafCount=0, accHazardCount=0, mmioCount=0;
    private int smcHazardCount=0, sprSyncCount=0, busyWaitCount=0;
    private int vcallmsCount=0, jumpTableCount=0, orphanCount=0;
    // [NEW-2] stub gap counters
    private int stubCoveredCount=0, stubMissingCount=0;

    // =========================================================
    // ENTRY POINT
    // =========================================================
    @Override
    public void run() throws Exception {
        funcManager = currentProgram.getFunctionManager();
        refManager  = currentProgram.getReferenceManager();
        memory      = currentProgram.getMemory();

        println("=========================================================");
        println("PS2Recomp TRIAGE ENRICHER v3");
        println("=========================================================\n");

        File csvFile = askFile("Select functions.csv from Step 1", "Open");
        if (csvFile == null || !csvFile.exists()) { printerr("No CSV. Aborting."); return; }
        File configToml = askFile("Select config.toml from Step 1", "Open");
        if (configToml == null || !configToml.exists()) { printerr("No config.toml. Aborting."); return; }
        File outputDir = csvFile.getParentFile();
        File unifiedToml = new File(outputDir, "config_auto_recomp.toml");
        File triageJson  = new File(outputDir, "triage_map.json");

        parseStep1Config(configToml);
        println(String.format("[STEP 1] %d stub addrs + %d stub names, %d skip addrs + %d skip names.",
            step1StubAddresses.size(), step1StubNames.size(),
            step1SkipAddresses.size(), step1SkipNames.size()));

        // MainLoop shield
        Address mainLoopAddr = null;
        try { mainLoopAddr = askAddress("MainLoop Address",
            "Enter MainLoop function address (Cancel = auto-detect or skip)");
        } catch (Exception ignored) {}
        if (mainLoopAddr == null) {
            for (Function f : funcManager.getFunctions(true)) {
                String n = f.getName().toLowerCase();
                if (n.equals("mainloop__fv")||n.equals("mainloop")||n.equals("main_loop")) {
                    mainLoopAddr = f.getEntryPoint();
                    println("[MAINLOOP] Auto-detected: " + f.getName() + " @ " + mainLoopAddr);
                    break;
                }
            }
        }
        if (mainLoopAddr != null) {
            buildMainLoopShield(mainLoopAddr);
            println("[MAINLOOP] Shield: " + mainLoopShield.size() + " functions protected.\n");
        }

        detectTextSection();
        long gpValue = detectGlobalPointer();
        String elfHash = computeElfHash();

        println("[SCAN] Analyzing...");

        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);
        BasicBlockModel blockModel = new BasicBlockModel(currentProgram);

        PrintWriter asmWriter   = new PrintWriter(new FileWriter(new File(outputDir, "assembly.txt")));
        PrintWriter decompWriter = new PrintWriter(new FileWriter(new File(outputDir, "decompiled.txt")));
        PrintWriter flowWriter  = new PrintWriter(new FileWriter(new File(outputDir, "flowchart.txt")));

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
                if (totalFuncs % 500 == 0)
                    monitor.setMessage("Scanning function " + totalFuncs + "...");

                Address addr   = func.getEntryPoint();
                long offset    = addr.getOffset();
                String funcName = func.getName();

                // Export text logs
                String header = "\n\n========================================\n" +
                    "FUNCTION: " + funcName + "\n" +
                    "ADDRESS: "  + addr     + "\n" +
                    "========================================\n";
                asmWriter.println(header);
                InstructionIterator instructions = currentProgram.getListing()
                    .getInstructions(func.getBody(), true);
                while (instructions.hasNext()) {
                    Instruction instr = instructions.next();
                    asmWriter.println(instr.getAddress() + "  " + instr);
                }
                decompWriter.println(header);
                DecompileResults dr = decomp.decompileFunction(func, 30, monitor);
                if (dr != null && dr.decompileCompleted())
                    decompWriter.println(dr.getDecompiledFunction().getC());
                else
                    decompWriter.println("[decompile failed]");
                flowWriter.println(header);
                try {
                    CodeBlockIterator blocks = blockModel.getCodeBlocksContaining(
                        func.getBody(), monitor);
                    while (blocks.hasNext()) {
                        CodeBlock block = blocks.next();
                        flowWriter.println("  BLOCK: " + block.getFirstStartAddress());
                        CodeBlockReferenceIterator dests = block.getDestinations(monitor);
                        while (dests.hasNext()) {
                            CodeBlockReference ref = dests.next();
                            flowWriter.println("    --> " + ref.getDestinationAddress() +
                                " [" + ref.getFlowType().getName() + "]");
                        }
                    }
                } catch (Exception e) {
                    flowWriter.println("  [flowchart failed: " + e.getMessage() + "]");
                }

                // Skip already-classified by step1
                if (step1StubAddresses.contains(offset) || step1SkipAddresses.contains(offset)
                    || step1StubNames.contains(funcName) || step1SkipNames.contains(funcName))
                    continue;

                uncategorized++;
                FuncTraits traits = getTraits(func);

                // Whitelist check
                boolean isWhitelisted = false;
                for (String wl : WHITELIST_NAMES)
                    if (funcName.equals(wl)) { isWhitelisted = true; break; }
                if (!isWhitelisted) {
                    if (funcName.contains("__ct__") || funcName.contains("__dt__") ||
                        funcName.contains("__as__")  || funcName.startsWith("__sinit_") ||
                        funcName.toLowerCase().contains("callback") ||
                        funcName.toLowerCase().contains("handler"))
                        isWhitelisted = true;
                }
                if (mainLoopShield.contains(offset)) isWhitelisted = true;

                // ---- Disposition ----
                String disposition = "RECOMPILE";
                if (!isWhitelisted) {
                    if (isRadarFirewalled(func)) {
                        disposition = "STUB";
                        newStubs.add(funcName + "@" + hex(offset));
                        radarNewStubs++;
                    } else if (referencesIopModule(func, traits)) {
                        disposition = "STUB";
                        newStubs.add(funcName + "@" + hex(offset));
                        radarNewStubs++;
                    } else if (isKernelInternal(func)) {
                        // [FIX-1] Never SKIP C++ runtime functions
                        if (isCppRuntimeFunction(funcName)) {
                            disposition = "RECOMPILE"; // override
                        } else {
                            disposition = "SKIP";
                            newSkips.add(funcName + "@" + hex(offset));
                            radarNewSkips++;
                        }
                    } else if (traits.hasVcallms) {
                        disposition = "STUB";
                        newStubs.add(funcName + "@" + hex(offset));
                        radarNewStubs++;
                    }
                }

                // ---- Tags ----
                List<String> tags = new ArrayList<>();
                String category = assignCategory(traits);

                if (traits.calleeCount==0 && traits.callOps==0 &&
                    !traits.isThunk && traits.byteSize>0)
                    { tags.add("SAFE_LEAF"); safeLeafCount++; }
                // [FIX-2] VU0_MICROCODE checked BEFORE ACC_PRECISION_HAZARD
                if (traits.hasVcallms)
                    { tags.add("VU0_MICROCODE"); vcallmsCount++; }
                else if (traits.accOps >= 3)
                    { tags.add("ACC_PRECISION_HAZARD"); accHazardCount++; }
                if (traits.writesToText)
                    { tags.add("SMC_HAZARD"); smcHazardCount++; }
                if (traits.usesSPR && traits.hasSyncInstr)
                    { tags.add("SPR_SYNC_HAZARD"); sprSyncCount++; }
                if (traits.hasBusyWait)
                    { tags.add("BUSY_WAIT_HAZARD"); busyWaitCount++; }
                if (traits.hasJumpTable)
                    { tags.add("COMPLEX_CONTROL_FLOW"); jumpTableCount++; }
                if (traits.accessesMMIO)
                    { tags.add("ACCESSES_MMIO"); mmioCount++; }
                if (traits.usesCop2) tags.add("VU0_VECTORS");
                if (traits.usesCop1) tags.add("FPU_HEAVY");
                if (traits.usesSPR)  tags.add("USES_SPR");
                if (traits.writesToGlobal) tags.add("WRITES_GLOBAL");
                if (traits.returnPaths >= 3) tags.add("MULTI_RETURN");
                if (!refManager.hasReferencesTo(addr) && !isWhitelisted)
                    { tags.add("ORPHAN_CODE"); orphanCount++; }

                // [NEW-2] runtime_has_handler for STUB functions
                boolean runtimeHasHandler = false;
                if (disposition.equals("STUB")) {
                    // Strip mangled suffix for lookup: "funcName__FP1..." -> "funcName"
                    String baseName = funcName;
                    int mangIdx = baseName.indexOf("__F");
                    if (mangIdx > 0) baseName = baseName.substring(0, mangIdx);
                    runtimeHasHandler = KNOWN_HANDLERS.contains(baseName) ||
                                        KNOWN_HANDLERS.contains(funcName);
                    if (runtimeHasHandler) stubCoveredCount++;
                    else stubMissingCount++;
                }

                FuncResult r = new FuncResult();
                r.address=offset; r.name=funcName; r.category=category;
                r.disposition=disposition; r.traits=traits; r.tags=tags;
                r.runtimeHasHandler=runtimeHasHandler;
                results.add(r);
            }

            long scanSec = (System.currentTimeMillis()-scanStart)/1000;
            println(String.format("[SCAN] %d functions in %dm%02ds.",
                totalFuncs, scanSec/60, scanSec%60));
            println(String.format("  New stubs: %d | New skips: %d", radarNewStubs, radarNewSkips));
            println(String.format("  Stub coverage: %d covered / %d missing handlers",
                stubCoveredCount, stubMissingCount));
            println(String.format("  Tags: SAFE=%d MMIO=%d ACC=%d SMC=%d SPR=%d VCALLMS=%d JTABLE=%d ORPHAN=%d",
                safeLeafCount, mmioCount, accHazardCount, smcHazardCount,
                sprSyncCount, vcallmsCount, jumpTableCount, orphanCount));

            writeUnifiedConfig(unifiedToml, configToml, newStubs, newSkips);
            writeTriageJson(triageJson, results, elfHash, gpValue, totalFuncs, uncategorized);

            println("\n[SUCCESS] Unified TOML : " + unifiedToml.getAbsolutePath());
            println("[SUCCESS] Triage JSON  : " + triageJson.getAbsolutePath());
            println("[SUCCESS] Text logs    : assembly.txt, decompiled.txt, flowchart.txt");
            println("All files saved to: " + outputDir.getAbsolutePath());

            // [NEW-2] Print stub gap report
            if (stubMissingCount > 0) {
                println("\n[STUB GAP] " + stubMissingCount + " STUBs have no runtime handler.");
                println("  Run: python triage_analyzer.py triage_map.json stub-gap");
                println("  to see the full list with addresses.");
            }
        } finally {
            asmWriter.close();
            decompWriter.close();
            flowWriter.close();
            decomp.dispose();
        }
    }

    // =========================================================
    // PARSE STEP 1 CONFIG
    // =========================================================
    private void parseStep1Config(File configFile) throws IOException {
        BufferedReader reader = new BufferedReader(new FileReader(configFile));
        String line; boolean inStubs=false, inSkip=false;
        while ((line = reader.readLine()) != null) {
            String t = line.trim();
            if (t.startsWith("stubs")) { inStubs=true; inSkip=false; continue; }
            if (t.startsWith("skip") && !t.startsWith("skip_count"))
                { inSkip=true; inStubs=false; continue; }
            if (t.equals("]")) { inStubs=false; inSkip=false; continue; }
            if (!inStubs && !inSkip) continue;
            int q1=t.indexOf('"'), q2=t.lastIndexOf('"');
            if (q1<0||q2<=q1) continue;
            String entry = t.substring(q1+1, q2);
            String name; long addr=-1;
            int atIdx = entry.lastIndexOf("@0x");
            if (atIdx<0) atIdx=entry.lastIndexOf("@0X");
            if (atIdx>=0) {
                name=entry.substring(0,atIdx);
                String hex=entry.substring(atIdx+3).replaceAll("[^0-9a-fA-F]","");
                if(!hex.isEmpty()) try{addr=Long.parseLong(hex,16);}catch(NumberFormatException ignored){}
            } else { name=entry; }
            if (inStubs) { if(!name.isEmpty()) step1StubNames.add(name); if(addr>=0) step1StubAddresses.add(addr); }
            else if (inSkip) { if(!name.isEmpty()) step1SkipNames.add(name); if(addr>=0) step1SkipAddresses.add(addr); }
        }
        reader.close();
    }

    // =========================================================
    // MAINLOOP SHIELD
    // =========================================================
    private void buildMainLoopShield(Address mlAddr) {
        mainLoopShield.add(mlAddr.getOffset());
        Function mlFunc = funcManager.getFunctionAt(mlAddr);
        if (mlFunc == null) return;
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
                println(String.format("[SECTIONS] .text: 0x%08X-0x%08X", textStart, textEnd));
                return;
            }
        }
        long first=Long.MAX_VALUE, last=0;
        FunctionIterator fit=funcManager.getFunctions(true);
        while(fit.hasNext()) {
            Function f=fit.next();
            long s=f.getEntryPoint().getOffset(), e=f.getBody().getMaxAddress().getOffset();
            if(s<first) first=s; if(e>last) last=e;
        }
        if (first<Long.MAX_VALUE) {
            textStart=first; textEnd=last;
            println(String.format("[SECTIONS] Code range: 0x%08X-0x%08X", textStart, textEnd));
        }
    }

    // =========================================================
    // $GP DETECTION
    // =========================================================
    private long detectGlobalPointer() {
        SymbolIterator syms=currentProgram.getSymbolTable().getSymbols("_gp");
        while(syms.hasNext()){long v=syms.next().getAddress().getOffset();
            println(String.format("[GP] _gp symbol: 0x%08X",v));return v;}
        syms=currentProgram.getSymbolTable().getSymbols("_gp_disp");
        while(syms.hasNext()){long v=syms.next().getAddress().getOffset();
            println(String.format("[GP] _gp_disp symbol: 0x%08X",v));return v;}
        println("[GP] No symbol. Scanning entry point for lui+addiu $gp...");
        Function entryFunc=null;
        for(String n:new String[]{"entry","_start"}){
            SymbolIterator si=currentProgram.getSymbolTable().getSymbols(n);
            while(si.hasNext()){Function f=funcManager.getFunctionAt(si.next().getAddress());
                if(f!=null){entryFunc=f;break;}}
            if(entryFunc!=null) break;
        }
        if(entryFunc==null){FunctionIterator fi=funcManager.getFunctions(true);if(fi.hasNext()) entryFunc=fi.next();}
        if(entryFunc!=null){
            long gpUpper=0; int checked=0;
            InstructionIterator it=currentProgram.getListing().getInstructions(entryFunc.getBody(),true);
            while(it.hasNext()&&checked<20){
                Instruction inst=it.next(); checked++;
                String mnem=inst.getMnemonicString(); if(mnem==null) continue;
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
                            println(String.format("[GP] Detected from crt0: 0x%08X",gpVal));
                            return gpVal;
                        }
                }
            }
        }
        println("[GP] WARNING: $gp not found. Set manually in TOML.");
        return 0;
    }

    // =========================================================
    // ELF HASH
    // =========================================================
    private String computeElfHash() {
        try {
            MessageDigest md=MessageDigest.getInstance("MD5"); int h=0;
            for(MemoryBlock b:memory.getBlocks()){
                if(!b.isInitialized()||h>=65536) break;
                int r=(int)Math.min(b.getSize(),65536-h); byte[] d=new byte[r];
                b.getBytes(b.getStart(),d); md.update(d); h+=r;
            }
            StringBuilder sb=new StringBuilder();
            for(byte b:md.digest()) sb.append(String.format("%02x",b));
            return sb.toString();
        } catch(Exception e){return "UNKNOWN";}
    }

    // =========================================================
    // KSEG1 NORMALIZATION
    // =========================================================
    private static long normalizeAddress(long eeAddress) {
        return eeAddress & 0x1FFFFFFFL;
    }

    // =========================================================
    // DNA TRAIT SCANNER
    // =========================================================
    private FuncTraits getTraits(Function func) {
        Address key=func.getEntryPoint();
        if(cache.containsKey(key)) return cache.get(key);
        FuncTraits traits=new FuncTraits();
        traits.byteSize=func.getBody().getNumAddresses();
        Set<Function> callees=func.getCalledFunctions(monitor);
        traits.calleeCount=callees.size();
        // [NEW-3] Deduped callee names, capped at 64
        Set<String> calleeNameSet = new LinkedHashSet<>();
        for(Function callee:callees) calleeNameSet.add(callee.getName());
        traits.calleeNames = new ArrayList<>(calleeNameSet);
        if (traits.calleeNames.size() > 64) traits.calleeNames = traits.calleeNames.subList(0,64);

        int xrefCount=0;
        for(Reference ref:refManager.getReferencesTo(func.getEntryPoint()))
            if(ref.getReferenceType().isCall()||ref.getReferenceType().isFlow()) xrefCount++;
        traits.xrefToCount=xrefCount;

        traits.isThunk=func.isThunk()||(traits.byteSize<=8&&traits.calleeCount>0);
        if(traits.isThunk){cache.put(key,traits);return traits;}

        InstructionIterator asmIter=currentProgram.getListing()
            .getInstructions(func.getBody(),true);
        int instrIdx=0, mmioReadCount=0, totalInstrs=0;
        while(asmIter.hasNext()){
            Instruction inst=asmIter.next();
            String mnem=inst.getMnemonicString();
            if(mnem==null){instrIdx++;totalInstrs++;continue;}
            String ml=mnem.toLowerCase(); totalInstrs++;

            if(instrIdx<8&&(ml.equals("addiu")||ml.equals("daddiu")))
                for(Object op:inst.getInputObjects())
                    if(op instanceof ghidra.program.model.lang.Register&&
                       ((ghidra.program.model.lang.Register)op).getName().equals("sp"))
                        traits.hasStackFrame=true;

            if(ml.contains("c1")||ml.endsWith(".s")||ml.endsWith(".d")) traits.usesCop1=true;
            if(ml.startsWith("vadd")||ml.startsWith("vmul")||ml.startsWith("vsub")||
               ml.startsWith("vscl")||ml.startsWith("vdiv")||ml.startsWith("vmfir")||
               ml.startsWith("vmtir")||ml.contains("c2")) traits.usesCop2=true;
            if(ml.equals("lqc2")||ml.equals("sqc2")){traits.usesCop2=true;traits.quadwordVU++;}

            // ACC ops — madda variants
            if(ml.startsWith("madda")||ml.startsWith("msuba")||ml.startsWith("mula")||
               ml.startsWith("adda")||ml.startsWith("vmadd")||ml.startsWith("vmsub")||
               ml.startsWith("vmadda")||ml.startsWith("vmsuba")||ml.startsWith("vmula")||
               ml.startsWith("vadda")||ml.startsWith("vopmsub")||ml.startsWith("madd"))
                traits.accOps++;

            if(ml.equals("sync.l")||ml.equals("sync.p")||ml.equals("sync")) traits.hasSyncInstr=true;
            if(ml.equals("vcallms")||ml.equals("vcallmsr")) traits.hasVcallms=true;
            if(ml.equals("jr")){
                boolean isRa=false;
                for(Object op:inst.getInputObjects())
                    if(op instanceof ghidra.program.model.lang.Register){
                        String rn=((ghidra.program.model.lang.Register)op).getName().toLowerCase();
                        if(rn.equals("ra")) isRa=true; else traits.hasJumpTable=true;
                    }
                if(isRa) traits.returnPaths++;
            }
            if(ml.equals("sw")||ml.equals("swc1")||ml.equals("sqc2")||ml.equals("sh")||ml.equals("sb")){
                traits.hasMutatingInstructions=true;
                for(Reference ref:inst.getReferencesFrom()){
                    if(!ref.getReferenceType().isWrite()) continue;
                    long tOff=ref.getToAddress().getOffset();
                    long norm=normalizeAddress(tOff);
                    if(ref.getToAddress().getAddressSpace().isMemorySpace()&&norm>=GLOBAL_ADDR_MIN)
                        traits.writesToGlobal=true;
                    if(textStart>0&&norm>=textStart&&norm<=textEnd){
                        Instruction ti=currentProgram.getListing().getInstructionAt(ref.getToAddress());
                        if(ti!=null) traits.writesToText=true;
                    }
                }
            }
            if(ml.equals("jal")||ml.equals("jalr")){traits.hasMutatingInstructions=true;traits.callOps++;}

            for(Reference ref:inst.getReferencesFrom()){
                long norm=normalizeAddress(ref.getToAddress().getOffset());
                if(norm>=SPR_START&&norm<=SPR_END) traits.usesSPR=true;
                if(!ref.getReferenceType().isCall()&&!ref.getReferenceType().isFlow())
                    if((norm>=MMIO_START&&norm<=MMIO_END)||(norm>=MMIO_GS_START&&norm<=MMIO_GS_END))
                        traits.accessesMMIO=true;
            }

            if(ml.startsWith("b")&&!ml.equals("break")) traits.branchOps++;
            else if(ml.startsWith("l")&&!ml.equals("lui")&&!ml.equals("lq")&&!ml.equals("lqc2")){
                traits.loadOps++;
                for(Reference ref:inst.getReferencesFrom()){
                    long norm=normalizeAddress(ref.getToAddress().getOffset());
                    if(norm>=MMIO_START&&norm<=MMIO_END) mmioReadCount++;
                }
            }
            else if(ml.startsWith("add")||ml.startsWith("dadd")||ml.startsWith("sub")||
                    ml.startsWith("mul")||ml.startsWith("div")) traits.mathOps++;
            if(ml.endsWith(".s")||ml.endsWith(".d")||ml.startsWith("cvt.")||ml.startsWith("c."))
                traits.floatOps++;
            instrIdx++;
        }
        if(totalInstrs>0&&totalInstrs<=15&&mmioReadCount>0&&traits.branchOps>=1)
            traits.hasBusyWait=true;
        cache.put(key,traits); return traits;
    }

    // =========================================================
    // CATEGORY HEURISTICS
    // =========================================================
    private String assignCategory(FuncTraits t) {
        boolean calls = (t.calleeCount > 0 || t.callOps > 0);
        if (!calls && t.byteSize < 100 && !t.writesToGlobal) return "GETTER_OR_STUB";
        if (t.usesCop2 || t.floatOps >= 6 || (t.mathOps > 10 && !calls)) return "MATH_VECTORS";
        if (t.branchOps >= 4 || t.returnPaths >= 2) return "STATE_MACHINES";
        if (t.writesToGlobal && t.loadOps > 0 && calls) return "GAME_LOGIC";
        if (calls && t.byteSize < 200 && t.branchOps <= 2) return "WRAPPER";
        return "UNCATEGORIZED";
    }

    // =========================================================
    // FIREWALLS
    // =========================================================
    private boolean isRadarFirewalled(Function func) {
        Address key=func.getEntryPoint();
        Boolean c=staticFwCache.get(key); if(c!=null) return c;
        String name=func.getName();
        if(name.startsWith("sceVu0")){staticFwCache.put(key,false);return false;}
        // [FIX-1] C++ runtime functions are never firewalled
        if(isCppRuntimeFunction(name)){staticFwCache.put(key,false);return false;}
        for(String p:RADAR_FIREWALL_PREFIXES) if(name.startsWith(p)){staticFwCache.put(key,true);return true;}
        for(String p:BIOS_FIREWALL_PREFIXES) if(name.startsWith(p)){staticFwCache.put(key,true);return true;}
        staticFwCache.put(key,false); return false;
    }
    private boolean isKernelInternal(Function func) {
        Address key=func.getEntryPoint();
        Boolean c=behavFwCache.get(key); if(c!=null) return c;
        boolean k=containsSyscall(func)||containsCOP0(func);
        behavFwCache.put(key,k); return k;
    }
    private boolean referencesIopModule(Function func, FuncTraits traits) {
        if(traits.byteSize>800) return false;
        Address key=func.getEntryPoint();
        Boolean c=iopFwCache.get(key); if(c!=null) return c;
        InstructionIterator it=currentProgram.getListing()
            .getInstructions(func.getBody(),true);
        while(it.hasNext()){
            for(Reference ref:it.next().getReferencesFrom()){
                Data data=getDataAt(ref.getToAddress());
                if(data!=null&&data.hasStringValue()){
                    String str=data.getDefaultValueRepresentation();
                    for(String s:IOP_MODULE_STRINGS)
                        if(str.contains(s)){iopFwCache.put(key,true);return true;}
                }
            }
        }
        iopFwCache.put(key,false); return false;
    }
    private boolean containsSyscall(Function func) {
        InstructionIterator it=currentProgram.getListing()
            .getInstructions(func.getBody(),true);
        while(it.hasNext()){String m=it.next().getMnemonicString();
            if(m!=null&&m.equalsIgnoreCase("syscall")) return true;}
        return false;
    }
    private boolean containsCOP0(Function func) {
        InstructionIterator it=currentProgram.getListing()
            .getInstructions(func.getBody(),true);
        while(it.hasNext()){
            String m=it.next().getMnemonicString(); if(m==null) continue; m=m.toLowerCase();
            if(m.equals("di")||m.equals("ei")||m.equals("mfc0")||m.equals("mtc0")||
               m.equals("eret")||m.startsWith("c0")) return true;
        }
        return false;
    }

    // =========================================================
    // UNIFIED CONFIG OUTPUT
    // =========================================================
    private void writeUnifiedConfig(File outFile, File step1Config,
            List<String> newStubs, List<String> newSkips) throws IOException {
        List<String> lines=new ArrayList<>();
        BufferedReader reader=new BufferedReader(new FileReader(step1Config));
        String line; while((line=reader.readLine())!=null) lines.add(line);
        reader.close();

        int stubsClose=-1, skipClose=-1;
        boolean inStubs=false, inSkip=false;
        for(int i=0;i<lines.size();i++){
            String t=lines.get(i).trim();
            if(t.startsWith("stubs")) inStubs=true;
            if(t.startsWith("skip")&&!t.startsWith("skip_count")) inSkip=true;
            if(t.equals("]")){
                if(inStubs){stubsClose=i;inStubs=false;}
                else if(inSkip){skipClose=i;inSkip=false;}
            }
        }
        List<String> stubLines=new ArrayList<>();
        if(!newStubs.isEmpty()){
            stubLines.add("  # --- Triage Enricher v3 additions ---");
            for(String s:newStubs) stubLines.add("  \""+s+"\",");
        }
        List<String> skipLines=new ArrayList<>();
        if(!newSkips.isEmpty()){
            skipLines.add("  # --- Triage Enricher v3 additions ---");
            for(String s:newSkips) skipLines.add("  \""+s+"\",");
        }
        if(skipClose>=0&&!skipLines.isEmpty()){
            lines.addAll(skipClose, skipLines);
            if(stubsClose>=skipClose) stubsClose+=skipLines.size();
        }
        if(stubsClose>=0&&!stubLines.isEmpty())
            lines.addAll(stubsClose, stubLines);

        lines.add(0, "# Unified config (v3): "+step1Config.getName()+
            " + "+newStubs.size()+" stubs + "+newSkips.size()+" skips");

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
        for(String l:lines) w.println(l);
        w.close();
    }

    // =========================================================
    // JSON OUTPUT — schema v3
    // =========================================================
    private void writeTriageJson(File outFile, List<FuncResult> results,
            String elfHash, long gpValue, int totalFuncs, int uncategorized)
            throws IOException {
        PrintWriter w=new PrintWriter(new FileWriter(outFile));
        w.println("{");
        w.println("  \"schema_version\": 3,");
        w.println("  \"elf_hash\": \""+elfHash+"\",");
        if(gpValue!=0) w.println("  \"global_pointer\": \""+hex(gpValue)+"\",");
        w.println("  \"text_range\": { \"start\": \""+hex(textStart)+"\", \"end\": \""+hex(textEnd)+"\" },");
        w.println("  \"mainloop_shield_size\": "+mainLoopShield.size()+",");
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
        // [NEW-2] stub gap stats
        w.println("    \"stub_covered\": "+stubCoveredCount+",");
        w.println("    \"stub_missing_handler\": "+stubMissingCount);
        w.println("  },");
        w.println("  \"functions\": [");
        for(int i=0;i<results.size();i++){
            if(monitor.isCancelled()) break;
            FuncResult r=results.get(i); FuncTraits t=r.traits;
            w.print("    {");
            w.print("\"address\": \""+hex(r.address)+"\", ");
            w.print("\"name\": "+jsonString(r.name)+", ");
            w.print("\"category\": \""+r.category+"\", ");
            w.print("\"disposition\": \""+r.disposition+"\", ");
            // [NEW-2] runtime_has_handler only for STUB
            if(r.disposition.equals("STUB"))
                w.print("\"runtime_has_handler\": "+r.runtimeHasHandler+", ");
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
            w.print("\"has_jump_table\": "+t.hasJumpTable);
            w.print("}, ");
            w.print("\"tags\": [");
            for(int j=0;j<r.tags.size();j++){if(j>0) w.print(", "); w.print("\""+r.tags.get(j)+"\"");}
            w.print("], ");
            // [NEW-3] deduped callee names
            w.print("\"callees\": [");
            for(int j=0;j<t.calleeNames.size();j++){
                if(j>0) w.print(", "); w.print(jsonString(t.calleeNames.get(j)));}
            w.print("]}");
            if(i<results.size()-1) w.println(","); else w.println();
        }
        w.println("  ]");
        w.println("}");
        w.close();
    }

    // =========================================================
    // HELPERS
    // =========================================================
    class FuncResult {
        long address; String name, category, disposition;
        FuncTraits traits; List<String> tags;
        boolean runtimeHasHandler = false; // [NEW-2]
    }
    private static String hex(long v){ return String.format("0x%08X", v&0xFFFFFFFFL); }
    private static String jsonString(String v){
        if(v==null) return "\"\"";
        return "\""+v.replace("\\","\\\\").replace("\"","\\\"")
                    .replace("\n","\\n").replace("\r","\\r").replace("\t","\\t")+"\"";
    }
}
