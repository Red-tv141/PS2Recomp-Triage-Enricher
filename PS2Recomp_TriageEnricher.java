// PS2Recomp Triage Enricher v2 — Ghidra Script (Step 2 of Pipeline)
// ==================================================================
// Run AFTER ExportPS2Functions.java on the same Ghidra project.
//
// OUTPUTS:
//   1. config_auto_recomp.toml — UNIFIED config ready for ps2recomp.exe
//      (merges Step 1 config.toml + our triage additions)
//   2. triage_map.json — full DNA map with tags for the report tool
//
// RULES IMPLEMENTED (17 + tags):
//   1.  No DANGEROUS_KEYWORDS (removed - was killing game logic)
//   2.  IOP_MODULE_STRINGS: only .IRX/.irx + specific module names (no .BIN/.DAT)
//   3.  referencesIopModule: size cap 800 bytes (larger = game logic)
//   4.  accessesHardware: DATA references only (not CALL/FLOW)
//   5.  accessesHardware → ACCESSES_MMIO tag only (not disposition)
//   6.  KSEG1 masking in all address checks (addr & 0x1FFFFFFF)
//   7.  isKernelInternal replaces isRadarBehaviorallyDangerous (syscall+COP0 only)
//   8.  IOP refs → STUB, kernel internals → SKIP
//   9.  TOML parser: handles name-only AND name@address entries
//   10. Whitelist: entry/_start exempt from all firewalls
//   11. MainLoop shield: ML + depth-1 callees exempt (manual or auto-detect)
//   12. $gp fallback: lui+addiu scan in entry point for stripped binaries
//   13. SMC detection: function boundaries + instruction-at-target check
//   14. No lui scanner for VIF (didn't work, removed)
//   15. No VIF_DMA_UPLOAD tag (ACCESSES_MMIO covers it)
//   16. vcallms → VU0_MICROCODE → forced STUB
//   17. jr $reg (reg!=ra) → COMPLEX_CONTROL_FLOW tag
//   +   ORPHAN_CODE tag for zero-xref functions
//   +   Unified config output (ready for ps2recomp.exe)
//
// @author Puggsy + Claude
// @category PS2Recomp

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
    private static final long PS2_BASE        = 0x00100000L;
    private static final long MMIO_START      = 0x10000000L;
    private static final long MMIO_END        = 0x1000FFFFL;
    private static final long KSEG1_START     = 0x20000000L;
    private static final long SPR_START       = 0x70000000L;
    private static final long SPR_END         = 0x70003FFFL;
    private static final long GLOBAL_ADDR_MIN = 0x00100000L;
    private static final long MMIO_GS_START   = 0x12000000L;
    private static final long MMIO_GS_END     = 0x12002000L;

    // =========================================================
    // FIREWALL LISTS — name-based (strict namespace prefixes only)
    // RULE 1: No DANGEROUS_KEYWORDS. Removed entirely.
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

    // RULE 2: Only .IRX and specific module names. No .BIN/.DAT.
    private static final String[] IOP_MODULE_STRINGS = {
        "loadcore","iopmac","iopheap","threadman","sysclib","sifman","sifcmd",
        "cdvdman","cdvdfsv","mcman","xmcman","mcserv","atad","hdd","pfs",
        "sio2man","padman","xpadman","mtapman","libsd","sdrdrv","audsrv","modmidi",
        "usbd","dev9","smap","ps2smap","ps2ip",".IRX",".irx"
    };

    // RULE 10: Absolute whitelist — immune to ALL firewalls
    private static final String[] WHITELIST_NAMES = {
        "entry", "_start", "crt0", "topThread", "cmd_sem_init"
    };

    // =========================================================
    // DNA ANALYSIS: FuncTraits
    // =========================================================
    class FuncTraits {
        int  floatOps=0, branchOps=0, mathOps=0, loadOps=0, returnPaths=0;
        long byteSize=0;
        int  calledCount=0;
        boolean isThunk=false;
        boolean writesToGlobal=false, usesCop1=false, usesCop2=false;
        boolean usesSPR=false, hasStackFrame=false, hasMutatingInstructions=false;
        int quadwordVU=0, accOps=0, callOps=0;
        boolean writesToText=false;
        boolean hasSyncInstr=false;
        boolean hasBusyWait=false;
        boolean hasVcallms=false;       // RULE 16
        boolean hasJumpTable=false;     // RULE 17
    }

    // =========================================================
    // STATE
    // =========================================================
    private FunctionManager  funcManager;
    private ReferenceManager refManager;
    private Memory           memory;

    private Map<Address, FuncTraits> cache = new HashMap<>();
    private Map<Address, Boolean> staticFwCache = new HashMap<>();
    private Map<Address, Boolean> iopFwCache    = new HashMap<>();
    private Map<Address, Boolean> behavFwCache  = new HashMap<>();

    // RULE 9: Dual tracking
    private Set<Long>   step1StubAddresses = new HashSet<>();
    private Set<Long>   step1SkipAddresses = new HashSet<>();
    private Set<String> step1StubNames     = new HashSet<>();
    private Set<String> step1SkipNames     = new HashSet<>();

    // RULE 11: MainLoop shield
    private Set<Long> mainLoopShield = new HashSet<>();

    private long textStart = 0, textEnd = 0;

    private int radarNewStubs=0, radarNewSkips=0;
    private int safeLeafCount=0, accHazardCount=0, mmioCount=0;
    private int smcHazardCount=0, sprSyncCount=0, busyWaitCount=0;
    private int vcallmsCount=0, jumpTableCount=0, orphanCount=0;

    // =========================================================
    // ENTRY POINT
    // =========================================================
    @Override
    public void run() throws Exception {
        funcManager = currentProgram.getFunctionManager();
        refManager  = currentProgram.getReferenceManager();
        memory      = currentProgram.getMemory();

        println("=========================================================");
        println("PS2Recomp TRIAGE ENRICHER v2 — 17 Rules + Unified Config");
        println("=========================================================\n");

        File csvFile = askFile("Select functions.csv from Step 1", "Open");
        if (csvFile == null || !csvFile.exists()) { printerr("No CSV. Aborting."); return; }

        File configToml = askFile("Select config.toml from Step 1", "Open");
        if (configToml == null || !configToml.exists()) { printerr("No config.toml. Aborting."); return; }

        File outputDir = csvFile.getParentFile();
        File unifiedToml = new File(outputDir, "config_auto_recomp.toml");
        File triageJson  = new File(outputDir, "triage_map.json");

        // RULE 9
        parseStep1Config(configToml);
        println(String.format("[STEP 1] %d stub addrs + %d stub names, %d skip addrs + %d skip names.",
                step1StubAddresses.size(), step1StubNames.size(),
                step1SkipAddresses.size(), step1SkipNames.size()));

        // RULE 11: MainLoop shield
        Address mainLoopAddr = null;
        try {
            mainLoopAddr = askAddress("MainLoop Address",
                "Enter MainLoop function address (Cancel = auto-detect or skip)");
        } catch (Exception ignored) {}

        if (mainLoopAddr == null) {
            for (Function f : funcManager.getFunctions(true)) {
                String n = f.getName().toLowerCase();
                if (n.equals("mainloop__fv") || n.equals("mainloop") || n.equals("main_loop")) {
                    mainLoopAddr = f.getEntryPoint();
                    println("[MAINLOOP] Auto-detected: " + f.getName() + " @ " + mainLoopAddr);
                    break;
                }
            }
        }
        if (mainLoopAddr != null) {
            buildMainLoopShield(mainLoopAddr);
            println("[MAINLOOP] Shield: " + mainLoopShield.size() + " functions protected.\n");
        } else {
            println("[MAINLOOP] No MainLoop found. Shield disabled.\n");
        }

        detectTextSection();
        long gpValue = detectGlobalPointer();
        String elfHash = computeElfHash();

        // --- Main scan ---
        println("[SCAN] Analyzing...");
        long scanStart = System.currentTimeMillis();

        FunctionIterator allFuncs = funcManager.getFunctions(true);
        int totalFuncs = 0, uncategorized = 0;
        List<FuncResult> results = new ArrayList<>();
        List<String> newStubs = new ArrayList<>();
        List<String> newSkips = new ArrayList<>();

        while (allFuncs.hasNext() && !monitor.isCancelled()) {
            Function func = allFuncs.next();
            totalFuncs++;
            Address addr = func.getEntryPoint();
            long offset = addr.getOffset();
            String funcName = func.getName();

            // RULE 9: Skip already classified
            if (step1StubAddresses.contains(offset) || step1SkipAddresses.contains(offset)
                    || step1StubNames.contains(funcName) || step1SkipNames.contains(funcName))
                continue;

            uncategorized++;
            FuncTraits traits = getTraits(func);

            // RULE 10: Whitelist (Extended for C++ game objects & Callbacks)
            boolean isWhitelisted = false;
            for (String wl : WHITELIST_NAMES) {
                if (funcName.equals(wl)) { isWhitelisted = true; break; }
            }
            // Add dynamic whitelist for Constructors, Destructors, Init functions, and Callbacks
            if (!isWhitelisted) {
                if (funcName.contains("__ct__") ||  // Constructors
                    (funcName.contains("__dt__") && !funcName.contains("std")) || // Destructors (non-std)
                    funcName.contains("__as__") ||  // Assignments
                    funcName.startsWith("__sinit_") || // Static initializers
                    funcName.toLowerCase().contains("callback") || // Callbacks
                    funcName.toLowerCase().contains("handler")) {  // Handlers
                    isWhitelisted = true;
                }
            }

            // RULE 11: MainLoop shield
            if (mainLoopShield.contains(offset)) isWhitelisted = true;

            // --- Firewall decisions ---
            String disposition = "RECOMPILE";

            if (!isWhitelisted) {
                if (isRadarFirewalled(func)) {
                    disposition = "STUB";
                    newStubs.add(funcName + "@" + hex(offset));
                    radarNewStubs++;
                } else if (referencesIopModule(func, traits)) {
                    // RULE 3+8: IOP refs (size-capped) → STUB
                    disposition = "STUB";
                    newStubs.add(funcName + "@" + hex(offset));
                    radarNewStubs++;
                } else if (isKernelInternal(func)) {
                    // RULE 7+8: syscall/COP0 → SKIP
                    disposition = "SKIP";
                    newSkips.add(funcName + "@" + hex(offset));
                    radarNewSkips++;
                } else if (traits.hasVcallms) {
                    // RULE 16: VU0 microcode → forced STUB
                    disposition = "STUB";
                    newStubs.add(funcName + "@" + hex(offset));
                    radarNewStubs++;
                }
            }

            // --- Tags ---
            List<String> tags = new ArrayList<>();
            String category = assignCategory(traits);

            if (traits.calledCount==0 && traits.callOps==0 && !traits.isThunk && traits.byteSize>0)
                { tags.add("SAFE_LEAF"); safeLeafCount++; }
            if (traits.accOps >= 3)
                { tags.add("ACC_PRECISION_HAZARD"); accHazardCount++; }
            if (traits.writesToText)
                { tags.add("SMC_HAZARD"); smcHazardCount++; }
            if (traits.usesSPR && traits.hasSyncInstr)
                { tags.add("SPR_SYNC_HAZARD"); sprSyncCount++; }
            if (traits.hasBusyWait)
                { tags.add("BUSY_WAIT_HAZARD"); busyWaitCount++; }
            if (traits.hasVcallms)
                { tags.add("VU0_MICROCODE"); vcallmsCount++; }
            if (traits.hasJumpTable)
                { tags.add("COMPLEX_CONTROL_FLOW"); jumpTableCount++; }

            // RULE 5: MMIO as tag only
            if (accessesHardware(func))
                { tags.add("ACCESSES_MMIO"); mmioCount++; }

            if (traits.usesCop2) tags.add("VU0_VECTORS");
            if (traits.usesCop1) tags.add("FPU_HEAVY");
            if (traits.usesSPR)  tags.add("USES_SPR");
            if (traits.writesToGlobal) tags.add("WRITES_GLOBAL");
            if (traits.returnPaths >= 3) tags.add("MULTI_RETURN");

            // ORPHAN tag: Fixed API check using hasReferencesTo directly
            if (!refManager.hasReferencesTo(addr) && !isWhitelisted)
                { tags.add("ORPHAN_CODE"); orphanCount++; }

            FuncResult r = new FuncResult();
            r.address=offset; r.name=funcName; r.category=category;
            r.disposition=disposition; r.traits=traits; r.tags=tags;
            results.add(r);
        }

        long scanSec = (System.currentTimeMillis()-scanStart)/1000;
        println(String.format("[SCAN] %d functions in %dm%02ds.", totalFuncs, scanSec/60, scanSec%60));
        println(String.format("  New stubs: %d | New skips: %d", radarNewStubs, radarNewSkips));
        println(String.format("  Tags: SAFE=%d MMIO=%d ACC=%d SMC=%d SPR=%d VCALLMS=%d JTABLE=%d ORPHAN=%d",
                safeLeafCount, mmioCount, accHazardCount, smcHazardCount,
                sprSyncCount, vcallmsCount, jumpTableCount, orphanCount));

        writeUnifiedConfig(unifiedToml, configToml, newStubs, newSkips);
        writeTriageJson(triageJson, results, elfHash, gpValue, totalFuncs, uncategorized);

        println("\n[SUCCESS] Unified TOML : " + unifiedToml.getAbsolutePath());
        println("[SUCCESS] Triage JSON  : " + triageJson.getAbsolutePath());
        println("\nRun:  ps2recomp.exe " + unifiedToml.getName());
    }

    // =========================================================
    // RULE 9: PARSE STEP 1 CONFIG
    // =========================================================
    private void parseStep1Config(File configFile) throws IOException {
        BufferedReader reader = new BufferedReader(new FileReader(configFile));
        String line; boolean inStubs=false, inSkip=false;
        while ((line = reader.readLine()) != null) {
            String t = line.trim();
            if (t.startsWith("stubs")) { inStubs=true; inSkip=false; continue; }
            if (t.startsWith("skip") && !t.startsWith("skip_count")) { inSkip=true; inStubs=false; continue; }
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
    // RULE 11: MAINLOOP SHIELD
    // =========================================================
    private void buildMainLoopShield(Address mlAddr) {
        mainLoopShield.add(mlAddr.getOffset());
        Function mlFunc = funcManager.getFunctionAt(mlAddr);
        if (mlFunc == null) return;
        for (Function callee : mlFunc.getCalledFunctions(monitor))
            mainLoopShield.add(callee.getEntryPoint().getOffset());
    }

    // =========================================================
    // RULE 13: DETECT CODE RANGE
    // =========================================================
    private void detectTextSection() {
        for (MemoryBlock block : memory.getBlocks()) {
            String bname = block.getName().toLowerCase();
            if (bname.equals(".text") || bname.equals("text")) {
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
            println(String.format("[SECTIONS] Code: 0x%08X-0x%08X", textStart, textEnd));
        } else { println("[SECTIONS] WARNING: No code range."); }
    }

    // =========================================================
    // RULE 12: DETECT $gp
    // =========================================================
    private long detectGlobalPointer() {
        SymbolIterator syms=currentProgram.getSymbolTable().getSymbols("_gp");
        while(syms.hasNext()){long v=syms.next().getAddress().getOffset();println(String.format("[GP] _gp: 0x%08X",v));return v;}
        syms=currentProgram.getSymbolTable().getSymbols("_gp_disp");
        while(syms.hasNext()){long v=syms.next().getAddress().getOffset();println(String.format("[GP] _gp_disp: 0x%08X",v));return v;}
        // Fallback: scan entry for lui+addiu $gp
        println("[GP] No symbol. Scanning entry...");
        Function entryFunc=null;
        for(String n:new String[]{"entry","_start"}){
            SymbolIterator si=currentProgram.getSymbolTable().getSymbols(n);
            while(si.hasNext()){Function f=funcManager.getFunctionAt(si.next().getAddress());if(f!=null){entryFunc=f;break;}}
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
                    for(Object op:inst.getResultObjects()) if(op instanceof ghidra.program.model.lang.Register&&((ghidra.program.model.lang.Register)op).getName().equalsIgnoreCase("gp")) isGp=true;
                    if(isGp) for(Object op:inst.getInputObjects()) if(op instanceof ghidra.program.model.scalar.Scalar) gpUpper=((ghidra.program.model.scalar.Scalar)op).getUnsignedValue()<<16;
                }
                if(gpUpper!=0&&(mnem.equalsIgnoreCase("addiu")||mnem.equalsIgnoreCase("ori"))){
                    boolean wGp=false,rGp=false;
                    for(Object op:inst.getResultObjects()) if(op instanceof ghidra.program.model.lang.Register&&((ghidra.program.model.lang.Register)op).getName().equalsIgnoreCase("gp")) wGp=true;
                    for(Object op:inst.getInputObjects()) if(op instanceof ghidra.program.model.lang.Register&&((ghidra.program.model.lang.Register)op).getName().equalsIgnoreCase("gp")) rGp=true;
                    if(wGp&&rGp) for(Object op:inst.getInputObjects()) if(op instanceof ghidra.program.model.scalar.Scalar){
                        long lower=((ghidra.program.model.scalar.Scalar)op).getValue();
                        long gpVal=gpUpper+lower;
                        println(String.format("[GP] crt0: 0x%08X",gpVal)); return gpVal;
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
    // RULE 6: KSEG1 NORMALIZATION
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
        traits.calledCount=func.getCalledFunctions(monitor).size();
        traits.isThunk=func.isThunk()||(traits.byteSize<=8&&traits.calledCount>0);
        if(traits.isThunk){cache.put(key,traits);return traits;}

        InstructionIterator asmIter=currentProgram.getListing().getInstructions(func.getBody(),true);
        int instrIdx=0, mmioReadCount=0, totalInstrs=0;
        while(asmIter.hasNext()){
            Instruction inst=asmIter.next();
            String mnem=inst.getMnemonicString();
            if(mnem==null){instrIdx++;totalInstrs++;continue;}
            String ml=mnem.toLowerCase(); totalInstrs++;

            // Stack frame
            if(instrIdx<8&&(ml.equals("addiu")||ml.equals("daddiu")))
                for(Object op:inst.getInputObjects())
                    if(op instanceof ghidra.program.model.lang.Register&&((ghidra.program.model.lang.Register)op).getName().equals("sp"))
                        traits.hasStackFrame=true;

            // COP1/COP2
            if(ml.contains("c1")||ml.endsWith(".s")||ml.endsWith(".d")) traits.usesCop1=true;
            if(ml.startsWith("vadd")||ml.startsWith("vmul")||ml.startsWith("vsub")||ml.startsWith("vscl")
                    ||ml.startsWith("vdiv")||ml.startsWith("vmfir")||ml.startsWith("vmtir")||ml.contains("c2"))
                traits.usesCop2=true;
            if(ml.equals("lqc2")||ml.equals("sqc2")){traits.usesCop2=true;traits.quadwordVU++;}

            // ACC ops
            if(ml.startsWith("madda")||ml.startsWith("vmadd")||ml.startsWith("vmsub")||ml.startsWith("madd"))
                traits.accOps++;

            // Sync
            if(ml.equals("sync.l")||ml.equals("sync.p")||ml.equals("sync")) traits.hasSyncInstr=true;

            // RULE 16: vcallms
            if(ml.equals("vcallms")||ml.equals("vcallmsr")) traits.hasVcallms=true;

            // RULE 17: jr detection + jump table
            if(ml.equals("jr")){
                boolean isRa=false;
                for(Object op:inst.getInputObjects())
                    if(op instanceof ghidra.program.model.lang.Register){
                        String rn=((ghidra.program.model.lang.Register)op).getName().toLowerCase();
                        if(rn.equals("ra")) isRa=true; else traits.hasJumpTable=true;
                    }
                if(isRa) traits.returnPaths++;
            }

            // Store: global write + SMC
            if(ml.equals("sw")||ml.equals("swc1")||ml.equals("sqc2")||ml.equals("sh")||ml.equals("sb")){
                traits.hasMutatingInstructions=true;
                for(Reference ref:inst.getReferencesFrom()){
                    if(!ref.getReferenceType().isWrite()) continue;
                    long tOff=ref.getToAddress().getOffset();
                    long norm=normalizeAddress(tOff);
                    if(ref.getToAddress().getAddressSpace().isMemorySpace()&&norm>=GLOBAL_ADDR_MIN)
                        traits.writesToGlobal=true;
                    // RULE 13: SMC
                    if(textStart>0&&norm>=textStart&&norm<=textEnd){
                        Instruction ti=currentProgram.getListing().getInstructionAt(ref.getToAddress());
                        if(ti!=null) traits.writesToText=true;
                    }
                }
            }

            // JAL/JALR
            if(ml.equals("jal")||ml.equals("jalr")){traits.hasMutatingInstructions=true;traits.callOps++;}

            // SPR (RULE 6: normalize)
            for(Reference ref:inst.getReferencesFrom()){
                long norm=normalizeAddress(ref.getToAddress().getOffset());
                if(norm>=SPR_START&&norm<=SPR_END) traits.usesSPR=true;
            }

            // Counters
            if(ml.startsWith("b")&&!ml.equals("break")) traits.branchOps++;
            else if(ml.startsWith("l")&&!ml.equals("lui")&&!ml.equals("lq")&&!ml.equals("lqc2")){
                traits.loadOps++;
                for(Reference ref:inst.getReferencesFrom()){
                    long norm=normalizeAddress(ref.getToAddress().getOffset());
                    if(norm>=MMIO_START&&norm<=MMIO_END) mmioReadCount++;
                }
            }
            else if(ml.startsWith("add")||ml.startsWith("dadd")||ml.startsWith("sub")
                    ||ml.startsWith("mul")||ml.startsWith("div")) traits.mathOps++;

            if(ml.endsWith(".s")||ml.endsWith(".d")||ml.startsWith("cvt.")||ml.startsWith("c."))
                traits.floatOps++;

            instrIdx++;
        }
        if(totalInstrs>0&&totalInstrs<=15&&mmioReadCount>0&&traits.branchOps>=1)
            traits.hasBusyWait=true;

        cache.put(key,traits); return traits;
    }

    // =========================================================
    // UPDATED CATEGORY HEURISTICS (Copy-Paste Ready)
    // =========================================================
    private String assignCategory(FuncTraits t) {
        boolean calls = (t.calledCount > 0 || t.callOps > 0);
        
        // Leaf functions that do nothing but return or simple math
        if (!calls && t.byteSize < 100 && !t.writesToGlobal) return "GETTER_OR_STUB";
        
        // Heavy FPU/VU math calculation (likely physics/matrices)
        if (t.usesCop2 || t.floatOps >= 6 || (t.mathOps > 10 && !calls)) return "MATH_VECTORS";
        
        // Lots of branches, usually state machines or AI logic
        if (t.branchOps >= 4 || t.returnPaths >= 2) return "STATE_MACHINES";
        
        // Functions modifying global state with mix of ops
        if (t.writesToGlobal && t.loadOps > 0 && calls) return "GAME_LOGIC";
        
        // Functions with small footprint but do have calls (often wrappers)
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
        for(String p:RADAR_FIREWALL_PREFIXES) if(name.startsWith(p)){staticFwCache.put(key,true);return true;}
        for(String p:BIOS_FIREWALL_PREFIXES) if(name.startsWith(p)){staticFwCache.put(key,true);return true;}
        staticFwCache.put(key,false); return false;
    }

    // RULE 7: syscall + COP0 only
    private boolean isKernelInternal(Function func) {
        Address key=func.getEntryPoint();
        Boolean c=behavFwCache.get(key); if(c!=null) return c;
        boolean k=containsSyscall(func)||containsCOP0(func);
        behavFwCache.put(key,k); return k;
    }

    // RULE 3: Size-capped IOP check
    private boolean referencesIopModule(Function func, FuncTraits traits) {
        if(traits.byteSize>800) return false;
        Address key=func.getEntryPoint();
        Boolean c=iopFwCache.get(key); if(c!=null) return c;
        InstructionIterator it=currentProgram.getListing().getInstructions(func.getBody(),true);
        while(it.hasNext()){
            for(Reference ref:it.next().getReferencesFrom()){
                Data data=getDataAt(ref.getToAddress());
                if(data!=null&&data.hasStringValue()){
                    String str=data.getDefaultValueRepresentation();
                    for(String s:IOP_MODULE_STRINGS) if(str.contains(s)){iopFwCache.put(key,true);return true;}
                }
            }
        }
        iopFwCache.put(key,false); return false;
    }

    private boolean containsSyscall(Function func) {
        InstructionIterator it=currentProgram.getListing().getInstructions(func.getBody(),true);
        while(it.hasNext()){String m=it.next().getMnemonicString();if(m!=null&&m.equalsIgnoreCase("syscall")) return true;}
        return false;
    }

    // RULE 4+6: DATA refs only, KSEG1 masked
    private boolean accessesHardware(Function func) {
        for(Address addr:func.getBody().getAddresses(true)){
            for(Reference ref:refManager.getReferencesFrom(addr)){
                if(ref.getReferenceType().isCall()||ref.getReferenceType().isFlow()) continue;
                long norm=normalizeAddress(ref.getToAddress().getOffset());
                if((norm>=MMIO_START&&norm<=MMIO_END)||(norm>=MMIO_GS_START&&norm<=MMIO_GS_END))
                    return true;
            }
        }
        return false;
    }

    private boolean containsCOP0(Function func) {
        InstructionIterator it=currentProgram.getListing().getInstructions(func.getBody(),true);
        while(it.hasNext()){
            String m=it.next().getMnemonicString(); if(m==null) continue; m=m.toLowerCase();
            if(m.equals("di")||m.equals("ei")||m.equals("mfc0")||m.equals("mtc0")||m.equals("eret")||m.startsWith("c0"))
                return true;
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
            stubLines.add("  # --- Triage Enricher v2 additions ---");
            for(String s:newStubs) stubLines.add("  \""+s+"\",");
        }
        List<String> skipLines=new ArrayList<>();
        if(!newSkips.isEmpty()){
            skipLines.add("  # --- Triage Enricher v2 additions ---");
            for(String s:newSkips) skipLines.add("  \""+s+"\",");
        }

        // Insert in reverse index order to preserve positions
        if(skipClose>=0&&!skipLines.isEmpty()){
            lines.addAll(skipClose, skipLines);
            if(stubsClose>=skipClose) stubsClose+=skipLines.size();
        }
        if(stubsClose>=0&&!stubLines.isEmpty())
            lines.addAll(stubsClose, stubLines);

        // Add header
        lines.add(0, "# Unified config: "+step1Config.getName()+" + "+newStubs.size()+" stubs + "+newSkips.size()+" skips");

        // Update Metadata Block counts
        for (int i = 0; i < lines.size(); i++) {
            String l = lines.get(i);
            if (l.startsWith("stub_count =")) {
                int oldStubCount = Integer.parseInt(l.split("=")[1].trim());
                lines.set(i, "stub_count = " + (oldStubCount + newStubs.size()));
            } else if (l.startsWith("skip_count =")) {
                int oldSkipCount = Integer.parseInt(l.split("=")[1].trim());
                lines.set(i, "skip_count = " + (oldSkipCount + newSkips.size()));
            }
        }

        PrintWriter w=new PrintWriter(new FileWriter(outFile));
        for(String l:lines) w.println(l);
        w.close();
    }
    // =========================================================
    // JSON OUTPUT
    // =========================================================
    private void writeTriageJson(File outFile, List<FuncResult> results,
                                 String elfHash, long gpValue,
                                 int totalFuncs, int uncategorized) throws IOException {
        PrintWriter w=new PrintWriter(new FileWriter(outFile));
        w.println("{");
        w.println("  \"schema_version\": 2,");
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
        w.println("    \"orphan_code\": "+orphanCount);
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
            w.print("\"size\": "+t.byteSize+", ");
            w.print("\"metrics\": {");
            w.print("\"fpu_ops\": "+t.floatOps+", ");
            w.print("\"math_ops\": "+t.mathOps+", ");
            w.print("\"branch_ops\": "+t.branchOps+", ");
            w.print("\"load_ops\": "+t.loadOps+", ");
            w.print("\"acc_ops\": "+t.accOps+", ");
            w.print("\"call_ops\": "+t.callOps+", ");
            w.print("\"callee_count\": "+t.calledCount+", ");
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
            w.print("]}");
            if(i<results.size()-1) w.println(","); else w.println();
        }
        w.println("  ]"); w.println("}"); w.close();
    }

    class FuncResult { long address; String name,category,disposition; FuncTraits traits; List<String> tags; }

    private static String hex(long v){return String.format("0x%08X",v&0xFFFFFFFFL);}
    private static String jsonString(String v){
        if(v==null) return "\"\"";
        return "\""+v.replace("\\","\\\\").replace("\"","\\\"").replace("\n","\\n").replace("\r","\\r").replace("\t","\\t")+"\"";
    }
}