//
//@author Tencent KeenLab
//@category Analysis
//@keybinding
//@menupath Analysis.BinAbsInspector
//@toolbar keenlogo.gif

import com.bai.checkers.CheckerManager;
import com.bai.env.funcs.FunctionModelManager;
import com.bai.solver.CFG;
import com.bai.util.*;
import com.bai.util.Config.HeadlessParser;
import com.microsoft.z3.Log;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.util.bin.MemoryByteProvider;
import ghidra.app.util.bin.format.elf.ElfException;
import ghidra.app.util.bin.format.elf.ElfHeader;
import ghidra.program.model.address.*;
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.block.CodeBlockIterator;
import ghidra.program.model.block.*;
import ghidra.program.model.lang.Language;
import ghidra.program.model.listing.*;
import ghidra.app.script.GhidraScript;
import com.bai.solver.InterSolver;

import java.awt.Color;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Pattern;

import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.util.task.TaskMonitor;
import org.apache.commons.lang3.StringUtils;
import org.python.antlr.ast.Print;
import org.python.antlr.op.Add;
import org.python.compiler.Code;

public class BinAbsInspector extends GhidraScript {

    protected boolean prepareProgram() {
        GlobalState.currentProgram = this.currentProgram;
        GlobalState.flatAPI = this;
        //
        GlobalState.basicBlockModel = new BasicBlockModel(GlobalState.currentProgram);
        GlobalState.decompInterface = new DecompInterface();
        GlobalState.doSearchMemcpyLikeFuns=true;
        GlobalState.toolkit=new Toolkit();
        GlobalState.callDeepLength=1000;
        GlobalState.callDeep=0;
        //
        Language language = GlobalState.currentProgram.getLanguage();
        return language != null;
    }

    protected boolean analyzeFromMain() {
        List<Function> functions = GlobalState.currentProgram.getListing().getGlobalFunctions("12345");
        if (functions == null || functions.size() == 0) {
            return false;
        }
        Function entryFunction = functions.get(0);
        if (entryFunction == null) {
            Logging.error("Cannot find entry function");
            return false;
        }
        Logging.info("Running solver on \"" + entryFunction + "()\" function");
        InterSolver solver = new InterSolver(entryFunction, true);
        solver.run();
        return true;
    }

    protected boolean analyzeFromAddress(Address entryAddress) {
        Function entryFunction = GlobalState.flatAPI.getFunctionAt(entryAddress);
        if (entryAddress == null) {
            Logging.error("Could not find entry function at " + entryAddress);
            return false;
        }
        Logging.info("Running solver on \"" + entryFunction + "()\" function");
        InterSolver solver = new InterSolver(entryFunction, false);
        solver.run();
        return true;
    }

    /**
     * Start analysis with following steps:
     * 1. Start from specific address if user provided, the address must be the entrypoint of a function.
     * 2. Start from "main" function if step 1 fails.
     * 3. Start from "e_entry" address from ELF header if step 2 fails.
     * @return
     */
    protected boolean analyze() {
        Program program = GlobalState.currentProgram;
        if (program == null) {
            Logging.error("Import program error.");
            return false;
        }
        String entryAddressStr = GlobalState.config.getEntryAddress();
        if (entryAddressStr != null) {
            Address entryAddress = GlobalState.flatAPI.toAddr(entryAddressStr);
            return analyzeFromAddress(entryAddress);
        } else {
            GlobalState.eEntryFunction = null;//GlobalState.eEntryFunction = Utils.getEntryFunction();
            //Address saddress=GlobalState.flatAPI.toAddr(0xC7FA40);
            //Address saddress=GlobalState.flatAPI.toAddr(0x7419F0); //ns_vpn_process_unauthenticated_request
            //Address saddress=GlobalState.flatAPI.toAddr(0x0C82BB0); //ns_aaa_saml_url_decode_inner
            //Address saddress=GlobalState.flatAPI.toAddr(0x0121c6f0); //asa952 ewsRun
            Address saddress=GlobalState.flatAPI.toAddr(0x1E124A0); // citrix nshttp_handler
            GlobalState.eEntryFunction=GlobalState.flatAPI.getFunctionAt(saddress);
            if (GlobalState.eEntryFunction == null) {
                Logging.error("Cannot find entry function, maybe unsupported file format or corrupted header.");
                return false;
            }
            if (!analyzeFromMain()) {
                Logging.info("Start from entrypoint");
                Logging.info("Running solver on \"" + GlobalState.eEntryFunction + "()\" function");
                InterSolver solver = new InterSolver(GlobalState.eEntryFunction, false);
                solver.run();
                return true;
            }
        }
        return true;
    }

    private void guiProcessResult() {
        if (!GlobalState.config.isGUI()) {
            return;
        }
        String msg = "Analysis finish!\n Found " + Logging.getCWEReports().size() + " CWE Warning.";
        GlobalState.ghidraScript.popup(msg);
        Logging.info(msg);
        for (CWEReport report : Logging.getCWEReports().keySet()) {
            GlobalState.ghidraScript.setBackgroundColor(report.getAddress(), Color.RED);
            GlobalState.ghidraScript.setEOLComment(report.getAddress(), report.toString());
            Logging.warn(report.toString());
        }
    }

    @Override
    public void run() throws Exception {
        GlobalState.config = new Config();
        if (isRunningHeadless()) {
            String allArgString = StringUtils.join(getScriptArgs()).strip();
            GlobalState.config = HeadlessParser.parseConfig(allArgString);
        } else {
            GlobalState.ghidraScript = this;
            GlobalState.config = new Config();
            GlobalState.config.setGUI(true);
            ConfigDialog dialog = new ConfigDialog(GlobalState.config);
            dialog.showDialog();
            if (!dialog.isSuccess()) {
                return;
            }
        }
        if (!Logging.init()) {
            return;
        }
        FunctionModelManager.initAll();
        if (GlobalState.config.isEnableZ3() && !Utils.checkZ3Installation()) {
            return;
        }
        Logging.info("Preparing the program");
        if (!prepareProgram()) {
            Logging.error("Failed to prepare the program");
            return;
        }
        if (isRunningHeadless()) {
            if (!Utils.registerExternalFunctionsConfig(GlobalState.currentProgram, GlobalState.config)) {
                return;
            }
        } else {
            Utils.loadCustomExternalFunctionFromLabelHistory(GlobalState.currentProgram);
        }

        GlobalState.arch = new Architecture(GlobalState.currentProgram);


        //
        //memcpy_funcs=YMsearchMemcpylikeFunc(memcpy_funcs);
        GlobalState.doSearchMemcpyLikeFuns=false;
        if(GlobalState.doSearchMemcpyLikeFuns){

            long startTime = System.nanoTime();

            Set<FuncInfo> memcpy_funcs =searchMemcpylikeFunc();
            long endTime = System.nanoTime();
            long duration = endTime - startTime;
            double seconds = (double)duration / 1_000_000_000.0;
            System.out.println("The code took " + seconds + " seconds to execute.");

            int func_num=0;
            for(FuncInfo memcpy:memcpy_funcs){
                Logging.info("find memcpy like funcs: "+memcpy.funcName);
                func_num+=1;
            }
            Logging.info("find memcpy like funcs number is "+func_num);
            ///home/tangent/Desktop/work/bs/MyBinAbs
            GlobalState.toolkit.SaveFuncInfoSetToFile(memcpy_funcs,"/home/tangent/Desktop/work/bs/MyBinAbs/Result/memcpylike.txt");
        }

        //

        boolean success = analyze();
        if (!success) {
            Logging.error("Failed to analyze the program: no entrypoint.");
            return;
        }
        Logging.info("Running checkers");
        CheckerManager.runCheckers(GlobalState.config);
        guiProcessResult();
        GlobalState.reset();
    }

    public static Set<FuncInfo> searchMemcpylikeFunc(){
        //Set<Function> memcpy_funcs=new HashSet<>();
        Set<FuncInfo> memcpy_funcs=new HashSet<>();
        Logging.info("Enter searchMemcpyLikeFunc...");
        for (Function f:GlobalState.currentProgram.getFunctionManager().getFunctions(true)){

            FuncInfo tmpFuncInfo=new FuncInfo();

            Logging.info("+++++++"+f.getName()+"+++++++");
            Logging.info("[searchMemcpyLikeFunc] Start analyze function: "+f.getName());
            tmpFuncInfo.funcName=f.getName();
            //
            if (f.getName().equals("ns_aaa_saml_url_decode_inner")){
            //if (f.getName().equals("FUN_090a32a0")){
                Logging.info("Find test funtion: "+f.getName());
            }

            // 1.the function name contains "memcpy"
            if(f.getName().contains("memcpy")){
                memcpy_funcs.add(tmpFuncInfo);
                continue;
            }
            int parameterCount=f.getParameterCount();
            Logging.info("The function parameter count is :"+parameterCount);
            tmpFuncInfo.paramNum=parameterCount;
            if(parameterCount>3){
                Logging.info("+++++function number is not equal to 3+++++");
                continue;
            }

            // 获取函数的交叉引用
            Reference[] xreflist=GlobalState.flatAPI.getReferencesTo(f.getEntryPoint());
            tmpFuncInfo.xrefNum=xreflist.length;
            if(xreflist.length<20){
                Logging.info("+++++xref is less than 20+++++");
                continue;
            }

            // 获取基本块数量
            int block_cnt=0;
            //
            try {
                // 基本块迭代器
                CodeBlockIterator block_it = GlobalState.basicBlockModel.getCodeBlocksContaining(f.getBody(), TaskMonitor.DUMMY);
                while(block_it.hasNext()){
                    block_it.next();
                    block_cnt+=1;
                }
            }catch (Exception e){
                continue;
            }
            Logging.info("[searchMemcpyLikeFunc] black number is " + block_cnt);
            tmpFuncInfo.basicBlockNum=block_cnt;

            int callee_num = f.getCalledFunctions(TaskMonitor.DUMMY).size();


            if (block_cnt<=1||block_cnt>25){
                Logging.info("+++++block number is more than 50+++++");
                continue;
            }



            //如果函数内部有调用其他函数
            //!todo

            //基本块的循环识别
//            if(!f.getName().equals("ns_aaa_saml_url_decode_inner")){
//                continue;
//            }
            try{
                CodeBlockIterator block_it = GlobalState.basicBlockModel.getCodeBlocksContaining(f.getBody(), TaskMonitor.DUMMY);
                while(block_it.hasNext()){
                    CodeBlock currentBlock=block_it.next();


                    boolean isLoop = isLooop(currentBlock);
                    if(isLoop){

                        int movInst=0;
                        int allInst=0;
                        int addInst=0;
                        System.out.println("Loop block:"+currentBlock.getName());
                        if(currentBlock.getName().contains("90A32C0".toLowerCase())){
                            System.out.println("Loop block:"+currentBlock.getName());
                        }
                        AddressSetView setView=new AddressSet(currentBlock.getMinAddress(),currentBlock.getMaxAddress());
                        InstructionIterator instructions=GlobalState.currentProgram.getListing()
                                .getInstructions(setView,true);
                        while (instructions.hasNext()) {
                            allInst+=1;
                            Instruction instruction = instructions.next();
                            if(instruction.getMnemonicString().startsWith("MOV")){
                                movInst+=1;
                            }else if(instruction.getMnemonicString().startsWith("ADD")){
                                addInst+=1;
                            }
                            //System.out.println("Instruction: " + instruction);
                        }
                        double fate=(double)movInst/allInst;
                        if(allInst>=15&&fate>=0.6&&addInst>=1){
                            Logging.info("this function maybe memcpy function!");
                            tmpFuncInfo.memcpyLike=true;
                            memcpy_funcs.add(tmpFuncInfo);
                        }

                    }
                }
            }catch (Exception e){
                continue;
            }





            if(f.getName().equals("ns_aaa_saml_url_decode_inner")){
                InterSolver solver = new InterSolver(f, false);
                solver.run();
            }

            //对单个函数进行分析





            Logging.info("+++++++END+++++++");
        }
        return memcpy_funcs;
    }

    public static boolean isLoop(CodeBlock block, Set<Address> visited){
        Address blockAddress = block.getMinAddress();
        if (visited.contains(blockAddress)) {
            // 如果我们已经访问过这个地址，那么这是一个循环
            return true;
        }

        visited.add(blockAddress);
        try{
            CodeBlockReferenceIterator blockIterator=block.getDestinations(TaskMonitor.DUMMY);
            while (blockIterator.hasNext()){
                CodeBlock destination=blockIterator.next().getDestinationBlock();
                if(isLoop(destination,visited)){
                    return true;
                }
            }
        }catch(Exception e){
            System.out.println(e);
        }

        return false;
    }
    public static boolean isLooop(CodeBlock block) {
        Map<CodeBlock, Integer> dealList = new HashMap<>();
        Set<CodeBlock> stackNodes = new HashSet<>();
        if (block == null) {
            return false;
        }
        Stack<CodeBlock> myStack = new Stack<>();
        myStack.add(block);
        stackNodes.add(block);

        while (!myStack.isEmpty()) {
            CodeBlock currentBlock = myStack.pop();
            stackNodes.remove(currentBlock);
            if (dealList.containsKey(currentBlock)) {
                int cnt = dealList.get(currentBlock);
                if (cnt >= 2) continue;
                cnt += 1;
                dealList.put(currentBlock, cnt);
            } else {
                dealList.put(currentBlock, 1);
            }
            try {
                CodeBlockReferenceIterator blockIterator = currentBlock.getDestinations(TaskMonitor.DUMMY);
                while (blockIterator.hasNext()) {
                    CodeBlock tmpBlock = blockIterator.next().getDestinationBlock();
                    if (stackNodes.contains(tmpBlock)) {
                        return true; // Loop detected
                    }
                    myStack.push(tmpBlock);
                    stackNodes.add(tmpBlock);
                }
            } catch (Exception e) {
                System.out.println(e);
            }
        }
        return false;
    }

    public static Set<Function> YMsearchMemcpylikeFunc(Set<Function> memcpy_funcs){
        Logging.info("Enter searchMemcpylikeFunc...");
        DecompInterface ifc = GlobalState.decompInterface;
//        int i = 0;
        for(Function f: GlobalState.currentProgram.getFunctionManager().getFunctions(true)){
//            if(f.getEntryPoint().getOffset() != 0x40876f1e && f.getEntryPoint().getOffset() != 0x040057f0) continue;
//            Logging.info("Handle: " + i++ + " " + f.getName());
            Logging.info("Start analyze function: "+f.getName());
            if (f.getName().equals("ns_aaa_saml_url_decode_inner")){
                Logging.info("Find test funtion: "+f.getName());
            }

            int callee_num = f.getCalledFunctions(TaskMonitor.DUMMY).size();

            // 1. only consider function has no callee and it is not a thunk function.
            if (f.isThunk() || callee_num > 1 || f.getEntryPoint().getOffset() < 0x10000  ||
                    f.getCallingFunctions(TaskMonitor.DUMMY).size() == 0)
                continue;

            // the function name contains
            if(f.getName().contains("memcpy")){
                //ShannonMemcpyFunc.addstaticSymbols(f.getName());
                memcpy_funcs.add(f);
                continue;
            }
//            if(!f.getName().contains("memcpy") && !f.getName().startsWith("FUN_")) continue;
            AtomicInteger nblock = new AtomicInteger();
            int bmemcpy = 1;


            // 2. only consider block number (1,5)
            try {
                AtomicInteger finalNblock = nblock;
                Callable<AtomicInteger> callable = () -> {
                    CodeBlockIterator it = GlobalState.basicBlockModel.getCodeBlocksContaining(f.getBody(), TaskMonitor.DUMMY);
                    while (it != null && it.hasNext()){
                        it.next(); finalNblock.getAndIncrement();
                        if((callee_num == 0 && finalNblock.get() > 5) || (callee_num == 1 && finalNblock.get() > 15)) break;
                    }
                    return finalNblock;
                };
                // CodeBlockIterator it = GlobalState.basicBlockModel.getCodeBlocksContaining(f.getBody(), TaskMonitor.DUMMY);
                ExecutorService threadPoolExecutor= Executors.newSingleThreadExecutor();
                final Future<AtomicInteger> future = threadPoolExecutor.submit(callable);
                nblock = future.get(3, TimeUnit.SECONDS);
            } catch (Exception e){
                continue;
            }
            if((callee_num == 0 && nblock.get() > 5) || (callee_num == 1 && nblock.get() > 15)) bmemcpy = 0;
            if(bmemcpy == 0 || nblock.get() <= 1) continue;

            // 3. only consider parameter number is 3 and there has an add_1 instruction.
            AddressSetView addrset = f.getBody();
            List<CodeUnit> codes =new ArrayList<>();
            GlobalState.currentProgram.getListing().getCodeUnits(addrset, true).forEach(codes::add);
            if((callee_num == 0 && (codes.size() < 5 || codes.size() > 15)) || (callee_num == 1 && codes.size() >30))
                continue;

            try {
                String defunc = ifc.decompileFunction(f, 60, TaskMonitor.DUMMY).getDecompiledFunction().getC();
                if(!defunc.contains("for") && !defunc.contains("while")) continue;

                String assemblyCode = org.apache.commons.lang.StringUtils.join(codes.toArray(),"!");
                String pattern = ".*!add((?!!).)*#0x1!.*";
                if(assemblyCode.contains("cmp ") && assemblyCode.contains("ldrb") && assemblyCode.contains("strb")
                        && (assemblyCode.contains("b ") || assemblyCode.contains("bhi")) && Pattern.matches(pattern, assemblyCode)) {
//                    Set<Function> callers = f.getCallingFunctions(TaskMonitor.DUMMY);
//                    List<Integer> pnum = new ArrayList<>();
//                    getFunctionParmNum(pnum, callers, f.getEntryPoint(), true);
                    if(defunc.contains("param_3")){
                        //ShannonMemcpyFunc.addstaticSymbols(f.getName());
                        memcpy_funcs.add(f);
                    }
//                    if(pnum.size() != 0 && Collections.max(pnum) == 3) {
//                        try{
//                            ShannonMemcpyFunc.addstaticSymbols(f.getName());
//                            memcpy_funcs.add(f.getName());
//                        } catch (Exception e) {
//                            Logging.info("...");
//                        }
//
//                    }
                }
            } catch (Exception e) {
                //e.printStackTrace();
                continue;
            }
        }
        return memcpy_funcs;
    }


}
