package com.bai.util;

import com.bai.env.ALoc;
import com.bai.env.Context;
import com.bai.env.ContextTransitionTable;
import com.bai.env.TaintMap;
import com.bai.env.funcs.FunctionModelManager;
import com.bai.env.region.Heap;
import com.bai.env.region.Local;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;

import com.bai.solver.CFG;

import ghidra.program.flatapi.FlatProgramAPI;

/**
 * Global state of current analysis.
 */
public class GlobalState {

    public static Program currentProgram;

    public static FlatProgramAPI flatAPI;

    public static Config config;

    public static GhidraScript ghidraScript;

    public static Architecture arch;

    /** e_entry from ELF header **/
    public static Function eEntryFunction;


    //添加
    public static BasicBlockModel basicBlockModel;
    public static DecompInterface decompInterface;

    public static Boolean doSearchMemcpyLikeFuns;

    public static Toolkit toolkit;

    public static boolean checkloop;

    public static int callDeepLength;
    public static int callDeep;

    //end

    /**
     * @hidden
     */
    public static void reset() {
        ALoc.resetPool();
        Context.resetPool();
        Heap.resetPool();
        Local.resetPool();
        CFG.resetPool();
        TaintMap.reset();
        Logging.resetReports();
        FunctionModelManager.resetConfig();
        FunctionModelManager.resetStdContainers();
        ContextTransitionTable.reset();
        System.gc();
    }
}
