package com.bai.checkers;

import com.bai.env.*;
import com.bai.env.region.Global;
import com.bai.util.*;
import ghidra.app.cmd.function.ApplyFunctionSignatureCmd;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.data.ParameterDefinitionImpl;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.task.TaskMonitor;
import jdk.jshell.execution.Util;
import org.javimmutable.collections.JImmutableMap;
import org.python.antlr.op.Add;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

public class HSL_chekcer  extends CheckerBase{

    public HSL_chekcer(){
        super("HSL_checker","0.1");
        description+="HSL Checker";
    }


    private boolean reportTaints(long taints, int idx, String funcName, Address address,Context context) {
        List<TaintMap.Source> taintSourceList = TaintMap.getTaintSourceList(taints);
        for (TaintMap.Source taintSource : taintSourceList) {
            CWEReport report = getNewReport("HSL_checker:"
                    + "from source of "
                    + taintSource.getContext().toString()
                    +  "(" + context.toString()
                    + ") at " + Utils.getOrdinal(idx) + " argument of \""
                    + funcName + "()\" call").setAddress(address);
            Logging.report(report);
            Logging.info(report.getFormattedMessage());
            return true;
        }
        return false;
    }

    private Long getStrTaints(AbsVal ptr, AbsEnv absEnv) {
        int len = StringUtils.strlen(ptr, absEnv);
        int offset = 0;
        while (offset < len) {
            ALoc aLoc = ALoc.getALoc(ptr.getRegion(), ptr.getValue() + offset, 1);
            JImmutableMap.Entry<ALoc, KSet> entry = absEnv.getOverlapEntry(aLoc);
            if (entry == null) {
                return null;
            }
            if (entry.getValue().isTaint()) {
                return entry.getValue().getTaints();
            }
            offset += entry.getKey().getLen();
        }
        return null;
    }
    private void defineExecSignature(Function function, String name, int argCount) {
        if (argCount == function.getParameters().length) {
            return;
        }
        try {
            final int tid = GlobalState.currentProgram.startTransaction("define signature");
            FunctionDefinitionDataType signature = new FunctionDefinitionDataType(name);
            ArrayList<ParameterDefinitionImpl> paramList = new ArrayList<>();
            for (int i = 0; i < argCount; i++) {
                paramList.add(new ParameterDefinitionImpl("arg" + i, PointerDataType.dataType, "arg" + i));
            }
            ParameterDefinitionImpl[] params = new ParameterDefinitionImpl[paramList.size()];
            signature.setArguments(paramList.toArray(params));
            signature.setReturnType(PointerDataType.dataType);
            ApplyFunctionSignatureCmd cmd = new ApplyFunctionSignatureCmd(
                    function.getEntryPoint(),
                    signature,
                    SourceType.USER_DEFINED
            );
            cmd.applyTo(GlobalState.currentProgram, TaskMonitor.DUMMY);
            GlobalState.currentProgram.endTransaction(tid, true);
        } catch (Exception e) {
            Logging.warn("Fail to define signature for " + name);
        }
    }


    private boolean checkFunctionParameters(AbsEnv absEnv, Function callee, Address address,Context context) {
        String name = callee.getName();
        int[] paramIndexes = taintDstSymbols.get(name);
        int argCount = Arrays.stream(paramIndexes).max().getAsInt() + 1;
        if (callee.getParameters().length != argCount) {
            // define function signature for taintDstSymbols, which missing function model.
            defineExecSignature(callee, name, argCount);
        }
        boolean result = false;
        for (int idx : paramIndexes) {
            KSet ptrKSet = getParamKSet(callee, idx, absEnv);
            if (ptrKSet.isTop()) {
                if (ptrKSet.isTaint()) {
                    long taints = ptrKSet.getTaints();
                    result = reportTaints(taints, idx, name, address,context);
                    return result;
                }
                return false;
            }
            for (AbsVal ptr : ptrKSet) {
                Long taints = getStrTaints(ptr, absEnv);
                if (taints == null) {
                    continue;
                }
                result = reportTaints(taints, idx, name, address,context);
                if (result) {
                    return true;
                }
            }
        }
        return result;
    }




    private static final Map<String,int[]> taintDstSymbols= Map.of(
            "ns_aaa_saml_url_decode",new int[]{0,1,2},
            //"ns_aaa_gwtest_get_event_and_target_names",new int[]{1,2,3}\
            "strncmp",new int[]{2,3},
            "snprintf",new int[]{0,1,2,3,4,5},
            "ns_aaa_oauth_send_openid_config",new int[]{0,1}

    );



    @Override
    public boolean check(){
        boolean hasWarning=false;
      try{
          for(Reference reference: Utils.getReferences(new ArrayList<>(taintDstSymbols.keySet()))){
//          List<Reference> test=Utils.getReferences(new ArrayList<>(taintDstSymbols.keySet()));
//          Reference reference=test.get(0);
              Address toAddress=reference.getToAddress();
              Address fromAddress=reference.getFromAddress();
              Function callee= GlobalState.flatAPI.getFunctionAt(toAddress);
              Function caller=GlobalState.flatAPI.getFunctionContaining(fromAddress);
              if(callee==null || caller==null){
                  continue;
              }
              //Logging.info(fromAddress + " -> " + toAddress + " " + callee.getName());
              for (Context context:Context.getContext(caller)){
                  AbsEnv absEnv = context.getAbsEnvIn().get(fromAddress);
                  if(absEnv==null){
                      continue;
                  }
                  hasWarning |=checkFunctionParameters(absEnv,callee,fromAddress,context);
              }
          }
      }catch (Exception exception){
          exception.printStackTrace();
      }
        return hasWarning;
    }
}
