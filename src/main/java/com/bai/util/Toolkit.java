package com.bai.util;

import ghidra.program.model.listing.Function;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.List;
import java.util.Set;

public class Toolkit {

    public boolean SaveStringArrayToFile(String[] inStringArray,String outFilePath){
        try(PrintWriter writer=new PrintWriter(outFilePath,"UTF-8")){
            for (String line:inStringArray){
                writer.println(line);
            }
            return true;
        }catch (IOException e){
            System.out.println("An error occurred while writing to the file.");
            e.printStackTrace();
            return false;
        }
    }

    public void SaveFuncInfoSetToFile(Set<FuncInfo> inFuncInfoSet, String outFilePath) {
        try (PrintWriter writer = new PrintWriter(outFilePath, "UTF-8")) {
            for (FuncInfo tmpfuncInfo : inFuncInfoSet) {
                List<String> tmp = tmpfuncInfo.serialize();
                for (String line : tmp) {
                    writer.println(line);
                }
            }
        } catch (IOException e) {
            System.out.println("An error occurred while writing to the file.");
            e.printStackTrace();
        }
    }

}
