package com.bai.util;

import java.util.ArrayList;
import java.util.List;

public class FuncInfo {
    public String funcName;
    public int basicBlockNum;

    public int paramNum;
    public int xrefNum;
    public boolean memcpyLike;

    public List<String> serialize(){
        List<String> out=new ArrayList<>();
        out.add("name:"+funcName);
        out.add("basicBlockNum: "+basicBlockNum);
        out.add("paramNum: "+paramNum);
        out.add("xrefNum: "+xrefNum);
        out.add("memcpyLike: "+memcpyLike);
        out.add("++++++++++++++++++++++++");
        return out;
    }

}
