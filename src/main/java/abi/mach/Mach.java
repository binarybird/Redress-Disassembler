package abi.mach;


import abi.generic.abi.ABI;
import abi.generic.abi.DataStructure;
import abi.generic.memory.data.Data;

import java.util.ArrayList;
import java.util.LinkedList;

/**
 * Created by jamesrichardson on 2/10/16.
 */
public abstract class Mach implements ABI {
    protected final byte[] raw;
    protected final ArrayList<DataStructure> dataStructures = new ArrayList<>();

    public Mach(byte[] binary) {
        this.raw=binary;
    }

    @Override
    public ArrayList<DataStructure> getDataStructures() {
        return dataStructures;
    }

    @Override
    public ArrayList<Data> getProcessedData() {
        ArrayList<Data> ret = new ArrayList<>();
        dataStructures.forEach(e-> ret.addAll(e.getStructureData()));
        return ret;
    }
}
