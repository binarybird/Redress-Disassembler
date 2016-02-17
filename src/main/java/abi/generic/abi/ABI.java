package abi.generic.abi;

import abi.generic.memory.data.Data;

import java.util.ArrayList;

/**
 * Created by jamesrichardson on 2/10/16.
 */
public interface ABI {
    public ArrayList<Data> getProcessedData();
    public ABIType getArch();
    public ArrayList<DataStructure> getDataStructures();
    public byte[] getRaw();
}
