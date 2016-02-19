package abi.generic;

import abi.memory.Addressable;
import abi.memory.DataStructure;
import abi.memory.data.CompiledText;
import abi.memory.data.Data;
import abi.memory.data.DataRange;

import java.util.LinkedList;

/**
 * Created by jamesrichardson on 2/10/16.
 */
public interface ABI extends Addressable{
    public ABIType getType();
    public ABIArch getArch();
    public LinkedList<DataStructure> getChildren();
    public LinkedList<CompiledText> getCompiledTextBlocks();
    public byte[] getRaw();
}
