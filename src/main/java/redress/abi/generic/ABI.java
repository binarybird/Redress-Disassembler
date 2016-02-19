package redress.abi.generic;

import redress.memory.Addressable;
import redress.memory.DataStructure;
import redress.memory.data.CompiledText;

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
