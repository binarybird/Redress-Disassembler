package abi.pe;


import abi.generic.ABI;
import abi.memory.DataStructure;
import abi.memory.address.Address;
import abi.memory.data.CompiledText;
import abi.memory.data.DWord;
import abi.memory.data.Data;
import abi.memory.data.DataRange;

import java.nio.ByteOrder;
import java.util.LinkedList;

/**
 * Created by jamesrichardson on 2/10/16.
 */
public abstract class PE implements ABI {
    public static final DWord PE_ID_32 = new DWord("0x00000000", ByteOrder.BIG_ENDIAN);
    public static final DWord PE_DI_32 = new DWord("0x00000000", ByteOrder.BIG_ENDIAN);
    public static final DWord PE_ID_64 = new DWord("0x00000000", ByteOrder.BIG_ENDIAN);
    public static final DWord PE_DI_64 = new DWord("0x00000000", ByteOrder.BIG_ENDIAN);

    protected final byte[] raw;
    protected final LinkedList<DataStructure> dataStructures = new LinkedList<>();
    protected final LinkedList<CompiledText> compiledCodeBlocks = new LinkedList<>();
    protected Address beginAddress;
    protected Address endAddress;
    protected String comment;

    public PE(byte[] binary) {
        this.raw=binary;
    }

    @Override
    public LinkedList<CompiledText> getCompiledCodeBlocks() {
        return compiledCodeBlocks;
    }

    @Override
    public LinkedList<DataStructure> getChildren() {
        return dataStructures;
    }

    @Override
    public Address getBeginAddress() {
        return beginAddress;
    }

    @Override
    public Address getEndAddress() {
        return endAddress;
    }

    @Override
    public void setComment(String comment) {
        this.comment = comment;
    }

    @Override
    public String getComment() {
        return comment;
    }
}
