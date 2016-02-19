package abi.mach;


import abi.generic.ABI;
import abi.generic.ABIArch;
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
public abstract class Mach implements ABI {
    public static final DWord MACH_ID_32 = new DWord("0xfeedface", ByteOrder.BIG_ENDIAN);
    public static final DWord MACH_DI_32 = new DWord("0xcefaedfe", ByteOrder.BIG_ENDIAN);
    public static final DWord MACH_ID_64 = new DWord("0xfeedfacf", ByteOrder.BIG_ENDIAN);
    public static final DWord MACH_DI_64 = new DWord("0xcffaedfe", ByteOrder.BIG_ENDIAN);

    protected final byte[] raw;
    protected final LinkedList<DataStructure> dataStructures = new LinkedList<>();
    protected final LinkedList<CompiledText> compiledCodeBlocks = new LinkedList<>();
    protected Address beginAddress;
    protected Address endAddress;
    protected String comment;

    public Mach(byte[] binary) {
        this.raw=binary;
    }

    @Override
    public ABIArch getArch() {
        return ABIArch.X86;//todo
    }

    @Override
    public LinkedList<DataStructure> getChildren() {
        return dataStructures;
    }

    @Override
    public LinkedList<CompiledText> getCompiledTextBlocks() {
        return compiledCodeBlocks;
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
