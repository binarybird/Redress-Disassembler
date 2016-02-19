package redress.abi.elf;


import redress.abi.generic.ABI;
import redress.abi.generic.ABIArch;
import redress.memory.DataStructure;
import redress.memory.address.Address;
import redress.memory.data.CompiledText;
import redress.memory.data.DWord;

import java.nio.ByteOrder;
import java.util.LinkedList;

/**
 * Created by jamesrichardson on 2/10/16.
 */
public abstract class ELF implements ABI {
    public static final DWord ELF_ID_32 = new DWord("0x00000000", ByteOrder.BIG_ENDIAN);
    public static final DWord ELF_DI_32 = new DWord("0x00000000", ByteOrder.BIG_ENDIAN);
    public static final DWord ELF_ID_64 = new DWord("0x00000000", ByteOrder.BIG_ENDIAN);
    public static final DWord ELF_DI_64 = new DWord("0x00000000", ByteOrder.BIG_ENDIAN);

    protected final byte[] raw;
    protected final LinkedList<DataStructure> dataStructures = new LinkedList<>();
    protected final LinkedList<CompiledText> compiledCodeBlocks = new LinkedList<>();
    protected Address beginAddress;
    protected Address endAddress;
    protected String comment;

    public ELF(byte[] binary) {
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
