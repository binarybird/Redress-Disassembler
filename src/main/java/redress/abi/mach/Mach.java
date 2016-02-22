package redress.abi.mach;


import redress.abi.generic.ABI;
import redress.abi.generic.ABIArch;
import redress.memory.struct.DataStructure;
import redress.memory.address.Address;
import redress.memory.data.DWord;
import redress.memory.data.Data;

import java.nio.ByteOrder;
import java.util.LinkedList;

/**
 * Created by jamesrichardson on 2/10/16.
 */
public abstract class Mach extends ABI {
    public static final DWord MACH_ID_32 = new DWord("0xfeedface", Data.Type.DATA_BYTE,ByteOrder.BIG_ENDIAN);
    public static final DWord MACH_DI_32 = new DWord("0xcefaedfe", Data.Type.DATA_BYTE,ByteOrder.BIG_ENDIAN);
    public static final DWord MACH_ID_64 = new DWord("0xfeedfacf", Data.Type.DATA_BYTE,ByteOrder.BIG_ENDIAN);
    public static final DWord MACH_DI_64 = new DWord("0xcffaedfe", Data.Type.DATA_BYTE,ByteOrder.BIG_ENDIAN);

    protected final byte[] raw;
    protected final LinkedList<DataStructure> dataStructures = new LinkedList<>();

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
