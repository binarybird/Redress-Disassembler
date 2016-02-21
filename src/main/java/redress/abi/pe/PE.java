package redress.abi.pe;


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
public abstract class PE implements ABI {
    public static final DWord PE_ID_32 = new DWord("0x00000000", Data.Type.DATA_BYTE, ByteOrder.BIG_ENDIAN);
    public static final DWord PE_DI_32 = new DWord("0x00000000", Data.Type.DATA_BYTE,ByteOrder.BIG_ENDIAN);
    public static final DWord PE_ID_64 = new DWord("0x00000000", Data.Type.DATA_BYTE,ByteOrder.BIG_ENDIAN);
    public static final DWord PE_DI_64 = new DWord("0x00000000", Data.Type.DATA_BYTE,ByteOrder.BIG_ENDIAN);

    protected final byte[] raw;
    protected final LinkedList<DataStructure> dataStructures = new LinkedList<>();
    protected Address beginAddress;
    protected Address endAddress;
    protected String comment;

    public PE(byte[] binary) {
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
