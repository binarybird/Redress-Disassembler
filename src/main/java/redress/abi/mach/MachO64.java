package redress.abi.mach;

import redress.abi.generic.ABI;
import redress.abi.generic.ABIType;
import redress.memory.struct.DataStructure;
import redress.memory.data.Data;

import java.util.LinkedList;

/**
 * Created by jamesrichardson on 2/10/16.
 */
public class MachO64 extends Mach{

    private static final ABIType ABI_TYPE = ABIType.MACH_64;

    public MachO64(byte[] binary) {
        super(binary);
    }

    @Override
    public ABIType getType() {
        return ABI_TYPE;
    }

    @Override
    public LinkedList<Data> buildDecompile() {
        return getAllData();
    }

    @Override
    public byte[] getRaw() {
        return raw;
    }

}
