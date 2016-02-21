package redress.abi.elf;

import redress.abi.generic.ABIType;
import redress.memory.data.Data;

import java.util.LinkedList;

/**
 * Created by jamesrichardson on 2/10/16.
 */
public class ELF32 extends ELF {

    private static final ABIType ABI_TYPE = ABIType.ELF_32;

    public ELF32(byte[] in){
        super(in);
    }

    @Override
    public ABIType getType() {
        return ABI_TYPE;
    }

    @Override
    public LinkedList<Data> buildDecompile() {
        return null;
    }

    @Override
    public byte[] getRaw() {
        return raw;
    }
}
