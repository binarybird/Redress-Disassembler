package abi.pe;

import abi.generic.ABIType;
import abi.memory.data.DataRange;

import java.util.LinkedList;

/**
 * Created by jamesrichardson on 2/10/16.
 */
public class PE32 extends PE {

    private static final ABIType ABI_TYPE = ABIType.PE_32;

    public PE32(byte[] in){
        super(in);
    }

    @Override
    public ABIType getArch() {
        return ABI_TYPE;
    }

    @Override
    public byte[] getRaw() {
        return raw;
    }
}
