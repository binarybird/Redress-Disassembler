package abi.mach;

import abi.generic.abi.*;
import abi.generic.memory.data.Data;

import java.util.ArrayList;

/**
 * Created by jamesrichardson on 2/10/16.
 */
public class MachO32 extends Mach {

    private static final ABIType ABI_TYPE = ABIType.MACH_32;

    public MachO32(byte[] in){
        super(in);
    }

    @Override
    public ABIType getArch() {
        return ABI_TYPE;
    }

    @Override
    public byte[] getRaw() {
        return new byte[0];
    }
}
