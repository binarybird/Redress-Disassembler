package redress.abi.mach;

import redress.abi.generic.ABIType;

/**
 * Created by jamesrichardson on 2/10/16.
 */
public class MachO32 extends Mach {

    private static final ABIType ABI_TYPE = ABIType.MACH_32;

    public MachO32(byte[] in){
        super(in);
    }

    @Override
    public ABIType getType() {
        return ABI_TYPE;
    }

    @Override
    public byte[] getRaw() {
        return new byte[0];
    }
}