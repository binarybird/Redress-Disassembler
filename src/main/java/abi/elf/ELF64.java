package abi.elf;

import abi.generic.ABIType;

/**
 * Created by jamesrichardson on 2/10/16.
 */
public class ELF64 extends ELF {

    private static final ABIType ABI_TYPE = ABIType.ELF_64;

    public ELF64(byte[] binary) {
        super(binary);
    }

    @Override
    public ABIType getType() {
        return ABI_TYPE;
    }

    @Override
    public byte[] getRaw() {
        return raw;
    }

}
