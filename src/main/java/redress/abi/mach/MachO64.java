package redress.abi.mach;

import redress.abi.generic.IContainer;
import redress.abi.generic.enums.ABIArch;
import redress.abi.generic.enums.ABIType;

import java.util.LinkedList;

/**
 * Created by jamesrichardson on 2/10/16.
 */
public class MachO64 extends Mach{

    public MachO64(byte[] raw) {
        super(raw);
    }

    @Override
    public ABIType getType() {
        return ABIType.MACH_64;
    }

    @Override
    public ABIArch getArch() {
        return ABIArch.X86;
    }

    @Override
    public LinkedList<IContainer> getStructureData() {
        return null;
    }
}
