package redress.abi.mach;

import redress.abi.generic.IContainer;
import redress.abi.generic.enums.ABIArch;
import redress.abi.generic.enums.ABIType;

import java.util.LinkedList;

/**
 * Created by jamesrichardson on 2/10/16.
 */
public class MachO32 extends Mach {

    public MachO32(byte[] raw) {
        super(raw);
    }

    @Override
    public ABIType getType() {
        return null;
    }

    @Override
    public ABIArch getArch() {
        return null;
    }

    @Override
    public LinkedList<IContainer> getStructureData() {
        return null;
    }
}
