package abi.mach.parse;

import abi.generic.ABI;
import abi.generic.Parser;
import abi.mach.MachO32;
import abi.mach.MachO64;

import java.io.IOException;

/**
 * Created by jamesrichardson on 2/10/16.
 */
public class MachParser32 extends Parser<MachO32> {

    public MachParser32(MachO32 model) throws IOException {
        super(model);
    }

    @Override
    public MachO32 getModel() {
        return model;
    }
}
