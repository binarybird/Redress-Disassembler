package abi.mach.parse;

import abi.generic.ABI;
import abi.generic.Parser;
import abi.mach.Mach;
import abi.mach.MachO64;

import java.io.File;
import java.io.IOException;

/**
 * Created by jamesrichardson on 2/10/16.
 */
public class MachParser64 extends Parser<MachO64>{

    public MachParser64(MachO64 model) throws IOException{
        super(model);
        parse();
    }

    private void parse(){
        ParseHeader parseHeader = new ParseHeader(model);
        ParseCommand parsecommand = new ParseCommand(parseHeader.getModel());
    }

    @Override
    public MachO64 getModel() {
        return null;
    }
}
