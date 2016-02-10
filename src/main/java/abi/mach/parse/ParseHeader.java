package abi.mach.parse;

import abi.generic.ABI;
import abi.generic.Arch;
import abi.generic.Parser;
import abi.mach.Mach;

/**
 * Created by jamesrichardson on 2/10/16.
 */
public class ParseHeader extends Parser {

    public ParseHeader(ABI in) {
        super(in);

        if (in.getArch() == Arch.SIXTYFOUR) {
            parse64Header();
        } else if (in.getArch() == Arch.THIRTYTWO) {
            parse32Header();
        }
    }

    private void parse32Header(){

    }

    private void parse64Header(){

    }

    @Override
    public ABI getModel() {
        return model;
    }
}
