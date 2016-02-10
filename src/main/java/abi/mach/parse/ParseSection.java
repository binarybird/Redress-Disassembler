package abi.mach.parse;

import abi.generic.ABI;
import abi.generic.Arch;
import abi.generic.Parser;

/**
 * Created by jamesrichardson on 2/10/16.
 */
public class ParseSection extends Parser {

    public ParseSection(ABI in) {
        super(in);

        if (in.getArch() == Arch.SIXTYFOUR) {
            parse64Section();
        } else if (in.getArch() == Arch.THIRTYTWO) {
            parse32Section();
        }
    }

    private void parse32Section(){

    }

    private void parse64Section(){

    }

    @Override
    public ABI getModel() {
        return model;
    }
}
