package abi.mach.parse;

import abi.generic.ABI;
import abi.generic.Arch;
import abi.generic.Parser;

/**
 * Created by jamesrichardson on 2/10/16.
 */
public class ParseSegment extends Parser {

    public ParseSegment(ABI in) {
        super(in);

        if (in.getArch() == Arch.SIXTYFOUR) {
            parse64Segment();
        } else if (in.getArch() == Arch.THIRTYTWO) {
            parse32Segment();
        }
    }

    private void parse32Segment(){

    }

    private void parse64Segment(){

    }

    @Override
    public ABI getModel() {
        return model;
    }
}
