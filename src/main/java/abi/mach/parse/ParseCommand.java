package abi.mach.parse;

import abi.generic.ABI;
import abi.generic.Arch;
import abi.generic.Parser;

/**
 * Created by jamesrichardson on 2/10/16.
 */
public class ParseCommand extends Parser {

    public ParseCommand(ABI in){
        super(in);
        if(in.getArch() == Arch.SIXTYFOUR){
            parse64Command();
        }else if(in.getArch() == Arch.THIRTYTWO){
            parse32Command();
        }
    }

    private void parse32Command(){

    }

    private void parse64Command(){

    }

    @Override
    public ABI getModel() {
        return null;
    }
}
