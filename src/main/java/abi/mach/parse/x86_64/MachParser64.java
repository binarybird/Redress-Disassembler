package abi.mach.parse.x86_64;

import abi.mach.MachO64;

import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Created by jamesrichardson on 2/10/16.
 */
public class MachParser64{
    private final static Logger LOGGER = Logger.getLogger(MachParser64.class.getName());


    private MachParser64(){
    }

    public static void parse(MachO64 model) throws Exception{
        LOGGER.log(Level.INFO,"Parsing header");
        ParseHeader64.parse(model);
        LOGGER.log(Level.INFO,"Parsing load commands");
        ParseCommand64.parse(model);

        System.out.println();
    }

}
