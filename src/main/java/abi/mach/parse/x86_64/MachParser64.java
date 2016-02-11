package abi.mach.parse.x86_64;

import abi.mach.MachO64;

import java.io.IOException;

/**
 * Created by jamesrichardson on 2/10/16.
 */
public class MachParser64{

    private MachParser64(){
    }


    public static void parse(MachO64 model) {
        ParseHeader64.parse(model);
        ParseCommand64.parse(model);

        System.out.println();
    }


}
