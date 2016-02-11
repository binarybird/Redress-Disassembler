package abi.mach.parse.x86_64;


import abi.generic.memory.Address32;
import abi.generic.memory.DWord;
import abi.mach.MachO64;
import util.B;

import java.nio.ByteOrder;

/**
 * Created by jamesrichardson on 2/10/16.
 */
public class ParseCommand64{

    private ParseCommand64(){}

    public static void parse(MachO64 in){

        final DWord dWordAtAddress = B.getDWordAtAddress(in.getRaw(), new Address32("0x00000020"), ByteOrder.LITTLE_ENDIAN);

    }
}
