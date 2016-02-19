package abi.mach.parse.x86_64;

import abi.memory.address.Address32;
import abi.memory.address.Address64;
import abi.mach.Loader;
import abi.mach.MachO64;
import util.B;

import java.nio.ByteOrder;

/**
 * Created by jamesrichardson on 2/10/16.
 */
public class ParseHeader64 {

    private ParseHeader64() {
    }

    public static void parse(MachO64 model){

        try {
            Loader.mach_header_64 mach_header_64 = new Loader.mach_header_64(model);

            mach_header_64.setBeginAddress(new Address64("0x0000000000000000"));
            mach_header_64.setEndAddress(new Address64("0x0000000000000020"));

            mach_header_64.magic = B.getDWordAtAddress(model.getRaw(),mach_header_64.getBeginAddress(),ByteOrder.LITTLE_ENDIAN);
            mach_header_64.cputype = B.getDWordAtAddress(model.getRaw(),new Address32("0x00000004"),ByteOrder.LITTLE_ENDIAN);
            mach_header_64.cpusubtype = B.getDWordAtAddress(model.getRaw(), new Address32("0x00000008"),ByteOrder.LITTLE_ENDIAN);
            mach_header_64.filetype = B.getDWordAtAddress(model.getRaw(), new Address32("0x0000000C"),ByteOrder.LITTLE_ENDIAN);
            mach_header_64.ncmds = B.getDWordAtAddress(model.getRaw(), new Address32("0x00000010"),ByteOrder.LITTLE_ENDIAN);
            mach_header_64.sizeofcmds = B.getDWordAtAddress(model.getRaw(), new Address32("0x00000014"),ByteOrder.LITTLE_ENDIAN);
            mach_header_64.flags = B.getDWordAtAddress(model.getRaw(), new Address32("0x00000018"),ByteOrder.LITTLE_ENDIAN);
            mach_header_64.reserved = B.getDWordAtAddress(model.getRaw(), new Address32("0x0000001C"),ByteOrder.LITTLE_ENDIAN);
            mach_header_64.setComment("MACH_HEADER_64");

            model.getChildren().add(mach_header_64);

        }catch(Exception e){
            e.printStackTrace();
        }

    }

}
