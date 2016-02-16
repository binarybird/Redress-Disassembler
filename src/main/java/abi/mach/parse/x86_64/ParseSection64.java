package abi.mach.parse.x86_64;

import abi.generic.abi.Command;
import abi.generic.memory.address.Address32;
import abi.mach.Loader;
import abi.mach.MachO64;
import util.B;

import java.nio.ByteOrder;

/**
 * Created by jamesrichardson on 2/10/16.
 */
public class ParseSection64{

    private ParseSection64() {}

    public static Loader.section_64 parse(MachO64 in,Address32 pointer,Command parent){
//        pointer.add(new Word("0x0050", ByteOrder.BIG_ENDIAN));
        Loader.section_64 section_64 = new Loader.section_64();
        section_64.setParentCommand(parent);

        section_64.setBeginAddress(pointer.clone());
        final byte[] container = B.getQWordAtAddressAndIncrement(in.getRaw(), pointer, ByteOrder.LITTLE_ENDIAN).getContainer();
        final byte[] container2 = B.getQWordAtAddressAndIncrement(in.getRaw(), pointer, ByteOrder.LITTLE_ENDIAN).getContainer();
        section_64.sectname = new Loader.char16(B.mergeBytes(container, container2));
        final byte[] container3 = B.getQWordAtAddressAndIncrement(in.getRaw(), pointer, ByteOrder.LITTLE_ENDIAN).getContainer();
        final byte[] container4 = B.getQWordAtAddressAndIncrement(in.getRaw(), pointer, ByteOrder.LITTLE_ENDIAN).getContainer();
        section_64.segname = new Loader.char16(B.mergeBytes(container3, container4));
        section_64.addr = B.getQWordAtAddressAndIncrement(in.getRaw(), pointer, ByteOrder.LITTLE_ENDIAN);
        section_64.size = B.getQWordAtAddressAndIncrement(in.getRaw(), pointer, ByteOrder.LITTLE_ENDIAN);
        section_64.offset = B.getDWordAtAddressAndIncrement(in.getRaw(), pointer, ByteOrder.LITTLE_ENDIAN);
        section_64.align = B.getDWordAtAddressAndIncrement(in.getRaw(), pointer, ByteOrder.LITTLE_ENDIAN);
        section_64.reloff = B.getDWordAtAddressAndIncrement(in.getRaw(), pointer, ByteOrder.LITTLE_ENDIAN);
        section_64.nreloc = B.getDWordAtAddressAndIncrement(in.getRaw(), pointer, ByteOrder.LITTLE_ENDIAN);
        section_64.flags = B.getDWordAtAddressAndIncrement(in.getRaw(), pointer, ByteOrder.LITTLE_ENDIAN);
        section_64.reserved1=B.getDWordAtAddressAndIncrement(in.getRaw(), pointer, ByteOrder.LITTLE_ENDIAN);
        section_64.reserved2=B.getDWordAtAddressAndIncrement(in.getRaw(), pointer, ByteOrder.LITTLE_ENDIAN);
        section_64.reserved3=B.getDWordAtAddressAndIncrement(in.getRaw(), pointer, ByteOrder.LITTLE_ENDIAN);
        section_64.setEndAddress(pointer.clone());

        return section_64;
    }

}
