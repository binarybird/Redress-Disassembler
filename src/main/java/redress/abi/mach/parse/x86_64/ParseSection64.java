package redress.abi.mach.parse.x86_64;

import redress.abi.generic.IContainer;
import redress.memory.data.AbstractData;
import redress.abi.generic.IStructure;
import redress.memory.address.Address32;
import redress.abi.mach.Loader;
import redress.abi.mach.MachO64;
import redress.util.B;

import java.nio.ByteOrder;
import java.util.LinkedList;

/**
 * Created by jamesrichardson on 2/10/16.
 */
public class ParseSection64{

    private ParseSection64() {}

    public static Loader.section_64 parse(MachO64 in,Address32 pointer,IStructure parent){
//        pointer.add(new Word("0x0050", ByteOrder.BIG_ENDIAN));
        Loader.section_64 section_64 = new Loader.section_64(parent);

        section_64.setBeginAddress(pointer.clone());
        final byte[] container = B.getQWordAtAddressAndIncrement(in.getRaw(), pointer, section_64,AbstractData.Type.DATA_BYTE,ByteOrder.LITTLE_ENDIAN).getContainer();
        final byte[] container2 = B.getQWordAtAddressAndIncrement(in.getRaw(), pointer, section_64,AbstractData.Type.DATA_BYTE,ByteOrder.LITTLE_ENDIAN).getContainer();
        section_64.sectname = new Loader.char16(B.mergeBytes(container, container2),section_64, AbstractData.Type.DATA_CHAR,ByteOrder.LITTLE_ENDIAN);
        section_64.sectname.setBeginAddress(section_64.getBeginAddress().clone());
        section_64.sectname.setEndAddress(pointer.clone());
        final byte[] container3 = B.getQWordAtAddressAndIncrement(in.getRaw(), pointer, section_64,AbstractData.Type.DATA_BYTE,ByteOrder.LITTLE_ENDIAN).getContainer();
        final byte[] container4 = B.getQWordAtAddressAndIncrement(in.getRaw(), pointer, section_64,AbstractData.Type.DATA_BYTE,ByteOrder.LITTLE_ENDIAN).getContainer();
        section_64.segname = new Loader.char16(B.mergeBytes(container3, container4),section_64, AbstractData.Type.DATA_CHAR,ByteOrder.LITTLE_ENDIAN);
        section_64.segname.setBeginAddress(section_64.getBeginAddress().clone());
        section_64.segname.setEndAddress(pointer.clone());
        section_64.addr = B.getQWordAtAddressAndIncrement(in.getRaw(), pointer, section_64,AbstractData.Type.DATA_BYTE, ByteOrder.LITTLE_ENDIAN);
        section_64.size = B.getQWordAtAddressAndIncrement(in.getRaw(), pointer, section_64,AbstractData.Type.DATA_BYTE,ByteOrder.LITTLE_ENDIAN);
        section_64.offset = B.getDWordAtAddressAndIncrement(in.getRaw(), pointer,section_64, AbstractData.Type.DATA_BYTE, ByteOrder.LITTLE_ENDIAN);
        section_64.align = B.getDWordAtAddressAndIncrement(in.getRaw(), pointer, section_64,AbstractData.Type.DATA_BYTE,ByteOrder.LITTLE_ENDIAN);
        section_64.reloff = B.getDWordAtAddressAndIncrement(in.getRaw(), pointer, section_64,AbstractData.Type.DATA_BYTE, ByteOrder.LITTLE_ENDIAN);
        section_64.nreloc = B.getDWordAtAddressAndIncrement(in.getRaw(), pointer, section_64,AbstractData.Type.DATA_BYTE, ByteOrder.LITTLE_ENDIAN);
        section_64.flags = B.getDWordAtAddressAndIncrement(in.getRaw(), pointer, section_64,AbstractData.Type.DATA_BYTE, ByteOrder.LITTLE_ENDIAN);
        section_64.reserved1=B.getDWordAtAddressAndIncrement(in.getRaw(), pointer, section_64,AbstractData.Type.DATA_BYTE, ByteOrder.LITTLE_ENDIAN);
        section_64.reserved2=B.getDWordAtAddressAndIncrement(in.getRaw(), pointer, section_64,AbstractData.Type.DATA_BYTE, ByteOrder.LITTLE_ENDIAN);
        section_64.reserved3=B.getDWordAtAddressAndIncrement(in.getRaw(), pointer, section_64,AbstractData.Type.DATA_BYTE, ByteOrder.LITTLE_ENDIAN);
        section_64.setEndAddress(pointer.clone());
        section_64.setComments("Section Name: " + section_64.sectname.value + " Segment Name: " + section_64.segname.value);


        section_64.setLoader(abi->{
            final LinkedList<IContainer> loadedContents = new LinkedList<>();
            return loadedContents;
        });
        //TODO - IF SECTION == TEXT
//        final Address64 begin64 = B.qWordToAddr64(section_64.addr);
//        final Address64 end64 = (Address64)B.qWordToAddr64(section_64.size);
//        end64.add(begin64);
//        begin64.subtract(new Address64("0x0000000100000000"));
//        end64.subtract(new Address64("0x0000000100000000"));
//        byte[] range = B.getRangeAtAddress(in.getRaw(),begin64,end64);
        //section_64.getChildren().add(new CompiledText(section_64,range,begin64,end64,in));

        //TODO - IF SECTION == STRING
        //---

        return section_64;
    }

}
