package redress.abi.mach.parse.x86_64;

import redress.abi.generic.IContainer;
import redress.memory.data.view.Color;
import redress.memory.data.view.TableSeperator;
import redress.memory.address.Address64;
import redress.memory.data.AbstractData;
import redress.abi.generic.IStructure;
import redress.memory.address.Address32;
import redress.abi.mach.Loader;
import redress.abi.mach.MachO64;
import redress.memory.data.Range;
import redress.util.B;
import redress.util.T;

import java.nio.ByteOrder;
import java.util.LinkedList;

/**
 * Created by jamesrichardson on 2/10/16.
 */
public class ParseSegSec64 {

    private ParseSegSec64() {}

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




        boolean strings = false;
        String flags = "";

        if(section_64.sectname.value.contains("__cfstring")){
            setAlignedStringLoader(in, section_64,8);
            strings=true;
        }

        if(Loader.SECTION_TYPE.and(section_64.flags)) {
            flags+="SECTION_TYPE, ";
        } if(Loader.SECTION_ATTRIBUTES.and(section_64.flags)){
            flags+="SECTION_ATTRIBUTES, ";
        } if(Loader.S_REGULAR.and(section_64.flags)){
            flags+="S_REGULAR, ";
        } if(Loader.S_ZEROFILL.and(section_64.flags)){
            flags+="S_ZEROFILL, ";
        } if(Loader.S_CSTRING_LITERALS.and(section_64.flags)){
            flags+="S_CSTRING_LITERALS, ";
            setCStringLoader(in, section_64);
            strings=true;
        } if(Loader.S_4BYTE_LITERALS.and(section_64.flags)){
            flags+="S_4BYTE_LITERALS, ";
            setAlignedStringLoader(in,section_64,4);
            strings=true;
        } if(Loader.S_8BYTE_LITERALS.and(section_64.flags)){
            flags+="S_8BYTE_LITERALS, ";
            setAlignedStringLoader(in,section_64,8);
            strings=true;
        } if(Loader.S_LITERAL_POINTERS.and(section_64.flags)){
            flags+="S_LITERAL_POINTERS, ";
            setCStringLoader(in, section_64);
            strings=true;
        } if(Loader.S_NON_LAZY_SYMBOL_POINTERS.and(section_64.flags)){
            flags+="S_NON_LAZY_SYMBOL_POINTERS, ";
        } if(Loader.S_LAZY_SYMBOL_POINTERS.and(section_64.flags)){
            flags+="S_LAZY_SYMBOL_POINTERS, ";
        } if(Loader.S_SYMBOL_STUBS.and(section_64.flags)){
            flags+="S_SYMBOL_STUBS, ";
        } if(Loader.S_MOD_INIT_FUNC_POINTERS.and(section_64.flags)){
            flags+="S_MOD_INIT_FUNC_POINTERS, ";
        } if(Loader.S_MOD_TERM_FUNC_POINTERS.and(section_64.flags)){
            flags+="S_MOD_TERM_FUNC_POINTERS, ";
        } if(Loader.S_COALESCED.and(section_64.flags)){
            flags+="S_COALESCED, ";
        } if(Loader.S_GB_ZEROFILL.and(section_64.flags)){
            flags+="S_GB_ZEROFILL, ";
        } if(Loader.S_INTERPOSING.and(section_64.flags)){
            flags+="S_INTERPOSING, ";
        } if(Loader.S_16BYTE_LITERALS.and(section_64.flags)){
            flags+="S_16BYTE_LITERALS, ";
        } if(Loader.S_DTRACE_DOF.and(section_64.flags)){
            flags+="S_DTRACE_DOF, ";
        } if(Loader.S_LAZY_DYLIB_SYMBOL_POINTERS.and(section_64.flags)){
            flags+="S_LAZY_DYLIB_SYMBOL_POINTERS, ";
        } if(Loader.SECTION_ATTRIBUTES_USR.and(section_64.flags)){
            flags+="SECTION_ATTRIBUTES_USR, ";
        } if(Loader.S_ATTR_PURE_INSTRUCTIONS.and(section_64.flags)){
            flags+="S_ATTR_PURE_INSTRUCTIONS, ";
        } if(Loader.S_ATTR_NO_TOC.and(section_64.flags)){
            flags+="S_ATTR_NO_TOC, ";
        } if(Loader.S_ATTR_STRIP_STATIC_SYMS.and(section_64.flags)){
            flags+="S_ATTR_STRIP_STATIC_SYMS, ";
        } if(Loader.S_ATTR_NO_DEAD_STRIP.and(section_64.flags)){
            flags+="S_ATTR_NO_DEAD_STRIP, ";
        } if(Loader.S_ATTR_LIVE_SUPPORT.and(section_64.flags)){
            flags+="S_ATTR_LIVE_SUPPORT, ";
        } if(Loader.S_ATTR_SELF_MODIFYING_CODE.and(section_64.flags)){
            flags+="S_ATTR_SELF_MODIFYING_CODE, ";
        } if(Loader.S_THREAD_LOCAL_REGULAR.and(section_64.flags)){
            flags+="S_THREAD_LOCAL_REGULAR, ";
        } if(Loader.S_THREAD_LOCAL_ZEROFILL.and(section_64.flags)){
            flags+="S_THREAD_LOCAL_ZEROFILL, ";
        } if(Loader.S_THREAD_LOCAL_VARIABLES.and(section_64.flags)){
            flags+="S_THREAD_LOCAL_VARIABLES, ";
        } if(Loader.S_THREAD_LOCAL_VARIABLE_POINTERS.and(section_64.flags)){
            flags+="S_THREAD_LOCAL_VARIABLE_POINTERS, ";
        } if(Loader.S_THREAD_LOCAL_INIT_FUNCTION_POINTERS.and(section_64.flags)){
            flags+="S_THREAD_LOCAL_INIT_FUNCTION_POINTERS, ";
        } if(Loader.S_ATTR_DEBUG.and(section_64.flags)){
            flags+="S_ATTR_DEBUG, ";
        } if(Loader.SECTION_ATTRIBUTES_SYS.and(section_64.flags)){
            flags+="SECTION_ATTRIBUTES_SYS, ";
        } if(Loader.S_ATTR_SOME_INSTRUCTIONS.and(section_64.flags)){
            flags+="S_ATTR_SOME_INSTRUCTIONS, ";
        } if(Loader.S_ATTR_EXT_RELOC.and(section_64.flags)){
            flags+="S_ATTR_EXT_RELOC, ";
        } if(Loader.S_ATTR_LOC_RELOC.and(section_64.flags)) {
            flags+="S_ATTR_LOC_RELOC, ";
        } if(flags.equals("")){
            flags="NONE";
        }


        section_64.addComments("Section Name: " + section_64.sectname.value + " Segment Name: " + section_64.segname.value + " Type: " + flags);
        section_64.flags.addComments("Flags: "+flags);

        //TODO - parse sections based on section type
        //TODO - Right now every section is treated as compiled text

        if(!strings){
            setDecompileLoader(in, section_64);
        }

        return section_64;
    }

    private static void setAlignedStringLoader(MachO64 in, Loader.section_64 section_64,int align) {
        section_64.setLoader(abi->{
            final LinkedList<IContainer> ret = new LinkedList<>();
            final Address64 begin64 = B.qWordToAddr64(section_64.addr);
            final Address64 end64 = (Address64)B.qWordToAddr64(section_64.size);
            end64.add(begin64);
            begin64.subtract(new Address64("0x0000000100000000"));
            end64.subtract(new Address64("0x0000000100000000"));

            final int length = end64.getIntValue() - begin64.getIntValue();

            Range range = B.getRangeAtAddress(in.getRaw(),section_64,begin64,end64, ByteOrder.LITTLE_ENDIAN);

            ret.add(new TableSeperator("Seg: "+section_64.segname.value,"Sec: "+section_64.sectname.value,"Procedure Start, Length: " + length + " bytes","",Color.rgba(255,28,0,0.43)));
            ret.addAll(T.deCompileStringsAligned(align,range, in));
            ret.add(new TableSeperator("","","Procedure End, Length: " + length + " bytes","", Color.rgba(255,28,0,0.43)));

            return ret;
        });
    }

    private static void setCStringLoader(MachO64 in, Loader.section_64 section_64) {
        section_64.setLoader(abi->{
            final LinkedList<IContainer> ret = new LinkedList<>();
            final Address64 begin64 = B.qWordToAddr64(section_64.addr);
            final Address64 end64 = (Address64)B.qWordToAddr64(section_64.size);
            end64.add(begin64);
            begin64.subtract(new Address64("0x0000000100000000"));
            end64.subtract(new Address64("0x0000000100000000"));

            final int length = end64.getIntValue() - begin64.getIntValue();

            Range range = B.getRangeAtAddress(in.getRaw(),section_64,begin64,end64, ByteOrder.LITTLE_ENDIAN);

            ret.add(new TableSeperator("Seg: "+section_64.segname.value,"Sec: "+section_64.sectname.value,"Procedure Start, Length: " + length + " bytes","",Color.rgba(255,28,0,0.43)));
            ret.addAll(T.deCompileCStrings(range, in));
            ret.add(new TableSeperator("","","Procedure End, Length: " + length + " bytes","",Color.rgba(255,28,0,0.43)));

            return ret;
        });
    }

    private static void setDecompileLoader(MachO64 in, Loader.section_64 section_64) {
        section_64.setLoader(abi->{
            final LinkedList<IContainer> ret = new LinkedList<>();
            final Address64 begin64 = B.qWordToAddr64(section_64.addr);
            final Address64 end64 = (Address64)B.qWordToAddr64(section_64.size);
            end64.add(begin64);
            begin64.subtract(new Address64("0x0000000100000000"));
            end64.subtract(new Address64("0x0000000100000000"));

            final int length = end64.getIntValue() - begin64.getIntValue();

            Range range = B.getRangeAtAddress(in.getRaw(),section_64,begin64,end64, ByteOrder.LITTLE_ENDIAN);

            ret.add(new TableSeperator("Seg: "+section_64.segname.value,"Sec: "+section_64.sectname.value,"Procedure Start, Length: " + length + " bytes","",Color.rgba(255,28,0,0.43)));
            ret.addAll(T.deCompileText(range, in));
            ret.add(new TableSeperator("","","Procedure End, Length: " + length + " bytes","",Color.rgba(255,28,0,0.43)));

            return ret;
        });
    }


}
