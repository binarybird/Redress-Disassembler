package abi.mach.parse.x86_64;


import abi.generic.abi.Command;
import abi.generic.memory.Address32;
import abi.generic.memory.DWord;
import abi.mach.Loader;
import abi.mach.MachO64;
import util.B;

import java.nio.ByteOrder;

/**
 * Created by jamesrichardson on 2/10/16.
 */
public class ParseCommand64{

    private ParseCommand64(){}

    private byte[] pointer;

    public static void parse(MachO64 in){

        final DWord numberOfCommands = new DWord(in.getHeader().ncmds,ByteOrder.LITTLE_ENDIAN);
        final DWord sizeOfCommands = new DWord(in.getHeader().sizeofcmds,ByteOrder.LITTLE_ENDIAN);

        Address32 pointer = new Address32("0x00000020");

        final DWord firstCommand = B.getDWordAtAddress(in.getRaw(), new Address32("0x00000020"), ByteOrder.LITTLE_ENDIAN);

        boolean finished = false;
        while(!finished) {
            if(sizeOfCommands.equals(sizeOfCommands))
                finished = true;
            pointer.increment(0x04);
            switch (firstCommand.getLeastSignificantByte()) {
                case Loader.LC_SEGMENT:
                    Loader.segment_command_64 segment_command_64 = new Loader.segment_command_64();
                    segment_command_64.setBeginAddress(pointer);

                    in.getCommands().add(segment_command_64);
                    break;
                case Loader.LC_SYMTAB:
                    Loader.symtab_command symtab_command = new Loader.symtab_command();
                    symtab_command.setBeginAddress(pointer);

                    in.getCommands().add(symtab_command);
                    break;
                case Loader.LC_SYMSEG:
                    Loader.symseg_command symseg_command = new Loader.symseg_command();
                    symseg_command.setBeginAddress(pointer);

                    in.getCommands().add(symseg_command);
                    break;
                case Loader.LC_THREAD:
                    Loader.thread_command thread_command = new Loader.thread_command();
                    thread_command.setBeginAddress(pointer);

                    in.getCommands().add(thread_command);
                    break;
                case Loader.LC_UNIXTHREAD:
                    break;
                case Loader.LC_LOADFVMLIB:
                    break;
                case Loader.LC_IDFVMLIB:
                    break;
                case Loader.LC_IDENT:
                    break;
                case Loader.LC_FVMFILE:
                    break;
                case Loader.LC_PREPAGE:
                    break;
                case Loader.LC_DYSYMTAB:
                    break;
                case Loader.LC_LOAD_DYLIB:
                    break;
                case Loader.LC_ID_DYLIB:
                    break;
                case Loader.LC_LOAD_DYLINKER:
                    break;
                case Loader.LC_ID_DYLINKER:
                    break;
                case Loader.LC_PREBOUND_DYLIB:
                    break;
                case Loader.LC_ROUTINES:
                    break;
                case Loader.LC_SUB_FRAMEWORK:
                    break;
                case Loader.LC_SUB_UMBRELLA:
                    break;
                case Loader.LC_SUB_CLIENT:
                    break;
                case Loader.LC_SUB_LIBRARY:
                    break;
                case Loader.LC_TWOLEVEL_HINTS:
                    break;
                case Loader.LC_PREBIND_CKSUM:
                    break;
                case Loader.LC_SEGMENT_64:
                    break;
                case Loader.LC_ROUTINES_64:
                    break;
                case Loader.LC_UUID:
                    break;
                case Loader.LC_CODE_SIGNATURE:
                    break;
                case Loader.LC_SEGMENT_SPLIT_INFO:
                    break;
                case Loader.LC_LAZY_LOAD_DYLIB:
                    break;
                case Loader.LC_ENCRYPTION_INFO:
                    break;
                case Loader.LC_DYLD_INFO:
                    break;
            }
        }
    }


}
