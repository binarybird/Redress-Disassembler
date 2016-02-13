package abi.mach.parse.x86_64;


import abi.generic.memory.*;
import abi.mach.Loader;
import abi.mach.MachO64;
import util.B;

import java.nio.ByteOrder;

/**
 * Created by jamesrichardson on 2/10/16.
 */
public class ParseCommand64 {

    private ParseCommand64() {}

    public static void parse(MachO64 in) {

        final DWord numberOfCommands = in.getHeader().ncmds;
        final DWord sizeOfCommands = in.getHeader().sizeofcmds;
        sizeOfCommands.add(in.getHeader().getEndAddress());

        Address32 pointer = new Address32("0x00000020");

        boolean finished = false;
        while (!finished) {
            final DWord command = B.getDWordAtAddress(in.getRaw(), pointer, ByteOrder.LITTLE_ENDIAN);

            if (command.equals(sizeOfCommands)) {
                finished = true;
            }

            if (command.equals(Loader.LC_REQ_DYLD)) {
                //Loader.dyld_info_command
            }else if(command.equals(Loader.LC_DYLD_INFO_ONLY)){
                Loader.dyld_info_command dyld_info_command = new Loader.dyld_info_command();
                dyld_info_command.setBeginAddress(pointer.clone());

                dyld_info_command.cmd = B.getDWordAtAddress(in.getRaw(), pointer, ByteOrder.LITTLE_ENDIAN);
                pointer.add(DWord.SIZEOF_B);
                dyld_info_command.cmdsize = B.getDWordAtAddress(in.getRaw(), pointer, ByteOrder.LITTLE_ENDIAN);

                in.getCommands().add(dyld_info_command);
            }else if(command.equals(Loader.LC_REEXPORT_DYLIB)){
                Loader.dylinker_command dylinker_command = new Loader.dylinker_command();
                dylinker_command.setBeginAddress(pointer.clone());

                in.getCommands().add(dylinker_command);
            }else if(command.equals(Loader.LC_RPATH)){
                Loader.rpath_command rpath_command = new Loader.rpath_command();
                rpath_command.setBeginAddress(pointer.clone());

                in.getCommands().add(rpath_command);
            }else if(command.equals(Loader.LC_LOAD_WEAK_DYLIB)){
                Loader.load_command load_command = new Loader.load_command();
                load_command.setBeginAddress(pointer.clone());

                in.getCommands().add(load_command);
            }else if (command.equals(Loader.LC_SEGMENT)){
                Loader.segment_command segment_command = new Loader.segment_command();
                segment_command.setBeginAddress(pointer.clone());

                in.getCommands().add(segment_command);

            }else if (command.equals(Loader.LC_SYMTAB)) {
                Loader.symtab_command symtab_command = new Loader.symtab_command();
                symtab_command.setBeginAddress(pointer.clone());

                symtab_command.cmd = B.getDWordAtAddress(in.getRaw(), pointer, ByteOrder.LITTLE_ENDIAN);
                pointer.add(DWord.SIZEOF_B);
                symtab_command.cmdsize = B.getDWordAtAddress(in.getRaw(), pointer, ByteOrder.LITTLE_ENDIAN);
                pointer.add(DWord.SIZEOF_B);
                symtab_command.symoff = B.getDWordAtAddress(in.getRaw(), pointer, ByteOrder.LITTLE_ENDIAN);
                pointer.add(DWord.SIZEOF_B);
                symtab_command.nsyms = B.getDWordAtAddress(in.getRaw(), pointer, ByteOrder.LITTLE_ENDIAN);
                pointer.add(DWord.SIZEOF_B);
                symtab_command.stroff = B.getDWordAtAddress(in.getRaw(), pointer, ByteOrder.LITTLE_ENDIAN);
                pointer.add(DWord.SIZEOF_B);
                symtab_command.strsize = B.getDWordAtAddress(in.getRaw(), pointer, ByteOrder.LITTLE_ENDIAN);
                pointer.add(DWord.SIZEOF_B);

                in.getCommands().add(symtab_command);
                
            } else if (command.equals(Loader.LC_SYMSEG)) {
                Loader.symseg_command symseg_command = new Loader.symseg_command();
                symseg_command.setBeginAddress(pointer.clone());

                in.getCommands().add(symseg_command);
                
            } else if (command.equals(Loader.LC_THREAD)) {
                Loader.thread_command thread_command = new Loader.thread_command();
                thread_command.setBeginAddress(pointer.clone());

                in.getCommands().add(thread_command);
                
            } else if (command.equals(Loader.LC_UNIXTHREAD)) {
                Loader.thread_command unix_thread_command = new Loader.thread_command();
                unix_thread_command.setBeginAddress(pointer.clone());

                in.getCommands().add(unix_thread_command);
                
            } else if (command.equals(Loader.LC_LOADFVMLIB)) {
                Loader.fvmlib_command fvmlib_command = new Loader.fvmlib_command();
                fvmlib_command.setBeginAddress(pointer.clone());

                in.getCommands().add(fvmlib_command);
                
            } else if (command.equals(Loader.LC_IDFVMLIB)) {
                Loader.fvmlib_command fvmlib_command1 = new Loader.fvmlib_command();
                fvmlib_command1.setBeginAddress(pointer.clone());

                in.getCommands().add(fvmlib_command1);
                
            } else if (command.equals(Loader.LC_IDENT)) {
                Loader.ident_command ident_command = new Loader.ident_command();
                ident_command.setBeginAddress(pointer.clone());

                in.getCommands().add(ident_command);
                
            } else if (command.equals(Loader.LC_FVMFILE)) {
                Loader.fvmfile_command fvmfile_command = new Loader.fvmfile_command();
                fvmfile_command.setBeginAddress(pointer.clone());

                in.getCommands().add(fvmfile_command);
                
            } else if (command.equals(Loader.LC_PREPAGE)) {
                System.out.println("Cannot parse LC_PREPAGE");
                
            } else if (command.equals(Loader.LC_DYSYMTAB)) {
                Loader.dysymtab_command dysymtab_command = new Loader.dysymtab_command();
                dysymtab_command.setBeginAddress(pointer.clone());

                dysymtab_command.cmd = B.getDWordAtAddress(in.getRaw(), pointer, ByteOrder.LITTLE_ENDIAN);
                pointer.add(DWord.SIZEOF_B);
                dysymtab_command.cmdsize = B.getDWordAtAddress(in.getRaw(), pointer, ByteOrder.LITTLE_ENDIAN);
                pointer.add(DWord.SIZEOF_B);
                dysymtab_command.ilocalsym = B.getDWordAtAddress(in.getRaw(), pointer, ByteOrder.LITTLE_ENDIAN);
                pointer.add(DWord.SIZEOF_B);
                dysymtab_command.nlocalsym = B.getDWordAtAddress(in.getRaw(), pointer, ByteOrder.LITTLE_ENDIAN);
                pointer.add(DWord.SIZEOF_B);
                dysymtab_command.iextdefsym = B.getDWordAtAddress(in.getRaw(), pointer, ByteOrder.LITTLE_ENDIAN);
                pointer.add(DWord.SIZEOF_B);
                dysymtab_command.nextdefsym = B.getDWordAtAddress(in.getRaw(), pointer, ByteOrder.LITTLE_ENDIAN);
                pointer.add(DWord.SIZEOF_B);
                dysymtab_command.iundefsym = B.getDWordAtAddress(in.getRaw(), pointer, ByteOrder.LITTLE_ENDIAN);
                pointer.add(DWord.SIZEOF_B);
                dysymtab_command.nundefsym = B.getDWordAtAddress(in.getRaw(), pointer, ByteOrder.LITTLE_ENDIAN);
                pointer.add(DWord.SIZEOF_B);
                dysymtab_command.tocoff = B.getDWordAtAddress(in.getRaw(), pointer, ByteOrder.LITTLE_ENDIAN);
                pointer.add(DWord.SIZEOF_B);
                dysymtab_command.ntoc = B.getDWordAtAddress(in.getRaw(), pointer, ByteOrder.LITTLE_ENDIAN);
                pointer.add(DWord.SIZEOF_B);
                dysymtab_command.modtaboff = B.getDWordAtAddress(in.getRaw(), pointer, ByteOrder.LITTLE_ENDIAN);
                pointer.add(DWord.SIZEOF_B);
                dysymtab_command.nmodtab = B.getDWordAtAddress(in.getRaw(), pointer, ByteOrder.LITTLE_ENDIAN);
                pointer.add(DWord.SIZEOF_B);
                dysymtab_command.extrefsymoff = B.getDWordAtAddress(in.getRaw(), pointer, ByteOrder.LITTLE_ENDIAN);
                pointer.add(DWord.SIZEOF_B);
                dysymtab_command.nextrefsyms = B.getDWordAtAddress(in.getRaw(), pointer, ByteOrder.LITTLE_ENDIAN);
                pointer.add(DWord.SIZEOF_B);
                dysymtab_command.indirectsymoff = B.getDWordAtAddress(in.getRaw(), pointer, ByteOrder.LITTLE_ENDIAN);
                pointer.add(DWord.SIZEOF_B);
                dysymtab_command.nindirectsyms = B.getDWordAtAddress(in.getRaw(), pointer, ByteOrder.LITTLE_ENDIAN);
                pointer.add(DWord.SIZEOF_B);
                dysymtab_command.extreloff = B.getDWordAtAddress(in.getRaw(), pointer, ByteOrder.LITTLE_ENDIAN);
                pointer.add(DWord.SIZEOF_B);
                dysymtab_command.nextrel = B.getDWordAtAddress(in.getRaw(), pointer, ByteOrder.LITTLE_ENDIAN);
                pointer.add(DWord.SIZEOF_B);
                dysymtab_command.locreloff = B.getDWordAtAddress(in.getRaw(), pointer, ByteOrder.LITTLE_ENDIAN);
                pointer.add(DWord.SIZEOF_B);
                dysymtab_command.nlocrel = B.getDWordAtAddress(in.getRaw(), pointer, ByteOrder.LITTLE_ENDIAN);
                pointer.add(DWord.SIZEOF_B);
                dysymtab_command.setEndAddress(pointer.clone());
                in.getCommands().add(dysymtab_command);
                
            } else if (command.equals(Loader.LC_LOAD_DYLIB)) {
                Loader.dylib_command dylib_command = new Loader.dylib_command();
                dylib_command.setBeginAddress(pointer.clone());

                in.getCommands().add(dylib_command);
                
            } else if (command.equals(Loader.LC_ID_DYLIB)) {
                System.out.println("Cannot parse LC_ID_DYLIB");
                
            } else if (command.equals(Loader.LC_LOAD_DYLINKER)) {
                Loader.dylinker_command dylinker_command = new Loader.dylinker_command();
                dylinker_command.setBeginAddress(pointer.clone());

                dylinker_command.cmd = B.getDWordAtAddress(in.getRaw(), pointer, ByteOrder.LITTLE_ENDIAN);
                pointer.add(DWord.SIZEOF_B);
                dylinker_command.cmdsize = B.getDWordAtAddress(in.getRaw(), pointer, ByteOrder.LITTLE_ENDIAN);
                dylinker_command.setEndAddress(B.getEndAddressFromOffset(dylinker_command.getBeginAddress(), dylinker_command.cmdsize));
                pointer.add(DWord.SIZEOF_B);
                Loader.lc_str lc_str = new Loader.lc_str();
                lc_str.offset = B.getDWordAtAddress(in.getRaw(), pointer, ByteOrder.LITTLE_ENDIAN);
                pointer.add(DWord.SIZEOF_B);
                lc_str.ptr = B.getRangeAtAddress(in.getRaw(), pointer, dylinker_command.getEndAddress());

                pointer = (Address32) dylinker_command.getEndAddress();
                in.getCommands().add(dylinker_command);
                
            } else if (command.equals(Loader.LC_ID_DYLINKER)) {
                System.out.println("Cannot parse LC_ID_DYLINKER");
                
            } else if (command.equals(Loader.LC_PREBOUND_DYLIB)) {
                Loader.prebound_dylib_command prebound_dylib_command = new Loader.prebound_dylib_command();
                prebound_dylib_command.setBeginAddress(pointer.clone());

                in.getCommands().add(prebound_dylib_command);
                
            } else if (command.equals(Loader.LC_ROUTINES)) {
                Loader.routines_command routines_command = new Loader.routines_command();
                routines_command.setBeginAddress(pointer.clone());

                in.getCommands().add(routines_command);
                
            } else if (command.equals(Loader.LC_SUB_FRAMEWORK)) {
                Loader.sub_framework_command sub_framework_command = new Loader.sub_framework_command();
                sub_framework_command.setBeginAddress(pointer.clone());

                in.getCommands().add(sub_framework_command);
                
            } else if (command.equals(Loader.LC_SUB_UMBRELLA)) {
                Loader.sub_umbrella_command sub_umbrella_command = new Loader.sub_umbrella_command();
                sub_umbrella_command.setBeginAddress(pointer.clone());

                in.getCommands().add(sub_umbrella_command);
                
            } else if (command.equals(Loader.LC_SUB_CLIENT)) {
                Loader.sub_client_command sub_client_command = new Loader.sub_client_command();
                sub_client_command.setBeginAddress(pointer.clone());

                in.getCommands().add(sub_client_command);
                
            } else if (command.equals(Loader.LC_SUB_LIBRARY)) {
                Loader.sub_library_command sub_library_command = new Loader.sub_library_command();
                sub_library_command.setBeginAddress(pointer.clone());

                in.getCommands().add(sub_library_command);
                
            } else if (command.equals(Loader.LC_TWOLEVEL_HINTS)) {
                Loader.twolevel_hints_command twolevel_hints_command = new Loader.twolevel_hints_command();
                twolevel_hints_command.setBeginAddress(pointer.clone());

                in.getCommands().add(twolevel_hints_command);
                
            } else if (command.equals(Loader.LC_PREBIND_CKSUM)) {
                Loader.prebind_cksum_command prebind_cksum_command = new Loader.prebind_cksum_command();
                prebind_cksum_command.setBeginAddress(pointer.clone());

                in.getCommands().add(prebind_cksum_command);
                
            } else if (command.equals(Loader.LC_SEGMENT_64)) {
                Loader.segment_command_64 segment_command_641 = new Loader.segment_command_64();
                segment_command_641.setBeginAddress(pointer.clone());

                segment_command_641.cmd = B.getDWordAtAddress(in.getRaw(), pointer, ByteOrder.LITTLE_ENDIAN);
                pointer.add(DWord.SIZEOF_B);
                segment_command_641.cmdsize = B.getDWordAtAddress(in.getRaw(), pointer, ByteOrder.LITTLE_ENDIAN);
                pointer.add(DWord.SIZEOF_B);
                final byte[] container = B.getQWordAtAddress(in.getRaw(), pointer, ByteOrder.LITTLE_ENDIAN).getContainer();
                pointer.add(QWord.SIZEOF_B);
                final byte[] container2 = B.getQWordAtAddress(in.getRaw(), pointer, ByteOrder.LITTLE_ENDIAN).getContainer();
                segment_command_641.segname = new Loader.char16(B.mergeBytes(container, container2));
                pointer.add(QWord.SIZEOF_B);
                segment_command_641.vmaddr = B.getQWordAtAddress(in.getRaw(), pointer, ByteOrder.LITTLE_ENDIAN);
                pointer.add(QWord.SIZEOF_B);
                segment_command_641.vmsize = B.getQWordAtAddress(in.getRaw(), pointer, ByteOrder.LITTLE_ENDIAN);
                pointer.add(QWord.SIZEOF_B);
                segment_command_641.fileoff = B.getQWordAtAddress(in.getRaw(), pointer, ByteOrder.LITTLE_ENDIAN);
                pointer.add(QWord.SIZEOF_B);
                segment_command_641.filesize = B.getQWordAtAddress(in.getRaw(), pointer, ByteOrder.LITTLE_ENDIAN);
                pointer.add(QWord.SIZEOF_B);
                segment_command_641.maxprot = B.getDWordAtAddress(in.getRaw(), pointer, ByteOrder.LITTLE_ENDIAN);
                pointer.add(DWord.SIZEOF_B);
                segment_command_641.initprot = B.getDWordAtAddress(in.getRaw(), pointer, ByteOrder.LITTLE_ENDIAN);
                pointer.add(DWord.SIZEOF_B);
                segment_command_641.nsects = B.getDWordAtAddress(in.getRaw(), pointer, ByteOrder.LITTLE_ENDIAN);
                pointer.add(DWord.SIZEOF_B);
                segment_command_641.flags = B.getDWordAtAddress(in.getRaw(), pointer, ByteOrder.LITTLE_ENDIAN);
                pointer.add(DWord.SIZEOF_B);

                int sections = segment_command_641.nsects.getIntValue();
                for (int i = 0; i < sections; i++) {
                    ParseSection64.parse(in);
                    pointer.add(new Word("0x0050", ByteOrder.BIG_ENDIAN));
                }

                in.getCommands().add(segment_command_641);
                
            } else if (command.equals(Loader.LC_ROUTINES_64)) {
                Loader.routines_command_64 routines_command_64 = new Loader.routines_command_64();
                routines_command_64.setBeginAddress(pointer.clone());

                in.getCommands().add(routines_command_64);
                
            } else if (command.equals(Loader.LC_UUID)) {
                Loader.uuid_command uuid_command = new Loader.uuid_command();
                uuid_command.setBeginAddress(pointer.clone());

                uuid_command.cmd = B.getDWordAtAddress(in.getRaw(), pointer, ByteOrder.LITTLE_ENDIAN);
                pointer.add(DWord.SIZEOF_B);
                uuid_command.cmdsize = B.getDWordAtAddress(in.getRaw(), pointer, ByteOrder.LITTLE_ENDIAN);
                pointer.add(DWord.SIZEOF_B);
                uuid_command.uuid = B.getQWordAtAddress(in.getRaw(), pointer, ByteOrder.LITTLE_ENDIAN).getContainer();

                in.getCommands().add(uuid_command);
                
            } else if (command.equals(Loader.LC_CODE_SIGNATURE)) {
                System.out.println("Cannot parse LC_CODE_SIGNATURE");
                
            } else if (command.equals(Loader.LC_SEGMENT_SPLIT_INFO)) {
                Loader.dyld_info_command dyld_info_command = new Loader.dyld_info_command();
                dyld_info_command.setBeginAddress(pointer.clone());

                in.getCommands().add(dyld_info_command);
                
            } else if (command.equals(Loader.LC_LAZY_LOAD_DYLIB)) {
                Loader.load_command load_command = new Loader.load_command();
                load_command.setBeginAddress(pointer.clone());

                in.getCommands().add(load_command);
                
            } else if (command.equals(Loader.LC_ENCRYPTION_INFO)) {
                Loader.encryption_info_command encryption_info_command = new Loader.encryption_info_command();
                encryption_info_command.setBeginAddress(pointer.clone());

                in.getCommands();
            } else if (command.equals(Loader.LC_DYLD_INFO)) {
                Loader.dyld_info_command dyld_info_command1 = new Loader.dyld_info_command();
                dyld_info_command1.setBeginAddress(pointer.clone());

                dyld_info_command1.cmd = B.getDWordAtAddress(in.getRaw(), pointer, ByteOrder.LITTLE_ENDIAN);
                pointer.add(DWord.SIZEOF_B);
                dyld_info_command1.cmdsize = B.getDWordAtAddress(in.getRaw(), pointer, ByteOrder.LITTLE_ENDIAN);
                pointer.add(DWord.SIZEOF_B);
                dyld_info_command1.rebase_off = B.getDWordAtAddress(in.getRaw(), pointer, ByteOrder.LITTLE_ENDIAN);
                pointer.add(DWord.SIZEOF_B);
                dyld_info_command1.rebase_size = B.getDWordAtAddress(in.getRaw(), pointer, ByteOrder.LITTLE_ENDIAN);
                pointer.add(DWord.SIZEOF_B);
                dyld_info_command1.bind_off = B.getDWordAtAddress(in.getRaw(), pointer, ByteOrder.LITTLE_ENDIAN);
                pointer.add(DWord.SIZEOF_B);
                dyld_info_command1.bind_size = B.getDWordAtAddress(in.getRaw(), pointer, ByteOrder.LITTLE_ENDIAN);
                pointer.add(DWord.SIZEOF_B);
                dyld_info_command1.weak_bind_off = B.getDWordAtAddress(in.getRaw(), pointer, ByteOrder.LITTLE_ENDIAN);
                pointer.add(DWord.SIZEOF_B);
                dyld_info_command1.weak_bind_size = B.getDWordAtAddress(in.getRaw(), pointer, ByteOrder.LITTLE_ENDIAN);
                pointer.add(DWord.SIZEOF_B);
                dyld_info_command1.lazy_bind_off = B.getDWordAtAddress(in.getRaw(), pointer, ByteOrder.LITTLE_ENDIAN);
                pointer.add(DWord.SIZEOF_B);
                dyld_info_command1.lazy_bind_size = B.getDWordAtAddress(in.getRaw(), pointer, ByteOrder.LITTLE_ENDIAN);
                pointer.add(DWord.SIZEOF_B);
                dyld_info_command1.export_off = B.getDWordAtAddress(in.getRaw(), pointer, ByteOrder.LITTLE_ENDIAN);
                pointer.add(DWord.SIZEOF_B);
                dyld_info_command1.export_size = B.getDWordAtAddress(in.getRaw(), pointer, ByteOrder.LITTLE_ENDIAN);
                pointer.add(DWord.SIZEOF_B);

                in.getCommands().add(dyld_info_command1);
            }

            System.out.println();
        }
    }
}
