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

            if (pointer.equals(sizeOfCommands)) {
                finished = true;
            }

            if(command.equals(Loader.LC_LOAD_UPWARD_DYLIB)) {
                Loader.load_command load_command = new Loader.load_command();
                load_command.setBeginAddress(pointer.clone());

                in.getCommands().add(load_command);
            }else if(command.equals(Loader.LC_VERSION_MIN_IPHONEOS)) {
                Loader.version_min_command version_min_command = new Loader.version_min_command();
                version_min_command.setBeginAddress(pointer.clone());

                in.getCommands().add(version_min_command);
            }else if(command.equals(Loader.LC_FUNCTION_STARTS)) {
                Loader.linkedit_data_command linkedit_data_command = new Loader.linkedit_data_command();

                linkedit_data_command.setBeginAddress(pointer.clone());
                linkedit_data_command.cmd = B.getDWordAtAddressAndIncrement(in.getRaw(), pointer, ByteOrder.LITTLE_ENDIAN);
                linkedit_data_command.cmdsize = B.getDWordAtAddressAndIncrement(in.getRaw(), pointer, ByteOrder.LITTLE_ENDIAN);
                linkedit_data_command.dataoff = B.getDWordAtAddressAndIncrement(in.getRaw(), pointer, ByteOrder.LITTLE_ENDIAN);
                linkedit_data_command.datasize = B.getDWordAtAddressAndIncrement(in.getRaw(), pointer, ByteOrder.LITTLE_ENDIAN);
                linkedit_data_command.setEndAddress(pointer.clone());

                in.getCommands().add(linkedit_data_command);
            }else if(command.equals(Loader.LC_DYLD_ENVIRONMENT)) {
                Loader.dyld_info_command dyld_info_command = new Loader.dyld_info_command();
                dyld_info_command.setBeginAddress(pointer.clone());

                in.getCommands().add(dyld_info_command);
            }else if(command.equals(Loader.LC_MAIN)) {
                Loader.entry_point_command entry_point_command = new Loader.entry_point_command();

                entry_point_command.setBeginAddress(pointer.clone());
                entry_point_command.cmd = B.getDWordAtAddressAndIncrement(in.getRaw(), pointer, ByteOrder.LITTLE_ENDIAN);
                entry_point_command.cmdsize = B.getDWordAtAddressAndIncrement(in.getRaw(), pointer, ByteOrder.LITTLE_ENDIAN);
                entry_point_command.entryoff = B.getQWordAtAddressAndIncrement(in.getRaw(), pointer, ByteOrder.LITTLE_ENDIAN);
                entry_point_command.stacksize = B.getQWordAtAddressAndIncrement(in.getRaw(), pointer, ByteOrder.LITTLE_ENDIAN);
                entry_point_command.setEndAddress(pointer.clone());

                in.getCommands().add(entry_point_command);
            }else if(command.equals(Loader.LC_DATA_IN_CODE)) {
                Loader.linkedit_data_command linkedit_data_command = new Loader.linkedit_data_command();

                linkedit_data_command.setBeginAddress(pointer.clone());
                linkedit_data_command.cmd = B.getDWordAtAddressAndIncrement(in.getRaw(), pointer, ByteOrder.LITTLE_ENDIAN);
                linkedit_data_command.cmdsize = B.getDWordAtAddressAndIncrement(in.getRaw(), pointer, ByteOrder.LITTLE_ENDIAN);
                linkedit_data_command.dataoff = B.getDWordAtAddressAndIncrement(in.getRaw(), pointer, ByteOrder.LITTLE_ENDIAN);
                linkedit_data_command.datasize = B.getDWordAtAddressAndIncrement(in.getRaw(), pointer, ByteOrder.LITTLE_ENDIAN);

                in.getCommands().add(linkedit_data_command);
            }else if(command.equals(Loader.LC_SOURCE_VERSION)) {
                Loader.source_version_command source_version_command = new Loader.source_version_command();

                source_version_command.setBeginAddress(pointer.clone());
                source_version_command.cmd = B.getDWordAtAddressAndIncrement(in.getRaw(), pointer, ByteOrder.LITTLE_ENDIAN);
                source_version_command.cmdsize = B.getDWordAtAddressAndIncrement(in.getRaw(), pointer, ByteOrder.LITTLE_ENDIAN);
                source_version_command.version = B.getQWordAtAddressAndIncrement(in.getRaw(), pointer, ByteOrder.LITTLE_ENDIAN);
                source_version_command.setEndAddress(pointer.clone());

                in.getCommands().add(source_version_command);
            }else if(command.equals(Loader.LC_DYLIB_CODE_SIGN_DRS)) {
                System.out.println("Cannot parse LC_DYLIB_CODE_SIGN_DRS");

            }else if(command.equals(Loader.LC_VERSION_MIN_MACOSX)){
                Loader.version_min_command version_min_command = new Loader.version_min_command();

                version_min_command.setBeginAddress(pointer.clone());
                version_min_command.cmd = B.getDWordAtAddressAndIncrement(in.getRaw(), pointer, ByteOrder.LITTLE_ENDIAN);
                version_min_command.cmdsize = B.getDWordAtAddressAndIncrement(in.getRaw(), pointer, ByteOrder.LITTLE_ENDIAN);
                version_min_command.version = B.getDWordAtAddressAndIncrement(in.getRaw(), pointer, ByteOrder.LITTLE_ENDIAN);
                version_min_command.sdk = B.getDWordAtAddressAndIncrement(in.getRaw(), pointer, ByteOrder.LITTLE_ENDIAN);
                version_min_command.setEndAddress(pointer.clone());

                in.getCommands().add(version_min_command);
            }else if (command.equals(Loader.LC_REQ_DYLD)) {
                Loader.load_command load_command = new Loader.load_command();
                load_command.setBeginAddress(pointer.clone());

                in.getCommands().add(load_command);
            }else if(command.equals(Loader.LC_DYLD_INFO_ONLY)){
                Loader.dyld_info_command dyld_info_command = new Loader.dyld_info_command();

                dyld_info_command.setBeginAddress(pointer.clone());
                dyld_info_command.cmd = B.getDWordAtAddressAndIncrement(in.getRaw(), pointer, ByteOrder.LITTLE_ENDIAN);
                dyld_info_command.cmdsize = B.getDWordAtAddressAndIncrement(in.getRaw(), pointer, ByteOrder.LITTLE_ENDIAN);
                dyld_info_command.rebase_off = B.getDWordAtAddressAndIncrement(in.getRaw(), pointer, ByteOrder.LITTLE_ENDIAN);
                dyld_info_command.rebase_size = B.getDWordAtAddressAndIncrement(in.getRaw(), pointer, ByteOrder.LITTLE_ENDIAN);
                dyld_info_command.bind_off = B.getDWordAtAddressAndIncrement(in.getRaw(), pointer, ByteOrder.LITTLE_ENDIAN);
                dyld_info_command.bind_size = B.getDWordAtAddressAndIncrement(in.getRaw(), pointer, ByteOrder.LITTLE_ENDIAN);
                dyld_info_command.weak_bind_off = B.getDWordAtAddressAndIncrement(in.getRaw(), pointer, ByteOrder.LITTLE_ENDIAN);
                dyld_info_command.weak_bind_size = B.getDWordAtAddressAndIncrement(in.getRaw(), pointer, ByteOrder.LITTLE_ENDIAN);
                dyld_info_command.lazy_bind_off = B.getDWordAtAddressAndIncrement(in.getRaw(), pointer, ByteOrder.LITTLE_ENDIAN);
                dyld_info_command.lazy_bind_size = B.getDWordAtAddressAndIncrement(in.getRaw(), pointer, ByteOrder.LITTLE_ENDIAN);
                dyld_info_command.export_off = B.getDWordAtAddressAndIncrement(in.getRaw(), pointer, ByteOrder.LITTLE_ENDIAN);
                dyld_info_command.export_size = B.getDWordAtAddressAndIncrement(in.getRaw(), pointer, ByteOrder.LITTLE_ENDIAN);
                dyld_info_command.setEndAddress(pointer.clone());

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
                symtab_command.cmd = B.getDWordAtAddressAndIncrement(in.getRaw(), pointer, ByteOrder.LITTLE_ENDIAN);
                symtab_command.cmdsize = B.getDWordAtAddressAndIncrement(in.getRaw(), pointer, ByteOrder.LITTLE_ENDIAN);
                symtab_command.symoff = B.getDWordAtAddressAndIncrement(in.getRaw(), pointer, ByteOrder.LITTLE_ENDIAN);
                symtab_command.nsyms = B.getDWordAtAddressAndIncrement(in.getRaw(), pointer, ByteOrder.LITTLE_ENDIAN);
                symtab_command.stroff = B.getDWordAtAddressAndIncrement(in.getRaw(), pointer, ByteOrder.LITTLE_ENDIAN);
                symtab_command.strsize = B.getDWordAtAddressAndIncrement(in.getRaw(), pointer, ByteOrder.LITTLE_ENDIAN);
                symtab_command.setEndAddress(pointer.clone());

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
                dysymtab_command.cmd = B.getDWordAtAddressAndIncrement(in.getRaw(), pointer, ByteOrder.LITTLE_ENDIAN);
                dysymtab_command.cmdsize = B.getDWordAtAddressAndIncrement(in.getRaw(), pointer, ByteOrder.LITTLE_ENDIAN);
                dysymtab_command.ilocalsym = B.getDWordAtAddressAndIncrement(in.getRaw(), pointer, ByteOrder.LITTLE_ENDIAN);
                dysymtab_command.nlocalsym = B.getDWordAtAddressAndIncrement(in.getRaw(), pointer, ByteOrder.LITTLE_ENDIAN);
                dysymtab_command.iextdefsym = B.getDWordAtAddressAndIncrement(in.getRaw(), pointer, ByteOrder.LITTLE_ENDIAN);
                dysymtab_command.nextdefsym = B.getDWordAtAddressAndIncrement(in.getRaw(), pointer, ByteOrder.LITTLE_ENDIAN);
                dysymtab_command.iundefsym = B.getDWordAtAddressAndIncrement(in.getRaw(), pointer, ByteOrder.LITTLE_ENDIAN);
                dysymtab_command.nundefsym = B.getDWordAtAddressAndIncrement(in.getRaw(), pointer, ByteOrder.LITTLE_ENDIAN);
                dysymtab_command.tocoff = B.getDWordAtAddressAndIncrement(in.getRaw(), pointer, ByteOrder.LITTLE_ENDIAN);
                dysymtab_command.ntoc = B.getDWordAtAddressAndIncrement(in.getRaw(), pointer, ByteOrder.LITTLE_ENDIAN);
                dysymtab_command.modtaboff = B.getDWordAtAddressAndIncrement(in.getRaw(), pointer, ByteOrder.LITTLE_ENDIAN);
                dysymtab_command.nmodtab = B.getDWordAtAddressAndIncrement(in.getRaw(), pointer, ByteOrder.LITTLE_ENDIAN);
                dysymtab_command.extrefsymoff = B.getDWordAtAddressAndIncrement(in.getRaw(), pointer, ByteOrder.LITTLE_ENDIAN);
                dysymtab_command.nextrefsyms = B.getDWordAtAddressAndIncrement(in.getRaw(), pointer, ByteOrder.LITTLE_ENDIAN);
                dysymtab_command.indirectsymoff = B.getDWordAtAddressAndIncrement(in.getRaw(), pointer, ByteOrder.LITTLE_ENDIAN);
                dysymtab_command.nindirectsyms = B.getDWordAtAddressAndIncrement(in.getRaw(), pointer, ByteOrder.LITTLE_ENDIAN);
                dysymtab_command.extreloff = B.getDWordAtAddressAndIncrement(in.getRaw(), pointer, ByteOrder.LITTLE_ENDIAN);
                dysymtab_command.nextrel = B.getDWordAtAddressAndIncrement(in.getRaw(), pointer, ByteOrder.LITTLE_ENDIAN);
                dysymtab_command.locreloff = B.getDWordAtAddressAndIncrement(in.getRaw(), pointer, ByteOrder.LITTLE_ENDIAN);
                dysymtab_command.nlocrel = B.getDWordAtAddressAndIncrement(in.getRaw(), pointer, ByteOrder.LITTLE_ENDIAN);
                dysymtab_command.setEndAddress(pointer.clone());

                in.getCommands().add(dysymtab_command);
            } else if (command.equals(Loader.LC_LOAD_DYLIB)) {
                Loader.dylib_command dylib_command = new Loader.dylib_command();

                dylib_command.setBeginAddress(pointer.clone());
                dylib_command.cmd = B.getDWordAtAddressAndIncrement(in.getRaw(), pointer, ByteOrder.LITTLE_ENDIAN);
                dylib_command.cmdsize = B.getDWordAtAddressAndIncrement(in.getRaw(), pointer, ByteOrder.LITTLE_ENDIAN);

                Loader.lc_str lcstr = new Loader.lc_str();
                lcstr.offset = B.getDWordAtAddressAndIncrement(in.getRaw(), pointer, ByteOrder.LITTLE_ENDIAN);

                Address32 begin = (Address32)dylib_command.getBeginAddress().clone();
                begin.add(lcstr.offset);

                Address32 end =  (Address32)dylib_command.getBeginAddress().clone();
                end.add(dylib_command.cmdsize);

                lcstr.ptr = B.getRangeAtAddress(in.getRaw(), begin, end);

                Loader.dylib l = new Loader.dylib();
                l.timestamp = B.getDWordAtAddressAndIncrement(in.getRaw(), pointer, ByteOrder.LITTLE_ENDIAN);
                l.current_version = B.getDWordAtAddressAndIncrement(in.getRaw(), pointer, ByteOrder.LITTLE_ENDIAN);
                l.compatibility_version = B.getDWordAtAddressAndIncrement(in.getRaw(), pointer, ByteOrder.LITTLE_ENDIAN);
                l.name = lcstr;

                dylib_command.dylib = l;
                dylib_command.setEndAddress(end);
                pointer = end;

                in.getCommands().add(dylib_command);
                
            } else if (command.equals(Loader.LC_ID_DYLIB)) {
                System.out.println("Cannot parse LC_ID_DYLIB");
                
            } else if (command.equals(Loader.LC_LOAD_DYLINKER)) {
                Loader.dylinker_command dylinker_command = new Loader.dylinker_command();

                dylinker_command.setBeginAddress(pointer.clone());
                dylinker_command.cmd = B.getDWordAtAddressAndIncrement(in.getRaw(), pointer, ByteOrder.LITTLE_ENDIAN);
                dylinker_command.cmdsize = B.getDWordAtAddressAndIncrement(in.getRaw(), pointer, ByteOrder.LITTLE_ENDIAN);

                final Address a = dylinker_command.getBeginAddress().clone();
                a.add(dylinker_command.cmdsize);
                dylinker_command.setEndAddress(a);

                Loader.lc_str lc_str = new Loader.lc_str();
                lc_str.offset = B.getDWordAtAddressAndIncrement(in.getRaw(), pointer, ByteOrder.LITTLE_ENDIAN);
                lc_str.ptr = B.getRangeAtAddress(in.getRaw(), pointer, dylinker_command.getEndAddress());

                dylinker_command.name=lc_str;

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
                segment_command_641.cmd = B.getDWordAtAddressAndIncrement(in.getRaw(), pointer, ByteOrder.LITTLE_ENDIAN);
                segment_command_641.cmdsize = B.getDWordAtAddressAndIncrement(in.getRaw(), pointer, ByteOrder.LITTLE_ENDIAN);
                final byte[] container = B.getQWordAtAddressAndIncrement(in.getRaw(), pointer, ByteOrder.LITTLE_ENDIAN).getContainer();
                final byte[] container2 = B.getQWordAtAddressAndIncrement(in.getRaw(), pointer, ByteOrder.LITTLE_ENDIAN).getContainer();
                segment_command_641.segname = new Loader.char16(B.mergeBytes(container, container2));
                segment_command_641.vmaddr = B.getQWordAtAddressAndIncrement(in.getRaw(), pointer, ByteOrder.LITTLE_ENDIAN);
                segment_command_641.vmsize = B.getQWordAtAddressAndIncrement(in.getRaw(), pointer, ByteOrder.LITTLE_ENDIAN);
                segment_command_641.fileoff = B.getQWordAtAddressAndIncrement(in.getRaw(), pointer, ByteOrder.LITTLE_ENDIAN);
                segment_command_641.filesize = B.getQWordAtAddressAndIncrement(in.getRaw(), pointer, ByteOrder.LITTLE_ENDIAN);
                segment_command_641.maxprot = B.getDWordAtAddressAndIncrement(in.getRaw(), pointer, ByteOrder.LITTLE_ENDIAN);
                segment_command_641.initprot = B.getDWordAtAddressAndIncrement(in.getRaw(), pointer, ByteOrder.LITTLE_ENDIAN);
                segment_command_641.nsects = B.getDWordAtAddressAndIncrement(in.getRaw(), pointer, ByteOrder.LITTLE_ENDIAN);
                segment_command_641.flags = B.getDWordAtAddressAndIncrement(in.getRaw(), pointer, ByteOrder.LITTLE_ENDIAN);

                final int sections = segment_command_641.nsects.getIntValue();
                for (int i = 0; i < sections; i++) {
                    segment_command_641.getSections().add(ParseSection64.parse(in,pointer));
                }
                segment_command_641.setEndAddress(pointer.clone());

                in.getCommands().add(segment_command_641);
                
            } else if (command.equals(Loader.LC_ROUTINES_64)) {
                Loader.routines_command_64 routines_command_64 = new Loader.routines_command_64();
                routines_command_64.setBeginAddress(pointer.clone());

                in.getCommands().add(routines_command_64);
                
            } else if (command.equals(Loader.LC_UUID)) {
                Loader.uuid_command uuid_command = new Loader.uuid_command();

                uuid_command.setBeginAddress(pointer.clone());
                uuid_command.cmd = B.getDWordAtAddressAndIncrement(in.getRaw(), pointer, ByteOrder.LITTLE_ENDIAN);;
                uuid_command.cmdsize = B.getDWordAtAddressAndIncrement(in.getRaw(), pointer, ByteOrder.LITTLE_ENDIAN);
                byte[] tmp1 = B.getQWordAtAddressAndIncrement(in.getRaw(), pointer, ByteOrder.LITTLE_ENDIAN).getContainer();
                byte[] tmp2 = B.getQWordAtAddressAndIncrement(in.getRaw(), pointer, ByteOrder.LITTLE_ENDIAN).getContainer();
                uuid_command.uuid = B.mergeBytes(tmp1,tmp2);
                uuid_command.setEndAddress(pointer.clone());

                in.getCommands().add(uuid_command);
                
            } else if (command.equals(Loader.LC_CODE_SIGNATURE)) {
                Loader.linkedit_data_command linkedit_data_command = new Loader.linkedit_data_command();
                
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
                dyld_info_command1.cmd = B.getDWordAtAddressAndIncrement(in.getRaw(), pointer, ByteOrder.LITTLE_ENDIAN);
                dyld_info_command1.cmdsize = B.getDWordAtAddressAndIncrement(in.getRaw(), pointer, ByteOrder.LITTLE_ENDIAN);
                dyld_info_command1.rebase_off = B.getDWordAtAddressAndIncrement(in.getRaw(), pointer, ByteOrder.LITTLE_ENDIAN);
                dyld_info_command1.rebase_size = B.getDWordAtAddressAndIncrement(in.getRaw(), pointer, ByteOrder.LITTLE_ENDIAN);
                dyld_info_command1.bind_off = B.getDWordAtAddressAndIncrement(in.getRaw(), pointer, ByteOrder.LITTLE_ENDIAN);
                dyld_info_command1.bind_size = B.getDWordAtAddressAndIncrement(in.getRaw(), pointer, ByteOrder.LITTLE_ENDIAN);
                dyld_info_command1.weak_bind_off = B.getDWordAtAddressAndIncrement(in.getRaw(), pointer, ByteOrder.LITTLE_ENDIAN);
                dyld_info_command1.weak_bind_size = B.getDWordAtAddressAndIncrement(in.getRaw(), pointer, ByteOrder.LITTLE_ENDIAN);
                dyld_info_command1.lazy_bind_off = B.getDWordAtAddressAndIncrement(in.getRaw(), pointer, ByteOrder.LITTLE_ENDIAN);
                dyld_info_command1.lazy_bind_size = B.getDWordAtAddressAndIncrement(in.getRaw(), pointer, ByteOrder.LITTLE_ENDIAN);
                dyld_info_command1.export_off = B.getDWordAtAddressAndIncrement(in.getRaw(), pointer, ByteOrder.LITTLE_ENDIAN);
                dyld_info_command1.export_size = B.getDWordAtAddressAndIncrement(in.getRaw(), pointer, ByteOrder.LITTLE_ENDIAN);
                dyld_info_command1.setEndAddress(pointer.clone());

                in.getCommands().add(dyld_info_command1);
            }

            System.out.println();
        }
    }
}
