package redress.abi.mach.parse.x86_64;


import redress.memory.data.AbstractData;
import redress.abi.generic.IStructure;
import redress.memory.address.AbstractAddress;
import redress.memory.address.Address32;
import redress.memory.data.Range;
import redress.memory.data.DWord;
import redress.abi.mach.Loader;
import redress.abi.mach.MachO64;
import redress.util.B;

import java.nio.ByteOrder;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Created by jamesrichardson on 2/10/16.
 */
public class ParseCommand64 {
    private final static Logger LOGGER = Logger.getLogger(ParseCommand64.class.getName());

    private ParseCommand64() {}

    public static void parse(MachO64 parent) throws Exception{

        final IStructure head = parent.getChildren().get(0);

        if(head == null) {
            LOGGER.log(Level.SEVERE, "Header must exist!");
            return;
        }

        DWord sizeOfCommands = DWord.NULL;
        if(head instanceof Loader.mach_header_64) {
            sizeOfCommands = ((Loader.mach_header_64) head).sizeofcmds;
            sizeOfCommands.add(head.getEndAddress());
        }

        Address32 pointer = new Address32("0x00000020");

        int MAX_LIMIT = 0;
        while (MAX_LIMIT < 500) {
            MAX_LIMIT++;
            final DWord command = B.getDWordAtAddress(parent.getRaw(), pointer, null,AbstractData.Type.DATA_BYTE, ByteOrder.LITTLE_ENDIAN);

            if (pointer.equals(sizeOfCommands)) {
                LOGGER.log(Level.INFO,"Load Command parsing complete");
                break;
            }

            boolean parsedSomething = false;

            if(command.equals(Loader.LC_LOAD_UPWARD_DYLIB)) {
                parsedSomething = true;
                LOGGER.log(Level.INFO,"Parsing LC_LOAD_UPWARD_DYLIB");
                Loader.load_command load_command = new Loader.load_command(parent);

                load_command.setBeginAddress(pointer.clone());
                LOGGER.log(Level.SEVERE, "\tNOT YET IMPLEMENTED");
                pointer.add(8);
                load_command.setEndAddress(pointer.clone());
                load_command.addComments("LC_LOAD_UPWARD_DYLIB");

                parent.getChildren().add(load_command);
            }else if(command.equals(Loader.LC_VERSION_MIN_IPHONEOS)) {
                parsedSomething = true;
                LOGGER.log(Level.INFO,"Parsing LC_VERSION_MIN_IPHONEOS");
                Loader.version_min_command version_min_command = new Loader.version_min_command(parent);

                version_min_command.setBeginAddress(pointer.clone());
                LOGGER.log(Level.SEVERE,"\tNOT YET IMPLEMENTED");
                pointer.add(16);
                version_min_command.setEndAddress(pointer.clone());
                version_min_command.addComments("LC_VERSION_MIN_IPHONEOS");

                parent.getChildren().add(version_min_command);
            }else if(command.equals(Loader.LC_FUNCTION_STARTS)) {
                parsedSomething = true;
                LOGGER.log(Level.INFO,"Parsing LC_FUNCTION_STARTS");
                Loader.linkedit_ABI_command linkedit_data_command = new Loader.linkedit_ABI_command(parent);

                linkedit_data_command.setBeginAddress(pointer.clone());
                linkedit_data_command.cmd = B.getDWordAtAddressAndIncrement(parent.getRaw(), pointer, linkedit_data_command,AbstractData.Type.DATA_BYTE, ByteOrder.LITTLE_ENDIAN);
                linkedit_data_command.cmdsize = B.getDWordAtAddressAndIncrement(parent.getRaw(), pointer, linkedit_data_command,AbstractData.Type.DATA_BYTE, ByteOrder.LITTLE_ENDIAN);
                linkedit_data_command.dataoff = B.getDWordAtAddressAndIncrement(parent.getRaw(), pointer, linkedit_data_command,AbstractData.Type.DATA_BYTE, ByteOrder.LITTLE_ENDIAN);
                linkedit_data_command.datasize = B.getDWordAtAddressAndIncrement(parent.getRaw(), pointer, linkedit_data_command,AbstractData.Type.DATA_BYTE, ByteOrder.LITTLE_ENDIAN);
                linkedit_data_command.setEndAddress(pointer.clone());
                linkedit_data_command.addComments("LC_FUNCTION_STARTS");

                parent.getChildren().add(linkedit_data_command);
            }else if(command.equals(Loader.LC_DYLD_ENVIRONMENT)) {
                parsedSomething = true;
                LOGGER.log(Level.INFO,"Parsing LC_DYLD_ENVIRONMENT");
                Loader.dyld_info_command dyld_info_command = new Loader.dyld_info_command(parent);

                dyld_info_command.setBeginAddress(pointer.clone());
                LOGGER.log(Level.SEVERE,"\tNOT YET IMPLEMENTED");
                pointer.add(48);
                dyld_info_command.setEndAddress(pointer.clone());
                dyld_info_command.addComments("LC_DYLD_ENVIRONMENT");

                parent.getChildren().add(dyld_info_command);
            }else if(command.equals(Loader.LC_MAIN)) {
                parsedSomething = true;
                LOGGER.log(Level.INFO,"Parsing LC_MAIN");
                Loader.entry_point_command entry_point_command = new Loader.entry_point_command(parent);

                entry_point_command.setBeginAddress(pointer.clone());
                entry_point_command.cmd = B.getDWordAtAddressAndIncrement(parent.getRaw(), pointer, entry_point_command,AbstractData.Type.DATA_BYTE, ByteOrder.LITTLE_ENDIAN);
                entry_point_command.cmdsize = B.getDWordAtAddressAndIncrement(parent.getRaw(), pointer, entry_point_command,AbstractData.Type.DATA_BYTE, ByteOrder.LITTLE_ENDIAN);
                entry_point_command.entryoff = B.getQWordAtAddressAndIncrement(parent.getRaw(), pointer, entry_point_command,AbstractData.Type.DATA_BYTE, ByteOrder.LITTLE_ENDIAN);
                entry_point_command.stacksize = B.getQWordAtAddressAndIncrement(parent.getRaw(), pointer, entry_point_command,AbstractData.Type.DATA_BYTE,  ByteOrder.LITTLE_ENDIAN);
                entry_point_command.setEndAddress(pointer.clone());
                entry_point_command.addComments("LC_MAIN");

                parent.getChildren().add(entry_point_command);
            }else if(command.equals(Loader.LC_DATA_IN_CODE)) {
                parsedSomething = true;
                LOGGER.log(Level.INFO,"Parsing LC_DATA_IN_CODE");
                Loader.linkedit_ABI_command linkedit_data_command = new Loader.linkedit_ABI_command(parent);

                linkedit_data_command.setBeginAddress(pointer.clone());
                linkedit_data_command.cmd = B.getDWordAtAddressAndIncrement(parent.getRaw(), pointer, linkedit_data_command,AbstractData.Type.DATA_BYTE, ByteOrder.LITTLE_ENDIAN);
                linkedit_data_command.cmdsize = B.getDWordAtAddressAndIncrement(parent.getRaw(), pointer,linkedit_data_command, AbstractData.Type.DATA_BYTE, ByteOrder.LITTLE_ENDIAN);
                linkedit_data_command.dataoff = B.getDWordAtAddressAndIncrement(parent.getRaw(), pointer,linkedit_data_command, AbstractData.Type.DATA_BYTE, ByteOrder.LITTLE_ENDIAN);
                linkedit_data_command.datasize = B.getDWordAtAddressAndIncrement(parent.getRaw(), pointer,linkedit_data_command, AbstractData.Type.DATA_BYTE,  ByteOrder.LITTLE_ENDIAN);
                linkedit_data_command.setEndAddress(pointer.clone());
                linkedit_data_command.addComments("LC_DATA_IN_CODE");
                //TODO .setLoader();

                parent.getChildren().add(linkedit_data_command);
            }else if(command.equals(Loader.LC_SOURCE_VERSION)) {
                parsedSomething = true;
                LOGGER.log(Level.INFO,"Parsing LC_SOURCE_VERSION");
                Loader.source_version_command source_version_command = new Loader.source_version_command(parent);

                source_version_command.setBeginAddress(pointer.clone());
                source_version_command.cmd = B.getDWordAtAddressAndIncrement(parent.getRaw(), pointer, source_version_command,AbstractData.Type.DATA_BYTE, ByteOrder.LITTLE_ENDIAN);
                source_version_command.cmdsize = B.getDWordAtAddressAndIncrement(parent.getRaw(), pointer, source_version_command,AbstractData.Type.DATA_BYTE,  ByteOrder.LITTLE_ENDIAN);
                source_version_command.version = B.getQWordAtAddressAndIncrement(parent.getRaw(), pointer, source_version_command,AbstractData.Type.DATA_BYTE,  ByteOrder.LITTLE_ENDIAN);
                source_version_command.setEndAddress(pointer.clone());
                source_version_command.addComments("LC_SOURCE_VERSION");

                parent.getChildren().add(source_version_command);
            }else if(command.equals(Loader.LC_DYLIB_CODE_SIGN_DRS)) {
                parsedSomething = true;
                LOGGER.log(Level.INFO,"Parsing LC_DYLIB_CODE_SIGN_DRS");
                Loader.linkedit_ABI_command linkedit_data_command = new Loader.linkedit_ABI_command(parent);

                linkedit_data_command.setBeginAddress(pointer.clone());
                linkedit_data_command.cmd = B.getDWordAtAddressAndIncrement(parent.getRaw(), pointer, linkedit_data_command,AbstractData.Type.DATA_BYTE,  ByteOrder.LITTLE_ENDIAN);
                linkedit_data_command.cmdsize = B.getDWordAtAddressAndIncrement(parent.getRaw(), pointer, linkedit_data_command,AbstractData.Type.DATA_BYTE,ByteOrder.LITTLE_ENDIAN);
                linkedit_data_command.dataoff = B.getDWordAtAddressAndIncrement(parent.getRaw(), pointer, linkedit_data_command,AbstractData.Type.DATA_BYTE, ByteOrder.LITTLE_ENDIAN);
                linkedit_data_command.datasize =B.getDWordAtAddressAndIncrement(parent.getRaw(), pointer,linkedit_data_command, AbstractData.Type.DATA_BYTE, ByteOrder.LITTLE_ENDIAN);
                linkedit_data_command.setEndAddress(pointer.clone());
                linkedit_data_command.addComments("LC_DYLIB_CODE_SIGN_DRS");

                parent.getChildren().add(linkedit_data_command);
            }else if(command.equals(Loader.LC_VERSION_MIN_MACOSX)){
                parsedSomething = true;
                LOGGER.log(Level.INFO,"Parsing LC_VERSION_MIN_MACOSX");
                Loader.version_min_command version_min_command = new Loader.version_min_command(parent);

                version_min_command.setBeginAddress(pointer.clone());
                version_min_command.cmd = B.getDWordAtAddressAndIncrement(parent.getRaw(), pointer, version_min_command,AbstractData.Type.DATA_BYTE,ByteOrder.LITTLE_ENDIAN);
                version_min_command.cmdsize = B.getDWordAtAddressAndIncrement(parent.getRaw(), pointer, version_min_command,AbstractData.Type.DATA_BYTE,  ByteOrder.LITTLE_ENDIAN);
                version_min_command.version = B.getDWordAtAddressAndIncrement(parent.getRaw(), pointer, version_min_command,AbstractData.Type.DATA_BYTE,  ByteOrder.LITTLE_ENDIAN);
                version_min_command.sdk = B.getDWordAtAddressAndIncrement(parent.getRaw(), pointer,version_min_command, AbstractData.Type.DATA_BYTE,ByteOrder.LITTLE_ENDIAN);
                version_min_command.setEndAddress(pointer.clone());
                version_min_command.addComments("LC_VERSION_MIN_MACOSX");

                parent.getChildren().add(version_min_command);
            }else if (command.equals(Loader.LC_REQ_DYLD)) {
                parsedSomething = true;
                LOGGER.log(Level.INFO,"Parsing LC_REQ_DYLD");
                Loader.load_command load_command = new Loader.load_command(parent);

                load_command.setBeginAddress(pointer.clone());
                LOGGER.log(Level.SEVERE,"\tNOT YET IMPLEMENTED");
                pointer.add(8);
                load_command.setEndAddress(pointer.clone());
                load_command.addComments("LC_REQ_DYLD");

                parent.getChildren().add(load_command);
            }else if(command.equals(Loader.LC_DYLD_INFO_ONLY)){
                parsedSomething = true;
                LOGGER.log(Level.INFO,"Parsing LC_DYLD_INFO_ONLY");
                Loader.dyld_info_command dyld_info_command = new Loader.dyld_info_command(parent);

                dyld_info_command.setBeginAddress(pointer.clone());
                dyld_info_command.cmd = B.getDWordAtAddressAndIncrement(parent.getRaw(), pointer,dyld_info_command, AbstractData.Type.DATA_BYTE, ByteOrder.LITTLE_ENDIAN);
                dyld_info_command.cmdsize = B.getDWordAtAddressAndIncrement(parent.getRaw(), pointer,dyld_info_command, AbstractData.Type.DATA_BYTE,  ByteOrder.LITTLE_ENDIAN);
                dyld_info_command.rebase_off = B.getDWordAtAddressAndIncrement(parent.getRaw(), pointer,dyld_info_command, AbstractData.Type.DATA_BYTE,  ByteOrder.LITTLE_ENDIAN);
                dyld_info_command.rebase_size = B.getDWordAtAddressAndIncrement(parent.getRaw(), pointer,dyld_info_command, AbstractData.Type.DATA_BYTE,  ByteOrder.LITTLE_ENDIAN);
                dyld_info_command.bind_off = B.getDWordAtAddressAndIncrement(parent.getRaw(), pointer, dyld_info_command,AbstractData.Type.DATA_BYTE,  ByteOrder.LITTLE_ENDIAN);
                dyld_info_command.bind_size = B.getDWordAtAddressAndIncrement(parent.getRaw(), pointer, dyld_info_command,AbstractData.Type.DATA_BYTE,  ByteOrder.LITTLE_ENDIAN);
                dyld_info_command.weak_bind_off = B.getDWordAtAddressAndIncrement(parent.getRaw(), pointer,dyld_info_command, AbstractData.Type.DATA_BYTE,  ByteOrder.LITTLE_ENDIAN);
                dyld_info_command.weak_bind_size = B.getDWordAtAddressAndIncrement(parent.getRaw(), pointer,dyld_info_command, AbstractData.Type.DATA_BYTE,  ByteOrder.LITTLE_ENDIAN);
                dyld_info_command.lazy_bind_off = B.getDWordAtAddressAndIncrement(parent.getRaw(), pointer, dyld_info_command,AbstractData.Type.DATA_BYTE,  ByteOrder.LITTLE_ENDIAN);
                dyld_info_command.lazy_bind_size = B.getDWordAtAddressAndIncrement(parent.getRaw(), pointer,dyld_info_command, AbstractData.Type.DATA_BYTE,  ByteOrder.LITTLE_ENDIAN);
                dyld_info_command.export_off = B.getDWordAtAddressAndIncrement(parent.getRaw(), pointer, dyld_info_command,AbstractData.Type.DATA_BYTE,  ByteOrder.LITTLE_ENDIAN);
                dyld_info_command.export_size = B.getDWordAtAddressAndIncrement(parent.getRaw(), pointer, dyld_info_command,AbstractData.Type.DATA_BYTE, ByteOrder.LITTLE_ENDIAN);
                dyld_info_command.setEndAddress(pointer.clone());
                dyld_info_command.addComments("LC_DYLD_INFO_ONLY");

                parent.getChildren().add(dyld_info_command);
            }else if(command.equals(Loader.LC_REEXPORT_DYLIB)){
                parsedSomething = true;
                LOGGER.log(Level.INFO,"Parsing LC_REEXPORT_DYLIB");
                Loader.dylinker_command dylinker_command = new Loader.dylinker_command(parent);

                dylinker_command.setBeginAddress(pointer.clone());
                LOGGER.log(Level.SEVERE,"\tNOT YET IMPLEMENTED");
                dylinker_command.setEndAddress(pointer.clone());
                dylinker_command.addComments("LC_REEXPORT_DYLIB");

                parent.getChildren().add(dylinker_command);
            }else if(command.equals(Loader.LC_RPATH)){
                parsedSomething = true;
                LOGGER.log(Level.INFO,"Parsing LC_RPATH");
                Loader.rpath_command rpath_command = new Loader.rpath_command(parent);

                rpath_command.setBeginAddress(pointer.clone());
                LOGGER.log(Level.SEVERE,"\tNOT YET IMPLEMENTED");
                rpath_command.setEndAddress(pointer.clone());
                rpath_command.addComments("LC_RPATH");

                parent.getChildren().add(rpath_command);
            }else if(command.equals(Loader.LC_LOAD_WEAK_DYLIB)){
                parsedSomething = true;
                LOGGER.log(Level.INFO,"Parsing LC_LOAD_WEAK_DYLIB");
                Loader.load_command load_command = new Loader.load_command(parent);

                load_command.setBeginAddress(pointer.clone());
                LOGGER.log(Level.SEVERE,"\tNOT YET IMPLEMENTED");
                load_command.setEndAddress(pointer.clone());
                load_command.addComments("LC_LOAD_WEAK_DYLIB");

                parent.getChildren().add(load_command);
            }else if (command.equals(Loader.LC_SEGMENT)){
                parsedSomething = true;
                LOGGER.log(Level.INFO,"Parsing LC_SEGMENT");
                Loader.segment_command segment_command = new Loader.segment_command(parent);

                segment_command.setBeginAddress(pointer.clone());
                LOGGER.log(Level.SEVERE,"\tNOT YET IMPLEMENTED");
                segment_command.setEndAddress(pointer.clone());
                segment_command.addComments("LC_SEGMENT");

                parent.getChildren().add(segment_command);

            }else if (command.equals(Loader.LC_SYMTAB)) {
                parsedSomething = true;
                LOGGER.log(Level.INFO,"Parsing LC_SYMTAB");
                Loader.symtab_command symtab_command = new Loader.symtab_command(parent);

                symtab_command.setBeginAddress(pointer.clone());
                symtab_command.cmd = B.getDWordAtAddressAndIncrement(parent.getRaw(), pointer, symtab_command,AbstractData.Type.DATA_BYTE, ByteOrder.LITTLE_ENDIAN);
                symtab_command.cmdsize = B.getDWordAtAddressAndIncrement(parent.getRaw(), pointer, symtab_command,AbstractData.Type.DATA_BYTE, ByteOrder.LITTLE_ENDIAN);
                symtab_command.symoff = B.getDWordAtAddressAndIncrement(parent.getRaw(), pointer, symtab_command,AbstractData.Type.DATA_BYTE, ByteOrder.LITTLE_ENDIAN);
                symtab_command.nsyms = B.getDWordAtAddressAndIncrement(parent.getRaw(), pointer, symtab_command,AbstractData.Type.DATA_BYTE, ByteOrder.LITTLE_ENDIAN);
                symtab_command.stroff = B.getDWordAtAddressAndIncrement(parent.getRaw(), pointer, symtab_command,AbstractData.Type.DATA_BYTE, ByteOrder.LITTLE_ENDIAN);
                symtab_command.strsize = B.getDWordAtAddressAndIncrement(parent.getRaw(), pointer, symtab_command,AbstractData.Type.DATA_BYTE, ByteOrder.LITTLE_ENDIAN);
                symtab_command.setEndAddress(pointer.clone());
                symtab_command.addComments("LC_SYMTAB");

                parent.getChildren().add(symtab_command);
            } else if (command.equals(Loader.LC_SYMSEG)) {
                parsedSomething = true;
                LOGGER.log(Level.INFO,"Parsing LC_SYMSEG");
                Loader.symseg_command symseg_command = new Loader.symseg_command(parent);

                symseg_command.setBeginAddress(pointer.clone());
                LOGGER.log(Level.SEVERE,"\tNOT YET IMPLEMENTED");
                symseg_command.setEndAddress(pointer.clone());
                symseg_command.addComments("LC_SYMSEG");

                parent.getChildren().add(symseg_command);
                
            } else if (command.equals(Loader.LC_THREAD)) {
                parsedSomething = true;
                LOGGER.log(Level.INFO,"Parsing LC_THREAD");
                Loader.thread_command thread_command = new Loader.thread_command(parent);

                thread_command.setBeginAddress(pointer.clone());
                LOGGER.log(Level.SEVERE,"\tNOT YET IMPLEMENTED");
                thread_command.setEndAddress(pointer.clone());
                thread_command.addComments("LC_THREAD");

                parent.getChildren().add(thread_command);
                
            } else if (command.equals(Loader.LC_UNIXTHREAD)) {
                parsedSomething = true;
                LOGGER.log(Level.INFO,"Parsing LC_UNIXTHREAD");
                Loader.thread_command unix_thread_command = new Loader.thread_command(parent);

                unix_thread_command.setBeginAddress(pointer.clone());
                LOGGER.log(Level.SEVERE,"\tNOT YET IMPLEMENTED");
                unix_thread_command.setEndAddress(pointer.clone());
                unix_thread_command.addComments("LC_UNIXTHREAD");

                parent.getChildren().add(unix_thread_command);
                
            } else if (command.equals(Loader.LC_LOADFVMLIB)) {
                parsedSomething = true;
                LOGGER.log(Level.INFO,"Parsing LC_LOADFVMLIB");
                Loader.fvmlib_command fvmlib_command = new Loader.fvmlib_command(parent);

                fvmlib_command.setBeginAddress(pointer.clone());
                LOGGER.log(Level.SEVERE,"\tNOT YET IMPLEMENTED");
                fvmlib_command.setEndAddress(pointer.clone());
                fvmlib_command.addComments("LC_LOADFVMLIB");

                parent.getChildren().add(fvmlib_command);
                
            } else if (command.equals(Loader.LC_IDFVMLIB)) {
                parsedSomething = true;
                LOGGER.log(Level.INFO,"Parsing LC_IDFVMLIB");
                Loader.fvmlib_command fvmlib_command1 = new Loader.fvmlib_command(parent);

                fvmlib_command1.setBeginAddress(pointer.clone());
                LOGGER.log(Level.SEVERE,"\tNOT YET IMPLEMENTED");
                fvmlib_command1.setEndAddress(pointer.clone());
                fvmlib_command1.addComments("LC_IDFVMLIB");

                parent.getChildren().add(fvmlib_command1);
                
            } else if (command.equals(Loader.LC_IDENT)) {
                parsedSomething = true;
                LOGGER.log(Level.INFO,"Parsing LC_IDENT");
                Loader.ident_command ident_command = new Loader.ident_command(parent);

                ident_command.setBeginAddress(pointer.clone());
                LOGGER.log(Level.SEVERE,"\tNOT YET IMPLEMENTED");
                ident_command.setEndAddress(pointer.clone());
                ident_command.addComments("LC_IDENT");

                parent.getChildren().add(ident_command);
                
            } else if (command.equals(Loader.LC_FVMFILE)) {
                parsedSomething = true;
                LOGGER.log(Level.INFO,"Parsing LC_FVMFILE");
                Loader.fvmfile_command fvmfile_command = new Loader.fvmfile_command(parent);

                fvmfile_command.setBeginAddress(pointer.clone());
                LOGGER.log(Level.SEVERE,"\tNOT YET IMPLEMENTED");
                fvmfile_command.setEndAddress(pointer.clone());
                fvmfile_command.addComments("LC_FVMFILE");

                parent.getChildren().add(fvmfile_command);
                
            } else if (command.equals(Loader.LC_PREPAGE)) {
                parsedSomething = true;
                LOGGER.log(Level.SEVERE,"Unknow parse command LC_PREPAGE");
                
            } else if (command.equals(Loader.LC_DYSYMTAB)) {
                parsedSomething = true;
                LOGGER.log(Level.INFO,"Parsing LC_DYSYMTAB");
                Loader.dysymtab_command dysymtab_command = new Loader.dysymtab_command(parent);

                dysymtab_command.setBeginAddress(pointer.clone());
                dysymtab_command.cmd = B.getDWordAtAddressAndIncrement(parent.getRaw(), pointer, dysymtab_command,AbstractData.Type.DATA_BYTE, ByteOrder.LITTLE_ENDIAN);
                dysymtab_command.cmdsize = B.getDWordAtAddressAndIncrement(parent.getRaw(), pointer, dysymtab_command,AbstractData.Type.DATA_BYTE, ByteOrder.LITTLE_ENDIAN);
                dysymtab_command.ilocalsym = B.getDWordAtAddressAndIncrement(parent.getRaw(), pointer, dysymtab_command,AbstractData.Type.DATA_BYTE, ByteOrder.LITTLE_ENDIAN);
                dysymtab_command.nlocalsym = B.getDWordAtAddressAndIncrement(parent.getRaw(), pointer, dysymtab_command,AbstractData.Type.DATA_BYTE, ByteOrder.LITTLE_ENDIAN);
                dysymtab_command.iextdefsym = B.getDWordAtAddressAndIncrement(parent.getRaw(), pointer, dysymtab_command,AbstractData.Type.DATA_BYTE, ByteOrder.LITTLE_ENDIAN);
                dysymtab_command.nextdefsym = B.getDWordAtAddressAndIncrement(parent.getRaw(), pointer, dysymtab_command,AbstractData.Type.DATA_BYTE, ByteOrder.LITTLE_ENDIAN);
                dysymtab_command.iundefsym = B.getDWordAtAddressAndIncrement(parent.getRaw(), pointer, dysymtab_command,AbstractData.Type.DATA_BYTE, ByteOrder.LITTLE_ENDIAN);
                dysymtab_command.nundefsym = B.getDWordAtAddressAndIncrement(parent.getRaw(), pointer, dysymtab_command,AbstractData.Type.DATA_BYTE, ByteOrder.LITTLE_ENDIAN);
                dysymtab_command.tocoff = B.getDWordAtAddressAndIncrement(parent.getRaw(), pointer, dysymtab_command,AbstractData.Type.DATA_BYTE, ByteOrder.LITTLE_ENDIAN);
                dysymtab_command.ntoc = B.getDWordAtAddressAndIncrement(parent.getRaw(), pointer,dysymtab_command, AbstractData.Type.DATA_BYTE, ByteOrder.LITTLE_ENDIAN);
                dysymtab_command.modtaboff = B.getDWordAtAddressAndIncrement(parent.getRaw(), pointer, dysymtab_command,AbstractData.Type.DATA_BYTE, ByteOrder.LITTLE_ENDIAN);
                dysymtab_command.nmodtab = B.getDWordAtAddressAndIncrement(parent.getRaw(), pointer, dysymtab_command,AbstractData.Type.DATA_BYTE, ByteOrder.LITTLE_ENDIAN);
                dysymtab_command.extrefsymoff = B.getDWordAtAddressAndIncrement(parent.getRaw(), pointer, dysymtab_command,AbstractData.Type.DATA_BYTE, ByteOrder.LITTLE_ENDIAN);
                dysymtab_command.nextrefsyms = B.getDWordAtAddressAndIncrement(parent.getRaw(), pointer,dysymtab_command, AbstractData.Type.DATA_BYTE, ByteOrder.LITTLE_ENDIAN);
                dysymtab_command.indirectsymoff = B.getDWordAtAddressAndIncrement(parent.getRaw(), pointer, dysymtab_command,AbstractData.Type.DATA_BYTE, ByteOrder.LITTLE_ENDIAN);
                dysymtab_command.nindirectsyms = B.getDWordAtAddressAndIncrement(parent.getRaw(), pointer,dysymtab_command, AbstractData.Type.DATA_BYTE, ByteOrder.LITTLE_ENDIAN);
                dysymtab_command.extreloff = B.getDWordAtAddressAndIncrement(parent.getRaw(), pointer, dysymtab_command,AbstractData.Type.DATA_BYTE, ByteOrder.LITTLE_ENDIAN);
                dysymtab_command.nextrel = B.getDWordAtAddressAndIncrement(parent.getRaw(), pointer, dysymtab_command,AbstractData.Type.DATA_BYTE, ByteOrder.LITTLE_ENDIAN);
                dysymtab_command.locreloff = B.getDWordAtAddressAndIncrement(parent.getRaw(), pointer, dysymtab_command,AbstractData.Type.DATA_BYTE, ByteOrder.LITTLE_ENDIAN);
                dysymtab_command.nlocrel = B.getDWordAtAddressAndIncrement(parent.getRaw(), pointer,dysymtab_command, AbstractData.Type.DATA_BYTE, ByteOrder.LITTLE_ENDIAN);
                dysymtab_command.setEndAddress(pointer.clone());
                dysymtab_command.addComments("LC_DYSYMTAB");

                parent.getChildren().add(dysymtab_command);
            } else if (command.equals(Loader.LC_LOAD_DYLIB)) {
                parsedSomething = true;
                LOGGER.log(Level.INFO,"Parsing LC_LOAD_DYLIB");
                Loader.dylib_command dylib_command = new Loader.dylib_command(parent);

                dylib_command.setBeginAddress(pointer.clone());
                dylib_command.cmd = B.getDWordAtAddressAndIncrement(parent.getRaw(), pointer,dylib_command, AbstractData.Type.DATA_BYTE, ByteOrder.LITTLE_ENDIAN);
                dylib_command.cmdsize = B.getDWordAtAddressAndIncrement(parent.getRaw(), pointer,dylib_command, AbstractData.Type.DATA_BYTE, ByteOrder.LITTLE_ENDIAN);

                Address32 end =  (Address32)dylib_command.getBeginAddress().clone();
                end.add(dylib_command.cmdsize);

                dylib_command.dylib = getDylib(parent, pointer, dylib_command,dylib_command);
                dylib_command.getChildren().add(dylib_command.dylib);
                dylib_command.setEndAddress(end.clone());
                dylib_command.addComments("LC_LOAD_DYLIB");
                pointer = end;

                parent.getChildren().add(dylib_command);
            } else if (command.equals(Loader.LC_ID_DYLIB)) {
                parsedSomething = true;
                LOGGER.log(Level.INFO,"Parsing LC_ID_DYLIB");
                Loader.dylib_command dylib_command = new Loader.dylib_command(parent);

                dylib_command.setBeginAddress(pointer.clone());
                dylib_command.cmd=B.getDWordAtAddressAndIncrement(parent.getRaw(), pointer,dylib_command, AbstractData.Type.DATA_BYTE, ByteOrder.LITTLE_ENDIAN);
                dylib_command.cmdsize=B.getDWordAtAddressAndIncrement(parent.getRaw(), pointer,dylib_command, AbstractData.Type.DATA_BYTE, ByteOrder.LITTLE_ENDIAN);

                Address32 end =  (Address32)dylib_command.getBeginAddress().clone();
                end.add(dylib_command.cmdsize);

                dylib_command.dylib = getDylib(parent, pointer, dylib_command,dylib_command);
                dylib_command.getChildren().add(dylib_command.dylib);
                dylib_command.setEndAddress(end.clone());
                dylib_command.addComments("LC_ID_DYLIB");
                pointer = end;

                parent.getChildren().add(dylib_command);
            } else if (command.equals(Loader.LC_LOAD_DYLINKER)) {
                parsedSomething = true;
                LOGGER.log(Level.INFO,"Parseing LC_LOAD_DYLINKER");
                Loader.dylinker_command dylinker_command = new Loader.dylinker_command(parent);

                dylinker_command.setBeginAddress(pointer.clone());
                dylinker_command.cmd = B.getDWordAtAddressAndIncrement(parent.getRaw(), pointer,dylinker_command, AbstractData.Type.DATA_BYTE, ByteOrder.LITTLE_ENDIAN);
                dylinker_command.cmdsize = B.getDWordAtAddressAndIncrement(parent.getRaw(), pointer,dylinker_command, AbstractData.Type.DATA_BYTE, ByteOrder.LITTLE_ENDIAN);

                final AbstractAddress a = dylinker_command.getBeginAddress().clone();
                a.add(dylinker_command.cmdsize);
                dylinker_command.setEndAddress(a);

                Loader.lc_str lc_str = new Loader.lc_str(dylinker_command);
                lc_str.offset = B.getDWordAtAddressAndIncrement(parent.getRaw(), pointer,lc_str, AbstractData.Type.DATA_BYTE, ByteOrder.LITTLE_ENDIAN);
                lc_str.ptr = new Range(B.getRangeAtAddress(parent.getRaw(), pointer, dylinker_command.getEndAddress()),pointer.clone(), dylinker_command.getEndAddress().clone(),lc_str, AbstractData.Type.DATA_BYTE, ByteOrder.LITTLE_ENDIAN);

                dylinker_command.name=lc_str;
                dylinker_command.getChildren().add(dylinker_command.name);
                dylinker_command.addComments("LC_LOAD_DYLINKER");

                pointer = (Address32) dylinker_command.getEndAddress();

                parent.getChildren().add(dylinker_command);
                
            } else if (command.equals(Loader.LC_ID_DYLINKER)) {
                parsedSomething = true;
                LOGGER.log(Level.SEVERE,"Unknown parse command LC_ID_DYLINKER");

            } else if (command.equals(Loader.LC_PREBOUND_DYLIB)) {
                parsedSomething = true;
                LOGGER.log(Level.INFO,"Parsing LC_PREBOUND_DYLIB");
                Loader.prebound_dylib_command prebound_dylib_command = new Loader.prebound_dylib_command(parent);

                prebound_dylib_command.setBeginAddress(pointer.clone());
                LOGGER.log(Level.SEVERE,"\tNOT YET IMPLEMENTED");
                prebound_dylib_command.setEndAddress(pointer.clone());
                prebound_dylib_command.addComments("LC_PREBOUND_DYLIB");

                parent.getChildren().add(prebound_dylib_command);
                
            } else if (command.equals(Loader.LC_ROUTINES)) {
                parsedSomething = true;
                LOGGER.log(Level.INFO,"Parsing LC_ROUTINES");
                Loader.routines_command routines_command = new Loader.routines_command(parent);

                routines_command.setBeginAddress(pointer.clone());
                LOGGER.log(Level.SEVERE,"\tNOT YET IMPLEMENTED");
                routines_command.setEndAddress(pointer.clone());
                routines_command.addComments("LC_ROUTINES");

                parent.getChildren().add(routines_command);
                
            } else if (command.equals(Loader.LC_SUB_FRAMEWORK)) {
                parsedSomething = true;
                LOGGER.log(Level.INFO,"Parsing LC_SUB_FRAMEWORK");
                Loader.sub_framework_command sub_framework_command = new Loader.sub_framework_command(parent);

                sub_framework_command.setBeginAddress(pointer.clone());
                LOGGER.log(Level.SEVERE,"\tNOT YET IMPLEMENTED");
                sub_framework_command.setEndAddress(pointer.clone());
                sub_framework_command.addComments("LC_SUB_FRAMEWORK");

                parent.getChildren().add(sub_framework_command);
                
            } else if (command.equals(Loader.LC_SUB_UMBRELLA)) {
                parsedSomething = true;
                LOGGER.log(Level.INFO,"Parsing LC_SUB_UMBRELLA");
                Loader.sub_umbrella_command sub_umbrella_command = new Loader.sub_umbrella_command(parent);

                sub_umbrella_command.setBeginAddress(pointer.clone());
                LOGGER.log(Level.SEVERE,"\tNOT YET IMPLEMENTED");
                sub_umbrella_command.setEndAddress(pointer.clone());
                sub_umbrella_command.addComments("LC_SUB_UMBRELLA");

                parent.getChildren().add(sub_umbrella_command);
                
            } else if (command.equals(Loader.LC_SUB_CLIENT)) {
                parsedSomething = true;
                LOGGER.log(Level.INFO,"Parsing LC_SUB_CLIENT");
                Loader.sub_client_command sub_client_command = new Loader.sub_client_command(parent);

                sub_client_command.setBeginAddress(pointer.clone());
                LOGGER.log(Level.SEVERE,"\tNOT YET IMPLEMENTED");
                sub_client_command.setEndAddress(pointer.clone());
                sub_client_command.addComments("LC_SUB_CLIENT");

                parent.getChildren().add(sub_client_command);
                
            } else if (command.equals(Loader.LC_SUB_LIBRARY)) {
                parsedSomething = true;
                LOGGER.log(Level.INFO,"Parsing LC_SUB_LIBRARY");
                Loader.sub_library_command sub_library_command = new Loader.sub_library_command(parent);

                sub_library_command.setBeginAddress(pointer.clone());
                LOGGER.log(Level.SEVERE,"\tNOT YET IMPLEMENTED");
                sub_library_command.setEndAddress(pointer.clone());
                sub_library_command.addComments("LC_SUB_LIBRARY");

                parent.getChildren().add(sub_library_command);
                
            } else if (command.equals(Loader.LC_TWOLEVEL_HINTS)) {
                parsedSomething = true;
                LOGGER.log(Level.INFO,"Parsing LC_TWOLEVEL_HINTS");
                Loader.twolevel_hints_command twolevel_hints_command = new Loader.twolevel_hints_command(parent);

                twolevel_hints_command.setBeginAddress(pointer.clone());
                LOGGER.log(Level.SEVERE,"\tNOT YET IMPLEMENTED");
                twolevel_hints_command.setEndAddress(pointer.clone());
                twolevel_hints_command.addComments("LC_TWOLEVEL_HINTS");

                parent.getChildren().add(twolevel_hints_command);
                
            } else if (command.equals(Loader.LC_PREBIND_CKSUM)) {
                parsedSomething = true;
                LOGGER.log(Level.INFO,"Parsing LC_PREBIND_CKSUM");
                Loader.prebind_cksum_command prebind_cksum_command = new Loader.prebind_cksum_command(parent);

                prebind_cksum_command.setBeginAddress(pointer.clone());
                LOGGER.log(Level.SEVERE,"\tNOT YET IMPLEMENTED");
                prebind_cksum_command.setEndAddress(pointer.clone());
                prebind_cksum_command.addComments("LC_PREBIND_CKSUM");

                parent.getChildren().add(prebind_cksum_command);
                
            } else if (command.equals(Loader.LC_SEGMENT_64)) {
                parsedSomething = true;
                LOGGER.log(Level.INFO,"Parsing LC_SEGMENT_64");
                Loader.segment_command_64 segment_command_641 = new Loader.segment_command_64(parent);

                segment_command_641.setBeginAddress(pointer.clone());
                segment_command_641.cmd = B.getDWordAtAddressAndIncrement(parent.getRaw(), pointer,segment_command_641, AbstractData.Type.DATA_BYTE, ByteOrder.LITTLE_ENDIAN);
                segment_command_641.cmdsize = B.getDWordAtAddressAndIncrement(parent.getRaw(), pointer,segment_command_641, AbstractData.Type.DATA_BYTE, ByteOrder.LITTLE_ENDIAN);
                AbstractAddress begin = pointer.clone();
                final byte[] container = B.getQWordAtAddressAndIncrement(parent.getRaw(), pointer,segment_command_641, AbstractData.Type.DATA_BYTE, ByteOrder.LITTLE_ENDIAN).getContainer();
                final byte[] container2 = B.getQWordAtAddressAndIncrement(parent.getRaw(), pointer,segment_command_641, AbstractData.Type.DATA_BYTE, ByteOrder.LITTLE_ENDIAN).getContainer();
                segment_command_641.segname = new Loader.char16(B.mergeBytes(container, container2),segment_command_641, AbstractData.Type.DATA_CHAR,ByteOrder.LITTLE_ENDIAN);
                segment_command_641.segname.setBeginAddress(begin);
                segment_command_641.segname.setEndAddress(pointer.clone());
                segment_command_641.vmaddr = B.getQWordAtAddressAndIncrement(parent.getRaw(), pointer,segment_command_641, AbstractData.Type.DATA_BYTE, ByteOrder.LITTLE_ENDIAN);
                segment_command_641.vmsize = B.getQWordAtAddressAndIncrement(parent.getRaw(), pointer,segment_command_641, AbstractData.Type.DATA_BYTE, ByteOrder.LITTLE_ENDIAN);
                segment_command_641.fileoff = B.getQWordAtAddressAndIncrement(parent.getRaw(), pointer,segment_command_641, AbstractData.Type.DATA_BYTE, ByteOrder.LITTLE_ENDIAN);
                segment_command_641.filesize = B.getQWordAtAddressAndIncrement(parent.getRaw(), pointer,segment_command_641, AbstractData.Type.DATA_BYTE, ByteOrder.LITTLE_ENDIAN);
                segment_command_641.maxprot = B.getDWordAtAddressAndIncrement(parent.getRaw(), pointer,segment_command_641, AbstractData.Type.DATA_BYTE, ByteOrder.LITTLE_ENDIAN);
                segment_command_641.initprot = B.getDWordAtAddressAndIncrement(parent.getRaw(), pointer,segment_command_641, AbstractData.Type.DATA_BYTE, ByteOrder.LITTLE_ENDIAN);
                segment_command_641.nsects = B.getDWordAtAddressAndIncrement(parent.getRaw(), pointer,segment_command_641, AbstractData.Type.DATA_BYTE, ByteOrder.LITTLE_ENDIAN);
                segment_command_641.flags = B.getDWordAtAddressAndIncrement(parent.getRaw(), pointer,segment_command_641, AbstractData.Type.DATA_BYTE, ByteOrder.LITTLE_ENDIAN);

                final int sections = segment_command_641.nsects.getIntValue();
                for (int i = 0; i < sections; i++) {
                    LOGGER.log(Level.INFO,"Parsing section {0} for segment {1}",new Object[]{i,segment_command_641.segname.value});
                    segment_command_641.getChildren().add(ParseSegSec64.parse(parent, pointer, segment_command_641));
                }
                segment_command_641.setEndAddress(pointer.clone());
                segment_command_641.addComments("LC_SEGMENT_64");

                parent.getChildren().add(segment_command_641);
                
            } else if (command.equals(Loader.LC_ROUTINES_64)) {
                parsedSomething = true;
                LOGGER.log(Level.INFO,"Parsing LC_ROUTINES_64");
                Loader.routines_command_64 routines_command_64 = new Loader.routines_command_64(parent);

                routines_command_64.setBeginAddress(pointer.clone());
                LOGGER.log(Level.SEVERE,"\tNOT YET IMPLEMENTED");
                routines_command_64.setEndAddress(pointer.clone());
                routines_command_64.addComments("LC_ROUTINES_64");

                parent.getChildren().add(routines_command_64);
                
            } else if (command.equals(Loader.LC_UUID)) {
                parsedSomething = true;
                LOGGER.log(Level.INFO,"Parsing LC_UUID");
                Loader.uuid_command uuid_command = new Loader.uuid_command(parent);

                uuid_command.setBeginAddress(pointer.clone());
                uuid_command.cmd = B.getDWordAtAddressAndIncrement(parent.getRaw(), pointer,uuid_command, AbstractData.Type.DATA_BYTE, ByteOrder.LITTLE_ENDIAN);;
                uuid_command.cmdsize = B.getDWordAtAddressAndIncrement(parent.getRaw(), pointer,uuid_command, AbstractData.Type.DATA_BYTE, ByteOrder.LITTLE_ENDIAN);
                AbstractAddress begin = pointer.clone();
                byte[] tmp1 = B.getQWordAtAddressAndIncrement(parent.getRaw(), pointer,uuid_command, AbstractData.Type.DATA_BYTE, ByteOrder.LITTLE_ENDIAN).getContainer();
                byte[] tmp2 = B.getQWordAtAddressAndIncrement(parent.getRaw(), pointer,uuid_command, AbstractData.Type.DATA_BYTE, ByteOrder.LITTLE_ENDIAN).getContainer();
                uuid_command.uuid = new Loader.char16(B.mergeBytes(tmp1,tmp2),uuid_command, AbstractData.Type.DATA_CHAR,ByteOrder.LITTLE_ENDIAN);
                uuid_command.uuid.setBeginAddress(begin);
                uuid_command.uuid.setEndAddress(pointer.clone());
                uuid_command.setEndAddress(pointer.clone());
                uuid_command.addComments("LC_UUID");

                parent.getChildren().add(uuid_command);
                
            } else if (command.equals(Loader.LC_CODE_SIGNATURE)) {
                parsedSomething = true;
                LOGGER.log(Level.INFO,"Parsing LC_CODE_SIGNATURE");
                Loader.linkedit_ABI_command linkedit_data_command = new Loader.linkedit_ABI_command(parent);

                linkedit_data_command.setBeginAddress(pointer.clone());
                LOGGER.log(Level.SEVERE,"\tNOT YET IMPLEMENTED");
                linkedit_data_command.setEndAddress(pointer.clone());
                linkedit_data_command.addComments("LC_CODE_SIGNATURE");

                parent.getChildren().add(linkedit_data_command);
            } else if (command.equals(Loader.LC_SEGMENT_SPLIT_INFO)) {
                parsedSomething = true;
                LOGGER.log(Level.INFO,"Parsing LC_SEGMENT_SPLIT_INFO");
                Loader.dyld_info_command dyld_info_command = new Loader.dyld_info_command(parent);

                dyld_info_command.setBeginAddress(pointer.clone());
                LOGGER.log(Level.SEVERE,"\tNOT YET IMPLEMENTED");
                dyld_info_command.setEndAddress(pointer.clone());
                dyld_info_command.addComments("LC_SEGMENT_SPLIT_INFO");

                parent.getChildren().add(dyld_info_command);
                
            } else if (command.equals(Loader.LC_LAZY_LOAD_DYLIB)) {
                parsedSomething = true;
                LOGGER.log(Level.INFO,"Parsing LC_LAZY_LOAD_DYLIB");
                Loader.load_command load_command = new Loader.load_command(parent);

                load_command.setBeginAddress(pointer.clone());
                LOGGER.log(Level.SEVERE,"\tNOT YET IMPLEMENTED");
                load_command.setEndAddress(pointer.clone());
                load_command.addComments("LC_LAZY_LOAD_DYLIB");

                parent.getChildren().add(load_command);
                
            } else if (command.equals(Loader.LC_ENCRYPTION_INFO)) {
                parsedSomething = true;
                LOGGER.log(Level.INFO,"Parsing LC_ENCRYPTION_INFO");
                Loader.encryption_info_command encryption_info_command = new Loader.encryption_info_command(parent);

                encryption_info_command.setBeginAddress(pointer.clone());
                LOGGER.log(Level.SEVERE,"\tNOT YET IMPLEMENTED");
                encryption_info_command.setEndAddress(pointer.clone());
                encryption_info_command.addComments("LC_ENCRYPTION_INFO");

                parent.getChildren().add(encryption_info_command);
            } else if (command.equals(Loader.LC_DYLD_INFO)) {
                parsedSomething = true;
                LOGGER.log(Level.INFO,"Parsing LC_DYLD_INFO");
                Loader.dyld_info_command dyld_info_command1 = new Loader.dyld_info_command(parent);

                dyld_info_command1.setBeginAddress(pointer.clone());
                dyld_info_command1.cmd = B.getDWordAtAddressAndIncrement(parent.getRaw(), pointer,dyld_info_command1, AbstractData.Type.DATA_BYTE, ByteOrder.LITTLE_ENDIAN);
                dyld_info_command1.cmdsize = B.getDWordAtAddressAndIncrement(parent.getRaw(), pointer, dyld_info_command1,AbstractData.Type.DATA_BYTE, ByteOrder.LITTLE_ENDIAN);
                dyld_info_command1.rebase_off = B.getDWordAtAddressAndIncrement(parent.getRaw(), pointer, dyld_info_command1,AbstractData.Type.DATA_BYTE, ByteOrder.LITTLE_ENDIAN);
                dyld_info_command1.rebase_size = B.getDWordAtAddressAndIncrement(parent.getRaw(), pointer, dyld_info_command1,AbstractData.Type.DATA_BYTE, ByteOrder.LITTLE_ENDIAN);
                dyld_info_command1.bind_off = B.getDWordAtAddressAndIncrement(parent.getRaw(), pointer, dyld_info_command1,AbstractData.Type.DATA_BYTE, ByteOrder.LITTLE_ENDIAN);
                dyld_info_command1.bind_size = B.getDWordAtAddressAndIncrement(parent.getRaw(), pointer, dyld_info_command1,AbstractData.Type.DATA_BYTE, ByteOrder.LITTLE_ENDIAN);
                dyld_info_command1.weak_bind_off = B.getDWordAtAddressAndIncrement(parent.getRaw(), pointer, dyld_info_command1,AbstractData.Type.DATA_BYTE, ByteOrder.LITTLE_ENDIAN);
                dyld_info_command1.weak_bind_size = B.getDWordAtAddressAndIncrement(parent.getRaw(), pointer, dyld_info_command1,AbstractData.Type.DATA_BYTE, ByteOrder.LITTLE_ENDIAN);
                dyld_info_command1.lazy_bind_off = B.getDWordAtAddressAndIncrement(parent.getRaw(), pointer, dyld_info_command1,AbstractData.Type.DATA_BYTE, ByteOrder.LITTLE_ENDIAN);
                dyld_info_command1.lazy_bind_size = B.getDWordAtAddressAndIncrement(parent.getRaw(), pointer, dyld_info_command1,AbstractData.Type.DATA_BYTE, ByteOrder.LITTLE_ENDIAN);
                dyld_info_command1.export_off = B.getDWordAtAddressAndIncrement(parent.getRaw(), pointer, dyld_info_command1,AbstractData.Type.DATA_BYTE, ByteOrder.LITTLE_ENDIAN);
                dyld_info_command1.export_size = B.getDWordAtAddressAndIncrement(parent.getRaw(), pointer, dyld_info_command1,AbstractData.Type.DATA_BYTE, ByteOrder.LITTLE_ENDIAN);
                dyld_info_command1.setEndAddress(pointer.clone());
                dyld_info_command1.addComments("LC_DYLD_INFO");

                parent.getChildren().add(dyld_info_command1);
            }

            if(parsedSomething == false){
                LOGGER.log(Level.SEVERE,"Unable to parse load command: "+command.toString());
                //throw new Exception("Unknown Load Command: "+command.toString());
            }
        }
    }

    private static Loader.dylib getDylib(MachO64 in, Address32 pointer, Loader.dylib_command dylib_command,IStructure parent) {
        Loader.dylib l = new Loader.dylib(parent);
        Loader.lc_str lcstr = new Loader.lc_str(l);

        lcstr.offset = B.getDWordAtAddressAndIncrement(in.getRaw(), pointer,lcstr, AbstractData.Type.DATA_BYTE, ByteOrder.LITTLE_ENDIAN);

        Address32 begin = (Address32)dylib_command.getBeginAddress().clone();
        begin.add(lcstr.offset);

        Address32 end =  (Address32)dylib_command.getBeginAddress().clone();
        end.add(dylib_command.cmdsize);

        lcstr.ptr = new Range(B.getRangeAtAddress(in.getRaw(), begin, end),begin,end,lcstr, AbstractData.Type.DATA_BYTE, ByteOrder.LITTLE_ENDIAN);

        l.timestamp = B.getDWordAtAddressAndIncrement(in.getRaw(), pointer,l, AbstractData.Type.DATA_BYTE, ByteOrder.LITTLE_ENDIAN);
        l.current_version = B.getDWordAtAddressAndIncrement(in.getRaw(), pointer,l, AbstractData.Type.DATA_BYTE, ByteOrder.LITTLE_ENDIAN);
        l.compatibility_version = B.getDWordAtAddressAndIncrement(in.getRaw(), pointer,l, AbstractData.Type.DATA_BYTE, ByteOrder.LITTLE_ENDIAN);
        l.name = lcstr;
        l.getChildren().add(lcstr);
        return l;
    }

}
