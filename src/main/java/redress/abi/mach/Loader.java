package redress.abi.mach;

import redress.memory.struct.DataStructure;
import redress.memory.Addressable;
import redress.memory.Container;
import redress.memory.address.Address;
import redress.memory.address.Address32;
import redress.memory.data.*;

import java.nio.ByteOrder;
import java.util.Arrays;
import java.util.LinkedList;

public interface Loader {

    /*
     * Copyright (c) 1999-2010 Apple Inc.  All Rights Reserved.
     *
     * @APPLE_LICENSE_HEADER_START@
     *
     * This file contains Original Code and/or Modifications of Original Code
     * as defined in and that are subject to the Apple Public Source License
     * Version 2.0 (the 'License'). You may not use this file except in
     * compliance with the License. Please obtain a copy of the License at
     * http://www.opensource.apple.com/apsl/ and read it before using this
     * file.
     *
     * The Original Code and all software distributed under the License are
     * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
     * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
     * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
     * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
     * Please see the License for the specific language governing rights and
     * limitations under the License.
     *
     * @APPLE_LICENSE_HEADER_END@
     */
    //#ifndef _MACHO_LOADER_H_
    //public static final DWord _MACHO_LOADER_H_

    /*
     * This file describes the format of mach object files.
     */
    //#include <stdint.h>

    /*
     * <mach/machine.h> is needed here for the cpu_type_t and cpu_subtype_t types
     * and contains the constants for the possible values of these types.
     */
    //#include <mach/machine.h>

    /*
     * <mach/vm_prot.h> is needed here for the vm_prot_t type and contains the
     * constants that are or'ed together for the possible values of this type.
     */
    //#include <mach/vm_prot.h>

    /*
     * <machine/thread_status.h> is expected to define the flavors of the thread
     * states and the public classures of those flavors for each machine.
     */
    //#include <mach/machine/thread_status.h>
    //#include <architecture/byte_order.h>


    public class union {
        public byte[] value;
    }

    public class char16 extends Data {
        public char16() {
            super(0, Address32.NULL, Address32.NULL, ByteOrder.BIG_ENDIAN);
        }

        public char16(byte[] in, Address begin, Address end) {
            super(in.length, begin, end, ByteOrder.LITTLE_ENDIAN);
            for (int i = 0; i < in.length; i++) {
                container[i] = in[i];
            }
            this.value = new String(in);
        }

        public String value;

        @Override
        public Container flipByteOrder() {
            return null;
        }

        @Override
        public Type getDataType() {
            return Type.DATA_CHAR;
        }

        @Override
        public Data clone() {
            return null;
        }
    }

    /*
     * The 32-bit mach header appears at the very beginning of the object file for
     * 32-bit architectures.
     */
    public class mach_header extends DataStructure {
        public DWord magic = new DWord();
        public final static String magicComment = "/* mach magic number identifier */";
        public DWord cputype = new DWord();
        public final static String cputypeComment = "/* cpu specifier */";
        public DWord cpusubtype = new DWord();
        public final static String cpusubtypeComment = "/* machine specifier */";
        public DWord filetype = new DWord();
        public final static String filetypeComment = "/* type of file */";
        public DWord ncmds = new DWord();
        public final static String ncmdsComment = "/* number of load commands */";
        public DWord sizeofcmds = new DWord();
        public final static String sizeofcmdsComment = "/* the size of all the load commands */";
        public DWord flags = new DWord();
        public final static String flagsComment = "/* flags */";

        public mach_header(Addressable parent) {
            super(parent);
        }

        @Override
        public LinkedList<Data> getStructureData() {
            magic.setComment(magicComment);
            cputype.setComment(cputypeComment);
            cpusubtype.setComment(cpusubtypeComment);
            filetype.setComment(filetypeComment);
            ncmds.setComment(ncmdsComment);
            sizeofcmds.setComment(sizeofcmdsComment);
            flags.setComment(flagsComment);
            return new LinkedList<Data>(Arrays.asList(magic, cputype, cpusubtype, filetype, ncmds, sizeofcmds, flags));
        }
    }

    ;

    /* Constant for the magic field of the mach_header (32-bit architectures) */
    public static final DWord MH_MAGIC = new DWord("0xfeedface", Data.Type.DATA_BYTE,ByteOrder.BIG_ENDIAN);	/* the mach magic number */
    public static final DWord MH_CIGAM = new DWord("0xcefaedfe", Data.Type.DATA_BYTE,ByteOrder.BIG_ENDIAN);	/* NXSwapInt(MH_MAGIC) */

    /*
     * The 64-bit mach header appears at the very beginning of object files for
     * 64-bit architectures.
     */
    public class mach_header_64 extends DataStructure {
        public DWord magic = new DWord();
        public final static String magicComment = "/* mach magic number identifier */";
        public DWord cputype = new DWord();
        public final static String cputypeComment = "/* cpu specifier */";
        public DWord cpusubtype = new DWord();
        public final static String cpusubtypeComment = "/* machine specifier */";
        public DWord filetype = new DWord();
        public final static String filetypeComment = "/* type of file */";
        public DWord ncmds = new DWord();
        public final static String ncmdsComment = "/* number of load commands */";
        public DWord sizeofcmds = new DWord();
        public final static String sizeofcmdsComment = "/* the size of all the load commands */";
        public DWord flags = new DWord();
        public final static String flagsComment = "/* flags */";
        public DWord reserved = new DWord();
        public final static String reservedComment = "/* reserved */";

        public mach_header_64(Addressable parent) {
            super(parent);
        }

        @Override
        public LinkedList<Data> getStructureData() {
            magic.setComment(magicComment);
            cputype.setComment(cputypeComment);
            cpusubtype.setComment(cpusubtypeComment);
            filetype.setComment(filetypeComment);
            ncmds.setComment(ncmdsComment);
            sizeofcmds.setComment(sizeofcmdsComment);
            flags.setComment(flagsComment);
            reserved.setComment(reservedComment);
            return new LinkedList<>(Arrays.asList(magic,cputype,cpusubtype,filetype,ncmds,sizeofcmds,flags,reserved));
        }
    }

    ;

    /* Constant for the magic field of the mach_header_64 (64-bit architectures) */
    public static final DWord MH_MAGIC_64 = new DWord("0xfeedfacf", Data.Type.DATA_BYTE,ByteOrder.BIG_ENDIAN); /* the 64-bit mach magic number */
    public static final DWord MH_CIGAM_64 = new DWord("0xcffaedfe", Data.Type.DATA_BYTE,ByteOrder.BIG_ENDIAN); /* NXSwapInt(MH_MAGIC_64) */

    /*
     * The layout of the file depends on the filetype.  For all but the MH_OBJECT
     * file type the segments are padded out and aligned on a segment alignment
     * boundary for efficient demand pageing.  The MH_EXECUTE, MH_FVMLIB, MH_DYLIB,
     * MH_DYLINKER and MH_BUNDLE file types also have the headers included as part
     * of their first segment.
     *
     * The file type MH_OBJECT is a compact format intended as output of the
     * assembler and input (and possibly output) of the link editor (the .o
     * format).  All sections are in one unnamed segment with no segment padding.
     * This format is used as an executable format when the file is so small the
     * segment padding greatly increases its size.
     *
     * The file type MH_PRELOAD is an executable format intended for things that
     * are not executed under the kernel (proms, stand alones, kernels, etc).  The
     * format can be executed under the kernel but may demand paged it and not
     * preload it before execution.
     *
     * A core file is in MH_CORE format and can be any in an arbritray legal
     * Mach-O file.
     *
     * Constants for the filetype field of the mach_header
     */
    public static final DWord MH_OBJECT = new DWord("0x00000001", Data.Type.DATA_BYTE, ByteOrder.BIG_ENDIAN);		/* relocatable object file */
    public static final DWord MH_EXECUTE = new DWord("0x00000002", Data.Type.DATA_BYTE, ByteOrder.BIG_ENDIAN);		/* demand paged executable file */
    public static final DWord MH_FVMLIB = new DWord("0x00000003", Data.Type.DATA_BYTE, ByteOrder.BIG_ENDIAN);		/* fixed VM shared library file */
    public static final DWord MH_CORE = new DWord("0x00000004", Data.Type.DATA_BYTE, ByteOrder.BIG_ENDIAN);		/* core file */
    public static final DWord MH_PRELOAD = new DWord("0x00000005", Data.Type.DATA_BYTE, ByteOrder.BIG_ENDIAN);		/* preloaded executable file */
    public static final DWord MH_DYLIB = new DWord("0x00000006", Data.Type.DATA_BYTE, ByteOrder.BIG_ENDIAN);		/* dynamically bound shared library */
    public static final DWord MH_DYLINKER = new DWord("0x00000007", Data.Type.DATA_BYTE, ByteOrder.BIG_ENDIAN);		/* dynamic link editor */
    public static final DWord MH_BUNDLE = new DWord("0x00000008", Data.Type.DATA_BYTE, ByteOrder.BIG_ENDIAN);		/* dynamically bound bundle file */
    public static final DWord MH_DYLIB_STUB = new DWord("0x00000009", Data.Type.DATA_BYTE, ByteOrder.BIG_ENDIAN);		/* shared library stub for static */
    /*  linking only, no section contents */
    public static final DWord MH_DSYM = new DWord("0x0000000a", Data.Type.DATA_BYTE, ByteOrder.BIG_ENDIAN);		/* companion file with only debug */
    /*  sections */
    public static final DWord MH_KEXT_BUNDLE = new DWord("0x0000000b", Data.Type.DATA_BYTE, ByteOrder.BIG_ENDIAN);		/* x86_64 kexts */

    /* Constants for the flags field of the mach_header */
    public static final DWord MH_NOUNDEFS = new DWord("0x00000001", Data.Type.DATA_BYTE, ByteOrder.BIG_ENDIAN);		/* the object file has no undefined
                       references */
    public static final DWord MH_INCRLINK = new DWord("0x00000002", Data.Type.DATA_BYTE, ByteOrder.BIG_ENDIAN);		/* the object file is the output of an
					   incremental link against a base file
					   and can't be link edited again */
    public static final DWord MH_DYLDLINK = new DWord("0x00000004", Data.Type.DATA_BYTE, ByteOrder.BIG_ENDIAN);		/* the object file is input for the
					   dynamic linker and can't be staticly
					   link edited again */
    public static final DWord MH_BINDATLOAD = new DWord("0x00000008", Data.Type.DATA_BYTE, ByteOrder.BIG_ENDIAN);		/* the object file's undefined
					   references are bound by the dynamic
					   linker when loaded. */
    public static final DWord MH_PREBOUND = new DWord("0x00000010", Data.Type.DATA_BYTE, ByteOrder.BIG_ENDIAN);		/* the file has its dynamic undefined
					   references prebound. */
    public static final DWord MH_SPLIT_SEGS = new DWord("0x00000020", Data.Type.DATA_BYTE, ByteOrder.BIG_ENDIAN);		/* the file has its read-only and
					   read-write segments split */
    public static final DWord MH_LAZY_INIT = new DWord("0x00000040", Data.Type.DATA_BYTE, ByteOrder.BIG_ENDIAN);		/* the shared library init routine is
					   to be run lazily via catching memory
					   faults to its writeable segments
					   (obsolete) */
    public static final DWord MH_TWOLEVEL = new DWord("0x00000080", Data.Type.DATA_BYTE, ByteOrder.BIG_ENDIAN);		/* the image is using two-level name
					   space bindings */
    public static final DWord MH_FORCE_FLAT = new DWord("0x00000100", Data.Type.DATA_BYTE, ByteOrder.BIG_ENDIAN);		/* the executable is forcing all images
					   to use flat name space bindings */
    public static final DWord MH_NOMULTIDEFS = new DWord("0x00000200", Data.Type.DATA_BYTE, ByteOrder.BIG_ENDIAN);		/* this umbrella guarantees no multiple
					   defintions of symbols in its
					   sub-images so the two-level namespace
					   hints can always be used. */
    public static final DWord MH_NOFIXPREBINDING = new DWord("0x00000400", Data.Type.DATA_BYTE, ByteOrder.BIG_ENDIAN);	/* do not have dyld notify the
					   prebinding agent about this
					   executable */
    public static final DWord MH_PREBINDABLE = new DWord("0x00000800", Data.Type.DATA_BYTE, ByteOrder.BIG_ENDIAN);           /* the binary is not prebound but can
					   have its prebinding redone. only used
                                           when MH_PREBOUND is not set. */
    public static final DWord MH_ALLMODSBOUND = new DWord("0x00001000", Data.Type.DATA_BYTE, ByteOrder.BIG_ENDIAN);		/* indicates that this binary binds to
                                           all two-level namespace modules of
					   its dependent libraries. only used
					   when MH_PREBINDABLE and MH_TWOLEVEL
					   are both set. */
    public static final DWord MH_SUBSECTIONS_VIA_SYMBOLS = new DWord("0x00002000", Data.Type.DATA_BYTE, ByteOrder.BIG_ENDIAN);/* safe to divide up the sections into
					    sub-sections via symbols for dead
					    code stripping */
    public static final DWord MH_CANONICAL = new DWord("0x00004000", Data.Type.DATA_BYTE, ByteOrder.BIG_ENDIAN);		/* the binary has been canonicalized
					   via the unprebind operation */
    public static final DWord MH_WEAK_DEFINES = new DWord("0x00008000", Data.Type.DATA_BYTE, ByteOrder.BIG_ENDIAN);		/* the final linked image contains
					   external weak symbols */
    public static final DWord MH_BINDS_TO_WEAK = new DWord("0x00010000", Data.Type.DATA_BYTE, ByteOrder.BIG_ENDIAN);	/* the final linked image uses
					   weak symbols */

    public static final DWord MH_ALLOW_STACK_EXECUTION = new DWord("0x00020000", Data.Type.DATA_BYTE, ByteOrder.BIG_ENDIAN);/* When this bit is set, all stacks
					   in the task will be given stack
					   execution privilege.  Only used in
					   MH_EXECUTE filetypes. */
    public static final DWord MH_DEAD_STRIPPABLE_DYLIB = new DWord("0x00400000", Data.Type.DATA_BYTE, ByteOrder.BIG_ENDIAN); /* Only for use on dylibs.  When
					     linking against a dylib that
					     has this bit set, the static linker
					     will automatically not create a
					     LC_LOAD_DYLIB load command to the
					     dylib if no symbols are being
					     referenced from the dylib. */
    public static final DWord MH_ROOT_SAFE = new DWord("0x00040000", Data.Type.DATA_BYTE, ByteOrder.BIG_ENDIAN);           /* When this bit is set, the binary
					  declares it is safe for use in
					  processes with uid zero */

    public static final DWord MH_SETUID_SAFE = new DWord("0x00080000", Data.Type.DATA_BYTE, ByteOrder.BIG_ENDIAN);         /* When this bit is set, the binary
					  declares it is safe for use in
					  processes when issetugid() is true */

    public static final DWord MH_NO_REEXPORTED_DYLIBS = new DWord("0x00100000", Data.Type.DATA_BYTE, ByteOrder.BIG_ENDIAN); /* When this bit is set on a dylib,
					  the static linker does not need to
					  examine dependent dylibs to see
					  if any are re-exported */
    public static final DWord MH_PIE = new DWord("0x00200000", Data.Type.DATA_BYTE, ByteOrder.BIG_ENDIAN);			/* When this bit is set, the OS will
					   load the main executable at a
					   random address.  Only used in
					   MH_EXECUTE filetypes. */

    /*
     * The load commands directly follow the mach_header.  The total size of all
     * of the commands is given by the sizeofcmds field in the mach_header.  All
     * load commands must have as their first two fields cmd and cmdsize.  The cmd
     * field is filled in with a constant for that command type.  Each command type
     * has a public classure specifically for it.  The cmdsize field is the size in bytes
     * of the particular load command public classure plus anything that follows it that
     * is a part of the load command (i.e. section public classures, strings, etc.).  To
     * advance to the next load command the cmdsize can be added to the offset or
     * pointer of the current load command.  The cmdsize for 32-bit architectures
     * MUST be a multiple of 4 bytes and for 64-bit architectures MUST be a multiple
     * of 8 bytes (these are forever the maximum alignment of any load commands).
     * The padded bytes must be zero.  All tables in the object file must also
     * follow these rules so the file can be memory mapped.  Otherwise the pointers
     * to these tables will not work well or at all on some machines.  With all
     * padding zeroed like objects will compare byte for byte.
     */
    public class load_command extends DataStructure {
        public DWord cmd = new DWord();
        public static final String cmdComment = "/* type of load command */";
        public DWord cmdsize = new DWord();
        public static final String cmdsizeComment = "/* total size of command in bytes */";

        public load_command(Addressable parent) {
            super(parent);
        }

        @Override
        public LinkedList<Data> getStructureData() {
            {
                cmd.setComment(cmdComment);
                cmdsize.setComment(cmdsizeComment);
                return new LinkedList<>(Arrays.asList(cmd, cmdsize));
            }
        }
    }

    ;

    /*
     * After MacOS X 10.1 when a new load command is added that is required to be
     * understood by the dynamic linker for the image to execute properly the
     * LC_REQ_DYLD bit will be or'ed into the load command constant.  If the dynamic
     * linker sees such a load command it it does not understand will issue a
     * "unknown load command required for execution" error and refuse to use the
     * image.  Other load commands without this bit that are not understood will
     * simply be ignored.
     */
    public static final DWord LC_REQ_DYLD = new DWord("0x80000000", Data.Type.DATA_BYTE, ByteOrder.BIG_ENDIAN);

    /* Constants for the cmd field of all load commands, the type */
    public static final DWord LC_SEGMENT = new DWord("0x00000001", Data.Type.DATA_BYTE, ByteOrder.BIG_ENDIAN);	/* segment of this file to be mapped */
    public static final DWord LC_SYMTAB = new DWord("0x00000002", Data.Type.DATA_BYTE, ByteOrder.BIG_ENDIAN);	/* link-edit stab symbol table info */
    public static final DWord LC_SYMSEG = new DWord("0x00000003", Data.Type.DATA_BYTE, ByteOrder.BIG_ENDIAN);	/* link-edit gdb symbol table info (obsolete) */
    public static final DWord LC_THREAD = new DWord("0x00000004", Data.Type.DATA_BYTE, ByteOrder.BIG_ENDIAN);	/* thread */
    public static final DWord LC_UNIXTHREAD = new DWord("0x00000005", Data.Type.DATA_BYTE, ByteOrder.BIG_ENDIAN);	/* unix thread (includes a stack) */
    public static final DWord LC_LOADFVMLIB = new DWord("0x00000006", Data.Type.DATA_BYTE, ByteOrder.BIG_ENDIAN);	/* load a specified fixed VM shared library */
    public static final DWord LC_IDFVMLIB = new DWord("0x00000007", Data.Type.DATA_BYTE, ByteOrder.BIG_ENDIAN);	/* fixed VM shared library identification */
    public static final DWord LC_IDENT = new DWord("0x00000008",Data.Type.DATA_BYTE,  ByteOrder.BIG_ENDIAN);	/* object identification info (obsolete) */
    public static final DWord LC_FVMFILE = new DWord("0x00000009", Data.Type.DATA_BYTE, ByteOrder.BIG_ENDIAN);	/* fixed VM file inclusion (internal use) */
    public static final DWord LC_PREPAGE = new DWord("0x0000000a", Data.Type.DATA_BYTE, ByteOrder.BIG_ENDIAN);     /* prepage command (internal use) */
    public static final DWord LC_DYSYMTAB = new DWord("0x0000000b", Data.Type.DATA_BYTE, ByteOrder.BIG_ENDIAN);	/* dynamic link-edit symbol table info */
    public static final DWord LC_LOAD_DYLIB = new DWord("0x0000000c", Data.Type.DATA_BYTE, ByteOrder.BIG_ENDIAN);	/* load a dynamically linked shared library */
    public static final DWord LC_ID_DYLIB = new DWord("0x0000000d", Data.Type.DATA_BYTE, ByteOrder.BIG_ENDIAN);	/* dynamically linked shared lib ident */
    public static final DWord LC_LOAD_DYLINKER = new DWord("0x0000000e", Data.Type.DATA_BYTE, ByteOrder.BIG_ENDIAN);	/* load a dynamic linker */
    public static final DWord LC_ID_DYLINKER = new DWord("0x0000000f", Data.Type.DATA_BYTE, ByteOrder.BIG_ENDIAN);	/* dynamic linker identification */
    public static final DWord LC_PREBOUND_DYLIB = new DWord("0x00000010",Data.Type.DATA_BYTE,  ByteOrder.BIG_ENDIAN);	/* modules prebound for a dynamically */
    /*  linked shared library */
    public static final DWord LC_ROUTINES = new DWord("0x00000011", Data.Type.DATA_BYTE, ByteOrder.BIG_ENDIAN);	/* image routines */
    public static final DWord LC_SUB_FRAMEWORK = new DWord("0x00000012", Data.Type.DATA_BYTE, ByteOrder.BIG_ENDIAN);	/* sub framework */
    public static final DWord LC_SUB_UMBRELLA = new DWord("0x00000013",Data.Type.DATA_BYTE, ByteOrder.BIG_ENDIAN);	/* sub umbrella */
    public static final DWord LC_SUB_CLIENT = new DWord("0x00000014", Data.Type.DATA_BYTE, ByteOrder.BIG_ENDIAN);	/* sub client */
    public static final DWord LC_SUB_LIBRARY = new DWord("0x00000015", Data.Type.DATA_BYTE, ByteOrder.BIG_ENDIAN);	/* sub library */
    public static final DWord LC_TWOLEVEL_HINTS = new DWord("0x00000016", Data.Type.DATA_BYTE, ByteOrder.BIG_ENDIAN);	/* two-level namespace lookup hints */
    public static final DWord LC_PREBIND_CKSUM = new DWord("0x00000017",Data.Type.DATA_BYTE,  ByteOrder.BIG_ENDIAN);	/* prebind checksum */

    /*
     * load a dynamically linked shared library that is allowed to be missing
     * (all symbols are weak imported).
     */
    public static final DWord LC_LOAD_WEAK_DYLIB = new DWord("0x80000018", Data.Type.DATA_BYTE, ByteOrder.BIG_ENDIAN);
    public static final DWord LC_SEGMENT_64 = new DWord("0x00000019", Data.Type.DATA_BYTE, ByteOrder.BIG_ENDIAN);	/* 64-bit segment of this file to be mapped */
    public static final DWord LC_ROUTINES_64 = new DWord("0x0000001a",Data.Type.DATA_BYTE,  ByteOrder.BIG_ENDIAN);	/* 64-bit image routines */
    public static final DWord LC_UUID = new DWord("0x0000001b", Data.Type.DATA_BYTE, ByteOrder.BIG_ENDIAN);	/* the uuid */
    public static final DWord LC_RPATH = new DWord("0x8000001c", Data.Type.DATA_BYTE, ByteOrder.BIG_ENDIAN);    /* runpath additions */
    public static final DWord LC_CODE_SIGNATURE = new DWord("0x0000001d", Data.Type.DATA_BYTE, ByteOrder.BIG_ENDIAN);	/* local of code signature */
    public static final DWord LC_SEGMENT_SPLIT_INFO = new DWord("0x0000001e", Data.Type.DATA_BYTE, ByteOrder.BIG_ENDIAN); /* local of info to split segments */
    public static final DWord LC_REEXPORT_DYLIB = new DWord("0x8000001f",Data.Type.DATA_BYTE,  ByteOrder.BIG_ENDIAN); /* load and re-export dylib */
    public static final DWord LC_LAZY_LOAD_DYLIB = new DWord("0x00000020", Data.Type.DATA_BYTE, ByteOrder.BIG_ENDIAN);	/* delay load of dylib until first use */
    public static final DWord LC_ENCRYPTION_INFO = new DWord("0x00000021",Data.Type.DATA_BYTE,  ByteOrder.BIG_ENDIAN);	/* encrypted segment information */
    public static final DWord LC_DYLD_INFO = new DWord("0x00000022",Data.Type.DATA_BYTE,  ByteOrder.BIG_ENDIAN);	/* compressed dyld information */
    public static final DWord LC_DYLD_INFO_ONLY = new DWord("0x80000022", Data.Type.DATA_BYTE, ByteOrder.BIG_ENDIAN);	/* compressed dyld information only */

    // public static final DWord	MH_DEAD_STRIPPABLE_DYLIB = new DWord("0x00400000",ByteOrder.LITTLE_ENDIAN);
    /* Only for use on dylibs.  When
					     linking against a dylib that
					     has this bit set, the static linker
					     will automatically not create a
					     LC_LOAD_DYLIB load command to the
					     dylib if no symbols are being
					     referenced from the dylib. */
    public static final DWord MH_HAS_TLV_DESCRIPTORS = new DWord("0x00800000",Data.Type.DATA_BYTE, ByteOrder.BIG_ENDIAN); /* Contains a section of type
					    S_THREAD_LOCAL_VARIABLES */

    public static final DWord MH_NO_HEAP_EXECUTION = new DWord("0x01000000", Data.Type.DATA_BYTE, ByteOrder.BIG_ENDIAN);	/* When this bit is set, the OS will
					   run the main executable with
					   a non-executable heap even on
					   platforms (e.g. i386) that don't
					   require it. Only used in MH_EXECUTE
					   filetypes. */
    public static final DWord LC_LOAD_UPWARD_DYLIB = new DWord("0x80000023", Data.Type.DATA_BYTE, ByteOrder.BIG_ENDIAN);// | LC_REQ_DYLD) /* load upward dylib */
    public static final DWord LC_VERSION_MIN_MACOSX = new DWord("0x00000024", Data.Type.DATA_BYTE, ByteOrder.BIG_ENDIAN);   /* build for MacOSX min OS version */
    public static final DWord LC_VERSION_MIN_IPHONEOS = new DWord("0x00000025", Data.Type.DATA_BYTE, ByteOrder.BIG_ENDIAN); /* build for iPhoneOS min OS version */
    public static final DWord LC_FUNCTION_STARTS = new DWord("0x00000026", Data.Type.DATA_BYTE, ByteOrder.BIG_ENDIAN); /* compressed table of function start addresses */
    public static final DWord LC_DYLD_ENVIRONMENT = new DWord("0x00000027", Data.Type.DATA_BYTE, ByteOrder.BIG_ENDIAN); /* string for dyld to treat
				    like environment variable */
    public static final DWord LC_MAIN = new DWord("0x80000028", Data.Type.DATA_BYTE, ByteOrder.BIG_ENDIAN);//|LC_REQ_DYLD) /* replacement for LC_UNIXTHREAD */
    public static final DWord LC_DATA_IN_CODE = new DWord("0x00000029", Data.Type.DATA_BYTE, ByteOrder.BIG_ENDIAN); /* table of non-instructions in __text */
    public static final DWord LC_SOURCE_VERSION = new DWord("0x0000002A", Data.Type.DATA_BYTE, ByteOrder.BIG_ENDIAN); /* source version used to build binary */
    public static final DWord LC_DYLIB_CODE_SIGN_DRS = new DWord("0x0000002B", Data.Type.DATA_BYTE, ByteOrder.BIG_ENDIAN); /* Code signing DRs copied from linked dylibs */

    /*
     * A variable length string in a load command is represented by an lc_str
     * union.  The strings are stored just after the load command public classure and
     * the offset is from the start of the load command public classure.  The size
     * of the string is reflected in the cmdsize field of the load command.
     * Once again any padded bytes to bring the cmdsize field to a multiple
     * of 4 bytes must be zero.
     */
    public class lc_str extends DataStructure {
        public DWord offset = new DWord();
        public Range ptr = new Range();

        public lc_str(Addressable parent) {
            super(parent);
        }

        @Override
        public LinkedList<Data> getStructureData() {

            return new LinkedList<>(Arrays.asList(offset, ptr));
        }
    }

    /*
     * The segment load command indicates that a part of this file is to be
     * mapped into the task's address space.  The size of this segment in memory,
     * vmsize, maybe equal to or larger than the amount to map from this file,
     * filesize.  The file is mapped starting at fileoff to the beginning of
     * the segment in memory, vmaddr.  The rest of the memory of the segment,
     * if any, is allocated zero fill on demand.  The segment's maximum virtual
     * memory protection and initial virtual memory protection are specified
     * by the maxprot and initprot fields.  If the segment has sections then the
     * section public classures directly follow the segment command and their size is
     * reflected in cmdsize.
     */
    public class segment_command extends DataStructure { /* for 32-bit architectures */
        public DWord cmd = new DWord();
        public final static String cmdComment = "/* LC_SEGMENT */";
        public DWord cmdsize = new DWord();
        public final static String cmdsizeComment = "/* includes sizeof section public classs */";
        public char16 segname = new char16();
        public final static String segnameComment = "/* segment name */";
        public DWord vmaddr = new DWord();
        public final static String vmaddrComment = "/* memory address of this segment */";
        public DWord vmsize = new DWord();
        public final static String vmsizeComment = "/* memory size of this segment */";
        public DWord fileoff = new DWord();
        public final static String fileoffComment = "/* file offset of this segment */";
        public DWord filesize = new DWord();
        public final static String filesizeComment = "/* amount to map from the file */";
        public DWord maxprot = new DWord();
        public final static String maxprotComment = "/* max VM protection */";
        public DWord initprot = new DWord();
        public final static String initprotComment = "/* initial VM protection */";
        public DWord nsects = new DWord();
        public final static String nsectsComment = "/* number of sections in segment */";
        public DWord flags = new DWord();
        public final static String flagsComment = "/* flags */";

        public segment_command(Addressable parent) {
            super(parent);
        }

        @Override
        public LinkedList<Data> getStructureData() {
            cmd.setComment(cmdComment);
            cmdsize.setComment(cmdsizeComment);
            segname.setComment(segnameComment);
            vmaddr.setComment(vmaddrComment);
            vmsize.setComment(vmsizeComment);
            fileoff.setComment(fileoffComment);
            filesize.setComment(filesizeComment);
            maxprot.setComment(maxprotComment);
            initprot.setComment(initprotComment);
            nsects.setComment(nsectsComment);
            flags.setComment(flagsComment);
            return new LinkedList<>(Arrays.asList(cmd, cmdsize, segname, vmaddr, vmsize, fileoff, filesize, maxprot, initprot, nsects, flags));
        }
    }

    ;

    /*
     * The 64-bit segment load command indicates that a part of this file is to be
     * mapped into a 64-bit task's address space.  If the 64-bit segment has
     * sections then section_64 public classures directly follow the 64-bit segment
     * command and their size is reflected in cmdsize.
     */
    public class segment_command_64 extends DataStructure { /* for 64-bit architectures */
        public DWord cmd = new DWord();
        public final static String cmdComment = "/* LC_SEGMENT_64 */";
        public DWord cmdsize = new DWord();
        public final static String cmdsizeComment = "/* includes sizeof section_64 public classs */";
        public char16 segname = new char16();
        public final static String segnameComment = "/* segment name */";
        public QWord vmaddr = new QWord();
        public final static String vmaddrComment = "/* memory address of this segment */";
        public QWord vmsize = new QWord();
        public final static String vmsizeComment = "/* memory size of this segment */";
        public QWord fileoff = new QWord();
        public final static String fileoffComment = "/* file offset of this segment */";
        public QWord filesize = new QWord();
        public final static String filesizeComment = "/* amount to map from the file */";
        public DWord maxprot = new DWord();
        public final static String maxprotComment = "/* maximum VM protection */";
        public DWord initprot = new DWord();
        public final static String initprotComment = "/* initial VM protection */";
        public DWord nsects = new DWord();
        public final static String nsectsComment = "/* number of sections in segment */";
        public DWord flags = new DWord();
        public final static String flagsComment = "/* flags */";

        public segment_command_64(Addressable parent) {
            super(parent);
        }

        @Override
        public LinkedList<Data> getStructureData() {
            cmd.setComment(cmdComment);
            cmdsize.setComment(cmdsizeComment);
            segname.setComment(segnameComment);
            vmaddr.setComment(vmaddrComment);
            vmsize.setComment(vmsizeComment);
            fileoff.setComment(fileoffComment);
            filesize.setComment(filesizeComment);
            maxprot.setComment(maxprotComment);
            initprot.setComment(initprotComment);
            nsects.setComment(nsectsComment);
            flags.setComment(flagsComment);
            return new LinkedList<>(Arrays.asList(cmd, cmdsize, segname, vmaddr, vmsize, maxprot, initprot, nsects, flags));
        }
    }

    ;

    /* Constants for the flags field of the segment_command */
    public static final DWord SG_HIGHVM = new DWord("0x00000001", Data.Type.DATA_BYTE, ByteOrder.BIG_ENDIAN);	/* the file contents for this segment is for
				   the high part of the VM space, the low part
				   is zero filled (for stacks in core files) */
    public static final DWord SG_FVMLIB = new DWord("0x00000002", Data.Type.DATA_BYTE, ByteOrder.BIG_ENDIAN);	/* this segment is the VM that is allocated by
				   a fixed VM library, for overlap checking in
				   the link editor */
    public static final DWord SG_NORELOC = new DWord("0x00000004", Data.Type.DATA_BYTE, ByteOrder.BIG_ENDIAN);	/* this segment has nothing that was relocated
				   in it and nothing relocated to it, that is
				   it maybe safely replaced without relocation*/
    public static final DWord SG_PROTECTED_VERSION_1 = new DWord("0x00000008", Data.Type.DATA_BYTE, ByteOrder.BIG_ENDIAN); /* This segment is protected.  If the
				       segment starts at file offset 0, the
				       first page of the segment is not
				       protected.  All other pages of the
				       segment are protected. */

    /*
     * A segment is made up of zero or more sections.  Non-MH_OBJECT files have
     * all of their segments with the proper sections in each, and padded to the
     * specified segment alignment when produced by the link editor.  The first
     * segment of a MH_EXECUTE and MH_FVMLIB format file contains the mach_header
     * and load commands of the object file before its first section.  The zero
     * fill sections are always last in their segment (in all formats).  This
     * allows the zeroed segment padding to be mapped into memory where zero fill
     * sections might be. The gigabyte zero fill sections, those with the section
     * type S_GB_ZEROFILL, can only be in a segment with sections of this type.
     * These segments are then placed after all other segments.
     *
     * The MH_OBJECT format has all of its sections in one segment for
     * compactness.  There is no padding to a specified segment boundary and the
     * mach_header and load commands are not part of the segment.
     *
     * Sections with the same section name, sectname, going into the same segment,
     * segname, are combined by the link editor.  The resulting section is aligned
     * to the maximum alignment of the combined sections and is the new section's
     * alignment.  The combined sections are aligned to their original alignment in
     * the combined section.  Any padded bytes to get the specified alignment are
     * zeroed.
     *
     * The format of the relocation entries referenced by the reloff and nreloc
     * fields of the section public classure for mach object files is described in the
     * header file <reloc.h>.
     */
    public class section extends DataStructure { /* for 32-bit architectures */
        //public section(Segment parent){}
        public char16 sectname = new char16();
        public final static String sectnameComment = "/* name of this section */";
        public char16 segname = new char16();
        public final static String segnameComment = "/* segment this section goes in */";
        public DWord addr = new DWord();
        public final static String addrComment = "/* memory address of this section */";
        public DWord size = new DWord();
        public final static String sizeComment = "/* size in bytes of this section */";
        public DWord offset = new DWord();
        public final static String offsetComment = "/* file offset of this section */";
        public DWord align = new DWord();
        public final static String alignComment = "/* section alignment (power of 2) */";
        public DWord reloff = new DWord();
        public final static String reloffComment = "/* file offset of relocation entries */";
        public DWord nreloc = new DWord();
        public final static String nrelocComment = "/* number of relocation entries */";
        public DWord flags = new DWord();
        public final static String flagsComment = "/* flags (section type and attributes)*/";
        public DWord reserved1 = new DWord();
        public final static String reserved1Comment = "/* reserved (for offset or index) */";
        public DWord reserved2 = new DWord();
        public final static String reserved2Comment = "/* reserved (for count or sizeof) */";

        public section(Addressable parent) {
            super(parent);
        }

        @Override
        public LinkedList<Data> getStructureData() {
            sectname.setComment(sectnameComment);
            segname.setComment(segnameComment);
            addr.setComment(addrComment);
            size.setComment(sizeComment);
            offset.setComment(offsetComment);
            align.setComment(alignComment);
            reloff.setComment(reloffComment);
            nreloc.setComment(nrelocComment);
            flags.setComment(flagsComment);
            reserved1.setComment(reserved1Comment);
            reserved2.setComment(reserved2Comment);
            return new LinkedList<>(Arrays.asList(sectname, segname, addr, size, offset, align, reloff, nreloc, flags, reserved1, reserved2));
        }
    }

    ;

    public class section_64 extends DataStructure { /* for 64-bit architectures */

        public char16 sectname = new char16();
        public final static String sectnameComment = "/* name of this section */";
        public char16 segname = new char16();
        public final static String segnameComment = "/* segment this section goes in */";
        public QWord addr = new QWord();
        public final static String addrComment = "/* memory address of this section */";
        public QWord size = new QWord();
        public final static String sizeComment = "/* size in bytes of this section */";
        public DWord offset = new DWord();
        public final static String offsetComment = "/* file offset of this section */";
        public DWord align = new DWord();
        public final static String alignComment = "/* section alignment (power of 2) */";
        public DWord reloff = new DWord();
        public final static String reloffComment = "/* file offset of relocation entries */";
        public DWord nreloc = new DWord();
        public final static String nrelocComment = "/* number of relocation entries */";
        public DWord flags = new DWord();
        public final static String flagsComment = "/* flags (section type and attributes)*/";
        public DWord reserved1 = new DWord();
        public final static String reserved1Comment = "/* reserved (for offset or index) */";
        public DWord reserved2 = new DWord();
        public final static String reserved2Comment = "/* reserved (for count or sizeof) */";
        public DWord reserved3 = new DWord();
        public final static String reserved3Comment = "/* reserved */";

        public section_64(Addressable parent) {
            super(parent);
        }

        @Override
        public LinkedList<Data> getStructureData() {
            sectname.setComment(sectnameComment);
            segname.setComment(segnameComment);

            addr.setComment(addrComment);
            size.setComment(sizeComment);

            offset.setComment(offsetComment);
            reloff.setComment(reloffComment);

            nreloc.setComment(nrelocComment);
            flags.setComment(flagsComment);

            reserved1.setComment(reserved1Comment);
            reserved2.setComment(reserved2Comment);

            reserved3.setComment(reserved3Comment);
            return new LinkedList<>(Arrays.asList(sectname, segname, addr, size, offset, reloff, nreloc, flags, reserved1, reserved2, reserved3));
        }
    }

    ;

    /*
     * The flags field of a section public classure is separated into two parts a section
     * type and section attributes.  The section types are mutually exclusive (it
     * can only have one type) but the section attributes are not (it may have more
     * than one attribute).
     */
    public static final DWord SECTION_TYPE = new DWord("0x000000ff", Data.Type.DATA_BYTE, ByteOrder.BIG_ENDIAN);	/* 256 section types */
    public static final DWord SECTION_ATTRIBUTES = new DWord("0xffffff00", Data.Type.DATA_BYTE, ByteOrder.BIG_ENDIAN);	/*  24 section attributes */

    /* Constants for the type of a section */
    public static final DWord S_REGULAR = new DWord("0x00000000", Data.Type.DATA_BYTE, ByteOrder.BIG_ENDIAN);	/* regular section */
    public static final DWord S_ZEROFILL = new DWord("0x00000001", Data.Type.DATA_BYTE, ByteOrder.BIG_ENDIAN);	/* zero fill on demand section */
    public static final DWord S_CSTRING_LITERALS = new DWord("0x00000002", Data.Type.DATA_BYTE, ByteOrder.BIG_ENDIAN);	/* section with only literal C strings*/
    public static final DWord S_4BYTE_LITERALS = new DWord("0x00000003", Data.Type.DATA_BYTE, ByteOrder.BIG_ENDIAN);	/* section with only 4 byte literals */
    public static final DWord S_8BYTE_LITERALS = new DWord("0x00000004", Data.Type.DATA_BYTE, ByteOrder.BIG_ENDIAN);	/* section with only 8 byte literals */
    public static final DWord S_LITERAL_POINTERS = new DWord("0x00000005", Data.Type.DATA_BYTE, ByteOrder.BIG_ENDIAN);	/* section with only pointers to */
    /*  literals */
    /*
     * For the two types of symbol pointers sections and the symbol stubs section
     * they have indirect symbol table entries.  For each of the entries in the
     * section the indirect symbol table entries, in corresponding order in the
     * indirect symbol table, start at the index stored in the reserved1 field
     * of the section public classure.  Since the indirect symbol table entries
     * correspond to the entries in the section the number of indirect symbol table
     * entries is inferred from the size of the section divided by the size of the
     * entries in the section.  For symbol pointers sections the size of the entries
     * in the section is 4 bytes and for symbol stubs sections the byte size of the
     * stubs is stored in the reserved2 field of the section public classure.
     */
    public static final DWord S_NON_LAZY_SYMBOL_POINTERS = new DWord("0x00000006", Data.Type.DATA_BYTE, ByteOrder.BIG_ENDIAN);	/* section with only non-lazy
						   symbol pointers */
    public static final DWord S_LAZY_SYMBOL_POINTERS = new DWord("0x00000007", Data.Type.DATA_BYTE, ByteOrder.BIG_ENDIAN);	/* section with only lazy symbol
						   pointers */
    public static final DWord S_SYMBOL_STUBS = new DWord("0x00000008", Data.Type.DATA_BYTE, ByteOrder.BIG_ENDIAN);	/* section with only symbol
						   stubs, byte size of stub in
						   the reserved2 field */
    public static final DWord S_MOD_INIT_FUNC_POINTERS = new DWord("0x00000009", Data.Type.DATA_BYTE, ByteOrder.BIG_ENDIAN);	/* section with only function
						   pointers for initialization*/
    public static final DWord S_MOD_TERM_FUNC_POINTERS = new DWord("0x0000000a", Data.Type.DATA_BYTE, ByteOrder.BIG_ENDIAN);	/* section with only function
						   pointers for termination */
    public static final DWord S_COALESCED = new DWord("0x0000000b", Data.Type.DATA_BYTE, ByteOrder.BIG_ENDIAN);	/* section contains symbols that
						   are to be coalesced */
    public static final DWord S_GB_ZEROFILL = new DWord("0x0000000c", Data.Type.DATA_BYTE, ByteOrder.BIG_ENDIAN);	/* zero fill on demand section
						   (that can be larger than 4
						   gigabytes) */
    public static final DWord S_INTERPOSING = new DWord("0x0000000d", Data.Type.DATA_BYTE, ByteOrder.BIG_ENDIAN);	/* section with only pairs of
						   function pointers for
						   interposing */
    public static final DWord S_16BYTE_LITERALS = new DWord("0x0000000e", Data.Type.DATA_BYTE, ByteOrder.BIG_ENDIAN);	/* section with only 16 byte
						   literals */
    public static final DWord S_DTRACE_DOF = new DWord("0x0000000f", Data.Type.DATA_BYTE, ByteOrder.BIG_ENDIAN);	/* section contains
						   DTrace Object Format */
    public static final DWord S_LAZY_DYLIB_SYMBOL_POINTERS = new DWord("0x00000010", Data.Type.DATA_BYTE, ByteOrder.BIG_ENDIAN);	/* section with only lazy
						   symbol pointers to lazy
						   loaded dylibs */
    /*
     * Constants for the section attributes part of the flags field of a section
     * public classure.
     */
    public static final DWord SECTION_ATTRIBUTES_USR = new DWord("0xff000000", Data.Type.DATA_BYTE, ByteOrder.BIG_ENDIAN);	/* User setable attributes */
    public static final DWord S_ATTR_PURE_INSTRUCTIONS = new DWord("0x80000000", Data.Type.DATA_BYTE, ByteOrder.BIG_ENDIAN);	/* section contains only true
						   machine instructions */
    public static final DWord S_ATTR_NO_TOC = new DWord("0x40000000", Data.Type.DATA_BYTE, ByteOrder.BIG_ENDIAN);	/* section contains coalesced
						   symbols that are not to be
						   in a ranlib table of
						   contents */
    public static final DWord S_ATTR_STRIP_STATIC_SYMS = new DWord("0x20000000", Data.Type.DATA_BYTE, ByteOrder.BIG_ENDIAN);	/* ok to strip static symbols
						   in this section in files
						   with the MH_DYLDLINK flag */
    public static final DWord S_ATTR_NO_DEAD_STRIP = new DWord("0x10000000", Data.Type.DATA_BYTE, ByteOrder.BIG_ENDIAN);	/* no dead stripping */
    public static final DWord S_ATTR_LIVE_SUPPORT = new DWord("0x08000000", Data.Type.DATA_BYTE, ByteOrder.BIG_ENDIAN);	/* blocks are live if they
						   reference live blocks */
    public static final DWord S_ATTR_SELF_MODIFYING_CODE = new DWord("0x04000000", Data.Type.DATA_BYTE, ByteOrder.BIG_ENDIAN);	/* Used with i386 code stubs
						   written on by dyld */

    /*
     * Section types to support thread local variables
     */
    public static final DWord S_THREAD_LOCAL_REGULAR = new DWord("0x00000011", Data.Type.DATA_BYTE, ByteOrder.BIG_ENDIAN);  /* template of initial
							  values for TLVs */
    public static final DWord S_THREAD_LOCAL_ZEROFILL = new DWord("0x00000012", Data.Type.DATA_BYTE, ByteOrder.BIG_ENDIAN);  /* template of initial
							  values for TLVs */
    public static final DWord S_THREAD_LOCAL_VARIABLES = new DWord("0x00000013", Data.Type.DATA_BYTE, ByteOrder.BIG_ENDIAN);  /* TLV descriptors */
    public static final DWord S_THREAD_LOCAL_VARIABLE_POINTERS = new DWord("0x00000014", Data.Type.DATA_BYTE, ByteOrder.BIG_ENDIAN);  /* pointers to TLV
                                                          descriptors */
    public static final DWord S_THREAD_LOCAL_INIT_FUNCTION_POINTERS = new DWord("0x00000015", Data.Type.DATA_BYTE, ByteOrder.BIG_ENDIAN);  /* functions to call
							  to initialize TLV
							  values */


    /*
 * If a segment contains any sections marked with S_ATTR_DEBUG then all
 * sections in that segment must have this attribute.  No section other than
 * a section marked with this attribute may reference the contents of this
 * section.  A section with this attribute may contain no symbols and must have
 * a section type S_REGULAR.  The static linker will not copy section contents
 * from sections with this attribute into its output file.  These sections
 * generally contain DWARF debugging info.
 */
    public static final DWord S_ATTR_DEBUG = new DWord("0x02000000", Data.Type.DATA_BYTE, ByteOrder.BIG_ENDIAN);	/* a debug section */
    public static final DWord SECTION_ATTRIBUTES_SYS = new DWord("0x00ffff00", Data.Type.DATA_BYTE, ByteOrder.BIG_ENDIAN);	/* system setable attributes */
    public static final DWord S_ATTR_SOME_INSTRUCTIONS = new DWord("0x00000400", Data.Type.DATA_BYTE, ByteOrder.BIG_ENDIAN);	/* section contains some
						   machine instructions */
    public static final DWord S_ATTR_EXT_RELOC = new DWord("0x00000200", Data.Type.DATA_BYTE, ByteOrder.BIG_ENDIAN);	/* section has external
						   relocation entries */
    public static final DWord S_ATTR_LOC_RELOC = new DWord("0x00000100", Data.Type.DATA_BYTE, ByteOrder.BIG_ENDIAN);	/* section has local
						   relocation entries */


/*
 * The names of segments and sections in them are mostly meaningless to the
 * link-editor.  But there are few things to support traditional UNIX
 * executables that require the link-editor and assembler to use some names
 * agreed upon by convention.
 *
 * The initial protection of the "__TEXT" segment has write protection turned
 * off (not writeable).
 *
 * The link-editor will allocate common symbols at the end of the "__common"
 * section in the "__DATA" segment.  It will create the section and segment
 * if needed.
 */

/* The currently known segment names and the section names in those segments */

    public static final String SEG_PAGEZERO = "__PAGEZERO";	/* the pagezero segment which has no */
					/* protections and catches NULL */
					/* references for MH_EXECUTE files */


    public static final String SEG_TEXT = "__TEXT";	/* the tradition UNIX text segment */
    public static final String SECT_TEXT = "__text";	/* the real text part of the text */
    /* section no headers, and no padding */
    public static final String SECT_FVMLIB_INIT0 = "__fvmlib_init0";	/* the fvmlib initialization */
    /*  section */
    public static final String SECT_FVMLIB_INIT1 = "__fvmlib_init1";	/* the section following the */
					        /*  fvmlib initialization */
						/*  section */

    public static final String SEG_DATA = "__DATA";	/* the tradition UNIX data segment */
    public static final String SECT_DATA = "__data";	/* the real initialized data section */
    /* no padding, no bss overlap */
    public static final String SECT_BSS = "__bss";		/* the real uninitialized data section*/
    /* no padding */
    public static final String SECT_COMMON = "__common";	/* the section common symbols are */
					/* allocated in by the link editor */

    public static final String SEG_OBJC = "__OBJC";	/* objective-C runtime segment */
    public static final String SECT_OBJC_SYMBOLS = "__symbol_table";	/* symbol table */
    public static final String SECT_OBJC_MODULES = "__module_info";	/* module information */
    public static final String SECT_OBJC_STRINGS = "__selector_strs";/* string table */
    public static final String SECT_OBJC_REFS = "__selector_refs";	/* string table */

    public static final String SEG_ICON = "__ICON";	/* the icon segment */
    public static final String SECT_ICON_HEADER = "__header";	/* the icon headers */
    public static final String SECT_ICON_TIFF = "__tiff";	/* the icons in tiff format */

    public static final String SEG_LINKEDIT = "__LINKEDIT";	/* the segment containing all public classs */
					/* created and maintained by the link */
					/* editor.  Created with -seglinkedit */
					/* option to ld(1) for MH_EXECUTE and */
					/* FVMLIB file types only */

    public static final String SEG_UNIXSTACK = "__UNIXSTACK";	/* the unix stack segment */

    public static final String SEG_IMPORT = "__IMPORT";	/* the segment for the self (dyld) */
					/* modifing code stubs that has read, */
					/* write and execute permissions */

    /*
     * Fixed virtual memory shared libraries are identified by two things.  The
     * target pathname (the name of the library as found for execution), and the
     * minor version number.  The address of where the headers are loaded is in
     * header_addr. (THIS IS OBSOLETE and no longer supported).
     */
    public class fvmlib extends DataStructure {
        public lc_str name = new lc_str(this);
        public final static String nameComment = "/* library's target pathname */";
        public DWord minor_version = new DWord();
        public final static String minor_versionComment = "/* library's minor version number */";
        public DWord header_addr = new DWord();
        public final static String header_addrComment = "/* library's header address */";

        public fvmlib(Addressable parent) {
            super(parent);
        }

        @Override
        public LinkedList<Data> getStructureData() {
            name.setComment(nameComment);
            minor_version.setComment(minor_versionComment);
            header_addr.setComment(header_addrComment);

            return new LinkedList<>(Arrays.asList(minor_version, header_addr));
        }
    }

    ;

    /*
     * A fixed virtual shared library (filetype == MH_FVMLIB in the mach header)
     * contains a fvmlib_command (cmd == LC_IDFVMLIB) to identify the library.
     * An object that uses a fixed virtual shared library also contains a
     * fvmlib_command (cmd == LC_LOADFVMLIB) for each library it uses.
     * (THIS IS OBSOLETE and no longer supported).
     */
    public class fvmlib_command extends DataStructure {
        public DWord cmd = new DWord();
        public final static String cmdComment = "/* LC_IDFVMLIB or LC_LOADFVMLIB */";
        public DWord cmdsize = new DWord();
        public final static String cmdsizeComment = "/* includes pathname string */";
        public fvmlib fvmlib = new fvmlib(this);
        public final static String fvmlibComment = "/* the library identification */";

        public fvmlib_command(Addressable parent) {
            super(parent);
        }

        @Override
        public LinkedList<Data> getStructureData() {
            cmd.setComment(cmdComment);
            cmdsize.setComment(cmdsizeComment);
            fvmlib.setComment(fvmlibComment);

            return new LinkedList<>(Arrays.asList(cmd, cmdsize));
        }
    }

    ;

    /*
     * Dynamicly linked shared libraries are identified by two things.  The
     * pathname (the name of the library as found for execution), and the
     * compatibility version number.  The pathname must match and the compatibility
     * number in the user of the library must be greater than or equal to the
     * library being used.  The time stamp is used to record the time a library was
     * built and copied into user so it can be use to determined if the library used
     * at runtime is exactly the same as used to built the program.
     */
    public class dylib extends DataStructure {
        public lc_str name = new lc_str(this);
        public final static String nameComment = "/* library's path name */";
        public DWord timestamp = new DWord();
        public final static String timestampComment = "/* library's build time stamp */";
        public DWord current_version = new DWord();
        public final static String current_versionComment = "/* library's current version number */";
        public DWord compatibility_version = new DWord();
        public final static String compatibility_versionComment = "/* library's compatibility vers number*/";

        public dylib(Addressable parent) {
            super(parent);
        }

        @Override
        public LinkedList<Data> getStructureData() {
            name.setComment(nameComment);
            timestamp.setComment(timestampComment);
            current_version.setComment(current_versionComment);
            compatibility_version.setComment(compatibility_versionComment);

            return new LinkedList<>(Arrays.asList(timestamp, current_version, compatibility_version));
        }
    }

    ;

    /*
     * A dynamically linked shared library (filetype == MH_DYLIB in the mach header)
     * contains a dylib_command (cmd == LC_ID_DYLIB) to identify the library.
     * An object that uses a dynamically linked shared library also contains a
     * dylib_command (cmd == LC_LOAD_DYLIB, LC_LOAD_WEAK_DYLIB, or
     * LC_REEXPORT_DYLIB) for each library it uses.
     */
    public class dylib_command extends DataStructure {
        public DWord cmd = new DWord();
        public final static String cmdComment = "/* LC_ID_DYLIB, LC_LOAD_{,WEAK_}DYLIB, LC_REEXPORT_DYLIB */";
        public DWord cmdsize = new DWord();
        public final static String cmdsizeComment = "/* includes pathname string */";
        public dylib dylib = new dylib(this);
        public final static String dylibComment = "/* the library identification */";

        public dylib_command(Addressable parent) {
            super(parent);
        }

        @Override
        public LinkedList<Data> getStructureData() {
            cmd.setComment(cmdComment);
            cmdsize.setComment(cmdsizeComment);
            dylib.setComment(dylibComment);

            return new LinkedList<>(Arrays.asList(cmd, cmdsize));
        }
    }

    ;

    /*
     * A dynamically linked shared library may be a subframework of an umbrella
     * framework.  If so it will be linked with "-umbrella umbrella_name" where
     * Where "umbrella_name" is the name of the umbrella framework. A subframework
     * can only be linked against by its umbrella framework or other subframeworks
     * that are part of the same umbrella framework.  Otherwise the static link
     * editor produces an error and states to link against the umbrella framework.
     * The name of the umbrella framework for subframeworks is recorded in the
     * following public classure.
     */
    public class sub_framework_command extends DataStructure {
        public DWord cmd = new DWord();
        public final static String cmdComment = "/* LC_SUB_FRAMEWORK */";
        public DWord cmdsize = new DWord();
        public final static String cmdsizeComment = "/* includes umbrella string */";
        public lc_str umbrella = new lc_str(this);
        public final static String umbrellaComment = "/* the umbrella framework name */";

        public sub_framework_command(Addressable parent) {
            super(parent);
        }

        @Override
        public LinkedList<Data> getStructureData() {
            cmd.setComment(cmdComment);
            cmdsize.setComment(cmdsizeComment);
            umbrella.setComment(umbrellaComment);

            return new LinkedList<>(Arrays.asList(cmd, cmdsize));
        }
    }

    ;

    /*
     * For dynamically linked shared libraries that are subframework of an umbrella
     * framework they can allow clients other than the umbrella framework or other
     * subframeworks in the same umbrella framework.  To do this the subframework
     * is built with "-allowable_client client_name" and an LC_SUB_CLIENT load
     * command is created for each -allowable_client flag.  The client_name is
     * usually a framework name.  It can also be a name used for bundles clients
     * where the bundle is built with "-client_name client_name".
     */
    public class sub_client_command extends DataStructure {
        public DWord cmd = new DWord();
        public final static String cmdComment = "/* LC_SUB_CLIENT */";
        public DWord cmdsize = new DWord();
        public final static String cmdsizeComment = "/* includes client string */";
        public lc_str client = new lc_str(this);
        public final static String clientComment = "/* the client name */";

        public sub_client_command(Addressable parent) {
            super(parent);
        }

        @Override
        public LinkedList<Data> getStructureData() {
            cmd.setComment(cmdComment);
            cmdsize.setComment(cmdsizeComment);
            client.setComment(clientComment);

            return new LinkedList<>(Arrays.asList(cmd, cmdsize));
        }
    }

    ;

    /*
     * A dynamically linked shared library may be a sub_umbrella of an umbrella
     * framework.  If so it will be linked with "-sub_umbrella umbrella_name" where
     * Where "umbrella_name" is the name of the sub_umbrella framework.  When
     * staticly linking when -twolevel_namespace is in effect a twolevel namespace
     * umbrella framework will only cause its subframeworks and those frameworks
     * listed as sub_umbrella frameworks to be implicited linked in.  Any other
     * dependent dynamic libraries will not be linked it when -twolevel_namespace
     * is in effect.  The primary library recorded by the static linker when
     * resolving a symbol in these libraries will be the umbrella framework.
     * Zero or more sub_umbrella frameworks may be use by an umbrella framework.
     * The name of a sub_umbrella framework is recorded in the following public classure.
     */
    public class sub_umbrella_command extends DataStructure {
        public DWord cmd = new DWord();
        public final static String cmdComment = "/* LC_SUB_UMBRELLA */";
        public DWord cmdsize = new DWord();
        public final static String cmdsizeComment = "/* includes sub_umbrella string */";
        public lc_str sub_umbrella = new lc_str(this);
        public final static String sub_umbrellaComment = "/* the sub_umbrella framework name */";

        public sub_umbrella_command(Addressable parent) {
            super(parent);
        }

        @Override
        public LinkedList<Data> getStructureData() {
            cmd.setComment(cmdComment);
            cmdsize.setComment(cmdsizeComment);
            sub_umbrella.setComment(sub_umbrellaComment);

            return new LinkedList<>(Arrays.asList(cmd, cmdsize));
        }
    }

    ;

    /*
     * A dynamically linked shared library may be a sub_library of another shared
     * library.  If so it will be linked with "-sub_library library_name" where
     * Where "library_name" is the name of the sub_library shared library.  When
     * staticly linking when -twolevel_namespace is in effect a twolevel namespace
     * shared library will only cause its subframeworks and those frameworks
     * listed as sub_umbrella frameworks and libraries listed as sub_libraries to
     * be implicited linked in.  Any other dependent dynamic libraries will not be
     * linked it when -twolevel_namespace is in effect.  The primary library
     * recorded by the static linker when resolving a symbol in these libraries
     * will be the umbrella framework (or dynamic library). Zero or more sub_library
     * shared libraries may be use by an umbrella framework or (or dynamic library).
     * The name of a sub_library framework is recorded in the following public classure.
     * For example /usr/lib/libobjc_profile.A.dylib would be recorded as "libobjc".
     */
    public class sub_library_command extends DataStructure {
        public DWord cmd = new DWord();
        public final static String cmdComment = "/* LC_SUB_LIBRARY */";
        public DWord cmdsize = new DWord();
        public final static String cmdsizeComment = "/* includes sub_library string */";
        public lc_str sub_library = new lc_str(this);
        public final static String sub_libraryComment = "/* the sub_library name */";

        public sub_library_command(Addressable parent) {
            super(parent);
        }

        @Override
        public LinkedList<Data> getStructureData() {
            cmd.setComment(cmdComment);
            cmdsize.setComment(cmdsizeComment);
            sub_library.setComment(sub_libraryComment);

            return new LinkedList<>(Arrays.asList(cmd, cmdsize));
        }
    }

    ;

    /*
     * A program (filetype == MH_EXECUTE) that is
     * prebound to its dynamic libraries has one of these for each library that
     * the static linker used in prebinding.  It contains a bit vector for the
     * modules in the library.  The bits indicate which modules are bound (1) and
     * which are not (0) from the library.  The bit for module 0 is the low bit
     * of the first byte.  So the bit for the Nth module is:
     * (linked_modules[N/8] >> N%8) & 1
     */
    public class prebound_dylib_command extends DataStructure {
        public DWord cmd = new DWord();
        public final static String cmdComment = "/* LC_PREBOUND_DYLIB */";
        public DWord cmdsize = new DWord();
        public final static String cmdsizeComment = "/* includes strings */";
        public lc_str name = new lc_str(this);
        public final static String nameComment = "/* library's path name */";
        public DWord nmodules = new DWord();
        public final static String nmodulesComment = "/* number of modules in library */";
        public lc_str linked_modules = new lc_str(this);
        public final static String linked_modulesComment = "/* bit vector of linked modules */";

        public prebound_dylib_command(Addressable parent) {
            super(parent);
        }

        @Override
        public LinkedList<Data> getStructureData() {
            cmd.setComment(cmdComment);
            cmdsize.setComment(cmdsizeComment);
            nmodules.setComment(nmodulesComment);
            name.setComment(nameComment);
            linked_modules.setComment(linked_modulesComment);

            return new LinkedList<>(Arrays.asList(cmd, cmdsize));
        }
    }

    ;

    /*
     * A program that uses a dynamic linker contains a dylinker_command to identify
     * the name of the dynamic linker (LC_LOAD_DYLINKER).  And a dynamic linker
     * contains a dylinker_command to identify the dynamic linker (LC_ID_DYLINKER).
     * A file can have at most one of these.
     */
    public class dylinker_command extends DataStructure {
        public DWord cmd = new DWord();
        public final static String cmdComment = "/* LC_ID_DYLINKER or LC_LOAD_DYLINKER */";
        public DWord cmdsize = new DWord();
        public final static String cmdsizeComment = "/* includes pathname string */";
        public lc_str name = new lc_str(this);
        public final static String nameComment = "/* dynamic linker's path name */";

        public dylinker_command(Addressable parent) {
            super(parent);
        }

        @Override
        public LinkedList<Data> getStructureData() {
            cmd.setComment(cmdComment);
            cmdsize.setComment(cmdsizeComment);
            name.setComment(nameComment);

            return new LinkedList<>(Arrays.asList(cmd, cmdsize));
        }
    }

    ;

    /*
     * Thread commands contain machine-specific data public classures suitable for
     * use in the thread state primitives.  The machine specific data public classures
     * follow the public class thread_command as follows.
     * Each flavor of machine specific data public classure is preceded by an unsigned
     * long constant for the flavor of that data public classure, an public DWord
     * that is the count of longs of the size of the state data public classure and then
     * the state data public classure follows.  This triple may be repeated for many
     * flavors.  The constants for the flavors, counts and state data public classure
     * definitions are expected to be in the header file <machine/thread_status.h>.
     * These machine specific data public classures sizes must be multiples of
     * 4 bytes  The cmdsize reflects the total size of the thread_command
     * and all of the sizes of the constants for the flavors, counts and state
     * data public classures.
     *
     * For executable objects that are unix processes there will be one
     * thread_command (cmd == LC_UNIXTHREAD) created for it by the link-editor.
     * This is the same as a LC_THREAD, except that a stack is automatically
     * created (based on the shell's limit for the stack size).  Command arguments
     * and environment variables are copied onto that stack.
     */
    public class thread_command extends DataStructure {
        public DWord cmd = new DWord();
        public final static String cmdComment = "/* LC_THREAD or  LC_UNIXTHREAD */";
        public DWord cmdsize = new DWord();
        public final static String cmdsizeComment = "/* total size of this command */";

        public thread_command(Addressable parent) {
            super(parent);
        }

        @Override
        public LinkedList<Data> getStructureData() {
            cmd.setComment(cmdComment);
            cmdsize.setComment(cmdsizeComment);

            return new LinkedList<>(Arrays.asList(cmd, cmdsize));
        }
	/* public DWord flavor		   flavor of thread state */
	/* public DWord count		   count of longs in thread state */
	/* public class XXX_thread_state state   thread state for this flavor */
	/* ... */
    }

    ;

    /*
     * The routines command contains the address of the dynamic shared library
     * initialization routine and an index into the module table for the module
     * that defines the routine.  Before any modules are used from the library the
     * dynamic linker fully binds the module that defines the initialization routine
     * and then calls it.  This gets called before any module initialization
     * routines (used for C++ static conpublic classors) in the library.
     */
    public class routines_command extends DataStructure { /* for 32-bit architectures */
        public DWord cmd = new DWord();
        public final static String cmdComment = "/* LC_ROUTINES */";
        public DWord cmdsize = new DWord();
        public final static String cmdsizeComment = "/* total size of this command */";
        public DWord init_address = new DWord();
        public final static String init_addressComment = "/* address of initialization routine */";
        public DWord init_module = new DWord();
        public final static String init_moduleComment = "/* index into the module table that the init routine is defined in */";
        public DWord reserved1 = new DWord();
        public final static String reserved1Comment = "/* reserved 1 */";
        public DWord reserved2 = new DWord();
        public final static String reserved2Comment = "/* reserved 2 */";
        public DWord reserved3 = new DWord();
        public final static String reserved3Comment = "/* reserved 3 */";
        public DWord reserved4 = new DWord();
        public final static String reserved4Comment = "/* reserved 4 */";
        public DWord reserved5 = new DWord();
        public final static String reserved5Comment = "/* reserved 5 */";
        public DWord reserved6 = new DWord();
        public final static String reserved6Comment = "/* reserved 6 */";

        public routines_command(Addressable parent) {
            super(parent);
        }

        @Override
        public LinkedList<Data> getStructureData() {
            cmd.setComment(cmdComment);
            cmdsize.setComment(cmdsizeComment);
            init_address.setComment(init_addressComment);
            init_module.setComment(init_moduleComment);
            reserved1.setComment(reserved1Comment);
            reserved2.setComment(reserved2Comment);
            reserved3.setComment(reserved3Comment);
            reserved4.setComment(reserved4Comment);
            reserved5.setComment(reserved5Comment);
            reserved6.setComment(reserved6Comment);
            return new LinkedList<>(Arrays.asList(cmd, cmdsize, init_address, init_module, reserved1, reserved2, reserved3, reserved4, reserved5, reserved6));
        }
    }

    ;

    /*
     * The 64-bit routines command.  Same use as above.
     */
    public class routines_command_64 extends DataStructure { /* for 64-bit architectures */
        public DWord cmd = new DWord();
        public final static String cmdComment = "/* LC_ROUTINES_64 */";
        public DWord cmdsize = new DWord();
        public final static String cmdsizeComment = "/* total size of this command */";
        public QWord init_address = new QWord();
        public final static String init_addressComment = "/* address of initialization routine */";
        public QWord init_module = new QWord();
        public final static String init_moduleComment = "/* index into the module table that the init routine is defined in */";
        public QWord reserved1 = new QWord();
        public final static String reserved1Comment = "/* reserved 1 */";
        public QWord reserved2 = new QWord();
        public final static String reserved2Comment = "/* reserved 2 */";
        public QWord reserved3 = new QWord();
        public final static String reserved3Comment = "/* reserved 3 */";
        public QWord reserved4 = new QWord();
        public final static String reserved4Comment = "/* reserved 4 */";
        public QWord reserved5 = new QWord();
        public final static String reserved5Comment = "/* reserved 5 */";
        public QWord reserved6 = new QWord();
        public final static String reserved6Comment = "/* reserved 6 */";

        public routines_command_64(Addressable parent) {
            super(parent);
        }

        @Override
        public LinkedList<Data> getStructureData() {
            cmd.setComment(cmdComment);
            cmdsize.setComment(cmdsizeComment);
            init_address.setComment(init_addressComment);
            init_module.setComment(init_moduleComment);
            reserved1.setComment(reserved1Comment);
            reserved2.setComment(reserved2Comment);
            reserved3.setComment(reserved3Comment);
            reserved4.setComment(reserved4Comment);
            reserved5.setComment(reserved5Comment);
            reserved6.setComment(reserved6Comment);
            return new LinkedList<>(Arrays.asList(cmd, cmdsize, init_address, init_module, reserved1, reserved2, reserved3, reserved4, reserved5, reserved6));
        }
    }

    ;

    /*
     * The symtab_command contains the offsets and sizes of the link-edit 4.3BSD
     * "stab" style symbol table information as described in the header files
     * <nlist.h> and <stab.h>.
     */
    public class symtab_command extends DataStructure {
        public DWord cmd = new DWord();
        public final static String cmdComment = "/* LC_SYMTAB */";
        public DWord cmdsize = new DWord();
        public final static String cmdsizeComment = "/* sizeof(public class symtab_command) */";
        public DWord symoff = new DWord();
        public final static String symoffComment = "/* symbol table offset */";
        public DWord nsyms = new DWord();
        public final static String nsymsComment = "/* number of symbol table entries */";
        public DWord stroff = new DWord();
        public final static String stroffComment = "/* string table offset */";
        public DWord strsize = new DWord();
        public final static String strsizeComment = "/* string table size in bytes */";

        public symtab_command(Addressable parent) {
            super(parent);
        }

        @Override
        public LinkedList<Data> getStructureData() {
            cmd.setComment(cmdComment);
            cmdsize.setComment(cmdsizeComment);
            symoff.setComment(symoffComment);
            nsyms.setComment(nsymsComment);
            stroff.setComment(stroffComment);
            strsize.setComment(strsizeComment);
            return new LinkedList<>(Arrays.asList(cmd, cmdsize, symoff, nsyms, stroff, strsize));
        }
    }

    ;

    /*
     * This is the second set of the symbolic information which is used to support
     * the data public classures for the dynamically link editor.
     *
     * The original set of symbolic information in the symtab_command which contains
     * the symbol and string tables must also be present when this load command is
     * present.  When this load command is present the symbol table is organized
     * into three groups of symbols:
     *	local symbols (static and debugging symbols) - grouped by module
     *	defined external symbols - grouped by module (sorted by name if not lib)
     *	undefined external symbols (sorted by name if MH_BINDATLOAD is not set,
     *	     			    and in order the were seen by the static
     *				    linker if MH_BINDATLOAD is set)
     * In this load command there are offsets and counts to each of the three groups
     * of symbols.
     *
     * This load command contains a the offsets and sizes of the following new
     * symbolic information tables:
     *	table of contents
     *	module table
     *	reference symbol table
     *	indirect symbol table
     * The first three tables above (the table of contents, module table and
     * reference symbol table) are only present if the file is a dynamically linked
     * shared library.  For executable and object modules, which are files
     * containing only one module, the information that would be in these three
     * tables is determined as follows:
     * 	table of contents - the defined external symbols are sorted by name
     *	module table - the file contains only one module so everything in the
     *		       file is part of the module.
     *	reference symbol table - is the defined and undefined external symbols
     *
     * For dynamically linked shared library files this load command also contains
     * offsets and sizes to the pool of relocation entries for all sections
     * separated into two groups:
     *	external relocation entries
     *	local relocation entries
     * For executable and object modules the relocation entries continue to hang
     * off the section public classures.
     */
    public class dysymtab_command extends DataStructure {
        public DWord cmd = new DWord();
        public final static String cmdComment = "/* LC_DYSYMTAB */";
        public DWord cmdsize = new DWord();
        public final static String cmdsizeComment = "/* sizeof(public class dysymtab_command) */";

        /*
         * The symbols indicated by symoff and nsyms of the LC_SYMTAB load command
         * are grouped into the following three groups:
         *    local symbols (further grouped by the module they are from)
         *    defined external symbols (further grouped by the module they are from)
         *    undefined symbols
         *
         * The local symbols are used only for debugging.  The dynamic binding
         * process may have to use them to indicate to the debugger the local
         * symbols for a module that is being bound.
         *
         * The last two groups are used by the dynamic binding process to do the
         * binding (indirectly through the module table and the reference symbol
         * table when this is a dynamically linked shared library file).
         */
        public DWord ilocalsym = new DWord();
        public final static String ilocalsymComment = "/* index to local symbols */";
        public DWord nlocalsym = new DWord();
        public final static String nlocalsymComment = "/* number of local symbols */";

        public DWord iextdefsym = new DWord();
        public final static String iextdefsymComment = "/* index to externally defined symbols */";
        public DWord nextdefsym = new DWord();
        public final static String nextdefsymComment = "/* number of externally defined symbols */";

        public DWord iundefsym = new DWord();
        public final static String iundefsymComment = "/* index to undefined symbols */";
        public DWord nundefsym = new DWord();
        public final static String nundefsymComment = "/* number of undefined symbols */";

        /*
         * For the for the dynamic binding process to find which module a symbol
         * is defined in the table of contents is used (analogous to the ranlib
         * public classure in an archive) which maps defined external symbols to modules
         * they are defined in.  This exists only in a dynamically linked shared
         * library file.  For executable and object modules the defined external
         * symbols are sorted by name and is use as the table of contents.
         */
        public DWord tocoff = new DWord();
        public final static String tocoffComment = "/* file offset to table of contents */";
        public DWord ntoc = new DWord();
        public final static String ntocComment = "/* number of entries in table of contents */";

        /*
         * To support dynamic binding of "modules" (whole object files) the symbol
         * table must reflect the modules that the file was created from.  This is
         * done by having a module table that has indexes and counts into the merged
         * tables for each module.  The module public classure that these two entries
         * refer to is described below.  This exists only in a dynamically linked
         * shared library file.  For executable and object modules the file only
         * contains one module so everything in the file belongs to the module.
         */
        public DWord modtaboff = new DWord();
        public final static String modtaboffComment = "/* file offset to module table */";
        public DWord nmodtab = new DWord();
        public final static String nmodtabComment = "/* number of module table entries */";

        /*
         * To support dynamic module binding the module public classure for each module
         * indicates the external references (defined and undefined) each module
         * makes.  For each module there is an offset and a count into the
         * reference symbol table for the symbols that the module references.
         * This exists only in a dynamically linked shared library file.  For
         * executable and object modules the defined external symbols and the
         * undefined external symbols indicates the external references.
         */
        public DWord extrefsymoff = new DWord();
        public final static String extrefsymoffComment = "/* offset to referenced symbol table */";
        public DWord nextrefsyms = new DWord();
        public final static String nextrefsymsComment = "/* number of referenced symbol table entries */";

        /*
         * The sections that contain "symbol pointers" and "routine stubs" have
         * indexes and (implied counts based on the size of the section and fixed
         * size of the entry) into the "indirect symbol" table for each pointer
         * and stub.  For every section of these two types the index into the
         * indirect symbol table is stored in the section header in the field
         * reserved1.  An indirect symbol table entry is simply a 32bit index into
         * the symbol table to the symbol that the pointer or stub is referring to.
         * The indirect symbol table is ordered to match the entries in the section.
         */
        public DWord indirectsymoff = new DWord();
        public final static String indirectsymoffComment = "/* file offset to the indirect symbol table */";
        public DWord nindirectsyms = new DWord();
        public final static String nindirectsymsComment = "/* number of indirect symbol table entries */";

        /*
         * To support relocating an individual module in a library file quickly the
         * external relocation entries for each module in the library need to be
         * accessed efficiently.  Since the relocation entries can't be accessed
         * through the section headers for a library file they are separated into
         * groups of local and external entries further grouped by module.  In this
         * case the presents of this load command who's extreloff, nextrel,
         * locreloff and nlocrel fields are non-zero indicates that the relocation
         * entries of non-merged sections are not referenced through the section
         * public classures (and the reloff and nreloc fields in the section headers are
         * set to zero).
         *
         * Since the relocation entries are not accessed through the section headers
         * this requires the r_address field to be something other than a section
         * offset to identify the item to be relocated.  In this case r_address is
         * set to the offset from the vmaddr of the first LC_SEGMENT command.
         * For MH_SPLIT_SEGS images r_address is set to the the offset from the
         * vmaddr of the first read-write LC_SEGMENT command.
         *
         * The relocation entries are grouped by module and the module table
         * entries have indexes and counts into them for the group of external
         * relocation entries for that the module.
         *
         * For sections that are merged across modules there must not be any
         * remaining external relocation entries for them (for merged sections
         * remaining relocation entries must be local).
         */
        public DWord extreloff = new DWord();
        public final static String extreloffComment = "/* offset to external relocation entries */";
        public DWord nextrel = new DWord();
        public final static String nextrelComment = "/* number of external relocation entries */";

        /*
         * All the local relocation entries are grouped together (they are not
         * grouped by their module since they are only used if the object is moved
         * from it staticly link edited address).
         */
        public DWord locreloff = new DWord();
        public final static String locreloffComment = "/* offset to local relocation entries */";
        public DWord nlocrel = new DWord();
        public final static String nlocrelComment = "/* number of local relocation entries */";

        public dysymtab_command(Addressable parent) {
            super(parent);
        }

        @Override
        public LinkedList<Data> getStructureData() {
            cmd.setComment(cmdComment);
            cmdsize.setComment(cmdsizeComment);
            ilocalsym.setComment(ilocalsymComment);
            nlocalsym.setComment(nlocalsymComment);
            iextdefsym.setComment(iextdefsymComment);
            nextrefsyms.setComment(nextrefsymsComment);
            iundefsym.setComment(iundefsymComment);
            nundefsym.setComment(nundefsymComment);
            tocoff.setComment(tocoffComment);
            ntoc.setComment(ntocComment);
            modtaboff.setComment(modtaboffComment);
            nmodtab.setComment(nmodtabComment);
            extrefsymoff.setComment(extrefsymoffComment);
            nextdefsym.setComment(nextdefsymComment);
            indirectsymoff.setComment(indirectsymoffComment);
            nindirectsyms.setComment(nindirectsymsComment);
            extreloff.setComment(extreloffComment);
            nextrel.setComment(nextrelComment);
            locreloff.setComment(locreloffComment);
            nlocrel.setComment(nlocrelComment);
            return new LinkedList<>(Arrays.asList(cmd, cmdsize, ilocalsym, nlocalsym, iextdefsym, nextrefsyms, iundefsym, nundefsym, tocoff, ntoc, modtaboff, nmodtab, extrefsymoff, nextdefsym, indirectsymoff, nindirectsyms, extreloff, nextrel, locreloff, nlocrel));
        }
    }

    ;

    /*
     * An indirect symbol table entry is simply a 32bit index into the symbol table
     * to the symbol that the pointer or stub is refering to.  Unless it is for a
     * non-lazy symbol pointer section for a defined symbol which strip(1) as
     * removed.  In which case it has the value INDIRECT_SYMBOL_LOCAL.  If the
     * symbol was also absolute INDIRECT_SYMBOL_ABS is or'ed with that.
     */
    public static final DWord INDIRECT_SYMBOL_LOCAL = new DWord("0x80000000", Data.Type.DATA_BYTE, ByteOrder.BIG_ENDIAN);
    public static final DWord INDIRECT_SYMBOL_ABS = new DWord("0x40000000", Data.Type.DATA_BYTE, ByteOrder.BIG_ENDIAN);


    /* a table of contents entry */
    public class dylib_table_of_contents extends DataStructure {
        public DWord symbol_index = new DWord();
        public final static String symbol_indexComment = "/* the defined external symbol (index into the symbol table) */";
        public DWord module_index = new DWord();
        public final static String module_indexComment = "/* index into the module table this symbol is defined in */";

        public dylib_table_of_contents(Addressable parent) {
            super(parent);
        }

        @Override
        public LinkedList<Data> getStructureData() {
            symbol_index.setComment(symbol_indexComment);
            module_index.setComment(module_indexComment);
            return new LinkedList<>(Arrays.asList(symbol_index, module_index));
        }
    }

    ;

    /* a module table entry */
    public class dylib_module extends DataStructure {
        public DWord module_name = new DWord();
        public final static String module_nameComment = "/* the module name (index into string table) */";

        public DWord iextdefsym = new DWord();
        public final static String iextdefsymComment = "/* index into externally defined symbols */";
        public DWord nextdefsym = new DWord();
        public final static String nextdefsymComment = "/* number of externally defined symbols */";
        public DWord irefsym = new DWord();
        public final static String irefsymComment = "/* index into reference symbol table */";
        public DWord nrefsym = new DWord();
        public final static String nrefsymComment = "/* number of reference symbol table entries */";
        public DWord ilocalsym = new DWord();
        public final static String ilocalsymComment = "/* index into symbols for local symbols */";
        public DWord nlocalsym = new DWord();
        public final static String nlocalsymComment = "/* number of local symbols */";

        public DWord iextrel = new DWord();
        public final static String iextrelComment = "/* index into external relocation entries */";
        public DWord nextrel = new DWord();
        public final static String nextrelComment = "/* number of external relocation entries */";

        public DWord iinit_iterm = new DWord();
        public final static String iinit_itermComment = "/* low 16 bits are the index into the init section, high 16 bits are the index into the term section */";
        public DWord ninit_nterm = new DWord();
        public final static String ninit_ntermComment = "/* low 16 bits are the number of init section entries, high 16 bits are the number of term section entries */";
        public DWord objc_module_info_addr = new DWord();
        public final static String objc_module_info_addrComment = "/* for this module address of the start of the (__OBJC,__module_info) section */";
        public DWord objc_module_info_size = new DWord();
        public final static String objc_module_info_sizeComment = "/* for this module size of the (__OBJC,__module_info) section */";

        public dylib_module(Addressable parent) {
            super(parent);
        }

        @Override
        public LinkedList<Data> getStructureData() {
            module_name.setComment(module_nameComment);
            iextdefsym.setComment(iextdefsymComment);
            nextdefsym.setComment(nextdefsymComment);
            irefsym.setComment(irefsymComment);
            ilocalsym.setComment(ilocalsymComment);
            nlocalsym.setComment(nlocalsymComment);
            iextrel.setComment(iextrelComment);
            nextrel.setComment(nextrelComment);
            iinit_iterm.setComment(iinit_itermComment);
            ninit_nterm.setComment(ninit_ntermComment);
            objc_module_info_addr.setComment(objc_module_info_addrComment);
            objc_module_info_size.setComment(objc_module_info_sizeComment);
            nrefsym.setComment(nrefsymComment);
            return new LinkedList<>(Arrays.asList(module_name, iextdefsym, nextdefsym, irefsym, ilocalsym, nlocalsym, iextrel, nextrel, iinit_iterm, ninit_nterm, objc_module_info_addr, objc_module_info_size, nrefsym));
        }
    }

    ;

    /* a 64-bit module table entry */
    public class dylib_module_64 extends DataStructure {
        public DWord module_name = new DWord();
        public final static String module_nameComment = "/* the module name (index into string table) */";
        public DWord iextdefsym = new DWord();
        public final static String iextdefsymComment = "/* index into externally defined symbols */";
        public DWord nextdefsym = new DWord();
        public final static String nextdefsymComment = "/* number of externally defined symbols */";
        public DWord irefsym = new DWord();
        public final static String irefsymComment = "/* index into reference symbol table */";
        public DWord nrefsym = new DWord();
        public final static String nrefsymComment = "/* number of reference symbol table entries */";
        public DWord ilocalsym = new DWord();
        public final static String ilocalsymComment = "/* index into symbols for local symbols */";
        public DWord nlocalsym = new DWord();
        public final static String nlocalsymComment = "/* number of local symbols */";
        public DWord iextrel = new DWord();
        public final static String iextrelComment = "/* index into external relocation entries */";
        public DWord nextrel = new DWord();
        public final static String nextrelComment = "/* number of external relocation entries */";
        public DWord iinit_iterm = new DWord();
        public final static String iinit_itermComment = "/* low 16 bits are the index into the init section, high 16 bits are the index into the term section */";
        public DWord ninit_nterm = new DWord();
        public final static String ninit_ntermComment = "/* low 16 bits are the number of init section entries, high 16 bits are the number of term section entries */";
        public DWord objc_module_info_size = new DWord();
        public final static String objc_module_info_sizeComment = "/* for this module size of the (__OBJC,__module_info) section */";
        public QWord objc_module_info_addr = new QWord();
        public final static String objc_module_info_addrComment = "/* for this module address of the start of the (__OBJC,__module_info) section */";

        public dylib_module_64(Addressable parent) {
            super(parent);
        }

        @Override
        public LinkedList<Data> getStructureData() {
            module_name.setComment(module_nameComment);
            iextdefsym.setComment(iextdefsymComment);
            nextdefsym.setComment(nextdefsymComment);
            irefsym.setComment(irefsymComment);
            ilocalsym.setComment(ilocalsymComment);
            nlocalsym.setComment(nlocalsymComment);
            iextrel.setComment(iextrelComment);
            nextrel.setComment(nextrelComment);
            iinit_iterm.setComment(iinit_itermComment);
            ninit_nterm.setComment(ninit_ntermComment);
            objc_module_info_addr.setComment(objc_module_info_addrComment);
            objc_module_info_size.setComment(objc_module_info_sizeComment);
            nrefsym.setComment(nrefsymComment);
            return new LinkedList<>(Arrays.asList(module_name, iextdefsym, nextdefsym, irefsym, ilocalsym, nlocalsym, iextrel, nextrel, iinit_iterm, ninit_nterm, objc_module_info_addr, objc_module_info_size, nrefsym));
        }
    }

    ;

    /*
     * The entries in the reference symbol table are used when loading the module
     * (both by the static and dynamic link editors) and if the module is unloaded
     * or replaced.  Therefore all external symbols (defined and undefined) are
     * listed in the module's reference table.  The flags describe the type of
     * reference that is being made.  The constants for the flags are defined in
     * <mach-o/nlist.h> as they are also used for symbol table entries.
     */
    public class dylib_reference extends DataStructure {
        public DWord isym = new DWord();
        public final static String isymComment = "/* index into the symbol table */";
        public DWord flags = new DWord();
        public final static String flagsComment = "/* flags to indicate the type of reference */";

        public dylib_reference(Addressable parent) {
            super(parent);
        }

        @Override
        public LinkedList<Data> getStructureData() {
            isym.setComment(isymComment);
            flags.setComment(flagsComment);
            return new LinkedList<>(Arrays.asList(isym, flags));
        }
    }

    ;

    /*
     * The twolevel_hints_command contains the offset and number of hints in the
     * two-level namespace lookup hints table.
     */
    public class twolevel_hints_command extends DataStructure {
        public DWord cmd = new DWord();
        public final static String cmdComment = "/* LC_TWOLEVEL_HINTS */";
        public DWord cmdsize = new DWord();
        public final static String cmdsizeComment = "/* sizeof(public class twolevel_hints_command) */";
        public DWord offset = new DWord();
        public final static String offsetComment = "/* offset to the hint table */";
        public DWord nhints = new DWord();
        public final static String nhintsComment = "/* number of hints in the hint table */";

        public twolevel_hints_command(Addressable parent) {
            super(parent);
        }

        @Override
        public LinkedList<Data> getStructureData() {
            cmd.setComment(cmdComment);
            cmdsize.setComment(cmdsizeComment);
            offset.setComment(offsetComment);
            nhints.setComment(nhintsComment);
            return new LinkedList<>(Arrays.asList(cmd, cmdsize, offset, nhints));
        }
    }

    ;

    /*
     * The entries in the two-level namespace lookup hints table are twolevel_hint
     * public classs.  These provide hints to the dynamic link editor where to start
     * looking for an undefined symbol in a two-level namespace image.  The
     * isub_image field is an index into the sub-images (sub-frameworks and
     * sub-umbrellas list) that made up the two-level image that the undefined
     * symbol was found in when it was built by the static link editor.  If
     * isub-image is 0 the the symbol is expected to be defined in library and not
     * in the sub-images.  If isub-image is non-zero it is an index into the array
     * of sub-images for the umbrella with the first index in the sub-images being
     * 1. The array of sub-images is the ordered list of sub-images of the umbrella
     * that would be searched for a symbol that has the umbrella recorded as its
     * primary library.  The table of contents index is an index into the
     * library's table of contents.  This is used as the starting point of the
     * binary search or a directed linear search.
     */
    public class twolevel_hint extends DataStructure {
        public DWord isub_image = new DWord();
        public final static String isub_imageComment = "/* index into the sub images */";
        public DWord itoc = new DWord();
        public final static String itocComment = "/* index into the table of contents */";

        public twolevel_hint(Addressable parent) {
            super(parent);
        }

        @Override
        public LinkedList<Data> getStructureData() {
            isub_image.setComment(isub_imageComment);
            itoc.setComment(itocComment);
            return new LinkedList<>(Arrays.asList(isub_image, itoc));
        }
    }

    ;

    /*
     * The prebind_cksum_command contains the value of the original check sum for
     * prebound files or zero.  When a prebound file is first created or modified
     * for other than updating its prebinding information the value of the check sum
     * is set to zero.  When the file has it prebinding re-done and if the value of
     * the check sum is zero the original check sum is calculated and stored in
     * cksum field of this load command in the output file.  If when the prebinding
     * is re-done and the cksum field is non-zero it is left unchanged from the
     * input file.
     */
    public class prebind_cksum_command extends DataStructure {
        public DWord cmd = new DWord();
        public final static String cmdComment = "/* LC_PREBIND_CKSUM */";
        public DWord cmdsize = new DWord();
        public final static String cmdsizeComment = "/* sizeof(public class prebind_cksum_command) */";
        public DWord cksum = new DWord();
        public final static String cksumComment = "/* the check sum or zero */";

        public prebind_cksum_command(Addressable parent) {
            super(parent);
        }

        @Override
        public LinkedList<Data> getStructureData() {
            cmd.setComment(cmdComment);
            cmdsize.setComment(cmdsizeComment);
            cksum.setComment(cksumComment);
            return new LinkedList<>(Arrays.asList(cmd, cmdsize, cksum));
        }
    }

    ;

    /*
     * The uuid load command contains a single 128-bit unique random number that
     * identifies an object produced by the static link editor.
     */
    public class uuid_command extends DataStructure {
        public DWord cmd = new DWord();
        public final static String cmdComment = "/* LC_UUID */";
        public DWord cmdsize = new DWord();
        public final static String cmdsizeComment = "/* sizeof(public class uuid_command) */";
        public char16 uuid = new char16();
        public final static String uuidComment = "/* the 128-bit uuid */";

        public uuid_command(Addressable parent) {
            super(parent);
        }

        @Override
        public LinkedList<Data> getStructureData() {
            cmd.setComment(cmdComment);
            cmdsize.setComment(cmdsizeComment);
            uuid.setComment(uuidComment);
            return new LinkedList<>(Arrays.asList(cmd, cmdsize, uuid));
        }
    }

    ;

    /*
     * The rpath_command contains a path which at runtime should be added to
     * the current run path used to find @rpath prefixed dylibs.
     */
    public class rpath_command extends DataStructure {
        public DWord cmd = new DWord();
        public final static String cmdComment = "/* LC_RPATH */";
        public DWord cmdsize = new DWord();
        public final static String cmdsizeComment = "/* includes string */";
        public lc_str path = new lc_str(this);
        public final static String pathComment = "/* path to add to run path */";

        public rpath_command(Addressable parent) {
            super(parent);
        }

        @Override
        public LinkedList<Data> getStructureData() {
            cmd.setComment(cmdComment);
            cmdsize.setComment(cmdsizeComment);
            path.setComment(pathComment);

            return new LinkedList<>(Arrays.asList(cmd, cmdsize));
        }
    }

    ;

    /*
 * The version_min_command contains the min OS version on which this
 * binary was built to run.
 */
    public class version_min_command extends DataStructure {
        public DWord cmd = new DWord();
        public final static String cmdComment = "/* LC_VERSION_MIN_MACOSX or LC_VERSION_MIN_IPHONEOS  */";
        public DWord cmdsize = new DWord();
        public final static String cmdsizeComment = "/* sizeof(struct min_version_command) */";
        public DWord version = new DWord();
        public final static String versionComment = "/* X.Y.Z is encoded in nibbles xxxx.yy.zz */";
        public DWord sdk = new DWord();
        public final static String sdkComment = "/* X.Y.Z is encoded in nibbles xxxx.yy.zz */";

        public version_min_command(Addressable parent) {
            super(parent);
        }

        @Override
        public LinkedList<Data> getStructureData() {
            cmd.setComment(cmdComment);
            cmdsize.setComment(cmdsizeComment);
            version.setComment(versionComment);
            sdk.setComment(sdkComment);
            return new LinkedList<>(Arrays.asList(cmd, cmdsize, version, sdk));
        }
    }

    ;


    /*
 * The linkedit_data_command contains the offsets and sizes of a blob
 * of data in the __LINKEDIT segment.
 */
    public class linkedit_data_command extends DataStructure {
        public DWord cmd = new DWord();
        public final static String cmdComment = "/* LC_CODE_SIGNATURE, LC_SEGMENT_SPLIT_INFO, LC_FUNCTION_STARTS, LC_DATA_IN_CODE, or LC_DYLIB_CODE_SIGN_DRS */";
        public DWord cmdsize = new DWord();
        public final static String cmdsizeComment = "/* sizeof(public class linkedit_data_command) */";
        public DWord dataoff = new DWord();
        public final static String dataoffComment = "/* file offset of data in __LINKEDIT segment */";
        public DWord datasize = new DWord();
        public final static String datasizeComment = "/* file size of data in __LINKEDIT segment  */";

        public linkedit_data_command(Addressable parent) {
            super(parent);
        }

        @Override
        public LinkedList<Data> getStructureData() {
            cmd.setComment(cmdComment);
            cmdsize.setComment(cmdsizeComment);
            dataoff.setComment(dataoffComment);
            datasize.setComment(datasizeComment);
            return new LinkedList<>(Arrays.asList(cmd, cmdsize, dataoff, datasize));
        }
    }

    ;

    /*
     * The encryption_info_command contains the file offset and size of an
     * of an encrypted segment.
     */
    public class encryption_info_command extends DataStructure {
        public DWord cmd = new DWord();
        public final static String cmdComment = "/* LC_ENCRYPTION_INFO */";
        public DWord cmdsize = new DWord();
        public final static String cmdsizeComment = "/* sizeof(public class encryption_info_command) */";
        public DWord cryptoff = new DWord();
        public final static String cryptoffComment = "/* file offset of encrypted range */";
        public DWord cryptsize = new DWord();
        public final static String cryptsizeComment = "/* file size of encrypted range */";
        public DWord cryptid = new DWord();
        public final static String cryptidComment = "/* which enryption system, 0 means not-encrypted yet */";

        public encryption_info_command(Addressable parent) {
            super(parent);
        }

        @Override
        public LinkedList<Data> getStructureData() {
            cmd.setComment(cmdComment);
            cmdsize.setComment(cmdsizeComment);
            cryptoff.setComment(cryptoffComment);
            cryptsize.setComment(cryptsizeComment);
            cryptid.setComment(cryptidComment);
            return new LinkedList<>(Arrays.asList(cmd, cmdsize, cryptoff, cryptsize, cryptid));
        }
    }

    ;

    /*
     * The dyld_info_command contains the file offsets and sizes of
     * the new compressed form of the information dyld needs to
     * load the image.  This information is used by dyld on Mac OS X
     * 10.6 and later.  All information pointed to by this command
     * is encoded using byte streams, so no endian swapping is needed
     * to interpret it.
     */
    public class dyld_info_command extends DataStructure {
        public DWord cmd = new DWord();
        public final static String cmdComment = "/* LC_DYLD_INFO or LC_DYLD_INFO_ONLY */";
        public DWord cmdsize = new DWord();
        public final static String cmdsizeComment = "/* sizeof(public class dyld_info_command) */";

        /*
         * Dyld rebases an image whenever dyld loads it at an address different
         * from its preferred address.  The rebase information is a stream
         * of byte sized opcodes whose symbolic names start with REBASE_OPCODE_.
         * Conceptually the rebase information is a table of tuples:
         *    <seg-index, seg-offset, type>
         * The opcodes are a compressed way to encode the table by only
         * encoding when a column changes.  In addition simple patterns
         * like "every n'th offset for m times" can be encoded in a few
         * bytes.
         */
        public DWord rebase_off = new DWord();
        public final static String rebase_offComment = "/* file offset to rebase info  */";
        public DWord rebase_size = new DWord();
        public final static String rebase_sizeComment = "/* size of rebase info   */";

        /*
         * Dyld binds an image during the loading process, if the image
         * requires any pointers to be initialized to symbols in other images.
         * The rebase information is a stream of byte sized
         * opcodes whose symbolic names start with BIND_OPCODE_.
         * Conceptually the bind information is a table of tuples:
         *    <seg-index, seg-offset, type, symbol-library-ordinal, symbol-name, addend>
         * The opcodes are a compressed way to encode the table by only
         * encoding when a column changes.  In addition simple patterns
         * like for runs of pointers initialzed to the same value can be
         * encoded in a few bytes.
         */
        public DWord bind_off = new DWord();
        public final static String bind_offComment = "/* file offset to binding info   */";
        public DWord bind_size = new DWord();
        public final static String bind_sizeComment = "/* size of binding info  */";

        /*
         * Some C++ programs require dyld to unique symbols so that all
         * images in the process use the same copy of some code/data.
         * This step is done after binding. The content of the weak_bind
         * info is an opcode stream like the bind_info.  But it is sorted
         * alphabetically by symbol name.  This enable dyld to walk
         * all images with weak binding information in order and look
         * for collisions.  If there are no collisions, dyld does
         * no updating.  That means that some fixups are also encoded
         * in the bind_info.  For instance, all calls to "operator new"
         * are first bound to libstdc++.dylib using the information
         * in bind_info.  Then if some image overrides operator new
         * that is detected when the weak_bind information is processed
         * and the call to operator new is then rebound.
         */
        public DWord weak_bind_off = new DWord();
        public final static String weak_bind_offComment = "/* file offset to weak binding info   */";
        public DWord weak_bind_size = new DWord();
        public final static String weak_bind_sizeComment = "/* size of weak binding info  */";

        /*
         * Some uses of external symbols do not need to be bound immediately.
         * Instead they can be lazily bound on first use.  The lazy_bind
         * are contains a stream of BIND opcodes to bind all lazy symbols.
         * Normal use is that dyld ignores the lazy_bind section when
         * loading an image.  Instead the static linker arranged for the
         * lazy pointer to initially point to a helper function which
         * pushes the offset into the lazy_bind area for the symbol
         * needing to be bound, then jumps to dyld which simply adds
         * the offset to lazy_bind_off to get the information on what
         * to bind.
         */
        public DWord lazy_bind_off = new DWord();
        public final static String lazy_bind_offComment = "/* file offset to lazy binding info */";
        public DWord lazy_bind_size = new DWord();
        public final static String lazy_bind_sizeComment = "/* size of lazy binding infs */";

        /*
         * The symbols exported by a dylib are encoded in a trie.  This
         * is a compact representation that factors out common prefixes.
         * It also reduces LINKEDIT pages in RAM because it encodes all
         * information (name, address, flags) in one small, contiguous range.
         * The export area is a stream of nodes.  The first node sequentially
         * is the start node for the trie.
         *
         * Nodes for a symbol start with a byte that is the length of
         * the exported symbol information for the string so far.
         * If there is no exported symbol, the byte is zero. If there
         * is exported info, it follows the length byte.  The exported
         * info normally consists of a flags and offset both encoded
         * in uleb128.  The offset is location of the content named
         * by the symbol.  It is the offset from the mach_header for
         * the image.
         *
         * After the initial byte and optional exported symbol information
         * is a byte of how many edges (0-255) that this node has leaving
         * it, followed by each edge.
         * Each edge is a zero terminated cstring of the addition chars
         * in the symbol, followed by a uleb128 offset for the node that
         * edge points to.
         *
         */
        public DWord export_off = new DWord();
        public final static String export_offComment = "/* file offset to lazy binding info */";
        public DWord export_size = new DWord();
        public final static String export_sizeComment = "/* size of lazy binding infs */";

        public dyld_info_command(Addressable parent) {
            super(parent);
        }

        @Override
        public LinkedList<Data> getStructureData() {
            cmd.setComment(cmdComment);
            cmdsize.setComment(cmdsizeComment);
            rebase_off.setComment(rebase_offComment);
            rebase_size.setComment(rebase_sizeComment);
            bind_off.setComment(bind_offComment);
            bind_size.setComment(bind_sizeComment);
            weak_bind_off.setComment(weak_bind_offComment);
            weak_bind_size.setComment(weak_bind_sizeComment);
            lazy_bind_off.setComment(lazy_bind_offComment);
            lazy_bind_size.setComment(lazy_bind_sizeComment);
            export_off.setComment(export_offComment);
            export_size.setComment(export_sizeComment);
            return new LinkedList<>(Arrays.asList(cmd, cmdsize, rebase_off, rebase_size, bind_off, bind_size, weak_bind_off, weak_bind_size, lazy_bind_off, lazy_bind_size, export_off, export_size));
        }
    }

    ;

    /*
     * The following are used to encode rebasing information
     */
    public static final int REBASE_TYPE_POINTER = 1;
    public static final int REBASE_TYPE_TEXT_ABSOLUTE32 = 2;
    public static final int REBASE_TYPE_TEXT_PCREL32 = 3;

    public static final DWord REBASE_OPCODE_MASK = new DWord("0x000000F0", Data.Type.DATA_BYTE, ByteOrder.BIG_ENDIAN);
    public static final DWord REBASE_IMMEDIATE_MASK = new DWord("0x0000000F", Data.Type.DATA_BYTE, ByteOrder.BIG_ENDIAN);
    public static final DWord REBASE_OPCODE_DONE = new DWord("0x00000000", Data.Type.DATA_BYTE, ByteOrder.BIG_ENDIAN);
    public static final DWord REBASE_OPCODE_SET_TYPE_IMM = new DWord("0x00000010", Data.Type.DATA_BYTE, ByteOrder.BIG_ENDIAN);
    public static final DWord REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB = new DWord("0x00000020", Data.Type.DATA_BYTE, ByteOrder.BIG_ENDIAN);
    public static final DWord REBASE_OPCODE_ADD_ADDR_ULEB = new DWord("0x00000030", Data.Type.DATA_BYTE, ByteOrder.BIG_ENDIAN);
    public static final DWord REBASE_OPCODE_ADD_ADDR_IMM_SCALED = new DWord("0x00000040", Data.Type.DATA_BYTE, ByteOrder.BIG_ENDIAN);
    public static final DWord REBASE_OPCODE_DO_REBASE_IMM_TIMES = new DWord("0x00000050", Data.Type.DATA_BYTE, ByteOrder.BIG_ENDIAN);
    public static final DWord REBASE_OPCODE_DO_REBASE_ULEB_TIMES = new DWord("0x00000060", Data.Type.DATA_BYTE, ByteOrder.BIG_ENDIAN);
    public static final DWord REBASE_OPCODE_DO_REBASE_ADD_ADDR_ULEB = new DWord("0x00000070", Data.Type.DATA_BYTE, ByteOrder.BIG_ENDIAN);
    public static final DWord REBASE_OPCODE_DO_REBASE_ULEB_TIMES_SKIPPING_ULEB = new DWord("0x00000080", Data.Type.DATA_BYTE, ByteOrder.BIG_ENDIAN);


    /*
     * The following are used to encode binding information
     */
    public static final int BIND_TYPE_POINTER = 1;
    public static final int BIND_TYPE_TEXT_ABSOLUTE32 = 2;
    public static final int BIND_TYPE_TEXT_PCREL32 = 3;

    public static final int BIND_SPECIAL_DYLIB_SELF = 0;
    public static final int BIND_SPECIAL_DYLIB_MAIN_EXECUTABLE = -1;
    public static final int BIND_SPECIAL_DYLIB_FLAT_LOOKUP = -2;

    public static final DWord BIND_SYMBOL_FLAGS_WEAK_IMPORT = new DWord("0x00000001", Data.Type.DATA_BYTE, ByteOrder.BIG_ENDIAN);
    public static final DWord BIND_SYMBOL_FLAGS_NON_WEAK_DEFINITION = new DWord("0x00000008", Data.Type.DATA_BYTE, ByteOrder.BIG_ENDIAN);

    public static final DWord BIND_OPCODE_MASK = new DWord("0x000000F0", Data.Type.DATA_BYTE, ByteOrder.BIG_ENDIAN);
    public static final DWord BIND_IMMEDIATE_MASK = new DWord("0x0000000F", Data.Type.DATA_BYTE, ByteOrder.BIG_ENDIAN);
    public static final DWord BIND_OPCODE_DONE = new DWord("0x00000000", Data.Type.DATA_BYTE, ByteOrder.BIG_ENDIAN);
    public static final DWord BIND_OPCODE_SET_DYLIB_ORDINAL_IMM = new DWord("0x00000010", Data.Type.DATA_BYTE, ByteOrder.BIG_ENDIAN);
    public static final DWord BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB = new DWord("0x00000020", Data.Type.DATA_BYTE, ByteOrder.BIG_ENDIAN);
    public static final DWord BIND_OPCODE_SET_DYLIB_SPECIAL_IMM = new DWord("0x00000030", Data.Type.DATA_BYTE, ByteOrder.BIG_ENDIAN);
    public static final DWord BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM = new DWord("0x00000040", Data.Type.DATA_BYTE, ByteOrder.BIG_ENDIAN);
    public static final DWord BIND_OPCODE_SET_TYPE_IMM = new DWord("0x00000050", Data.Type.DATA_BYTE, ByteOrder.BIG_ENDIAN);
    public static final DWord BIND_OPCODE_SET_ADDEND_SLEB = new DWord("0x00000060", Data.Type.DATA_BYTE, ByteOrder.BIG_ENDIAN);
    public static final DWord BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB = new DWord("0x00000070", Data.Type.DATA_BYTE, ByteOrder.BIG_ENDIAN);
    public static final DWord BIND_OPCODE_ADD_ADDR_ULEB = new DWord("0x00000080", Data.Type.DATA_BYTE, ByteOrder.BIG_ENDIAN);
    public static final DWord BIND_OPCODE_DO_BIND = new DWord("0x00000090", Data.Type.DATA_BYTE, ByteOrder.BIG_ENDIAN);
    public static final DWord BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB = new DWord("0x000000A0", Data.Type.DATA_BYTE, ByteOrder.BIG_ENDIAN);
    public static final DWord BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED = new DWord("0x000000B0", Data.Type.DATA_BYTE, ByteOrder.BIG_ENDIAN);
    public static final DWord BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB = new DWord("0x000000C0", Data.Type.DATA_BYTE, ByteOrder.BIG_ENDIAN);


    /*
     * The following are used on the flags byte of a terminal node
     * in the export information.
     */
    public static final DWord EXPORT_SYMBOL_FLAGS_KIND_MASK = new DWord("0x00000003", Data.Type.DATA_BYTE, ByteOrder.BIG_ENDIAN);
    public static final DWord EXPORT_SYMBOL_FLAGS_KIND_REGULAR = new DWord("0x00000000", Data.Type.DATA_BYTE, ByteOrder.BIG_ENDIAN);
    public static final DWord EXPORT_SYMBOL_FLAGS_KIND_THREAD_LOCAL = new DWord("0x00000001", Data.Type.DATA_BYTE, ByteOrder.BIG_ENDIAN);
    public static final DWord EXPORT_SYMBOL_FLAGS_WEAK_DEFINITION = new DWord("0x00000004", Data.Type.DATA_BYTE, ByteOrder.BIG_ENDIAN);
    public static final DWord EXPORT_SYMBOL_FLAGS_INDIRECT_DEFINITION = new DWord("0x00000008", Data.Type.DATA_BYTE, ByteOrder.BIG_ENDIAN);
    public static final DWord EXPORT_SYMBOL_FLAGS_HAS_SPECIALIZATIONS = new DWord("0x00000010", Data.Type.DATA_BYTE, ByteOrder.BIG_ENDIAN);
    /* In Version 2010:
    #define EXPORT_SYMBOL_FLAGS_REEXPORT				0x08
#define EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER			0x10
     */

    /*
     * The symseg_command contains the offset and size of the GNU style
     * symbol table information as described in the header file <symseg.h>.
     * The symbol roots of the symbol segments must also be aligned properly
     * in the file.  So the requirement of keeping the offsets aligned to a
     * multiple of a 4 bytes translates to the length field of the symbol
     * roots also being a multiple of a long.  Also the padding must again be
     * zeroed. (THIS IS OBSOLETE and no longer supported).
     */
    public class symseg_command extends DataStructure {
        public DWord cmd = new DWord();
        public final static String cmdComment = "/* LC_SYMSEG */";
        public DWord cmdsize = new DWord();
        public final static String cmdsizeComment = "/* sizeof(public class symseg_command) */";
        public DWord offset = new DWord();
        public final static String offsetComment = "/* symbol segment offset */";
        public DWord size = new DWord();
        public final static String sizeComment = "/* symbol segment size in bytes */";

        public symseg_command(Addressable parent) {
            super(parent);
        }

        @Override
        public LinkedList<Data> getStructureData() {
            cmd.setComment(cmdComment);
            cmdsize.setComment(cmdsizeComment);
            offset.setComment(offsetComment);
            size.setComment(sizeComment);
            return new LinkedList<>(Arrays.asList(cmd, cmdsize, offset, size));
        }
    }

    ;

    /*
     * The ident_command contains a free format string table following the
     * ident_command public classure.  The strings are null terminated and the size of
     * the command is padded out with zero bytes to a multiple of 4 bytes/
     * (THIS IS OBSOLETE and no longer supported).
     */
    public class ident_command extends DataStructure {
        public DWord cmd = new DWord();
        public final static String cmdComment = "/* LC_IDENT */";
        public DWord cmdsize = new DWord();
        public final static String cmdsizeComment = "/* strings that follow this command */";

        public ident_command(Addressable parent) {
            super(parent);
        }

        @Override
        public LinkedList<Data> getStructureData() {
            cmd.setComment(cmdComment);
            cmdsize.setComment(cmdsizeComment);
            return new LinkedList<>(Arrays.asList(cmd, cmdsize));
        }
    }

    ;

    /*
     * The fvmfile_command contains a reference to a file to be loaded at the
     * specified virtual address.  (Presently, this command is reserved for
     * internal use.  The kernel ignores this command when loading a program into
     * memory).
     */
    public class fvmfile_command extends DataStructure {
        public DWord cmd = new DWord();
        public final static String cmdComment = "/* LC_FVMFILE */";
        public DWord cmdsize = new DWord();
        public final static String cmdsizeComment = "/* includes pathname string */";
        public lc_str name = new lc_str(this);
        public final static String nameComment = "/* files pathname */";
        public DWord header_addr = new DWord();
        public final static String header_addrComment = "/* files virtual address */";

        public fvmfile_command(Addressable parent) {
            super(parent);
        }

        @Override
        public LinkedList<Data> getStructureData() {
            cmd.setComment(cmdComment);
            cmdsize.setComment(cmdsizeComment);
            name.setComment(nameComment);
            header_addr.setComment(header_addrComment);

            return new LinkedList<>(Arrays.asList(cmd, cmdsize, header_addr));
        }
    }

    ;


    /*
     * The entry_point_command is a replacement for thread_command.
     * It is used for main executables to specify the location (file offset)
     * of main().  If -stack_size was used at link time, the stacksize
     * field will contain the stack size need for the main thread.
     */
    public class entry_point_command extends DataStructure {
        public DWord cmd = new DWord();
        public final static String cmdComment = "/* LC_MAIN only used in MH_EXECUTE filetypes */";
        public DWord cmdsize = new DWord();
        public final static String cmdsizeComment = "/* 24 */";
        public QWord entryoff = new QWord();
        public final static String entryoffComment = "/* file (__TEXT) offset of main() */";
        public QWord stacksize = new QWord();
        public final static String stacksizeComment = "/* if not zero, initial stack size */";

        public entry_point_command(Addressable parent) {
            super(parent);
        }

        @Override
        public LinkedList<Data> getStructureData() {
            cmd.setComment(cmdComment);
            cmdsize.setComment(cmdsizeComment);
            entryoff.setComment(entryoffComment);
            stacksize.setComment(stacksizeComment);
            return new LinkedList<>(Arrays.asList(cmd, cmdsize, entryoff, stacksize));
        }
    }

    ;


    /*
     * The source_version_command is an optional load command containing
     * the version of the sources used to build the binary.
     */
    public class source_version_command extends DataStructure {
        public DWord cmd = new DWord();
        public final static String cmdComment = "/* LC_SOURCE_VERSION */";
        public DWord cmdsize = new DWord();
        public final static String cmdsizeComment = "/* 16 */";
        public QWord version = new QWord();
        public final static String versionComment = "/* A.B.C.D.E packed as a24.b10.c10.d10.e10 */";

        public source_version_command(Addressable parent) {
            super(parent);
        }

        @Override
        public LinkedList<Data> getStructureData() {
            cmd.setComment(cmdComment);
            cmdsize.setComment(cmdsizeComment);
            version.setComment(versionComment);
            return new LinkedList<>(Arrays.asList(cmd, cmdsize, version));
        }
    }

    ;


    /*
     * The LC_DATA_IN_CODE load commands uses a linkedit_data_command
     * to point to an array of data_in_code_entry entries. Each entry
     * describes a range of data in a code section.  This load command
     * is only used in final linked images.
     */
    public class data_in_code_entry extends DataStructure {
        public DWord offset = new DWord();
        public final static String offsetComment = "/* from mach_header to start of data range*/";
        public Word length = new Word();
        public final static String lengthComment = "/* number of bytes in data range */";
        public Word kind = new Word();
        public final static String kindComment = " /* a DICE_KIND_* value  */";

        public data_in_code_entry(Addressable parent) {
            super(parent);
        }

        @Override
        public LinkedList<Data> getStructureData() {
            offset.setComment(offsetComment);
            length.setComment(lengthComment);
            kind.setComment(kindComment);
            return new LinkedList<>(Arrays.asList(offset, length, kind));
        }
    }

    ;
    public static final Word DICE_KIND_DATA = new Word("0x0001", Data.Type.DATA_BYTE, ByteOrder.BIG_ENDIAN);  /* L$start$data$...  label */
    public static final Word DICE_KIND_JUMP_TABLE8 = new Word("0x0002", Data.Type.DATA_BYTE, ByteOrder.BIG_ENDIAN);  /* L$start$jt8$...   label */
    public static final Word DICE_KIND_JUMP_TABLE16 = new Word("0x0003", Data.Type.DATA_BYTE, ByteOrder.BIG_ENDIAN);  /* L$start$jt16$...  label */
    public static final Word DICE_KIND_JUMP_TABLE32 = new Word("0x0004", Data.Type.DATA_BYTE, ByteOrder.BIG_ENDIAN);  /* L$start$jt32$...  label */
    public static final Word DICE_KIND_ABS_JUMP_TABLE32 = new Word("0x0005", Data.Type.DATA_BYTE, ByteOrder.BIG_ENDIAN);  /* L$start$jta32$... label */


    /*
     * Sections of type S_THREAD_LOCAL_VARIABLES contain an array
     * of tlv_descriptor structures.
     */
    public class tlv_descriptor extends DataStructure {
        byte[] tlv_descriptor;
        public final static String tlv_descriptorComment = "/*tlv_descriptor/*";
        public QWord key = new QWord();
        public final static String keyComment = "/*key*/";
        public QWord offset = new QWord();
        public final static String offsetComment = "/*offset*/";

        public tlv_descriptor(Addressable parent) {
            super(parent);
        }

        @Override
        public LinkedList<Data> getStructureData() {
            key.setComment(keyComment);
            offset.setComment(offsetComment);
            return new LinkedList<>(Arrays.asList(key, offset));
        }
    }

    ;

}

//#endif /* _MACHO_LOADER_H_ */

