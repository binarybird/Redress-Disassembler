package abi.mach;

import abi.generic.Command;
import abi.generic.Header;
import abi.generic.Section;

public interface Loader {
/*
 * Copyright (c) 1999-2008 Apple Inc.  All Rights Reserved.
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
    //byte[] _MACHO_LOADER_H_

/*
 * This file describes the format of abi.mach object files.
 */
    //#include <stdint.h>

/*
 * <abi.mach/machine.h> is needed here for the cpu_type_t and cpu_subtype_t types
 * and contains the constants for the possible values of these types.
 */
    //#include <abi.mach/machine.h>

/*
 * <abi.mach/vm_prot.h> is needed here for the vm_prot_t type and contains the
 * constants that are or'ed together for the possible values of this type.
 */
    //#include <abi.mach/vm_prot.h>

/*
 * <machine/thread_status.h> is expected to define the flavors of the thread
 * states and the structures of those flavors for each machine.
 */
    //#include <abi.mach/machine/thread_status.h>
    //#include <architecture/byte_order.h>

    /* Constant for the magic field of the mach_header (32-bit architectures) */
    public static final byte[] MH_MAGIC  = {(byte)0xfe,(byte)0xed,(byte)0xfa,(byte)0xce};	/* the abi.mach magic number */
    public static final byte[] MH_CIGAM  = {(byte)0xce,(byte)0xfa,(byte)0xed,(byte)0xfe};	/* NXSwapInt(MH_MAGIC) */
    /* Constant for the magic field of the mach_header_64 (64-bit architectures) */
    public static final byte[] MH_MAGIC_64 = {(byte)0xfe,(byte)0xed,(byte)0xfa,(byte)0xcf}; /* the 64-bit abi.mach magic number */
    public static final byte[] MH_CIGAM_64 = {(byte)0xcf,(byte)0xfa,(byte)0xed,(byte)0xfe}; /* NXSwapInt(MH_MAGIC_64) */

    public static final byte[] HEADLENGTH = {(byte)0x20};
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
    public static final byte[] MH_OBJECT= {(byte)0x01};		/* relocatable object file */
    public static final byte[] MH_EXECUTE
            = {(byte)0x02}	;	/* demand paged executable file */


    public static final  byte[] MH_FVMLIB
            = {(byte)0x03};		/* fixed VM shared library file */
    public static final  byte[] MH_CORE
            = {(byte)0x04};		/* core file */
    public static final  byte[] MH_PRELOAD
            = {(byte)0x05};		/* preloaded executable file */
    public static final  byte[] MH_DYLIB
            = {(byte)0x06};		/* dynamically bound shared library */
    public static final  byte[] MH_DYLINKER
            = {(byte)0x07};		/* dynamic link editor */
    public static final  byte[] MH_BUNDLE
            = {(byte)0x08};		/* dynamically bound bundle file */
    public static final  byte[] MH_DYLIB_STUB
            = {(byte)0x09};		/* shared library stub for static */
    /*  linking only, no section contents */
    public static final  byte[] MH_DSYM
            = {(byte)0x0a};		/* companion file with only debug */
    /*  sections */
    public static final  byte[] MH_KEXT_BUNDLE
            = {(byte)0x0b};		/* x86_64 kexts */
    /* Constants for the flags field of the mach_header */
    public static final  byte[] MH_NOUNDEFS
            = {(byte)0x01};		/* the object file has no undefined
					   references */
    public static final  byte[] MH_INCRLINK
            = {(byte)0x02};		/* the object file is the output of an
					   incremental link against a base file
					   and can't be link edited again */
    public static final  byte[] MH_DYLDLINK
            = {(byte)0x04};		/* the object file is input for the
					   dynamic linker and can't be staticly
					   link edited again */
    public static final  byte[] MH_BINDATLOAD
            = {(byte)0x08};		/* the object file's undefined
					   references are bound by the dynamic
					   linker when loaded. */
    public static final  byte[] MH_PREBOUND
            = {(byte)0x10};		/* the file has its dynamic undefined
					   references prebound. */
    public static final  byte[] MH_SPLIT_SEGS
            = {(byte)0x20};		/* the file has its read-only and
					   read-write segments split */
    public static final  byte[] MH_LAZY_INIT
            = {(byte)0x40};		/* the shared library init routine is
					   to be run lazily via catching memory
					   faults to its writeable segments
					   (obsolete) */
    public static final  byte[] MH_TWOLEVEL
            = {(byte)0x80};		/* the image is using two-level name
					   space bindings */
    public static final  byte[] MH_FORCE_FLAT
            = {(byte)0x01,(byte)0x00};		/* the executable is forcing all images
					   to use flat name space bindings */
    public static final  byte[] MH_NOMULTIDEFS
            = {(byte)0x02,(byte)0x00};		/* this umbrella guarantees no multiple
					   defintions of symbols in its
					   sub-images so the two-level namespace
					   hints can always be used. */
    public static final  byte[] MH_NOFIXPREBINDING
            = {(byte)0x04,(byte)0x00};	/* do not have dyld notify the
					   prebinding agent about this
					   executable */
    public static final  byte[] MH_PREBINDABLE
            = {(byte)0x08,(byte)0x00};           /* the binary is not prebound but can
					   have its prebinding redone. only used
                                           when MH_PREBOUND is not set. */
    public static final  byte[] MH_ALLMODSBOUND
            = {(byte)0x10,(byte)0x00};		/* indicates that this binary binds to
                                           all two-level namespace modules of
					   its dependent libraries. only used
					   when MH_PREBINDABLE and MH_TWOLEVEL
					   are both set. */
    public static final  byte[] MH_SUBSECTIONS_VIA_SYMBOLS
            = {(byte)0x20,(byte)0x00};/* safe to divide up the sections into
					    sub-sections via symbols for dead
					    code stripping */
    public static final  byte[] MH_CANONICAL
            = {(byte)0x40,(byte)0x00};		/* the binary has been canonicalized
					   via the unprebind operation */
    public static final  byte[] MH_WEAK_DEFINES
            = {(byte)0x80,(byte)0x00};		/* the final linked image contains
					   external weak symbols */
    public static final  byte[] MH_BINDS_TO_WEAK
            = {(byte)0x01,(byte)0x00,(byte)0x00};	/* the final linked image uses
					   weak symbols */
    public static final  byte[] MH_ALLOW_STACK_EXECUTION
            = {(byte)0x02,(byte)0x00,(byte)0x00};/* When this bit is set, all stacks
					   in the task will be given stack
					   execution privilege.  Only used in
					   MH_EXECUTE filetypes. */
    public static final  byte[] MH_DEAD_STRIPPABLE_DYLIB
            = {(byte)0x40,(byte)0x00,(byte)0x00}; /* Only for use on dylibs.  When
					     linking against a dylib that
					     has this bit set, the static linker
					     will automatically not create a
					     LC_LOAD_DYLIB load command to the
					     dylib if no symbols are being
					     referenced from the dylib. */
    public static final  byte[] MH_ROOT_SAFE
            = {(byte)0x04,(byte)0x00,(byte)0x00};           /* When this bit is set, the binary
					  declares it is safe for use in
					  processes with uid zero */
    public static final  byte[] MH_SETUID_SAFE
            = {(byte)0x08,(byte)0x00,(byte)0x00};         /* When this bit is set, the binary
					  declares it is safe for use in
					  processes when issetugid() is true */
    public static final  byte[] MH_NO_REEXPORTED_DYLIBS
            = {(byte)0x10,(byte)0x00,(byte)0x00}; /* When this bit is set on a dylib,
					  the static linker does not need to
					  examine dependent dylibs to see
					  if any are re-exported */
    public static final  byte[] MH_PIE
            = {(byte)0x20,(byte)0x00,(byte)0x00};			/* When this bit is set, the OS will
					   load the main executable at a
					   random address.  Only used in
					   MH_EXECUTE filetypes. */
    /*
     * After MacOS X 10.1 when a new load command is added that is required to be
     * understood by the dynamic linker for the image to execute properly the
     * LC_REQ_DYLD bit will be or'ed into the load command constant.  If the dynamic
     * linker sees such a load command it it does not understand will issue a
     * "unknown load command required for execution" error and refuse to use the
     * image.  Other load commands without this bit that are not understood will
     * simply be ignored.
     */
    public static final  byte[] LC_REQ_DYLD
            = {(byte)0x80,(byte)0x00,(byte)0x00,(byte)0x00};
    /*
     * load a dynamically linked shared library that is allowed to be missing
     * (all symbols are weak imported).
     */
//    public static final byte[] LC_LOAD_WEAK_DYLIB= {((byte)0x18|LC_REQ_DYLD)};
//    public static final byte[] LC_RPATH= ((byte)0x1c|LC_REQ_DYLD);  /* runpath additions */
//    public static final byte[] LC_REEXPORT_DYLIB= ((byte)0x1f|LC_REQ_DYLD); /* load and re-export dylib */
//    public static final byte[] LC_DYLD_INFO_ONLY= ((byte)0x22|LC_REQ_DYLD);	/* compressed dyld information only */


    /* Constants for the cmd field of all load commands, the type */
    public static final  byte[] LC_SEGMENT
            = {(byte)0x1};	/* segment of this file to be mapped */
    public static final  byte[] LC_SYMTAB
            = {(byte)0x2};	/* link-edit stab symbol table info */
    public static final  byte[] LC_SYMSEG
            = {(byte)0x3};	/* link-edit gdb symbol table info (obsolete) */
    public static final  byte[] LC_THREAD
            = {(byte)0x4};	/* thread */
    public static final  byte[] LC_UNIXTHREAD
            = {(byte)0x5};	/* unix thread (includes a stack) */
    public static final  byte[] LC_LOADFVMLIB
            = {(byte)0x6};	/* load a specified fixed VM shared library */
    public static final  byte[] LC_IDFVMLIB
            = {(byte)0x7};	/* fixed VM shared library identification */
    public static final  byte[] LC_IDENT
            = {(byte)0x8};	/* object identification info (obsolete) */
    public static final  byte[] LC_FVMFILE
            = {(byte)0x9};	/* fixed VM file inclusion (internal use) */
    public static final  byte[] LC_PREPAGE
            = {(byte)0xa} ;    /* prepage command (internal use) */
    public static final  byte[] LC_DYSYMTAB
            = {(byte)0xb};	/* dynamic link-edit symbol table info */
    public static final  byte[] LC_LOAD_DYLIB
            = {(byte)0xc};	/* load a dynamically linked shared library */
    public static final  byte[] LC_ID_DYLIB
            = {(byte)0xd};	/* dynamically linked shared lib ident */
    public static final  byte[] LC_LOAD_DYLINKER
            = {(byte)0xe};	/* load a dynamic linker */
    public static final  byte[] LC_ID_DYLINKER
            = {(byte)0xf};	/* dynamic linker identification */
    public static final  byte[] LC_PREBOUND_DYLIB
            = {(byte)0x10};	/* modules prebound for a dynamically */
    /*  linked shared library */
    public static final  byte[] LC_ROUTINES
            = {(byte)0x11};	/* image routines */
    public static final  byte[] LC_SUB_FRAMEWORK
            = {(byte)0x12};	/* sub framework */
    public static final  byte[] LC_SUB_UMBRELLA
            = {(byte)0x13};	/* sub umbrella */
    public static final  byte[] LC_SUB_CLIENT
            = {(byte)0x14};	/* sub client */
    public static final  byte[] LC_SUB_LIBRARY
            = {(byte)0x15};	/* sub library */
    public static final  byte[] LC_TWOLEVEL_HINTS
            = {(byte)0x16};	/* two-level namespace lookup hints */
    public static final  byte[] LC_PREBIND_CKSUM
            = {(byte)0x17};	/* prebind checksum */
    public static final  byte[] LC_SEGMENT_64
            = {(byte)0x19};	/* 64-bit segment of this file to be
				   mapped */
    public static final  byte[] LC_ROUTINES_64
            = {(byte)0x1a};	/* 64-bit image routines */
    public static final  byte[] LC_UUID
            = {(byte)0x1b};	/* the uuid */
    public static final  byte[] LC_CODE_SIGNATURE
            = {(byte)0x1d};	/* local of code signature */
    public static final  byte[] LC_SEGMENT_SPLIT_INFO
            = {(byte)0x1e}; /* local of info to split segments */
    public static final  byte[] LC_LAZY_LOAD_DYLIB
            = {(byte)0x20};	/* delay load of dylib until first use */
    public static final  byte[] LC_ENCRYPTION_INFO
            = {(byte)0x21};	/* encrypted segment information */
    public static final  byte[] LC_DYLD_INFO
            = {(byte)0x22};	/* compressed dyld information */
    /* Constants for the flags field of the segment_command */
    public static final  byte[] SG_HIGHVM
            = {(byte)0x1};	/* the file contents for this segment is for
				   the high part of the VM space, the low part
				   is zero filled (for stacks in core files) */
    public static final  byte[] SG_FVMLIB
            = {(byte)0x2};	/* this segment is the VM that is allocated by
				   a fixed VM library, for overlap checking in
				   the link editor */
    public static final  byte[] SG_NORELOC
            = {(byte)0x4};	/* this segment has nothing that was relocated
				   in it and nothing relocated to it, that is
				   it maybe safely replaced without relocation*/
    public static final  byte[] SG_PROTECTED_VERSION_1
            = {(byte)0x8}; /* This segment is protected.  If the
				       segment starts at file offset 0, the
				       first page of the segment is not
				       protected.  All other pages of the
				       segment are protected. */
    /*
     * The flags field of a section structure is separated into two parts a section
     * type and section attributes.  The section types are mutually exclusive (it
     * can only have one type) but the section attributes are not (it may have more
     * than one attribute).
     */
    public static final  byte[] SECTION_TYPE
            = {(byte)0x00,(byte)0x00,(byte)0x00,(byte)0xff};	/* 256 section types */
    public static final  byte[] SECTION_ATTRIBUTES
            = {(byte)0xff,(byte)0xff,(byte)0xff,(byte)0x00};	/*  24 section attributes */


    /* Constants for the type of a section */
    public static final  byte[] S_REGULAR
            = {(byte)0x0};	/* regular section */
    public static final  byte[] S_ZEROFILL
            = {(byte)0x1};	/* zero fill on demand section */


    public static final  byte[] S_CSTRING_LITERALS
            = {(byte)0x2};	/* section with only literal C strings*/


    public static final  byte[] S_4BYTE_LITERALS
            = {(byte)0x3};	/* section with only 4 byte literals */
    public static final  byte[] S_8BYTE_LITERALS
            = {(byte)0x4};	/* section with only 8 byte literals */
    public static final  byte[] S_LITERAL_POINTERS
            = {(byte)0x5};	/* section with only pointers to */
    /*  literals */
/*
 * For the two types of symbol pointers sections and the symbol stubs section
 * they have indirect symbol table entries.  For each of the entries in the
 * section the indirect symbol table entries, in corresponding order in the
 * indirect symbol table, start at the index stored in the reserved1 field
 * of the section structure.  Since the indirect symbol table entries
 * correspond to the entries in the section the number of indirect symbol table
 * entries is inferred from the size of the section divided by the size of the
 * entries in the section.  For symbol pointers sections the size of the entries
 * in the section is 4 bytes and for symbol stubs sections the byte size of the
 * stubs is stored in the reserved2 field of the section structure.
 */
    public static final  byte[] S_NON_LAZY_SYMBOL_POINTERS
            = {(byte)0x6};	/* section with only non-lazy
						   symbol pointers */
    public static final  byte[] S_LAZY_SYMBOL_POINTERS
            = {(byte)0x7};	/* section with only lazy symbol
						   pointers */


    public static final  byte[] S_SYMBOL_STUBS
            = {(byte)0x8};	/* section with only symbol
						   stubs, byte size of stub in
						   the reserved2 field */


    public static final  byte[] S_MOD_INIT_FUNC_POINTERS
            = {(byte)0x9};	/* section with only function
						   pointers for initialization*/
    public static final  byte[] S_MOD_TERM_FUNC_POINTERS
            = {(byte)0xa};	/* section with only function
						   pointers for termination */
    public static final  byte[] S_COALESCED
            = {(byte)0xb};	/* section contains symbols that
						   are to be coalesced */
    public static final  byte[] S_GB_ZEROFILL
            = {(byte)0xc};	/* zero fill on demand section
						   (that can be larger than 4
						   gigabytes) */
    public static final  byte[] S_INTERPOSING
            = {(byte)0xd};	/* section with only pairs of
						   function pointers for
						   interposing */
    public static final  byte[] S_16BYTE_LITERALS
            = {(byte)0xe};	/* section with only 16 byte
						   literals */
    public static final  byte[] S_DTRACE_DOF
            = {(byte)0xf};	/* section contains
						   DTrace Object Format */
    public static final  byte[] S_LAZY_DYLIB_SYMBOL_POINTERS
            = {(byte)0x10};	/* section with only lazy
						   symbol pointers to lazy
						   loaded dylibs */
    /*
     * Constants for the section attributes part of the flags field of a section
     * structure.
     */
    public static final  byte[] SECTION_ATTRIBUTES_USR
            = {(byte)0xff,(byte)0x00,(byte)0x00,(byte)0x00};	/* User setable attributes */
    public static final  byte[] S_ATTR_PURE_INSTRUCTIONS
            = {(byte)0x80,(byte)0x00,(byte)0x00,(byte)0x00};	/* section contains only true
						   machine instructions */
    public static final  byte[] S_ATTR_NO_TOC
            = {(byte)0x40,(byte)0x00,(byte)0x00,(byte)0x00};	/* section contains coalesced
						   symbols that are not to be
						   in a ranlib table of
						   contents */
    public static final  byte[] S_ATTR_STRIP_STATIC_SYMS
            = {(byte)0x20,(byte)0x00,(byte)0x00,(byte)0x00};	/* ok to strip static symbols
						   in this section in files
						   with the MH_DYLDLINK flag */
    public static final  byte[] S_ATTR_NO_DEAD_STRIP
            = {(byte)0x10,(byte)0x00,(byte)0x00,(byte)0x00};	/* no dead stripping */
    public static final  byte[] S_ATTR_LIVE_SUPPORT
            = {(byte)0x08,(byte)0x00,(byte)0x00,(byte)0x00};	/* blocks are live if they
						   reference live blocks */
    public static final  byte[] S_ATTR_SELF_MODIFYING_CODE
            = {(byte)0x04,(byte)0x00,(byte)0x00,(byte)0x00};	/* Used with i386 code stubs
						   written on by dyld */
    /*
     * If a segment contains any sections marked with S_ATTR_DEBUG then all
     * sections in that segment must have this attribute.  No section other than
     * a section marked with this attribute may reference the contents of this
     * section.  A section with this attribute may contain no symbols and must have
     * a section type S_REGULAR.  The static linker will not copy section contents
     * from sections with this attribute into its output file.  These sections
     * generally contain DWARF debugging info.
     */
    public static final  byte[] S_ATTR_DEBUG
            = {(byte)0x02,(byte)0x00,(byte)0x00,(byte)0x00};	/* a debug section */
    public static final  byte[] SECTION_ATTRIBUTES_SYS
            = {(byte)0x00,(byte)0xff,(byte)0xff,(byte)0x00};	/* system setable attributes */
    public static final  byte[] S_ATTR_SOME_INSTRUCTIONS
            = {(byte)0x00,(byte)0x00,(byte)0x04,(byte)0x00};	/* section contains some
						   machine instructions */
    public static final  byte[] S_ATTR_EXT_RELOC
            = {(byte)0x00,(byte)0x00,(byte)0x02,(byte)0x00};	/* section has external
						   relocation entries */
    public static final  byte[] S_ATTR_LOC_RELOC
            = {(byte)0x00,(byte)0x00,(byte)0x01,(byte)0x00};	/* section has local
						   relocation entries */
    public static final String SEG_PAGEZERO=
            "__PAGEZERO";	/* the pagezero segment which has no */
    public static final String SEG_TEXT=
            "__TEXT";	/* the tradition UNIX text segment */
    public static final String SECT_TEXT=
            "__text";	/* the real text part of the text */
    /* section no headers, and no padding */
    public static final String SECT_FVMLIB_INIT0=
            "__fvmlib_init0";	/* the fvmlib initialization */
    /*  section */
    public static final String SECT_FVMLIB_INIT1=
            "__fvmlib_init1";	/* the section following the */
    public static final String SEG_DATA=
            "__DATA";	/* the tradition UNIX data segment */
    public static final String SECT_DATA=
            "__data";	/* the real initialized data section */
    /* no padding, no bss overlap */
    public static final String SECT_BSS=
            "__bss";		/* the real uninitialized data section*/
    /* no padding */
    public static final String SECT_COMMON=
            "__common";	/* the section common symbols are */
    public static final String SEG_OBJC=
            "__OBJC";	/* objective-C runtime segment */
    public static final String SECT_OBJC_SYMBOLS=
            "__symbol_table";	/* symbol table */


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
    public static final String SECT_OBJC_MODULES=
            "__module_info";	/* module information */
    /* protections and catches NULL */
					/* references for MH_EXECUTE files */
    public static final String SECT_OBJC_STRINGS=
            "__selector_strs";	/* string table */
    public static final String SECT_OBJC_REFS=
            "__selector_refs";	/* string table */
    public static final String SEG_ICON=
            "__ICON";	/* the icon segment */
    public static final String SECT_ICON_HEADER=
            "__header";	/* the icon headers */
    /*  fvmlib initialization */
						/*  section */
    public static final String SECT_ICON_TIFF=
            "__tiff";	/* the icons in tiff format */
    public static final String SEG_LINKEDIT=
            "__LINKEDIT";	/* the segment containing all structs */
    public static final String SEG_UNIXSTACK=
            "__UNIXSTACK";	/* the unix stack segment */
    public static final String SEG_IMPORT=
            "__IMPORT";	/* the segment for the self (dyld) */
    /* allocated in by the link editor */
    /*
     * An indirect symbol table entry is simply a 32bit index into the symbol table
     * to the symbol that the pointer or stub is refering to.  Unless it is for a
     * non-lazy symbol pointer section for a defined symbol which strip(1) as
     * removed.  In which case it has the value INDIRECT_SYMBOL_LOCAL.  If the
     * symbol was also absolute INDIRECT_SYMBOL_ABS is or'ed with that.
     */
    public static final  byte[] INDIRECT_SYMBOL_LOCAL
            = {(byte)0x80,(byte)0x00,(byte)0x00,(byte)0x00};
    public static final  byte[] INDIRECT_SYMBOL_ABS
            = {(byte)0x40,(byte)0x00,(byte)0x00,(byte)0x00};
    /*
     * The following are used to encode rebasing information
     */
    public static final  byte[] REBASE_TYPE_POINTER =
            {(byte)0x1};
    public static final  byte[] REBASE_TYPE_TEXT_ABSOLUTE32 =
            {(byte)0x2};
    public static final  byte[] REBASE_TYPE_TEXT_PCREL32 =
            {(byte)0x3};
    public static final  byte[] REBASE_OPCODE_MASK
            = {(byte)0xF0};
    public static final  byte[] REBASE_IMMEDIATE_MASK
            = {(byte)0x0F};
    public static final  byte[] REBASE_OPCODE_DONE
            = {(byte)0x00};
    public static final  byte[] REBASE_OPCODE_SET_TYPE_IMM
            = {(byte)0x10};
    /* created and maintained by the link */
					/* editor.  Created with -seglinkedit */
					/* option to ld(1) for MH_EXECUTE and */
					/* FVMLIB file types only */
    public static final  byte[] REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB
            = {(byte)0x20};
    public static final  byte[] REBASE_OPCODE_ADD_ADDR_ULEB
            = {(byte)0x30};
    /* modifing code stubs that has read, */
					/* write and execute permissions */
    public static final  byte[] REBASE_OPCODE_ADD_ADDR_IMM_SCALED
            = {(byte)0x40};


    public static final  byte[] REBASE_OPCODE_DO_REBASE_IMM_TIMES
            = {(byte)0x50};


    public static final  byte[] REBASE_OPCODE_DO_REBASE_ULEB_TIMES
            = {(byte)0x60};


    public static final  byte[] REBASE_OPCODE_DO_REBASE_ADD_ADDR_ULEB
            = {(byte)0x70};


    public static final  byte[] REBASE_OPCODE_DO_REBASE_ULEB_TIMES_SKIPPING_ULEB
            = {(byte)0x80};


    /*
     * The following are used to encode binding information
     */
    public static final  byte[] BIND_TYPE_POINTER =
            {(byte)0x1};


    public static final  byte[] BIND_TYPE_TEXT_ABSOLUTE32 =
            {(byte)0x2};


    public static final  byte[] BIND_TYPE_TEXT_PCREL32 =
            {(byte)0x3};


    public static final  byte[] BIND_SPECIAL_DYLIB_SELF =
            {(byte)0x0};


    public static final  byte[] BIND_SPECIAL_DYLIB_MAIN_EXECUTABLE =
            {(byte)0x1};


    public static final  byte[] BIND_SPECIAL_DYLIB_FLAT_LOOKUP =
            {(byte)0x2};


    public static final  byte[] BIND_SYMBOL_FLAGS_WEAK_IMPORT
            = {(byte)0x1};


    public static final  byte[] BIND_SYMBOL_FLAGS_NON_WEAK_DEFINITION
            = {(byte)0x8};


    public static final  byte[] BIND_OPCODE_MASK
            = {(byte)0xF0};


    public static final  byte[] BIND_IMMEDIATE_MASK
            = {(byte)0x0F};


    public static final  byte[] BIND_OPCODE_DONE
            = {(byte)0x00};
    public static final  byte[] BIND_OPCODE_SET_DYLIB_ORDINAL_IMM
            = {(byte)0x10};
    public static final  byte[] BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB
            = {(byte)0x20};


    public static final  byte[] BIND_OPCODE_SET_DYLIB_SPECIAL_IMM
            = {(byte)0x30};


    public static final  byte[] BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM
            = {(byte)0x40};


    public static final  byte[] BIND_OPCODE_SET_TYPE_IMM
            = {(byte)0x50};


    public static final  byte[] BIND_OPCODE_SET_ADDEND_SLEB
            = {(byte)0x60};


    public static final  byte[] BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB
            = {(byte)0x70};


    public static final  byte[] BIND_OPCODE_ADD_ADDR_ULEB
            = {(byte)0x80};


    byte[] BIND_OPCODE_DO_BIND
            = {(byte)0x90};


    public static final  byte[] BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB
            = {(byte)0xA0};


    public static final  byte[] BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED
            = {(byte)0xB0};


    public static final  byte[] BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB
            = {(byte)0xC0};

    /*
     * The following are used on the flags byte of a terminal node
     * in the export information.
     */
    public static final  byte[] EXPORT_SYMBOL_FLAGS_KIND_MASK
            = {(byte)0x03};


    public static final  byte[] EXPORT_SYMBOL_FLAGS_KIND_REGULAR
            = {(byte)0x00};
    public static final  byte[] EXPORT_SYMBOL_FLAGS_KIND_THREAD_LOCAL
            = {(byte)0x01};
    public static final  byte[] EXPORT_SYMBOL_FLAGS_WEAK_DEFINITION
            = {(byte)0x04};
    public static final  byte[] EXPORT_SYMBOL_FLAGS_INDIRECT_DEFINITION
            = {(byte)0x08};
    public static final  byte[] EXPORT_SYMBOL_FLAGS_HAS_SPECIALIZATIONS
            = {(byte)0x10};

    /*
     * The 32-bit abi.mach header appears at the very beginning of the object file for
     * 32-bit architectures.
     */
    public class cpu_type_t {

    }

    public class cpu_subtype_t{

    }

    public class mach_header implements Header{
        public byte[] magic;		/* abi.mach magic number identifier */
        public cpu_type_t cputype;	/* cpu specifier */
        public cpu_subtype_t cpusubtype;	/* machine specifier */
        public byte[] filetype;	/* type of file */
        public byte[] ncmds;		/* number of load commands */
        public byte[] sizeofcmds;	/* the size of all the load commands */
        public byte[] flags;		/* flags */
    }

    /*
     * The 64-bit abi.mach header appears at the very beginning of object files for
     * 64-bit architectures.
     */
    public class mach_header_64 implements Header{
        public byte[] magic;		/* abi.mach magic number identifier */
        public cpu_type_t cputype;	/* cpu specifier */
        public cpu_subtype_t cpusubtype;	/* machine specifier */
        public byte[] filetype;	/* type of file */
        public byte[] ncmds;		/* number of load commands */
        public byte[] sizeofcmds;	/* the size of all the load commands */
        public byte[] flags;		/* flags */
        public byte[] reserved;	/* reserved */
    }

    /*
     * The load commands directly follow the mach_header.  The total size of all
     * of the commands is given by the sizeofcmds field in the mach_header.  All
     * load commands must have as their first two fields cmd and cmdsize.  The cmd
     * field is filled in with a constant for that command type.  Each command type
     * has a structure specifically for it.  The cmdsize field is the size in bytes
     * of the particular load command structure plus anything that follows it that
     * is a part of the load command (i.e. section structures, strings, etc.).  To
     * advance to the next load command the cmdsize can be added to the offset or
     * pointer of the current load command.  The cmdsize for 32-bit architectures
     * MUST be a multiple of 4 bytes and for 64-bit architectures MUST be a multiple
     * of 8 bytes (these are forever the maximum alignment of any load commands).
     * The padded bytes must be zero.  All tables in the object file must also
     * follow these rules so the file can be memory mapped.  Otherwise the pointers
     * to these tables will not work well or at all on some machines.  With all
     * padding zeroed like objects will compare byte for byte.
     */
    public class load_command implements Command {
        public byte[] cmd;		/* type of load command */
        public byte[] cmdsize;	/* total size of command in bytes */
    }

    /*
     * A variable length string in a load command is represented by an lc_str
     * union.  The strings are stored just after the load command structure and
     * the offset is from the start of the load command structure.  The size
     * of the string is reflected in the cmdsize field of the load command.
     * Once again any padded bytes to bring the cmdsize field to a multiple
     * of 4 bytes must be zero.
     */
    public class lc_str

    {
        public byte[] offset;	/* offset to the string */

        char[] ptr;	/* pointer to the string */

    }

    public class vm_prot_t implements Command {

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
     * section structures directly follow the segment command and their size is
     * reflected in cmdsize.
     */
    public class segment_command  implements Command { /* for 32-bit architectures */
        public byte[] cmd;		/* LC_SEGMENT */
        public byte[] cmdsize;	/* includes sizeof section structs */
        public byte[] segname;	/* segment name */
        public byte[] vmaddr;		/* memory address of this segment */
        public byte[] vmsize;		/* memory size of this segment */
        public byte[] fileoff;	/* file offset of this segment */
        public byte[] filesize;	/* amount to map from the file */
        public vm_prot_t maxprot;	/* maximum VM protection */
        public vm_prot_t initprot;	/* initial VM protection */
        public byte[] nsects;		/* number of sections in segment */
        public byte[] flags;		/* flags */
    }

    /*
     * The 64-bit segment load command indicates that a part of this file is to be
     * mapped into a 64-bit task's address space.  If the 64-bit segment has
     * sections then section_64 structures directly follow the 64-bit segment
     * command and their size is reflected in cmdsize.
     */
    public class segment_command_64  implements Command { /* for 64-bit architectures */
        public byte[] cmd;		/* LC_SEGMENT_64 */
        public byte[] cmdsize;	/* includes sizeof section_64 structs */
        public byte[] segname;	/* segment name */
        public byte[] vmaddr;		/* memory address of this segment */
        public byte[] vmsize;		/* memory size of this segment */
        public byte[] fileoff;	/* file offset of this segment */
        public byte[] filesize;	/* amount to map from the file */
        public vm_prot_t maxprot;	/* maximum VM protection */
        public vm_prot_t initprot;	/* initial VM protection */
        public byte[] nsects;		/* number of sections in segment */
        public byte[] flags;		/* flags */
    }

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
     * fields of the section structure for abi.mach object files is described in the
     * header file <reloc.h>.
     */
    public class section implements Section { /* for 32-bit architectures */
        public String sectname;	/* name of this section */
        public String segname;	/* segment this section goes in */
        public byte[] addr;		/* memory address of this section */
        public byte[] size;		/* size in bytes of this section */
        public byte[] offset;		/* file offset of this section */
        public byte[] align;		/* section alignment (power of 2) */
        public byte[] reloff;		/* file offset of relocation entries */
        public byte[] nreloc;		/* number of relocation entries */
        public byte[] flags;		/* flags (section type and attributes)*/
        public byte[] reserved1;	/* reserved (for offset or index) */
        public byte[] reserved2;	/* reserved (for count or sizeof) */
    }

    public class section_64 implements Section { /* for 64-bit architectures */
        public String sectname;	/* name of this section */
        public String segname;	/* segment this section goes in */
        public byte[] addr;		/* memory address of this section */
        public byte[] size;		/* size in bytes of this section */
        public byte[] offset;		/* file offset of this section */
        public byte[] align;		/* section alignment (power of 2) */
        public byte[] reloff;		/* file offset of relocation entries */
        public byte[] nreloc;		/* number of relocation entries */
        public byte[] flags;		/* flags (section type and attributes)*/
        public byte[] reserved1;	/* reserved (for offset or index) */
        public byte[] reserved2;	/* reserved (for count or sizeof) */
        public byte[] reserved3;	/* reserved */
    }

    /*
     * Fixed virtual memory shared libraries are identified by two things.  The
     * target pathname (the name of the library as found for execution), and the
     * minor version number.  The address of where the headers are loaded is in
     * header_addr. (THIS IS OBSOLETE and no public byte[]er supported).
     */
    public class fvmlib {
        lc_str name;		/* library's target pathname */
        public byte[] minor_version;	/* library's minor version number */
        public byte[] header_addr;	/* library's header address */
    }

    /*
     * A fixed virtual shared library (filetype == MH_FVMLIB in the abi.mach header)
     * contains a fvmlib_command (cmd == LC_IDFVMLIB) to identify the library.
     * An object that uses a fixed virtual shared library also contains a
     * fvmlib_command (cmd == LC_LOADFVMLIB) for each library it uses.
     * (THIS IS OBSOLETE and no public byte[]er supported).
     */
    public class fvmlib_command implements Command {
        public byte[] cmd;		/* LC_IDFVMLIB or LC_LOADFVMLIB */
        public byte[] cmdsize;	/* includes pathname string */
        public fvmlib fvmlib;		/* the library identification */
    }

    /*
     * Dynamicly linked shared libraries are identified by two things.  The
     * pathname (the name of the library as found for execution), and the
     * compatibility version number.  The pathname must match and the compatibility
     * number in the user of the library must be greater than or equal to the
     * library being used.  The time stamp is used to record the time a library was
     * built and copied into user so it can be use to determined if the library used
     * at runtime is exactly the same as used to built the program.
     */
    public class dylib {
        public lc_str name;			/* library's path name */
        public byte[] timestamp;			/* library's build time stamp */
        public byte[] current_version;		/* library's current version number */
        public byte[] compatibility_version;	/* library's compatibility vers number*/
    }

    /*
     * A dynamically linked shared library (filetype == MH_DYLIB in the abi.mach header)
     * contains a dylib_command (cmd == LC_ID_DYLIB) to identify the library.
     * An object that uses a dynamically linked shared library also contains a
     * dylib_command (cmd == LC_LOAD_DYLIB, LC_LOAD_WEAK_DYLIB, or
     * LC_REEXPORT_DYLIB) for each library it uses.
     */
    public class dylib_command  implements Command {
        public byte[] cmd;		/* LC_ID_DYLIB, LC_LOAD_ implements Command {,WEAK_}DYLIB,
					   LC_REEXPORT_DYLIB */
        public byte[] cmdsize;	/* includes pathname string */
        public dylib dylib;		/* the library identification */
    }

    /*
     * A dynamically linked shared library may be a subframework of an umbrella
     * framework.  If so it will be linked with "-umbrella umbrella_name" where
     * Where "umbrella_name" is the name of the umbrella framework. A subframework
     * can only be linked against by its umbrella framework or other subframeworks
     * that are part of the same umbrella framework.  Otherwise the static link
     * editor produces an error and states to link against the umbrella framework.
     * The name of the umbrella framework for subframeworks is recorded in the
     * following structure.
     */
    public class sub_framework_command implements Command {
        public byte[] cmd;		/* LC_SUB_FRAMEWORK */
        public byte[] cmdsize;	/* includes umbrella string */
        public lc_str umbrella;	/* the umbrella framework name */
    }

    /*
     * For dynamically linked shared libraries that are subframework of an umbrella
     * framework they can allow clients other than the umbrella framework or other
     * subframeworks in the same umbrella framework.  To do this the subframework
     * is built with "-allowable_client client_name" and an LC_SUB_CLIENT load
     * command is created for each -allowable_client flag.  The client_name is
     * usually a framework name.  It can also be a name used for bundles clients
     * where the bundle is built with "-client_name client_name".
     */
    public class sub_client_command implements Command {
        public byte[] cmd;		/* LC_SUB_CLIENT */
        public byte[] cmdsize;	/* includes client string */
        public lc_str
                client;		/* the client name */
    }

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
     * The name of a sub_umbrella framework is recorded in the following structure.
     */
    public class sub_umbrella_command implements Command {
        public byte[] cmd;		/* LC_SUB_UMBRELLA */
        public byte[] cmdsize;	/* includes sub_umbrella string */
        public lc_str
                sub_umbrella;	/* the sub_umbrella framework name */
    }

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
     * The name of a sub_library framework is recorded in the following structure.
     * For example /usr/lib/libobjc_profile.A.dylib would be recorded as "libobjc".
     */
    public class sub_library_command implements Command {
        public byte[] cmd;		/* LC_SUB_LIBRARY */
        public byte[] cmdsize;	/* includes sub_library string */
        public lc_str
                sub_library;	/* the sub_library name */
    }

    /*
     * A program (filetype == MH_EXECUTE) that is
     * prebound to its dynamic libraries has one of these for each library that
     * the static linker used in prebinding.  It contains a bit vector for the
     * modules in the library.  The bits indicate which modules are bound (1) and
     * which are not (0) from the library.  The bit for module 0 is the low bit
     * of the first byte.  So the bit for the Nth module is:
     * (linked_modules[N/8] >> N%8) & 1
     */
    public class prebound_dylib_command implements Command {
        public byte[] cmd;		/* LC_PREBOUND_DYLIB */
        public byte[] cmdsize;	/* includes strings */
        public lc_str
                name;		/* library's path name */
        public byte[] nmodules;	/* number of modules in library */
        public lc_str
                linked_modules;	/* bit vector of linked modules */
    }

    /*
     * A program that uses a dynamic linker contains a dylinker_command to identify
     * the name of the dynamic linker (LC_LOAD_DYLINKER).  And a dynamic linker
     * contains a dylinker_command to identify the dynamic linker (LC_ID_DYLINKER).
     * A file can have at most one of these.
     */
    public class dylinker_command implements Command {
        public byte[] cmd;		/* LC_ID_DYLINKER or LC_LOAD_DYLINKER */
        public byte[] cmdsize;	/* includes pathname string */
        public lc_str
                name;		/* dynamic linker's path name */
    }

    /*
     * Thread commands contain machine-specific data structures suitable for
     * use in the thread state primitives.  The machine specific data structures
     * follow the struct thread_command as follows.
     * Each flavor of machine specific data structure is preceded by an unsigned
     * byte[] constant for the flavor of that data structure, an byte[]
     * that is the count of byte[]s of the size of the state data structure and then
     * the state data structure follows.  This triple may be repeated for many
     * flavors.  The constants for the flavors, counts and state data structure
     * definitions are expected to be in the header file <machine/thread_status.h>.
     * These machine specific data structures sizes must be multiples of
     * 4 bytes  The cmdsize reflects the total size of the thread_command
     * and all of the sizes of the constants for the flavors, counts and state
     * data structures.
     *
     * For executable objects that are unix processes there will be one
     * thread_command (cmd == LC_UNIXTHREAD) created for it by the link-editor.
     * This is the same as a LC_THREAD, except that a stack is automatically
     * created (based on the shell's limit for the stack size).  Command arguments
     * and environment variables are copied onto that stack.
     */
    public class thread_command implements Command {
        public byte[] cmd;		/* LC_THREAD or  LC_UNIXTHREAD */
        public byte[] cmdsize;	/* total size of this command */
	/* byte[] flavor		   flavor of thread state */
	/* byte[] count		   count of byte[]s in thread state */
	/* struct XXX_thread_state state   thread state for this flavor */
	/* ... */
    }

    /*
     * The routines command contains the address of the dynamic shared library
     * initialization routine and an index into the module table for the module
     * that defines the routine.  Before any modules are used from the library the
     * dynamic linker fully binds the module that defines the initialization routine
     * and then calls it.  This gets called before any module initialization
     * routines (used for C++ static constructors) in the library.
     */
    public class routines_command implements Command { /* for 32-bit architectures */
        public byte[] cmd;		/* LC_ROUTINES */
        public byte[] cmdsize;	/* total size of this command */
        public byte[] init_address;	/* address of initialization routine */
        public byte[] init_module;	/* index into the module table that */
        /*  the init routine is defined in */
        public byte[] reserved1;
        public byte[] reserved2;
        public byte[] reserved3;
        public byte[] reserved4;
        public byte[] reserved5;
        public byte[] reserved6;
    }

    /*
     * The 64-bit routines command.  Same use as above.
     */
    public class routines_command_64 implements Command { /* for 64-bit architectures */
        public byte[] cmd;		/* LC_ROUTINES_64 */
        public byte[] cmdsize;	/* total size of this command */
        public byte[] init_address;	/* address of initialization routine */
        public byte[] init_module;	/* index into the module table that */
        /*  the init routine is defined in */
        public byte[] reserved1;
        public byte[] reserved2;
        public byte[] reserved3;
        public byte[] reserved4;
        public byte[] reserved5;
        public byte[] reserved6;
    }

    /*
     * The symtab_command contains the offsets and sizes of the link-edit 4.3BSD
     * "stab" style symbol table information as described in the header files
     * <nlist.h> and <stab.h>.
     */
    public class symtab_command implements Command {
        public byte[] cmd;		/* LC_SYMTAB */
        public byte[] cmdsize;	/* sizeof(struct symtab_command) */
        public byte[] symoff;		/* symbol table offset */
        public byte[] nsyms;		/* number of symbol table entries */
        public byte[] stroff;		/* string table offset */
        public byte[] strsize;	/* string table size in bytes */
    }

    /*
     * This is the second set of the symbolic information which is used to support
     * the data structures for the dynamically link editor.
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
     * off the section structures.
     */
    public class dysymtab_command implements Command {
        public byte[] cmd;	/* LC_DYSYMTAB */
        public byte[] cmdsize;	/* sizeof(struct dysymtab_command) */

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
        public byte[] ilocalsym;	/* index to local symbols */
        public byte[] nlocalsym;	/* number of local symbols */

        public byte[] iextdefsym;/* index to externally defined symbols */
        public byte[] nextdefsym;/* number of externally defined symbols */

        public byte[] iundefsym;	/* index to undefined symbols */
        public byte[] nundefsym;	/* number of undefined symbols */

        /*
         * For the for the dynamic binding process to find which module a symbol
         * is defined in the table of contents is used (analogous to the ranlib
         * structure in an archive) which maps defined external symbols to modules
         * they are defined in.  This exists only in a dynamically linked shared
         * library file.  For executable and object modules the defined external
         * symbols are sorted by name and is use as the table of contents.
         */
        public byte[] tocoff;	/* file offset to table of contents */
        public byte[] ntoc;	/* number of entries in table of contents */

        /*
         * To support dynamic binding of "modules" (whole object files) the symbol
         * table must reflect the modules that the file was created from.  This is
         * done by having a module table that has indexes and counts into the merged
         * tables for each module.  The module structure that these two entries
         * refer to is described below.  This exists only in a dynamically linked
         * shared library file.  For executable and object modules the file only
         * contains one module so everything in the file bebyte[]s to the module.
         */
        public byte[] modtaboff;	/* file offset to module table */
        public byte[] nmodtab;	/* number of module table entries */

        /*
         * To support dynamic module binding the module structure for each module
         * indicates the external references (defined and undefined) each module
         * makes.  For each module there is an offset and a count into the
         * reference symbol table for the symbols that the module references.
         * This exists only in a dynamically linked shared library file.  For
         * executable and object modules the defined external symbols and the
         * undefined external symbols indicates the external references.
         */
        public byte[] extrefsymoff;	/* offset to referenced symbol table */
        public byte[] nextrefsyms;	/* number of referenced symbol table entries */

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
        public byte[] indirectsymoff; /* file offset to the indirect symbol table */
        public byte[] nindirectsyms;  /* number of indirect symbol table entries */

        /*
         * To support relocating an individual module in a library file quickly the
         * external relocation entries for each module in the library need to be
         * accessed efficiently.  Since the relocation entries can't be accessed
         * through the section headers for a library file they are separated into
         * groups of local and external entries further grouped by module.  In this
         * case the presents of this load command who's extreloff, nextrel,
         * locreloff and nlocrel fields are non-zero indicates that the relocation
         * entries of non-merged sections are not referenced through the section
         * structures (and the reloff and nreloc fields in the section headers are
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
        public byte[] extreloff;	/* offset to external relocation entries */
        public byte[] nextrel;	/* number of external relocation entries */

        /*
         * All the local relocation entries are grouped together (they are not
         * grouped by their module since they are only used if the object is moved
         * from it staticly link edited address).
         */
        public byte[] locreloff;	/* offset to local relocation entries */
        public byte[] nlocrel;	/* number of local relocation entries */

    }

    /* a table of contents entry */
    public class dylib_table_of_contents {
        public byte[] symbol_index;	/* the defined external symbol
				   (index into the symbol table) */
        public byte[] module_index;	/* index into the module table this symbol
				   is defined in */
    }

    /* a module table entry */
    public class dylib_module {
        public byte[] module_name;	/* the module name (index into string table) */

        public byte[] iextdefsym;	/* index into externally defined symbols */
        public byte[] nextdefsym;	/* number of externally defined symbols */
        public byte[] irefsym;		/* index into reference symbol table */
        public byte[] nrefsym;		/* number of reference symbol table entries */
        public byte[] ilocalsym;		/* index into symbols for local symbols */
        public byte[] nlocalsym;		/* number of local symbols */

        public byte[] iextrel;		/* index into external relocation entries */
        public byte[] nextrel;		/* number of external relocation entries */

        public byte[] iinit_iterm;	/* low 16 bits are the index into the init
				   section, high 16 bits are the index into
			           the term section */
        public byte[] ninit_nterm;	/* low 16 bits are the number of init section
				   entries, high 16 bits are the number of
				   term section entries */

        public byte[]			/* for this module address of the start of */
                objc_module_info_addr;  /*  the (__OBJC,__module_info) section */
        public byte[]			/* for this module size of */
                objc_module_info_size;	/*  the (__OBJC,__module_info) section */
    }

    /* a 64-bit module table entry */
    public class dylib_module_64 {
        public byte[] module_name;	/* the module name (index into string table) */

        public byte[] iextdefsym;	/* index into externally defined symbols */
        public byte[] nextdefsym;	/* number of externally defined symbols */
        public byte[] irefsym;		/* index into reference symbol table */
        public byte[] nrefsym;		/* number of reference symbol table entries */
        public byte[] ilocalsym;		/* index into symbols for local symbols */
        public byte[] nlocalsym;		/* number of local symbols */

        public byte[] iextrel;		/* index into external relocation entries */
        public byte[] nextrel;		/* number of external relocation entries */

        public byte[] iinit_iterm;	/* low 16 bits are the index into the init
				   section, high 16 bits are the index into
				   the term section */
        public byte[] ninit_nterm;      /* low 16 bits are the number of init section
				  entries, high 16 bits are the number of
				  term section entries */

        public byte[]			/* for this module size of */
                objc_module_info_size;	/*  the (__OBJC,__module_info) section */
        public byte[]			/* for this module address of the start of */
                objc_module_info_addr;	/*  the (__OBJC,__module_info) section */
    }

    /*
     * The entries in the reference symbol table are used when loading the module
     * (both by the static and dynamic link editors) and if the module is unloaded
     * or replaced.  Therefore all external symbols (defined and undefined) are
     * listed in the module's reference table.  The flags describe the type of
     * reference that is being made.  The constants for the flags are defined in
     * <abi.mach-o/nlist.h> as they are also used for symbol table entries.
     */
    public class dylib_reference {
        public byte[] isym
                ={(byte)0x24};		/* index into the symbol table */
        public byte[] flags = {(byte)0x8};	/* flags to indicate the type of reference */
    }

    /*
     * The twolevel_hints_command contains the offset and number of hints in the
     * two-level namespace lookup hints table.
     */
    public class twolevel_hints_command implements Command {
        public byte[] cmd;	/* LC_TWOLEVEL_HINTS */
        public byte[] cmdsize;	/* sizeof(struct twolevel_hints_command) */
        public byte[] offset;	/* offset to the hint table */
        public byte[] nhints;	/* number of hints in the hint table */
    }

    /*
     * The entries in the two-level namespace lookup hints table are twolevel_hint
     * structs.  These provide hints to the dynamic link editor where to start
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
    public class twolevel_hint {
        public byte[]
                isub_image = {(byte)0x8};	/* index into the sub images */
        public byte[] itoc = {(byte)0x24};	/* index into the table of contents */
    }

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
    public class prebind_cksum_command implements Command {
        public byte[] cmd;	/* LC_PREBIND_CKSUM */
        public byte[] cmdsize;	/* sizeof(struct prebind_cksum_command) */
        public byte[] cksum;	/* the check sum or zero */
    }

    /*
     * The uuid load command contains a single 128-bit unique random number that
     * identifies an object produced by the static link editor.
     */
    public class uuid_command implements Command {
        public byte[] cmd;		/* LC_UUID */
        public byte[] cmdsize;	/* sizeof(struct uuid_command) */
        public byte[] uuid;	/* the 128-bit uuid */
    }

    /*
     * The rpath_command contains a path which at runtime should be added to
     * the current run path used to find @rpath prefixed dylibs.
     */
    public class rpath_command implements Command {
        public byte[] cmd;		/* LC_RPATH */
        public byte[] cmdsize;	/* includes string */
        lc_str
                path;		/* path to add to run path */
    }

    /*
     * The linkedit_data_command contains the offsets and sizes of a blob
     * of data in the __LINKEDIT segment.
     */
    public class linkedit_data_command implements Command {
        public byte[] cmd;		/* LC_CODE_SIGNATURE or LC_SEGMENT_SPLIT_INFO */
        public byte[] cmdsize;	/* sizeof(struct linkedit_data_command) */
        public byte[] dataoff;	/* file offset of data in __LINKEDIT segment */
        public byte[] datasize;	/* file size of data in __LINKEDIT segment  */
    }

    /*
     * The encryption_info_command contains the file offset and size of an
     * of an encrypted segment.
     */
    public class encryption_info_command implements Command {
        public byte[] cmd;		/* LC_ENCRYPTION_INFO */
        public byte[] cmdsize;	/* sizeof(struct encryption_info_command) */
        public byte[] cryptoff;	/* file offset of encrypted range */
        public byte[] cryptsize;	/* file size of encrypted range */
        public byte[] cryptid;	/* which enryption system,
				   0 means not-encrypted yet */
    }

    /*
     * The dyld_info_command contains the file offsets and sizes of
     * the new compressed form of the information dyld needs to
     * load the image.  This information is used by dyld on Mac OS X
     * 10.6 and later.  All information pointed to by this command
     * is encoded using byte streams, so no endian swapping is needed
     * to interpret it.
     */
    public class dyld_info_command implements Command {
        public byte[] cmd;		/* LC_DYLD_INFO or LC_DYLD_INFO_ONLY */
        public byte[] cmdsize;		/* sizeof(struct dyld_info_command) */

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
        public byte[] rebase_off;	/* file offset to rebase info  */
        public byte[] rebase_size;	/* size of rebase info   */

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
        public byte[] bind_off;	/* file offset to binding info   */
        public byte[] bind_size;	/* size of binding info  */

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
        public byte[] weak_bind_off;	/* file offset to weak binding info   */
        public byte[] weak_bind_size;  /* size of weak binding info  */

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
        public byte[] lazy_bind_off;	/* file offset to lazy binding info */
        public byte[] lazy_bind_size;  /* size of lazy binding infs */

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
        public byte[] export_off;	/* file offset to lazy binding info */
        public byte[] export_size;	/* size of lazy binding infs */
    }

    /*
     * The symseg_command contains the offset and size of the GNU style
     * symbol table information as described in the header file <symseg.h>.
     * The symbol roots of the symbol segments must also be aligned properly
     * in the file.  So the requirement of keeping the offsets aligned to a
     * multiple of a 4 bytes translates to the length field of the symbol
     * roots also being a multiple of a byte[].  Also the padding must again be
     * zeroed. (THIS IS OBSOLETE and no byte[]er supported).
     */
    public class symseg_command implements Command {
        public byte[] cmd;		/* LC_SYMSEG */
        public byte[] cmdsize;	/* sizeof(struct symseg_command) */
        public byte[] offset;		/* symbol segment offset */
        public byte[] size;		/* symbol segment size in bytes */
    }



    /*
     * The ident_command contains a free format string table following the
     * ident_command structure.  The strings are null terminated and the size of
     * the command is padded out with zero bytes to a multiple of 4 bytes/
     * (THIS IS OBSOLETE and no byte[]er supported).
     */
    public class ident_command implements Command {
        public byte[] cmd;		/* LC_IDENT */
        public byte[] cmdsize;	/* strings that follow this command */
    }



    /*
     * The fvmfile_command contains a reference to a file to be loaded at the
     * specified virtual address.  (Presently, this command is reserved for
     * internal use.  The kernel ignores this command when loading a program into
     * memory).
     */
    public class fvmfile_command implements Command {
        public byte[] cmd;			/* LC_FVMFILE */
        public byte[] cmdsize;		/* includes pathname string */
        public lc_str
                name;		/* files pathname */
        public byte[] header_addr;	/* files virtual address */
    }



    //#endif /* _MACHO_LOADER_H_ */
}