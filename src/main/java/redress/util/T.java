package redress.util;

import capstone.Capstone;
import capstone.X86;
import redress.abi.generic.AbstractABI;
import redress.abi.generic.IContainer;
import redress.abi.generic.IStructure;
import redress.abi.generic.enums.ABIArch;
import redress.abi.generic.enums.ABIType;
import redress.memory.address.AbstractAddress;
import redress.memory.address.Address32;
import redress.memory.data.AbstractData;
import redress.memory.data.Range;
import redress.memory.data.Text;

import java.nio.ByteOrder;
import java.util.LinkedList;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Created by jamesrichardson on 2/22/16.
 */
public class T {
    private final static Logger LOGGER = Logger.getLogger(T.class.getName());

    private T(){}

    public static LinkedList<IContainer> deCompileStringsAligned(int aligned, Range text, AbstractABI abi){
        final LinkedList<IContainer> ret = new LinkedList<>();
        final int length = text.getEndAddress().getIntValue()-text.getBeginAddress().getIntValue();
        LOGGER.log(Level.INFO,"Decompiling {4} byte aligned Strings {0} bytes from {1} to {2}, first byte {3}",new Object[]{length, text.getBeginAddress().toString(),text.getEndAddress().toString(), B.bytesToHexString(new byte[]{text.getContainer()[0]}),aligned});

        int count=0;
        for(int i=0;i<text.getContainer().length;i++){
            if(i%aligned == 0 && i!=0){
                count++;
                byte[] str = new byte[aligned];
                for(int j=0;j<aligned;j++){
                    str[j]=text.getContainer()[i-j];
                }

                final AbstractAddress strBegin = text.getBeginAddress().clone();
                strBegin.add(aligned*count - aligned);
                final AbstractAddress strEnd = text.getBeginAddress().clone();
                strEnd.add(aligned*count);

                final Range range = new Range(str, strBegin, strEnd, text.getParent(), AbstractData.Type.DATA_CHAR, ByteOrder.LITTLE_ENDIAN);
                String rets = "";
                for(String s : B.bytesToPrettyHexString(str)){
                    rets+=s;
                }
                range.addComments("Hex Representation: "+rets);

                ret.add(range);
            }
        }

        return ret;
    }

    public static LinkedList<IContainer> deCompileCStrings(Range text, AbstractABI abi){
        final LinkedList<IContainer> ret = new LinkedList<>();
        final int length = text.getEndAddress().getIntValue()-text.getBeginAddress().getIntValue();
        LOGGER.log(Level.INFO,"Decompiling CStrings {0} bytes from {1} to {2}, first byte {3}",new Object[]{length, text.getBeginAddress().toString(),text.getEndAddress().toString(), B.bytesToHexString(new byte[]{text.getContainer()[0]})});

        int previousEnd = -1;
        for(int i=1;i<text.getContainer().length;i++){
            if(text.getContainer()[i] == 0x00)
            {
                int beg = 0;
                byte[] str = new byte[i+1];

                for(int j=i;j>previousEnd;j--){
                    str[j]=text.getContainer()[j];
                    beg=j;
                }

                final AbstractAddress strBegin = text.getBeginAddress().clone();
                strBegin.subtract(beg);
                final AbstractAddress strEnd = text.getBeginAddress().clone();
                strEnd.add(i);

                previousEnd = i;

                final Range range = new Range(str, strBegin, strEnd, text.getParent(), AbstractData.Type.DATA_CHAR, ByteOrder.LITTLE_ENDIAN);
                String rets = "";
                for(String s : B.bytesToPrettyHexString(str)){
                    rets+=s;
                }
                range.addComments("Hex Representation: "+rets);

                ret.add(range);
            }
        }
        return ret;
    }

    public static LinkedList<IContainer> deCompileText(Range text, AbstractABI abi){
        final LinkedList<IContainer> ret = new LinkedList<>();
        final int length = text.getEndAddress().getIntValue()-text.getBeginAddress().getIntValue();
        final Capstone cs = getCapstone(abi.getType(), abi.getArch());

        LOGGER.log(Level.INFO,"Decompiling Code {0} bytes from {1} to {2}, first byte {3}",new Object[]{length, text.getBeginAddress().toString(),text.getEndAddress().toString(), B.bytesToHexString(new byte[]{text.getContainer()[0]})});

        try {
            final Capstone.CsInsn[] disasm = cs.disasm(text.getContainer(), text.getBeginAddress().getIntValue());
            for (Capstone.CsInsn csin : disasm) {
                ret.add(print_ins_detail(csin, cs, abi,text.getParent()));
            }
        }catch(Exception e){
            e.printStackTrace();
        }

        return ret;
    }

    private static Capstone getCapstone(ABIType fileType, ABIArch abiArch) {
        Capstone cs = null;
        if(fileType == ABIType.MACH_64 || fileType == ABIType.PE_64 || fileType == ABIType.ELF_64){
            if(abiArch == ABIArch.X86) {
                cs = new Capstone(Capstone.CS_ARCH_X86, Capstone.CS_MODE_64);
            }
        }else if(fileType == ABIType.MACH_32 || fileType == ABIType.PE_32 || fileType == ABIType.ELF_32) {
            if (abiArch == ABIArch.X86) {
                cs = new Capstone(Capstone.CS_ARCH_X86, Capstone.CS_MODE_32);
            }
        }
        return cs;
    }

    /**
     * Code adapted from Capstone project
     */
    private static Text print_ins_detail(Capstone.CsInsn ins,Capstone cs,AbstractABI abi,IStructure parent) {
        final StringBuilder comment = new StringBuilder();

        //TODO - comment is instruction string
        //TODO - container is instruction raw
        //TODO - get raw inst from abi raw
        //TODO - get proper addr size from abi
//        final byte[] lengthOfInstruction = B.intToBytes(B.shortToInt(ins.size), ByteOrder.BIG_ENDIAN);
//        final Address begin = new Address32(B.intToBytes(B.longToInt(ins.address),ByteOrder.BIG_ENDIAN));
//        final Address end = (Address)begin.clone().add(new Address32(lengthOfInstruction));
//        final byte[] rawInst = B.getRangeAtAddress(abi.getRaw(),begin,end);
        //final Range range = new Range(rawInst,begin,end,Data.Type.TEXT_DECOMPILED, ByteOrder.BIG_ENDIAN);

        final Address32 begin = new Address32(B.intToBytes(B.longToInt(ins.address), ByteOrder.BIG_ENDIAN));
        final Range range = new Range(new byte[0],begin,Address32.NULL, parent,AbstractData.Type.TEXT_DECOMPILED, ByteOrder.BIG_ENDIAN);


        comment.append(ins.mnemonic);
        comment.append(" ");
        comment.append(ins.opStr);

        X86.OpInfo operands = (X86.OpInfo) ins.operands;

        if(operands != null) {
            comment.append("Prefix: ");
            comment.append(B.bytesToHexString(operands.prefix));
            comment.append("\n");

            comment.append("Opcode:");
            comment.append(B.bytesToHexString(operands.opcode));
            comment.append("\n");

            // print REX prefix (non-zero value is relevant for x86_64)
            comment.append("rex: ");
            comment.append(operands.rex);
            comment.append("\n");

            // print address size
            comment.append("addr_size: ");
            comment.append(operands.addrSize);
            comment.append("\n");

            // print modRM byte
            comment.append("modrm: ");
            comment.append(operands.modrm);
            comment.append("\n");

            // print displacement value
            comment.append("disp: 0x%x");
            comment.append(operands.disp);
            comment.append("\n");

            // SIB is not available in 16-bit mode
            if ((cs.mode & Capstone.CS_MODE_16) == 0) {
                // print SIB byte
                comment.append("sib: ");
                comment.append(operands.sib);
                if (operands.sib != 0) {
                    comment.append("\tsib_base: ");
                    comment.append(ins.regName(operands.sibBase));
                    comment.append("\n");
                    comment.append("\tsib_index: ");
                    comment.append(ins.regName(operands.sibIndex));
                    comment.append("\n");
                    comment.append("\tsib_scale: ");
                    comment.append(operands.sibScale);
                    comment.append("\n");
                }
            }

            if (operands.sseCC != 0) {
                comment.append("sse_cc: ");
                comment.append(operands.sseCC);
                comment.append("\n");
            }

            if (operands.avxCC != 0) {
                comment.append("avx_cc: ");
                comment.append(operands.avxCC);
                comment.append("\n");
            }

            if (operands.avxSae) {
                comment.append("avx_sae: TRUE\n");
            }

            if (operands.avxRm != 0) {
                comment.append("avx_rm: ");
                comment.append(operands.avxRm);
                comment.append("\n");
            }

            int count = ins.opCount(capstone.X86_const.X86_OP_IMM);
            if (count > 0) {
                comment.append("imm_count: ");
                comment.append(count);
                comment.append("\n");
                for (int i = 0; i < count; i++) {
                    int index = ins.opIndex(capstone.X86_const.X86_OP_IMM, i + 1);
                    comment.append("\timms");
                    comment.append(i);
                    comment.append("]: ");
                    comment.append(operands.op[index].value.imm);
                    comment.append("\n");
                }
            }

            if (operands.op.length != 0) {
                comment.append("op_count:");
                comment.append(operands.op.length);
                for (int c = 0; c < operands.op.length; c++) {
                    X86.Operand i = (X86.Operand) operands.op[c];
                    String imm = String.valueOf(i.value.imm);
                    if (i.type == capstone.X86_const.X86_OP_REG) {
                        comment.append("\toperands[" + c + "].type: REG = ");
                        comment.append(ins.regName(i.value.reg));
                        comment.append("\n");
                    }
                    if (i.type == capstone.X86_const.X86_OP_IMM) {
                        comment.append("\toperands[" + c + "].type: IMM = ");
                        comment.append(i.value.imm);
                        comment.append("\n");
                    }
                    if (i.type == capstone.X86_const.X86_OP_FP) {
                        comment.append("\toperands[" + c + "].type: FP = ");
                        comment.append(i.value.fp);
                        comment.append("\n");
                    }
                    if (i.type == capstone.X86_const.X86_OP_MEM) {
                        comment.append("\toperands[" + c + "].type: MEM\n");
                        String segment = ins.regName(i.value.mem.segment);
                        String base = ins.regName(i.value.mem.base);
                        String index = ins.regName(i.value.mem.index);
                        if (segment != null) {
                            comment.append("\t\toperands[" + c + "].mem.segment: REG = ");
                            comment.append(segment);
                            comment.append("\n");
                        }
                        if (base != null) {
                            comment.append("\t\toperands[" + c + "].mem.base: REG = ");
                            comment.append(base);
                            comment.append("\n");
                        }
                        if (index != null) {
                            comment.append("\t\toperands[" + c + "].mem.index: REG = ");
                            comment.append(index);
                            comment.append("\n");
                        }
                        if (i.value.mem.scale != 1) {
                            comment.append("\t\toperands[" + c + "].mem.scale: ");
                            comment.append(i.value.mem.scale);
                            comment.append("\n");
                        }
                        if (i.value.mem.disp != 0) {
                            comment.append("\t\toperands[" + c + "].mem.disp: ");
                            comment.append(i.value.mem.disp);
                            comment.append("\n");
                        }
                    }

                    // AVX broadcast type
                    if (i.avx_bcast != capstone.X86_const.X86_AVX_BCAST_INVALID) {
                        comment.append("\toperands[" + c + "].avx_bcast: ");
                        comment.append(i.avx_bcast);
                        comment.append("\n");
                    }

                    // AVX zero opmask {z}
                    if (i.avx_zero_opmask) {
                        comment.append("\toperands[" + c + "].avx_zero_opmask: TRUE\n");
                    }

                    comment.append("\toperands[" + c + "].size: ");
                    comment.append(i.size);
                    comment.append("\n");
                }
            }
        }

        return new Text(range,ins,comment.toString());
    }
}
