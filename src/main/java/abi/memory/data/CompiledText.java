package abi.memory.data;

import abi.generic.ABIArch;
import abi.generic.ABIType;
import abi.memory.Container;
import abi.memory.address.Address;
import abi.memory.address.Address32;
import abi.memory.address.Address64;
import capstone.Capstone;
import capstone.X86;
import util.B;
import capstone.X86_const;

import java.nio.ByteOrder;
import java.util.LinkedList;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Created by jamesrichardson on 2/18/16.
 */
public class CompiledText extends DataRange{

    private final static Logger LOGGER = Logger.getLogger(CompiledText.class.getName());

    @Override
    public Type getDataType() {
        return Type.COMPILED_TEXT;
    }

    public class DeCompiledTextSet extends Data{

        private final Type type;

        private String instruction;

        public DeCompiledTextSet(Address address, String inst, Type type) {
            super(0, address, Address64.NULL, ByteOrder.BIG_ENDIAN);
            this.type = type;
            this.instruction = inst;
        }

        @Override
        public Container flipByteOrder() {
            return null;
        }

        @Override
        public Type getDataType() {
            return type;
        }

        @Override
        public Data clone() {
            return null;
        }

        @Override
        public String toString(){
            return instruction;
        }
    }

    public CompiledText(byte[] in, Address begin, Address end, ByteOrder order){
        super(in,begin,end,order);
    }

    public LinkedList<DeCompiledTextSet> deCompileText(ABIType fileType,ABIArch abiArch){
        final LinkedList<DeCompiledTextSet> ret = new LinkedList<>();
        final int length = this.endAddress.getIntValue()-this.beginAddress.getIntValue();

        final DeCompiledTextSet deCompiledTextSet = new DeCompiledTextSet(Address64.NULL, getContainingDataStructure().getComment(), Type.COMMENT_STRING);
        deCompiledTextSet.comment="Procedure Start, Length: "+length+" bytes";
        ret.add(deCompiledTextSet);

        Capstone cs = null;
        if(fileType == ABIType.MACH_64 || fileType == ABIType.PE_64 || fileType == ABIType.ELF_64){
            if(abiArch == ABIArch.X86) {
                cs = new Capstone(Capstone.CS_ARCH_X86, Capstone.CS_MODE_64);
            }
        }else if(fileType == ABIType.MACH_32 || fileType == ABIType.PE_32 || fileType == ABIType.ELF_32){
            if(abiArch == ABIArch.X86) {
                cs = new Capstone(Capstone.CS_ARCH_X86, Capstone.CS_MODE_32);
            }
        }

        byte[] tmp;
        if(this.BYTEORDER == ByteOrder.BIG_ENDIAN)
            tmp = B.flipByteOrder(container);
        else
            tmp=container;
        LOGGER.log(Level.INFO,"Decompiling {0} bytes from {1} to {2}, first byte {3}",new Object[]{length, beginAddress.toString(),endAddress.toString(),B.bytesToString(new byte[]{tmp[0]})});

        try {
            final Capstone.CsInsn[] disasm = cs.disasm(tmp, beginAddress.getIntValue());
            for (Capstone.CsInsn csin : disasm) {
                ret.add(print_ins_detail(csin, cs));
            }
        }catch(Exception e){
            e.printStackTrace();
        }

        final DeCompiledTextSet deCompiledTextSetEnd = new DeCompiledTextSet(Address64.NULL, getContainingDataStructure().getComment(), Type.COMMENT_STRING);
        deCompiledTextSetEnd.comment="Procedure End, Length: "+length+" bytes";
        ret.add(deCompiledTextSetEnd);

        return ret;
    }
    public DeCompiledTextSet print_ins_detail(Capstone.CsInsn ins,Capstone cs) {
        final StringBuilder code = new StringBuilder();
        final StringBuilder comment = new StringBuilder();

        final Address addr = new Address32(B.intToBytes(B.longToInt(ins.address),ByteOrder.BIG_ENDIAN));

        code.append(ins.mnemonic);
        code.append(" ");
        code.append(ins.opStr);

        X86.OpInfo operands = (X86.OpInfo) ins.operands;

        if(operands != null) {
            comment.append("Prefix: ");
            comment.append(B.bytesToString(operands.prefix));
            comment.append("\n");

            comment.append("Opcode:");
            comment.append(B.bytesToString(operands.opcode));
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
        final DeCompiledTextSet deCompiledTextSet = new DeCompiledTextSet(addr, code.toString(), Type.DECOMPILED_TEXT);
        deCompiledTextSet.setComment(comment.toString());
        return deCompiledTextSet;
    }
}
