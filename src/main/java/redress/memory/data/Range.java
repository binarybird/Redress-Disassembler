package redress.memory.data;

import capstone.Capstone;
import capstone.X86;
import redress.abi.generic.ABIArch;
import redress.abi.generic.ABIType;
import redress.memory.Container;
import redress.memory.address.Address;
import redress.memory.address.Address32;
import redress.memory.address.Address64;
import redress.util.B;

import java.nio.ByteOrder;
import java.util.LinkedList;
import java.util.logging.Level;

/**
 * Created by jamesrichardson on 2/16/16.
 */
public class Range extends Data{

    public Range(){
        this(new byte[0],null,null,ByteOrder.BIG_ENDIAN);
    }

    public Range(byte[] in, Address begin, Address end, ByteOrder order) {
       this(in,begin,end,Type.DATA_NULL,order);
    }

    public Range(byte[] in, Address begin, Address end, Type type, ByteOrder order) {
        super(in.length, begin,end,type, order);
        for(int i=0;i<in.length;i++){
            container[i]=in[i];
        }
    }

    @Override
    public Container flipByteOrder() {
        return new Range(B.flipByteOrder(container),this.beginAddress,this.endAddress,this.BYTEORDER);
    }

    @Override
    public Type getDataType() {
        return type;
    }

    @Override
    public Data clone() {
        return new Range(container,this.beginAddress,this.endAddress,this.BYTEORDER);
    }


}
