package redress.memory.data;

import redress.abi.generic.IContainer;
import redress.abi.generic.IStructure;
import redress.memory.address.AbstractAddress;
import redress.util.B;

import java.nio.ByteOrder;
import java.util.LinkedList;

/**
 * Created by jamesrichardson on 2/16/16.
 */
public class Range extends AbstractData {

    public Range(){
        this(new byte[0],null,null,null,ByteOrder.BIG_ENDIAN);
    }

    public Range(byte[] in, AbstractAddress begin, AbstractAddress end, IStructure parent,ByteOrder order) {
       this(in,begin,end,parent,Type.DATA_NULL,order);
    }

    public Range(byte[] in, AbstractAddress begin, AbstractAddress end, IStructure parent,Type type, ByteOrder order) {
        super(in.length,parent,type, order);
        this.beginAddress=begin;
        this.endAddress=end;
        for(int i=0;i<in.length;i++){
            container[i]=in[i];
        }
    }

    @Override
    public Range flipByteOrder() {
        return new Range(B.flipByteOrder(container),this.beginAddress,this.endAddress,this.parent,this.BYTEORDER);
    }

    @Override
    public Type getDataType() {
        return type;
    }

    @Override
    public AbstractData clone() {
        return new Range(container,this.beginAddress,this.endAddress,this.parent,this.BYTEORDER);
    }

}
