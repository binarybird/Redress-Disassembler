package redress.memory.data;

import redress.abi.generic.IStructure;
import redress.abi.generic.visitors.AbstractContainerVisitor;
import redress.memory.address.AbstractAddress;
import redress.memory.address.Address32;
import redress.util.B;

import java.nio.ByteOrder;

/**
 * Created by jamesrichardson on 2/11/16.
 */
public class Word extends AbstractData {
    public static final Word SIZEOF_B = new Word("0x0002", AbstractData.Type.DATA_BYTE, ByteOrder.BIG_ENDIAN);
    public static final Word SIZEOF_L = new Word("0x0200", AbstractData.Type.DATA_BYTE, ByteOrder.LITTLE_ENDIAN);
    public static final Word NULL = new Word();

    public Word(){
        super(0,null,Type.DATA_NULL, ByteOrder.BIG_ENDIAN);
    }

    public Word(byte[] in,Type type,ByteOrder order){
        this(in,Address32.NULL,null,type,order);
    }
    public Word(byte[] in,AbstractAddress beginAddress,IStructure parent,Type type,ByteOrder order){
        super(2,parent,type,order);
        this.beginAddress=beginAddress;
        this.endAddress=beginAddress.clone();
        B.add(this.endAddress,new Address32("0x00000002"));
        if(in.length != BYTES){
            return;
        }
        for(int i=0;i<BYTES;i++){
            container[i]=in[i];
        }
    }

    public Word(String in,Type type,ByteOrder order){
        this(in,Address32.NULL,null,type,order);
    }
    public Word(String in,AbstractAddress beginAddress,IStructure parent,Type type,ByteOrder order){
        super(2,parent,type,order);
        this.beginAddress=beginAddress;
        this.endAddress=beginAddress.clone();
        B.add(this.endAddress,new Address32("0x00000002"));
        final byte[] tmp = B.stringToBytes(in);
        if(tmp.length != BYTES){
            System.out.println("Size Overflow!");
            return;
        }
        for(int i=0;i<BYTES;i++){
            container[i]=tmp[i];
        }
    }

    @Override
    public void accept(AbstractContainerVisitor visitor) {
        if(visitor.preVisit())
            visitor.visit(this);
        visitor.postVisit();
        nextSibling.accept(visitor);
    }

    public void setDataType(Type in){
        this.type=in;
    }

    @Override
    public Type getDataType() {
        return type;
    }

    @Override
    public Word flipByteOrder() {
        byte[] flip = new byte[BYTES];
        for(int i=0;i<BYTES;i++){
            flip[i] = container[(BYTES-1)-i];
        }

        return new Word(flip,this.type,BYTEORDER==ByteOrder.BIG_ENDIAN?ByteOrder.LITTLE_ENDIAN:ByteOrder.BIG_ENDIAN);
    }

    @Override
    public Word clone() {
        return new Word(container,this.type,BYTEORDER);
    }
}
