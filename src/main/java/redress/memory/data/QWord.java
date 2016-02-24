package redress.memory.data;

import redress.abi.generic.IContainer;
import redress.abi.generic.IStructure;
import redress.memory.address.AbstractAddress;
import redress.memory.address.Address32;
import redress.util.B;

import java.nio.ByteOrder;
import java.util.LinkedList;

/**
 * Created by jamesrichardson on 2/11/16.
 */
public class QWord extends AbstractData {
    public static final Word SIZEOF_B = new Word("0x0008", AbstractData.Type.DATA_BYTE,ByteOrder.BIG_ENDIAN);
    public static final Word SIZEOF_L = new Word("0x0800", AbstractData.Type.DATA_BYTE,ByteOrder.LITTLE_ENDIAN);
    public static final QWord NULL = new QWord();

    public QWord(){
        super(0,null,Type.DATA_NULL,ByteOrder.BIG_ENDIAN);
    }

    public QWord(byte[] in,Type type,ByteOrder order){
        this(in,Address32.NULL,null,type,order);
    }
    public QWord(byte[] in,AbstractAddress beginAddress,IStructure parent,Type type,ByteOrder order){
        super(8,parent,type,order);
        this.beginAddress=beginAddress;
        this.endAddress=beginAddress.clone();
        B.add(this.endAddress,new Address32("0x00000008"));
        if(in.length != BYTES){
            return;
        }
        for(int i=0;i<BYTES;i++){
            container[i]=in[i];
        }
    }

    public QWord(String in,Type type,ByteOrder order){
        this(in,Address32.NULL,null,type,order);
    }
    public QWord(String in,AbstractAddress beginAddress,IStructure parent,Type type,ByteOrder order){
        super(8,parent,type,order);
        this.beginAddress=beginAddress;
        this.endAddress=beginAddress.clone();
        B.add(this.endAddress,new Address32("0x00000008"));
        final byte[] tmp = B.stringToBytes(in);
        if(tmp.length != BYTES){
            System.out.println("Size Overflow!");
            return;
        }
        for(int i=0;i<BYTES;i++){
            container[i]=tmp[i];
        }
    }

    public void setDataType(Type in){
        this.type=in;
    }

    @Override
    public Type getDataType() {
        return type;
    }

    @Override
    public QWord flipByteOrder() {
        byte[] flip = new byte[BYTES];
        for(int i=0;i<BYTES;i++){
            flip[i] = container[(BYTES-1)-i];
        }

        return new QWord(flip,this.type,BYTEORDER==ByteOrder.BIG_ENDIAN?ByteOrder.LITTLE_ENDIAN:ByteOrder.BIG_ENDIAN);
    }

    @Override
    public QWord clone() {
        return new QWord(container,this.type,BYTEORDER);
    }


    }
