package abi.memory.data;

import abi.memory.address.Address;
import abi.memory.address.Address32;
import util.B;

import java.nio.ByteOrder;

/**
 * Created by jamesrichardson on 2/11/16.
 */
public class QWord extends Data{
    public static final Word SIZEOF_B = new Word("0x0008",ByteOrder.BIG_ENDIAN);
    public static final Word SIZEOF_L = new Word("0x0800",ByteOrder.LITTLE_ENDIAN);
    public static final QWord NULL = new QWord();

    public QWord(){
        super(0, Address32.NULL, Address32.NULL, ByteOrder.BIG_ENDIAN);
    }

    public QWord(byte[] in,ByteOrder order){
        this(in,new Address32("0x00000000"),order);
    }

    public QWord(byte zero,byte one,byte two,byte three,byte four,byte five,byte six,byte seven,ByteOrder order){
        this(zero,one,two,three,four,five,six,seven,new Address32("0x00000000"),order);
    }

    public QWord(String in,ByteOrder order){
        this(in,new Address32("0x00000000"),order);
    }

    public QWord(byte[] in,Address beginAddress,ByteOrder order){
        super(8,beginAddress,beginAddress.clone(),order);
        this.endAddress.add(new Address32("0x00000008"));
        if(in.length != BYTES){
            return;
        }
        for(int i=0;i<BYTES;i++){
            container[i]=in[i];
        }
    }

    public QWord(byte zero,byte one,byte two,byte three,byte four,byte five,byte six,byte seven,Address beginAddress,ByteOrder order){
        super(8,beginAddress,beginAddress.clone(),order);
        this.endAddress.add(new Address32("0x00000008"));
        container[0]=zero;
        container[1]=one;
        container[2]=two;
        container[3]=three;
        container[4]=four;
        container[5]=five;
        container[6]=six;
        container[7]=seven;
    }

    public QWord(String in,Address beginAddress,ByteOrder order){
        super(8,beginAddress,beginAddress.clone(),order);
        this.endAddress.add(new Address32("0x00000008"));
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
    public QWord flipByteOrder() {
        byte[] flip = new byte[BYTES];
        for(int i=0;i<BYTES;i++){
            flip[i] = container[(BYTES-1)-i];
        }

        return new QWord(flip,BYTEORDER==ByteOrder.BIG_ENDIAN?ByteOrder.LITTLE_ENDIAN:ByteOrder.BIG_ENDIAN);
    }

    @Override
    public QWord clone() {
        return new QWord(container,BYTEORDER);
    }
}
