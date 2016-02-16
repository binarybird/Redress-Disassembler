package abi.generic.memory.data;

import abi.generic.memory.address.Address;
import util.B;

import java.nio.ByteOrder;

/**
 * Created by jamesrichardson on 2/11/16.
 */
public class DWord extends Data {
    public static final Word SIZEOF_B = new Word("0x0004",ByteOrder.BIG_ENDIAN);
    public static final Word SIZEOF_L = new Word("0x0400",ByteOrder.LITTLE_ENDIAN);

    public DWord(){
        this(new byte[0],ByteOrder.BIG_ENDIAN);
    }

    public DWord(byte[] in,Address addr,ByteOrder order){
        this(in, order);
        this.address = addr;
    }

    public DWord(byte zero,byte one,byte two,byte three,Address addr,ByteOrder order){
        this(zero,one,two,three,order);
        this.address = addr;
    }

    public DWord(String in,Address addr,ByteOrder order){
        this(in,order);
        this.address = addr;
    }

    public DWord(byte[] in,ByteOrder order){
        super(4,order);
        if(in.length != BYTES){
            return;
        }
        for(int i=0;i<BYTES;i++){
            container[i]=in[i];
        }
    }

    public DWord(byte zero,byte one,byte two,byte three,ByteOrder order){
        super(4,order);
        container[0]=zero;
        container[1]=one;
        container[2]=two;
        container[3]=three;
    }

    public DWord(String in,ByteOrder order){
        super(4,order);
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
    public DWord flipByteOrder() {
        byte[] flip = new byte[BYTES];
        for(int i=0;i<BYTES;i++){
            flip[i] = container[(BYTES-1)-i];
        }

        return new DWord(flip,BYTEORDER==ByteOrder.BIG_ENDIAN?ByteOrder.LITTLE_ENDIAN:ByteOrder.BIG_ENDIAN);
    }

    @Override
    public DWord clone() {
        return new DWord(container,BYTEORDER);
    }
}
