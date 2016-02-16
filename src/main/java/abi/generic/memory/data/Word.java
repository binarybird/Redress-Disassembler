package abi.generic.memory.data;

import abi.generic.memory.address.Address;
import util.B;

import java.nio.ByteOrder;

/**
 * Created by jamesrichardson on 2/11/16.
 */
public class Word extends Data {
    public static final Word SIZEOF_B = new Word("0x0002",ByteOrder.BIG_ENDIAN);
    public static final Word SIZEOF_L = new Word("0x0200",ByteOrder.LITTLE_ENDIAN);

    public Word(){
        this(new byte[0],ByteOrder.BIG_ENDIAN);
    }

    public Word(byte[] in,Address addr,ByteOrder order){
        this(in,order);
        this.address = addr;
    }

    public Word(byte zero,byte one,Address addr,ByteOrder order){
        this(zero,one,order);
        this.address = addr;
    }

    public Word(String in,Address addr,ByteOrder order){
        this(in,order);
        this.address = addr;
    }

    public Word(byte[] in,ByteOrder order){
        super(2,order);
        if(in.length != BYTES){
            return;
        }
        for(int i=0;i<BYTES;i++){
            container[i]=in[i];
        }
    }

    public Word(byte zero,byte one,ByteOrder order){
        super(2,order);
        container[0]=zero;
        container[1]=one;
    }

    public Word(String in,ByteOrder order){
        super(2,order);
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
    public Word flipByteOrder() {
        byte[] flip = new byte[BYTES];
        for(int i=0;i<BYTES;i++){
            flip[i] = container[(BYTES-1)-i];
        }

        return new Word(flip,BYTEORDER==ByteOrder.BIG_ENDIAN?ByteOrder.LITTLE_ENDIAN:ByteOrder.BIG_ENDIAN);
    }

    @Override
    public Word clone() {
        return new Word(container,BYTEORDER);
    }
}
