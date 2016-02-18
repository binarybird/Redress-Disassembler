package abi.memory.data;

import abi.memory.address.Address;
import abi.memory.address.Address32;
import util.B;

import java.nio.ByteOrder;

/**
 * Created by jamesrichardson on 2/11/16.
 */
public class Word extends Data {
    public static final Word SIZEOF_B = new Word("0x0002",ByteOrder.BIG_ENDIAN);
    public static final Word SIZEOF_L = new Word("0x0200",ByteOrder.LITTLE_ENDIAN);
    public static final Word NULL = new Word();

    public Word(){
        super(0, Address32.NULL,Address32.NULL, ByteOrder.BIG_ENDIAN);
    }

    public Word(byte[] in,ByteOrder order){
        this(in,new Address32("0x00000000"),order);
    }

    public Word(byte zero,byte one,ByteOrder order){
        this(zero,one,new Address32("0x00000000"),order);
    }

    public Word(String in,ByteOrder order){
        this(in,new Address32("0x00000000"),order);
    }

    public Word(byte[] in,Address beginAddress,ByteOrder order){
        super(2,beginAddress,beginAddress.clone(),order);
        this.endAddress.add(new Address32("0x00000002"));
        if(in.length != BYTES){
            return;
        }
        for(int i=0;i<BYTES;i++){
            container[i]=in[i];
        }
    }

    public Word(byte zero,byte one,Address beginAddress,ByteOrder order){
        super(2,beginAddress,beginAddress.clone(),order);
        this.endAddress.add(new Address32("0x00000002"));
        container[0]=zero;
        container[1]=one;
    }

    public Word(String in,Address beginAddress,ByteOrder order){
        super(2,beginAddress,beginAddress.clone(),order);
        this.endAddress.add(new Address32("0x00000002"));
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
