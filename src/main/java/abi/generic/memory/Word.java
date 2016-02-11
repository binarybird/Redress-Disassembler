package abi.generic.memory;

import util.B;

import java.nio.ByteOrder;

/**
 * Created by jamesrichardson on 2/11/16.
 */
public class Word extends Container {
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
}
