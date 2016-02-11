package abi.generic.memory;

import util.B;

import java.nio.ByteOrder;

/**
 * Created by jamesrichardson on 2/11/16.
 */
public class QWord extends Container{
    public QWord(byte[] in,ByteOrder order){
        super(8,order);
        if(in.length != BYTES){
            return;
        }
        for(int i=0;i<BYTES;i++){
            container[i]=in[i];
        }
    }

    public QWord(byte zero,byte one,byte two,byte three,byte four,byte five,byte six,byte seven,ByteOrder order){
        super(8,order);
        container[0]=zero;
        container[1]=one;
        container[2]=two;
        container[3]=three;
        container[4]=four;
        container[5]=five;
        container[6]=six;
        container[7]=seven;
    }

    public QWord(String in,ByteOrder order){
        super(8,order);
        final byte[] tmp = B.stringToBytes(in);
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
}
