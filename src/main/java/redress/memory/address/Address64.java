package redress.memory.address;

import redress.util.B;

/**
 * Created by jamesrichardson on 2/11/16.
 */
public class Address64 extends Address {
    public static final Address64 NULL = new Address64("0x0000000000000000");

    public Address64(byte[] in){
        super(8);
        if(in.length != BYTES)
            return;

        for(int i=0;i<BYTES;i++){
            container[i]=in[i];
        }

    }
    public Address64(byte mostSignificant,byte seven,byte six,byte five,byte four,byte three,byte two,byte leastSignificant){
        super(8);
        container[0]=mostSignificant;
        container[1]=seven;
        container[2]=six;
        container[3]=five;
        container[4]=four;
        container[5]=three;
        container[6]=two;
        container[7]=leastSignificant;
    }

    public Address64(String in){
        super(8);
        final byte[] tmp = B.stringToBytes(in);
        for(int i=0;i<BYTES;i++){
            container[i]=tmp[i];
        }
    }

    @Override
    public Address64 flipByteOrder() {
        byte[] flip = new byte[BYTES];
        for(int i=0;i<BYTES;i++){
            flip[i] = container[(BYTES-1)-i];
        }

        return new Address64(flip);
    }

    @Override
    public Address64 clone() {
        return new Address64(container);
    }

}
