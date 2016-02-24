package redress.memory.address;

import redress.util.B;

/**
 * Created by jamesrichardson on 2/11/16.
 */
public class Address16 extends AbstractAddress {
    public static final Address16 NULL = new Address16("0x0000");

    public Address16(byte[] in){
        super(2);
        if(in.length != BYTES)
            return;

        for(int i=0;i<BYTES;i++){
            container[i]=in[i];
        }

    }
    public Address16(byte mostSignificant, byte leastSignificant){
        super(2);
        container[0]=mostSignificant;
        container[1]=leastSignificant;
    }
    public Address16(String in){
        super(2);
        final byte[] tmp = B.stringToBytes(in);
        for(int i=0;i<BYTES;i++){
            container[i]=tmp[i];
        }
    }

    @Override
    public Address16 flipByteOrder() {

        byte[] flip = new byte[BYTES];
        for(int i=0;i<BYTES;i++){
            flip[i] = container[(BYTES-1)-i];
        }

        return new Address16(flip);
    }

    @Override
    public Address16 clone() {
        return new Address16(container);
    }


}
