package redress.memory.address;

import redress.abi.generic.IContainer;
import redress.abi.generic.IStructure;
import redress.util.B;

/**
 * Created by jamesrichardson on 2/11/16.
 */
public class Address32 extends AbstractAddress {
    public static final Address32 NULL = new Address32("0x00000000");

    public Address32(byte[] in){
        super(4);
        if(in.length != BYTES)
            return;

        for(int i=0;i<BYTES;i++){
            container[i]=in[i];
        }

    }

    public Address32(byte mostSignificant,byte three,byte two,byte leastSignificant){
        super(4);
        container[0]=mostSignificant;
        container[1]=three;
        container[2]=two;
        container[3]=leastSignificant;
    }

    public Address32(String in){
        super(4);
        final byte[] tmp = B.stringToBytes(in);
        for(int i=0;i<BYTES;i++){
            container[i]=tmp[i];
        }
    }



    @Override
    public Address32 flipByteOrder() {
        byte[] flip = new byte[BYTES];
        for(int i=0;i<BYTES;i++){
            flip[i] = container[(BYTES-1)-i];
        }

        return new Address32(flip);
    }

    @Override
    public Address32 clone() {
        return new Address32(container);
    }

}
