package abi.generic.memory.data;

import abi.generic.memory.Container;
import abi.generic.memory.address.Address;
import util.B;

import java.nio.ByteOrder;

/**
 * Created by jamesrichardson on 2/16/16.
 */
public class ArbitrarySize extends Data{
    public ArbitrarySize(){
        this(new byte[0],ByteOrder.BIG_ENDIAN);
    }

    public ArbitrarySize(byte[] in, ByteOrder order) {
        super(in.length, order);
        for(int i=0;i<in.length;i++){
            container[i]=in[i];
        }
    }

    public ArbitrarySize(byte[] in, Address addr, ByteOrder order) {
        super(in.length, addr, order);
        for(int i=0;i<in.length;i++){
            container[i]=in[i];
        }
    }

    @Override
    public Container flipByteOrder() {
        return new ArbitrarySize(B.flipByteOrder(container),this.BYTEORDER);
    }

    @Override
    public Data clone() {
        return new ArbitrarySize(container,this.BYTEORDER);
    }
}
