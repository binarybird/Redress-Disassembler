package abi.generic.memory;

import util.B;

import java.math.BigInteger;
import java.nio.ByteOrder;

/**
 * Created by jamesrichardson on 2/11/16.
 *
 * for enforcing some order on byte[]
 * instead of arrays around all willy nilly
 */
public abstract class Container {

    public final int BYTES;
    public final ByteOrder BYTEORDER;

    protected final byte[] container;

    public Container(int bytes, ByteOrder order){
        BYTES=bytes;
        BYTEORDER=order;
        container = new byte[BYTES];
    }

    public byte[] getContainer(){return container;}

    public abstract Container flipByteOrder();

    @Override
    public boolean equals(Object o){
        if(!(o instanceof Container))
            return false;
        return equals((Container) o, false);
    }

    public boolean equals(Container o, boolean ignoreLength){
        Container tmp;
        if(this.BYTEORDER == o.BYTEORDER){
            tmp = o;
        }else{
            tmp = o.flipByteOrder();
        }

        if(ignoreLength){
            if(this.BYTES <= tmp.BYTES){
                for(int i=0;i<this.BYTES;i++){
                    if(this.container[i] != tmp.container[i])
                        return false;
                }

            }else{
                for(int i=0;i<tmp.BYTES;i++){
                    if(this.container[i] != tmp.container[i])
                        return false;
                }
            }
        }else{
            if(this.BYTES != tmp.BYTES) {
                return false;
            }
            for(int i=0;i<this.BYTES;i++){
                if(this.container[i] != tmp.container[i])
                    return false;
            }
        }
        return true;
    }

    public int getIntValue(){
        return B.bytesToInt(container,BYTEORDER);
    }

    public BigInteger getIntegerValue(){
        return new BigInteger(container);
    }

    public String getStringValue(){
        return B.bytesToString(container);
    }

    public long getLongValue(){
        return B.bytesToLong(container,BYTEORDER);
    }

    public byte getLeastSignificantByte(){
        if(BYTEORDER == ByteOrder.LITTLE_ENDIAN){
            return container[BYTES-1];
        }
        return container[0];
    }

    public byte getMostSignificantByte(){
        if(BYTEORDER == ByteOrder.LITTLE_ENDIAN){
            return container[0];
        }
        return container[BYTES-1];
    }

    public byte getByteAtOffset(int offset){
        if(offset >= BYTES){
            return (byte)0x00;
        }

        if(BYTEORDER == ByteOrder.LITTLE_ENDIAN){
            return container[BYTES-offset];
        }
        return container[offset];
    }

}
