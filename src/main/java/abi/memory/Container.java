package abi.memory;

import util.B;

import java.math.BigInteger;
import java.nio.ByteOrder;
import java.util.Arrays;

/**
 * Created by jamesrichardson on 2/11/16.
 *
 * for enforcing some order on byte[]
 * instead of arrays around all willynilly
 */
public abstract class Container implements Comparable<Container>{

    public final int BYTES;
    public final ByteOrder BYTEORDER;

    protected final byte[] container;

    public Container(int bytes, ByteOrder order){
        BYTES=bytes;
        BYTEORDER=order;
        container = new byte[BYTES];
    }

    public abstract Container flipByteOrder();
    public abstract Container clone();

    public byte[] getContainer(){return container;}

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
        return new BigInteger(1,container);
    }

    public String getStringValue(){
        return B.bytesToString(container);
    }

    public long getLongValue(){
        return B.bytesToLong(container,BYTEORDER);
    }

    public double getDoubleValue(){return B.bytesToDouble(container,BYTEORDER);}

    public byte getLeastSignificantByte(){
        if(BYTEORDER == ByteOrder.LITTLE_ENDIAN){
            return container[0];
        }
        return container[BYTES-1];
    }

    public byte getMostSignificantByte(){
        if(BYTEORDER == ByteOrder.LITTLE_ENDIAN){
            return container[BYTES-1];
        }
        return container[0];
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

    public void add(Container in){
        //No unsigned values anywhere in java - we have to do it the hard way
        Container otherContainer;
        Container thisContainer;

        //BigInt takes BigEndian only
        if(in.BYTEORDER == ByteOrder.LITTLE_ENDIAN){
            otherContainer = in.flipByteOrder();
        }else{
            otherContainer = in;
        }
        if(BYTEORDER == ByteOrder.LITTLE_ENDIAN){
            thisContainer = this.flipByteOrder();
        }else{
            thisContainer = this;
        }

        //Get BigInt
        final BigInteger otherUnsigned = new BigInteger(1,otherContainer.getContainer());
        final BigInteger thisUnsigned = new BigInteger(1,thisContainer.getContainer());

        //Add
        final BigInteger add = thisUnsigned.add(otherUnsigned);
        final byte[] res = add.toByteArray();

        Arrays.fill(container, (byte) 0x00);

        //Restore original endinass
        byte[] tmp;
        if(BYTEORDER == ByteOrder.LITTLE_ENDIAN){
            tmp = B.flipByteOrder(res);
            //store result
            if(BYTES >= res.length){
                for(int i=0;i<tmp.length;i++){
                    container[i] = tmp[i];
                }
            }else{
                for(int i=0;i<BYTES;i++){
                    container[i] = tmp[i];
                }
            }
        }else{
            tmp = res;
            //store result
            if(BYTES >= res.length){
                int padding = BYTES - tmp.length;
                for(int i=0;i<tmp.length;i++){
                    container[padding+i] = tmp[i];
                }
            }else{
                int padding = tmp.length - BYTES;
                for(int i=0;i<BYTES;i++){
                    container[i] = tmp[i+padding];
                }
            }
        }
    }

    public void subtract(Container in){
        //No unsigned values anywhere in java - we have to do it the hard way
        Container otherContainer;
        Container thisContainer;

        //BigInt takes BigEndian only
        if(in.BYTEORDER == ByteOrder.LITTLE_ENDIAN){
            otherContainer = in.flipByteOrder();
        }else{
            otherContainer = in;
        }
        if(BYTEORDER == ByteOrder.LITTLE_ENDIAN){
            thisContainer = this.flipByteOrder();
        }else{
            thisContainer = this;
        }

        //Get BigInt
        final BigInteger otherUnsigned = new BigInteger(1,otherContainer.getContainer());
        final BigInteger thisUnsigned = new BigInteger(1,thisContainer.getContainer());

        //Subtract
        final BigInteger add = thisUnsigned.subtract(otherUnsigned);
        final byte[] res = add.toByteArray();

        Arrays.fill(container, (byte) 0x00);

        //Restore original endinass
        byte[] tmp;
        if(BYTEORDER == ByteOrder.LITTLE_ENDIAN){
            tmp = B.flipByteOrder(res);
            //store result
            if(BYTES >= res.length){
                for(int i=0;i<tmp.length;i++){
                    container[i] = tmp[i];
                }
            }else{
                for(int i=0;i<BYTES;i++){
                    container[i] = tmp[i];
                }
            }
        }else{
            tmp = res;
            //store result
            if(BYTES >= res.length){
                int padding = BYTES - tmp.length;
                for(int i=0;i<tmp.length;i++){
                    container[padding+i] = tmp[i];
                }
            }else{
                int padding = tmp.length - BYTES;
                for(int i=0;i<BYTES;i++){
                    container[i] = tmp[i+padding];
                }
            }
        }
    }

    @Override
    public String toString(){
        return "0x"+getStringValue();
    }

    @Override
    public int compareTo(Container o) {
        if(o == null)
            return 0;

        if(o.getIntValue() == this.getIntValue()){
            return 0;
        }

        if(o.getIntValue() > this.getIntValue()){
            return -1;
        }

        if(o.getIntValue() < this.getIntValue()){
            return 1;
        }

        return 0;
    }
}
