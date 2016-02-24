package redress.memory.address;

import redress.abi.generic.IContainer;
import redress.util.B;

import java.math.BigInteger;
import java.nio.ByteOrder;
import java.util.Arrays;

/**
 * Created by jamesrichardson on 2/11/16.
 * Addresses are always big endian in my world
 */
public abstract class AbstractAddress implements IContainer,Comparable<AbstractAddress> {

    protected final int BYTES;
    protected final ByteOrder BYTEORDER;
    protected final byte[] container;

    public AbstractAddress(int bytes){
        this.BYTES = bytes;
        this.BYTEORDER = ByteOrder.BIG_ENDIAN;
        container = new byte[BYTES];
    }

    @Override
    public abstract AbstractAddress clone();

    @Override
    public ByteOrder getByteOrder(){return BYTEORDER;}

    @Override
    public byte[] getContainer(){return container;}

    @Override
    public int compareTo(AbstractAddress o) {
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

    public void add(IContainer in){
        B.add(this,in);
    }

    public void subtract(IContainer in){
        B.subtract(this,in);
    }

    public int getIntValue(){
        return B.bytesToInt(container, BYTEORDER);
    }

    public String getStringValue(){
        return B.bytesToString(container);
    }

    @Override
    public boolean equals(Object o){
        if(!(o instanceof IContainer))
            return false;
        return equals((IContainer) o, false);
    }

    public boolean equals(IContainer o, boolean ignoreLength){
        IContainer tmp;
        if(this.BYTEORDER == o.getByteOrder()){
            tmp = o;
        }else{
            tmp = o.flipByteOrder();
        }

        if(ignoreLength){
            if(this.BYTES <= tmp.getContainer().length){
                for(int i=0;i<this.BYTES;i++){
                    if(this.container[i] != tmp.getContainer()[i])
                        return false;
                }
            }else{
                for(int i=0;i<tmp.getContainer().length;i++){
                    if(this.container[i] != tmp.getContainer()[i])
                        return false;
                }
            }
        }else{
            if(this.BYTES != tmp.getContainer().length) {
                return false;
            }
            for(int i=0;i<this.BYTES;i++){
                if(this.container[i] != tmp.getContainer()[i])
                    return false;
            }
        }
        return true;
    }

    @Override
    public String toString(){
        return "0x"+getStringValue();
    }

}
