package redress.memory.address;

import redress.abi.generic.IContainer;
import redress.abi.generic.IStructure;
import redress.abi.generic.visitors.AbstractContainerVisitor;
import redress.memory.data.AbstractData;
import redress.memory.data.QWord;
import redress.util.B;

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
    public void accept(AbstractContainerVisitor visitor) {

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

    public void add(int i){
        QWord w = new QWord(B.intToBytes(i,ByteOrder.BIG_ENDIAN), AbstractData.Type.DATA_NULL,ByteOrder.BIG_ENDIAN);
        add(w);
    }

    public void subtract(IContainer in){
        B.subtract(this,in);
    }

    public void subtract(int i){
        QWord w = new QWord(B.intToBytes(i,ByteOrder.BIG_ENDIAN), AbstractData.Type.DATA_NULL,ByteOrder.BIG_ENDIAN);
        subtract(w);
    }

    public int getIntValue(){
        return B.bytesToInt(container, BYTEORDER);
    }

    public String getStringValue(){
        return B.bytesToHexString(container);
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
    public int hashCode() {
        int result = this.BYTES;
        result = 31 * result + (this.BYTEORDER != null ? this.BYTEORDER.hashCode() : 0);
        result = 31 * result + Arrays.hashCode(this.container);
        return result;
    }

    @Override
    public IContainer getNextSibling() {
        return null;
    }

    @Override
    public IContainer getPreviousSibling() {
        return null;
    }

    @Override
    public IStructure getParent() {
        return null;
    }

    @Override
    public String toString(){
        return "0x"+getStringValue();
    }

}
