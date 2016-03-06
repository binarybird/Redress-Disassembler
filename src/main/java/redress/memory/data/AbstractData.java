package redress.memory.data;

import redress.abi.generic.IAddressable;
import redress.abi.generic.IContainer;
import redress.abi.generic.IStructure;

import redress.memory.address.AbstractAddress;
import redress.util.B;

import java.math.BigInteger;
import java.nio.ByteOrder;
import java.util.HashSet;

/**
 * Created by jamesrichardson on 2/16/16.
 *
 * A single data item
 */
public abstract class AbstractData implements IContainer, IAddressable{

    public enum Type{
        DATA_NULL,
        DATA_BYTE,
        DATA_CHAR,
        DATA_U_INT,
        DATA_INT,
        DATA_FLOAT,
        DATA_DOUBLE,
        DATA_LONG,
        DATA_BOOL,
        TEXT_DECOMPILED,
        TEXT_COMPILED,
        COMMENT
    }

    protected final IStructure parent;
    protected IContainer previousSibling;
    protected IContainer nextSibling;
    protected AbstractAddress beginAddress;
    protected AbstractAddress endAddress;
    protected final byte[] container;
    protected final ByteOrder BYTEORDER;
    public final int BYTES;
    protected Object userData = null;
    protected Type type = Type.DATA_NULL;
    protected final HashSet<String> comment = new HashSet<>();


    protected AbstractData(int bytes, IStructure parent, Type type, ByteOrder order){
        BYTES=bytes;
        BYTEORDER=order;
        container = new byte[BYTES];
        this.type = type;
        this.parent = parent;
    }

    @Override
    public IStructure getParent(){
        return parent;
    }

    public void setNextSibling(IContainer c){
        this.nextSibling = c;
    }

    @Override
    public IContainer getNextSibling() {
        return nextSibling;
    }

    public void setPreviousSibling(IContainer c){
        this.previousSibling = c;
    }

    @Override
    public IContainer getPreviousSibling() {
        return previousSibling;
    }

    public byte[] getContainer(){return container;}

    public ByteOrder getByteOrder(){return BYTEORDER;}

    public Type getDataType(){
        return this.type;
    }

    public void add(IContainer in){
        B.add(this,in);
    }

    public void add(int i){
        QWord w = new QWord(B.intToBytes(i,ByteOrder.BIG_ENDIAN),Type.DATA_NULL,ByteOrder.BIG_ENDIAN);
        add(w);
    }

    public void subtract(IContainer in){
        B.subtract(this,in);
    }

    public void subtract(int i){
        QWord w = new QWord(B.intToBytes(i,ByteOrder.BIG_ENDIAN), AbstractData.Type.DATA_NULL,ByteOrder.BIG_ENDIAN);
        subtract(w);
    }

    public void setDataType(Type type){
        this.type = type;
    }

    public void setUserData(Object in){this.userData = in;}

    public Object getUserData(){return userData;}

    public int getIntValue(){
        return B.bytesToInt(container, BYTEORDER);
    }

    public BigInteger getIntegerValue(){
        return new BigInteger(1,container);
    }

    public String getStringValue(){
        return B.bytesToHexString(container);
    }

    public long getLongValue(){
        return B.bytesToLong(container,BYTEORDER);
    }

    public double getDoubleValue(){return B.bytesToDouble(container,BYTEORDER);}

    public char[] getCharValue(){

        String g = new String(container);
        char[] o = g.toCharArray();

        return o;
    }

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

    @Override
    public int compareTo(IAddressable o) {
        if(o == null)
            return 0;

        return this.beginAddress.compareTo(o.getBeginAddress());
    }

    @Override
    public boolean equals(Object o){
        if(!(o instanceof AbstractData))
            return false;
        return equals((AbstractData) o, false);
    }

    public boolean and(IContainer in){
        final byte[] container1;

        if(this.getByteOrder() != in.getByteOrder())
            container1 = in.flipByteOrder().getContainer();
        else
            container1 = in.getContainer();

        if(container1.length >= container.length){
            for(int i=0;i<container.length;i++){
                if(container1[i] != 0 && container1[i] == container[i])
                    return true;
            }
        }else{
            for(int i=0;i<container1.length;i++){
                if(container1[i] != 0 && container1[i] == container[i])
                    return true;
            }
        }
        return false;
    }

    public boolean equals(AbstractData o, boolean ignoreLength){
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
    public AbstractAddress getBeginAddress(){
        return beginAddress;
    }

    @Override
    public AbstractAddress getEndAddress(){
        return endAddress;
    }

    @Override
    public void setBeginAddress(AbstractAddress in){
        this.beginAddress = in;
    }

    @Override
    public void setEndAddress(AbstractAddress in){
        this.endAddress = in;
    }

    @Override
    public void addComments(String... comment){
        for(String s : comment)
            this.comment.add(s);
    }

    @Override
    public HashSet<String> getComments(){
        return comment;
    }

    public abstract AbstractData clone();

    @Override
    public String toString(){
        switch(type){
            case DATA_NULL:
                return getStringValue();
            case DATA_BYTE:
                return getStringValue();
            case DATA_CHAR:
                return new String(getCharValue());
            case DATA_U_INT:
                return String.valueOf(getIntValue());
            case DATA_INT:
                return String.valueOf(getIntValue());
            case DATA_FLOAT:break;
            case DATA_DOUBLE:break;
            case DATA_LONG:break;
            case DATA_BOOL:break;
            case COMMENT:
                return "";
            default:break;
        }
        return getStringValue()+" "+BYTEORDER;
    }


}
