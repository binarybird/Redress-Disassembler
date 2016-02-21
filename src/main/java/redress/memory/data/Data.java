package redress.memory.data;

import redress.memory.Addressable;
import redress.memory.Container;
import redress.memory.struct.DataStructure;
import redress.memory.address.Address;

import java.nio.ByteOrder;

/**
 * Created by jamesrichardson on 2/16/16.
 */
public abstract class Data extends Container implements Addressable{

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
        TEXT_COMPILED,
        TEXT_DECOMPILED,
        COMMENT
    }

    protected final Address beginAddress;
    protected final Address endAddress;

    protected Type type = Type.DATA_NULL;
    protected DataStructure parent;
    protected String comment;

    public Data(int bytes,Address beginAddr,Address endAddress, Type type, ByteOrder order){
        super(bytes, order);
        this.beginAddress = beginAddr;
        this.endAddress = endAddress;
        this.type = type;
    }

    public Data(int bytes,Address beginAddr,Address endAddress, ByteOrder order){
        this(bytes,beginAddr,endAddress,Type.DATA_NULL,order);
    }

    public Type getDataType(){
        return this.type;
    }

    public void setDataType(Type type){
        this.type = type;
    }

    public void setContainingDataStructure(DataStructure in){
        this.parent = in;
    }

    public DataStructure getContainingDataStructure(){return parent;}

    @Override
    public Address getBeginAddress(){
        return beginAddress;
    }

    @Override
    public Address getEndAddress(){
        return endAddress;
    }

    @Override
    public void setComment(String comment){
        this.comment = comment;
    }

    @Override
    public String getComment(){
        return comment;
    }

    public abstract Data clone();

    @Override
    public String toString(){
        return getStringValue()+" "+BYTEORDER;
    }

    public static Data generateCommentContainer(String comment){
        Word comm = new Word(new byte[0],Type.COMMENT, ByteOrder.BIG_ENDIAN);
        comm.setComment(comment);
        return comm;
    }
}
