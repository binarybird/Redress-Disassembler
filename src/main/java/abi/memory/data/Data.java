package abi.memory.data;

import abi.memory.Addressable;
import abi.memory.Container;
import abi.memory.DataStructure;
import abi.memory.address.Address;

import java.nio.ByteOrder;

/**
 * Created by jamesrichardson on 2/16/16.
 */
public abstract class Data extends Container implements Addressable{

    final Address beginAddress;
    final Address endAddress;

    protected DataStructure parent;
    protected String comment;

    public Data(int bytes,Address beginAddr,Address endAddress, ByteOrder order){
        super(bytes, order);
        this.beginAddress = beginAddr;
        this.endAddress = endAddress;
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
        return "0x"+getStringValue()+" "+BYTEORDER;
    }

}
