package abi.generic.memory.data;

import abi.generic.memory.Container;
import abi.generic.memory.address.Address;

import java.nio.ByteOrder;

/**
 * Created by jamesrichardson on 2/16/16.
 */
public abstract class Data extends Container {
    public Data(int bytes,ByteOrder order){
        super(bytes, order);
    }

    public Data(int bytes,Address addr, ByteOrder order){
        super(bytes, order);
        this.address = addr;
    }

    protected Address address;
    protected String comment ="";
    public void setAddress(Address in){this.address = in;}
    public Address getAddress(){return address;}
    public Data setComment(String comment){this.comment = comment;return this;}
    public String getComment(){return comment;}

    @Override
    public abstract Data clone();

    @Override
    public String toString(){
        return "0x"+getStringValue()+" "+BYTEORDER;
    }
}
