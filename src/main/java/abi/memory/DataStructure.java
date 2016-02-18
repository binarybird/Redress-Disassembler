package abi.memory;

import abi.memory.address.Address;
import abi.memory.data.Data;

import java.util.ArrayList;
import java.util.LinkedList;

/**
 * Created by jamesrichardson on 2/10/16.
 */
public abstract class DataStructure implements Addressable {

    protected final Addressable parent;
    protected final ArrayList<DataStructure> children = new ArrayList<>();
    protected Address beginAddress;
    protected Address endAddress;
    protected String comment="";

    public DataStructure(Addressable parent){
        this.parent = parent;
    }

    @Override
    public Address getBeginAddress(){
        return beginAddress;
    }
    public void setBeginAddress(Address in){
        this.beginAddress = in;
    }
    @Override
    public Address getEndAddress(){
        return endAddress;
    }
    public void setEndAddress(Address in){
        this.endAddress = in;
    }
    @Override
    public void setComment(String comment){
        this.comment=comment;
    }
    @Override
    public String getComment(){
        return comment;
    }
    public Addressable getParent(){
        return parent;
    }
    public ArrayList<DataStructure> getChildren(){
        return children;
    }

    public abstract LinkedList<Data> getStructureData();
}
