package abi.generic.abi;

import abi.generic.memory.Addressable;
import abi.generic.memory.address.Address;
import abi.generic.memory.data.Data;

import java.util.ArrayList;
import java.util.LinkedList;

/**
 * Created by jamesrichardson on 2/10/16.
 */
public abstract class DataStructure implements Addressable {

    protected final DataStructure parent;
    protected final ArrayList<DataStructure> children = new ArrayList<>();
    protected final String name;
    protected Address beginAddress;
    protected Address endAddress;
    protected String comment="";

    public DataStructure(DataStructure parent, String name){
        this.parent = parent;
        this.name=name;
    }
    public String getName(){
        return name;
    }
    @Override
    public Address getBeginAddress(){
        return beginAddress;
    }
    public void setBeginAddress(Address in){

    }
    @Override
    public Address getEndAddress(){
        return endAddress;
    }
    public void setEndAddress(Address in){

    }
    @Override
    public void setComment(String comment){
        this.comment=comment;
    }
    @Override
    public String getComment(){
        return comment;
    }
    public DataStructure getParent(){
        return parent;
    }
    public ArrayList<DataStructure> getChildren(){
        return children;
    }

    public abstract LinkedList<Data> getStructureData();
}
