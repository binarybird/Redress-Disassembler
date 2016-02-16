package abi.generic.memory;

import abi.generic.memory.address.Address;
import abi.generic.memory.data.Data;

import java.util.HashSet;

/**
 * Created by jamesrichardson on 2/11/16.
 */
public abstract class Addressable {
    protected Address beginAddress = null;
    protected Address endAddress = null;
    public Address getBeginAddress(){return beginAddress;}
    public void setBeginAddress(Address in){this.beginAddress = in;}
    public Address getEndAddress(){return endAddress;}
    public void setEndAddress(Address in){this.endAddress = in;}
    public abstract Data[] getProcessedData();
}
