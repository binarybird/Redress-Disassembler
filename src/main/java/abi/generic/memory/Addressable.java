package abi.generic.memory;

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
}
