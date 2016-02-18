package abi.memory;

import abi.memory.address.Address;

/**
 * Created by jamesrichardson on 2/11/16.
 */
public interface Addressable {
    public Address getBeginAddress();
    public Address getEndAddress();

    public void setComment(String comment);
    public String getComment();
}
