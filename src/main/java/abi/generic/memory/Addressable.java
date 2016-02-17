package abi.generic.memory;

import abi.generic.memory.address.Address;
import abi.generic.memory.data.Data;

import java.util.HashSet;

/**
 * Created by jamesrichardson on 2/11/16.
 */
public interface Addressable {
    public Address getBeginAddress();
    public Address getEndAddress();

    public void setComment(String comment);
    public String getComment();
}
