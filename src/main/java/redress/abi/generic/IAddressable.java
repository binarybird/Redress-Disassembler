package redress.abi.generic;

import redress.memory.address.AbstractAddress;

import java.util.HashSet;

/**
 * Created by jamesrichardson on 2/11/16.
 */
public interface IAddressable extends Comparable<IAddressable>{
    public AbstractAddress getBeginAddress();
    public AbstractAddress getEndAddress();

    public void setBeginAddress(AbstractAddress in);
    public void setEndAddress(AbstractAddress in);

    public void addComments(String... comment);
    public HashSet<String> getComments();
}
