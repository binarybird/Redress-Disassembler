package redress.abi.generic;

import redress.memory.address.AbstractAddress;

/**
 * Created by jamesrichardson on 2/11/16.
 */
public interface IAddressable extends Comparable<IAddressable>{
    public AbstractAddress getBeginAddress();
    public AbstractAddress getEndAddress();

    public void setBeginAddress(AbstractAddress in);
    public void setEndAddress(AbstractAddress in);

    public void setComments(String... comment);
    public String[] getComment();
}
