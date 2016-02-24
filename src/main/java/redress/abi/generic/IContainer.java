package redress.abi.generic;

import java.nio.ByteOrder;

/**
 * Created by jamesrichardson on 2/23/16.
 */
public interface IContainer {
    public byte[] getContainer();
    public ByteOrder getByteOrder();

    public IContainer flipByteOrder();
    public IContainer clone();
}
