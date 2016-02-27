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

    public void add(IContainer i);
    public void add(int i);

    public void subtract(IContainer i);
    public void subtract(int i);
}
