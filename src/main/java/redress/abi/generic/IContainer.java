package redress.abi.generic;

import redress.abi.generic.visitors.AbstractContainerVisitor;

import java.nio.ByteOrder;

/**
 * Created by jamesrichardson on 2/23/16.
 */
public interface IContainer extends IVisitable<AbstractContainerVisitor> {
    public byte[] getContainer();
    public ByteOrder getByteOrder();

    public IContainer getNextSibling();
    public IContainer getPreviousSibling();
    public IStructure getParent();

    public IContainer flipByteOrder();
    public IContainer clone();

    public void add(IContainer i);
    public void add(int i);

    public void subtract(IContainer i);
    public void subtract(int i);
}
