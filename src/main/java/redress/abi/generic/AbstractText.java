package redress.abi.generic;

import capstone.Capstone;
import redress.abi.generic.visitors.AbstractStructureVisitor;
import redress.memory.address.AbstractAddress;

import java.nio.ByteOrder;
import java.util.LinkedList;

/**
 * Created by jamesrichardson on 2/23/16.
 */
public abstract class AbstractText implements IStructure, IContainer {

    protected final LinkedList<IStructure> children = new LinkedList<>();
    protected final IStructure parent;
    protected AbstractAddress beginAddress;
    protected AbstractAddress endAddress;
    protected String[] comment = new String[0];
    protected final Capstone.CsInsn instruction;
    protected byte[] container;
    protected ByteOrder order;

    protected AbstractText(IStructure parent,Capstone.CsInsn ins) {
        this.parent = parent;
        this.instruction = ins;
    }

    public Capstone.CsInsn getInstruction(){
        return instruction;
    }

    public void setContiner(byte[] in){
        this.container = in;
    }

    @Override
    public byte[] getContainer(){
        return container;
    }

    public void setByteOrder(ByteOrder in){
        this.order = in;
    }

    @Override
    public ByteOrder getByteOrder() {
        return order;
    }

    @Override
    public IContainer flipByteOrder() {
        return null;
    }

    @Override
    public abstract AbstractText clone();

    @Override
    public void accept(AbstractStructureVisitor visitor) {
        if(visitor.preVisit())
            visitor.visit(this);
        visitor.postVisit();
        for(IStructure child : getChildren()){
            child.accept(visitor);
        }
    }

    @Override
    public IStructure getParent() {
        return parent;
    }

    @Override
    public LinkedList<IStructure> getChildren() {
        return children;
    }

    @Override
    public AbstractAddress getBeginAddress() {
        return beginAddress;
    }

    @Override
    public AbstractAddress getEndAddress() {
        return endAddress;
    }

    @Override
    public void setBeginAddress(AbstractAddress in){
        this.beginAddress = in;
    }

    @Override
    public void setEndAddress(AbstractAddress in){
        this.endAddress = in;
    }

    @Override
    public void setComments(String... comment) {
        this.comment = comment;
    }

    @Override
    public String[] getComment() {
        return comment;
    }

    @Override
    public int compareTo(IAddressable o) {
        if(o == null)
            return 0;

        return this.beginAddress.compareTo(o.getBeginAddress());
    }
}
