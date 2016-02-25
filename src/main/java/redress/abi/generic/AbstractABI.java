package redress.abi.generic;

import redress.abi.generic.enums.ABIArch;
import redress.abi.generic.enums.ABIType;
import redress.abi.generic.visitors.AbstractStructureVisitor;
import redress.memory.address.AbstractAddress;


import java.util.HashSet;
import java.util.LinkedList;

/**
 * Created by jamesrichardson on 2/10/16.
 */
public abstract class AbstractABI implements IStructure{

    protected AbstractABI(byte[] raw) {
        this.raw=raw;
    }

    public abstract ABIType getType();
    public abstract ABIArch getArch();

    protected final byte[] raw;
    protected final LinkedList<IStructure> children = new LinkedList<>();
    protected final IStructure parent = null;
    protected AbstractAddress beginAddress;
    protected AbstractAddress endAddress;
    protected final HashSet<String> comment = new HashSet<>();
    public byte[] getRaw(){return raw;}

    public AbstractSegment getSegment(String name){
        for(IStructure s : getChildren()){
            if(s instanceof AbstractSegment && ((AbstractSegment) s).getName().equals(name)){
                return (AbstractSegment)s;
            }
        }
        return null;
    }

    @Override
    public int compareTo(IAddressable o) {
        if(o == null)
            return 0;

        return this.beginAddress.compareTo(o.getBeginAddress());
    }

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
    public void addComments(String... comment) {
        for(String s:comment)
            this.comment.add(s);
    }

    @Override
    public HashSet<String> getComments() {
        return comment;
    }
}
