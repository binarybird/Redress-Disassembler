package redress.abi.generic;

import redress.abi.generic.visitors.AbstractStructureVisitor;
import redress.memory.address.AbstractAddress;

import java.util.LinkedList;

/**
 * Created by jamesrichardson on 2/23/16.
 */
public abstract class AbstractHeader implements IStructure, ILoadable {
    protected final LinkedList<IStructure> children = new LinkedList<>();
    protected final IStructure parent;
    protected AbstractAddress beginAddress;
    protected AbstractAddress endAddress;
    protected String[] comment = new String[0];
    protected ILoader load;

    protected AbstractHeader(IStructure parent) {
        this.parent = parent;
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
    public void setLoader(ILoader loader){
        this.load = loader;
    }

    @Override
    public ILoader getLoader(){
        return this.load;
    }

    @Override
    public int compareTo(IAddressable o) {
        if(o == null)
            return 0;

        return this.beginAddress.compareTo(o.getBeginAddress());
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
}
