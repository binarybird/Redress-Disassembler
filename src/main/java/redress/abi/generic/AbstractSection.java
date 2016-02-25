package redress.abi.generic;

import redress.abi.generic.visitors.AbstractStructureVisitor;
import redress.memory.address.AbstractAddress;

import java.util.HashSet;
import java.util.LinkedList;

/**
 * Created by jamesrichardson on 2/23/16.
 */
public abstract class AbstractSection implements IStructure, ILoadable  {

    protected final LinkedList<IStructure> children = new LinkedList<>();
    protected final IStructure parent;
    protected AbstractAddress beginAddress;
    protected AbstractAddress endAddress;
    protected String name = "";
    protected final HashSet<String> comment = new HashSet<>();
    protected ILoader load;

    protected AbstractSection(IStructure parent) {
        this.parent = parent;
    }

    public String getName(){return this.name;}

    public void setName(String name){this.name=name;}

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
    public void addComments(String... comment){
        for(String s : comment)
            this.comment.add(s);
    }

    @Override
    public HashSet<String> getComments(){
        return comment;
    }
}
