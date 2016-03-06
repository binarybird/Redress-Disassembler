package redress.abi.generic.visitors;

import redress.abi.generic.*;

/**
 * Created by jamesrichardson on 2/24/16.
 */
public abstract class AbstractStructureVisitor implements IVisitor{

    public boolean preVisit(){return true;}
    public void postVisit(){}
    public void visit(AbstractSegment in){}
    public void visit(AbstractSection in){}
    public void visit(AbstractLoadCommand in){}
    public void visit(AbstractHeader in){}
    public void visit(AbstractABI in){}
    public void visit(AbstractText in){}
    public void visit(AbstractTable in){}


}
