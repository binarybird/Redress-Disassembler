package redress.abi.generic.visitors;

import redress.abi.generic.*;
import redress.memory.data.*;

/**
 * Created by jamesrichardson on 2/23/16.
 */
public interface IVisitor {

    public boolean preVisit();
    public void postVisit();
    public void visit(AbstractSegment in);
    public void visit(AbstractSection in);
    public void visit(AbstractLoadCommand in);
    public void visit(AbstractHeader in);
    public void visit(AbstractABI in);
    public void visit(AbstractText in);
    public void visit(AbstractTable in);

}
