package redress.abi.generic.visitors;

import redress.abi.mach.Loader;
import redress.memory.data.*;

/**
 * Created by jamesrichardson on 3/3/16.
 */
public abstract class AbstractContainerVisitor implements IVisitor{
    public boolean preVisit(){return true;}
    public void postVisit(){}
    public void visit(Word in){}
    public void visit(DWord in){}
    public void visit(QWord in){}
    public void visit(Text in){}
    public void visit(Range in){}
    public void visit(Loader.char16 in){}
}
