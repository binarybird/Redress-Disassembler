package redress.abi.generic.visitors;

import redress.abi.generic.*;
import redress.memory.data.*;

/**
 * Created by jamesrichardson on 2/23/16.
 */
public interface IVisitor {

    public boolean preVisit();
    public void postVisit();


}
