package redress.abi.generic;

import redress.abi.generic.visitors.IVisitor;

/**
 * Created by jamesrichardson on 2/24/16.
 */
public interface IVisitable<T extends IVisitor> {

    public void accept(T visitor);
}
