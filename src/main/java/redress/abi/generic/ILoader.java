package redress.abi.generic;


import java.util.LinkedList;

/**
 * Created by jamesrichardson on 2/23/16.
 */
public interface ILoader {
    public LinkedList<IContainer> load(AbstractABI in);
}
