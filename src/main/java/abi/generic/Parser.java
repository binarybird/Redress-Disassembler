package abi.generic;

/**
 * Created by jamesrichardson on 2/10/16.
 */
public abstract class Parser<T extends ABI> {

    protected final T model;

    public Parser(T model){
        this.model = model;
    }

    public abstract T getModel();
}
