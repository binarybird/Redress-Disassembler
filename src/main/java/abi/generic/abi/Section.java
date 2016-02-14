package abi.generic.abi;

import abi.generic.memory.Addressable;

/**
 * Created by jamesrichardson on 2/10/16.
 */
public abstract class Section extends Addressable {
    private Command parentCommand;
    public void setParentCommand(Command in){this.parentCommand=in;}
    public Command getParentCommand(){return parentCommand;}
//    private final Segment parentSegment;
//
//    public Section(Segment parent){
//        this.parentSegment = parent;
//    }
}
