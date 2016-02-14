package abi.generic.abi;

import abi.generic.memory.Addressable;

import java.util.LinkedList;

/**
 * Created by jamesrichardson on 2/10/16.
 */
public abstract class Command extends Addressable {

    private final LinkedList<Section> sections = new LinkedList<>();
    public LinkedList<Section> getSections(){return sections;}


}
