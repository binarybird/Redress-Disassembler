package redress.memory.data;

import capstone.Capstone;
import redress.abi.generic.*;
import redress.memory.address.AbstractAddress;

import java.nio.ByteOrder;
import java.util.LinkedList;

/**
 * Created by jamesrichardson on 2/23/16.
 */
public class Text extends AbstractText {

    protected Text(IStructure parent, AbstractAddress endAddress, AbstractAddress beginAddress, Capstone.CsInsn ins) {
        super(parent,ins);
        this.beginAddress=beginAddress;
        this.endAddress=endAddress;
    }

    @Override
    public LinkedList<IContainer> getStructureData() {
        return null;
    }

    @Override
    public AbstractText clone() {
        return null;
    }

}
