package redress.memory.data;

import capstone.Capstone;
import redress.abi.generic.*;

import java.util.LinkedList;

/**
 * Created by jamesrichardson on 2/23/16.
 */
public class Text extends AbstractText {
    final Range range;

    public Text(Range range, Capstone.CsInsn ins, String builtInstruction) {
        super(range.parent, range.getBeginAddress(), range.getEndAddress(), range.container, ins, builtInstruction);
        this.range = range;
    }

    @Override
    public LinkedList<IContainer> getStructureData() {
        return new LinkedList<>();
    }

    @Override
    public AbstractText clone() {
        return new Text(range,instruction,instructionStringValue);
    }

}
