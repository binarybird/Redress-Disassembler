package redress.abi.generic;

import redress.memory.Addressable;
import redress.memory.struct.DataStructure;
import redress.memory.data.Data;

import java.util.LinkedList;

/**
 * Created by jamesrichardson on 2/10/16.
 */
public abstract class ABI implements Addressable{
    public abstract ABIType getType();
    public abstract ABIArch getArch();
    public abstract LinkedList<DataStructure> getChildren();
    public abstract LinkedList<Data> buildDecompile();
    public abstract byte[] getRaw();

    protected LinkedList<Data> getAllData(){
        final LinkedList<Data> ret = new LinkedList<>();
        for(DataStructure s : getChildren()){
            ret.add(Data.generateCommentContainer(s.getComment()));
            ret.addAll(getAllData(s));
        }
        return ret;
    }

    private LinkedList<Data> getAllData(DataStructure dataStructure){
        final LinkedList<Data> ret = new LinkedList<>();

        if(dataStructure == null)
            return ret;

        ret.addAll(dataStructure.getStructureData());
        for(DataStructure child : dataStructure.getChildren()){
            ret.add(Data.generateCommentContainer(child.getComment()));
            ret.addAll(getAllData(child));
        }

        return ret;
    }
}
