package redress.abi.generic.visitors;

import redress.abi.generic.*;

import java.util.LinkedList;

/**
 * Created by jamesrichardson on 2/24/16.
 */
public class DataCollectVisitor extends AbstractStructureVisitor {
    private final LinkedList<IContainer> allData = new LinkedList<>();

    @Override
    public boolean preVisit(){
        return true;
    }

    @Override
    public void postVisit() {

    }

    @Override
    public void visit(AbstractSegment in){
        if(in.getStructureData() != null) {
            allData.addAll(in.getStructureData());
        }
    }
    @Override
    public void visit(AbstractSection in){
        if(in.getStructureData() != null) {
            allData.addAll(in.getStructureData());
        }
    }
    @Override
    public void visit(AbstractLoadCommand in){
        if(in.getStructureData() != null) {
            allData.addAll(in.getStructureData());
        }
    }
    @Override
    public void visit(AbstractHeader in){
        if(in.getStructureData() != null) {
            allData.addAll(in.getStructureData());
        }
    }
    @Override
    public void visit(AbstractABI in){
        if(in.getStructureData() != null) {
            allData.addAll(in.getStructureData());
        }
    }

    @Override
    public void visit(AbstractTable in){
        if(in.getStructureData() != null) {
            allData.addAll(in.getStructureData());
        }
    }
    public LinkedList<IContainer> getData(){
        return allData;
    }
}
