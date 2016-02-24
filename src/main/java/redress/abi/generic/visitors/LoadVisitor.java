package redress.abi.generic.visitors;

import redress.abi.generic.*;

import java.util.LinkedList;

/**
 * Created by jamesrichardson on 2/24/16.
 */
public class LoadVisitor extends AbstractStructureVisitor  {

    private final AbstractABI abi;
    private final LinkedList<IContainer> loadedContents = new LinkedList<>();

    public LoadVisitor(AbstractABI abi){
        this.abi=abi;
    }

    @Override
    public boolean preVisit(){
        return true;
    }

    @Override
    public void postVisit() {

    }

    public LinkedList<IContainer> getData(){
        return loadedContents;
    }

    @Override
    public void visit(AbstractSegment in){
        final ILoader loader = in.getLoader();
        if(loader != null) {
            loadedContents.addAll(loader.load(abi));
        }
    }

    @Override
    public void visit(AbstractSection in){
        final ILoader loader = in.getLoader();
        if(loader != null) {
            loadedContents.addAll(loader.load(abi));
        }
    }

    @Override
    public void visit(AbstractLoadCommand in){
        final ILoader loader = in.getLoader();
        if(loader != null) {
            loadedContents.addAll(loader.load(abi));
        }
    }

    @Override
    public void visit(AbstractHeader in){
        final ILoader loader = in.getLoader();
        if(loader != null) {
            loadedContents.addAll(loader.load(abi));
        }
    }

}
