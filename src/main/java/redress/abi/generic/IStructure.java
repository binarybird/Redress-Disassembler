package redress.abi.generic;

import redress.abi.generic.visitors.AbstractStructureVisitor;

import java.util.LinkedList;

/**
 * Created by jamesrichardson on 2/10/16.
 *
 * This is a super class for all data structures in ABIs
 * eg. Segments, Sections, Versions, Load Commands, etc..
 * See redress.abi.mach.Loader
 *
 */
public interface IStructure extends IAddressable, IVisitable<AbstractStructureVisitor>{
    public IStructure getParent();
    public LinkedList<IStructure> getChildren();
    public LinkedList<IContainer> getStructureData();
}
