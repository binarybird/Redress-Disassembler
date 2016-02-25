package redress.abi.generic;

import capstone.Capstone;
import redress.abi.generic.visitors.AbstractStructureVisitor;
import redress.memory.address.AbstractAddress;
import redress.memory.data.AbstractData;

import java.nio.ByteOrder;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;

/**
 * Created by jamesrichardson on 2/23/16.
 */
public abstract class AbstractText implements IStructure, IContainer {

    protected final LinkedList<IStructure> children = new LinkedList<>();
    protected final IStructure parent;
    protected AbstractAddress beginAddress;
    protected AbstractAddress endAddress;
    protected final HashSet<String> comment = new HashSet<>();
    protected final Capstone.CsInsn instruction;
    protected byte[] container;
    protected ByteOrder order;
    protected final String instructionStringValue;
    protected String segment = "";
    protected String section = "";

    public AbstractText(IStructure parent,AbstractAddress begin,AbstractAddress end,byte[] content,Capstone.CsInsn ins,String builtInstruction) {
        this.parent = parent;
        this.instruction = ins;
        this.beginAddress = begin;
        this.endAddress = end;
        this.container = new byte[content.length];
        for(int i=0;i<content.length;i++)
            this.container[i] = content[i];
        this.instructionStringValue = builtInstruction;
    }

    public AbstractData.Type getDataType(){
        return AbstractData.Type.TEXT_DECOMPILED;
    }

    public Capstone.CsInsn getInstruction(){
        return instruction;
    }

    public void setSegmentName(String in){
        this.segment = in;
    }
    public String getSegmentName(){
        return segment;
    }
    public void setSectionName(String in){
        this.section = in;
    }
    public String getSectionName(){
        return section;
    }

    public void setContiner(byte[] in){
        this.container = in;
    }

    @Override
    public byte[] getContainer(){
        return container;
    }

    public void setByteOrder(ByteOrder in){
        this.order = in;
    }

    @Override
    public ByteOrder getByteOrder() {
        return order;
    }

    @Override
    public IContainer flipByteOrder() {
        return null;
    }

    @Override
    public abstract AbstractText clone();

    @Override
    public void accept(AbstractStructureVisitor visitor) {
        if(visitor.preVisit())
            visitor.visit(this);
        visitor.postVisit();
        for(IStructure child : getChildren()){
            child.accept(visitor);
        }
    }

    @Override
    public IStructure getParent() {
        return parent;
    }

    @Override
    public LinkedList<IStructure> getChildren() {
        return children;
    }

    @Override
    public AbstractAddress getBeginAddress() {
        return beginAddress;
    }

    @Override
    public AbstractAddress getEndAddress() {
        return endAddress;
    }

    @Override
    public void setBeginAddress(AbstractAddress in){
        this.beginAddress = in;
    }

    @Override
    public void setEndAddress(AbstractAddress in){
        this.endAddress = in;
    }

    @Override
    public void addComments(String... comment){
        for(String s : comment)
            this.comment.add(s);
    }

    @Override
    public HashSet<String> getComments(){
        return comment;
    }

    @Override
    public int compareTo(IAddressable o) {
        if(o == null)
            return 0;

        return this.beginAddress.compareTo(o.getBeginAddress());
    }

    @Override
    public String toString(){
        return this.instructionStringValue;
    }
}
