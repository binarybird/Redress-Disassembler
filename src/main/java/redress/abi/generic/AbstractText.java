package redress.abi.generic;

import capstone.Capstone;
import redress.abi.generic.visitors.AbstractContainerVisitor;
import redress.abi.generic.visitors.AbstractStructureVisitor;
import redress.memory.address.AbstractAddress;
import redress.memory.data.AbstractData;
import redress.memory.data.QWord;
import redress.util.B;

import java.nio.ByteOrder;
import java.util.HashSet;
import java.util.LinkedList;

/**
 * Created by jamesrichardson on 2/23/16.
 */
public abstract class AbstractText implements IContainer {

    protected final LinkedList<IStructure> children = new LinkedList<>();
    protected final IStructure parent;
    protected IContainer previousSibling;
    protected IContainer nextSibling;
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

    public void setNextSibling(IContainer c){
        this.nextSibling = c;
    }

    @Override
    public IContainer getNextSibling() {
        return nextSibling;
    }

    public void setPreviousSibling(IContainer c){
        this.previousSibling = c;
    }

    @Override
    public IContainer getPreviousSibling() {
        return previousSibling;
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

    public void add(IContainer in){
        B.add(this, in);
    }

    public void add(int i){
        QWord w = new QWord(B.intToBytes(i,ByteOrder.BIG_ENDIAN), AbstractData.Type.DATA_NULL,ByteOrder.BIG_ENDIAN);
        add(w);
    }

    public void subtract(IContainer in){
        B.subtract(this,in);
    }

    public void subtract(int i){
        QWord w = new QWord(B.intToBytes(i,ByteOrder.BIG_ENDIAN), AbstractData.Type.DATA_NULL,ByteOrder.BIG_ENDIAN);
        subtract(w);
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
    public IStructure getParent() {
        return parent;
    }

    public LinkedList<IStructure> getChildren() {
        return children;
    }

    public AbstractAddress getBeginAddress() {
        return beginAddress;
    }

    public AbstractAddress getEndAddress() {
        return endAddress;
    }

    public void setBeginAddress(AbstractAddress in){
        this.beginAddress = in;
    }

    public void setEndAddress(AbstractAddress in){
        this.endAddress = in;
    }

    public void addComments(String... comment){
        for(String s : comment)
            this.comment.add(s);
    }

    public HashSet<String> getComments(){
        return comment;
    }

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
