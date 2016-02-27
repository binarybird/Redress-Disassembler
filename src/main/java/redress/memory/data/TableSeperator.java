package redress.memory.data;

/**
 * Created by jamesrichardson on 2/25/16.
 */

import redress.abi.generic.IContainer;

import java.nio.ByteOrder;

/**
 * Created by jamesrichardson on 2/25/16.
 */
public class TableSeperator implements IContainer {
    private final String addressCell,typeCell,codeCell,commentCell,color;

    public TableSeperator(String addressCell,String typeCell,String codeCell,String commentCell,String color){
        this.addressCell = addressCell;
        this.typeCell=typeCell;
        this.codeCell=codeCell;
        this.commentCell=commentCell;
        this.color=color;
    }

    public TableSeperator(String addressCell,String typeCell,String codeCell,String commentCell){
        this(addressCell,typeCell,codeCell,commentCell,"rgba(104, 255, 0, 0.43)");
    }

    public String getAddressCell(){
        return addressCell;
    }

    public String gettypeCell(){
        return typeCell;
    }

    public String getcodeCell(){
        return codeCell;
    }

    public String getcommentCell(){
        return commentCell;
    }

    public String getColor(){
        return color;
    }

    @Override
    public byte[] getContainer() {
        return new byte[0];
    }

    @Override
    public ByteOrder getByteOrder() {
        return ByteOrder.BIG_ENDIAN;
    }

    @Override
    public IContainer flipByteOrder() {
        return null;
    }

    @Override
    public IContainer clone() {
        return null;
    }

    @Override
    public void add(IContainer i) {

    }

    @Override
    public void add(int i) {

    }

    @Override
    public void subtract(IContainer i) {

    }

    @Override
    public void subtract(int i) {

    }
}
