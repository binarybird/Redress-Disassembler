package gui;

import abi.memory.data.Data;
import abi.memory.data.DataRange;
import javafx.beans.property.SimpleStringProperty;

/**
 * Created by jamesrichardson on 2/18/16.
 */
public class CodeSet implements Comparable<Data>{

    private final SimpleStringProperty address;
    private final SimpleStringProperty code;
    private final SimpleStringProperty comment;
    private final Data data;

    public CodeSet(Data in){
        this.address = new SimpleStringProperty(in.getBeginAddress().toString());
        this.code = new SimpleStringProperty(in.toString());
        this.comment = new SimpleStringProperty(in.getComment());
        this.data=in;
    }

    public CodeSet(String address,String code,String comment,DataRange in){
        this.address = new SimpleStringProperty(address);
        this.code = new SimpleStringProperty(code);
        this.comment = new SimpleStringProperty(comment);
        this.data=in;
    }

    public String getAddress(){return address.get();}
    public void setAddress(String in){address.set(in);}
    public String getCode(){return code.get();}
    public void setCode(String in){code.set(in);}
    public String getComment(){return comment.get();}
    public void setComment(String in){comment.set(in);}

    public Data getData(){
        return data;
    }

    @Override
    public int compareTo(Data o) {
        if(o == null || o.getBeginAddress() == null)
            return 0;

        return this.getData().getBeginAddress().compareTo(o.getBeginAddress());
    }
}
