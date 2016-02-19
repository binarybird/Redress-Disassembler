package gui;

import abi.memory.data.Data;
import javafx.beans.property.SimpleStringProperty;

/**
 * Created by jamesrichardson on 2/18/16.
 */
public class DisplaySet implements Comparable<Data>{

    private final SimpleStringProperty address;
    private final SimpleStringProperty text;
    private final SimpleStringProperty comment;
    private final SimpleStringProperty informationType;
    private final Data data;

    public DisplaySet(Data in){
        if(in.getDataType() == Data.Type.COMMENT_STRING) {
            this.address = new SimpleStringProperty(in.getComment());
            this.text = new SimpleStringProperty(in.toString());
            this.comment = new SimpleStringProperty("");
        }else if(in.getDataType() == Data.Type.COMMENT_SEPERATOR) {
            this.address = new SimpleStringProperty("");
            this.text = new SimpleStringProperty(in.getComment());
            this.comment = new SimpleStringProperty("");
        }else{
            this.address = new SimpleStringProperty(in.getBeginAddress().toString());
            this.text = new SimpleStringProperty(in.toString());
            this.comment = new SimpleStringProperty(in.getComment());
        }
        this.data=in;
        this.informationType = new SimpleStringProperty(in.getDataType().toString());
    }

    public String getAddress(){return address.get();}
    public void setAddress(String in){address.set(in);}

    public String getText(){return text.get();}
    public void setText(String in){
        text.set(in);}

    public String getComment(){return comment.get();}
    public void setComment(String in){comment.set(in);}

    public Data getData(){
        return data;
    }
    public String getInformationType(){
        return informationType.get();
    }

    @Override
    public int compareTo(Data o) {

        if(o == null || o.getBeginAddress() == null)
            return 0;

        if(o.getDataType() == Data.Type.COMMENT_STRING)
            return 0;

        return this.getData().getBeginAddress().compareTo(o.getBeginAddress());
    }
}
