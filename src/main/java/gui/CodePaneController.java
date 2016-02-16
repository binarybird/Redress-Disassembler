package gui;

import abi.generic.memory.address.Address;
import abi.generic.memory.Container;
import abi.generic.memory.data.Data;
import javafx.beans.property.SimpleStringProperty;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.collections.ObservableSet;
import javafx.scene.control.TableColumn;
import javafx.scene.control.TableView;
import javafx.scene.control.cell.PropertyValueFactory;

import java.util.*;
import java.util.logging.Logger;

/**
 * Created by jamesrichardson on 2/16/16.
 */
public class CodePaneController extends TableView<CodePaneController.CodeSet> {
    private final static Logger LOGGER = Logger.getLogger(CodePaneController.class.getName());
    private final TableColumn<CodeSet,String> addressColumn = new TableColumn<>("Address");
    private final TableColumn<CodeSet,String> codeColumn = new TableColumn<>("Code");
    private final TableColumn<CodeSet,String> commentColumn = new TableColumn<>("Comment");

    public CodePaneController(){
        this.widthProperty().addListener(c->{
            final double w = this.getWidth();
            addressColumn.setPrefWidth(w/4);
            codeColumn.setPrefWidth(this.getWidth() / 2);
            commentColumn.setPrefWidth(w / 4);
        });
        addressColumn.setCellValueFactory(new PropertyValueFactory<CodeSet,String>("address"));
        codeColumn.setCellValueFactory(new PropertyValueFactory<CodeSet,String>("code"));
        commentColumn.setCellValueFactory(new PropertyValueFactory<CodeSet,String>("comment"));

        this.getColumns().addAll(addressColumn,codeColumn,commentColumn);
    }

    public void set(TreeSet<Data> in){

        List<CodeSet> tmp = new LinkedList<>();
        in.forEach(e-> tmp.add(new CodeSet(e)));

        final ObservableList<CodeSet> wrapped = FXCollections.<CodeSet>observableList(tmp);

        this.setItems(wrapped);
    }

    public class CodeSet implements Comparable<Data>{

        private final SimpleStringProperty address;
        private final SimpleStringProperty code;
        private final SimpleStringProperty comment;
        private final Data data;

        public CodeSet(Data in){
            this.address = new SimpleStringProperty(in.getAddress().toString());
            this.code = new SimpleStringProperty(in.toString());
            this.comment = new SimpleStringProperty(in.getComment());
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
            if(o == null || o.getAddress() == null)
                return 0;

            return this.getData().getAddress().compareTo(o.getAddress());
        }
    }

}
