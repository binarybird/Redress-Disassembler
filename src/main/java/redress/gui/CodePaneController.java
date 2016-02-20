package redress.gui;

import javafx.beans.property.SimpleStringProperty;
import redress.memory.data.Data;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.scene.control.TableColumn;
import javafx.scene.control.TableRow;
import javafx.scene.control.TableView;
import javafx.scene.control.cell.PropertyValueFactory;

import java.util.*;
import java.util.logging.Logger;

/**
 * Created by jamesrichardson on 2/16/16.
 */
public class CodePaneController extends TableView<CodePaneController.DisplaySet> {
    private final static Logger LOGGER = Logger.getLogger(CodePaneController.class.getName());
    private final TableColumn<DisplaySet,String> addressColumn = new TableColumn<>("Address");
    private final TableColumn<DisplaySet,String> codeColumn = new TableColumn<>("Code");
    private final TableColumn<DisplaySet,String> commentColumn = new TableColumn<>("Comment");

    public CodePaneController(){
        this.widthProperty().addListener(c->{
            final double w = this.getWidth();
            addressColumn.setPrefWidth(w/4);
            codeColumn.setPrefWidth(this.getWidth() / 2);
            commentColumn.setPrefWidth(w / 4);
        });
        addressColumn.setCellValueFactory(new PropertyValueFactory<DisplaySet, String>("address"));
        codeColumn.setCellValueFactory(new PropertyValueFactory<DisplaySet, String>("text"));
        commentColumn.setCellValueFactory(new PropertyValueFactory<DisplaySet,String>("comment"));

        this.setRowFactory(tableView -> {
            TableRow<DisplaySet> row = new TableRow<>();
            row.itemProperty().addListener((obs, prev, cur) -> {
                if (cur != null && Data.Type.valueOf(cur.getInformationType()) == Data.Type.COMMENT) {
                    row.setStyle("-fx-background-color: yellowgreen;");
                    return;
                }
                row.setStyle("");
            });
            return row;
        });


        this.getColumns().addAll(addressColumn, codeColumn, commentColumn);
    }

    public void set(LinkedList<Data> in){
        final List<DisplaySet> tmp = new LinkedList<>();
        in.forEach(e-> tmp.add(new DisplaySet(e)));
        final ObservableList<DisplaySet> wrapped = FXCollections.<DisplaySet>observableList(tmp);
        this.setItems(wrapped);
    }

    public class DisplaySet implements Comparable<Data>{
        private final SimpleStringProperty address;
        private final SimpleStringProperty text;
        private final SimpleStringProperty comment;
        private final SimpleStringProperty informationType;
        private final Data data;

        public DisplaySet(Data in){
            if(in.getDataType() == Data.Type.COMMENT) {
                this.address = new SimpleStringProperty("");
                this.text = new SimpleStringProperty(in.toString());
                this.comment = new SimpleStringProperty(in.getComment());
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
        public void setText(String in){text.set(in);}

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

            if(o.getDataType() == Data.Type.COMMENT)
                return 0;

            return this.getData().getBeginAddress().compareTo(o.getBeginAddress());
        }
    }
}
