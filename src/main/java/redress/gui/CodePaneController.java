package redress.gui;

import javafx.beans.property.SimpleStringProperty;
import redress.abi.generic.IContainer;
import redress.memory.data.AbstractData;
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
    private final TableColumn<DisplaySet,String> dataTypeColumn = new TableColumn<>("DataType");
    private final TableColumn<DisplaySet,String> codeColumn = new TableColumn<>("Code");
    private final TableColumn<DisplaySet,String> commentColumn = new TableColumn<>("Comment");

    public CodePaneController(){
        this.widthProperty().addListener(c->{
            final double w = this.getWidth();
            addressColumn.setPrefWidth(w/4);
            dataTypeColumn.setPrefWidth(w/4);
            codeColumn.setPrefWidth(w/4);
            commentColumn.setPrefWidth(w / 4);
        });
        addressColumn.setCellValueFactory(new PropertyValueFactory<DisplaySet, String>("address"));
        dataTypeColumn.setCellValueFactory(new PropertyValueFactory<DisplaySet, String>("informationType"));
        codeColumn.setCellValueFactory(new PropertyValueFactory<DisplaySet, String>("text"));
        commentColumn.setCellValueFactory(new PropertyValueFactory<DisplaySet,String>("comment"));

        this.setRowFactory(tableView -> {
            TableRow<DisplaySet> row = new TableRow<>();
            row.itemProperty().addListener((obs, prev, cur) -> {
                if (cur != null && AbstractData.Type.valueOf(cur.getInformationType()) == AbstractData.Type.COMMENT) {
                    row.setStyle("-fx-background-color: yellowgreen;");
                    return;
                }
                row.setStyle("");
            });
            return row;
        });


        this.getColumns().addAll(addressColumn,dataTypeColumn, codeColumn, commentColumn);
    }

    public void set(LinkedList<IContainer> in){
        final List<DisplaySet> tmp = new LinkedList<>();
        in.forEach(e-> tmp.add(new DisplaySet(e)));
        final ObservableList<DisplaySet> wrapped = FXCollections.<DisplaySet>observableList(tmp);
        this.setItems(wrapped);
    }

    public class DisplaySet implements Comparable<AbstractData>{
        private final SimpleStringProperty address;
        private final SimpleStringProperty text;
        private final SimpleStringProperty comment;
        private final SimpleStringProperty informationType;
        private final IContainer data;

        //TODO - add color ivar to Data
        public DisplaySet(IContainer in){
            if(in instanceof AbstractData) {
                if(((AbstractData) in).getDataType() == AbstractData.Type.COMMENT) {
                    String one = "";
                    String two = "";
                    String three = "";

                    if(((AbstractData) in).getComment().length != 3) {
                        this.comment = new SimpleStringProperty("Comment length for spacer must 4");
                        this.address = new SimpleStringProperty("");
                        this.text = new SimpleStringProperty("");
                        this.informationType = new SimpleStringProperty(((AbstractData) in).getDataType().toString());
                    }
                    else {
                        this.comment = new SimpleStringProperty(((AbstractData) in).getComment()[2]);
                        this.address = new SimpleStringProperty(((AbstractData) in).getComment()[0]);
                        this.text = new SimpleStringProperty(((AbstractData) in).getComment()[1]);
                        this.informationType = new SimpleStringProperty(((AbstractData) in).getDataType().toString());
                    }
                }else{
                    this.address = new SimpleStringProperty(((AbstractData) in).getBeginAddress().toString());
                    this.text = new SimpleStringProperty(in.toString());
                    String s = "";
                    if(((AbstractData) in).getComment() != null && ((AbstractData) in).getComment()[0] != null)
                        s = ((AbstractData) in).getComment()[0];
                    this.comment = new SimpleStringProperty(s);
                    this.informationType = new SimpleStringProperty(((AbstractData) in).getDataType().toString());
                }
            }else{
                this.address = new SimpleStringProperty("");
                this.text = new SimpleStringProperty(in.toString());
                this.comment = new SimpleStringProperty("");
                this.informationType = new SimpleStringProperty("");
            }
            this.data = in;
        }

        public String getAddress(){return address.get();}
        public void setAddress(String in){address.set(in);}

        public String getText(){return text.get();}
        public void setText(String in){text.set(in);}

        public String getComment(){return comment.get();}
        public void setComment(String in){comment.set(in);}

        public String getInformationType(){
            return informationType.get();
        }
        public void setInformationType(String type){
            this.informationType.set(type);
        }

        public IContainer getData(){
            return data;
        }


        @Override
        public int compareTo(AbstractData o) {

            if(o == null || o.getBeginAddress() == null)
                return 0;

            if(o.getDataType() == AbstractData.Type.COMMENT)
                return 0;

            if(this.getData() instanceof AbstractData)
                return ((AbstractData)this.getData()).getBeginAddress().compareTo(o.getBeginAddress());
            else return 0;
        }
    }
}
