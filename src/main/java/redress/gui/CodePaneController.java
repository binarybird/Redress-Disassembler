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
import redress.memory.data.Text;
import redress.memory.data.view.TableSeperator;

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
            addressColumn.setPrefWidth(w/6);
            dataTypeColumn.setPrefWidth(w/6);
            codeColumn.setPrefWidth(w/6);
            commentColumn.setPrefWidth(w / 2);
        });
        addressColumn.setCellValueFactory(new PropertyValueFactory<>("address"));
        dataTypeColumn.setCellValueFactory(new PropertyValueFactory<>("informationType"));
        codeColumn.setCellValueFactory(new PropertyValueFactory<>("text"));
        commentColumn.setCellValueFactory(new PropertyValueFactory<>("comment"));

        this.setRowFactory(tableView -> {
            TableRow<DisplaySet> row = new TableRow<>();
            row.itemProperty().addListener((obs, prev, cur) -> {
                row.setStyle("");
                if (cur == null)
                    return;
                if(cur.getData() instanceof TableSeperator){
                    row.setStyle("-fx-background-color: "+((TableSeperator)cur.getData()).getColor());
                }
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

        public DisplaySet(IContainer in){
            if(in instanceof AbstractData) {
                this.address = new SimpleStringProperty(((AbstractData) in).getBeginAddress().toString());
                this.text = new SimpleStringProperty(in.toString());
                this.comment = new SimpleStringProperty(generateCommentString(((AbstractData) in).getComments()));
                this.informationType = new SimpleStringProperty(((AbstractData) in).getDataType().toString());
            }else if(in instanceof TableSeperator) {
                this.address = new SimpleStringProperty(((TableSeperator) in).getAddressCell());
                this.text = new SimpleStringProperty(((TableSeperator) in).getcodeCell());
                this.comment = new SimpleStringProperty(((TableSeperator) in).getcommentCell());
                this.informationType = new SimpleStringProperty(((TableSeperator) in).gettypeCell());
            }else if(in instanceof Text) {
                this.address = new SimpleStringProperty(((Text) in).getBeginAddress().toString());
                this.text = new SimpleStringProperty(in.toString());
                this.comment = new SimpleStringProperty(generateCommentString(((Text) in).getComments()));
                this.informationType = new SimpleStringProperty(((Text) in).getDataType().toString());
            }else{
                this.address = new SimpleStringProperty("");
                this.text = new SimpleStringProperty(in.toString());
                this.comment = new SimpleStringProperty("");
                this.informationType = new SimpleStringProperty("");
            }
            this.data = in;
        }

        private String generateCommentString(HashSet<String> in){
            if(in == null)
                return "";
            String ret = "";
            for(String s : in){
                ret+=s+"\n";
            }
            return ret;
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
