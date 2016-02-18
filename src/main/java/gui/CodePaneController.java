package gui;

import abi.memory.data.CompiledText;
import abi.memory.data.Data;
import abi.memory.data.DataRange;
import javafx.beans.property.SimpleStringProperty;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.scene.control.TableColumn;
import javafx.scene.control.TableView;
import javafx.scene.control.cell.PropertyValueFactory;

import java.util.*;
import java.util.logging.Logger;

/**
 * Created by jamesrichardson on 2/16/16.
 */
public class CodePaneController extends TableView<CodeSet> {
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

    public void set(TreeSet<Data> in,LinkedList<CompiledText> in2){

        List<CodeSet> tmp = new LinkedList<>();
        in.forEach(e-> tmp.add(new CodeSet(e)));

        in2.forEach(e->{tmp.addAll(e.deCompileText());});

        final ObservableList<CodeSet> wrapped = FXCollections.<CodeSet>observableList(tmp);

        this.setItems(wrapped);
    }

    public CodeSet initCodeSet(String address,String code,String comment,DataRange in){
        return new CodeSet(address,code,comment,in);
    }



}
