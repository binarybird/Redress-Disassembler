package gui;

import abi.memory.data.Data;
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
public class CodePaneController extends TableView<DisplaySet> {
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
                if (cur != null && Data.Type.valueOf(cur.getInformationType()) == Data.Type.COMMENT_STRING) {
                    row.setStyle("-fx-background-color: green;");
                    return;
                }
                if (cur != null && Data.Type.valueOf(cur.getInformationType()) == Data.Type.COMMENT_SEPERATOR) {
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
}
