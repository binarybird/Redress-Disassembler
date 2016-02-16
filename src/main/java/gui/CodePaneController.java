package gui;

import abi.generic.memory.address.Address;
import abi.generic.memory.Container;
import javafx.scene.control.TableColumn;
import javafx.scene.control.TableView;

import java.util.logging.Logger;

/**
 * Created by jamesrichardson on 2/16/16.
 */
public class CodePaneController<T> extends TableView<T> {
    private final static Logger LOGGER = Logger.getLogger(CodePaneController.class.getName());
    private final TableColumn<T,Address> addressColumn = new TableColumn<>("Address");
    private final TableColumn<T,Container> codeColumn = new TableColumn<>("Code");
    private final TableColumn<T,String> commentColumn = new TableColumn<>("Comment");

    public CodePaneController(){

        this.widthProperty().addListener(c->{
            final double w = this.getWidth();
            addressColumn.setPrefWidth(w/4);
            codeColumn.setPrefWidth(this.getWidth() / 2);
            commentColumn.setPrefWidth(w / 4);
        });

        this.getColumns().addAll(addressColumn,codeColumn,commentColumn);


    }


}
