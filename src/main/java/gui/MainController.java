package gui;

import abi.generic.abi.ABI;
import javafx.application.Application;
import javafx.fxml.FXML;
import javafx.fxml.FXMLLoader;
import javafx.scene.control.TableColumn;
import javafx.scene.control.TableView;
import javafx.scene.image.Image;
import javafx.scene.image.ImageView;
import javafx.scene.layout.AnchorPane;
import javafx.scene.layout.Pane;
import org.dockfx.*;
import org.dockfx.demo.DockFX;

import java.io.IOException;

/**
 * Created by jamesrichardson on 2/15/16.
 */
public class MainController extends AnchorPane {
    private ABI abi;
    @FXML
    private AnchorPane content;


    public MainController(ABI abi){
        this.abi = abi;
        FXMLLoader fxmlLoader = new FXMLLoader(getClass().getResource("MainController.fxml"));
        fxmlLoader.setRoot(this);
        fxmlLoader.setController(this);
        try {
            fxmlLoader.load();
        } catch (IOException exception) {
            //noinspection ProhibitedExceptionThrown
            throw new RuntimeException(exception);
        }
    }

    @FXML
    public void initialize() {
        DockPane dockPane = new DockPane();
        dockPane.prefWidthProperty().bind(content.widthProperty());
        dockPane.prefHeightProperty().bind(content.heightProperty());
        final Image dockImage = new Image(DockFX.class.getResource("docknode.png").toExternalForm());

        TableView<String> tableView = new TableView<String>();
        tableView.getColumns().addAll(new TableColumn<String, String>("A"), new TableColumn<String, String>("B"), new TableColumn<String, String>("C"));

        Pane paneLeft = new Pane();
        paneLeft.setStyle("fx-background-color:blue;");

        Pane paneRight = new Pane();
        paneRight.setStyle("fx-background-color:red;");

        DockNode tableDock = new DockNode(tableView,"MAIN",new ImageView(dockImage));
        tableDock.setDockTitleBar(null);
        tableDock.setPrefSize(300, 100);
        tableDock.dock(dockPane, DockPos.BOTTOM);

        DockNode paneLeftDoc = new DockNode(paneLeft,"LEFT",new ImageView(dockImage));
        paneLeftDoc.setPrefSize(300, 100);
        paneLeftDoc.dock(dockPane, DockPos.LEFT);

        DockNode paneRightDoc = new DockNode(paneRight,"RIGHT",new ImageView(dockImage));
        paneRightDoc.setPrefSize(300, 100);
        paneRightDoc.dock(dockPane, DockPos.RIGHT);

        Application.setUserAgentStylesheet(Application.STYLESHEET_MODENA);
        DockPane.initializeDefaultUserAgentStylesheet();

        content.getChildren().add(dockPane);
    }
}
