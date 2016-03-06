package redress.gui;

import javafx.fxml.FXML;
import javafx.scene.control.ListView;
import javafx.scene.control.TextArea;
import javafx.scene.layout.AnchorPane;
import javafx.scene.layout.Pane;
import javafx.scene.text.Text;
import javafx.stage.Stage;
import org.dockfx.DockNode;
import org.dockfx.DockPos;

/**
 * Created by jamesrichardson on 2/16/16.
 */
public class LeftPane extends Pane {

    private final DockNode dockNode;
    private final ListView<String> stringsView;

    public LeftPane(){
        dockNode = new DockNode(this);
        dockNode.setPrefSize(300, 100);

        stringsView = new ListView<>();
        stringsView.prefWidthProperty().bind(dockNode.prefWidthProperty());
        stringsView.layoutYProperty().bind(dockNode.prefHeightProperty().divide(2));
        stringsView.setPrefHeight(200);
        stringsView.getItems().addAll("Test","ewfwefwefewfewfwefewfwefwef");

//        stringsView.widthProperty().addListener((o,w,a)->{System.out.println("StringsView: "+a);});
//        dockNode.prefWidthProperty().addListener((o,w,a)->{System.out.println("DockNode: "+a);});

        this.getChildren().addAll(new Text("Left Pane Stuff"),stringsView);
    }
    public DockNode getDockNode(){
        return dockNode;
    }

}
