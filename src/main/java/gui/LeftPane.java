package gui;

import javafx.scene.layout.Pane;
import javafx.scene.text.Text;

/**
 * Created by jamesrichardson on 2/16/16.
 */
public class LeftPane extends Pane {
    public LeftPane(){
        this.getChildren().add(new Text("Left Pane Stuff"));
    }
}
