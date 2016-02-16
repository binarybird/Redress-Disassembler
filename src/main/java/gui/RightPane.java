package gui;

import javafx.scene.layout.Pane;
import javafx.scene.text.Text;

/**
 * Created by jamesrichardson on 2/16/16.
 */
public class RightPane extends Pane{
    public RightPane(){
        this.getChildren().add(new Text("Right Pane Stuff"));
    }
}
