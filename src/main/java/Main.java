import abi.mach.Mach;
import abi.mach.parse.Reader;
import gui.MainController;
import javafx.application.Application;
import javafx.scene.Scene;
import javafx.scene.layout.Pane;
import javafx.stage.Stage;

import java.io.File;
import java.util.logging.Level;
import java.util.logging.Logger;

public class Main extends Application {
    private final static Logger LOGGER = Logger.getLogger(Main.class.getName());
    public static void main(String[] args){
        LOGGER.log(Level.INFO,"Starting Disassemble...");
        Application.launch(args);
    }

    @Override
    public void start(Stage primaryStage) {
        final Scene scene = new Scene(MainController.getSharedMainController());
        primaryStage.setScene(scene);
        primaryStage.show();
        MainController.getSharedMainController().setPrimaryStage(primaryStage);
    }
}
