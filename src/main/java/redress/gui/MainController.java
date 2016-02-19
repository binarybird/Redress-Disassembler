package redress.gui;

import redress.abi.generic.ABI;
import redress.memory.DataStructure;
import redress.memory.data.Data;
import redress.memory.data.Word;
import javafx.application.Application;
import javafx.beans.property.SimpleBooleanProperty;
import javafx.beans.value.ChangeListener;
import javafx.fxml.FXML;
import javafx.fxml.FXMLLoader;
import javafx.scene.control.MenuBar;
import javafx.scene.image.Image;
import javafx.scene.image.ImageView;
import javafx.scene.layout.AnchorPane;
import javafx.stage.Stage;
import org.dockfx.*;
import org.dockfx.demo.DockFX;

import java.io.IOException;
import java.util.*;
import java.util.logging.Logger;

/**
 * Created by jamesrichardson on 2/15/16.
 */
public class MainController extends AnchorPane {
    public static final String CODEWINDOW_NAME = "Code Window";

    private final static Logger LOGGER = Logger.getLogger(MainController.class.getName());
    private static MainController mainController;
    private static final Image dockImage = new Image(DockFX.class.getResource("docknode.png").toExternalForm());
    private final SimpleBooleanProperty loadedProperty = new SimpleBooleanProperty(false);

    private ABI abi;
    private CodePaneController codePaneController;
    private MenuBarController menuBarController;
    private DockNode codePaneDock;
    private Stage primaryStage;

    @FXML
    private AnchorPane content;
    @FXML
    private MenuBar menuBar;

    public static MainController getSharedMainController(){
        if(mainController == null) {
            mainController = new MainController();
        }
        return mainController;
    }

    private MainController(){
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
    RightPane rp;
    LeftPane lp;
    @FXML
    public void initialize() {
        DockPane dockPane = new DockPane();
        dockPane.prefWidthProperty().bind(content.widthProperty());
        dockPane.prefHeightProperty().bind(content.heightProperty());

        codePaneController= new CodePaneController();
        menuBarController = new MenuBarController(menuBar);

        codePaneDock = new DockNode(codePaneController,CODEWINDOW_NAME,new ImageView(dockImage));
        codePaneDock.setDockTitleBar(null);
        codePaneDock.setPrefSize(300, 100);
        codePaneDock.dock(dockPane, DockPos.BOTTOM);

        rp = new RightPane();
        lp = new LeftPane();

        DockNode lpdn = new DockNode(lp);
        lpdn.setPrefSize(300, 100);
        lpdn.dock(dockPane, DockPos.LEFT);

        DockNode rpdn = new DockNode(rp);
        rpdn.setPrefSize(300, 100);
        rpdn.dock(dockPane, DockPos.RIGHT);

        Application.setUserAgentStylesheet(Application.STYLESHEET_MODENA);
        DockPane.initializeDefaultUserAgentStylesheet();

        content.getChildren().add(dockPane);

    }
    public void registerLoadListener(ChangeListener<? super Boolean> in){
        loadedProperty.addListener(in);
    }

    public boolean isLoaded(){return loadedProperty.get();}
    public Stage getPrimaryStage(){return primaryStage;}
    public void setPrimaryStage(Stage stage){this.primaryStage = stage;}
    public ABI getABI(){return abi;}
    public void setABI(ABI abi){
        this.abi = abi;
        final LinkedList<Data> tableData = new LinkedList<>();

        getAllData(abi).forEach(tableData::add);
        abi.getCompiledTextBlocks().forEach(e->{tableData.addAll(e.deCompileText(abi.getType(),abi.getArch()));});

        this.codePaneController.set(tableData);
        this.loadedProperty.set(true);
    }

    private LinkedList<Data> getAllData(ABI abi){
        final LinkedList<Data> ret = new LinkedList<>();
        for(DataStructure s : abi.getChildren()){
            ret.add(getSeperator(s));
            ret.addAll(getAllData(s));
        }
        return ret;
    }

    private LinkedList<Data> getAllData(DataStructure dataStructure){
        final LinkedList<Data> ret = new LinkedList<>();

        if(dataStructure == null)
            return ret;

        ret.addAll(dataStructure.getStructureData());
        for(DataStructure child : dataStructure.getChildren()){
            ret.add(getSeperator(child));
            ret.addAll(getAllData(child));
        }

        return ret;
    }

    private Data getSeperator(DataStructure ds){
        final Word seperator = new Word();
        seperator.setComment(ds.getComment());
        seperator.setDataType(Data.Type.COMMENT_SEPERATOR);
        return seperator;
    }

    public CodePaneController getCodePaneController(){return codePaneController;}
    public MenuBarController getMenuBarController(){return menuBarController;}

    public class AddrComparator implements Comparator<Data>{
        @Override
        public int compare(Data o1, Data o2) {
            if(o1 == null || o2 == null)
                return 0;
            if(o1.getBeginAddress() == null || o2.getBeginAddress() == null)
                return 0;
            return o1.getBeginAddress().compareTo(o2.getBeginAddress());
        }
    }

}
