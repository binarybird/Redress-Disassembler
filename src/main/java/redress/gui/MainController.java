package redress.gui;

import redress.abi.generic.AbstractABI;
import redress.abi.generic.IContainer;
import redress.abi.generic.visitors.LoadVisitor;
import redress.memory.data.AbstractData;
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
import redress.abi.generic.visitors.DataCollectVisitor;

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

    private final SimpleBooleanProperty loadedProperty = new SimpleBooleanProperty(false);

    private RightPane rp;
    private LeftPane lp;
    private AbstractABI abi;
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

    @FXML
    public void initialize() {
        DockPane dockPane = new DockPane();
        dockPane.prefWidthProperty().bind(content.widthProperty());
        dockPane.prefHeightProperty().bind(content.heightProperty());

        codePaneController= new CodePaneController();
        menuBarController = new MenuBarController(menuBar);

        codePaneDock = new DockNode(codePaneController,CODEWINDOW_NAME);
        codePaneDock.setDockTitleBar(null);
        codePaneDock.setPrefSize(300, 100);
        codePaneDock.dock(dockPane, DockPos.BOTTOM);


        lp = new LeftPane();

        lp.getDockNode().dock(dockPane, DockPos.LEFT);
//        dockPane.widthProperty().addListener((o,w,a)->{System.out.println("DockPane: "+a);});
//        lp.widthProperty().addListener((o,w,a)->{System.out.println("LeftPane : "+a);});
//        lp.getDockNode().widthProperty().addListener((o,w,a)->{System.out.println("DockNode: "+a);});

        rp = new RightPane();
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
    public AbstractABI getABI(){return abi;}
    public void setABI(AbstractABI abi){
        this.abi = abi;

        final LinkedList<IContainer> tableData = new LinkedList<>();
        final DataCollectVisitor v = new DataCollectVisitor();
        final LoadVisitor lv = new LoadVisitor(abi);

        abi.accept(v);
        tableData.addAll(v.getData());

        abi.accept(lv);
        tableData.addAll(lv.getData());

        this.codePaneController.set(tableData);
        this.loadedProperty.set(true);
    }

    public CodePaneController getCodePaneController(){return codePaneController;}

    public MenuBarController getMenuBarController(){return menuBarController;}

    public class AddrComparator implements Comparator<AbstractData>{
        @Override
        public int compare(AbstractData o1, AbstractData o2) {
            if(o1 == null || o2 == null)
                return 0;
            if(o1.getBeginAddress() == null || o2.getBeginAddress() == null)
                return 0;
            return o1.getBeginAddress().compareTo(o2.getBeginAddress());
        }
    }
}
