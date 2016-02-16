package gui;

import abi.generic.abi.ABI;
import abi.mach.Mach;
import abi.mach.parse.Reader;
import javafx.scene.control.Menu;
import javafx.scene.control.MenuBar;
import javafx.scene.control.MenuItem;
import javafx.scene.input.KeyCombination;
import javafx.stage.FileChooser;

import java.io.File;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Created by jamesrichardson on 2/16/16.
 */
public class MenuBarController {
    private final static Logger LOGGER = Logger.getLogger(MenuBarController.class.getName());

    public static final String MENU_FILE = "File";
    public static final String MENU_EDIT = "Edit";
    public static final String MENU_HELP = "Help";
    public static final String MENU_WINDOW = "Window";
    public static final String OPEN = "Open...";
    public static final String SAVE = "Save...";
    public static final String PREFERENCES = "Preferences...";
    public static final String QUIT = "Quit";
    public static final String DELETE = "Delete";
    public static final String CODEWINDOW = "Code Window";
    public static final String LEFTWINDOW = "Left Pane";
    public static final String RIGHTWINDOW = "Right Pane";
    public static final String ABOUT = "About" ;

    private final MenuBar menuBar;
    private final Menu fileMenu = new Menu(MENU_FILE);
    private final Menu editMenu = new Menu(MENU_EDIT);
    private final Menu helpMenu = new Menu(MENU_HELP);
    private final Menu windowMenu = new Menu(MENU_WINDOW);
    private final MenuItem openMenuItem = new MenuItem(OPEN);
    private final MenuItem saveMenuItem = new MenuItem(SAVE);
    private final MenuItem preferencesMenuItem = new MenuItem(PREFERENCES);
    private final MenuItem quitMenuItem = new MenuItem(QUIT);
    private final MenuItem deleteMenuItem = new MenuItem(DELETE);
    private final MenuItem codeWindowMenuItem = new MenuItem(CODEWINDOW);
    private final MenuItem leftWindowMenuItem = new MenuItem(LEFTWINDOW);
    private final MenuItem rightWindowMenuItem = new MenuItem(RIGHTWINDOW);
    private final MenuItem aboutMenuItem = new MenuItem(ABOUT);

    public MenuBarController(MenuBar in){
        this.menuBar=in;

        initFileMenu();
        initEditMenu();
        initWindowMenu();
        initHelpMenu();

        fileMenu.getItems().addAll(openMenuItem,saveMenuItem,preferencesMenuItem,quitMenuItem);
        editMenu.getItems().addAll(deleteMenuItem);
        windowMenu.getItems().addAll(codeWindowMenuItem,leftWindowMenuItem,rightWindowMenuItem);
        helpMenu.getItems().addAll(aboutMenuItem);
        menuBar.getMenus().addAll(fileMenu,editMenu,windowMenu,helpMenu);
    }

    private void initFileMenu(){
        openMenuItem.setAccelerator(KeyCombination.keyCombination(KeyCombination.META_DOWN+"+o"));
        openMenuItem.setOnAction((ae)->{
            FileChooser fileChooser = new FileChooser();
            fileChooser.setTitle("Open Binary");


            fileChooser.setInitialDirectory(new File(System.getProperty("user.home")));
            File toOpen = fileChooser.showOpenDialog(MainController.getSharedMainController().getPrimaryStage());

            if(toOpen == null)
                return;

            ABI read = null;
            try {
                read = Reader.Read(new File("/Users/jamesrichardson/Desktop/reverse/a.out"));
            }catch(Exception e){
                e.printStackTrace();
            }

            if(read == null)
                return;

            MainController.getSharedMainController().setABI(read);
        });
    }
    private void initEditMenu(){

    }
    private void initWindowMenu(){

    }
    private void initHelpMenu(){

    }


}
