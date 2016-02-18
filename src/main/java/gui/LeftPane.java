package gui;

import abi.generic.ABI;
import abi.memory.address.Address16;
import abi.memory.data.Word;
import capstone.Capstone;
import capstone.X86;
import javafx.fxml.FXML;
import javafx.scene.Scene;
import javafx.scene.control.Button;
import javafx.scene.control.TextArea;
import javafx.scene.layout.AnchorPane;
import javafx.scene.layout.Pane;
import javafx.scene.text.Text;
import javafx.stage.Stage;
import util.B;

import java.nio.ByteOrder;

import static capstone.X86_const.*;
import static capstone.X86_const.X86_AVX_BCAST_INVALID;

/**
 * Created by jamesrichardson on 2/16/16.
 */
public class LeftPane extends Pane {

    @FXML
    public void initialize() {
        this.getChildren().add(new Text("Left Pane Stuff"));
    }

    public void thing(Stage stage){
        AnchorPane popup = new AnchorPane();
        TextArea decodeArea = new TextArea();

        decodeArea.prefWidthProperty().bind(popup.prefWidthProperty());
        popup.prefWidthProperty().addListener((o,w,a)->{
            decodeArea.setPrefWidth(a.doubleValue());
        });
        popup.prefHeightProperty().addListener((o,w,a)->{
            decodeArea.setPrefHeight(a.doubleValue());
        });
        decodeArea.prefHeightProperty().bind(popup.prefHeightProperty());
//
//        Capstone cs = new Capstone(Capstone.CS_ARCH_X86,Capstone.CS_MODE_64);
//        final ABI abi = MainController.getSharedMainController().getABI();
//
//        Address16 start = new Address16("0x0f40");
//        Address16 end = new Address16("0x0f6c");
//
//        final long addr =start.getIntValue();
//
//        byte[] range = B.getRangeAtAddress(abi.getRaw(),start,end);
//
//        System.out.println("START LONG "+addr);
//        System.out.println("START BYTE "+B.bytesToString(B.byteToBytes(abi.getRaw()[(int)addr])));
//
//
//
//        String s = "";
//        for(Capstone.CsInsn i : disasm){
//            s+=i.insnName()+" "+i.mnemonic+" "+i.opStr+"\n";
//            try{print_ins_detail(i);}catch(Exception e){}
//        }
//
//        decodeArea.setText(s);
//        popup.getChildren().add(decodeArea);
//
//        final Scene scene = new Scene(popup);
//        final Stage stage1 = new Stage();
//        stage1.setScene(scene);
//        stage1.show();
//
//        System.out.println();

    }


}
