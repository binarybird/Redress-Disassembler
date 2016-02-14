import abi.mach.parse.Reader;

import java.io.File;
import java.util.logging.Level;
import java.util.logging.Logger;

public class Main {
    private final static Logger LOGGER = Logger.getLogger(Main.class.getName());

    public static void main(String[] args){
        LOGGER.log(Level.INFO,"Starting Disassemble...");
        File in =new File("/Users/james/Desktop/reverse/a.out");

        try {
            Reader.Read(in);
        }catch(Exception e){
            e.printStackTrace();
        }
    }
}
