package redress.abi.generic;


import redress.memory.data.DWord;
import redress.abi.mach.Mach;
import redress.memory.data.Data;

import java.io.File;
import java.io.FileInputStream;
import java.nio.ByteOrder;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Created by jamesrichardson on 2/18/16.
 */
public final class Reader {
    private final static Logger LOGGER = Logger.getLogger(Reader.class.getName());

    public static ABI Read(File in) throws Exception {

        final FileInputStream fis = new FileInputStream(in);
        final byte[] id = new byte[4];
        fis.read(id);
        final DWord binID = new DWord(id, Data.Type.DATA_BYTE,ByteOrder.LITTLE_ENDIAN);

        if(binID.equals(Mach.MACH_DI_32) || binID.equals(Mach.MACH_ID_32) ||
           binID.equals(Mach.MACH_DI_64) || binID.equals(Mach.MACH_ID_64)){
            return redress.abi.mach.parse.Reader.Read(in);
        }

        LOGGER.log(Level.SEVERE,"Unable to parse ADI: Unknown ABI");

        return null;
    }
}
