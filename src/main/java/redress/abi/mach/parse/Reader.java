package redress.abi.mach.parse;


import redress.memory.address.Address64;
import redress.memory.data.DWord;
import redress.abi.mach.Loader;
import redress.abi.mach.Mach;
import redress.abi.mach.MachO32;
import redress.abi.mach.MachO64;
import redress.abi.mach.parse.x86.MachParser32;
import redress.abi.mach.parse.x86_64.MachParser64;
import redress.memory.data.Data;
import redress.util.B;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.ByteOrder;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Created by jamesrichardson on 2/10/16.
 */
public class Reader {

    private final static Logger LOGGER = Logger.getLogger(Reader.class.getName());

    private Reader(){}

    public static Mach Read(final File in) throws Exception{

        long fileLengthInBytes = -1;
        if(in.exists()){
            fileLengthInBytes = in.length();
        }

        if(fileLengthInBytes == -1){
            LOGGER.log(Level.SEVERE,"Unable to get size of binary!");
            throw new IOException("Unable to get binary size.");
        }

        final byte[] binary = new byte[java.lang.Math.toIntExact(fileLengthInBytes)];

        LOGGER.log(Level.INFO,"Reading binary: {0}, size: {1}bytes",new Object[] {in.getAbsolutePath(),fileLengthInBytes});

        final FileInputStream fis = new FileInputStream(in);
        fis.read(binary);

        final DWord dWordAtAddress = B.getDWordAtAddress(binary, new Address64("0x0000000000000000"), Data.Type.DATA_BYTE, ByteOrder.LITTLE_ENDIAN);

        if(dWordAtAddress == null)
            return null;

        Mach ret = null;

        if(Loader.MH_MAGIC_64.equals(dWordAtAddress) || Loader.MH_CIGAM_64.equals(dWordAtAddress)){
            ret = new MachO64(binary);
            MachParser64.parse((MachO64)ret);
        } else if(Loader.MH_MAGIC.equals(dWordAtAddress) || Loader.MH_CIGAM.equals(dWordAtAddress)){
            ret = new MachO32(binary);
            MachParser32.parse((MachO32)ret);
        }

        return ret;
    }
}
