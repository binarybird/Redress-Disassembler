package redress.abi.mach.parse;


import org.apache.commons.io.IOUtils;
import redress.memory.address.Address64;
import redress.memory.data.DWord;
import redress.abi.mach.Loader;
import redress.abi.mach.Mach;
import redress.abi.mach.MachO32;
import redress.abi.mach.MachO64;
import redress.abi.mach.parse.x86.MachParser32;
import redress.abi.mach.parse.x86_64.MachParser64;
import redress.memory.data.AbstractData;
import redress.util.B;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
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

        final FileInputStream fis = new FileInputStream(in);

        return Read(fis);
    }

    public static Mach Read(final InputStream inputStream) throws Exception{

        LOGGER.log(Level.INFO,"Reading binary");

        final byte[] binary = IOUtils.toByteArray(inputStream);

        return getMach(binary);
    }

    private static Mach getMach(byte[] binary) throws Exception {
        final DWord dWordAtAddress = B.getDWordAtAddress(binary, new Address64("0x0000000000000000"), null, AbstractData.Type.DATA_BYTE, ByteOrder.LITTLE_ENDIAN);

        if(dWordAtAddress == null)
            return null;

        Mach ret = null;

        if(Loader.MH_MAGIC_64.equals(dWordAtAddress) || Loader.MH_CIGAM_64.equals(dWordAtAddress)){
            ret = new MachO64(binary);
            MachParser64.parse((MachO64) ret);
        } else if(Loader.MH_MAGIC.equals(dWordAtAddress) || Loader.MH_CIGAM.equals(dWordAtAddress)){
            ret = new MachO32(binary);
            MachParser32.parse((MachO32) ret);
        }

        return ret;
    }
}
