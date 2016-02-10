package abi.mach.parse;

import abi.generic.Parser;
import abi.mach.Loader;
import abi.mach.MachO32;
import abi.mach.MachO64;
import util.ByteUtils;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.ByteOrder;

/**
 * Created by jamesrichardson on 2/10/16.
 */
public class Reader {

    private Reader(){}

    public static Parser Read(final File in) throws IOException,ArithmeticException{

        long fileLengthInBytes = -1;
        if(in.exists()){
            fileLengthInBytes = in.length();
        }

        if(fileLengthInBytes == -1)
            throw new IOException("Unable to get binary size.");

        final byte[] binary = new byte[java.lang.Math.toIntExact(fileLengthInBytes)];

        final FileInputStream fis = new FileInputStream(in);
        fis.read(binary);

        final byte[] init = {(byte)0x00};
        final byte[] dWordAtAddress = ByteUtils.getDWordAtAddress(binary, init);

        if(dWordAtAddress == null)
            return null;

        if(ByteUtils.equals(Loader.MH_MAGIC_64,dWordAtAddress) || ByteUtils.equals(Loader.MH_CIGAM_64,dWordAtAddress)){
            return new MachParser64(new MachO64(binary));
        } else if(ByteUtils.equals(Loader.MH_MAGIC,dWordAtAddress) || ByteUtils.equals(Loader.MH_CIGAM,dWordAtAddress)){
            return new MachParser32(new MachO32(binary));
        }

        return null;
    }

}
