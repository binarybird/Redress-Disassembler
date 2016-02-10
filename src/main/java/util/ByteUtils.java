package util;

import javax.xml.bind.DatatypeConverter;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

/**
 * Created by jamesrichardson on 2/10/16.
 */
public class ByteUtils {
    private static ByteBuffer buffer = ByteBuffer.allocate(Long.BYTES);

    public static byte[] longToBytes(long x) {
        buffer.putLong(0, x);
        return buffer.array();
    }

    // Underflow issue
//    public static long bytesToLong(byte[] bytes) {
//        buffer.put(bytes, 0, bytes.length);
//        buffer.flip();//need flip
//        return buffer.getLong();
//    }

    public static long bytesToLong(byte[] bytes,ByteOrder byteOrder){
        long value = 0;

        if(byteOrder == ByteOrder.LITTLE_ENDIAN) {
            for (int i = 0; i < bytes.length; i++) {
                value += ((long) bytes[i] & 0xffL) << (8 * i);
            }
        }else{
            for (int i = 0; i < bytes.length; i++)
            {
                value = (value << 8) + (bytes[i] & 0xff);
            }
        }

        return value;
    }

    public static int longToInt(long in){
        return java.lang.Math.toIntExact(in);
    }

    public static boolean equals(final byte[] one,final byte[] two){

        if(one.length != two.length)
            return false;

        for(int i=0;i<one.length;i++){
            if(one[i] != two[i])
                return false;
        }

        return true;
    }

    public static byte[] stringToBytes(String in){
        return DatatypeConverter.parseHexBinary(in);
    }

    public static String bytesToString(byte[] in){
        return DatatypeConverter.printHexBinary(in);
    }

    public static byte[] getWordAtAddress(final byte[] raw,final byte[] address){

        final byte[] ret = new byte[2];
        final int addr = longToInt(bytesToLong(address,ByteOrder.BIG_ENDIAN));

        ret[0] = raw[addr];
        ret[1] = raw[addr+1];

        return ret;
    }

    public static byte[] getDWordAtAddress(final byte[] raw, final byte[] address){

        final byte[] ret = new byte[4];
        final int addr = longToInt(bytesToLong(address,ByteOrder.BIG_ENDIAN));

        ret[0] = raw[addr];
        ret[1] = raw[addr+1];
        ret[2] = raw[addr+2];
        ret[3] = raw[addr+3];

        return ret;
    }

    public static byte[] getQWordAtAddress(final byte[] raw,final byte[] address){

        final byte[] ret = new byte[8];
        final int addr = longToInt(bytesToLong(address,ByteOrder.BIG_ENDIAN));

        ret[0] = raw[addr];
        ret[1] = raw[addr+1];
        ret[2] = raw[addr+2];
        ret[3] = raw[addr+3];
        ret[4] = raw[addr+4];
        ret[5] = raw[addr+5];
        ret[6] = raw[addr+6];
        ret[7] = raw[addr+7];

        return ret;
    }


}
