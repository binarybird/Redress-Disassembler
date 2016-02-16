package util;

import abi.generic.memory.*;
import abi.generic.memory.address.Address;
import abi.generic.memory.data.DWord;
import abi.generic.memory.data.QWord;
import abi.generic.memory.data.Word;

import javax.xml.bind.DatatypeConverter;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;

/**
 * Created by jamesrichardson on 2/10/16.
 *
 * Byte Utils
 */
public final class B {

    private B(){}

    /**
     * Wraps a single byte in to a byte[]
     * @param b byte to be wrapped
     * @return byte array containing byte b
     */
    public static byte[] byteToBytes(byte b){
        final byte[] bytes = {b};
        return bytes;
    }

    /**
     * Transform an in to an unsigned byte[] array
     * @param in integer to be wrapped
     * @param order resulting byte order to be returned
     * @return byte array containing the ints value
     */
    public static byte[] intToBytes(int in,ByteOrder order){
        return ByteBuffer.allocate(Integer.BYTES).order(order).putInt(in).array();
    }

    /**
     * Byte array to int. Assumes unsigned integer in the byte array
     * @param in byte array to be transformed
     * @param order byte order the array is in
     * @return integer
     */
    public static int bytesToInt(byte [] in,ByteOrder order){

        byte[] tmp;
        if(order == ByteOrder.LITTLE_ENDIAN) {
            tmp = in;
        }else{
            tmp = flipByteOrder(in);
        }
        int ret = 0;
        for(int i=0;i<tmp.length;i++){
            ret |= (tmp[i] & 0xFF) << (i*8);
        }
        return ret;
    }

    public static byte[] doubleToBytes(double in,ByteOrder order){
        return ByteBuffer.allocate(Double.BYTES).order(order).putDouble(in).array();
    }

    public static double bytesToDouble(byte[] in,ByteOrder order){
        byte[] tmp = new byte[Double.BYTES];
        Arrays.fill(tmp, (byte)0x0);
        if(order == ByteOrder.BIG_ENDIAN) {
            for (int i = tmp.length-1; i >= 0; i--) {
                tmp[i] = in[i];
            }
        }else{
            for (int i = 0; i <tmp.length; i++) {
                tmp[i] = in[i];
            }
        }
        return ByteBuffer.wrap(tmp).getDouble();
    }

    public static byte[] longToBytes(long in,ByteOrder order){
        return ByteBuffer.allocate(Long.BYTES).order(order).putDouble(in).array();
    }

    public static long bytesToLong(byte[] in,ByteOrder order){
        byte[] tmp = new byte[Long.BYTES];
        Arrays.fill(tmp, (byte)0x0);
        if(order == ByteOrder.BIG_ENDIAN) {
            for (int i = tmp.length-1; i >= 0; i--) {
                tmp[i] = in[i];
            }
        }else{
            for (int i = 0; i <tmp.length; i++) {
                tmp[i] = in[i];
            }
        }
        return ByteBuffer.wrap(tmp).getLong();
    }

    public static int longToInt(long in){
        return java.lang.Math.toIntExact(in);
    }

    public static byte[] stringToBytes(String in){
        return DatatypeConverter.parseHexBinary(in.replaceAll("0x",""));
    }

    public static String bytesToString(byte[] in){
        return DatatypeConverter.printHexBinary(in);
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

    public static boolean equalsIgnoreLength(final byte[] one,final byte[] two){
        if(one.length <= two.length){
            for(int i=0;i<one.length;i++){
                if(one[i] != two[i])
                    return false;
            }
        }else{
            for(int i=0;i<two.length;i++){
                if(one[i] != two[i])
                    return false;
            }
        }
        return true;
    }

    public static Word getWordAtAddress(final byte[] raw, final Address address, ByteOrder resultOrder){
        final int addr = bytesToInt(address.getContainer(),address.BYTEORDER);

        return new Word(raw[addr],raw[addr+1],address.clone(),resultOrder);
    }

    public static Word getWordAtAddressAndIncrement(final byte[] raw, final Address address, ByteOrder resultOrder){
        final Word ret = getWordAtAddress(raw,address,resultOrder);

        address.add(Word.SIZEOF_B);

        return ret;
    }

    public static DWord getDWordAtAddress(final byte[] raw, final Address address, ByteOrder resultOrder){
        final int addr = bytesToInt(address.getContainer(),address.BYTEORDER);

        return new DWord(raw[addr],raw[addr+1],raw[addr+2],raw[addr+3],address.clone(),resultOrder);
    }

    public static DWord getDWordAtAddressAndIncrement(final byte[] raw, final Address address, ByteOrder resultOrder){
        final DWord ret = getDWordAtAddress(raw,address,resultOrder);

        address.add(DWord.SIZEOF_B);

        return ret;
    }

    public static QWord getQWordAtAddress(final byte[] raw, final Address address, ByteOrder resultOrder){
        final int addr = bytesToInt(address.getContainer(),address.BYTEORDER);

        return new QWord(raw[addr],raw[addr+1],raw[addr+2],raw[addr+3],raw[addr+4],raw[addr+5],raw[addr+6],raw[addr+7],address.clone(),resultOrder);
    }

    public static QWord getQWordAtAddressAndIncrement(final byte[] raw, final Address address, ByteOrder resultOrder){
        final QWord ret = getQWordAtAddress(raw,address,resultOrder);

        address.add(QWord.SIZEOF_B);

        return ret;
    }

    public static byte[] getRangeAtAddress(final byte[] raw, final Address begin, final Address end){
        final int beginArrAddr = bytesToInt(begin.getContainer(),begin.BYTEORDER);
        final int endArrAddr = bytesToInt(end.getContainer(),begin.BYTEORDER);

        final byte[] ret = new byte[endArrAddr-beginArrAddr];

        for(int i=beginArrAddr;i<endArrAddr;i++){
            ret[i-beginArrAddr] = raw[i];
        }

        return ret;
    }

    public static byte[] mergeBytes(byte[] first, byte[] last){
        byte[] join = new byte[first.length+last.length];
        for(int i=0;i<first.length;i++){
            join[i]=first[i];
        }
        for(int i=first.length;i<join.length;i++){
            join[i]=last[i-first.length];
        }
        return join;
    }

    public static byte[] flipByteOrder(byte[] in){
        byte[] ret = new byte[in.length];
        Arrays.fill(ret,(byte)0x00);

        for(int i=0;i<in.length;i++){
            ret[i]=in[(in.length-1)-i];
        }

        return ret;
    }

    public static <T extends Address> T getEndAddressFromOffset(T beginning, Container offset){

        final T ret = (T)beginning.clone();

        if(offset.BYTEORDER == ByteOrder.LITTLE_ENDIAN) {
            ret.add(offset.flipByteOrder());
        }else{
            ret.add(offset);
        }

        return ret;
    }

//    public static byte[] getWordAtAddress(final byte[] raw,final byte[] address){
//
//        final byte[] ret = new byte[2];
//        final int addr = longToInt(bytesToLong(address,ByteOrder.BIG_ENDIAN));
//
//        ret[0] = raw[addr];
//        ret[1] = raw[addr+1];
//
//        return ret;
//    }
//
//    public static byte[] getDWordAtAddress(final byte[] raw, final byte[] address){
//
//        final byte[] ret = new byte[4];
//        final int addr = longToInt(bytesToLong(address,ByteOrder.BIG_ENDIAN));
//
//        ret[0] = raw[addr];
//        ret[1] = raw[addr+1];
//        ret[2] = raw[addr+2];
//        ret[3] = raw[addr+3];
//
//        return ret;
//    }
//
//
//    public static byte[] getQWordAtAddress(final byte[] raw,final byte[] address){
//
//        final byte[] ret = new byte[8];
//        final int addr = longToInt(bytesToLong(address,ByteOrder.BIG_ENDIAN));
//
//        ret[0] = raw[addr];
//        ret[1] = raw[addr+1];
//        ret[2] = raw[addr+2];
//        ret[3] = raw[addr+3];
//        ret[4] = raw[addr+4];
//        ret[5] = raw[addr+5];
//        ret[6] = raw[addr+6];
//        ret[7] = raw[addr+7];
//
//        return ret;
//    }
}
