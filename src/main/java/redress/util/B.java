package redress.util;

import redress.memory.data.AbstractData;
import redress.abi.generic.IContainer;
import redress.abi.generic.IStructure;
import redress.memory.address.AbstractAddress;
import redress.memory.address.Address32;
import redress.memory.address.Address64;
import redress.memory.data.*;

import javax.xml.bind.DatatypeConverter;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Created by jamesrichardson on 2/10/16.
 *
 * Byte Utils
 */
public final class B {
    private final static Logger LOGGER = Logger.getLogger(B.class.getName());
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

    /*
     Ill do the rest of these someday....
     */
    public static byte[] doubleToBytes(double in,ByteOrder order){
        return ByteBuffer.allocate(Double.BYTES).order(order).putDouble(in).array();
    }

    public static double bytesToDouble(byte[] in,ByteOrder order){
        byte[] tmp = new byte[Double.BYTES];
        Arrays.fill(tmp, (byte)0x0);
        if(order == ByteOrder.BIG_ENDIAN) {
            for (int i = in.length-1; i >= 0; i--) {
                tmp[i] = in[i];
            }
        }else{
            for (int i = 0; i <in.length; i++) {
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
            for (int i = in.length-1; i >= 0; i--) {
                tmp[i] = in[i];
            }
        }else{
            for (int i = 0; i <in.length; i++) {
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

    public static String bytesToHexString(byte[] in){
        return DatatypeConverter.printHexBinary(in);
    }

    public static LinkedList<String> bytesToPrettyHexString(byte[] in){
        LinkedList<String> ret = new LinkedList<>();

        for(int i=0;i<in.length;i++){
            if(i==(in.length-1))
                ret.add("0x"+bytesToHexString(new byte[]{in[i]}));
            else
                ret.add("0x"+bytesToHexString(new byte[]{in[i]})+", ");
        }

        return ret;
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

    public static Address32 dWordToAddr32(DWord begin){
        byte[] tmpBegin;
        if(begin.getByteOrder() == ByteOrder.LITTLE_ENDIAN){
            tmpBegin = begin.flipByteOrder().getContainer();
        }else{
            tmpBegin = begin.getContainer();
        }
        return new Address32(tmpBegin);
    }

    public static Address64 qWordToAddr64(QWord begin){
        byte[] tmpBegin;
        if(begin.getByteOrder() == ByteOrder.LITTLE_ENDIAN){
            tmpBegin = begin.flipByteOrder().getContainer();
        }else{
            tmpBegin = begin.getContainer();
        }
        return new Address64(tmpBegin);
    }

    public static Word getWordAtAddress(final byte[] raw, final AbstractAddress address,IStructure parent, AbstractData.Type type, ByteOrder resultOrder){
        final int addr = bytesToInt(address.getContainer(),address.getByteOrder());

        return new Word(new byte[]{raw[addr],raw[addr+1]},address.clone(),parent,type,resultOrder);
    }

    public static Word getWordAtAddressAndIncrement(final byte[] raw, final AbstractAddress address,IStructure parent, AbstractData.Type type, ByteOrder resultOrder){
        final Word ret = getWordAtAddress(raw,address,parent,type,resultOrder);

        add(ret,Word.SIZEOF_B);

        return ret;
    }

    public static DWord getDWordAtAddress(final byte[] raw, final AbstractAddress address,IStructure parent, AbstractData.Type type, ByteOrder resultOrder){
        final int addr = bytesToInt(address.getContainer(),address.getByteOrder());

        return new DWord(new byte[]{raw[addr],raw[addr+1],raw[addr+2],raw[addr+3]},address.clone(),parent,type,resultOrder);
    }

    public static DWord getDWordAtAddressAndIncrement(final byte[] raw, final AbstractAddress address,IStructure parent, AbstractData.Type type, ByteOrder resultOrder){
        final DWord ret = getDWordAtAddress(raw,address,parent,type,resultOrder);

        add(address, DWord.SIZEOF_B);

        return ret;
    }

    public static QWord getQWordAtAddress(final byte[] raw, final AbstractAddress address,IStructure parent, AbstractData.Type type, ByteOrder resultOrder){
        final int addr = bytesToInt(address.getContainer(),address.getByteOrder());

        return new QWord(new byte[]{raw[addr],raw[addr+1],raw[addr+2],raw[addr+3],raw[addr+4],raw[addr+5],raw[addr+6],raw[addr+7]},address.clone(),parent,type,resultOrder);
    }

    public static QWord getQWordAtAddressAndIncrement(final byte[] raw, final AbstractAddress address,IStructure parent, AbstractData.Type type, ByteOrder resultOrder){
        final QWord ret = getQWordAtAddress(raw,address,parent,type,resultOrder);

        add(address, QWord.SIZEOF_B);

        return ret;
    }

    public static byte[] getRangeAtAddress(final byte[] raw, final AbstractAddress begin, final AbstractAddress end){
        final int beginArrAddr = bytesToInt(begin.getContainer(),begin.getByteOrder());
        final int endArrAddr = bytesToInt(end.getContainer(),begin.getByteOrder());

        final byte[] ret = new byte[endArrAddr-beginArrAddr];

        for(int i=beginArrAddr;i<endArrAddr;i++){
            ret[i-beginArrAddr] = raw[i];
        }

        return ret;
    }
    public static Range getRangeAtAddress(final byte[] raw, IStructure parent, final AbstractAddress begin, final AbstractAddress end, ByteOrder order){
        final byte[] rangeAtAddress = getRangeAtAddress(raw, begin, end);

        return new Range(rangeAtAddress,begin,end,parent,order);
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

    /**
     *
     * @param toMe
     * @param addMe
     * @return Adds argument addMe to argument toMe
     */
    public static IContainer add(IContainer toMe,IContainer addMe){
        //No unsigned values anywhere in java (cept char) - we have to do it the hard way
        IContainer oneContainer;
        IContainer twoContainer;

        //BigInt takes BigEndian only
        if(toMe.getByteOrder() == ByteOrder.LITTLE_ENDIAN){
            oneContainer = toMe.flipByteOrder();
        }else{
            oneContainer = toMe;
        }

        if(addMe.getByteOrder() == ByteOrder.LITTLE_ENDIAN){
            twoContainer = addMe.flipByteOrder();
        }else{
            twoContainer = addMe;
        }


        //Get BigInt
        final BigInteger oneUnsigned = new BigInteger(1,oneContainer.getContainer());
        final BigInteger twoUnsigned = new BigInteger(1,twoContainer.getContainer());

        //Add
        final byte[] res  = oneUnsigned.add(twoUnsigned).toByteArray();


        Arrays.fill(toMe.getContainer(), (byte) 0x00);

        //Restore original endinass
        byte[] tmp;
        if(toMe.getByteOrder() == ByteOrder.LITTLE_ENDIAN){
            tmp = B.flipByteOrder(res);
            //store result
            if(toMe.getContainer().length >= res.length){
                for(int i=0;i<tmp.length;i++){
                    toMe.getContainer()[i] = tmp[i];
                }
            }else{
                for(int i=0;i<toMe.getContainer().length;i++){
                    toMe.getContainer()[i] = tmp[i];
                }
            }
        }else{
            tmp = res;
            //store result
            if(toMe.getContainer().length >= tmp.length){
                int padding = toMe.getContainer().length - tmp.length;
                for(int i=0;i<tmp.length;i++){
                    toMe.getContainer()[padding+i] = tmp[i];
                }
            }else{
                int padding = tmp.length - toMe.getContainer().length;
                for(int i=0;i<toMe.getContainer().length;i++){
                    toMe.getContainer()[i] = tmp[i+padding];
                }
            }
        }
        return toMe;
    }

    /**
     *
     * @param fromMe
     * @param subMe
     * @return Adds argument addMe to argument toMe
     */
    public static IContainer subtract(IContainer fromMe,IContainer subMe){
        //No unsigned values anywhere in java (cept char) - we have to do it the hard way
        IContainer oneContainer;
        IContainer twoContainer;

        //BigInt takes BigEndian only
        if(fromMe.getByteOrder() == ByteOrder.LITTLE_ENDIAN){
            oneContainer = fromMe.flipByteOrder();
        }else{
            oneContainer = fromMe;
        }

        if(subMe.getByteOrder() == ByteOrder.LITTLE_ENDIAN){
            twoContainer = subMe.flipByteOrder();
        }else{
            twoContainer = subMe;
        }


        //Get BigInt
        final BigInteger oneUnsigned = new BigInteger(1,oneContainer.getContainer());
        final BigInteger twoUnsigned = new BigInteger(1,twoContainer.getContainer());

        //Add
        final byte[] res  = oneUnsigned.subtract(twoUnsigned).toByteArray();


        Arrays.fill(fromMe.getContainer(), (byte) 0x00);

        //Restore original endinass
        byte[] tmp;
        if(fromMe.getByteOrder() == ByteOrder.LITTLE_ENDIAN){
            tmp = B.flipByteOrder(res);
            //store result
            if(fromMe.getContainer().length >= res.length){
                for(int i=0;i<tmp.length;i++){
                    fromMe.getContainer()[i] = tmp[i];
                }
            }else{
                for(int i=0;i<fromMe.getContainer().length;i++){
                    fromMe.getContainer()[i] = tmp[i];
                }
            }
        }else{
            tmp = res;
            //store result
            if(fromMe.getContainer().length >= tmp.length){
                int padding = fromMe.getContainer().length - tmp.length;
                for(int i=0;i<tmp.length;i++){
                    fromMe.getContainer()[padding+i] = tmp[i];
                }
            }else{
                int padding = tmp.length - fromMe.getContainer().length;
                for(int i=0;i<fromMe.getContainer().length;i++){
                    fromMe.getContainer()[i] = tmp[i+padding];
                }
            }
        }
        return fromMe;
    }


}
