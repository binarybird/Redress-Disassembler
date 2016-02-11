package abi.generic.memory;

import java.nio.ByteOrder;

/**
 * Created by jamesrichardson on 2/11/16.
 * Addresses are always big endian in my world
 */
public abstract class Address extends Container {
    public Address(int bytes){
        super(bytes,ByteOrder.BIG_ENDIAN);
    }

    public boolean increment(int amount){
        boolean ret = false;
        if(BYTEORDER == ByteOrder.LITTLE_ENDIAN){
            ret = incrementRecursively(amount,0);
        }else {
            ret = incrementRecursively(amount,BYTES-1);
        }

        return ret;
    }

    private boolean incrementRecursively(int amount,int pointer){
        if(pointer >= BYTES || pointer < 0)
            return false;

        if(BYTEORDER == ByteOrder.LITTLE_ENDIAN){

            if(container[pointer] != 0xff){

                int room = 0xff - container[pointer];
                if(amount > room){
                    int res = amount - room;
                    container[pointer] = (byte)0xff;
                    incrementRecursively((byte)res,pointer++);
                }else if(amount <= room){
                    container[pointer]+=amount;
                    return true;
                }


                return true;
            }else{
                incrementRecursively(amount,pointer++);
            }
        }else{
            if(container[pointer] != 0xff){

                int room = 0xff - container[pointer];
                if(amount > room){
                    int res = amount - room;
                    container[pointer] = (byte)0xff;
                    incrementRecursively((byte)res,pointer--);
                }else if(amount <= room){
                    container[pointer]+=amount;
                    return true;
                }

            }else{
                incrementRecursively(amount,pointer--);
            }
        }
        return false;
    }

    public boolean decrement(int amount){
        boolean ret = false;


        return ret;
    }
    public boolean jump(Address amount){
        return false;
    }
}
