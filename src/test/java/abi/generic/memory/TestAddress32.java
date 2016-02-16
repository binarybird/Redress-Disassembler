package abi.generic.memory;

import abi.generic.memory.data.DWord;

import java.nio.ByteOrder;

/**
 * Created by jamesrichardson on 2/12/16.
 */
public class TestAddress32 {

    public static void main(String argv[]) {
        testIncrement();
    }

    private static void testIncrement(){
        DWord testOne = new DWord("0x000000ff",ByteOrder.BIG_ENDIAN);
        testOne.add(new DWord("0x000000ff", ByteOrder.BIG_ENDIAN));
        if(!testOne.equals(new DWord("0x000001FE",ByteOrder.BIG_ENDIAN))){
            System.out.println("ERROR");
        }

        DWord testTwo = new DWord("0x000000ff",ByteOrder.BIG_ENDIAN);
        testTwo.add(new DWord("0xff000000", ByteOrder.LITTLE_ENDIAN));
        if(!testTwo.equals(new DWord("0x000001FE",ByteOrder.BIG_ENDIAN))){
            System.out.println("ERROR");
        }

        DWord testThree = new DWord("0xff000000",ByteOrder.LITTLE_ENDIAN);
        testThree.add(new DWord("0x000000ff", ByteOrder.BIG_ENDIAN));
        if(!testThree.equals(new DWord("0xFE010000",ByteOrder.LITTLE_ENDIAN))){
            System.out.println("ERROR");
        }

        DWord testFour = new DWord("0xff000000",ByteOrder.LITTLE_ENDIAN);
        testFour.add(new DWord("0xff000000", ByteOrder.LITTLE_ENDIAN));
        if(!testFour.equals(new DWord("0xFE010000",ByteOrder.LITTLE_ENDIAN))){
            System.out.println("ERROR");
        }

        System.out.println();
    }
}
