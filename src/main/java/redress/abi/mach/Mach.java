package redress.abi.mach;


import redress.abi.generic.AbstractABI;
import redress.memory.data.DWord;
import redress.memory.data.AbstractData;

import java.nio.ByteOrder;

/**
 * Created by jamesrichardson on 2/10/16.
 */
public abstract class Mach extends AbstractABI {
    public static final DWord MACH_ID_32 = new DWord("0xfeedface", AbstractData.Type.DATA_BYTE,ByteOrder.BIG_ENDIAN);
    public static final DWord MACH_DI_32 = new DWord("0xcefaedfe", AbstractData.Type.DATA_BYTE,ByteOrder.BIG_ENDIAN);
    public static final DWord MACH_ID_64 = new DWord("0xfeedfacf", AbstractData.Type.DATA_BYTE,ByteOrder.BIG_ENDIAN);
    public static final DWord MACH_DI_64 = new DWord("0xcffaedfe", AbstractData.Type.DATA_BYTE,ByteOrder.BIG_ENDIAN);


    public Mach(byte[] raw) {
        super(raw);
    }
}
