package abi.mach;

import abi.generic.abi.*;

import java.util.LinkedList;

/**
 * Created by jamesrichardson on 2/10/16.
 */
public class MachO64 extends Mach{

    private static final ABIType ABI_TYPE = ABIType.MACH_64;
    private LinkedList<Command> commands = new LinkedList<>();
    private LinkedList<Segment> segments = new LinkedList<>();
    private LinkedList<Section> sections = new LinkedList<>();

    private Loader.mach_header_64 mach_header_64 = null;

    public MachO64(byte[] binary){
        super(binary);
    }

    @Override
    public byte[] getRaw() {
        return raw;
    }

    @Override
    public ABIType getArch() {
        return ABI_TYPE;
    }

    @Override
    public Loader.mach_header_64 getHeader() {
        return mach_header_64;
    }

    public void setHeader(Loader.mach_header_64 in){
        this.mach_header_64 = in;
    }

    @Override
    public LinkedList<Command> getCommands() {
        return commands;
    }

    @Override
    public LinkedList<Segment> getSegments() {
        return segments;
    }

    @Override
    public LinkedList<Section> getSections() {
        return sections;
    }

}
