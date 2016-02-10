package abi.mach;

import abi.generic.*;

import java.util.LinkedList;

/**
 * Created by jamesrichardson on 2/10/16.
 */
public class MachO64 extends ABI implements Mach{

    private static final Arch arch = Arch.SIXTYFOUR;
    private LinkedList<Command> commands = new LinkedList<>();
    private LinkedList<Segment> segments = new LinkedList<>();
    private LinkedList<Section> sections = new LinkedList<>();

    private Loader.mach_header_64 mach_header_64 = new Loader.mach_header_64();

    public MachO64(byte[] binary){
        super(binary);
    }

    @Override
    public byte[] getRaw() {
        return raw;
    }

    @Override
    public Arch getArch() {
        return arch;
    }

    @Override
    public Header getHeader() {
        return mach_header_64;
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
