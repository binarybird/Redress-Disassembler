package abi.mach;

import abi.generic.abi.*;
import abi.generic.memory.data.Data;

import java.util.*;

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
    public ArrayList<Data> getProcessedData() {
        final ArrayList<Data> processedData = new ArrayList<>();

        processedData.addAll(Arrays.asList(mach_header_64.getProcessedData()));
        commands.forEach(e -> processedData.addAll(Arrays.asList(e.getProcessedData())));
        segments.forEach(e -> processedData.addAll(Arrays.asList(e.getProcessedData())));
        sections.forEach(e -> processedData.addAll(Arrays.asList(e.getProcessedData())));

        return processedData;
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
