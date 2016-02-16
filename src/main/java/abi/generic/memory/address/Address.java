package abi.generic.memory.address;

import abi.generic.memory.Container;

import java.nio.ByteOrder;

/**
 * Created by jamesrichardson on 2/11/16.
 * Addresses are always big endian in my world
 */
public abstract class Address extends Container{
    public Address(int bytes){
        super(bytes,ByteOrder.BIG_ENDIAN);
    }

    @Override
    public abstract Address clone();
}
