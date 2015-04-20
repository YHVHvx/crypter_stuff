package net.c0fe.experiments.reflection;

import java.io.*;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.MalformedURLException;

/**
 * User: kostapc
 */

public class CryptByteCodeLoader extends ClassLoader {

    private String fullClassName;
    private byte[] classByteCode;

    public CryptByteCodeLoader(String inFullClassName, byte[] inClassByteCode) {
        fullClassName = inFullClassName;
        classByteCode = inClassByteCode;
    }

    @Override
    public Class<?> loadClass(String name) throws ClassNotFoundException {
        if(!name.equals(fullClassName)) {
            return findSystemClass(name);
        }
        return defineClass(name, classByteCode, 0, classByteCode.length);
    }

}
