package org.example;

public class FileAccessControl {

    static {
        System.loadLibrary("FileAccessControlNative"); // Загрузка библиотеки
    }

    // Нативные методы
    public native boolean blockAccess();
    public native boolean allowAccess();
    public native boolean unblockSpecific(String path);
}
