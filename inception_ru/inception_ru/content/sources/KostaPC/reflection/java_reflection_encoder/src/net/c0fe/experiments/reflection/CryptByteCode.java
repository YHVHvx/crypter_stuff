package net.c0fe.experiments.reflection;

import net.c0fe.tools.Base64Coder;
import org.apache.bcel.classfile.ClassParser;
import org.apache.bcel.classfile.JavaClass;

import java.io.*;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

/**
 * User: kostapc
 */

public class CryptByteCode {
    public static final String charset = "UTF-8";

    public static final String encExt = ".claxx";
    public static final String nrmExt = ".class";
    //public static final String folder = "data/";
    //public static final String packageName = "net.c0fe.experiments.reflection.sample";

    public static byte[] readFileBinary(String fileName)throws IOException{
        File file = new File(fileName);
        return readFileBinary(file);
    }

    public static byte[] readFileBinary(File file) throws IOException{
        byte[] buffer = new byte[(int) file.length()];
        InputStream inputStream = null;
        try {
            inputStream = new FileInputStream(file);
            if (inputStream.read(buffer) == -1) {
                throw new IOException("EOF reached while trying to read the whole file");
            }
        } finally {
            try {
                if (inputStream != null)
                    inputStream.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
        return buffer;
    }

    public static void writeFileBinary(String filename, byte[] data) {
        FileOutputStream fop = null;
        File file;
        try {
            file = new File(filename);
            fop = new FileOutputStream(file);
            if (!file.exists()) {
                file.createNewFile();
            }
            fop.write(data);
            fop.flush();
            fop.close();
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            try {
                if (fop != null) {
                    fop.close();
                }
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    public byte[] encryptData(byte[] source) {
        char[] result = Base64Coder.encode(source);
        String stringData = new String(result);
        try {
            return stringData.getBytes(charset);
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        return null;
    }

    public byte[] decryptData(byte[] source) {
        String stringData = new String(source);
        byte[] result = Base64Coder.decode(stringData.toCharArray());
        return result;
    }


    public static void main(String[] argc) {
        if(argc.length==0) {
            System.out.println("give me file! (in first arg)");
            System.exit(0);
        }
        String file = argc[0];
        System.out.println("FILE: "+file);
        String folder = getFolder(argc[0]);
        System.out.println("folder: "+file);

        if(argc[0].endsWith(nrmExt)) {
            try {
                String className = getClassName(file);
                System.out.println("class name: "+className);
                ClassParser parser = new ClassParser(file);
                JavaClass clazzDesc = parser.parse();
                String packageName = clazzDesc.getPackageName();
                byte[] byteCode = readFileBinary(file);
                byteCode = mergeData(packageName, className, byteCode);
                CryptByteCode crypter = new CryptByteCode();
                byte[] encoded = crypter.encryptData(byteCode);
                if(encoded!=null) {
                    writeFileBinary(folder+className+encExt, encoded);
                }
            } catch (IOException ex) {
                System.out.println("class file reading problems: " + ex.getMessage());
                ex.printStackTrace();
                System.exit(0);
            }
        } else if(argc[0].endsWith(encExt)) {
            try {
                byte[] fileData = CryptByteCode.readFileBinary(file);
                if(fileData==null) {
                    throw new FileNotFoundException();
                }
                CryptByteCode encoder = new CryptByteCode();
                byte[] decodedFile = encoder.decryptData(fileData);
                DataInputStream in = new DataInputStream(new ByteArrayInputStream(decodedFile));

                String packageName = readStringByLenght(in);
                String className = readStringByLenght(in);

                int codeSize = in.readInt();
                byte[] classData = new byte[codeSize];
                in.read(classData);

                System.out.println("class name: "+className);
                System.out.println("package name: "+packageName);
                className = packageName+"."+"Print5Digits";
                System.out.println("full name: "+className);

                CryptByteCodeLoader loader = new CryptByteCodeLoader(className,classData);
                Class aClass = loader.loadClass(className);
                @SuppressWarnings("unchecked")
                Method main = aClass.getDeclaredMethod("main",String[].class);
                main.invoke(null, ((Object)argc));

            } catch (Exception ex) {
                System.out.println("class file loading problems: " + ex.getMessage());
                ex.printStackTrace();
                System.exit(0);
            }
        }
    }

    private static byte[] mergeData(String packageName, String className, byte[] byteCode) {
        ByteArrayOutputStream byteArrayStream = new ByteArrayOutputStream();
        DataOutputStream out = new DataOutputStream(byteArrayStream);
        try {
            out.writeInt(packageName.length());
            out.write(packageName.getBytes(charset));
            out.writeInt(className.length());
            out.write(className.getBytes(charset));
            out.writeInt(byteCode.length);
            out.write(byteCode);
        } catch (IOException e) {
            e.printStackTrace();
        }
        return byteArrayStream.toByteArray();
    }

    private static String getFolder(String path) {
        int end = path.lastIndexOf("/");
        if(end==-1) {
            end = path.lastIndexOf("\\");
        }
        return path.substring(0,end+1);
    }

    private static String getClassName(String path) {
        int start = path.lastIndexOf("/");
        if(start==-1) {
            start = path.lastIndexOf("\\");
        }
        int end = path.lastIndexOf(".");
        return path.substring(start+1, end);
    }

    private static String readStringByLenght(DataInputStream in) throws IOException {
        int tmp = in.readInt();
        byte[] stringArr = new byte[tmp];
        in.read(stringArr);
        return new String(stringArr, charset);
    }


}