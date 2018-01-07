import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;

import org.apache.commons.io.IOUtils;

public class FileUtil {
    public static void writeByte2File(byte bytes[], String strFilePath) 
    {
        try {
            FileOutputStream fos = new FileOutputStream(strFilePath);
            fos.write(bytes); 
            fos.close();
        } catch (FileNotFoundException ex) {
            System.out.println("FileNotFoundException" + ex);
        } catch (IOException ioe) {
            System.out.println("IOException" + ioe);
        }
    }
    
    public static byte[] readByteFromFile(String strFilePath)
    {
        System.out.println("Let's start reading file");
        byte[] bytes = null;
        try {
           File file = new File(strFilePath);
           InputStream is = new FileInputStream(file);
           DataInputStream dis = new DataInputStream(is);
           bytes = IOUtils.toByteArray(dis);
           System.out.println("There you go");
        } catch (IOException e) {
           e.printStackTrace();
        }
        return bytes;
    }
}
