package AESCrypto;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;

/**
 * @author Sebastian Norén <s.norén@gmail.com>
 * @version 1.0
 * @since   2020-11-24
 */

public class AESCryptoFile {

    private final String ALGORITHM;

    public AESCryptoFile() {

        this.ALGORITHM = "AES";
    }

    public void encryptFile(SecretKeySpec key, File file) {
        try {
            if (file.length() >= 1000000000) {
                throw new OutOfMemoryError("FileSize exceed 1 GB!, USE blockEncryptFile");
            }
                Cipher cipher = Cipher.getInstance(ALGORITHM);
                cipher.init(Cipher.ENCRYPT_MODE, key);
                FileInputStream FiS = new FileInputStream(file);
                byte[] fileDataBuffer;
                fileDataBuffer = FiS.readAllBytes();
                FileOutputStream outputStream = new FileOutputStream(file);
                CipherOutputStream cos = new CipherOutputStream(outputStream,cipher);
                cos.write(fileDataBuffer);
                cos.flush();
                cos.close();
                FiS.close();
                outputStream.flush();
                outputStream.close();

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void decryptFile(SecretKeySpec key, File file) {
        try {
            if (file.length() >= 1000000000) {
                throw new OutOfMemoryError("FileSize exceed 1 GB!, USE blockDecryptFile");
            }
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, key);
            FileInputStream FiS = new FileInputStream(file);
            CipherInputStream cis = new CipherInputStream(FiS,cipher);
            byte[] fileDataBuffer;
            fileDataBuffer = cis.readAllBytes();
            FileOutputStream outputStream = new FileOutputStream(file);
            outputStream.write(fileDataBuffer);
            FiS.close();
            cis.close();
            outputStream.flush();
            outputStream.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void blockEncryptFile(SecretKeySpec key, File file) {
        try {
            String originalFileName = file.getAbsolutePath();
            String path = getPathName(file);
            String tempPath = path+"temp";
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, key);
            FileInputStream inputStream = new FileInputStream(file);
            File encryptedFile = new File(tempPath);
            FileOutputStream outputStream = new FileOutputStream(encryptedFile);
            CipherOutputStream cipherOutputStream = new CipherOutputStream(outputStream,cipher);
            int count;
            byte[] buffer = new byte[8192];
            int bytesToRead = (int) file.length();
            while ((count = inputStream.read(buffer, 0, bytesToRead < 8192 ? bytesToRead : 8192)) > 0) {
                cipherOutputStream.write(buffer, 0, count);
                bytesToRead = bytesToRead - count;
            }
            inputStream.close();
            cipherOutputStream.flush();
            cipherOutputStream.close();
            outputStream.flush();
            outputStream.close();
            file.delete();
            encryptedFile.renameTo(new File(originalFileName));

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void blockDecryptFile(SecretKeySpec key, File file) {
        try {
            String originalFileName = file.getAbsolutePath();
            String path = getPathName(file);
            String tempPath = path+"temp";
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, key);
            FileInputStream inputStream = new FileInputStream(file);
            File decryptedFile = new File(tempPath);
            FileOutputStream outputStream = new FileOutputStream(decryptedFile);
            CipherOutputStream cipherOutputStream = new CipherOutputStream(outputStream,cipher);
            int count;
            byte[] buffer = new byte[8192];
            int bytesToRead = (int) file.length();
            while ((count = inputStream.read(buffer, 0, bytesToRead < 8192 ? bytesToRead : 8192)) > 0) {
                cipherOutputStream.write(buffer, 0, count);
                bytesToRead = bytesToRead - count;
            }
            inputStream.close();
            cipherOutputStream.flush();
            cipherOutputStream.close();
            outputStream.flush();
            outputStream.close();
            file.delete();
            decryptedFile.renameTo(new File(originalFileName));

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private String getPathName(File file){
        return file.getAbsolutePath().replace(file.getName(),"");
    }


}
