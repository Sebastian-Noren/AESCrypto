package AESCrypto;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Base64;

/**
 * @author Sebastian Norén <s.norén@gmail.com>
 * @version 1.0
 * @since   2020-11-24
 */

public class AESCrypto {

    private final String ALGORITHM;

    public AESCrypto() {
        this.ALGORITHM = "AES";
    }

    public SecretKeySpec generateAESKey() {
        SecretKeySpec key;
        try {
            KeyGenerator keyGenerator = KeyGenerator.getInstance(ALGORITHM);
            SecureRandom rand = new SecureRandom();
            keyGenerator.init(256, rand);
            SecretKey secretKey = keyGenerator.generateKey();
            key = new SecretKeySpec(secretKey.getEncoded(), ALGORITHM);
            return key;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public SecretKeySpec createAESKeyString(String password) {
        SecretKeySpec secretKey;
        try {
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            KeySpec spec = new PBEKeySpec(password.toCharArray(), password.getBytes(), 65536, 256);
            SecretKey tmp = factory.generateSecret(spec);
            secretKey = new SecretKeySpec(tmp.getEncoded(), ALGORITHM);
            return secretKey;
        } catch (InvalidKeySpecException | NoSuchAlgorithmException keyEx) {
            keyEx.printStackTrace();
        }
        return null;
    }

    public SecretKeySpec createAESKeyStringSalt(String password, byte[] salt) {
        SecretKeySpec secretKey;
        try {
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 65536, 256);
            SecretKey tmp = factory.generateSecret(spec);
            secretKey = new SecretKeySpec(tmp.getEncoded(), ALGORITHM);
            return secretKey;
        } catch (InvalidKeySpecException | NoSuchAlgorithmException keyEx) {
            keyEx.printStackTrace();
        }
        return null;
    }

    public String AESEncryptionString(SecretKeySpec secretKey, String message) {
        String encryptedMessage = "";
        try {
            byte[] encrypted = AESEncryption(secretKey,message.getBytes());
            encryptedMessage = Base64.getEncoder().encodeToString(encrypted);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return encryptedMessage;
    }

    public String AESDecryptionString(SecretKeySpec secretKey, String messageToDecrypt) {
        String decryptedMessage = "";
        try {
            byte[] decrypted = AESDecryption(secretKey,Base64.getDecoder().decode(messageToDecrypt));
            if (decrypted != null) {
                decryptedMessage = new String(decrypted);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return decryptedMessage;
    }

    public byte[] AESEncryption(SecretKeySpec secretKey, byte[] dataToEncrypt) {
        try {
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            return cipher.doFinal(dataToEncrypt);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public byte[] AESDecryption(SecretKeySpec secretKey, byte[] dataToDecrypt) {
        try {
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.DECRYPT_MODE, secretKey);
            return cipher.doFinal(dataToDecrypt);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null ;
    }

    public byte[] AESEncryption(SecretKeySpec secretKey,byte[] IV, byte[] dataToEncrypt) {
        try {
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(IV));
            return cipher.doFinal(dataToEncrypt);
        } catch (NoSuchAlgorithmException | IllegalBlockSizeException |
                BadPaddingException | NoSuchPaddingException |
                InvalidAlgorithmParameterException | InvalidKeyException e) {
            e.printStackTrace();
        }
        return null;
    }

    public byte[] AESDecryption(SecretKeySpec secretKey,byte[] IV, byte[] dataToDecrypt) {
        try {
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(IV));
            return cipher.doFinal(dataToDecrypt);
        } catch (NoSuchAlgorithmException | IllegalBlockSizeException |
                BadPaddingException | NoSuchPaddingException |
                InvalidAlgorithmParameterException | InvalidKeyException e) {
            e.printStackTrace();
        }
        return null;
    }

}
