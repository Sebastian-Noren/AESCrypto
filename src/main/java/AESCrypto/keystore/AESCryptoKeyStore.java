package AESCrypto.keystore;

import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

/**
 * @author Sebastian Norén <s.norén@gmail.com>
 * @version 1.0
 * @since   2020-11-24
 */

public class AESCryptoKeyStore {

    public void createKeyStore(File keyStoreFile, String keyStorePassword, SecretKeySpec secretKey, String alias, String keyPassword){
        try {
            KeyStore keyStore = keyStoreBase(keyStoreFile,keyStorePassword);
            KeyStore.SecretKeyEntry secretKeyEntry = new KeyStore.SecretKeyEntry(secretKey);
            KeyStore.PasswordProtection keyPasswordProtection = new KeyStore.PasswordProtection(keyPassword.toCharArray());
            if (keyStore != null) {
                keyStore.setEntry(alias, secretKeyEntry,keyPasswordProtection);
                keyStore.store(new FileOutputStream(keyStoreFile), keyStorePassword.toCharArray());
            }
        } catch (CertificateException | NoSuchAlgorithmException | KeyStoreException | IOException e) {
            e.printStackTrace();
        }
    }

    private KeyStore keyStoreBase(File keyStoreFile, String keyStorePassword){
        try {
            final KeyStore keyStore = KeyStore.getInstance("JCEKS");
            if (keyStoreFile.exists()){
                keyStore.load(new FileInputStream(keyStoreFile), keyStorePassword.toCharArray());
            }else {
                keyStore.load(null,null);
                keyStore.store(new FileOutputStream(keyStoreFile), keyStorePassword.toCharArray());
            }
            return keyStore;
        } catch (KeyStoreException | NoSuchAlgorithmException |
                CertificateException | IOException e) {
            e.printStackTrace();
        }
        return null;
    }

    public SecretKeySpec getAESKeyKeyStore(File keyStoreFile, String keyStorePassword, String alias, String keyPassword) {
        SecretKeySpec secretKey;
        try {
            FileInputStream inputStream = new FileInputStream(keyStoreFile);
            final KeyStore keyStore = KeyStore.getInstance("JCEKS");
            keyStore.load(inputStream, keyStorePassword.toCharArray());
            inputStream.close();
            secretKey = (SecretKeySpec) keyStore.getKey(alias, keyPassword.toCharArray());
            return secretKey;
        } catch (IOException | KeyStoreException |
                NoSuchAlgorithmException | UnrecoverableKeyException |
                CertificateException e) {
            e.printStackTrace();
        }
        return null;
    }

}
