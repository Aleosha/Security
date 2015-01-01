package mta.security.java.crypto;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

public class Decryptor {

	public static void main(String[] args) {
		try {
			byte[] encryptedSecretKey = FileProvider.getSecretFileAsBytes();
			Key privateKey = getPrivateKey();
			byte[] decryptedSecretKey = decipher(encryptedSecretKey, privateKey);
			System.out.println(new String(decryptedSecretKey));
			byte[] encryptedFile = FileProvider.getEncryptedFileAsBytes();
			
		
			Key k = new SecretKeySpec(decryptedSecretKey, "AES");
	        Cipher c = Cipher.getInstance("AES");
	        c.init(Cipher.DECRYPT_MODE, k);
	        
	        byte[] decValue = c.doFinal(encryptedFile);
	        String decryptedValue = new String(decValue);
			
			System.out.println(decryptedValue);
		} catch (URISyntaxException | IOException | UnrecoverableKeyException | KeyStoreException | NoSuchAlgorithmException | CertificateException | InvalidKeyException | NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException | NoSuchProviderException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
	}

	
	//TODO refactor!!!
	private static Key getPrivateKey() throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException, UnrecoverableKeyException {
		KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
		File file = new File("C:\\temp\\keystore2.jks");
		
		FileInputStream keystoreFile = new FileInputStream(file);
		keyStore.load(keystoreFile, "abcd1234".toCharArray());
		Key k = keyStore.getKey("decryptor", "abcd1234".toCharArray());
		
		return k;
	}

	//TODO refactor!!!
	private static byte[] decipher(byte[] content, Key privateKey) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchProviderException {
		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.DECRYPT_MODE, privateKey);
		
		byte[] cipherText = cipher.doFinal(content);
		
		System.out.println("Cipher text: " + new String(cipherText));
		return cipherText;
	}
}
