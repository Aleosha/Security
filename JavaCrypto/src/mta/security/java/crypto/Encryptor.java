package mta.security.java.crypto;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;


public class Encryptor {	

	public static void main(String[] args) {
		
		
		try {
			
			byte[] content = FileProvider.getFlatFileAsBytes();
				
			Key privateKey = KeyProvider.getPrivateKey(Sides.ENCRYPTOR);
			// Get signature for the file
			byte[] signatureBytes = SignatureProvider.signContent(content, privateKey);
			
			Key publicKey = KeyProvider.getPublicKey(Sides.ENCRYPTOR);
				
			File configurationFile = FileProvider.getSignatureConfigurationFile();
			
			try (FileOutputStream outputStream = new FileOutputStream(configurationFile)) {
				outputStream.write(signatureBytes);
			}
			
			
			File encryptedFile = FileProvider.getEncryptedFile();
			
			SecretKey secretKey = CipherProvider.writeSecureFile(encryptedFile, content);
			
			configurationFile = FileProvider.getSecretConfigurationFile();
			
			byte[] secretKeyCipher = CipherProvider.cipher(secretKey.getEncoded(), publicKey);
			
			try (FileOutputStream outputStream = new FileOutputStream(configurationFile)) {
				outputStream.write(secretKeyCipher);
			}
			
			System.out.println("Encryption completed");
		} 
		catch (Exception e) {
			e.printStackTrace();
		}
	}
}
