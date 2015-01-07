package mta.security.java.crypto;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

public class KeyProvider {

	public static Key getPublicKey(Sides side) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
		KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
		File file = null;
		String alias = "";
		switch (side)
		{
		case ENCRYPTOR:
			file = new File("C:\\temp\\keystore.jks");
			alias = "decryptor";
			break;
		case DECRYPTOR:
			file = new File("C:\\temp\\keystore2.jks");
			alias = "encryptor";
			break;
		}
		
		if (file != null)
		{
			try (FileInputStream keystoreFile = new FileInputStream(file)) {
				keyStore.load(keystoreFile, "abcd1234".toCharArray());
				
				return keyStore.getCertificate(alias).getPublicKey();
			}
		}
		
		return null;
	
	}
	
	public static Key getPrivateKey(Sides side) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException, UnrecoverableKeyException {
		KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
		File file = null;
		Key k = null;
		if (Sides.DECRYPTOR.equals(side)) {
			file = new File("C:\\temp\\keystore2.jks");	
		}
		else {
			file = new File("C:\\temp\\keystore.jks");
		}
		
		
		FileInputStream keystoreFile = new FileInputStream(file);
		keyStore.load(keystoreFile, "abcd1234".toCharArray());
		if (Sides.DECRYPTOR.equals(side)) {
			k = keyStore.getKey("decryptor", "abcd1234".toCharArray());	
		}
		else {
			k = keyStore.getKey("encryptor", "abcd1234".toCharArray());
		}
		
		
		return k;
	}

}
