package mta.security.java.crypto;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

public class KeyProvider {

	private static final String ENCRYPTOR_KEYSTORE_ALIAS = "encryptor";
	private static final String DECRYPTOR_KEYSTORE_ALIAS = "decryptor";
	private static final String ENCRYPTOR_KEYSTORE_LOCATION = "C:\\temp\\keystore.jks";
	private static final String DECRYPTOR_KEYSTORE_LOCATION = "C:\\temp\\keystore2.jks";
	private static final char[] DECRYPTOR_KEYSTORE_PASSWORD = "abcd1234".toCharArray();
	private static final char[] ENCRYPTOR_KEYSTORE_PASSWORD = "abcd1234".toCharArray();

	public static Key getPublicKey(Sides side) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
		KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
		File file = null;
		String alias = "";
		switch (side)
		{
		case ENCRYPTOR:
			file = new File(ENCRYPTOR_KEYSTORE_LOCATION);
			alias = DECRYPTOR_KEYSTORE_ALIAS;
			break;
		case DECRYPTOR:
			file = new File(DECRYPTOR_KEYSTORE_LOCATION);
			alias = ENCRYPTOR_KEYSTORE_ALIAS;
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
			file = new File(DECRYPTOR_KEYSTORE_LOCATION);	
		}
		else {
			file = new File(ENCRYPTOR_KEYSTORE_LOCATION);
		}
		
		
		FileInputStream keystoreFile = new FileInputStream(file);
		
		if (Sides.DECRYPTOR.equals(side)) {
			keyStore.load(keystoreFile, DECRYPTOR_KEYSTORE_PASSWORD);
			k = keyStore.getKey(DECRYPTOR_KEYSTORE_ALIAS, DECRYPTOR_KEYSTORE_PASSWORD);	
		}
		else {
			keyStore.load(keystoreFile, ENCRYPTOR_KEYSTORE_PASSWORD);
			k = keyStore.getKey(ENCRYPTOR_KEYSTORE_ALIAS, ENCRYPTOR_KEYSTORE_PASSWORD);
		}
		
		
		return k;
	}

}
