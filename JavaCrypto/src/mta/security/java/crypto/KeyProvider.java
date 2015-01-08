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
	private char[] encryptorKeystorePassword;
	private char[] decryptorKeystorePassword;
	
	/**
	 * 
	 * @param side - which site requests the public key. Each side will receive the public key of the OTHER side
	 * @return - Public key of the other side
	 * @throws KeyStoreException
	 * @throws NoSuchAlgorithmException
	 * @throws CertificateException
	 * @throws IOException
	 */
	public Key getPublicKey(Sides side) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
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
	
	public Key getPrivateKey(Sides side) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException, UnrecoverableKeyException {
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
			keyStore.load(keystoreFile, getDecryptorKeystorePassword());
			k = keyStore.getKey(DECRYPTOR_KEYSTORE_ALIAS, getDecryptorKeystorePassword());	
		}
		else {
			keyStore.load(keystoreFile, getEncryptorKeystorePassword());
			k = keyStore.getKey(ENCRYPTOR_KEYSTORE_ALIAS, getEncryptorKeystorePassword());
		}
		
		
		return k;
	}

	private char[] getDecryptorKeystorePassword() {
		return this.decryptorKeystorePassword;
	}

	private char[] getEncryptorKeystorePassword() {
		return this.encryptorKeystorePassword;
	}

	public void setEncryptorKeystorePassword(String password) {
		this.encryptorKeystorePassword = password.toCharArray();
	}

	public void setDecryptorKeystorePassword(String password) {
		this.decryptorKeystorePassword = password.toCharArray();
	}

}
