package mta.security.java.crypto;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.URI;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;


public class Encryptor {

	// Provider that we're using
	private static final String PROVIDER = "SUN";
	

	public static void main(String[] args) {
		
		
		try {
			
			byte[] content = FileProvider.getFlatFile();
			
			// Generate key pair
			// TODO get keypair from keystore
			KeyPair keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
			PrivateKey privateKey = keyPair.getPrivate();
			
			// Get signature for the file
			byte[] signatureBytes = signContent(content, privateKey);
			
			// Digest file
			byte[] digest = digestContent(content);
			
			// cipher content
			byte[] cipherText = cipherDigest(content, privateKey);
			KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
			
			File file = FileProvider.getConfigurationFile();
			
			try (FileOutputStream outputStream = new FileOutputStream(file)) {
				outputStream.write(signatureBytes);
			}
			
			
			file = FileProvider.getEncryptedFile();
			
			writeSecureFile(file, cipherText);
		} 
		catch (Exception e) {
			e.printStackTrace();
		}
	}

	

	/**
	 * 
	 * @param file
	 * @param signatureBytes
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws InvalidKeyException
	 * @throws FileNotFoundException
	 * @throws IOException
	 * @throws NoSuchProviderException 
	 */
	private static void writeSecureFile(File file, byte[] signatureBytes) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, FileNotFoundException, IOException, NoSuchProviderException {
		// TODO get secret key?
		KeyGenerator keyGen = KeyGenerator.getInstance("AES");
		 keyGen.init(128);
		SecretKey secretKey = keyGen.generateKey();
       
		Cipher cipher = Cipher.getInstance("AES");
		
		SecureRandom secureRandom = SecureRandom.getInstance("SHA1PRNG", PROVIDER);
		cipher.init(Cipher.ENCRYPT_MODE, secretKey, secureRandom);
		
		try (FileOutputStream outputStream = new FileOutputStream(file))
		{
			try (CipherOutputStream cipherStream = new CipherOutputStream(outputStream, cipher))
			{
				cipherStream.write(signatureBytes);
			}
		}
	}

	/**
	 * Get cipher from digest
	 * @param digest
	 * @param privateKey
	 * @return
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws InvalidKeyException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 * @throws NoSuchProviderException 
	 */
	private static byte[] cipherDigest(byte[] content, Key privateKey) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchProviderException {
		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.ENCRYPT_MODE, privateKey);
		
		byte[] cipherText = cipher.doFinal(content);
		
		System.out.println("Cipher text: " + new String(cipherText));
		return cipherText;
	}

	/**
	 * Get digest from content
	 * @param content
	 * @return
	 * @throws NoSuchAlgorithmException
	 */
	private static byte[] digestContent(byte[] content) throws NoSuchAlgorithmException {
		MessageDigest sha1 = MessageDigest.getInstance("SHA1");
		byte[] digest = sha1.digest(content);
		
		System.out.println("Digest is:" + new String(digest));
		return digest;
	}

	/**
	 * Sign content using provided private key
	 * @param content
	 * @param privateKey
	 * @return
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeyException
	 * @throws SignatureException
	 * @throws NoSuchProviderException 
	 */
	private static byte[] signContent(byte[] content, PrivateKey privateKey) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, NoSuchProviderException {
		byte[] signatureBytes;
		Signature signature = Signature.getInstance("SHA1withRSA");
		
		signature.initSign(privateKey);
		signature.update(content);
		
		signatureBytes = signature.sign();
		
		System.out.println("Signature is:" + new String(signatureBytes));
		
		return signatureBytes;
	}

}
