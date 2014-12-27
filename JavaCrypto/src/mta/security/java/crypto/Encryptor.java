package mta.security.java.crypto;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;


public class Encryptor {

	public static void main(String[] args) {
		
		
		try {
			
			byte[] content = null;
			// Read flat file
			URL messageAsResource = Encryptor.class.getResource("/message.txt");
			if (messageAsResource != null) {
				URI uri = messageAsResource.toURI();
				content = Files.readAllBytes(Paths.get(uri));
				System.out.println("The message to encrypt is:" + new String(content));
			}
			
			// Generate key pair
			KeyPair keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
			PrivateKey privateKey = keyPair.getPrivate();
			
			// Get signature for the file
			byte[] signatureBytes = signContent(content, privateKey);
			
			// Digest file
			byte[] digest = digestContent(content);
			
			// cipher
			byte[] cipherText = cipherDigest(digest, privateKey);
			
			Cipher cipher = Cipher.getInstance("AES");
			
			URL configurationFile = Encryptor.class.getResource("/configuration.txt");
			String path = configurationFile.getPath();
			File file = new File(path);
			try (FileOutputStream outputStream = new FileOutputStream(file))
			{
				try (CipherOutputStream cipherStream = new CipherOutputStream(outputStream, cipher))
				{
					cipherStream.write(signatureBytes);
				}
			}
			
			
		} 
		catch (Exception e) {
			e.printStackTrace();
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
	 */
	private static byte[] cipherDigest(byte[] digest, Key privateKey) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.ENCRYPT_MODE, privateKey);
		byte[] cipherText = cipher.doFinal(digest);
		
		System.out.println("cipher text: " + new String(cipherText));
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
	 */
	private static byte[] signContent(byte[] content, PrivateKey privateKey) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
		byte[] signatureBytes;
		Signature signature = Signature.getInstance("SHA1withRSA");
		
		signature.initSign(privateKey);
		signature.update(content);
		
		signatureBytes = signature.sign();
		
		System.out.println("Signature is:" + new String(signatureBytes));
		
		return signatureBytes;
	}

}
