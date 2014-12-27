package mta.security.java.crypto;

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
			
			// Cypher
			byte[] cypher = cypherDigest(digest, privateKey);
			
			
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (URISyntaxException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (SignatureException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (BadPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	/**
	 * Get cypher from digest
	 * @param digest
	 * @param privateKey
	 * @return
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws InvalidKeyException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 */
	private static byte[] cypherDigest(byte[] digest, Key privateKey) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.ENCRYPT_MODE, privateKey);
		byte[] cypherText = cipher.doFinal(digest);
		
		System.out.println("Cypher text: " + new String(cypherText));
		return cypherText;
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
