package mta.security.java.crypto;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.SecureRandom;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class CipherProvider {
	
	private static final String ASYMMETRIC_ALGORITHM = "RSA";
	
	// Provider that we're using
	private static final String PROVIDER = "SUN";

	private static final String RANDOM_ALGORITHM = "SHA1PRNG";

	private static final String SYMMETRIC_ALGORITHM = "AES";

	public static byte[] decipher(byte[] content, Key privateKey) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchProviderException {
		Cipher cipher = Cipher.getInstance(ASYMMETRIC_ALGORITHM);
		cipher.init(Cipher.DECRYPT_MODE, privateKey);
		
		byte[] cipherText = cipher.doFinal(content);
		
		return cipherText;
	}
	
	/**
	 * Get cipher from digest
	 * @param digest
	 * @param publicKey
	 * @return
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws InvalidKeyException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 * @throws NoSuchProviderException 
	 */
	public static byte[] cipher(byte[] content, Key publicKey) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchProviderException {
		Cipher cipher = Cipher.getInstance(ASYMMETRIC_ALGORITHM);
		cipher.init(Cipher.ENCRYPT_MODE, publicKey);
		
		byte[] cipherText = cipher.doFinal(content);
		
		return cipherText;
	}

	public static byte[] decipher(byte[] encryptedFile, byte[] decryptedSecretKey) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		SecretKey k = new SecretKeySpec(decryptedSecretKey, SYMMETRIC_ALGORITHM);
        Cipher c = Cipher.getInstance(SYMMETRIC_ALGORITHM);
        c.init(Cipher.DECRYPT_MODE, k);
        
        byte[] decValue = c.doFinal(encryptedFile);
        
        return decValue;
	}

	/**
	 * 
	 * @param file
	 * @param signatureBytes
	 * @return 
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws InvalidKeyException
	 * @throws FileNotFoundException
	 * @throws IOException
	 * @throws NoSuchProviderException 
	 */
	public static SecretKey writeSecureFile(File file, byte[] signatureBytes) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, FileNotFoundException, IOException, NoSuchProviderException {

		KeyGenerator keyGen = KeyGenerator.getInstance(SYMMETRIC_ALGORITHM);
		keyGen.init(128);
		SecretKey secretKey = keyGen.generateKey();
       
		Cipher cipher = Cipher.getInstance(SYMMETRIC_ALGORITHM);
		
		SecureRandom secureRandom = SecureRandom.getInstance(RANDOM_ALGORITHM, PROVIDER);
		cipher.init(Cipher.ENCRYPT_MODE, secretKey, secureRandom);
		
		try (FileOutputStream outputStream = new FileOutputStream(file))
		{
			try (CipherOutputStream cipherStream = new CipherOutputStream(outputStream, cipher))
			{
				cipherStream.write(signatureBytes);
			}
		}
		
		return secretKey;
	}
}
