package mta.security.java.crypto;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class CipherProvider {

	private static final int IV_LENGTH = 16;

	private static final int SYMMETRIC_ALGORITHM_KEY_SIZE = 128;

	private static final String SYMMETRIC_ALGORITHM_PADDING = "PKCS5Padding";

	private static final String SUMMETRIC_ALGORITHM_MODE = "CBC";

	private static final String ASYMMETRIC_ALGORITHM = "RSA";

	// Provider that we're using
	private static final String PROVIDER = "SunJCE";

	private static final String RANDOM_ALGORITHM = "SHA1PRNG";

	private static final String SYMMETRIC_ALGORITHM = "AES";

	private static final String SYMMETRIC_ALGORITHM_WITH_MODE = SYMMETRIC_ALGORITHM
			+ "/"
			+ SUMMETRIC_ALGORITHM_MODE
			+ "/"
			+ SYMMETRIC_ALGORITHM_PADDING;

	/**
	 * Decipher assymetric content using private key 
	 * @param content
	 * @param privateKey
	 * @return
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws InvalidKeyException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 * @throws NoSuchProviderException
	 */
	public static byte[] decipher(byte[] content, Key privateKey)
			throws NoSuchAlgorithmException, NoSuchPaddingException,
			InvalidKeyException, IllegalBlockSizeException,
			BadPaddingException, NoSuchProviderException {
		Cipher cipher = Cipher.getInstance(ASYMMETRIC_ALGORITHM, PROVIDER);
		cipher.init(Cipher.DECRYPT_MODE, privateKey);

		byte[] cipherText = cipher.doFinal(content);

		return cipherText;
	}

	/**
	 * Cipher content assymetrically using public key of the other side
	 * 
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
	public static byte[] cipher(byte[] content, Key publicKey)
			throws NoSuchAlgorithmException, NoSuchPaddingException,
			InvalidKeyException, IllegalBlockSizeException,
			BadPaddingException, NoSuchProviderException {
		Cipher cipher = Cipher.getInstance(ASYMMETRIC_ALGORITHM, PROVIDER);
		cipher.init(Cipher.ENCRYPT_MODE, publicKey);

		byte[] cipherText = cipher.doFinal(content);

		return cipherText;
	}

	/**
	 * Decipher symmetrically encrypted file using secret key and IV
	 * @param encryptedFile
	 * @param decryptedSecretKey
	 * @param iv
	 * @return
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws InvalidKeyException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 * @throws InvalidAlgorithmParameterException
	 * @throws NoSuchProviderException
	 */
	public static byte[] decipher(byte[] encryptedFile,
			byte[] decryptedSecretKey, byte[] iv)
			throws NoSuchAlgorithmException, NoSuchPaddingException,
			InvalidKeyException, IllegalBlockSizeException,
			BadPaddingException, InvalidAlgorithmParameterException, NoSuchProviderException {
		SecretKey k = new SecretKeySpec(decryptedSecretKey, SYMMETRIC_ALGORITHM);
		Cipher c = Cipher.getInstance(SYMMETRIC_ALGORITHM_WITH_MODE, PROVIDER);
		IvParameterSpec ivspec = new IvParameterSpec(iv);

		c.init(Cipher.DECRYPT_MODE, k, ivspec);

		byte[] decValue = c.doFinal(encryptedFile);

		return decValue;
	}

	/**
	 * Writes file encoded with symmetric algorithm
	 * @param file - file to write to
	 * @param content - content to write
	 * @return - combination of secret key and IV
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws InvalidKeyException
	 * @throws FileNotFoundException
	 * @throws IOException
	 * @throws NoSuchProviderException
	 * @throws InvalidAlgorithmParameterException
	 */
	public static SecretKeyHolder writeSecureFile(File file,
			byte[] content) throws NoSuchAlgorithmException,
			NoSuchPaddingException, InvalidKeyException, FileNotFoundException,
			IOException, NoSuchProviderException,
			InvalidAlgorithmParameterException {

		KeyGenerator keyGen = KeyGenerator.getInstance(SYMMETRIC_ALGORITHM, PROVIDER);
		keyGen.init(SYMMETRIC_ALGORITHM_KEY_SIZE);
		SecretKey secretKey = keyGen.generateKey();

		Cipher cipher = Cipher.getInstance(SYMMETRIC_ALGORITHM_WITH_MODE);

		SecureRandom secureRandom = SecureRandom.getInstance(RANDOM_ALGORITHM);
		byte[] iv = new byte[IV_LENGTH];
		SecureRandom prng = new SecureRandom();
		prng.nextBytes(iv);

		cipher.init(Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(iv));

		try (FileOutputStream outputStream = new FileOutputStream(file)) {
			try (CipherOutputStream cipherStream = new CipherOutputStream(
					outputStream, cipher)) {
				cipherStream.write(content);
			}
		}

		return new SecretKeyHolder(secretKey, secureRandom, iv);
	}

}
