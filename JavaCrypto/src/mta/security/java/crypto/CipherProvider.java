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

	private String symmetricAlgorithmPadding = "PKCS5Padding";

	private String symmetricAlgorithmMode = "CBC";

	private String asymmetricAlgorithm = "RSA";

	// Provider that we're using
	private static final String PROVIDER = "SunJCE";

	public String getSymmetricAlgorithmPadding() {
		return symmetricAlgorithmPadding;
	}

	public void setSymmetricAlgorithmPadding(String symmetricAlgorithmPadding) {
		this.symmetricAlgorithmPadding = symmetricAlgorithmPadding;
	}

	public String getSymmetricAlgorithmMode() {
		return symmetricAlgorithmMode;
	}

	public void setSymmetricAlgorithmMode(String symmetricAlgorithmMode) {
		this.symmetricAlgorithmMode = symmetricAlgorithmMode;
	}

	public String getAsymmetricAlgorithm() {
		return asymmetricAlgorithm;
	}

	public void setAsymmetricAlgorithm(String asymmetricAlgorithm) {
		this.asymmetricAlgorithm = asymmetricAlgorithm;
	}

	public String getSymmetricAlgorithm() {
		return symmetricAlgorithm;
	}

	public void setSymmetricAlgorithm(String symmetricAlgorithm) {
		this.symmetricAlgorithm = symmetricAlgorithm;
	}

	public String getSymmetricAlgorithmWithMode() {
		return symmetricAlgorithmWithMode;
	}

	public void setSymmetricAlgorithmWithMode(String symmetricAlgorithmWithMode) {
		this.symmetricAlgorithmWithMode = symmetricAlgorithmWithMode;
	}

	private String symmetricAlgorithm = "AES";

	private String symmetricAlgorithmWithMode = symmetricAlgorithm
			+ "/"
			+ symmetricAlgorithmMode
			+ "/"
			+ symmetricAlgorithmPadding;

	/**
	 * Decipher assymetric content using private key
	 * 
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
	public byte[] decipher(byte[] content, Key privateKey)
			throws NoSuchAlgorithmException, NoSuchPaddingException,
			InvalidKeyException, IllegalBlockSizeException,
			BadPaddingException, NoSuchProviderException {
		Cipher cipher = Cipher.getInstance(asymmetricAlgorithm, PROVIDER);
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
	public byte[] cipher(byte[] content, Key publicKey)
			throws NoSuchAlgorithmException, NoSuchPaddingException,
			InvalidKeyException, IllegalBlockSizeException,
			BadPaddingException, NoSuchProviderException {
		Cipher cipher = Cipher.getInstance(asymmetricAlgorithm, PROVIDER);
		cipher.init(Cipher.ENCRYPT_MODE, publicKey);

		byte[] cipherText = cipher.doFinal(content);

		return cipherText;
	}

	/**
	 * Decipher symmetrically encrypted file using secret key and IV
	 * 
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
	public byte[] decipher(byte[] encryptedFile,
			byte[] decryptedSecretKey, byte[] iv)
			throws NoSuchAlgorithmException, NoSuchPaddingException,
			InvalidKeyException, IllegalBlockSizeException,
			BadPaddingException, InvalidAlgorithmParameterException,
			NoSuchProviderException {
		SecretKey k = new SecretKeySpec(decryptedSecretKey, symmetricAlgorithm);
		Cipher c = Cipher.getInstance(symmetricAlgorithmWithMode, PROVIDER);
		IvParameterSpec ivspec = new IvParameterSpec(iv);

		c.init(Cipher.DECRYPT_MODE, k, ivspec);

		byte[] decValue = c.doFinal(encryptedFile);

		return decValue;
	}

	/**
	 * Writes file encoded with symmetric algorithm
	 * 
	 * @param file
	 *            - file to write to
	 * @param content
	 *            - content to write
	 * @return - combination of secret key and IV
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws InvalidKeyException
	 * @throws FileNotFoundException
	 * @throws IOException
	 * @throws NoSuchProviderException
	 * @throws InvalidAlgorithmParameterException
	 */
	public SecretKeyHolder writeSecureFile(File file, byte[] content)
			throws NoSuchAlgorithmException, NoSuchPaddingException,
			InvalidKeyException, FileNotFoundException, IOException,
			NoSuchProviderException, InvalidAlgorithmParameterException {

		KeyGenerator keyGen = KeyGenerator.getInstance(symmetricAlgorithm,
				PROVIDER);
		keyGen.init(SYMMETRIC_ALGORITHM_KEY_SIZE);
		// generate secret key
		SecretKey secretKey = keyGen.generateKey();

		Cipher cipher = Cipher.getInstance(symmetricAlgorithmWithMode,
				PROVIDER);
		// create random iv
		byte[] iv = new byte[IV_LENGTH];
		SecureRandom prng = new SecureRandom();
		prng.nextBytes(iv);

		cipher.init(Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(iv));

		// encrypt plain with symmetric key
		try (FileOutputStream outputStream = new FileOutputStream(file)) {
			try (CipherOutputStream cipherStream = new CipherOutputStream(
					outputStream, cipher)) {
				cipherStream.write(content);
			}
		}

		return new SecretKeyHolder(secretKey, iv);
	}

}
