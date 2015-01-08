package mta.security.java.crypto;

import java.io.FileOutputStream;
import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.List;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class Decryptor {

	private static final int SIGNATURE_ALGORITHM_INDEX = 4;
	private static final int SYMMETRIC_ALGORITHM_PADDING_INDEX = 3;
	private static final int SYMMETRIC_ALGORITHM_MODE_INDEX = 2;
	private static final int SYMMETRIC_ALGORITHM_INDEX = 1;
	private static final int ASYMMETRIC_ALGORITHM_INDEX = 0;

	public static void main(String[] args) {
		try {

			if (args.length == 0) {
				throw new IllegalArgumentException(
						"Keystore password not provided");
			}

			byte[] encryptedSecretKey = FileProvider.getSecretFileAsBytes();
			KeyProvider keyProvider = new KeyProvider();
			keyProvider.setDecryptorKeystorePassword(args[0]); // args[0] is
																// password to
																// Key store
			// get decryptor's private key
			Key privateKey = keyProvider.getPrivateKey(Sides.DECRYPTOR);
			CipherProvider cipherProvider = new CipherProvider();
			// get algorithm configurations
			List<String> algorithmConfiguration = Files.readAllLines(
					FileProvider.getAlgorithmFile().toPath(),
					Charset.defaultCharset());

			if (algorithmConfiguration.size() != 5) {
				throw new IllegalArgumentException(
						"Wrong number of algorithm parameters");
			}

			cipherProvider.setAsymmetricAlgorithm(algorithmConfiguration
					.get(ASYMMETRIC_ALGORITHM_INDEX));
			cipherProvider.setSymmetricAlgorithm(algorithmConfiguration
					.get(SYMMETRIC_ALGORITHM_INDEX));
			cipherProvider.setSymmetricAlgorithmMode(algorithmConfiguration
					.get(SYMMETRIC_ALGORITHM_MODE_INDEX));
			cipherProvider.setSymmetricAlgorithmPadding(algorithmConfiguration
					.get(SYMMETRIC_ALGORITHM_PADDING_INDEX));

			// decrypt symmetric key
			byte[] decryptedSecretKey = cipherProvider.decipher(
					encryptedSecretKey, privateKey);

			byte[] encryptedFile = FileProvider.getEncryptedFileAsBytes();
			// get IV
			byte[] iv = FileProvider.getIv();
			// decrypt cyphertext
			byte[] decValue = cipherProvider.decipher(encryptedFile,
					decryptedSecretKey, iv);
			String decryptedValue = new String(decValue);

			System.out.println("Decrypted message is:" + decryptedValue);

			try (FileOutputStream outputStream = new FileOutputStream(
					FileProvider.getDecryptedFile())) {
				outputStream.write(decryptedValue.getBytes());
			}
			// check for signature
			byte[] signature = FileProvider.getSignatureFileAsBytes();

			SignatureProvider signatureProvider = new SignatureProvider();
			signatureProvider.setSignatureAlgorithm(algorithmConfiguration
					.get(SIGNATURE_ALGORITHM_INDEX));

			if (signatureProvider.verify(decValue, signature, keyProvider)) {
				System.out.println("Signature is valid");
			} else {
				System.out.println("Invalid signature");
			}
		} catch (URISyntaxException | IOException | UnrecoverableKeyException
				| KeyStoreException | NoSuchAlgorithmException
				| CertificateException | InvalidKeyException
				| NoSuchPaddingException | IllegalBlockSizeException
				| BadPaddingException | NoSuchProviderException
				| SignatureException | InvalidAlgorithmParameterException e1) {
			e1.printStackTrace();
		}
	}
}
