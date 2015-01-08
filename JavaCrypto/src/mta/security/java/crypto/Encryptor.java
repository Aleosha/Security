package mta.security.java.crypto;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.security.Key;

public class Encryptor {

	public static void main(String[] args) {

		try {
			byte[] content = null;

			if (args.length >= 1) {
				// get plain text file path from arguments
				String path = args[0]; // args[0] is file path
				File fileToEncrypt = new File(path);
				if (!fileToEncrypt.isFile()) {
					throw new IllegalArgumentException("File name is not valid");
				} else {
					content = FileProvider.getFile(path);
				}
			} else {
				// get default plain text file path from arguments
				content = FileProvider.getFlatFileAsBytes();
			}
			if (args.length < 2) {
				throw new IllegalArgumentException(
						"Keystore password not provided");
			}
			KeyProvider keyProvider = new KeyProvider();
			keyProvider.setEncryptorKeystorePassword(args[1]); // args[1] is
																// password to
																// Key store

			// get encriptor's private key for signature
			Key privateKey = keyProvider.getPrivateKey(Sides.ENCRYPTOR);

			SignatureProvider signatureProvider = new SignatureProvider();

			// get signature for the file
			byte[] signatureBytes = signatureProvider.signContent(content,
					privateKey);

			// store signature in configuration file
			File configurationFile = FileProvider
					.getSignatureConfigurationFile();

			try (FileOutputStream outputStream = new FileOutputStream(
					configurationFile)) {
				outputStream.write(signatureBytes);
			}

			CipherProvider cipherProvider = new CipherProvider();

			File encryptedFile = FileProvider.getEncryptedFile();
			// symmetric encryption of plain
			SecretKeyHolder secretKeyHolder = cipherProvider.writeSecureFile(
					encryptedFile, content);

			configurationFile = FileProvider.getSecretConfigurationFile();

			// get decriptor's public key for encryption of our symmetric key
			Key publicKey = keyProvider.getPublicKey(Sides.ENCRYPTOR);
			// encrypt symmetric key
			byte[] secretKeyCipher = cipherProvider.cipher(secretKeyHolder
					.getSecretKey().getEncoded(), publicKey);

			try (FileOutputStream outputStream = new FileOutputStream(
					configurationFile)) {
				outputStream.write(secretKeyCipher);
			}

			configurationFile = FileProvider.getIvConfigurationFile();
			// insert IV into configuration file
			try (FileOutputStream outputStream = new FileOutputStream(
					configurationFile)) {
				outputStream.write(secretKeyHolder.getIv());
			}
			// algorithm configurations
			writeAlgorithmConfiguration(cipherProvider, signatureProvider);

			System.out.println("Encryption completed");
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	private static void writeAlgorithmConfiguration(
			CipherProvider cipherProvider, SignatureProvider signatureProvider)
			throws IOException {
		try (BufferedWriter writer = new BufferedWriter(new FileWriter(
				FileProvider.getAlgorithmFile()))) {
			writer.write(cipherProvider.getAsymmetricAlgorithm());
			writer.newLine();
			writer.write(cipherProvider.getSymmetricAlgorithm());
			writer.newLine();
			writer.write(cipherProvider.getSymmetricAlgorithmMode());
			writer.newLine();
			writer.write(cipherProvider.getSymmetricAlgorithmPadding());
			writer.newLine();
			writer.write(signatureProvider.getSignatureAlgorithm());
			writer.newLine();
		}
	}
}
