package mta.security.java.crypto;

import java.io.File;
import java.io.FileOutputStream;
import java.nio.file.Paths;
import java.security.Key;

import javax.crypto.SecretKey;


public class Encryptor {	

	public static void main(String[] args) {
		
		
		try {
			byte[] content = null;
			
			if (args.length >= 1) {
				String path = args[0];
				File fileToEncrypt = new File(path);
				if (!fileToEncrypt.isFile()) {
					throw new IllegalArgumentException("File name is not valid");
				}
				else {
					content = FileProvider.getFile(path);
				}
			}
			else {
				content = FileProvider.getFlatFileAsBytes();	
			}
			
				
			Key privateKey = KeyProvider.getPrivateKey(Sides.ENCRYPTOR);
			// Get signature for the file
			byte[] signatureBytes = SignatureProvider.signContent(content, privateKey);
			
			Key publicKey = KeyProvider.getPublicKey(Sides.ENCRYPTOR);
				
			File configurationFile = FileProvider.getSignatureConfigurationFile();
			
			try (FileOutputStream outputStream = new FileOutputStream(configurationFile)) {
				outputStream.write(signatureBytes);
			}
			
			
			File encryptedFile = FileProvider.getEncryptedFile();
			
			SecretKeyHolder secretKeyHolder = CipherProvider.writeSecureFile(encryptedFile, content);
			
			configurationFile = FileProvider.getSecretConfigurationFile();
			
			byte[] secretKeyCipher = CipherProvider.cipher(secretKeyHolder.getSecretKey().getEncoded(), publicKey);
			
			try (FileOutputStream outputStream = new FileOutputStream(configurationFile)) {
				outputStream.write(secretKeyCipher);
			}
			
			configurationFile = FileProvider.getIvConfigurationFile();
			
			byte[] ivCipher = CipherProvider.cipher(secretKeyHolder.getIv(), publicKey);
			
			try (FileOutputStream outputStream = new FileOutputStream(configurationFile)) {
				outputStream.write(ivCipher);
			}
			
			System.out.println("Encryption completed");
		} 
		catch (Exception e) {
			e.printStackTrace();
		}
	}
}
