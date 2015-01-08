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

	public static void main(String[] args) {
		try {
			
			if (args.length == 0) {
				throw new IllegalArgumentException("Keystore password not provided");
			}
			
			byte[] encryptedSecretKey = FileProvider.getSecretFileAsBytes();
			KeyProvider keyProvider = new KeyProvider();
			keyProvider.setDecryptorKeystorePassword(args[0]);
			Key privateKey = keyProvider.getPrivateKey(Sides.DECRYPTOR);
			CipherProvider cipherProvider = new CipherProvider();
			List<String> algorithmConfiguration = Files.readAllLines(FileProvider.getAlgorithmFile().toPath(), Charset.defaultCharset());
			
			if (algorithmConfiguration.size() != 4) {
				throw new IllegalArgumentException("Wrong number of algorithm parameters");
			}
			
			cipherProvider.setAsymmetricAlgorithm(algorithmConfiguration.get(0));
			cipherProvider.setSymmetricAlgorithm(algorithmConfiguration.get(1));
			cipherProvider.setSymmetricAlgorithmMode(algorithmConfiguration.get(2));
			cipherProvider.setSymmetricAlgorithmPadding(algorithmConfiguration.get(3));
			
			byte[] decryptedSecretKey = cipherProvider.decipher(encryptedSecretKey, privateKey);
			
			byte[] encryptedFile = FileProvider.getEncryptedFileAsBytes();
			byte[] iv = FileProvider.getIv();
			//iv = CipherProvider.decipher(iv, privateKey);
							
	        byte[] decValue = cipherProvider.decipher(encryptedFile, decryptedSecretKey, iv);
			String decryptedValue = new String(decValue );
			
			System.out.println("Decrypted message is:" + decryptedValue);
			
			try (FileOutputStream outputStream = new FileOutputStream(FileProvider.getDecryptedFile())) {
				outputStream.write(decryptedValue.getBytes());
			}
			
			byte[] signature = FileProvider.getSignatureFileAsBytes();

			
			if (SignatureProvider.verify(decValue, signature, keyProvider)) {
				System.out.println("Signature is valid");
			}
			else {
				System.out.println("Invalid signature");
			}
		} catch (URISyntaxException | IOException | UnrecoverableKeyException | 
				KeyStoreException | NoSuchAlgorithmException | CertificateException | 
				InvalidKeyException | NoSuchPaddingException | IllegalBlockSizeException | 
				BadPaddingException | NoSuchProviderException | SignatureException | InvalidAlgorithmParameterException e1) {
			e1.printStackTrace();
		}
	}
}
