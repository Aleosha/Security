package mta.security.java.crypto;

import java.io.IOException;
import java.net.URISyntaxException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class Decryptor {

	public static void main(String[] args) {
		try {
			byte[] encryptedSecretKey = FileProvider.getSecretFileAsBytes();
			Key privateKey = KeyProvider.getPrivateKey(Sides.DECRYPTOR);
			byte[] decryptedSecretKey = CipherProvider.decipher(encryptedSecretKey, privateKey);
			
			byte[] encryptedFile = FileProvider.getEncryptedFileAsBytes();
			byte[] iv = FileProvider.getIv();
			iv = CipherProvider.decipher(iv, privateKey);
							
	        byte[] decValue = CipherProvider.decipher(encryptedFile, decryptedSecretKey, iv);
			String decryptedValue = new String(decValue );
			
			System.out.println("Decrypted message is:" + decryptedValue);
			byte[] signature = FileProvider.getSignatureFileAsBytes();

			
			if (SignatureProvider.verify(decValue, signature)) {
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
