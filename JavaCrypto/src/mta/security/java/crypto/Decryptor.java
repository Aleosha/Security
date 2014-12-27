package mta.security.java.crypto;

import java.io.File;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;

public class Decryptor {

	public static void main(String[] args) {
		File ecryptedFile = FileProvider.getEncryptedFile();
		
		try {
			Cipher cipher = Cipher.getInstance("AES");
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} 
	//	cipher.init(Cipher.DECRYPT_MODE, key);
	//	byte[] stringBytes = cipher.doFinal(raw);
	}

}
