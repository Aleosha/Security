package mta.security.java.crypto;

import java.security.SecureRandom;

import javax.crypto.SecretKey;

public class SecretKeyHolder {

	private SecretKey secretKey;
	private SecureRandom secureRandom;
	private byte[] iv;

	public SecretKeyHolder(SecretKey secretKey, SecureRandom secureRandom, byte[] iv) {
		this.setSecretKey(secretKey);
		this.setSecureRandom(secureRandom);
		this.setIv(iv);
	}

	public SecretKey getSecretKey() {
		return secretKey;
	}

	public void setSecretKey(SecretKey secretKey) {
		this.secretKey = secretKey;
	}

	public SecureRandom getSecureRandom() {
		return secureRandom;
	}

	public void setSecureRandom(SecureRandom secureRandom) {
		this.secureRandom = secureRandom;
	}

	public byte[] getIv() {
		return iv;
	}

	public void setIv(byte[] iv) {
		this.iv = iv;
	}

}
