package mta.security.java.crypto;

import javax.crypto.SecretKey;

public class SecretKeyHolder {

	private SecretKey secretKey;
	private byte[] iv;

	public SecretKeyHolder(SecretKey secretKey, byte[] iv) {
		this.setSecretKey(secretKey);
		this.setIv(iv);
	}

	public SecretKey getSecretKey() {
		return secretKey;
	}

	public void setSecretKey(SecretKey secretKey) {
		this.secretKey = secretKey;
	}

	public byte[] getIv() {
		return iv;
	}

	public void setIv(byte[] iv) {
		this.iv = iv;
	}

}
