package mta.security.java.crypto;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateException;

public class SignatureProvider {

	private String signatureAlgorithm = "SHA1withDSA";
	
	private static final String PROVIDER = "SUN";
	
	

	public String getSignatureAlgorithm() {
		return signatureAlgorithm;
	}


	public void setSignatureAlgorithm(String signatureAlgorithm) {
		this.signatureAlgorithm = signatureAlgorithm;
	}


	/**
	 * 
	 * @param decodedValue
	 * @param signature
	 * @param keyProvider 
	 * @return
	 * @throws InvalidKeyException
	 * @throws KeyStoreException
	 * @throws NoSuchAlgorithmException
	 * @throws CertificateException
	 * @throws IOException
	 * @throws SignatureException
	 * @throws NoSuchProviderException 
	 */
	public boolean verify(byte[] decodedValue, byte[] signature, KeyProvider keyProvider) throws InvalidKeyException, KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException, SignatureException, NoSuchProviderException {
		Signature signatureValidator = Signature.getInstance(signatureAlgorithm, PROVIDER);
		signatureValidator.initVerify( (PublicKey) keyProvider.getPublicKey(Sides.DECRYPTOR));
		signatureValidator.update(decodedValue);
		return signatureValidator.verify(signature);		
	}


	/**
	 * Sign content using provided private key
	 * @param content
	 * @param privateKey
	 * @return
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeyException
	 * @throws SignatureException
	 * @throws NoSuchProviderException 
	 */
	public byte[] signContent(byte[] content, Key privateKey) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, NoSuchProviderException {
		byte[] signatureBytes;
		Signature signature = Signature.getInstance(signatureAlgorithm, PROVIDER);
		
		signature.initSign((PrivateKey) privateKey);
		signature.update(content);
		
		signatureBytes = signature.sign();		
		
		return signatureBytes;
	}
}
