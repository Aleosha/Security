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

	private static final String SIGNATURE_ALGORITHM = "SHA1withDSA";
	
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
	 */
	public static boolean verify(byte[] decodedValue, byte[] signature, KeyProvider keyProvider) throws InvalidKeyException, KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException, SignatureException {
		Signature signatureValidator = Signature.getInstance(SIGNATURE_ALGORITHM);
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
	public static byte[] signContent(byte[] content, Key privateKey) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, NoSuchProviderException {
		byte[] signatureBytes;
		Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
		
		signature.initSign((PrivateKey) privateKey);
		signature.update(content);
		
		signatureBytes = signature.sign();		
		
		return signatureBytes;
	}
}
