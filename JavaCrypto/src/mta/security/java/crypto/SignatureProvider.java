package mta.security.java.crypto;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateException;

public class SignatureProvider {

	public static boolean verify(byte[] decValue, byte[] signature) throws InvalidKeyException, KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException, SignatureException {
		Signature signatureValidator = Signature.getInstance("SHA1withDSA");
		signatureValidator.initVerify( (PublicKey) KeyProvider.getPublicKey(Sides.DECRYPTOR));
		signatureValidator.update(decValue);
		return signatureValidator.verify(signature);		
	}
}
