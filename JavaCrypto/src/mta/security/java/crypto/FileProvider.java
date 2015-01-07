package mta.security.java.crypto;

import java.io.File;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Paths;

public class FileProvider {
	

	// Path to the file we're encoding
	private static final String FLAT_FILE_NAME = "/message.txt";
	private final static String SECRET_FILE_NAME = "/secret.txt";
	private static final String ENCODED_FILE_NAME = "/encodedMessage.txt";
	private static final String SIGNATURE_FILE_NAME = "/signature.txt";
	private static final String IV_FILE = "/iv.txt";
	
	private final static String SECRET_FILE_PATH = FileProvider.class.getResource("/").getPath() + SECRET_FILE_NAME;	

	/**
	 * Get the encrypted file
	 * @return
	 */
	static File getEncryptedFile() {
		File file = new File(FileProvider.class.getResource("/").getPath() + ENCODED_FILE_NAME);
		return file;
	}
	
	/**
	 * Get the configuration file
	 * @return
	 */
	static File getSignatureConfigurationFile() {
		File file = new File(FileProvider.class.getResource("/").getPath() + SIGNATURE_FILE_NAME);
		
		return file;
	}
	
	static File getSecretConfigurationFile() {
		File file = new File(SECRET_FILE_PATH);
		
		return file;
	}

	/**
	 * Get the original (not encrypted) file
	 * @return
	 * @throws URISyntaxException
	 * @throws IOException
	 */
	public static byte[] getFlatFileAsBytes() throws URISyntaxException, IOException {
		return getFile(FLAT_FILE_NAME);
	}
	
	public static byte[] getSecretFileAsBytes() throws URISyntaxException, IOException {
		
		return getFile(SECRET_FILE_NAME);
	}
	
	public static byte[] getEncryptedFileAsBytes() throws URISyntaxException, IOException {
		
		return getFile(ENCODED_FILE_NAME);
	}
	
	public static byte[] getFile(String path) throws URISyntaxException, IOException
	{
		byte[] content = null;
		// Read flat file into byte array
		URL messageAsResource = Encryptor.class.getResource(path);
		
		if (messageAsResource != null) {
			URI uri = messageAsResource.toURI();
			content = Files.readAllBytes(Paths.get(uri));
		}
		else {
			content = Files.readAllBytes(Paths.get(path));
		}
		return content;
	}

	public static byte[] getSignatureFileAsBytes() throws URISyntaxException, IOException {
		return getFile(SIGNATURE_FILE_NAME);
	}

	public static byte[] getIv() throws URISyntaxException, IOException {
		return getFile(IV_FILE);
	}

	public static File getIvConfigurationFile() {
		File file = new File(FileProvider.class.getResource("/").getPath() + IV_FILE);
		
		return file;
	}
}
