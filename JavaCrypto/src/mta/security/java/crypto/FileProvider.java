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
	private static final String FLAT_FILE_PATH = "/message.txt";
	private final static String SECRET_FILE_PATH = FileProvider.class.getResource("/").getPath() + "/secret.txt";

	/**
	 * Get the encrypted file
	 * @return
	 */
	static File getEncryptedFile() {
		File file = new File(FileProvider.class.getResource("/").getPath() + "/encodedMessage.txt");
		return file;
	}
	
	/**
	 * Get the configuration file
	 * @return
	 */
	static File getSignatureConfigurationFile() {
		File file = new File(FileProvider.class.getResource("/").getPath() + "/signature.txt");
		
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
		return getFile(FLAT_FILE_PATH);
	}
	
	public static byte[] getSecretFileAsBytes() throws URISyntaxException, IOException {
		
		return getFile("/secret.txt");
	}
	
	public static byte[] getEncryptedFileAsBytes() throws URISyntaxException, IOException {
		
		return getFile("/encodedMessage.txt");
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
		return content;
	}
}
