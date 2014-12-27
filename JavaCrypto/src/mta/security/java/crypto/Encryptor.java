package mta.security.java.crypto;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Paths;


public class Encryptor {

	public static void main(String[] args) {
		
		
		try {
			// Read flat file
			URL messageAsResource = Encryptor.class.getResource("/message.txt");
			URI uri = messageAsResource.toURI();
			byte[] content = Files.readAllBytes(Paths.get(uri));
			System.out.println("The message to encrypt is:" + new String(content));
			
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (URISyntaxException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

}
