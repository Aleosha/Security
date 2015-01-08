Submitters:
Victor Bronov	324637925
Alexey Soshin	314264185

Created using Java 7 and Eclipse Luna

Considerations for choosing provider:
	Does provider supply such implementation
	Does provider implementation has received federal certification
	
	
Please run commands specified in the commands.txt before executing the programs.
	
The project is divided into two main applications: Encryptor and Decryptor
Encryptor receives full path to file as it's only argument and outputs in into \bin\encodedMessage.txt
If no argument is provided, it will use \resources\plaintext.txt file as an example
In addition to encodedMessage.txt two more files are created in the same directory:
1. signature.txt - contains the signature for the message
2. iv.txt - contains crypted IV
3. secret.txt - contains crypted secret key for the message

Decryptor reads decrypted.txt, secret.txt and signature.txt from the \bin directory, and outputs:
1. The decoded message
2. Whether the signature on the file is valid or not