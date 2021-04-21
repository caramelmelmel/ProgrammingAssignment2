import java.io.BufferedInputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.net.Socket;
import java.util.Scanner;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import java.util.Base64;

import java.io.*;
import java.nio.*;
import java.security.*;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.*;

public class ClientCP1 {

	public static byte[] readFromServer(DataInputStream server) throws IOException{
		int numBytes = server.readInt();
		byte [] message = new byte[numBytes];
		server.readFully(message, 0, numBytes);

		return message;
	}

	public static void sendToServer(byte[] message, DataOutputStream server) throws IOException{
		server.writeInt(message.length);
		server.write(message);
	}

	public static byte[] useCipher(byte[] message, boolean encrypt, String crpytoSystem, Key key) throws Exception{
		Cipher cipher = Cipher.getInstance(crpytoSystem);
		if (encrypt) cipher.init(Cipher.ENCRYPT_MODE, key);
		else cipher.init(Cipher.DECRYPT_MODE, key);

		return cipher.doFinal(message);
	}

	public static Cipher initCipher(String crpytoSystem, boolean encrypt, Key key) throws Exception {
		Cipher cipher = Cipher.getInstance(crpytoSystem);
		if (encrypt) cipher.init(Cipher.ENCRYPT_MODE, key);
		else cipher.init(Cipher.DECRYPT_MODE, key);

		return cipher;
	}

	public static byte[] generateNonce(){
		byte[] nonce = new byte[32];
		SecureRandom random = new SecureRandom();
		random.nextBytes(nonce);
		return nonce;
	}

	public static void main(String[] args) {
		/**
		 *  INITIALIZE VARIABLES
		 */
		int numBytes = 0;
		int port = 4321;

		Socket clientSocket = null;

		DataOutputStream toServer = null;
		DataInputStream fromServer = null;

		FileInputStream fileInputStream = null;
		BufferedInputStream bufferedFileInputStream = null;

		long timeStarted;
		String filename;
		String serverAddress = "localhost";

		/**
		 *  BEGIN AUTHENTICATION PROTOCOL (AP)
		 */

		try {

			// Connect to server and get the input and output streams
			System.out.println("Establishing connection to server...");

			clientSocket = new Socket(serverAddress, port);
			toServer = new DataOutputStream(clientSocket.getOutputStream());
			fromServer = new DataInputStream(clientSocket.getInputStream());

			// Send initial message to SecStore
			// Client contacts Server to sign the message using its private key and send it back to Client

			//**NOTE: message string is replaced with a nonce
			final byte[] nonce = generateNonce();
			sendToServer(nonce, toServer);
			System.out.println("Nonce Sent to Server");


			//   Receive encrypted message from server
			byte[] encryptedNonce = readFromServer(fromServer);

			// System.out.println(Base64.getEncoder().encodeToString(encryptedMessage));

			//receiving certificate from server
			byte[] encryptedCert = readFromServer(fromServer);
			System.out.println("Received Certificate from Server");
			// System.out.println(Base64.getEncoder().encodeToString(encryptedCert));

			//   Obtain public key of server
			// Client decrypts signed certificate from Server using CA's public key, and stores it as the server's public key
			InputStream fis = new FileInputStream("cacsertificate.crt");
			CertificateFactory cf = CertificateFactory.getInstance("X.509");
			X509Certificate CAcert =(X509Certificate)cf.generateCertificate(fis);
			PublicKey CAPubKey = CAcert.getPublicKey();


			// //Verifies that the signed certificate is actually from the CA
			InputStream signedCertStream = new ByteArrayInputStream(encryptedCert);
			CertificateFactory cf2 = CertificateFactory.getInstance("X.509");
			X509Certificate ServerCert = (X509Certificate)cf2.generateCertificate(signedCertStream);
			ServerCert.checkValidity();
			ServerCert.verify(CAPubKey);

			System.out.println("Verified Signed Certificate from Server");

			//  Decrypt message using server public key
			// Check that previously received msg from server is correct by decrypting it and matching with initial message
			// Postcondition: Returns false if message does not match, true if it does
			System.out.println("Decrypting Nonce and verifying server");

			// Get Server's Pub Key
			PublicKey ServerPubKey = ServerCert.getPublicKey();

			// Decrypt message from server using pub key
			byte[] decryptedNonce = useCipher(encryptedNonce, false, "RSA", ServerPubKey);

			//if (!message.equals(receivedMessage)){
			if (!Arrays.equals(nonce, decryptedNonce)){
				throw new Exception("Sorry we don't talk to strangers here");
			}

			System.out.println("Server Verified!");

			// Init RSA encryption cypher with server pub key
			Cipher cipherCP1 = initCipher("RSA", true, ServerPubKey);

			/**
			 *  START OF FILE SENDING PROTOCOL
			 */

			Scanner sc = new Scanner(System.in);

			// Begin loop to get user input and upload file
			while(true) {
				System.out.println("Enter File (EXIT to exit): ");

				filename = sc.nextLine(); // read a string from input

				// Check if text is 'Exit'
				if (filename.equalsIgnoreCase("exit")){
					toServer.writeInt(2);
					toServer.flush();
					break;
				}

				try {
					// Check if input is valid
					fileInputStream = new FileInputStream(filename);
				} catch (FileNotFoundException e) {
					System.out.println("File not found!");
					continue;
				}

				System.out.println("Sending file...");
				bufferedFileInputStream = new BufferedInputStream(fileInputStream);

				timeStarted = System.nanoTime(); // Begin logging time for sending file

				// BEGIN SENDING FILE
				//encrypt and send filename
				toServer.writeInt(0);
				byte [] filenameCP1 = cipherCP1.doFinal(filename.getBytes());
				toServer.writeInt(filenameCP1.length);
				toServer.write(filenameCP1);
				toServer.flush();

				byte [] fromFileBuffer = new byte[117];
				// Send the file
				for (boolean fileEnded = false; !fileEnded;) {
					numBytes = bufferedFileInputStream.read(fromFileBuffer);
					fileEnded = numBytes < 117;
					// System.out.println(i++);
					// System.out.println("bytes read: " + numBytes);


					//encrypt and send 117bytes-long block of file data with server public key
					toServer.writeInt(1);
					byte [] fromFileBufferCP1 = cipherCP1.doFinal(fromFileBuffer);

					// System.out.println("bytes encrypted: " + fromFileBufferCP1.length);

					toServer.writeInt(numBytes);
					toServer.write(fromFileBufferCP1);
					toServer.flush();
				}

				// Record time taken for file to send
				long timeTaken = System.nanoTime() - timeStarted;
				System.out.println("File took " + timeTaken/1000000.0 + "ms to send");

				// Close file streams
				bufferedFileInputStream.close();
				fileInputStream.close();

				System.out.println("Closing File connection...");
			}


			System.out.println("Close all connections and scanner");

			// Close scanner
			sc.close();

			// Close sockets (commenting this out fixes the race condition but leads to an fd leak. it do be like that sometimes)
			toServer.close();
			fromServer.close();
			clientSocket.close();

		} catch (Exception e) {
			e.printStackTrace();
		}
	}
}
