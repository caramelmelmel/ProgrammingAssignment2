import java.io.BufferedOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.*;

public class ServerCP2 {
    public static PrivateKey getPrivateKey(String filename) throws Exception {

        byte[] keyBytes = Files.readAllBytes(Paths.get(filename));

        PKCS8EncodedKeySpec spec =
                new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePrivate(spec);
    }

    public static PublicKey getPublicKey(String filename) throws Exception {

        byte[] keyBytes = Files.readAllBytes(Paths.get(filename));

        X509EncodedKeySpec spec =
                new X509EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePublic(spec);
    }

    public static byte[] readFromClient(DataInputStream client) throws IOException{
        int numBytes = client.readInt();
        byte [] message = new byte[numBytes];
        client.readFully(message, 0, numBytes);

        return message;
    }

    public static void sendToClient(byte[] message, DataOutputStream client) throws IOException{
        client.writeInt(message.length);
        client.write(message);
    }

    public static byte[] readEncryptedFromClient(Cipher cipher, DataInputStream client) throws Exception{
        int numBytes = client.readInt();

        byte [] encryptedMessage = new byte[128];
        client.readFully(encryptedMessage, 0, 128);

        byte [] decryptedMessage = new byte[numBytes];
        decryptedMessage = cipher.doFinal(encryptedMessage);

        return decryptedMessage;
    }

    public static Cipher initCipher(String crpytoSystem, boolean encrypt, Key key) throws Exception {
        Cipher cipher = Cipher.getInstance(crpytoSystem);
        if (encrypt) cipher.init(Cipher.ENCRYPT_MODE, key);
        else cipher.init(Cipher.DECRYPT_MODE, key);

        return cipher;
    }

    public static void main(String[] args) {
        /**
         *  INITIALIZE VARIABLES
         */

        int port = 4321;
        // if (args.length > 0) port = Integer.parseInt(args[0]);

        ServerSocket welcomeSocket = null;
        Socket connectionSocket = null;
        DataOutputStream toClient = null;
        DataInputStream fromClient = null;

        FileOutputStream fileOutputStream = null;
        BufferedOutputStream bufferedFileOutputStream = null;
        PrivateKey privatekey = null;

        byte[] decryptedSessionKey = null;
        SecretKey seshKey = null;

        Cipher RSAdecryptcipher = null;
        Cipher RSAencryptcipher = null;
        Cipher seshKeyCipher = null;

        int numBytes = 0;

        // READ PRIVATE AND PUBLIC KEY
        try {
            privatekey = ServerCP2.getPrivateKey("private_key.der");
            // publickey = ServerWithSecurity.getPublicKey("public_key.der");
        } catch (Exception e) {
            System.out.println("Failed to read Public or Private Key");
            e.printStackTrace();
        }

        /**
         *  BEGIN AUTHENTICATION PROTOCOL (AP)
         */

        try {
            System.out.println("Initializing Server");

            // Create Server, init input and output stream
            welcomeSocket = new ServerSocket(port);
            connectionSocket = welcomeSocket.accept();
            fromClient = new DataInputStream(connectionSocket.getInputStream());
            toClient = new DataOutputStream(connectionSocket.getOutputStream());

            // Init RSAcypher
            RSAdecryptcipher = initCipher("RSA", false, privatekey);
            RSAencryptcipher = initCipher("RSA", true, privatekey);

            // Prove server identity
            // Server receives hello message from client, sends back same message encrypted with server's private key

            byte[] nonce = readFromClient(fromClient);
            // System.out.println(decryptedMessage);
            // System.out.println(Base64.getEncoder().encodeToString(helloMessage));

            // Encrypt Message
            System.out.println("Encrypting Nonce");

            byte[] encryptedNonce = RSAencryptcipher.doFinal(nonce);

            // Send Encrypted message back to client
            sendToClient(encryptedNonce, toClient);
            System.out.println("Sent Encrypted Nonce back to Client");

            // TODO: Send SecStore's signed Certificate
            // Server receives Client's request for its Certificate, and sends back Certificate from CA

            InputStream cert = new FileInputStream("certificate_1004589.crt");
            byte[] certAsBytes = new byte[cert.available()];
            cert.read(certAsBytes);

            // Send byte array to client
            sendToClient(certAsBytes, toClient);
            System.out.println("Sent Server's CA to Client");

            // FOR CP2 PROTOCOL, ACCEPT SESSION KEY AND DECRYPT IT
            System.out.println("Using CP2");

            decryptedSessionKey = readEncryptedFromClient(RSAdecryptcipher, fromClient);

            // System.out.println(new String(decryptedSessionKey));

            // Saving the key into a SecretKey
            seshKey = new SecretKeySpec(decryptedSessionKey, 0, decryptedSessionKey.length, "AES");
            seshKeyCipher = initCipher("AES", false, seshKey);

            /**
             *  START OF FILE RECEIVING PROTOCOL
             */

            // After authenticating, begin waiting for input
            while (!connectionSocket.isClosed()) {
                int packetType = fromClient.readInt();

                if (packetType == 2) {
                    // Received Exit packet from client
                    System.out.println("Closing sockets");

                    fromClient.close();
                    toClient.close();
                    connectionSocket.close();
                    cert.close();
                    break;

                }

                // If the packet is for transferring the filename
                if (packetType == 0) {

                    System.out.println("Receiving file...");

                    numBytes = fromClient.readInt();
                    byte [] encryptedfilename = new byte[numBytes];
                    fromClient.readFully(encryptedfilename, 0, numBytes);

                    byte[] filename = seshKeyCipher.doFinal(encryptedfilename);

                    fileOutputStream = new FileOutputStream("recv_"+new String(filename));
                    bufferedFileOutputStream = new BufferedOutputStream(fileOutputStream);

                    // If the packet is for transferring a chunk of the file
                } else if (packetType == 1) {

                    numBytes = fromClient.readInt();
                    byte [] encryptedBlock = new byte[128];
                    fromClient.readFully(encryptedBlock, 0, 128);

                    byte[] block = new byte[numBytes];
                    block = seshKeyCipher.doFinal(encryptedBlock);
                    // System.out.println(numBytes);

                    if (numBytes > 0){
                        // System.out.println(i++);
                        bufferedFileOutputStream.write(block, 0, numBytes);
                    }

                    if (numBytes < 117) {
                        System.out.println("Closing File connection...");

                        if (bufferedFileOutputStream != null) bufferedFileOutputStream.close();
                        if (bufferedFileOutputStream != null) fileOutputStream.close();

                    }
                }
            }



        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
