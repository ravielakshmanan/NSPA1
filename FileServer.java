package com.ns.clientserver;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.io.Writer;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Objects;

import org.apache.commons.io.FileUtils;

import com.ns.crypto.CryptoKeyUtil;
import com.ns.crypto.DecryptUtil;
import com.ns.crypto.EncryptUtil;
import com.ns.crypto.HashUtil;
import com.ns.fileutil.FileOperations;
import com.ns.message.MessageContent;
 
public class FileServer extends Thread{
	private static Socket socket;
    private static ServerSocket serverSocket;
    
    public FileServer(int port) throws IOException {
    	serverSocket = new ServerSocket(port);
        System.out.println("Server Started and listening to the port " + port);
     }
    
    public void run() {
    	try{
        	//Server is set to running
            while(true){
            	if (!CryptoKeyUtil.areKeysPresent()) {
                	CryptoKeyUtil.setKeyFiles("server");
            		CryptoKeyUtil.generateKeyPair();
            	}
            	
                //Reading the message from the client
                socket = serverSocket.accept();
                InputStream is = socket.getInputStream();
                ObjectInputStream objInput = new ObjectInputStream(is);
                String messageStatus = "No Response";
                
                MessageContent messageFromClient = (MessageContent)objInput.readObject();
                
                byte[] initVector = messageFromClient.getInitVector();
                File encryptedFile = messageFromClient.getEncryptedFile();
                byte[] encryptedHashValue = messageFromClient.getEncryptedHashValue();
                byte[] encryptedPassword = messageFromClient.getEncryptedPassword();
                
                //Decrypt the signature using the client's public key
                CryptoKeyUtil.setKeyFiles("client");
                ObjectInputStream clientKeyInputStream = new ObjectInputStream(new FileInputStream(CryptoKeyUtil.PUBLIC_KEY_FILE));
                final PublicKey publicKey = (PublicKey) clientKeyInputStream.readObject();
                final String plainTextHash = CryptoKeyUtil.decryptHashWithRSA(encryptedHashValue, publicKey);
                clientKeyInputStream.close();
                
                //Decrypt the encrypted password and the initialization vector using the server's private key
                CryptoKeyUtil.setKeyFiles("server");
                ObjectInputStream serverKeyInputStream = new ObjectInputStream(new FileInputStream(CryptoKeyUtil.PRIVATE_KEY_FILE));
            	final PrivateKey privateKey = (PrivateKey) serverKeyInputStream.readObject();
                final String plainTextPassword = CryptoKeyUtil.decryptHashWithRSAPvt(encryptedPassword, privateKey);
                final String plainTextInitVector = CryptoKeyUtil.decryptHashWithRSAPvt(initVector, privateKey);
                serverKeyInputStream.close();
                
                String plainText = DecryptUtil.decrypt(plainTextPassword, plainTextInitVector, encryptedFile );
                System.out.println(plainText);
                //Save a copy of the received file to the server in the same format
                File decryptedFile = new File("decryptedfile");
                Writer output = new BufferedWriter(new FileWriter(decryptedFile));
                output.write(plainText);
                output.close();
                
                //Encrypt the received file
                File serverEncryptedFile = EncryptUtil.encrypt(plainTextPassword, plainTextInitVector, 
                								FileOperations.readFile(decryptedFile));
                
                //Calculate the hash of the decrypted file
                String serverHashValue = HashUtil.signFileWithSHA256Hash(decryptedFile);
                
                //Set the message status depending on the result of the values compared
                if( Objects.equals(serverHashValue, plainTextHash) && FileUtils.contentEquals(serverEncryptedFile, encryptedFile))
                	messageStatus = "Authentication Successful";
                else
                	messageStatus = "Verification Failed";
                
                //Sending the response back to the client.
                OutputStream os = socket.getOutputStream();
                ObjectOutputStream objOutput = new ObjectOutputStream(os);
                
                //Create a MessageContent object to pass back the message
                MessageContent messageToClient = new MessageContent();
                messageToClient.setMessage(messageStatus);
                objOutput.writeObject(messageToClient);
            }
        }catch (Exception e){
            e.printStackTrace();
        }
        finally{
            try{
                socket.close();
            }catch(Exception e){}
        }
    }
 
    public static void main(String[] args)
    {
    	//Accept the port number as inputs
    	int port = Integer.parseInt(args[0]);
    	
    	try {
    		//Invoke an instance of the server by passing the port
            Thread t = new FileServer(port);
            t.start();
            
        }catch(IOException e) {
        	e.printStackTrace();
         }
    }
}