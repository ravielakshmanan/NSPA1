package com.ns.clientserver;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.Socket;
import java.security.PrivateKey;
import java.security.PublicKey;

import com.ns.crypto.*;
import com.ns.fileutil.*;
import com.ns.message.*;

public class FileClient{
	private static Socket clientSocket;
	
	private static MessageContent performCryptoOperations(String key, String initVector, String inputFileName){
		MessageContent message = new MessageContent();
		
		try{
			//Read the input file
        	File inputFile = new File(inputFileName);
        	
        	//Perform the AES encryption
        	File encryptedFile = EncryptUtil.encrypt(key, initVector, FileOperations.readFile(inputFile));
        	
        	//Sign the file with SHA-256
        	String hashValue = HashUtil.signFileWithSHA256Hash(inputFile);
        	
        	//Generate the key pair
        	if (!CryptoKeyUtil.areKeysPresent()) {
        		CryptoKeyUtil.setKeyFiles("client");
        		CryptoKeyUtil.generateKeyPair();
        	}
        	
        	//Generate the hash using the client's private key
        	ObjectInputStream clientInputStream = new ObjectInputStream(new FileInputStream(CryptoKeyUtil.PRIVATE_KEY_FILE));
        	final PrivateKey privateKey = (PrivateKey) clientInputStream.readObject();
            final byte[] cipherText = CryptoKeyUtil.encryptHashWithRSA(hashValue, privateKey);
            clientInputStream.close();
            
            //Encrypt the password and the initialization vector using the server's public key
            CryptoKeyUtil.setKeyFiles("server");
            ObjectInputStream serverInputStream = new ObjectInputStream(new FileInputStream(CryptoKeyUtil.PUBLIC_KEY_FILE));
            final PublicKey serverPublicKey = (PublicKey) serverInputStream.readObject();
            final byte[] passwordCipherText = CryptoKeyUtil.encryptHashWithRSAPub(key, serverPublicKey);
            final byte[] initVectorCipherText = CryptoKeyUtil.encryptHashWithRSAPub(initVector, serverPublicKey);
            serverInputStream.close();
            
            //Set the message with appropriate values
            message.setEncryptedFile(encryptedFile);
            message.setHashValue(hashValue);
            message.setEncryptedHashValue(cipherText);
            message.setEncryptedPassword(passwordCipherText);
            message.setInitVector(initVectorCipherText);
        	
        } catch (Exception ex) {
            ex.printStackTrace();
        }
		
		//return the message object
		return message;
		
	}
 
    public static void main(String args[]){
    	OutputStream os = null;
    	
        try{
            //Accept inputs
        	String serverName = args[0]; //"localhost" - server name
            int port = Integer.parseInt(args[1]); //2500 - port number
            String key = args[2]; //"Bar12345Bar12345" - 128 bit key
            String initVector = args[3]; //"RandomInitVector" - 16 bytes IV
            String inputFileName = args[4]; //path to input file
            
            if((key.length() != 16)||(initVector.length() != 16)){
            	System.out.println("Length of the key or initialization vector not 16 bytes");
            	System.exit(1);
            }
            	

            InetAddress address = InetAddress.getByName(serverName);
            clientSocket = new Socket(address, port);
            
            System.out.println("Just connected to " + clientSocket.getRemoteSocketAddress());
            
            //Send the message to the server
            os = clientSocket.getOutputStream();
            ObjectOutputStream objOutput = new ObjectOutputStream(os);
            
            MessageContent message = performCryptoOperations(key, initVector, inputFileName);
            objOutput.writeObject(message);
            
            //objOutput.close();
 
            System.out.println("Message sent to the server...");
 
            //Get the return message from the server
            InputStream is = clientSocket.getInputStream();
            ObjectInputStream objInput = new ObjectInputStream(is);
            
            MessageContent messageFromServer = (MessageContent)objInput.readObject();
            
            System.out.println("Message received from the server : " + messageFromServer.getMessage());
        }
        catch (Exception exception){
            exception.printStackTrace();
        }
        finally{
            //Closing the socket
            try{
            	clientSocket.close();
            }catch(Exception e){
                e.printStackTrace();
            }
        }
    }
}