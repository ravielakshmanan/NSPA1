package com.ns.message;

import java.io.File;
import java.io.Serializable;

public class MessageContent implements Serializable {
	
	private static final long serialVersionUID = 1L;
	private String key;
	private byte[] initVector;
	private File encryptedFile;
	private String hashValue;
	private byte[] encryptedHashValue;
	private byte[] encryptedPassword;
	private String message;
	
	public String getKey() {
		return key;
	}
	
	//Method to set the key
	public void setKey(String key) {
		this.key = key;
	}
	
	//Method to get the Initialization Vector
	public byte[] getInitVector() {
		return initVector;
	}
	
	//Method to set the Initialization Vector
	public void setInitVector(byte[] initVector) {
		this.initVector = initVector;
	}
	
	//Method to get the Encrypted File
	public File getEncryptedFile() {
		return encryptedFile;
	}
	
	//Method to SET the Encrypted File
	public void setEncryptedFile(File encryptedFile) {
		this.encryptedFile = encryptedFile;
	}
	
	//Method to get the Hash Value
	public String getHashValue() {
		return hashValue;
	}
	
	//Method to set the Hash Value
	public void setHashValue(String hashValue) {
		this.hashValue = hashValue;
	}
	
	//Method to get the Encrypted Hash Value
	public byte[] getEncryptedHashValue() {
		return encryptedHashValue;
	}
	
	//Method to set the Encrypted Hash Value
	public void setEncryptedHashValue(byte[] encryptedHashValue) {
		this.encryptedHashValue = encryptedHashValue;
	}
	
	//Method to get the Encrypted Password
	public byte[] getEncryptedPassword() {
		return encryptedPassword;
	}
	
	//Method to set the Encrypted Password
	public void setEncryptedPassword(byte[] encryptedPassword) {
		this.encryptedPassword = encryptedPassword;
	}
	
	//Method to get the Message Status
	public String getMessage() {
		return message;
	}
	
	//Method to set the Message Status
	public void setMessage(String message) {
		this.message = message;
	}
}
