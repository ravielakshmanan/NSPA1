package com.ns.crypto;

import java.io.File;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import com.ns.fileutil.FileOperations;

public class DecryptUtil {
	
	//Method that performs the AES decryption in AES/CBC mode
	public static String decrypt(String key, String initVector, File encryptedFile) {
        try {
            
        	IvParameterSpec iv = new IvParameterSpec(initVector.getBytes("UTF-8"));
            SecretKeySpec skeySpec = new SecretKeySpec(key.getBytes("UTF-8"), "AES");

            //Get an instance of the cipher passing in the mode
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
            cipher.init(Cipher.DECRYPT_MODE, skeySpec, iv);
            
            //Read the encrypted file to generate the byte array
            byte[] encryptedFileStream = FileOperations.readFile(encryptedFile);

            //Generate the plain text
            byte[] originalPlainText = cipher.doFinal(encryptedFileStream);

            //Return the original plain text
            return new String(originalPlainText);
        
        } catch (Exception ex) {
            ex.printStackTrace();
        }

        return null;
    }
}
