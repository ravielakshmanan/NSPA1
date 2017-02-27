package com.ns.crypto;

import java.io.File;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base64;

import com.ns.fileutil.FileOperations;

public class EncryptUtil {
	
	//Method that performs the AES encryption in AES/CBC mode
	public static File encrypt(String key, String initVector, byte[] inputFileStream) {
        try {
        	//Set the initialization vector
            IvParameterSpec iv = new IvParameterSpec(initVector.getBytes("UTF-8"));
            
            //Set the secret key specification to AES
            SecretKeySpec skeySpec = new SecretKeySpec(key.getBytes("UTF-8"), "AES");

            //Initialize a cipher instance in AES?CBC mode
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
            cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv);

            //Generate the cipher text
            byte[] encrypted = cipher.doFinal(inputFileStream);
            System.out.println("encrypted string: " + Base64.encodeBase64String(encrypted));
            
            //Write the contents to a file and return it
            File encryptedFile = new File("document.encrypted");
            
            encryptedFile = FileOperations.writeFile(encryptedFile, encrypted);

            return encryptedFile;
        } catch (Exception ex) {
            ex.printStackTrace();
        }

        return null;
    }
}
