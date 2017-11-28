package Sender;

import java.io.*;
import java.math.BigInteger;
import java.security.DigestInputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Scanner;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class Sender {

	private static final String YPUBLIC = "YPublic.key";
	private static final String AES = "symmetric.key";
	private static final String MESSAGEOUTPUT = "message.dd";
	private static final String AESENCRYPTION = "message.add-msg";
	private static final String RSAENCRYPTION = "message.rsacipher";
	private static int BUFFER_SIZE = 32 * 1024;
	static String IV = "1234567890ABCDEF";
	
	
	public static void main(String[] args) throws IOException, NoSuchAlgorithmException, NoSuchProviderException, 
												  NoSuchPaddingException, InvalidKeyException, 
												  InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
	
		SecureRandom random = new SecureRandom();
		
		//Getting the name of the message
		System.out.println("Input the name of the message: ");
		Scanner userInput = new Scanner(System.in);
		String messageName = userInput.nextLine();
		
		//Reading the YPublic Key
		ObjectInputStream yPublicFile = new ObjectInputStream( new BufferedInputStream( new FileInputStream (YPUBLIC)));
		
		BigInteger yPublicMod = null;
		try {
			yPublicMod = (BigInteger) yPublicFile.readObject();
		} catch (ClassNotFoundException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
		BigInteger yPublicExp = null;
		try {
			yPublicExp = (BigInteger) yPublicFile.readObject();
		} catch (ClassNotFoundException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
		
		RSAPublicKeySpec keySpec = new RSAPublicKeySpec(yPublicMod, yPublicExp);
		KeyFactory factory = KeyFactory.getInstance("RSA");
		PublicKey yPublic = null;
		try {
			yPublic = factory.generatePublic(keySpec);
		} catch (InvalidKeySpecException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}

		
		//Reading the Symmetric Key
		FileReader symKey = new FileReader(AES);
		BufferedReader symmetricKey = new BufferedReader(symKey);
		String aesSymmetricKey = symmetricKey.readLine();
		symmetricKey.close();
		
		//Sha Hashing.
		FileInputStream messageFile = new FileInputStream(messageName);
		BufferedInputStream theMessage = new BufferedInputStream(messageFile);
		MessageDigest md = MessageDigest.getInstance("SHA-256");
		DigestInputStream in = new DigestInputStream(theMessage, md);
		int i;
		byte[] buffer = new byte[BUFFER_SIZE];
		do {
			i = in.read(buffer, 0, BUFFER_SIZE);
		} while (i == BUFFER_SIZE);
		md = in.getMessageDigest();
		in.close();
		
		byte[] hash = md.digest();
		
		ObjectOutputStream shaHash = new ObjectOutputStream(
				new BufferedOutputStream (new FileOutputStream(MESSAGEOUTPUT)));
		for(int k=0,j=0; k<hash.length; k++, j++) {
			System.out.format("%2X", new Byte(hash[k]), "\n");
			shaHash.writeObject(hash[k]);
			shaHash.flush();
			if(j >= 15) {
				System.out.println("");
				j= -1;
			}
		}
		//AES Encryption
		Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding", "SunJCE");
		SecretKeySpec key = new SecretKeySpec(aesSymmetricKey.getBytes("UTF-8"),"AES");
		cipher.init(cipher.ENCRYPT_MODE, key, new IvParameterSpec(IV.getBytes("UTF-8")));
		FileOutputStream aesFile = new FileOutputStream(AESENCRYPTION);
		byte[] encryption = cipher.doFinal(hash);
		
		for(int k=0,j=0; k<encryption.length; k++,j++) {
			System.out.format("%2x", new Byte(encryption[k]), "\n");
			if(j >= encryption.length) {
				System.out.println("");
				j= -1;
			}
		}
		try {
			aesFile.write(cipher.doFinal(encryption));
			//aesFile.write(theMessage.read());
		} catch (IllegalBlockSizeException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (BadPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
			
		finally{
		aesFile.close();
			}
		
		//RSA Encryption
		FileInputStream aesRead = new FileInputStream(AESENCRYPTION);
		Cipher cipherRSA = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		byte[] aesShaInput = new byte[117];
		int index;
		do {
			index = aesRead.read(aesShaInput, 0, 117);
		} while (index == 117);
		
		cipherRSA.init(cipherRSA.ENCRYPT_MODE, yPublic, random);
		byte[] encryptedAes = cipherRSA.doFinal(aesShaInput);
	//	byte[] cipherText = 
	//			cipherRSA.doFinal(aesShaInput);
		ObjectOutputStream rsaCipher = 
				new ObjectOutputStream(new BufferedOutputStream ( new FileOutputStream(RSAENCRYPTION)));
			rsaCipher.writeObject(encryptedAes);
			rsaCipher.writeObject(aesShaInput);
			rsaCipher.flush();
		}
	}

