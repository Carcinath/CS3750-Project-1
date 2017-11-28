package Reciever;

import java.io.*;
import java.math.BigInteger;
import java.nio.Buffer;
import java.security.DigestInputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Scanner;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class Reciever {

	private static final String RSACIPHER = "message.rsacipher";
	private static final String YPRIVATE = "YPrivate.key";
	private static final String AES = "symmetric.key";
	private static final String SHAHASH = "message.dd";
	private static final String RSADECRYPT = "message.add-msg";
	private static int BUFFER_SIZE = 32*1024;
	static String IV = "1234567890ABCDEF";

	
	public static void main(String[] args) throws IOException, NoSuchAlgorithmException, 
	InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, 
	BadPaddingException, NoSuchProviderException, InvalidAlgorithmParameterException {
	
		// TODO Auto-generated method stub
		SecureRandom random = new SecureRandom();
		
		//Getting the name of the message
		System.out.println("Input the name of the message: ");
		Scanner userInput = new Scanner(System.in);
		String messageName = userInput.nextLine();
		
		//Reading the YPrivate Key
		ObjectInputStream yPrivateFile = new ObjectInputStream( new BufferedInputStream( new FileInputStream (YPRIVATE)));
		
		BigInteger yPrivateMod = null;
		try {
			yPrivateMod = (BigInteger) yPrivateFile.readObject();
		} catch (ClassNotFoundException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
		BigInteger yPrivateExp = null;
		try {
			yPrivateExp = (BigInteger) yPrivateFile.readObject();
		} catch (ClassNotFoundException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
		
		RSAPrivateKeySpec keySpec = new RSAPrivateKeySpec(yPrivateMod, yPrivateExp);
		KeyFactory factory = KeyFactory.getInstance("RSA");
		PrivateKey yPrivate = null;
		try {
			yPrivate = factory.generatePrivate(keySpec);
		} catch (InvalidKeySpecException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}

		
		//Reading the Symmetric Key
		FileReader symKey = new FileReader(AES);
		BufferedReader symmetricKey = new BufferedReader(symKey);
		String aesSymmetricKey = symmetricKey.readLine();
		symmetricKey.close();
		
		//Reading RSACipherText
		ObjectInputStream cipherText = new ObjectInputStream (new BufferedInputStream (
										new FileInputStream(RSACIPHER)));
		int i;
		byte[] text = new byte[128];
		do {
			i = cipherText.read(text, 0, 128);
		}while (i == 128);
		
		cipherText.close();
		
		Cipher cipherRSA = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		cipherRSA.init(cipherRSA.DECRYPT_MODE, yPrivate, random);
		byte[] decrypted = cipherRSA.doFinal(text);
		
		ObjectOutputStream rsaDecrypt = new ObjectOutputStream ( new BufferedOutputStream(
										new FileOutputStream(RSADECRYPT)));
		rsaDecrypt.writeObject(decrypted);
		rsaDecrypt.flush();
		rsaDecrypt.close();
		
		//Digital Digest and Message
		ObjectInputStream aesHash = new ObjectInputStream( new BufferedInputStream(
										  new FileInputStream(RSADECRYPT)));
		byte[] firstBytes = new byte[32];
		firstBytes = aesHash.readUTF().getBytes();
		String appendedMessage = aesHash.readUTF();
		String message = appendedMessage.substring(32, appendedMessage.length());
		
		Cipher cipherAES = Cipher.getInstance("AES/CBC/NoPadding", "SunJCE");
		SecretKeySpec aesKey = new SecretKeySpec(aesSymmetricKey.getBytes("UTF-8"),"AES");
		cipherAES.init(cipherAES.DECRYPT_MODE, aesKey, new IvParameterSpec(IV.getBytes("UTF-8")));
		
		ObjectOutputStream shaHash = new ObjectOutputStream ( new BufferedOutputStream (
									 new FileOutputStream(SHAHASH)));
		shaHash.writeObject(cipherAES.doFinal(firstBytes));
		shaHash.flush();
		shaHash.close();
		for(int k=0,j=0; k<firstBytes.length;k++,j++) {
		System.out.format("%2X", new Byte(firstBytes[k]), "\n");
		if( j >= firstBytes.length) {
			System.out.println("");
			j=-1;
			}
		}
		ObjectOutputStream messageWrite = new ObjectOutputStream( new BufferedOutputStream (
										  new FileOutputStream(messageName)));
		messageWrite.writeObject(message);
		messageWrite.flush();
		messageWrite.close();
		//Read and Compare
		ObjectInputStream messageRead = new ObjectInputStream(new BufferedInputStream(
										new FileInputStream (messageName)));
		MessageDigest md = MessageDigest.getInstance("SHA-256");
		DigestInputStream in = new DigestInputStream(messageRead, md);
		int index;
		byte[] buffer = new byte[BUFFER_SIZE];
		do {
			index = in.read(buffer, 0, BUFFER_SIZE);
		} while (index == BUFFER_SIZE);
		md = in.getMessageDigest();
		in.close();
		
		byte[] hash = md.digest();
		
		if(hash == firstBytes) {
			System.out.println("The hashes match");
		}
		else {
			System.out.println("The hashes do not match");
		}
	}
}