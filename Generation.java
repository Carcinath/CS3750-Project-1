package keyGen;

import java.security.*;
import java.io.*;
import java.math.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.*;

public class Generation {
	private static final String OUTPUT_XPUBLIC = "XPublic.key";
	private static final String OUTPUT_XPRIVATE = "XPrivate.key";
	private static final String OUTPUT_YPUBLIC = "YPublic.key";
	private static final String OUTPUT_YPRIVATE = "YPrivate.key";
	private static final String OUTPUT_AESSYMMETRIC = "symmetric.key";
	
	public static void main(String[] args) throws NoSuchAlgorithmException, IOException {
		 KeyPairGenerator xKey = KeyPairGenerator.getInstance("RSA");
		 KeyPairGenerator yKey = KeyPairGenerator.getInstance("RSA");
		 
		 System.out.println("Please enter your 16-bit key: ");
		 Scanner userInput = new Scanner(System.in); 
		 String AESSymmetric = userInput.nextLine();
		 String AESSymKey = null;
		 if(AESSymmetric.length() > 16) {
			 AESSymKey = AESSymmetric.substring(0, 15);
			 System.out.println("Length of key has been changed to 16 bits."
			 		+ " Your new key is: " + AESSymKey);
		 }
		 
		 xKey.initialize(1024);
		 yKey.initialize(1024);
		 
		 KeyPair xPair = xKey.generateKeyPair();
		 KeyPair yPair = yKey.generateKeyPair();
		 
		 RSAPublicKey publicX = (RSAPublicKey) xPair.getPublic();
		 RSAPrivateKey privateX = (RSAPrivateKey) xPair.getPrivate();
		
		 RSAPublicKey publicY = (RSAPublicKey) yPair.getPublic();
		 RSAPrivateKey privateY = (RSAPrivateKey) yPair.getPrivate();
		 
		 BigInteger PubXMod = publicX.getModulus();
		 BigInteger PubXExp = publicX.getPublicExponent();
		 
		 BigInteger PrivXMod = privateX.getModulus();
		 BigInteger PrivXExp = privateX.getPrivateExponent();
		 
		 BigInteger PubYMod = publicY.getModulus();
		 BigInteger PubYExp = publicY.getPublicExponent();
		 
		 BigInteger PrivYMod = privateY.getModulus();
		 BigInteger PrivYExp = privateY.getPrivateExponent();

		 try {
			ObjectOutputStream writeKeys = new ObjectOutputStream (
					new BufferedOutputStream ( new FileOutputStream(OUTPUT_XPUBLIC)));
			writeKeys.writeObject("Modulus: ");
			writeKeys.writeObject(PubXMod);
			writeKeys.writeObject(", Exponent: ");
			writeKeys.writeObject(PubXExp);
			writeKeys.flush();
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
			
			try {
				ObjectOutputStream writeKeys = new ObjectOutputStream(
						new BufferedOutputStream( new FileOutputStream(OUTPUT_XPRIVATE)));
				writeKeys.writeObject("Modulus: ");
				writeKeys.writeObject(PrivXMod);
				writeKeys.writeObject(", Exponent: ");
				writeKeys.writeObject(PrivXExp);
				writeKeys.flush();
			} catch (FileNotFoundException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}		
				try {
					ObjectOutputStream writeKeys = new ObjectOutputStream(
							new BufferedOutputStream( new FileOutputStream(OUTPUT_YPUBLIC)));
			//		writeKeys.writeObject("Modulus: ");
					writeKeys.writeObject(PubYMod);
			//		writeKeys.writeObject(", Exponent: ");
					writeKeys.writeObject(PubYExp);
					writeKeys.flush();
				} catch (FileNotFoundException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}	
					try {
						ObjectOutputStream writeKeys = new ObjectOutputStream 
								(new BufferedOutputStream ( new FileOutputStream (OUTPUT_YPRIVATE)));
					//	writeKeys.writeObject("Modulus: ");
						writeKeys.writeObject(PrivYMod);
					//	writeKeys.writeObject(", Exponent: ");
						writeKeys.writeObject(PrivYExp);
						writeKeys.flush();
					} catch (FileNotFoundException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					}
					
					try {
						ObjectOutputStream writeKeys = new ObjectOutputStream(
								new BufferedOutputStream (new FileOutputStream(OUTPUT_AESSYMMETRIC)));
						//writeKeys.writeObject("Symmetric Key: ");
						if (AESSymmetric.length() > 16) {
							writeKeys.writeObject(AESSymKey);
						}
						else {
						writeKeys.writeObject(AESSymmetric);
						}
						writeKeys.flush();
					} catch (FileNotFoundException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					}
				}
			
		}