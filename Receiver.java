import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.DigestInputStream;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.spec.RSAPrivateKeySpec;
import java.util.Scanner;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public class Receiver {
	static int BUFFER_SIZE = 32*1024;
	static byte[] digested = new byte[32];
			
	public static void main(String[] args) throws Exception {
		// Fetch keys		
		PrivateKey yPrivKey = readPrivKeyFromFile("YPrivate.key");
		SecretKeySpec symmetric = readSymKeyFromFile("symmetric.key");
		//Getting the save file name
		Scanner input = new Scanner(System.in);
		System.out.println("Input the name of the message");
		String messageName = input.nextLine();
		//Decryption
	//	decryptRSA("message.rsacipher", yPrivKey, "message.add-msg");
		decryptAES("message.add-msg", symmetric);
		msgDigest("message.txt");
		

	}

	  /**
	   * Decrypts the AES encrypted message with AES decryption using the symmetric key
	   */
	  public static void decryptAES(String cipherFileName, SecretKeySpec symKey) throws Exception 
	  {
		  InputStream in = new FileInputStream(cipherFileName);
		  byte[] sha32 = new byte[32];
		  in.read(sha32, 0, 32);
		  Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding","SunJCE");
		  cipher.init(Cipher.DECRYPT_MODE, symKey);
		  
		  byte[] decryptedSha = new byte[32];
				  decryptedSha = cipher.doFinal(sha32);
				  
				  digested = decryptedSha;
	  }//End decryptAES()
	  
	  
	  /**
	   * Seporating the digital digest (SHA256) and the message, saving the message to 
	   * msgFileName and calculating the RSA decryption of the digital digest.
	   */
	  public static void decryptRSA(String dsFileName, PrivateKey yPrivKey, 
	                                String msgFileName) throws Exception 
	  {
	    Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
	    InputStream in = new FileInputStream(dsFileName);
	    
	    
	    //Decrypt the RSA encrypted hash value
	    byte[] dsContents = new byte[128];
	    byte[] hashBytes = new byte[128];
	    int i = 1;
	    cipher.init(Cipher.DECRYPT_MODE, yPrivKey);
	    while( i > 0) {
	    	i = in.read(dsContents);
	    	hashBytes = cipher.doFinal(dsContents);
	    	saveToFile("message.dd", hashBytes, false);
	    }
	    
	    in.close();
	/**    
	    cipher.init(Cipher.DECRYPT_MODE, yPrivKey);
	    hashBytes = cipher.doFinal(dsContents);
	    
	    */ 
	    
	    
	  }//End decryptRSA()
	  
	  
	  /**
	   * Seporates the message from message.add-msg and puts it into msgFileName
	   */
	  public static void seporateMsg(String dsMsgFileName, String msgFileName) throws Exception 
	  {
	    InputStream in = new FileInputStream(dsMsgFileName);
	    byte[] MsgContents = new byte[BUFFER_SIZE],
	           dsContents = new byte[32];
	    int bytesRead = 0;
	    boolean firstBlock = true,
	            append = true;
	    
	    in.read(dsContents);
	    
	    while( (bytesRead = in.read(MsgContents)) != -1 )
	    {
	      append = true;
	      if(firstBlock)
	      {
	         firstBlock = false;
	         append = false;
	      }
	      
	      if(bytesRead == BUFFER_SIZE)
	      {
	         saveToFile(msgFileName, MsgContents, append);
	      }
	      else //Adjust array before saving to file
	      {
	         byte[] tempRemains = new byte[bytesRead];
	         
	         for(int parser = 0; parser < bytesRead; parser++)
	            tempRemains[parser] = MsgContents[parser];
	            
	         saveToFile(msgFileName, tempRemains, append);
	      }
	      
	    }//End while - buffer each block
	    in.close();
	    
	  }//End seporateMsg()
	  
	  
	  /**
	   * Calculating the digital digest (SHA256) of the message file
	   */
	  public static void msgDigest(String msgFileName) throws Exception 
	  {
	    //Contents of message.add-msg
	    InputStream hashFile = new BufferedInputStream(new FileInputStream(msgFileName));
	    byte[] sha = new byte[32];
	    hashFile.read(sha);
	    hashFile.close();
	    
	    //Calculate the SHA of the message we got
	    BufferedInputStream file = new BufferedInputStream(new FileInputStream(msgFileName));
	    MessageDigest md = MessageDigest.getInstance("SHA-256");
	    DigestInputStream in = new DigestInputStream(file, md);
	    int i;
	    byte[] buffer = new byte[BUFFER_SIZE];
	    do {
	      i = in.read(buffer, 0, BUFFER_SIZE);
	    } while (i == BUFFER_SIZE);
	    md = in.getMessageDigest();
	    in.close();

	    byte[] hash = md.digest();
	    
	    
	    //Print the hashed message
	    System.out.println("\nDigit digest of the message (hash value) Received:");
	    print(digested);
	    //Print the hashed message
	    System.out.println("Digit digest of the message (hash value) Calculated:");
	    print(hash);
	    
	    
	    //Compare the hashes
	    boolean hashPassed = true;
	    for(int reader = 0; reader < hash.length; reader++)
	    {
	      if(hash[reader] != digested[reader])
	         hashPassed = false;
	    }
	    
	    if(hashPassed)
	      System.out.println("\nPassed: The hashes are the same.");
	    else
	      System.out.println("\nFailed: The hashes are NOT the same!");
	    
	  }//End msgDigest()
	  
	  
	  /**
	   * Prints out the array in the parameter
	   */
	  public static void print(byte[] arrayToPrint) //throws Exception 
	  {
	    for (int k=0, j=0; k < arrayToPrint.length; k++, j++) 
	    {
	      System.out.format("%2X ", new Byte(arrayToPrint[k]) ) ;
	      
	      if (j >= 15) 
	      {
	        System.out.println("");
	        j=-1;
	      }
	    }
	    System.out.println("");
	  }//End print()
	  
	  
	  /**
	    * save the contents of the byte array to file
	    */
	   public static void saveToFile(String fileName, byte[] contents, 
	                                 boolean appendToFile) throws IOException 
	   {
	      //Open file
	      OutputStream out = null;
	      if(appendToFile)
	         out = new FileOutputStream(fileName, appendToFile);
	      else
	         out = new FileOutputStream(fileName);
	      
	      //Write to file
	      try {
	         out.write(contents);
	         out.flush();
	      } catch (Exception e) {
	         throw new IOException("Unexpected error", e);
	      } finally {
	         out.close();
	      }
	      
	   }//End saveToFile()


	  /**
	   * read key parameters from a file and generate the public key
	   */
	  public static PrivateKey readPrivKeyFromFile(String keyFileName) throws IOException 
	  {
	    FileInputStream in = new FileInputStream(new File(keyFileName));
	    ObjectInputStream oin =
	        new ObjectInputStream(new BufferedInputStream(in));
	    
	    try {
	      BigInteger m = (BigInteger) oin.readObject();
	      BigInteger e = (BigInteger) oin.readObject();
	      
	      RSAPrivateKeySpec keySpec = new RSAPrivateKeySpec(m, e);
	      KeyFactory factory = KeyFactory.getInstance("RSA");
	      PrivateKey key = factory.generatePrivate(keySpec);
	      
	      return key;
	    } catch (Exception e) {
	      throw new RuntimeException("Spurious serialisation error", e);
	    } finally {
	      oin.close();
	    }
	  }//End readPubKeyFromFile()


	  /**
	   * read symmetric key from a file
	   */
	  public static SecretKeySpec readSymKeyFromFile(String keyFileName) throws IOException 
	  {

	    FileInputStream in = new FileInputStream(new File(keyFileName));
	    ObjectInputStream oin =
	        new ObjectInputStream(new BufferedInputStream(in));

	    try {
	      String tempSymKey = oin.readUTF();
	      SecretKeySpec symKey = new SecretKeySpec(tempSymKey.getBytes("UTF-8"), "AES");
	      return symKey;
	    } catch (Exception e) {
	      throw new RuntimeException("Spurious serialisation error", e);
	    } finally {
	      oin.close();
	    }
	  }//End readSymKeyFromFile()

}
