import java.io.BufferedOutputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.*;

public class KeyGenerator {

	public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeySpecException, IOException {
		// Generate the Symmetric Key
		 System.out.println("Please enter your 16-bit key: ");
		 String AESSymmetric = new Scanner(System.in).nextLine();  
		 if(AESSymmetric.length() > 16) {
			 AESSymmetric = AESSymmetric.substring(0, 15);
			 System.out.println("Length of key has been changed to 16 bits."
			 		+ " Your new key is: " + AESSymmetric);
		 }
		 //Generate a pair of RSA keys
		 SecureRandom random = new SecureRandom();
		 KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
		 
		 generator.initialize(1024, random); //Key size of 1024 bits
		 KeyPair pair = generator.generateKeyPair();
		 Key publicX = pair.getPublic();
		 Key privateX = pair.getPrivate();
		 
		 generator.initialize(1024, random);
		 pair = generator.generateKeyPair();
		 Key publicY = pair.getPublic();
		 Key privateY = pair.getPrivate();
		 
		 KeyFactory factory = KeyFactory.getInstance("RSA");
		 RSAPublicKeySpec xPubSpec = factory.getKeySpec(publicX, RSAPublicKeySpec.class);
		 RSAPrivateKeySpec xPrivSpec = factory.getKeySpec(privateX, RSAPrivateKeySpec.class);
		 RSAPublicKeySpec yPubSpec = factory.getKeySpec(publicY, RSAPublicKeySpec.class);
		 RSAPrivateKeySpec yPrivSpec = factory.getKeySpec(privateY, RSAPrivateKeySpec.class);
		 
		 System.out.println("Public X key: " +  xPubSpec.getModulus() + " " + xPubSpec.getPublicExponent());
		 System.out.println("Private X key: " +  xPrivSpec.getModulus() + " " + xPrivSpec.getPrivateExponent());
		 saveToFile("XPublic.key", xPubSpec.getModulus(), xPubSpec.getPublicExponent());
		 saveToFile("XPrivate.key", xPrivSpec.getModulus(), xPrivSpec.getPrivateExponent());
		 
		 System.out.println("Public Y key: " +  yPubSpec.getModulus() + " " + yPubSpec.getPublicExponent());
		 System.out.println("Private Y key: " +  yPrivSpec.getModulus() + " " + yPrivSpec.getPrivateExponent());
		 saveToFile("YPublic.key", yPubSpec.getModulus(), yPubSpec.getPublicExponent());
		 saveToFile("YPrivate.key", yPrivSpec.getModulus(), yPrivSpec.getPrivateExponent());
		 
		 System.out.println("Symmetric Key: " + AESSymmetric);
		 saveToFile("symmetric.key", AESSymmetric);

	}
	
	   public static void saveToFile(String fileName,
		         BigInteger mod, BigInteger exp) throws IOException 
		   {
		      ObjectOutputStream oout = new ObjectOutputStream(
		                                   new BufferedOutputStream(
		                                      new FileOutputStream(fileName)));
		      try 
		      {
		         oout.writeObject(mod);
		         oout.writeObject(exp);
		      } 
		      catch (Exception e) 
		      {
		         throw new IOException("Unexpected error", e);
		      } 
		      finally 
		      {
		         oout.close();
		      }
		      
		   }
		   
		   
		   
		   /**
		    * save the symmetric key to file
		    */
		   public static void saveToFile(String fileName, String symKey) throws IOException 
		   {
		      ObjectOutputStream oout = new ObjectOutputStream(
		                                   new BufferedOutputStream(
		                                      new FileOutputStream(fileName)));
		      try 
		      {
		         oout.writeUTF(symKey);
		      } 
		      catch (Exception e) 
		      {
		         throw new IOException("Unexpected error", e);
		      } 
		      finally 
		      {
		         oout.close();
		      }
		      
		   }
}