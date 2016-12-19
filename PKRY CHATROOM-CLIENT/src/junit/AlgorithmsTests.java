package junit;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Properties;

import org.junit.Test;

import cipher.AES;
import cipher.DiffieHellman;
import cipher.ElGamalSignature;

/**
 * JUnitTests , Unit test for Algorithms: Diffie-Hellman key agreement,
 * Elgamal digital signature, AES encryption and decryption     
 */
public class AlgorithmsTests {
	/**
	 * Elgamal tests via Input Vectors (p,d,t,k,M)
	 * and needed output (b,k',y1,y2)
	 * @see <a href="https://blogs.msdn.microsoft.com/laurasa/2012/10/01/information-security-digital-signature-elgamal-and-dss-algorithm-and-examples/">1st 2nd 3th vector</a>
	 * @see <a href="http://slideplayer.com/slide/5869081/">4th vector</a>
	 * @see <a href="http://slideplayer.com/slide/10923269/">5th vector</a>	 
	 */
	@Test
	public void elgamalTest() {
		List<String> ps = Arrays.asList("467","547","739","11","19");
		List<String> ds = Arrays.asList("2","9","7","2","10");
		List<String> ts = Arrays.asList("127","23","25","8","16");
		List<String> ks = Arrays.asList("213","125","127","9","5");
		List<String> Ms = Arrays.asList("100","100","100","5","14");
		
		List<String> bsShouldBe = Arrays.asList("132","81","162","3","4");
		List<String> inverseKsShouldBe = Arrays.asList("431","83","523","9","11");
		List<String> ys1ShouldBe = Arrays.asList("29","304","683","6","3");
		List<String> ys2ShouldBe = Arrays.asList("51","172","215","3","4");
		
		for(int i =0; i< ps.size(); i++)
		{
			checkElgamalVector(new BigInteger(ps.get(i)),new BigInteger(ds.get(i)),new BigInteger(ts.get(i)),
					new BigInteger(ks.get(i)),new BigInteger(Ms.get(i)),
					new BigInteger(bsShouldBe.get(i)),new BigInteger(inverseKsShouldBe.get(i)),
					new BigInteger(ys1ShouldBe.get(i)),new BigInteger(ys2ShouldBe.get(i)), i);
			System.out.println("Elgamal test num:"+ (i+1) + " succeed.");
		}
	}
	
	/**
	 * AES tests via Input Vectors (key,Message)
	 * and needed output (cipher)
	 *  @see <a href="http://csrc.nist.gov/groups/STM/cavp/documents/aes/AESAVS.pdf">5 first verctors</a>
	 *  @see <a href="http://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf">Rest of vectors</a>
	 */
	@Test
	public void AESTest() {
		AES aes = new AES();
		List<byte[]> keys = new ArrayList<>();
		List<byte[]> ciphers = new ArrayList<>();
		getKeysAndCiphers(keys,ciphers);
		byte[] initialVector = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};// "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
		int counter = 0;
		for (byte[] key : keys) {
			byte[] encrypted = aes.encrypt(initialVector, key);
			assertArrayEquals("AES failed test num:"+counter,ciphers.get(counter), encrypted);
			counter++;
			System.out.println("AES 1test num:"+ counter + " succeed.");
		}
		String key = "2b7e151628aed2a6abf7158809cf4f3c ";
		String[] plaintexts = {
				"6bc1bee22e409f96e93d7e117393172a",
				"ae2d8a571e03ac9c9eb76fac45af8e51",
				"30c81c46a35ce411e5fbc1191a0a52ef",
				"f69f2445df4f9b17ad2b417be66c3710"};
		String[] cyphertexts = {
				"3ad77bb40d7a3660a89ecaf32466ef97",
				"f5d3d58503b9699de785895a96fdbaaf",
				"43b1cd7f598ece23881b00e3ed030688",
				"7b0c785e27e8ad3f8223207104725dd4"};
		byte[] keyBytes = fromStringToBytes(key);
	    StringBuilder sb = new StringBuilder();
	    
	    for (byte b : keyBytes) {
	        sb.append(String.format("%02X ", b));
	    }
		for(int k = 0; k < 4; k++)
		{

			byte[] plaintextBytes = fromStringToBytes(plaintexts[k]);
			byte[] cyphertextBytes = fromStringToBytes(cyphertexts[k]);
			byte[] aesAns = aes.encrypt(plaintextBytes, keyBytes);
			assertArrayEquals(aesAns, cyphertextBytes);
			System.out.println("AES 2test num:"+ (k+1) + " succeed.");
		}
		
		for(int k = 1; k < 5;k++)
		{
			List<byte[]> plainsVector = new ArrayList<>();
			List<byte[]> ciphersVector = new ArrayList<>();
			byte[] keyVector = getKeyPlainsAndCiphers(plainsVector, ciphersVector, k);
			counter = 0;
			for(byte[] plian : plainsVector)
			{
				byte[] aesAns = aes.encrypt(plian, keyVector);
				assertArrayEquals(aesAns, ciphersVector.get(counter));
				System.out.println("AES "+k+" key plains and ciphers num: " + (counter+1) +" try succeed.");
				counter++;
			}
		}
	}
	
	/**
	 * Diffie-Hellman tests via Input Vectors (p,g,a,b)
	 * and needed output (A,B,key)
	 * @see <a href="https://scotthelme.co.uk/perfect-forward-secrecy/">1st vector</a>
	 * @see <a href="http://www.slideshare.net/debanjanbhattacharya3/16974-ch-15-key-management">2nd vector</a>
	 * @see <a href="https://nixaid.com/diffie-hellman-key-exchange-example-in-python/">3th vector</a>
	 * @see <a href="http://slideplayer.com/slide/7475055/">4th vector</a>
	 * @see <a href="http://www.irongeek.com/diffie-hellman.php?">5th vector</a>
	 */
	@Test
	public void DiffieHellmanTest() {
		List<String> ps = Arrays.asList("23","353","265339","53","123");
		List<String> gs = Arrays.asList("5","3","9242968","17","999");
		List<String> as = Arrays.asList("6","97","53516","5","74");
		List<String> bs = Arrays.asList("15","233","46844","7","28");
		
		List<String> AsShouldBe = Arrays.asList("8","40","35113","40","33");
		List<String> BsShouldBe = Arrays.asList("19","248","123415","6","105");
		List<String> keysShouldBe = Arrays.asList("2","160","13749","38","57");
		
		for(int i =0; i< ps.size(); i++)
		{
			checkDiffieHellmanVector(new BigInteger(ps.get(i)),new BigInteger(gs.get(i)),
					new BigInteger(as.get(i)),new BigInteger(AsShouldBe.get(i)),
					new BigInteger(bs.get(i)),new BigInteger(BsShouldBe.get(i)),
					new BigInteger(keysShouldBe.get(i)), i);
			System.out.println("Diffie-Hellman test num:"+ (i+1) + " succeed.");
		}
	}

	
	/**
	 * Parse method needed to encrypt property
	 * @param key String to encrypt needed to be cast to byte[]
	 * @return byte array of given string
	 */
	private byte[] fromStringToBytes(String key)
	{
		int[] keyArray = new int[key.length()];
		byte[] out = new byte[key.length()/2];
		for(int i = 0; i < key.length(); i++)
		{
			if (key.charAt(i) == 'a')
				keyArray[i] = 10;
			else if (key.charAt(i) == 'b')
				keyArray[i] = 11;
			else if (key.charAt(i) == 'c')
				keyArray[i] = 12;
			else if (key.charAt(i) == 'd')
				keyArray[i] = 13;
			else if (key.charAt(i) == 'e')
				keyArray[i] = 14;
			else if (key.charAt(i) == 'f')
				keyArray[i] = 15;
			else if (Character.isDigit(key.charAt(i)))
				keyArray[i] = Character.getNumericValue(key.charAt(i));
		
		}
		for(int j = 0; j < out.length; j++)
		{
			out[j] = (byte) (keyArray[j * 2] * 16 + keyArray[j * 2 + 1]);
		}
		return out;
	}
	
	private void checkElgamalVector(BigInteger p,BigInteger d,BigInteger t,BigInteger k,BigInteger M,
			BigInteger bShouldBe, BigInteger inverseKShouldBe, BigInteger y1ShouldBe, BigInteger y2ShouldBe, int testNum)
	{
		ElGamalSignature elgamal = new ElGamalSignature();
		elgamal.setPublicBigPrime(p);
		elgamal.setPublicGenerator(d);
		elgamal.setPrivateRandomNumber(t);
		
		elgamal.countPublicValue();
		assertTrue("Elgamal:Wrong counted public value test num:" + testNum,
				elgamal.getPublicComputedNumber().equals(bShouldBe));
		
		elgamal.setSecretRandomNumber(k);
		elgamal.calculateInverseSecretNumber();
		assertTrue("Elgamal:Wrong k' value test num:" + testNum,
				elgamal.getInverseOfSecretRandomNumber().equals(inverseKShouldBe));
		
		
		elgamal.countSendingValues(M);
		assertTrue("Elgamal:Wrong y1 value test num:" + testNum,
				elgamal.getSendingFirstValue().equals(y1ShouldBe));
		assertTrue("Elgamal:Wrong y2 value test num:" + testNum,
				elgamal.getSendingSecondValue().equals(y2ShouldBe));
		
		ElGamalSignature elgamalCheck = new ElGamalSignature();
		elgamalCheck.setPublicBigPrime(p);
		elgamalCheck.setPublicGenerator(d);
		elgamalCheck.setPublicComputedNumber(elgamal.getPublicComputedNumber());
		
		BigInteger left = elgamalCheck.checkSignatureLeft(M);
		BigInteger right = elgamalCheck.checkSignatureRight(elgamal.getSendingFirstValue(),
				elgamal.getSendingSecondValue());
		assertTrue("Elgamal:Checking singature failed test num:" + testNum,
				left.equals(right));
	}
	
	private void checkDiffieHellmanVector(BigInteger p, BigInteger g,BigInteger a, BigInteger AShouldBe, BigInteger b,
			BigInteger BShouldBe, BigInteger KShouldBe, int testNum)
	{
		DiffieHellman dhSending = new DiffieHellman();
		dhSending.setPublicVars(p, g);
		dhSending.setPrivateValue(a);
		dhSending.calculateSendingValue();
		assertTrue("Diffie-Hellman:A sending value failes test num:"+ testNum, dhSending.getSendingValue().equals(AShouldBe));
		
		DiffieHellman dhReceiving = new DiffieHellman();
		dhReceiving.setPublicVars(p, g);
		dhReceiving.setReceivedValue(dhSending.getSendingValue());
		dhReceiving.setPrivateValue(b);
		dhReceiving.calculateSendingValue();
		assertTrue("Diffie-Hellman:B sending value failes test num:"+ testNum, dhReceiving.getSendingValue().equals(BShouldBe));
		
		
		dhSending.setReceivedValue(dhReceiving.getSendingValue());
		
		dhSending.generateKey();
		dhReceiving.generateKey();
		
		assertTrue("Diffie-Hellman:Sending site generates wrong key value test num:"+ testNum,
				dhSending.getKey().equals(KShouldBe));
		assertTrue("Diffie-Hellman:Receiving site generates wrong key value test num:"+ testNum,
				dhReceiving.getKey().equals(KShouldBe));
	}

	
	private void getKeysAndCiphers(List<byte[]> keys, List<byte[]> ciphers) {
		File file = new File("AESVectors1.properties");
		if (!file.exists()) {
			try {
				file.createNewFile();
				String defaultData = "key1=c47b0294dbbbee0fec4757f22ffeee3587ca4730c3d33b691df38bab076bc558\n"
						+ "key2=28d46cffa158533194214a91e712fc2b45b518076675affd910edeca5f41ac64\n"
						+ "key3=c1cc358b449909a19436cfbb3f852ef8bcb5ed12ac7058325f56e6099aab1a1c\n"
						+ "key4=984ca75f4ee8d706f46c2d98c0bf4a45f5b00d791c2dfeb191b5ed8e420fd627\n"
						+ "key5=b43d08a447ac8609baadae4ff12918b9f68fc1653f1269222f123981ded7a92f\n"
						+ "cipher1=46f2fb342d6f0ab477476fc501242c5f\n" + "cipher2=4bf3b0a69aeb6657794f2901b1440ad4\n"
						+ "cipher3=352065272169abf9856843927d0674fd\n" + "cipher4=4307456a9e67813b452e15fa8fffe398\n"
						+ "cipher5=4663446607354989477a5c6f0f007ef4\n";
				;
				FileWriter fileWritter = new FileWriter(file.getName(), true);
				BufferedWriter bufferWritter = new BufferedWriter(fileWritter);
				bufferWritter.write(defaultData);
				bufferWritter.close();
			} catch (IOException e) {
				fail(e.getMessage());
			}

		}
		try (FileReader reader = new FileReader("AESVectors1.properties")) {
			Properties prop = new Properties();
			prop.load(reader);
			for (int i = 1; i < 6; i++) {
				keys.add(hexStringToByteArray(prop.getProperty("key" + i)));
				ciphers.add(hexStringToByteArray(prop.getProperty("cipher" + i)));
			}
			
			

		} catch (FileNotFoundException e) {
			fail(e.getMessage());
		} catch (IOException e) {
			fail(e.getMessage());
		}
	}

	/**
	 * Read aesVectors2.properties file to get key and plain texts and needed ciphers for that
	 * @param plains plain text to encrypt list
	 * @param ciphers needed result of ciphers list
	 * @param num number of key
	 * @return key needed to encrypt whole lists
	 */
	private byte[] getKeyPlainsAndCiphers(List<byte[]> plains, List<byte[]> ciphers, int num) {
		File file = new File("AESVectors2.properties");
		if (!file.exists()) {
			try {
				file.createNewFile();
				String defaultData = "#ECB-AES128.Encrypt  \n" +     
					"Key1 =2b7e151628aed2a6abf7158809cf4f3c\n" +       
					"Plaintext11 =6bc1bee22e409f96e93d7e117393172a\n" +  
					"Ciphertext11 =3ad77bb40d7a3660a89ecaf32466ef97\n" +      
					"#Block #2\n" +  
					"Plaintext12 =ae2d8a571e03ac9c9eb76fac45af8e51\n" +   
					"Ciphertext12 =f5d3d58503b9699de785895a96fdbaaf\n" +      
					"#Block #3\n" +  
					"Plaintext13 =30c81c46a35ce411e5fbc1191a0a52ef\n" +   
					"Ciphertext13 =43b1cd7f598ece23881b00e3ed030688\n" +      
					"#Block #4\n" +  
					"Plaintext14 =f69f2445df4f9b17ad2b417be66c3710\n" +    
					"Ciphertext14 =7b0c785e27e8ad3f8223207104725dd4\n" +
					      
					"#ECB-AES128.Decrypt\n" +       
					"Key2 =2b7e151628aed2a6abf7158809cf4f3c\n" +      
					"#Block #1\n" +  
					"Ciphertext21 =3ad77bb40d7a3660a89ecaf32466ef97\n" +       
					"Plaintext21 =6bc1bee22e409f96e93d7e117393172a\n" +  
					"#Block #2\n" +  
					"Ciphertext22 =f5d3d58503b9699de785895a96fdbaaf\n" +        
					"Plaintext22 =ae2d8a571e03ac9c9eb76fac45af8e51\n" +  
					"#Block #3\n" +  
					"Ciphertext23 =43b1cd7f598ece23881b00e3ed030688\n" +        
					"Plaintext23 =30c81c46a35ce411e5fbc1191a0a52ef\n" +  
					"#Block #4\n" +  
					"Ciphertext24 =7b0c785e27e8ad3f8223207104725dd4\n" +       
					"Plaintext24 =f69f2445df4f9b17ad2b417be66c3710\n" +  
					  
					"#ECB-AES256.Encrypt\n" +       
					"Key3 =603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4\n" +  
					"#Block #1 \n" + 
					"Plaintext31 =6bc1bee22e409f96e93d7e117393172a\n" +    
					"Ciphertext31 =f3eed1bdb5d2a03c064b5a7e3db181f8\n" +      
					"#Block #2\n" +  
					"Plaintext32 =ae2d8a571e03ac9c9eb76fac45af8e51\n" +    
					"Ciphertext32 =591ccb10d410ed26dc5ba74a31362870\n" +      
					"#Block #3\n" +  
					"Plaintext33 =30c81c46a35ce411e5fbc1191a0a52ef\n" +    
					"Ciphertext33 =b6ed21b99ca6f4f9f153e7b1beafed1d\n" +      
					"#Block #4\n" +  
					"Plaintext34 =f69f2445df4f9b17ad2b417be66c3710\n" +    
					"Ciphertext34 =23304b7a39f9f3ff067d8d8f9e24ecc7\n" +
					      
					"#ECB-AES256.Decrypt\n" +       
					"Key4 =603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4\n" +      
					"#Block #1\n" +  
					"Ciphertext41 =f3eed1bdb5d2a03c064b5a7e3db181f8\n" +        
					"Plaintext41 =6bc1bee22e409f96e93d7e117393172a\n" +  
					"#Block #2\n" +  
					"Ciphertext42 =591ccb10d410ed26dc5ba74a31362870\n" +        
					"Plaintext42 =ae2d8a571e03ac9c9eb76fac45af8e51\n" +  
					"#Block #3\n" +  
					"Ciphertext43 =b6ed21b99ca6f4f9f153e7b1beafed1d\n" +        
					"Plaintext43 =30c81c46a35ce411e5fbc1191a0a52ef\n" + 
					"Ciphertext44 =23304b7a39f9f3ff067d8d8f9e24ecc7\n" +        
					"Plaintext44 =f69f2445df4f9b17ad2b417be66c3710\n";

				FileWriter fileWritter = new FileWriter(file.getName(), true);
				BufferedWriter bufferWritter = new BufferedWriter(fileWritter);
				bufferWritter.write(defaultData);
				bufferWritter.close();
			} catch (IOException e) {
				fail(e.getMessage());
			}

		}
		try (FileReader reader = new FileReader("AESVectors2.properties")) {
			Properties prop = new Properties();
			prop.load(reader);
			for (int i = 1; i < 5; i++) {
				
				plains.add(fromStringToBytes(prop.getProperty("Plaintext"+ num + i)));
				ciphers.add(fromStringToBytes(prop.getProperty("Ciphertext"+ num + i)));
			}
			return fromStringToBytes(prop.getProperty("Key" + num));

		} catch (FileNotFoundException e) {
			fail(e.getMessage());
		} catch (IOException e) {
			fail(e.getMessage());
		}
		return null;
	}
	
	/**
	 * Parse method needed to encrypt property
	 * @param s String to encrypt needed to be cast to byte[]
	 * @return byte array of given string
	 */
	private byte[] hexStringToByteArray(String s) {
		int len = s.length();
		byte[] data = new byte[len / 2];
		for (int i = 0; i < len; i += 2) {
			data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4) + Character.digit(s.charAt(i + 1), 16));
		}
		return data;
	}

}
