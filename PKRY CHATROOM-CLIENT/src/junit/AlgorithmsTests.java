package junit;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertTrue;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.List;

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

	/*
	 * ELGAMAL UNIT TEST
	 * Input: p,d,t,k,M 
	 * Output: b,k',y1,y2
	 */
	@Test
	public void eglamalTest1() {
		
		List<String> input = Arrays.asList("467","2","127","213","100");
		List<String> output = Arrays.asList("132","431","29","51");
		checkElgamalVector(new BigInteger(input.get(0)),new BigInteger(input.get(1)),new BigInteger(input.get(2)),
						new BigInteger(input.get(3)),new BigInteger(input.get(4)),new BigInteger(output.get(0)),
						new BigInteger(output.get(1)),new BigInteger(output.get(2)),new BigInteger(output.get(3)),1);
		System.out.println("Elgamal test num 1 succeed.");
	}
	
	/*
	 * ELGAMAL UNIT TEST
	 * Input: p,d,t,k,M 
	 * Output: b,k',y1,y2
	 */
	@Test
	public void eglamalTest2() {
		List<String> input = Arrays.asList("547","9","23","125","100");
		List<String> output = Arrays.asList("81","83","304","172");
		checkElgamalVector(new BigInteger(input.get(0)),new BigInteger(input.get(1)),new BigInteger(input.get(2)),
						new BigInteger(input.get(3)),new BigInteger(input.get(4)),new BigInteger(output.get(0)),
						new BigInteger(output.get(1)),new BigInteger(output.get(2)),new BigInteger(output.get(3)),2);
		System.out.println("Elgamal test num 2 succeed.");
	}
	
	/*
	 * ELGAMAL UNIT TEST
	 * Input: p,d,t,k,M 
	 * Output: b,k',y1,y2
	 */
	@Test
	public void eglamalTest3() {
		List<String> input = Arrays.asList("739","7","25","127","100");
		List<String> output = Arrays.asList("162","523","683","215");
		checkElgamalVector(new BigInteger(input.get(0)),new BigInteger(input.get(1)),new BigInteger(input.get(2)),
						new BigInteger(input.get(3)),new BigInteger(input.get(4)),new BigInteger(output.get(0)),
						new BigInteger(output.get(1)),new BigInteger(output.get(2)),new BigInteger(output.get(3)),3);
		System.out.println("Elgamal test num 3 succeed.");
	}
	
	/*
	 * ELGAMAL UNIT TEST
	 * Input: p,d,t,k,M 
	 * Output: b,k',y1,y2
	 */
	@Test
	public void eglamalTest4() {
		List<String> input = Arrays.asList("11","2","8","9","5");
		List<String> output = Arrays.asList("3","9","6","3");
		checkElgamalVector(new BigInteger(input.get(0)),new BigInteger(input.get(1)),new BigInteger(input.get(2)),
						new BigInteger(input.get(3)),new BigInteger(input.get(4)),new BigInteger(output.get(0)),
						new BigInteger(output.get(1)),new BigInteger(output.get(2)),new BigInteger(output.get(3)),4);
		System.out.println("Elgamal test num 4 succeed.");
	}
	
	/*
	 * ELGAMAL UNIT TEST
	 * Input: p,d,t,k,M 
	 * Output: b,k',y1,y2
	 */
	@Test
	public void eglamalTest5() {
		List<String> input = Arrays.asList("19","10","16","5","14");
		List<String> output = Arrays.asList("4","11","3","4");
		checkElgamalVector(new BigInteger(input.get(0)),new BigInteger(input.get(1)),new BigInteger(input.get(2)),
						new BigInteger(input.get(3)),new BigInteger(input.get(4)),new BigInteger(output.get(0)),
						new BigInteger(output.get(1)),new BigInteger(output.get(2)),new BigInteger(output.get(3)),5);
		System.out.println("Elgamal test num 5 succeed.");
	}

	
	/**
	 * AES UNIT TEST
	 * Input: key, initialVector
	 * Output: cipher
	 * @see <a href="http://csrc.nist.gov/groups/STM/cavp/documents/aes/AESAVS.pdf">5 first verctors</a>
	 */
	@Test
	public void AESTest1() {
		AES aes = new AES();
		byte[] key = hexStringToByteArray("c47b0294dbbbee0fec4757f22ffeee3587ca4730c3d33b691df38bab076bc558");
		byte[] cipher = hexStringToByteArray("46f2fb342d6f0ab477476fc501242c5f");
		byte[] initialVector = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
		byte[] encrypted = aes.encrypt(initialVector, key);
		assertArrayEquals("AES (same message) failed test num 1",cipher, encrypted);
		
		byte[] aesResult = aes.decrypt(cipher, key);
		assertArrayEquals("AES (same message) failed test num 1, decrypted message isn't the same.",
				aesResult,initialVector);
		System.out.println("AES (same message) test num 1 succeed.");
	}
	
	/**
	 * AES UNIT TEST
	 * Input: key, initialVector
	 * Output: cipher
	 * @see <a href="http://csrc.nist.gov/groups/STM/cavp/documents/aes/AESAVS.pdf">5 first verctors</a>
	 */
	@Test
	public void AESTest2() {
		AES aes = new AES();
		byte[] key = hexStringToByteArray("28d46cffa158533194214a91e712fc2b45b518076675affd910edeca5f41ac64");
		byte[] cipher = hexStringToByteArray("4bf3b0a69aeb6657794f2901b1440ad4");
		byte[] initialVector = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
		byte[] encrypted = aes.encrypt(initialVector, key);
		assertArrayEquals("AES (same message) failed test num 2",cipher, encrypted);
		
		byte[] aesResult = aes.decrypt(cipher, key);
		assertArrayEquals("AES (same message) failed test num 2, decrypted message isn't the same.",
				aesResult,initialVector);
		System.out.println("AES (same message) test num 2 succeed.");
	}
	
	/**
	 * AES UNIT TEST
	 * Input: key, initialVector
	 * Output: cipher
	 * @see <a href="http://csrc.nist.gov/groups/STM/cavp/documents/aes/AESAVS.pdf">5 first verctors</a>
	 */
	@Test
	public void AESTest3() {
		AES aes = new AES();
		byte[] key = hexStringToByteArray("c1cc358b449909a19436cfbb3f852ef8bcb5ed12ac7058325f56e6099aab1a1c");
		byte[] cipher = hexStringToByteArray("352065272169abf9856843927d0674fd");
		byte[] initialVector = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
		byte[] encrypted = aes.encrypt(initialVector, key);
		assertArrayEquals("AES (same message) failed test num 3",cipher, encrypted);
		
		byte[] aesResult = aes.decrypt(cipher, key);
		assertArrayEquals("AES (same message) failed test num 3, decrypted message isn't the same.",
				aesResult,initialVector);
		System.out.println("AES (same message) test num 3 succeed.");
	}
	
	/**
	 * AES UNIT TEST
	 * Input: key, initialVector
	 * Output: cipher
	 * @see <a href="http://csrc.nist.gov/groups/STM/cavp/documents/aes/AESAVS.pdf">5 first verctors</a>
	 */
	@Test
	public void AESTest4() {
		AES aes = new AES();
		byte[] key = hexStringToByteArray("984ca75f4ee8d706f46c2d98c0bf4a45f5b00d791c2dfeb191b5ed8e420fd627");
		byte[] cipher = hexStringToByteArray("4307456a9e67813b452e15fa8fffe398");
		byte[] initialVector = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
		byte[] encrypted = aes.encrypt(initialVector, key);
		assertArrayEquals("AES (same message) failed test num 4",cipher, encrypted);
		
		byte[] aesResult = aes.decrypt(cipher, key);
		assertArrayEquals("AES (same message) failed test num 4, decrypted message isn't the same.",
				aesResult,initialVector);
		System.out.println("AES (same message) test num 4 succeed.");
	}
	
	/**
	 * AES UNIT TEST
	 * Input: key, initialVector
	 * Output: cipher
	 * @see <a href="http://csrc.nist.gov/groups/STM/cavp/documents/aes/AESAVS.pdf">5 first verctors</a>
	 */
	@Test
	public void AESTest5() {
		AES aes = new AES();
		byte[] key = hexStringToByteArray("b43d08a447ac8609baadae4ff12918b9f68fc1653f1269222f123981ded7a92f");
		byte[] cipher = hexStringToByteArray("4663446607354989477a5c6f0f007ef4");
		byte[] initialVector = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
		byte[] encrypted = aes.encrypt(initialVector, key);
		assertArrayEquals("AES (same message) failed test num 5",cipher, encrypted);
		
		byte[] aesResult = aes.decrypt(cipher, key);
		assertArrayEquals("AES (same message) failed test num 5, decrypted message isn't the same.",
				aesResult,initialVector);
		System.out.println("AES (same message) test num 5 succeed.");
	}
	
	/**
	 * AES128 UNIT TEST
	 * Input: Plain,Key
	 * Output: Cipher
	 * @see <a href="http://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf">Rest of vectors</a>
	 */
	@Test
	public void AES128Test1() {
		AES aes = new AES();
		byte[] plainVector = fromStringToBytes("6bc1bee22e409f96e93d7e117393172a");
		byte[] cipherVector = fromStringToBytes("3ad77bb40d7a3660a89ecaf32466ef97");
		byte[] keyVector = fromStringToBytes("2b7e151628aed2a6abf7158809cf4f3c");
		byte[] aesAns = aes.encrypt(plainVector, keyVector);
		assertArrayEquals("AES 128 key, plains and ciphers num 1 failed.",
				aesAns, cipherVector);
		
		
		byte[] aesResult = aes.decrypt(cipherVector, keyVector);
		assertArrayEquals("AES 128 key, plains and ciphers num 1 failed decrypted message isn't the same.",
				aesResult,plainVector);
		System.out.println("AES 128 key, plains and ciphers num 1 try succeed.");
	}
	
	/**
	 * AES128 UNIT TEST
	 * Input: Plain,Key
	 * Output: Cipher
	 * @see <a href="http://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf">Rest of vectors</a>
	 */
	@Test
	public void AES128Test2() {
		AES aes = new AES();
		byte[] plainVector = fromStringToBytes("ae2d8a571e03ac9c9eb76fac45af8e51");
		byte[] cipherVector = fromStringToBytes("f5d3d58503b9699de785895a96fdbaaf");
		byte[] keyVector = fromStringToBytes("2b7e151628aed2a6abf7158809cf4f3c");
		byte[] aesAns = aes.encrypt(plainVector, keyVector);
		assertArrayEquals("AES 128 key, plains and ciphers num 2 failed.",
				aesAns, cipherVector);
		
		
		byte[] aesResult = aes.decrypt(cipherVector, keyVector);
		assertArrayEquals("AES 128 key, plains and ciphers num 2 failed decrypted message isn't the same.",
				aesResult,plainVector);
		System.out.println("AES 128 key, plains and ciphers num 2 try succeed.");
	}
	
	/**
	 * AES128 UNIT TEST
	 * Input: Plain,Key
	 * Output: Cipher
	 * @see <a href="http://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf">Rest of vectors</a>
	 */
	@Test
	public void AES128Test3() {
		AES aes = new AES();
		byte[] plainVector = fromStringToBytes("30c81c46a35ce411e5fbc1191a0a52ef");
		byte[] cipherVector = fromStringToBytes("43b1cd7f598ece23881b00e3ed030688");
		byte[] keyVector = fromStringToBytes("2b7e151628aed2a6abf7158809cf4f3c");
		byte[] aesAns = aes.encrypt(plainVector, keyVector);
		assertArrayEquals("AES 128 key, plains and ciphers num 3 failed.",
				aesAns, cipherVector);
		
		
		byte[] aesResult = aes.decrypt(cipherVector, keyVector);
		assertArrayEquals("AES 128 key, plains and ciphers num 3 failed decrypted message isn't the same.",
				aesResult,plainVector);
		System.out.println("AES 128 key, plains and ciphers num 3 try succeed.");
	}
	
	/**
	 * AES128 UNIT TEST
	 * Input: Plain,Key
	 * Output: Cipher
	 * @see <a href="http://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf">Rest of vectors</a>
	 */
	@Test
	public void AES128Test4() {
		AES aes = new AES();
		byte[] plainVector = fromStringToBytes("f69f2445df4f9b17ad2b417be66c3710");
		byte[] cipherVector = fromStringToBytes("7b0c785e27e8ad3f8223207104725dd4");
		byte[] keyVector = fromStringToBytes("2b7e151628aed2a6abf7158809cf4f3c");
		byte[] aesAns = aes.encrypt(plainVector, keyVector);
		assertArrayEquals("AES 128 key, plains and ciphers num 4 failed.",
				aesAns, cipherVector);
		
		
		byte[] aesResult = aes.decrypt(cipherVector, keyVector);
		assertArrayEquals("AES 128 key, plains and ciphers num 4 failed decrypted message isn't the same.",
				aesResult,plainVector);
		System.out.println("AES 128 key, plains and ciphers num 4 try succeed.");
	}
	
	/**
	 * AES256 UNIT TEST
	 * Input: Plain,Key
	 * Output: Cipher
	 * @see <a href="http://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf">Rest of vectors</a>
	 */
	@Test
	public void AES256Test1() {
		AES aes = new AES();
		byte[] plainVector = fromStringToBytes("6bc1bee22e409f96e93d7e117393172a");
		byte[] cipherVector = fromStringToBytes("f3eed1bdb5d2a03c064b5a7e3db181f8");
		byte[] keyVector = fromStringToBytes("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4");
		byte[] aesAns = aes.encrypt(plainVector, keyVector);
		assertArrayEquals("AES 256 key, plains and ciphers num 1 failed.",
				aesAns, cipherVector);
		
		
		byte[] aesResult = aes.decrypt(cipherVector, keyVector);
		assertArrayEquals("AES 256 key, plains and ciphers num 1 failed decrypted message isn't the same.",
				aesResult,plainVector);
		System.out.println("AES 256 key, plains and ciphers num 1 try succeed.");
	}
	
	/**
	 * AES256 UNIT TEST
	 * Input: Plain,Key
	 * Output: Cipher
	 * @see <a href="http://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf">Rest of vectors</a>
	 */
	@Test
	public void AES256Test2() {
		AES aes = new AES();
		byte[] plainVector = fromStringToBytes("ae2d8a571e03ac9c9eb76fac45af8e51");
		byte[] cipherVector = fromStringToBytes("591ccb10d410ed26dc5ba74a31362870");
		byte[] keyVector = fromStringToBytes("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4");
		byte[] aesAns = aes.encrypt(plainVector, keyVector);
		assertArrayEquals("AES 256 key, plains and ciphers num 2 failed.",
				aesAns, cipherVector);
		
		
		byte[] aesResult = aes.decrypt(cipherVector, keyVector);
		assertArrayEquals("AES 256 key, plains and ciphers num 2 failed decrypted message isn't the same.",
				aesResult,plainVector);
		System.out.println("AES 256 key, plains and ciphers num 2 try succeed.");
	}
	
	/**
	 * AES256 UNIT TEST
	 * Input: Plain,Key
	 * Output: Cipher
	 * @see <a href="http://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf">Rest of vectors</a>
	 */
	@Test
	public void AES256Test3() {
		AES aes = new AES();
		byte[] plainVector = fromStringToBytes("30c81c46a35ce411e5fbc1191a0a52ef");
		byte[] cipherVector = fromStringToBytes("b6ed21b99ca6f4f9f153e7b1beafed1d");
		byte[] keyVector = fromStringToBytes("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4");
		byte[] aesAns = aes.encrypt(plainVector, keyVector);
		assertArrayEquals("AES 256 key, plains and ciphers num 3 failed.",
				aesAns, cipherVector);
		
		
		byte[] aesResult = aes.decrypt(cipherVector, keyVector);
		assertArrayEquals("AES 256 key, plains and ciphers num 3 failed decrypted message isn't the same.",
				aesResult,plainVector);
		System.out.println("AES 256 key, plains and ciphers num 3 try succeed.");
	}
	
	/**
	 * AES256 UNIT TEST
	 * Input: Plain,Key
	 * Output: Cipher
	 * @see <a href="http://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf">Rest of vectors</a>
	 */
	@Test
	public void AES256Test4() {
		AES aes = new AES();
		byte[] plainVector = fromStringToBytes("f69f2445df4f9b17ad2b417be66c3710");
		byte[] cipherVector = fromStringToBytes("23304b7a39f9f3ff067d8d8f9e24ecc7");
		byte[] keyVector = fromStringToBytes("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4");
		byte[] aesAns = aes.encrypt(plainVector, keyVector);
		assertArrayEquals("AES 256 key, plains and ciphers num 4 failed.",
				aesAns, cipherVector);
		
		
		byte[] aesResult = aes.decrypt(cipherVector, keyVector);
		assertArrayEquals("AES 256 key, plains and ciphers num 4 failed decrypted message isn't the same.",
				aesResult,plainVector);
		System.out.println("AES 256 key, plains and ciphers num 4 try succeed.");
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
	
	/**
	 * DIFFIE HELLMAN UNIT TEST
	 * Input: p,g,a,b
	 * Output: A,B,key
	 */
	@Test
	public void DiffieHellmanTest1() {
		List<String> input = Arrays.asList("23","5","6","15");
		List<String> output = Arrays.asList("8","19","2");
		checkDiffieHellmanVector(new BigInteger(input.get(0)),new BigInteger(input.get(1)),new BigInteger(input.get(2)),
						new BigInteger(input.get(3)),new BigInteger(output.get(0)),
						new BigInteger(output.get(1)),new BigInteger(output.get(2)),1);
		System.out.println("Diffie-Hellman test num 1 succeed.");
	}
	
	/**
	 * DIFFIE HELLMAN UNIT TEST
	 * Input: p,g,a,b
	 * Output: A,B,key
	 */
	@Test
	public void DiffieHellmanTest2() {
		List<String> input = Arrays.asList("353","3","97","233");
		List<String> output = Arrays.asList("40","248","160");
		checkDiffieHellmanVector(new BigInteger(input.get(0)),new BigInteger(input.get(1)),new BigInteger(input.get(2)),
						new BigInteger(input.get(3)),new BigInteger(output.get(0)),
						new BigInteger(output.get(1)),new BigInteger(output.get(2)),2);
		System.out.println("Diffie-Hellman test num 2 succeed.");
	}
	
	/**
	 * DIFFIE HELLMAN UNIT TEST
	 * Input: p,g,a,b
	 * Output: A,B,key
	 */
	@Test
	public void DiffieHellmanTest3() {
		List<String> input = Arrays.asList("265339","9242968","53516","46844");
		List<String> output = Arrays.asList("35113","123415","13749");
		checkDiffieHellmanVector(new BigInteger(input.get(0)),new BigInteger(input.get(1)),new BigInteger(input.get(2)),
						new BigInteger(input.get(3)),new BigInteger(output.get(0)),
						new BigInteger(output.get(1)),new BigInteger(output.get(2)),3);
		System.out.println("Diffie-Hellman test num 3 succeed.");
	}
	
	/**
	 * DIFFIE HELLMAN UNIT TEST
	 * Input: p,g,a,b
	 * Output: A,B,key
	 */
	@Test
	public void DiffieHellmanTest4() {
		List<String> input = Arrays.asList("53","17","5","7");
		List<String> output = Arrays.asList("40","6","38");
		checkDiffieHellmanVector(new BigInteger(input.get(0)),new BigInteger(input.get(1)),new BigInteger(input.get(2)),
						new BigInteger(input.get(3)),new BigInteger(output.get(0)),
						new BigInteger(output.get(1)),new BigInteger(output.get(2)),4);
		System.out.println("Diffie-Hellman test num 4 succeed.");
	}
	
	/**
	 * DIFFIE HELLMAN UNIT TEST
	 * Input: p,g,a,b
	 * Output: A,B,key
	 */
	@Test
	public void DiffieHellmanTest5() {
		List<String> input = Arrays.asList("123","999","74","28");
		List<String> output = Arrays.asList("33","105","57");
		checkDiffieHellmanVector(new BigInteger(input.get(0)),new BigInteger(input.get(1)),new BigInteger(input.get(2)),
						new BigInteger(input.get(3)),new BigInteger(output.get(0)),
						new BigInteger(output.get(1)),new BigInteger(output.get(2)),5);
		System.out.println("Diffie-Hellman test num 5 succeed.");
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
	
	private void checkDiffieHellmanVector(BigInteger p, BigInteger g,BigInteger a,  BigInteger b,BigInteger AShouldBe,
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
