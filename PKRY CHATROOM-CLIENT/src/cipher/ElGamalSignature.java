package cipher;

import java.math.BigInteger;
import java.util.Random;

/**
 * Represents Elgamal digital signature algorithm 
 */
public class ElGamalSignature {
	/** big length for p and d */
	private int bitLength = 256;

	/** p  - PUBLIC KEY (big prime number - which got from Diffie-Hellman)*/
	private BigInteger publicBigPrime;
	/** d  - PUBLIC KEY  (number - which got from Diffie-Hellman)*/
	private BigInteger publicGenerator;
	/** b  - PUBLIC KEY (calculated number b=d^t(modp)*/
	private BigInteger publicComputedNumber;
	/** k - private generated relative prime to (p-1) number*/
	private BigInteger secretRandomNumber;
	/** k' - inverse of k value that  k * k’ = 1mod(p-1)*/
	private BigInteger inverseOfSecretRandomNumber;
	
	/** t - PRIVATE KEY  (random number less than p-1 - which got from Diffie-Hellman)*/
	private BigInteger privateRandomNumber;
	
	/** y1 - signature 1st value*/
	private BigInteger sendingFirstValue;
	/** y2 - signature 2nd value*/
	private BigInteger sendingSecondValue;
	
	/** Compute  b = d^t(modp) value */
	public void countPublicValue()
	{
		if(publicComputedNumber == null)
			publicComputedNumber = publicGenerator.modPow(privateRandomNumber,publicBigPrime);
	}

	/** Random private t value */
	public void generatePrivateValue()
	{
		Random randomizer = new Random();
		do {
			privateRandomNumber =new BigInteger(publicBigPrime.bitLength(), randomizer);
		} while (privateRandomNumber.compareTo(publicBigPrime.subtract(new BigInteger("1"))) > 0);
	}
	/** Random private value k and calculate k' */
	public void randomPrivateValue()
	{
		Random randomizer = new Random();
		do {
			secretRandomNumber =BigInteger.probablePrime(bitLength, randomizer);
		} while (!((publicBigPrime.subtract(BigInteger.ONE)).gcd(secretRandomNumber)).equals(BigInteger.ONE));
		
		calculateInverseSecretNumber();
	}
	
	/** Calculate k' value (inverse of k value)
	 * (k*k')%(p-1) =(k'*k)%(p-1) = 1 */
	public void calculateInverseSecretNumber()
	{
		inverseOfSecretRandomNumber = secretRandomNumber.modInverse(publicBigPrime.subtract(new BigInteger("1")));
	}

	/** Counts y1 and y2 values where   y1 = d^k(modp)  
	 * and  y2 = (M - t*y1)*k’ mod(p-1) 
	 * @param M message that need to be signed
	 */
	public void countSendingValues(BigInteger M)
	{
		sendingFirstValue = publicGenerator.modPow(secretRandomNumber, publicBigPrime);
		BigInteger tmpMultiplier = M.subtract(privateRandomNumber.multiply(sendingFirstValue));

		tmpMultiplier = tmpMultiplier.multiply(inverseOfSecretRandomNumber);
		BigInteger publicMinusOne = publicBigPrime.subtract(new BigInteger("1"));
		sendingSecondValue = tmpMultiplier.mod(publicMinusOne);
	}
	
	/** Calculates left side of equation for checking signature 
	 * @param  message message needed to be checked 
	 * @return d^M(modp)
	 */
	public BigInteger checkSignatureLeft(BigInteger message) 
	{
		return publicGenerator.modPow(message, publicBigPrime);
	}

	/** Calculates right side of equation for checking signature 
	 * @param  receivedSignature1 first value of signature
	 * @param  receivedSignature2 second value of signature
	 * @return  (b^y1 * y1^y2)modp
	 */
	public BigInteger checkSignatureRight(BigInteger receivedSignature1,BigInteger receivedSignature2) 
	{
		BigInteger by1 = publicComputedNumber.modPow(receivedSignature1, publicBigPrime);
		BigInteger y1y2 = receivedSignature1.modPow(receivedSignature2, publicBigPrime);
		BigInteger multiply = by1.multiply(y1y2);
		return  multiply.mod(publicBigPrime);
	}
	
	// GETTERS AND SETTERS
	public int getBitLength() 
	{
		return bitLength;
	}
	
	public void setBitLength(int bitLength) 
	{
		this.bitLength = bitLength;
	}
	
	public BigInteger getPublicBigPrime() 
	{
		return publicBigPrime;
	}
	
	public void setPublicBigPrime(BigInteger publicBigPrime) 
	{
		this.publicBigPrime = publicBigPrime;
	}
	
	public BigInteger getPublicGenerator() 
	{
		return publicGenerator;
	}
	
	public void setPublicGenerator(BigInteger publicGenerator) 
	{
		this.publicGenerator = publicGenerator;
	}
	
	public BigInteger getPublicComputedNumber() 
	{
		return publicComputedNumber;
	}
	
	public void setPublicComputedNumber(BigInteger publicComputedNumber) 
	{
		this.publicComputedNumber = publicComputedNumber;
	}
	
	public BigInteger getSecretRandomNumber() 
	{
		return secretRandomNumber;
	}
	
	public void setSecretRandomNumber(BigInteger secretRandomNumber) 
	{
		this.secretRandomNumber = secretRandomNumber;
	}
	
	public BigInteger getPrivateRandomNumber()
	{
		return privateRandomNumber;
	}
	
	public void setPrivateRandomNumber(BigInteger privateRandomNumber) 
	{
		this.privateRandomNumber = privateRandomNumber;
	}
	
	public BigInteger getSendingFirstValue() {
		return sendingFirstValue;
	}
	
	public void setSendingFirstValue(BigInteger sendingFirstValue)
	{
		this.sendingFirstValue = sendingFirstValue;
	}
	
	public BigInteger getSendingSecondValue() {
		return sendingSecondValue;
	}
	
	public void setSendingSecondValue(BigInteger sendingSecondValue) 
	{
		this.sendingSecondValue = sendingSecondValue;
	}
	
	public BigInteger getInverseOfSecretRandomNumber() 
	{
		return inverseOfSecretRandomNumber;
	}

	public void setInverseOfSecretRandomNumber(BigInteger inverseOfSecretRandomNumber) 
	{
		this.inverseOfSecretRandomNumber = inverseOfSecretRandomNumber;
	}

}
