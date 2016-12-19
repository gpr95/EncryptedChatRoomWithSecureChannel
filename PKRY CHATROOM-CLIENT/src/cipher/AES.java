package cipher;

/**
 * Represents software implementation of Advanced Encryption Standard. This
 * block cipher algorithm is working in Electronic Codebook (ECB) mode. Block
 * sizes of 128, 160, 192, 224, and 256 bits are supported by the Rijndael
 * algorithm, but only the 128-bit block size is specified in the AES standard,
 * thats why Nb = 4. Possible key lengths are 128, 192, 256 bit.
 */
public class AES
{

	/** Number of 32-bit words in message block */
	private int			Nb;
	/** Number of 32-bit words in key block */
	private int			Nk;
	/** Number of rounds needed by specific combination of Nb and Nr */
	private int			Nr;
	/** Constant table used to select number of rounds */
	private int[][]		NumberOfRounds			= { { 10, 12, 14 }, { 12, 12, 14 }, { 14, 14, 14 } };

	/**
	 * Counted exponentiation of 2 to a user-specified value performed in
	 * Rijndael's finite field.
	 */
	public final int[]	Rcon					= { 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36,
			0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef,
			0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d,
			0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab,
			0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39,
			0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8,
			0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f,
			0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3,
			0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01,
			0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63,
			0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2,
			0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08,
			0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35,
			0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a,
			0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d };

	/** Lookup table used by the Rijndael cipher */
	public final int[]	RijndaelSBox			= { 0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67,
			0x2B, 0xFE, 0xD7, 0xAB, 0x76, 0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C,
			0xA4, 0x72, 0xC0, 0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31,
			0x15, 0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75, 0x09,
			0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84, 0x53, 0xD1, 0x00,
			0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF, 0xD0, 0xEF, 0xAA, 0xFB, 0x43,
			0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8, 0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38,
			0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2, 0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4,
			0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73, 0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8,
			0x14, 0xDE, 0x5E, 0x0B, 0xDB, 0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91,
			0x95, 0xE4, 0x79, 0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE,
			0x08, 0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A, 0x70,
			0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E, 0xE1, 0xF8, 0x98,
			0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF, 0x8C, 0xA1, 0x89, 0x0D, 0xBF,
			0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16 };

	/** Inverse lookup table used by the Rijndael cipher */
	public final int[]	InvertedRijndaelSBox	= { 0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3,
			0x9E, 0x81, 0xF3, 0xD7, 0xFB, 0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4,
			0xDE, 0xE9, 0xCB, 0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3,
			0x4E, 0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25, 0x72,
			0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92, 0x6C, 0x70, 0x48,
			0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84, 0x90, 0xD8, 0xAB, 0x00, 0x8C,
			0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06, 0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F,
			0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B, 0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97,
			0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73, 0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37,
			0xE8, 0x1C, 0x75, 0xDF, 0x6E, 0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA,
			0x18, 0xBE, 0x1B, 0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A,
			0xF4, 0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F, 0x60,
			0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF, 0xA0, 0xE0, 0x3B,
			0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61, 0x17, 0x2B, 0x04, 0x7E, 0xBA,
			0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D };

	/**
	 * AES constructor.
	 */
	public AES()
	{
		// No initialization needed here.
	}

	/**
	 * Main encrypting method.
	 * 
	 * @param message
	 *            Message to encrypt as byte array
	 * @param key
	 *            Key used to encrypt message, given in bytes. Possible bit
	 *            lengths are: 128, 192, 256
	 * @return encrypted message
	 */
	public byte[] encrypt(byte[] message, byte[] key)
	{

		Nb = 4;
		Nk = key.length / 4;
		Nr = NumberOfRounds[Nk / 2 - 2][Nb / 2 - 2];

		byte[] ms = message;
		byte[] out;
		byte[][] blocks;
		byte[][] encryptedBlocks;
		int blockLenght = Nb * 4;
		int numberOfBlocks = (int) Math.ceil((double) ms.length / blockLenght);
		blocks = new byte[numberOfBlocks][blockLenght];
		encryptedBlocks = new byte[numberOfBlocks][blockLenght];

		for (int blockNR = 0; blockNR < numberOfBlocks; blockNR++)
			for (int i = 0; i < blockLenght; i++)
			{
				if (blockNR * blockLenght + i != ms.length)
					blocks[blockNR][i] = ms[blockNR * blockLenght + i];
				else
					break;
			}

		blocks[numberOfBlocks - 1] = addPadding(blocks[numberOfBlocks - 1], blockLenght);

		for (int k = 0; k < numberOfBlocks; k++)
			encryptedBlocks[k] = encryptBlock(blocks[k], key);

		out = new byte[numberOfBlocks * blockLenght];
		for (int blockNR = 0; blockNR < numberOfBlocks; blockNR++)
			for (int i = 0; i < blockLenght; i++)
				out[blockNR * blockLenght + i] = encryptedBlocks[blockNR][i];

		return out;
	}

	/**
	 * Adds padding to the data blocks to make them equal length(32 bit),
	 * according to PKCS#7 that is described in RFC 5652
	 * 
	 * @param message
	 *            message block that has to be padded
	 * @param blockLenght
	 *            length of the message block (4 * 4 = 16 words)
	 * @return padded block
	 */
	private byte[] addPadding(byte[] message, int blockLenght)
	{

		byte[] newMs = null;
		int lenghtOfMessageInBytes = message.length;
		int padding;
		if (lenghtOfMessageInBytes > 32)
		{
			System.err.println("Block is too long");
			return null;
		}

		if (lenghtOfMessageInBytes == blockLenght)
		{
			// No padding
			newMs = message;
		} else
		{
			newMs = new byte[blockLenght];
			padding = blockLenght - lenghtOfMessageInBytes;
			for (int i = 0; i < lenghtOfMessageInBytes; i++)
			{
				newMs[i] = (byte) message[i];
			}
			for (int i = 0; i < padding; i++)
			{
				newMs[lenghtOfMessageInBytes + i] = (byte) padding;
			}
		}

		return newMs;
	}

	/**
	 * Encrypting block of 128, 192 or 256 bits with key that have the same
	 * possible lengths
	 * 
	 * @param input
	 *            block to be encrypted
	 * @param key
	 *            key used for block encryption
	 * @return encrypted block
	 */
	private byte[] encryptBlock(byte[] input, byte[] key)
	{

		byte[] temp = new byte[input.length];
		byte[][] state = new byte[4][Nb];
		byte[][][] rounKey = rijndaelKeySchedule(key);

		for (int i = 0; i < input.length; i++)
			state[i / 4][i % 4] = input[i % 4 * 4 + i / 4];

		state = addRoundKey(state, rounKey[0]);
		for (int round = 1; round < Nr; round++)
		{
			state = sub(state);
			state = shiftRow(state);
			state = mixColumns(state);
			state = addRoundKey(state, rounKey[round]);
		}
		state = sub(state);
		state = shiftRow(state);
		state = addRoundKey(state, rounKey[Nr]);

		for (int i = 0; i < temp.length; i++)
			temp[i % 4 * 4 + i / 4] = state[i / 4][i % 4];

		return temp;
	}

	/**
	 * Generate matrix of round keys
	 * 
	 * @param key
	 *            key used to generate round keys
	 * @return matrix of round keys
	 */
	private byte[][][] rijndaelKeySchedule(byte[] key)
	{

		int keyLenght = key.length;
		int numberOfColumns = Nb;
		int conR;
		int colId;
		int roundId;
		int progress = 0;
		int target = (Nr + 1) * numberOfColumns * 4;
		byte[] temp = new byte[4];
		byte[][][] out = new byte[Nr + 1][numberOfColumns][4];

		outerLoop: for (int i = 0; i < 2; i++)
		{
			for (int j = 0; j < numberOfColumns; j++)
			{
				for (int k = 0; k < 4; k++)
				{
					out[i][j][k] = key[i * 16 + j * 4 + k];
					if (i * 16 + j * 4 + k == keyLenght - 1)
					{

						break outerLoop;
					}
				}
			}
		}
		progress = keyLenght;

		while (progress < target)
		{
			colId = (int) (Math.floor((double) progress / 4) % numberOfColumns);
			roundId = (int) Math.floor((double) progress / 16);

			for (int k = 0; k < temp.length; k++)
			{
				if (colId == 0)
					temp[k] = out[roundId - 1][numberOfColumns - 1][k];
				else
					temp[k] = out[roundId][colId - 1][k];
			}
			conR = progress / 4;
			if (conR % Nk == 0)
			{
				temp = byteSub(byteRotate(temp));
				temp[0] = (byte) (temp[0] ^ (Rcon[conR / Nk] & 0xff));
			} else if (Nk > 6 && conR % Nk == 4)
			{
				temp = byteSub(temp);
			}

			if (Nk == 4)
				out[roundId][colId] = xor(out[roundId - 1][colId], temp);
			else if (Nk == 6)
				if (colId == 0)
					out[roundId][colId] = xor(out[roundId - 2][numberOfColumns - 2], temp);
				else if (colId == 1)
					out[roundId][colId] = xor(out[roundId - 2][numberOfColumns - colId], temp);
				else
					out[roundId][colId] = xor(out[roundId - 1][colId - 2], temp);
			else if (Nk == 8)
				out[roundId][colId] = xor(out[roundId - 2][colId], temp);

			progress += 4;
		}
		return out;
	}

	/**
	 * XOR of bytes a and b
	 * 
	 * @param a
	 *            first byte for xor
	 * @param b
	 *            second byte for xor
	 * @return result of a xor b
	 */
	private byte[] xor(byte[] a, byte[] b)
	{

		byte[] out = new byte[a.length];
		for (int i = 0; i < a.length; i++)
		{
			out[i] = (byte) (a[i] ^ b[i]);
		}
		return out;

	}

	/**
	 * Non-linear substitution step where each byte is replaced with another
	 * according to RijndaelSBox
	 * 
	 * @param in
	 *            byte to be replaced
	 * @return result of substitution
	 */
	private byte[] byteSub(byte[] in)
	{

		byte[] tmp = new byte[in.length];

		for (int i = 0; i < tmp.length; i++)
			tmp[i] = (byte) (RijndaelSBox[in[i] & 0x000000ff] & 0xff);

		return tmp;
	}

	/**
	 * Rotates eight bytes to the left
	 * 
	 * @param in
	 *            byte for rotation
	 * @return result of rotation
	 */
	private byte[] byteRotate(byte[] in)
	{

		byte[] tmp = new byte[4];
		tmp[0] = in[1];
		tmp[1] = in[2];
		tmp[2] = in[3];
		tmp[3] = in[0];

		return tmp;
	}

	/**
	 * Methods for encryption, each block of the state is combined with a block
	 * of the round key using bitwise xor.
	 * 
	 * @param state
	 *            message during encryption
	 * @param roundKey
	 *            round Key
	 * @return result of rotation
	 */
	private byte[][] addRoundKey(byte[][] state, byte[][] roundKey)
	{

		byte[][] out = new byte[state.length][state[0].length];
		for (int i = 0; i < Nb; i++)
		{
			for (int j = 0; j < 4; j++)
			{
				out[j][i] = (byte) (roundKey[i][j] ^ state[j][i]);
			}
		}
		return out;
	}

	/**
	 * Non-linear substitution step where each byte in message block is replaced
	 * with another according to RijndaelSBox
	 * 
	 * @param state
	 *            message block for substitution
	 * @return result of substitution
	 */
	private byte[][] sub(byte[][] state)
	{

		byte[][] out = new byte[state.length][state[0].length];

		for (int row = 0; row < 4; row++)
			for (int col = 0; col < Nb; col++)
				out[row][col] = (byte) (RijndaelSBox[(state[row][col] & 0x000000ff)] & 0xff);

		return out;

	}

	/**
	 * Transposition step where the last three rows of the state are shifted
	 * cyclically a certain number of steps.
	 * 
	 * @param state
	 *            state block for shift
	 * @return result of row shifting
	 */
	private byte[][] shiftRow(byte[][] state)
	{

		byte[] t = new byte[4];
		for (int r = 1; r < 4; r++)
		{
			for (int c = 0; c < Nb; c++)
				t[c] = state[r][(c + r) % Nb];
			for (int c = 0; c < Nb; c++)
				state[r][c] = t[c];
		}

		return state;
	}

	/**
	 * Mixing operation which operates on the columns of the state, combining
	 * the four bytes in each column.
	 * 
	 * @param state
	 *            message block for mixing
	 * @return result of mixing
	 */
	private byte[][] mixColumns(byte[][] state)
	{

		int[] sp = new int[4];
		byte b02 = (byte) 0x02;
		byte b03 = (byte) 0x03;
		byte[][] out = new byte[4][4];

		for (int c = 0; c < 4; c++)
		{
			sp[0] = gMul(b02, state[0][c]) ^ gMul(b03, state[1][c]) ^ state[2][c] ^ state[3][c];
			sp[1] = state[0][c] ^ gMul(b02, state[1][c]) ^ gMul(b03, state[2][c]) ^ state[3][c];
			sp[2] = state[0][c] ^ state[1][c] ^ gMul(b02, state[2][c]) ^ gMul(b03, state[3][c]);
			sp[3] = gMul(b03, state[0][c]) ^ state[1][c] ^ state[2][c] ^ gMul(b02, state[3][c]);
			for (int i = 0; i < 4; i++)
				out[i][c] = (byte) (sp[i]);
		}
		return out;
	}

	/**
	 * Multiplication of two bytes conducted in Galois Field(up to 256)
	 * 
	 * @param a
	 *            first byte for multiplication
	 * @param b
	 *            second byte for multiplication
	 * @return result of multiplication
	 */
	public byte gMul(byte a, byte b)
	{

		byte out = 0;
		int aCopy = a, bCopy = b, t;
		while (aCopy != 0)
		{
			if ((aCopy & 1) != 0)
				out = (byte) (out ^ bCopy);

			t = (bCopy & 128);
			bCopy = (bCopy << 1);

			if (t != 0)
				bCopy = (bCopy ^ 27);
			aCopy = ((aCopy & 255) >> 1);
		}
		return out;
	}

	///
	/// Decrypting
	///

	/**
	 * Main decrypting method.
	 * 
	 * @param message
	 *            byte array containing encrypted message to decrypt
	 * @param key
	 *            key used to decrypt message, given in bytes. Possible bit
	 *            lengths are: 128, 192, 256
	 * @return decrypted message as byte array
	 */
	public byte[] decrypt(byte[] message, byte[] key)
	{

		Nb = 4;
		Nk = key.length / 4;
		Nr = NumberOfRounds[Nk / 2 - 2][Nb / 2 - 2];

		int blockLenght = Nb * 4;
		int numberOfBlocks = message.length / blockLenght;
		byte[] out = new byte[message.length];
		byte[][] encryptedBlocks = new byte[numberOfBlocks][blockLenght];
		byte[][] decryptedBlocks = new byte[numberOfBlocks][blockLenght];

		for (int blockNR = 0; blockNR < numberOfBlocks; blockNR++)
			for (int i = 0; i < blockLenght; i++)
			{
				encryptedBlocks[blockNR][i] = message[blockNR * blockLenght + i];
			}

		for (int i = 0; i < numberOfBlocks; i++)
		{
			decryptedBlocks[i] = decryptBlock(encryptedBlocks[i], key);
		}
		for (int i = 0; i < decryptedBlocks.length; i++)
			for (int j = 0; j < decryptedBlocks[0].length; j++)
				out[i * blockLenght + j] = decryptedBlocks[i][j];

		out = deletePadding(out);
		
		return out;
	}

	/**
	 * Deletes padding from the message block.
	 * 
	 * @param input
	 *            message block that has padding to be deleted
	 * @return block without padding
	 */
	private byte[] deletePadding(byte[] input)
	{

		if (input.length == 0 || input == null)
			return null;
		boolean paddingPresent = false;
		int padding;
		byte[] out = null;
		padding = input[input.length - 1];
		for (int i = 1; i <= padding; i++)
		{
			if (input[input.length - i] == padding)
			{
				paddingPresent = true;
			} else
			{
				paddingPresent = false;
				break;
			}
		}

		if (paddingPresent)
		{
			out = new byte[input.length - padding];
			for (int i = 0; i < out.length; i++)
				out[i] = input[i];
		} else
		{
			out = input;
		}

		return out;
	}

	/**
	 * Decrypts single message block
	 * 
	 * @param input
	 *            message block to be decrypted
	 * @param key
	 *            key used for decryption
	 * @return block without padding
	 */
	private byte[] decryptBlock(byte[] input, byte[] key)
	{

		byte[] temp = new byte[input.length];
		byte[][] state = new byte[4][Nb];
		byte[][][] rounKey = rijndaelKeySchedule(key);

		for (int i = 0; i < input.length; i++)
			state[i / 4][i % 4] = input[i % 4 * 4 + i / 4];

		state = addRoundKey(state, rounKey[Nr]);
		for (int round = Nr - 1; round >= 1; round--)
		{
			state = inverseByteSub(state);
			state = inverseShiftRow(state);
			state = addRoundKey(state, rounKey[round]);
			state = inverseMixColumns(state);
		}
		state = inverseByteSub(state);
		state = inverseShiftRow(state);
		state = addRoundKey(state, rounKey[0]);

		for (int i = 0; i < temp.length; i++)
			temp[i % 4 * 4 + i / 4] = state[i / 4][i % 4];

		return temp;
	}

	/**
	 * Inverse non-linear substitution step where each byte is replaced with
	 * another according to InvertedRijndaelSBox
	 * 
	 * @param state byte to be replaced
	 * @return result of inverse substitution
	 */
	private byte[][] inverseByteSub(byte[][] state)
	{

		for (int row = 0; row < 4; row++)
			for (int col = 0; col < Nb; col++)
				state[row][col] = (byte) (InvertedRijndaelSBox[(state[row][col] & 0x000000ff)] & 0xff);

		return state;
	}

	/**
	 * Inverse transposition step where the last three rows of the state are
	 * shifted cyclically a certain number of steps.
	 * 
	 * @param state
	 *            state block for inverse row shifting
	 * @return result of inverse row shifting
	 */
	private byte[][] inverseShiftRow(byte[][] state)
	{

		byte[] t = new byte[4];
		for (int r = 1; r < 4; r++)
		{
			for (int c = 0; c < Nb; c++)
				t[(c + r) % Nb] = state[r][c];
			for (int c = 0; c < Nb; c++)
				state[r][c] = t[c];
		}
		return state;
	}

	/**
	 * Inverse mixing operation which operates on the columns of the state,
	 * combining the four bytes in each column.
	 * 
	 * @param state
	 *            message block for inverse mixing
	 * @return result of inverse mixing
	 */
	private byte[][] inverseMixColumns(byte[][] state)
	{

		int[] sp = new int[4];
		byte b02 = (byte) 0x0e, b03 = (byte) 0x0b, b04 = (byte) 0x0d, b05 = (byte) 0x09;
		for (int c = 0; c < 4; c++)
		{
			sp[0] = gMul(b02, state[0][c]) ^ gMul(b03, state[1][c]) ^ gMul(b04, state[2][c]) ^ gMul(b05, state[3][c]);
			sp[1] = gMul(b05, state[0][c]) ^ gMul(b02, state[1][c]) ^ gMul(b03, state[2][c]) ^ gMul(b04, state[3][c]);
			sp[2] = gMul(b04, state[0][c]) ^ gMul(b05, state[1][c]) ^ gMul(b02, state[2][c]) ^ gMul(b03, state[3][c]);
			sp[3] = gMul(b03, state[0][c]) ^ gMul(b04, state[1][c]) ^ gMul(b05, state[2][c]) ^ gMul(b02, state[3][c]);
			for (int i = 0; i < 4; i++)
				state[i][c] = (byte) (sp[i]);
		}

		return state;
	}
}