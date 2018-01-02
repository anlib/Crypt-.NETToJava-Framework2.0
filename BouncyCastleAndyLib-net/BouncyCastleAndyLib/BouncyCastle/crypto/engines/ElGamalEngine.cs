using System;

using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Crypto.Engines
{
	/**
	* this does your basic ElGamal algorithm.
	*/
	public class ElGamalEngine
		: IAsymmetricBlockCipher
	{
		private ElGamalKeyParameters key;
		private SecureRandom random;
		private bool forEncryption;
		private int bitSize;

		public string AlgorithmName
		{
			get { return "ElGamal"; }
		}

		/**
		* initialise the ElGamal engine.
		*
		* @param forEncryption true if we are encrypting, false otherwise.
		* @param param the necessary ElGamal key parameters.
		*/
		public void Init(
			bool				forEncryption,
			ICipherParameters	parameters)
		{
			if (parameters is ParametersWithRandom)
			{
				ParametersWithRandom p = (ParametersWithRandom) parameters;

				this.key = (ElGamalKeyParameters) p.Parameters;
				this.random = p.Random;
			}
			else
			{
				this.key = (ElGamalKeyParameters) parameters;
				this.random = new SecureRandom();
			}

			this.forEncryption = forEncryption;
			this.bitSize = key.Parameters.P.BitLength;

			if (forEncryption)
			{
				if (!(key is ElGamalPublicKeyParameters))
				{
					throw new ArgumentException("ElGamalPublicKeyParameters are required for encryption.");
				}
			}
			else
			{
				if (!(key is ElGamalPrivateKeyParameters))
				{
					throw new ArgumentException("ElGamalPrivateKeyParameters are required for decryption.");
				}
			}
		}

		/**
		* Return the maximum size for an input block to this engine.
		* For ElGamal this is always one byte less than the size of P on
		* encryption, and twice the length as the size of P on decryption.
		*
		* @return maximum size for an input block.
		*/
		public int GetInputBlockSize()
		{
			if (forEncryption)
			{
				return (bitSize - 1) / 8;
			}

			return 2 * ((bitSize + 7) / 8);
		}

		/**
		* Return the maximum size for an output block to this engine.
		* For ElGamal this is always one byte less than the size of P on
		* decryption, and twice the length as the size of P on encryption.
		*
		* @return maximum size for an output block.
		*/
		public int GetOutputBlockSize()
		{
			if (forEncryption)
			{
				return 2 * ((bitSize + 7) / 8);
			}

			return (bitSize - 1) / 8;
		}

		/**
		* Process a single block using the basic ElGamal algorithm.
		*
		* @param in the input array.
		* @param inOff the offset into the input buffer where the data starts.
		* @param length the length of the data to be processed.
		* @return the result of the ElGamal process.
		* @exception DataLengthException the input block is too large.
		*/
		public byte[] ProcessBlock(
			byte[]	input,
			int		inOff,
			int		length)
		{
			if (key == null)
				throw new InvalidOperationException("ElGamal engine not initialised");

			int maxLength = forEncryption
				?	(bitSize - 1 + 7) / 8
				:	GetInputBlockSize();

			if (length > maxLength)
				throw new DataLengthException("input too large for ElGamal cipher.\n");

			BigInteger p = key.Parameters.P;

			byte[] output;
			if (key is ElGamalPrivateKeyParameters) // decryption
			{
				byte[] in1 = new byte[length / 2];
				byte[] in2 = new byte[length / 2];

				Array.Copy(input, inOff, in1, 0, in1.Length);
				Array.Copy(input, inOff + in1.Length, in2, 0, in2.Length);

				BigInteger gamma = new BigInteger(1, in1);
				BigInteger phi = new BigInteger(1, in2);

				ElGamalPrivateKeyParameters priv = (ElGamalPrivateKeyParameters) key;

				BigInteger m = gamma.ModPow(p.Subtract(BigInteger.One).Subtract(priv.X), p).Multiply(phi).Mod(p);

				output = m.ToByteArrayUnsigned();
			}
			else // encryption
			{
				byte[] block;
				if (inOff != 0 || length != input.Length)
				{
					block = new byte[length];
					Array.Copy(input, inOff, block, 0, length);
				}
				else
				{
					block = input;
				}

				BigInteger tmp = new BigInteger(1, block);

				if (tmp.BitLength >= p.BitLength)
					throw new DataLengthException("input too large for ElGamal cipher.\n");


				ElGamalPublicKeyParameters pub = (ElGamalPublicKeyParameters) key;

				BigInteger pSub2 = p.Subtract(BigInteger.Two);
				BigInteger k;
				do
				{
					k = new BigInteger(p.BitLength, random);
				}
				while (k.SignValue == 0 || k.CompareTo(pSub2) > 0);

				BigInteger g = key.Parameters.G;
				BigInteger gamma = g.ModPow(k, p);
				BigInteger phi = tmp.Multiply(pub.Y.ModPow(k, p)).Mod(p);

				byte[] out1 = gamma.ToByteArray();
				byte[] out2 = phi.ToByteArray();
				output = new byte[this.GetOutputBlockSize()];

				int out1Start = out1[0] == 0 ? 1 : 0;
				Array.Copy(out1, out1Start, output, output.Length / 2 - (out1.Length - out1Start), out1.Length - out1Start);

				int out2Start = out2[0] == 0 ? 1 : 0;
				Array.Copy(out2, out2Start, output, output.Length - (out2.Length - out2Start), out2.Length - out2Start);
			}

			return output;
		}
	}
}
