using System;
using System.Collections;
using System.IO;
using System.Text;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Crypto.Signers
{
	public class Gost3410DigestSigner
		: ISigner
	{
		private readonly IDigest digest;
		private readonly IDsa dsaSigner;
		private bool forSigning;

		public Gost3410DigestSigner(
			IDsa	signer,
			IDigest	digest)
		{
			this.dsaSigner = signer;
			this.digest = digest;
		}

		public string AlgorithmName
		{
			get { return digest.AlgorithmName + "with" + dsaSigner.AlgorithmName; }
		}

		public void Init(
			bool				forSigning,
			ICipherParameters	parameters)
		{
			this.forSigning = forSigning;

			AsymmetricKeyParameter k;
			if (parameters is ParametersWithRandom)
			{
				k = (AsymmetricKeyParameter)((ParametersWithRandom)parameters).Parameters;
			}
			else
			{
				k = (AsymmetricKeyParameter)parameters;
			}

			if (forSigning && !k.IsPrivate)
			{
				throw new InvalidKeyException("Signing Requires Private Key.");
			}

			if (!forSigning && k.IsPrivate)
			{
				throw new InvalidKeyException("Verification Requires Public Key.");
			}

			Reset();

			dsaSigner.Init(forSigning, parameters);
		}

		/**
		 * update the internal digest with the byte b
		 */
		public void Update(
			byte input)
		{
			digest.Update(input);
		}

		/**
		 * update the internal digest with the byte array in
		 */
		public void BlockUpdate(
			byte[]	input,
			int		inOff,
			int		length)
		{
			digest.BlockUpdate(input, inOff, length);
		}

		/**
		 * Generate a signature for the message we've been loaded with using
		 * the key we were initialised with.
		 */
		public byte[] GenerateSignature()
		{
			if (!forSigning)
				throw new InvalidOperationException("GOST3410DigestSigner not initialised for signature generation.");

			byte[] hash = new byte[digest.GetDigestSize()];
			digest.DoFinal(hash, 0);

			try
			{
				BigInteger[] sig = dsaSigner.GenerateSignature(hash);
				byte[] r = sig[0].ToByteArray();
				byte[] s = sig[1].ToByteArray();

				byte[] sigBytes = new byte[64];
				if (s[0] != 0)
				{
					Array.Copy(s, 0, sigBytes, 32 - s.Length, s.Length);
				}
				else
				{
					Array.Copy(s, 1, sigBytes, 32 - (s.Length - 1), s.Length - 1);
				}

				if (r[0] != 0)
				{
					Array.Copy(r, 0, sigBytes, 64 - r.Length, r.Length);
				}
				else
				{
					Array.Copy(r, 1, sigBytes, 64 - (r.Length - 1), r.Length - 1);
				}

				return sigBytes;
			}
			catch (Exception e)
			{
				throw new SignatureException(e.Message, e);
			}
		}

		/// <returns>true if the internal state represents the signature described in the passed in array.</returns>
		public bool VerifySignature(
			byte[] signature)
		{
			if (forSigning)
				throw new InvalidOperationException("DSADigestSigner not initialised for verification");

			byte[] hash = new byte[digest.GetDigestSize()];
			digest.DoFinal(hash, 0);

			BigInteger R, S;
			try
			{
				byte[] x = new byte[32];

				Array.Copy(signature, 32, x, 0, 32);
				R = new BigInteger(1, x);

				Array.Copy(signature, 0, x, 0, 32);
				S = new BigInteger(1, x);
			}
			catch (Exception e)
			{
				throw new SignatureException("error decoding signature bytes.", e);
			}

			return dsaSigner.VerifySignature(hash, R, S);
		}

		/// <summary>Reset the internal state</summary>
		public void Reset()
		{
			digest.Reset();
		}
	}
}
