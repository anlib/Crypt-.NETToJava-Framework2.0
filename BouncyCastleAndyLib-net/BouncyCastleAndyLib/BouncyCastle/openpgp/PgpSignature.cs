using System;
using System.IO;
using Org.BouncyCastle.Asn1;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.Date;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{
	/// <remarks>A PGP signature object.</remarks>
    public class PgpSignature
    {
        public const int BinaryDocument = 0x00;
        public const int CanonicalTextDocument = 0x01;
        public const int StandAlone = 0x02;

        public const int DefaultCertification = 0x10;
        public const int NoCertification = 0x11;
        public const int CasualCertification = 0x12;
        public const int PositiveCertification = 0x13;

        public const int SubkeyBinding = 0x18;
        public const int DirectKey = 0x1f;
        public const int KeyRevocation = 0x20;
        public const int SubkeyRevocation = 0x28;
        public const int CertificationRevocation = 0x30;
        public const int Timestamp = 0x40;

        private SignaturePacket	sigPck;
        private ISigner			sig;
        private int				signatureType;
        private TrustPacket		trustPck;
		private byte			lastb;

        internal PgpSignature(
            BcpgInputStream bcpgInput)
            : this((SignaturePacket)bcpgInput.ReadPacket())
        {
        }

		internal PgpSignature(
            SignaturePacket sigPacket)
        {
            sigPck = sigPacket;
            signatureType = sigPck.SignatureType;
            trustPck = null;
        }

        internal PgpSignature(
            SignaturePacket	sigPacket,
            TrustPacket		trustPacket)
            : this(sigPacket)
        {
            this.trustPck = trustPacket;
        }

        private void GetSig()
        {
            this.sig = SignerUtilities.GetSigner(
				PgpUtilities.GetSignatureName(sigPck.KeyAlgorithm, sigPck.HashAlgorithm));
        }

		/// <summary>The OpenPGP version number for this signature.</summary>
		public int Version
		{
			get { return sigPck.Version; }
		}

		/// <summary>The key algorithm associated with this signature.</summary>
		public PublicKeyAlgorithmTag KeyAlgorithm
		{
			get { return sigPck.KeyAlgorithm; }
		}

		/// <summary>The hash algorithm associated with this signature.</summary>
		public HashAlgorithmTag HashAlgorithm
		{
			get { return sigPck.HashAlgorithm; }
		}

		public void InitVerify(
            PgpPublicKey pubKey)
        {
			lastb = 0;
            if (sig == null)
            {
                GetSig();
            }
            try
            {
                sig.Init(false, pubKey.GetKey());
            }
            catch (InvalidKeyException e)
            {
                throw new PgpException("invalid key.", e);
            }
        }

        public void Update(
            byte b)
        {
            if (signatureType == PgpSignature.CanonicalTextDocument)
            {
				doCanonicalUpdateByte(b);
            }
            else
            {
                sig.Update(b);
            }
        }

		private void doCanonicalUpdateByte(
			byte b)
		{
			if (b == '\r')
			{
				doUpdateCRLF();
			}
			else if (b == '\n')
			{
				if (lastb != '\r')
				{
					doUpdateCRLF();
				}
			}
			else
			{
				sig.Update(b);
			}

			lastb = b;
		}

		private void doUpdateCRLF()
		{
			sig.Update((byte)'\r');
			sig.Update((byte)'\n');
		}

		public void Update(
            byte[] bytes)
        {
            if (signatureType == PgpSignature.CanonicalTextDocument)
            {
                for (int i = 0; i != bytes.Length; i++)
                {
                    this.doCanonicalUpdateByte(bytes[i]);
                }
            }
            else
            {
                sig.BlockUpdate(bytes, 0, bytes.Length);
            }
        }

		public void Update(
            byte[]	bytes,
            int		off,
            int		length)
        {
            if (signatureType == PgpSignature.CanonicalTextDocument)
            {
                int finish = off + length;

				for (int i = off; i != finish; i++)
                {
                    this.doCanonicalUpdateByte(bytes[i]);
                }
            }
            else
            {
                sig.BlockUpdate(bytes, off, length);
            }
        }

		public bool Verify()
        {
            byte[] trailer = this.GetSignatureTrailer();
            sig.BlockUpdate(trailer, 0, trailer.Length);

			return sig.VerifySignature(this.GetSignature());
        }

		/// <summary>
		/// Verify the signature as certifying the passed in public key as associated
		/// with the passed in ID.
		/// </summary>
		/// <param name="id">ID the key was stored under.</param>
		/// <param name="key">The key to be verified.</param>
		/// <returns>True, if the signature matches, false otherwise.</returns>
        public bool VerifyCertification(
            string			id,
            PgpPublicKey	key)
        {
            byte[] keyBytes;
            try
            {
                keyBytes = key.publicPk.GetEncodedContents();
            }
            catch (IOException e)
            {
                throw new PgpException("can't Get encoding of public key", e);
            }

			this.Update((byte)0x99);
            this.Update((byte)(keyBytes.Length >> 8));
            this.Update((byte)(keyBytes.Length));
            this.Update(keyBytes);

			//
            // hash in the id
            //
            byte[] idBytes = new byte[id.Length];

			for (int i = 0; i != idBytes.Length; i++)
            {
                idBytes[i] = (byte)id[i];
            }

			this.Update((byte)0xb4);
            this.Update((byte)(idBytes.Length >> 24));
            this.Update((byte)(idBytes.Length >> 16));
            this.Update((byte)(idBytes.Length >> 8));
            this.Update((byte)(idBytes.Length));
            this.Update(idBytes, 0, idBytes.Length);
            byte[] trailer = sigPck.GetSignatureTrailer();
            this.Update(trailer, 0, trailer.Length);

			return sig.VerifySignature(this.GetSignature());
        }

		/// <summary>Verify a certification for the passed in key against the passed in master key.</summary>
		/// <param name="masterKey">The key we are verifying against.</param>
		/// <param name="pubKey">The key we are verifying.</param>
		/// <returns>True, if the certification is valid, false otherwise.</returns>
        public bool VerifyCertification(
            PgpPublicKey	masterKey,
            PgpPublicKey	pubKey)
        {
            byte[] keyBytes;
            try
            {
                keyBytes = masterKey.publicPk.GetEncodedContents();
            }
            catch (IOException e)
            {
                throw new PgpException("exception preparing key.", e);
            }

			this.Update((byte)0x99);
            this.Update((byte)(keyBytes.Length >> 8));
            this.Update((byte)(keyBytes.Length));
            this.Update(keyBytes, 0, keyBytes.Length);

			try
            {
                keyBytes = pubKey.publicPk.GetEncodedContents();
            }
            catch (IOException e)
            {
                throw new PgpException("exception preparing key.", e);
            }
            this.Update((byte)0x99);
            this.Update((byte)(keyBytes.Length >> 8));
            this.Update((byte)(keyBytes.Length));
            this.Update(keyBytes, 0, keyBytes.Length);

			byte[] trailer = sigPck.GetSignatureTrailer();
            this.Update(trailer, 0, trailer.Length);

			return sig.VerifySignature(this.GetSignature());
        }

		/// <summary>Verify a key certification, such as revocation, for the passed in key.</summary>
		/// <param name="pubKey">The key we are checking.</param>
		/// <returns>True, if the certification is valid, false otherwise.</returns>
        public bool VerifyCertification(
            PgpPublicKey pubKey)
        {
            if (this.SignatureType != KeyRevocation
                && this.SignatureType != SubkeyRevocation)
            {
                throw new InvalidOperationException("signature is not a key signature");
            }

			byte[] keyBytes;
			try
            {
                keyBytes = pubKey.publicPk.GetEncodedContents();
            }
            catch (IOException e)
            {
                throw new PgpException("exception preparing key.", e);
            }

			this.Update((byte)0x99);
            this.Update((byte)(keyBytes.Length >> 8));
            this.Update((byte)(keyBytes.Length));
            this.Update(keyBytes, 0, keyBytes.Length);

			byte[] trailer = sigPck.GetSignatureTrailer();
            this.Update(trailer, 0, trailer.Length);

			return sig.VerifySignature(this.GetSignature());
        }

		public int SignatureType
        {
			get { return sigPck.SignatureType; }
        }

		/// <summary>The ID of the key that created the signature.</summary>
        public long KeyId
        {
            get { return sigPck.KeyId; }
        }

		[Obsolete("Use 'CreationTime' property instead")]
		public DateTime GetCreationTime()
		{
			return CreationTime;
		}

		/// <summary>The creation time of this signature.</summary>
        public DateTime CreationTime
        {
			get { return DateTimeUtilities.UnixMsToDateTime(sigPck.CreationTime); }
        }

		public byte[] GetSignatureTrailer()
        {
            return sigPck.GetSignatureTrailer();
        }

		public PgpSignatureSubpacketVector GetHashedSubPackets()
        {
            return createSubpacketVector(sigPck.GetHashedSubPackets());
        }

		public PgpSignatureSubpacketVector GetUnhashedSubPackets()
        {
            return createSubpacketVector(sigPck.GetUnhashedSubPackets());
        }

		private PgpSignatureSubpacketVector createSubpacketVector(SignatureSubpacket[] pcks)
		{
			return pcks == null ? null : new PgpSignatureSubpacketVector(pcks);
		}

		public byte[] GetSignature()
        {
            MPInteger[] sigValues = sigPck.GetSignature();
            byte[] signature;
            if (sigValues.Length == 1)    // an RSA signature
            {
                byte[] sBytes = sigValues[0].Value.ToByteArray();

				if (sBytes[0] == 0)
                {
                    signature = new byte[sBytes.Length - 1];
                    Array.Copy(sBytes, 1, signature, 0, signature.Length);
                }
                else
                {
                    signature = sBytes;
                }
            }
            else
            {
				try
                {
                    signature = new DerSequence(
						new DerInteger(sigValues[0].Value),
						new DerInteger(sigValues[1].Value)).GetEncoded();
                }
                catch (IOException e)
                {
                    throw new PgpException("exception encoding DSA sig.", e);
                }
            }

			return signature;
        }

		// TODO Handle the encoding stuff by subclassing BcpgObject?
		public byte[] GetEncoded()
        {
            MemoryStream bOut = new MemoryStream();

			this.Encode(bOut);

			return bOut.ToArray();
        }

		public void Encode(
            Stream outStream)
        {
            BcpgOutputStream bcpgOut = BcpgOutputStream.Wrap(outStream);

			bcpgOut.WritePacket(sigPck);

			if (trustPck != null)
            {
                bcpgOut.WritePacket(trustPck);
            }
        }
    }
}
