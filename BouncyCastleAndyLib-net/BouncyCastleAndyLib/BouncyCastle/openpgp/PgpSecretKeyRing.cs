using System;
using System.Collections;
using System.IO;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.Collections;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{
	/// <remarks>Holder for a collection of PGP secret keys.</remarks>
    public class PgpSecretKeyRing
		: PgpObject
    {
        private readonly ArrayList keys;

		internal PgpSecretKeyRing(
			ArrayList keys)
        {
            this.keys = keys;
        }

        public PgpSecretKeyRing(
            byte[] encoding)
            : this(new MemoryStream(encoding))
        {
        }

		public PgpSecretKeyRing(
            Stream inputStream)
        {
			this.keys = new ArrayList();

			BcpgInputStream bcpgInput = BcpgInputStream.Wrap(inputStream);
            PacketTag initialTag = bcpgInput.NextPacketTag();

			if (initialTag != PacketTag.SecretKey && initialTag != PacketTag.SecretSubkey)
            {
                throw new IOException(
                    "secret key ring doesn't start with secret key tag: " +
                    "tag 0x" + initialTag.ToString("X"));
            }

            SecretKeyPacket secret = (SecretKeyPacket)bcpgInput.ReadPacket();
            TrustPacket trust = null;
            ArrayList keySigs = new ArrayList();
            ArrayList ids = new ArrayList();
            ArrayList idTrusts = new ArrayList();
            ArrayList idSigs = new ArrayList();
            IDigest sha;

			try
            {
                sha = DigestUtilities.GetDigest("SHA1");
            }
            catch (Exception)
            {
                throw new IOException("can't find SHA1 digest");
            }

            //
            // ignore GPG comment packets if found.
            //
            while (bcpgInput.NextPacketTag() == PacketTag.Experimental2)
            {
                bcpgInput.ReadPacket();
            }

            if (bcpgInput.NextPacketTag() == PacketTag.Trust)
            {
                trust = (TrustPacket) bcpgInput.ReadPacket(); // ignore for the moment
            }

            //
            // revocation and direct signatures
            //
            while (bcpgInput.NextPacketTag() == PacketTag.Signature)
            {
                try
                {
                    keySigs.Add(new PgpSignature(bcpgInput));
                }
                catch (PgpException e)
                {
                    throw new IOException("can't create signature object: " + e.Message + ", cause: " + e.InnerException.ToString());
                }
            }

            while (bcpgInput.NextPacketTag() == PacketTag.UserId
                || bcpgInput.NextPacketTag() == PacketTag.UserAttribute)
            {
                object obj = bcpgInput.ReadPacket();
                ArrayList sigList = new ArrayList();

                if (obj is UserIdPacket)
                {
                    UserIdPacket id = (UserIdPacket)obj;
                    ids.Add(id.GetId());
                }
                else
                {
                    UserAttributePacket user = (UserAttributePacket)obj;
                    ids.Add(new PgpUserAttributeSubpacketVector(user.GetSubpackets()));
                }

                if (bcpgInput.NextPacketTag() == PacketTag.Trust)
                {
                    idTrusts.Add(bcpgInput.ReadPacket());
                }
                else
                {
                    idTrusts.Add(null);
                }

				idSigs.Add(sigList);

				while (bcpgInput.NextPacketTag() == PacketTag.Signature)
                {
                    SignaturePacket s = (SignaturePacket) bcpgInput.ReadPacket();

					if (bcpgInput.NextPacketTag() == PacketTag.Trust)
                    {
                        sigList.Add(new PgpSignature(s, (TrustPacket) bcpgInput.ReadPacket()));
                    }
                    else
                    {
                        sigList.Add(new PgpSignature(s));
                    }
                }
            }

			keys.Add(new PgpSecretKey(secret, trust, sha, keySigs, ids, idTrusts, idSigs));

            while (bcpgInput.NextPacketTag() == PacketTag.SecretSubkey)
            {
                SecretSubkeyPacket sub = (SecretSubkeyPacket)bcpgInput.ReadPacket();
                TrustPacket subTrust = null;
                ArrayList sigList = new ArrayList();

                //
                // ignore GPG comment packets if found.
                //
                while (bcpgInput.NextPacketTag() == PacketTag.Experimental2)
                {
                    bcpgInput.ReadPacket();
                }

                if (bcpgInput.NextPacketTag() == PacketTag.Trust)
                {
                    subTrust = (TrustPacket) bcpgInput.ReadPacket();
                }

				while (bcpgInput.NextPacketTag() == PacketTag.Signature)
                {
                    SignaturePacket s = (SignaturePacket) bcpgInput.ReadPacket();

					if (bcpgInput.NextPacketTag() == PacketTag.Trust)
                    {
                        sigList.Add(new PgpSignature(s, (TrustPacket) bcpgInput.ReadPacket()));
                    }
                    else
                    {
                        sigList.Add(new PgpSignature(s));
                    }
                }

				keys.Add(new PgpSecretKey(sub, subTrust, sha, sigList));
            }
        }

		/// <summary>Return the public key for the master key.</summary>
        public PgpPublicKey GetPublicKey()
        {
            return ((PgpSecretKey) keys[0]).PublicKey;
        }

		/// <summary>Return the master private key.</summary>
        public PgpSecretKey GetSecretKey()
        {
            return (PgpSecretKey) keys[0];
        }

		/// <summary>Allows enumeration of the secret keys.</summary>
		/// <returns>An <c>IEnumerable</c> of <c>PgpSecretKey</c> objects.</returns>
		public IEnumerable GetSecretKeys()
        {
            return new EnumerableProxy(keys);
        }

        public PgpSecretKey GetSecretKey(
            long keyId)
        {
			foreach (PgpSecretKey k in keys)
			{
				if (keyId == k.KeyId)
				{
					return k;
				}
			}

			return null;
        }

		public byte[] GetEncoded()
        {
            MemoryStream bOut = new MemoryStream();

            this.Encode(bOut);

            return bOut.ToArray();
        }

        public void Encode(
            Stream outStr)
        {
			if (outStr == null)
				throw new ArgumentNullException("outStr");

			foreach (PgpSecretKey k in keys)
			{
				k.Encode(outStr);
			}
        }

		/// <summary>
		/// Returns a new key ring with the secret key passed in either added or
		/// replacing an existing one with the same key ID.
		/// </summary>
		/// <param name="secRing">The secret key ring to be modified.</param>
		/// <param name="secKey">The secret key to be inserted.</param>
		/// <returns>A new <c>PgpSecretKeyRing</c></returns>
		public static PgpSecretKeyRing InsertSecretKey(
            PgpSecretKeyRing  secRing,
            PgpSecretKey      secKey)
        {
            ArrayList keys = new ArrayList(secRing.keys);
            bool found = false;

			for (int i = 0; i != keys.Count; i++)
            {
                PgpSecretKey key = (PgpSecretKey) keys[i];

				if (key.KeyId == secKey.KeyId)
                {
                    found = true;
                    keys[i] = secKey;
                }
            }

            if (!found)
            {
                keys.Add(secKey);
            }

            return new PgpSecretKeyRing(keys);
        }

		/// <summary>Returns a new key ring with the secret key passed in removed from the key ring.</summary>
		/// <param name="secRing">The secret key ring to be modified.</param>
		/// <param name="secKey">The secret key to be removed.</param>
		/// <returns>A new <c>PgpSecretKeyRing</c>, or null if secKey is not found.</returns>
        public static PgpSecretKeyRing RemoveSecretKey(
            PgpSecretKeyRing  secRing,
            PgpSecretKey      secKey)
        {
            ArrayList keys = new ArrayList(secRing.keys);
            bool found = false;

			for (int i = 0; i < keys.Count; i++)
            {
                PgpSecretKey key = (PgpSecretKey)keys[i];

				if (key.KeyId == secKey.KeyId)
                {
                    found = true;
                    keys.RemoveAt(i);
                }
            }

			return found ? new PgpSecretKeyRing(keys) : null;
        }
    }
}
