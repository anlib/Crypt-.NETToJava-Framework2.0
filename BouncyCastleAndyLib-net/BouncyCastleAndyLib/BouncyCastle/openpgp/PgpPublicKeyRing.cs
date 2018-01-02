using System;
using System.Collections;
using System.IO;

using Org.BouncyCastle.Utilities.Collections;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{
	/// <remarks>General class to hold a collection of PGP public keys.</remarks>
    public class PgpPublicKeyRing
		: PgpObject
    {
        private readonly ArrayList keys;

		public PgpPublicKeyRing(
            byte[] encoding)
            : this(new MemoryStream(encoding, false))
        {
        }

		internal PgpPublicKeyRing(
            ArrayList pubKeys)
        {
            this.keys = pubKeys;
        }

		public PgpPublicKeyRing(
            Stream inputStream)
        {
			this.keys = new ArrayList();

            BcpgInputStream bcpgInput = BcpgInputStream.Wrap(inputStream);

			PacketTag initialTag = bcpgInput.NextPacketTag();
            if (initialTag != PacketTag.PublicKey && initialTag != PacketTag.PublicSubkey)
            {
                throw new IOException(
                    "public key ring doesn't start with public key tag: " +
                    "tag 0x" + initialTag.ToString("X"));
            }

			PublicKeyPacket   pubPk;
            TrustPacket       trustPk;
            ArrayList         keySigs = new ArrayList();
            ArrayList         ids = new ArrayList();
            ArrayList         idTrust = new ArrayList();
            ArrayList         idSigs = new ArrayList();

			pubPk = (PublicKeyPacket)bcpgInput.ReadPacket();
            trustPk = null;
            if (bcpgInput.NextPacketTag() == PacketTag.Trust)
            {
                trustPk = (TrustPacket)bcpgInput.ReadPacket();
            }

			//
            // direct signatures and revocations
            //
            while (bcpgInput.NextPacketTag() == PacketTag.Signature)
            {
                try
                {
                    SignaturePacket s = (SignaturePacket) bcpgInput.ReadPacket();

                    if (bcpgInput.NextPacketTag() == PacketTag.Trust)
                    {
                        keySigs.Add(new PgpSignature(s, (TrustPacket) bcpgInput.ReadPacket()));
                    }
                    else
                    {
                        keySigs.Add(new PgpSignature(s));
                    }
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
                    idTrust.Add(bcpgInput.ReadPacket());
                }
                else
                {
                    idTrust.Add(null);
                }

				ArrayList sigList = new ArrayList();

				idSigs.Add(sigList);

				while (bcpgInput.NextPacketTag() == PacketTag.Signature)
                {
                    try
                    {
                        SignaturePacket s = (SignaturePacket) bcpgInput.ReadPacket();
                        PacketTag next = bcpgInput.NextPacketTag();
                        TrustPacket tp = (next == PacketTag.Trust)
                            ?    (TrustPacket) bcpgInput.ReadPacket()
                            :    null;

						PgpSignature pgpSig = new PgpSignature(s, tp);
                        sigList.Add(pgpSig);
                    }
                    catch (PgpException e)
                    {
                        throw new IOException("can't create signature object: " + e.Message + ", cause: " + e.InnerException.ToString());
                    }
                }
            }

			keys.Add(new PgpPublicKey(pubPk, trustPk, keySigs, ids, idTrust, idSigs));

			while (bcpgInput.NextPacketTag() == PacketTag.PublicSubkey)
            {
                PublicKeyPacket	pk = (PublicKeyPacket)bcpgInput.ReadPacket();
                TrustPacket		kTrust = null;

				if (bcpgInput.NextPacketTag() == PacketTag.Trust)
                {
                    kTrust = (TrustPacket)bcpgInput.ReadPacket();
                }

				ArrayList sigList = new ArrayList();

				try
                {
                    //
                    // PGP 8 actually leaves out the signature.
                    //
                    while (bcpgInput.NextPacketTag() == PacketTag.Signature)
                    {
                        SignaturePacket s = (SignaturePacket) bcpgInput.ReadPacket();

						if (bcpgInput.NextPacketTag() == PacketTag.Trust)
                        {
                            sigList.Add(new PgpSignature(s, (TrustPacket)bcpgInput.ReadPacket()));
                        }
                        else
                        {
                            sigList.Add(new PgpSignature(s));
                        }
                    }
                }
                catch (PgpException e)
                {
                    throw new IOException("can't create signature object: " + e.Message + ", cause: " + e.InnerException.ToString());
                }

				keys.Add(new PgpPublicKey(pk, kTrust, sigList));
            }
        }

		/// <summary>Return the first public key in the ring.</summary>
        public PgpPublicKey GetPublicKey()
        {
            return (PgpPublicKey) keys[0];
        }

		/// <summary>Return the public key referred to by the passed in key ID if it is present.</summary>
        public PgpPublicKey GetPublicKey(
            long keyId)
        {
			foreach (PgpPublicKey k in keys)
			{
				if (keyId == k.KeyId)
                {
                    return k;
                }
            }

			return null;
        }

		/// <summary>Allows enumeration of all the public keys.</summary>
		/// <returns>An <c>IEnumerable</c> of <c>PgpPublicKey</c> objects.</returns>
        public IEnumerable GetPublicKeys()
        {
            return new EnumerableProxy(keys);
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

			foreach (PgpPublicKey k in keys)
			{
				k.Encode(outStr);
            }
        }

		/// <summary>
		/// Returns a new key ring with the public key passed in either added or
		/// replacing an existing one.
		/// </summary>
		/// <param name="pubRing">The public key ring to be modified.</param>
		/// <param name="pubKey">The public key to be inserted.</param>
		/// <returns>A new <c>PgpPublicKeyRing</c></returns>
        public static PgpPublicKeyRing InsertPublicKey(
            PgpPublicKeyRing	pubRing,
            PgpPublicKey		pubKey)
        {
            ArrayList keys = new ArrayList(pubRing.keys);
            bool found = false;

			for (int i = 0; i != keys.Count; i++)
            {
                PgpPublicKey key = (PgpPublicKey) keys[i];

				if (key.KeyId == pubKey.KeyId)
                {
                    found = true;
                    keys[i] = pubKey;
                }
            }

			if (!found)
            {
                keys.Add(pubKey);
            }

			return new PgpPublicKeyRing(keys);
        }

		/// <summary>Returns a new key ring with the public key passed in removed from the key ring.</summary>
		/// <param name="pubRing">The public key ring to be modified.</param>
		/// <param name="pubKey">The public key to be removed.</param>
		/// <returns>A new <c>PgpPublicKeyRing</c>, or null if pubKey is not found.</returns>
        public static PgpPublicKeyRing RemovePublicKey(
            PgpPublicKeyRing	pubRing,
            PgpPublicKey		pubKey)
        {
            ArrayList keys = new ArrayList(pubRing.keys);
            bool found = false;

			for (int i = 0; i < keys.Count; i++)
            {
                PgpPublicKey key = (PgpPublicKey) keys[i];

				if (key.KeyId == pubKey.KeyId)
                {
                    found = true;
                    keys.RemoveAt(i);
                }
            }

			return found ? new PgpPublicKeyRing(keys) : null;
        }
    }
}
