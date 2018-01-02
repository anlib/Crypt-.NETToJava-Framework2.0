using System;

using Org.BouncyCastle.Crypto;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{
	/// <remarks>General class to contain a private key for use with other OpenPGP objects.</remarks>
    public class PgpPrivateKey
    {
        private readonly long keyId;
        private readonly AsymmetricKeyParameter privateKey;

		internal PgpPrivateKey(
            AsymmetricKeyParameter	privateKey,
            long					keyId)
        {
			if (!privateKey.IsPrivate)
				throw new ArgumentException("Expected a private key", "privateKey");

			this.privateKey = privateKey;
            this.keyId = keyId;
        }

		/// <summary>The keyId associated with the contained private key.</summary>
        public long KeyId
        {
			get { return keyId; }
        }

		/// <summary>The contained private key.</summary>
        public AsymmetricKeyParameter Key
        {
			get { return privateKey; }
        }
    }
}
