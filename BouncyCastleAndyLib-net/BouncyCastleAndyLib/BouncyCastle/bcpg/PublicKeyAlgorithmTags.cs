namespace Org.BouncyCastle.Bcpg
{
	/// <remarks>Public Key Algorithm tag numbers.</remarks>
    public enum PublicKeyAlgorithmTag
    {
        RsaGeneral = 1,			// RSA (Encrypt or Sign)
        RsaEncrypt = 2,			// RSA Encrypt-Only
        RsaSign = 3,			// RSA Sign-Only
        ElGamalEncrypt = 16,	// Elgamal (Encrypt-Only), see [ELGAMAL]
        Dsa = 17,				// DSA (Digital Signature Standard)
        EC = 18,				// Reserved for Elliptic Curve
        ECDsa = 19,				// Reserved for ECDSA
        ElGamalGeneral = 20,	// Elgamal (Encrypt or Sign)
        DiffieHellman = 21		// Reserved for Diffie-Hellman (X9.42, as defined for IETF-S/MIME)
    }
}
