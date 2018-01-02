using System;
using System.Collections;

using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Cms
{
	class CmsEnvelopedHelper
	{
		internal static readonly CmsEnvelopedHelper Instance = new CmsEnvelopedHelper();

		private static readonly IDictionary KeySizes = new Hashtable();
		private static readonly IDictionary Ciphers = new Hashtable();

		static CmsEnvelopedHelper()
		{
			KeySizes.Add(CmsEnvelopedGenerator.DesEde3Cbc, 192);
			KeySizes.Add(CmsEnvelopedGenerator.Aes128Cbc, 128);
			KeySizes.Add(CmsEnvelopedGenerator.Aes192Cbc, 192);
			KeySizes.Add(CmsEnvelopedGenerator.Aes256Cbc, 256);

			Ciphers.Add(CmsEnvelopedGenerator.DesEde3Cbc, "DESEDE");
			Ciphers.Add(CmsEnvelopedGenerator.Aes128Cbc, "AES");
			Ciphers.Add(CmsEnvelopedGenerator.Aes192Cbc, "AES");
			Ciphers.Add(CmsEnvelopedGenerator.Aes256Cbc, "AES");
		}

		private string GetEncryptionAlgName(
			string encryptionAlgOid)
		{
			if (PkcsObjectIdentifiers.RsaEncryption.Id.Equals(encryptionAlgOid))
			{
				return "RSA/ECB/PKCS1Padding";
			}

			return encryptionAlgOid;    
		}

		internal IBufferedCipher CreateAsymmetricCipher(
			string encryptionOid)
		{
			try
			{
				return CipherUtilities.GetCipher(encryptionOid);
			}
			catch(SecurityUtilityException)
			{
				return CipherUtilities.GetCipher(GetEncryptionAlgName(encryptionOid));
			}
		}

		internal IWrapper CreateWrapper(
			string encryptionOid)
		{
			try
			{
				return WrapperUtilities.GetWrapper(encryptionOid);
			}
			catch (SecurityUtilityException)
			{
				return WrapperUtilities.GetWrapper(GetEncryptionAlgName(encryptionOid));
			}
		}

		internal CipherKeyGenerator CreateKeyGenerator(
			string encryptionOid)
		{
			return GeneratorUtilities.GetKeyGenerator(encryptionOid);
		}

		internal string GetRfc3211WrapperName(
			string oid)
		{
			string alg = (string)Ciphers[oid];

			if (alg == null)
			{
				throw new ArgumentException("no name for " + oid, "oid");
			}

			return alg + "RFC3211Wrap";
		}

		internal int GetKeySize(
			string oid)
		{
			if (!KeySizes.Contains(oid))
			{
				throw new ArgumentException("no keysize for " + oid, "oid");
			}

			return (int) KeySizes[oid];
		}
	}
}
