using System;
using System.Collections;
using System.Globalization;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.CryptoPro;
using Org.BouncyCastle.Asn1.Iana;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Asn1.Oiw;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;

namespace Org.BouncyCastle.Security
{
	public sealed class GeneratorUtilities
	{
		private GeneratorUtilities()
		{
		}

		private static readonly Hashtable kgAlgorithms = new Hashtable();
		private static readonly Hashtable kpgAlgorithms = new Hashtable();

		static GeneratorUtilities()
		{
			//
			// key generators.
			//
			kgAlgorithms["AESWRAP"] = "AES";
			kgAlgorithms["2.16.840.1.101.3.4.2"] = "AES128";
			kgAlgorithms["2.16.840.1.101.3.4.22"] = "AES192";
			kgAlgorithms["2.16.840.1.101.3.4.42"] = "AES256";
			kgAlgorithms[NistObjectIdentifiers.IdAes128Cbc.Id] = "AES128";
			kgAlgorithms[NistObjectIdentifiers.IdAes128Cfb.Id] = "AES128";
			kgAlgorithms[NistObjectIdentifiers.IdAes128Ecb.Id] = "AES128";
			kgAlgorithms[NistObjectIdentifiers.IdAes128Ofb.Id] = "AES128";
			kgAlgorithms[NistObjectIdentifiers.IdAes128Wrap.Id] = "AES128";
			kgAlgorithms[NistObjectIdentifiers.IdAes192Cbc.Id] = "AES192";
			kgAlgorithms[NistObjectIdentifiers.IdAes192Cfb.Id] = "AES192";
			kgAlgorithms[NistObjectIdentifiers.IdAes192Ecb.Id] = "AES192";
			kgAlgorithms[NistObjectIdentifiers.IdAes192Ofb.Id] = "AES192";
			kgAlgorithms[NistObjectIdentifiers.IdAes192Wrap.Id] = "AES192";
			kgAlgorithms[NistObjectIdentifiers.IdAes256Cbc.Id] = "AES256";
			kgAlgorithms[NistObjectIdentifiers.IdAes256Cfb.Id] = "AES256";
			kgAlgorithms[NistObjectIdentifiers.IdAes256Ecb.Id] = "AES256";
			kgAlgorithms[NistObjectIdentifiers.IdAes256Ofb.Id] = "AES256";
			kgAlgorithms[NistObjectIdentifiers.IdAes256Wrap.Id] = "AES256";
			kgAlgorithms["1.2.840.113533.7.66.10"] = "CAST5";
			kgAlgorithms[OiwObjectIdentifiers.DesCbc.Id] = "DES";
			kgAlgorithms["DESEDEWRAP"] = "DESEDE";
			kgAlgorithms[PkcsObjectIdentifiers.DesEde3Cbc.Id] = "DESEDE3";
			kgAlgorithms["GOST"] = "GOST28147";
			kgAlgorithms["GOST-28147"] = "GOST28147";
			kgAlgorithms[CryptoProObjectIdentifiers.GostR28147Cbc.Id] = "GOST28147";
			kgAlgorithms["1.3.6.1.4.1.188.7.1.1.2"] = "IDEA";
			kgAlgorithms[PkcsObjectIdentifiers.RC2Cbc.Id] = "RC2";
			kgAlgorithms["ARC4"] = "RC4";
			kgAlgorithms["1.2.840.113549.3.4"] = "RC4";
			kgAlgorithms["RC5-32"] = "RC5";

			//
			// HMac key generators
			//
			AddHMacKeyGenerator("MD2");
			AddHMacKeyGenerator("MD4");
			AddHMacKeyGenerator("MD5",
				IanaObjectIdentifiers.HmacMD5);
			AddHMacKeyGenerator("SHA1",
				PkcsObjectIdentifiers.IdHmacWithSha1,
				IanaObjectIdentifiers.HmacSha1);
			AddHMacKeyGenerator("SHA224",
				PkcsObjectIdentifiers.IdHmacWithSha224);
			AddHMacKeyGenerator("SHA256",
				PkcsObjectIdentifiers.IdHmacWithSha256);
			AddHMacKeyGenerator("SHA384",
				PkcsObjectIdentifiers.IdHmacWithSha384);
			AddHMacKeyGenerator("SHA512",
				PkcsObjectIdentifiers.IdHmacWithSha512);
			AddHMacKeyGenerator("RIPEMD128");
			AddHMacKeyGenerator("RIPEMD160",
				IanaObjectIdentifiers.HmacRipeMD160);
			AddHMacKeyGenerator("TIGER",
				IanaObjectIdentifiers.HmacTiger);



			//
			// key pair generators.
			//
			kpgAlgorithms["ECIES"] = "ECDH";
			kpgAlgorithms["ECGOST-3410"] = "ECGOST3410";
			kpgAlgorithms["GOST-3410-2001"] = "ECGOST3410";
			kpgAlgorithms["GOST-3410"] = "GOST3410";
			kpgAlgorithms["GOST-3410-94"] = "GOST3410";
			kpgAlgorithms["1.2.840.113549.1.1.1"] = "RSA";
		}

		private static void AddHMacKeyGenerator(
			string algorithm,
			params object[] aliases)
		{
			string mainName = "HMAC" + algorithm;

			kgAlgorithms["HMAC-" + algorithm] = mainName;
			kgAlgorithms["HMAC/" + algorithm] = mainName;

			foreach (object alias in aliases)
			{
				kgAlgorithms[alias.ToString()] = mainName;
			}
		}

		public static CipherKeyGenerator GetKeyGenerator(
			DerObjectIdentifier oid)
		{
			return GetKeyGenerator(oid.Id);
		}

		public static CipherKeyGenerator GetKeyGenerator(
			string algorithm)
		{
			string upper = algorithm.ToUpper(CultureInfo.InvariantCulture);
			string mechanism = (string) kgAlgorithms[upper];

			if (mechanism == null)
			{
				mechanism = upper;
			}

			switch (mechanism)
			{
				case "DES":
					return new DesKeyGenerator(64);
				case "DESEDE":
				case "DESEDE3":
					return new DesEdeKeyGenerator(192);
				case "AES":
					return new CipherKeyGenerator(192);
				case "AES128":
					return new CipherKeyGenerator(128);
				case "AES192":
					return new CipherKeyGenerator(192);
				case "AES256":
					return new CipherKeyGenerator(256);
				case "BLOWFISH":
					return new CipherKeyGenerator(448);
				case "CAMELLIA":
					return new CipherKeyGenerator(256);
				case "CAST5":
					return new CipherKeyGenerator(128);
				case "CAST6":
					return new CipherKeyGenerator(256);
				case "GOST28147":
					return new CipherKeyGenerator(256);
				case "HMACMD2":
				case "HMACMD4":
				case "HMACMD5":
					return new CipherKeyGenerator(128);
				case "HMACSHA1":
					return new CipherKeyGenerator(160);
				case "HMACSHA224":
					return new CipherKeyGenerator(224);
				case "HMACSHA256":
					return new CipherKeyGenerator(256);
				case "HMACSHA384":
					return new CipherKeyGenerator(384);
				case "HMACSHA512":
					return new CipherKeyGenerator(512);
				case "HMACRIPEMD128":
					return new CipherKeyGenerator(128);
				case "HMACRIPEMD160":
					return new CipherKeyGenerator(160);
				case "HMACTIGER":
					return new CipherKeyGenerator(192);
				case "IDEA":
					return new CipherKeyGenerator(128);
				case "RC2":
				case "RC4":
				case "RC5":
					return new CipherKeyGenerator(128);
				case "RC5-64":
				case "RC6":
					return new CipherKeyGenerator(256);
				case "RIJNDAEL":
					return new CipherKeyGenerator(192);
				case "SERPENT":
					return new CipherKeyGenerator(192);
				case "SKIPJACK":
					return new CipherKeyGenerator(80);
				case "TEA":
				case "XTEA":
					return new CipherKeyGenerator(128);
				case "TWOFISH":
					return new CipherKeyGenerator(256);
			}

			throw new SecurityUtilityException("KeyGenerator " + algorithm + " not recognised.");
		}

		public static IAsymmetricCipherKeyPairGenerator GetKeyPairGenerator(
			DerObjectIdentifier oid)
		{
			return GetKeyPairGenerator(oid.Id);
		}

		public static IAsymmetricCipherKeyPairGenerator GetKeyPairGenerator(
			string algorithm)
		{
			string upper = algorithm.ToUpper(CultureInfo.InvariantCulture);
			string mechanism = (string) kpgAlgorithms[upper];

			if (mechanism == null)
			{
				mechanism = upper;
			}

			switch (mechanism)
			{
				case "DH":
					return new DHKeyPairGenerator();
				case "DSA":
					return new DsaKeyPairGenerator();
				case "EC":
				case "ECDH":
				case "ECDHC":
				case "ECDSA":
				case "ECGOST3410":
					return new ECKeyPairGenerator(mechanism);
				case "ELGAMAL":
					return new ElGamalKeyPairGenerator();
				case "GOST3410":
					return new Gost3410KeyPairGenerator();
				case "RSA":
					return new RsaKeyPairGenerator();
				default:
					break;
			}

			throw new SecurityUtilityException("KeyPairGenerator " + algorithm + " not recognised.");
		}
	}
}
