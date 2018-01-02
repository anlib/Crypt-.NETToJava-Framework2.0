using System;
using System.Collections;
using System.Globalization;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.CryptoPro;
using Org.BouncyCastle.Asn1.Misc;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Asn1.Oiw;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;

namespace Org.BouncyCastle.Security
{
	public sealed class ParameterUtilities
	{
		private ParameterUtilities()
		{
		}

		private static readonly Hashtable algorithms = new Hashtable();

		static ParameterUtilities()
		{
			algorithms["AESWRAP"] = "AES";
			algorithms["2.16.840.1.101.3.4.2"] = "AES";
			algorithms["2.16.840.1.101.3.4.22"] = "AES";
			algorithms["2.16.840.1.101.3.4.42"] = "AES";
			algorithms[NistObjectIdentifiers.IdAes128Cbc.Id] = "AES";
			algorithms[NistObjectIdentifiers.IdAes128Cfb.Id] = "AES";
			algorithms[NistObjectIdentifiers.IdAes128Ecb.Id] = "AES";
			algorithms[NistObjectIdentifiers.IdAes128Ofb.Id] = "AES";
			algorithms[NistObjectIdentifiers.IdAes128Wrap.Id] = "AES";
			algorithms[NistObjectIdentifiers.IdAes192Cbc.Id] = "AES";
			algorithms[NistObjectIdentifiers.IdAes192Cfb.Id] = "AES";
			algorithms[NistObjectIdentifiers.IdAes192Ecb.Id] = "AES";
			algorithms[NistObjectIdentifiers.IdAes192Ofb.Id] = "AES";
			algorithms[NistObjectIdentifiers.IdAes192Wrap.Id] = "AES";
			algorithms[NistObjectIdentifiers.IdAes256Cbc.Id] = "AES";
			algorithms[NistObjectIdentifiers.IdAes256Cfb.Id] = "AES";
			algorithms[NistObjectIdentifiers.IdAes256Ecb.Id] = "AES";
			algorithms[NistObjectIdentifiers.IdAes256Ofb.Id] = "AES";
			algorithms[NistObjectIdentifiers.IdAes256Wrap.Id] = "AES";

			algorithms["1.2.840.113533.7.66.10"] = "CAST5";

			algorithms[OiwObjectIdentifiers.DesCbc.Id] = "DES";

			algorithms[PkcsObjectIdentifiers.DesEde3Cbc.Id] = "DESEDE";
			algorithms[PkcsObjectIdentifiers.IdAlgCms3DesWrap.Id] = "DESEDE";

			algorithms["GOST"] = "GOST28147";
			algorithms["GOST-28147"] = "GOST28147";
			algorithms[CryptoProObjectIdentifiers.GostR28147Cbc.Id] = "GOST28147";

			algorithms["1.3.6.1.4.1.188.7.1.1.2"] = "IDEA";

			algorithms[PkcsObjectIdentifiers.RC2Cbc.Id] = "RC2";
			algorithms[PkcsObjectIdentifiers.IdAlgCmsRC2Wrap.Id] = "RC2";

			algorithms["ARC4"] = "RC4";
			algorithms["1.2.840.113549.3.4"] = "RC4";
		}

		public static KeyParameter CreateKeyParameter(
			DerObjectIdentifier algOid,
			byte[]				keyBytes)
		{
			return CreateKeyParameter(algOid.Id, keyBytes);
		}

		public static KeyParameter CreateKeyParameter(
			string	algorithm,
			byte[]	keyBytes)
		{
			if (algorithm == null)
				throw new ArgumentNullException("algorithm");

			string upper = algorithm.ToUpper(CultureInfo.InvariantCulture);
			string mechanism = (string) algorithms[upper];

			if (mechanism == null)
			{
				mechanism = upper;
			}

			switch (mechanism)
			{
				case "AES":
				case "BLOWFISH":
				case "CAMELLIA":
				case "CAST5":
				case "CAST6":
				case "GOST28147":
				case "IDEA":
				case "RC4":
				case "RC6":
				case "RIJNDAEL":
				case "SERPENT":
				case "SKIPJACK":
				case "TEA":
				case "TWOFISH":
				case "XTEA":
					return new KeyParameter(keyBytes);
				case "DES":
					return new DesParameters(keyBytes);
				case "DESEDE":
				case "DESEDE3":
					return new DesEdeParameters(keyBytes);
				case "RC2":
					return new RC2Parameters(keyBytes);
			}

			throw new SecurityUtilityException("Algorithm " + mechanism + " not recognised.");
		}

		public static ICipherParameters GetCipherParameters(
			DerObjectIdentifier	algOid,
			ICipherParameters	key,
			Asn1Object			asn1Params)
		{
			return GetCipherParameters(algOid.Id, key, asn1Params);
		}

		public static ICipherParameters GetCipherParameters(
			string				algorithm,
			ICipherParameters	key,
			Asn1Object			asn1Params)
		{
			if (algorithm == null)
				throw new ArgumentNullException("algorithm");

			string upper = algorithm.ToUpper(CultureInfo.InvariantCulture);
			string mechanism = (string) algorithms[upper];

			if (mechanism == null)
			{
				mechanism = upper;
			}

			byte[] iv = null;

			try
			{
				switch (mechanism)
				{
					case "AES":
					case "BLOWFISH":
					case "DES":
					case "DESEDE":
					case "RIJNDAEL":
					case "SKIPJACK":
					case "TWOFISH":
						iv = ((Asn1OctetString) asn1Params).GetOctets();
						break;
					case "RC2":
						iv = RC2CbcParameter.GetInstance(asn1Params).GetIV();
						break;
					case "IDEA":
						iv = IdeaCbcPar.GetInstance(asn1Params).GetIV();
						break;
					case "CAST5":
						iv = Cast5CbcParameters.GetInstance(asn1Params).GetIV();
						break;
				}
			}
			catch (Exception e)
			{
				throw new ArgumentException("Could not process ASN.1 parameters", "asn1Params", e);
			}

			if (iv != null)
			{
				return new ParametersWithIV(key, iv);
			}

			throw new SecurityUtilityException("Algorithm " + mechanism + " not recognised.");
		}

		public static Asn1Encodable GenerateParameters(
			DerObjectIdentifier algID,
			SecureRandom		random)
		{
			return GenerateParameters(algID.Id, random);
		}

		public static Asn1Encodable GenerateParameters(
			string			algorithm,
			SecureRandom	random)
		{
			if (algorithm == null)
				throw new ArgumentNullException("algorithm");

			string upper = algorithm.ToUpper(CultureInfo.InvariantCulture);
			string mechanism = (string) algorithms[upper];

			if (mechanism == null)
			{
				mechanism = upper;
			}

			switch (mechanism)
			{
				// TODO These algorithms support an IV (see GetCipherParameters)
				// but JCE doesn't seem to provide an AlgorithmParametersGenerator for them
//				case "BLOWFISH":
//				case "RIJNDAEL":
//				case "SKIPJACK":
//				case "TWOFISH":

				case "AES":
					return CreateIVOctetString(random, 16);
				case "CAST5":
					return new Cast5CbcParameters(CreateIV(random, 8), 128);
				case "DES":
				case "DESEDE":
					return CreateIVOctetString(random, 8);
				case "IDEA":
					return new IdeaCbcPar(CreateIV(random, 8));
				case "RC2":
					return new RC2CbcParameter(CreateIV(random, 8));
			}

			throw new SecurityUtilityException("Algorithm " + mechanism + " not recognised.");
		}

		private static Asn1OctetString CreateIVOctetString(
			SecureRandom	random,
			int				ivLength)
		{
			return new DerOctetString(CreateIV(random, ivLength));
		}

		private static byte[] CreateIV(
			SecureRandom	random,
			int				ivLength)
		{
			byte[] iv = new byte[ivLength];
			random.NextBytes(iv);
			return iv;
		}
	}
}
