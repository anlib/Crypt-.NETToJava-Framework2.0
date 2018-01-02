using System;
using System.Collections;
using System.IO;
using System.Text;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.CryptoPro;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Asn1.Oiw;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;

namespace Org.BouncyCastle.Security
{
    public sealed class PublicKeyFactory
    {
        private PublicKeyFactory()
        {
        }

		public static AsymmetricKeyParameter CreateKey(
			byte[] keyInfoData)
		{
			return CreateKey(
				SubjectPublicKeyInfo.GetInstance(
					Asn1Object.FromByteArray(keyInfoData)));
		}

		public static AsymmetricKeyParameter CreateKey(
			Stream inStr)
		{
			return CreateKey(
				SubjectPublicKeyInfo.GetInstance(
					new Asn1InputStream(inStr).ReadObject()));
		}

		public static AsymmetricKeyParameter CreateKey(
			SubjectPublicKeyInfo keyInfo)
        {
            AlgorithmIdentifier algID = keyInfo.AlgorithmID;

			if (algID.ObjectID.Equals(PkcsObjectIdentifiers.RsaEncryption)
				|| algID.ObjectID.Equals(X509ObjectIdentifiers.IdEARsa))
			{
				RsaPublicKeyStructure pubKey = RsaPublicKeyStructure.GetInstance(keyInfo.GetPublicKey());

				return new RsaKeyParameters(false, pubKey.Modulus, pubKey.PublicExponent);
			}
			else if (algID.ObjectID.Equals(PkcsObjectIdentifiers.DhKeyAgreement)
				|| algID.ObjectID.Equals(X9ObjectIdentifiers.DHPublicNumber))
			{
				DHParameter para = new DHParameter((Asn1Sequence)keyInfo.AlgorithmID.Parameters);
				DerInteger derY = (DerInteger)keyInfo.GetPublicKey();

				return new DHPublicKeyParameters(derY.Value, new DHParameters(para.P, para.G));
			}
			else if (algID.ObjectID.Equals(OiwObjectIdentifiers.ElGamalAlgorithm))
			{
				ElGamalParameter para = new ElGamalParameter((Asn1Sequence)keyInfo.AlgorithmID.Parameters);
				DerInteger derY = (DerInteger)keyInfo.GetPublicKey();

				return new ElGamalPublicKeyParameters(derY.Value, new ElGamalParameters(para.P, para.G));
			}
			else if (algID.ObjectID.Equals(X9ObjectIdentifiers.IdDsa)
				|| algID.ObjectID.Equals(OiwObjectIdentifiers.DsaWithSha1))
			{
				DsaParameter para = DsaParameter.GetInstance(keyInfo.AlgorithmID.Parameters);
				DerInteger derY = (DerInteger)keyInfo.GetPublicKey();

				return new DsaPublicKeyParameters(derY.Value, new DsaParameters(para.P, para.Q, para.G));
			}
			else if (algID.ObjectID.Equals(X9ObjectIdentifiers.IdECPublicKey))
			{
				X962Parameters para = new X962Parameters((Asn1Object)keyInfo.AlgorithmID.Parameters);
				ECDomainParameters dParams = null;

				if (para.IsNamedCurve)
				{
					DerObjectIdentifier oid = (DerObjectIdentifier)para.Parameters;
					X9ECParameters ecP = X962NamedCurves.GetByOid(oid);

					if (ecP == null)
					{
						ecP = SecNamedCurves.GetByOid(oid);

						if (ecP == null)
						{
							ecP = NistNamedCurves.GetByOid(oid);
						}
					}

					dParams = new ECDomainParameters(
						ecP.Curve,
						ecP.G,
						ecP.N,
						ecP.H,
						ecP.GetSeed());
				}
				else
				{
					X9ECParameters ecP = new X9ECParameters((Asn1Sequence)para.Parameters.ToAsn1Object());

					dParams = new ECDomainParameters(
						ecP.Curve,
						ecP.G,
						ecP.N,
						ecP.H,
						ecP.GetSeed());
				}

				DerBitString bits = keyInfo.PublicKeyData;
				byte[] data = bits.GetBytes();
				Asn1OctetString key = new DerOctetString(data);

				X9ECPoint derQ = new X9ECPoint(dParams.Curve, key);

				return new ECPublicKeyParameters(derQ.Point, dParams);
			}
			else if (algID.ObjectID.Equals(CryptoProObjectIdentifiers.GostR3410x2001))
			{
				Gost3410PublicKeyAlgParameters gostParams = new Gost3410PublicKeyAlgParameters(
					(Asn1Sequence) algID.Parameters);

				Asn1OctetString key;
				try
				{
					key = (Asn1OctetString) keyInfo.GetPublicKey();
				}
				catch (IOException)
				{
					throw new ArgumentException("invalid info structure in GOST3410 public key");
				}

				byte[] keyEnc = key.GetOctets();
				byte[] x = new byte[32];
				byte[] y = new byte[32];

				for (int i = 0; i != y.Length; i++)
				{
					x[i] = keyEnc[32 - 1 - i];
				}

				for (int i = 0; i != x.Length; i++)
				{
					y[i] = keyEnc[64 - 1 - i];
				}

				ECDomainParameters ecP = ECGost3410NamedCurves.GetByOid(gostParams.PublicKeyParamSet);

				if (ecP == null)
					return null;

				ECCurve curve = ecP.Curve;
				ECPoint q;

				if (curve is FpCurve)
				{
					FpCurve curveFp = (FpCurve) curve;
					q = new FpPoint(
						curveFp,
						new FpFieldElement(curveFp.Q, new BigInteger(1, x)),
						new FpFieldElement(curveFp.Q, new BigInteger(1, y)));
				}
				else
				{
					F2mCurve curveF2m = (F2mCurve) curve;
					q = new F2mPoint(
						curveF2m,
						new F2mFieldElement(curveF2m.M, curveF2m.K1, curveF2m.K2, curveF2m.K3, new BigInteger(1, x)),
						new F2mFieldElement(curveF2m.M, curveF2m.K1, curveF2m.K2, curveF2m.K3, new BigInteger(1, y)),
						false);
				}

				return new ECPublicKeyParameters(q, gostParams.PublicKeyParamSet);
			}
			else if (algID.ObjectID.Equals(CryptoProObjectIdentifiers.GostR3410x94))
			{
				Gost3410PublicKeyAlgParameters algParams = new Gost3410PublicKeyAlgParameters(
					(Asn1Sequence) algID.Parameters);

				DerOctetString derY;
				try
				{
					derY = (DerOctetString) keyInfo.GetPublicKey();
				}
				catch (IOException)
				{
					throw new ArgumentException("invalid info structure in GOST3410 public key");
				}

				byte[] keyEnc = derY.GetOctets();
				byte[] keyBytes = new byte[keyEnc.Length];

				for (int i = 0; i != keyEnc.Length; i++)
				{
					keyBytes[i] = keyEnc[keyEnc.Length - 1 - i]; // was little endian
				}

				BigInteger y = new BigInteger(1, keyBytes);

				return new Gost3410PublicKeyParameters(y, algParams.PublicKeyParamSet);
			}
            else
            {
                throw new SecurityUtilityException("algorithm identifier in key not recognised: " + algID.ObjectID);
            }
        }
    }
}
