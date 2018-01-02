using System;
using System.Collections;
using System.IO;
using System.Text;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.CryptoPro;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Asn1.Oiw;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Pkcs
{
    public sealed class PrivateKeyInfoFactory
    {
        private PrivateKeyInfoFactory()
        {
        }

        public static PrivateKeyInfo CreatePrivateKeyInfo(
			AsymmetricKeyParameter key)
        {
			if (key == null)
				throw new ArgumentNullException("key");
			if (!key.IsPrivate)
				throw new ArgumentException("Public key passed - private key expected", "key");

			if (key is ElGamalPrivateKeyParameters)
            {
                ElGamalPrivateKeyParameters _key = (ElGamalPrivateKeyParameters)key;
                PrivateKeyInfo info = new PrivateKeyInfo(
                    new AlgorithmIdentifier(
                        OiwObjectIdentifiers.ElGamalAlgorithm,
                        new ElGamalParameter(
                            _key.Parameters.P,
                            _key.Parameters.G).ToAsn1Object()),
					new DerInteger(_key.X));

				return info;
			}

			if (key is DsaPrivateKeyParameters)
            {
                DsaPrivateKeyParameters _key = (DsaPrivateKeyParameters)key;
                PrivateKeyInfo info = new PrivateKeyInfo(
                    new AlgorithmIdentifier(
                        X9ObjectIdentifiers.IdDsa,
                        new DsaParameter(
                            _key.Parameters.P,
                            _key.Parameters.Q,
                            _key.Parameters.G).ToAsn1Object()),
					new DerInteger(_key.X));

				return info;
            }

			if (key is DHPrivateKeyParameters)
            {
				/*
					Process DH private key.
					The value for L was set to zero implicitly.
					This is the same action as found in JCEDHPrivateKey GetEncoded method.
				*/

				DHPrivateKeyParameters _key = (DHPrivateKeyParameters)key;

				DHParameter withNewL = new DHParameter(
					_key.Parameters.P, _key.Parameters.G, 0);

				PrivateKeyInfo info = new PrivateKeyInfo(
                    new AlgorithmIdentifier(
						PkcsObjectIdentifiers.DhKeyAgreement,
						withNewL.ToAsn1Object()),
					new DerInteger(_key.X));

				return info;
            }

			if (key is RsaKeyParameters)
			{
				if (key is RsaPrivateCrtKeyParameters)
				{
					RsaPrivateCrtKeyParameters _key = (RsaPrivateCrtKeyParameters)key;
					PrivateKeyInfo info = new PrivateKeyInfo(
						new AlgorithmIdentifier(
							PkcsObjectIdentifiers.RsaEncryption,
							DerNull.Instance),
						new RsaPrivateKeyStructure(
							_key.Modulus,
							_key.PublicExponent,
							_key.Exponent,
							_key.P,
							_key.Q,
							_key.DP,
							_key.DQ,
							_key.QInv).ToAsn1Object());

					return info;
				}

				// TODO Check that we are not supposed to be able to encode these
//				RsaKeyParameters rkp = (RsaKeyParameters) key;
			}

			if (key is ECPrivateKeyParameters)
            {
                ECPrivateKeyParameters _key = (ECPrivateKeyParameters)key;

				if (_key.AlgorithmName == "ECGOST3410")
				{
					throw new NotImplementedException();
				}
				else
				{
					X9ECParameters ecP = new X9ECParameters(
						_key.Parameters.Curve,
						_key.Parameters.G,
						_key.Parameters.N,
						_key.Parameters.H,
						_key.Parameters.GetSeed());

					X962Parameters x962 = new X962Parameters(ecP);

					PrivateKeyInfo info = new PrivateKeyInfo(
						new AlgorithmIdentifier(X9ObjectIdentifiers.IdECPublicKey, x962.ToAsn1Object()),
						new ECPrivateKeyStructure(_key.D).ToAsn1Object());

					return info;
				}
            }

			if (key is Gost3410PrivateKeyParameters)
			{
				Gost3410PrivateKeyParameters _key = (Gost3410PrivateKeyParameters)key;

				if (_key.PublicKeyParamSet == null)
					throw new NotImplementedException("Encoding only implemented for CryptoPro parameter sets");

				// TODO Once it is efficiently implemented, use ToByteArrayUnsigned
				byte[] keyEnc = _key.X.ToByteArray();
				byte[] keyBytes;

				if (keyEnc[0] == 0)
				{
					keyBytes = new byte[keyEnc.Length - 1];
				}
				else
				{
					keyBytes = new byte[keyEnc.Length];
				}

				for (int i = 0; i != keyBytes.Length; i++)
				{
					keyBytes[i] = keyEnc[keyEnc.Length - 1 - i]; // must be little endian
				}

				Gost3410PublicKeyAlgParameters algParams = new Gost3410PublicKeyAlgParameters(
					_key.PublicKeyParamSet, CryptoProObjectIdentifiers.GostR3411x94CryptoProParamSet, null);

				AlgorithmIdentifier algID = new AlgorithmIdentifier(
					CryptoProObjectIdentifiers.GostR3410x94,
					algParams.ToAsn1Object());

				return new PrivateKeyInfo(algID, new DerOctetString(keyBytes));
			}

			throw new ArgumentException("Class provided is not convertible: " + key.GetType().FullName);
        }

		public static PrivateKeyInfo CreatePrivateKeyInfo(
			char[]					passPhrase,
			EncryptedPrivateKeyInfo	encInfo)
		{
			return CreatePrivateKeyInfo(passPhrase, false, encInfo);
		}

		public static PrivateKeyInfo CreatePrivateKeyInfo(
			char[]					passPhrase,
			bool					wrongPkcs12Zero,
			EncryptedPrivateKeyInfo	encInfo)
        {
			AlgorithmIdentifier algID = encInfo.EncryptionAlgorithm;
			IBufferedCipher cipher = PbeUtilities.CreateEngine(algID.ObjectID) as IBufferedCipher;

			if (cipher == null)
			{
				// TODO Throw exception?
			}

			ICipherParameters keyParameters = PbeUtilities.GenerateCipherParameters(
				algID.ObjectID, passPhrase, wrongPkcs12Zero, algID.Parameters);

			cipher.Init(false, keyParameters);

			byte[] keyBytes = encInfo.GetEncryptedData();
			byte[] encoding = cipher.DoFinal(keyBytes);
			Asn1Object asn1Data = Asn1Object.FromByteArray(encoding);

			return PrivateKeyInfo.GetInstance(asn1Data);
        }
    }
}
