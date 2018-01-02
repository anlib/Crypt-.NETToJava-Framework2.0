using System;
using System.Collections;
using System.IO;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Asn1.Oiw;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.IO;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.Date;
using Org.BouncyCastle.X509;

namespace Org.BouncyCastle.Cms
{
    /// <remarks>
    /// General class for generating a CMS enveloped-data message.
    ///
    /// A simple example of usage.
    ///
    /// <pre>
    ///      CmsEnvelopedDataGenerator  fact = new CmsEnvelopedDataGenerator();
    ///
    ///      fact.AddKeyTransRecipient(cert);
    ///
    ///      CmsEnvelopedData         data = fact.Generate(content, algorithm);
    /// </pre>
    /// </remarks>
    public class CmsEnvelopedDataGenerator
		: CmsEnvelopedGenerator
    {
		public CmsEnvelopedDataGenerator()
        {
        }

		/// <summary>
		/// Generate an enveloped object that contains a CMS Enveloped Data
		/// object using the passed in key generator.
		/// </summary>
        private CmsEnvelopedData Generate(
            CmsProcessable		content,
            string				encryptionOid,
            CipherKeyGenerator	keyGen)
        {
            AlgorithmIdentifier encAlgId = null;
			KeyParameter encKey = null;
            Asn1OctetString encContent;

			try
			{
				IBufferedCipher cipher = CipherUtilities.GetCipher(encryptionOid);

				byte[] encKeyBytes = keyGen.GenerateKey();
				encKey = ParameterUtilities.CreateKeyParameter(encryptionOid, encKeyBytes);

				Asn1Encodable asn1Params = null;

				try
				{
					if (encryptionOid.Equals(RC2Cbc))
					{
						// mix in a bit extra...
						rand.SetSeed(DateTime.Now.Ticks);

						byte[] iv = rand.GenerateSeed(8);

						// TODO Is this detailed repeat of Java version really necessary?
						int effKeyBits = encKeyBytes.Length * 8;
						int parameterVersion;

						if (effKeyBits < 256)
						{
							parameterVersion = rc2Table[effKeyBits];
						}
						else
						{
							parameterVersion = effKeyBits;
						}

						asn1Params = new RC2CbcParameter(parameterVersion, iv);
					}
					else
					{
						asn1Params = ParameterUtilities.GenerateParameters(encryptionOid, rand);
					}
				}
				catch (SecurityUtilityException)
				{
					// No problem... no parameters generated
				}


				Asn1Object asn1Object;
				ICipherParameters cipherParameters;

				if (asn1Params != null)
				{
					asn1Object = asn1Params.ToAsn1Object();
					cipherParameters = ParameterUtilities.GetCipherParameters(
						encryptionOid, encKey, asn1Object);
				}
				else
				{
					asn1Object = DerNull.Instance;
					cipherParameters = encKey;
				}


				encAlgId = new AlgorithmIdentifier(
					new DerObjectIdentifier(encryptionOid),
					asn1Object);


				cipher.Init(true, cipherParameters);

				MemoryStream bOut = new MemoryStream();
				CipherStream cOut = new CipherStream(bOut, null, cipher);

				content.Write(cOut);

				cOut.Close();

				encContent = new BerOctetString(bOut.ToArray());
			}
			catch (SecurityUtilityException e)
			{
				throw new CmsException("couldn't create cipher.", e);
			}
			catch (InvalidKeyException e)
			{
				throw new CmsException("key invalid in message.", e);
			}
			catch (IOException e)
			{
				throw new CmsException("exception decoding algorithm parameters.", e);
			}


			Asn1EncodableVector recipientInfos = new Asn1EncodableVector();

            foreach (RecipientInf recipient in recipientInfs)
            {
                try
                {
                    recipientInfos.Add(recipient.ToRecipientInfo(encKey));
                }
                catch (IOException e)
                {
                    throw new CmsException("encoding error.", e);
                }
                catch (InvalidKeyException e)
                {
                    throw new CmsException("key inappropriate for algorithm.", e);
                }
                catch (GeneralSecurityException e)
                {
                    throw new CmsException("error making encrypted content.", e);
                }
            }

            EncryptedContentInfo eci = new EncryptedContentInfo(
                PkcsObjectIdentifiers.Data,
                encAlgId,
                encContent);

            Asn1.Cms.ContentInfo contentInfo = new Asn1.Cms.ContentInfo(
                PkcsObjectIdentifiers.EnvelopedData,
                new EnvelopedData(null, new DerSet(recipientInfos), eci, null));

            return new CmsEnvelopedData(contentInfo);
        }

		/// <summary>Generate an enveloped object that contains an CMS Enveloped Data object.</summary>
        public CmsEnvelopedData Generate(
            CmsProcessable	content,
            string			encryptionOid)
        {
            try
            {
				CipherKeyGenerator keyGen = GeneratorUtilities.GetKeyGenerator(encryptionOid);

				return Generate(content, encryptionOid, keyGen);
            }
            catch (SecurityUtilityException e)
            {
                throw new CmsException("can't find key generation algorithm.", e);
            }
        }

		/// <summary>Generate an enveloped object that contains an CMS Enveloped Data object.</summary>
        public CmsEnvelopedData Generate(
            CmsProcessable  content,
            string          encryptionOid,
            int             keySize)
        {
            try
            {
				CipherKeyGenerator keyGen = GeneratorUtilities.GetKeyGenerator(encryptionOid);

				keyGen.Init(new KeyGenerationParameters(new SecureRandom(), keySize));

				return Generate(content, encryptionOid, keyGen);
            }
            catch (SecurityUtilityException e)
            {
                throw new CmsException("can't find key generation algorithm.", e);
            }
        }
    }
}
