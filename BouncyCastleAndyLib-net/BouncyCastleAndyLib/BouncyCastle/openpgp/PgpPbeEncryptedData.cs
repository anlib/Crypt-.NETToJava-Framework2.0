using System;
using System.IO;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.IO;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{
	/// <remarks>A password based encryption object.</remarks>
    public class PgpPbeEncryptedData
        : PgpEncryptedData
    {
        private SymmetricKeyEncSessionPacket keyData;

        internal PgpPbeEncryptedData(
            SymmetricKeyEncSessionPacket	keyData,
            InputStreamPacket				encData)
            : base(encData)
        {
            this.keyData = keyData;
        }

		/// <summary>Return the raw input stream for the data stream.</summary>
        public override Stream GetInputStream()
        {
            return encData.GetInputStream();
        }

		/// <summary>Return the decrypted input stream, using the passed in passphrase.</summary>
        public Stream GetDataStream(
            char[] passPhrase)
        {
            IBufferedCipher c;

			try
            {
                SymmetricKeyAlgorithmTag alg = keyData.EncAlgorithm;

                string cName = PgpUtilities.GetSymmetricCipherName(alg);

                if (encData is SymmetricEncIntegrityPacket)
                {
                    cName += "/CFB/NoPadding";
                }
                else
                {
                    cName += "/OpenPGPCFB/NoPadding";
                }

                c = CipherUtilities.GetCipher(cName);
            }
            catch (PgpException e)
            {
                throw e;
            }
            catch (Exception e)
            {
                throw new PgpException("exception creating cipher", e);
            }

            if (c != null)
            {
                try
                {
                    KeyParameter key = PgpUtilities.MakeKeyFromPassPhrase(
						keyData.EncAlgorithm, keyData.S2k, passPhrase);

					byte[] iv = new byte[c.GetBlockSize()];

					c.Init(false, new ParametersWithIV(key, iv));

					encStream = BcpgInputStream.Wrap(new CipherStream(encData.GetInputStream(), c, null));

					if (encData is SymmetricEncIntegrityPacket)
                    {
                        truncStream = new TruncatedStream(encStream);

                        string digestName = PgpUtilities.GetDigestName(HashAlgorithmTag.Sha1);
                        IDigest digest = DigestUtilities.GetDigest(digestName);

                        encStream = new DigestStream(truncStream, digest, null);
                    }

					for (int i = 0; i != iv.Length; i++)
                    {
                        int ch = encStream.ReadByte();

						if (ch < 0)
                        {
                            throw new EndOfStreamException("unexpected end of stream.");
                        }

						iv[i] = (byte)ch;
                    }

					int v1 = encStream.ReadByte();
                    int v2 = encStream.ReadByte();

					if (v1 < 0 || v2 < 0)
                    {
                        throw new EndOfStreamException("unexpected end of stream.");
                    }


					// Note: the oracle attack on the "quick check" bytes is not deemed
					// a security risk for PBE (see PgpPublicKeyEncryptedData)

					bool repeatCheckPassed =
							iv[iv.Length - 2] == (byte)v1
						&&	iv[iv.Length - 1] == (byte)v2;

					// Note: some versions of PGP appear to produce 0 for the extra
					// bytes rather than repeating the two previous bytes
					bool zeroesCheckPassed =
							v1 == 0
						&&	v2 == 0;

					if (!repeatCheckPassed && !zeroesCheckPassed)
					{
						throw new PgpDataValidationException("quick check failed.");
					}


					return encStream;
                }
                catch (PgpException e)
                {
                    throw e;
                }
                catch (Exception e)
                {
                    throw new PgpException("Exception creating cipher", e);
                }
            }
            else
            {
                return encData.GetInputStream();
            }
		}
	}
}
