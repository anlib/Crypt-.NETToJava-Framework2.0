using System;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Text;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Security.Certificates;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.X509;

namespace Org.BouncyCastle.OpenSsl
{
	/// <remarks>General purpose writer for OpenSSL PEM objects.</remarks>
	public class PemWriter
	{
		private readonly TextWriter writer;

		public TextWriter Writer
		{
			get { return writer; }
		}

		/// <param name="writer">The TextWriter object to write the output to.</param>
		public PemWriter(
			TextWriter writer)
		{
			if (writer == null)
				throw new ArgumentNullException("writer");

			this.writer = writer;
		}

		public void WriteObject(
			object obj) 
		{
			if (obj == null)
				throw new ArgumentNullException("obj");

			string type;
			byte[] encoding;
	        
			if (obj is X509Certificate)
			{
				// TODO Should we prefer "X509 CERTIFICATE" here?
				type = "CERTIFICATE";
				try
				{
					encoding = ((X509Certificate)obj).GetEncoded();
				}
				catch (CertificateEncodingException e)
				{
					throw new IOException("Cannot Encode object: " + e.ToString());
				}
			}
			else if (obj is X509Crl)
			{
				type = "X509 CRL";
				try
				{
					encoding = ((X509Crl)obj).GetEncoded();
				}
				catch (CrlException e)
				{
					throw new IOException("Cannot Encode object: " + e.ToString());
				}
			}
			else if (obj is AsymmetricCipherKeyPair)
			{
				WriteObject(((AsymmetricCipherKeyPair)obj).Private);
				return;
			}
			else if (obj is AsymmetricKeyParameter)
			{
				AsymmetricKeyParameter akp = (AsymmetricKeyParameter) obj;
				if (akp.IsPrivate)
				{
					PrivateKeyInfo info = PrivateKeyInfoFactory.CreatePrivateKeyInfo(akp);

					if (obj is RsaKeyParameters)
					{
						type = "RSA PRIVATE KEY";

						encoding = info.PrivateKey.GetEncoded();
					}
					else if (obj is DsaPrivateKeyParameters)
					{
						type = "DSA PRIVATE KEY";

						DsaParameter p = DsaParameter.GetInstance(info.AlgorithmID.Parameters);

						BigInteger x = ((DsaPrivateKeyParameters)obj).X;
						BigInteger y = p.G.ModPow(x, p.P);

						// TODO Create an ASN1 object somewhere for this?
						encoding = new DerSequence(
							new DerInteger(0),
							new DerInteger(p.P),
							new DerInteger(p.Q),
							new DerInteger(p.G),
							new DerInteger(y),
							new DerInteger(x)).GetEncoded();
					}
					else
					{
						throw new IOException("Cannot identify private key");
					}
				}
				else
				{
					type = "PUBLIC KEY";

					encoding = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(akp).GetDerEncoded();
				}
			}
			else if (obj is IX509AttributeCertificate)
			{
				type = "ATTRIBUTE CERTIFICATE";
				encoding = ((X509V2AttributeCertificate)obj).GetEncoded();
			}
			else if (obj is Pkcs10CertificationRequest)
			{
				type = "CERTIFICATE REQUEST";
				encoding = ((Pkcs10CertificationRequest)obj).GetEncoded();
			}
			else if (obj is Asn1.Cms.ContentInfo)
			{
				type = "PKCS7";
				encoding = ((Asn1.Cms.ContentInfo)obj).GetEncoded();
			}
			else
			{
				throw new ArgumentException("Object type not supported: " + obj.GetType().FullName, "obj");
			}

			WriteHeader(type);
			WriteBase64Encoded(encoding);
			WriteFooter(type);
		}

		public void WriteObject(
			object			obj,
			string			algorithm,
			char[]			password,
			SecureRandom	random)
		{
			if (obj == null)
				throw new ArgumentNullException("obj");
			if (algorithm == null)
				throw new ArgumentNullException("algorithm");
			if (password == null)
				throw new ArgumentNullException("password");
			if (random == null)
				throw new ArgumentNullException("random");


			byte[] keyData = null;

			if (obj is RsaPrivateCrtKeyParameters)
			{
				RsaPrivateCrtKeyParameters k = (RsaPrivateCrtKeyParameters) obj;

				keyData = PrivateKeyInfoFactory.CreatePrivateKeyInfo(k).PrivateKey.GetEncoded();
			}
			else
			{
				// TODO Support other types?
				throw new ArgumentException("Object type not supported: " + obj.GetType().FullName, "obj");
			}


			byte[] salt = new byte[8];
			random.NextBytes(salt);

			OpenSslPbeParametersGenerator pGen = new OpenSslPbeParametersGenerator();

			pGen.Init(PbeParametersGenerator.Pkcs5PasswordToBytes(password), salt);

			ICipherParameters secretKey = null;
			if (algorithm.ToUpper(CultureInfo.InvariantCulture).Equals("DESEDE"))
			{
				// generate key
				int keyLength = 24;
				secretKey = pGen.GenerateDerivedParameters(keyLength * 8);
			}
			else
			{
				throw new IOException("unknown algorithm in WriteObject");
			}


			byte[] encData = null;

			// cipher  
			try
			{
				IBufferedCipher c = CipherUtilities.GetCipher("DESede/CBC/PKCS5Padding");
				c.Init(true, new ParametersWithIV(secretKey, salt));

				encData = c.DoFinal(keyData);
			}
			catch (Exception e)
			{
				throw new IOException("exception using cipher: " + e.ToString());
			}

			// write the data
			string type = "RSA PRIVATE KEY";

			WriteHeader(type);
			writer.WriteLine("Proc-Type: 4,ENCRYPTED");
			writer.Write("DEK-Info: DES-EDE3-CBC,");
			WriteHexEncoded(salt);
			writer.WriteLine();
			WriteBase64Encoded(encData);
			WriteFooter(type);
		}

		private void WriteHeader(
			string type)
		{
			writer.WriteLine("-----BEGIN " + type + "-----");
		}

		private void WriteFooter(
			string type)
		{
			writer.WriteLine("-----END " + type + "-----");
		}

		private void WriteHexEncoded(
			byte[] bytes)
		{
			WriteBytes(Hex.Encode(bytes));
		}

		private void WriteBase64Encoded(
			byte[] bytes) 
		{
			WriteBytes(Base64.Encode(bytes));
		}

		private const int LineLength = 64;

		private void WriteBytes(
			byte[] bytes)
		{
			// TODO Allow non-zero initial line position?
			int pos = 0;
			int remaining = bytes.Length;
			char[] buf = new char[LineLength];

			while (remaining > LineLength)
			{
				Encoding.ASCII.GetChars(bytes, pos, LineLength, buf, 0);
				writer.WriteLine(buf);

				pos += LineLength;
				remaining -= LineLength;
			}

			Encoding.ASCII.GetChars(bytes, pos, remaining, buf, 0);
			writer.WriteLine(buf, 0, remaining);
		}
	}
}
