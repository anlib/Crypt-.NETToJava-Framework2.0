using System;
using System.Collections;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Security.Certificates;

namespace Org.BouncyCastle.X509
{
	/// <remarks>
	/// The Holder object.
	/// <pre>
	/// Holder ::= SEQUENCE {
	/// 	baseCertificateID   [0] IssuerSerial OPTIONAL,
	/// 		-- the issuer and serial number of
	/// 		-- the holder's Public Key Certificate
	/// 	entityName          [1] GeneralNames OPTIONAL,
	/// 		-- the name of the claimant or role
	/// 	objectDigestInfo    [2] ObjectDigestInfo OPTIONAL
	/// 		-- used to directly authenticate the holder,
	/// 		-- for example, an executable
	/// }
	/// </pre>
	/// This holder currently supports use of the baseCertificateID and the entityName.
	/// </remarks>
	public class AttributeCertificateHolder
		// TODO Put back in
		//: CertSelector, Selector
	{
		internal readonly Holder holder;

		internal AttributeCertificateHolder(
			Asn1Sequence seq)
		{
			holder = Holder.GetInstance(seq);
		}

		public AttributeCertificateHolder(
			X509Name	issuerName,
			BigInteger	serialNumber)
		{
			holder = new Holder(
				new IssuerSerial(
					GenerateGeneralNames(issuerName),
					new DerInteger(serialNumber)));
		}

		public AttributeCertificateHolder(
			X509Certificate	cert)
		{
			X509Name name;
			try
			{
				name = PrincipalUtilities.GetIssuerX509Principal(cert);
			}
			catch (Exception e)
			{
				throw new CertificateParsingException(e.Message);
			}

			holder = new Holder(new IssuerSerial(GenerateGeneralNames(name), new DerInteger(cert.SerialNumber)));
		}

		public AttributeCertificateHolder(
			X509Name principal)
		{
			holder = new Holder(GenerateGeneralNames(principal));
		}

		private GeneralNames GenerateGeneralNames(
			X509Name principal)
		{
//			return GeneralNames.GetInstance(new DerSequence(new GeneralName(principal)));
			return new GeneralNames(new GeneralName(principal));
		}

		private bool MatchesDN(
			X509Name		subject,
			GeneralNames	targets)
		{
			GeneralName[] names = targets.GetNames();

			for (int i = 0; i != names.Length; i++)
			{
				GeneralName gn = names[i];

				if (gn.TagNo == GeneralName.DirectoryName)
				{
					try
					{
						if (X509Name.GetInstance(gn.Name).Equivalent(subject))
						{
							return true;
						}
					}
					catch (Exception)
					{
					}
				}
			}

			return false;
		}

		private object[] GetNames(
			GeneralName[] names)
		{
			ArrayList l = new ArrayList(names.Length);

			for (int i = 0; i != names.Length; i++)
			{
				if (names[i].TagNo == GeneralName.DirectoryName)
				{
					l.Add(X509Name.GetInstance(names[i].Name));
				}
			}

			return l.ToArray();
		}

		private X509Name[] GetPrincipals(
			GeneralNames names)
		{
			object[] p = this.GetNames(names.GetNames());
			ArrayList l = new ArrayList(p.Length);

			for (int i = 0; i != p.Length; i++)
			{
				if (p[i] is X509Name)
				{
					l.Add(p[i]);
				}
			}

			return (X509Name[]) l.ToArray(typeof(X509Name));
		}

		/**
		 * Return any principal objects inside the attribute certificate holder entity names field.
		 *
		 * @return an array of IPrincipal objects (usually X509Name), null if no entity names field is set.
		 */
		public X509Name[] GetEntityNames()
		{
			if (holder.EntityName != null)
			{
				return GetPrincipals(holder.EntityName);
			}

			return null;
		}

		/**
		 * Return the principals associated with the issuer attached to this holder
		 *
		 * @return an array of principals, null if no BaseCertificateID is set.
		 */
		public X509Name[] GetIssuer()
		{
			if (holder.BaseCertificateID != null)
			{
				return GetPrincipals(holder.BaseCertificateID.Issuer);
			}

			return null;
		}

		/**
		 * Return the serial number associated with the issuer attached to this holder.
		 *
		 * @return the certificate serial number, null if no BaseCertificateID is set.
		 */
		public BigInteger SerialNumber
		{
			get
			{
				if (holder.BaseCertificateID != null)
				{
					return holder.BaseCertificateID.Serial.Value;
				}

				return null;
			}
		}

		public object Clone()
		{
			return new AttributeCertificateHolder((Asn1Sequence)holder.ToAsn1Object());
		}

		public bool Match(
//			Certificate cert)
			X509Certificate x509Cert)
		{
//			if (!(cert is X509Certificate))
//			{
//				return false;
//			}
//
//			X509Certificate x509Cert = (X509Certificate)cert;

			try
			{
				if (holder.BaseCertificateID != null)
				{
					return holder.BaseCertificateID.Serial.Value.Equals(x509Cert.SerialNumber)
						&& MatchesDN(PrincipalUtilities.GetIssuerX509Principal(x509Cert), holder.BaseCertificateID.Issuer);
				}

				if (holder.EntityName != null)
				{
					if (MatchesDN(PrincipalUtilities.GetSubjectX509Principal(x509Cert), holder.EntityName))
					{
						return true;
					}
				}
			}
			catch (CertificateEncodingException)
			{
				return false;
			}

			// objectDigestInfo not supported
			return false;
		}

		public override bool Equals(
			object obj)
		{
			if (obj == this)
			{
				return true;
			}

			if (!(obj is AttributeCertificateHolder))
			{
				return false;
			}

			AttributeCertificateHolder other = (AttributeCertificateHolder)obj;

			return this.holder.Equals(other.holder);
		}

		public override int GetHashCode()
		{
			return this.holder.GetHashCode();
		}

		public bool Match(
			object obj)
		{
			if (!(obj is X509Certificate))
			{
				return false;
			}

//			return Match((Certificate)obj);
			return Match((X509Certificate)obj);
		}
	}
}
