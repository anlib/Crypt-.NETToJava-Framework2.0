using System;

using Org.BouncyCastle.Math;
using Org.BouncyCastle.Utilities.Date;

namespace Org.BouncyCastle.X509.Store
{
	/**
	* This class is an <code>Selector</code> like implementation to select
	* attribute certificates from a given set of criteria.
	*
	* @see Org.BouncyCastle.x509.X509AttributeCertificate
	* @see Org.BouncyCastle.x509.X509Store
	*/
	public class X509AttrCertStoreSelector
		: IX509Selector
	{
		// TODO: name constraints???

		private IX509AttributeCertificate attributeCert;
		private DateTimeObject attributeCertificateValid;
		private AttributeCertificateHolder holder;
		private AttributeCertificateIssuer issuer;
		private BigInteger serialNumber;

		public X509AttrCertStoreSelector()
		{
		}

		private X509AttrCertStoreSelector(
			X509AttrCertStoreSelector o)
		{
			this.attributeCert = o.attributeCert;
			this.attributeCertificateValid = o.attributeCertificateValid;
			this.holder = o.holder;
			this.issuer = o.issuer;
			this.serialNumber = o.serialNumber;
		}

		/// <summary>
		/// Decides if the given attribute certificate should be selected.
		/// </summary>
		/// <param name="obj">The attribute certificate to be checked.</param>
		/// <returns><code>true</code> if the object matches this selector.</returns>
		public bool Match(
			object obj)
		{
			if (obj == null)
				throw new ArgumentNullException("obj");

			IX509AttributeCertificate attrCert = obj as IX509AttributeCertificate;
			if (attrCert == null)
				return false;

			if (this.attributeCert != null && !this.attributeCert.Equals(attrCert))
				return false;

			if (serialNumber != null && !attrCert.SerialNumber.Equals(serialNumber))
				return false;

			if (holder != null && !attrCert.Holder.Equals(holder))
				return false;

			if (issuer != null && !attrCert.Issuer.Equals(issuer))
				return false;

			if (attributeCertificateValid != null && !attrCert.IsValid(attributeCertificateValid.Value))
				return false;

			return true;
		}

		public object Clone()
		{
			return new X509AttrCertStoreSelector(this);
		}

		/// <summary>The attribute certificate which must be matched.</summary>
		public IX509AttributeCertificate AttributeCert
		{
			get { return attributeCert; }
			set { this.attributeCert = value; }
		}

		/// <summary>The criteria for validity</summary>
		public DateTimeObject AttribueCertificateValid
		{
			get { return attributeCertificateValid; }
			set { this.attributeCertificateValid = value; }
		}

		/// <summary>The holder.</summary>
		public AttributeCertificateHolder Holder
		{
			get { return holder; }
			set { this.holder = value; }
		}

		/// <summary>The issuer.</summary>
		public AttributeCertificateIssuer Issuer
		{
			get { return issuer; }
			set { this.issuer = value; }
		}

		/// <summary>The serial number.</summary>
		public BigInteger SerialNumber
		{
			get { return serialNumber; }
			set { this.serialNumber = value; }
		}
	}
}
