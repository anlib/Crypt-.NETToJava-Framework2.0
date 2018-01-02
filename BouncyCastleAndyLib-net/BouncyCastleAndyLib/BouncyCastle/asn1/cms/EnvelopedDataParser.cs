using System;

namespace Org.BouncyCastle.Asn1.Cms
{
	/**
	* <pre>
	* EnvelopedData ::= SEQUENCE {
	*     version CMSVersion,
	*     originatorInfo [0] IMPLICIT OriginatorInfo OPTIONAL,
	*     recipientInfos RecipientInfos,
	*     encryptedContentInfo EncryptedContentInfo,
	*     unprotectedAttrs [1] IMPLICIT UnprotectedAttributes OPTIONAL
	* }
	* </pre>
	*/
	public class EnvelopedDataParser
	{
		private Asn1SequenceParser	_seq;
		private DerInteger			_version;
		private IAsn1Convertible			_nextObject;

		public EnvelopedDataParser(
			Asn1SequenceParser seq)
		{
			this._seq = seq;
			this._version = (DerInteger)seq.ReadObject();
		}

		public DerInteger Version
		{
			get { return _version; }
		}

		public Asn1SetParser GetCertificates()
		{
			_nextObject = _seq.ReadObject();

			if (_nextObject is Asn1TaggedObject && ((Asn1TaggedObject)_nextObject).TagNo == 0)
			{
				Asn1SetParser certs = (Asn1SetParser)((Asn1TaggedObject)_nextObject).GetObjectParser(Asn1Tags.Set, false);
				_nextObject = null;

				return certs;
			}

			return null;
		}

		public Asn1SetParser GetCrls()
		{
			if (_nextObject == null)
			{
				_nextObject = _seq.ReadObject();
			}

			if (_nextObject is Asn1TaggedObject && ((Asn1TaggedObject)_nextObject).TagNo == 1)
			{
				Asn1SetParser crls = (Asn1SetParser)((Asn1TaggedObject)_nextObject).GetObjectParser(Asn1Tags.Set, false);
				_nextObject = null;

				return crls;
			}

			return null;
		}

		public Asn1SetParser GetRecipientInfos()
		{
			return (Asn1SetParser)_seq.ReadObject();
		}

		public EncryptedContentInfoParser GetEncryptedContentInfo()
		{
			return new EncryptedContentInfoParser((Asn1SequenceParser)_seq.ReadObject());
		}

		public Asn1SetParser GetUnprotectedAttrs()
		{
			IAsn1Convertible o = _seq.ReadObject();

			if (o == null)
				return null;

			return (Asn1SetParser)((Asn1TaggedObjectParser)o).GetObjectParser(Asn1Tags.Set, false);
		}
	}
}
