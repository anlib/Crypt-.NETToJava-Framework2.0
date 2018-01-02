using System;

namespace Org.BouncyCastle.Asn1.X509
{
    public class Holder
        : Asn1Encodable
    {
		internal readonly IssuerSerial		baseCertificateID;
        internal readonly GeneralNames		entityName;
        internal readonly ObjectDigestInfo	objectDigestInfo;

		public static Holder GetInstance(
            object obj)
        {
            if (obj is Holder)
            {
                return (Holder) obj;
            }

			if (obj is Asn1Sequence)
            {
                return new Holder((Asn1Sequence) obj);
            }

			throw new ArgumentException("unknown object in factory");
        }

		private Holder(
            Asn1Sequence seq)
        {
			if (seq.Count > 3)
			{
				throw new ArgumentException("Bad sequence size: " + seq.Count);
			}

			for (int i = 0; i != seq.Count; i++)
            {
				Asn1TaggedObject tObj = Asn1TaggedObject.GetInstance(seq[i]);

				switch (tObj.TagNo)
                {
                    case 0:
                        baseCertificateID = IssuerSerial.GetInstance(tObj, false);
                        break;
                    case 1:
                        entityName = GeneralNames.GetInstance(tObj, false);
                        break;
                    case 2:
                        objectDigestInfo = ObjectDigestInfo.GetInstance(tObj, false);
                        break;
                    default:
                        throw new ArgumentException("unknown tag in Holder");
                }
            }
        }

		public Holder(
			IssuerSerial baseCertificateID)
		{
			this.baseCertificateID = baseCertificateID;
		}

		public Holder(
			GeneralNames entityName)
		{
			this.entityName = entityName;
		}

		public IssuerSerial BaseCertificateID
		{
			get { return baseCertificateID; }
		}

		public GeneralNames EntityName
		{
			get { return entityName; }
		}

		public ObjectDigestInfo ObjectDigestInfo
		{
			get { return objectDigestInfo; }
		}

		/**
         * The Holder object.
         * <pre>
         *  Holder ::= Sequence {
         *        baseCertificateID   [0] IssuerSerial OPTIONAL,
         *                 -- the issuer and serial number of
         *                 -- the holder's Public Key Certificate
         *        entityName          [1] GeneralNames OPTIONAL,
         *                 -- the name of the claimant or role
         *        objectDigestInfo    [2] ObjectDigestInfo OPTIONAL
         *                 -- used to directly authenticate the holder,
         *                 -- for example, an executable
         *  }
         * </pre>
         */
		public override Asn1Object ToAsn1Object()
		{
			Asn1EncodableVector v = new Asn1EncodableVector();

			if (baseCertificateID != null)
			{
				v.Add(new DerTaggedObject(false, 0, baseCertificateID));
			}

			if (entityName != null)
			{
				v.Add(new DerTaggedObject(false, 1, entityName));
			}

			if (objectDigestInfo != null)
			{
				v.Add(new DerTaggedObject(false, 2, objectDigestInfo));
			}

			return new DerSequence(v);
		}
	}
}
