using System;

namespace Org.BouncyCastle.Asn1.X509
{
    public class ObjectDigestInfo
        : Asn1Encodable
    {
        internal readonly DerEnumerated			digestedObjectType;
        internal readonly DerObjectIdentifier	otherObjectTypeID;
        internal readonly AlgorithmIdentifier	digestAlgorithm;
        internal readonly DerBitString			objectDigest;

		public static ObjectDigestInfo GetInstance(
            object obj)
        {
            if (obj == null || obj is ObjectDigestInfo)
            {
                return (ObjectDigestInfo) obj;
            }

			if (obj is Asn1Sequence)
            {
                return new ObjectDigestInfo((Asn1Sequence) obj);
            }

			throw new ArgumentException("illegal object in GetInstance: " + obj);
        }

		public static ObjectDigestInfo GetInstance(
            Asn1TaggedObject	obj,
            bool				isExplicit)
        {
            return GetInstance(Asn1Sequence.GetInstance(obj, isExplicit));
        }

		private ObjectDigestInfo(
			Asn1Sequence seq)
        {
			if (seq.Count > 4 || seq.Count < 3)
			{
				throw new ArgumentException("Bad sequence size: " + seq.Count);
			}

			digestedObjectType = DerEnumerated.GetInstance(seq[0]);

			int offset = 0;

			if (seq.Count == 4)
            {
                otherObjectTypeID = DerObjectIdentifier.GetInstance(seq[1]);
                offset++;
            }

			digestAlgorithm = AlgorithmIdentifier.GetInstance(seq[1 + offset]);
			objectDigest = DerBitString.GetInstance(seq[2 + offset]);
		}

		public DerEnumerated DigestedObjectType
		{
			get { return digestedObjectType; }
		}

		public DerObjectIdentifier OtherObjectTypeID
		{
			get { return otherObjectTypeID; }
		}

		public AlgorithmIdentifier DigestAlgorithm
		{
			get { return digestAlgorithm; }
		}

		public DerBitString ObjectDigest
		{
			get { return objectDigest; }
		}

		/**
         * Produce an object suitable for an Asn1OutputStream.
         * <pre>
         *  ObjectDigestInfo ::= Sequence {
         *       digestedObjectType  Enumerated {
         *               publicKey            (0),
         *               publicKeyCert        (1),
         *               otherObjectTypes     (2) },
         *                       -- otherObjectTypes MUST NOT
         *                       -- be used in this profile
         *       otherObjectTypeID   OBJECT IDENTIFIER OPTIONAL,
         *       digestAlgorithm     AlgorithmIdentifier,
         *       objectDigest        BIT STRING
         *  }
         * </pre>
         */
        public override Asn1Object ToAsn1Object()
        {
            Asn1EncodableVector v = new Asn1EncodableVector(digestedObjectType);

			if (otherObjectTypeID != null)
            {
                v.Add(otherObjectTypeID);
            }

			v.Add(digestAlgorithm, objectDigest);

			return new DerSequence(v);
        }
    }
}
