using System;

using Org.BouncyCastle.Asn1;

namespace Org.BouncyCastle.Asn1.Esf
{
    /**
    * Commitment type qualifiers, used in the Commitment-Type-Indication attribute (RFC3126).
    *
    * <pre>
    *   CommitmentTypeQualifier ::= SEQUENCE {
    *       commitmentTypeIdentifier  CommitmentTypeIdentifier,
    *       qualifier          ANY DEFINED BY commitmentTypeIdentifier OPTIONAL }
    * </pre>
    */
    public class CommitmentTypeQualifier
        : Asn1Encodable
    {
        private DerObjectIdentifier commitmentTypeIdentifier;
        private Asn1Encodable qualifier;

        /**
        * Creates a new <code>CommitmentTypeQualifier</code> instance.
        *
        * @param commitmentTypeIdentifier a <code>CommitmentTypeIdentifier</code> value
        */
        public CommitmentTypeQualifier(
            DerObjectIdentifier commitmentTypeIdentifier)
            : this(commitmentTypeIdentifier, null)
        {
        }

    /**
        * Creates a new <code>CommitmentTypeQualifier</code> instance.
        *
        * @param commitmentTypeIdentifier a <code>CommitmentTypeIdentifier</code> value
        * @param qualifier the qualifier, defined by the above field.
        */
        public CommitmentTypeQualifier(
            DerObjectIdentifier commitmentTypeIdentifier,
            Asn1Encodable qualifier)
        {
            this.commitmentTypeIdentifier = commitmentTypeIdentifier;
            this.qualifier = qualifier;
        }

        /**
        * Creates a new <code>CommitmentTypeQualifier</code> instance.
        *
        * @param as <code>CommitmentTypeQualifier</code> structure
        * encoded as an Asn1Sequence.
        */
        public CommitmentTypeQualifier(
            Asn1Sequence asSeq)
        {
            commitmentTypeIdentifier = (DerObjectIdentifier)asSeq[0];

			if (asSeq.Count > 1)
            {
                qualifier = asSeq[1];
            }
        }

		public static CommitmentTypeQualifier GetInstance(
			object asObj)
        {
            if (asObj is CommitmentTypeQualifier || asObj == null)
            {
                return (CommitmentTypeQualifier)asObj;
            }

			if (asObj is Asn1Sequence)
            {
                return new CommitmentTypeQualifier((Asn1Sequence)asObj);
            }

			throw new ArgumentException("unknown object in GetInstance.");
        }

		public DerObjectIdentifier CommitmentTypeIdentifier
		{
			get { return commitmentTypeIdentifier; }
		}

		public Asn1Encodable Qualifier
		{
			get { return qualifier; }
		}

		/**
        * Returns a DER-encodable representation of this instance.
        *
        * @return a <code>Asn1Object</code> value
        */
		public override Asn1Object ToAsn1Object()
		{
			Asn1EncodableVector v = new Asn1EncodableVector(
				commitmentTypeIdentifier);

			if (qualifier != null)
			{
				v.Add(qualifier);
			}

			return new DerSequence(v);
		}
    }
}
