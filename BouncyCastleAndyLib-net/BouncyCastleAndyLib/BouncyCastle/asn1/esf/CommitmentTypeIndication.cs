using System;

using Org.BouncyCastle.Asn1;

namespace Org.BouncyCastle.Asn1.Esf
{
    public class CommitmentTypeIndication
        : Asn1Encodable
    {
        private readonly DerObjectIdentifier	commitmentTypeId;
        private readonly Asn1Sequence			commitmentTypeQualifier;

		public CommitmentTypeIndication(
            Asn1Sequence seq)
        {
            commitmentTypeId = (DerObjectIdentifier)seq[0];

			if (seq.Count > 1)
            {
                commitmentTypeQualifier = (Asn1Sequence)seq[1];
            }
        }

		public CommitmentTypeIndication(
            DerObjectIdentifier commitmentTypeId)
        {
            this.commitmentTypeId = commitmentTypeId;
        }

		public CommitmentTypeIndication(
            DerObjectIdentifier	commitmentTypeId,
            Asn1Sequence		commitmentTypeQualifier)
        {
            this.commitmentTypeId = commitmentTypeId;
            this.commitmentTypeQualifier = commitmentTypeQualifier;
        }

		public static CommitmentTypeIndication GetInstance(
            object obj)
        {
            if (obj == null || obj is CommitmentTypeIndication)
            {
                return (CommitmentTypeIndication) obj;
            }

			return new CommitmentTypeIndication(Asn1Sequence.GetInstance(obj));
        }

		public DerObjectIdentifier CommitmentTypeID
		{
			get { return commitmentTypeId; }
		}

		public Asn1Sequence CommitmentTypeQualifier
		{
			get { return commitmentTypeQualifier; }
		}

		/**
        * <pre>
        * CommitmentTypeIndication ::= SEQUENCE {
        *      commitmentTypeId   CommitmentTypeIdentifier,
        *      commitmentTypeQualifier   SEQUENCE SIZE (1..MAX) OF
        *              CommitmentTypeQualifier OPTIONAL }
        * </pre>
        */
        public override Asn1Object ToAsn1Object()
        {
            Asn1EncodableVector v = new Asn1EncodableVector();

			v.Add(commitmentTypeId);

			if (commitmentTypeQualifier != null)
            {
                v.Add(commitmentTypeQualifier);
            }

			return new DerSequence(v);
        }
    }
}
