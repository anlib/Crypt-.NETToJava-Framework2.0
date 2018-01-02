using System;

namespace Org.BouncyCastle.Asn1.X509
{
    /**
     * IssuingDistributionPoint ::= Sequence {
     *      distributionPoint          [0] DistributionPointName OPTIONAL,
     *      onlyContainsUserCerts      [1] Boolean DEFAULT FALSE,
     *      onlyContainsCACerts        [2] Boolean DEFAULT FALSE,
     *      onlySomeReasons            [3] ReasonFlags OPTIONAL,
     *      indirectCRL                [4] Boolean DEFAULT FALSE,
     *      onlyContainsAttributeCerts [5] Boolean DEFAULT FALSE }
     */
    public class IssuingDistributionPoint
        : Asn1Encodable
    {
        private readonly bool	_onlyContainsUserCerts;
        private readonly bool	_onlyContainsCACerts;
        private readonly bool	_indirectCRL;
        private readonly bool	_onlyContainsAttributeCerts;

		private readonly Asn1Sequence seq;

		public static IssuingDistributionPoint GetInstance(
            Asn1TaggedObject	obj,
            bool				explicitly)
        {
            return GetInstance(Asn1Sequence.GetInstance(obj, explicitly));
        }

		public static IssuingDistributionPoint GetInstance(
            object obj)
        {
            if (obj == null || obj is IssuingDistributionPoint)
            {
                return (IssuingDistributionPoint) obj;
            }

			if (obj is Asn1Sequence)
            {
                return new IssuingDistributionPoint((Asn1Sequence) obj);
            }

			throw new ArgumentException("unknown object in factory");
        }

		/**
         * Constructor from Asn1Sequence
         */
        private IssuingDistributionPoint(
            Asn1Sequence seq)
        {
            this.seq = seq;

			for (int i = 0; i != seq.Count; i++)
            {
				Asn1TaggedObject o = Asn1TaggedObject.GetInstance(seq[i]);

				switch (o.TagNo)
                {
					case 0:
						break;
					case 1:
						_onlyContainsUserCerts = DerBoolean.GetInstance(o, false).IsTrue;
						break;
					case 2:
						_onlyContainsCACerts = DerBoolean.GetInstance(o, false).IsTrue;
						break;
					case 3:
						break;
					case 4:
						_indirectCRL = DerBoolean.GetInstance(o, false).IsTrue;
						break;
					case 5:
						_onlyContainsAttributeCerts = DerBoolean.GetInstance(o, false).IsTrue;
						break;
					default:
						throw new ArgumentException("unknown tag in IssuingDistributionPoint");
                }
            }
        }

		public bool OnlyContainsUserCerts
		{
			get { return _onlyContainsUserCerts; }
		}

		public bool OnlyContainsCACerts
		{
			get { return _onlyContainsCACerts; }
		}

		public bool IsIndirectCrl
		{
			get { return _indirectCRL; }
		}

		public bool OnlyContainsAttributeCerts
		{
			get { return _onlyContainsAttributeCerts; }
		}

		public override Asn1Object ToAsn1Object()
        {
            return seq;
        }
    }
}
